//! The cached effective-set loader.
//!
//! The [`Authz`](crate::auth::authz::Authz) seam answers `can_read` /
//! `can_write` / `can_admin` from a principal's resolved
//! [`EffectiveSet`](super::EffectiveSet). Computing that set is a DB round trip
//! (`user_role → repository_privilege`), far too costly to run on every
//! download/restore request. This module sits in front of that load with
//! [`forge_cache::Cache`] — **in-process only**
//! ([`forge_cache::Cache::get_or_try_insert_local`]): an effective set is an
//! authorization decision, so it is never read from or written to Redis,
//! where anyone with access to Redis could plant an admin set. Redis carries
//! only the invalidations (the pub/sub backplane), so a grant change still
//! evicts every instance's copy.
//!
//! ## What is cached, and the key
//!
//! We cache the **owner's** [`RawEffectiveSet`] — the serializable, pre-compile
//! form — keyed by principal:
//!
//! * authenticated user → `authz:user:{user_id}`
//! * anonymous          → `authz:anon` (a single shared entry)
//!
//! Per-token scoping is **not** part of the key: a token narrows its owner's set
//! and the scope is intersected *after* the cache lookup ([`intersect_scope`]),
//! so all of a user's tokens share one cached owner set. The cached value is the
//! `RawEffectiveSet` (raw glob strings, not compiled globs) so it round-trips
//! through JSON cheaply; the [`EffectiveSet`] (with compiled `GlobSet`s) is built
//! per lookup from it — building is a handful of glob compiles, vastly cheaper
//! than the DB query, and keeps `Arc<GlobSet>` out of the serialized form.
//!
//! [`EffectiveSet`]: super::EffectiveSet
//! [`intersect_scope`]: super::EffectiveSet::intersect_scope
//!
//! ## Invalidation (cross-instance, authoritative)
//!
//! Every mutation that changes a principal's authorization must invalidate the
//! cache. Two granularities, both broadcast on the backplane so every node drops
//! its stale L1:
//!
//! * **Targeted** — a `user_role` change for user `U` invalidates exactly
//!   `authz:user:{U}` via [`invalidate_user`].
//! * **Blanket** — a change to a *role*'s grants/selectors (which can affect many
//!   principals) invalidates the whole `authz` namespace via
//!   [`invalidate_all`]. This is an "epoch roll", realized with the cache
//!   crate's `invalidate_ns` (drop all `authz:*` and broadcast);
//!   it is O(1) to publish and always correct. Enumerating affected users is a
//!   future optimization, not a correctness requirement.
//!
//! ## TTL backstop / fail-closed
//!
//! A short TTL bounds staleness even if a backplane message is lost or Redis is
//! absent — privilege *removal* takes effect within `min(backplane latency,
//! TTL)`. A *factory* (DB) error is **not** cached and is surfaced to the caller,
//! which denies (fail-closed): an evaluation error never grants.

use std::time::Duration;

use forge_cache::Cache;
use forge_db::authz_dao::{self, EffectiveRows};
use sqlx::PgPool;

use super::eval::{EffectiveSet, RawEffectiveSet, RawGrant, SelectorPatterns};

/// Cache namespace for resolved effective sets. Invalidating this whole
/// namespace ([`invalidate_all`]) is the blanket "epoch roll".
pub const NS_AUTHZ: &str = "authz";

/// Default TTL backstop for a cached effective set. Short so that, even without
/// Redis / a missed backplane message, a privilege change converges quickly.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// A DB error while loading an effective set.
///
/// `Clone` because [`forge_cache::Cache::get_or_try_insert_with`] coalesces
/// concurrent loads and hands every waiter a shared error on a failing factory;
/// we clone the message out for each caller (and the cache stores nothing, so
/// the next call retries). The seam treats any such error as **deny**.
#[derive(Debug, Clone, thiserror::Error)]
#[error("authz effective-set load failed: {0}")]
pub struct LoadError(String);

impl From<sqlx::Error> for LoadError {
    fn from(e: sqlx::Error) -> Self {
        LoadError(e.to_string())
    }
}

/// The cache key for a principal's owner effective set.
fn user_key(user_id: i64) -> String {
    format!("user:{user_id}")
}

/// The single shared cache key for the anonymous role's grants.
const ANON_KEY: &str = "anon";

/// The cache key for a single role's effective set (WIF workload principals).
fn role_key(role_id: i64) -> String {
    format!("role:{role_id}")
}

/// Load (cached) the **owner** effective set for an authenticated user, building
/// the compiled [`EffectiveSet`] from the cached raw form.
///
/// `dual_read_is_admin` is the slice-1 `app_user.is_admin` fallback: during the
/// migration window the admin short-circuit is `in_admin_role OR is_admin`. It is
/// folded into the *built* set (not the cached raw set) so the cache stays a pure
/// role-derived projection and the fallback can be dropped later without a cache
/// format change.
pub async fn load_user_effective(
    pool: &PgPool,
    cache: &Cache,
    user_id: i64,
    dual_read_is_admin: bool,
) -> Result<EffectiveSet, LoadError> {
    let raw = cache
        .get_or_try_insert_local(NS_AUTHZ, &user_key(user_id), DEFAULT_TTL, || async {
            let rows = authz_dao::load_user_effective(pool, user_id).await?;
            Ok::<RawEffectiveSet, LoadError>(to_raw_set(rows))
        })
        .await?;

    build_set(raw, dual_read_is_admin)
}

/// Load (cached) the effective set applied to **anonymous** callers (exactly the
/// built-in `anonymous` role's grants). Never admin, no dual-read.
pub async fn load_anonymous_effective(
    pool: &PgPool,
    cache: &Cache,
) -> Result<EffectiveSet, LoadError> {
    let raw = cache
        .get_or_try_insert_local(NS_AUTHZ, ANON_KEY, DEFAULT_TTL, || async {
            let rows = authz_dao::load_anonymous_effective(pool).await?;
            Ok::<RawEffectiveSet, LoadError>(to_raw_set(rows))
        })
        .await?;

    build_set(raw, false)
}

/// Load (cached) the effective set granted by a **single role**, for a
/// workload-identity (WIF) principal. The validated CI token is
/// mapped to one forge role; this resolves that role's grants directly (no
/// `app_user` / `user_role` membership). `is_admin` is set iff the role is the
/// built-in `admin` role — never via a dual-read fallback (a workload has no
/// `app_user.is_admin` column). A role-grant change invalidates this via the
/// blanket [`invalidate_all`] "epoch roll", like any other role edit.
pub async fn load_role_effective(
    pool: &PgPool,
    cache: &Cache,
    role_id: i64,
) -> Result<EffectiveSet, LoadError> {
    let raw = cache
        .get_or_try_insert_local(NS_AUTHZ, &role_key(role_id), DEFAULT_TTL, || async {
            let rows = authz_dao::load_role_effective(pool, role_id).await?;
            Ok::<RawEffectiveSet, LoadError>(to_raw_set(rows))
        })
        .await?;

    build_set(raw, false)
}

/// Build the compiled [`EffectiveSet`] from a cached raw set, applying the
/// dual-read admin fallback.
///
/// A selector that fails to compile fails the whole build (fail-closed: the
/// caller denies rather than silently treating the grant as unscoped).
fn build_set(
    mut raw: RawEffectiveSet,
    dual_read_is_admin: bool,
) -> Result<EffectiveSet, LoadError> {
    if dual_read_is_admin {
        raw.is_admin = true;
    }
    EffectiveSet::build(&raw).map_err(|e| LoadError(e.to_string()))
}

/// Convert the DB layer's [`EffectiveRows`] into the core crate's serializable
/// [`RawEffectiveSet`].
///
/// A selector whose stored jsonb is not an array of strings is **dropped along
/// with its grant** (fail-closed: we never silently widen a malformed
/// selector-scoped grant into an unscoped one). The dropped grant is logged.
fn to_raw_set(rows: EffectiveRows) -> RawEffectiveSet {
    let mut grants = Vec::with_capacity(rows.grants.len());
    for g in rows.grants {
        let selector = match &g.selector {
            None => None,
            Some(sel) => match sel.patterns() {
                Ok((includes, excludes)) => Some(SelectorPatterns { includes, excludes }),
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        action = %g.action,
                        "dropping grant with malformed content selector (fail-closed)"
                    );
                    // Drop the whole grant rather than keep it unscoped.
                    continue;
                }
            },
        };
        grants.push(RawGrant {
            action: g.action,
            repo: g.repository_id,
            selector,
        });
    }
    RawEffectiveSet {
        is_admin: rows.is_admin,
        grants,
    }
}

/// Invalidate one user's cached effective set (targeted): a `user_role` change
/// for `user_id`. Broadcasts on the backplane so every node drops its L1.
pub async fn invalidate_user(cache: &Cache, user_id: i64) {
    cache.invalidate(NS_AUTHZ, &user_key(user_id)).await;
}

/// Invalidate the anonymous effective set: an `anonymous`-role grant change.
pub async fn invalidate_anonymous(cache: &Cache) {
    cache.invalidate(NS_AUTHZ, ANON_KEY).await;
}

/// Blanket-invalidate **all** cached effective sets (the "epoch roll"): a change
/// to any role's grants/selectors that may affect many principals. Drops the
/// whole `authz` namespace and broadcasts.
pub async fn invalidate_all(cache: &Cache) {
    cache.invalidate_ns(NS_AUTHZ).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_db::authz_dao::{EffectiveGrantRow, SelectorRow};
    use serde_json::json;

    #[test]
    fn to_raw_set_maps_grants_and_admin() {
        let rows = EffectiveRows {
            is_admin: true,
            grants: vec![
                EffectiveGrantRow {
                    action: "read".into(),
                    repository_id: Some(1),
                    selector: None,
                },
                EffectiveGrantRow {
                    action: "write".into(),
                    repository_id: None,
                    selector: Some(SelectorRow {
                        id: 5,
                        includes: json!(["company.*"]),
                        excludes: json!(["company.secret*"]),
                    }),
                },
            ],
        };
        let raw = to_raw_set(rows);
        assert!(raw.is_admin);
        assert_eq!(raw.grants.len(), 2);
        assert_eq!(raw.grants[0].action, "read");
        assert_eq!(raw.grants[0].repo, Some(1));
        assert!(raw.grants[0].selector.is_none());
        let sel = raw.grants[1].selector.as_ref().expect("selector");
        assert_eq!(sel.includes, vec!["company.*"]);
        assert_eq!(sel.excludes, vec!["company.secret*"]);
    }

    #[test]
    fn to_raw_set_drops_grant_with_malformed_selector() {
        // A selector whose includes is not an array of strings ⇒ drop the grant
        // (fail-closed): it must NOT become an unscoped grant.
        let rows = EffectiveRows {
            is_admin: false,
            grants: vec![EffectiveGrantRow {
                action: "read".into(),
                repository_id: Some(1),
                selector: Some(SelectorRow {
                    id: 9,
                    includes: json!("not-an-array"),
                    excludes: json!([]),
                }),
            }],
        };
        let raw = to_raw_set(rows);
        assert!(raw.grants.is_empty(), "malformed-selector grant dropped");
    }

    #[test]
    fn build_set_dual_read_forces_admin() {
        let raw = RawEffectiveSet::empty();
        let no_dual = build_set(raw.clone(), false).expect("build");
        assert!(!no_dual.is_admin());
        let dual = build_set(raw, true).expect("build");
        assert!(
            dual.is_admin(),
            "dual-read is_admin forces admin short-circuit"
        );
    }
}
