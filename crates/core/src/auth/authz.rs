//! Authorization seam (§12.4: the single fine-grained-RBAC decision point).
//!
//! ## The seam
//! Authorization is decided by the [`Authz`] service. It owns the data handles a
//! fine-grained policy needs — a [`PgPool`] (authoritative privilege data) and a
//! [`Cache`] (the resolved effective-permission set, with cross-node
//! invalidation) — and exposes the predicates the whole codebase routes through:
//!
//! * [`Authz::can_read`] — download / list / search.
//! * [`Authz::can_write`] — push / delete / relist.
//! * [`Authz::can_admin`] — repository config + privilege management.
//! * [`Authz::package_filter`] — the package-level visibility predicate applied
//!   when listing/serving packages and re-applied on direct download.
//!
//! Every gate (request dispatch in `server::dispatch`, the browse read
//! endpoints, the admin `require_admin` middleware, and identity-aware group
//! resolution in `core::repo::group`) calls these methods. Keeping them on one
//! service is what lets §12.4 answer them from the cached RBAC evaluator
//! **without touching any call site**.
//!
//! ## Behavior (fine-grained RBAC, §12.4 Phase 3)
//! Each predicate resolves the principal's **effective set** (the additive union
//! of its roles' grants) and asks the pure evaluator:
//!
//! * **User** — its `user_role`-derived grants, loaded once per user and cached
//!   ([`crate::authz::cache`]). The slice-1 `app_user.is_admin` flag is folded in
//!   as a **dual-read** admin fallback (`in_admin_role OR is_admin`) so existing
//!   admins keep working during the migration window — it can only ever *grant*
//!   admin, never remove it.
//! * **Anonymous** — exactly the built-in `anonymous` role's grants (cached under
//!   one shared key). On an un-migrated install that role has no grants ⇒ deny.
//! * **Token-scoped** — when the principal carries a `token_id`, the token's
//!   optional `scope` is loaded (outside the per-user cache) and **intersected**
//!   with the owner's effective set *after* the cache lookup. A token can only
//!   narrow, never widen.
//! * **Unauthenticated** — always denied.
//!
//! ## Fail-closed
//! The methods return `bool` (preserving the slice-1 call sites). Any evaluation
//! error — a DB load failure, a selector that won't compile, a malformed token
//! scope — is **logged and denied**: an error never grants. The repo-level gate
//! is a fast in-memory set test over the (warm-cache) effective set; selector
//! filtering happens separately via [`Authz::package_filter`].

use forge_cache::Cache;
use forge_db::authz_dao;
use forge_db::model::Repository;
use sqlx::PgPool;

use super::principal::Principal;
use crate::authz::cache as authz_cache;
use crate::authz::{parse_token_scope, Action, EffectiveSet, PackageFilter, TokenScope};

/// The authorization decision service (§12.4 seam).
///
/// Cheaply cloneable: the [`PgPool`] and [`Cache`] inside are both `Arc`-backed.
/// Constructed once during server wiring and held in app state / threaded into
/// `core` operations (e.g. group resolution) that need to make decisions.
#[derive(Clone)]
pub struct Authz {
    pool: PgPool,
    cache: Cache,
}

impl Authz {
    /// Build the service from the shared DB pool and cache.
    pub fn new(pool: PgPool, cache: Cache) -> Self {
        Authz { pool, cache }
    }

    /// May `principal` read (download / list / search) `repo`?
    ///
    /// Fail-closed: an evaluation error logs and denies.
    pub async fn can_read(&self, principal: &Principal, repo: &Repository) -> bool {
        self.allows(principal, Action::Read, repo.id).await
    }

    /// May `principal` write (push / delete / relist) to `repo`?
    ///
    /// Writing always requires a held `write` grant; anonymous callers can only
    /// write if the `anonymous` role was explicitly granted `write` (it is not,
    /// by default). Fail-closed.
    pub async fn can_write(&self, principal: &Principal, repo: &Repository) -> bool {
        self.allows(principal, Action::Write, repo.id).await
    }

    /// May `principal` perform admin operations on `repo`?
    ///
    /// Admin is the `admin`-role short-circuit (or the `is_admin` dual-read
    /// fallback); a per-repo `admin` grant also satisfies it. Fail-closed.
    pub async fn can_admin(&self, principal: &Principal, repo: &Repository) -> bool {
        self.allows(principal, Action::Admin, repo.id).await
    }

    /// Is `principal` a **global admin** — i.e. a member of the built-in `admin`
    /// role (or the slice-1 `is_admin` dual-read fallback)?
    ///
    /// This is the repo-less admin gate used by the privilege-management admin
    /// API (`/admin/roles`, `/admin/users/{id}/roles`, …), which has no single
    /// repository to scope against. It is satisfied **only** by the allow-all
    /// `admin` short-circuit, never by a per-repo `admin` grant — managing roles
    /// and grants is a server-wide capability. Fail-closed: an evaluation error
    /// (or an anonymous / unauthenticated principal) denies.
    pub async fn is_global_admin(&self, principal: &Principal) -> bool {
        match self.effective(principal).await {
            Ok(eff) => eff.is_admin(),
            Err(()) => false,
        }
    }

    /// The package-visibility predicate for `principal` reading `repo`.
    ///
    /// Used when listing/serving packages and **re-applied on direct download**
    /// so a selector-excluded package cannot be fetched by guessing its URL
    /// (the caller returns 404, not 403, to avoid leaking existence). An
    /// evaluation error fails closed to [`PackageFilter::DenyAll`].
    pub async fn package_filter(&self, principal: &Principal, repo: &Repository) -> PackageFilter {
        match self.effective(principal).await {
            Ok(eff) => eff.package_filter(repo.id),
            Err(()) => PackageFilter::DenyAll,
        }
    }

    /// Resolve the principal's effective set and test the repo-level gate.
    /// Any error is logged and denied.
    async fn allows(&self, principal: &Principal, action: Action, repo_id: i64) -> bool {
        match self.effective(principal).await {
            Ok(eff) => eff.allows_repo(action, repo_id),
            Err(()) => false,
        }
    }

    /// Resolve the principal's effective [`EffectiveSet`] (cached owner set,
    /// then token-scope intersection). Returns `Err(())` on any failure; the
    /// error has already been logged. The caller maps `Err` to deny.
    async fn effective(&self, principal: &Principal) -> Result<EffectiveSet, ()> {
        match principal {
            Principal::Unauthenticated => Ok(EffectiveSet::empty()),
            Principal::Anonymous { .. } => {
                authz_cache::load_anonymous_effective(&self.pool, &self.cache)
                    .await
                    .map_err(|e| tracing::error!(error = %e, "authz anonymous load failed"))
            }
            Principal::User {
                user_id,
                token_id,
                is_admin,
            } => {
                let owner = authz_cache::load_user_effective(
                    &self.pool,
                    &self.cache,
                    *user_id,
                    *is_admin, // dual-read admin fallback (grant-only)
                )
                .await
                .map_err(|e| tracing::error!(error = %e, user_id, "authz user load failed"))?;

                match token_id {
                    None => Ok(owner),
                    Some(tid) => self.apply_token_scope(owner, *tid).await,
                }
            }
        }
    }

    /// Load and apply a token's `scope`, intersecting it with the owner set.
    ///
    /// The scope is read **outside** the per-user cache (the cache holds the
    /// shared owner set). `NULL` scope ⇒ no narrowing. A malformed scope is
    /// fail-closed: rather than fall back to the owner's full set (which would
    /// silently widen the token), the token is treated as carrying an
    /// **empty-allowlist** scope — it can touch nothing — and the error is logged.
    async fn apply_token_scope(
        &self,
        owner: EffectiveSet,
        token_id: i64,
    ) -> Result<EffectiveSet, ()> {
        let raw = authz_dao::load_token_scope(&self.pool, token_id)
            .await
            .map_err(|e| tracing::error!(error = %e, token_id, "authz token-scope load failed"))?;

        match parse_token_scope(raw) {
            Ok(None) => Ok(owner),
            Ok(Some(scope)) => Ok(owner.intersect_scope(&scope)),
            Err(e) => {
                tracing::error!(error = %e, token_id, "malformed token scope; denying (fail-closed)");
                // Empty allowlists ⇒ intersect to the empty set (grants nothing).
                Ok(owner.intersect_scope(&deny_all_scope()))
            }
        }
    }
}

/// A scope that allows no actions and no repositories — intersecting any owner
/// set with it yields the empty (deny-all) set. Used as the fail-closed fallback
/// for a token whose stored scope is malformed.
fn deny_all_scope() -> TokenScope {
    TokenScope {
        actions: Some(Vec::new()),
        repositories: Some(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(is_admin: bool) -> Principal {
        Principal::User {
            user_id: 42,
            token_id: None,
            is_admin,
        }
    }

    fn anon() -> Principal {
        Principal::Anonymous {
            ip: "127.0.0.1".parse().unwrap(),
        }
    }

    /// A pool that is never actually queried in the pure tests below (they cover
    /// only paths that short-circuit before any DB access).
    fn authz() -> Authz {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://forge:forge@localhost:5433/forge")
            .expect("lazy pool");
        Authz::new(pool, Cache::l1_only(16))
    }

    #[test]
    fn deny_all_scope_is_empty_allowlists() {
        let s = deny_all_scope();
        assert_eq!(s.actions, Some(Vec::new()));
        assert_eq!(s.repositories, Some(Vec::new()));
    }

    #[tokio::test]
    async fn unauthenticated_denies_without_db() {
        // Unauthenticated short-circuits to the empty set: no DB touched, all
        // actions denied. (The lazy pool would panic if queried.)
        let az = authz();
        let eff = az.effective(&Principal::Unauthenticated).await.expect("ok");
        assert!(!eff.allows_repo(Action::Read, 1));
        assert!(!eff.allows_repo(Action::Write, 1));
        assert!(!eff.allows_repo(Action::Admin, 1));
        assert!(!eff.is_admin());
    }

    #[test]
    fn principals_distinguish_user_anon() {
        assert!(user(true).is_user());
        assert!(!anon().is_user());
    }
}
