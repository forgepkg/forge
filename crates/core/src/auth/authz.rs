//! Authorization seam (§12.4: the single fine-grained-RBAC decision point).
//!
//! ## The seam
//! Authorization is decided by the [`Authz`] service. It owns the data handles a
//! fine-grained policy needs — a [`PgPool`] (authoritative privilege data) and a
//! [`Cache`] (the resolved effective-permission set, with cross-node
//! invalidation) — and exposes the three predicates the whole codebase routes
//! through:
//!
//! * [`Authz::can_read`] — download / list / search.
//! * [`Authz::can_write`] — push / delete / relist.
//! * [`Authz::can_admin`] — repository config + privilege management.
//!
//! Every gate (request dispatch in `server::dispatch`, the browse read endpoints,
//! the admin `require_admin` middleware, and identity-aware group resolution in
//! `core::repo::group`) calls these methods. Keeping them on one service is what
//! lets §12.4 swap the coarse bodies for the cached RBAC evaluator **without
//! touching any call site**.
//!
//! ## Current behavior (coarse, unchanged from Slice 1)
//! Phase 0 of §12.4 introduces the service but keeps the decision logic identical
//! to Slice 1 — the `pool`/`cache` handles are wired but not yet consulted. The
//! rules are:
//! * **read**  — any authenticated `User`, **or** an `Anonymous` caller when
//!   `repository.anonymous_read` is set.
//! * **write** (push / delete / relist) — any authenticated `User`. Never
//!   anonymous.
//! * **admin** — a `User` with `is_admin`.
//!
//! The pure coarse rules live in the free functions [`coarse_can_read`] /
//! [`coarse_can_write`] / [`coarse_can_admin`] so they stay unit-testable in
//! isolation; the [`Authz`] methods delegate to them today and will grow a cached
//! DB-backed evaluator in later phases.

use forge_cache::Cache;
use forge_db::model::Repository;
use sqlx::PgPool;

use super::principal::Principal;

/// The authorization decision service (§12.4 seam).
///
/// Cheaply cloneable: the [`PgPool`] and [`Cache`] inside are both `Arc`-backed.
/// Constructed once during server wiring and held in app state / threaded into
/// `core` operations (e.g. group resolution) that need to make decisions.
#[derive(Clone)]
pub struct Authz {
    // Held for the fine-grained evaluator added in later §12.4 phases. The coarse
    // Phase-0 logic does not read them yet, but wiring them now keeps the public
    // constructor stable across the slice.
    #[allow(dead_code)]
    pool: PgPool,
    #[allow(dead_code)]
    cache: Cache,
}

impl Authz {
    /// Build the service from the shared DB pool and cache.
    pub fn new(pool: PgPool, cache: Cache) -> Self {
        Authz { pool, cache }
    }

    /// May `principal` read (download / list / search) `repo`?
    pub async fn can_read(&self, principal: &Principal, repo: &Repository) -> bool {
        coarse_can_read(principal, repo)
    }

    /// May `principal` write (push / delete / relist) to `repo`?
    ///
    /// Writing always requires an authenticated user; anonymous callers can never
    /// write, regardless of `anonymous_read`.
    pub async fn can_write(&self, principal: &Principal, repo: &Repository) -> bool {
        coarse_can_write(principal, repo)
    }

    /// May `principal` perform admin operations on `repo`?
    ///
    /// Requires an authenticated user with the admin flag.
    pub async fn can_admin(&self, principal: &Principal, repo: &Repository) -> bool {
        coarse_can_admin(principal, repo)
    }
}

/// Coarse Slice-1 read rule (pure). See module docs.
fn coarse_can_read(principal: &Principal, repo: &Repository) -> bool {
    match principal {
        Principal::User { .. } => true,
        Principal::Anonymous { .. } => repo.anonymous_read,
        Principal::Unauthenticated => false,
    }
}

/// Coarse Slice-1 write rule (pure). See module docs.
fn coarse_can_write(principal: &Principal, _repo: &Repository) -> bool {
    matches!(principal, Principal::User { .. })
}

/// Coarse Slice-1 admin rule (pure). See module docs.
fn coarse_can_admin(principal: &Principal, _repo: &Repository) -> bool {
    matches!(principal, Principal::User { is_admin: true, .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    /// Build a minimal [`Repository`] with the given `anonymous_read` flag.
    fn repo(anonymous_read: bool) -> Repository {
        Repository {
            id: 1,
            name: "nuget-hosted".into(),
            format: "nuget".into(),
            kind: "hosted".into(),
            anonymous_read,
            online: true,
            config: json!({}),
            remote_url: None,
            package_delay_seconds: 0,
            upstream_username: None,
            upstream_password: None,
            allow_private_upstream: false,
            metadata_ttl_seconds: None,
            not_found_ttl_seconds: None,
            allow_redeploy: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn user(is_admin: bool) -> Principal {
        Principal::User {
            user_id: 42,
            token_id: Some(7),
            is_admin,
        }
    }

    fn anon() -> Principal {
        Principal::Anonymous {
            ip: "127.0.0.1".parse().unwrap(),
        }
    }

    /// Build an [`Authz`] backed by an L1-only cache and a lazily-connected pool.
    ///
    /// The Phase-0 coarse logic never touches the pool, so a pool created with
    /// `PgPool::connect_lazy` (no live server) is sufficient and keeps these unit
    /// tests free of a database dependency.
    fn authz() -> Authz {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://forge:forge@localhost:5433/forge")
            .expect("lazy pool");
        Authz::new(pool, Cache::l1_only(16))
    }

    #[tokio::test]
    async fn authz_matrix() {
        let az = authz();
        // (label, principal, anonymous_read, want_read, want_write, want_admin)
        let cases: &[(&str, Principal, bool, bool, bool, bool)] = &[
            (
                "admin user, anon_read off",
                user(true),
                false,
                true,
                true,
                true,
            ),
            (
                "admin user, anon_read on",
                user(true),
                true,
                true,
                true,
                true,
            ),
            (
                "plain user, anon_read off",
                user(false),
                false,
                true,
                true,
                false,
            ),
            (
                "plain user, anon_read on",
                user(false),
                true,
                true,
                true,
                false,
            ),
            ("anon, anon_read on", anon(), true, true, false, false),
            ("anon, anon_read off", anon(), false, false, false, false),
            (
                "unauthenticated, anon_read on",
                Principal::Unauthenticated,
                true,
                false,
                false,
                false,
            ),
            (
                "unauthenticated, anon_read off",
                Principal::Unauthenticated,
                false,
                false,
                false,
                false,
            ),
        ];

        for (label, p, anon_read, want_read, want_write, want_admin) in cases {
            let r = repo(*anon_read);
            assert_eq!(az.can_read(p, &r).await, *want_read, "read: {label}");
            assert_eq!(az.can_write(p, &r).await, *want_write, "write: {label}");
            assert_eq!(az.can_admin(p, &r).await, *want_admin, "admin: {label}");
        }
    }
}
