//! Authorization seam (§12.4: the single fine-grained-RBAC decision point).
//!
//! ## The seam
//! Authorization is decided by the [`Authz`] service. It owns the data handles a
//! fine-grained policy needs — a [`PgPool`] (authoritative privilege data) and a
//! [`Cache`] (the resolved effective-permission set, with cross-node
//! invalidation) — and exposes the predicates the whole codebase routes through:
//!
//! * [`Authz::can_read`] — download / list / search.
//! * [`Authz::can_write`] — push / relist.
//! * [`Authz::can_delete`] — unlist / delete.
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
//!   ([`crate::authz::cache`]). Membership in the built-in `admin` role makes it
//!   an admin.
//! * **Anonymous** — exactly the built-in `anonymous` role's grants (cached under
//!   one shared key). On an un-migrated install that role has no grants ⇒ deny.
//! * **Public read** — for `read` (the [`Authz::can_read`] gate and the read
//!   package filter) every principal additionally holds the anonymous reach:
//!   the `anonymous` role's `read` grants and the repository's
//!   `anonymous_read` flag. Signing in therefore never loses access an
//!   anonymous caller would have. This is added to the owner set *before* any
//!   token scope is applied, so it is still cut down to the token's scope.
//! * **Token-scoped** — when the principal carries a `token_id`, the token's
//!   optional `scope` is loaded (outside the per-user cache) and **intersected**
//!   with the owner's effective set *after* the cache lookup. A token can only
//!   narrow, never widen, and it holds `admin` only when its scope lists the
//!   `admin` action explicitly; an unscoped token (`NULL` scope) is evaluated
//!   as the default scope, i.e. the owner's set without `admin`. See
//!   [`EffectiveSet::intersect_scope`].
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
    /// Whether authenticated principals also hold the public read reach (see
    /// [`Self::can_read`]). Off unless the server reads anonymously for
    /// everyone (`anonymous_mode = "all"`).
    public_read_for_signed_in: bool,
}

impl Authz {
    /// Build the service from the shared DB pool and cache. Authenticated
    /// principals hold only their own grants until
    /// [`Self::with_public_read_for_signed_in`] says otherwise.
    pub fn new(pool: PgPool, cache: Cache) -> Self {
        Authz {
            pool,
            cache,
            public_read_for_signed_in: false,
        }
    }

    /// Give authenticated principals the public read reach as well. The server
    /// enables this only for `anonymous_mode = "all"`, where anyone may read
    /// those repositories anyway. Under `off` the reach is inert for everyone,
    /// and under `allowlist` it depends on the caller's address and `Host`,
    /// which authorization does not see — granting it there would let a
    /// signed-in user (or their token, or a workload) read from anywhere what
    /// only allowlisted networks may read anonymously.
    pub fn with_public_read_for_signed_in(mut self, enabled: bool) -> Self {
        self.public_read_for_signed_in = enabled;
        self
    }

    /// May `principal` read (download / list / search) `repo`?
    ///
    /// `repo.anonymous_read` is a first-class toggle (exposed by the admin
    /// API/UI and honored independently of RBAC grants): when set, the anonymous
    /// principal may read the repo. This preserves slice-1 semantics for repos
    /// created with `anonymous_read = true` even on a fresh, default-deny RBAC
    /// install. RBAC grants are still consulted for everything else.
    ///
    /// With [`Self::with_public_read_for_signed_in`] (`anonymous_mode = "all"`),
    /// authenticated principals (users, tokens, workloads) hold the same public
    /// reach — the flag and the `anonymous` role's `read` grants — on top of
    /// their own grants, so a signed-in user without grants is not denied a repo
    /// any anonymous caller may read. For a token this is still intersected
    /// with the token's scope.
    ///
    /// Fail-closed: an evaluation error logs and denies.
    pub async fn can_read(&self, principal: &Principal, repo: &Repository) -> bool {
        match self.read_effective(principal, repo).await {
            Ok(eff) => eff.allows_repo(Action::Read, repo.id),
            Err(()) => false,
        }
    }

    /// May `principal` write (push / relist) to `repo`?
    ///
    /// Writing always requires a held `write` grant; anonymous callers can only
    /// write if the `anonymous` role was explicitly granted `write` (it is not,
    /// by default). Fail-closed.
    pub async fn can_write(&self, principal: &Principal, repo: &Repository) -> bool {
        self.allows(principal, Action::Write, repo.id).await
    }

    /// May `principal` delete / unlist a package from `repo`?
    ///
    /// Delete is deliberately distinct from write so a publisher can be
    /// allowed to add and relist packages without being able to remove them.
    pub async fn can_delete(&self, principal: &Principal, repo: &Repository) -> bool {
        self.allows(principal, Action::Delete, repo.id).await
    }

    /// May `principal` perform admin operations on `repo`?
    ///
    /// Admin is the `admin`-role short-circuit; a per-repo `admin` grant also
    /// satisfies it. Fail-closed.
    pub async fn can_admin(&self, principal: &Principal, repo: &Repository) -> bool {
        self.allows(principal, Action::Admin, repo.id).await
    }

    /// Is `principal` a **global admin** — i.e. a member of the built-in `admin`
    /// role?
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

    /// May `principal` write (publish) to **every** repository, ones created
    /// later included, with no package scope? True for the `admin` role and
    /// for an unscoped `write` grant on ANY repository, such as the built-in
    /// `writer` role's; a token scope narrows it like every other check.
    /// Fail-closed.
    pub async fn can_write_every_repository(&self, principal: &Principal) -> bool {
        match self.effective(principal).await {
            Ok(eff) => eff.allows_every_repo(Action::Write),
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
        self.package_filter_for(principal, repo, Action::Read).await
    }

    /// The package predicate for a specific action on `repo`.
    ///
    /// The repo-level gate and package-level predicate intentionally remain
    /// separate: a selector-scoped grant reaches the repository, but only a
    /// matching canonical package id reaches an identifier-addressed read or
    /// mutation. Evaluation errors return deny-all.
    pub async fn package_filter_for(
        &self,
        principal: &Principal,
        repo: &Repository,
        action: Action,
    ) -> PackageFilter {
        // Reads use the same set as `can_read` (own grants + public reach,
        // then the token scope): `anonymous_read` grants full package
        // visibility; without it, an anon-readable repo's gate would pass but
        // every package would be filtered out on a default-deny RBAC install.
        let eff = if action == Action::Read {
            self.read_effective(principal, repo).await
        } else {
            self.effective(principal).await
        };
        match eff {
            Ok(eff) => eff.package_filter_for(action, repo.id),
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
        self.effective_with(principal, None).await
    }

    /// The effective set for **reading** `repo`: the principal's own set plus
    /// the public read reach (the `anonymous` role's `read` grants and
    /// `repo.anonymous_read`), with any token scope applied *after* the union
    /// so a token can never read beyond its scope.
    async fn read_effective(
        &self,
        principal: &Principal,
        repo: &Repository,
    ) -> Result<EffectiveSet, ()> {
        let flag = repo.anonymous_read.then_some(repo.id);
        self.effective_with(principal, Some(flag)).await
    }

    /// The anonymous role's effective set (cached under one shared key).
    async fn anonymous_set(&self) -> Result<EffectiveSet, ()> {
        authz_cache::load_anonymous_effective(&self.pool, &self.cache)
            .await
            .map_err(|e| tracing::error!(error = %e, "authz anonymous load failed"))
    }

    /// Add the public read reach to an authenticated principal's own set. A
    /// failed anonymous-set load only drops that extra reach (logged), it never
    /// grants: the principal keeps exactly its own grants.
    async fn add_public_read(
        &self,
        own: EffectiveSet,
        anonymous_read_repo: Option<i64>,
    ) -> EffectiveSet {
        match self.anonymous_set().await {
            Ok(public) => own.with_public_read(&public, anonymous_read_repo),
            Err(()) => own.with_public_read(&EffectiveSet::empty(), anonymous_read_repo),
        }
    }

    /// Shared body of [`Self::effective`] / [`Self::read_effective`]. With
    /// `public_read = Some(flag)` the public read reach is added (`flag` is the
    /// repository id when its `anonymous_read` is set), before any token scope.
    async fn effective_with(
        &self,
        principal: &Principal,
        public_read: Option<Option<i64>>,
    ) -> Result<EffectiveSet, ()> {
        match principal {
            Principal::Unauthenticated => Ok(EffectiveSet::empty()),
            Principal::Anonymous { .. } => {
                let anon = self.anonymous_set().await?;
                Ok(match public_read {
                    Some(flag) => anon.with_public_read(&EffectiveSet::empty(), flag),
                    None => anon,
                })
            }
            Principal::User {
                user_id, token_id, ..
            } => {
                let mut owner = authz_cache::load_user_effective(&self.pool, &self.cache, *user_id)
                    .await
                    .map_err(|e| tracing::error!(error = %e, user_id, "authz user load failed"))?;
                if let Some(flag) = public_read.filter(|_| self.public_read_for_signed_in) {
                    owner = self.add_public_read(owner, flag).await;
                }

                match token_id {
                    None => Ok(owner),
                    Some(tid) => self.apply_token_scope(owner, *tid).await,
                }
            }
            // WIF (slice 12.8): a workload is authorized purely by the single
            // forge role its realm's claim-rules mapped it to (plus, for reads,
            // the public reach every principal holds). No `app_user`, no token
            // scope — a deleted role resolves to deny-all.
            Principal::Workload { role_id, .. } => {
                let role = authz_cache::load_role_effective(&self.pool, &self.cache, *role_id)
                    .await
                    .map_err(
                        |e| tracing::error!(error = %e, role_id, "authz workload role load failed"),
                    )?;
                Ok(
                    match public_read.filter(|_| self.public_read_for_signed_in) {
                        Some(flag) => self.add_public_read(role, flag).await,
                        None => role,
                    },
                )
            }
        }
    }

    /// Load and apply a token's `scope`, intersecting it with the owner set.
    ///
    /// The scope is read **outside** the per-user cache (the cache holds the
    /// shared owner set). `NULL` scope ⇒ the default scope: the owner's
    /// `read` / `write` / `delete` reach, never `admin` (B4: an API token is not
    /// an admin credential unless its scope names `admin`). A malformed scope is
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
            Ok(None) => Ok(owner.intersect_scope(&TokenScope::default())),
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

    fn user() -> Principal {
        Principal::User {
            user_id: 42,
            token_id: None,
            method: crate::auth::AuthMethod::Password,
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
        assert!(user().is_user());
        assert!(!anon().is_user());
    }
}
