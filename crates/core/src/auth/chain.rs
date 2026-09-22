//! The ordered [`AuthProvider`] chain (slice 12.3, phase 1).
//!
//! The chain owns *only* the password-style authentication path. Token auth
//! runs before it (see [`super::token`]). Given a [`PasswordCredential`], the
//! chain walks its providers in configured order and folds their
//! [`AuthOutcome`]s into a single [`ChainOutcome`].
//!
//! ## Semantics (security-critical)
//! 1. Providers run in order; the **first** [`AuthOutcome::Authenticated`] wins
//!    and short-circuits — later providers are not consulted, so a local user
//!    is never forwarded upstream once the local provider accepts.
//! 2. [`AuthOutcome::Skip`] advances to the next provider.
//! 3. [`AuthOutcome::Rejected`] from a **local** provider is **terminal**: the
//!    username belongs to a local account with a password, so a wrong password
//!    is a definitive "no" and is never forwarded to a later (upstream)
//!    provider — otherwise an upstream account sharing the name could vouch for
//!    it, and the local user's typed password would leak upstream. A rejection
//!    from a non-local provider is remembered but does **not** stop the chain
//!    (a username may exist in a later provider). On its own it never grants.
//! 4. [`AuthOutcome::Unavailable`] is remembered but does **not** grant.
//!    **Fail closed:** an unreachable upstream can never open a hole — if no
//!    provider authenticates and an `Unavailable` was seen, the chain reports
//!    [`ChainOutcome::Unavailable`] (distinct from [`ChainOutcome::Rejected`])
//!    so the caller denies and can log/metric the upstream health separately.
//! 5. No provider authenticated and none rejected/was-unavailable (all
//!    [`AuthOutcome::Skip`] or an empty chain) → [`ChainOutcome::NoCredentials`]:
//!    the password path simply had nothing to say, and the caller falls back to
//!    its anonymous-access policy (exactly as slice 1 did when password-basic
//!    was off / the user was unknown).

use std::sync::Arc;

use sqlx::PgPool;

use super::principal::UserPrincipal;
use super::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential, ProvenIdentity};

/// The folded result of running the [`AuthProvider`] chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainOutcome {
    /// A provider authenticated the credential. Carries the vouched-for
    /// identity (for mapping / auto-provision) and the winning provider id.
    Authenticated {
        /// The identity the winning provider vouched for.
        identity: ProvenIdentity,
        /// The `id()` of the provider that authenticated (owned: realm-driven
        /// providers carry per-realm ids, 12.7).
        provider_id: String,
    },
    /// No provider authenticated and at least one definitively **rejected** the
    /// credential. The caller returns 401 (bad credentials), never anonymous.
    Rejected,
    /// No provider authenticated and at least one was **unavailable** (and none
    /// rejected). Fail-closed: the caller denies. Surfaced distinctly from
    /// [`ChainOutcome::Rejected`] so the caller can log/metric upstream health,
    /// but per §12.3 the wire response is still a denial (typically 401 to
    /// avoid leaking upstream health).
    Unavailable,
    /// No provider had anything to say about this credential (all skipped, or
    /// the chain is empty). The caller applies its anonymous-access policy.
    NoCredentials,
}

/// An ordered chain of [`AuthProvider`]s for the password-style auth path.
pub struct Chain {
    providers: Vec<Box<dyn AuthProvider>>,
}

impl Chain {
    /// Build a chain from an ordered list of providers. Order is significant
    /// (see module docs): the first provider to authenticate wins.
    pub fn new(providers: Vec<Box<dyn AuthProvider>>) -> Self {
        Self { providers }
    }

    /// Whether the chain has no providers configured.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// The configured provider ids, in order (for operator visibility / logs).
    pub fn provider_ids(&self) -> Vec<String> {
        self.providers.iter().map(|p| p.id().to_string()).collect()
    }

    /// Run the credential through the chain and fold the outcomes.
    ///
    /// See the module-level docs for the exact ordering / fail-closed
    /// semantics.
    pub async fn authenticate(&self, cred: &PasswordCredential<'_>) -> ChainOutcome {
        let mut saw_rejected = false;
        let mut saw_unavailable = false;

        for provider in &self.providers {
            match provider.authenticate(cred).await {
                AuthOutcome::Authenticated(identity) => {
                    // First acceptance wins; later providers are not consulted.
                    return ChainOutcome::Authenticated {
                        identity,
                        provider_id: provider.id().to_string(),
                    };
                }
                // A local account owns this username: a wrong password is final
                // (never forwarded upstream, see module docs rule 3).
                AuthOutcome::Rejected if provider.source() == AuthSource::Local => {
                    return ChainOutcome::Rejected;
                }
                AuthOutcome::Rejected => saw_rejected = true,
                AuthOutcome::Unavailable => saw_unavailable = true,
                AuthOutcome::Skip => {}
            }
        }

        // No provider authenticated. A definitive rejection outranks an
        // infrastructure outage for the wire verdict (both deny), but an
        // outage that produced *no* rejection must still fail closed — never
        // fall through to NoCredentials (which would let the anon policy grant).
        if saw_rejected {
            ChainOutcome::Rejected
        } else if saw_unavailable {
            ChainOutcome::Unavailable
        } else {
            ChainOutcome::NoCredentials
        }
    }
}

/// Supplies the *current* password-auth [`Chain`] to the Basic source.
///
/// Slice 12.3 built the chain once at startup from static config. With 12.7
/// the realms live in the database and are editable at runtime, so the source
/// asks this seam on every password attempt and the server hands back its
/// (snapshot-cached) realm-built chain. `None` means the password path is
/// disabled entirely (slice-1 `allow_password_basic = false` parity).
#[async_trait::async_trait]
pub trait ChainSource: Send + Sync {
    /// The chain to run a password credential through right now, or `None`
    /// when the password path is disabled.
    async fn password_chain(&self) -> Option<Arc<Chain>>;
}

/// A fixed [`ChainSource`]: the startup-built chain (or a disabled path).
/// Used by tests and any wiring without DB-driven realms.
pub struct StaticChainSource(pub Option<Arc<Chain>>);

#[async_trait::async_trait]
impl ChainSource for StaticChainSource {
    async fn password_chain(&self) -> Option<Arc<Chain>> {
        self.0.clone()
    }
}

/// Map a chain-vouched [`ProvenIdentity`] to a concrete [`UserPrincipal`].
///
/// Providers only vouch for a *username*; this resolves that username to a
/// forge `app_user` (its id and admin flag) so the caller can build a
/// [`super::principal::Principal::User`]. The lookup is **source-bound**:
///
/// * [`AuthSource::Local`] → the `app_user` of that name (the local provider
///   only authenticates an existing, active user with a local password, so this
///   is the same row it verified).
/// * [`AuthSource::UpstreamBasic`] → only an `app_user` whose `auth_source` is
///   `'upstream-basic'` (and, when both are known, of the vouching realm). An
///   upstream realm vouching for a name that belongs to a local or OIDC account
///   must never be mapped onto that account (account takeover by a colliding
///   upstream username).
/// * [`AuthSource::Oidc`] → never produced by the password chain; denied.
///
/// Returns `Ok(None)` when no matching active user exists, `Err` only on a DB
/// failure (the caller must fail closed on `Err`).
pub async fn map_identity_to_principal(
    pool: &PgPool,
    identity: &ProvenIdentity,
) -> sqlx::Result<Option<UserPrincipal>> {
    let user = match identity.source {
        AuthSource::Local => {
            forge_db::user_dao::find_user_by_username(pool, &identity.username).await?
        }
        AuthSource::UpstreamBasic => {
            forge_db::user_dao::find_upstream_user(pool, &identity.username, identity.realm_id)
                .await?
        }
        AuthSource::Oidc => None,
    };
    let Some(user) = user else {
        return Ok(None);
    };
    if !user.active {
        return Ok(None);
    }
    Ok(Some(UserPrincipal {
        user_id: user.id,
        // Password-style auth never carries a token.
        token_id: None,
        is_admin: user.is_admin,
    }))
}

/// Resolve a chain-vouched [`ProvenIdentity`] to a [`UserPrincipal`],
/// **auto-provisioning** an `app_user` when the identity's vouching provider
/// allows it (slice 12.3 phase 5; per-realm since 12.7 — the flag rides on the
/// identity instead of a chain-global setting).
///
/// This is [`map_identity_to_principal`] plus the upstream auto-provision step:
///
/// * [`AuthSource::UpstreamBasic`] with `identity.auto_provision` → upsert the
///   user via [`forge_db::user_dao::provision_upstream_user`] (creates a
///   passwordless `'upstream-basic'` account on first login, recording the
///   vouching realm as `app_user.realm_id`). A same-named **non-upstream**
///   account (local / OIDC / another realm's upstream user) is never taken over:
///   the upsert returns no row and the login is denied. The user is always
///   `active = true` on insert; an operator who later sets `active = false` is
///   honored on the next call.
/// * **Admin tracking** (upstream-basic users only): when the identity's admin
///   reading is authoritative (`admin_authoritative` — the realm maps an admin
///   group and this login fetched the groups), both `app_user.is_admin` and the
///   built-in `admin` role membership follow the upstream verdict, so an upstream
///   demotion takes effect here. Without an authoritative reading (no admin
///   mapping, or a validated-credential cache hit) nothing is changed for an
///   existing user. A role change is picked up by the authz cache within its TTL
///   (callers holding the cache may invalidate sooner).
/// * [`AuthSource::UpstreamBasic`] without `auto_provision` → behave like
///   [`map_identity_to_principal`]: an existing, active upstream-basic user of
///   that name, else `Ok(None)` (caller denies).
/// * [`AuthSource::Local`] / [`AuthSource::Oidc`] → never provisioned here;
///   delegate to [`map_identity_to_principal`].
///
/// Returns `Ok(None)` when no usable principal results (unknown/inactive and not
/// auto-provisioned, or a name owned by another account kind), `Err` only on a
/// DB failure (caller must fail closed).
pub async fn provision_and_map(
    pool: &PgPool,
    identity: &ProvenIdentity,
) -> sqlx::Result<Option<UserPrincipal>> {
    if identity.source == AuthSource::UpstreamBasic && identity.auto_provision {
        let Some(user) = forge_db::user_dao::provision_upstream_user(
            pool,
            &identity.username,
            identity.suggested_is_admin,
            identity.admin_authoritative,
            identity.realm_id,
        )
        .await?
        else {
            // The username belongs to a non-upstream account (or another
            // realm's user): never map or take it over.
            tracing::warn!(
                username = %identity.username,
                "upstream login denied: username is owned by a non-upstream account"
            );
            return Ok(None);
        };
        // A provisioned/refreshed user could have been deactivated by an operator
        // between logins; honor that (the upsert does not reactivate).
        if !user.active {
            return Ok(None);
        }
        // §12.4 Phase 5: on a legacy-open-access (upgraded slice-1) install, an
        // auto-provisioned upstream-basic user must inherit the `authenticated`
        // role immediately so it keeps the slice-1 "read/write everywhere"
        // behavior — `ensure_legacy_rbac` only runs at boot. The upsert is
        // idempotent, so a re-login of an already-provisioned user is a no-op on a
        // closed install (flag false) it does nothing. No cache invalidation is
        // needed: a re-resolve happens before the next authz lookup.
        forge_db::authz_dao::assign_authenticated_if_legacy_open(pool, user.id).await?;
        if identity.admin_authoritative {
            // Keep the RBAC admin role in step with the (authoritative) upstream
            // verdict so a demotion does not leave a stale role behind.
            forge_db::authz_dao::sync_admin_role(pool, user.id, user.is_admin).await?;
        }
        return Ok(Some(UserPrincipal {
            user_id: user.id,
            token_id: None,
            is_admin: user.is_admin,
        }));
    }

    map_identity_to_principal(pool, identity).await
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::auth::provider::AuthSource;

    /// A stub provider returning a fixed outcome and counting its calls.
    struct StubProvider {
        id: &'static str,
        source: AuthSource,
        outcome: AuthOutcome,
        calls: Arc<AtomicUsize>,
    }

    impl StubProvider {
        fn new(
            id: &'static str,
            source: AuthSource,
            outcome: AuthOutcome,
        ) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    id,
                    source,
                    outcome,
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    #[async_trait::async_trait]
    impl AuthProvider for StubProvider {
        fn id(&self) -> &str {
            self.id
        }
        fn source(&self) -> AuthSource {
            self.source
        }
        async fn authenticate(&self, _cred: &PasswordCredential<'_>) -> AuthOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.clone()
        }
    }

    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    fn cred<'a>(username: &'a str, password: &'a str) -> PasswordCredential<'a> {
        PasswordCredential {
            username,
            password,
            client_ip: ip(),
        }
    }

    fn authed(username: &str, source: AuthSource) -> AuthOutcome {
        AuthOutcome::Authenticated(ProvenIdentity {
            username: username.to_string(),
            source,
            external_subject: None,
            groups: Vec::new(),
            suggested_is_admin: false,
            admin_authoritative: false,
            auto_provision: false,
            realm_id: None,
        })
    }

    #[tokio::test]
    async fn empty_chain_is_no_credentials() {
        let chain = Chain::new(vec![]);
        assert_eq!(
            chain.authenticate(&cred("alice", "pw")).await,
            ChainOutcome::NoCredentials
        );
    }

    #[tokio::test]
    async fn first_authenticated_wins_and_short_circuits() {
        let (p1, c1) = StubProvider::new(
            "local-password",
            AuthSource::Local,
            authed("alice", AuthSource::Local),
        );
        let (p2, c2) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            authed("alice", AuthSource::UpstreamBasic),
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);

        let out = chain.authenticate(&cred("alice", "pw")).await;
        match out {
            ChainOutcome::Authenticated {
                identity,
                provider_id,
            } => {
                assert_eq!(provider_id, "local-password");
                assert_eq!(identity.source, AuthSource::Local);
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
        // The first provider won; the second must never have been consulted.
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ordering_is_significant() {
        // Reversed order: upstream is tried first and wins.
        let (p_local, _) = StubProvider::new(
            "local-password",
            AuthSource::Local,
            authed("alice", AuthSource::Local),
        );
        let (p_up, _) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            authed("alice", AuthSource::UpstreamBasic),
        );
        let chain = Chain::new(vec![Box::new(p_up), Box::new(p_local)]);

        match chain.authenticate(&cred("alice", "pw")).await {
            ChainOutcome::Authenticated { provider_id, .. } => {
                assert_eq!(provider_id, "upstream-basic");
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn skip_advances_to_next_provider() {
        let (p1, c1) = StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Skip);
        let (p2, c2) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            authed("bob", AuthSource::UpstreamBasic),
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);

        match chain.authenticate(&cred("bob", "pw")).await {
            ChainOutcome::Authenticated { provider_id, .. } => {
                assert_eq!(provider_id, "upstream-basic");
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn all_skip_is_no_credentials() {
        let (p1, _) = StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Skip);
        let (p2, _) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            AuthOutcome::Skip,
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);
        assert_eq!(
            chain.authenticate(&cred("nobody", "pw")).await,
            ChainOutcome::NoCredentials
        );
    }

    #[tokio::test]
    async fn rejected_with_no_auth_is_rejected() {
        let (p1, _) = StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Rejected);
        let chain = Chain::new(vec![Box::new(p1)]);
        assert_eq!(
            chain.authenticate(&cred("alice", "wrong")).await,
            ChainOutcome::Rejected
        );
    }

    #[tokio::test]
    async fn local_rejection_is_terminal_and_never_forwarded() {
        // A local user with a password presents a wrong one: the chain must stop
        // right there — the password is never forwarded to the upstream, which
        // could otherwise vouch for the same username (account takeover).
        let (p1, c1) =
            StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Rejected);
        let (p2, c2) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            authed("alice", AuthSource::UpstreamBasic),
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);

        assert_eq!(
            chain.authenticate(&cred("alice", "pw")).await,
            ChainOutcome::Rejected
        );
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 0, "upstream never consulted");
    }

    #[tokio::test]
    async fn upstream_rejection_does_not_stop_chain_later_authenticated_wins() {
        // A non-local rejection is not terminal: a later realm may own the user.
        let (p1, c1) = StubProvider::new(
            "realm:first",
            AuthSource::UpstreamBasic,
            AuthOutcome::Rejected,
        );
        let (p2, c2) = StubProvider::new(
            "realm:second",
            AuthSource::UpstreamBasic,
            authed("alice", AuthSource::UpstreamBasic),
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);

        match chain.authenticate(&cred("alice", "pw")).await {
            ChainOutcome::Authenticated { provider_id, .. } => {
                assert_eq!(provider_id, "realm:second");
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn local_skip_still_reaches_upstream() {
        // Unknown locally (Skip) → the upstream may still authenticate.
        let (p1, _) = StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Skip);
        let (p2, c2) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            authed("carol", AuthSource::UpstreamBasic),
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);
        assert!(matches!(
            chain.authenticate(&cred("carol", "pw")).await,
            ChainOutcome::Authenticated { .. }
        ));
        assert_eq!(c2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn oidc_identity_is_never_mapped_by_the_password_chain() {
        // The password chain never produces OIDC identities; mapping one must
        // deny without touching the DB (the lazy pool would fail if queried).
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://forge:forge@localhost:1/forge")
            .expect("lazy pool");
        let mut id = ProvenIdentity::local("alice");
        id.source = AuthSource::Oidc;
        assert_eq!(map_identity_to_principal(&pool, &id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn unavailable_alone_fails_closed_not_no_credentials() {
        // The ONLY provider is unavailable: must NOT become NoCredentials (which
        // could let the anon policy grant). Fail closed → Unavailable.
        let (p1, _) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            AuthOutcome::Unavailable,
        );
        let chain = Chain::new(vec![Box::new(p1)]);
        assert_eq!(
            chain.authenticate(&cred("alice", "pw")).await,
            ChainOutcome::Unavailable
        );
    }

    #[tokio::test]
    async fn skip_then_unavailable_fails_closed() {
        let (p1, _) = StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Skip);
        let (p2, _) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            AuthOutcome::Unavailable,
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);
        assert_eq!(
            chain.authenticate(&cred("alice", "pw")).await,
            ChainOutcome::Unavailable
        );
    }

    #[tokio::test]
    async fn rejected_outranks_unavailable_for_verdict() {
        // A definitive upstream rejection plus another realm's outage →
        // Rejected (both deny on the wire; rejection is the more specific
        // verdict).
        let (p1, _) = StubProvider::new(
            "realm:first",
            AuthSource::UpstreamBasic,
            AuthOutcome::Rejected,
        );
        let (p2, _) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            AuthOutcome::Unavailable,
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);
        assert_eq!(
            chain.authenticate(&cred("alice", "pw")).await,
            ChainOutcome::Rejected
        );
    }

    #[tokio::test]
    async fn authenticated_before_unavailable_short_circuits() {
        // Acceptance wins even though a later provider would be unavailable —
        // and the unavailable provider is never even consulted.
        let (p1, c1) = StubProvider::new(
            "local-password",
            AuthSource::Local,
            authed("alice", AuthSource::Local),
        );
        let (p2, c2) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            AuthOutcome::Unavailable,
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);

        assert!(matches!(
            chain.authenticate(&cred("alice", "pw")).await,
            ChainOutcome::Authenticated { .. }
        ));
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn provider_ids_reports_order() {
        let (p1, _) = StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Skip);
        let (p2, _) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            AuthOutcome::Skip,
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);
        assert_eq!(
            chain.provider_ids(),
            vec!["local-password".to_string(), "upstream-basic".to_string()]
        );
        assert!(!chain.is_empty());
    }
}
