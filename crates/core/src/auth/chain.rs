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
//! 3. [`AuthOutcome::Rejected`] is remembered but does **not** stop the chain
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
        /// The `id()` of the provider that authenticated.
        provider_id: &'static str,
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
    pub fn provider_ids(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.id()).collect()
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
                        provider_id: provider.id(),
                    };
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

/// Map a chain-vouched [`ProvenIdentity`] to a concrete [`UserPrincipal`].
///
/// Providers only vouch for a *username*; this resolves that username to a
/// forge `app_user` (its id and admin flag) so the caller can build a
/// [`super::principal::Principal::User`].
///
/// **Phase 2 (this slice) scope:** the user must already exist and be active.
/// Auto-provisioning of upstream-vouched users that don't yet have an
/// `app_user` row is phase 5 (it runs in a `db` transaction with provenance);
/// here a vouched-for identity with no matching active row resolves to `None`
/// so the caller denies. For the `local-password` provider this can never
/// happen — it only authenticates an existing, active user — so this is a
/// behaviour-preserving lookup for slice 1.
///
/// Returns `Ok(None)` when no matching active user exists, `Err` only on a DB
/// failure (the caller must fail closed on `Err`).
pub async fn map_identity_to_principal(
    pool: &PgPool,
    identity: &ProvenIdentity,
) -> sqlx::Result<Option<UserPrincipal>> {
    let Some(user) = forge_db::user_dao::find_user_by_username(pool, &identity.username).await?
    else {
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
/// **auto-provisioning** an `app_user` when the source allows it (slice 12.3,
/// phase 5).
///
/// This is [`map_identity_to_principal`] plus the upstream auto-provision step:
///
/// * [`AuthSource::UpstreamBasic`] with `auto_provision = true` → upsert the
///   user via [`forge_db::user_dao::provision_upstream_user`] (creates a
///   passwordless `'upstream-basic'` account on first login, grants admin if the
///   identity's `suggested_is_admin` is set, never downgrades a local account)
///   and return its principal. The user is always `active = true` on insert; an
///   operator who later sets `active = false` is honored on the next call.
/// * [`AuthSource::UpstreamBasic`] with `auto_provision = false` → behave like
///   [`map_identity_to_principal`]: the user must already exist and be active,
///   else `Ok(None)` (caller denies).
/// * [`AuthSource::Local`] / [`AuthSource::Oidc`] → never provisioned here;
///   delegate to [`map_identity_to_principal`] (a behaviour-preserving lookup —
///   local users always pre-exist, OIDC has its own interactive provision path).
///
/// Returns `Ok(None)` when no usable principal results (unknown/inactive and not
/// auto-provisioned), `Err` only on a DB failure (caller must fail closed).
pub async fn provision_and_map(
    pool: &PgPool,
    identity: &ProvenIdentity,
    auto_provision: bool,
) -> sqlx::Result<Option<UserPrincipal>> {
    if identity.source == AuthSource::UpstreamBasic && auto_provision {
        let user = forge_db::user_dao::provision_upstream_user(
            pool,
            &identity.username,
            identity.suggested_is_admin,
        )
        .await?;
        // A provisioned/refreshed user could have been deactivated by an operator
        // between logins; honor that (the upsert does not reactivate).
        if !user.active {
            return Ok(None);
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
        fn id(&self) -> &'static str {
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
    async fn rejected_does_not_stop_chain_later_authenticated_wins() {
        // local rejects (wrong local pw), upstream accepts → user is upstream.
        let (p1, c1) =
            StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Rejected);
        let (p2, c2) = StubProvider::new(
            "upstream-basic",
            AuthSource::UpstreamBasic,
            authed("alice", AuthSource::UpstreamBasic),
        );
        let chain = Chain::new(vec![Box::new(p1), Box::new(p2)]);

        match chain.authenticate(&cred("alice", "pw")).await {
            ChainOutcome::Authenticated { provider_id, .. } => {
                assert_eq!(provider_id, "upstream-basic");
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 1);
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
        // A definitive local rejection plus an upstream outage → Rejected
        // (both deny on the wire; rejection is the more specific verdict).
        let (p1, _) = StubProvider::new("local-password", AuthSource::Local, AuthOutcome::Rejected);
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
            vec!["local-password", "upstream-basic"]
        );
        assert!(!chain.is_empty());
    }
}
