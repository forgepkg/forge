//! A credential-forwarding realm that no longer forwards: its accounts sign
//! in with the password hashes the realm kept (`captured_password_only`,
//! migration 0035).
//!
//! A realm that keeps password hashes (`capture_password_hash`, see
//! [`super::upstream_basic`]) stores the last password its upstream accepted
//! on each account. Switched to `captured_password_only`, it stops asking the
//! upstream altogether and checks the presented password against that hash
//! instead — the way to keep the realm's accounts signing in while the
//! upstream (e.g. a Nexus) is switched off, before or instead of turning them
//! into local accounts.
//!
//! * The account is the realm's upstream account of the canonical username
//!   (never an orphan of a deleted realm, never a local or OIDC account); its
//!   kept hash is verified with argon2id behind the shared
//!   [`PasswordHashLimiter`].
//! * An unknown name, or an account that keeps no hash, is
//!   [`AuthOutcome::Rejected`] after a verification against a dummy hash, so
//!   the response time does not show which names keep a password. Such an
//!   account cannot sign in through the realm any more.
//! * The verdict goes through the realm's [`ValidatedCredentialCache`] like a
//!   forwarded one, so NuGet's per-request Basic credentials cost one argon2
//!   verification per credential per TTL window, not one per request.
//! * The password is never sent anywhere and no new hash is kept: the hashes
//!   stay what the upstream last accepted.
//! * A failed account lookup or a saturated argon2 limiter is
//!   [`AuthOutcome::Unavailable`] (fail closed, never cached).

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;

use super::cred_cache::{CredCacheError, UpstreamVerdict, ValidatedCredentialCache};
use super::local_password::{LimiterSaturated, PasswordHashLimiter};
use super::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential, ProvenIdentity};

/// A credential-forwarding realm in `captured_password_only` mode, as an
/// [`AuthProvider`] (see the [module docs](self)).
pub struct CapturedPasswordProvider {
    provider_id: String,
    realm_id: i64,
    pool: PgPool,
    cache: ValidatedCredentialCache,
    limiter: Arc<PasswordHashLimiter>,
}

impl CapturedPasswordProvider {
    /// The provider of realm `realm_id`, keyed `provider_id` in the
    /// validated-credential `cache` (the id its forwarding provider had, so
    /// identities and the cache stay the realm's), verifying in the slots of
    /// `limiter`.
    pub fn new(
        provider_id: String,
        realm_id: i64,
        pool: PgPool,
        cache: ValidatedCredentialCache,
        limiter: Arc<PasswordHashLimiter>,
    ) -> Self {
        Self {
            provider_id,
            realm_id,
            pool,
            cache,
            limiter,
        }
    }

    /// Check `password` against the hash the account keeps: the cache factory
    /// body, run on a cache miss only.
    async fn verify(&self, username: &str, password: &str) -> UpstreamVerdict {
        let stored = match forge_db::user_dao::find_captured_password_hash(
            &self.pool,
            username,
            self.realm_id,
        )
        .await
        {
            Ok(stored) => stored,
            Err(e) => {
                tracing::warn!(error = %e, "captured-password: account lookup failed (fail-closed)");
                return UpstreamVerdict::Unavailable;
            }
        };
        let verified = match stored {
            Some(hash) => self.limiter.verify(hash, password.to_string()).await,
            // Costs what a wrong password does.
            None => self.limiter.verify_dummy(password.to_string()).await,
        };
        match verified {
            Ok(true) => UpstreamVerdict::Valid,
            Ok(false) => UpstreamVerdict::Rejected,
            Err(LimiterSaturated) => {
                tracing::warn!(
                    "captured-password: no argon2 slot freed up within the queue timeout"
                );
                UpstreamVerdict::Unavailable
            }
        }
    }
}

#[async_trait]
impl AuthProvider for CapturedPasswordProvider {
    fn id(&self) -> &str {
        &self.provider_id
    }

    /// The realm's accounts stay credential-forwarding accounts: an identity
    /// maps only onto the realm's own upstream account.
    fn source(&self) -> AuthSource {
        AuthSource::UpstreamBasic
    }

    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome {
        let username = cred.username.to_string();
        let password = cred.password.to_string();
        let result = self
            .cache
            .check(self.id(), cred.username, cred.password, || async move {
                self.verify(&username, &password).await
            })
            .await;
        match result {
            Ok(true) => AuthOutcome::Authenticated(ProvenIdentity {
                username: cred.username.to_string(),
                source: AuthSource::UpstreamBasic,
                external_subject: Some(cred.username.to_string()),
                groups: Vec::new(),
                // No upstream answer, so no groups: an existing account's
                // admin state is left alone.
                suggested_is_admin: false,
                admin_authoritative: false,
                // Only an existing account keeps a password.
                auto_provision: false,
                realm_id: Some(self.realm_id),
                captured_password_hash: None,
            }),
            Ok(false) => AuthOutcome::Rejected,
            Err(CredCacheError::Unavailable) => AuthOutcome::Unavailable,
            Err(CredCacheError::Db(e)) => {
                tracing::warn!(error = %e, "captured-password: credential cache store error (fail-closed)");
                AuthOutcome::Failed
            }
        }
    }
}
