//! The reject-only guard of a credential-forwarding realm in the clients'
//! password chain (#756).
//!
//! A credential-forwarding realm that accepts no passwords from clients
//! (`accept_client_passwords: false`) does not check them there, but its
//! accounts' names stay its own: [`ForwardingRealmGuard`] takes its place in
//! that chain and refuses a name the realm owns
//! ([`forge_db::user_dao::find_upstream_user`] of that realm) as
//! [`AuthOutcome::NotAccepted`], which ends the chain. The password then
//! never reaches the upstream of a credential-forwarding realm behind it, as
//! a closed local realm's passwords never do
//! ([`super::LocalPasswordProvider::reject_only`]). A name the realm does not
//! own goes on to the next provider.

use sqlx::PgPool;

use super::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential};

/// Refuses, without checking any password, the names of the accounts of one
/// credential-forwarding realm; skips every other name. Asks no upstream.
pub struct ForwardingRealmGuard {
    id: String,
    realm_id: i64,
    pool: PgPool,
}

impl ForwardingRealmGuard {
    /// The guard of realm `realm_id`; `id` is the realm's provider id
    /// (`realm:<name>`), for the logs and the sign-in metrics.
    pub fn new(id: impl Into<String>, realm_id: i64, pool: PgPool) -> Self {
        Self {
            id: id.into(),
            realm_id,
            pool,
        }
    }
}

#[async_trait::async_trait]
impl AuthProvider for ForwardingRealmGuard {
    fn id(&self) -> &str {
        &self.id
    }

    fn source(&self) -> AuthSource {
        AuthSource::UpstreamBasic
    }

    /// An account of the realm, active or not: `NotAccepted`. Any other name:
    /// `Skip`. A failed lookup: `Failed`, so the password is not forwarded
    /// to the next realm either.
    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome {
        match forge_db::user_dao::find_upstream_user(&self.pool, cred.username, Some(self.realm_id))
            .await
        {
            Ok(Some(_)) => AuthOutcome::NotAccepted,
            Ok(None) => AuthOutcome::Skip,
            Err(e) => {
                tracing::warn!(provider = %self.id, error = %e, "forwarding realm guard: user lookup failed");
                AuthOutcome::Failed
            }
        }
    }
}
