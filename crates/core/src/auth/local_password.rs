//! The `local-password` [`AuthProvider`] (slice 12.3, phase 2).
//!
//! This is the refactor of slice 1's password-basic path
//! ([`super::token::verify_password`]) into the pluggable [`AuthProvider`]
//! chain. Its behaviour is **byte-for-byte** the slice-1 logic:
//!
//! * Look up the user by username.
//! * An inactive user, an unknown user, or a user without a local
//!   `password_hash` (i.e. an `upstream-basic` / `oidc` provisioned account)
//!   can never authenticate here — they are [`AuthOutcome::Skip`] ("not my
//!   user"), so a later provider may still accept them.
//! * argon2id PHC verification runs on a blocking thread (CPU-bound).
//! * A present-but-wrong password is [`AuthOutcome::Rejected`].
//! * A correct password yields [`AuthOutcome::Authenticated`] with a
//!   [`ProvenIdentity::local`].
//!
//! The provider only *vouches for* the username; mapping that identity back to
//! a concrete [`UserPrincipal`] (user id, admin flag) is the chain caller's job
//! (see [`super::chain`] mapping helpers). This keeps providers free of the
//! `UserPrincipal` shape and lets §12.4 reshape authz without touching them.
//!
//! ## Skip vs Rejected — why it matters for the chain
//! Slice 1's [`super::token::verify_password`] returned `None` for *both*
//! "unknown user" and "wrong password". In the chain those must differ:
//! * unknown / no-local-hash / inactive → **Skip** (a later provider, e.g.
//!   `upstream-basic`, may own this username);
//! * known local user, wrong password → **Rejected** (definitive "no", but the
//!   chain still consults later providers in case the user is *also* upstream).
//!
//! When the chain is just `["local-password"]` this distinction is invisible on
//! the wire: both `Skip` (→ `NoCredentials` → anon policy) and `Rejected`
//! (→ 401) reproduce slice-1 behaviour, because slice 1's `BasicAuthSource`
//! turned a `None` password verify into `SourceOutcome::Invalid` only when the
//! basic header was present (creds were attempted), which is exactly what the
//! refactored `BasicAuthSource` still does. See the phase-2 tests.

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use sqlx::PgPool;

use super::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential, ProvenIdentity};

/// Slice-1 local argon2id password authentication, as an [`AuthProvider`].
pub struct LocalPasswordProvider {
    pool: PgPool,
}

impl LocalPasswordProvider {
    /// The stable provider id (matches the config chain spelling).
    pub const ID: &'static str = "local-password";

    /// Build the provider over the given pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AuthProvider for LocalPasswordProvider {
    fn id(&self) -> &str {
        Self::ID
    }

    fn source(&self) -> AuthSource {
        AuthSource::Local
    }

    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome {
        let user = match forge_db::user_dao::find_user_by_username(&self.pool, cred.username).await
        {
            Ok(Some(u)) => u,
            // Unknown user → not ours; a later provider may own this username.
            Ok(None) => return AuthOutcome::Skip,
            Err(e) => {
                // A DB error is an infrastructure failure: fail closed, never
                // grant — but let the chain decide the wire verdict.
                tracing::warn!(error = %e, "local-password user lookup failed");
                return AuthOutcome::Unavailable;
            }
        };

        // Inactive users never authenticate locally. Slice 1 returned `None`
        // here; in the chain this is Skip (the account exists but isn't ours to
        // accept — and an inactive user shouldn't be forwarded upstream either,
        // but that is the upstream provider's own active-check concern).
        if !user.active {
            return AuthOutcome::Skip;
        }

        // Users with no local password (auth_source upstream-basic / oidc) can
        // never authenticate via the local store — this username is not ours.
        let Some(stored) = user.password_hash.clone() else {
            return AuthOutcome::Skip;
        };

        let candidate = cred.password.to_string();
        let verified = tokio::task::spawn_blocking(move || {
            let parsed = match PasswordHash::new(&stored) {
                Ok(p) => p,
                Err(_) => return false,
            };
            Argon2::default()
                .verify_password(candidate.as_bytes(), &parsed)
                .is_ok()
        })
        .await
        .unwrap_or(false);

        if verified {
            AuthOutcome::Authenticated(ProvenIdentity::local(user.username))
        } else {
            // Known local user, wrong password → definitive rejection.
            AuthOutcome::Rejected
        }
    }
}
