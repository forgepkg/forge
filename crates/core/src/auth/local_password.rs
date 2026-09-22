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
//! * A present-but-wrong password is [`AuthOutcome::Rejected`] (terminal in
//!   the chain: the password is never forwarded upstream).
//! * Every `Skip` path still runs one argon2 verification against a static
//!   dummy hash, so an unknown / passwordless / inactive username costs the same
//!   time as a known one (no timing-based username enumeration).
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
//! * known local user, wrong password → **Rejected** (definitive "no"; the
//!   chain stops here — a username owned by a local account with a password is
//!   never forwarded to an upstream realm).
//!
//! When the chain is just `["local-password"]` this distinction is invisible on
//! the wire: both `Skip` (→ `NoCredentials` → anon policy) and `Rejected`
//! (→ 401) reproduce slice-1 behaviour, because slice 1's `BasicAuthSource`
//! turned a `None` password verify into `SourceOutcome::Invalid` only when the
//! basic header was present (creds were attempted), which is exactly what the
//! refactored `BasicAuthSource` still does. See the phase-2 tests.

use std::sync::OnceLock;

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
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

/// A throwaway argon2id PHC hash (default parameters, random password) used to
/// equalize the cost of the `Skip` paths with a real verification. Built once.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"forge-timing-equalizer", &salt)
            .map(|h| h.to_string())
            .unwrap_or_default()
    })
}

/// Verify `candidate` against a PHC `stored` hash on a blocking thread.
async fn verify_blocking(stored: String, candidate: String) -> bool {
    tokio::task::spawn_blocking(move || {
        let parsed = match PasswordHash::new(&stored) {
            Ok(p) => p,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(candidate.as_bytes(), &parsed)
            .is_ok()
    })
    .await
    .unwrap_or(false)
}

/// Burn one argon2 verification on the dummy hash, then report `Skip`: the
/// caller learns "not ours" in the same time a wrong password would take.
async fn skip_after_dummy_verify(candidate: &str) -> AuthOutcome {
    let _ = verify_blocking(dummy_hash().to_string(), candidate.to_string()).await;
    AuthOutcome::Skip
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
            Ok(None) => return skip_after_dummy_verify(cred.password).await,
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
            return skip_after_dummy_verify(cred.password).await;
        }

        // Users with no local password (auth_source upstream-basic / oidc) can
        // never authenticate via the local store — this username is not ours.
        let Some(stored) = user.password_hash.clone() else {
            return skip_after_dummy_verify(cred.password).await;
        };

        let verified = verify_blocking(stored, cred.password.to_string()).await;

        if verified {
            AuthOutcome::Authenticated(ProvenIdentity::local(user.username))
        } else {
            // Known local user, wrong password → definitive rejection.
            AuthOutcome::Rejected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_hash_is_a_valid_default_argon2id_phc() {
        let parsed = PasswordHash::new(dummy_hash()).expect("valid PHC string");
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        // Same parameters as a freshly created user's hash, so the timing matches.
        let salt = SaltString::generate(&mut OsRng);
        let real = Argon2::default().hash_password(b"x", &salt).unwrap();
        assert_eq!(parsed.params, real.params);
    }

    #[tokio::test]
    async fn dummy_verify_never_accepts() {
        assert!(!verify_blocking(dummy_hash().to_string(), "forge".into()).await);
        assert_eq!(skip_after_dummy_verify("anything").await, AuthOutcome::Skip);
    }
}
