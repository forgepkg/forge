//! Credential verification: API tokens and passwords, plus the
//! [`PrincipalSource`] abstraction that turns request headers into a
//! [`Principal`].
//!
//! ## Security invariants
//! * Tokens are stored only as a SHA-256 hash. We look up by hash and then
//!   compare the stored hash against the recomputed hash in **constant time**
//!   (defense in depth against any non-constant-time DB comparison).
//! * Expired or revoked tokens, and inactive users, are rejected.
//! * Password verification (argon2 PHC) runs on a blocking thread.
//! * **Bad credentials are never downgraded to anonymous.** If any source
//!   reports credentials were present but invalid, [`resolve_principal`]
//!   returns `Unauthorized` even when anonymous access would otherwise apply.

use std::net::IpAddr;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::Engine;
use chrono::Utc;
use http::HeaderMap;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use super::principal::{Principal, UserPrincipal};

/// Hash a token secret into the lowercase-hex SHA-256 form stored in the DB.
pub fn hash_token(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode(digest)
}

/// Generate a fresh 256-bit token secret as a URL-safe base64 string (no
/// padding). The plaintext is shown to the user once; only its [`hash_token`]
/// is persisted.
pub fn generate_token_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Verify an API token secret.
///
/// Returns `Some(UserPrincipal)` only if the token exists, is neither expired
/// nor revoked, and belongs to an active user. Best-effort updates
/// `last_used_at` (failure there does not fail authentication).
pub async fn verify_token(pool: &PgPool, secret: &str) -> Option<UserPrincipal> {
    let hash = hash_token(secret);

    let token = forge_db::token_dao::find_token_by_hash(pool, &hash)
        .await
        .map_err(|e| tracing::warn!(error = %e, "token lookup failed"))
        .ok()??;

    // Defense in depth: constant-time compare of stored vs recomputed hash.
    // (The DB lookup matched on `hash`, but we never want a timing side channel
    // to leak whether a near-miss hash exists.)
    if token.token_hash.as_bytes().ct_eq(hash.as_bytes()).unwrap_u8() != 1 {
        return None;
    }

    let now = Utc::now();
    if let Some(exp) = token.expires_at {
        if exp <= now {
            return None;
        }
    }
    if token.revoked_at.is_some() {
        return None;
    }

    let user = forge_db::user_dao::find_user_by_id(pool, token.user_id)
        .await
        .map_err(|e| tracing::warn!(error = %e, "user lookup failed"))
        .ok()??;
    if !user.active {
        return None;
    }

    // Best-effort touch; ignore errors.
    if let Err(e) = forge_db::token_dao::touch_last_used(pool, token.id).await {
        tracing::debug!(error = %e, token_id = token.id, "touch_last_used failed");
    }

    Some(UserPrincipal {
        user_id: user.id,
        token_id: Some(token.id),
        is_admin: user.is_admin,
    })
}

/// Verify a username/password pair against the stored argon2 PHC hash.
///
/// Returns `Some(UserPrincipal)` only for an active user whose password
/// verifies. argon2 verification (CPU-bound) runs on a blocking thread.
pub async fn verify_password(
    pool: &PgPool,
    username: &str,
    password: &str,
) -> Option<UserPrincipal> {
    let user = forge_db::user_dao::find_user_by_username(pool, username)
        .await
        .map_err(|e| tracing::warn!(error = %e, "user lookup failed"))
        .ok()??;
    if !user.active {
        return None;
    }

    let stored = user.password_hash.clone();
    let candidate = password.to_string();
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

    if !verified {
        return None;
    }

    Some(UserPrincipal {
        user_id: user.id,
        token_id: None,
        is_admin: user.is_admin,
    })
}

/// Result of asking a [`PrincipalSource`] to resolve credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceOutcome {
    /// Credentials were present and valid.
    Authenticated(Principal),
    /// No credentials of this source's kind were present.
    NoCredentials,
    /// Credentials were present but invalid (wrong/expired/revoked).
    Invalid,
}

/// Errors from principal resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// Credentials were supplied but rejected.
    #[error("unauthorized")]
    Unauthorized,
}

/// A way to derive a principal from request headers (token header, basic auth, …).
#[async_trait::async_trait]
pub trait PrincipalSource: Send + Sync {
    /// Attempt to resolve a principal from the given headers / peer IP.
    async fn resolve(&self, headers: &HeaderMap, peer_ip: IpAddr) -> SourceOutcome;
}

/// Resolves the `X-NuGet-ApiKey` header as an API token.
pub struct TokenHeaderSource {
    pool: PgPool,
}

impl TokenHeaderSource {
    /// Header name carrying the NuGet API key.
    pub const HEADER: &'static str = "X-NuGet-ApiKey";

    /// Build a source over the given pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl PrincipalSource for TokenHeaderSource {
    async fn resolve(&self, headers: &HeaderMap, _peer_ip: IpAddr) -> SourceOutcome {
        let Some(value) = headers.get(Self::HEADER) else {
            return SourceOutcome::NoCredentials;
        };
        let Ok(secret) = value.to_str() else {
            // Present but unreadable → treat as invalid (creds were attempted).
            return SourceOutcome::Invalid;
        };
        if secret.is_empty() {
            return SourceOutcome::NoCredentials;
        }
        match verify_token(&self.pool, secret).await {
            Some(up) => SourceOutcome::Authenticated(Principal::from_user(up)),
            None => SourceOutcome::Invalid,
        }
    }
}

/// Resolves HTTP Basic auth. The basic secret is tried as a **token** first,
/// then (only if `allow_password_basic`) as a **password** for the supplied
/// username.
pub struct BasicAuthSource {
    pool: PgPool,
    /// Whether to fall back to password verification when the basic secret is
    /// not a valid token.
    pub allow_password_basic: bool,
}

impl BasicAuthSource {
    /// Build a source over the given pool.
    pub fn new(pool: PgPool, allow_password_basic: bool) -> Self {
        Self {
            pool,
            allow_password_basic,
        }
    }
}

/// Decode a `Basic <base64>` header value into `(username, secret)`.
fn parse_basic(value: &str) -> Option<(String, String)> {
    let rest = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    // NuGet sends `username:apikey`; the colon splits user from secret. A secret
    // may itself contain colons, so split only on the first.
    let (user, secret) = text.split_once(':')?;
    Some((user.to_string(), secret.to_string()))
}

#[async_trait::async_trait]
impl PrincipalSource for BasicAuthSource {
    async fn resolve(&self, headers: &HeaderMap, _peer_ip: IpAddr) -> SourceOutcome {
        let Some(value) = headers.get(http::header::AUTHORIZATION) else {
            return SourceOutcome::NoCredentials;
        };
        let Ok(text) = value.to_str() else {
            return SourceOutcome::Invalid;
        };
        // Only handle the Basic scheme; other schemes are "no credentials" for us.
        if !(text.starts_with("Basic ") || text.starts_with("basic ")) {
            return SourceOutcome::NoCredentials;
        }
        let Some((username, secret)) = parse_basic(text) else {
            return SourceOutcome::Invalid;
        };
        if secret.is_empty() {
            return SourceOutcome::Invalid;
        }

        // Try the secret as a token first.
        if let Some(up) = verify_token(&self.pool, &secret).await {
            return SourceOutcome::Authenticated(Principal::from_user(up));
        }
        // Then, if allowed, as a password.
        if self.allow_password_basic {
            if let Some(up) = verify_password(&self.pool, &username, &secret).await {
                return SourceOutcome::Authenticated(Principal::from_user(up));
            }
        }
        SourceOutcome::Invalid
    }
}

pub use crate::auth::client_ip::AnonPolicy;

/// Resolve a [`Principal`] from a chain of sources.
///
/// Semantics (security-critical):
/// * Sources run in order; the **first** `Authenticated` wins.
/// * If no source authenticates but **any** reported `Invalid`, return
///   `Err(Unauthorized)`. Bad credentials are *never* downgraded to anonymous.
/// * If all sources report `NoCredentials`, apply the anonymous policy: become
///   [`Principal::Anonymous`] if the client IP is allowed, else
///   [`Principal::Unauthenticated`].
pub async fn resolve_principal(
    sources: &[Box<dyn PrincipalSource>],
    headers: &HeaderMap,
    client_ip: IpAddr,
    anon: &AnonPolicy,
) -> Result<Principal, AuthError> {
    let mut saw_invalid = false;
    for source in sources {
        match source.resolve(headers, client_ip).await {
            SourceOutcome::Authenticated(p) => return Ok(p),
            SourceOutcome::Invalid => saw_invalid = true,
            SourceOutcome::NoCredentials => {}
        }
    }

    if saw_invalid {
        return Err(AuthError::Unauthorized);
    }

    if anon.allows(client_ip) {
        Ok(Principal::Anonymous { ip: client_ip })
    } else {
        Ok(Principal::Unauthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_sha256_hex() {
        // Known SHA-256 of "abc".
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn generate_token_secret_is_unique_and_decodes_to_32_bytes() {
        let a = generate_token_secret();
        let b = generate_token_secret();
        assert_ne!(a, b);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&a)
            .expect("valid base64url");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn parse_basic_decodes_user_and_secret() {
        // base64("alice:s3cr3t")
        let enc = base64::engine::general_purpose::STANDARD.encode("alice:s3cr3t");
        let (u, s) = parse_basic(&format!("Basic {enc}")).unwrap();
        assert_eq!(u, "alice");
        assert_eq!(s, "s3cr3t");
    }

    #[test]
    fn parse_basic_secret_may_contain_colon() {
        let enc = base64::engine::general_purpose::STANDARD.encode("bob:a:b:c");
        let (u, s) = parse_basic(&format!("Basic {enc}")).unwrap();
        assert_eq!(u, "bob");
        assert_eq!(s, "a:b:c");
    }

    // ── downgrade-prevention: pure unit tests with stub sources ──────────────

    struct StubSource(SourceOutcome);

    #[async_trait::async_trait]
    impl PrincipalSource for StubSource {
        async fn resolve(&self, _h: &HeaderMap, _ip: IpAddr) -> SourceOutcome {
            self.0
        }
    }

    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    #[tokio::test]
    async fn invalid_creds_never_downgrade_to_anonymous() {
        // Anonymous would normally be allowed (All), but an Invalid source must
        // force 401 instead of anonymous.
        let sources: Vec<Box<dyn PrincipalSource>> =
            vec![Box::new(StubSource(SourceOutcome::Invalid))];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
        assert_eq!(res, Err(AuthError::Unauthorized));
    }

    #[tokio::test]
    async fn invalid_after_nocreds_still_unauthorized() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::NoCredentials)),
            Box::new(StubSource(SourceOutcome::Invalid)),
        ];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
        assert_eq!(res, Err(AuthError::Unauthorized));
    }

    #[tokio::test]
    async fn first_authenticated_wins_over_later_invalid() {
        let authed = Principal::User {
            user_id: 1,
            token_id: Some(2),
            is_admin: false,
        };
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::Authenticated(authed))),
            Box::new(StubSource(SourceOutcome::Invalid)),
        ];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::Off).await;
        assert_eq!(res, Ok(authed));
    }

    #[tokio::test]
    async fn no_credentials_becomes_anonymous_when_allowed() {
        let sources: Vec<Box<dyn PrincipalSource>> =
            vec![Box::new(StubSource(SourceOutcome::NoCredentials))];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
        assert_eq!(res, Ok(Principal::Anonymous { ip: ip() }));
    }

    #[tokio::test]
    async fn no_credentials_becomes_unauthenticated_when_anon_off() {
        let sources: Vec<Box<dyn PrincipalSource>> =
            vec![Box::new(StubSource(SourceOutcome::NoCredentials))];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::Off).await;
        assert_eq!(res, Ok(Principal::Unauthenticated));
    }
}
