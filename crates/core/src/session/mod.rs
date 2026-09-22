//! Server-side login sessions (slice 12.2, §3.7).
//!
//! The `session` row is the **authority**; the `forge_session` cookie carries
//! only an opaque 256-bit secret, and the DB stores only its `sha256`
//! (`token_hash`) — mirroring the slice-1 token model, so a DB read yields no
//! usable credential. A session is valid iff
//! `revoked_at IS NULL AND now() < idle_expiry AND now() < absolute_expiry`
//! (the predicate is enforced in SQL by [`session_dao::find_valid_by_hash`]).
//!
//! This service is the cross-instance-correct seam Phase 5's cookie middleware
//! and `/auth` routes build on: every operation is a single DB round-trip
//! against the shared Postgres, so a session created on instance A is
//! immediately visible (and revocable) on instance B.

use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use forge_db::model::Session;
use forge_db::session_dao::{self, NewSession};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;

/// Default throttle (seconds) for refreshing `last_seen_at` on use — avoids a
/// write per request, like slice-1 `token.last_used_at`.
const DEFAULT_TOUCH_THROTTLE_SECS: i64 = 60;

/// Errors from the session service.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// A database error.
    #[error("session db error: {0}")]
    Db(String),
}

/// What a caller gets back after creating (or rotating into) a session: the
/// persisted row **plus** the one-time plaintext cookie secret to set on the
/// `forge_session` cookie. The plaintext is never stored and never returned
/// again.
#[derive(Debug, Clone)]
pub struct IssuedSession {
    /// The persisted session row (its `token_hash` is `sha256(cookie_secret)`).
    pub session: Session,
    /// Plaintext 256-bit base64url cookie secret — set this on the cookie now;
    /// it cannot be recovered later.
    pub cookie_secret: String,
}

/// Create/validate/rotate/revoke sessions over a shared Postgres.
///
/// Cheaply [`Clone`]able (just a pool + a couple of durations). TTLs come from
/// the OIDC config; the server builds one of these at startup.
#[derive(Clone)]
pub struct SessionService {
    pool: PgPool,
    idle_ttl: ChronoDuration,
    absolute_ttl: ChronoDuration,
    touch_throttle_secs: i64,
}

impl SessionService {
    /// Build a service with the given idle / absolute TTLs.
    pub fn new(pool: PgPool, idle_ttl: ChronoDuration, absolute_ttl: ChronoDuration) -> Self {
        Self {
            pool,
            idle_ttl,
            absolute_ttl,
            touch_throttle_secs: DEFAULT_TOUCH_THROTTLE_SECS,
        }
    }

    /// Override the `last_seen_at` touch throttle (mainly for tests).
    pub fn with_touch_throttle_secs(mut self, secs: i64) -> Self {
        self.touch_throttle_secs = secs;
        self
    }

    /// Create a fresh session for `user_id`, returning the row + the one-time
    /// cookie secret. A new CSRF secret is generated and stored on the row for
    /// the double-submit defense (§3.8).
    pub async fn create_for_user(
        &self,
        user_id: i64,
        external_identity_id: Option<i64>,
        user_agent_hash: Option<String>,
    ) -> Result<IssuedSession, SessionError> {
        let cookie_secret = random_secret();
        let token_hash = sha256_hex(&cookie_secret);
        let csrf_secret = random_secret();
        let now = Utc::now();

        let session = session_dao::create(
            &self.pool,
            NewSession {
                user_id,
                external_identity_id,
                token_hash,
                csrf_secret,
                user_agent_hash,
                idle_expiry: now + self.idle_ttl,
                absolute_expiry: now + self.absolute_ttl,
            },
        )
        .await
        .map_err(|e| SessionError::Db(e.to_string()))?;

        Ok(IssuedSession {
            session,
            cookie_secret,
        })
    }

    /// Validate a presented cookie secret. Returns the session row iff it maps to
    /// a currently-valid session (not revoked, within idle + absolute expiry).
    ///
    /// On a hit, best-effort **touches** `last_seen_at`/`idle_expiry` (throttled)
    /// so active sessions slide forward; a touch failure never fails validation.
    /// An unknown/tampered cookie simply hashes to a missing row → `None`.
    pub async fn validate(&self, cookie_secret: &str) -> Result<Option<Session>, SessionError> {
        if cookie_secret.is_empty() {
            return Ok(None);
        }
        let hash = sha256_hex(cookie_secret);
        let Some(session) = session_dao::find_valid_by_hash(&self.pool, &hash)
            .await
            .map_err(|e| SessionError::Db(e.to_string()))?
        else {
            return Ok(None);
        };

        // Defense in depth: constant-time compare of stored vs recomputed hash,
        // matching the slice-1 token path (no timing side channel on near-miss).
        if session
            .token_hash
            .as_bytes()
            .ct_eq(hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Ok(None);
        }

        // Best-effort throttled slide of the idle window.
        if let Err(e) = session_dao::touch_last_seen(
            &self.pool,
            session.id,
            self.touch_throttle_secs,
            self.idle_ttl.num_seconds(),
        )
        .await
        {
            tracing::debug!(error = %e, session_id = session.id, "session touch failed");
        }

        Ok(Some(session))
    }

    /// Rotate a session: create a brand-new session for the same user/identity
    /// and **revoke the old one**. Returns the new [`IssuedSession`] (with a new
    /// cookie secret to set). Used right after login and on privilege change to
    /// prevent session fixation (§3.7).
    pub async fn rotate(&self, old: &Session) -> Result<IssuedSession, SessionError> {
        let issued = self
            .create_for_user(
                old.user_id,
                old.external_identity_id,
                old.user_agent_hash.clone(),
            )
            .await?;
        // Revoke the old row only after the new one exists, so a failure never
        // leaves the user with no session.
        session_dao::revoke(&self.pool, old.id)
            .await
            .map_err(|e| SessionError::Db(e.to_string()))?;
        Ok(issued)
    }

    /// Revoke a session by id (logout). Returns whether a row was revoked.
    pub async fn revoke(&self, session_id: i64) -> Result<bool, SessionError> {
        session_dao::revoke(&self.pool, session_id)
            .await
            .map_err(|e| SessionError::Db(e.to_string()))
    }

    /// Revoke all of a user's active sessions (admin action / global logout).
    pub async fn revoke_all_for_user(&self, user_id: i64) -> Result<u64, SessionError> {
        session_dao::revoke_all_for_user(&self.pool, user_id)
            .await
            .map_err(|e| SessionError::Db(e.to_string()))
    }

    /// Delete sessions that are no longer usable (revoked / expired). Returns the
    /// number reaped. Driven by the Phase-6 background reaper.
    pub async fn reap_expired(&self) -> Result<u64, SessionError> {
        session_dao::reap_expired(&self.pool)
            .await
            .map_err(|e| SessionError::Db(e.to_string()))
    }
}

/// Constant-time compare of a presented CSRF token against a session's stored
/// `csrf_secret` (double-submit defense, §3.8). `false` on any length/byte
/// mismatch, with no early-exit timing leak.
pub fn csrf_token_matches(presented: &str, session_csrf_secret: &str) -> bool {
    presented
        .as_bytes()
        .ct_eq(session_csrf_secret.as_bytes())
        .unwrap_u8()
        == 1
}

/// Generate a fresh 256-bit URL-safe base64 (no-pad) secret — used for both the
/// cookie value and the per-session CSRF secret.
fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Lowercase-hex SHA-256, matching the slice-1 `token_hash` form.
fn sha256_hex(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_secret_is_unique_and_32_bytes() {
        let a = random_secret();
        let b = random_secret();
        assert_ne!(a, b);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&a)
            .expect("base64url");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn sha256_hex_is_stable_lowercase_hex() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn csrf_compare_accepts_match_rejects_mismatch() {
        let secret = random_secret();
        assert!(csrf_token_matches(&secret, &secret));
        assert!(!csrf_token_matches("not-it", &secret));
        // Length mismatch is rejected without panicking.
        assert!(!csrf_token_matches("short", &secret));
        assert!(!csrf_token_matches("", &secret));
    }
}
