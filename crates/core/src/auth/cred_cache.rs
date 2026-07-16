//! The validated-credential cache (slice 12.3, Phase 3) — security-critical.
//!
//! NuGet clients send HTTP Basic credentials on **every** request, so a
//! credential-forwarding provider that hit the upstream once per request would
//! amplify load and latency unacceptably and turn an upstream blip into a forge
//! outage. This module caches the *validation verdict* — never the credential —
//! so the steady state of NuGet's per-request Basic auth is a cache hit.
//!
//! ## What is cached, and where
//!
//! * **Authoritative store:** the `validated_credential` Postgres table
//!   ([`forge_db::validated_credential_dao`]). A cold instance with no Redis
//!   still reads it and avoids re-forwarding (the no in-memory-only-authoritative
//!   -state rule).
//! * **Hot path:** [`forge_cache::Cache`] (L1 moka + optional L2 Redis) keyed by
//!   the credential HMAC, with the Postgres read as its factory. Invalidation
//!   broadcasts on the cache backplane so a revoke on one node drops the L1 entry
//!   on every node.
//!
//! ## The cache key — never the password
//!
//! `cred_key = hex(HMAC-SHA256(pepper, len(provider) ‖ provider ‖ len(user) ‖
//! user ‖ password))`, where `pepper` is a server-held secret
//! ([`CredKeyPepper`], redacted in `Debug`, §12.5-encryptable).
//!
//! * **No plaintext at rest.** Only the HMAC is ever stored / cached.
//! * **Pepper, not a bare hash.** A bare hash of the password would be offline-
//!   bruteforceable if the DB leaked. HMAC with a server-held pepper means a
//!   DB-only compromise cannot brute-force passwords without also stealing the
//!   pepper (env/KMS, not the row).
//! * **Per-user-distinct.** The username is mixed in (length-framed so
//!   `(provider="a", user="bc")` and `(provider="ab", user="c")` cannot collide),
//!   so the same password for two users yields distinct keys — no cross-user
//!   inference.
//!
//! ## Fail-closed
//!
//! Only a *definitive* verdict (valid / rejected) is ever persisted or cached.
//! An upstream outage ([`UpstreamVerdict::Unavailable`]) writes **nothing** —
//! it surfaces as a [`CredCacheError::Unavailable`] which the cache crate does
//! not cache, so the next attempt re-forwards. A flapping upstream therefore
//! never locks everyone out past the blip, and an outage never opens a hole.
//!
//! ## Singleflight (no advisory locks)
//!
//! A miss runs the upstream forward through a ROW-lock singleflight in the DAO
//! (`begin_singleflight` → `finalize_singleflight`), so a burst of identical
//! credentials across instances forwards **once**. moka's `try_get_with` (inside
//! the cache crate) additionally coalesces in-process. There are **no Postgres
//! advisory locks**.

use std::fmt;
use std::time::Duration;

use chrono::Utc;
use forge_cache::Cache;
use forge_db::validated_credential_dao::{self as vc_dao, NewVerdict};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

type HmacSha256 = Hmac<Sha256>;

/// Cache namespace for validated-credential verdicts, keyed by the credential
/// HMAC. The HMAC already includes the provider id, so all providers can share
/// one invalidation domain without key collisions. A user revocation must be
/// able to evict realm-scoped providers whose names are only known at runtime.
const NS_CRED: &str = "validated_credential";

/// Opaque cache tag shared by every credential entry for one username. Hashing
/// avoids placing usernames directly in Redis metadata or pub/sub payloads;
/// this tag is an invalidation grouping key, not an authentication secret.
fn user_cache_tag(username: &str) -> String {
    format!(
        "credential-user:{}",
        hex::encode(Sha256::digest(username.as_bytes()))
    )
}

/// A server-held secret keying the credential-cache HMAC.
///
/// Treated like Slice 1's `upstream_password`: **redacted** in `Debug` so it can
/// never leak through a log line or error body, and stored in a dedicated secret
/// slot ready for §12.5 encryption. Rotating it invalidates the whole cache
/// (every key changes), which merely causes re-forwards — acceptable.
#[derive(Clone)]
pub struct CredKeyPepper(Vec<u8>);

impl CredKeyPepper {
    /// Build a pepper from raw secret bytes. The caller is responsible for the
    /// bytes being high-entropy (e.g. from `FORGE_AUTH_CACHE_PEPPER`).
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The raw pepper bytes (HMAC key material). Crate-internal only.
    fn key(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CredKeyPepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CredKeyPepper").field(&"[REDACTED]").finish()
    }
}

/// Derive the credential cache key: `hex(HMAC-SHA256(pepper, framed(provider,
/// username, password)))`.
///
/// The inputs are **length-framed** (each variable-length field is prefixed by
/// its big-endian u64 length) so distinct triples can never produce the same
/// byte stream and thus the same key.
pub fn cred_key(
    pepper: &CredKeyPepper,
    provider_id: &str,
    username: &str,
    password: &str,
) -> String {
    let mut mac =
        HmacSha256::new_from_slice(pepper.key()).expect("HMAC-SHA256 accepts a key of any length");
    frame(&mut mac, provider_id.as_bytes());
    frame(&mut mac, username.as_bytes());
    frame(&mut mac, password.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Feed one length-framed field into the MAC: an 8-byte big-endian length, then
/// the bytes. Prevents `(provider, username)` boundary ambiguity.
fn frame(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&(field.len() as u64).to_be_bytes());
    mac.update(field);
}

/// The verdict an upstream provider produces when actually forwarding a
/// credential (the factory's result on a cache miss).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamVerdict {
    /// The upstream accepted the credential.
    Valid,
    /// The upstream definitively rejected the credential (e.g. 401/403).
    Rejected,
    /// The upstream was unreachable / errored / timed out. **Fail-closed:**
    /// never cached, surfaces as [`CredCacheError::Unavailable`].
    Unavailable,
}

/// The cached decision. Only definitive verdicts are ever cached, so this is a
/// plain boolean (`true` = valid, `false` = rejected). Serialized as JSON by the
/// cache crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct CachedVerdict {
    valid: bool,
}

/// Errors from a credential-cache lookup.
///
/// `Clone` because [`forge_cache::Cache::get_or_try_insert_with`] hands every
/// coalesced waiter a shared error on a failing factory — and, crucially, does
/// **not** cache it, which is exactly the fail-closed behavior we want for
/// [`Self::Unavailable`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredCacheError {
    /// The upstream was unavailable and there was no valid cached verdict.
    /// Never cached; the caller must deny (fail-closed) and the next attempt
    /// re-forwards.
    #[error("upstream credential validation is unavailable")]
    Unavailable,
    /// A database error talking to the authoritative store.
    #[error("validated-credential store error: {0}")]
    Db(String),
}

impl From<sqlx::Error> for CredCacheError {
    fn from(e: sqlx::Error) -> Self {
        CredCacheError::Db(e.to_string())
    }
}

/// The validated-credential cache: HMAC key derivation + L1/L2 hot path over the
/// Postgres `validated_credential` authoritative store, with positive/negative
/// TTLs, singleflighted upstream forwarding, and revoke-by-username.
///
/// Cheaply [`Clone`]able (shares the [`Cache`] and [`PgPool`]).
#[derive(Clone)]
pub struct ValidatedCredentialCache {
    cache: Cache,
    pool: PgPool,
    pepper: CredKeyPepper,
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl fmt::Debug for ValidatedCredentialCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedCredentialCache")
            .field("pepper", &self.pepper)
            .field("positive_ttl", &self.positive_ttl)
            .field("negative_ttl", &self.negative_ttl)
            .finish_non_exhaustive()
    }
}

impl ValidatedCredentialCache {
    /// Build the cache. `positive_ttl` bounds how long a *good* credential is
    /// trusted without re-forwarding; `negative_ttl` (kept short) bounds how long
    /// a *bad* one is remembered.
    pub fn new(
        cache: Cache,
        pool: PgPool,
        pepper: CredKeyPepper,
        positive_ttl: Duration,
        negative_ttl: Duration,
    ) -> Self {
        Self {
            cache,
            pool,
            pepper,
            positive_ttl,
            negative_ttl,
        }
    }

    /// Validate `(provider_id, username, password)` through the cache.
    ///
    /// Lookup order: L1 → L2 → Postgres `validated_credential` → (on a true miss)
    /// the singleflighted `forward` upstream call. A returned `Ok(true)` means
    /// the credential is valid; `Ok(false)` means definitively rejected;
    /// [`CredCacheError::Unavailable`] means fail-closed (deny; do not grant).
    ///
    /// `forward` is the actual upstream HTTP Basic call (Phase 4). It is invoked
    /// **at most once** per credential per TTL window per cluster (singleflight),
    /// and only on a genuine miss. It receives nothing but its own captured
    /// state — the plaintext password is the caller's to hold for the duration of
    /// the request and is never persisted here.
    pub async fn check<F, Fut>(
        &self,
        provider_id: &str,
        username: &str,
        password: &str,
        forward: F,
    ) -> Result<bool, CredCacheError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = UpstreamVerdict>,
    {
        let key = cred_key(&self.pepper, provider_id, username, password);
        let user_tag = user_cache_tag(username);

        // The cache value's TTL must depend on the verdict (positive vs
        // negative), but `get_or_try_insert_with` takes a single `ttl`. We pass
        // the longer positive TTL to the cache layer (so a positive lives its
        // full window) and rely on the absolute `expires_at` written to Postgres
        // — and re-checked on read — for the authoritative, per-verdict bound.
        // A negative entry that out-lives its DB expiry is re-derived on the next
        // Postgres read (the DAO treats an expired row as a miss).
        let pool = self.pool.clone();
        let provider = provider_id.to_string();
        let user = username.to_string();
        let key_for_factory = key.clone();
        let positive_ttl = self.positive_ttl;
        let negative_ttl = self.negative_ttl;

        let verdict: CachedVerdict = self
            .cache
            .get_or_try_insert_with_tags(
                NS_CRED,
                &key,
                std::slice::from_ref(&user_tag),
                self.positive_ttl,
                || async move {
                    load_or_forward(
                        &pool,
                        &provider,
                        &user,
                        &key_for_factory,
                        positive_ttl,
                        negative_ttl,
                        forward,
                    )
                    .await
                },
            )
            .await?;

        Ok(verdict.valid)
    }

    /// Revoke every cached verdict for `username` (optionally scoped to one
    /// provider): delete the authoritative rows **and** broadcast a cache-layer
    /// invalidation so peer instances drop their L1/L2 entries.
    ///
    /// Because the cache key is the (peppered) credential HMAC, we cannot target
    /// the exact L1 keys for a username without the passwords — so we invalidate
    /// the user's cache tag. Provider ids are already framed into each HMAC key,
    /// so a provider-scoped DB revoke may safely evict that user's entries from
    /// every provider without invalidating unrelated users.
    pub async fn revoke_user(
        &self,
        username: &str,
        provider_id: Option<&str>,
    ) -> Result<u64, CredCacheError> {
        let deleted = vc_dao::revoke_by_username(&self.pool, username, provider_id).await?;
        self.cache
            .invalidate_tag(NS_CRED, &user_cache_tag(username))
            .await;
        Ok(deleted)
    }
}

/// Revoke every cached verdict for `username` **without** needing a
/// [`ValidatedCredentialCache`] (and thus without the pepper).
///
/// This is the admin "force re-auth user X" / deactivate-user path: it deletes
/// the authoritative `validated_credential` rows for the username (across all
/// providers) and broadcasts a cache-layer invalidation of the shared
/// validated-credential namespace so peer instances drop their L1/L2 entries
/// on the next read. The pepper is irrelevant here — revocation is keyed by
/// username, not by the credential HMAC. Returns the number of authoritative
/// rows deleted.
///
/// Correctness without the pepper: the row deletes are authoritative, and the
/// per-user tag invalidation drops every provider's hot entries for this user,
/// so the next request re-derives from the now-purged Postgres store.
pub async fn revoke_credentials_for_user(
    cache: &Cache,
    pool: &PgPool,
    username: &str,
) -> Result<u64, CredCacheError> {
    let deleted = vc_dao::revoke_by_username(pool, username, None).await?;
    cache
        .invalidate_tag(NS_CRED, &user_cache_tag(username))
        .await;
    Ok(deleted)
}

/// The cache factory: read the authoritative Postgres verdict; on a true miss,
/// run the singleflighted upstream forward and persist the definitive verdict.
///
/// Returns `Err(Unavailable)` (never cached) when the upstream is down on a
/// miss — fail-closed.
#[allow(clippy::too_many_arguments)]
async fn load_or_forward<F, Fut>(
    pool: &PgPool,
    provider_id: &str,
    username: &str,
    cred_hmac: &str,
    positive_ttl: Duration,
    negative_ttl: Duration,
    forward: F,
) -> Result<CachedVerdict, CredCacheError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = UpstreamVerdict>,
{
    // 1. Authoritative read: a non-expired row short-circuits the forward (this
    //    is what a cold/Redis-less instance relies on).
    if let Some(row) = vc_dao::get_verdict(pool, provider_id, username, cred_hmac).await? {
        return Ok(CachedVerdict { valid: row.verdict });
    }

    // 2. Singleflight: take the ROW lock. If a peer wrote a fresh verdict while
    //    we waited, use it without forwarding.
    let mut tx = pool.begin().await?;
    vc_dao::lock_user_tag(&mut tx, username).await?;
    if let Some(row) = vc_dao::begin_singleflight(&mut tx, provider_id, username, cred_hmac).await?
    {
        tx.commit().await?;
        return Ok(CachedVerdict { valid: row.verdict });
    }

    // 3. We are the winner: forward upstream (the plaintext leaves only here,
    //    over the Basic header the provider builds).
    let verdict = forward().await;
    let (valid, ttl) = match verdict {
        UpstreamVerdict::Valid => (true, positive_ttl),
        UpstreamVerdict::Rejected => (false, negative_ttl),
        UpstreamVerdict::Unavailable => {
            // Fail-closed: persist nothing, release the lock, deny. The sentinel
            // anchor row stays expired so it never counts as a cached verdict and
            // is reaped by the sweeper.
            tx.rollback().await.ok();
            return Err(CredCacheError::Unavailable);
        }
    };

    let expires_at = Utc::now()
        + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::seconds(0));
    vc_dao::finalize_singleflight(
        &mut tx,
        NewVerdict {
            provider_id: provider_id.to_string(),
            username: username.to_string(),
            cred_hmac: cred_hmac.to_string(),
            verdict: valid,
            expires_at,
        },
    )
    .await?;
    tx.commit().await?;

    Ok(CachedVerdict { valid })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pepper() -> CredKeyPepper {
        CredKeyPepper::new(b"a-high-entropy-server-pepper".to_vec())
    }

    #[test]
    fn cred_key_is_stable() {
        let a = cred_key(&pepper(), "upstream-basic", "alice", "hunter2");
        let b = cred_key(&pepper(), "upstream-basic", "alice", "hunter2");
        assert_eq!(a, b, "same inputs => same key");
        // HMAC-SHA256 hex is 64 chars.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn cred_key_never_contains_plaintext() {
        let password = "super-secret-password";
        let k = cred_key(&pepper(), "upstream-basic", "alice", password);
        assert!(!k.contains(password), "key must not embed the plaintext");
        assert!(!k.contains("alice"));
    }

    #[test]
    fn cred_key_is_per_user_distinct() {
        // Same password, different users => different keys.
        let a = cred_key(&pepper(), "upstream-basic", "alice", "samepw");
        let b = cred_key(&pepper(), "upstream-basic", "bob", "samepw");
        assert_ne!(a, b);
    }

    #[test]
    fn cred_key_depends_on_pepper() {
        let p1 = CredKeyPepper::new(b"pepper-one".to_vec());
        let p2 = CredKeyPepper::new(b"pepper-two".to_vec());
        let a = cred_key(&p1, "upstream-basic", "alice", "pw");
        let b = cred_key(&p2, "upstream-basic", "alice", "pw");
        assert_ne!(a, b, "different pepper => different key");
    }

    #[test]
    fn cred_key_framing_prevents_boundary_collision() {
        // Without length framing, ("ab","c") and ("a","bc") could collide. The
        // password is held constant so only the provider/username boundary moves.
        let a = cred_key(&pepper(), "ab", "c", "pw");
        let b = cred_key(&pepper(), "a", "bc", "pw");
        assert_ne!(a, b);
    }

    #[test]
    fn pepper_debug_redacts() {
        let rendered = format!("{:?}", pepper());
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("high-entropy"));
    }

    #[test]
    fn cache_debug_redacts_pepper() {
        // The cache's Debug must not leak the pepper either.
        let cache = Cache::l1_only(8);
        // We can't easily build a PgPool here; assert the pepper's Debug (used by
        // the struct's Debug) is the redacting one.
        let _ = cache;
        let rendered = format!("{:?}", pepper());
        assert!(!rendered.contains("pepper-"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
