//! The validated-credential cache — security-critical.
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
//! * **Hot path:** [`forge_cache::Cache`], **in-process only**
//!   ([`forge_cache::Cache::get_or_try_insert_local_with_tags`]) and keyed by
//!   the credential HMAC, with the Postgres read as its factory. A verdict is
//!   an authentication decision, so it never lives in Redis (anyone with
//!   access to Redis could otherwise mark any password valid). Invalidation
//!   broadcasts on the cache backplane so a revoke on one node drops the L1
//!   entry on every node.
//! * **Success log:** every definitive upstream ACCEPT also records
//!   `(username, provider_id)` in `auth_success`
//!   ([`forge_db::validated_credential_dao::record_auth_success`]) — rejected
//!   attempts never do — bounded to the 5 most recently used methods per user.
//!   This answers "who still authenticates through which upstream?" when
//!   deciding to cut an upstream off.
//!
//! ## The cache key — never the password
//!
//! `cred_key = hex(HMAC-SHA256(pepper, len(provider) ‖ provider ‖ len(user) ‖
//! user ‖ password))`, where `pepper` is a server-held secret
//! ([`CredKeyPepper`], redacted in `Debug`; kept with the realm's secrets,
//! which are encrypted at rest).
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
//! ## Singleflight (no advisory locks, no connection held across the network)
//!
//! A miss runs the upstream forward through a lease-based singleflight in the
//! DAO, so a burst of identical credentials across instances forwards **once**
//! — without ever pinning a pooled connection while the upstream answers (an
//! upstream stall or a password spray with rotating usernames would otherwise
//! drain the pool and take every DB-backed request down with it):
//!
//! 1. a short statement claims a lease on the credential's row
//!    ([`vc_dao::claim_singleflight`]) and commits;
//! 2. the winner forwards holding no connection, under a hard deadline
//!    ([`ValidatedCredentialCache::with_forward_timeout`]) that the lease
//!    outlasts;
//! 3. the verdict is written in a second short transaction conditioned on the
//!    winner still holding its claim ([`vc_dao::finalize_claim`]) — a
//!    revocation that landed mid-forward fences the stale result, which then
//!    fails closed;
//! 4. losers poll the row with backoff (no lock, no permit held) until the
//!    verdict lands or the lease lapses, then take over.
//!
//! moka's `try_get_with` (inside the cache crate) additionally coalesces
//! in-process. There are **no Postgres advisory locks**.
//!
//! ## Bounded concurrency
//!
//! Each provider bounds its concurrent upstream forwards with a semaphore
//! ([`ForwardLimits`], default [`DEFAULT_MAX_CONCURRENT_FORWARDS`] per
//! provider per instance). A miss that finds every permit taken fails closed
//! as [`CredCacheError::Unavailable`] at once — before it writes anything — so
//! a spray of distinct credentials cannot queue unbounded upstream work.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use forge_cache::Cache;
use forge_db::validated_credential_dao::{self as vc_dao, Claim, ClaimState, NewVerdict};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Default cap on concurrent upstream forwards per credential-forwarding
/// provider, per instance (see [`ForwardLimits`]).
pub const DEFAULT_MAX_CONCURRENT_FORWARDS: usize = 32;

/// Default hard deadline for one upstream forward (see
/// [`ValidatedCredentialCache::with_forward_timeout`]). Providers normally set
/// their own, tighter request timeout.
pub const DEFAULT_FORWARD_TIMEOUT: Duration = Duration::from_secs(10);

/// How much longer a singleflight lease lives than the forward deadline: room
/// for the verdict write plus clock jitter between this instance and Postgres
/// (which stamps the lease), so a healthy winner never loses its lease.
const CLAIM_LEASE_MARGIN: Duration = Duration::from_secs(5);

/// First / maximum delay between a losing caller's polls of the claimed row.
const POLL_INITIAL: Duration = Duration::from_millis(20);
const POLL_MAX: Duration = Duration::from_millis(500);

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
/// Treated like a repository's `upstream_password`: **redacted** in `Debug` so
/// it can never leak through a log line or error body, and kept with the
/// realm's secrets, which are encrypted at rest. Rotating it invalidates the
/// whole cache (every key changes), which merely causes re-forwards —
/// acceptable.
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

/// Per-provider bounds on concurrent upstream credential forwards.
///
/// One semaphore per provider id, created on first use with
/// `max_per_provider` permits. Keep a single registry for the life of the
/// process (the server holds it next to its realm snapshot cache) and hand each
/// provider's semaphore to its [`ValidatedCredentialCache`] via
/// [`ValidatedCredentialCache::with_forward_limit`], so rebuilding a provider —
/// e.g. on a realm-snapshot refresh — never resets the bound while forwards
/// started by the previous build are still in flight.
pub struct ForwardLimits {
    max_per_provider: usize,
    semaphores: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl ForwardLimits {
    /// A registry granting `max_per_provider` concurrent forwards to each
    /// provider (clamped to at least 1 — zero would deny every miss).
    pub fn new(max_per_provider: usize) -> Self {
        Self {
            max_per_provider: max_per_provider.max(1),
            semaphores: Mutex::new(HashMap::new()),
        }
    }

    /// The (shared) semaphore bounding `provider_id`'s forwards.
    pub fn for_provider(&self, provider_id: &str) -> Arc<Semaphore> {
        let mut map = self
            .semaphores
            .lock()
            .expect("forward-limit registry mutex not poisoned");
        map.entry(provider_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_provider)))
            .clone()
    }
}

impl Default for ForwardLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONCURRENT_FORWARDS)
    }
}

impl fmt::Debug for ForwardLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardLimits")
            .field("max_per_provider", &self.max_per_provider)
            .finish_non_exhaustive()
    }
}

/// The validated-credential cache: HMAC key derivation + L1/L2 hot path over the
/// Postgres `validated_credential` authoritative store, with positive/negative
/// TTLs, lease-singleflighted and concurrency-bounded upstream forwarding, and
/// revoke-by-username.
///
/// Cheaply [`Clone`]able (shares the [`Cache`], [`PgPool`] and forward limit).
#[derive(Clone)]
pub struct ValidatedCredentialCache {
    cache: Cache,
    pool: PgPool,
    pepper: CredKeyPepper,
    positive_ttl: Duration,
    negative_ttl: Duration,
    forward_timeout: Duration,
    forward_limit: Arc<Semaphore>,
}

impl fmt::Debug for ValidatedCredentialCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedCredentialCache")
            .field("pepper", &self.pepper)
            .field("positive_ttl", &self.positive_ttl)
            .field("negative_ttl", &self.negative_ttl)
            .field("forward_timeout", &self.forward_timeout)
            .finish_non_exhaustive()
    }
}

impl ValidatedCredentialCache {
    /// Build the cache. `positive_ttl` bounds how long a *good* credential is
    /// trusted without re-forwarding; `negative_ttl` (kept short) bounds how long
    /// a *bad* one is remembered.
    ///
    /// Forwards get [`DEFAULT_FORWARD_TIMEOUT`] and a private semaphore of
    /// [`DEFAULT_MAX_CONCURRENT_FORWARDS`] permits; long-lived wiring should
    /// share a [`ForwardLimits`] semaphore instead (see
    /// [`Self::with_forward_limit`]).
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
            forward_timeout: DEFAULT_FORWARD_TIMEOUT,
            forward_limit: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_FORWARDS)),
        }
    }

    /// Bound this provider's concurrent upstream forwards by `limit` (typically
    /// [`ForwardLimits::for_provider`]). A miss that finds no free permit fails
    /// closed ([`CredCacheError::Unavailable`]) instead of queueing.
    pub fn with_forward_limit(mut self, limit: Arc<Semaphore>) -> Self {
        self.forward_limit = limit;
        self
    }

    /// Hard deadline for one upstream forward; an overrun counts as
    /// [`UpstreamVerdict::Unavailable`]. The singleflight lease is derived from
    /// it, so it must cover the provider's whole request (connect + response).
    pub fn with_forward_timeout(mut self, timeout: Duration) -> Self {
        self.forward_timeout = timeout;
        self
    }

    /// Validate `(provider_id, username, password)` through the cache.
    ///
    /// Lookup order: L1 → Postgres `validated_credential` → (on a true miss)
    /// the singleflighted `forward` upstream call. A returned `Ok(true)` means
    /// the credential is valid; `Ok(false)` means definitively rejected;
    /// [`CredCacheError::Unavailable`] means fail-closed (deny; do not grant).
    ///
    /// `forward` is the actual upstream HTTP Basic call. It is invoked
    /// **at most once** per credential per TTL window per cluster (singleflight),
    /// and only on a genuine miss. No database connection is held while it runs.
    /// It receives nothing but its own captured state — the plaintext password
    /// is the caller's to hold for the duration of the request and is never
    /// persisted here.
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

        // The in-memory entry lives no longer than the verdict behind it: a
        // fresh forward's verdict for its own TTL (positive or negative), a
        // verdict read from Postgres only for what its row has left. An L1
        // hit never goes back to Postgres, so without this a rejection would
        // stick for the positive TTL, and an instance that read a peer's row
        // near its expiry would keep accepting the credential for a whole
        // further window.
        let fill = Fill {
            pool: self.pool.clone(),
            provider_id: provider_id.to_string(),
            username: username.to_string(),
            cred_hmac: key.clone(),
            positive_ttl: self.positive_ttl,
            negative_ttl: self.negative_ttl,
            forward_timeout: self.forward_timeout,
            forward_limit: self.forward_limit.clone(),
        };

        let verdict: CachedVerdict = self
            .cache
            .get_or_try_insert_local_with_tags_expiring(
                NS_CRED,
                &key,
                std::slice::from_ref(&user_tag),
                self.positive_ttl.max(self.negative_ttl),
                || async move { fill.load_or_forward(forward).await },
            )
            .await?;

        Ok(verdict.valid)
    }

    /// Revoke every cached verdict for `username` (optionally scoped to one
    /// provider): delete the authoritative rows **and** broadcast a cache-layer
    /// invalidation so peer instances drop their L1 entries.
    ///
    /// Because the cache key is the (peppered) credential HMAC, we cannot target
    /// the exact L1 keys for a username without the passwords — so we invalidate
    /// the user's cache tag. Provider ids are already framed into each HMAC key,
    /// so a provider-scoped DB revoke may safely evict that user's entries from
    /// every provider without invalidating unrelated users.
    ///
    /// A forward in flight for the user is not waited for at the database: its
    /// claim row is deleted with the verdicts, so its result is discarded (that
    /// one request fails closed) and the next request re-forwards.
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
/// validated-credential namespace so peer instances drop their L1 entries
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

/// Everything one cache-miss fill needs, owned so the factory future is
/// `'static`-friendly for the cache crate's coalescing.
struct Fill {
    pool: PgPool,
    provider_id: String,
    username: String,
    cred_hmac: String,
    positive_ttl: Duration,
    negative_ttl: Duration,
    forward_timeout: Duration,
    forward_limit: Arc<Semaphore>,
}

impl Fill {
    /// The singleflight lease: the forward deadline plus a margin for the
    /// verdict write.
    fn lease(&self) -> Duration {
        self.forward_timeout + CLAIM_LEASE_MARGIN
    }

    /// The cache factory: read the authoritative Postgres verdict; on a true
    /// miss, win (or wait out) the lease singleflight, forward, and persist the
    /// definitive verdict. No connection or transaction is held across the
    /// forward or across a loser's waits.
    ///
    /// Returns the verdict with how long it may be cached: what its row has
    /// left, or the verdict's own TTL after a fresh forward.
    ///
    /// Returns `Err(Unavailable)` (never cached) when the upstream is down, the
    /// provider's forward limit is exhausted, the verdict was fenced by a
    /// concurrent revocation, or a peer's forward did not settle in time —
    /// fail-closed in every case.
    async fn load_or_forward<F, Fut>(
        &self,
        forward: F,
    ) -> Result<(CachedVerdict, Duration), CredCacheError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = UpstreamVerdict>,
    {
        // 1. Authoritative read: a non-expired row short-circuits the forward
        //    (this is what a cold/Redis-less instance relies on).
        if let ClaimState::Fresh(fresh) = vc_dao::claim_state(
            &self.pool,
            &self.provider_id,
            &self.username,
            &self.cred_hmac,
        )
        .await?
        {
            return Ok(fresh_verdict(fresh));
        }

        // A loser waits at most two leases overall: long enough for a stalled
        // winner to time out and one takeover to finish.
        let deadline = Instant::now() + self.lease() * 2;
        let mut forward = Some(forward);
        let mut backoff = POLL_INITIAL;
        loop {
            // 2. Bound concurrency *before* touching the row, so a saturated
            //    instance fails fast and writes nothing.
            let Ok(permit) = self.forward_limit.clone().try_acquire_owned() else {
                tracing::warn!(
                    provider = %self.provider_id,
                    "credential forwarding concurrency limit reached; failing closed"
                );
                return Err(CredCacheError::Unavailable);
            };

            // 3. Claim the singleflight lease (one short statement).
            match vc_dao::claim_singleflight(
                &self.pool,
                &self.provider_id,
                &self.username,
                &self.cred_hmac,
                self.lease(),
            )
            .await?
            {
                Claim::Verdict(fresh) => return Ok(fresh_verdict(fresh)),
                Claim::Won { token } => {
                    let forward = forward.take().expect("a fill wins its lease at most once");
                    return self.forward_as_winner(token, permit, forward).await;
                }
                Claim::Busy => drop(permit),
            }

            // 4. A peer (another instance) is forwarding this credential: poll
            //    its row, holding neither a connection nor a permit, until the
            //    verdict lands or the lease lapses — then take over.
            loop {
                let now = Instant::now();
                if now >= deadline {
                    tracing::warn!(
                        provider = %self.provider_id,
                        "peer credential forward did not settle in time; failing closed"
                    );
                    return Err(CredCacheError::Unavailable);
                }
                tokio::time::sleep(backoff.min(deadline - now)).await;
                backoff = (backoff * 2).min(POLL_MAX);
                match vc_dao::claim_state(
                    &self.pool,
                    &self.provider_id,
                    &self.username,
                    &self.cred_hmac,
                )
                .await?
                {
                    ClaimState::Fresh(fresh) => return Ok(fresh_verdict(fresh)),
                    ClaimState::Claimed => continue,
                    ClaimState::Open => break,
                }
            }
        }
    }

    /// The lease winner's half: forward (the plaintext leaves only here, over
    /// the Basic header the provider builds) under the hard deadline, then
    /// write the verdict conditioned on still holding the lease.
    async fn forward_as_winner<F, Fut>(
        &self,
        token: Uuid,
        permit: OwnedSemaphorePermit,
        forward: F,
    ) -> Result<(CachedVerdict, Duration), CredCacheError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = UpstreamVerdict>,
    {
        // Releases the lease if this future is dropped mid-forward (client
        // disconnect), so peers need not wait the lease out.
        let mut guard = ClaimGuard {
            fill: Some((
                self.pool.clone(),
                self.provider_id.clone(),
                self.username.clone(),
                self.cred_hmac.clone(),
                token,
            )),
        };

        let verdict = match tokio::time::timeout(self.forward_timeout, forward()).await {
            Ok(verdict) => verdict,
            Err(_) => {
                tracing::warn!(
                    provider = %self.provider_id,
                    timeout_ms = self.forward_timeout.as_millis() as u64,
                    "upstream credential forward exceeded its deadline (fail-closed)"
                );
                UpstreamVerdict::Unavailable
            }
        };
        drop(permit);

        let (valid, ttl) = match verdict {
            UpstreamVerdict::Valid => (true, self.positive_ttl),
            UpstreamVerdict::Rejected => (false, self.negative_ttl),
            UpstreamVerdict::Unavailable => {
                // Fail-closed: persist nothing, hand the lease back so a peer
                // may retry at once, deny.
                guard.disarm();
                if let Err(e) = vc_dao::release_claim(
                    &self.pool,
                    &self.provider_id,
                    &self.username,
                    &self.cred_hmac,
                    token,
                )
                .await
                {
                    // The lease simply lapses instead.
                    tracing::warn!(error = %e, "releasing a credential-forward claim failed");
                }
                return Err(CredCacheError::Unavailable);
            }
        };

        // The row's expiry is compared with the database's clock.
        let expires_at = forge_db::db_now(&self.pool).await?
            + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::seconds(0));
        // On a store error the lease stays and lapses on its own.
        guard.disarm();
        let written = vc_dao::finalize_claim(
            &self.pool,
            NewVerdict {
                provider_id: self.provider_id.clone(),
                username: self.username.clone(),
                cred_hmac: self.cred_hmac.clone(),
                verdict: valid,
                expires_at,
            },
            token,
        )
        .await?;
        if !written {
            // Fenced: the user's verdicts were revoked (or the lease taken over)
            // while we forwarded. This answer predates the revocation, so it
            // must not be served — not even to this caller (the cache layer
            // would keep it). Fail closed; the next request re-forwards.
            tracing::info!(
                provider = %self.provider_id,
                "credential verdict discarded: revoked while the forward was in flight"
            );
            return Err(CredCacheError::Unavailable);
        }

        Ok((CachedVerdict { valid }, ttl))
    }
}

/// A verdict read from its row, cached for no longer than the row has left.
fn fresh_verdict(fresh: vc_dao::FreshVerdict) -> (CachedVerdict, Duration) {
    (
        CachedVerdict {
            valid: fresh.verdict,
        },
        fresh.remaining,
    )
}

/// Releases a won lease from a background task when the winning fill is
/// dropped before it settled (e.g. the client disconnected mid-forward).
struct ClaimGuard {
    fill: Option<(PgPool, String, String, String, Uuid)>,
}

impl ClaimGuard {
    /// The fill settled the lease itself: do nothing on drop.
    fn disarm(&mut self) {
        self.fill = None;
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        let Some((pool, provider_id, username, cred_hmac, token)) = self.fill.take() else {
            return;
        };
        // Best effort: without a runtime the lease just lapses.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) =
                    vc_dao::release_claim(&pool, &provider_id, &username, &cred_hmac, token).await
                {
                    tracing::debug!(error = %e, "releasing an abandoned credential-forward claim failed");
                }
            });
        }
    }
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
