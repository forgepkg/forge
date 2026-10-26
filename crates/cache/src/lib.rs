//! `forge-cache` — a HybridCache analogue.
//!
//! A two-tier cache that is **generic over value types via `serde`**:
//!
//! * **L1** — an in-process [`moka`](https://docs.rs/moka) cache (size-bounded,
//!   per-entry TTL). Always present.
//! * **L2** — an *optional* Redis cache (shared across instances). When absent
//!   the cache is still fully correct — it just rebuilds from the factory more
//!   often.
//! * **Backplane** — an *optional* Redis pub/sub channel that broadcasts tag
//!   generations so every instance immediately observes logical invalidations.
//!   Only present when L2 is.
//!
//! ## Tag barriers
//!
//! Every entry is stamped with immutable generations for a synthetic namespace
//! tag, a synthetic key tag, and any caller-supplied tags. Invalidating a tag is
//! O(1): increment its Redis generation and publish that generation. Reads hide
//! entries whose stamps predate the current barrier, while Redis writes use a
//! compare-and-set script so an older fill can never republish stale data after
//! invalidation. This follows FusionCache's passive tag-expiration model without
//! scanning every tagged key.
//!
//! A generation far beyond anything a tag can reach by counting (2^48) is
//! forged: it counts as an invalidation but raises the barrier by one only, so
//! no barrier is ever left without room to advance.
//!
//! ## Coalescing / stampede protection
//!
//! Concurrent callers asking for the same `(ns, key)` are coalesced by moka's
//! [`try_get_with`](moka::future::Cache::try_get_with): exactly one of them runs
//! the (L2 → factory) load while the rest await the same in-flight future. On
//! success every waiter receives the same value; on error none of them cache it
//! and they are free to retry on the next call.
//!
//! ## TTL approach
//!
//! moka's own per-entry TTL (via an `Expiry`) governs L1. We *also* stamp each
//! stored entry with an absolute `expires_at` [`Instant`] and treat an entry
//! whose deadline has passed as a **miss** on read. Belt-and-suspenders: it
//! makes expiry deterministic for tests (which can't depend on moka's
//! background eviction timing) while moka's expiry bounds memory.
//!
//! ## Value representation
//!
//! Values are stored as JSON bytes (so the cache is type-generic) inside a
//! versioned envelope carrying tag stamps. The single moka cache remains keyed
//! by `"{ns}:{key}"`.
//!
//! ## Local-only entries (Redis is a trust boundary)
//!
//! Anyone who can write to the Redis instance can write L2 entries. That is
//! tolerable only for values whose forgery costs availability at most (a
//! proxy's "listing refreshed" and "version rejected" markers). For **security
//! decisions** and for content clients act on it is not: a forged
//! authorization set, credential verdict, JWKS, workload-token verdict, or a
//! proxy's upstream service index, manifest or registration would be accepted
//! by every instance. Such values go through [`Cache::get_or_try_insert_local`] /
//! [`Cache::get_or_try_insert_local_with_tags`]: they live in L1 only and
//! are never read from or written to Redis. Redis still carries their
//! **invalidations** (tag generations over the backplane), so an
//! invalidation on one instance still evicts them everywhere — the worst a
//! Redis writer can do to them is evict entries early.
//!
//! ## Graceful L2 degradation vs. factory errors
//!
//! An L2 (Redis) failure is a *cache* failure, never a source-of-truth failure:
//! on an L2 get/set/publish error we log and fall through (read → factory,
//! write → skip). A **factory** error, by contrast, is propagated to the caller
//! verbatim and is *not* cached — the next call retries.
//!
//! Redis is connected **lazily**: a cache built while Redis is unreachable
//! works L1-only until it comes back (the backplane keeps resubscribing and
//! flushes L1 once it is live), so an instance can start during a Redis
//! outage. Every command is bounded by [`RedisTimeouts`], connections use TCP
//! keepalive, and the subscriber pings its connection, so a Redis that
//! vanishes without closing the socket is noticed, not waited on forever.
//!
//! ## No lock across Redis I/O
//!
//! Neither reads nor invalidations take a lock that is held across a Redis
//! round-trip: a stalled Redis slows the requests that talk to it, never a
//! whole namespace. An invalidation advances this instance's tag barrier
//! **before** it bumps the generation in Redis and publishes it, so reads here
//! hide older entries once it returns (when the bump fails, L1 is flushed
//! instead: the local barrier may lag a generation read from Redis). A fill that raced it is dropped by the
//! post-fill check, and a caller that arrived after the invalidation but was
//! coalesced onto a fill that started before it loads again (see
//! [`Cache::get_or_try_insert_with`]).

mod backplane;
mod l1;
mod l2_redis;

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::backplane::Backplane;
use crate::l1::L1;
use crate::l2_redis::RedisL2;
use forge_telemetry::cache::Tier;

/// Errors raised by the cache infrastructure itself (construction / L2 setup).
///
/// Note these are *not* the errors returned by [`Cache::get_or_try_insert_with`]
/// — that method is generic over the factory's own error type `E`. These only
/// surface from constructors such as [`Cache::with_redis`].
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// Could not establish the Redis connection / connection manager.
    #[error("redis connection error: {0}")]
    Redis(#[from] redis::RedisError),
}

/// A HybridCache-style two-tier cache. Cheaply [`Clone`]able (shares all state).
#[derive(Clone)]
pub struct Cache {
    inner: Arc<Inner>,
}

struct Inner {
    l1: L1,
    l2: Option<RedisL2>,
    backplane: Option<Backplane>,
    tag_versions: TagVersions,
}

/// How many times [`Cache::load`] re-runs a lookup that was coalesced onto a
/// fill older than a barrier the caller had already observed. One re-run
/// suffices (that fill starts after the caller), the bound is a safeguard.
const MAX_LOAD_ATTEMPTS: usize = 3;

const ENTRY_FORMAT_VERSION: u8 = 1;

/// The highest tag generation a barrier adopts from Redis or the backplane.
/// Generations count one tag's invalidations one at a time, so a genuine one
/// never comes near this: a larger one was forged by someone who can write to
/// Redis. Adopting it (`u64::MAX` in particular) would leave the barrier no
/// room to advance, so every later invalidation of the tag would be ignored.
/// It stays well below 2^53, where the Redis scripts' (double-precision)
/// arithmetic stops counting exactly.
const MAX_GENERATION: u64 = 1 << 48;

/// One tag generation captured when an entry was produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TagStamp {
    tag: String,
    generation: u64,
}

/// Versioned L1/L2 envelope. The value remains the caller's JSON bytes; tags
/// are cache metadata and never become part of the caller's serialized type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredEntry {
    format_version: u8,
    tags: Vec<TagStamp>,
    value: Vec<u8>,
    /// A lifetime shorter than the caller's TTL that the factory chose for
    /// this value ([`Cache::get_or_try_insert_local_with_tags_expiring`]).
    /// In-process only: an entry read back from Redis carries the remaining
    /// Redis TTL instead.
    #[serde(skip)]
    lifetime: Option<Duration>,
}

impl StoredEntry {
    pub(crate) fn lifetime(&self) -> Option<Duration> {
        self.lifetime
    }

    /// About how much memory the entry holds (its value and tags).
    pub(crate) fn weight_bytes(&self) -> usize {
        self.value.len() + self.tags.iter().map(|t| t.tag.len() + 8).sum::<usize>()
    }

    fn has_tags(&self, expected: &[String]) -> bool {
        self.format_version == ENTRY_FORMAT_VERSION
            && self.tags.len() == expected.len()
            && self
                .tags
                .iter()
                .zip(expected)
                .all(|(stamp, tag)| stamp.tag == *tag)
    }
}

/// Bounds on every Redis interaction. The defaults suit a cache: a
/// round-trip that takes longer than this is treated as a miss / failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedisTimeouts {
    /// TCP connect (and reconnect) deadline.
    pub connect: Duration,
    /// Per-command response deadline.
    pub response: Duration,
}

impl Default for RedisTimeouts {
    fn default() -> Self {
        RedisTimeouts {
            connect: Duration::from_secs(2),
            response: Duration::from_secs(2),
        }
    }
}

impl RedisTimeouts {
    /// One reconnect attempt per failure: a command waiting on a reconnect
    /// waits about two connect deadlines, not the default six with backoff.
    pub(crate) fn manager_config(&self) -> redis::aio::ConnectionManagerConfig {
        redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(self.connect))
            .set_response_timeout(Some(self.response))
            .set_number_of_retries(1)
    }
}

/// TCP keepalive on every Redis connection, so a peer that disappears without
/// closing the socket (node lost, NAT or load-balancer state dropped) is
/// detected by the kernel too, not only by the backplane's pings.
fn tcp_settings() -> redis::io::tcp::TcpSettings {
    let keepalive = redis::io::tcp::socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let keepalive = keepalive.with_interval(Duration::from_secs(10));
    redis::io::tcp::TcpSettings::default()
        .set_nodelay(true)
        .set_keepalive(keepalive)
}

/// The most tags whose barriers an instance keeps ([`TagVersions`]). Real
/// invalidations name few distinct tags; anything that can publish to Redis
/// can name endless ones, and every instance kept them all.
pub(crate) const MAX_TAGS: usize = 100_000;

/// Locally observed tag generations. Redis is authoritative when configured;
/// pub/sub eagerly advances this map so L1 lookups need no Redis round-trip.
///
/// The map holds at most [`MAX_TAGS`] tags. A barrier cannot simply be
/// forgotten (an L1 entry stamped before the invalidation it records would
/// pass as current again), so at the cap the whole L1 is emptied first and
/// the map starts over: what is cached afterwards is stamped afresh.
#[derive(Clone)]
pub(crate) struct TagVersions {
    inner: Arc<Mutex<HashMap<String, u64>>>,
    /// The L1 the barriers guard, emptied when the map is reset.
    l1: L1,
    cap: usize,
}

impl TagVersions {
    pub(crate) fn new(l1: L1) -> Self {
        Self::with_cap(l1, MAX_TAGS)
    }

    pub(crate) fn with_cap(l1: L1, cap: usize) -> Self {
        TagVersions {
            inner: Arc::new(Mutex::new(HashMap::new())),
            l1,
            cap,
        }
    }

    /// Make room for `tag` in `versions`: at the cap, empty the L1 and forget
    /// every barrier (see the type docs).
    fn make_room(&self, versions: &mut HashMap<String, u64>, tag: &str) {
        if versions.len() >= self.cap && !versions.contains_key(tag) {
            tracing::warn!(
                max_tags = self.cap,
                "cache tag barriers reached their cap; emptying the local cache and starting over"
            );
            self.l1.invalidate_all();
            versions.clear();
        }
    }

    pub(crate) fn current(&self, tag: &str) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(tag)
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn snapshot(&self, tags: &[String]) -> Vec<TagStamp> {
        let versions = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tags.iter()
            .map(|tag| TagStamp {
                tag: tag.clone(),
                generation: versions.get(tag).copied().unwrap_or(0),
            })
            .collect()
    }

    /// Merge Redis's authoritative snapshot with locally newer pub/sub
    /// barriers without retaining every ordinary cache key in the local map.
    /// The map therefore grows with invalidated tags, not with all reads.
    pub(crate) fn merge_snapshot(&self, tags: &[String], remote: &[TagStamp]) -> Vec<TagStamp> {
        let versions = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tags.iter()
            .zip(remote)
            .map(|(tag, stamp)| TagStamp {
                tag: tag.clone(),
                generation: stamp
                    .generation
                    .max(versions.get(tag).copied().unwrap_or(0)),
            })
            .collect()
    }

    /// Raise each tag's barrier to its stamp. A generation above
    /// [`MAX_GENERATION`] is forged: it still reports an invalidation of the
    /// tag, so the barrier advances, but by one rather than to that value.
    pub(crate) fn observe(&self, stamps: &[TagStamp]) {
        let mut versions = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for stamp in stamps {
            self.make_room(&mut versions, &stamp.tag);
            let current = versions.entry(stamp.tag.clone()).or_default();
            if stamp.generation > MAX_GENERATION {
                tracing::warn!(
                    tag = %stamp.tag,
                    generation = stamp.generation,
                    "implausible cache tag generation; advancing the barrier by one instead"
                );
                *current = current.saturating_add(1);
            } else {
                *current = (*current).max(stamp.generation);
            }
        }
    }

    /// A peer's invalidation of `tag` at `generation`: the barrier moves past
    /// what this instance has seen even when `generation` is not above it.
    /// A peer's generations restart low once Redis lost the tag's key (a
    /// restart without persistence, an LRU eviction) and that peer starts
    /// afresh; taken as a plain maximum, its invalidations would be ignored
    /// until its counter caught up. A forged, implausibly large generation
    /// still advances the barrier by one only.
    pub(crate) fn observe_invalidation(&self, tag: &str, generation: u64) {
        let mut versions = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.make_room(&mut versions, tag);
        let current = versions.entry(tag.to_string()).or_default();
        let next = current.saturating_add(1);
        if generation > MAX_GENERATION {
            tracing::warn!(
                tag,
                generation,
                "implausible cache tag generation; advancing the barrier by one instead"
            );
            *current = next;
        } else {
            *current = next.max(generation);
        }
    }

    pub(crate) fn observe_one(&self, tag: &str, generation: u64) {
        self.observe(&[TagStamp {
            tag: tag.to_string(),
            generation,
        }]);
    }

    pub(crate) fn is_current(&self, stamps: &[TagStamp]) -> bool {
        let versions = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stamps
            .iter()
            .all(|stamp| versions.get(&stamp.tag).copied().unwrap_or(0) <= stamp.generation)
    }
}

/// Make aws-lc-rs the process-wide rustls provider unless one is set: the
/// Redis TLS connector builds its config from the process default, and with
/// more than one provider compiled in rustls cannot choose by itself.
fn install_tls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // A concurrent install winning the race is just as good.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

impl Cache {
    /// Build an **L1-only** cache. No Redis calls are ever made; the cache is
    /// still fully correct, it just rebuilds from the factory more often.
    ///
    /// `l1_max_capacity` bounds the number of entries held in process.
    pub fn l1_only(l1_max_capacity: u64) -> Self {
        Cache {
            inner: Arc::new({
                let l1 = L1::new(l1_max_capacity);
                Inner {
                    tag_versions: TagVersions::new(l1.clone()),
                    l1,
                    l2: None,
                    backplane: None,
                }
            }),
        }
    }

    /// Build a cache backed by Redis L2 **and** a pub/sub invalidation
    /// backplane, with the default [`RedisTimeouts`]. Spawns a subscriber that
    /// advances local tag barriers when another node publishes an
    /// invalidation.
    pub async fn with_redis(l1_max_capacity: u64, redis_url: &str) -> Result<Self, CacheError> {
        Self::with_redis_timeouts(l1_max_capacity, redis_url, RedisTimeouts::default()).await
    }

    /// Like [`Cache::with_redis`] with explicit Redis timeouts.
    ///
    /// Fails only on an invalid URL: connections are made lazily, so Redis
    /// need not be reachable yet (see the [crate docs](crate)). Waits a few
    /// seconds at most for the first backplane subscription.
    pub async fn with_redis_timeouts(
        l1_max_capacity: u64,
        redis_url: &str,
        timeouts: RedisTimeouts,
    ) -> Result<Self, CacheError> {
        let l1 = L1::new(l1_max_capacity);
        let tag_versions = TagVersions::new(l1.clone());
        if redis_url.starts_with("rediss://") {
            install_tls_crypto_provider();
        }
        let info = redis::IntoConnectionInfo::into_connection_info(redis_url)?
            .set_tcp_settings(tcp_settings());
        let client = redis::Client::open(info)?;

        let l2 = RedisL2::connect(client.clone(), timeouts)?;
        let backplane = Backplane::start(
            client,
            l2.clone(),
            l1.clone(),
            tag_versions.clone(),
            timeouts,
        )
        .await?;

        Ok(Cache {
            inner: Arc::new(Inner {
                l1,
                l2: Some(l2),
                backplane: Some(backplane),
                tag_versions,
            }),
        })
    }

    /// Look up `(ns, key)`, computing-and-caching via `factory` on a miss.
    ///
    /// Lookup order is **L1 → L2 (if present) → factory**. On a factory success
    /// the value is written to L1 (and L2, if present) with `ttl`. Concurrent
    /// callers for the same `(ns, key)` run the factory **once** (request
    /// coalescing — see the crate docs). A caller never gets a value computed
    /// before an invalidation this instance had already applied when the
    /// call started: coalesced onto such a fill, it loads again.
    ///
    /// A factory `Err(E)` is returned to the caller and **not** cached.
    pub async fn get_or_try_insert_with<T, F, Fut, E>(
        &self,
        ns: &str,
        key: &str,
        ttl: Duration,
        factory: F,
    ) -> Result<T, E>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        // `E: Clone + Send + Sync + 'static` is required by moka's `try_get_with`,
        // which hands every coalesced waiter a shared `Arc<E>` on a failing load;
        // we clone the inner error out for each caller (and cache nothing).
        E: Clone + Send + Sync + 'static,
    {
        self.get_or_try_insert_with_tags(ns, key, &[], ttl, factory)
            .await
    }

    /// Look up `(ns, key)` with additional logical tags attached to the entry.
    /// [`Cache::invalidate_tag`] expires every entry in the same namespace that
    /// carries a matching tag without scanning L1 or Redis keys.
    pub async fn get_or_try_insert_with_tags<T, F, Fut, E>(
        &self,
        ns: &str,
        key: &str,
        tags: &[String],
        ttl: Duration,
        factory: F,
    ) -> Result<T, E>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: Clone + Send + Sync + 'static,
    {
        self.load(ns, key, tags, ttl, factory, true).await
    }

    /// Like [`Cache::get_or_try_insert_with`], but the value is cached **in
    /// this process only**: never read from or written to Redis, so nobody
    /// with access to Redis can supply it. Invalidations still propagate over
    /// the backplane. Use it for every value a security decision rests on
    /// (see the [crate docs](crate#local-only-entries-redis-is-a-trust-boundary)).
    pub async fn get_or_try_insert_local<T, F, Fut, E>(
        &self,
        ns: &str,
        key: &str,
        ttl: Duration,
        factory: F,
    ) -> Result<T, E>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: Clone + Send + Sync + 'static,
    {
        self.load(ns, key, &[], ttl, factory, false).await
    }

    /// [`Cache::get_or_try_insert_local`] with logical tags, like
    /// [`Cache::get_or_try_insert_with_tags`].
    pub async fn get_or_try_insert_local_with_tags<T, F, Fut, E>(
        &self,
        ns: &str,
        key: &str,
        tags: &[String],
        ttl: Duration,
        factory: F,
    ) -> Result<T, E>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: Clone + Send + Sync + 'static,
    {
        self.load(ns, key, tags, ttl, factory, false).await
    }

    /// [`Cache::get_or_try_insert_local_with_tags`] for a value whose own
    /// lifetime the factory knows: it returns the value with how long it may
    /// live, and the entry expires after the shorter of that and `ttl` (counted
    /// from the start of the fill). For a value copied from a record that
    /// expires on its own (a stored verdict nearer its expiry than `ttl`), or
    /// for values of one kind that deserve different TTLs.
    pub async fn get_or_try_insert_local_with_tags_expiring<T, F, Fut, E>(
        &self,
        ns: &str,
        key: &str,
        tags: &[String],
        ttl: Duration,
        factory: F,
    ) -> Result<T, E>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(T, Duration), E>>,
        E: Clone + Send + Sync + 'static,
    {
        self.load_with_lifetime(
            ns,
            key,
            tags,
            ttl,
            || async move {
                factory()
                    .await
                    .map(|(value, lifetime)| (value, Some(lifetime)))
            },
            false,
        )
        .await
    }

    /// The shared lookup: L1 → (L2, when `shared` and configured) → factory.
    async fn load<T, F, Fut, E>(
        &self,
        ns: &str,
        key: &str,
        tags: &[String],
        ttl: Duration,
        factory: F,
        shared: bool,
    ) -> Result<T, E>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: Clone + Send + Sync + 'static,
    {
        self.load_with_lifetime(
            ns,
            key,
            tags,
            ttl,
            || async move { factory().await.map(|value| (value, None)) },
            shared,
        )
        .await
    }

    /// [`Cache::load`] for a factory that may cap its value's lifetime.
    async fn load_with_lifetime<T, F, Fut, E>(
        &self,
        ns: &str,
        key: &str,
        tags: &[String],
        ttl: Duration,
        factory: F,
        shared: bool,
    ) -> Result<T, E>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(T, Option<Duration>), E>>,
        E: Clone + Send + Sync + 'static,
    {
        let full_key = make_key(ns, key);
        let entry_tags = Arc::new(entry_tags(ns, key, tags));
        // The barriers this caller has already observed: a value stamped
        // older than these predates an invalidation applied before the call.
        let seen = self.inner.tag_versions.snapshot(&entry_tags);
        let mut factory = Some(factory);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let unused_factory = &mut factory;
            let entry = self
                .fill(&full_key, &entry_tags, ttl, shared, move || {
                    unused_factory.take()
                })
                .await?;

            // A remote tag bump may have raced the completed factory. Never
            // leave such a result resident in L1; the in-progress caller may
            // still use the value it started computing before the invalidation
            // linearized. Only the *resident* entry is checked before
            // evicting: a concurrent task may already have refilled the key
            // with a fresh post-bump entry, which must survive.
            if !self.inner.tag_versions.is_current(&entry.tags) {
                self.inner
                    .l1
                    .invalidate_if_stale(&full_key, &self.inner.tag_versions)
                    .await;
            }

            // Coalesced onto another caller's fill that captured its stamps
            // before an invalidation this caller had already seen: load again
            // (this call's factory is still unused then).
            let predates_call = entry
                .tags
                .iter()
                .zip(&seen)
                .any(|(stamp, seen)| stamp.generation < seen.generation);
            if predates_call && factory.is_some() && attempt < MAX_LOAD_ATTEMPTS {
                continue;
            }

            let value: T = serde_json::from_slice(&entry.value)
                .expect("cached JSON bytes must deserialize back into T");
            return Ok(value);
        }
    }

    /// One coalesced lookup: L1 → (L2, when `shared` and configured) →
    /// `factory`, run by whichever caller's init moka picks. `take_factory`
    /// hands over this caller's factory when its init runs.
    async fn fill<T, F, Fut, E>(
        &self,
        full_key: &str,
        entry_tags: &Arc<Vec<String>>,
        ttl: Duration,
        shared: bool,
        take_factory: impl FnOnce() -> Option<F>,
    ) -> Result<Arc<StoredEntry>, E>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(T, Option<Duration>), E>>,
        E: Clone + Send + Sync + 'static,
    {
        let entry_tags = entry_tags.clone();
        let l2 = if shared { self.inner.l2.clone() } else { None };
        let tag_versions = self.inner.tag_versions.clone();

        // moka's `try_get_with` coalesces concurrent loads for `full_key` and
        // caches only on `Ok`. The init future does: L2 lookup → factory, and
        // writes L2 on a factory hit. We then deserialize the resulting bytes.
        //
        // The init future's error type is the *factory's* error `E` (wrapped by
        // moka in an `Arc`). L2 infrastructure errors never become `E`: they are
        // logged inside the future and we fall through to the factory.
        let key_for_l2 = full_key.to_string();
        // Set by the init, which runs on an L1 miss only.
        let missed = Arc::new(AtomicBool::new(false));
        let init_missed = missed.clone();
        let result = self
            .inner
            .l1
            .try_get_entry_with(
                full_key.to_string(),
                ttl,
                entry_tags.clone(),
                tag_versions.clone(),
                move || async move {
                init_missed.store(true, Ordering::Relaxed);
                let factory = take_factory()
                    .expect("a caller's factory is taken only by its own, single init");
                // L2 read (graceful degradation on infra error → None → factory).
                if let Some(l2) = &l2 {
                    match l2.get(&key_for_l2).await {
                        Ok(Some(bytes)) => {
                            match serde_json::from_slice::<StoredEntry>(&bytes) {
                                Ok(candidate) if candidate.has_tags(&entry_tags) => {
                                    match l2.tag_versions(&entry_tags).await {
                                        Ok(stamps) => {
                                            let current =
                                                tag_versions.merge_snapshot(&entry_tags, &stamps);
                                            // Only an entry whose payload decodes
                                            // as `T` is a hit: a shared Redis, a
                                            // changed type after an upgrade, or a
                                            // tampered value must degrade to a
                                            // miss, not panic the decode below.
                                            if candidate.tags == current
                                                && serde_json::from_slice::<T>(&candidate.value)
                                                    .is_ok()
                                            {
                                                forge_telemetry::cache::lookup(Tier::L2, true);
                                                return Ok(Arc::new(candidate));
                                            }
                                            if candidate.tags == current {
                                                tracing::warn!(key = %key_for_l2, "L2 entry does not decode as the expected type; refilling");
                                            }
                                            if let Err(err) = l2.del(&key_for_l2).await {
                                                tracing::warn!(error = %err, key = %key_for_l2, "stale tagged L2 entry cleanup failed");
                                            }
                                        }
                                        Err(err) => {
                                            tracing::warn!(error = %err, key = %key_for_l2, "tag generation read failed; ignoring L2 entry");
                                        }
                                    }
                                }
                                Ok(candidate)
                                    if candidate.format_version == ENTRY_FORMAT_VERSION =>
                                {
                                    // A current-format envelope stamped with a
                                    // *different* tag set: another code version
                                    // (or call site) owns this (ns, key) with
                                    // its own tags. Treat it as a miss but
                                    // leave it in place — deleting here would
                                    // make both versions perpetually destroy
                                    // each other's valid entries during a
                                    // rolling deploy. Our conditional write
                                    // below simply replaces it.
                                }
                                Ok(_) | Err(_) => {
                                    // Not a current-format envelope (another format
                                    // version, or a value that is no envelope). Treat
                                    // it as a miss; the next successful fill replaces it
                                    // with a tagged envelope.
                                    if let Err(err) = l2.del(&key_for_l2).await {
                                        tracing::warn!(error = %err, key = %key_for_l2, "unreadable L2 entry cleanup failed");
                                    }
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(err) => {
                            tracing::warn!(error = %err, key = %key_for_l2, "L2 get failed; falling through to factory");
                        }
                    }
                    forge_telemetry::cache::lookup(Tier::L2, false);
                }

                let (stamps, redis_generations_available) = if let Some(l2) = &l2 {
                    match l2.tag_versions(&entry_tags).await {
                        Ok(remote) => {
                            let merged = tag_versions.merge_snapshot(&entry_tags, &remote);
                            // Heal a Redis that fell behind locally observed
                            // barriers (a bump that failed after pub/sub already
                            // advanced them): raise each lagging tag so the
                            // conditional write below — and every peer's — can
                            // succeed again instead of being rejected until the
                            // next invalidation.
                            for (stamp, seen) in merged.iter().zip(&remote) {
                                if stamp.generation > seen.generation {
                                    if let Err(err) =
                                        l2.raise_tag(&stamp.tag, stamp.generation).await
                                    {
                                        tracing::warn!(error = %err, tag = %stamp.tag, "raising lagging Redis tag generation failed");
                                    }
                                }
                            }
                            (merged, true)
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, key = %key_for_l2, "tag generation read failed; filling L1 only");
                            (tag_versions.snapshot(&entry_tags), false)
                        }
                    }
                } else {
                    (tag_versions.snapshot(&entry_tags), false)
                };

                // Factory: errors propagate (and are NOT cached by moka).
                let (value, lifetime) = factory().await?;
                let value = serde_json::to_vec(&value)
                    .expect("cache value must serialize to JSON");
                let lifetime = lifetime.filter(|lifetime| *lifetime < ttl);
                let entry = Arc::new(StoredEntry {
                    format_version: ENTRY_FORMAT_VERSION,
                    tags: stamps,
                    value,
                    lifetime,
                });
                let l2_ttl = lifetime.unwrap_or(ttl);

                // Redis compares every captured tag generation atomically before
                // writing. If an invalidation raced the factory, the stale value
                // is returned to the already-running caller but is not persisted.
                // A value with no lifetime left is not written at all.
                if redis_generations_available && !l2_ttl.is_zero() {
                    if let Some(l2) = &l2 {
                        let encoded = serde_json::to_vec(entry.as_ref())
                            .expect("tagged cache entry must serialize to JSON");
                        match l2
                            .set_if_tag_versions(&key_for_l2, &encoded, l2_ttl, &entry.tags)
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                if let Ok(current) = l2.tag_versions(&entry_tags).await {
                                    tag_versions.observe(&current);
                                }
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, key = %key_for_l2, "conditional L2 set failed; entry cached in L1 only");
                            }
                        }
                    }
                }

                Ok(entry)
            },
            )
            .await;
        // A caller coalesced onto another's fill counts as a hit: it did not
        // fill.
        forge_telemetry::cache::lookup(Tier::L1, !missed.load(Ordering::Relaxed));
        result
    }

    /// Whether the Redis invalidation backplane is subscribed: `None`
    /// without Redis.
    pub fn backplane_subscribed(&self) -> Option<bool> {
        self.inner.backplane.as_ref().map(Backplane::is_subscribed)
    }

    /// Invalidate a single `(ns, key)` by advancing its synthetic key tag and
    /// publishing the new generation.
    pub async fn invalidate(&self, ns: &str, key: &str) {
        self.invalidate_internal_tag(ns, &key_tag(ns, key)).await;
    }

    /// Invalidate an entire namespace by advancing one passive namespace tag.
    /// No L1 walk or Redis `SCAN` is required.
    pub async fn invalidate_ns(&self, ns: &str) {
        self.invalidate_internal_tag(ns, &namespace_tag(ns)).await;
    }

    /// Invalidate every entry in `ns` carrying `tag`. The operation increments a
    /// single passive barrier and publishes it; it never scans cache entries.
    pub async fn invalidate_tag(&self, ns: &str, tag: &str) {
        self.invalidate_internal_tag(ns, &custom_tag(ns, tag)).await;
    }

    async fn invalidate_internal_tag(&self, ns: &str, tag: &str) {
        forge_telemetry::cache::invalidation_sent();
        // Raise the local barrier first: from here on this instance hides
        // every entry stamped before it, whatever Redis does next. No lock is
        // held across the Redis round-trips below (see the crate docs).
        let current = self.inner.tag_versions.current(tag);
        self.inner
            .tag_versions
            .observe_one(tag, current.saturating_add(1));
        let generation = if let Some(l2) = &self.inner.l2 {
            match l2.bump_tag(tag, current).await {
                Ok(generation) => generation,
                Err(err) => {
                    // The locally advanced generation is still published below;
                    // the next fill that sees Redis lagging raises it to catch
                    // up (see `raise_tag`), so this stays a transient gap.
                    // This instance's map may lag Redis, though: an entry
                    // stamped with a newer Redis generation would survive the
                    // local barrier, so drop L1 rather than serve it.
                    tracing::warn!(error = %err, ns, tag, "Redis tag bump failed; flushed L1, invalidation is local/backplane-only until Redis recovers");
                    self.inner.l1.invalidate_all();
                    current.saturating_add(1)
                }
            }
        } else {
            current.saturating_add(1)
        };
        self.inner.tag_versions.observe_one(tag, generation);
        if let Some(bp) = &self.inner.backplane {
            bp.publish_tag(ns, tag, generation).await;
        }
    }
}

/// Build the flat L1/L2 key from a namespace and key.
fn make_key(ns: &str, key: &str) -> String {
    format!("{ns}:{key}")
}

pub(crate) fn namespace_tag(ns: &str) -> String {
    format!("@ns:{ns}")
}

pub(crate) fn key_tag(ns: &str, key: &str) -> String {
    format!("@key:{ns}:{key}")
}

fn custom_tag(ns: &str, tag: &str) -> String {
    format!("@tag:{ns}:{tag}")
}

fn entry_tags(ns: &str, key: &str, custom: &[String]) -> Vec<String> {
    let mut tags = Vec::with_capacity(custom.len() + 2);
    tags.push(namespace_tag(ns));
    tags.push(key_tag(ns, key));
    tags.extend(custom.iter().map(|tag| custom_tag(ns, tag)));
    tags.sort();
    tags.dedup();
    tags
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// #126: forged invalidations naming ever new tags keep the barrier map
    /// at its cap. At the cap the L1 is emptied before the barriers are
    /// forgotten, so no entry stamped before a forgotten barrier is served
    /// again, and a real invalidation still applies afterwards.
    #[tokio::test]
    async fn tag_barriers_stay_bounded_and_flush_the_l1_at_the_cap() {
        let cache = Cache::l1_only(100);
        let calls = Arc::new(AtomicUsize::new(0));
        let read = || {
            let (cache, calls) = (cache.clone(), calls.clone());
            async move {
                cache
                    .get_or_try_insert_local::<usize, _, _, ()>(
                        "ns",
                        "key",
                        Duration::from_secs(600),
                        || async move { Ok(calls.fetch_add(1, Ordering::SeqCst)) },
                    )
                    .await
                    .unwrap()
            }
        };
        assert_eq!(read().await, 0);
        assert_eq!(read().await, 0, "cached");

        let versions = &cache.inner.tag_versions;
        for i in 0..1_000_000 {
            versions.observe_invalidation(&format!("forged-{i}"), 1);
        }
        assert!(versions.inner.lock().unwrap().len() <= MAX_TAGS);
        assert_eq!(read().await, 1, "the L1 was emptied at the cap");
        assert_eq!(read().await, 1, "and caches again");

        cache.invalidate_ns("ns").await;
        assert_eq!(read().await, 2, "a real invalidation still applies");
    }
}
