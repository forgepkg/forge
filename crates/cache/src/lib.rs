//! `forge-cache` — a HybridCache analogue (design spec §2.1).
//!
//! A two-tier cache that is **generic over value types via `serde`**:
//!
//! * **L1** — an in-process [`moka`](https://docs.rs/moka) cache (size-bounded,
//!   per-entry TTL). Always present.
//! * **L2** — an *optional* Redis cache (shared across instances). When absent
//!   the cache is still fully correct — it just rebuilds from the factory more
//!   often (the "default-correct" mode from the spec).
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
//! ## Graceful L2 degradation vs. factory errors
//!
//! An L2 (Redis) failure is a *cache* failure, never a source-of-truth failure:
//! on an L2 get/set/publish error we log and fall through (read → factory,
//! write → skip). A **factory** error, by contrast, is propagated to the caller
//! verbatim and is *not* cached — the next call retries.

mod backplane;
mod l1;
mod l2_redis;

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::backplane::Backplane;
use crate::l1::L1;
use crate::l2_redis::RedisL2;

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
    namespace_locks: NamespaceLocks,
    tag_versions: TagVersions,
}

const ENTRY_FORMAT_VERSION: u8 = 1;

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
}

impl StoredEntry {
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
    pub(crate) fn manager_config(&self) -> redis::aio::ConnectionManagerConfig {
        redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(self.connect))
            .set_response_timeout(Some(self.response))
    }
}

/// Locally observed tag generations. Redis is authoritative when configured;
/// pub/sub eagerly advances this map so L1 lookups need no Redis round-trip.
#[derive(Clone, Default)]
pub(crate) struct TagVersions {
    inner: Arc<Mutex<HashMap<String, u64>>>,
}

impl TagVersions {
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

    pub(crate) fn observe(&self, stamps: &[TagStamp]) {
        let mut versions = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for stamp in stamps {
            let current = versions.entry(stamp.tag.clone()).or_default();
            *current = (*current).max(stamp.generation);
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

/// Per-namespace read/write fences. Cache fills take a shared guard while
/// invalidations take an exclusive guard, so a fill that started before a
/// revocation cannot publish a stale L1/L2 value after that revocation has
/// completed. The same locks are used by the Redis backplane subscriber.
#[derive(Clone, Default)]
pub(crate) struct NamespaceLocks {
    inner: Arc<Mutex<HashMap<String, Arc<tokio::sync::RwLock<()>>>>>,
}

impl NamespaceLocks {
    pub(crate) fn get(&self, ns: &str) -> Arc<tokio::sync::RwLock<()>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(ns.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(())))
            .clone()
    }
}

impl Cache {
    /// Build an **L1-only** cache. No Redis calls are ever made; this is the
    /// default-correct mode from the spec.
    ///
    /// `l1_max_capacity` bounds the number of entries held in process.
    pub fn l1_only(l1_max_capacity: u64) -> Self {
        let namespace_locks = NamespaceLocks::default();
        let tag_versions = TagVersions::default();
        Cache {
            inner: Arc::new(Inner {
                l1: L1::new(l1_max_capacity),
                l2: None,
                backplane: None,
                namespace_locks,
                tag_versions,
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
    pub async fn with_redis_timeouts(
        l1_max_capacity: u64,
        redis_url: &str,
        timeouts: RedisTimeouts,
    ) -> Result<Self, CacheError> {
        let l1 = L1::new(l1_max_capacity);
        let namespace_locks = NamespaceLocks::default();
        let tag_versions = TagVersions::default();
        let client = redis::Client::open(redis_url)?;

        let l2 = RedisL2::connect(client.clone(), timeouts).await?;
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
                namespace_locks,
                tag_versions,
            }),
        })
    }

    /// Look up `(ns, key)`, computing-and-caching via `factory` on a miss.
    ///
    /// Lookup order is **L1 → L2 (if present) → factory**. On a factory success
    /// the value is written to L1 (and L2, if present) with `ttl`. Concurrent
    /// callers for the same `(ns, key)` run the factory **once** (request
    /// coalescing — see the crate docs).
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
        let namespace_lock = self.inner.namespace_locks.get(ns);
        let _fill_guard = namespace_lock.read().await;
        let full_key = make_key(ns, key);
        let entry_tags = Arc::new(entry_tags(ns, key, tags));
        let l2 = self.inner.l2.clone();
        let tag_versions = self.inner.tag_versions.clone();

        // moka's `try_get_with` coalesces concurrent loads for `full_key` and
        // caches only on `Ok`. The init future does: L2 lookup → factory, and
        // writes L2 on a factory hit. We then deserialize the resulting bytes.
        //
        // The init future's error type is the *factory's* error `E` (wrapped by
        // moka in an `Arc`). L2 infrastructure errors never become `E`: they are
        // logged inside the future and we fall through to the factory.
        let key_for_l2 = full_key.clone();
        let entry = self
            .inner
            .l1
            .try_get_entry_with(
                full_key.clone(),
                ttl,
                entry_tags.clone(),
                tag_versions.clone(),
                || async move {
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
                                    // Rolling upgrades can encounter the former raw-value
                                    // format. Treat it as a miss; the next successful fill
                                    // replaces it with a tagged envelope.
                                    if let Err(err) = l2.del(&key_for_l2).await {
                                        tracing::warn!(error = %err, key = %key_for_l2, "legacy L2 entry cleanup failed");
                                    }
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(err) => {
                            tracing::warn!(error = %err, key = %key_for_l2, "L2 get failed; falling through to factory");
                        }
                    }
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
                let value = factory().await?;
                let value = serde_json::to_vec(&value)
                    .expect("cache value must serialize to JSON");
                let entry = Arc::new(StoredEntry {
                    format_version: ENTRY_FORMAT_VERSION,
                    tags: stamps,
                    value,
                });

                // Redis compares every captured tag generation atomically before
                // writing. If an invalidation raced the factory, the stale value
                // is returned to the already-running caller but is not persisted.
                if redis_generations_available {
                    if let Some(l2) = &l2 {
                        let encoded = serde_json::to_vec(entry.as_ref())
                            .expect("tagged cache entry must serialize to JSON");
                        match l2
                            .set_if_tag_versions(&key_for_l2, &encoded, ttl, &entry.tags)
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
            .await?;

        // A remote tag bump may have raced the completed factory. Never leave
        // such a result resident in L1; the in-progress caller may still use the
        // value it started computing before the invalidation linearized. Only
        // the *resident* entry is checked before evicting: a concurrent task may
        // already have refilled the key with a fresh post-bump entry, which must
        // survive.
        if !self.inner.tag_versions.is_current(&entry.tags) {
            self.inner
                .l1
                .invalidate_if_stale(&full_key, &self.inner.tag_versions)
                .await;
        }

        let value: T = serde_json::from_slice(&entry.value)
            .expect("cached JSON bytes must deserialize back into T");
        Ok(value)
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
        let namespace_lock = self.inner.namespace_locks.get(ns);
        let _invalidation_guard = namespace_lock.write().await;
        let current = self.inner.tag_versions.current(tag);
        let generation = if let Some(l2) = &self.inner.l2 {
            match l2.bump_tag(tag, current).await {
                Ok(generation) => generation,
                Err(err) => {
                    // The locally advanced generation is still published below;
                    // the next fill that sees Redis lagging raises it to catch
                    // up (see `raise_tag`), so this stays a transient gap.
                    tracing::warn!(error = %err, ns, tag, "Redis tag bump failed; invalidation is local/backplane-only until Redis recovers");
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
