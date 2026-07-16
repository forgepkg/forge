//! `forge-cache` — a HybridCache analogue (design spec §2.1).
//!
//! A two-tier cache that is **generic over value types via `serde`**:
//!
//! * **L1** — an in-process [`moka`](https://docs.rs/moka) cache (size-bounded,
//!   per-entry TTL). Always present.
//! * **L2** — an *optional* Redis cache (shared across instances). When absent
//!   the cache is still fully correct — it just rebuilds from the factory more
//!   often (the "default-correct" mode from the spec).
//! * **Backplane** — an *optional* Redis pub/sub channel that broadcasts
//!   invalidations so every instance drops the stale L1 entry. Only present when
//!   L2 is.
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
//! single moka cache keyed by the string `"{ns}:{key}"`. Each L1 entry is a
//! [`L1Entry`] holding the deadline plus the shared bytes.
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
use serde::Serialize;

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
        Cache {
            inner: Arc::new(Inner {
                l1: L1::new(l1_max_capacity),
                l2: None,
                backplane: None,
                namespace_locks,
            }),
        }
    }

    /// Build a cache backed by Redis L2 **and** a pub/sub invalidation
    /// backplane. Spawns a background subscriber task that drops matching L1
    /// entries when another node publishes an invalidation.
    pub async fn with_redis(l1_max_capacity: u64, redis_url: &str) -> Result<Self, CacheError> {
        let l1 = L1::new(l1_max_capacity);
        let namespace_locks = NamespaceLocks::default();
        let client = redis::Client::open(redis_url)?;

        let l2 = RedisL2::connect(client.clone()).await?;
        let backplane =
            Backplane::start(client, l1.clone(), l2.clone(), namespace_locks.clone()).await?;

        Ok(Cache {
            inner: Arc::new(Inner {
                l1,
                l2: Some(l2),
                backplane: Some(backplane),
                namespace_locks,
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
        let namespace_lock = self.inner.namespace_locks.get(ns);
        let _fill_guard = namespace_lock.read().await;
        let full_key = make_key(ns, key);
        let l2 = self.inner.l2.clone();

        // moka's `try_get_with` coalesces concurrent loads for `full_key` and
        // caches only on `Ok`. The init future does: L2 lookup → factory, and
        // writes L2 on a factory hit. We then deserialize the resulting bytes.
        //
        // The init future's error type is the *factory's* error `E` (wrapped by
        // moka in an `Arc`). L2 infrastructure errors never become `E`: they are
        // logged inside the future and we fall through to the factory.
        let key_for_l2 = full_key.clone();
        let bytes = self
            .inner
            .l1
            .try_get_bytes_with(full_key, ttl, || async move {
                // L2 read (graceful degradation on infra error → None → factory).
                if let Some(l2) = &l2 {
                    match l2.get(&key_for_l2).await {
                        Ok(Some(bytes)) => return Ok(bytes),
                        Ok(None) => {}
                        Err(err) => {
                            tracing::warn!(error = %err, key = %key_for_l2, "L2 get failed; falling through to factory");
                        }
                    }
                }

                // Factory: errors propagate (and are NOT cached by moka).
                let value = factory().await?;
                let bytes = serde_json::to_vec(&value)
                    .expect("cache value must serialize to JSON");
                let bytes = Arc::new(bytes);

                // L2 write (graceful degradation on infra error → log + skip).
                if let Some(l2) = &l2 {
                    if let Err(err) = l2.set(&key_for_l2, &bytes, ttl).await {
                        tracing::warn!(error = %err, key = %key_for_l2, "L2 set failed; entry cached in L1 only");
                    }
                }

                Ok(bytes)
            })
            .await?;

        let value: T =
            serde_json::from_slice(&bytes).expect("cached JSON bytes must deserialize back into T");
        Ok(value)
    }

    /// Invalidate a single `(ns, key)`: fence older local fills, drop from L1
    /// and L2, and publish on the backplane so peers fence their own older fills
    /// before re-dropping both tiers.
    pub async fn invalidate(&self, ns: &str, key: &str) {
        let namespace_lock = self.inner.namespace_locks.get(ns);
        let _invalidation_guard = namespace_lock.write().await;
        let full_key = make_key(ns, key);
        self.inner.l1.invalidate(&full_key).await;

        if let Some(l2) = &self.inner.l2 {
            if let Err(err) = l2.del(&full_key).await {
                tracing::warn!(error = %err, key = %full_key, "L2 del failed during invalidate");
            }
        }
        if let Some(bp) = &self.inner.backplane {
            bp.publish_key(&full_key).await;
        }
    }

    /// Invalidate an entire namespace: fence older local fills, drop all
    /// `ns:*` entries from L1 and L2, and broadcast the fenced invalidation on
    /// the backplane.
    pub async fn invalidate_ns(&self, ns: &str) {
        let namespace_lock = self.inner.namespace_locks.get(ns);
        let _invalidation_guard = namespace_lock.write().await;
        let prefix = format!("{ns}:");
        self.inner.l1.invalidate_prefix(&prefix).await;

        if let Some(l2) = &self.inner.l2 {
            if let Err(err) = l2.del_ns(ns).await {
                tracing::warn!(error = %err, ns = %ns, "L2 ns-del failed during invalidate_ns");
            }
        }
        if let Some(bp) = &self.inner.backplane {
            bp.publish_ns(ns).await;
        }
    }
}

/// Build the flat L1/L2 key from a namespace and key.
fn make_key(ns: &str, key: &str) -> String {
    format!("{ns}:{key}")
}
