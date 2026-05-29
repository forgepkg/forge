//! L1 — the in-process [`moka`] tier.
//!
//! Stores [`L1Entry`] values (deadline + shared JSON bytes) in a single moka
//! cache keyed by the flat `"{ns}:{key}"` string. Coalescing of concurrent
//! loads is delegated to moka's [`try_get_with`](moka::future::Cache::try_get_with).
//!
//! TTL is enforced two ways (see crate docs): a moka [`Expiry`] bounds memory by
//! evicting in the background, and an absolute `expires_at` stamp lets reads
//! treat a past-deadline entry as a miss deterministically.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache as MokaCache;
use moka::Expiry;
use tokio::time::Instant;

/// One cached entry: its absolute expiry deadline and the shared JSON bytes.
#[derive(Clone)]
pub struct L1Entry {
    expires_at: Instant,
    bytes: Arc<Vec<u8>>,
}

impl L1Entry {
    fn ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Per-entry expiry driver: tells moka to evict each entry at its own deadline.
struct PerEntryExpiry;

impl Expiry<String, L1Entry> for PerEntryExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &L1Entry,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl())
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &L1Entry,
        _updated_at: std::time::Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl())
    }
}

/// The L1 tier. Cheaply [`Clone`]able (moka caches share state via `Arc`).
#[derive(Clone)]
pub struct L1 {
    cache: MokaCache<String, L1Entry>,
}

impl L1 {
    pub fn new(max_capacity: u64) -> Self {
        let cache = MokaCache::builder()
            .max_capacity(max_capacity)
            // Required for `invalidate_entries_if` (namespace invalidation).
            .support_invalidation_closures()
            .expire_after(PerEntryExpiry)
            .build();
        L1 { cache }
    }

    /// Coalesced get-or-insert. Runs `init` at most once across concurrent
    /// callers for `full_key`; on `init` error nothing is cached and the error
    /// propagates. An entry already present but past its deadline is treated as
    /// a miss (it is invalidated and `init` re-runs).
    pub async fn try_get_bytes_with<F, Fut, E>(
        &self,
        full_key: String,
        ttl: Duration,
        init: F,
    ) -> Result<Arc<Vec<u8>>, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Arc<Vec<u8>>, E>>,
        E: Clone + Send + Sync + 'static,
    {
        // Fast path: a live entry already present. (`try_get_with` would also
        // return it, but checking here lets us detect a *stale* entry and force
        // a re-run rather than serving expired bytes.)
        if let Some(entry) = self.cache.get(&full_key).await {
            if entry.is_expired() {
                self.cache.invalidate(&full_key).await;
            } else {
                return Ok(entry.bytes);
            }
        }

        let expires_at = Instant::now() + ttl;
        let entry = self
            .cache
            .try_get_with(full_key, async move {
                let bytes = init().await?;
                Ok::<L1Entry, E>(L1Entry { expires_at, bytes })
            })
            .await
            // moka wraps the init (factory) error in an `Arc<E>` because every
            // coalesced waiter that observed the *same* failing load shares it.
            // We therefore clone the inner `E` out (hence the `E: Clone` bound).
            // Crucially, on this error path moka has NOT cached anything, so the
            // next call re-runs the factory.
            .map_err(|arc_err| (*arc_err).clone())?;

        Ok(entry.bytes)
    }

    /// Drop a single entry from L1.
    pub async fn invalidate(&self, full_key: &str) {
        self.cache.invalidate(full_key).await;
    }

    /// Drop every entry whose key begins with `prefix` (i.e. `"{ns}:"`).
    ///
    /// moka removes the matched entries during a maintenance pass, but its
    /// retrieval methods already refuse to return values that match a registered
    /// predicate — so reads observe the invalidation immediately. We still run
    /// pending tasks to make the eviction deterministic for callers/tests.
    pub async fn invalidate_prefix(&self, prefix: &str) {
        let prefix = prefix.to_string();
        if let Err(err) = self
            .cache
            .invalidate_entries_if(move |k, _v| k.starts_with(&prefix))
        {
            tracing::error!(error = %err, "L1 prefix invalidation closure rejected");
            return;
        }
        self.cache.run_pending_tasks().await;
    }
}
