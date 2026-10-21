//! L1 — the in-process [`moka`] tier.
//!
//! Stores [`L1Entry`] values (deadline + tagged entry) in a single moka
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

use crate::{StoredEntry, TagVersions};

/// One cached entry: its absolute expiry deadline and the shared JSON bytes.
#[derive(Clone)]
pub struct L1Entry {
    expires_at: Instant,
    entry: Arc<StoredEntry>,
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

/// The bytes one unit of the L1's capacity stands for.
pub const WEIGHT_UNIT_BYTES: usize = 16 * 1024;

/// The L1 tier. Cheaply [`Clone`]able (moka caches share state via `Arc`).
#[derive(Clone)]
pub struct L1 {
    cache: MokaCache<String, L1Entry>,
}

impl L1 {
    /// Drop every entry (used after the invalidation backplane was
    /// disconnected: invalidations published meanwhile were missed).
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// An L1 of `max_capacity` entries, an entry larger than
    /// [`WEIGHT_UNIT_BYTES`] counting once per started unit: small values
    /// (verdicts, version lists) count once, and a multi-megabyte document
    /// counts as the many entries its memory could hold, so the capacity
    /// bounds memory as well as the entry count.
    pub fn new(max_capacity: u64) -> Self {
        let cache = MokaCache::builder()
            .max_capacity(max_capacity)
            .weigher(|key: &String, value: &L1Entry| {
                let bytes = key.len() + value.entry.weight_bytes();
                u32::try_from(bytes.div_ceil(WEIGHT_UNIT_BYTES).max(1)).unwrap_or(u32::MAX)
            })
            .expire_after(PerEntryExpiry)
            .build();
        L1 { cache }
    }

    /// Coalesced get-or-insert. Runs `init` at most once across concurrent
    /// callers for `full_key`; on `init` error nothing is cached and the error
    /// propagates. An entry already present but past its deadline is treated as
    /// a miss (it is invalidated and `init` re-runs).
    pub async fn try_get_entry_with<F, Fut, E>(
        &self,
        full_key: String,
        ttl: Duration,
        expected_tags: Arc<Vec<String>>,
        tag_versions: TagVersions,
        init: F,
    ) -> Result<Arc<StoredEntry>, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Arc<StoredEntry>, E>>,
        E: Clone + Send + Sync + 'static,
    {
        // Fast path: a live entry already present. (`try_get_with` would also
        // return it, but checking here lets us detect a *stale* entry and force
        // a re-run rather than serving expired bytes.)
        if let Some(entry) = self.cache.get(&full_key).await {
            if entry.is_expired()
                || !entry.entry.has_tags(&expected_tags)
                || !tag_versions.is_current(&entry.entry.tags)
            {
                self.cache.invalidate(&full_key).await;
            } else {
                return Ok(entry.entry);
            }
        }

        let started = Instant::now();
        let entry = self
            .cache
            .try_get_with(full_key, async move {
                let entry = init().await?;
                // A factory-chosen lifetime only ever shortens the TTL.
                let expires_at = started + entry.lifetime().map_or(ttl, |l| l.min(ttl));
                Ok::<L1Entry, E>(L1Entry { expires_at, entry })
            })
            .await
            // moka wraps the init (factory) error in an `Arc<E>` because every
            // coalesced waiter that observed the *same* failing load shares it.
            // We therefore clone the inner `E` out (hence the `E: Clone` bound).
            // Crucially, on this error path moka has NOT cached anything, so the
            // next call re-runs the factory.
            .map_err(|arc_err| (*arc_err).clone())?;

        Ok(entry.entry)
    }

    /// Drop the resident entry only when *it* is stamped behind the current tag
    /// barriers. Used by the post-fill staleness check: the fill that raced an
    /// invalidation must not evict a fresh entry a concurrent task already
    /// refilled under the new generation.
    pub async fn invalidate_if_stale(&self, full_key: &str, tag_versions: &TagVersions) {
        if let Some(resident) = self.cache.get(full_key).await {
            if !tag_versions.is_current(&resident.entry.tags) {
                self.cache.invalidate(full_key).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StoredEntry, ENTRY_FORMAT_VERSION};

    fn entry(bytes: usize) -> L1Entry {
        L1Entry {
            expires_at: Instant::now() + Duration::from_secs(600),
            entry: Arc::new(StoredEntry {
                format_version: ENTRY_FORMAT_VERSION,
                tags: Vec::new(),
                value: vec![0; bytes],
                lifetime: None,
            }),
        }
    }

    #[tokio::test]
    async fn the_capacity_bounds_memory_not_just_entries() {
        // 64 units: 64 small entries, or 1 MiB of large ones.
        let l1 = L1::new(64);
        for i in 0..32 {
            l1.cache.insert(format!("ns:{i}"), entry(256 * 1024)).await;
        }
        l1.cache.run_pending_tasks().await;
        assert!(l1.cache.weighted_size() <= 64);
        assert!(l1.cache.entry_count() <= 4, "{}", l1.cache.entry_count());

        let l1 = L1::new(64);
        for i in 0..64 {
            l1.cache.insert(format!("ns:{i}"), entry(100)).await;
        }
        l1.cache.run_pending_tasks().await;
        assert_eq!(l1.cache.entry_count(), 64, "a small entry counts once");
    }
}
