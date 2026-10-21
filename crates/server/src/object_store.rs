//! The object store at startup and in the background: the S3 client with the
//! optional local blob cache in front of it (`[blob_cache]`), the bucket
//! check, and the cache's periodic maintenance.
//!
//! Without the cache, an S3 that cannot be reached at startup fails startup,
//! as before. With it, the instance starts **degraded**: it serves what its
//! cache holds (a persistent cache survives the restart), `/readyz` reports
//! the object store `degraded` instead of failing, and the bucket check is
//! retried in the background until S3 answers.

use std::time::Duration;

use anyhow::Context;
use forge_storage::{BlobCache, BlobCacheStats, BlobStore};
use serde_json::{json, Value};

use crate::config::Config;

/// How often the cache re-reads its filesystem and evicts down to its limit.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

/// Every this many maintenance runs, the cache's statistics are logged.
const LOG_EVERY: u64 = 10;

/// Longest pause between two bucket checks while S3 is down at startup.
const BUCKET_RETRY_MAX: Duration = Duration::from_secs(30);

/// The S3 store from `config`, with the local blob cache in front of it when
/// `blob_cache.path` is set. Opening the cache scans its directory (blocking);
/// a directory that cannot be created or read fails startup.
pub fn open(config: &Config) -> anyhow::Result<BlobStore> {
    let store = BlobStore::new(config.s3.to_storage());
    let Some(cache_config) = config.blob_cache() else {
        return Ok(store);
    };
    let path = cache_config.path.clone();
    let cache = BlobCache::open(cache_config)
        .with_context(|| format!("open the local blob cache at {}", path.display()))?;
    Ok(store.with_cache(cache))
}

/// Make sure the bucket exists. Without the blob cache, any failure fails
/// startup. With it, an S3 that cannot be reached does not: the check is
/// retried in the background and the instance serves its cache meanwhile.
pub async fn ensure_bucket(store: &BlobStore) -> anyhow::Result<()> {
    let error = match store.ensure_bucket().await {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    if store.cache().is_none() || !error.is_unavailable() {
        return Err(error).context("ensure S3 bucket");
    }
    tracing::warn!(
        %error,
        "S3 is unreachable; starting degraded (serving the local blob cache) and \
         retrying the bucket check in the background"
    );
    let store = store.clone();
    tokio::spawn(async move {
        let mut delay = Duration::from_secs(1);
        loop {
            tokio::time::sleep(delay).await;
            match store.ensure_bucket().await {
                Ok(()) => {
                    tracing::info!("S3 is reachable again; the bucket check succeeded");
                    return;
                }
                Err(error) => {
                    tracing::debug!(%error, "the S3 bucket check failed again");
                    delay = (delay * 2).min(BUCKET_RETRY_MAX);
                }
            }
        }
    });
    Ok(())
}

/// Re-read the cache's filesystem and evict down to its limit every
/// `interval`, logging its statistics now and then.
pub fn spawn_maintenance(cache: BlobCache, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut runs = 0u64;
        loop {
            ticker.tick().await;
            let cache = cache.clone();
            let stats = match tokio::task::spawn_blocking(move || cache.maintain()).await {
                Ok(stats) => stats,
                Err(error) => {
                    tracing::warn!(%error, "blob cache maintenance failed");
                    continue;
                }
            };
            runs += 1;
            if runs % LOG_EVERY == 1 {
                log_stats(&stats);
            }
        }
    })
}

fn log_stats(stats: &BlobCacheStats) {
    tracing::info!(
        entries = stats.entries,
        size_bytes = stats.size_bytes,
        limit_bytes = stats.limit_bytes,
        limit_auto = stats.limit_auto,
        hit_ratio = format!("{:.3}", stats.hit_ratio()),
        hits = stats.hits,
        hit_bytes = stats.hit_bytes,
        hits_while_store_down = stats.hits_while_store_down,
        misses = stats.misses,
        fills = stats.fills,
        fill_failures = stats.fill_failures,
        corrupt = stats.corrupt,
        evictions = stats.evictions,
        bypassed = stats.bypassed,
        "local blob cache"
    );
}

/// The cache's statistics as JSON (`GET /admin/blob-cache`).
pub fn stats_json(store: &BlobStore) -> Value {
    let Some(cache) = store.cache() else {
        return json!({ "enabled": false });
    };
    let s = cache.stats();
    json!({
        "enabled": true,
        "path": s.path.display().to_string(),
        "object_store_down": store.is_unavailable(),
        "entries": s.entries,
        "size_bytes": s.size_bytes,
        "reserved_bytes": s.reserved_bytes,
        "limit_bytes": s.limit_bytes,
        "limit_auto": s.limit_auto,
        "hit_ratio": s.hit_ratio(),
        "hits": s.hits,
        "hit_bytes": s.hit_bytes,
        "hits_while_store_down": s.hits_while_store_down,
        "misses": s.misses,
        "fills": s.fills,
        "fill_failures": s.fill_failures,
        "corrupt": s.corrupt,
        "evictions": s.evictions,
        "evicted_bytes": s.evicted_bytes,
        "bypassed": s.bypassed,
    })
}
