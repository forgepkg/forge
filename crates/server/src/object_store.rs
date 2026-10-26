//! The object store at startup and in the background: the S3 client with the
//! optional local blob cache in front of it (`[blob_cache]`), the bucket
//! check, and the cache's periodic maintenance.
//!
//! Garbage collection drops a blob it deletes from S3 from the cache of the
//! instance that deletes it. Every other instance drops its copy at its next
//! check of the cached blobs against the `blob` table
//! ([`drop_deleted`], every [`DROP_DELETED_EVERY`] maintenance runs), so no
//! instance keeps deleted bytes on disk for long.
//!
//! Without the cache, an S3 that cannot be reached at startup fails startup,
//! as before. With it, the instance starts **degraded**: it serves what its
//! cache holds (a persistent cache survives the restart), `/readyz` reports
//! the object store `degraded` instead of failing, and the bucket check is
//! retried in the background until S3 answers.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;
use forge_storage::{BlobCache, BlobCacheStats, BlobStore};
use serde_json::{json, Value};
use sqlx::PgPool;
use tracing::Instrument;

use crate::config::Config;
use crate::state::Instance;

/// How often the cache re-reads its filesystem and evicts down to its limit.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

/// The maintenance worker's name (logs, `forge_worker_*`).
pub const WORKER: &str = "blob-cache";

/// Every this many maintenance runs, the cache's statistics are logged.
const LOG_EVERY: u64 = 10;

/// Every this many maintenance runs (the first included), the cached blobs
/// are checked against the database ([`drop_deleted`]).
pub const DROP_DELETED_EVERY: u64 = 10;

/// Cached blobs looked up in the database per query by [`drop_deleted`].
const DROP_DELETED_BATCH: usize = 1000;

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
/// `interval`, drop the blobs garbage collection deleted elsewhere every
/// [`DROP_DELETED_EVERY`] runs, and log the cache's statistics now and then.
pub fn spawn_maintenance(
    cache: BlobCache,
    pool: PgPool,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut runs = 0u64;
        loop {
            ticker.tick().await;
            runs += 1;
            let run = forge_telemetry::workers::Run::start(WORKER);
            let mut ok = true;
            if runs % DROP_DELETED_EVERY == 1 {
                match drop_deleted(&cache, &pool).instrument(run.span()).await {
                    Ok(0) => {}
                    Ok(dropped) => tracing::info!(
                        dropped,
                        "dropped cached blobs that garbage collection deleted"
                    ),
                    Err(error) => {
                        ok = false;
                        tracing::warn!(%error, "checking the blob cache against the database failed")
                    }
                }
            }
            let maintained = cache.clone();
            let stats = match tokio::task::spawn_blocking(move || maintained.maintain()).await {
                Ok(stats) => stats,
                Err(error) => {
                    tracing::warn!(%error, "blob cache maintenance failed");
                    run.finish(false);
                    continue;
                }
            };
            run.finish(ok);
            if runs % LOG_EVERY == 1 {
                log_stats(&stats);
            }
        }
    })
}

/// Drop the cached blobs the database no longer holds (or is deleting):
/// garbage collection deleted them from S3, on this instance or another.
/// Returns how many were dropped.
pub async fn drop_deleted(cache: &BlobCache, pool: &PgPool) -> anyhow::Result<u64> {
    let mut dropped = 0;
    for chunk in cache.sha256_chunks(DROP_DELETED_BATCH) {
        let live: HashSet<String> = forge_db::blob_dao::live_among(pool, &chunk)
            .await?
            .into_iter()
            .collect();
        for sha256 in chunk.iter().filter(|sha256| !live.contains(*sha256)) {
            cache.evict(sha256).await;
            dropped += 1;
        }
    }
    Ok(dropped)
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

/// The cache's statistics as JSON (`GET /admin/blob-cache`). Every instance
/// has a cache of its own: `instance` names the one they are from.
pub fn stats_json(store: &BlobStore, instance: &Instance) -> Value {
    let Some(cache) = store.cache() else {
        return json!({ "enabled": false, "instance": instance });
    };
    let s = cache.stats();
    json!({
        "enabled": true,
        "instance": instance,
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
