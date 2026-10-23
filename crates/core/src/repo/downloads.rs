//! Batched download counting (#119).
//!
//! Every `.nupkg` download updates its version's download counters
//! ([`forge_db::download_dao`]). Written one download at a time, every
//! download of one version updated the same rows: a burst of downloads of one
//! version (a CI wave restoring an internal package, or anyone flooding a
//! package anonymous callers may read) queued on those row locks, each
//! waiting task holding a pool connection, until request-path reads failed
//! for lack of one.
//!
//! A [`DownloadTally`] counts downloads in memory instead and writes them in
//! batches: every [`FLUSH_INTERVAL`], one statement per kind for everything
//! counted since the last write, so a burst costs one row update per version
//! and interval, whatever its size, and at most one connection. The writer
//! task starts with the first count and ends once a write finds nothing
//! pending. At most [`MAX_PENDING`] versions are pending at once; downloads
//! of further versions are not counted until the next write (the counters are
//! best-effort). Counts not yet written when the process exits are lost.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use sqlx::PgPool;

/// How long counts collect before they are written.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// The most versions with pending counts at once.
pub const MAX_PENDING: usize = 10_000;

/// Download counts not written yet.
#[derive(Default)]
struct Pending {
    /// `(asset id, component id) -> downloads` of hosted versions.
    hosted: HashMap<(i64, i64), i64>,
    /// `(repository id, lowercase id, version) -> downloads` of proxied ones.
    proxy: HashMap<(i64, String, String), i64>,
    /// Downloads not counted because [`MAX_PENDING`] versions were pending.
    dropped: u64,
}

impl Pending {
    fn len(&self) -> usize {
        self.hosted.len() + self.proxy.len()
    }

    fn is_empty(&self) -> bool {
        self.hosted.is_empty() && self.proxy.is_empty()
    }
}

/// Counts downloads and writes them in batches (see the [module docs](self)).
/// Shared by every repository facade of a process.
pub struct DownloadTally {
    pool: PgPool,
    interval: Duration,
    pending: Mutex<Pending>,
    /// Whether a writer task is running.
    writing: AtomicBool,
}

impl DownloadTally {
    /// A tally writing to `pool` every [`FLUSH_INTERVAL`].
    pub fn new(pool: PgPool) -> Arc<Self> {
        Self::with_interval(pool, FLUSH_INTERVAL)
    }

    /// A tally writing every `interval` (tests use a short one).
    pub fn with_interval(pool: PgPool, interval: Duration) -> Arc<Self> {
        Arc::new(DownloadTally {
            pool,
            interval,
            pending: Mutex::new(Pending::default()),
            writing: AtomicBool::new(false),
        })
    }

    /// Count a download of the hosted `.nupkg` asset `asset_id` of
    /// `component_id`.
    pub fn count_hosted(self: &Arc<Self>, asset_id: i64, component_id: i64) {
        self.count(|pending| {
            let full = pending.len() >= MAX_PENDING;
            match pending.hosted.get_mut(&(asset_id, component_id)) {
                Some(n) => *n += 1,
                None if full => pending.dropped += 1,
                None => {
                    pending.hosted.insert((asset_id, component_id), 1);
                }
            }
        });
    }

    /// Count a download of the proxied `name` (lowercase) `version` in
    /// `repository_id`.
    pub fn count_proxy(self: &Arc<Self>, repository_id: i64, name: &str, version: &str) {
        self.count(|pending| {
            let key = (repository_id, name.to_string(), version.to_string());
            let full = pending.len() >= MAX_PENDING;
            match pending.proxy.get_mut(&key) {
                Some(n) => *n += 1,
                None if full => pending.dropped += 1,
                None => {
                    pending.proxy.insert(key, 1);
                }
            }
        });
    }

    fn count(self: &Arc<Self>, add: impl FnOnce(&mut Pending)) {
        add(&mut self.pending.lock().unwrap_or_else(PoisonError::into_inner));
        if !self.writing.swap(true, Ordering::AcqRel) {
            let tally = self.clone();
            tokio::spawn(async move { tally.write_until_idle().await });
        }
    }

    /// Write what is pending every interval until a write finds nothing.
    async fn write_until_idle(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.interval).await;
            if !self.write_pending().await {
                self.writing.store(false, Ordering::Release);
                // A count that saw this writer still running started none:
                // take over again if one landed meanwhile and nobody else has.
                let idle = self
                    .pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_empty();
                if idle || self.writing.swap(true, Ordering::AcqRel) {
                    return;
                }
            }
        }
    }

    /// Write and clear what is pending. Returns whether there was anything.
    pub async fn write_pending(&self) -> bool {
        let pending =
            std::mem::take(&mut *self.pending.lock().unwrap_or_else(PoisonError::into_inner));
        if pending.is_empty() {
            return false;
        }
        if pending.dropped > 0 {
            tracing::warn!(
                dropped = pending.dropped,
                max_pending = MAX_PENDING,
                "download tracking: more versions were downloaded in one interval than are counted; some downloads were not counted"
            );
        }
        if !pending.hosted.is_empty() {
            let mut rows: Vec<_> = pending.hosted.into_iter().collect();
            // One lock order for every writer.
            rows.sort_unstable();
            let (keys, counts): (Vec<(i64, i64)>, Vec<i64>) = rows.into_iter().unzip();
            let (assets, components): (Vec<i64>, Vec<i64>) = keys.into_iter().unzip();
            if let Err(e) = forge_db::download_dao::bump_hosted_downloads(
                &self.pool,
                &assets,
                &components,
                &counts,
            )
            .await
            {
                tracing::warn!(error = %e, versions = assets.len(), "download tracking write failed");
            }
        }
        if !pending.proxy.is_empty() {
            let mut rows: Vec<_> = pending.proxy.into_iter().collect();
            rows.sort_unstable();
            let mut repositories = Vec::with_capacity(rows.len());
            let mut names = Vec::with_capacity(rows.len());
            let mut versions = Vec::with_capacity(rows.len());
            let mut counts = Vec::with_capacity(rows.len());
            for ((repository, name, version), n) in rows {
                repositories.push(repository);
                names.push(name);
                versions.push(version);
                counts.push(n);
            }
            if let Err(e) = forge_db::download_dao::bump_proxy_downloads_by_name(
                &self.pool,
                &repositories,
                &names,
                &versions,
                &counts,
            )
            .await
            {
                tracing::warn!(error = %e, versions = names.len(), "proxy download tracking write failed");
            }
        }
        true
    }
}
