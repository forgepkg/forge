//! Optional local disk cache for blobs (`[blob_cache]`).
//!
//! A copy of downloaded blobs on a local disk, so hot downloads skip S3 and
//! cached packages keep resolving while S3 is down. S3 stays the source of
//! truth: an entry is only ever a copy of an object S3 already has, and
//! since blobs are content-addressed and immutable a copy needs no
//! invalidation — it is the right bytes or it is absent.
//!
//! ## Layout
//!
//! `<path>/<sha256[0..2]>/<sha256>` holds one blob, named by the hash the
//! database knows it by, so a lookup needs no S3 call. Fills in progress
//! live in `<path>/tmp/` until checked against that hash and size, and are
//! then renamed into place; the startup scan removes what a killed process
//! left there.
//!
//! ## Eviction: FIFO
//!
//! Over its limit, the cache drops the entries filled longest ago, however
//! often they were read: a read changes nothing, so a hit takes no lock for
//! bookkeeping and writes nothing. A file's mtime is its fill time, so the
//! startup scan rebuilds the queue from the directory and the order survives
//! a restart. The index lives in memory only.
//!
//! ## Size limit
//!
//! [`CacheLimit::Auto`] sizes the cache from the filesystem holding `path`
//! (its size, minus `min_free_bytes`, minus the staging budget when staging
//! shares the filesystem); [`CacheLimit::Bytes`] is a fixed limit. Either way
//! the cache never lets the filesystem's free space drop below
//! `min_free_bytes` (default 5 % of its size): it evicts instead, so a disk
//! shared with something else never fills up. [`BlobCache::maintain`]
//! re-reads the filesystem, so a resized volume is picked up without a
//! restart; in between, fills go by what it read, less what the cache
//! itself added since, so no request waits for `statvfs`.
//!
//! ## Locking
//!
//! One mutex guards the index and is held for bookkeeping only: an eviction
//! drops entries under it and removes their files after releasing it, on
//! the blocking pool, so a hit never waits for an unlink. Until its old
//! file is gone, a key is neither filled nor written through again.
//!
//! ## Robustness
//!
//! Every cache I/O error fails open: the entry is dropped, the reader falls
//! back to S3, and the error is logged. Entries found by the startup scan
//! are checked against their hash on their first hit, so a file damaged
//! while the process was down is detected and fetched again.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use bytes::Bytes;
use futures_util::{FutureExt, Stream, StreamExt};
use sha2::{Digest, Sha256};
use tempfile::TempPath;

use crate::cas::create_private_dir;
use tokio::sync::watch;

/// A blob's bytes as a stream of chunks.
pub type BlobStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>;

/// The directory of fills in progress, under the cache root.
const TMP_DIR: &str = "tmp";

/// A fill writes what arrived up to this many bytes at once.
const FILL_WRITE_BATCH: usize = 256 * 1024;

/// How large the cache may grow (`blob_cache.max_bytes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheLimit {
    /// The size of the filesystem holding the cache, minus `min_free_bytes`
    /// (and the staging budget when staging is on the same filesystem).
    Auto,
    /// A fixed number of bytes.
    Bytes(u64),
}

/// Configuration of a [`BlobCache`].
#[derive(Debug, Clone)]
pub struct BlobCacheConfig {
    /// The cache directory (created if missing).
    pub path: PathBuf,
    /// How large the cache may grow.
    pub max_bytes: CacheLimit,
    /// Free space to leave on the filesystem; `None`: 5 % of its size.
    pub min_free_bytes: Option<u64>,
    /// The staging directory and its byte budget: with
    /// [`CacheLimit::Auto`], the budget is kept free too when the directory
    /// is on the cache's filesystem.
    pub staging: Option<(PathBuf, u64)>,
}

/// Size and free space of a filesystem, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsSpace {
    /// Total size.
    pub total: u64,
    /// Space available to unprivileged writers.
    pub available: u64,
}

/// Reads a filesystem's [`FsSpace`] (`statvfs`; tests substitute their own).
pub type FsProbe = Arc<dyn Fn(&Path) -> std::io::Result<FsSpace> + Send + Sync>;

/// The real [`FsProbe`]: `statvfs(2)`.
pub fn statvfs_probe() -> FsProbe {
    Arc::new(fs_space)
}

#[cfg(unix)]
fn fs_space(path: &Path) -> std::io::Result<FsSpace> {
    let stat = rustix::fs::statvfs(path)?;
    Ok(FsSpace {
        total: stat.f_blocks.saturating_mul(stat.f_frsize),
        available: stat.f_bavail.saturating_mul(stat.f_frsize),
    })
}

#[cfg(not(unix))]
fn fs_space(_path: &Path) -> std::io::Result<FsSpace> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "filesystem size is only known on Unix",
    ))
}

/// Whether two paths are on the same filesystem (assumed when unknown).
fn same_filesystem(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev(),
            _ => true,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        true
    }
}

/// The effective limit: what the cache may hold given the configured limit
/// and the filesystem, `cache_bytes` being what it holds on disk now.
///
/// The configured part is `max` itself, or for [`CacheLimit::Auto`] the
/// filesystem's size minus `min_free` and `staging_reserve`. The free-space
/// part keeps `min_free` bytes free: the cache may hold what it holds now
/// plus what is available, minus `min_free` — less than it holds when
/// something else has eaten into `min_free`, so it gives space back.
pub fn effective_limit(
    max: CacheLimit,
    min_free: Option<u64>,
    staging_reserve: u64,
    fs: FsSpace,
    cache_bytes: u64,
) -> u64 {
    let min_free = min_free.unwrap_or(fs.total / 20);
    let configured = match max {
        CacheLimit::Auto => fs
            .total
            .saturating_sub(min_free)
            .saturating_sub(staging_reserve),
        CacheLimit::Bytes(bytes) => bytes,
    };
    let disk = cache_bytes
        .saturating_add(fs.available)
        .saturating_sub(min_free);
    configured.min(disk)
}

/// A blob's key: its SHA-256.
type Key = [u8; 32];

/// The key of a lowercase-hex SHA-256, `None` for anything else (which then
/// never reaches the filesystem).
fn parse_key(sha256: &str) -> Option<Key> {
    let bytes = sha256.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut key = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        key[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(key)
}

fn hex(key: &Key) -> String {
    use std::fmt::Write;
    key.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One cached blob.
#[derive(Debug, Clone, Copy)]
struct Entry {
    size: u64,
    /// Position in the FIFO queue (fill order).
    seq: u64,
    /// Checked against its hash: filled or written through by this process,
    /// or verified on its first hit after the startup scan.
    verified: bool,
}

/// The in-memory index, behind one lock.
#[derive(Default)]
struct Index {
    entries: HashMap<Key, Entry>,
    /// Keys in fill order; an item whose `seq` no longer matches its entry
    /// (the entry was removed or filled again) is skipped.
    fifo: VecDeque<(Key, u64)>,
    next_seq: u64,
    /// Bytes of the entries.
    bytes: u64,
    /// Bytes promised to fills and write-throughs in progress.
    reserved: u64,
    /// Fills in progress, joined by concurrent misses of the same blob.
    fills: HashMap<Key, Arc<watch::Sender<FillState>>>,
    /// Keys whose entries are gone and whose files are being removed,
    /// outside the lock: no fill or write-through of them starts, and none
    /// commits, until the old file is gone.
    unlinking: HashSet<Key>,
    /// The filesystem as maintenance last read it, with the cache's bytes
    /// at that moment.
    space: Option<(FsSpace, u64)>,
    /// The limit last computed.
    limit: u64,
}

impl Index {
    fn push(&mut self, key: Key, size: u64, verified: bool) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(
            key,
            Entry {
                size,
                seq,
                verified,
            },
        );
        self.fifo.push_back((key, seq));
        self.bytes += size;
    }

    /// Forget `key` (only the entry at `seq`, when given) and return it.
    fn forget(&mut self, key: &Key, seq: Option<u64>) -> Option<Entry> {
        let entry = *self.entries.get(key)?;
        if seq.is_some_and(|seq| seq != entry.seq) {
            return None;
        }
        self.entries.remove(key);
        self.bytes -= entry.size;
        // Stale queue items are skipped when popped; compact once they
        // dominate, so removals outside the FIFO order cannot grow it.
        if self.fifo.len() > 2 * self.entries.len() + 1024 {
            let entries = &self.entries;
            self.fifo
                .retain(|(key, seq)| entries.get(key).is_some_and(|e| e.seq == *seq));
        }
        Some(entry)
    }

    /// The oldest entry, removed from the index.
    fn pop_oldest(&mut self) -> Option<(Key, Entry)> {
        while let Some((key, seq)) = self.fifo.pop_front() {
            if let Some(entry) = self.forget(&key, Some(seq)) {
                return Some((key, entry));
            }
        }
        None
    }
}

/// Cache activity counters.
#[derive(Debug, Default)]
struct Counters {
    hits: AtomicU64,
    hit_bytes: AtomicU64,
    hits_while_store_down: AtomicU64,
    misses: AtomicU64,
    fills: AtomicU64,
    fill_failures: AtomicU64,
    corrupt: AtomicU64,
    evictions: AtomicU64,
    evicted_bytes: AtomicU64,
    bypassed: AtomicU64,
}

/// A snapshot of the cache's size and activity since startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobCacheStats {
    /// The cache directory.
    pub path: PathBuf,
    /// Cached blobs.
    pub entries: u64,
    /// Their bytes.
    pub size_bytes: u64,
    /// Bytes promised to fills in progress.
    pub reserved_bytes: u64,
    /// The effective limit.
    pub limit_bytes: u64,
    /// Whether the limit is sized from the disk (`max_bytes = "auto"`).
    pub limit_auto: bool,
    /// Reads served from a cached file.
    pub hits: u64,
    /// Bytes those reads served.
    pub hit_bytes: u64,
    /// Hits served while S3 was known to be down.
    pub hits_while_store_down: u64,
    /// Reads that found no cached file.
    pub misses: u64,
    /// Blobs added (by a fill from S3, or written through by an upload).
    pub fills: u64,
    /// Fills that failed (S3 error, cache I/O error, hash mismatch).
    pub fill_failures: u64,
    /// Cached files found damaged and dropped.
    pub corrupt: u64,
    /// Entries evicted (over the limit, or deleted from S3).
    pub evictions: u64,
    /// Their bytes.
    pub evicted_bytes: u64,
    /// Misses served straight from S3 without caching (no room).
    pub bypassed: u64,
}

impl BlobCacheStats {
    /// Hits per read, `0` before the first read.
    pub fn hit_ratio(&self) -> f64 {
        let reads = self.hits + self.misses;
        if reads == 0 {
            0.0
        } else {
            self.hits as f64 / reads as f64
        }
    }
}

/// The local blob cache. Cheap to clone; clones share one cache.
#[derive(Clone)]
pub struct BlobCache {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    tmp: PathBuf,
    max_bytes: CacheLimit,
    min_free_bytes: Option<u64>,
    /// Staging budget kept free under [`CacheLimit::Auto`].
    staging_reserve: u64,
    fs: FsProbe,
    index: Mutex<Index>,
    counters: Counters,
}

impl std::fmt::Debug for BlobCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobCache")
            .field("root", &self.inner.root)
            .field("max_bytes", &self.inner.max_bytes)
            .finish_non_exhaustive()
    }
}

impl BlobCache {
    /// Open the cache at `config.path`: create it, remove partial fills,
    /// rebuild the FIFO queue from the files there, and evict down to the
    /// limit. Blocking (a directory scan): call it at startup.
    pub fn open(config: BlobCacheConfig) -> std::io::Result<Self> {
        Self::open_with(config, statvfs_probe())
    }

    /// [`Self::open`] reading filesystem space through `fs`.
    pub fn open_with(config: BlobCacheConfig, fs: FsProbe) -> std::io::Result<Self> {
        let root = config.path;
        // Entries are private package bytes, and a file in place of one is
        // served as it: the directory must be Forge's alone (no sticky
        // exception, since anyone may create a shard directory in one).
        create_private_dir(&root, true)?;
        if restore_after_fs_group(&root)? {
            tracing::warn!(
                dir = %root.display(),
                "the blob cache directory was made group-writable (a Kubernetes fsGroup \
                 pass?); restored it to Forge's user alone. Set the pod's \
                 fsGroupChangePolicy to OnRootMismatch"
            );
        }
        crate::cas::ensure_owned_dir(&root, "blob cache directory", "blob_cache.path", false)?;
        let tmp = root.join(TMP_DIR);
        create_private_dir(&tmp, true)?;
        let partial = clear_dir(&tmp)?;
        if partial > 0 {
            tracing::info!(removed = partial, dir = %tmp.display(), "removed partial blob cache fills");
        }
        let staging_reserve = match (&config.staging, config.max_bytes) {
            (Some((dir, budget)), CacheLimit::Auto) if same_filesystem(dir, &root) => *budget,
            _ => 0,
        };
        let mut found = scan(&root)?;
        // Fill order: oldest mtime first (name breaks ties).
        found.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
        let mut index = Index::default();
        for (key, size, _) in found {
            index.push(key, size, false);
        }
        let cache = BlobCache {
            inner: Arc::new(Inner {
                root,
                tmp,
                max_bytes: config.max_bytes,
                min_free_bytes: config.min_free_bytes,
                staging_reserve,
                fs,
                index: Mutex::new(index),
                counters: Counters::default(),
            }),
        };
        // The disk must be readable for `auto`; a fixed limit works without.
        if let Err(error) = (cache.inner.fs)(&cache.inner.root) {
            if cache.inner.max_bytes == CacheLimit::Auto {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("cannot read the filesystem size of the blob cache: {error}"),
                ));
            }
        }
        let stats = cache.maintain();
        tracing::info!(
            path = %stats.path.display(),
            entries = stats.entries,
            size_bytes = stats.size_bytes,
            limit_bytes = stats.limit_bytes,
            limit_auto = stats.limit_auto,
            "local blob cache opened"
        );
        if stats.limit_bytes == 0 {
            tracing::warn!(
                path = %stats.path.display(),
                "the local blob cache has no room (its filesystem has less free space than \
                 blob_cache.min_free_bytes, 5 % of it by default): nothing is cached until \
                 space frees up"
            );
        }
        Ok(cache)
    }

    /// The cache directory.
    pub fn path(&self) -> &Path {
        &self.inner.root
    }

    fn lock(&self) -> MutexGuard<'_, Index> {
        self.inner
            .index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn path_of(&self, key: &Key) -> PathBuf {
        let name = hex(key);
        self.inner.root.join(&name[..2]).join(name)
    }

    /// The filesystem now, `None` (logged) when it cannot be read.
    fn probe(&self) -> Option<FsSpace> {
        match (self.inner.fs)(&self.inner.root) {
            Ok(space) => Some(space),
            Err(error) => {
                tracing::warn!(%error, path = %self.inner.root.display(), "cannot read the blob cache's filesystem size");
                None
            }
        }
    }

    /// The limit, from the filesystem as maintenance last read it (the last
    /// limit when the filesystem is unknown). What the cache itself filled
    /// or evicted since came out of, or went back to, the free space then.
    fn limit(&self, index: &Index) -> u64 {
        match (index.space, self.inner.max_bytes) {
            (Some((space, bytes_then)), max) => effective_limit(
                max,
                self.inner.min_free_bytes,
                self.inner.staging_reserve,
                FsSpace {
                    total: space.total,
                    available: space
                        .available
                        .saturating_add(bytes_then)
                        .saturating_sub(index.bytes),
                },
                index.bytes,
            ),
            (None, CacheLimit::Bytes(bytes)) => bytes,
            (None, CacheLimit::Auto) => index.limit,
        }
    }

    /// Remove `key`'s file. Its entry is gone and the key is in
    /// `unlinking`, so no lookup reaches the file and no fill replaces it
    /// while it goes. Blocking.
    fn unlink(&self, key: &Key) {
        let path = self.path_of(key);
        if let Err(error) = std::fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, path = %path.display(), "cannot remove a blob cache file");
            }
        }
    }

    /// Forget `key`'s entry (only the one at `seq`, when given) and mark its
    /// file for removal: the caller removes it ([`Self::remove_files`])
    /// after releasing the lock.
    fn drop_entry(&self, index: &mut Index, key: &Key, seq: Option<u64>) -> Option<Entry> {
        let entry = index.forget(key, seq)?;
        index.unlinking.insert(*key);
        Some(entry)
    }

    /// Remove the files of dropped entries (blocking), then let their keys
    /// be filled again.
    fn remove_files(&self, victims: Vec<Key>) {
        if victims.is_empty() {
            return;
        }
        for key in &victims {
            self.unlink(key);
        }
        let mut index = self.lock();
        for key in &victims {
            index.unlinking.remove(key);
        }
    }

    /// [`Self::remove_files`] on the blocking pool, so no runtime worker
    /// waits for the filesystem (inline without a runtime).
    fn remove_files_later(&self, victims: Vec<Key>) {
        if victims.is_empty() {
            return;
        }
        let cache = self.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn_blocking(move || cache.remove_files(victims))),
            Err(_) => cache.remove_files(victims),
        }
    }

    /// Evict the oldest entries until `needed` more bytes fit under `limit`,
    /// adding them to `victims` (their files go after the lock is released).
    fn make_room(
        &self,
        index: &mut Index,
        limit: u64,
        needed: u64,
        victims: &mut Vec<Key>,
    ) -> bool {
        while index.bytes + index.reserved + needed > limit {
            let Some((key, entry)) = index.pop_oldest() else {
                return false;
            };
            index.unlinking.insert(key);
            victims.push(key);
            self.inner
                .counters
                .evictions
                .fetch_add(1, Ordering::Relaxed);
            self.inner
                .counters
                .evicted_bytes
                .fetch_add(entry.size, Ordering::Relaxed);
        }
        true
    }

    /// Re-read the filesystem, evict down to the limit, and report. Run it
    /// periodically (blocking: it reads the filesystem and removes files);
    /// between runs, fills go by the filesystem as it read it.
    pub fn maintain(&self) -> BlobCacheStats {
        let space = self.probe();
        let mut victims = Vec::new();
        {
            let mut index = self.lock();
            if let Some(space) = space {
                index.space = Some((space, index.bytes));
            }
            let limit = self.limit(&index);
            index.limit = limit;
            self.make_room(&mut index, limit, 0, &mut victims);
        }
        self.remove_files(victims);
        self.stats()
    }

    /// A snapshot of size and counters.
    pub fn stats(&self) -> BlobCacheStats {
        let (entries, size_bytes, reserved_bytes, limit_bytes) = {
            let index = self.lock();
            (
                index.entries.len() as u64,
                index.bytes,
                index.reserved,
                index.limit,
            )
        };
        let c = &self.inner.counters;
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        BlobCacheStats {
            path: self.inner.root.clone(),
            entries,
            size_bytes,
            reserved_bytes,
            limit_bytes,
            limit_auto: self.inner.max_bytes == CacheLimit::Auto,
            hits: get(&c.hits),
            hit_bytes: get(&c.hit_bytes),
            hits_while_store_down: get(&c.hits_while_store_down),
            misses: get(&c.misses),
            fills: get(&c.fills),
            fill_failures: get(&c.fill_failures),
            corrupt: get(&c.corrupt),
            evictions: get(&c.evictions),
            evicted_bytes: get(&c.evicted_bytes),
            bypassed: get(&c.bypassed),
        }
    }

    /// Whether `sha256` is cached.
    pub fn contains(&self, sha256: &str) -> bool {
        parse_key(sha256).is_some_and(|key| self.lock().entries.contains_key(&key))
    }

    /// Drop `sha256` from the cache (its object was deleted from S3, or its
    /// file failed a read), removing its file on the blocking pool.
    pub async fn evict(&self, sha256: &str) {
        let Some(key) = parse_key(sha256) else { return };
        let Some(entry) = self.drop_entry(&mut self.lock(), &key, None) else {
            return;
        };
        self.inner
            .counters
            .evictions
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .counters
            .evicted_bytes
            .fetch_add(entry.size, Ordering::Relaxed);
        self.remove_files_now(vec![key]).await;
    }

    /// [`Self::remove_files`] on the blocking pool, waiting for it.
    async fn remove_files_now(&self, victims: Vec<Key>) {
        let cache = self.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || cache.remove_files(victims)).await {
            tracing::warn!(%error, "removing blob cache files failed");
        }
    }

    /// The cached file of `sha256`, open for reading, when it is cached
    /// with `size` bytes. An entry first hit after the startup scan is
    /// checked against its hash before it is served. A file that is missing,
    /// unreadable, of another size or damaged is dropped (`None`: fetch it
    /// from S3 again).
    pub(crate) async fn lookup(&self, sha256: &str, size: u64) -> Option<Arc<File>> {
        let key = parse_key(sha256)?;
        let entry = *self.lock().entries.get(&key)?;
        let path = self.path_of(&key);
        let check =
            tokio::task::spawn_blocking(move || -> std::io::Result<Result<File, String>> {
                let mut file = File::open(&path)?;
                let len = file.metadata()?.len();
                if len != size || len != entry.size {
                    return Ok(Err(format!("{len} bytes on disk, {size} expected")));
                }
                if !entry.verified {
                    let mut hasher = Sha256::new();
                    let mut buf = vec![0u8; 256 * 1024];
                    loop {
                        let n = file.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                    }
                    if hasher.finalize()[..] != key[..] {
                        return Ok(Err("content does not match its sha256".into()));
                    }
                }
                Ok(Ok(file))
            })
            .await;
        let problem = match check {
            Ok(Ok(Ok(file))) => {
                if !entry.verified {
                    if let Some(current) = self.lock().entries.get_mut(&key) {
                        if current.seq == entry.seq {
                            current.verified = true;
                        }
                    }
                }
                return Some(Arc::new(file));
            }
            Ok(Ok(Err(damage))) => {
                self.inner.counters.corrupt.fetch_add(1, Ordering::Relaxed);
                damage
            }
            Ok(Err(error)) => format!("read error: {error}"),
            Err(error) => format!("check failed: {error}"),
        };
        tracing::warn!(sha256, problem = %problem, "dropping a damaged blob cache entry; reading it from S3");
        let dropped = self.drop_entry(&mut self.lock(), &key, Some(entry.seq));
        if dropped.is_some() {
            // Gone before the caller fills it again.
            self.remove_files_now(vec![key]).await;
        }
        None
    }

    /// Count a hit (`store_down`: while S3 is known to be down).
    pub(crate) fn record_hit(&self, store_down: bool) {
        let c = &self.inner.counters;
        c.hits.fetch_add(1, Ordering::Relaxed);
        if store_down {
            c.hits_while_store_down.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count bytes a hit served.
    pub(crate) fn record_hit_bytes(&self, bytes: u64) {
        self.inner
            .counters
            .hit_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count a miss.
    pub(crate) fn record_miss(&self) {
        self.inner.counters.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Join the fill of `sha256` in progress, or become its leader with
    /// `size` bytes reserved. [`Begin::Bypass`] when it cannot be cached
    /// (no room, not a SHA-256); [`Begin::Cached`] when it was filled
    /// meanwhile (look it up again).
    /// Its evictions remove their files on the blocking pool.
    pub(crate) fn begin_fill(&self, sha256: &str, size: u64) -> Begin {
        let Some(key) = parse_key(sha256) else {
            return Begin::Bypass;
        };
        let mut victims = Vec::new();
        let begin = {
            let mut index = self.lock();
            if index.entries.contains_key(&key) {
                return Begin::Cached;
            }
            if let Some(fill) = index.fills.get(&key) {
                return Begin::Join(fill.subscribe());
            }
            if !self.reserve(&mut index, &key, size, &mut victims) {
                Begin::Bypass
            } else {
                let state = Arc::new(watch::Sender::new(FillState::Starting));
                index.fills.insert(key, state.clone());
                Begin::Lead(FillSlot {
                    cache: self.clone(),
                    key,
                    size,
                    state,
                    finished: false,
                })
            }
        };
        self.remove_files_later(victims);
        begin
    }

    /// Reserve `size` bytes for `key`, evicting as needed into `victims`
    /// (counted as bypassed when they cannot fit, or while `key`'s old file
    /// is still being removed).
    fn reserve(&self, index: &mut Index, key: &Key, size: u64, victims: &mut Vec<Key>) -> bool {
        let limit = self.limit(index);
        index.limit = limit;
        if index.unlinking.contains(key)
            || size > limit
            || !self.make_room(index, limit, size, victims)
        {
            self.inner.counters.bypassed.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        index.reserved += size;
        true
    }

    /// Give back a reservation of `size` bytes.
    fn release(&self, index: &mut Index, size: u64) {
        index.reserved = index.reserved.saturating_sub(size);
    }

    /// Move the checked file at `temp` into place as `key`'s entry, stamped
    /// with the current time as its fill time. Consumes the `size`-byte
    /// reservation either way; an entry that appeared meanwhile is kept and
    /// `temp` removed. Blocking.
    fn commit(&self, key: Key, size: u64, temp: TempPath, file: &File) -> std::io::Result<()> {
        let target = self.path_of(&key);
        let prepared = file
            .set_modified(SystemTime::now())
            .and_then(|()| make_private(file))
            .and_then(|()| match target.parent() {
                Some(parent) => create_private_dir(parent, true),
                None => Ok(()),
            });
        let mut index = self.lock();
        self.release(&mut index, size);
        prepared?;
        // Cached meanwhile, or an evicted copy's file is still going (which
        // would take this one with it).
        if index.entries.contains_key(&key) || index.unlinking.contains(&key) {
            return Ok(());
        }
        temp.persist(&target).map_err(|e| e.error)?;
        index.push(key, size, true);
        self.inner.counters.fills.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Write-through: add the freshly uploaded file at `staged` (already
    /// hashed to `sha256` while it was staged), unless it is cached or being
    /// filled. A hard link when the cache shares the staging filesystem;
    /// otherwise a copy, made in the background from an open handle, so the
    /// caller may remove `staged` at once. Fails open: errors are logged.
    pub async fn insert_staged(&self, sha256: &str, size: u64, staged: &Path) {
        let Some(key) = parse_key(sha256) else { return };
        let mut victims = Vec::new();
        let reserved = {
            let mut index = self.lock();
            if index.entries.contains_key(&key) || index.fills.contains_key(&key) {
                return;
            }
            self.reserve(&mut index, &key, size, &mut victims)
        };
        self.remove_files_later(victims);
        if !reserved {
            return;
        }
        let reservation = Reservation {
            cache: self.clone(),
            size,
        };
        let temp = match TempPath::try_from_path(
            self.inner
                .tmp
                .join(format!("{sha256}.{}.part", uuid::Uuid::new_v4().simple())),
        ) {
            Ok(temp) => temp,
            Err(error) => {
                tracing::warn!(sha256, %error, "blob cache write-through failed");
                return;
            }
        };
        let cache = self.clone();
        let staged = staged.to_path_buf();
        // Linked: done here. Not linked (another filesystem): hand the copy
        // an open handle, which outlives the staged file's removal.
        let linked =
            tokio::task::spawn_blocking(move || match std::fs::hard_link(&staged, &temp) {
                Ok(()) => File::open(&temp).and_then(|file| {
                    reservation.disarm();
                    cache.commit(key, size, temp, &file)?;
                    Ok(None)
                }),
                Err(_) => File::open(&staged).map(|source| Some((source, temp, reservation))),
            })
            .await
            .unwrap_or_else(|error| Err(std::io::Error::other(error)));
        let (mut source, temp, reservation) = match linked {
            Ok(None) => return,
            Ok(Some(copy)) => copy,
            Err(error) => {
                tracing::warn!(sha256, %error, "blob cache write-through failed");
                return;
            }
        };
        let cache = self.clone();
        let sha256 = sha256.to_string();
        tokio::task::spawn_blocking(move || {
            let result = create_private_file(&temp).and_then(|mut file| {
                let copied = std::io::copy(&mut source, &mut file)?;
                if copied != size {
                    return Err(std::io::Error::other(format!(
                        "copied {copied} bytes, {size} expected"
                    )));
                }
                reservation.disarm();
                cache.commit(key, size, temp, &file)
            });
            if let Err(error) = result {
                tracing::warn!(sha256, %error, "blob cache write-through failed");
            }
        });
    }
}

/// A reservation given back unless [disarmed](Self::disarm) (the commit
/// consumes it instead).
struct Reservation {
    cache: BlobCache,
    size: u64,
}

impl Reservation {
    fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut index = self.cache.lock();
        self.cache.release(&mut index, self.size);
    }
}

/// The outcome of [`BlobCache::begin_fill`].
pub(crate) enum Begin {
    /// Cached meanwhile: look it up again.
    Cached,
    /// Another request fills it: read along.
    Join(watch::Receiver<FillState>),
    /// This request fills it.
    Lead(FillSlot),
    /// Not cached: serve it from S3.
    Bypass,
}

/// How far a fill has got. Readers follow it through a `watch` channel.
#[derive(Clone)]
pub(crate) enum FillState {
    /// Waiting for S3's answer.
    Starting,
    /// `written` bytes are in `file` so far.
    Writing { file: Arc<File>, written: u64 },
    /// Complete and checked; `file` holds the whole blob.
    Done { file: Arc<File> },
    /// Abandoned: readers continue from S3.
    Failed,
}

impl FillState {
    /// The file and how many of its bytes of a `size`-byte blob a reader may
    /// take: all once checked, otherwise all written but the last byte, so a
    /// response is never complete before its bytes were checked.
    pub(crate) fn readable(&self, size: u64) -> Option<(Arc<File>, u64)> {
        match self {
            FillState::Writing { file, written } => {
                Some((file.clone(), (*written).min(size.saturating_sub(1))))
            }
            FillState::Done { file } => Some((file.clone(), size)),
            FillState::Starting | FillState::Failed => None,
        }
    }
}

/// The leader of a fill. Dropping it before [`FillSlot::run`] completed the
/// fill abandons it: the reservation is given back and readers fall back to
/// S3.
pub(crate) struct FillSlot {
    cache: BlobCache,
    key: Key,
    size: u64,
    state: Arc<watch::Sender<FillState>>,
    finished: bool,
}

impl FillSlot {
    /// Follow this fill (the leader's own reader).
    pub(crate) fn subscribe(&self) -> watch::Receiver<FillState> {
        self.state.subscribe()
    }

    /// Create the fill's temp file: `(writer, reader, path)`.
    pub(crate) fn create_file(&self) -> std::io::Result<(File, Arc<File>, TempPath)> {
        let (file, path) = tempfile::Builder::new()
            .prefix(&format!("{}.", hex(&self.key)))
            .suffix(".part")
            .tempfile_in(&self.cache.inner.tmp)?
            .into_parts();
        let reader = File::open(&path)?;
        Ok((file, Arc::new(reader), path))
    }

    /// Copy `body` into `file`, check it against the blob's hash and size,
    /// and move it into place. Readers see each write as it lands.
    pub(crate) async fn run(
        mut self,
        mut body: BlobStream,
        file: File,
        reader: Arc<File>,
        path: TempPath,
    ) {
        let sha256 = hex(&self.key);
        self.state.send_replace(FillState::Writing {
            file: reader.clone(),
            written: 0,
        });
        let mut writer = Some((file, Sha256::new()));
        let mut written = 0u64;
        loop {
            let mut batch = Vec::new();
            let mut batch_len = 0usize;
            let mut end = false;
            // Take what has arrived, up to a batch, without waiting for more.
            let first = body.next().await;
            let mut next = Some(first);
            while let Some(item) = next.take() {
                match item {
                    Some(Ok(chunk)) => {
                        batch_len += chunk.len();
                        batch.push(chunk);
                        if batch_len < FILL_WRITE_BATCH {
                            next = body.next().now_or_never();
                        }
                    }
                    Some(Err(error)) => {
                        tracing::warn!(%sha256, %error, "blob cache fill: reading from S3 failed");
                        return self.fail();
                    }
                    None => end = true,
                }
            }
            if !batch.is_empty() {
                let (mut file, mut hasher) = writer.take().expect("writer is put back");
                let wrote = tokio::task::spawn_blocking(move || {
                    for chunk in &batch {
                        file.write_all(chunk)?;
                        hasher.update(chunk);
                    }
                    Ok::<_, std::io::Error>((file, hasher))
                })
                .await;
                match wrote {
                    Ok(Ok(back)) => writer = Some(back),
                    Ok(Err(error)) => {
                        tracing::warn!(%sha256, %error, "blob cache fill: writing failed; serving from S3");
                        return self.fail();
                    }
                    Err(error) => {
                        tracing::warn!(%sha256, %error, "blob cache fill: writing failed; serving from S3");
                        return self.fail();
                    }
                }
                written += batch_len as u64;
                if written > self.size {
                    break;
                }
                self.state.send_modify(|state| {
                    if let FillState::Writing { written: w, .. } = state {
                        *w = written;
                    }
                });
            }
            if end {
                break;
            }
        }
        let (file, hasher) = writer.take().expect("writer is put back");
        if written != self.size || hasher.finalize()[..] != self.key[..] {
            self.cache
                .inner
                .counters
                .corrupt
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(
                %sha256,
                expected_bytes = self.size,
                received_bytes = written,
                "the object store returned bytes that do not match the blob's sha256 and size; not caching them"
            );
            return self.fail();
        }
        let cache = self.cache.clone();
        let (key, size) = (self.key, self.size);
        let committed =
            tokio::task::spawn_blocking(move || cache.commit(key, size, path, &file)).await;
        match committed {
            Ok(Ok(())) => {
                // `commit` gave back the reservation and added the entry.
                self.finished = true;
                let mut index = self.cache.lock();
                if index
                    .fills
                    .get(&self.key)
                    .is_some_and(|s| Arc::ptr_eq(s, &self.state))
                {
                    index.fills.remove(&self.key);
                }
                self.state.send_replace(FillState::Done { file: reader });
            }
            Ok(Err(error)) => {
                // The reservation is gone with the failed commit.
                self.size = 0;
                tracing::warn!(%sha256, %error, "blob cache fill: storing failed; serving from S3");
                self.fail();
            }
            Err(error) => {
                tracing::warn!(%sha256, %error, "blob cache fill: storing failed; serving from S3");
                self.fail();
            }
        }
    }

    /// Abandon the fill.
    fn fail(self) {
        drop(self);
    }
}

impl Drop for FillSlot {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.cache
            .inner
            .counters
            .fill_failures
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut index = self.cache.lock();
            self.cache.release(&mut index, self.size);
            if index
                .fills
                .get(&self.key)
                .is_some_and(|s| Arc::ptr_eq(s, &self.state))
            {
                index.fills.remove(&self.key);
            }
        }
        self.state.send_replace(FillState::Failed);
    }
}

/// Remove everything in `dir`; returns how many entries went.
/// Make an entry readable by Forge's user alone, however it was made (a
/// hard link keeps the staged file's mode).
fn make_private(file: &File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// Create the new file `path`, readable by Forge's user alone.
fn create_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn clear_dir(dir: &Path) -> std::io::Result<usize> {
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let gone = if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match gone {
            Ok(()) => removed += 1,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "cannot remove a partial blob cache fill")
            }
        }
    }
    Ok(removed)
}

/// Undo what the kubelet does to a volume of a pod with `fsGroup` (and no
/// `fsGroupChangePolicy: OnRootMismatch`) each time it mounts it: every
/// directory gets `mode | 02770`, every file `mode | 0660`. When `root` is
/// this process's user's and shows that mark (setgid, group-writable, not
/// writable by others), its directories go back to 0700 and its files to
/// 0600, and `true` is returned. Anything else is left for
/// [`crate::cas::ensure_owned_dir`] to judge.
///
/// Only Forge's user (or root) can have widened a directory it owns, and the
/// entries the scan then finds are checked against their hash on their first
/// hit, as after any restart.
fn restore_after_fs_group(root: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(root)?;
        let mode = meta.permissions().mode();
        if !meta.is_dir()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || mode & 0o2020 != 0o2020
            || mode & 0o002 != 0
        {
            return Ok(false);
        }
        fn chmod(path: &Path, mode: u32) -> std::io::Result<()> {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("cannot restore the mode of {}: {error}", path.display()),
                )
            })
        }
        fn restore(dir: &Path) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    restore(&entry.path())?;
                } else if kind.is_file() {
                    chmod(&entry.path(), 0o600)?;
                }
            }
            chmod(dir, 0o700)
        }
        restore(root)?;
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Ok(false)
    }
}

/// The cached blobs under `root`: `(key, size, mtime)`. Anything that is not
/// `<xx>/<sha256 starting with xx>` is left alone.
fn scan(root: &Path) -> std::io::Result<Vec<(Key, u64, SystemTime)>> {
    let mut found = Vec::new();
    for dir in std::fs::read_dir(root)? {
        let dir = dir?;
        let prefix = dir.file_name();
        let Some(prefix) = prefix.to_str() else {
            continue;
        };
        if prefix.len() != 2 || !dir.file_type()?.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(dir.path())? {
            let file = file?;
            let name = file.file_name();
            let Some(key) = name
                .to_str()
                .filter(|n| n.starts_with(prefix))
                .and_then(parse_key)
            else {
                continue;
            };
            let meta = file.metadata()?;
            if !meta.is_file() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            found.push((key, meta.len(), mtime));
        }
    }
    Ok(found)
}

/// Read up to `len` bytes of `file` at `offset` (blocking).
pub(crate) fn read_at(file: &File, offset: u64, len: usize) -> std::io::Result<Bytes> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        #[cfg(unix)]
        let n =
            std::os::unix::fs::FileExt::read_at(file, &mut buf[filled..], offset + filled as u64)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_read(
            file,
            &mut buf[filled..],
            offset + filled as u64,
        )?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "blob cache file is shorter than expected",
            ));
        }
        filled += n;
    }
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    #[test]
    fn auto_is_the_filesystem_minus_min_free_and_staging() {
        let fs = FsSpace {
            total: 100 * GIB,
            available: 100 * GIB,
        };
        // Default min_free: 5 % of the filesystem.
        assert_eq!(effective_limit(CacheLimit::Auto, None, 0, fs, 0), 95 * GIB);
        assert_eq!(
            effective_limit(CacheLimit::Auto, Some(10 * GIB), 4 * GIB, fs, 0),
            86 * GIB
        );
    }

    #[test]
    fn a_fixed_limit_is_capped_by_min_free() {
        let fs = FsSpace {
            total: 100 * GIB,
            available: 30 * GIB,
        };
        // 20 GiB cached + 30 GiB free: the cache may grow by 30 - 5 GiB.
        assert_eq!(
            effective_limit(CacheLimit::Bytes(80 * GIB), None, 0, fs, 20 * GIB),
            45 * GIB
        );
        assert_eq!(
            effective_limit(CacheLimit::Bytes(10 * GIB), None, 0, fs, 0),
            10 * GIB
        );
        // Something else filled the disk past min_free: shrink below usage.
        let full = FsSpace {
            total: 100 * GIB,
            available: GIB,
        };
        assert_eq!(
            effective_limit(
                CacheLimit::Bytes(80 * GIB),
                Some(2 * GIB),
                0,
                full,
                20 * GIB
            ),
            19 * GIB
        );
    }

    #[test]
    fn auto_is_capped_by_free_space_too() {
        let fs = FsSpace {
            total: 100 * GIB,
            available: 10 * GIB,
        };
        assert_eq!(
            effective_limit(CacheLimit::Auto, Some(GIB), 0, fs, 50 * GIB),
            59 * GIB
        );
    }

    #[test]
    fn keys_are_lowercase_hex_sha256_only() {
        let sha = "ab".repeat(32);
        let key = parse_key(&sha).expect("valid");
        assert_eq!(hex(&key), sha);
        assert!(parse_key(&"AB".repeat(32)).is_none());
        assert!(parse_key("../etc/passwd").is_none());
        assert!(parse_key(&"ab".repeat(31)).is_none());
    }

    #[test]
    fn the_fifo_skips_forgotten_entries() {
        let mut index = Index::default();
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        index.push(a, 10, true);
        index.push(b, 20, true);
        index.push(c, 30, true);
        assert!(index.forget(&b, None).is_some());
        // `a` filled again: its old queue position is stale.
        index.forget(&a, None);
        index.push(a, 10, true);
        assert_eq!(index.bytes, 40);
        assert_eq!(index.pop_oldest().map(|(k, _)| k), Some(c));
        assert_eq!(index.pop_oldest().map(|(k, _)| k), Some(a));
        assert_eq!(index.pop_oldest().map(|(k, _)| k), None);
        assert_eq!(index.bytes, 0);
    }

    #[test]
    fn a_fill_holds_back_its_last_byte_until_checked() {
        let file = Arc::new(tempfile::tempfile().unwrap());
        let writing = FillState::Writing {
            file: file.clone(),
            written: 10,
        };
        assert_eq!(writing.readable(10).map(|(_, n)| n), Some(9));
        assert_eq!(writing.readable(20).map(|(_, n)| n), Some(10));
        let done = FillState::Done { file };
        assert_eq!(done.readable(10).map(|(_, n)| n), Some(10));
        assert!(FillState::Failed.readable(10).is_none());
    }
}
