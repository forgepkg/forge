//! Content-addressed storage (CAS) ingest.
//!
//! [`Cas::stage`] streams an arbitrary reader to a temp file while hashing it
//! without mutating the database or S3. [`Cas::commit`] then registers an ingest
//! lease and uploads the object **only if absent**. The lease fences deferred
//! deletion until the caller atomically consumes it with
//! `blob_dao::commit_ingest_and_incref` in the transaction that attaches the
//! component/asset reference.
//!
//! The returned [`StoredBlob`] keeps the temp file alive ([`tempfile::TempPath`])
//! so the caller can hand it to a format parser before dropping it.
//!
//! ## Temp space
//!
//! Staged files live in one directory ([`Staging`]) and count against an
//! optional byte budget shared by every upload and download of the process:
//! bytes are reserved as they arrive and released when the temp file is
//! dropped, and a stage that would exceed the budget fails with
//! [`CasError::StagingFull`] instead of filling the disk (a burst of
//! first-time proxy downloads of large packages would otherwise get the pod
//! evicted). Each process stages in a subdirectory of its own, locked while
//! the process lives, so [`Staging::sweep_stale`] removes what a killed
//! process left there at startup, however recent, instead of letting it take
//! up space beside the new process's budget.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use sqlx::PgPool;
use tempfile::TempPath;
use tokio::io::{copy, AsyncRead, ReadBuf};
use tokio::sync::Semaphore;

use crate::hash::HashingWriter;
use crate::s3::{BlobStore, S3Error};

/// An ingest lease comfortably covers S3 promotion plus package transaction
/// work. Abandoned leases are ignored after this bound and pruned by the
/// reconciler; successful commits consume them immediately.
const INGEST_LEASE: chrono::Duration = chrono::Duration::hours(1);

/// Renew far ahead of expiry. The heartbeat runs independently of an
/// arbitrarily slow S3 request and remains alive with `StoredBlob` through the
/// caller's database transaction.
const INGEST_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(20);

/// A crashed delete owner may be fenced out after this interval. S3 deletion
/// is idempotent, and the DB token prevents the stale owner from finalizing a
/// reservation it no longer owns.
pub(crate) const DELETE_RESERVATION_LEASE: chrono::Duration = chrono::Duration::seconds(60);

/// Poll interval while a healthy peer is completing an S3 delete.
const DELETION_WAIT: std::time::Duration = std::time::Duration::from_millis(25);

/// Errors raised while ingesting content into the CAS.
#[derive(Debug, thiserror::Error)]
pub enum CasError {
    #[error("content exceeds max_bytes limit of {limit} bytes")]
    TooLarge { limit: u64 },
    /// Staging this content would exceed the process-wide temp-space budget
    /// (`limit` bytes); the caller should answer "try again later".
    #[error("temporary staging space is exhausted ({limit} bytes in use)")]
    StagingFull { limit: u64 },
    #[error("content size {size} bytes exceeds i64::MAX and cannot be stored")]
    SizeOverflow { size: u64 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("s3 error: {0}")]
    S3(#[from] S3Error),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Locally staged bytes and their content hashes.
///
/// Staging is intentionally mutation-free so a format parser and authorization
/// policy can inspect package identity before any database/S3 side effect.
#[derive(Debug)]
pub struct StagedBlob {
    pub sha256: String,
    pub sha512_base64: String,
    pub size: u64,
    pub temp_path: TempPath,
    /// The temp-space reservation, released with the temp file.
    reservation: Option<Reservation>,
    /// Keeps the process's staging subdirectory (and its lock) alive while
    /// the temp file is in it.
    own_dir: Option<Arc<OwnDir>>,
}

/// Result of ingesting content: its content address, integrity hash, size, and
/// the live temp file holding the bytes.
#[derive(Debug)]
pub struct StoredBlob {
    /// Lowercase hex SHA-256 — the blob primary key and S3 key material.
    pub sha256: String,
    /// Standard base64 SHA-512 — for asset integrity / NuGet hash fields.
    pub sha512_base64: String,
    /// Total byte count.
    pub size: u64,
    /// The temp file holding the content. Kept alive so callers can re-read it
    /// (e.g. parse the package) before it is dropped/unlinked.
    pub temp_path: TempPath,
    /// The S3 key the object was stored under.
    pub s3_key: String,
    /// Whether this ingest performed a fresh S3 upload (`false` = dedup hit).
    pub uploaded: bool,
    /// Lease consumed atomically with the reference-count increment.
    pub ingest_token: uuid::Uuid,
    _lease_guard: IngestLeaseGuard,
    /// The temp-space reservation, released with the temp file.
    _reservation: Option<Reservation>,
    /// Keeps the staging subdirectory alive while the temp file is in it.
    _own_dir: Option<Arc<OwnDir>>,
}

/// Bytes reserved from a staging budget, given back when dropped. Counted in
/// `u64` itself: a tokio permit keeps its count in a `u32`, which one staged
/// file of 4 GiB or more would overflow.
#[derive(Debug)]
struct Reservation {
    budget: Arc<Semaphore>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget
            .add_permits(usize::try_from(self.bytes).unwrap_or(usize::MAX));
    }
}

#[derive(Debug)]
struct IngestLeaseGuard {
    token: uuid::Uuid,
    pool: PgPool,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl IngestLeaseGuard {
    fn start(pool: PgPool, token: uuid::Uuid) -> Self {
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let heartbeat_pool = pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(INGEST_HEARTBEAT);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = ticker.tick() => {
                        match forge_db::blob_dao::refresh_ingest(
                            &heartbeat_pool,
                            token,
                            chrono::Utc::now() + INGEST_LEASE,
                        ).await {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(error) => tracing::warn!(
                                ingest_token = %token,
                                error = %error,
                                "failed to renew blob ingest lease"
                            ),
                        }
                    }
                }
            }
        });
        Self {
            token,
            pool,
            stop: Some(stop),
        }
    }
}

impl Drop for IngestLeaseGuard {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // Successful reference transactions already consumed the token. On
        // every rollback/early-return path this best-effort cleanup removes the
        // deletion fence immediately instead of waiting for lease expiry.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let pool = self.pool.clone();
            let token = self.token;
            runtime.spawn(async move {
                if let Err(error) = forge_db::blob_dao::abort_ingest(&pool, token).await {
                    tracing::warn!(
                        ingest_token = %token,
                        error = %error,
                        "failed to release dropped blob ingest lease"
                    );
                }
            });
        }
    }
}

/// Where staged bytes are written and how many may be staged at once.
#[derive(Clone, Debug)]
pub struct Staging {
    /// The staging directory, possibly shared with other processes.
    dir: PathBuf,
    /// This process's own subdirectory of `dir`, where it stages (`None` only
    /// for the fallback of [`Staging::default`], which stages in `dir`).
    own: Option<Arc<OwnDir>>,
    /// One permit per byte; `None` = no budget.
    budget: Option<Arc<Semaphore>>,
    limit: u64,
}

/// A process's own staging subdirectory, removed with the last handle to it.
/// Its lock file stays locked (`flock`) while the directory is in use, and
/// the kernel releases the lock when the process dies: that is how
/// [`Staging::sweep_stale`] tells a live process's directory, however old,
/// from one a killed process left, however recent.
#[derive(Debug)]
struct OwnDir {
    path: PathBuf,
    _lock: std::fs::File,
}

impl OwnDir {
    /// Create and lock a new subdirectory of `dir`. It is locked under a
    /// hidden name and only then renamed to one a sweep looks at, so no sweep
    /// ever finds it unlocked.
    fn create(dir: &Path) -> std::io::Result<Arc<Self>> {
        let name = format!(
            "{}{}",
            Staging::OWN_DIR_PREFIX,
            uuid::Uuid::new_v4().simple()
        );
        let pending = dir.join(format!(".{name}"));
        let path = dir.join(name);
        std::fs::create_dir(&pending)?;
        let locked = (|| {
            let lock = std::fs::File::create(pending.join(Staging::LOCK_FILE))?;
            lock.try_lock()?;
            std::fs::rename(&pending, &path)?;
            Ok(lock)
        })();
        match locked {
            Ok(lock) => Ok(Arc::new(OwnDir { path, _lock: lock })),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&pending);
                Err(e)
            }
        }
    }
}

impl Drop for OwnDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Staging {
    /// File-name prefix of staged files.
    const PREFIX: &'static str = "forge-staging-";

    /// Name prefix of a process's own subdirectory ([`OwnDir`]).
    const OWN_DIR_PREFIX: &'static str = "forge-staging-proc-";

    /// The lock file in such a subdirectory.
    const LOCK_FILE: &'static str = ".lock";

    /// The default staging directory: `forge-staging` under the system temp
    /// directory.
    pub fn default_dir() -> PathBuf {
        std::env::temp_dir().join("forge-staging")
    }

    /// Stage under `dir` (created if missing), in a new subdirectory of this
    /// process's own, with at most `max_bytes` in use at once (`None`: no
    /// budget).
    pub fn new(dir: impl Into<PathBuf>, max_bytes: Option<u64>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let own = Some(OwnDir::create(&dir)?);
        let limit = max_bytes.unwrap_or(0);
        let budget = max_bytes.map(|bytes| {
            let permits = usize::try_from(bytes)
                .unwrap_or(usize::MAX)
                .min(Semaphore::MAX_PERMITS);
            Arc::new(Semaphore::new(permits))
        });
        Ok(Staging {
            dir,
            own,
            budget,
            limit,
        })
    }

    /// The staging directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where this process stages its files.
    fn own_dir(&self) -> &Path {
        self.own.as_ref().map_or(&self.dir, |own| &own.path)
    }

    /// Remove what killed processes left in the staging directory. Returns
    /// how many staged files were removed.
    ///
    /// - A process subdirectory goes whenever its lock is free, whatever its
    ///   age: a live process (this one, or another instance sharing the
    ///   directory) holds its lock until it exits.
    /// - Loose staged files (from versions that staged in the directory
    ///   itself) go once not modified for `older_than`: a running stage writes
    ///   its file continuously and holds it for seconds after, so a long-idle
    ///   one is orphaned. So do subdirectories whose creation was cut short.
    pub fn sweep_stale(&self, older_than: std::time::Duration) -> std::io::Result<usize> {
        let now = std::time::SystemTime::now();
        let idle = |meta: &std::fs::Metadata| {
            meta.modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .unwrap_or_default()
        };
        let is_staged = |name: &str| name.starts_with(Self::PREFIX);
        let mut removed = 0;
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Ok(meta) = entry.metadata() else { continue };
            let path = entry.path();
            if meta.is_dir() && name.starts_with(Self::OWN_DIR_PREFIX) {
                // Taking the lock proves its process gone; held until removed.
                let Ok(lock) = std::fs::File::open(path.join(Self::LOCK_FILE)) else {
                    continue;
                };
                if lock.try_lock().is_err() {
                    continue;
                }
                let staged = std::fs::read_dir(&path).map_or(0, |entries| {
                    entries
                        .filter_map(Result::ok)
                        .filter(|entry| is_staged(&entry.file_name().to_string_lossy()))
                        .count()
                });
                if std::fs::remove_dir_all(&path).is_ok() {
                    removed += staged;
                }
            } else if meta.is_dir()
                && name
                    .strip_prefix('.')
                    .is_some_and(|name| name.starts_with(Self::OWN_DIR_PREFIX))
                && idle(&meta) >= older_than
            {
                let _ = std::fs::remove_dir_all(&path);
            } else if meta.is_file()
                && is_staged(&name)
                && idle(&meta) >= older_than
                && std::fs::remove_file(&path).is_ok()
            {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

impl Default for Staging {
    /// [`Self::default_dir`] without a budget. Falls back to the system temp
    /// directory itself if the subdirectory cannot be created.
    fn default() -> Self {
        Staging::new(Self::default_dir(), None).unwrap_or_else(|_| Staging {
            dir: std::env::temp_dir(),
            own: None,
            budget: None,
            limit: 0,
        })
    }
}

/// Content-addressed store coordinating the S3 object store and the blob table.
#[derive(Clone)]
pub struct Cas {
    store: BlobStore,
    pool: PgPool,
    staging: Staging,
}

impl Cas {
    pub fn new(store: BlobStore, pool: PgPool) -> Self {
        Self {
            store,
            pool,
            staging: Staging::default(),
        }
    }

    /// Stage into `staging` (directory and temp-space budget) instead of the
    /// unbounded default.
    pub fn with_staging(mut self, staging: Staging) -> Self {
        self.staging = staging;
        self
    }

    /// Compute the stable prefix for a content hash:
    /// `blobs/sha256/{aa}/{bb}/{hash}`.
    ///
    /// New CAS rows append an incarnation UUID to this prefix. Existing rows
    /// keep their stored key. The suffix prevents a delayed DELETE for a
    /// garbage-collected incarnation from deleting a newly revived object.
    pub fn blob_key(sha256: &str) -> String {
        // sha256 hex is 64 chars; aa/bb are the first two byte-pairs.
        let aa = &sha256[0..2];
        let bb = &sha256[2..4];
        format!("blobs/sha256/{aa}/{bb}/{sha256}")
    }

    /// Stage `reader` into a local temp file without DB or S3 mutation.
    ///
    /// 1. Copy bytes into a temp file via [`HashingWriter`], enforcing
    ///    `max_bytes`.
    ///
    /// The temp file is cleaned up automatically on every error path (RAII via
    /// [`TempPath`]).
    pub async fn stage<R>(&self, reader: R, max_bytes: u64) -> Result<StagedBlob, CasError>
    where
        R: AsyncRead + Unpin,
    {
        // Hold a NamedTempFile; convert to TempPath only on success. Until then,
        // dropping it (on any early return) unlinks the file.
        let temp = tempfile::Builder::new()
            .prefix(Staging::PREFIX)
            .tempfile_in(self.staging.own_dir())?;

        // Cap the body while streaming so we never buffer an oversized
        // payload to disk in full, and reserve temp space as it arrives.
        let mut reader = BudgetedReader {
            inner: LimitedReader::new(reader, max_bytes),
            budget: self.staging.budget.clone(),
            reservation: None,
            exhausted: false,
        };
        let (sha256, sha512_base64, size) = {
            let file = tokio::fs::File::create(temp.path()).await?;
            let mut writer = HashingWriter::new(file);
            match copy(&mut reader, &mut writer).await {
                Ok(_) => {}
                // The copy failed because we tripped a limit; surface a typed
                // error rather than the synthetic io error.
                Err(_) if reader.inner.exceeded => {
                    return Err(CasError::TooLarge { limit: max_bytes });
                }
                Err(_) if reader.exhausted => {
                    tracing::warn!(
                        limit = self.staging.limit,
                        dir = %self.staging.dir.display(),
                        "staging budget exhausted; refusing this upload or download for now"
                    );
                    return Err(CasError::StagingFull {
                        limit: self.staging.limit,
                    });
                }
                Err(e) => return Err(CasError::Io(e)),
            }
            // `finalize` flushes the inner file and returns the digests + size.
            writer.finalize().await?
        };

        let temp_path = temp.into_temp_path();
        Ok(StagedBlob {
            sha256,
            sha512_base64,
            size,
            temp_path,
            reservation: reader.reservation,
            own_dir: self.staging.own.clone(),
        })
    }

    /// Promote locally staged bytes into the CAS and register an ingest lease.
    ///
    /// Lease registration happens before S3 HEAD/PUT. A delete reservation and
    /// an ingest lease both lock the same blob row, so a deletion can neither
    /// start after this method observes the old object nor run before the
    /// caller consumes `ingest_token` in its reference transaction.
    pub async fn commit(&self, staged: StagedBlob) -> Result<StoredBlob, CasError> {
        let size_i64 =
            i64::try_from(staged.size).map_err(|_| CasError::SizeOverflow { size: staged.size })?;
        let candidate_s3_key = format!(
            "{}/{}",
            Self::blob_key(&staged.sha256),
            uuid::Uuid::new_v4()
        );

        let (ingest_token, s3_key) = loop {
            let now = chrono::Utc::now();
            match forge_db::blob_dao::begin_ingest(
                &self.pool,
                &staged.sha256,
                size_i64,
                &candidate_s3_key,
                now + INGEST_LEASE,
                now - DELETE_RESERVATION_LEASE,
            )
            .await?
            {
                forge_db::blob_dao::BeginIngestOutcome::Ready { token, s3_key, .. } => {
                    break (token, s3_key)
                }
                forge_db::blob_dao::BeginIngestOutcome::DeletionInProgress => {
                    tokio::time::sleep(DELETION_WAIT).await;
                }
                forge_db::blob_dao::BeginIngestOutcome::CompleteStaleDeletion(reservation) => {
                    if let Err(error) = self.store.delete(&reservation.s3_key).await {
                        // A failed response can be ambiguous: the delete may
                        // still complete after this call returns. Keep the
                        // reservation fenced instead of making its key
                        // reusable. A later owner will take over the stale
                        // reservation, finish deletion, and only then create a
                        // fresh blob incarnation.
                        return Err(error.into());
                    }
                    // A newer owner may have fenced us out. Either way, retry
                    // from the retained temp file and re-observe DB state.
                    let _ =
                        forge_db::blob_dao::finalize_delete_reservation(&self.pool, &reservation)
                            .await?;
                }
            }
        };
        let lease_guard = IngestLeaseGuard::start(self.pool.clone(), ingest_token);

        // Content addressing guarantees an existing object is byte-identical.
        // The live ingest lease prevents a deleter from racing this check/put.
        let uploaded = match self.store.put_if_absent(&s3_key, &staged.temp_path).await {
            Ok(uploaded) => uploaded,
            Err(error) => {
                let _ = forge_db::blob_dao::abort_ingest(&self.pool, ingest_token).await;
                return Err(error.into());
            }
        };

        Ok(StoredBlob {
            sha256: staged.sha256,
            sha512_base64: staged.sha512_base64,
            size: staged.size,
            temp_path: staged.temp_path,
            s3_key,
            uploaded,
            ingest_token,
            _lease_guard: lease_guard,
            _reservation: staged.reservation,
            _own_dir: staged.own_dir,
        })
    }

    /// Stage and immediately promote bytes. Callers that need to parse and
    /// authorize package identity before mutation should call [`Self::stage`]
    /// and [`Self::commit`] separately.
    pub async fn store<R>(&self, reader: R, max_bytes: u64) -> Result<StoredBlob, CasError>
    where
        R: AsyncRead + Unpin,
    {
        let staged = self.stage(reader, max_bytes).await?;
        self.commit(staged).await
    }
}

/// A reader adapter that stops the stream once more than `limit` bytes have been
/// read. It records the overflow in `exceeded` and returns an io error so the
/// surrounding `copy` aborts; the caller maps that to [`CasError::TooLarge`].
struct LimitedReader<R> {
    inner: R,
    remaining: u64,
    exceeded: bool,
}

impl<R> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
            exceeded: false,
        }
    }
}

/// Reserves one permit of the staging budget per byte read, failing the read
/// (and flagging `exhausted`) when the budget has none left. The permits are
/// counted in `reservation` and given back when the staged file is dropped.
struct BudgetedReader<R> {
    inner: R,
    budget: Option<Arc<Semaphore>>,
    reservation: Option<Reservation>,
    exhausted: bool,
}

impl<R: AsyncRead + Unpin> AsyncRead for BudgetedReader<LimitedReader<R>> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let me = &mut *self;
        match Pin::new(&mut me.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len() - before;
                let Some(budget) = me.budget.as_ref().filter(|_| read > 0) else {
                    return Poll::Ready(Ok(()));
                };
                // A read never exceeds the caller's buffer, far below u32::MAX.
                let permits = u32::try_from(read).unwrap_or(u32::MAX);
                match budget.try_acquire_many(permits) {
                    Ok(permit) => {
                        // Tracked (and given back) by `Reservation` instead.
                        permit.forget();
                        let reservation = me.reservation.get_or_insert_with(|| Reservation {
                            budget: budget.clone(),
                            bytes: 0,
                        });
                        reservation.bytes += u64::from(permits);
                        Poll::Ready(Ok(()))
                    }
                    Err(_) => {
                        me.exhausted = true;
                        Poll::Ready(Err(std::io::Error::other("staging budget exhausted")))
                    }
                }
            }
            other => other,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LimitedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let me = &mut *self;
        match Pin::new(&mut me.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = (buf.filled().len() - before) as u64;
                if read > me.remaining {
                    me.exceeded = true;
                    return Poll::Ready(Err(std::io::Error::other("max_bytes exceeded")));
                }
                me.remaining -= read;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reservation of more than `u32::MAX` bytes (one staged file of 4 GiB
    /// or more) is given back whole.
    #[test]
    fn a_reservation_above_u32_is_given_back_whole() {
        const GIB: usize = 1 << 30;
        let budget = Arc::new(Semaphore::new(8 * GIB));
        let mut reservation = Reservation {
            budget: budget.clone(),
            bytes: 0,
        };
        for _ in 0..5 {
            budget.try_acquire_many(GIB as u32).unwrap().forget();
            reservation.bytes += GIB as u64;
        }
        assert_eq!(budget.available_permits(), 3 * GIB);
        drop(reservation);
        assert_eq!(budget.available_permits(), 8 * GIB);
    }
}
