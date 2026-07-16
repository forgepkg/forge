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

use std::pin::Pin;
use std::task::{Context, Poll};

use sqlx::PgPool;
use tempfile::TempPath;
use tokio::io::{copy, AsyncRead, ReadBuf};

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

/// Content-addressed store coordinating the S3 object store and the blob table.
#[derive(Clone)]
pub struct Cas {
    store: BlobStore,
    pool: PgPool,
}

impl Cas {
    pub fn new(store: BlobStore, pool: PgPool) -> Self {
        Self { store, pool }
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
        let temp = tempfile::NamedTempFile::new()?;

        let (sha256, sha512_base64, size) = {
            let file = tokio::fs::File::create(temp.path()).await?;
            let mut writer = HashingWriter::new(file);

            // Cap the body while streaming so we never buffer an oversized
            // payload to disk in full.
            let mut limited = LimitedReader::new(reader, max_bytes);
            match copy(&mut limited, &mut writer).await {
                Ok(_) => {}
                Err(e) if limited.exceeded => {
                    // The copy failed because we tripped the limit; surface a
                    // typed error rather than the synthetic io error.
                    let _ = e;
                    return Err(CasError::TooLarge { limit: max_bytes });
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
