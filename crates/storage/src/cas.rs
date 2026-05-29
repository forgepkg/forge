//! Content-addressed storage (CAS) ingest.
//!
//! [`Cas::store`] streams an arbitrary reader to a temp file while hashing it,
//! records a `pending` blob row (dedup-safe via `ON CONFLICT DO NOTHING`), and
//! uploads the object to S3 **only if absent**. It deliberately does NOT incref
//! the blob or insert any asset row — that is the caller's job, done in its own
//! transaction together with `commit_and_incref` once the surrounding write
//! (e.g. an asset/component insert) is known to succeed.
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

/// Errors raised while ingesting content into the CAS.
#[derive(Debug, thiserror::Error)]
pub enum CasError {
    #[error("content exceeds max_bytes limit of {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("s3 error: {0}")]
    S3(#[from] S3Error),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
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

    /// Compute the S3 key for a content hash: `blobs/sha256/{aa}/{bb}/{hash}`.
    pub fn blob_key(sha256: &str) -> String {
        // sha256 hex is 64 chars; aa/bb are the first two byte-pairs.
        let aa = &sha256[0..2];
        let bb = &sha256[2..4];
        format!("blobs/sha256/{aa}/{bb}/{sha256}")
    }

    /// Stream `reader` into the CAS.
    ///
    /// 1. Copy bytes into a temp file via [`HashingWriter`], enforcing
    ///    `max_bytes`.
    /// 2. `upsert_pending` the blob row (no-op if it already exists).
    /// 3. `put_if_absent` the object (HEAD-then-PUT dedup — no duplicate upload
    ///    for content already present).
    ///
    /// Does not incref or touch assets; see the module docs. The temp file is
    /// cleaned up automatically on every error path (RAII via [`TempPath`]).
    pub async fn store<R>(&self, reader: R, max_bytes: u64) -> Result<StoredBlob, CasError>
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

        let size_i64 = i64::try_from(size).unwrap_or(i64::MAX);
        let s3_key = Self::blob_key(&sha256);

        // Record the pending row (idempotent across concurrent ingests).
        forge_db::blob_dao::upsert_pending(&self.pool, &sha256, size_i64, &s3_key).await?;

        // Upload only if absent. Content addressing guarantees an existing
        // object is byte-identical, so a dedup hit needs no upload.
        let temp_path = temp.into_temp_path();
        let uploaded = self.store.put_if_absent(&s3_key, &temp_path).await?;

        Ok(StoredBlob {
            sha256,
            sha512_base64,
            size,
            temp_path,
            s3_key,
            uploaded,
        })
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
