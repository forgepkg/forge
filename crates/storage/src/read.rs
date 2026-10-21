//! Reading stored blobs, through the local blob cache when there is one.
//!
//! Without a cache, [`BlobStore::open`] streams the object from S3. With
//! one ([`BlobStore::with_cache`]):
//!
//! * **Hit:** the cached file is streamed; S3 is not contacted.
//! * **Miss:** one request (the leader) streams the object from S3 into a
//!   new cache file; it and every concurrent request for the same blob read
//!   that file as it grows. The fill runs on its own, so it completes even
//!   when its clients disconnect, and the file is checked against the
//!   blob's hash and size before it joins the cache. A reader is handed a
//!   fill's last byte only after that check, so no response completes with
//!   unchecked bytes.
//! * **Fail open:** when the cache cannot help (no room, a fill or a cache
//!   read fails), a reader continues from S3 at the offset it has reached.
//!
//! While S3 is down, hits are served as usual and misses fail at once with
//! [`S3Error::Unavailable`].

use std::fs::File;
use std::ops::Range;
use std::sync::Arc;

use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use futures_util::StreamExt;
use tokio::sync::watch;

use crate::blob_cache::{read_at, Begin, BlobCache, BlobStream, FillSlot, FillState};
use crate::s3::{BlobStore, S3Error};

/// A stored blob: its content hash, where S3 keeps it, and its size (the
/// `blob` row).
#[derive(Debug, Clone, Copy)]
pub struct BlobRef<'a> {
    /// Lowercase hex SHA-256 (the cache key).
    pub sha256: &'a str,
    /// The S3 object key.
    pub s3_key: &'a str,
    /// Size in bytes.
    pub size: u64,
}

/// Bytes read from a cached file at once.
const READ_CHUNK: u64 = 256 * 1024;

impl BlobStore {
    /// Stream `range` of `blob` (all of it for `None`; clamped to the blob).
    ///
    /// Errors before the first byte (S3 unreachable, a missing object) are
    /// returned here; an error after that ends the stream with an error.
    pub async fn open(
        &self,
        blob: BlobRef<'_>,
        range: Option<Range<u64>>,
    ) -> Result<BlobStream, S3Error> {
        let (start, end) = match &range {
            Some(range) => (range.start, range.end.min(blob.size)),
            None => (0, blob.size),
        };
        if start >= end && range.is_some() {
            return Ok(Box::pin(futures_util::stream::empty()));
        }
        let Some(cache) = self.cache() else {
            return Ok(s3_stream(self.get_range(blob.s3_key, range).await?));
        };
        for _ in 0..3 {
            if let Some(file) = cache.lookup(blob.sha256, blob.size).await {
                cache.record_hit(self.is_unavailable());
                let mut reader = self.reader(blob, start, end, Source::File(file));
                reader.hit = Some(cache.clone());
                return Ok(reader.into_stream());
            }
            match cache.begin_fill(blob.sha256, blob.size) {
                // Filled meanwhile: look it up again.
                Begin::Cached => continue,
                Begin::Join(fill) => {
                    cache.record_miss();
                    return self.follow(blob, start, end, fill).await;
                }
                Begin::Lead(slot) => {
                    cache.record_miss();
                    return self.lead(blob, start, end, slot).await;
                }
                Begin::Bypass => {
                    cache.record_miss();
                    break;
                }
            }
        }
        self.direct(blob, start, end).await
    }

    /// Read a whole (small) blob into memory, through the cache.
    pub async fn read_all(&self, blob: BlobRef<'_>) -> Result<Vec<u8>, S3Error> {
        let mut stream = self.open(blob, None).await?;
        let mut bytes = Vec::with_capacity(usize::try_from(blob.size).unwrap_or(0).min(1 << 20));
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
        }
        Ok(bytes)
    }

    /// `start..end` of `blob` straight from S3.
    async fn direct(&self, blob: BlobRef<'_>, start: u64, end: u64) -> Result<BlobStream, S3Error> {
        let range = (start > 0 || end < blob.size).then_some(start..end);
        Ok(s3_stream(self.get_range(blob.s3_key, range).await?))
    }

    /// Read along with another request's fill once it has S3's answer;
    /// straight from S3 if that fill fails before.
    async fn follow(
        &self,
        blob: BlobRef<'_>,
        start: u64,
        end: u64,
        mut fill: watch::Receiver<FillState>,
    ) -> Result<BlobStream, S3Error> {
        loop {
            let started = match &*fill.borrow_and_update() {
                FillState::Starting => None,
                FillState::Failed => Some(false),
                FillState::Writing { .. } | FillState::Done { .. } => Some(true),
            };
            match started {
                Some(true) => {
                    return Ok(self
                        .reader(blob, start, end, Source::Fill(fill))
                        .into_stream())
                }
                Some(false) => break,
                None => {
                    if fill.changed().await.is_err() {
                        break;
                    }
                }
            }
        }
        self.direct(blob, start, end).await
    }

    /// Fill the cache with `blob` and read along. Without a cache file to
    /// fill, this request is served from the S3 response alone.
    async fn lead(
        &self,
        blob: BlobRef<'_>,
        start: u64,
        end: u64,
        slot: FillSlot,
    ) -> Result<BlobStream, S3Error> {
        // A failure here drops the slot, which sends readers to S3.
        let body = self.get(blob.s3_key).await?;
        match slot.create_file() {
            Ok((file, reader, path)) => {
                let fill = slot.subscribe();
                tokio::spawn(slot.run(s3_stream(body), file, reader, path));
                Ok(self
                    .reader(blob, start, end, Source::Fill(fill))
                    .into_stream())
            }
            Err(error) => {
                tracing::warn!(sha256 = blob.sha256, %error, "blob cache: cannot create a fill file; serving from S3");
                drop(slot);
                if start == 0 && end == blob.size {
                    Ok(s3_stream(body))
                } else {
                    self.direct(blob, start, end).await
                }
            }
        }
    }

    fn reader(&self, blob: BlobRef<'_>, start: u64, end: u64, source: Source) -> Reader {
        Reader {
            store: self.clone(),
            sha256: blob.sha256.to_string(),
            s3_key: blob.s3_key.to_string(),
            size: blob.size,
            pos: start,
            end,
            source,
            hit: None,
        }
    }
}

/// An S3 response body as a [`BlobStream`].
fn s3_stream(body: ByteStream) -> BlobStream {
    Box::pin(futures_util::stream::unfold(body, |mut body| async move {
        body.next()
            .await
            .map(|chunk| (chunk.map_err(std::io::Error::other), body))
    }))
}

/// Where a [`Reader`] takes its bytes from.
enum Source {
    /// A complete, checked cache file.
    File(Arc<File>),
    /// A fill in progress.
    Fill(watch::Receiver<FillState>),
    /// S3, from the reader's offset.
    S3(ByteStream),
    /// Ended (after an error).
    Ended,
}

/// Streams `pos..end` of a blob from the cache, continuing from S3 when the
/// cache fails.
struct Reader {
    store: BlobStore,
    sha256: String,
    s3_key: String,
    size: u64,
    pos: u64,
    end: u64,
    source: Source,
    /// Set for a hit: counts the bytes it serves.
    hit: Option<BlobCache>,
}

/// What a reader of a fill does next.
enum Step {
    Read(Arc<File>, u64),
    Wait,
    Fallback,
}

impl Reader {
    fn into_stream(self) -> BlobStream {
        Box::pin(futures_util::stream::unfold(
            self,
            |mut reader| async move { reader.next().await.map(|item| (item, reader)) },
        ))
    }

    async fn next(&mut self) -> Option<std::io::Result<Bytes>> {
        while self.pos < self.end {
            match &mut self.source {
                Source::Ended => return None,
                Source::File(file) => {
                    let file = file.clone();
                    match self.read(file, self.end).await {
                        Ok(bytes) => {
                            if let Some(cache) = &self.hit {
                                cache.record_hit_bytes(bytes.len() as u64);
                            }
                            return Some(Ok(bytes));
                        }
                        Err(error) => {
                            tracing::warn!(sha256 = %self.sha256, %error, "blob cache: reading a cached file failed; dropping it and continuing from S3");
                            if let Some(cache) = self.store.cache() {
                                cache.evict(&self.sha256);
                            }
                            if let Err(error) = self.fallback().await {
                                return Some(Err(error));
                            }
                        }
                    }
                }
                Source::Fill(fill) => {
                    let step = {
                        let state = fill.borrow_and_update();
                        match &*state {
                            FillState::Failed => Step::Fallback,
                            other => match other.readable(self.size) {
                                Some((file, readable)) if readable > self.pos => {
                                    Step::Read(file, readable)
                                }
                                _ => Step::Wait,
                            },
                        }
                    };
                    match step {
                        Step::Read(file, readable) => {
                            match self.read(file, readable.min(self.end)).await {
                                Ok(bytes) => return Some(Ok(bytes)),
                                Err(error) => {
                                    tracing::warn!(sha256 = %self.sha256, %error, "blob cache: reading a fill failed; continuing from S3");
                                    if let Err(error) = self.fallback().await {
                                        return Some(Err(error));
                                    }
                                }
                            }
                        }
                        Step::Wait => {
                            if fill.changed().await.is_err() {
                                // The fill ended without a final state.
                                if let Err(error) = self.fallback().await {
                                    return Some(Err(error));
                                }
                            }
                        }
                        Step::Fallback => {
                            if let Err(error) = self.fallback().await {
                                return Some(Err(error));
                            }
                        }
                    }
                }
                Source::S3(body) => {
                    return match body.next().await {
                        Some(Ok(mut chunk)) => {
                            let left = self.end - self.pos;
                            if chunk.len() as u64 > left {
                                chunk.truncate(left as usize);
                            }
                            self.pos += chunk.len() as u64;
                            Some(Ok(chunk))
                        }
                        Some(Err(error)) => {
                            self.source = Source::Ended;
                            Some(Err(std::io::Error::other(error)))
                        }
                        None => {
                            self.source = Source::Ended;
                            Some(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "the object store ended the blob early",
                            )))
                        }
                    };
                }
            }
        }
        None
    }

    /// The next chunk of `file`, up to `limit`.
    async fn read(&mut self, file: Arc<File>, limit: u64) -> std::io::Result<Bytes> {
        let pos = self.pos;
        let len = (limit - pos).min(READ_CHUNK) as usize;
        let bytes = tokio::task::spawn_blocking(move || read_at(&file, pos, len))
            .await
            .map_err(std::io::Error::other)??;
        self.pos += bytes.len() as u64;
        Ok(bytes)
    }

    /// Continue from S3 at the current offset.
    async fn fallback(&mut self) -> std::io::Result<()> {
        self.hit = None;
        match self
            .store
            .get_range(&self.s3_key, Some(self.pos..self.end))
            .await
        {
            Ok(body) => {
                self.source = Source::S3(body);
                Ok(())
            }
            Err(error) => {
                self.source = Source::Ended;
                Err(std::io::Error::other(error))
            }
        }
    }
}
