//! S3-compatible blob object store.
//!
//! Wraps `aws-sdk-s3` with the configuration quirks needed to talk to
//! [versitygw](https://github.com/versity/versitygw) (and MinIO):
//!
//! * **Path-style addressing** — versitygw/MinIO expose buckets as
//!   `endpoint/bucket/key`, not `bucket.endpoint/key`.
//! * **Checksums disabled unless required** — aws-sdk-s3 1.x defaults to
//!   sending a `x-amz-checksum-crc32` (flexible checksum) on every upload.
//!   versitygw rejects or mishandles these, so we set both request and response
//!   checksum calculation to `WhenRequired`.
//!
//! CAS object keys use the layout
//! `blobs/sha256/{aa}/{bb}/{full-hash}/{incarnation}` where `aa`/`bb` are the
//! first two hex byte-pairs of the content's SHA-256. The incarnation suffix
//! fences delayed deletes after a fully garbage-collected blob is revived;
//! legacy rows without the suffix remain readable.

use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client;

use crate::blob_cache::BlobCache;
use crate::breaker::CircuitBreaker;

/// Errors raised by the blob store.
#[derive(Debug, thiserror::Error)]
pub enum S3Error {
    #[error("s3 error: {0}")]
    S3(String),
    /// S3 cannot be reached: the circuit breaker is open, or the call failed
    /// to connect, timed out or got a `5xx`. Only raised with the local blob
    /// cache enabled ([`BlobStore::with_cache`]), where the caller answers
    /// "try again later" instead of a server error.
    #[error("object store unavailable: {0}")]
    Unavailable(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl S3Error {
    /// Whether S3 could not be reached ([`S3Error::Unavailable`]).
    pub fn is_unavailable(&self) -> bool {
        matches!(self, S3Error::Unavailable(_))
    }
}

/// Dedup strategy for [`BlobStore::put_if_absent`].
///
/// A conditional PUT (`If-None-Match: *`) folds the existence check into the
/// upload itself: one round trip instead of HEAD + PUT, with the backend
/// answering `412 Precondition Failed` when the object already exists (a dedup
/// hit). Real AWS S3 and MinIO support this; versitygw answers
/// `501 NotImplemented`. This is purely an optimization — keys are
/// content-addressed, so observable behavior is identical on every path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConditionalWrites {
    /// Try the conditional PUT; on a `NotImplemented`/501-style rejection,
    /// permanently (for the process lifetime) fall back to HEAD-then-PUT and
    /// retry the failed put on that path.
    #[default]
    Auto,
    /// Always use the conditional PUT. A backend without support surfaces the
    /// `NotImplemented` error to the caller (a misconfiguration to fix, not
    /// silently paper over).
    On,
    /// Always use HEAD-then-PUT (the pre-conditional-writes behavior).
    Off,
}

/// Connection + behavior configuration for [`BlobStore`]. `Debug` omits the
/// secret key.
#[derive(Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    /// Path-style addressing (true for versitygw/MinIO, false for real AWS S3).
    pub force_path_style: bool,
    /// Bodies at or above this many bytes are uploaded via multipart.
    pub multipart_threshold: u64,
    /// `If-None-Match: *` dedup PUTs: auto-detect / force on / force off.
    pub conditional_writes: ConditionalWrites,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("force_path_style", &self.force_path_style)
            .field("multipart_threshold", &self.multipart_threshold)
            .field("conditional_writes", &self.conditional_writes)
            .finish()
    }
}

/// S3 connect deadline.
const S3_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Maximum wait for response data from S3 (first byte / between reads).
const S3_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// A content-addressed object store over an S3-compatible backend.
#[derive(Debug, Clone)]
pub struct BlobStore {
    client: Client,
    bucket: String,
    multipart_threshold: u64,
    conditional_writes: ConditionalWrites,
    /// Sticky latch for [`ConditionalWrites::Auto`]: set once the backend
    /// rejects `If-None-Match` with `NotImplemented`, after which every
    /// `put_if_absent` uses HEAD-then-PUT for the rest of the process
    /// lifetime. Shared (`Arc`) so clones of the store learn the verdict too.
    conditional_unsupported: Arc<AtomicBool>,
    /// The local blob cache in front of reads ([`Self::with_cache`]).
    cache: Option<BlobCache>,
    /// Fails calls fast while S3 is down; installed with the cache.
    breaker: Option<Arc<CircuitBreaker>>,
}

/// S3's minimum part size for all but the final part of a multipart upload.
const MULTIPART_PART_SIZE: u64 = 8 * 1024 * 1024; // 8 MiB

impl BlobStore {
    /// Build a store from [`S3Config`], wiring up the versitygw-friendly client.
    pub fn new(cfg: S3Config) -> Self {
        let creds = Credentials::new(cfg.access_key, cfg.secret_key, None, None, "forge-static");

        let s3_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(cfg.region))
            .endpoint_url(cfg.endpoint)
            .credentials_provider(creds)
            .force_path_style(cfg.force_path_style)
            // versitygw chokes on the aws-sdk default flexible checksums; only
            // emit/verify them when the operation actually demands it.
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            // Bound a stalled object store: connect, and the wait for response
            // data. No total-operation deadline — multi-hundred-MiB package
            // transfers must be allowed to take as long as they keep moving.
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(S3_CONNECT_TIMEOUT)
                    .read_timeout(S3_READ_TIMEOUT)
                    .build(),
            )
            .build();

        Self {
            client: Client::from_conf(s3_config),
            bucket: cfg.bucket,
            multipart_threshold: cfg.multipart_threshold,
            conditional_writes: cfg.conditional_writes,
            conditional_unsupported: Arc::new(AtomicBool::new(false)),
            cache: None,
            breaker: None,
        }
    }

    /// Put the local blob `cache` in front of reads ([`Self::open`]), write
    /// uploads through to it, and evict what [`Self::delete_blob`] deletes.
    /// Also installs a [`CircuitBreaker`]: while S3 is down, calls fail at
    /// once with [`S3Error::Unavailable`] instead of waiting for a timeout,
    /// and cached blobs are served as usual.
    pub fn with_cache(self, cache: BlobCache) -> Self {
        self.with_cache_and_breaker(cache, CircuitBreaker::default())
    }

    /// [`Self::with_cache`] with an explicitly tuned breaker (tests).
    pub fn with_cache_and_breaker(mut self, cache: BlobCache, breaker: CircuitBreaker) -> Self {
        self.cache = Some(cache);
        self.breaker = Some(Arc::new(breaker));
        self
    }

    /// The local blob cache, if enabled.
    pub fn cache(&self) -> Option<&BlobCache> {
        self.cache.as_ref()
    }

    /// Whether S3 is currently known to be down (the breaker is open).
    pub fn is_unavailable(&self) -> bool {
        self.breaker.as_ref().is_some_and(|b| b.is_open())
    }

    /// Fail fast while the breaker is open.
    fn admit(&self) -> Result<(), S3Error> {
        match &self.breaker {
            Some(breaker) if !breaker.admit() => Err(S3Error::Unavailable(
                "the object store is down (failing fast until it answers again)".into(),
            )),
            _ => Ok(()),
        }
    }

    /// Report a call's outcome to the breaker.
    fn observe<T, E>(&self, result: &Result<T, SdkError<E, HttpResponse>>) {
        if let Some(breaker) = &self.breaker {
            match result {
                Err(e) if is_unreachable(e) => breaker.record_failure(),
                _ => breaker.record_success(),
            }
        }
    }

    /// Convert an SDK error: [`S3Error::Unavailable`] when S3 could not be
    /// reached and the breaker is installed.
    fn error<E: std::fmt::Debug>(&self, e: SdkError<E, HttpResponse>) -> S3Error {
        if self.breaker.is_some() && is_unreachable(&e) {
            S3Error::Unavailable(format!("{e:?}"))
        } else {
            S3Error::S3(format!("{e:?}"))
        }
    }

    /// Run one SDK call: report it to the breaker and convert its error.
    async fn call<T, E: std::fmt::Debug>(
        &self,
        call: impl std::future::Future<Output = Result<T, SdkError<E, HttpResponse>>>,
    ) -> Result<T, S3Error> {
        let result = call.await;
        self.observe(&result);
        result.map_err(|e| self.error(e))
    }

    /// Readiness probe: the bucket is reachable with the configured
    /// credentials.
    pub async fn ping(&self) -> Result<(), S3Error> {
        self.admit()?;
        self.call(self.client.head_bucket().bucket(&self.bucket).send())
            .await
            .map(|_| ())
    }

    /// Create the bucket if it does not already exist.
    ///
    /// versitygw's posix backend needs the bucket directory to exist before any
    /// object operation. Treats an already-existing bucket as success.
    pub async fn ensure_bucket(&self) -> Result<(), S3Error> {
        self.admit()?;
        // Fast path: bucket already there.
        let head = self.client.head_bucket().bucket(&self.bucket).send().await;
        self.observe(&head);
        if head.is_ok() {
            return Ok(());
        }
        let created = self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await;
        self.observe(&created);
        match created {
            Ok(_) => Ok(()),
            Err(e) => {
                // Tolerate races / "already owned by you".
                let msg = format!("{e:?}");
                if msg.contains("BucketAlreadyOwnedByYou") || msg.contains("BucketAlreadyExists") {
                    Ok(())
                } else {
                    Err(self.error(e))
                }
            }
        }
    }

    /// Return whether an object exists at `key`.
    pub async fn head(&self, key: &str) -> Result<bool, S3Error> {
        self.admit()?;
        self.head_object(key).await
    }

    /// [`Self::head`] without the breaker's admission (the caller's
    /// operation was admitted already).
    async fn head_object(&self, key: &str) -> Result<bool, S3Error> {
        let result = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;
        self.observe(&result);
        match result {
            Ok(_) => Ok(true),
            Err(e) => {
                if is_not_found(&e) {
                    Ok(false)
                } else {
                    Err(self.error(e))
                }
            }
        }
    }

    /// Upload the file at `path` to `key`, but only if no object already exists
    /// there (content-addressed dedup — identical content yields an identical
    /// key, so a pre-existing object is byte-identical).
    ///
    /// Returns `true` if an upload happened, `false` if the object was already
    /// present (dedup hit). Bodies at/above the multipart threshold use a
    /// multipart upload.
    ///
    /// Single-part bodies may use a conditional PUT (`If-None-Match: *`)
    /// instead of HEAD-then-PUT, per [`ConditionalWrites`]; the two paths are
    /// observably identical, the conditional one just saves a round trip.
    pub async fn put_if_absent(&self, key: &str, path: &Path) -> Result<bool, S3Error> {
        self.admit()?;
        let size = tokio::fs::metadata(path).await?.len();

        // Multipart bodies always take the HEAD-then-PUT path: `If-None-Match`
        // applies to `PutObject` (and on real AWS also to
        // `CompleteMultipartUpload`), but conditional *multipart* support is
        // far patchier across S3-compatible backends and a rejection would
        // only surface at `complete` time — after every part was already
        // uploaded. The dedup round-trip win matters for the high-volume
        // small-blob case, so large bodies stay on the simple path.
        if size >= self.multipart_threshold {
            if self.head_object(key).await? {
                return Ok(false);
            }
            self.put_multipart(key, path, size).await?;
            return Ok(true);
        }

        if self.conditional_put_enabled() {
            match self.put_conditional(key, path).await? {
                ConditionalPut::Uploaded => return Ok(true),
                ConditionalPut::AlreadyPresent => return Ok(false),
                ConditionalPut::Unsupported(err) => {
                    if self.conditional_writes == ConditionalWrites::On {
                        // `on` promises "never HEAD-then-PUT": surface the
                        // misconfiguration instead of papering over it.
                        return Err(err);
                    }
                    // `auto`: latch the fallback for the process lifetime and
                    // retry this put below on the unconditional path.
                    self.conditional_unsupported.store(true, Ordering::Relaxed);
                    tracing::warn!(
                        error = %err,
                        "s3 backend rejected If-None-Match (conditional write); \
                         falling back to HEAD-then-PUT for the process lifetime"
                    );
                }
                ConditionalPut::Conflict => {
                    // A concurrent conditional write is racing us on the same
                    // key with byte-identical content (content-addressed).
                    // Settle this put via the plain path; no latching — the
                    // backend evidently understood the header.
                    tracing::debug!(key, "conditional put conflict; retrying via HEAD-then-PUT");
                }
            }
        }

        if self.head_object(key).await? {
            return Ok(false);
        }
        self.put_single(key, path).await?;
        Ok(true)
    }

    /// Whether the next single-part `put_if_absent` should attempt the
    /// conditional (`If-None-Match: *`) PUT.
    fn conditional_put_enabled(&self) -> bool {
        match self.conditional_writes {
            ConditionalWrites::Off => false,
            ConditionalWrites::On => true,
            ConditionalWrites::Auto => !self.conditional_unsupported.load(Ordering::Relaxed),
        }
    }

    /// One conditional PUT attempt. Maps the interesting backend answers
    /// (412 / NotImplemented / 409) into [`ConditionalPut`]; anything else is
    /// a real error.
    async fn put_conditional(&self, key: &str, path: &Path) -> Result<ConditionalPut, S3Error> {
        let body = body_from_path(path).await?;
        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .if_none_match("*")
            .body(body)
            .send()
            .await;
        self.observe(&result);
        match result {
            Ok(_) => Ok(ConditionalPut::Uploaded),
            Err(e) => {
                let msg = format!("{e:?}");
                match classify_conditional_put_error(&msg) {
                    CondPutError::PreconditionFailed => Ok(ConditionalPut::AlreadyPresent),
                    CondPutError::NotImplemented => {
                        Ok(ConditionalPut::Unsupported(S3Error::S3(msg)))
                    }
                    CondPutError::Conflict => Ok(ConditionalPut::Conflict),
                    CondPutError::Other => Err(self.error(e)),
                }
            }
        }
    }

    /// Single-shot unconditional PUT of `path` to `key`.
    async fn put_single(&self, key: &str, path: &Path) -> Result<(), S3Error> {
        let body = body_from_path(path).await?;
        self.call(
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .body(body)
                .send(),
        )
        .await?;
        Ok(())
    }

    /// Multipart upload of `path` (already known to be `size` bytes).
    ///
    /// Every exit except a successful `complete` aborts the upload so its parts
    /// do not linger (and bill) on the backend: a failed part upload or a
    /// failed `complete` aborts before the error is returned, and dropping the
    /// future mid-upload (client disconnect, request cancellation) aborts from
    /// a spawned task via [`MultipartAbortGuard`]. A process kill can still
    /// leave an incomplete upload behind; that is what the bucket's
    /// `AbortIncompleteMultipartUpload` lifecycle rule is for.
    async fn put_multipart(&self, key: &str, path: &Path, size: u64) -> Result<(), S3Error> {
        let create = self
            .call(
                self.client
                    .create_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .send(),
            )
            .await?;
        let upload_id = create
            .upload_id()
            .ok_or_else(|| S3Error::S3("create_multipart_upload returned no upload_id".into()))?
            .to_string();
        let guard = MultipartAbortGuard {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key: key.to_string(),
            upload_id: Some(upload_id.clone()),
        };

        let mut completed_parts: Vec<CompletedPart> = Vec::new();
        let mut part_number: i32 = 1;
        let mut offset: u64 = 0;

        let result: Result<(), S3Error> = async {
            while offset < size {
                let len = std::cmp::min(MULTIPART_PART_SIZE, size - offset);
                let body = ByteStream::read_from()
                    .path(path)
                    .offset(offset)
                    .length(aws_sdk_s3::primitives::Length::Exact(len))
                    .build()
                    .await
                    .map_err(|e| S3Error::S3(format!("multipart body slice: {e:?}")))?;

                let part = self
                    .call(
                        self.client
                            .upload_part()
                            .bucket(&self.bucket)
                            .key(key)
                            .upload_id(&upload_id)
                            .part_number(part_number)
                            .body(body)
                            .send(),
                    )
                    .await?;

                completed_parts.push(
                    CompletedPart::builder()
                        .part_number(part_number)
                        .set_e_tag(part.e_tag().map(|s| s.to_string()))
                        .build(),
                );

                offset += len;
                part_number += 1;
            }

            let completed = CompletedMultipartUpload::builder()
                .set_parts(Some(completed_parts))
                .build();
            self.call(
                self.client
                    .complete_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .multipart_upload(completed)
                    .send(),
            )
            .await?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                guard.disarm();
                Ok(())
            }
            Err(e) => {
                // A failed `complete` can be ambiguous (the backend may have
                // completed before the response was lost). Aborting is still
                // safe: aborting an already-completed upload is a no-op
                // (`NoSuchUpload`) that never removes the object.
                guard.abort().await;
                Err(e)
            }
        }
    }

    /// Fetch the object at `key` as a streaming [`ByteStream`], straight
    /// from S3 (reads of stored blobs go through [`Self::open`]).
    pub async fn get(&self, key: &str) -> Result<ByteStream, S3Error> {
        self.get_range(key, None).await
    }

    /// Fetch `range` (all of it for `None`) of the object at `key`, straight
    /// from S3. The range must be non-empty.
    pub async fn get_range(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<ByteStream, S3Error> {
        self.admit()?;
        let request = self.client.get_object().bucket(&self.bucket).key(key);
        let request = match range {
            Some(range) => request.range(format!(
                "bytes={}-{}",
                range.start,
                range.end.saturating_sub(1)
            )),
            None => request,
        };
        let out = self.call(request.send()).await?;
        Ok(out.body)
    }

    /// Delete the object at `key`. Idempotent: a missing object is `Ok(())`.
    pub async fn delete(&self, key: &str) -> Result<(), S3Error> {
        self.admit()?;
        let result = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;
        self.observe(&result);
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                if is_not_found(&e) {
                    Ok(())
                } else {
                    Err(self.error(e))
                }
            }
        }
    }

    /// Delete the object at `key` holding the blob `sha256`, and drop the
    /// blob from the local cache (garbage collection).
    pub async fn delete_blob(&self, sha256: &str, key: &str) -> Result<(), S3Error> {
        self.delete(key).await?;
        if let Some(cache) = &self.cache {
            cache.evict(sha256);
        }
        Ok(())
    }
}

/// Aborts an in-progress multipart upload unless [disarmed](Self::disarm).
///
/// [`BlobStore::put_multipart`] awaits [`abort`](Self::abort) on its error
/// paths. If the upload future is instead dropped mid-flight (the request was
/// cancelled), `Drop` spawns the abort on the current Tokio runtime so the
/// parts uploaded so far are released promptly rather than waiting for the
/// bucket lifecycle rule.
struct MultipartAbortGuard {
    client: Client,
    bucket: String,
    key: String,
    /// `None` once the upload completed or was aborted.
    upload_id: Option<String>,
}

impl MultipartAbortGuard {
    /// The upload completed; nothing to abort.
    fn disarm(mut self) {
        self.upload_id = None;
    }

    /// Abort now (best-effort). Should this future itself be dropped before
    /// the request finishes, `Drop` still spawns the abort.
    async fn abort(mut self) {
        if let Some(upload_id) = self.upload_id.clone() {
            abort_multipart(&self.client, &self.bucket, &self.key, &upload_id).await;
            self.upload_id = None;
        }
    }
}

impl Drop for MultipartAbortGuard {
    fn drop(&mut self) {
        let Some(upload_id) = self.upload_id.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let client = self.client.clone();
                let bucket = std::mem::take(&mut self.bucket);
                let key = std::mem::take(&mut self.key);
                runtime.spawn(async move {
                    abort_multipart(&client, &bucket, &key, &upload_id).await;
                });
            }
            Err(_) => tracing::warn!(
                key = %self.key,
                upload_id = %upload_id,
                "multipart upload dropped outside a Tokio runtime; leaving it to the \
                 bucket's AbortIncompleteMultipartUpload lifecycle rule"
            ),
        }
    }
}

/// Best-effort `AbortMultipartUpload`; failures are logged, never returned (the
/// caller is already on an error or cancellation path).
async fn abort_multipart(client: &Client, bucket: &str, key: &str, upload_id: &str) {
    if let Err(error) = client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .send()
        .await
    {
        tracing::warn!(
            key,
            upload_id,
            error = ?error,
            "failed to abort multipart upload; its parts stay on the backend until \
             the bucket's AbortIncompleteMultipartUpload lifecycle rule reclaims them"
        );
    }
}

/// Outcome of a single conditional (`If-None-Match: *`) PUT attempt.
enum ConditionalPut {
    /// 2xx — no object existed; the body was uploaded.
    Uploaded,
    /// 412 Precondition Failed — a (byte-identical) object already exists:
    /// the dedup hit, learned without a HEAD.
    AlreadyPresent,
    /// 501 NotImplemented — the backend (e.g. versitygw) does not support the
    /// conditional header. Carries the underlying error for `on` mode.
    Unsupported(S3Error),
    /// 409 ConditionalRequestConflict — a concurrent conditional write to the
    /// same key is in flight (AWS-only, transient).
    Conflict,
}

/// Classification of a failed conditional PUT, derived from the SDK error's
/// debug rendering (matching both the XML error code and the raw HTTP status,
/// in the same belt-and-braces style as [`is_not_found`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondPutError {
    PreconditionFailed,
    NotImplemented,
    Conflict,
    Other,
}

/// Classify the debug rendering of a conditional-PUT [`SdkError`].
fn classify_conditional_put_error(msg: &str) -> CondPutError {
    if msg.contains("PreconditionFailed") || mentions_status(msg, 412) {
        CondPutError::PreconditionFailed
    } else if msg.contains("NotImplemented") || mentions_status(msg, 501) {
        CondPutError::NotImplemented
    } else if msg.contains("ConditionalRequestConflict") || mentions_status(msg, 409) {
        CondPutError::Conflict
    } else {
        CondPutError::Other
    }
}

/// Whether an SDK error debug rendering mentions the given HTTP status, in
/// either of the formats the smithy runtime uses (`status: 412` in some error
/// summaries, `StatusCode(412)` in raw-response debug output).
fn mentions_status(msg: &str, code: u16) -> bool {
    msg.contains(&format!("status: {code}")) || msg.contains(&format!("StatusCode({code})"))
}

/// Open `path` as a sized streaming body.
async fn body_from_path(path: &Path) -> Result<ByteStream, S3Error> {
    ByteStream::from_path(path).await.map_err(|e| {
        S3Error::S3(format!(
            "failed to read body from {}: {e:?}",
            path.display()
        ))
    })
}

/// Whether an SDK error means S3 could not be reached: no connection, a
/// timeout, an unreadable response, or a `5xx` other than `501` (a backend
/// refusing a feature answered, so it is up).
fn is_unreachable<E>(e: &SdkError<E, HttpResponse>) -> bool {
    match e {
        SdkError::DispatchFailure(_) | SdkError::TimeoutError(_) | SdkError::ResponseError(_) => {
            true
        }
        SdkError::ServiceError(se) => {
            matches!(se.raw().status().as_u16(), 500 | 502 | 503 | 504)
        }
        _ => false,
    }
}

/// Whether an SDK error represents a 404 / NoSuchKey / NotFound.
fn is_not_found<E, R>(e: &SdkError<E, R>) -> bool
where
    E: std::fmt::Debug,
    R: std::fmt::Debug,
{
    if let SdkError::ServiceError(se) = e {
        // HEAD has no typed error body, so fall back to the HTTP status.
        let msg = format!("{:?}", se.err());
        if msg.contains("NotFound") || msg.contains("NoSuchKey") {
            return true;
        }
    }
    // Some backends surface 404 only via the raw response.
    let msg = format!("{e:?}");
    msg.contains("NotFound") || msg.contains("NoSuchKey") || msg.contains("status: 404")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store that never talks to a network (the client is only built, not
    /// used) — enough to exercise the conditional-writes decision logic.
    fn store(mode: ConditionalWrites) -> BlobStore {
        BlobStore::new(S3Config {
            endpoint: "http://127.0.0.1:1".into(),
            region: "us-east-1".into(),
            bucket: "test".into(),
            access_key: "ak".into(),
            secret_key: "sk".into(),
            force_path_style: true,
            multipart_threshold: 8 * 1024 * 1024,
            conditional_writes: mode,
        })
    }

    #[test]
    fn debug_never_shows_the_secret_key() {
        let shown = format!(
            "{:?}",
            S3Config {
                endpoint: "http://127.0.0.1:1".into(),
                region: "us-east-1".into(),
                bucket: "test".into(),
                access_key: "ak".into(),
                secret_key: "sk".into(),
                force_path_style: true,
                multipart_threshold: 1,
                conditional_writes: ConditionalWrites::Off,
            }
        );
        assert!(shown.contains("access_key: \"ak\""), "{shown}");
        assert!(!shown.contains("\"sk\""), "{shown}");
    }

    #[test]
    fn conditional_writes_defaults_to_auto() {
        assert_eq!(ConditionalWrites::default(), ConditionalWrites::Auto);
    }

    #[test]
    fn mode_off_never_enables_conditional_puts() {
        let s = store(ConditionalWrites::Off);
        assert!(!s.conditional_put_enabled());
        // The latch is irrelevant in `off`.
        s.conditional_unsupported.store(true, Ordering::Relaxed);
        assert!(!s.conditional_put_enabled());
    }

    #[test]
    fn mode_on_always_enables_conditional_puts() {
        let s = store(ConditionalWrites::On);
        assert!(s.conditional_put_enabled());
        // Even a (spuriously) set latch never disables `on`.
        s.conditional_unsupported.store(true, Ordering::Relaxed);
        assert!(s.conditional_put_enabled());
    }

    #[test]
    fn mode_auto_disables_after_unsupported_latch() {
        let s = store(ConditionalWrites::Auto);
        assert!(s.conditional_put_enabled(), "auto tries conditional first");
        s.conditional_unsupported.store(true, Ordering::Relaxed);
        assert!(
            !s.conditional_put_enabled(),
            "auto falls back permanently once latched"
        );
    }

    #[test]
    fn unsupported_latch_is_shared_across_clones() {
        let original = store(ConditionalWrites::Auto);
        let clone = original.clone();
        clone.conditional_unsupported.store(true, Ordering::Relaxed);
        assert!(
            !original.conditional_put_enabled(),
            "a clone's 501 verdict must apply to every handle on the store"
        );
    }

    #[test]
    fn classifies_precondition_failed() {
        // XML error code path (what AWS/MinIO return on a dedup hit).
        assert_eq!(
            classify_conditional_put_error("ServiceError { code: \"PreconditionFailed\" }"),
            CondPutError::PreconditionFailed
        );
        // Raw-status fallbacks (unmodeled errors / empty bodies).
        assert_eq!(
            classify_conditional_put_error("... status: 412 ..."),
            CondPutError::PreconditionFailed
        );
        assert_eq!(
            classify_conditional_put_error("Response { status: StatusCode(412), .. }"),
            CondPutError::PreconditionFailed
        );
    }

    #[test]
    fn classifies_not_implemented() {
        // What versitygw answers for `If-None-Match`.
        assert_eq!(
            classify_conditional_put_error("ServiceError { code: \"NotImplemented\" }"),
            CondPutError::NotImplemented
        );
        assert_eq!(
            classify_conditional_put_error("... status: 501 ..."),
            CondPutError::NotImplemented
        );
        assert_eq!(
            classify_conditional_put_error("Response { status: StatusCode(501), .. }"),
            CondPutError::NotImplemented
        );
    }

    #[test]
    fn classifies_conditional_request_conflict() {
        assert_eq!(
            classify_conditional_put_error("ServiceError { code: \"ConditionalRequestConflict\" }"),
            CondPutError::Conflict
        );
        assert_eq!(
            classify_conditional_put_error("Response { status: StatusCode(409), .. }"),
            CondPutError::Conflict
        );
    }

    #[test]
    fn other_errors_stay_errors() {
        assert_eq!(
            classify_conditional_put_error("DispatchFailure { connection refused }"),
            CondPutError::Other
        );
        assert_eq!(
            classify_conditional_put_error("ServiceError { code: \"AccessDenied\", status: 403 }"),
            CondPutError::Other
        );
    }
}
