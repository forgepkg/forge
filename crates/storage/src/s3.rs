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
//! All object keys follow the layout
//! `blobs/sha256/{aa}/{bb}/{full-hash}` where `aa`/`bb` are the first two hex
//! byte-pairs of the content's SHA-256 (computed by the CAS layer).

use std::path::Path;

use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client;

/// Errors raised by the blob store.
#[derive(Debug, thiserror::Error)]
pub enum S3Error {
    #[error("s3 error: {0}")]
    S3(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl<E, R> From<SdkError<E, R>> for S3Error
where
    E: std::fmt::Debug,
    R: std::fmt::Debug,
{
    fn from(e: SdkError<E, R>) -> Self {
        S3Error::S3(format!("{e:?}"))
    }
}

/// Connection + behavior configuration for [`BlobStore`].
#[derive(Debug, Clone)]
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
}

/// A content-addressed object store over an S3-compatible backend.
#[derive(Debug, Clone)]
pub struct BlobStore {
    client: Client,
    bucket: String,
    multipart_threshold: u64,
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
            .build();

        Self {
            client: Client::from_conf(s3_config),
            bucket: cfg.bucket,
            multipart_threshold: cfg.multipart_threshold,
        }
    }

    /// Create the bucket if it does not already exist.
    ///
    /// versitygw's posix backend needs the bucket directory to exist before any
    /// object operation. Treats an already-existing bucket as success.
    pub async fn ensure_bucket(&self) -> Result<(), S3Error> {
        // Fast path: bucket already there.
        if self
            .client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .is_ok()
        {
            return Ok(());
        }
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // Tolerate races / "already owned by you".
                let msg = format!("{e:?}");
                if msg.contains("BucketAlreadyOwnedByYou") || msg.contains("BucketAlreadyExists") {
                    Ok(())
                } else {
                    Err(S3Error::S3(msg))
                }
            }
        }
    }

    /// Return whether an object exists at `key`.
    pub async fn head(&self, key: &str) -> Result<bool, S3Error> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if is_not_found(&e) {
                    Ok(false)
                } else {
                    Err(S3Error::S3(format!("{e:?}")))
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
    pub async fn put_if_absent(&self, key: &str, path: &Path) -> Result<bool, S3Error> {
        if self.head(key).await? {
            return Ok(false);
        }

        let size = tokio::fs::metadata(path).await?.len();
        if size >= self.multipart_threshold {
            self.put_multipart(key, path, size).await?;
        } else {
            let body = ByteStream::from_path(path).await.map_err(|e| {
                S3Error::S3(format!(
                    "failed to read body from {}: {e:?}",
                    path.display()
                ))
            })?;
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .body(body)
                .send()
                .await?;
        }
        Ok(true)
    }

    /// Multipart upload of `path` (already known to be `size` bytes).
    async fn put_multipart(&self, key: &str, path: &Path, size: u64) -> Result<(), S3Error> {
        let create = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        let upload_id = create
            .upload_id()
            .ok_or_else(|| S3Error::S3("create_multipart_upload returned no upload_id".into()))?
            .to_string();

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
                    .client
                    .upload_part()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .part_number(part_number)
                    .body(body)
                    .send()
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
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                let completed = CompletedMultipartUpload::builder()
                    .set_parts(Some(completed_parts))
                    .build();
                self.client
                    .complete_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .multipart_upload(completed)
                    .send()
                    .await?;
                Ok(())
            }
            Err(e) => {
                // Best-effort abort so we don't leak parts on the backend.
                let _ = self
                    .client
                    .abort_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .send()
                    .await;
                Err(e)
            }
        }
    }

    /// Fetch the object at `key` as a streaming [`ByteStream`].
    pub async fn get(&self, key: &str) -> Result<ByteStream, S3Error> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(out.body)
    }

    /// Delete the object at `key`. Idempotent: a missing object is `Ok(())`.
    pub async fn delete(&self, key: &str) -> Result<(), S3Error> {
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                if is_not_found(&e) {
                    Ok(())
                } else {
                    Err(S3Error::S3(format!("{e:?}")))
                }
            }
        }
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
