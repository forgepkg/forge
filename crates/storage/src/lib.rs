//! Blob storage for Forge.
//!
//! This crate is the storage half of the system:
//!
//! * [`hash`] — streaming SHA-256/SHA-512 hashing of upload bodies.
//! * [`s3`] — a versitygw/MinIO-friendly S3 object store ([`s3::BlobStore`]),
//!   with its credentials from static keys, the AWS default chain or STS web
//!   identity ([`credentials`]).
//! * [`blob_cache`] — the optional local disk cache in front of S3 reads
//!   ([`blob_cache::BlobCache`]), with [`breaker`] failing S3 calls fast
//!   while S3 is down and [`read`] serving blobs through both.
//! * [`cas`] — content-addressed ingest ([`cas::Cas`]) that dedups objects and
//!   records `pending` blob rows.
//! * [`outbox_worker`] — drains `blob_outbox` to perform deferred S3 deletes
//!   without ever holding a DB transaction across an S3 call.
//! * [`reconciler`] — a safety net that cleans up orphaned objects/rows that
//!   slipped past the outbox (never-committed ingests, dangling rows).

pub mod blob_cache;
pub mod breaker;
pub mod cas;
pub mod credentials;
pub mod hash;
pub mod outbox_worker;
pub mod read;
pub mod reconciler;
pub mod s3;

pub use aws_sdk_s3::primitives::ByteStream;
pub use blob_cache::{BlobCache, BlobCacheConfig, BlobCacheStats, BlobStream, CacheLimit};
pub use cas::{Cas, CasError, StagedBlob, Staging, StoredBlob};
pub use credentials::{S3Credentials, WebIdentity};
pub use read::BlobRef;
pub use s3::{BlobStore, ConditionalWrites, S3Config, S3Error};
