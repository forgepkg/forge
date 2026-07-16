//! Blob storage for envisia-forge.
//!
//! This crate is the storage half of the system:
//!
//! * [`hash`] — streaming SHA-256/SHA-512 hashing of upload bodies.
//! * [`s3`] — a versitygw/MinIO-friendly S3 object store ([`s3::BlobStore`]).
//! * [`cas`] — content-addressed ingest ([`cas::Cas`]) that dedups objects and
//!   records `pending` blob rows.
//! * [`outbox_worker`] — drains `blob_outbox` to perform deferred S3 deletes
//!   without ever holding a DB transaction across an S3 call.
//! * [`reconciler`] — a safety net that cleans up orphaned objects/rows that
//!   slipped past the outbox (never-committed ingests, dangling rows).

pub mod cas;
pub mod hash;
pub mod outbox_worker;
pub mod reconciler;
pub mod s3;

pub use cas::{Cas, CasError, StagedBlob, StoredBlob};
pub use s3::{BlobStore, ConditionalWrites, S3Config, S3Error};
