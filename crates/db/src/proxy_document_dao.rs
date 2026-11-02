//! Data access for `proxy_document`: the documents a proxy's format fetched
//! from its upstream, their bytes in the CAS.
//!
//! A document is one row per repository and [`key`] naming one CAS blob,
//! and each row holds exactly one `blob.ref_count` reference (see the
//! schema): [`store`] takes it with the ingest lease of the fetched bytes,
//! in the transaction that inserts the row or points it at new content, and
//! every delete releases it in the transaction that removes the row.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::blob_dao;

/// A stored document, with the S3 key of its blob.
#[derive(Debug, Clone)]
pub struct ProxyDocument {
    pub id: i64,
    pub blob_sha256: String,
    pub s3_key: String,
    pub size: i64,
    /// The origins its absolute URLs name, as written (`scheme://host:port`).
    pub named_origins: Vec<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// The repository's `remote_url` when the document was fetched.
    pub remote_url: String,
    /// The repository's `updated_at` when the document was fetched or last
    /// confirmed.
    pub repository_updated_at: DateTime<Utc>,
    /// How long ago the upstream last sent or confirmed it, in seconds on the
    /// database's clock.
    pub age_seconds: f64,
}

/// A document to store.
#[derive(Debug, Clone)]
pub struct NewProxyDocument<'a> {
    pub repository_id: i64,
    pub url: &'a str,
    pub accept: Option<&'a str>,
    pub sha256: &'a str,
    pub size: i64,
    pub named_origins: &'a [String],
    pub etag: Option<&'a str>,
    pub last_modified: Option<&'a str>,
    pub remote_url: &'a str,
    pub repository_updated_at: DateTime<Utc>,
}

/// The `key` of the document at `url` fetched with `accept`: the hex
/// SHA-256 of `"{url}\n{accept}"`, or of `url` without one. A digest keeps
/// the unique index small whatever the URL's length.
pub fn key(url: &str, accept: Option<&str>) -> String {
    let mut digest = Sha256::new();
    digest.update(url.as_bytes());
    if let Some(accept) = accept {
        digest.update(b"\n");
        digest.update(accept.as_bytes());
    }
    digest
        .finalize()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// The document `key` of repository `repository_id`, marked as used (at most
/// one write per hour per document) for [`prune_unused`].
pub async fn read(
    pool: &PgPool,
    repository_id: i64,
    key: &str,
) -> sqlx::Result<Option<ProxyDocument>> {
    sqlx::query_as!(
        ProxyDocument,
        r#"
        WITH used AS (
            UPDATE proxy_document SET used_at = now()
            WHERE repository_id = $1 AND key = $2 AND used_at < now() - interval '1 hour'
        )
        SELECT d.id, d.blob_sha256, b.s3_key, d.size, d.named_origins, d.etag,
               d.last_modified, d.remote_url, d.repository_updated_at,
               extract(epoch FROM now() - d.fetched_at)::float8 AS "age_seconds!"
        FROM proxy_document d
        JOIN blob b ON b.sha256 = d.blob_sha256
        WHERE d.repository_id = $1 AND d.key = $2
        "#,
        repository_id,
        key,
    )
    .fetch_optional(pool)
    .await
}

/// Store `doc` (fetched now) under its [`key`], replacing what was stored
/// there: its blob's reference is taken with `ingest_token`, and a replaced
/// blob's released (deleted after `grace` once nothing names it).
pub async fn store(
    tx: &mut Transaction<'_, Postgres>,
    doc: &NewProxyDocument<'_>,
    ingest_token: Uuid,
    grace: chrono::Duration,
) -> sqlx::Result<()> {
    let key = key(doc.url, doc.accept);
    for _ in 0..3 {
        let inserted = sqlx::query_scalar!(
            r#"
            INSERT INTO proxy_document (repository_id, key, url, accept, blob_sha256, size,
                                        named_origins, etag, last_modified, remote_url,
                                        repository_updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (repository_id, key) DO NOTHING
            RETURNING id
            "#,
            doc.repository_id,
            key,
            doc.url,
            doc.accept,
            doc.sha256,
            doc.size,
            doc.named_origins,
            doc.etag,
            doc.last_modified,
            doc.remote_url,
            doc.repository_updated_at,
        )
        .fetch_optional(&mut **tx)
        .await?;
        if inserted.is_some() {
            blob_dao::commit_ingest_and_incref(tx, doc.sha256, ingest_token).await?;
            return Ok(());
        }

        // Stored already (an insert in flight was waited for).
        let Some(existing) = sqlx::query!(
            r#"
            SELECT id, blob_sha256 FROM proxy_document
            WHERE repository_id = $1 AND key = $2
            FOR UPDATE
            "#,
            doc.repository_id,
            key,
        )
        .fetch_optional(&mut **tx)
        .await?
        else {
            // Deleted in between: insert again.
            continue;
        };
        sqlx::query!(
            r#"
            UPDATE proxy_document
            SET blob_sha256 = $2, size = $3, named_origins = $4, etag = $5,
                last_modified = $6, remote_url = $7, repository_updated_at = $8,
                fetched_at = now(), used_at = now()
            WHERE id = $1
            "#,
            existing.id,
            doc.sha256,
            doc.size,
            doc.named_origins,
            doc.etag,
            doc.last_modified,
            doc.remote_url,
            doc.repository_updated_at,
        )
        .execute(&mut **tx)
        .await?;
        if existing.blob_sha256 == doc.sha256 {
            // The same bytes: the row keeps its reference, and the unused
            // ingest lease is given back by its holder.
            return Ok(());
        }
        // Blob rows are locked in hash order by every writer that touches
        // two at once.
        if doc.sha256 < existing.blob_sha256.as_str() {
            blob_dao::commit_ingest_and_incref(tx, doc.sha256, ingest_token).await?;
            blob_dao::decref_and_maybe_enqueue_delete(tx, &existing.blob_sha256, grace).await?;
        } else {
            blob_dao::decref_and_maybe_enqueue_delete(tx, &existing.blob_sha256, grace).await?;
            blob_dao::commit_ingest_and_incref(tx, doc.sha256, ingest_token).await?;
        }
        return Ok(());
    }
    Err(sqlx::Error::Protocol(format!(
        "proxy document {:?} kept being deleted while it was stored",
        doc.url
    )))
}

/// Record that the upstream confirmed document `id` (a `304 Not Modified`)
/// under the repository's `repository_updated_at`, with the validators it
/// sent along (`None` keeps the stored one). Only while the row still names
/// `sha256`: a document another instance replaced meanwhile is left as it
/// is. Returns whether it did.
pub async fn confirm(
    pool: &PgPool,
    id: i64,
    sha256: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
    repository_updated_at: DateTime<Utc>,
) -> sqlx::Result<bool> {
    let updated = sqlx::query!(
        r#"
        UPDATE proxy_document
        SET fetched_at = now(), used_at = now(),
            etag = coalesce($3, etag),
            last_modified = coalesce($4, last_modified),
            repository_updated_at = $5
        WHERE id = $1 AND blob_sha256 = $2
        "#,
        id,
        sha256,
        etag,
        last_modified,
        repository_updated_at,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated > 0)
}

/// Delete document `id` while it still names `sha256` (the upstream no
/// longer has it, or no longer serves it within the size limit), releasing
/// its blob reference. Returns whether it did.
pub async fn delete(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    sha256: &str,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let deleted = sqlx::query_scalar!(
        "DELETE FROM proxy_document WHERE id = $1 AND blob_sha256 = $2 RETURNING blob_sha256",
        id,
        sha256,
    )
    .fetch_optional(&mut **tx)
    .await?;
    match deleted {
        Some(sha256) => {
            blob_dao::decref_and_maybe_enqueue_delete(tx, &sha256, grace).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Delete every document of `repository_id` (its cache invalidated, its
/// upstream changed, or the repository deleted), releasing their blob
/// references. Returns how many were deleted.
pub async fn purge_repository(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    let shas = sqlx::query_scalar!(
        "DELETE FROM proxy_document WHERE repository_id = $1 RETURNING blob_sha256",
        repository_id,
    )
    .fetch_all(&mut **tx)
    .await?;
    blob_dao::decref_many_and_maybe_enqueue_delete(tx, &shas, grace).await?;
    Ok(shas.len() as u64)
}

/// Delete up to `limit` documents nobody read for `unused_for`, releasing
/// their blob references. Documents another transaction holds are left for
/// a later pass. Returns how many were deleted.
pub async fn prune_unused(
    pool: &PgPool,
    unused_for: chrono::Duration,
    limit: i64,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    let mut tx = crate::begin(pool).await?;
    let shas = sqlx::query_scalar!(
        r#"
        WITH unused AS (
            SELECT id FROM proxy_document
            WHERE used_at < now() - make_interval(secs => $1)
            ORDER BY used_at
            LIMIT $2
            FOR UPDATE SKIP LOCKED
        )
        DELETE FROM proxy_document d
        USING unused
        WHERE d.id = unused.id
        RETURNING d.blob_sha256
        "#,
        unused_for.num_seconds() as f64,
        limit,
    )
    .fetch_all(&mut *tx)
    .await?;
    blob_dao::decref_many_and_maybe_enqueue_delete(&mut tx, &shas, grace).await?;
    tx.commit().await?;
    Ok(shas.len() as u64)
}
