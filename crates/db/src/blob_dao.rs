//! Data access for `blob` and the deferred-delete `blob_outbox` enqueue.

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};

use crate::model::Blob;

/// Insert a pending, zero-refcount blob row keyed by `sha256`.
///
/// Uses `ON CONFLICT (sha256) DO NOTHING`. Returns `true` if a new row was
/// inserted, `false` if a row for this `sha256` already existed.
pub async fn upsert_pending(
    pool: &PgPool,
    sha256: &str,
    size: i64,
    s3_key: &str,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        INSERT INTO blob (sha256, size, s3_key, ref_count, state)
        VALUES ($1, $2, $3, 0, 'pending')
        ON CONFLICT (sha256) DO NOTHING
        "#,
        sha256,
        size,
        s3_key,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Fetch a blob by content hash.
pub async fn get_blob(pool: &PgPool, sha256: &str) -> sqlx::Result<Option<Blob>> {
    sqlx::query_as!(
        Blob,
        r#"
        SELECT sha256, size, s3_key, ref_count, state, created_at
        FROM blob
        WHERE sha256 = $1
        "#,
        sha256,
    )
    .fetch_optional(pool)
    .await
}

/// Mark a blob committed and increment its reference count by one.
///
/// Runs inside the caller's transaction so it composes with the asset/component
/// writes that justify the new reference.
pub async fn commit_and_incref(
    tx: &mut Transaction<'_, Postgres>,
    sha256: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE blob
        SET state = 'committed', ref_count = ref_count + 1
        WHERE sha256 = $1
        "#,
        sha256,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Decrement a blob's reference count by one. If it reaches zero, enqueue a
/// `delete_object` row in `blob_outbox` (in the **same** transaction) with
/// `available_at = now() + grace`, deferring the actual S3 delete.
///
/// Returns `true` if the ref count hit zero (and a delete was enqueued),
/// `false` otherwise (nothing enqueued).
///
/// Note: `grace` is truncated to whole seconds before being passed to
/// `make_interval`; sub-second precision is lost.
pub async fn decref_and_maybe_enqueue_delete(
    tx: &mut Transaction<'_, Postgres>,
    sha256: &str,
    grace: Duration,
) -> sqlx::Result<bool> {
    // Decrement and read back the new count + s3_key atomically.
    let row = sqlx::query!(
        r#"
        UPDATE blob
        SET ref_count = ref_count - 1
        WHERE sha256 = $1
        RETURNING ref_count, s3_key
        "#,
        sha256,
    )
    .fetch_one(&mut **tx)
    .await?;

    if row.ref_count > 0 {
        return Ok(false);
    }

    // Hit zero: enqueue a deferred delete in the same transaction.
    let grace_secs = grace.num_seconds();
    sqlx::query!(
        r#"
        INSERT INTO blob_outbox (op, sha256, s3_key, available_at)
        VALUES ('delete_object', $1, $2, now() + make_interval(secs => $3))
        "#,
        sha256,
        row.s3_key,
        grace_secs as f64,
    )
    .execute(&mut **tx)
    .await?;

    Ok(true)
}

/// Delete a blob row **only if** it is still at `ref_count = 0`.
///
/// Used by the deferred-delete worker after it has removed the S3 object: a
/// concurrent re-push may have revived the blob (`ref_count > 0`), in which case
/// the row must survive. Accepts any executor so it composes with the worker's
/// short transaction. Returns `true` if a row was deleted.
pub async fn delete_if_unreferenced<'e, E>(executor: E, sha256: &str) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        DELETE FROM blob
        WHERE sha256 = $1 AND ref_count = 0
        "#,
        sha256,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// List `pending` blobs created before `cutoff`.
///
/// These are uploads whose owning transaction never committed (the asset insert
/// and `commit_and_incref` never ran). Used by the orphan reconciler to find S3
/// objects to drop. Accepts any executor.
pub async fn list_stale_pending<'e, E>(
    executor: E,
    cutoff: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<Blob>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        Blob,
        r#"
        SELECT sha256, size, s3_key, ref_count, state, created_at
        FROM blob
        WHERE state = 'pending' AND created_at < $1
        ORDER BY created_at
        LIMIT $2
        "#,
        cutoff,
        limit,
    )
    .fetch_all(executor)
    .await
}

/// List zero-refcount blobs created before `cutoff` that have **no** pending
/// (unprocessed) `blob_outbox` delete row.
///
/// These are committed blobs that fell to zero references but whose deferred
/// delete already completed (or was never enqueued), leaving a dangling row.
/// The reconciler removes them. Accepts any executor.
pub async fn list_stale_unreferenced<'e, E>(
    executor: E,
    cutoff: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<Blob>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        Blob,
        r#"
        SELECT b.sha256, b.size, b.s3_key, b.ref_count, b.state, b.created_at
        FROM blob b
        WHERE b.ref_count = 0
          AND b.created_at < $1
          AND NOT EXISTS (
              SELECT 1 FROM blob_outbox o
              WHERE o.sha256 = b.sha256 AND o.processed_at IS NULL
          )
        ORDER BY b.created_at
        LIMIT $2
        "#,
        cutoff,
        limit,
    )
    .fetch_all(executor)
    .await
}

/// Delete a blob row **only if** it is still `pending` and created before
/// `cutoff`.
///
/// Used by the orphan reconciler after removing the S3 object: a slow-but-valid
/// ingest transaction may have committed the blob (`state = 'committed'`,
/// `ref_count > 0`) between listing and deletion, in which case the row must
/// survive. The `created_at < cutoff` guard re-confirms the staleness window
/// atomically with the delete. Returns `true` if a row was deleted.
pub async fn delete_if_stale_pending<'e, E>(
    executor: E,
    sha256: &str,
    cutoff: DateTime<Utc>,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        DELETE FROM blob
        WHERE sha256 = $1 AND state = 'pending' AND created_at < $2
        "#,
        sha256,
        cutoff,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}
