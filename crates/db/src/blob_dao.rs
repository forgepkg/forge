//! Data access for `blob` and the deferred-delete `blob_outbox` enqueue.

use chrono::Duration;
use sqlx::{PgPool, Postgres, Transaction};

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
