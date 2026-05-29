//! Data access for `blob_outbox` — the deferred S3-delete work queue.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};

use crate::model::BlobOutbox;

/// Claim up to `batch` due, unlocked outbox rows for processing.
///
/// "Due" = not yet processed, `available_at <= now`, and not currently leased
/// by another worker (`locked_until` is null or in the past). Claimed rows are
/// locked with `FOR UPDATE SKIP LOCKED` so concurrent workers never claim the
/// same row, and their `locked_until` is set to `now + lease` in the same
/// statement, giving a visibility lease beyond the transaction.
///
/// Runs inside the caller's transaction so the row locks are held until commit.
///
/// Note: `lease` is truncated to whole seconds before being passed to
/// `make_interval`; sub-second precision is lost.
pub async fn claim_due(
    tx: &mut Transaction<'_, Postgres>,
    batch: i64,
    now: DateTime<Utc>,
    lease: chrono::Duration,
) -> sqlx::Result<Vec<BlobOutbox>> {
    let lease_secs = lease.num_seconds() as f64;
    sqlx::query_as!(
        BlobOutbox,
        r#"
        WITH due AS (
            SELECT id
            FROM blob_outbox
            WHERE processed_at IS NULL
              AND available_at <= $1
              AND (locked_until IS NULL OR locked_until < $1)
            ORDER BY id
            FOR UPDATE SKIP LOCKED
            LIMIT $2
        )
        UPDATE blob_outbox o
        SET locked_until = $1 + make_interval(secs => $3)
        FROM due
        WHERE o.id = due.id
        RETURNING
            o.id, o.op, o.sha256, o.s3_key, o.available_at,
            o.attempts, o.locked_until, o.processed_at, o.created_at
        "#,
        now,
        batch,
        lease_secs,
    )
    .fetch_all(&mut **tx)
    .await
}

/// Mark an outbox row as successfully processed.
pub async fn mark_processed(pool: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE blob_outbox
        SET processed_at = now(), locked_until = NULL
        WHERE id = $1
        "#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a failed attempt: bump `attempts`, clear the lease, and reschedule the
/// row to `next_available_at` (caller computes the backoff).
pub async fn bump_attempt(
    pool: &PgPool,
    id: i64,
    next_available_at: DateTime<Utc>,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE blob_outbox
        SET attempts = attempts + 1,
            available_at = $2,
            locked_until = NULL
        WHERE id = $1
        "#,
        id,
        next_available_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}
