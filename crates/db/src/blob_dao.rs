//! Data access for `blob` and the deferred-delete `blob_outbox` enqueue.

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgExecutor, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::model::Blob;

/// Result of registering an ingest before its S3 HEAD/PUT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginIngestOutcome {
    /// The caller owns a live ingest lease and may touch the object store.
    Ready {
        token: Uuid,
        inserted: bool,
        /// Authoritative key for this blob incarnation. On a dedup hit this is
        /// the existing row's key, not the caller's fresh candidate key.
        s3_key: String,
    },
    /// Another process owns a non-stale deletion reservation. Retry shortly.
    DeletionInProgress,
    /// A deleter crashed after reserving the row. The caller now owns that
    /// reservation and must finish its idempotent S3 delete before retrying.
    CompleteStaleDeletion(BlobDeletionReservation),
}

/// A fencing token for the DB -> S3 -> DB deletion protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobDeletionReservation {
    pub sha256: String,
    pub s3_key: String,
    pub token: Uuid,
}

/// Result of trying to reserve a candidate for deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveDeleteOutcome {
    Reserved(BlobDeletionReservation),
    Missing,
    Referenced,
    Busy,
}

#[derive(Debug, Clone, Copy)]
enum DeleteKind {
    /// A due outbox row. `row_id` (when known) identifies the row being
    /// processed so a *later* deferred delete for the same content can
    /// supersede it.
    Outbox {
        row_id: Option<i64>,
    },
    StalePending {
        created_before: DateTime<Utc>,
    },
    DanglingCommitted {
        created_before: DateTime<Utc>,
    },
}

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

/// Register an ingest lease before checking or uploading the S3 object.
///
/// The blob row is locked while its state is inspected and the lease is
/// inserted, which serializes this operation with [`reserve_outbox_delete`]
/// and the reconciler reservation paths. Therefore any caller that receives
/// `Ready` is protected from object deletion until it atomically consumes the
/// returned token via [`commit_ingest_and_incref`] (or the lease expires).
///
/// If a deletion owner crashed, a caller may fence it out and receive
/// `CompleteStaleDeletion`; finishing that idempotent delete lets the ingest
/// create a clean pending row on its next attempt.
///
/// A deletion that finalizes between this call's `INSERT … ON CONFLICT DO
/// NOTHING` (which saw the old row and so inserted nothing) and its row lock
/// leaves no row to lock. That attempt is rolled back and retried at once: the
/// next `INSERT` creates a fresh pending incarnation. Should the row keep
/// vanishing, the call degrades to `DeletionInProgress` so the caller backs
/// off and retries instead of failing the upload.
#[allow(clippy::too_many_arguments)]
pub async fn begin_ingest(
    pool: &PgPool,
    sha256: &str,
    size: i64,
    s3_key: &str,
    lease_expires_at: DateTime<Utc>,
    stale_deletion_before: DateTime<Utc>,
) -> sqlx::Result<BeginIngestOutcome> {
    /// Immediate retries after the blob row vanished under a finalizing
    /// deletion. Each one requires a *new* deletion to finalize in between, so
    /// more than one retry is already exceptional.
    const VANISHED_RETRIES: usize = 3;

    for _ in 0..VANISHED_RETRIES {
        if let Some(outcome) = begin_ingest_attempt(
            pool,
            sha256,
            size,
            s3_key,
            lease_expires_at,
            stale_deletion_before,
        )
        .await?
        {
            return Ok(outcome);
        }
    }
    Ok(BeginIngestOutcome::DeletionInProgress)
}

/// One [`begin_ingest`] transaction. `None` means the row was deleted by a
/// concurrently finalizing deletion after the insert observed it; nothing was
/// written and the caller should retry.
async fn begin_ingest_attempt(
    pool: &PgPool,
    sha256: &str,
    size: i64,
    s3_key: &str,
    lease_expires_at: DateTime<Utc>,
    stale_deletion_before: DateTime<Utc>,
) -> sqlx::Result<Option<BeginIngestOutcome>> {
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query(
        r#"
        INSERT INTO blob (sha256, size, s3_key, ref_count, state)
        VALUES ($1, $2, $3, 0, 'pending')
        ON CONFLICT (sha256) DO NOTHING
        "#,
    )
    .bind(sha256)
    .bind(size)
    .bind(s3_key)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;

    // `ON CONFLICT DO NOTHING` does not lock the conflicting row, so a
    // deletion may finalize (delete it) before this lock is granted.
    let Some(row) = sqlx::query(
        r#"
        SELECT state, s3_key, delete_started_at
        FROM blob
        WHERE sha256 = $1
        FOR UPDATE
        "#,
    )
    .bind(sha256)
    .fetch_optional(&mut *tx)
    .await?
    else {
        tx.rollback().await?;
        return Ok(None);
    };

    let state: String = row.try_get("state")?;
    if state == "deleting" {
        // A deletion reservation on a blob an asset still names is bogus (a
        // reservation is never taken while one does, and nothing increments a
        // deleting blob): cancel it rather than delete the object, then retry
        // as an ordinary blob.
        let referenced = asset_references(&mut tx, sha256).await?;
        if referenced > 0 {
            let stored_key: String = row.try_get("s3_key")?;
            cancel_referenced_deletion(&mut tx, sha256, &stored_key, referenced).await?;
            tx.commit().await?;
            return Ok(None);
        }
        let delete_started_at: DateTime<Utc> = row.try_get("delete_started_at")?;
        if delete_started_at < stale_deletion_before {
            let token = Uuid::new_v4();
            let stored_key: String = row.try_get("s3_key")?;
            sqlx::query(
                r#"
                UPDATE blob
                SET delete_token = $2, delete_started_at = now()
                WHERE sha256 = $1 AND state = 'deleting'
                "#,
            )
            .bind(sha256)
            .bind(token)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(Some(BeginIngestOutcome::CompleteStaleDeletion(
                BlobDeletionReservation {
                    sha256: sha256.to_owned(),
                    s3_key: stored_key,
                    token,
                },
            )));
        }

        tx.rollback().await?;
        return Ok(Some(BeginIngestOutcome::DeletionInProgress));
    }

    // Stale leases are no longer deletion fences. Prune them on this hot path
    // so frequently deduplicated live blobs do not accumulate lease rows.
    sqlx::query("DELETE FROM blob_ingest WHERE blob_sha256 = $1 AND expires_at <= now()")
        .bind(sha256)
        .execute(&mut *tx)
        .await?;

    let token = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO blob_ingest (token, blob_sha256, expires_at)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(token)
    .bind(sha256)
    .bind(lease_expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let stored_key: String = row.try_get("s3_key")?;
    Ok(Some(BeginIngestOutcome::Ready {
        token,
        inserted,
        s3_key: stored_key,
    }))
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
    let result = sqlx::query(
        r#"
        UPDATE blob
        SET state = 'committed', ref_count = ref_count + 1
        WHERE sha256 = $1 AND state <> 'deleting'
        "#,
    )
    .bind(sha256)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// Commit one reference and consume the ingest lease in the same transaction.
///
/// Both the token and a non-`deleting` row are required. The row update locks
/// the blob before the token is consumed, serializing against every deletion
/// reservation. This is the production counterpart to [`begin_ingest`].
pub async fn commit_ingest_and_incref(
    tx: &mut Transaction<'_, Postgres>,
    sha256: &str,
    ingest_token: Uuid,
) -> sqlx::Result<()> {
    let result = sqlx::query(
        r#"
        UPDATE blob b
        SET state = 'committed', ref_count = ref_count + 1
        WHERE b.sha256 = $1
          AND b.state <> 'deleting'
          AND EXISTS (
              SELECT 1
              FROM blob_ingest i
              WHERE i.token = $2 AND i.blob_sha256 = b.sha256
          )
        "#,
    )
    .bind(sha256)
    .bind(ingest_token)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }

    let consumed = sqlx::query("DELETE FROM blob_ingest WHERE token = $1 AND blob_sha256 = $2")
        .bind(ingest_token)
        .bind(sha256)
        .execute(&mut **tx)
        .await?;
    if consumed.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// Release an ingest lease after an S3 failure or an explicit caller abort.
pub async fn abort_ingest<'e, E>(executor: E, ingest_token: Uuid) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query("DELETE FROM blob_ingest WHERE token = $1")
        .bind(ingest_token)
        .execute(executor)
        .await?;
    Ok(())
}

/// Extend a live ingest lease. Returns `false` once the token was consumed,
/// aborted, or fenced out by stale-lease cleanup.
pub async fn refresh_ingest(
    pool: &PgPool,
    ingest_token: Uuid,
    lease_expires_at: DateTime<Utc>,
) -> sqlx::Result<bool> {
    let result = sqlx::query("UPDATE blob_ingest SET expires_at = $2 WHERE token = $1")
        .bind(ingest_token)
        .bind(lease_expires_at)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Decrement a blob's reference count by one. If it reaches zero, enqueue a
/// `delete_object` row in `blob_outbox` (in the **same** transaction) with
/// `available_at = now() + grace`, deferring the actual S3 delete.
///
/// Returns `true` if the ref count hit zero (and a delete was enqueued),
/// `false` otherwise (nothing enqueued).
///
/// Callers must decrement only for asset rows they actually removed in the
/// same transaction (e.g. via `DELETE … RETURNING blob_sha256` after locking
/// the owning component), or two concurrent deletes of one reference both
/// decrement it. A decrement below zero violates the
/// `blob_ref_count_nonnegative` constraint and aborts the transaction instead
/// of enqueueing a delete for an object other rows may still reference.
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

/// Reserve a due outbox blob for deletion.
pub async fn reserve_outbox_delete(
    pool: &PgPool,
    sha256: &str,
    stale_deletion_before: DateTime<Utc>,
) -> sqlx::Result<ReserveDeleteOutcome> {
    reserve_delete(
        pool,
        sha256,
        DeleteKind::Outbox { row_id: None },
        stale_deletion_before,
    )
    .await
}

/// Reserve the blob of outbox row `row_id` for deletion, unless a later
/// deferred delete for the same content exists (the blob was revived and
/// dereferenced again after this row was written): that row's later grace
/// window governs, and this one retires as [`ReserveDeleteOutcome::Referenced`].
pub async fn reserve_outbox_row_delete(
    pool: &PgPool,
    row_id: i64,
    sha256: &str,
    stale_deletion_before: DateTime<Utc>,
) -> sqlx::Result<ReserveDeleteOutcome> {
    reserve_delete(
        pool,
        sha256,
        DeleteKind::Outbox {
            row_id: Some(row_id),
        },
        stale_deletion_before,
    )
    .await
}

/// Reserve a stale, never-committed pending blob for reconciliation.
pub async fn reserve_stale_pending_delete(
    pool: &PgPool,
    sha256: &str,
    created_before: DateTime<Utc>,
    stale_deletion_before: DateTime<Utc>,
) -> sqlx::Result<ReserveDeleteOutcome> {
    reserve_delete(
        pool,
        sha256,
        DeleteKind::StalePending { created_before },
        stale_deletion_before,
    )
    .await
}

/// Reserve a stale committed zero-ref blob without a pending outbox row.
pub async fn reserve_dangling_delete(
    pool: &PgPool,
    sha256: &str,
    created_before: DateTime<Utc>,
    stale_deletion_before: DateTime<Utc>,
) -> sqlx::Result<ReserveDeleteOutcome> {
    reserve_delete(
        pool,
        sha256,
        DeleteKind::DanglingCommitted { created_before },
        stale_deletion_before,
    )
    .await
}

/// How many assets name the blob (under the caller's blob row lock).
async fn asset_references(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sha256: &str,
) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT count(*) FROM asset WHERE blob_sha256 = $1")
        .bind(sha256)
        .fetch_one(&mut **tx)
        .await
}

/// Cancel the deletion reservation of a blob that assets still name (the
/// aftermath of the pre-release concurrent hard-delete race): back to
/// `committed` with the true reference count. Its object may already be gone;
/// the warning names the key to restore from backup if so.
async fn cancel_referenced_deletion(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sha256: &str,
    s3_key: &str,
    referenced: i64,
) -> sqlx::Result<()> {
    tracing::warn!(
        sha256,
        s3_key,
        referenced,
        "blob reserved for deletion is still referenced by assets; deletion cancelled \
         (if its object is missing from the bucket, restore it from a backup)"
    );
    sqlx::query(
        r#"
        UPDATE blob
        SET state = 'committed', ref_count = $2, delete_token = NULL,
            delete_previous_state = NULL, delete_started_at = NULL
        WHERE sha256 = $1 AND state = 'deleting'
        "#,
    )
    .bind(sha256)
    .bind(referenced)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn reserve_delete(
    pool: &PgPool,
    sha256: &str,
    kind: DeleteKind,
    stale_deletion_before: DateTime<Utc>,
) -> sqlx::Result<ReserveDeleteOutcome> {
    let mut tx = pool.begin().await?;
    let Some(row) = sqlx::query(
        r#"
        SELECT
            state, ref_count, s3_key, created_at,
            delete_previous_state, delete_started_at
        FROM blob
        WHERE sha256 = $1
        FOR UPDATE
        "#,
    )
    .bind(sha256)
    .fetch_optional(&mut *tx)
    .await?
    else {
        tx.rollback().await?;
        return Ok(ReserveDeleteOutcome::Missing);
    };

    let ref_count: i64 = row.try_get("ref_count")?;
    if ref_count > 0 {
        tx.rollback().await?;
        return Ok(ReserveDeleteOutcome::Referenced);
    }

    // Defence in depth against counter drift: never reserve a blob that an
    // asset still names, whatever `ref_count` says. Drift is repaired here, to
    // the true asset count, under the blob row lock every increment and
    // decrement also takes, so later decrements stay correct.
    let referenced = asset_references(&mut tx, sha256).await?;
    if referenced > 0 {
        tracing::warn!(
            sha256,
            ref_count,
            referenced,
            "blob ref_count drifted below its asset references; repaired, not deleting"
        );
        let state: String = row.try_get("state")?;
        if state == "deleting" {
            let stored_key: String = row.try_get("s3_key")?;
            cancel_referenced_deletion(&mut tx, sha256, &stored_key, referenced).await?;
        } else {
            sqlx::query("UPDATE blob SET ref_count = $2 WHERE sha256 = $1")
                .bind(sha256)
                .bind(referenced)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        return Ok(ReserveDeleteOutcome::Referenced);
    }

    let state: String = row.try_get("state")?;
    let original_state = if state == "deleting" {
        let started: DateTime<Utc> = row.try_get("delete_started_at")?;
        if started >= stale_deletion_before {
            tx.rollback().await?;
            return Ok(ReserveDeleteOutcome::Busy);
        }
        row.try_get::<String, _>("delete_previous_state")?
    } else {
        state.clone()
    };
    let created_at: DateTime<Utc> = row.try_get("created_at")?;

    let eligible = match kind {
        // A later deferred delete for the same content means the blob was
        // revived and dereferenced again after this row was written; that
        // row's (later) grace window governs. Treat this row like a revived
        // blob so it retires without deleting anything. A takeover of an
        // abandoned in-flight deletion (`state = 'deleting'`) must always
        // complete, so it is exempt.
        DeleteKind::Outbox {
            row_id: Some(row_id),
        } if state != "deleting" => {
            let superseded: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM blob_outbox later, blob_outbox this
                    WHERE this.id = $2
                      AND later.sha256 = $1
                      AND later.id <> this.id
                      AND later.processed_at IS NULL
                      AND later.available_at > this.available_at
                )
                "#,
            )
            .bind(sha256)
            .bind(row_id)
            .fetch_one(&mut *tx)
            .await?;
            if superseded {
                tx.rollback().await?;
                return Ok(ReserveDeleteOutcome::Referenced);
            }
            true
        }
        DeleteKind::Outbox { .. } => true,
        DeleteKind::StalePending { created_before } => {
            original_state == "pending" && created_at < created_before
        }
        DeleteKind::DanglingCommitted { created_before } => {
            if original_state != "committed" || created_at >= created_before {
                false
            } else {
                let outstanding: bool = sqlx::query_scalar(
                    r#"
                    SELECT EXISTS (
                        SELECT 1 FROM blob_outbox
                        WHERE sha256 = $1 AND processed_at IS NULL
                    )
                    "#,
                )
                .bind(sha256)
                .fetch_one(&mut *tx)
                .await?;
                !outstanding
            }
        }
    };
    if !eligible {
        tx.rollback().await?;
        return Ok(ReserveDeleteOutcome::Busy);
    }

    // Expired leases no longer represent a caller that may attach a reference.
    sqlx::query("DELETE FROM blob_ingest WHERE blob_sha256 = $1 AND expires_at <= now()")
        .bind(sha256)
        .execute(&mut *tx)
        .await?;
    let live_ingest: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM blob_ingest WHERE blob_sha256 = $1)")
            .bind(sha256)
            .fetch_one(&mut *tx)
            .await?;
    if live_ingest {
        tx.rollback().await?;
        return Ok(ReserveDeleteOutcome::Busy);
    }

    let token = Uuid::new_v4();
    sqlx::query(
        r#"
        UPDATE blob
        SET state = 'deleting',
            delete_token = $2,
            delete_previous_state = CASE
                WHEN state = 'deleting' THEN delete_previous_state
                ELSE state
            END,
            delete_started_at = now()
        WHERE sha256 = $1
        "#,
    )
    .bind(sha256)
    .bind(token)
    .execute(&mut *tx)
    .await?;
    let s3_key: String = row.try_get("s3_key")?;
    tx.commit().await?;

    Ok(ReserveDeleteOutcome::Reserved(BlobDeletionReservation {
        sha256: sha256.to_owned(),
        s3_key,
        token,
    }))
}

/// Remove a blob row only for the exact deletion reservation that performed
/// the S3 delete. A newer owner fences a stale worker out.
pub async fn finalize_delete_reservation<'e, E>(
    executor: E,
    reservation: &BlobDeletionReservation,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let result = sqlx::query(
        r#"
        DELETE FROM blob
        WHERE sha256 = $1
          AND state = 'deleting'
          AND ref_count = 0
          AND delete_token = $2
        "#,
    )
    .bind(&reservation.sha256)
    .bind(reservation.token)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Prune expired ingest leases in bounded batches. Blob-local deletion paths
/// also prune their own expired leases before deciding eligibility.
pub async fn prune_expired_ingests(pool: &PgPool, limit: i64) -> sqlx::Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM blob_ingest
        WHERE token IN (
            SELECT token
            FROM blob_ingest
            WHERE expires_at <= now()
            ORDER BY expires_at
            LIMIT $1
        )
        "#,
    )
    .bind(limit)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// List `pending` blobs created before `cutoff`.
///
/// These are uploads whose owning transaction never committed (the asset insert
/// and `commit_and_incref` never ran). Used by the orphan reconciler to find S3
/// objects to drop. Accepts any executor.
///
/// `pending` and `deleting` rows are zero-ref by construction; the explicit
/// `ref_count = 0` lets the `blob_zero_ref_created_at_idx` partial index serve
/// the scan (and mirrors the reservation's own referenced check).
pub async fn list_stale_pending<'e, E>(
    executor: E,
    cutoff: DateTime<Utc>,
    stale_deletion_before: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<Blob>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as::<_, Blob>(
        r#"
        SELECT sha256, size, s3_key, ref_count, state, created_at
        FROM blob
        WHERE ref_count = 0
          AND created_at < $1
          AND (
              state = 'pending'
              OR (
                  state = 'deleting'
                  AND delete_previous_state = 'pending'
                  AND delete_started_at < $2
              )
          )
        ORDER BY created_at
        LIMIT $3
        "#,
    )
    .bind(cutoff)
    .bind(stale_deletion_before)
    .bind(limit)
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
    stale_deletion_before: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<Blob>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as::<_, Blob>(
        r#"
        SELECT b.sha256, b.size, b.s3_key, b.ref_count, b.state, b.created_at
        FROM blob b
        WHERE b.ref_count = 0
          AND b.created_at < $1
          AND (
              b.state = 'committed'
              OR (
                  b.state = 'deleting'
                  AND b.delete_previous_state = 'committed'
                  AND b.delete_started_at < $2
              )
          )
          AND NOT EXISTS (
              SELECT 1 FROM blob_outbox o
              WHERE o.sha256 = b.sha256 AND o.processed_at IS NULL
          )
        ORDER BY b.created_at
        LIMIT $3
        "#,
    )
    .bind(cutoff)
    .bind(stale_deletion_before)
    .bind(limit)
    .fetch_all(executor)
    .await
}
