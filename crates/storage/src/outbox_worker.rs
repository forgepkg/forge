//! Deferred S3-delete worker (transactional-outbox consumer).
//!
//! Blob deletes are never done inline: when a blob's ref count hits zero,
//! `blob_dao::decref_and_maybe_enqueue_delete` writes a `delete_object` row to
//! `blob_outbox` in the same transaction as the decref. This worker drains that
//! queue.
//!
//! **Invariant (Addendum A7):** never hold a database transaction open across an
//! S3 network call. We therefore split each unit of work into short
//! transactions around the network I/O:
//!   1. claim a batch (leases the rows) — short tx, committed immediately;
//!   2. for each row: re-check the blob, do the S3 delete outside any tx, then
//!      delete the row + mark processed in a second short tx.

use std::time::Duration as StdDuration;

use chrono::Utc;
use sqlx::PgPool;

use crate::s3::BlobStore;

/// Lease held on a claimed outbox row, long enough to cover one S3 round trip
/// plus DB writes.
const LEASE: chrono::Duration = chrono::Duration::seconds(60);

/// Process up to `batch` due outbox rows once. Returns the number of rows that
/// reached a terminal state (`mark_processed`) this call.
///
/// Errors against S3 or the DB for an individual row are not fatal: the row's
/// attempt counter is bumped and it is rescheduled with backoff, and processing
/// continues with the next row.
pub async fn run_once(pool: &PgPool, store: &BlobStore, batch: i64) -> anyhow::Result<usize> {
    // 1. Claim a batch in a short transaction, then commit to release the tx
    //    (the rows stay leased via `locked_until`).
    let claimed = {
        let mut tx = pool.begin().await?;
        let rows = forge_db::outbox_dao::claim_due(&mut tx, batch, Utc::now(), LEASE).await?;
        tx.commit().await?;
        rows
    };

    let mut processed = 0usize;

    for row in claimed {
        match process_row(pool, store, &row).await {
            Ok(true) => processed += 1,
            Ok(false) => { /* deliberately skipped; already terminal */ }
            Err(e) => {
                tracing::warn!(
                    outbox_id = row.id,
                    sha256 = %row.sha256,
                    error = %e,
                    "outbox delete failed; rescheduling with backoff"
                );
                let next = Utc::now() + backoff(row.attempts);
                // Best-effort reschedule; if this also fails the lease will
                // simply expire and the row gets retried later.
                if let Err(e2) = forge_db::outbox_dao::bump_attempt(pool, row.id, next).await {
                    tracing::error!(outbox_id = row.id, error = %e2, "bump_attempt failed");
                }
            }
        }
    }

    Ok(processed)
}

/// Process a single claimed row. Returns `Ok(true)` if the row was marked
/// processed, `Ok(false)` if it was intentionally skipped (also marked
/// processed but not a "delete" — kept distinct for the counter only when
/// nothing happened). Any error is propagated for backoff handling.
async fn process_row(
    pool: &PgPool,
    store: &BlobStore,
    row: &forge_db::model::BlobOutbox,
) -> anyhow::Result<bool> {
    // Re-check the blob: a concurrent re-push may have revived it
    // (ref_count > 0), or a prior worker run may have already removed the row.
    let blob = forge_db::blob_dao::get_blob(pool, &row.sha256).await?;
    match blob {
        // Revived: keep both the object and the row. Mark the outbox entry done.
        Some(b) if b.ref_count > 0 => {
            forge_db::outbox_dao::mark_processed(pool, row.id).await?;
            tracing::debug!(
                outbox_id = row.id,
                sha256 = %row.sha256,
                "blob revived (ref_count > 0); skipping S3 delete"
            );
            Ok(true)
        }
        // Blob row already gone: nothing to delete, just close the outbox row.
        None => {
            forge_db::outbox_dao::mark_processed(pool, row.id).await?;
            Ok(true)
        }
        // Still unreferenced: delete the object, then the row.
        Some(_) => {
            // S3 delete is idempotent and runs OUTSIDE any DB transaction.
            store.delete(&row.s3_key).await?;

            // Short tx: drop the blob row only if it is still unreferenced, then
            // mark the outbox row processed.
            let mut tx = pool.begin().await?;
            forge_db::blob_dao::delete_if_unreferenced(&mut *tx, &row.sha256).await?;
            tx.commit().await?;

            forge_db::outbox_dao::mark_processed(pool, row.id).await?;
            Ok(true)
        }
    }
}

/// Exponential backoff (capped) for a row that has failed `attempts` times.
fn backoff(attempts: i32) -> chrono::Duration {
    let secs = match attempts {
        0 => 5,
        1 => 15,
        2 => 60,
        3 => 300,
        _ => 900,
    };
    chrono::Duration::seconds(secs)
}

/// Spawn a background loop that calls [`run_once`] every `interval`.
///
/// Returns the [`tokio::task::JoinHandle`]; the loop runs until the handle is
/// aborted or the process exits. Intended for wiring up from the server.
pub fn spawn_loop(
    pool: PgPool,
    store: BlobStore,
    batch: i64,
    interval: StdDuration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = run_once(&pool, &store, batch).await {
                tracing::error!(error = %e, "outbox worker run_once failed");
            }
        }
    })
}
