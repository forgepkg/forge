//! Deferred S3-delete worker (transactional-outbox consumer).
//!
//! Blob deletes are never done inline: when a blob's ref count hits zero,
//! `blob_dao::decref_and_maybe_enqueue_delete` writes a `delete_object` row to
//! `blob_outbox` in the same transaction as the decref. This worker drains that
//! queue.
//!
//! **Invariant:** never hold a database transaction open across an
//! S3 network call. We therefore split each unit of work into short
//! transactions around the network I/O:
//!   1. claim a batch (leases the rows) — short tx, committed immediately;
//!   2. for each row: reserve the zero-ref blob in a short transaction (which
//!      fails while an ingest lease is live), do the S3 delete outside any tx,
//!      then token-conditionally delete the row + mark processed.
//!
//! Processed rows are terminal; [`prune_processed`] deletes them once they are
//! older than the configured retention so the queue does not grow forever.

use std::time::Duration as StdDuration;

use chrono::Utc;
use sqlx::PgPool;
use tracing::Instrument;

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
        let mut tx = forge_db::begin(pool).await?;
        // Due-ness on the database clock, which set `available_at`
        // (`now() + grace`): an instance whose clock runs ahead would
        // otherwise delete objects before the grace period that backups and
        // in-flight downloads rely on.
        let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT now()")
            .fetch_one(&mut *tx)
            .await?;
        let rows = forge_db::outbox_dao::claim_due(&mut tx, batch, now, LEASE).await?;
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
                // Best-effort reschedule; if this also fails the lease will
                // simply expire and the row gets retried later. Due-ness is
                // decided on the database's clock, so the backoff is too.
                let bumped = match forge_db::db_now(pool).await {
                    Ok(now) => {
                        forge_db::outbox_dao::bump_attempt(
                            pool,
                            row.id,
                            now + backoff(row.attempts),
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                if let Err(e2) = bumped {
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
    use forge_db::blob_dao::ReserveDeleteOutcome;

    let stale_before = forge_db::db_now(pool).await? - crate::cas::DELETE_RESERVATION_LEASE;
    match forge_db::blob_dao::reserve_outbox_row_delete(pool, row.id, &row.sha256, stale_before)
        .await?
    {
        // A committed ingest won before deletion could reserve the row.
        ReserveDeleteOutcome::Referenced => {
            forge_db::outbox_dao::mark_processed(pool, row.id).await?;
            tracing::debug!(
                outbox_id = row.id,
                sha256 = %row.sha256,
                "blob revived (ref_count > 0); skipping S3 delete"
            );
            Ok(true)
        }
        ReserveDeleteOutcome::Missing => {
            forge_db::outbox_dao::mark_processed(pool, row.id).await?;
            Ok(true)
        }
        // An ingest has registered before its S3 check, or another deletion
        // owner still holds a live fencing token. Keep the outbox row pending.
        ReserveDeleteOutcome::Busy => {
            anyhow::bail!("blob is protected by an ingest or deletion reservation")
        }
        ReserveDeleteOutcome::Reserved(reservation) => {
            // S3 delete is idempotent and runs OUTSIDE any DB transaction. If
            // it fails, the response may be ambiguous and the operation may
            // still complete later. Keep the reservation fenced so no ingest
            // can reuse this incarnation; a later worker or ingest may take
            // over the stale reservation and finish it safely.
            if let Err(error) = store
                .delete_blob(&reservation.sha256, &reservation.s3_key)
                .await
            {
                return Err(error.into());
            }

            // Short tx: finalize only our exact fencing token and mark the
            // outbox row processed atomically. A stale owner cannot delete a
            // newer row or close work now owned by another process.
            let mut tx = forge_db::begin(pool).await?;
            let finalized =
                forge_db::blob_dao::finalize_delete_reservation(&mut *tx, &reservation).await?;
            if !finalized {
                tx.rollback().await?;
                anyhow::bail!("blob deletion reservation was superseded before finalization");
            }
            forge_db::outbox_dao::mark_processed(&mut *tx, row.id).await?;
            tx.commit().await?;
            forge_telemetry::storage::gc_deleted(forge_telemetry::storage::GcSource::Outbox, 1);

            Ok(true)
        }
    }
}

/// Rows deleted per statement by [`prune_processed`].
const PRUNE_BATCH: i64 = 1_000;

/// Upper bound on batches per [`prune_processed`] call, so one maintenance
/// tick never turns into an unbounded delete; a larger backlog drains over
/// subsequent ticks.
const PRUNE_MAX_BATCHES: usize = 50;

/// Delete processed outbox rows whose `processed_at` is older than
/// `retention`, in batches of [`PRUNE_BATCH`] (at most [`PRUNE_MAX_BATCHES`]
/// per call). Returns the number of rows deleted.
///
/// Processed rows are terminal and never consulted by the worker or the
/// reconciler, so this only bounds `blob_outbox` growth; unprocessed rows are
/// never touched. Each batch is its own short statement (no long-running
/// transaction, no lock on live rows), and the delete is idempotent, so every
/// instance can run it concurrently.
pub async fn prune_processed(pool: &PgPool, retention: chrono::Duration) -> anyhow::Result<u64> {
    let cutoff = forge_db::db_now(pool).await? - retention;
    let mut total = 0u64;
    for _ in 0..PRUNE_MAX_BATCHES {
        let deleted = forge_db::outbox_dao::prune_processed(pool, cutoff, PRUNE_BATCH).await?;
        total += deleted;
        if deleted < PRUNE_BATCH as u64 {
            break;
        }
    }
    Ok(total)
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
            let run = forge_telemetry::workers::Run::start(WORKER);
            let pass = run_once(&pool, &store, batch).instrument(run.span()).await;
            run.finish(pass.is_ok());
            if let Err(e) = pass {
                tracing::error!(error = %e, "outbox worker run_once failed");
            }
        }
    })
}

/// The worker's name (logs, `forge_worker_*`).
pub const WORKER: &str = "outbox";
