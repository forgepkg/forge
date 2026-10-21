//! Orphan reconciler — the safety net behind the outbox.
//!
//! Two classes of leftover state can survive a crash or a never-committed
//! ingest transaction:
//!
//! 1. **Stale `pending` blobs.** [`Cas::store`](crate::cas::Cas::store) uploads
//!    the object and writes a `pending` row, then hands the temp file back to
//!    the caller. If the caller's transaction (asset insert +
//!    `commit_and_incref`) never commits, the row stays `pending` forever and
//!    the S3 object is orphaned. After `grace`, we delete the object and row.
//!
//! 2. **Dangling zero-refcount blobs.** A committed blob can drop to
//!    `ref_count = 0` with no outstanding `blob_outbox` delete row (e.g. the
//!    outbox row was already processed but the blob row delete lost a race, or
//!    a manual decref path). After `grace`, we delete the object and row.
//!
//! Like the outbox worker, the reconciler never holds a DB transaction across an
//! S3 call: it lists candidates, reserves each eligible row with a fencing
//! token, deletes the object, then token-conditionally deletes the row. Live
//! ingest leases make a candidate ineligible.

use chrono::Duration;
use sqlx::PgPool;

use crate::s3::BlobStore;

/// Maximum candidates examined per reconcile pass (per class).
const RECONCILE_BATCH: i64 = 200;

/// Reconcile orphaned blobs older than `grace`. Returns the number of blob rows
/// removed across both classes.
pub async fn reconcile_orphans(
    pool: &PgPool,
    store: &BlobStore,
    grace: Duration,
) -> anyhow::Result<usize> {
    // Both cutoffs are compared with database timestamps: take the
    // database's clock.
    let now = forge_db::db_now(pool).await?;
    let cutoff = now - grace;
    let stale_deletion_before = now - crate::cas::DELETE_RESERVATION_LEASE;
    let mut removed = 0usize;

    // Expired leases on live/referenced blobs might never pass through a delete
    // candidate. Keep the coordination table bounded independently.
    forge_db::blob_dao::prune_expired_ingests(pool, RECONCILE_BATCH).await?;

    // Class 1: stale pending uploads whose owning tx never committed.
    let stale_pending = forge_db::blob_dao::list_stale_pending(
        pool,
        cutoff,
        stale_deletion_before,
        RECONCILE_BATCH,
    )
    .await?;
    for blob in stale_pending {
        let res = async {
            let reservation = match forge_db::blob_dao::reserve_stale_pending_delete(
                pool,
                &blob.sha256,
                cutoff,
                stale_deletion_before,
            )
            .await?
            {
                forge_db::blob_dao::ReserveDeleteOutcome::Reserved(reservation) => reservation,
                _ => return Ok::<bool, anyhow::Error>(false),
            };
            if let Err(error) = store
                .delete_blob(&reservation.sha256, &reservation.s3_key)
                .await
            {
                // The failed response may hide a delete that completes later.
                // Retain the fence until a stale-reservation takeover so this
                // object incarnation cannot be revived underneath it.
                return Err(error.into());
            }
            let finalized =
                forge_db::blob_dao::finalize_delete_reservation(pool, &reservation).await?;
            if !finalized {
                anyhow::bail!("stale pending deletion reservation was superseded");
            }
            Ok(true)
        }
        .await;
        match res {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(
                sha256 = %blob.sha256,
                error = %e,
                "reconcile of stale pending blob failed"
            ),
        }
    }

    // Class 2: committed-then-unreferenced blobs with no pending outbox row.
    let stale_unref = forge_db::blob_dao::list_stale_unreferenced(
        pool,
        cutoff,
        stale_deletion_before,
        RECONCILE_BATCH,
    )
    .await?;
    for blob in stale_unref {
        let res = async {
            let reservation = match forge_db::blob_dao::reserve_dangling_delete(
                pool,
                &blob.sha256,
                cutoff,
                stale_deletion_before,
            )
            .await?
            {
                forge_db::blob_dao::ReserveDeleteOutcome::Reserved(reservation) => reservation,
                _ => return Ok::<bool, anyhow::Error>(false),
            };
            if let Err(error) = store
                .delete_blob(&reservation.sha256, &reservation.s3_key)
                .await
            {
                // Preserve the reservation on an ambiguous failure; releasing
                // it would allow a new reference to reuse a key that a delayed
                // delete can still remove.
                return Err(error.into());
            }
            let finalized =
                forge_db::blob_dao::finalize_delete_reservation(pool, &reservation).await?;
            if !finalized {
                anyhow::bail!("dangling blob deletion reservation was superseded");
            }
            Ok(true)
        }
        .await;
        match res {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(
                sha256 = %blob.sha256,
                error = %e,
                "reconcile of dangling unreferenced blob failed"
            ),
        }
    }

    Ok(removed)
}
