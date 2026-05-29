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
//! S3 call: it lists candidates, deletes objects outside any transaction, then
//! deletes the rows.

use chrono::{Duration, Utc};
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
    let cutoff = Utc::now() - grace;
    let mut removed = 0usize;

    // Class 1: stale pending uploads whose owning tx never committed.
    let stale_pending =
        forge_db::blob_dao::list_stale_pending(pool, cutoff, RECONCILE_BATCH).await?;
    for blob in stale_pending {
        // Delete the S3 object first (idempotent, no tx held), then drop the row
        // only if it is *still* a stale pending row — a slow-but-valid ingest
        // could have committed it in the meantime, in which case we leave it.
        let res = async {
            store.delete(&blob.s3_key).await?;
            let removed =
                forge_db::blob_dao::delete_if_stale_pending(pool, &blob.sha256, cutoff).await?;
            Ok::<bool, anyhow::Error>(removed)
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
    let stale_unref =
        forge_db::blob_dao::list_stale_unreferenced(pool, cutoff, RECONCILE_BATCH).await?;
    for blob in stale_unref {
        let res = async {
            store.delete(&blob.s3_key).await?;
            // Drop the row only if it is still unreferenced (a re-push may have
            // revived it).
            let removed = forge_db::blob_dao::delete_if_unreferenced(pool, &blob.sha256).await?;
            Ok::<bool, anyhow::Error>(removed)
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
