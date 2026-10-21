//! Garbage collection of registry rows: abandoned upload sessions and blob
//! links no manifest references any more. Each removed row releases its blob
//! reference; the blob outbox deletes what nothing references after its
//! grace period, so a layer another image still links is never removed.
//!
//! Safe on every instance at once: each candidate is locked and re-checked
//! in its own transaction.

use chrono::Duration;
use forge_db::oci_dao;
use sqlx::PgPool;

/// Candidates looked at per pass and kind.
const BATCH: i64 = 500;

/// What one sweep removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepSummary {
    pub uploads: u64,
    pub links: u64,
}

/// One sweep: uploads idle longer than `upload_ttl`, and links unused for
/// `unreferenced_ttl` that no manifest of their image names.
pub async fn sweep_once(
    pool: &PgPool,
    upload_ttl: Duration,
    unreferenced_ttl: Duration,
    grace: Duration,
) -> sqlx::Result<SweepSummary> {
    let now = forge_db::db_now(pool).await?;
    let mut summary = SweepSummary::default();

    let upload_cutoff = now - upload_ttl;
    for id in oci_dao::stale_uploads(pool, upload_cutoff, BATCH).await? {
        if oci_dao::expire_upload(pool, id, upload_cutoff, grace).await? {
            summary.uploads += 1;
        }
    }

    let link_cutoff = now - unreferenced_ttl;
    for key in oci_dao::unreferenced_links(pool, link_cutoff, BATCH).await? {
        if oci_dao::sweep_link(pool, &key, link_cutoff, grace).await? {
            summary.links += 1;
        }
    }
    Ok(summary)
}
