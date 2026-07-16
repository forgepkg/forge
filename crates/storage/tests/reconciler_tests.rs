//! Integration tests for the orphan reconciler.
//!
//! Requires Docker (versitygw + postgres).

mod common;

use std::io::Cursor;

use chrono::Duration;
use forge_storage::cas::Cas;
use forge_storage::reconciler;
use tokio::sync::Mutex;

const MAX: u64 = 100 * 1024 * 1024;

// Every reconciler pass intentionally scans all eligible rows in the shared
// test database. Serialize this test binary so one test cannot reserve and
// delete another test's blob between its object and row assertions.
static RECONCILE_LOCK: Mutex<()> = Mutex::const_new(());

/// A `pending` blob older than the grace window whose S3 object exists (a
/// never-committed ingest) is reconciled: object + row removed.
#[tokio::test]
async fn reconciles_stale_pending() {
    let _guard = RECONCILE_LOCK.lock().await;
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    // Ingest but never commit -> stays pending, object uploaded.
    let stored = cas
        .store(Cursor::new(format!("orphan-pending-{n}").into_bytes()), MAX)
        .await
        .unwrap();
    assert!(store.head(&stored.s3_key).await.unwrap(), "object present");
    // Simulate the caller abandoning the staged promotion. `StoredBlob` would
    // release this on drop; make it deterministic while retaining its fields.
    forge_db::blob_dao::abort_ingest(&pool, stored.ingest_token)
        .await
        .unwrap();

    // Backdate created_at so it falls outside the grace window.
    backdate_blob(&pool, &stored.sha256, Duration::hours(2)).await;

    // Reconcile with a 1h grace. Assert on the per-blob end state rather than
    // the aggregate count so unrelated leftovers cannot affect the result.
    reconciler::reconcile_orphans(&pool, &store, Duration::hours(1))
        .await
        .unwrap();

    // Object and row gone.
    assert!(!store.head(&stored.s3_key).await.unwrap(), "object removed");
    assert!(
        forge_db::blob_dao::get_blob(&pool, &stored.sha256)
            .await
            .unwrap()
            .is_none(),
        "blob row removed"
    );
}

/// A `pending` blob NEWER than the grace window is left alone (its owning
/// transaction may still be in flight).
#[tokio::test]
async fn leaves_fresh_pending_alone() {
    let _guard = RECONCILE_LOCK.lock().await;
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let stored = cas
        .store(Cursor::new(format!("fresh-pending-{n}").into_bytes()), MAX)
        .await
        .unwrap();

    // Long grace: nothing should be reconciled.
    let _ = reconciler::reconcile_orphans(&pool, &store, Duration::hours(24))
        .await
        .unwrap();

    assert!(
        store.head(&stored.s3_key).await.unwrap(),
        "fresh object kept"
    );
    assert!(
        forge_db::blob_dao::get_blob(&pool, &stored.sha256)
            .await
            .unwrap()
            .is_some(),
        "fresh blob row kept"
    );

    // Cleanup.
    store.delete(&stored.s3_key).await.unwrap();
}

/// A committed-then-unreferenced blob (ref_count = 0) older than grace with no
/// pending outbox row is reconciled.
#[tokio::test]
async fn reconciles_dangling_unreferenced() {
    let _guard = RECONCILE_LOCK.lock().await;
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let stored = cas
        .store(Cursor::new(format!("dangling-{n}").into_bytes()), MAX)
        .await
        .unwrap();

    // Commit once then bring ref_count back to zero WITHOUT enqueuing an outbox
    // row (simulate the outbox row already having been processed).
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::commit_ingest_and_incref(&mut tx, &stored.sha256, stored.ingest_token)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    set_ref_count_zero(&pool, &stored.sha256).await;

    backdate_blob(&pool, &stored.sha256, Duration::hours(2)).await;

    reconciler::reconcile_orphans(&pool, &store, Duration::hours(1))
        .await
        .unwrap();

    assert!(!store.head(&stored.s3_key).await.unwrap());
    assert!(forge_db::blob_dao::get_blob(&pool, &stored.sha256)
        .await
        .unwrap()
        .is_none());
}

/// A stale-looking pending row is not deleted while the CAS promotion's ingest
/// lease is live. This covers the reconciler side of the same fence used by the
/// outbox worker.
#[tokio::test]
async fn live_ingest_lease_fences_stale_pending_reconcile() {
    let _guard = RECONCILE_LOCK.lock().await;
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let stored = cas
        .store(Cursor::new(format!("leased-pending-{n}").into_bytes()), MAX)
        .await
        .unwrap();
    backdate_blob(&pool, &stored.sha256, Duration::hours(2)).await;

    reconciler::reconcile_orphans(&pool, &store, Duration::hours(1))
        .await
        .unwrap();

    assert!(store.head(&stored.s3_key).await.unwrap());
    assert!(forge_db::blob_dao::get_blob(&pool, &stored.sha256)
        .await
        .unwrap()
        .is_some());

    forge_db::blob_dao::abort_ingest(&pool, stored.ingest_token)
        .await
        .unwrap();
    reconciler::reconcile_orphans(&pool, &store, Duration::hours(1))
        .await
        .unwrap();
    assert!(!store.head(&stored.s3_key).await.unwrap());
}

/// Backdate a blob's `created_at` by `age` so it falls outside a grace window.
async fn backdate_blob(pool: &sqlx::PgPool, sha256: &str, age: Duration) {
    sqlx::query("UPDATE blob SET created_at = now() - make_interval(secs => $2) WHERE sha256 = $1")
        .bind(sha256)
        .bind(age.num_seconds() as f64)
        .execute(pool)
        .await
        .unwrap();
}

/// Force a blob's ref_count to zero (and state committed) without touching the
/// outbox.
async fn set_ref_count_zero(pool: &sqlx::PgPool, sha256: &str) {
    sqlx::query("UPDATE blob SET ref_count = 0, state = 'committed' WHERE sha256 = $1")
        .bind(sha256)
        .execute(pool)
        .await
        .unwrap();
}
