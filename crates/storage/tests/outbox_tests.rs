//! Integration tests for the deferred-delete outbox worker.
//!
//! Requires Docker (versitygw + postgres).

mod common;

use std::io::Cursor;

use chrono::Duration;
use forge_storage::cas::Cas;
use forge_storage::outbox_worker;

const MAX: u64 = 100 * 1024 * 1024;

/// Helper: ingest `content` and commit one reference, returning the sha256/key.
async fn ingest_and_commit(cas: &Cas, pool: &sqlx::PgPool, content: Vec<u8>) -> (String, String) {
    let stored = cas.store(Cursor::new(content), MAX).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::commit_and_incref(&mut tx, &stored.sha256)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (stored.sha256, stored.s3_key)
}

/// Enqueue a delete (decref to zero, zero grace) then run the worker: the S3
/// object is gone, the blob row is gone, and the outbox row is processed.
#[tokio::test]
async fn worker_deletes_object_and_row() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let (sha, key) = ingest_and_commit(&cas, &pool, format!("outbox-del-{n}").into_bytes()).await;
    assert!(
        store.head(&key).await.unwrap(),
        "object present after commit"
    );

    // Decref to zero with zero grace -> enqueues a due delete_object row.
    let mut tx = pool.begin().await.unwrap();
    let hit_zero =
        forge_db::blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::zero())
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert!(hit_zero, "ref count hit zero, delete enqueued");

    // Run the worker until this sha's outbox row is processed. (Tests share a
    // DB and run in parallel, so a sibling test's worker invocation may process
    // our row and vice-versa — assert on the per-sha end state, not a global
    // processed count.)
    drain_outbox_for(&pool, &store, &sha).await;

    // S3 object gone.
    assert!(!store.head(&key).await.unwrap(), "object deleted");
    // Blob row gone.
    assert!(
        forge_db::blob_dao::get_blob(&pool, &sha)
            .await
            .unwrap()
            .is_none(),
        "blob row deleted"
    );
    // Outbox row processed.
    let outstanding = pending_outbox_count(&pool, &sha).await;
    assert_eq!(outstanding, 0, "no unprocessed outbox rows remain");
}

/// If the blob is revived (ref_count > 0) before the worker runs, the worker
/// must NOT delete the S3 object and must mark the outbox row processed.
#[tokio::test]
async fn worker_skips_revived_blob() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let (sha, key) =
        ingest_and_commit(&cas, &pool, format!("outbox-revive-{n}").into_bytes()).await;

    // Decref to zero -> enqueue delete.
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::zero())
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Revive: a re-push increfs the blob back above zero before the worker runs.
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    drain_outbox_for(&pool, &store, &sha).await;

    // S3 object MUST still be present.
    assert!(
        store.head(&key).await.unwrap(),
        "object preserved for revived blob"
    );
    // Blob row still present with ref_count > 0.
    let blob = forge_db::blob_dao::get_blob(&pool, &sha)
        .await
        .unwrap()
        .expect("blob row still present");
    assert!(blob.ref_count > 0, "blob revived");
    // Outbox row is processed (no unprocessed rows).
    assert_eq!(pending_outbox_count(&pool, &sha).await, 0);

    // Cleanup.
    store.delete(&key).await.unwrap();
}

/// Drive `run_once` until the outbox row for `sha256` is processed (no
/// unprocessed rows remain for it). Robust under parallel tests sharing the DB:
/// any worker invocation (ours or a sibling's) may be the one that drains it.
async fn drain_outbox_for(pool: &sqlx::PgPool, store: &forge_storage::BlobStore, sha256: &str) {
    for _ in 0..30 {
        outbox_worker::run_once(pool, store, 10).await.unwrap();
        if pending_outbox_count(pool, sha256).await == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("outbox row for {sha256} was never processed");
}

/// Count unprocessed outbox rows for a given sha256.
async fn pending_outbox_count(pool: &sqlx::PgPool, sha256: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM blob_outbox WHERE sha256 = $1 AND processed_at IS NULL",
    )
    .bind(sha256)
    .fetch_one(pool)
    .await
    .unwrap()
}
