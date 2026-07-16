//! Integration tests for the deferred-delete outbox worker.
//!
//! Requires Docker (versitygw + postgres).

mod common;

use std::io::Cursor;

use chrono::{Duration, Utc};
use forge_storage::cas::Cas;
use forge_storage::outbox_worker;
use forge_storage::{BlobStore, S3Config};

const MAX: u64 = 100 * 1024 * 1024;
static OUTBOX_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Helper: ingest `content` and commit one reference, returning the sha256/key.
async fn ingest_and_commit(cas: &Cas, pool: &sqlx::PgPool, content: Vec<u8>) -> (String, String) {
    let stored = cas.store(Cursor::new(content), MAX).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::commit_ingest_and_incref(&mut tx, &stored.sha256, stored.ingest_token)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (stored.sha256, stored.s3_key)
}

/// Enqueue a delete (decref to zero, zero grace) then run the worker: the S3
/// object is gone, the blob row is gone, and the outbox row is processed.
#[tokio::test]
async fn worker_deletes_object_and_row() {
    let _test_guard = OUTBOX_TEST_LOCK.lock().await;
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

/// A failed S3 response is ambiguous: the remote delete may still complete
/// after the SDK returns. The worker must retain the reservation so a new
/// ingest cannot reuse that incarnation while the old delete is in flight.
#[tokio::test]
async fn ambiguous_delete_failure_keeps_incarnation_fenced() {
    let _test_guard = OUTBOX_TEST_LOCK.lock().await;
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let (sha, key) =
        ingest_and_commit(&cas, &pool, format!("outbox-ambiguous-{n}").into_bytes()).await;
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::zero())
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Point the worker at a closed loopback port so DELETE deterministically
    // fails without touching the real object.
    let unavailable = BlobStore::new(S3Config {
        endpoint: "http://127.0.0.1:1".to_string(),
        region: "us-east-1".to_string(),
        bucket: "unreachable".to_string(),
        access_key: "test".to_string(),
        secret_key: "test".to_string(),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: Default::default(),
    });
    assert_eq!(
        outbox_worker::run_once(&pool, &unavailable, 1)
            .await
            .unwrap(),
        0
    );

    let (state, delete_token): (String, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT state, delete_token FROM blob WHERE sha256 = $1")
            .bind(&sha)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "deleting");
    assert!(delete_token.is_some(), "failed delete retains its fence");
    assert!(store.head(&key).await.unwrap(), "real object was untouched");

    let outcome = forge_db::blob_dao::begin_ingest(
        &pool,
        &sha,
        1,
        "candidate/new-incarnation",
        Utc::now() + Duration::hours(1),
        Utc::now() - Duration::minutes(1),
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        forge_db::blob_dao::BeginIngestOutcome::DeletionInProgress,
        "an ambiguous delete keeps the old incarnation unavailable"
    );

    // Cleanup through the same stale-owner takeover protocol used in
    // production, then close the test's outbox row.
    sqlx::query(
        "UPDATE blob SET delete_started_at = now() - interval '2 minutes' WHERE sha256 = $1",
    )
    .bind(&sha)
    .execute(&pool)
    .await
    .unwrap();
    let takeover = match forge_db::blob_dao::reserve_outbox_delete(
        &pool,
        &sha,
        Utc::now() - Duration::minutes(1),
    )
    .await
    .unwrap()
    {
        forge_db::blob_dao::ReserveDeleteOutcome::Reserved(reservation) => reservation,
        other => panic!("cleanup takeover failed: {other:?}"),
    };
    store.delete(&takeover.s3_key).await.unwrap();
    assert!(
        forge_db::blob_dao::finalize_delete_reservation(&pool, &takeover)
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE blob_outbox SET processed_at = now(), locked_until = NULL WHERE sha256 = $1",
    )
    .bind(&sha)
    .execute(&pool)
    .await
    .unwrap();
}

/// If the blob is revived (ref_count > 0) before the worker runs, the worker
/// must NOT delete the S3 object and must mark the outbox row processed.
#[tokio::test]
async fn worker_skips_revived_blob() {
    let _test_guard = OUTBOX_TEST_LOCK.lock().await;
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

/// The hard interleaving: an ingest registers, observes the old deduplicated S3
/// object, and only later attaches its DB reference. A deleter must be unable to
/// reserve in that gap; otherwise it could remove the object before incref.
#[tokio::test]
async fn ingest_lease_fences_delete_between_s3_dedup_and_incref() {
    let _test_guard = OUTBOX_TEST_LOCK.lock().await;
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let content = format!("dedup-delete-barrier-{n}").into_bytes();
    let initial = cas.store(Cursor::new(content.clone()), MAX).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::commit_ingest_and_incref(&mut tx, &initial.sha256, initial.ingest_token)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Leave a future-due outbox row so sibling test workers cannot claim it;
    // this test drives the reservation boundary directly.
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::decref_and_maybe_enqueue_delete(
        &mut tx,
        &initial.sha256,
        Duration::hours(1),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Registers the ingest lease before HEAD and observes the old object.
    let revived = cas.store(Cursor::new(content), MAX).await.unwrap();
    assert!(!revived.uploaded, "revival deduplicated onto old object");

    let outcome = forge_db::blob_dao::reserve_outbox_delete(
        &pool,
        &revived.sha256,
        Utc::now() - Duration::minutes(2),
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        forge_db::blob_dao::ReserveDeleteOutcome::Busy,
        "live ingest lease must fence deletion after the S3 dedup check"
    );

    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::commit_ingest_and_incref(&mut tx, &revived.sha256, revived.ingest_token)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let outcome = forge_db::blob_dao::reserve_outbox_delete(
        &pool,
        &revived.sha256,
        Utc::now() - Duration::minutes(2),
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        forge_db::blob_dao::ReserveDeleteOutcome::Referenced
    );
    assert!(store.head(&revived.s3_key).await.unwrap());

    // Per-test object key is unique; avoid leaving S3 fixtures behind.
    store.delete(&revived.s3_key).await.unwrap();
}

/// If a delete owner is fenced out after a timeout, its in-flight S3 request
/// may still finish late. A revived row must use a new object incarnation so
/// that stale request can only touch the old key.
#[tokio::test]
async fn stale_delete_cannot_remove_revived_object_incarnation() {
    let _test_guard = OUTBOX_TEST_LOCK.lock().await;
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let content = format!("delete-incarnation-fence-{n}").into_bytes();
    let initial = cas.store(Cursor::new(content.clone()), MAX).await.unwrap();
    let old_key = initial.s3_key.clone();
    let sha = initial.sha256.clone();
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::commit_ingest_and_incref(&mut tx, &sha, initial.ingest_token)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::hours(1))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let first = match forge_db::blob_dao::reserve_outbox_delete(
        &pool,
        &sha,
        Utc::now() - Duration::minutes(2),
    )
    .await
    .unwrap()
    {
        forge_db::blob_dao::ReserveDeleteOutcome::Reserved(r) => r,
        other => panic!("first reservation failed: {other:?}"),
    };

    sqlx::query(
        "UPDATE blob SET delete_started_at = now() - interval '2 minutes' WHERE sha256 = $1",
    )
    .bind(&sha)
    .execute(&pool)
    .await
    .unwrap();
    let takeover = match forge_db::blob_dao::reserve_outbox_delete(
        &pool,
        &sha,
        Utc::now() - Duration::minutes(1),
    )
    .await
    .unwrap()
    {
        forge_db::blob_dao::ReserveDeleteOutcome::Reserved(r) => r,
        other => panic!("takeover reservation failed: {other:?}"),
    };
    assert_ne!(first.token, takeover.token);

    store.delete(&takeover.s3_key).await.unwrap();
    assert!(
        forge_db::blob_dao::finalize_delete_reservation(&pool, &takeover)
            .await
            .unwrap()
    );

    let revived = cas.store(Cursor::new(content), MAX).await.unwrap();
    assert_ne!(revived.s3_key, old_key, "revival must rotate object key");
    let mut tx = pool.begin().await.unwrap();
    forge_db::blob_dao::commit_ingest_and_incref(&mut tx, &sha, revived.ingest_token)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Simulate the first owner's delayed S3 completion and stale DB finalize.
    store.delete(&first.s3_key).await.unwrap();
    assert!(
        !forge_db::blob_dao::finalize_delete_reservation(&pool, &first)
            .await
            .unwrap()
    );
    assert!(
        store.head(&revived.s3_key).await.unwrap(),
        "late delete only targeted the old incarnation"
    );

    store.delete(&revived.s3_key).await.unwrap();
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
