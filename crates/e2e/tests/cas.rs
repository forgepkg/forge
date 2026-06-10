//! E2E: content-addressed storage — dedup + refcount transitions (2→1→0) with
//! the outbox worker performing the deferred S3 delete, and the orphan
//! reconciler reclaiming a never-committed `pending` blob (spec §9). Gated
//! behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::time::Duration;

use forge_e2e::{make_nupkg, StackBuilder, S3_ACCESS, S3_BUCKET, S3_SECRET};
use forge_storage::{BlobStore, Cas, S3Config};
use sha2::{Digest, Sha256};

/// sha256 hex of `bytes` (the CAS key for the nupkg blob).
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

async fn ref_count(pool: &sqlx::PgPool, sha: &str) -> Option<i64> {
    sqlx::query_scalar::<_, i64>("SELECT ref_count FROM blob WHERE sha256 = $1")
        .bind(sha)
        .fetch_optional(pool)
        .await
        .unwrap()
}

/// Push the same package to two hosted repos ⇒ one shared blob with
/// `ref_count == 2`. Hard-delete one ⇒ `ref_count == 1`, no S3 delete. Hard-
/// delete the other ⇒ the outbox worker removes the S3 object and the blob row.
#[tokio::test]
async fn dedup_refcount_2_to_1_to_0_with_outbox_delete() {
    // Workers on so the outbox drains; grace_seconds=0 ⇒ deletes are due now.
    let srv = StackBuilder::default().workers(true).start().await;

    let id = "Dedup.Lib";
    for repo in ["dd-a", "dd-b"] {
        assert_eq!(
            srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted"}))
                .await
                .status(),
            201
        );
    }

    let bytes = make_nupkg(id, "1.0.0");
    let sha = sha256_hex(&bytes);

    assert_eq!(srv.push_nupkg("dd-a", bytes.clone()).await.status(), 201);
    assert_eq!(srv.push_nupkg("dd-b", bytes.clone()).await.status(), 201);

    // Dedup: one blob, ref_count == 2.
    assert_eq!(
        ref_count(&srv.pool, &sha).await,
        Some(2),
        "same bytes pushed to two repos ⇒ one blob, ref_count 2"
    );

    // The S3 object exists.
    let s3_key = Cas::blob_key(&sha);
    assert!(
        srv.state.blob_store.get(&s3_key).await.is_ok(),
        "blob object present in S3"
    );

    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // Hard-delete from repo A ⇒ ref_count 1, no S3 delete.
    let resp = client
        .delete(format!(
            "{}/admin/repositories/dd-a/packages/{id}/1.0.0",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "hard delete A");

    assert_eq!(
        ref_count(&srv.pool, &sha).await,
        Some(1),
        "after deleting one repo's reference, ref_count drops to 1"
    );
    // Give any (incorrect) outbox delete a chance to run, then assert the object
    // is still present (no delete enqueued while ref_count > 0).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        srv.state.blob_store.get(&s3_key).await.is_ok(),
        "S3 object must remain while ref_count > 0"
    );

    // Hard-delete from repo B ⇒ ref_count 0 ⇒ outbox delete enqueued.
    let resp = client
        .delete(format!(
            "{}/admin/repositories/dd-b/packages/{id}/1.0.0",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "hard delete B");

    // The worker (poll 1s, grace 0) removes the blob row + S3 object AND marks
    // every outbox row processed. Poll all three together: the outbox finalize
    // (set processed_at) happens in a short tx *after* the blob-row delete (A7),
    // so `pending == 0` is the authoritative "fully drained" signal.
    let mut gone = false;
    for _ in 0..40 {
        let row = ref_count(&srv.pool, &sha).await;
        let s3_present = srv.state.blob_store.get(&s3_key).await.is_ok();
        let pending: i64 =
            sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE processed_at IS NULL")
                .fetch_one(&srv.pool)
                .await
                .unwrap();
        if row.is_none() && !s3_present && pending == 0 {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        gone,
        "outbox worker must delete the S3 object + blob row and fully drain the outbox once ref_count hits 0"
    );
}

/// The orphan reconciler reclaims a `pending` blob whose ingest transaction
/// never committed (the CAS stored bytes + a pending row, but no commit/incref).
#[tokio::test]
async fn orphan_reconciler_reclaims_pending_blob() {
    let srv = StackBuilder::default().start().await; // no workers; drive reconciler directly

    // Build a standalone CAS over the same store + pool and store bytes WITHOUT
    // committing — simulating a publish whose tx never finished.
    let store = BlobStore::new(S3Config {
        endpoint: srv.state.config.s3.endpoint.clone(),
        region: "us-east-1".into(),
        bucket: S3_BUCKET.into(),
        access_key: S3_ACCESS.into(),
        secret_key: S3_SECRET.into(),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: Default::default(),
    });
    let cas = Cas::new(store.clone(), srv.pool.clone());

    let bytes = make_nupkg("Orphan.Lib", "1.0.0");
    let sha = sha256_hex(&bytes);
    let stored = cas
        .store(std::io::Cursor::new(bytes), 64 * 1024 * 1024)
        .await
        .expect("cas store");
    assert_eq!(stored.sha256, sha);

    // It is a pending, zero-ref blob.
    let state: String = sqlx::query_scalar("SELECT state FROM blob WHERE sha256 = $1")
        .bind(&sha)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(state, "pending");
    assert_eq!(ref_count(&srv.pool, &sha).await, Some(0));
    let s3_key = Cas::blob_key(&sha);
    assert!(store.get(&s3_key).await.is_ok(), "pending object in S3");

    // Reconcile with grace 0 ⇒ the stale pending blob is reclaimed.
    let reclaimed =
        forge_storage::reconciler::reconcile_orphans(&srv.pool, &store, chrono::Duration::zero())
            .await
            .expect("reconcile");
    assert!(reclaimed >= 1, "reconciler reclaimed at least the orphan");

    assert_eq!(
        ref_count(&srv.pool, &sha).await,
        None,
        "orphan blob row removed"
    );
    assert!(
        store.get(&s3_key).await.is_err(),
        "orphan S3 object removed"
    );
}
