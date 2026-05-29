//! Integration tests for the content-addressed store (`Cas`).
//!
//! Requires Docker (versitygw + postgres).

mod common;

use std::io::Cursor;

use forge_storage::cas::{Cas, CasError};
use tokio::io::AsyncReadExt;

const MAX: u64 = 100 * 1024 * 1024;

/// Identical bytes stored twice produce ONE S3 object: the first ingest
/// uploads, the second is a dedup hit (no second PUT). The blob row exists once.
#[tokio::test]
async fn identical_bytes_dedup_to_one_object() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let content = format!("dedup-me-{n}").into_bytes();

    // First store: fresh upload.
    let first = cas.store(Cursor::new(content.clone()), MAX).await.unwrap();
    assert!(first.uploaded, "first ingest uploads");
    assert!(store.head(&first.s3_key).await.unwrap(), "object present");

    // Second store of identical bytes: dedup hit, same key, no new upload.
    let second = cas.store(Cursor::new(content.clone()), MAX).await.unwrap();
    assert_eq!(first.sha256, second.sha256, "same content hash");
    assert_eq!(first.s3_key, second.s3_key, "same S3 key");
    assert!(!second.uploaded, "second ingest is a dedup hit (no PUT)");

    // Exactly one blob row, still pending (caller never committed).
    let blob = forge_db::blob_dao::get_blob(&pool, &first.sha256)
        .await
        .unwrap()
        .expect("blob row exists");
    assert_eq!(blob.ref_count, 0);
    assert_eq!(blob.state, "pending");
    assert_eq!(blob.size, content.len() as i64);

    // sha512 is populated and stable across ingests.
    assert!(!first.sha512_base64.is_empty());
    assert_eq!(first.sha512_base64, second.sha512_base64);

    store.delete(&first.s3_key).await.unwrap();
}

/// Different bytes produce two distinct objects / blob rows.
#[tokio::test]
async fn different_bytes_two_objects() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let a = format!("content-a-{n}").into_bytes();
    let b = format!("content-b-{n}").into_bytes();

    let sa = cas.store(Cursor::new(a), MAX).await.unwrap();
    let sb = cas.store(Cursor::new(b), MAX).await.unwrap();

    assert_ne!(sa.sha256, sb.sha256);
    assert_ne!(sa.s3_key, sb.s3_key);
    assert!(sa.uploaded && sb.uploaded);
    assert!(store.head(&sa.s3_key).await.unwrap());
    assert!(store.head(&sb.s3_key).await.unwrap());

    store.delete(&sa.s3_key).await.unwrap();
    store.delete(&sb.s3_key).await.unwrap();
}

/// The temp file stays alive in `StoredBlob` and contains the original bytes,
/// so a caller can hand it to a parser before committing.
#[tokio::test]
async fn temp_file_holds_content() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    let content = format!("read-me-back-{n}").into_bytes();
    let stored = cas.store(Cursor::new(content.clone()), MAX).await.unwrap();

    let mut f = tokio::fs::File::open(&stored.temp_path).await.unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, content, "temp file holds the ingested bytes");

    store.delete(&stored.s3_key).await.unwrap();
}

/// Exceeding `max_bytes` errors and uploads nothing.
#[tokio::test]
async fn enforces_max_bytes() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());

    let n = common::unique();
    // 2 KiB of content, 1 KiB cap.
    let content = vec![(n % 256) as u8; 2048];
    let err = cas.store(Cursor::new(content), 1024).await.unwrap_err();
    assert!(
        matches!(err, CasError::TooLarge { limit: 1024 }),
        "got {err:?}"
    );
}
