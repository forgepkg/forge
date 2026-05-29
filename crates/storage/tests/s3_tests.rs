//! Integration tests for the S3 `BlobStore` against a live versitygw container.
//!
//! Requires Docker (like the `forge-db` tests).

mod common;

use tokio::io::AsyncReadExt;

/// put -> head(true) -> get(bytes match) -> delete -> delete-again(ok) ->
/// head(false). The full object lifecycle on versitygw.
#[tokio::test]
async fn object_lifecycle() {
    let store = common::blob_store().await;
    let n = common::unique();
    let key = format!("test/lifecycle/{n}");
    let body = format!("hello versitygw {n}").into_bytes();

    // Write the body to a temp file (put_if_absent uploads from a path).
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tokio::fs::write(tmp.path(), &body).await.unwrap();

    // put
    assert!(!store.head(&key).await.unwrap(), "absent before put");
    let uploaded = store.put_if_absent(&key, tmp.path()).await.unwrap();
    assert!(uploaded, "first put should upload");

    // head(true)
    assert!(store.head(&key).await.unwrap(), "present after put");

    // get -> bytes match
    let mut got = Vec::new();
    store
        .get(&key)
        .await
        .unwrap()
        .into_async_read()
        .read_to_end(&mut got)
        .await
        .unwrap();
    assert_eq!(got, body, "round-tripped bytes match");

    // put_if_absent again -> dedup hit, no upload
    let uploaded_again = store.put_if_absent(&key, tmp.path()).await.unwrap();
    assert!(!uploaded_again, "second put is a dedup hit");

    // delete
    store.delete(&key).await.unwrap();
    // delete again -> idempotent Ok
    store.delete(&key).await.unwrap();

    // head(false)
    assert!(!store.head(&key).await.unwrap(), "absent after delete");
}

/// Multipart path: a body above the (small) threshold uploads via multipart and
/// round-trips intact.
#[tokio::test]
async fn multipart_upload_round_trips() {
    // 9 MiB threshold-1 trick: set threshold to 4 MiB and upload ~10 MiB so we
    // exercise multiple parts.
    let store = common::blob_store_with_threshold(4 * 1024 * 1024).await;
    let n = common::unique();
    let key = format!("test/multipart/{n}");

    // ~10 MiB of pseudo-random-ish but deterministic content.
    let mut body = Vec::with_capacity(10 * 1024 * 1024);
    for i in 0..(10 * 1024 * 1024u32) {
        body.push((i.wrapping_mul(2654435761) >> 13) as u8);
    }

    let tmp = tempfile::NamedTempFile::new().unwrap();
    tokio::fs::write(tmp.path(), &body).await.unwrap();

    let uploaded = store.put_if_absent(&key, tmp.path()).await.unwrap();
    assert!(uploaded);
    assert!(store.head(&key).await.unwrap());

    let mut got = Vec::new();
    store
        .get(&key)
        .await
        .unwrap()
        .into_async_read()
        .read_to_end(&mut got)
        .await
        .unwrap();
    assert_eq!(got.len(), body.len(), "multipart length matches");
    assert_eq!(got, body, "multipart bytes match");

    store.delete(&key).await.unwrap();
}
