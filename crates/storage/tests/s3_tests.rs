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

// ── multipart abort (review 2026-10-02 L2) ──────────────────────────────────

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use forge_storage::{BlobStore, S3Config};

/// A minimal in-process S3 endpoint that speaks just enough of the multipart
/// protocol to inject the faults versitygw cannot: `CompleteMultipartUpload`
/// always fails, and `UploadPart` optionally never answers (a stalled
/// transfer the test can cancel). It records every abort it receives.
#[derive(Default)]
struct FakeS3 {
    stall_parts: bool,
    completes: AtomicUsize,
    aborts: AtomicUsize,
    part_started: tokio::sync::Notify,
    aborted: tokio::sync::Notify,
}

impl FakeS3 {
    /// Serve a fake on an ephemeral port and return it with a store pointed at
    /// it. The threshold of 1 byte sends every body down the multipart path.
    async fn start(stall_parts: bool) -> (Arc<Self>, BlobStore) {
        let fake = Arc::new(FakeS3 {
            stall_parts,
            ..Default::default()
        });
        let app = axum::Router::new()
            .fallback(fake_s3)
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let store = BlobStore::new(S3Config {
            endpoint: format!("http://{addr}"),
            region: "us-east-1".into(),
            bucket: "fake".into(),
            access_key: "ak".into(),
            secret_key: "sk".into(),
            force_path_style: true,
            multipart_threshold: 1,
            conditional_writes: Default::default(),
        });
        (fake, store)
    }
}

fn xml(status: StatusCode, body: &'static str) -> Response {
    (status, [("content-type", "application/xml")], body).into_response()
}

async fn fake_s3(
    State(fake): State<Arc<FakeS3>>,
    method: Method,
    uri: Uri,
    _body: Bytes,
) -> Response {
    let query = uri.query().unwrap_or_default();
    if method == Method::HEAD {
        // The object is absent, so `put_if_absent` proceeds to upload.
        StatusCode::NOT_FOUND.into_response()
    } else if method == Method::POST && query.contains("uploads") {
        xml(
            StatusCode::OK,
            "<InitiateMultipartUploadResult><Bucket>fake</Bucket><Key>k</Key>\
             <UploadId>fake-upload</UploadId></InitiateMultipartUploadResult>",
        )
    } else if method == Method::PUT && query.contains("partNumber=") {
        fake.part_started.notify_one();
        if fake.stall_parts {
            std::future::pending::<()>().await;
        }
        (StatusCode::OK, [("etag", "\"etag-1\"")]).into_response()
    } else if method == Method::POST && query.contains("uploadId=") {
        fake.completes.fetch_add(1, SeqCst);
        xml(
            StatusCode::BAD_REQUEST,
            "<Error><Code>InvalidPart</Code><Message>injected</Message></Error>",
        )
    } else if method == Method::DELETE && query.contains("uploadId=") {
        fake.aborts.fetch_add(1, SeqCst);
        fake.aborted.notify_one();
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_IMPLEMENTED.into_response()
    }
}

/// L2: a failed `CompleteMultipartUpload` aborts the upload (releasing its
/// parts) before the error reaches the caller.
#[tokio::test]
async fn multipart_upload_aborted_when_complete_fails() {
    let (fake, store) = FakeS3::start(false).await;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tokio::fs::write(tmp.path(), vec![7u8; 1024]).await.unwrap();

    store
        .put_if_absent("blobs/fake/complete-fails", tmp.path())
        .await
        .expect_err("the injected complete failure surfaces");
    assert_eq!(fake.completes.load(SeqCst), 1);
    assert_eq!(
        fake.aborts.load(SeqCst),
        1,
        "the failed upload must be aborted"
    );
}

/// L2: dropping the upload future mid-transfer (a client disconnect cancels
/// the request handler) aborts the multipart upload from a spawned task.
#[tokio::test]
async fn multipart_upload_aborted_when_cancelled() {
    let (fake, store) = FakeS3::start(true).await;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tokio::fs::write(tmp.path(), vec![7u8; 1024]).await.unwrap();
    let path = tmp.path().to_path_buf();

    let upload =
        tokio::spawn(async move { store.put_if_absent("blobs/fake/cancelled", &path).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        fake.part_started.notified(),
    )
    .await
    .expect("the part upload started");
    upload.abort();
    assert!(upload.await.unwrap_err().is_cancelled());

    tokio::time::timeout(std::time::Duration::from_secs(10), fake.aborted.notified())
        .await
        .expect("a dropped multipart upload must be aborted");
    assert_eq!(fake.aborts.load(SeqCst), 1);
    assert_eq!(fake.completes.load(SeqCst), 0);
}
