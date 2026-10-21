//! `BlobStore::ensure_bucket` against a fake S3 endpoint (#113): a new bucket
//! is created in the configured region, a bucket another account owns is an
//! error that names it, and one the credentials already own is success.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use forge_storage::{BlobStore, S3Config};

/// What the fake answers a `CreateBucket` with.
#[derive(Clone, Copy)]
enum Create {
    Created,
    OwnedByYou,
    TakenByAnotherAccount,
}

struct FakeS3 {
    create: Create,
    /// The bodies of the `CreateBucket` requests received.
    create_bodies: Mutex<Vec<String>>,
}

async fn fake_s3(State(fake): State<Arc<FakeS3>>, method: Method, body: Bytes) -> Response {
    let error = |code: &str| {
        (
            StatusCode::CONFLICT,
            [("content-type", "application/xml")],
            format!("<Error><Code>{code}</Code><Message>injected</Message></Error>"),
        )
            .into_response()
    };
    match method {
        // The bucket is not reachable with these credentials.
        Method::HEAD => match fake.create {
            Create::TakenByAnotherAccount => StatusCode::FORBIDDEN.into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        },
        Method::PUT => {
            fake.create_bodies
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&body).into_owned());
            match fake.create {
                Create::Created => StatusCode::OK.into_response(),
                Create::OwnedByYou => error("BucketAlreadyOwnedByYou"),
                Create::TakenByAnotherAccount => error("BucketAlreadyExists"),
            }
        }
        _ => StatusCode::NOT_IMPLEMENTED.into_response(),
    }
}

async fn start(create: Create, region: &str) -> (Arc<FakeS3>, BlobStore) {
    let fake = Arc::new(FakeS3 {
        create,
        create_bodies: Mutex::default(),
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
        region: region.into(),
        bucket: "forge-blobs".into(),
        access_key: "ak".into(),
        secret_key: "sk".into(),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: Default::default(),
    });
    (fake, store)
}

/// Outside `us-east-1` the create names the region as `LocationConstraint`
/// (AWS refuses it otherwise with `IllegalLocationConstraintException`); in
/// `us-east-1` it carries no constraint, which AWS would refuse there.
#[tokio::test]
async fn a_missing_bucket_is_created_in_the_configured_region() {
    let (fake, store) = start(Create::Created, "eu-central-1").await;
    store.ensure_bucket().await.expect("created");
    let bodies = fake.create_bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("<LocationConstraint>eu-central-1</LocationConstraint>"),
        "{bodies:?}"
    );

    let (fake, store) = start(Create::Created, "us-east-1").await;
    store.ensure_bucket().await.expect("created");
    let bodies = fake.create_bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    assert!(!bodies[0].contains("LocationConstraint"), "{bodies:?}");
}

/// `BucketAlreadyExists` for a bucket these credentials cannot reach means
/// another account owns the name: an error naming the bucket, not a start
/// whose readiness probe then fails without saying why.
#[tokio::test]
async fn a_bucket_another_account_owns_is_an_error_naming_it() {
    let (_fake, store) = start(Create::TakenByAnotherAccount, "eu-central-1").await;
    let err = store
        .ensure_bucket()
        .await
        .expect_err("not ours")
        .to_string();
    assert!(err.contains("\"forge-blobs\""), "{err}");
    assert!(err.contains("another account"), "{err}");
}

/// `BucketAlreadyOwnedByYou` (a concurrent start created it) is success.
#[tokio::test]
async fn a_bucket_already_owned_by_these_credentials_is_success() {
    let (_fake, store) = start(Create::OwnedByYou, "eu-central-1").await;
    store.ensure_bucket().await.expect("ours");
}
