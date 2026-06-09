//! Shared test harness for the storage integration tests.
//!
//! Mirrors the `forge-db` harness: one Postgres container and one versitygw
//! (S3) container are started once per test binary, intentionally leaked so
//! their async `Drop` never runs on a torn-down per-test runtime, and a fresh
//! pool / `BlobStore` is built per test. Tests isolate themselves via
//! content-addressed keys (unique bytes) so they can run in parallel.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use forge_storage::{BlobStore, S3Config};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::Mutex;

// --- Postgres ---------------------------------------------------------------

static PG_ENDPOINT: OnceLock<String> = OnceLock::new();
static S3_ENDPOINT: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());
static MIGRATED: OnceLock<()> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(0);

const S3_ACCESS: &str = "test";
const S3_SECRET: &str = "test";
const S3_BUCKET: &str = "forge-test";
const S3_PORT: u16 = 7070;

async fn pg_endpoint() -> &'static str {
    if let Some(e) = PG_ENDPOINT.get() {
        return e;
    }
    let _guard = INIT_LOCK.lock().await;
    if let Some(e) = PG_ENDPOINT.get() {
        return e;
    }

    let container = Postgres::default()
        .with_db_name("forge")
        .with_user("forge")
        .with_password("forge")
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres testcontainer (is Docker running?)");

    let host = container.get_host().await.expect("host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");

    let _: &'static ContainerAsync<Postgres> = Box::leak(Box::new(container));

    let e = format!("{host}:{port}");
    PG_ENDPOINT.set(e).ok();
    PG_ENDPOINT.get().unwrap()
}

/// A fresh, migrated pool for the calling test, backed by the shared container.
pub async fn pool() -> PgPool {
    let endpoint = pg_endpoint().await;
    let url = format!("postgres://forge:forge@{endpoint}/forge");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect");

    if MIGRATED.get().is_none() {
        let _guard = INIT_LOCK.lock().await;
        if MIGRATED.get().is_none() {
            forge_db::migrate(&pool).await.expect("migrate");
            MIGRATED.set(()).ok();
        }
    }
    pool
}

// --- versitygw (S3) ---------------------------------------------------------

async fn s3_endpoint() -> &'static str {
    if let Some(e) = S3_ENDPOINT.get() {
        return e;
    }
    let _guard = INIT_LOCK.lock().await;
    if let Some(e) = S3_ENDPOINT.get() {
        return e;
    }

    // versitygw posix backend: each subdir of the root dir is a bucket. The
    // root MUST already exist or versitygw refuses to start, so we use `/tmp`
    // (always present in the image) rather than `/data` (which the image does
    // not create). We wait for the "listening" banner on stdout, then retry
    // `ensure_bucket` below to absorb any residual startup lag.
    let container = GenericImage::new("versity/versitygw", "v1.4.1")
        .with_exposed_port(S3_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("listening on"))
        .with_cmd([
            "--port", ":7070", "--access", S3_ACCESS, "--secret", S3_SECRET, "posix", "/tmp",
        ])
        .start()
        .await
        .expect("failed to start versitygw testcontainer (is Docker running?)");

    let host = container.get_host().await.expect("host");
    let port = container
        .get_host_port_ipv4(S3_PORT)
        .await
        .expect("mapped port");

    let _: &'static ContainerAsync<GenericImage> = Box::leak(Box::new(container));

    let e = format!("http://{host}:{port}");
    S3_ENDPOINT.set(e).ok();
    S3_ENDPOINT.get().unwrap()
}

/// A `BlobStore` with its bucket ensured, backed by the shared versitygw
/// container. Each call uses the same bucket; tests dedup by content so the
/// shared bucket is safe.
pub async fn blob_store() -> BlobStore {
    let endpoint = s3_endpoint().await.to_string();
    let store = BlobStore::new(S3Config {
        endpoint,
        region: "us-east-1".to_string(),
        bucket: S3_BUCKET.to_string(),
        access_key: S3_ACCESS.to_string(),
        secret_key: S3_SECRET.to_string(),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: Default::default(),
    });

    // Retry ensure_bucket: versitygw may still be coming up right after the
    // fixed wait.
    let mut last_err = None;
    for _ in 0..30 {
        match store.ensure_bucket().await {
            Ok(()) => return store,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
    panic!("versitygw never became ready: {last_err:?}");
}

/// A `BlobStore` with a small multipart threshold, for exercising the multipart
/// upload path without needing huge bodies.
pub async fn blob_store_with_threshold(threshold: u64) -> BlobStore {
    let endpoint = s3_endpoint().await.to_string();
    let store = BlobStore::new(S3Config {
        endpoint,
        region: "us-east-1".to_string(),
        bucket: S3_BUCKET.to_string(),
        access_key: S3_ACCESS.to_string(),
        secret_key: S3_SECRET.to_string(),
        force_path_style: true,
        multipart_threshold: threshold,
        conditional_writes: Default::default(),
    });
    let _ = store.ensure_bucket().await;
    store
}

/// A process-unique suffix for building collision-free content within a test
/// run (so different tests produce different content hashes / S3 keys).
pub fn unique() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
