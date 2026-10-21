//! Shared Postgres test harness for `forge-core` integration tests.
//!
//! Mirrors the `forge-db` harness: one Postgres container per test binary,
//! intentionally leaked so its async `Drop` never runs on a torn-down per-test
//! runtime, with a fresh migrated pool per test. Tests isolate themselves via
//! [`unique`] suffixes so they can run in parallel against the shared schema.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use forge_storage::{BlobStore, Cas, S3Config, S3Credentials};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::Mutex;

static ENDPOINT: OnceLock<String> = OnceLock::new();
static S3_ENDPOINT: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());
static MIGRATED: OnceLock<()> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(0);

const S3_ACCESS: &str = "test";
const S3_SECRET: &str = "test";
const S3_BUCKET: &str = "forge-test";
const S3_PORT: u16 = 7070;

async fn endpoint() -> &'static str {
    if let Some(e) = ENDPOINT.get() {
        return e;
    }
    let _guard = INIT_LOCK.lock().await;
    if let Some(e) = ENDPOINT.get() {
        return e;
    }

    let container = Postgres::default()
        .with_db_name("forge")
        .with_user("forge")
        .with_password("forge")
        .with_name("mirror.gcr.io/library/postgres")
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
    ENDPOINT.set(e).ok();
    ENDPOINT.get().unwrap()
}

/// The test database URL: the shared container, or `FORGE_TEST_DATABASE_URL`.
async fn database_url() -> String {
    match std::env::var("FORGE_TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            let endpoint = endpoint().await;
            format!("postgres://forge:forge@{endpoint}/forge")
        }
    }
}

/// A migrated pool capped at `max_connections`, whose `acquire` gives up after
/// `acquire_timeout` — for tests asserting that work does not hold pooled
/// connections (an exhausted pool then fails fast instead of hanging).
pub async fn small_pool(max_connections: u32, acquire_timeout: Duration) -> PgPool {
    // Make sure the schema exists before handing out the constrained pool.
    pool().await.close().await;
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(acquire_timeout)
        .connect(&database_url().await)
        .await
        .expect("connect")
}

/// A pool on the same database whose clock runs one hour **ahead** of this
/// process's: unqualified `now()` in its queries resolves to
/// `forge_skew.now()` (search_path puts that schema before `pg_catalog`), the
/// way a database host with a skewed clock would answer. Column defaults keep
/// the real clock.
#[allow(dead_code)]
pub async fn pool_with_clock_ahead() -> PgPool {
    let pool = pool().await;
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS forge_skew; \
         CREATE OR REPLACE FUNCTION forge_skew.now() RETURNS timestamptz \
         LANGUAGE sql STABLE AS $$ SELECT pg_catalog.now() + interval '1 hour' $$;",
    )
    .execute(&pool)
    .await
    .expect("create the skewed clock");
    pool.close().await;
    let options: sqlx::postgres::PgConnectOptions =
        database_url().await.parse().expect("database url");
    PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options.options([("search_path", "forge_skew,public,pg_catalog")]))
        .await
        .expect("connect")
}

/// A fresh, migrated pool for the calling test, backed by the shared container
/// — or by an external Postgres when `FORGE_TEST_DATABASE_URL` is set (for
/// environments without Docker).
pub async fn pool() -> PgPool {
    let url = database_url().await;
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

/// A process-unique suffix for building collision-free names within a test run.
pub fn unique() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
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
    // Docker-less environments point at an already-running gateway (e.g. a
    // local `versitygw --access test --secret test posix <dir>`).
    if let Ok(endpoint) = std::env::var("FORGE_TEST_S3_ENDPOINT") {
        S3_ENDPOINT.set(endpoint).ok();
        return S3_ENDPOINT.get().unwrap();
    }

    // versitygw posix backend (see storage harness): root must already exist,
    // so we point it at `/tmp` and use a named bucket subdir we create below.
    let container = GenericImage::new("mirror.gcr.io/versity/versitygw", "v1.4.1")
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
/// container. Tests dedup by content, so a single shared bucket is safe.
pub async fn blob_store() -> BlobStore {
    let endpoint = s3_endpoint().await.to_string();
    let store = BlobStore::new(S3Config {
        endpoint,
        region: "us-east-1".to_string(),
        bucket: S3_BUCKET.to_string(),
        credentials: S3Credentials::from_keys(S3_ACCESS, S3_SECRET),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: Default::default(),
    });

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

/// A content-addressed store over the shared pool + versitygw bucket.
pub async fn cas(pool: &PgPool) -> Cas {
    Cas::new(blob_store().await, pool.clone())
}
