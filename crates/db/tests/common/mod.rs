//! Shared test harness.
//!
//! Each `#[tokio::test]` runs on its own Tokio runtime, so a connection pool
//! created on one test's runtime cannot be shared with another (its background
//! tasks die when that runtime shuts down). We therefore:
//!   * share **one** Postgres container across the whole test binary (started
//!     once, behind a blocking mutex, and intentionally leaked so its async
//!     `Drop` never runs on a torn-down runtime), and
//!   * build a **fresh pool per test** against that container.
//!
//! Tests isolate themselves with unique names (see [`unique`]) so they can run
//! in parallel against the shared schema.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt},
};
use tokio::sync::Mutex;

// `host:port` of the shared container, computed once.
static ENDPOINT: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());
static MIGRATED: OnceLock<()> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(0);

async fn endpoint() -> &'static str {
    if let Some(e) = ENDPOINT.get() {
        return e;
    }
    // Serialize first-time startup across concurrent tests.
    let _guard = INIT_LOCK.lock().await;
    if let Some(e) = ENDPOINT.get() {
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

    // Leak the container so its async Drop never runs (it would otherwise try
    // to use whichever test runtime is shutting down). The OS / testcontainers
    // reaper cleans it up when the process exits.
    let _: &'static ContainerAsync<Postgres> = Box::leak(Box::new(container));

    let e = format!("{host}:{port}");
    ENDPOINT.set(e).ok();
    ENDPOINT.get().unwrap()
}

/// A fresh, migrated pool for the calling test, backed by the shared container.
pub async fn pool() -> PgPool {
    let endpoint = endpoint().await;
    let url = format!("postgres://forge:forge@{endpoint}/forge");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect");

    // Run migrations exactly once for the whole binary.
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
