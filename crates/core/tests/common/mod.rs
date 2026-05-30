//! Shared Postgres test harness for `forge-core` integration tests.
//!
//! Mirrors the `forge-db` harness: one Postgres container per test binary,
//! intentionally leaked so its async `Drop` never runs on a torn-down per-test
//! runtime, with a fresh migrated pool per test. Tests isolate themselves via
//! [`unique`] suffixes so they can run in parallel against the shared schema.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt},
};
use tokio::sync::Mutex;

static ENDPOINT: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());
static MIGRATED: OnceLock<()> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(0);

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

/// A fresh, migrated pool for the calling test, backed by the shared container.
pub async fn pool() -> PgPool {
    let endpoint = endpoint().await;
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

/// A process-unique suffix for building collision-free names within a test run.
pub fn unique() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
