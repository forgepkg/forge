//! Integration test: spin up a real Postgres in a container, run the migrations,
//! and assert every expected table exists.
//!
//! Requires Docker to be available on the host running the test.

use sqlx::Row;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{runners::AsyncRunner, ImageExt},
};

/// Every table the `0001_init.sql` migration is expected to create.
const EXPECTED_TABLES: &[&str] = &[
    "repository",
    "group_member",
    "blob",
    "blob_outbox",
    "component",
    "asset",
    "proxy_cached_version",
    "proxy_upstream_index",
    "app_user",
    "token",
];

#[tokio::test]
async fn migrations_create_all_expected_tables() {
    // Start a throwaway Postgres 17 container matching docker-compose (db/user/pw = forge).
    let container = Postgres::default()
        .with_db_name("forge")
        .with_user("forge")
        .with_password("forge")
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres testcontainer (is Docker running?)");

    let host = container
        .get_host()
        .await
        .expect("failed to get container host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get mapped port");

    let url = format!("postgres://forge:forge@{host}:{port}/forge");

    let pool = forge_db::connect(&url).await.expect("failed to connect");
    forge_db::migrate(&pool).await.expect("migrations failed");

    // Assert every expected table is present in the public schema.
    let rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
    )
    .fetch_all(&pool)
    .await
    .expect("failed to query information_schema.tables");

    let actual: Vec<String> = rows
        .iter()
        .map(|r| r.get::<String, _>("table_name"))
        .collect();

    for expected in EXPECTED_TABLES {
        assert!(
            actual.iter().any(|t| t == expected),
            "expected table `{expected}` to exist after migration; found tables: {actual:?}"
        );
    }
}
