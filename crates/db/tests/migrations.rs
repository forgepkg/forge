//! Integration test: spin up a real Postgres in a container, run the migrations,
//! and assert every expected table exists.
//!
//! Requires Docker to be available on the host running the test.

use sqlx::Row;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{runners::AsyncRunner, ImageExt},
};

/// Every table the migrations are expected to create.
/// `0001_init.sql` creates the slice-1 tables; `0002_retention.sql` adds the
/// two retention coordination tables.
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
    // 0002_retention.sql
    "retention_run",
    "retention_audit",
];

/// Columns `0002_retention.sql` adds to existing slice-1 tables: (table, column).
const EXPECTED_RETENTION_COLUMNS: &[(&str, &str)] = &[
    ("repository", "retention_policy"),
    ("repository", "retention_last_run_at"),
    ("asset", "last_downloaded_at"),
    ("asset", "download_count"),
    ("component", "last_downloaded_at"),
    ("proxy_cached_version", "last_downloaded_at"),
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

    // Assert the retention columns added to slice-1 tables exist.
    for (table, column) in EXPECTED_RETENTION_COLUMNS {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2\
             )",
        )
        .bind(table)
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("failed to query information_schema.columns");

        assert!(
            exists,
            "expected column `{table}.{column}` to exist after the retention migration"
        );
    }

    // `repository.retention_policy` is jsonb and accepts a well-formed policy
    // document (sanity check that the column type is usable from SQL).
    sqlx::query(
        "INSERT INTO repository (name, kind, retention_policy) \
         VALUES ($1, 'hosted', $2::jsonb)",
    )
    .bind("retention-jsonb-test")
    .bind(
        r#"{"version":1,"enabled":true,"dry_run_only":false,
            "min_run_interval_seconds":3600,
            "rules":[{"id":"r1","action":"hard_delete","release_type":"any",
                      "criteria":{"keep_last_n":10,"older_than_days":90}}]}"#,
    )
    .execute(&pool)
    .await
    .expect("retention_policy column should accept a jsonb policy document");

    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT retention_policy FROM repository WHERE name = $1")
            .bind("retention-jsonb-test")
            .fetch_one(&pool)
            .await
            .expect("failed to read back stored retention_policy");

    assert_eq!(
        stored["version"], 1,
        "round-tripped retention_policy jsonb should preserve its shape"
    );

    // retention_run upsert + lazy creation works (PK = repository_id).
    let repo_id: i64 = sqlx::query_scalar("SELECT id FROM repository WHERE name = $1")
        .bind("retention-jsonb-test")
        .fetch_one(&pool)
        .await
        .expect("failed to read repo id");

    sqlx::query("INSERT INTO retention_run (repository_id) VALUES ($1)")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("retention_run row should be insertable for a repository");

    // retention_audit row referencing the same repo is insertable.
    sqlx::query(
        "INSERT INTO retention_audit \
             (repository_id, run_id, rule_id, action, target_kind, package_name, version, reason) \
         VALUES ($1, gen_random_uuid(), 'r1', 'hard_delete', 'component', 'Sample.Lib', '1.0.0', '{}'::jsonb)",
    )
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("retention_audit row should be insertable");
}
