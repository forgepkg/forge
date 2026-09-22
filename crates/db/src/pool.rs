use sqlx::migrate::MigrateError;
use sqlx::postgres::PgPool;

/// Connect to Postgres and build a connection pool (sqlx defaults).
pub async fn connect(url: &str) -> sqlx::Result<PgPool> {
    PgPool::connect(url).await
}

/// Connect with an explicit pool size and acquire deadline: a request that
/// cannot get a connection within `acquire_timeout` fails instead of queueing
/// indefinitely behind a saturated pool.
pub async fn connect_with(
    url: &str,
    max_connections: u32,
    acquire_timeout: std::time::Duration,
) -> sqlx::Result<PgPool> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(acquire_timeout)
        .connect(url)
        .await
}

/// Run all pending migrations against the given pool.
///
/// Migrations live in the workspace-level `migrations/` directory and are
/// embedded at compile time via `sqlx::migrate!`.
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}
