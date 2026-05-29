use sqlx::migrate::MigrateError;
use sqlx::postgres::PgPool;

/// Connect to Postgres and build a connection pool.
pub async fn connect(url: &str) -> sqlx::Result<PgPool> {
    PgPool::connect(url).await
}

/// Run all pending migrations against the given pool.
///
/// Migrations live in the workspace-level `migrations/` directory and are
/// embedded at compile time via `sqlx::migrate!`.
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}
