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

/// Run all pending migrations against the given pool, then repair what a
/// migration cannot do in SQL: usernames are brought into the canonical form
/// the server looks them up by
/// ([`crate::user_dao::canonicalize_stored_usernames`]).
///
/// Migrations live in the workspace-level `migrations/` directory and are
/// embedded at compile time via `sqlx::migrate!`.
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    let repairs = crate::user_dao::canonicalize_stored_usernames(pool)
        .await
        .map_err(MigrateError::Execute)?;
    for r in repairs {
        tracing::warn!(
            id = r.id,
            from = %r.from,
            to = %r.to,
            "username was not in canonical form (migration 0021 lowercases by the database collation); renamed"
        );
    }
    Ok(())
}
