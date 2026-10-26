use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::PgPool;
use sqlx::AssertSqlSafe;

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

/// The migrations, embedded at compile time from the workspace-level
/// `migrations/` directory.
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Run all pending migrations against the given pool.
///
/// A database created by Forge 1.x or by a build before 2.0.0 is refused
/// first, with a message that says so ([`refuse_earlier_build`]).
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    refuse_earlier_build(pool, &MIGRATOR).await?;
    MIGRATOR.run(pool).await
}

/// Refuse a database whose schema an earlier build created.
///
/// 2.0.0 starts the schema over: `0001_init.sql` is a baseline that replaced
/// the migrations of 1.x and of the builds before 2.0.0, and nothing upgrades
/// a database they created. Such a database records versions this build does
/// not have, or a version 1 with another checksum; sqlx would refuse it as
/// "migration 1 was previously applied but has been modified", which does not
/// say why.
///
/// A database that records migrations is therefore refused unless this
/// baseline is among them, unchanged. One this baseline created is left to
/// sqlx: a version this build does not have then comes from a newer build,
/// and sqlx names it.
async fn refuse_earlier_build(pool: &PgPool, migrator: &Migrator) -> Result<(), MigrateError> {
    let table = migrator.table_name.as_ref();
    let recorded: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(pool)
        .await?;
    if !recorded {
        return Ok(());
    }
    // The table name is sqlx's own (`_sqlx_migrations`), never input.
    let applied: Vec<(i64, Vec<u8>)> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT version, checksum FROM {table} ORDER BY version"
    )))
    .fetch_all(pool)
    .await?;
    let baseline = migrator.iter().find(|m| m.version == 1);
    let baseline_applied = applied.iter().any(|(version, checksum)| {
        *version == 1 && baseline.is_some_and(|m| *m.checksum == **checksum)
    });
    if applied.is_empty() || baseline_applied {
        return Ok(());
    }
    Err(MigrateError::Source(Box::new(EarlierBuildDatabase)))
}

/// The database was created by Forge 1.x or by a build before 2.0.0.
#[derive(Debug, thiserror::Error)]
#[error(
    "the database was created by Forge 1.x or by a build before 2.0.0, and \
     2.0.0 does not upgrade it: Forge 2.0.0 needs an empty database (point \
     database.url, FORGE_DATABASE__URL, at one)"
)]
struct EarlierBuildDatabase;

/// The database's clock (`now()`).
///
/// A timestamp the database compares with its own `now()` — a lease's or
/// backoff's end, a staleness cutoff — must be computed from this, not from
/// this process's clock: with the two minutes apart, failing outbox rows were
/// retried every poll, a retention run failed its own lease fence, and live
/// delete reservations looked stale.
pub async fn db_now<'e, E>(executor: E) -> sqlx::Result<chrono::DateTime<chrono::Utc>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar!(r#"SELECT now() AS "now!""#)
        .fetch_one(executor)
        .await
}
