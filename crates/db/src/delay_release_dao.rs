//! Data access for `package_delay_release`: the versions of a proxy
//! repository an administrator released from the package delay early.
//!
//! A release names a package (lowercased, as the proxy stores it) and a
//! normalized version, whether the proxy has seen that version yet or not.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// A row of `package_delay_release`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DelayRelease {
    pub repository_id: i64,
    /// The package id, lowercased.
    pub name: String,
    /// The normalized version.
    pub version: String,
    /// Why the version was released early.
    pub reason: String,
    /// The administrator who released it (an audit label: `user:<name>`,
    /// `token:<id>`, …).
    pub released_by: String,
    pub released_at: DateTime<Utc>,
}

/// Release `(name, version)` of `repository_id` from the package delay.
/// Returns the release and whether this call created it: a version released
/// already keeps its first release (reason, administrator and time).
pub async fn release(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
    reason: &str,
    released_by: &str,
) -> sqlx::Result<(DelayRelease, bool)> {
    let inserted = sqlx::query_as!(
        DelayRelease,
        r#"
        INSERT INTO package_delay_release (repository_id, name, version, reason, released_by)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (repository_id, name, version) DO NOTHING
        RETURNING repository_id, name, version, reason, released_by, released_at
        "#,
        repository_id,
        name,
        version,
        reason,
        released_by,
    )
    .fetch_optional(pool)
    .await?;
    if let Some(row) = inserted {
        return Ok((row, true));
    }
    let existing = find(pool, repository_id, name, version)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    Ok((existing, false))
}

/// The release of `(name, version)`, if there is one.
pub async fn find(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<Option<DelayRelease>> {
    sqlx::query_as!(
        DelayRelease,
        r#"
        SELECT repository_id, name, version, reason, released_by, released_at
        FROM package_delay_release
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_optional(pool)
    .await
}

/// The released versions of package `name`, with when each was released.
pub async fn released_versions(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
) -> sqlx::Result<Vec<(String, DateTime<Utc>)>> {
    let rows = sqlx::query!(
        r#"
        SELECT version, released_at
        FROM package_delay_release
        WHERE repository_id = $1 AND name = $2
        "#,
        repository_id,
        name,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.version, row.released_at))
        .collect())
}

/// The released `(name, version)`s of the packages `names`.
pub async fn released_of_packages(
    pool: &PgPool,
    repository_id: i64,
    names: &[String],
) -> sqlx::Result<Vec<(String, String)>> {
    let rows = sqlx::query!(
        r#"
        SELECT name, version
        FROM package_delay_release
        WHERE repository_id = $1 AND name = ANY($2::text[])
        "#,
        repository_id,
        names,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.name, row.version))
        .collect())
}

/// Every release of `repository_id`, newest first, each with whether the
/// proxy has seen its version upstream yet (a confirmed cached-version row).
pub async fn list_with_seen(
    pool: &PgPool,
    repository_id: i64,
) -> sqlx::Result<Vec<(DelayRelease, bool)>> {
    let rows = sqlx::query!(
        r#"
        SELECT r.repository_id, r.name, r.version, r.reason, r.released_by, r.released_at,
               EXISTS (
                   SELECT 1 FROM proxy_cached_version v
                   WHERE v.repository_id = r.repository_id AND v.name = r.name
                     AND v.version = r.version AND v.confirmed
               ) AS "seen!"
        FROM package_delay_release r
        WHERE r.repository_id = $1
        ORDER BY r.released_at DESC, r.name, r.version
        "#,
        repository_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                DelayRelease {
                    repository_id: row.repository_id,
                    name: row.name,
                    version: row.version,
                    reason: row.reason,
                    released_by: row.released_by,
                    released_at: row.released_at,
                },
                row.seen,
            )
        })
        .collect())
}

/// Whether the proxy has seen `(name, version)` upstream: a confirmed
/// cached-version row.
pub async fn seen(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<bool> {
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM proxy_cached_version
            WHERE repository_id = $1 AND name = $2 AND version = $3 AND confirmed
        ) AS "seen!"
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_one(pool)
    .await
}

/// Withdraw the release of `(name, version)`: the version waits out its
/// delay again. Returns whether there was one.
pub async fn withdraw(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        DELETE FROM package_delay_release
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// The repositories whose package-delay overrides name content selector
/// `name` (`"selector": "<name>"`), by name: deleting the selector is
/// refused while there are any, and editing it touches them.
pub async fn repositories_using_selector(
    pool: &PgPool,
    name: &str,
) -> sqlx::Result<Vec<(i64, String)>> {
    let rows = sqlx::query!(
        r#"
        SELECT r.id, r.name
        FROM repository r
        WHERE jsonb_path_exists(
                r.config,
                '$.package_delay_overrides[*] ? (@.selector == $name)',
                jsonb_build_object('name', $1::text)
              )
        ORDER BY r.name
        "#,
        name,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.name)).collect())
}
