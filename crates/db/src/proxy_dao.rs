//! Data access for `proxy_cached_version` and `proxy_upstream_index`.

use serde_json::Value as JsonValue;
use sqlx::{PgPool, Postgres, Transaction};

use crate::model::{ProxyCachedVersion, ProxyUpstreamIndex};

/// All settable fields when creating a proxy cached-version row.
#[derive(Debug, Clone)]
pub struct NewProxyCachedVersion {
    pub repository_id: i64,
    pub name: String,
    pub version: String,
    pub listed: bool,
    pub downloaded: bool,
    pub not_found: bool,
}

/// Insert a cached-version marker, ignoring conflicts on the
/// `(repository_id, name, version)` unique key. Returns `true` if a new row was
/// inserted, `false` if it already existed.
pub async fn upsert_cached_version(
    pool: &PgPool,
    new: NewProxyCachedVersion,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        INSERT INTO proxy_cached_version (
            repository_id, name, version, listed, downloaded, not_found
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (repository_id, name, version) DO NOTHING
        "#,
        new.repository_id,
        new.name,
        new.version,
        new.listed,
        new.downloaded,
        new.not_found,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Fetch a cached-version row by its unique key.
pub async fn get_cached_version(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<Option<ProxyCachedVersion>> {
    sqlx::query_as!(
        ProxyCachedVersion,
        r#"
        SELECT
            id, repository_id, name, version, listed, first_seen_at,
            downloaded, metadata_refreshed_at, not_found, not_found_at
        FROM proxy_cached_version
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_optional(pool)
    .await
}

/// Singleflight helper: lock a cached-version row `FOR UPDATE` inside the
/// caller's transaction so only one worker proceeds to fetch/download the
/// artifact while others block on the row lock. Returns the locked row, or
/// `None` if it does not exist yet (caller should `upsert_cached_version` first,
/// then call this).
pub async fn lock_cached_version_for_update(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<Option<ProxyCachedVersion>> {
    sqlx::query_as!(
        ProxyCachedVersion,
        r#"
        SELECT
            id, repository_id, name, version, listed, first_seen_at,
            downloaded, metadata_refreshed_at, not_found, not_found_at
        FROM proxy_cached_version
        WHERE repository_id = $1 AND name = $2 AND version = $3
        FOR UPDATE
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_optional(&mut **tx)
    .await
}

/// Fetch the upstream service index for a proxy repository.
pub async fn get_upstream_index(
    pool: &PgPool,
    repository_id: i64,
) -> sqlx::Result<Option<ProxyUpstreamIndex>> {
    sqlx::query_as!(
        ProxyUpstreamIndex,
        r#"
        SELECT repository_id, resources, fetched_at, etag
        FROM proxy_upstream_index
        WHERE repository_id = $1
        "#,
        repository_id,
    )
    .fetch_optional(pool)
    .await
}

/// Insert or replace the upstream service index for a proxy repository.
/// `fetched_at` is set to `now()`.
pub async fn set_upstream_index(
    pool: &PgPool,
    repository_id: i64,
    resources: JsonValue,
    etag: Option<&str>,
) -> sqlx::Result<ProxyUpstreamIndex> {
    sqlx::query_as!(
        ProxyUpstreamIndex,
        r#"
        INSERT INTO proxy_upstream_index (repository_id, resources, fetched_at, etag)
        VALUES ($1, $2, now(), $3)
        ON CONFLICT (repository_id)
        DO UPDATE SET resources = EXCLUDED.resources,
                      fetched_at = EXCLUDED.fetched_at,
                      etag = EXCLUDED.etag
        RETURNING repository_id, resources, fetched_at, etag
        "#,
        repository_id,
        resources,
        etag,
    )
    .fetch_one(pool)
    .await
}
