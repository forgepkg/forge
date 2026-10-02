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

/// Record every upstream-listed `versions` of `name` in one round-trip.
///
/// A first sighting inserts a confirmed row stamped `first_seen_at = now()`.
/// The upstream listing is authoritative that each version exists, so an
/// existing row that is still **unconfirmed** (created by a download attempt
/// for a version the upstream did not have yet) or carries a **not-found
/// marker** is revived: the marker is cleared and the row confirmed — an
/// unconfirmed row also restarts `first_seen_at`, because this is the version's
/// first real sighting (a row planted early by a request must not shorten the
/// package-delay window). Already-confirmed rows keep their `first_seen_at` and
/// are not rewritten. Duplicates in `versions` are ignored. Returns the number
/// of rows inserted or revived.
pub async fn upsert_cached_versions(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    versions: &[String],
) -> sqlx::Result<u64> {
    if versions.is_empty() {
        return Ok(0);
    }
    let res = sqlx::query!(
        r#"
        INSERT INTO proxy_cached_version (
            repository_id, name, version, listed, downloaded, not_found, metadata_refreshed_at,
            confirmed
        )
        SELECT $1, $2, v, true, false, false, now(), true
        FROM (SELECT DISTINCT v FROM unnest($3::text[]) AS t(v)) AS d
        ON CONFLICT (repository_id, name, version) DO UPDATE
        SET not_found = false,
            not_found_at = NULL,
            first_seen_at = CASE
                WHEN proxy_cached_version.confirmed THEN proxy_cached_version.first_seen_at
                ELSE now()
            END,
            confirmed = true,
            metadata_refreshed_at = now()
        WHERE proxy_cached_version.not_found OR NOT proxy_cached_version.confirmed
        "#,
        repository_id,
        name,
        versions,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Guarantee a row exists for a version a client asked to download, so the
/// download singleflight can lock it. A new row is **unconfirmed**: it is never
/// enumerated until an upstream listing or a successful download confirms the
/// version (see [`upsert_cached_versions`], [`mark_downloaded`]), so a request
/// for a version that does not exist — or whose fetch fails — cannot create a
/// phantom version. An existing row is left untouched.
pub async fn insert_unconfirmed_cached_version(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO proxy_cached_version (
            repository_id, name, version, listed, downloaded, not_found, confirmed
        )
        VALUES ($1, $2, $3, true, false, false, false)
        ON CONFLICT (repository_id, name, version) DO NOTHING
        "#,
        repository_id,
        name,
        version,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Finalize a successful download of the row `id` inside the caller's
/// transaction: mark it downloaded, clear any not-found marker and confirm it.
/// A row confirmed only now (it was created by the download singleflight)
/// restarts `first_seen_at`, exactly like a first listing sighting. Returns the
/// row's resulting `first_seen_at` for the package-delay gate.
pub async fn mark_downloaded(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> sqlx::Result<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar!(
        r#"
        UPDATE proxy_cached_version
        SET downloaded = true,
            not_found = false,
            not_found_at = NULL,
            first_seen_at = CASE WHEN confirmed THEN first_seen_at ELSE now() END,
            confirmed = true
        WHERE id = $1
        RETURNING first_seen_at
        "#,
        id,
    )
    .fetch_one(&mut **tx)
    .await
}

/// Clear `downloaded` on the row `id` because its local copy is gone (e.g.
/// retention deleted the component), so the next fetch re-attaches fresh
/// assets. `first_seen_at` and the confirmation are kept: the version stays
/// listed and its package-delay window does not restart.
pub async fn mark_not_downloaded(pool: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"UPDATE proxy_cached_version SET downloaded = false WHERE id = $1 AND downloaded"#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Store the upstream listing state (`listed`, from the upstream registration)
/// of `name`'s `versions` in one round-trip and stamp
/// `metadata_refreshed_at`. `versions` and `listed` are parallel slices.
pub async fn set_listed(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    versions: &[String],
    listed: &[bool],
) -> sqlx::Result<u64> {
    if versions.is_empty() {
        return Ok(0);
    }
    let res = sqlx::query!(
        r#"
        UPDATE proxy_cached_version AS p
        SET listed = c.listed, metadata_refreshed_at = now()
        FROM unnest($3::text[], $4::bool[]) AS c(version, listed)
        WHERE p.repository_id = $1 AND p.name = $2 AND p.version = c.version
          AND p.listed IS DISTINCT FROM c.listed
        "#,
        repository_id,
        name,
        versions,
        listed,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
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
