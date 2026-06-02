//! Best-effort download-tracking writes (slice 12.1, design §3.7).
//!
//! These feed the download-sensitive retention criteria
//! (`keep_n_most_downloaded`, `not_downloaded_for_days`,
//! `not_pulled_for_days`). They are **non-authoritative**: a lost increment
//! only makes a package look slightly colder than it is, exactly like
//! `token.last_used_at`. Callers fire them off the response hot path (a spawned
//! task) and log — never propagate — failures.
//!
//! There are two shapes:
//!
//! * [`bump_hosted_download`] — a hosted/group `.nupkg` GET: bump the served
//!   `asset`'s `download_count` + `last_downloaded_at` and denormalize the
//!   component's `last_downloaded_at` (the `max` over its assets; since `now()`
//!   is monotonic per call this is simply "set to now").
//! * [`bump_proxy_download`] — a proxy cache hit: stamp the
//!   `proxy_cached_version.last_downloaded_at`, and, when a parallel cached
//!   `component`/`asset` exists, bump those too so a proxy repo can also use the
//!   hosted-style download criteria.
//!
//! All timestamps come from Postgres `now()` (single clock, §6 "time source").

use sqlx::PgExecutor;

/// Bump download tracking for a hosted `.nupkg` download identified by its
/// `asset.id` and owning `component.id`.
///
/// Increments `asset.download_count`, stamps `asset.last_downloaded_at = now()`,
/// and sets `component.last_downloaded_at = now()` (the denormalized max — a new
/// download is always the most recent). Two statements on the same executor; a
/// caller that wants atomicity passes a transaction, but best-effort callers
/// pass the pool directly.
pub async fn bump_hosted_download<'e, E>(
    executor: E,
    asset_id: i64,
    component_id: i64,
) -> sqlx::Result<()>
where
    E: PgExecutor<'e> + Copy,
{
    sqlx::query!(
        r#"
        UPDATE asset
        SET download_count = download_count + 1,
            last_downloaded_at = now()
        WHERE id = $1
        "#,
        asset_id,
    )
    .execute(executor)
    .await?;

    sqlx::query!(
        r#"UPDATE component SET last_downloaded_at = now() WHERE id = $1"#,
        component_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Bump download tracking for a proxy cache hit identified by the
/// `proxy_cached_version.id`.
///
/// Stamps `proxy_cached_version.last_downloaded_at = now()`. If a parallel
/// cached `component` (same repository/name/version) exists, its served
/// `.nupkg` asset + the component get the hosted-style bump too, so proxy repos
/// can drive `keep_n_most_downloaded` / `not_downloaded_for_days` as well as the
/// proxy-only `not_pulled_for_days`.
pub async fn bump_proxy_download<'e, E>(executor: E, cached_version_id: i64) -> sqlx::Result<()>
where
    E: PgExecutor<'e> + Copy,
{
    sqlx::query!(
        r#"
        UPDATE proxy_cached_version
        SET last_downloaded_at = now()
        WHERE id = $1
        "#,
        cached_version_id,
    )
    .execute(executor)
    .await?;

    // Mirror the hosted bump onto the parallel component/asset, if cached.
    sqlx::query!(
        r#"
        UPDATE asset a
        SET download_count = a.download_count + 1,
            last_downloaded_at = now()
        FROM proxy_cached_version pcv
        JOIN component c
          ON c.repository_id = pcv.repository_id
         AND c.name = pcv.name
         AND c.version = pcv.version
        WHERE pcv.id = $1
          AND a.component_id = c.id
          AND a.path LIKE '%.nupkg'
        "#,
        cached_version_id,
    )
    .execute(executor)
    .await?;

    sqlx::query!(
        r#"
        UPDATE component c
        SET last_downloaded_at = now()
        FROM proxy_cached_version pcv
        WHERE pcv.id = $1
          AND c.repository_id = pcv.repository_id
          AND c.name = pcv.name
          AND c.version = pcv.version
        "#,
        cached_version_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Like [`bump_proxy_download`] but keyed by `(repository_id, name, version)`
/// instead of the cached-version id.
///
/// The proxy read path resolves a download by name/version (it does not always
/// have the `proxy_cached_version.id` in hand), so this variant stamps the
/// cached row and mirrors onto the parallel component/asset in one call. A
/// `(repo, name, version)` is unique, so at most one cached row matches.
pub async fn bump_proxy_download_by_name<'e, E>(
    executor: E,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<()>
where
    E: PgExecutor<'e> + Copy,
{
    sqlx::query!(
        r#"
        UPDATE proxy_cached_version
        SET last_downloaded_at = now()
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
    )
    .execute(executor)
    .await?;

    sqlx::query!(
        r#"
        UPDATE asset a
        SET download_count = a.download_count + 1,
            last_downloaded_at = now()
        FROM component c
        WHERE c.repository_id = $1
          AND c.name = $2
          AND c.version = $3
          AND a.component_id = c.id
          AND a.path LIKE '%.nupkg'
        "#,
        repository_id,
        name,
        version,
    )
    .execute(executor)
    .await?;

    sqlx::query!(
        r#"
        UPDATE component
        SET last_downloaded_at = now()
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
    )
    .execute(executor)
    .await?;
    Ok(())
}
