//! Best-effort download-tracking writes.
//!
//! These feed the download-sensitive retention criteria
//! (`keep_n_most_downloaded`, `not_downloaded_for_days`,
//! `not_pulled_for_days`). They are **non-authoritative**: a lost increment
//! only makes a package look slightly colder than it is, exactly like
//! `token.last_used_at`. Callers count downloads in memory and write them in
//! batches off the response hot path (`forge_core::repo::downloads`), and log
//! — never propagate — failures.
//!
//! There are two shapes, each written for a batch of counted downloads in a
//! few statements (one row lock per row and batch, not per download):
//!
//! * [`bump_hosted_downloads`] — hosted/group `.nupkg` GETs: bump each served
//!   `asset`'s `download_count` + `last_downloaded_at` and denormalize the
//!   component's `last_downloaded_at` (the `max` over its assets; since `now()`
//!   is monotonic per call this is simply "set to now").
//! * [`bump_proxy_downloads_by_name`] (and [`bump_proxy_download`] for one
//!   cached row by id) — proxy cache hits: stamp the
//!   `proxy_cached_version.last_downloaded_at`, and, when a parallel cached
//!   `component`/`asset` exists, bump those too so a proxy repo can also use the
//!   hosted-style download criteria.
//!
//! All timestamps come from Postgres `now()` (single clock).

use sqlx::PgExecutor;

/// Bump download tracking for hosted `.nupkg` downloads: `counts[i]`
/// downloads of the asset `asset_ids[i]`, which belongs to the component
/// `component_ids[i]`.
///
/// Adds the counts to `asset.download_count`, stamps
/// `asset.last_downloaded_at = now()`, and sets
/// `component.last_downloaded_at = now()` (the denormalized max — a new
/// download is always the most recent). Two statements on the same executor; a
/// caller that wants atomicity passes a transaction, but best-effort callers
/// pass the pool directly.
pub async fn bump_hosted_downloads<'e, E>(
    executor: E,
    asset_ids: &[i64],
    component_ids: &[i64],
    counts: &[i64],
) -> sqlx::Result<()>
where
    E: PgExecutor<'e> + Copy,
{
    sqlx::query!(
        r#"
        UPDATE asset a
        SET download_count = a.download_count + d.n,
            last_downloaded_at = now()
        FROM UNNEST($1::bigint[], $2::bigint[]) AS d(id, n)
        WHERE a.id = d.id
        "#,
        asset_ids,
        counts,
    )
    .execute(executor)
    .await?;

    sqlx::query!(
        r#"UPDATE component SET last_downloaded_at = now() WHERE id = ANY($1)"#,
        component_ids,
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

/// Like [`bump_proxy_download`], for a batch of proxy downloads keyed by
/// `(repository_ids[i], names[i], versions[i])` instead of the cached-version
/// id, `counts[i]` downloads each.
///
/// The proxy read path resolves a download by name/version (it does not always
/// have the `proxy_cached_version.id` in hand), so this variant stamps the
/// cached rows and mirrors onto the parallel components/assets. A
/// `(repo, name, version)` is unique, so at most one cached row matches each.
pub async fn bump_proxy_downloads_by_name<'e, E>(
    executor: E,
    repository_ids: &[i64],
    names: &[String],
    versions: &[String],
    counts: &[i64],
) -> sqlx::Result<()>
where
    E: PgExecutor<'e> + Copy,
{
    sqlx::query!(
        r#"
        UPDATE proxy_cached_version p
        SET last_downloaded_at = now()
        FROM UNNEST($1::bigint[], $2::text[], $3::text[]) AS d(repository_id, name, version)
        WHERE p.repository_id = d.repository_id
          AND p.name = d.name
          AND p.version = d.version
        "#,
        repository_ids,
        names,
        versions,
    )
    .execute(executor)
    .await?;

    sqlx::query!(
        r#"
        UPDATE asset a
        SET download_count = a.download_count + d.n,
            last_downloaded_at = now()
        FROM component c,
             UNNEST($1::bigint[], $2::text[], $3::text[], $4::bigint[])
                 AS d(repository_id, name, version, n)
        WHERE c.repository_id = d.repository_id
          AND c.name = d.name
          AND c.version = d.version
          AND a.component_id = c.id
          AND a.path LIKE '%.nupkg'
        "#,
        repository_ids,
        names,
        versions,
        counts,
    )
    .execute(executor)
    .await?;

    sqlx::query!(
        r#"
        UPDATE component c
        SET last_downloaded_at = now()
        FROM UNNEST($1::bigint[], $2::text[], $3::text[]) AS d(repository_id, name, version)
        WHERE c.repository_id = d.repository_id
          AND c.name = d.name
          AND c.version = d.version
        "#,
        repository_ids,
        names,
        versions,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Total `.nupkg` downloads per package id (lowercased `component.name`) in a
/// repository, for the ids in `names`. Ids without downloads are omitted.
pub async fn total_downloads_by_name(
    pool: &sqlx::PgPool,
    repository_id: i64,
    names: &[String],
) -> sqlx::Result<Vec<(String, i64)>> {
    let rows = sqlx::query!(
        r#"
        SELECT c.name AS "name!", COALESCE(SUM(a.download_count), 0)::bigint AS "total!"
        FROM component c
        JOIN asset a ON a.component_id = c.id AND a.path = 'package.nupkg'
        WHERE c.repository_id = $1 AND c.name = ANY($2)
        GROUP BY c.name
        "#,
        repository_id,
        names,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| (r.name, r.total)).collect())
}
