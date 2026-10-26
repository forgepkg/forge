//! Package tags (migration 0047): names for versions of a package, such as
//! npm's dist-tags (`latest`, `next`). A hosted repository's are set by its
//! clients (a format plugin's tag changes); a proxy's are its upstream's
//! as last read ([`replace_tags`]).

use std::collections::BTreeMap;

use sqlx::{PgExecutor, Postgres, Transaction};

/// The tags of `package` in repository `repository_id`, tag → version.
pub async fn tags<'e, E>(
    executor: E,
    repository_id: i64,
    package: &str,
) -> sqlx::Result<BTreeMap<String, String>>
where
    E: PgExecutor<'e>,
{
    let rows = sqlx::query!(
        r#"
        SELECT tag, version FROM package_tag
        WHERE repository_id = $1 AND package = $2
        "#,
        repository_id,
        package,
    )
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().map(|r| (r.tag, r.version)).collect())
}

/// Point `tag` of `package` at `version`.
pub async fn set_tag<'e, E>(
    executor: E,
    repository_id: i64,
    package: &str,
    tag: &str,
    version: &str,
) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        INSERT INTO package_tag (repository_id, package, tag, version)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (repository_id, package, tag)
        DO UPDATE SET version = EXCLUDED.version, updated_at = now()
        "#,
        repository_id,
        package,
        tag,
        version,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Remove `tag` of `package`. Returns whether it existed.
pub async fn delete_tag<'e, E>(
    executor: E,
    repository_id: i64,
    package: &str,
    tag: &str,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"DELETE FROM package_tag WHERE repository_id = $1 AND package = $2 AND tag = $3"#,
        repository_id,
        package,
        tag,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Remove every tag of `package`, or only those naming `version`.
pub async fn delete_tags<'e, E>(
    executor: E,
    repository_id: i64,
    package: &str,
    version: Option<&str>,
) -> sqlx::Result<u64>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        DELETE FROM package_tag
        WHERE repository_id = $1 AND package = $2 AND ($3::text IS NULL OR version = $3)
        "#,
        repository_id,
        package,
        version,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected())
}

/// Every `(package, version)` a tag of repository `repository_id`
/// names: what retention never deletes.
pub async fn tagged_versions<'e, E>(
    executor: E,
    repository_id: i64,
) -> sqlx::Result<Vec<(String, String)>>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        r#"SELECT DISTINCT package, version FROM package_tag WHERE repository_id = $1"#,
        repository_id,
    )
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().map(|r| (r.package, r.version)).collect())
}

/// Whether a tag of `package` names `version`.
pub async fn is_tagged<'e, E>(
    executor: E,
    repository_id: i64,
    package: &str,
    version: &str,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM package_tag
            WHERE repository_id = $1 AND package = $2 AND version = $3
        ) AS "tagged!"
        "#,
        repository_id,
        package,
        version,
    )
    .fetch_one(executor)
    .await
}

/// Make `tags` the tags of `package` (a proxy's, as its upstream gave them):
/// the others are removed. Returns whether anything changed.
pub async fn replace_tags(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    package: &str,
    tags: &BTreeMap<String, String>,
) -> sqlx::Result<bool> {
    let current = self::tags(&mut **tx, repository_id, package).await?;
    if &current == tags {
        return Ok(false);
    }
    delete_tags(&mut **tx, repository_id, package, None).await?;
    for (tag, version) in tags {
        set_tag(&mut **tx, repository_id, package, tag, version).await?;
    }
    Ok(true)
}

/// Remove every tag of repository `repository_id` (a repointed proxy's).
pub async fn delete_repository_tags<'e, E>(executor: E, repository_id: i64) -> sqlx::Result<u64>
where
    E: PgExecutor<'e>,
{
    Ok(sqlx::query!(
        r#"DELETE FROM package_tag WHERE repository_id = $1"#,
        repository_id
    )
    .execute(executor)
    .await?
    .rows_affected())
}
