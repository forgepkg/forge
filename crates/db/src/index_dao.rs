//! The indexes a repository's format keeps (apt): what they are made of,
//! and which generation a repository serves (`repository_index`). The
//! index files themselves are `raw_file` rows of the repository.

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, Postgres, Transaction};

use crate::blob_dao;

/// A listed version of a repository, as an index lists it.
#[derive(Debug, Clone)]
pub struct IndexedVersion {
    pub name: String,
    pub version: String,
    pub version_original: String,
    pub manifest_summary: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub size: i64,
    pub sha256: String,
    pub sha512_base64: Option<String>,
}

/// Every listed version of `repository_id`, with its package (the asset at
/// `package_path`).
pub async fn listed_versions<'e, E>(
    executor: E,
    repository_id: i64,
    package_path: &str,
) -> sqlx::Result<Vec<IndexedVersion>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        IndexedVersion,
        r#"
        SELECT c.name, c.version, c.version_original, c.manifest_summary, c.created_at,
               a.size, a.blob_sha256 AS sha256, a.sha512_base64
        FROM component c
        JOIN asset a ON a.component_id = c.id AND a.path = $2
        WHERE c.repository_id = $1 AND c.listed
        ORDER BY c.name, c.id
        "#,
        repository_id,
        package_path,
    )
    .fetch_all(executor)
    .await
}

/// A digest of the listed versions of `repository_id` and their packages:
/// it changes whenever a version is published, deleted, unlisted, relisted
/// or replaced.
pub async fn versions_digest<'e, E>(
    executor: E,
    repository_id: i64,
    package_path: &str,
) -> sqlx::Result<String>
where
    E: PgExecutor<'e>,
{
    let digest = sqlx::query_scalar!(
        r#"
        SELECT md5(coalesce(string_agg(
                   c.id::text || ':' || c.version || ':' || a.blob_sha256 || ':'
                       || c.updated_at::text,
                   ',' ORDER BY c.id), '')) AS "digest!"
        FROM component c
        JOIN asset a ON a.component_id = c.id AND a.path = $2
        WHERE c.repository_id = $1 AND c.listed
        "#,
        repository_id,
        package_path,
    )
    .fetch_one(executor)
    .await?;
    Ok(digest)
}

/// The fingerprint of the generation `repository_id` serves, if any.
pub async fn current<'e, E>(executor: E, repository_id: i64) -> sqlx::Result<Option<String>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(
        "SELECT fingerprint FROM repository_index WHERE repository_id = $1",
        repository_id,
    )
    .fetch_optional(executor)
    .await
}

/// Lock the generation of `repository_id` (creating its row), returning
/// its fingerprint (`""` before the first).
pub async fn lock(tx: &mut Transaction<'_, Postgres>, repository_id: i64) -> sqlx::Result<String> {
    sqlx::query!(
        r#"
        INSERT INTO repository_index (repository_id, fingerprint)
        VALUES ($1, '')
        ON CONFLICT (repository_id) DO NOTHING
        "#,
        repository_id,
    )
    .execute(&mut **tx)
    .await?;
    sqlx::query_scalar!(
        "SELECT fingerprint FROM repository_index WHERE repository_id = $1 FOR UPDATE",
        repository_id,
    )
    .fetch_one(&mut **tx)
    .await
}

/// Record that `repository_id` serves the generation `fingerprint`.
pub async fn set(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    fingerprint: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE repository_index SET fingerprint = $2, generated_at = now()
        WHERE repository_id = $1
        "#,
        repository_id,
        fingerprint,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Delete the files of `repository_id` that the generation of `paths` does
/// not name: at once, except a content-addressed file (`immutable`), which
/// goes once no generation has named it for `keep`. Releases their blob
/// references; returns how many were deleted.
pub async fn prune(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    paths: &[String],
    keep: chrono::Duration,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    let keep_seconds = keep.num_seconds() as f64;
    let mut shas = sqlx::query_scalar!(
        r#"
        DELETE FROM raw_file
        WHERE repository_id = $1
          AND NOT (path = ANY($2))
          AND (NOT immutable
               OR checked_at IS NULL
               OR checked_at < now() - make_interval(secs => $3))
        RETURNING blob_sha256
        "#,
        repository_id,
        paths,
        keep_seconds,
    )
    .fetch_all(&mut **tx)
    .await?;
    shas.sort_unstable();
    for sha in &shas {
        blob_dao::decref_and_maybe_enqueue_delete(tx, sha, grace).await?;
    }
    Ok(shas.len() as u64)
}
