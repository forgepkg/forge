//! Data access for `component`.

use sqlx::{PgExecutor, PgPool, Postgres, Transaction};

use crate::blob_dao;
use crate::model::Component;

/// All settable fields when creating a component row.
#[derive(Debug, Clone)]
pub struct NewComponent {
    pub repository_id: i64,
    pub name: String,
    pub original_id: String,
    pub version: String,
    pub version_original: String,
    pub listed: bool,
}

/// Insert a component, returning the persisted row.
///
/// Accepts any [`PgExecutor`] (pool, `&mut Transaction`, etc.) so the insert
/// can participate in the same transaction as `blob_dao::commit_and_incref`.
pub async fn insert_component<'e, E>(executor: E, new: NewComponent) -> sqlx::Result<Component>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        Component,
        r#"
        INSERT INTO component (
            repository_id, name, original_id, version, version_original, listed
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
            id, repository_id, name, original_id, version, version_original,
            listed, created_at, updated_at
        "#,
        new.repository_id,
        new.name,
        new.original_id,
        new.version,
        new.version_original,
        new.listed,
    )
    .fetch_one(executor)
    .await
}

/// Find a component by its `(repository_id, name, version)` unique key.
///
/// Accepts any [`PgExecutor`] (pool, `&mut Transaction`, etc.) so the read can
/// participate in the same transaction as a subsequent write — required to
/// serialize the publish/redeploy duplicate-check against concurrent pushes.
pub async fn find_component<'e, E>(
    executor: E,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<Option<Component>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        Component,
        r#"
        SELECT
            id, repository_id, name, original_id, version, version_original,
            listed, created_at, updated_at
        FROM component
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_optional(executor)
    .await
}

/// List every version of a component within a repository, ordered by id.
pub async fn list_versions(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
) -> sqlx::Result<Vec<Component>> {
    sqlx::query_as!(
        Component,
        r#"
        SELECT
            id, repository_id, name, original_id, version, version_original,
            listed, created_at, updated_at
        FROM component
        WHERE repository_id = $1 AND name = $2
        ORDER BY id
        "#,
        repository_id,
        name,
    )
    .fetch_all(pool)
    .await
}

/// The ids (lowercase names) of `repository_id` with at least one version a
/// search shows: listed, a release unless `prerelease`, and not SemVer 2.0.0
/// (build metadata, or a `.` in the prerelease label of `version_original`)
/// unless `include_semver2`. With a non-empty `name_substring`, only ids
/// containing it. Ordered by name; hosted search pages over this list and
/// loads versions for the page only ([`search_versions`]).
pub async fn search_names(
    pool: &PgPool,
    repository_id: i64,
    name_substring: &str,
    prerelease: bool,
    include_semver2: bool,
) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar!(
        r#"
        SELECT DISTINCT name AS "name!"
        FROM component
        WHERE repository_id = $1 AND listed
          AND ($2 = '' OR strpos(name, $2) > 0)
          AND ($3 OR strpos(version, '-') = 0)
          AND ($4 OR version_original !~ '[+]|-.*[.]')
        ORDER BY name
        "#,
        repository_id,
        name_substring,
        prerelease,
        include_semver2,
    )
    .fetch_all(pool)
    .await
}

/// The versions of `names` in `repository_id` that [`search_names`] counts
/// (same filters), ordered by `(name, id)`.
pub async fn search_versions(
    pool: &PgPool,
    repository_id: i64,
    names: &[String],
    prerelease: bool,
    include_semver2: bool,
) -> sqlx::Result<Vec<Component>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as!(
        Component,
        r#"
        SELECT
            id, repository_id, name, original_id, version, version_original,
            listed, created_at, updated_at
        FROM component
        WHERE repository_id = $1 AND name = ANY($2::text[]) AND listed
          AND ($3 OR strpos(version, '-') = 0)
          AND ($4 OR version_original !~ '[+]|-.*[.]')
        ORDER BY name, id
        "#,
        repository_id,
        names,
        prerelease,
        include_semver2,
    )
    .fetch_all(pool)
    .await
}

/// The `(repository_id, name)` pairs of `repository_ids` × `names`
/// (lowercased package ids) with at least one component row — any version,
/// listed or not.
///
/// One batched existence query, used by group resolution's dependency-confusion
/// guard to decide which hosted leaves own an id regardless of who asks. Each
/// pair appears once; order is unspecified.
pub async fn repositories_having_names(
    pool: &PgPool,
    repository_ids: &[i64],
    names: &[String],
) -> sqlx::Result<Vec<(i64, String)>> {
    if repository_ids.is_empty() || names.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT repository_id, name
        FROM component
        WHERE repository_id = ANY($1) AND name = ANY($2)
        "#,
        repository_ids,
        names,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.repository_id, row.name))
        .collect())
}

/// Set the `listed` flag on a specific component version. Returns whether a row
/// was updated.
pub async fn set_listed<'e, E>(
    executor: E,
    repository_id: i64,
    name: &str,
    version: &str,
    listed: bool,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        UPDATE component
        SET listed = $4, updated_at = now()
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
        listed,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Delete a component version. Accepts any executor (pool or `&mut *tx`) so it
/// can participate in the larger delete transaction that also decrements blob
/// refcounts. Returns whether a row was deleted.
pub async fn delete_component<'e, E>(
    executor: E,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        DELETE FROM component
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Hard-delete one component version inside `tx`: remove the component and
/// all its assets and decrement each referenced blob (enqueuing a deferred S3
/// delete when one reaches zero refs, see
/// [`blob_dao::decref_and_maybe_enqueue_delete`]). Returns `false` when the
/// version does not exist — including when a concurrent hard delete removed it
/// first.
///
/// Concurrency: the component row is locked `FOR UPDATE` **before** its assets
/// are touched, and only the blob references whose asset rows this
/// transaction's own `DELETE … RETURNING` removed are decremented. A second
/// overlapping delete (a client retry, a double click, a retention run) blocks
/// on the row lock, then finds the row gone and decrements nothing — the
/// unlocked read-then-decref this replaces let both decrement, driving a blob
/// shared with another repository to zero refs while still referenced. The
/// lock also serializes against redeploys (which lock the same row) and
/// against asset inserts (whose foreign-key check takes `FOR KEY SHARE` on it).
pub async fn hard_delete_component(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    name: &str,
    version: &str,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let Some(id) = sqlx::query_scalar!(
        r#"
        SELECT id
        FROM component
        WHERE repository_id = $1 AND name = $2 AND version = $3
        FOR UPDATE
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(false);
    };
    delete_locked_components(tx, &[id], grace).await?;
    Ok(true)
}

/// Hard-delete **every** component of `repository_id` inside `tx`, with the
/// same per-reference decrement guarantees as [`hard_delete_component`].
/// Returns the number of components removed.
///
/// Used when a repository is deleted. The caller must already hold the
/// repository row `FOR UPDATE` (see `repository_dao::lock_repository`): that
/// blocks new component inserts, whose foreign-key check needs `FOR KEY SHARE`
/// on it, so nothing can be added between this purge and the repository
/// delete in the same transaction.
pub async fn hard_delete_all_components(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    // Lock in id order so overlapping purges acquire row locks consistently.
    let ids = sqlx::query_scalar!(
        r#"
        SELECT id
        FROM component
        WHERE repository_id = $1
        ORDER BY id
        FOR UPDATE
        "#,
        repository_id,
    )
    .fetch_all(&mut **tx)
    .await?;
    if ids.is_empty() {
        return Ok(0);
    }
    delete_locked_components(tx, &ids, grace).await?;
    Ok(ids.len() as u64)
}

/// Whether `repository_id` owns any component. Pass the transaction that holds
/// the repository row lock so the answer stays true until commit.
pub async fn repository_has_components<'e, E>(executor: E, repository_id: i64) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let exists = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM component WHERE repository_id = $1) AS "exists!""#,
        repository_id,
    )
    .fetch_one(executor)
    .await?;
    Ok(exists)
}

/// Delete the assets and rows of components the caller has locked `FOR
/// UPDATE`, decrementing one blob reference per asset row actually deleted.
async fn delete_locked_components(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[i64],
    grace: chrono::Duration,
) -> sqlx::Result<()> {
    let mut blob_refs = sqlx::query!(
        r#"DELETE FROM asset WHERE component_id = ANY($1)
           RETURNING component_id, path, blob_sha256"#,
        ids,
    )
    .fetch_all(&mut **tx)
    .await?;
    // Decrement in the order every other writer locks blob rows — one
    // component at a time, its assets by path (the `.nupkg` before the
    // `.nuspec`, as publish, redeploy, NuGet DELETE and retention do) — so a
    // concurrent writer sharing the same blobs cannot deadlock with this one.
    // Duplicates are kept: each asset row holds one reference.
    blob_refs.sort_unstable_by(|a, b| (a.component_id, &a.path).cmp(&(b.component_id, &b.path)));
    for row in &blob_refs {
        blob_dao::decref_and_maybe_enqueue_delete(tx, &row.blob_sha256, grace).await?;
    }
    sqlx::query!(r#"DELETE FROM component WHERE id = ANY($1)"#, ids)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// One version's registration data in a single row: listing state, publish
/// time, the stored manifest summary and the `.nupkg` hash.
#[derive(Debug, Clone)]
pub struct RegistrationRow {
    pub id: i64,
    pub original_id: String,
    pub version: String,
    pub listed: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub manifest_summary: Option<serde_json::Value>,
    pub package_hash_sha512_base64: Option<String>,
}

/// Every version of `name` with its registration data, in one query (the
/// `.nupkg` asset at `nupkg_path` supplies the hash).
pub async fn list_registration_rows(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    nupkg_path: &str,
) -> sqlx::Result<Vec<RegistrationRow>> {
    sqlx::query_as!(
        RegistrationRow,
        r#"
        SELECT
            c.id, c.original_id, c.version, c.listed, c.created_at,
            c.manifest_summary, a.sha512_base64 AS "package_hash_sha512_base64?"
        FROM component c
        LEFT JOIN asset a ON a.component_id = c.id AND a.path = $3
        WHERE c.repository_id = $1 AND c.name = $2
        ORDER BY c.id
        "#,
        repository_id,
        name,
        nupkg_path,
    )
    .fetch_all(pool)
    .await
}

/// Every version of `name` in `repository_id` with its publication time and
/// the size of its asset at `nupkg_path` (`None` without one): what a package
/// detail page shows per version, in one query.
pub async fn version_sizes(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    nupkg_path: &str,
) -> sqlx::Result<Vec<(String, chrono::DateTime<chrono::Utc>, Option<i64>)>> {
    let rows = sqlx::query!(
        r#"
        SELECT c.version, c.created_at, a.size AS "size?"
        FROM component c
        LEFT JOIN asset a ON a.component_id = c.id AND a.path = $3
        WHERE c.repository_id = $1 AND c.name = $2
        "#,
        repository_id,
        name,
        nupkg_path,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.version, r.created_at, r.size))
        .collect())
}

/// [`list_registration_rows`] for `versions` (normalized) only: a
/// registration page loads its own versions' summaries, not every version's.
pub async fn list_registration_rows_for_versions(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    versions: &[String],
    nupkg_path: &str,
) -> sqlx::Result<Vec<RegistrationRow>> {
    if versions.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as!(
        RegistrationRow,
        r#"
        SELECT
            c.id, c.original_id, c.version, c.listed, c.created_at,
            c.manifest_summary, a.sha512_base64 AS "package_hash_sha512_base64?"
        FROM component c
        LEFT JOIN asset a ON a.component_id = c.id AND a.path = $4
        WHERE c.repository_id = $1 AND c.name = $2 AND c.version = ANY($3::text[])
        ORDER BY c.id
        "#,
        repository_id,
        name,
        versions,
        nupkg_path,
    )
    .fetch_all(pool)
    .await
}

/// One version's registration data (see [`list_registration_rows`]).
pub async fn find_registration_row(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
    nupkg_path: &str,
) -> sqlx::Result<Option<RegistrationRow>> {
    sqlx::query_as!(
        RegistrationRow,
        r#"
        SELECT
            c.id, c.original_id, c.version, c.listed, c.created_at,
            c.manifest_summary, a.sha512_base64 AS "package_hash_sha512_base64?"
        FROM component c
        LEFT JOIN asset a ON a.component_id = c.id AND a.path = $4
        WHERE c.repository_id = $1 AND c.name = $2 AND c.version = $3
        "#,
        repository_id,
        name,
        version,
        nupkg_path,
    )
    .fetch_optional(pool)
    .await
}

/// The stored manifest summaries of `(names[i], versions[i])` in one query;
/// pairs without a stored summary are absent from the result.
pub async fn manifest_summaries(
    pool: &PgPool,
    repository_id: i64,
    names: &[String],
    versions: &[String],
) -> sqlx::Result<Vec<(String, String, serde_json::Value)>> {
    let rows = sqlx::query!(
        r#"
        SELECT c.name, c.version, c.manifest_summary AS "manifest_summary!"
        FROM component c
        JOIN UNNEST($2::text[], $3::text[]) AS w(name, version)
          ON w.name = c.name AND w.version = c.version
        WHERE c.repository_id = $1 AND c.manifest_summary IS NOT NULL
        "#,
        repository_id,
        names,
        versions,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.name, r.version, r.manifest_summary))
        .collect())
}

/// Store the manifest summary of a component published before summaries
/// were stored, unless one has been set since: a reader that parsed the old
/// manifest must not overwrite the summary a concurrent redeploy stored.
pub async fn backfill_manifest_summary(
    pool: &sqlx::PgPool,
    component_id: i64,
    summary: &serde_json::Value,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"UPDATE component SET manifest_summary = $2
           WHERE id = $1 AND manifest_summary IS NULL"#,
        component_id,
        summary,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Store the manifest summary of a component (at publish).
pub async fn set_manifest_summary<'e, E>(
    executor: E,
    component_id: i64,
    summary: &serde_json::Value,
) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"UPDATE component SET manifest_summary = $2 WHERE id = $1"#,
        component_id,
        summary,
    )
    .execute(executor)
    .await?;
    Ok(())
}
