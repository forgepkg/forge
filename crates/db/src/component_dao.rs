//! Data access for `component`.

use sqlx::{PgExecutor, PgPool};

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
pub async fn insert_component(pool: &PgPool, new: NewComponent) -> sqlx::Result<Component> {
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
    .fetch_one(pool)
    .await
}

/// Find a component by its `(repository_id, name, version)` unique key.
pub async fn find_component(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<Option<Component>> {
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
    .fetch_optional(pool)
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

/// Set the `listed` flag on a specific component version. Returns whether a row
/// was updated.
pub async fn set_listed(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
    listed: bool,
) -> sqlx::Result<bool> {
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
    .execute(pool)
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
