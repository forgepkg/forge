//! Data access for `asset`.

use sqlx::PgExecutor;

use crate::model::Asset;

/// All settable fields when creating an asset row.
#[derive(Debug, Clone)]
pub struct NewAsset {
    pub component_id: i64,
    pub path: String,
    pub content_type: String,
    pub blob_sha256: String,
    pub size: i64,
    pub sha512_base64: Option<String>,
}

/// Insert an asset, returning the persisted row.
///
/// Accepts any [`PgExecutor`] (pool, `&mut Transaction`, etc.) so the insert
/// can participate in the same transaction as `blob_dao::commit_and_incref`.
pub async fn insert_asset<'e, E>(executor: E, new: NewAsset) -> sqlx::Result<Asset>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        Asset,
        r#"
        INSERT INTO asset (
            component_id, path, content_type, blob_sha256, size, sha512_base64
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
            id, component_id, path, content_type, blob_sha256, size,
            sha512_base64, created_at
        "#,
        new.component_id,
        new.path,
        new.content_type,
        new.blob_sha256,
        new.size,
        new.sha512_base64,
    )
    .fetch_one(executor)
    .await
}

/// Find an asset by its `(component_id, path)` unique key.
///
/// Accepts any [`PgExecutor`] so the read can run on the same transaction
/// connection that holds the component's `FOR UPDATE` lock during a redeploy
/// swap — otherwise the lookup could observe rows a concurrent redeploy already
/// swapped in, corrupting blob ref-counts.
pub async fn find_asset<'e, E>(
    executor: E,
    component_id: i64,
    path: &str,
) -> sqlx::Result<Option<Asset>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        Asset,
        r#"
        SELECT
            id, component_id, path, content_type, blob_sha256, size,
            sha512_base64, created_at
        FROM asset
        WHERE component_id = $1 AND path = $2
        "#,
        component_id,
        path,
    )
    .fetch_optional(executor)
    .await
}

/// List all assets belonging to a component, ordered by path.
///
/// Accepts any [`PgExecutor`] so a hard delete can read the asset set inside
/// the same transaction that locked the component row `FOR UPDATE`, preventing
/// a concurrent redeploy from swapping blob references out from under it.
pub async fn assets_for_component<'e, E>(executor: E, component_id: i64) -> sqlx::Result<Vec<Asset>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        Asset,
        r#"
        SELECT
            id, component_id, path, content_type, blob_sha256, size,
            sha512_base64, created_at
        FROM asset
        WHERE component_id = $1
        ORDER BY path
        "#,
        component_id,
    )
    .fetch_all(executor)
    .await
}
