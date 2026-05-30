//! Data access for `repository` and `group_member`.

use serde_json::Value as JsonValue;
use sqlx::PgPool;

use crate::model::Repository;

/// All settable fields when creating a repository row.
///
/// Server-managed columns (`id`, `created_at`, `updated_at`) are not included.
#[derive(Debug, Clone)]
pub struct NewRepository {
    pub name: String,
    pub format: String,
    pub kind: String,
    pub anonymous_read: bool,
    pub online: bool,
    pub config: JsonValue,
    pub remote_url: Option<String>,
    pub package_delay_seconds: i32,
    pub upstream_username: Option<String>,
    pub upstream_password: Option<String>,
    pub allow_private_upstream: bool,
    pub metadata_ttl_seconds: Option<i32>,
    pub not_found_ttl_seconds: Option<i32>,
    pub allow_redeploy: bool,
}

impl NewRepository {
    /// Convenience constructor for a hosted repository with default options.
    pub fn hosted(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            format: "nuget".to_string(),
            kind: "hosted".to_string(),
            anonymous_read: false,
            online: true,
            config: JsonValue::Object(Default::default()),
            remote_url: None,
            package_delay_seconds: 0,
            upstream_username: None,
            upstream_password: None,
            allow_private_upstream: false,
            metadata_ttl_seconds: None,
            not_found_ttl_seconds: None,
            allow_redeploy: false,
        }
    }

    /// Convenience constructor for a group repository.
    pub fn group(name: impl Into<String>) -> Self {
        Self {
            kind: "group".to_string(),
            ..Self::hosted(name)
        }
    }

    /// Convenience constructor for a proxy repository with default options.
    pub fn proxy(name: impl Into<String>) -> Self {
        Self {
            kind: "proxy".to_string(),
            ..Self::hosted(name)
        }
    }
}

/// Insert a repository, returning the full persisted row.
pub async fn insert_repository(pool: &PgPool, new: NewRepository) -> sqlx::Result<Repository> {
    sqlx::query_as!(
        Repository,
        r#"
        INSERT INTO repository (
            name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            allow_private_upstream, metadata_ttl_seconds, not_found_ttl_seconds, allow_redeploy
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            allow_private_upstream, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        "#,
        new.name,
        new.format,
        new.kind,
        new.anonymous_read,
        new.online,
        new.config,
        new.remote_url,
        new.package_delay_seconds,
        new.upstream_username,
        new.upstream_password,
        new.allow_private_upstream,
        new.metadata_ttl_seconds,
        new.not_found_ttl_seconds,
        new.allow_redeploy,
    )
    .fetch_one(pool)
    .await
}

/// Find a repository by its unique name.
pub async fn find_repository_by_name(
    pool: &PgPool,
    name: &str,
) -> sqlx::Result<Option<Repository>> {
    sqlx::query_as!(
        Repository,
        r#"
        SELECT
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            allow_private_upstream, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        FROM repository
        WHERE name = $1
        "#,
        name,
    )
    .fetch_optional(pool)
    .await
}

/// Find a repository by id.
pub async fn find_repository_by_id(pool: &PgPool, id: i64) -> sqlx::Result<Option<Repository>> {
    sqlx::query_as!(
        Repository,
        r#"
        SELECT
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            allow_private_upstream, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        FROM repository
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// List all repositories ordered by name.
pub async fn list_repositories(pool: &PgPool) -> sqlx::Result<Vec<Repository>> {
    sqlx::query_as!(
        Repository,
        r#"
        SELECT
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            allow_private_upstream, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        FROM repository
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await
}

/// Return the members of a group joined to their repository rows, ordered by
/// `priority` **descending** so the highest-priority member (which wins ties per
/// spec §7) comes first.
pub async fn group_members(pool: &PgPool, group_id: i64) -> sqlx::Result<Vec<(Repository, i32)>> {
    let rows = sqlx::query!(
        r#"
        SELECT
            r.id, r.name, r.format, r.kind, r.anonymous_read, r.online, r.config,
            r.remote_url, r.package_delay_seconds, r.upstream_username, r.upstream_password,
            r.allow_private_upstream, r.metadata_ttl_seconds, r.not_found_ttl_seconds,
            r.allow_redeploy, r.created_at, r.updated_at,
            gm.priority
        FROM group_member gm
        JOIN repository r ON r.id = gm.member_id
        WHERE gm.group_id = $1
        ORDER BY gm.priority DESC
        "#,
        group_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            (
                Repository {
                    id: row.id,
                    name: row.name,
                    format: row.format,
                    kind: row.kind,
                    anonymous_read: row.anonymous_read,
                    online: row.online,
                    config: row.config,
                    remote_url: row.remote_url,
                    package_delay_seconds: row.package_delay_seconds,
                    upstream_username: row.upstream_username,
                    upstream_password: row.upstream_password,
                    allow_private_upstream: row.allow_private_upstream,
                    metadata_ttl_seconds: row.metadata_ttl_seconds,
                    not_found_ttl_seconds: row.not_found_ttl_seconds,
                    allow_redeploy: row.allow_redeploy,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                },
                row.priority,
            )
        })
        .collect())
}

/// Add a member to a group with the given priority (unique per group).
pub async fn add_group_member(
    pool: &PgPool,
    group_id: i64,
    member_id: i64,
    priority: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO group_member (group_id, member_id, priority)
        VALUES ($1, $2, $3)
        "#,
        group_id,
        member_id,
        priority,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove a member from a group. Returns whether a row was deleted.
pub async fn remove_group_member(
    pool: &PgPool,
    group_id: i64,
    member_id: i64,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        DELETE FROM group_member
        WHERE group_id = $1 AND member_id = $2
        "#,
        group_id,
        member_id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Mutable settings of an existing repository (admin update).
///
/// Identity columns (`id`, `format`, `kind`) and server-managed timestamps are
/// **not** updatable here — changing a repository's kind is structurally unsafe
/// (it would orphan components/members), so the admin API rejects it and a
/// kind change is a delete-then-recreate.
#[derive(Debug, Clone)]
pub struct RepositoryUpdate {
    pub name: String,
    pub anonymous_read: bool,
    pub online: bool,
    pub config: JsonValue,
    pub remote_url: Option<String>,
    pub package_delay_seconds: i32,
    pub upstream_username: Option<String>,
    pub upstream_password: Option<String>,
    pub allow_private_upstream: bool,
    pub metadata_ttl_seconds: Option<i32>,
    pub not_found_ttl_seconds: Option<i32>,
    pub allow_redeploy: bool,
}

/// Update the mutable settings of a repository by id. Returns the updated row,
/// or `None` if no repository has that id. `updated_at` is bumped to `now()`.
pub async fn update_repository(
    pool: &PgPool,
    id: i64,
    upd: RepositoryUpdate,
) -> sqlx::Result<Option<Repository>> {
    sqlx::query_as!(
        Repository,
        r#"
        UPDATE repository SET
            name = $2,
            anonymous_read = $3,
            online = $4,
            config = $5,
            remote_url = $6,
            package_delay_seconds = $7,
            upstream_username = $8,
            upstream_password = $9,
            allow_private_upstream = $10,
            metadata_ttl_seconds = $11,
            not_found_ttl_seconds = $12,
            allow_redeploy = $13,
            updated_at = now()
        WHERE id = $1
        RETURNING
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            allow_private_upstream, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        "#,
        id,
        upd.name,
        upd.anonymous_read,
        upd.online,
        upd.config,
        upd.remote_url,
        upd.package_delay_seconds,
        upd.upstream_username,
        upd.upstream_password,
        upd.allow_private_upstream,
        upd.metadata_ttl_seconds,
        upd.not_found_ttl_seconds,
        upd.allow_redeploy,
    )
    .fetch_optional(pool)
    .await
}

/// Delete a repository by id. Returns whether a row was deleted.
///
/// FK constraints cascade `group_member` rows that reference it (as group or
/// member); component/asset rows must already be gone (the admin layer hard-
/// deletes packages first) or the FK will reject the delete.
pub async fn delete_repository(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(r#"DELETE FROM repository WHERE id = $1"#, id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}
