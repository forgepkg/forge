//! Data access for `app_user`.

use sqlx::PgPool;

use crate::model::AppUser;

/// All settable fields when creating a user row.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub active: bool,
}

/// Insert a user, returning the persisted row.
pub async fn insert_user(pool: &PgPool, new: NewUser) -> sqlx::Result<AppUser> {
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user (username, password_hash, is_admin, active)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, password_hash, is_admin, active, created_at, updated_at
        "#,
        new.username,
        new.password_hash,
        new.is_admin,
        new.active,
    )
    .fetch_one(pool)
    .await
}

/// Find a user by their unique username.
pub async fn find_user_by_username(pool: &PgPool, username: &str) -> sqlx::Result<Option<AppUser>> {
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT id, username, password_hash, is_admin, active, created_at, updated_at
        FROM app_user
        WHERE username = $1
        "#,
        username,
    )
    .fetch_optional(pool)
    .await
}

/// Find a user by id.
pub async fn find_user_by_id(pool: &PgPool, id: i64) -> sqlx::Result<Option<AppUser>> {
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT id, username, password_hash, is_admin, active, created_at, updated_at
        FROM app_user
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}
