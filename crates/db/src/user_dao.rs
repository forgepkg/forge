//! Data access for `app_user`.

use sqlx::PgPool;

use crate::model::AppUser;

/// All settable fields when creating a user row.
///
/// `password_hash` is `None` for users with no local password (upstream-basic /
/// oidc). `auth_source` defaults conceptually to `'local'`; callers provisioning
/// a non-local user set it explicitly along with `external_subject`. The DB
/// CHECK enforces that a `'local'` user has a non-null `password_hash`.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub active: bool,
    pub auth_source: String,
    pub external_subject: Option<String>,
}

impl NewUser {
    /// Convenience constructor for a slice-1 local (argon2 password) user.
    pub fn local(username: String, password_hash: String, is_admin: bool, active: bool) -> Self {
        Self {
            username,
            password_hash: Some(password_hash),
            is_admin,
            active,
            auth_source: "local".to_string(),
            external_subject: None,
        }
    }
}

/// Insert a user, returning the persisted row.
pub async fn insert_user(pool: &PgPool, new: NewUser) -> sqlx::Result<AppUser> {
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, is_admin, active, auth_source, external_subject)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        new.username,
        new.password_hash,
        new.is_admin,
        new.active,
        new.auth_source,
        new.external_subject,
    )
    .fetch_one(pool)
    .await
}

/// Find a user by their unique username.
pub async fn find_user_by_username(pool: &PgPool, username: &str) -> sqlx::Result<Option<AppUser>> {
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
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
        SELECT
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        FROM app_user
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// List all users ordered by username (admin listing).
pub async fn list_users(pool: &PgPool) -> sqlx::Result<Vec<AppUser>> {
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        FROM app_user
        ORDER BY username
        "#,
    )
    .fetch_all(pool)
    .await
}

/// Set a user's `is_admin` flag (bumping `updated_at` only when it changes) and
/// return the resulting row.
///
/// Used by OIDC login to **recompute** admin on every sign-in from the IdP's
/// group/role claim (slice 12.2 §3.6): a user added to or removed from the admin
/// group gains/loses admin on their next login.
pub async fn update_is_admin(pool: &PgPool, id: i64, is_admin: bool) -> sqlx::Result<AppUser> {
    sqlx::query_as!(
        AppUser,
        r#"
        UPDATE app_user
        SET is_admin = $2,
            updated_at = CASE WHEN is_admin <> $2 THEN now() ELSE updated_at END
        WHERE id = $1
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        id,
        is_admin,
    )
    .fetch_one(pool)
    .await
}

/// Delete a user by id (cascading their tokens). Returns whether a row went.
pub async fn delete_user(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(r#"DELETE FROM app_user WHERE id = $1"#, id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}
