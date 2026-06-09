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

/// Provision (or refresh) a user authenticated by the `upstream-basic` provider
/// (slice 12.3, phase 5).
///
/// Called by the auth chain after the upstream **definitively accepts** a
/// credential. Idempotent and **never destructive to a local account**:
///
/// * **New username** → insert a fresh user with `auth_source = 'upstream-basic'`,
///   `password_hash = NULL` (no local password — the DB CHECK only requires one
///   for `'local'` users), `external_subject = username`, `active = true`, and
///   `is_admin = suggested_is_admin` (the upstream's admin-group mapping; grant
///   only on first provision).
/// * **Existing username** → only stamp `last_auth_source_at = now()` and, when
///   `suggested_is_admin` is true, **grant** `is_admin` (never revoke it here —
///   admin downgrade is operator-managed / §12.4). The row's `auth_source`,
///   `password_hash`, and `external_subject` are left untouched, so an existing
///   `'local'` admin is never downgraded to a passwordless upstream account by an
///   upstream login (plan §2.4 / §6 username-collision note).
///
/// Returns the resulting (post-provision) row. The unique constraint on
/// `username` makes the `ON CONFLICT` path race-safe across instances.
pub async fn provision_upstream_user(
    pool: &PgPool,
    username: &str,
    suggested_is_admin: bool,
) -> sqlx::Result<AppUser> {
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, is_admin, active, auth_source,
             external_subject, last_auth_source_at)
        VALUES ($1, NULL, $2, true, 'upstream-basic', $1, now())
        ON CONFLICT (username) DO UPDATE SET
            -- Grant-only admin: never flip an existing admin off here.
            is_admin = app_user.is_admin OR EXCLUDED.is_admin,
            last_auth_source_at = now(),
            -- Touch updated_at only when the admin grant actually changes the row.
            updated_at = CASE
                WHEN EXCLUDED.is_admin AND NOT app_user.is_admin THEN now()
                ELSE app_user.updated_at
            END
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        username,
        suggested_is_admin,
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

/// Record which auth realm last vouched for / provisioned this user (12.7
/// provenance — informational, never an authorization input). A no-op write
/// when the value is unchanged.
pub async fn set_user_realm(pool: &PgPool, user_id: i64, realm_id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE app_user
        SET realm_id = $2
        WHERE id = $1 AND realm_id IS DISTINCT FROM $2
        "#,
        user_id,
        realm_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
