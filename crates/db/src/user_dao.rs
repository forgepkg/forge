//! Data access for `app_user`.

use sqlx::PgPool;

use crate::model::AppUser;
use crate::username::canonical_username;

/// The canonical form of a username used as a lookup key, or `None` when it
/// can never name an account (empty, control characters, oversized).
fn lookup_key(username: &str) -> Option<String> {
    canonical_username(username).ok()
}

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
///
/// The username is stored in its canonical form
/// ([`crate::username::canonical_username`]); an invalid one is refused with
/// [`sqlx::Error::InvalidArgument`] (callers validate first to answer 400).
pub async fn insert_user(pool: &PgPool, new: NewUser) -> sqlx::Result<AppUser> {
    let username = canonical_username(&new.username)
        .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?;
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
        username,
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
/// credential. Idempotent and **never touches a non-upstream account**:
///
/// * **New username** → insert a fresh user with `auth_source = 'upstream-basic'`,
///   `password_hash = NULL` (no local password — the DB CHECK only requires one
///   for `'local'` users), `external_subject = username`, `active = true`,
///   `realm_id` = the vouching realm, and `is_admin = suggested_is_admin`.
/// * **Existing `'upstream-basic'` username** (same realm, or no realm recorded
///   on either side) → stamp `last_auth_source_at = now()`, record the realm if
///   none was recorded yet, and — only when `admin_authoritative` (the realm
///   maps an admin group and the groups were freshly fetched) — set `is_admin`
///   to the upstream's current verdict, so revocation upstream demotes here too.
///   Without an authoritative reading the stored admin flag is left alone.
/// * **Existing username owned by anything else** (a `'local'` or `'oidc'`
///   account, or an upstream user of a different realm) → **no row** is
///   returned: an upstream login must never be mapped onto (or take over) an
///   account it did not create. The caller denies.
///
/// The unique constraint on `username` makes the `ON CONFLICT` path race-safe
/// across instances. The username is canonicalized first; an invalid one
/// provisions nothing (`None` ⇒ deny).
pub async fn provision_upstream_user(
    pool: &PgPool,
    username: &str,
    suggested_is_admin: bool,
    admin_authoritative: bool,
    realm_id: Option<i64>,
) -> sqlx::Result<Option<AppUser>> {
    let Some(username) = lookup_key(username) else {
        return Ok(None);
    };
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, is_admin, active, auth_source,
             external_subject, last_auth_source_at, realm_id)
        VALUES ($1, NULL, $2, true, 'upstream-basic', $1, now(), $4)
        ON CONFLICT (username) DO UPDATE SET
            is_admin = CASE WHEN $3 THEN EXCLUDED.is_admin ELSE app_user.is_admin END,
            last_auth_source_at = now(),
            realm_id = COALESCE(app_user.realm_id, EXCLUDED.realm_id),
            -- Touch updated_at only when the admin flag actually changes.
            updated_at = CASE
                WHEN $3 AND EXCLUDED.is_admin <> app_user.is_admin THEN now()
                ELSE app_user.updated_at
            END
        WHERE app_user.auth_source = 'upstream-basic'
          AND (EXCLUDED.realm_id IS NULL
               OR app_user.realm_id IS NULL
               OR app_user.realm_id = EXCLUDED.realm_id)
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        username,
        suggested_is_admin,
        admin_authoritative,
        realm_id,
    )
    .fetch_optional(pool)
    .await
}

/// Find the `'upstream-basic'` user an upstream realm vouched for: the username
/// must belong to an upstream-provisioned account, and when both the vouching
/// realm and the user's recorded realm are known they must match. Local and
/// OIDC accounts of the same name are never returned (`None` ⇒ deny).
pub async fn find_upstream_user(
    pool: &PgPool,
    username: &str,
    realm_id: Option<i64>,
) -> sqlx::Result<Option<AppUser>> {
    let Some(username) = lookup_key(username) else {
        return Ok(None);
    };
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        FROM app_user
        WHERE username = $1
          AND auth_source = 'upstream-basic'
          AND ($2::bigint IS NULL OR realm_id IS NULL OR realm_id = $2)
        "#,
        username,
        realm_id,
    )
    .fetch_optional(pool)
    .await
}

/// Find a user by their unique username (compared in canonical form, so
/// `Alice`, `alice` and ` alice ` find the same account).
pub async fn find_user_by_username(pool: &PgPool, username: &str) -> sqlx::Result<Option<AppUser>> {
    let Some(username) = lookup_key(username) else {
        return Ok(None);
    };
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

/// Set a user's `active` flag (bumping `updated_at` only when it changes) and
/// return the resulting row, or `None` when no such user exists.
///
/// The admin deactivate/activate path. `active = false` is honored by every
/// authentication path (tokens, passwords, sessions, OIDC and upstream
/// logins), and no provisioning path ever flips it back: the upstream-basic
/// upsert ([`provision_upstream_user`]) and OIDC resolution leave an existing
/// row's `active` alone.
pub async fn set_active(pool: &PgPool, id: i64, active: bool) -> sqlx::Result<Option<AppUser>> {
    sqlx::query_as!(
        AppUser,
        r#"
        UPDATE app_user
        SET active = $2,
            updated_at = CASE WHEN active <> $2 THEN now() ELSE updated_at END
        WHERE id = $1
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        id,
        active,
    )
    .fetch_optional(pool)
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
