//! Data access for `external_identity` (IdP identity -> `app_user` mapping).
//!
//! The join key is `(issuer, subject)` — NEVER email (emails are reassignable;
//! `sub` is the stable, issuer-scoped identifier). The denormalized claim
//! columns (`preferred_username`/`email`/`display_name`) are display/debugging
//! only and carry no authority.

use sqlx::PgPool;

use crate::model::{AppUser, ExternalIdentity};

/// Claim fields denormalized onto the identity row at link/login time.
#[derive(Debug, Clone, Default)]
pub struct IdentityClaims {
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

/// Link an IdP identity to an `app_user`, or refresh an existing link.
///
/// Upserts on the unique `(issuer, subject)` key: inserts on first login, and on
/// a repeat login updates the denormalized claims, bumps `last_login_at`, and
/// touches `updated_at`. Returns the persisted row. The `user_id` is only set on
/// insert — a re-link never re-points an existing `(issuer, subject)` to a
/// different user.
pub async fn link(
    pool: &PgPool,
    user_id: i64,
    issuer: &str,
    subject: &str,
    claims: IdentityClaims,
) -> sqlx::Result<ExternalIdentity> {
    sqlx::query_as!(
        ExternalIdentity,
        r#"
        INSERT INTO external_identity (
            user_id, issuer, subject,
            preferred_username, email, display_name, last_login_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, now())
        ON CONFLICT (issuer, subject) DO UPDATE
        SET preferred_username = EXCLUDED.preferred_username,
            email              = EXCLUDED.email,
            display_name       = EXCLUDED.display_name,
            last_login_at      = now(),
            updated_at         = now()
        RETURNING
            id, user_id, issuer, subject,
            preferred_username, email, display_name,
            last_login_at, created_at, updated_at
        "#,
        user_id,
        issuer,
        subject,
        claims.preferred_username,
        claims.email,
        claims.display_name,
    )
    .fetch_one(pool)
    .await
}

/// Whether `user_id` is linked to any IdP identity (of any issuer).
pub async fn user_has_identity(pool: &PgPool, user_id: i64) -> sqlx::Result<bool> {
    let linked = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM external_identity WHERE user_id = $1) AS "linked!""#,
        user_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(linked)
}

/// The display name the IdP sent for identity `id` at its last sign-in, if
/// the identity exists and the IdP sent one.
pub async fn display_name(pool: &PgPool, id: i64) -> sqlx::Result<Option<String>> {
    let name = sqlx::query_scalar!(
        "SELECT display_name FROM external_identity WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(name.flatten())
}

/// Find the identity row for `(issuer, subject)`, if any.
pub async fn find_by_issuer_subject(
    pool: &PgPool,
    issuer: &str,
    subject: &str,
) -> sqlx::Result<Option<ExternalIdentity>> {
    sqlx::query_as!(
        ExternalIdentity,
        r#"
        SELECT
            id, user_id, issuer, subject,
            preferred_username, email, display_name,
            last_login_at, created_at, updated_at
        FROM external_identity
        WHERE issuer = $1 AND subject = $2
        "#,
        issuer,
        subject,
    )
    .fetch_optional(pool)
    .await
}

/// Resolve the `app_user` linked to `(issuer, subject)`, if any. Joins through
/// `external_identity` so the caller gets the user in one round-trip.
pub async fn find_user_by_subject(
    pool: &PgPool,
    issuer: &str,
    subject: &str,
) -> sqlx::Result<Option<AppUser>> {
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            u.id, u.username, u.password_hash, u.active,
            u.auth_source, u.external_subject, u.kind, u.created_at, u.updated_at
        FROM app_user u
        JOIN external_identity ei ON ei.user_id = u.id
        WHERE ei.issuer = $1 AND ei.subject = $2
        "#,
        issuer,
        subject,
    )
    .fetch_optional(pool)
    .await
}
