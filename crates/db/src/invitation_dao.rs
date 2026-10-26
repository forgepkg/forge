//! Data access for invitations (#322): a local account an
//! administrator created without a password (`app_user.invited`), and the
//! one live `user_invitation` with which its user sets the password.
//!
//! Only the SHA-256 of an invitation token is stored (`token_hash`); the
//! caller hashes. A new invitation replaces the account's previous one, so
//! the old link stops working; accepting sets the password, clears
//! `invited` and marks the invitation accepted in one transaction, so a token
//! signs up once.

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};

use crate::model::AppUser;
use crate::username::canonical_account_username;

/// An account's invitation.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Invitation {
    pub user_id: i64,
    /// The address it was sent (or made) for.
    pub email: String,
    pub expires_at: DateTime<Utc>,
    /// The administrator who made it.
    pub created_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    /// When the email service took the message.
    pub sent_at: Option<DateTime<Utc>>,
    pub accepted_at: Option<DateTime<Utc>>,
}

impl Invitation {
    /// Whether its link still works (not accepted, not expired).
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.accepted_at.is_none() && self.expires_at > now
    }
}

/// An account's onboarding fields (`app_user.email`, `app_user.invited`).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Onboarding {
    pub user_id: i64,
    pub email: Option<String>,
    pub invited: bool,
}

/// The columns of an [`Invitation`], as a literal for `concat!`.
macro_rules! invitation_columns {
    () => {
        "user_id, email, expires_at, created_by, created_at, sent_at, accepted_at"
    };
}

/// Create an invited local account: active, without a password, invited.
/// The username is a UPN, refused like [`crate::user_dao::insert_user`]'s
/// otherwise ([`sqlx::Error::InvalidArgument`]); it must also suit a
/// password login (no `:`), since its user will set one.
pub async fn insert_invited_user<'e, E>(
    executor: E,
    username: &str,
    email: &str,
) -> sqlx::Result<AppUser>
where
    E: PgExecutor<'e>,
{
    let username = canonical_account_username(username, true)
        .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?;
    sqlx::query_as(
        "INSERT INTO app_user (username, password_hash, active, auth_source, email, invited) \
         VALUES ($1, NULL, true, 'local', $2, true) \
         RETURNING id, username, password_hash, active, auth_source, external_subject, \
                   kind, created_at, updated_at",
    )
    .bind(username)
    .bind(email)
    .fetch_one(executor)
    .await
}

/// Set an account's address.
pub async fn set_email<'e, E>(executor: E, user_id: i64, email: Option<&str>) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query("UPDATE app_user SET email = $2, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .bind(email)
        .execute(executor)
        .await?;
    Ok(())
}

/// The onboarding fields of `user_id`.
pub async fn onboarding<'e, E>(executor: E, user_id: i64) -> sqlx::Result<Option<Onboarding>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as("SELECT id AS user_id, email, invited FROM app_user WHERE id = $1")
        .bind(user_id)
        .fetch_optional(executor)
        .await
}

/// The onboarding fields of every account.
pub async fn list_onboarding<'e, E>(executor: E) -> sqlx::Result<Vec<Onboarding>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as("SELECT id AS user_id, email, invited FROM app_user")
        .fetch_all(executor)
        .await
}

/// Make the invitation of `user_id`, replacing its previous one (whose link
/// then stops working). `None` when the account is not an active invited
/// one.
pub async fn put<'e, E>(
    executor: E,
    user_id: i64,
    token_hash: &str,
    email: &str,
    expires_at: DateTime<Utc>,
    created_by: Option<i64>,
) -> sqlx::Result<Option<Invitation>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as(concat!(
        "INSERT INTO user_invitation (user_id, token_hash, email, expires_at, created_by) \
         SELECT u.id, $2, $3, $4, $5 FROM app_user u \
         WHERE u.id = $1 AND u.invited AND u.active \
         ON CONFLICT (user_id) DO UPDATE SET \
             token_hash = EXCLUDED.token_hash, email = EXCLUDED.email, \
             expires_at = EXCLUDED.expires_at, created_by = EXCLUDED.created_by, \
             created_at = now(), sent_at = NULL, accepted_at = NULL \
         RETURNING ",
        invitation_columns!()
    ))
    .bind(user_id)
    .bind(token_hash)
    .bind(email)
    .bind(expires_at)
    .bind(created_by)
    .fetch_optional(executor)
    .await
}

/// Record that the email service took the invitation `token_hash` (if it is
/// still the account's).
pub async fn mark_sent<'e, E>(executor: E, user_id: i64, token_hash: &str) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE user_invitation SET sent_at = now() WHERE user_id = $1 AND token_hash = $2",
    )
    .bind(user_id)
    .bind(token_hash)
    .execute(executor)
    .await?;
    Ok(())
}

/// The invitation of `user_id`, live or not.
pub async fn get<'e, E>(executor: E, user_id: i64) -> sqlx::Result<Option<Invitation>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as(concat!(
        "SELECT ",
        invitation_columns!(),
        " FROM user_invitation WHERE user_id = $1"
    ))
    .bind(user_id)
    .fetch_optional(executor)
    .await
}

/// Every invitation, live or not.
pub async fn list<'e, E>(executor: E) -> sqlx::Result<Vec<Invitation>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as(concat!(
        "SELECT ",
        invitation_columns!(),
        " FROM user_invitation"
    ))
    .fetch_all(executor)
    .await
}

/// The username a live invitation `token_hash` is for: not accepted, not
/// expired, of an active account still invited. `None` otherwise.
pub async fn find_live<'e, E>(
    executor: E,
    token_hash: &str,
) -> sqlx::Result<Option<(String, DateTime<Utc>)>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT u.username, i.expires_at FROM user_invitation i \
         JOIN app_user u ON u.id = i.user_id \
         WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.expires_at > now() \
           AND u.invited AND u.active",
    )
    .bind(token_hash)
    .fetch_optional(executor)
    .await
}

/// Accept the live invitation `token_hash`: the account's password becomes
/// `password_hash` and it is no longer invited, and the invitation is marked
/// accepted. `None` when the token is not live (unknown, accepted, expired,
/// replaced, revoked, or its account deactivated); a token is accepted once.
pub async fn accept(
    pool: &PgPool,
    token_hash: &str,
    password_hash: &str,
) -> sqlx::Result<Option<AppUser>> {
    let mut tx = pool.begin().await?;
    let user_id: Option<i64> = sqlx::query_scalar(
        "UPDATE user_invitation i SET accepted_at = now() \
         FROM app_user u \
         WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.expires_at > now() \
           AND u.id = i.user_id AND u.invited AND u.active \
         RETURNING i.user_id",
    )
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user_id) = user_id else {
        return Ok(None);
    };
    let user: Option<AppUser> = sqlx::query_as(
        "UPDATE app_user SET password_hash = $2, invited = false, updated_at = now() \
         WHERE id = $1 AND invited AND active \
         RETURNING id, username, password_hash, active, auth_source, external_subject, \
                   kind, created_at, updated_at",
    )
    .bind(user_id)
    .bind(password_hash)
    .fetch_optional(&mut *tx)
    .await?;
    if user.is_some() {
        tx.commit().await?;
    }
    Ok(user)
}

/// Revoke the invitation of `user_id` (unless accepted). Returns whether
/// there was one.
pub async fn revoke<'e, E>(executor: E, user_id: i64) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    Ok(
        sqlx::query("DELETE FROM user_invitation WHERE user_id = $1 AND accepted_at IS NULL")
            .bind(user_id)
            .execute(executor)
            .await?
            .rows_affected()
            > 0,
    )
}
