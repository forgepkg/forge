//! Data access for `email_oauth_flow` (migration 0044): the OAuth
//! authorizations of the email service's `smtp_oauth` transport in progress
//! (#321), by the authorization code flow with PKCE or the device
//! authorization grant. Rows are short-lived and taken (deleted) when the
//! flow completes.

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

/// A flow row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct EmailOauthFlow {
    pub id: Uuid,
    /// `code` or `device`.
    pub kind: String,
    /// The administrator who started it.
    pub user_id: i64,
    /// What it authorizes: a result for settings that changed meanwhile is
    /// dropped.
    pub issuer: String,
    pub client_id: String,
    pub username: String,
    /// `code`: the OAuth `state`.
    pub state: Option<String>,
    /// `code`: the hash of the browser's flow cookie.
    pub browser_binding: Option<String>,
    /// `code`: the PKCE verifier.
    pub pkce_verifier: Option<String>,
    /// `device`: the device code.
    pub device_code: Option<String>,
    /// `device`: how long to wait between polls.
    pub interval_secs: Option<i32>,
    /// `device`: the earliest next poll.
    pub next_poll_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

/// What the flows authorize.
#[derive(Debug, Clone)]
pub struct FlowTarget {
    pub user_id: i64,
    pub issuer: String,
    pub client_id: String,
    pub username: String,
}

/// The columns every query returns, as a literal for `concat!`.
macro_rules! columns {
    () => {
        "id, kind, user_id, issuer, client_id, username, state, browser_binding, \
         pkce_verifier, device_code, interval_secs, next_poll_at, expires_at"
    };
}

/// Start an authorization code flow.
pub async fn begin_code(
    pool: &PgPool,
    target: &FlowTarget,
    state: &str,
    browser_binding: &str,
    pkce_verifier: &str,
    expires_at: DateTime<Utc>,
) -> sqlx::Result<EmailOauthFlow> {
    sqlx::query_as(concat!(
        "INSERT INTO email_oauth_flow \
             (kind, user_id, issuer, client_id, username, state, browser_binding, \
              pkce_verifier, expires_at) \
         VALUES ('code', $1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING ",
        columns!()
    ))
    .bind(target.user_id)
    .bind(&target.issuer)
    .bind(&target.client_id)
    .bind(&target.username)
    .bind(state)
    .bind(browser_binding)
    .bind(pkce_verifier)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Take (delete and return) the live code flow of `state`: a state is used
/// once.
pub async fn take_code(pool: &PgPool, state: &str) -> sqlx::Result<Option<EmailOauthFlow>> {
    sqlx::query_as(concat!(
        "DELETE FROM email_oauth_flow \
         WHERE kind = 'code' AND state = $1 AND expires_at > now() \
         RETURNING ",
        columns!()
    ))
    .bind(state)
    .fetch_optional(pool)
    .await
}

/// Start a device authorization flow.
pub async fn begin_device(
    pool: &PgPool,
    target: &FlowTarget,
    device_code: &str,
    interval_secs: i32,
    expires_at: DateTime<Utc>,
) -> sqlx::Result<EmailOauthFlow> {
    sqlx::query_as(concat!(
        "INSERT INTO email_oauth_flow \
             (kind, user_id, issuer, client_id, username, device_code, interval_secs, \
              next_poll_at, expires_at) \
         VALUES ('device', $1, $2, $3, $4, $5, $6, now(), $7) \
         RETURNING ",
        columns!()
    ))
    .bind(target.user_id)
    .bind(&target.issuer)
    .bind(&target.client_id)
    .bind(&target.username)
    .bind(device_code)
    .bind(interval_secs)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Claim the next poll of the live device flow `id` of `user_id`: returns it
/// when it is due (and moves its next poll `interval_secs` on), `None` when
/// it is unknown, expired, another administrator's, or not due yet.
pub async fn claim_device_poll(
    pool: &PgPool,
    id: Uuid,
    user_id: i64,
) -> sqlx::Result<Option<EmailOauthFlow>> {
    sqlx::query_as(concat!(
        "UPDATE email_oauth_flow \
         SET next_poll_at = now() + make_interval(secs => interval_secs) \
         WHERE id = $1 AND kind = 'device' AND user_id = $2 \
           AND expires_at > now() AND next_poll_at <= now() \
         RETURNING ",
        columns!()
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// The device flow `id` of `user_id`, live or not.
pub async fn get_device(
    pool: &PgPool,
    id: Uuid,
    user_id: i64,
) -> sqlx::Result<Option<EmailOauthFlow>> {
    sqlx::query_as(concat!(
        "SELECT ",
        columns!(),
        " FROM email_oauth_flow \
         WHERE id = $1 AND kind = 'device' AND user_id = $2"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Slow a device flow down (`slow_down`, RFC 8628 §3.5): five more seconds
/// between polls.
pub async fn slow_down<'e, E>(executor: E, id: Uuid) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE email_oauth_flow \
         SET interval_secs = interval_secs + 5, \
             next_poll_at = now() + make_interval(secs => interval_secs + 5) \
         WHERE id = $1",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Delete a flow (completed or failed).
pub async fn delete<'e, E>(executor: E, id: Uuid) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query("DELETE FROM email_oauth_flow WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Delete every flow (the settings changed: none of them applies).
pub async fn delete_all(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(sqlx::query("DELETE FROM email_oauth_flow")
        .execute(pool)
        .await?
        .rows_affected())
}

/// Delete the expired flows. Returns how many went.
pub async fn sweep_expired(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(
        sqlx::query("DELETE FROM email_oauth_flow WHERE expires_at <= now()")
            .execute(pool)
            .await?
            .rows_affected(),
    )
}
