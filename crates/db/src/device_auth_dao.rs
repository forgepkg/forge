//! Device authorization requests (`device_authorization`, RFC 8628): a
//! command-line client polls with a device code while its user types the
//! user code on the web UI's `/device` page and approves or denies it.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};

/// A request as the `/device` page shows it.
#[derive(Debug, Clone)]
pub struct DeviceAuthorization {
    pub id: i64,
    /// The user code, normalized (eight letters, no hyphen).
    pub user_code: String,
    pub client_id: String,
    /// The requested scope, normalized; `None`: the user's rights.
    pub scope: Option<String>,
    pub client_ip: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A request to store ([`insert`]).
#[derive(Debug, Clone)]
pub struct NewDeviceAuthorization<'a> {
    pub device_code_hash: &'a str,
    pub user_code: &'a str,
    pub client_id: &'a str,
    pub scope: Option<&'a str>,
    pub client_ip: Option<&'a str>,
    pub interval_seconds: i32,
    pub expires_at: DateTime<Utc>,
}

/// Store a new pending request; returns its id. Returns `None`, storing
/// nothing, when a request (live or expired, not yet reaped) holds the same
/// user code: the caller draws another.
pub async fn insert(pool: &PgPool, new: NewDeviceAuthorization<'_>) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar!(
        r#"
        INSERT INTO device_authorization
            (device_code_hash, user_code, client_id, scope, client_ip, interval_seconds, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (user_code) DO NOTHING
        RETURNING id
        "#,
        new.device_code_hash,
        new.user_code,
        new.client_id,
        new.scope,
        new.client_ip,
        new.interval_seconds,
        new.expires_at,
    )
    .fetch_optional(pool)
    .await
}

/// The live (not expired), still pending request with `user_code`.
pub async fn find_pending(
    pool: &PgPool,
    user_code: &str,
) -> sqlx::Result<Option<DeviceAuthorization>> {
    sqlx::query_as!(
        DeviceAuthorization,
        r#"
        SELECT id, user_code, client_id, scope, client_ip, created_at, expires_at
        FROM device_authorization
        WHERE user_code = $1 AND status = 'pending' AND expires_at > now()
        "#,
        user_code,
    )
    .fetch_optional(pool)
    .await
}

/// Approve (for `approved_by`) or, with `None`, deny the live pending request
/// with `user_code`. Returns the request as it was decided, `None` when there
/// is no such request (unknown, expired or decided already).
pub async fn decide(
    pool: &PgPool,
    user_code: &str,
    approved_by: Option<i64>,
) -> sqlx::Result<Option<DeviceAuthorization>> {
    sqlx::query_as!(
        DeviceAuthorization,
        r#"
        UPDATE device_authorization
        SET status = CASE WHEN $2::bigint IS NULL THEN 'denied' ELSE 'approved' END,
            user_id = $2,
            decided_at = now()
        WHERE user_code = $1 AND status = 'pending' AND expires_at > now()
        RETURNING id, user_code, client_id, scope, client_ip, created_at, expires_at
        "#,
        user_code,
        approved_by,
    )
    .fetch_optional(pool)
    .await
}

/// Where a request stands for its client's poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollState {
    /// Waiting for the user.
    Pending,
    /// Approved by the user; the token is still to be collected.
    Approved { user_id: i64 },
    /// Denied by the user.
    Denied,
    /// Its token was collected, or it expired.
    Expired,
}

/// A request as a poll of its device code finds it, locked for the poll's
/// transaction ([`lock_for_poll`]).
#[derive(Debug, Clone)]
pub struct PolledRequest {
    pub id: i64,
    pub client_id: String,
    pub scope: Option<String>,
    pub state: PollState,
    /// The interval the client must keep between polls (seconds).
    pub interval_seconds: i32,
    /// Whether this poll came sooner than that after the previous one.
    pub too_fast: bool,
}

/// Find and lock the request whose device code hashes to `device_code_hash`
/// in the transaction on `conn` (`SELECT … FOR UPDATE`, so two polls of one
/// code are answered one after the other). The clock is the database's.
pub async fn lock_for_poll(
    conn: &mut PgConnection,
    device_code_hash: &str,
) -> sqlx::Result<Option<PolledRequest>> {
    let row = sqlx::query!(
        r#"
        SELECT id, client_id, scope, status, user_id, interval_seconds,
               expires_at <= now() AS "expired!",
               COALESCE(
                   last_polled_at > now() - make_interval(secs => interval_seconds),
                   false
               ) AS "too_fast!"
        FROM device_authorization
        WHERE device_code_hash = $1
        FOR UPDATE
        "#,
        device_code_hash,
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|row| {
        let state = match (row.status.as_str(), row.user_id) {
            _ if row.expired => PollState::Expired,
            ("pending", _) => PollState::Pending,
            ("approved", Some(user_id)) => PollState::Approved { user_id },
            ("denied", _) => PollState::Denied,
            // `collected`, or an approval without its user (deleted).
            _ => PollState::Expired,
        };
        PolledRequest {
            id: row.id,
            client_id: row.client_id,
            scope: row.scope,
            state,
            interval_seconds: row.interval_seconds,
            too_fast: row.too_fast,
        }
    }))
}

/// Record a poll of the pending request `id` now, with the interval the
/// client must keep from now on.
pub async fn record_poll(
    conn: &mut PgConnection,
    id: i64,
    interval_seconds: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE device_authorization
        SET last_polled_at = now(), interval_seconds = $2
        WHERE id = $1
        "#,
        id,
        interval_seconds,
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Mark the approved request `id` collected: its token was minted, and a
/// later poll gets `expired_token`.
pub async fn mark_collected(conn: &mut PgConnection, id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE device_authorization
        SET status = 'collected', last_polled_at = now()
        WHERE id = $1
        "#,
        id,
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Delete expired requests (the auth reaper). Returns how many.
pub async fn delete_expired(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(
        sqlx::query!(r#"DELETE FROM device_authorization WHERE expires_at <= now()"#)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}
