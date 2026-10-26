//! Command-line logins approved in the browser (`cli_login`): a client
//! such as `npm login` is given a login URL to open and a done URL to poll.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// A login as its approval page shows it.
#[derive(Debug, Clone)]
pub struct CliLogin {
    /// The client (the repository's format, `npm`).
    pub client: String,
    pub id: i64,
    pub repository_id: i64,
    pub hostname: Option<String>,
    pub client_ip: Option<String>,
    pub user_id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Start a login of `client` for repository `repository_id`, valid until
/// `expires_at`.
#[allow(clippy::too_many_arguments)]
pub async fn insert(
    pool: &PgPool,
    login_hash: &str,
    done_hash: &str,
    client: &str,
    repository_id: i64,
    hostname: Option<&str>,
    client_ip: Option<&str>,
    expires_at: DateTime<Utc>,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO cli_login (login_hash, done_hash, client, repository_id, hostname, client_ip, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        login_hash,
        done_hash,
        client,
        repository_id,
        hostname,
        client_ip,
        expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// The live (not expired) login whose login URL secret hashes to
/// `login_hash`.
pub async fn find(pool: &PgPool, login_hash: &str) -> sqlx::Result<Option<CliLogin>> {
    sqlx::query_as!(
        CliLogin,
        r#"
        SELECT id, client, repository_id, hostname, client_ip, user_id, created_at, expires_at
        FROM cli_login
        WHERE login_hash = $1 AND expires_at > now()
        "#,
        login_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Approve the live, not yet approved login `login_hash` for `user_id`.
/// Returns whether it was approved now.
pub async fn approve(pool: &PgPool, login_hash: &str, user_id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        UPDATE cli_login SET user_id = $2, approved_at = now()
        WHERE login_hash = $1 AND expires_at > now() AND user_id IS NULL
        "#,
        login_hash,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Deny (delete) the live login `login_hash`. Returns whether it existed.
pub async fn deny(pool: &PgPool, login_hash: &str) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"DELETE FROM cli_login WHERE login_hash = $1 AND user_id IS NULL"#,
        login_hash,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// What polling a login's done URL finds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliLoginState {
    /// No live login has this done URL (unknown, expired, denied or
    /// collected already).
    Unknown,
    /// Waiting for the browser.
    Pending,
    /// Approved by `user_id`, for `hostname`: the row is gone now, the
    /// caller mints the token.
    Approved {
        user_id: i64,
        repository_id: i64,
        hostname: Option<String>,
    },
}

/// Poll the login whose done URL secret hashes to `done_hash`. An
/// approved login is taken (deleted) by the first poll that finds it.
pub async fn poll(pool: &PgPool, done_hash: &str) -> sqlx::Result<CliLoginState> {
    if let Some(row) = sqlx::query!(
        r#"
        DELETE FROM cli_login
        WHERE done_hash = $1 AND expires_at > now() AND user_id IS NOT NULL
        RETURNING user_id AS "user_id!", repository_id, hostname
        "#,
        done_hash,
    )
    .fetch_optional(pool)
    .await?
    {
        return Ok(CliLoginState::Approved {
            user_id: row.user_id,
            repository_id: row.repository_id,
            hostname: row.hostname,
        });
    }
    let pending = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM cli_login WHERE done_hash = $1 AND expires_at > now()
        ) AS "pending!"
        "#,
        done_hash,
    )
    .fetch_one(pool)
    .await?;
    Ok(if pending {
        CliLoginState::Pending
    } else {
        CliLoginState::Unknown
    })
}

/// Delete expired logins (the auth reaper). Returns how many.
pub async fn delete_expired(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(
        sqlx::query!(r#"DELETE FROM cli_login WHERE expires_at <= now()"#)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}
