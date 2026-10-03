//! `login_known_network`: the networks a username signed in from, which the
//! login throttle exempts from that username's soft backoff (see
//! `forge_core::auth::login_throttle`). Shared by every instance and kept
//! across restarts.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Record a successful sign-in of `username_sha256` from `network` at `at`
/// (an earlier timestamp never replaces a later one).
pub async fn remember(
    pool: &PgPool,
    username_sha256: &[u8],
    network: &str,
    at: DateTime<Utc>,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO login_known_network (username_sha256, network, last_success_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (username_sha256, network) DO UPDATE
        SET last_success_at = GREATEST(login_known_network.last_success_at, EXCLUDED.last_success_at)
        "#,
        username_sha256,
        network,
        at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// The networks `username_sha256` signed in from since `since`, most recent
/// first, at most `limit`.
pub async fn recent(
    pool: &PgPool,
    username_sha256: &[u8],
    since: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<(String, DateTime<Utc>)>> {
    let rows = sqlx::query!(
        r#"
        SELECT network, last_success_at
        FROM login_known_network
        WHERE username_sha256 = $1 AND last_success_at >= $2
        ORDER BY last_success_at DESC
        LIMIT $3
        "#,
        username_sha256,
        since,
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.network, r.last_success_at))
        .collect())
}

/// Delete up to `limit` rows last used before `before`; returns how many.
pub async fn prune(pool: &PgPool, before: DateTime<Utc>, limit: i64) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        r#"
        DELETE FROM login_known_network
        WHERE ctid = ANY(ARRAY(
            SELECT ctid FROM login_known_network
            WHERE last_success_at < $1
            LIMIT $2
        ))
        "#,
        before,
        limit,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
