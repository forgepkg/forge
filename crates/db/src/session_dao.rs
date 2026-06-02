//! Data access for `session` (server-side login sessions).
//!
//! The session row is the **authority**; the `forge_session` cookie is just an
//! opaque pointer. Only `sha256(cookie_secret)` is stored (`token_hash`),
//! mirroring the slice-1 `token.token_hash` model, so a DB read yields no usable
//! credential. A session is valid iff
//! `revoked_at IS NULL AND now() < idle_expiry AND now() < absolute_expiry`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::model::Session;

/// All settable fields when creating a session row.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub user_id: i64,
    /// Optional link to the `external_identity` this session was created from.
    pub external_identity_id: Option<i64>,
    /// `sha256(cookie_secret)` — never the plaintext.
    pub token_hash: String,
    /// Per-session double-submit CSRF secret.
    pub csrf_secret: String,
    /// Optional binding to detect cookie theft.
    pub user_agent_hash: Option<String>,
    /// `last_seen_at + idle_ttl`, refreshed (throttled) on use.
    pub idle_expiry: DateTime<Utc>,
    /// Hard cap regardless of activity (`created_at + absolute_ttl`).
    pub absolute_expiry: DateTime<Utc>,
}

/// Insert a session, returning the persisted row.
pub async fn create(pool: &PgPool, new: NewSession) -> sqlx::Result<Session> {
    sqlx::query_as!(
        Session,
        r#"
        INSERT INTO session (
            user_id, external_identity_id, token_hash, csrf_secret,
            user_agent_hash, idle_expiry, absolute_expiry
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING
            id, user_id, external_identity_id, token_hash, csrf_secret,
            user_agent_hash, created_at, last_seen_at, idle_expiry,
            absolute_expiry, revoked_at
        "#,
        new.user_id,
        new.external_identity_id,
        new.token_hash,
        new.csrf_secret,
        new.user_agent_hash,
        new.idle_expiry,
        new.absolute_expiry,
    )
    .fetch_one(pool)
    .await
}

/// Find a session by its `token_hash` **only if currently valid** (not revoked,
/// within both idle and absolute expiry). The validity predicate is enforced in
/// SQL so an expired/revoked session is indistinguishable from a missing one.
pub async fn find_valid_by_hash(pool: &PgPool, token_hash: &str) -> sqlx::Result<Option<Session>> {
    sqlx::query_as!(
        Session,
        r#"
        SELECT
            id, user_id, external_identity_id, token_hash, csrf_secret,
            user_agent_hash, created_at, last_seen_at, idle_expiry,
            absolute_expiry, revoked_at
        FROM session
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND now() < idle_expiry
          AND now() < absolute_expiry
        "#,
        token_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Refresh `last_seen_at`/`idle_expiry` for a session, but only if the existing
/// `last_seen_at` is older than `min_age_secs` (throttle to avoid a write per
/// request, like slice-1 `token.last_used_at`). The new `idle_expiry` is
/// `now() + idle_ttl_secs`. Returns whether a row was touched.
pub async fn touch_last_seen(
    pool: &PgPool,
    id: i64,
    min_age_secs: i64,
    idle_ttl_secs: i64,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        UPDATE session
        SET last_seen_at = now(),
            idle_expiry  = now() + make_interval(secs => $2)
        WHERE id = $1
          AND revoked_at IS NULL
          AND last_seen_at < now() - make_interval(secs => $3)
        "#,
        id,
        idle_ttl_secs as f64,
        min_age_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Mark a session revoked (`revoked_at = now()`) if not already revoked. Returns
/// whether a row was updated. Revocation is instant cluster-wide since the row
/// is the authority.
pub async fn revoke(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        UPDATE session
        SET revoked_at = now()
        WHERE id = $1 AND revoked_at IS NULL
        "#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Revoke all of a user's currently-active sessions (e.g. on privilege change or
/// admin action). Returns the number revoked.
pub async fn revoke_all_for_user(pool: &PgPool, user_id: i64) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        r#"
        UPDATE session
        SET revoked_at = now()
        WHERE user_id = $1 AND revoked_at IS NULL
        "#,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Delete sessions that are no longer usable — revoked, idle-expired, or
/// absolute-expired. Returns the number deleted. Pure `DELETE`; runs on any
/// instance.
pub async fn reap_expired(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        r#"
        DELETE FROM session
        WHERE revoked_at IS NOT NULL
           OR now() >= idle_expiry
           OR now() >= absolute_expiry
        "#,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
