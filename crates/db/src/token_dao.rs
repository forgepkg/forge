//! Data access for `token` (API access tokens).

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::model::Token;

/// All settable fields when creating a token row.
///
/// Only the **hash** of the token is stored; the plaintext is shown to the user
/// once at creation time and never persisted.
#[derive(Debug, Clone)]
pub struct NewToken {
    pub user_id: i64,
    pub name: String,
    pub token_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
    /// Minted from a session that credential forwarding established: revoked
    /// by [`revoke_forwarded_tokens_for_user`] (an admin-forced reauth).
    pub minted_with_forwarded_credential: bool,
}

/// Insert a token, returning the persisted row.
pub async fn insert_token(pool: &PgPool, new: NewToken) -> sqlx::Result<Token> {
    sqlx::query_as!(
        Token,
        r#"
        INSERT INTO token
            (user_id, name, token_hash, expires_at, minted_with_forwarded_credential)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING
            id, user_id, name, token_hash, expires_at, revoked_at,
            last_used_at, created_at, scope
        "#,
        new.user_id,
        new.name,
        new.token_hash,
        new.expires_at,
        new.minted_with_forwarded_credential,
    )
    .fetch_one(pool)
    .await
}

/// Find a token by its unique hash. Returns the row regardless of
/// expiry/revocation — the caller is responsible for validity checks.
pub async fn find_token_by_hash(pool: &PgPool, token_hash: &str) -> sqlx::Result<Option<Token>> {
    sqlx::query_as!(
        Token,
        r#"
        SELECT
            id, user_id, name, token_hash, expires_at, revoked_at,
            last_used_at, created_at, scope
        FROM token
        WHERE token_hash = $1
        "#,
        token_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Find a token by its primary key (used to enforce ownership before a
/// session-scoped revoke). Returns `None` if no such row exists.
pub async fn find_token_by_id(pool: &PgPool, id: i64) -> sqlx::Result<Option<Token>> {
    sqlx::query_as!(
        Token,
        r#"
        SELECT
            id, user_id, name, token_hash, expires_at, revoked_at,
            last_used_at, created_at, scope
        FROM token
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// List a user's tokens ordered by creation time (admin listing). Hashes are
/// included on the row but the admin layer never serializes them.
pub async fn list_tokens_for_user(pool: &PgPool, user_id: i64) -> sqlx::Result<Vec<Token>> {
    sqlx::query_as!(
        Token,
        r#"
        SELECT
            id, user_id, name, token_hash, expires_at, revoked_at,
            last_used_at, created_at, scope
        FROM token
        WHERE user_id = $1
        ORDER BY created_at
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
}

/// Mark a token revoked (`revoked_at = now()`) if not already revoked. Returns
/// whether a row was updated.
pub async fn revoke_token(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        UPDATE token
        SET revoked_at = now()
        WHERE id = $1 AND revoked_at IS NULL
        "#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Set (or clear) a token's per-token privilege `scope` jsonb (§12.4 Phase 6).
///
/// `scope = None` clears the column (the token then inherits its owner's full
/// effective set); `Some(value)` stores the raw jsonb (the caller validates its
/// shape against [`forge_core`'s `TokenScope`] before persisting). Only an
/// **unrevoked** token is updated — scoping a revoked token is a no-op. Returns
/// `true` iff a row was updated.
///
/// The token `scope` is read outside the per-user effective-set cache (the seam
/// loads it per request and intersects post-cache), so a scope change needs **no
/// cache invalidation** — the next request reads the new value directly.
pub async fn set_token_scope(
    pool: &PgPool,
    id: i64,
    scope: Option<&serde_json::Value>,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        UPDATE token
        SET scope = $2
        WHERE id = $1 AND revoked_at IS NULL
        "#,
        id,
        scope,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Update a token's `last_used_at` to `now()`.
pub async fn touch_last_used(pool: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE token
        SET last_used_at = now()
        WHERE id = $1
        "#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke every live token of `user_id` that was minted from a session
/// credential forwarding established (see [`NewToken`]). Returns how many
/// were revoked. Used by the admin-forced reauth: such a token must not
/// outlive the upstream verdict it was minted on.
pub async fn revoke_forwarded_tokens_for_user(pool: &PgPool, user_id: i64) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        r#"
        UPDATE token
        SET revoked_at = now()
        WHERE user_id = $1
          AND minted_with_forwarded_credential
          AND revoked_at IS NULL
        "#,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
