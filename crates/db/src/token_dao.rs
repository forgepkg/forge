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
}

/// Insert a token, returning the persisted row.
pub async fn insert_token(pool: &PgPool, new: NewToken) -> sqlx::Result<Token> {
    sqlx::query_as!(
        Token,
        r#"
        INSERT INTO token (user_id, name, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING
            id, user_id, name, token_hash, expires_at, revoked_at,
            last_used_at, created_at
        "#,
        new.user_id,
        new.name,
        new.token_hash,
        new.expires_at,
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
            last_used_at, created_at
        FROM token
        WHERE token_hash = $1
        "#,
        token_hash,
    )
    .fetch_optional(pool)
    .await
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
