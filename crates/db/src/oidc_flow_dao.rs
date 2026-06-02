//! Data access for `oidc_flow` (ephemeral authorization-code-flow state).
//!
//! This table is the crux of multi-instance correctness: `state`, `nonce`, the
//! PKCE verifier, and the post-login redirect target all live in Postgres, so a
//! callback can be completed by a **different** instance than the one that began
//! the login. Rows are **single-use** — [`consume`] runs `DELETE ... RETURNING`,
//! which is naturally race-safe (only one `DELETE` returns the row) and blocks
//! replay of a once-used `state`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::model::OidcFlow;

/// All settable fields when beginning a login flow.
#[derive(Debug, Clone)]
pub struct NewOidcFlow {
    /// CSPRNG `state` — also the OAuth `state` param the IdP echoes back. PK.
    pub state: String,
    /// CSPRNG `nonce` — checked against the ID token's `nonce` claim.
    pub nonce: String,
    /// PKCE `code_verifier` (S256) — sent verbatim to the token endpoint.
    pub pkce_verifier: String,
    /// Validated post-login relative redirect path.
    pub redirect_to: String,
    /// Short absolute expiry (e.g. `now() + 10min`).
    pub expires_at: DateTime<Utc>,
}

/// Insert a flow row, returning the persisted row.
pub async fn begin(pool: &PgPool, new: NewOidcFlow) -> sqlx::Result<OidcFlow> {
    sqlx::query_as!(
        OidcFlow,
        r#"
        INSERT INTO oidc_flow (state, nonce, pkce_verifier, redirect_to, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING state, nonce, pkce_verifier, redirect_to, created_at, expires_at
        "#,
        new.state,
        new.nonce,
        new.pkce_verifier,
        new.redirect_to,
        new.expires_at,
    )
    .fetch_one(pool)
    .await
}

/// Atomically consume a flow row by `state`, returning it iff it exists and has
/// not expired. Single-use: a second call for the same `state` returns `None`
/// (the row was already deleted). Expired rows return `None` and are removed.
///
/// The `DELETE ... RETURNING` is race-safe across instances — under concurrent
/// duplicate callbacks only one wins and gets the row; the others get `None`.
pub async fn consume(pool: &PgPool, state: &str) -> sqlx::Result<Option<OidcFlow>> {
    sqlx::query_as!(
        OidcFlow,
        r#"
        DELETE FROM oidc_flow
        WHERE state = $1 AND expires_at > now()
        RETURNING state, nonce, pkce_verifier, redirect_to, created_at, expires_at
        "#,
        state,
    )
    .fetch_optional(pool)
    .await
}

/// Delete all expired flow rows. Returns the number deleted. Safe to run on any
/// instance (a pure `DELETE`, no locking needed).
pub async fn reap_expired(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        r#"
        DELETE FROM oidc_flow
        WHERE expires_at <= now()
        "#,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
