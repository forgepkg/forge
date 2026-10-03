//! Admin token management (plan 10.4).
//!
//! On issue, a fresh 256-bit secret is generated; the **plaintext is returned
//! once** in the create response and only its SHA-256 hash is persisted. Listing
//! never returns the hash or plaintext, but does return each token's `scope`.
//!
//! A token without a scope carries its owner's `read` / `write` / `delete`
//! reach but never `admin`: it cannot call `/admin/*`. A token meant for admin
//! automation must be issued with `"scope": {"actions": ["admin"]}` (no
//! `repositories` restriction); for an admin account that is a full admin
//! credential, including minting further tokens.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use forge_core::auth::token::{generate_token_secret, hash_token};
use forge_db::model::Token;
use forge_db::token_dao::{self, NewToken};
use forge_db::user_dao;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::db_error;
use crate::state::AppState;

/// Metadata view of a token (no secret, no hash).
#[derive(Debug, Serialize)]
pub struct TokenView {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// The token's privilege scope as stored (`{"actions": [...],
    /// "repositories": [...]}`), or `null` for an unscoped token, so a
    /// mistyped or missing scope is visible instead of silently unscoped.
    pub scope: Option<JsonValue>,
}

impl From<&Token> for TokenView {
    fn from(t: &Token) -> Self {
        TokenView {
            id: t.id,
            user_id: t.user_id,
            name: t.name.clone(),
            expires_at: t.expires_at,
            revoked_at: t.revoked_at,
            last_used_at: t.last_used_at,
            created_at: t.created_at,
            scope: t.scope.clone(),
        }
    }
}

/// Issue-token request. Unknown fields are rejected so a mistyped `scope` key
/// cannot silently issue an unscoped token.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateToken {
    pub name: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional per-token privilege scope (§12.4): a subset that **narrows** the
    /// owner's effective set (it can never widen it). Omit / `null` ⇒ the token
    /// inherits the owner's set **except `admin`**, which must be listed in
    /// `actions` explicitly. Unknown keys are rejected (400/422).
    #[serde(default)]
    pub scope: Option<forge_core::authz::TokenScope>,
}

/// Persist an issue request's optional `scope` on the freshly inserted token
/// and return the canonical jsonb that was stored (for the response view).
///
/// Validated by deserialization into `TokenScope`; re-serialized to the
/// canonical jsonb. A scope can only narrow at evaluation time, so no
/// validation against the owner's set is needed here. No cache invalidation:
/// the scope is read outside the per-user effective-set cache and intersected
/// per request. Shared by the admin and the self-service (`/admin/me/tokens`)
/// issue paths.
pub(crate) async fn store_scope(
    state: &AppState,
    token_id: i64,
    scope: Option<&forge_core::authz::TokenScope>,
) -> Result<Option<JsonValue>, Response> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    let value = serde_json::to_value(scope).map_err(|e| {
        tracing::error!(error = %e, "serializing token scope failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    })?;
    token_dao::set_token_scope(&state.pool, token_id, Some(&value))
        .await
        .map_err(db_error)?;
    Ok(Some(value))
}

/// Issue-token response — the only time the plaintext `token` is ever returned.
#[derive(Debug, Serialize)]
pub struct CreatedToken {
    #[serde(flatten)]
    pub view: TokenView,
    /// Plaintext secret — store it now; it cannot be retrieved again.
    pub token: String,
}

/// `GET /admin/users/{id}/tokens`
pub async fn list_for_user(State(state): State<AppState>, Path(user_id): Path<i64>) -> Response {
    match token_dao::list_tokens_for_user(&state.pool, user_id).await {
        Ok(tokens) => {
            let views: Vec<TokenView> = tokens.iter().map(TokenView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `POST /admin/users/{id}/tokens`
pub async fn create(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Json(body): Json<CreateToken>,
) -> Response {
    // Ensure the target user exists (FK would also catch it, but a clean 404 is
    // friendlier than a 500).
    match user_dao::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    }

    let secret = generate_token_secret();
    let token_hash = hash_token(&secret);
    let new = NewToken {
        user_id,
        name: body.name.clone(),
        token_hash,
        expires_at: body.expires_at,
    };
    let t = match token_dao::insert_token(&state.pool, new).await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    // Persist the optional per-token scope (§12.4).
    let scope = match store_scope(&state, t.id, body.scope.as_ref()).await {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    let mut view = TokenView::from(&t);
    view.scope = scope;
    let resp = CreatedToken {
        view,
        token: secret,
    };
    (StatusCode::CREATED, Json(resp)).into_response()
}

/// `DELETE /admin/tokens/{id}` — revoke (sets `revoked_at`).
pub async fn revoke(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match token_dao::revoke_token(&state.pool, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => {
            // Either unknown or already revoked; 404 keeps it idempotent-ish
            // while signaling nothing changed.
            (StatusCode::NOT_FOUND, "token not found or already revoked").into_response()
        }
        Err(e) => db_error(e),
    }
}
