//! Admin token management (plan 10.4).
//!
//! On issue, a fresh 256-bit secret is generated; the **plaintext is returned
//! once** in the create response and only its SHA-256 hash is persisted. Listing
//! never returns the hash or plaintext.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use forge_core::auth::token::{generate_token_secret, hash_token};
use forge_db::model::Token;
use forge_db::token_dao::{self, NewToken};
use forge_db::user_dao;
use serde::{Deserialize, Serialize};

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
        }
    }
}

/// Issue-token request.
#[derive(Debug, Deserialize)]
pub struct CreateToken {
    pub name: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional per-token privilege scope (§12.4): a subset that **narrows** the
    /// owner's effective set (it can never widen it). Omit / `null` ⇒ the token
    /// inherits the owner's full set.
    #[serde(default)]
    pub scope: Option<forge_core::authz::TokenScope>,
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

    // Persist the optional per-token scope (§12.4). Validated by deserialization
    // into `TokenScope`; re-serialized to the canonical jsonb. A scope can only
    // narrow at evaluation time, so no validation against the owner's set is
    // needed here. No cache invalidation: the scope is read outside the per-user
    // effective-set cache and intersected per request.
    if let Some(scope) = &body.scope {
        match serde_json::to_value(scope) {
            Ok(v) => {
                if let Err(e) = token_dao::set_token_scope(&state.pool, t.id, Some(&v)).await {
                    return db_error(e);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "serializing token scope failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
            }
        }
    }

    let resp = CreatedToken {
        view: TokenView::from(&t),
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
