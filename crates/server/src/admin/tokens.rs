//! Admin token management.
//!
//! On issue, a fresh 256-bit secret is generated; the **plaintext is returned
//! once** in the create response and only its SHA-256 hash is persisted. Listing
//! never returns the hash or plaintext, but does return each token's `scope`.
//!
//! A token without a scope carries its owner's levels (`read`, `write`,
//! `delete`) but never `admin`: it cannot call `/admin/*`. A token meant for
//! admin automation must be issued with `"scope": {"admin": true}` (no
//! `repositories` restriction); for an admin account that is a full admin
//! credential, including minting further tokens.

use axum::extract::rejection::JsonRejection;
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

use super::{db_error, json_rejection};
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
    /// The token's privilege scope as stored (`{"level": "...", "admin":
    /// true, "repositories": [...]}`), or `null` for an unscoped token, so a
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
    /// Optional per-token privilege scope: a subset that **narrows** the
    /// owner's effective set (it can never widen it). Omit / `null` ⇒ the token
    /// inherits the owner's set **except `admin`**, which needs `"admin":
    /// true`. Unknown keys are rejected with 400, `actions` with a message
    /// naming `level`.
    #[serde(default)]
    pub scope: Option<forge_core::authz::TokenScope>,
}

pub(crate) fn validate_expiry(expires_at: Option<DateTime<Utc>>) -> Result<(), Response> {
    if expires_at.is_some_and(|expires_at| expires_at <= Utc::now()) {
        return Err((StatusCode::BAD_REQUEST, "expires_at must be in the future").into_response());
    }
    Ok(())
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

/// The audit line of a token a user minted for themselves from a signed-in
/// session (`/admin/me/tokens`, `/auth/tokens`), like the tokens a client
/// login mints (`crate::cli_auth`). The admin API's own mints are logged by
/// its audit trail (`crate::admin::require_admin`). Never the secret, nor the
/// name the user chose: the token's id names it.
pub(crate) fn audit_self_service_mint(token: &Token, scope: Option<&JsonValue>) {
    tracing::info!(
        target: "forge::audit",
        user_id = token.user_id,
        token_id = token.id,
        expires_at = ?token.expires_at,
        scope = %scope.map(JsonValue::to_string).unwrap_or_default(),
        "token minted in the web UI"
    );
}

/// The audit line of a token a user revoked from a signed-in session.
pub(crate) fn audit_self_service_revoke(user_id: i64, token_id: i64) {
    tracing::info!(
        target: "forge::audit",
        user_id,
        token_id,
        "token revoked in the web UI"
    );
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
    body: Result<Json<CreateToken>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection(rejection),
    };
    if let Err(response) = validate_expiry(body.expires_at) {
        return response;
    }
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
        minted_with_forwarded_credential: false,
    };
    let t = match token_dao::insert_token(&state.pool, new).await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    // Persist the optional per-token scope.
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Collects what a `fmt` subscriber writes.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The lines `log` writes under `forge::audit`.
    fn audit_lines(log: impl FnOnce()) -> String {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .with_env_filter("off,forge::audit=info")
            .finish();
        tracing::subscriber::with_default(subscriber, log);
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn a_self_service_mint_and_revoke_are_audited_without_the_token_name() {
        let now = Utc::now();
        let token = Token {
            id: 41,
            user_id: 7,
            name: "laptop-of-alice".into(),
            token_hash: "hash-never-logged".into(),
            expires_at: Some(now),
            revoked_at: None,
            last_used_at: None,
            created_at: now,
            scope: None,
        };
        let scope = serde_json::json!({"level": "read", "repositories": [3]});
        let minted = audit_lines(|| audit_self_service_mint(&token, Some(&scope)));
        assert!(minted.contains("token minted in the web UI"), "{minted}");
        assert!(minted.contains("user_id=7"), "{minted}");
        assert!(minted.contains("token_id=41"), "{minted}");
        assert!(minted.contains(r#""repositories":[3]"#), "{minted}");
        assert!(!minted.contains("laptop-of-alice"), "{minted}");
        assert!(!minted.contains("hash-never-logged"), "{minted}");

        let revoked = audit_lines(|| audit_self_service_revoke(7, 41));
        assert!(revoked.contains("token revoked in the web UI"), "{revoked}");
        assert!(revoked.contains("user_id=7 token_id=41"), "{revoked}");
    }
}
