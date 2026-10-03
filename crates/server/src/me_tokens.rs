//! Self-service token management: `/admin/me/tokens`.
//!
//! Any signed-in user can mint, list, and revoke **their own** registry tokens
//! here (the admin-only `/admin/users/{id}/tokens` surface stays for managing
//! other users' tokens). Mounted **outside** the admin `require_admin` gate,
//! next to `/admin/me`.
//!
//! Security model:
//! * Tokens are credentials for the package feed / API — they are **not** a way
//!   to sign in to the UI, and a token must not be able to mint further tokens
//!   (otherwise revoking one would not cut off access). Every route here
//!   therefore requires a **browser session** ([`AuthMethod::Session`]):
//!   token-authenticated callers get 403, and so does a password sent over
//!   HTTP Basic — a password that NuGet clients store and replay on every feed
//!   request must not be able to mint long-lived credentials.
//! * Cookie-authenticated mutations are CSRF-checked by the principal
//!   middleware (`X-CSRF-Token`); `POST` also requires a JSON content type.
//! * Reuses the admin token DTOs: the plaintext secret is returned exactly once
//!   from `POST`, listing returns metadata (including each token's `scope`)
//!   only, and an optional scope can only narrow the owner's privileges. An
//!   unknown scope key (e.g. a mistyped `repos`) is a 400, never an unscoped
//!   token. Without a scope the token carries no `admin` reach.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use forge_core::auth::principal::{AuthMethod, Principal};
use forge_core::auth::token::{generate_token_secret, hash_token};
use forge_db::token_dao::{self, NewToken};
use forge_db::user_dao;

use crate::admin::db_error;
use crate::admin::tokens::{store_scope, CreateToken, CreatedToken, TokenView};
use crate::middleware::principal_of;
use crate::state::AppState;

/// Resolve the calling user id, enforcing the "browser session only" rule.
/// Returns the user id or the (boxed, to keep the `Err` variant small) error
/// response to send.
fn session_user_of<B>(req: &axum::http::Request<B>) -> Result<i64, Box<Response>> {
    match principal_of(req) {
        Principal::User {
            user_id,
            method: AuthMethod::Session,
            ..
        } => Ok(user_id),
        Principal::User {
            method: AuthMethod::Token,
            ..
        } => Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "tokens cannot manage tokens; sign in with your password or identity provider",
            )
                .into_response(),
        )),
        Principal::User {
            method: AuthMethod::Password,
            ..
        } => Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "tokens are managed from a signed-in session; a password sent over HTTP Basic cannot mint them",
            )
                .into_response(),
        )),
        _ => Err(Box::new(
            (StatusCode::UNAUTHORIZED, "authentication required").into_response(),
        )),
    }
}

/// `GET /admin/me/tokens` — the caller's own tokens (metadata only).
pub async fn list(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let user_id = match session_user_of(&req) {
        Ok(id) => id,
        Err(denied) => return *denied,
    };
    match token_dao::list_tokens_for_user(&state.pool, user_id).await {
        Ok(tokens) => {
            let views: Vec<TokenView> = tokens.iter().map(TokenView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `POST /admin/me/tokens` — mint a token for the caller. The plaintext is
/// returned once; only its hash is stored.
pub async fn create(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let user_id = match session_user_of(&req) {
        Ok(id) => id,
        Err(denied) => return *denied,
    };

    // Manual body extraction: the principal check above needs the full request,
    // and axum's `Json` extractor cannot run after `Request` is consumed by
    // value in the signature, so deserialize here — enforcing the same
    // `Content-Type: application/json` the extractor would (no form posts).
    if !is_json_request(req.headers()) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected Content-Type: application/json",
        )
            .into_response();
    }
    let bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid body").into_response(),
    };
    let body: CreateToken = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid body: {e}")).into_response(),
    };

    // A session of an upstream-basic account was established by credential
    // forwarding: such a token must not outlive an admin-forced reauth.
    let forwarded = match user_dao::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(user)) => user.auth_source == "upstream-basic",
        Ok(None) => return (StatusCode::UNAUTHORIZED, "authentication required").into_response(),
        Err(e) => return db_error(e),
    };
    let secret = generate_token_secret();
    let token_hash = hash_token(&secret);
    let new = NewToken {
        user_id,
        name: body.name.clone(),
        token_hash,
        expires_at: body.expires_at,
        minted_with_forwarded_credential: forwarded,
    };
    let t = match token_dao::insert_token(&state.pool, new).await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    // Optional per-token scope (§12.4): evaluated as an intersection with the
    // owner's effective set, so it can only narrow — safe for self-service.
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

/// Whether the request declares a JSON body (`application/json`, optionally
/// with parameters such as `charset`).
fn is_json_request(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
}

/// `DELETE /admin/me/tokens/{id}` — revoke one of the caller's own tokens.
/// Another user's token id answers 404 (not 403) to avoid confirming it exists.
pub async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let user_id = match session_user_of(&req) {
        Ok(id) => id,
        Err(denied) => return *denied,
    };
    match token_dao::find_token_by_id(&state.pool, id).await {
        Ok(Some(t)) if t.user_id == user_id => {}
        Ok(_) => return (StatusCode::NOT_FOUND, "token not found").into_response(),
        Err(e) => return db_error(e),
    }
    match token_dao::revoke_token(&state.pool, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "token not found or already revoked").into_response(),
        Err(e) => db_error(e),
    }
}

/// Build the `/admin/me/tokens` router (mounted at the top level, outside the
/// admin gate; each handler enforces the session-principal rule itself).
pub fn me_tokens_router() -> Router<AppState> {
    Router::new()
        .route("/admin/me/tokens", get(list).post(create))
        .route("/admin/me/tokens/{id}", axum::routing::delete(revoke))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap, HeaderValue};

    #[test]
    fn json_content_type_is_required() {
        let mut h = HeaderMap::new();
        assert!(!is_json_request(&h), "missing");
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!is_json_request(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        assert!(!is_json_request(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(is_json_request(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );
        assert!(is_json_request(&h));
    }
}
