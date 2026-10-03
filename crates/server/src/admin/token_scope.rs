//! Admin per-token privilege scoping (§12.4 Phase 6).
//!
//! `PATCH /admin/tokens/{id}/scope` sets (or clears) a token's `scope` jsonb. A
//! scope can only ever **narrow** its owner's effective set; the intersection is
//! computed live at request time (see [`forge_core::auth::authz`]), so a scope
//! that names an action/repo the owner lacks simply contributes nothing — it can
//! never widen. We still validate the JSON shape here (a malformed scope would
//! fail-closed at evaluation, denying the token everything — better to reject the
//! write with a 400).
//!
//! The token `scope` is read **outside** the per-user effective-set cache (the
//! seam loads it per request and intersects after the cache lookup), so a scope
//! change needs **no cache invalidation**: the next request reads the new value.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::authz::TokenScope;
use forge_db::token_dao;
use serde::Deserialize;

use super::db_error;
use crate::state::AppState;

/// Set-scope request. `scope = null` (or omitted) **clears** the scope (the
/// token then inherits its owner's effective set **without `admin`**); a
/// present object is validated against [`TokenScope`] (which rejects unknown
/// keys) before persisting. Unknown top-level keys are rejected too, so a
/// mistyped `"scop"` cannot clear the scope by accident.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetScope {
    #[serde(default)]
    pub scope: Option<TokenScope>,
}

/// `PATCH /admin/tokens/{id}/scope`
pub async fn set(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<SetScope>,
) -> Response {
    // Re-serialize the validated scope to the canonical jsonb we store; `None`
    // clears the column.
    let scope_json = match &body.scope {
        None => None,
        Some(scope) => match serde_json::to_value(scope) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::error!(error = %e, "serializing token scope failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
            }
        },
    };

    match token_dao::set_token_scope(&state.pool, id, scope_json.as_ref()).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        // Unknown id or the token is revoked (a revoked token's scope is moot).
        Ok(false) => (StatusCode::NOT_FOUND, "token not found or revoked").into_response(),
        Err(e) => db_error(e),
    }
}
