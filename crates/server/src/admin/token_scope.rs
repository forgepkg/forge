//! Admin per-token privilege scoping.
//!
//! `PATCH /admin/tokens/{id}/scope` sets (or, on an explicit `null`, clears) a
//! token's `scope` jsonb: `{"level": "read" | "write" | "delete", "admin":
//! true, "repositories": [<id>, ...]}`, every key optional. A scope can only
//! ever **narrow** its owner's effective set; the intersection is computed
//! live at request time (see [`forge_core::auth::authz`]), so a scope that
//! names a level or repo the owner lacks simply contributes nothing — it can
//! never widen. We still validate the JSON shape here (a malformed scope would
//! fail-closed at evaluation, denying the token everything — better to reject
//! the write with a 400). `actions`, which `level` and `admin` replaced, is
//! refused with a 400 naming them.
//!
//! A group in `repositories` reaches only the members also listed: reading a
//! group never grants read on its members, so a token scoped to the group
//! alone sees an empty feed.
//!
//! The token `scope` is read **outside** the per-user effective-set cache (the
//! seam loads it per request and intersects after the cache lookup), so a scope
//! change needs **no cache invalidation**: the next request reads the new value.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::authz::TokenScope;
use forge_db::token_dao;
use serde::Deserialize;

use super::{db_error, double_option, json_rejection};
use crate::state::AppState;

/// Set-scope request. The `scope` key is required: an object sets the scope
/// (validated against [`TokenScope`], which rejects unknown keys, before
/// persisting) and an explicit `"scope": null` **clears** it (the token then
/// inherits its owner's effective set **without `admin`**). A body without the
/// key (`{}`) is refused with 400 rather than read as "clear", because clearing
/// widens the token. Unknown top-level keys are rejected too, so a mistyped
/// `"scop"` cannot pass for a missing key either.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetScope {
    /// Absent = refused, `null` = clear, object = set.
    #[serde(default, deserialize_with = "double_option")]
    pub scope: Option<Option<TokenScope>>,
}

/// `PATCH /admin/tokens/{id}/scope`
pub async fn set(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    body: Result<Json<SetScope>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection(rejection),
    };
    let Some(scope) = body.scope else {
        return (
            StatusCode::BAD_REQUEST,
            "scope is required (expected {\"scope\": {...}}, or {\"scope\": null} to clear it)",
        )
            .into_response();
    };
    // Re-serialize the validated scope to the canonical jsonb we store; `None`
    // clears the column.
    let scope_json = match &scope {
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
