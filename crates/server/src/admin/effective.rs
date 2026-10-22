//! Admin effective-set explain endpoint (§12.4 Phase 6).
//!
//! * `GET /admin/users/{id}/effective` — the resolved effective grant set for a
//!   user (admin flag + flat grant list), for support and the test matrix.
//! * `GET /admin/anonymous/effective`  — the effective set applied to anonymous
//!   callers (the built-in `anonymous` role's grants).
//!
//! This reads the **authoritative DB** directly (not the request cache), so it
//! always reflects the live grant state — exactly what makes it useful for
//! debugging a cache-vs-DB discrepancy. It does **not** apply per-token scoping
//! (that is per-token, not per-user).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_db::authz_dao::{self, EffectiveGrantRow, EffectiveRows};
use forge_db::user_dao;
use serde::Serialize;
use serde_json::Value as JsonValue;

use super::db_error;
use crate::state::AppState;

/// The computed effective set, as returned by the explain endpoint.
#[derive(Debug, Serialize)]
pub struct EffectiveView {
    /// Resolves to allow-all when `true` (`admin` role membership).
    pub is_admin: bool,
    /// The flat, additive union of the principal's grants.
    pub grants: Vec<GrantView>,
}

/// One grant in the effective view.
#[derive(Debug, Serialize)]
pub struct GrantView {
    pub action: String,
    pub repository_id: Option<i64>,
    pub selector_id: Option<i64>,
    pub includes: Option<JsonValue>,
    pub excludes: Option<JsonValue>,
}

impl From<EffectiveGrantRow> for GrantView {
    fn from(g: EffectiveGrantRow) -> Self {
        let (selector_id, includes, excludes) = match g.selector {
            Some(s) => (Some(s.id), Some(s.includes), Some(s.excludes)),
            None => (None, None, None),
        };
        GrantView {
            action: g.action,
            repository_id: g.repository_id,
            selector_id,
            includes,
            excludes,
        }
    }
}

fn view(rows: EffectiveRows) -> EffectiveView {
    EffectiveView {
        is_admin: rows.is_admin,
        grants: rows.grants.into_iter().map(GrantView::from).collect(),
    }
}

/// `GET /admin/users/{id}/effective`
pub async fn for_user(State(state): State<AppState>, Path(user_id): Path<i64>) -> Response {
    match user_dao::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    }

    match authz_dao::load_user_effective(&state.pool, user_id).await {
        Ok(rows) => Json(view(rows)).into_response(),
        Err(e) => db_error(e),
    }
}

/// `GET /admin/anonymous/effective`
pub async fn for_anonymous(State(state): State<AppState>) -> Response {
    match authz_dao::load_anonymous_effective(&state.pool).await {
        Ok(rows) => Json(view(rows)).into_response(),
        Err(e) => db_error(e),
    }
}
