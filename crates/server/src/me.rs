//! `GET /admin/me` — the authenticated principal's identity + capability flags
//! (plan §12.6 Phase 0, §8).
//!
//! This endpoint is mounted **outside** the admin module's [`require_admin`]
//! gate: it is reachable by any *authenticated* user (admin or not) so the SPA
//! can decide which navigation/management screens to show. It still requires an
//! authenticated principal — an anonymous or unauthenticated caller gets `401`,
//! matching the plan's "401 if no/invalid principal" contract.
//!
//! ## Capabilities
//! Slice 1's authorization is binary (`is_admin`), so the capability list is
//! derived from `is_admin`:
//! * every authenticated user can read (`repo.read`);
//! * an admin additionally gets `repo.admin` / `user.admin` / `token.admin`.
//!
//! When §12.4 RBAC lands it refines this list without changing the route shape
//! or the SPA's consumption of it.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use forge_core::auth::principal::Principal;
use forge_db::user_dao;
use serde::Serialize;

use crate::admin::db_error;
use crate::middleware::principal_of;
use crate::state::AppState;

/// The authenticated user's identity as returned by `GET /admin/me`.
#[derive(Debug, Serialize)]
pub struct MeUser {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub active: bool,
}

/// `GET /admin/me` response body.
#[derive(Debug, Serialize)]
pub struct MeView {
    pub user: MeUser,
    pub is_admin: bool,
    pub capabilities: Vec<&'static str>,
}

/// Derive the capability list for a principal from its admin flag (Slice 1).
fn capabilities_for(is_admin: bool) -> Vec<&'static str> {
    if is_admin {
        vec!["repo.read", "repo.admin", "user.admin", "token.admin"]
    } else {
        vec!["repo.read"]
    }
}

/// Build the `/admin/me` router. Mounted at the top level (not under the admin
/// `require_admin` gate) so any authenticated user can call it; the principal
/// middleware still runs, and the handler rejects anonymous callers with 401.
pub fn me_router() -> Router<AppState> {
    Router::new().route("/admin/me", get(me))
}

/// `GET /admin/me` — identity + capabilities for the authenticated principal.
///
/// * `User` → 200 with the looked-up `app_user` row + capabilities.
/// * `Anonymous` / `Unauthenticated` → 401 (the SPA then routes to login).
pub async fn me(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let principal = principal_of(&req);
    let Principal::User { user_id, .. } = principal else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };

    // Resolve the live user row so the response reflects the current
    // username/admin/active state (a token's cached `is_admin` could be stale).
    match user_dao::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) => {
            let view = MeView {
                is_admin: u.is_admin,
                capabilities: capabilities_for(u.is_admin),
                user: MeUser {
                    id: u.id,
                    username: u.username,
                    is_admin: u.is_admin,
                    active: u.active,
                },
            };
            Json(view).into_response()
        }
        // A valid principal whose user row vanished (deleted mid-session): treat
        // as unauthenticated so the SPA re-authenticates.
        Ok(None) => (StatusCode::UNAUTHORIZED, "authentication required").into_response(),
        Err(e) => db_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_capabilities_superset_of_reader() {
        let reader = capabilities_for(false);
        let admin = capabilities_for(true);
        assert!(reader.contains(&"repo.read"));
        assert!(!reader.contains(&"repo.admin"));
        for cap in &reader {
            assert!(admin.contains(cap), "admin must include reader cap {cap}");
        }
        assert!(admin.contains(&"repo.admin"));
    }
}
