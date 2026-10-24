//! `GET /admin/me` — the authenticated principal's identity + capability flags.
//!
//! This endpoint is mounted **outside** the admin module's [`require_admin`]
//! gate: it is reachable by any *authenticated* user (admin or not) so the SPA
//! can decide which navigation/management screens to show. It still requires an
//! authenticated principal — an anonymous or unauthenticated caller gets `401`.
//!
//! ## Capabilities
//! `is_admin` and the capability list come from the **effective RBAC** verdict
//! ([`forge_core::auth::authz::Authz::is_global_admin`]: the built-in `admin`
//! role) for the calling principal — the same check the admin API's `require_admin` gate uses, so the
//! SPA never hides screens from an RBAC admin nor shows them to a demoted one.
//! A token-scoped principal reports what that token may do.
//! * every authenticated user can read (`repo.read`);
//! * a principal that may publish to every repository (the built-in `writer`
//!   role, or any unscoped `write` or `delete` grant on every repository) gets
//!   `repo.write`, so the SPA can show push instructions;
//! * an admin additionally gets `repo.admin` / `user.admin` / `token.admin`
//!   (and `repo.write`).

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

/// Derive the capability list for a principal from its effective admin
/// verdict and whether it may write to every repository.
fn capabilities_for(is_admin: bool, writes_everywhere: bool) -> Vec<&'static str> {
    if is_admin {
        vec![
            "repo.read",
            "repo.write",
            "repo.admin",
            "user.admin",
            "token.admin",
        ]
    } else if writes_everywhere {
        vec!["repo.read", "repo.write"]
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
    // username/active state, and the effective RBAC verdict (not the legacy
    // column) for admin.
    match user_dao::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) => {
            let is_admin = state.authz.is_global_admin(&principal).await;
            let writes_everywhere = state.authz.can_write_every_repository(&principal).await;
            let view = MeView {
                is_admin,
                capabilities: capabilities_for(is_admin, writes_everywhere),
                user: MeUser {
                    id: u.id,
                    username: u.username,
                    is_admin,
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
        let reader = capabilities_for(false, false);
        let admin = capabilities_for(true, true);
        assert!(reader.contains(&"repo.read"));
        assert!(!reader.contains(&"repo.admin"));
        for cap in &reader {
            assert!(admin.contains(cap), "admin must include reader cap {cap}");
        }
        assert!(admin.contains(&"repo.admin"));
    }

    #[test]
    fn writers_get_repo_write_but_no_administration() {
        let writer = capabilities_for(false, true);
        assert_eq!(writer, vec!["repo.read", "repo.write"]);
        assert!(capabilities_for(true, false).contains(&"repo.write"));
        assert!(!capabilities_for(false, false).contains(&"repo.write"));
    }
}
