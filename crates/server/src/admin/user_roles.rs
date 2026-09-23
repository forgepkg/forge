//! Admin user-role assignment (§12.4 Phase 6).
//!
//! * `GET    /admin/users/{id}/roles` — list the roles a user holds.
//! * `PUT    /admin/users/{id}/roles` — assign a role (idempotent).
//! * `DELETE /admin/users/{id}/roles/{role_id}` — unassign a role.
//!
//! A `user_role` change affects exactly one principal, so it uses **targeted**
//! cache invalidation ([`invalidate_user`]) rather than the epoch roll — cheaper
//! and just as correct.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::authz::invalidate_user;
use forge_db::authz_dao::{self, Role};
use forge_db::user_dao;
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::state::AppState;

/// A role view (same shape as [`super::roles::RoleView`]).
#[derive(Debug, Serialize)]
pub struct RoleView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub builtin: bool,
}

impl From<Role> for RoleView {
    fn from(r: Role) -> Self {
        RoleView {
            id: r.id,
            name: r.name,
            description: r.description,
            builtin: r.builtin,
        }
    }
}

/// Assign-role request. The role is identified by **name** (a stable,
/// human-meaningful identifier) or by `role_id`; at least one is required.
#[derive(Debug, Deserialize)]
pub struct AssignRole {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub role_id: Option<i64>,
}

/// `GET /admin/users/{id}/roles`
pub async fn list(State(state): State<AppState>, Path(user_id): Path<i64>) -> Response {
    match user_dao::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    }
    match authz_dao::list_roles_for_user(&state.pool, user_id).await {
        Ok(roles) => {
            let views: Vec<RoleView> = roles.into_iter().map(RoleView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `PUT /admin/users/{id}/roles`
pub async fn assign(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Json(body): Json<AssignRole>,
) -> Response {
    match user_dao::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    }

    let role_id = match resolve_role_id(&state, &body.role, body.role_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if let Err(e) = authz_dao::assign_role(&state.pool, user_id, role_id).await {
        return db_error(e);
    }
    let result = sync_legacy_admin_flag(&state, user_id, role_id, true).await;
    invalidate_user(&state.cache, user_id).await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/users/{id}/roles/{role_id}`
pub async fn unassign(
    State(state): State<AppState>,
    Path((user_id, role_id)): Path<(i64, i64)>,
) -> Response {
    // Clear the legacy flag first: while `app_user.is_admin` is set the user
    // stays a global admin through the dual-read fallback, so removing only the
    // role would silently leave the admin rights in place.
    if let Err(e) = sync_legacy_admin_flag(&state, user_id, role_id, false).await {
        return db_error(e);
    }
    let result = authz_dao::unassign_role(&state.pool, user_id, role_id).await;
    invalidate_user(&state.cache, user_id).await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(e),
    }
}

/// Keep the slice-1 `app_user.is_admin` column in step with membership of the
/// built-in `admin` role. The authz seam still honors the column as a
/// dual-read fallback, so the role alone cannot revoke admin: an unassign that
/// left the flag set would be a no-op. A no-op for any other role, or for a
/// user that no longer exists.
async fn sync_legacy_admin_flag(
    state: &AppState,
    user_id: i64,
    role_id: i64,
    is_admin: bool,
) -> sqlx::Result<()> {
    if authz_dao::role_id_by_name(&state.pool, authz_dao::ADMIN_ROLE).await? != Some(role_id) {
        return Ok(());
    }
    match user_dao::update_is_admin(&state.pool, user_id, is_admin).await {
        Ok(_) | Err(sqlx::Error::RowNotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Resolve `(role, role_id)` to a concrete role id, returning a 400/404 response
/// on a missing/unknown role.
async fn resolve_role_id(
    state: &AppState,
    role_name: &Option<String>,
    role_id: Option<i64>,
) -> Result<i64, Response> {
    if let Some(id) = role_id {
        match authz_dao::find_role_by_id(&state.pool, id).await {
            Ok(Some(_)) => return Ok(id),
            Ok(None) => return Err((StatusCode::NOT_FOUND, "role not found").into_response()),
            Err(e) => return Err(db_error(e)),
        }
    }
    if let Some(name) = role_name {
        match authz_dao::role_id_by_name(&state.pool, name).await {
            Ok(Some(id)) => return Ok(id),
            Ok(None) => return Err((StatusCode::NOT_FOUND, "role not found").into_response()),
            Err(e) => return Err(db_error(e)),
        }
    }
    Err((StatusCode::BAD_REQUEST, "role or role_id is required").into_response())
}
