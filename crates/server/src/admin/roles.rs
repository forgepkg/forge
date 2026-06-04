//! Admin role management (§12.4 Phase 6).
//!
//! Roles are named, assignable bundles of grants. This module CRUDs the `role`
//! table; grants are managed by [`super::grants`] and assignments by
//! [`super::user_roles`].
//!
//! Built-in protections (plan §3, §6 "Builtin-role tampering"):
//! * **DELETE** of a built-in role (`admin`/`authenticated`/`anonymous`) is
//!   forbidden (**403**).
//! * **PATCH** may edit a built-in role's `description` but never its identity
//!   (`name`/`builtin` are immutable for every role).
//!
//! Every mutation blanket-invalidates the authz cache (epoch roll) after the
//! transaction commits, because a role's grants can affect many principals.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::authz::invalidate_all;
use forge_db::authz_dao::{self, Role};
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::state::AppState;

/// A role view.
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

/// Create-role request. `name` must be a non-empty url-safe slug.
#[derive(Debug, Deserialize)]
pub struct CreateRole {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// Update-role request (only `description` is mutable).
#[derive(Debug, Deserialize)]
pub struct UpdateRole {
    pub description: String,
}

/// `GET /admin/roles`
pub async fn list(State(state): State<AppState>) -> Response {
    match authz_dao::list_roles(&state.pool).await {
        Ok(roles) => {
            let views: Vec<RoleView> = roles.into_iter().map(RoleView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `GET /admin/roles/{id}`
pub async fn get(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match authz_dao::find_role_by_id(&state.pool, id).await {
        Ok(Some(r)) => Json(RoleView::from(r)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "role not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/roles`
pub async fn create(State(state): State<AppState>, Json(body): Json<CreateRole>) -> Response {
    let name = body.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "role name is required").into_response();
    }
    match authz_dao::insert_role(&state.pool, name, &body.description).await {
        Ok(r) => {
            // A brand-new role holds no grants and is assigned to no user, so no
            // cached set can reference it yet; invalidate defensively anyway so a
            // name reused within a TTL window cannot serve a stale decision.
            invalidate_all(&state.cache).await;
            (StatusCode::CREATED, Json(RoleView::from(r))).into_response()
        }
        Err(e) if is_unique_violation(&e) => {
            (StatusCode::CONFLICT, "role name already exists").into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `PATCH /admin/roles/{id}` — edit description (allowed for builtin roles too;
/// only `name`/`builtin` are immutable).
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateRole>,
) -> Response {
    match authz_dao::update_role_description(&state.pool, id, &body.description).await {
        Ok(Some(r)) => {
            invalidate_all(&state.cache).await;
            Json(RoleView::from(r)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "role not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/roles/{id}` — forbidden for built-in roles.
pub async fn delete(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    // Look up first so we can give a precise 403 for a builtin vs 404 for absent.
    match authz_dao::find_role_by_id(&state.pool, id).await {
        Ok(Some(r)) if r.builtin => {
            return (StatusCode::FORBIDDEN, "built-in roles cannot be deleted").into_response();
        }
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "role not found").into_response(),
        Err(e) => return db_error(e),
    }

    match authz_dao::delete_role(&state.pool, id).await {
        Ok(true) => {
            // Grants + user assignments cascade; many principals may be affected.
            invalidate_all(&state.cache).await;
            StatusCode::NO_CONTENT.into_response()
        }
        // Raced with another delete, or the row was a builtin (defense in depth).
        Ok(false) => (StatusCode::NOT_FOUND, "role not found").into_response(),
        Err(e) => db_error(e),
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
