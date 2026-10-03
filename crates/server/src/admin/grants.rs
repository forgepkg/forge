//! Admin grant management (§12.4 Phase 6): the `repository_privilege` edges that
//! give a role `<action>` on `<repo|ANY>`, optionally scoped by a content
//! selector.
//!
//! * `GET    /admin/roles/{id}/grants` — list a role's grants.
//! * `PUT    /admin/roles/{id}/grants` — add a grant (idempotent).
//! * `DELETE /admin/roles/{id}/grants/{grant_id}` — remove a grant.
//!
//! A grant is `(repository|ANY, action, selector?)`:
//! * `repository` omitted/`null` ⇒ **ANY** repo (wildcard grant).
//! * `action` is one of `read`/`write`/`delete`/`admin` (validated against the
//!   pure [`Action`] parser so an unknown verb is a 400, never a silent widen).
//! * `selector_id` optionally narrows the grant to packages matching a content
//!   selector. The repo-level gate ignores the selector; it only filters which
//!   packages are visible.
//!
//! Every mutation blanket-invalidates the authz cache (epoch roll) after commit:
//! a grant change can affect every principal holding the role.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::authz::{invalidate_all, Action};
use forge_db::authz_dao::{self, GrantRow};
use forge_db::repository_dao;
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::state::AppState;

/// A grant view. `repository_id` is `null` for an ANY-repo grant.
#[derive(Debug, Serialize)]
pub struct GrantView {
    pub id: i64,
    pub role_id: i64,
    pub repository_id: Option<i64>,
    pub action: String,
    pub selector_id: Option<i64>,
}

impl From<GrantRow> for GrantView {
    fn from(g: GrantRow) -> Self {
        GrantView {
            id: g.id,
            role_id: g.role_id,
            repository_id: g.repository_id,
            action: g.action,
            selector_id: g.selector_id,
        }
    }
}

/// Add-grant request. Unknown fields are rejected: a mistyped field silently
/// ignored would leave `repository` absent, which means *every* repository.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddGrant {
    /// Repository **name**; omit / `null` (and no `repository_id`) for an
    /// ANY-repo (wildcard) grant.
    #[serde(default)]
    pub repository: Option<String>,
    /// Repository id, as [`GrantView`] lists it (an alternative to
    /// `repository`; give at most one).
    #[serde(default)]
    pub repository_id: Option<i64>,
    /// Action verb: `read` / `write` / `delete` / `admin`.
    pub action: String,
    /// Optional content-selector id to scope the grant.
    #[serde(default)]
    pub selector_id: Option<i64>,
}

/// `GET /admin/roles/{id}/grants`
pub async fn list(State(state): State<AppState>, Path(role_id): Path<i64>) -> Response {
    // 404 if the role itself is unknown, so the caller can tell "no grants" from
    // "no such role".
    match authz_dao::find_role_by_id(&state.pool, role_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "role not found").into_response(),
        Err(e) => return db_error(e),
    }
    match authz_dao::list_grants_for_role(&state.pool, role_id).await {
        Ok(grants) => {
            let views: Vec<GrantView> = grants.into_iter().map(GrantView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `PUT /admin/roles/{id}/grants`
pub async fn add(
    State(state): State<AppState>,
    Path(role_id): Path<i64>,
    Json(body): Json<AddGrant>,
) -> Response {
    // Validate the action verb up front (unknown ⇒ 400, never persisted).
    let action = match Action::parse(&body.action) {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "action must be one of read/write/delete/admin",
            )
                .into_response();
        }
    };

    // The role must exist.
    match authz_dao::find_role_by_id(&state.pool, role_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "role not found").into_response(),
        Err(e) => return db_error(e),
    }

    // Resolve the optional repository (name or id) → id (neither ⇒ ANY).
    let repository_id = match (&body.repository, body.repository_id) {
        (Some(_), Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                "give either repository or repository_id, not both",
            )
                .into_response();
        }
        (None, None) => None,
        (Some(name), None) => {
            match repository_dao::find_repository_by_name(&state.pool, name).await {
                Ok(Some(r)) => Some(r.id),
                Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
                Err(e) => return db_error(e),
            }
        }
        (None, Some(id)) => match repository_dao::find_repository_by_id(&state.pool, id).await {
            Ok(Some(r)) => Some(r.id),
            Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
            Err(e) => return db_error(e),
        },
    };

    // Validate the optional selector id exists.
    if let Some(sel_id) = body.selector_id {
        match authz_dao::find_content_selector_by_id(&state.pool, sel_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return (StatusCode::NOT_FOUND, "content selector not found").into_response()
            }
            Err(e) => return db_error(e),
        }
    }

    match authz_dao::add_grant(
        &state.pool,
        role_id,
        repository_id,
        action.as_str(),
        body.selector_id,
    )
    .await
    {
        Ok(()) => {
            invalidate_all(&state.cache).await;
            StatusCode::CREATED.into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/roles/{id}/grants/{grant_id}`
pub async fn remove(
    State(state): State<AppState>,
    Path((role_id, grant_id)): Path<(i64, i64)>,
) -> Response {
    match authz_dao::delete_grant(&state.pool, role_id, grant_id).await {
        Ok(true) => {
            invalidate_all(&state.cache).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "grant not found").into_response(),
        Err(e) => db_error(e),
    }
}
