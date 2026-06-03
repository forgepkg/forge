//! Admin group-membership management (plan 10.4, nested groups in §12.4 Phase 4).
//!
//! Validation (spec §7 + §12.4):
//! * The `{name}` repository must be a **group**.
//! * A member must exist. It **may** itself be a group (nested groups, §12.4) —
//!   but the resulting group graph must stay an acyclic DAG of bounded depth.
//! * A member cannot be the group itself.
//! * Adding an edge that would create a **cycle** or exceed
//!   `groups.max_nesting_depth` is rejected with **409** (fail-closed; the check
//!   runs in the same transaction as the insert under a row lock, so concurrent
//!   edits cannot race a cycle into existence).
//! * `priority` is unique within a group; a duplicate → **409**.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_db::model::RepoKind;
use forge_db::repository_dao::{self, AddMemberOutcome};
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::state::AppState;

/// A group member view (member name + its priority).
#[derive(Debug, Serialize)]
pub struct MemberView {
    pub name: String,
    pub kind: String,
    pub priority: i32,
}

/// Add-member request.
#[derive(Debug, Deserialize)]
pub struct AddMember {
    /// Member repository name.
    pub member: String,
    /// Priority within the group (higher wins ties; unique per group).
    pub priority: i32,
}

/// Resolve the `{name}` path segment to a group repository, or an error
/// response (404 unknown / 400 not-a-group).
async fn group_or_err(
    state: &AppState,
    name: &str,
) -> Result<forge_db::model::Repository, Response> {
    match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(r)) if r.kind() == RepoKind::Group => Ok(r),
        Ok(Some(_)) => Err((StatusCode::BAD_REQUEST, "repository is not a group").into_response()),
        Ok(None) => Err((StatusCode::NOT_FOUND, "group not found").into_response()),
        Err(e) => Err(db_error(e)),
    }
}

/// `GET /admin/repositories/{name}/members`
pub async fn list(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let group = match group_or_err(&state, &name).await {
        Ok(g) => g,
        Err(resp) => return resp,
    };
    match repository_dao::group_members(&state.pool, group.id).await {
        Ok(members) => {
            let views: Vec<MemberView> = members
                .iter()
                .map(|(repo, priority)| MemberView {
                    name: repo.name.clone(),
                    kind: repo.kind.clone(),
                    priority: *priority,
                })
                .collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `POST /admin/repositories/{name}/members`
pub async fn add(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<AddMember>,
) -> Response {
    let group = match group_or_err(&state, &name).await {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    let member = match repository_dao::find_repository_by_name(&state.pool, &body.member).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "member repository not found").into_response(),
        Err(e) => return db_error(e),
    };

    if member.id == group.id {
        return (StatusCode::BAD_REQUEST, "a group cannot contain itself").into_response();
    }
    // Nested groups are allowed (§12.4); the checked insert runs the cycle +
    // depth guard in the same transaction.
    let max_depth = state.config.groups.max_nesting_depth;

    match repository_dao::add_group_member_checked(
        &state.pool,
        group.id,
        member.id,
        body.priority,
        max_depth,
    )
    .await
    {
        Ok(AddMemberOutcome::Added) => StatusCode::CREATED.into_response(),
        Ok(AddMemberOutcome::WouldCycle) => (
            StatusCode::CONFLICT,
            "adding this member would create a cycle in the group graph",
        )
            .into_response(),
        Ok(AddMemberOutcome::TooDeep) => (
            StatusCode::CONFLICT,
            "adding this member would exceed the maximum group nesting depth",
        )
            .into_response(),
        Ok(AddMemberOutcome::Duplicate) => (
            StatusCode::CONFLICT,
            "duplicate member or priority in this group",
        )
            .into_response(),
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/repositories/{name}/members/{member}`
pub async fn remove(
    State(state): State<AppState>,
    Path((name, member_name)): Path<(String, String)>,
) -> Response {
    let group = match group_or_err(&state, &name).await {
        Ok(g) => g,
        Err(resp) => return resp,
    };
    let member = match repository_dao::find_repository_by_name(&state.pool, &member_name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "member repository not found").into_response(),
        Err(e) => return db_error(e),
    };

    match repository_dao::remove_group_member(&state.pool, group.id, member.id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "membership not found").into_response(),
        Err(e) => db_error(e),
    }
}
