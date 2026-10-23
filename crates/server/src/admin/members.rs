//! Admin group-membership management, including nested groups.
//!
//! Validation:
//! * The `{name}` repository must be a **group**.
//! * A member must exist. It **may** itself be a group (nested groups) —
//!   but the resulting group graph must stay an acyclic DAG of bounded depth.
//! * A member cannot be the group itself.
//! * Adding an edge that would create a **cycle** or exceed
//!   `groups.max_nesting_depth` is rejected with **409** (fail-closed; the check
//!   runs in the same transaction as the insert under a row lock, so concurrent
//!   edits cannot race a cycle into existence).
//! * `priority` is unique within a group; a duplicate → **409**.
//! * `owner` flags a member as owning the group's package ids (see
//!   `forge_core::repo::group`): once any member is flagged, only flagged
//!   members claim ids under `prefer_hosted` and serve `reserved_prefixes`.
//!   Set it when adding the member, or later with
//!   `PATCH /admin/repositories/{name}/members/{member}` `{"owner": bool}`.
//!   A proxy member cannot be an owner (**400**). An owner cannot be removed
//!   (**409**) until it is unflagged: removing a group's last owner would
//!   silently return the group to trusting every hosted member. The flag is
//!   set in the insert that adds the member, and the remove's owner check is
//!   part of its `DELETE`, so concurrent edits cannot slip between them.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_db::model::RepoKind;
use forge_db::repository_dao::{self, AddMemberOutcome, RemoveMemberOutcome};
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::state::AppState;

/// A group member view (member name, its priority, and whether it owns the
/// group's package ids).
#[derive(Debug, Serialize)]
pub struct MemberView {
    pub name: String,
    pub kind: String,
    pub priority: i32,
    pub owner: bool,
}

/// Add-member request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddMember {
    /// Member repository name.
    pub member: String,
    /// Priority within the group (higher wins ties; unique per group).
    pub priority: i32,
    /// Flag the member as an owner of the group's package ids (default
    /// `false`; see the module docs).
    #[serde(default)]
    pub owner: bool,
}

/// Update-member request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMember {
    /// Whether the member owns the group's package ids.
    pub owner: bool,
}

/// Refuse to flag a proxy as an owner: it would never own anything, and a
/// group whose only flagged member is a proxy would serve its reserved ids
/// from nowhere.
fn owner_kind_error(member: &forge_db::model::Repository) -> Option<Response> {
    (member.kind() == RepoKind::Proxy).then(|| {
        (
            StatusCode::BAD_REQUEST,
            "a proxy member cannot own package ids",
        )
            .into_response()
    })
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
    let owners = match repository_dao::group_owner_ids(&state.pool, group.id).await {
        Ok(owners) => owners,
        Err(e) => return db_error(e),
    };
    match repository_dao::group_members(&state.pool, group.id).await {
        Ok(members) => {
            let views: Vec<MemberView> = members
                .iter()
                .map(|(repo, priority)| MemberView {
                    name: repo.name.clone(),
                    kind: repo.kind.clone(),
                    priority: *priority,
                    owner: owners.contains(&repo.id),
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
    // A group serves one protocol: every member is of the group's format
    // (a repository's format never changes, so checking here suffices).
    if member.format != group.format {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "member format {:?} differs from the group's format {:?}",
                member.format, group.format
            ),
        )
            .into_response();
    }
    if body.owner {
        if let Some(resp) = owner_kind_error(&member) {
            return resp;
        }
    }
    // Nested groups are allowed; the checked insert runs the cycle + depth
    // guard in the same transaction.
    let max_depth = state.config.groups.max_nesting_depth;

    match repository_dao::add_group_member_checked(
        &state.pool,
        group.id,
        member.id,
        body.priority,
        body.owner,
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

/// `PATCH /admin/repositories/{name}/members/{member}` — set `owner`.
pub async fn update(
    State(state): State<AppState>,
    Path((name, member_name)): Path<(String, String)>,
    Json(body): Json<UpdateMember>,
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
    if body.owner {
        if let Some(resp) = owner_kind_error(&member) {
            return resp;
        }
    }
    match repository_dao::set_group_member_owner(&state.pool, group.id, member.id, body.owner).await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "membership not found").into_response(),
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
        Ok(RemoveMemberOutcome::Removed) => StatusCode::NO_CONTENT.into_response(),
        Ok(RemoveMemberOutcome::NotFound) => {
            (StatusCode::NOT_FOUND, "membership not found").into_response()
        }
        Ok(RemoveMemberOutcome::Owner) => (
            StatusCode::CONFLICT,
            "this member owns the group's package ids; unflag it as owner before removing it",
        )
            .into_response(),
        Err(e) => db_error(e),
    }
}
