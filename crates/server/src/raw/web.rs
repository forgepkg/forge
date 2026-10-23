//! The raw endpoints of the web UI and the admin API.
//!
//! The web UI reads listings from `/raw/<repo>/<dir>/` itself (as JSON, with
//! its session). Changing files through `/raw` takes an API token, like
//! every package client, so the UI changes them here, with its session
//! (whose CSRF token the principal middleware checks):
//!
//! * `POST /browse/raw/{repo}/files?directory=<dir>` — a multipart upload
//!   into `<dir>` ([`upload::multipart`]);
//! * `DELETE /browse/raw/{repo}/files?path=<file>` — delete a file.
//!
//! Both take the same permissions as `/raw`: write (and, to replace a
//! file, delete) on the repository and its selectors.
//!
//! * `DELETE /admin/repositories/{name}/files?path=<path>` (admin API) —
//!   delete a file, or with a path ending in `/` (or empty: everything) a
//!   directory and all files below it, in hosted and proxy repositories
//!   (a proxy's cached copies). Answers `{"deleted": <n>}`.

use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::auth::principal::Principal;
use forge_db::model::{RepoKind, Repository};
use forge_db::{raw_dao, repository_dao};
use serde::Deserialize;

use super::{path, upload, Raw, RawError};
use crate::middleware::principal_of;
use crate::state::AppState;

/// Files a directory delete removes per transaction.
const DELETE_BATCH: i64 = 500;

#[derive(Debug, Deserialize)]
pub struct DirectoryQuery {
    #[serde(default)]
    pub directory: String,
}

#[derive(Debug, Deserialize)]
pub struct PathQuery {
    #[serde(default)]
    pub path: String,
}

/// The raw repository `name` for a signed-in caller (`/browse` is for
/// signed-in users only).
async fn browse_target(
    state: &AppState,
    principal: &Principal,
    name: &str,
) -> Result<Repository, Response> {
    if !matches!(principal, Principal::User { .. }) {
        return Err((StatusCode::UNAUTHORIZED, "authentication required").into_response());
    }
    match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(repo)) if repo.is_raw() && state.authz.can_read(principal, &repo).await => Ok(repo),
        Ok(_) => Err((StatusCode::NOT_FOUND, "repository not found").into_response()),
        Err(e) => Err(RawError::from(e).into_response()),
    }
}

/// `POST /browse/raw/{repo}/files?directory=<dir>`
pub async fn browse_upload(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DirectoryQuery>,
    req: Request,
) -> Response {
    let principal = principal_of(&req);
    let repo = match browse_target(&state, &principal, &name).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let directory = match path::normalize_directory(&query.directory) {
        Ok(dir) => dir,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let raw = Raw {
        state: &state,
        principal,
    };
    let response = upload::multipart(&raw, &repo, &directory, req, upload::Via::Browser).await;
    audit(&repo, "POST", &directory, &principal, &response);
    response
}

/// `DELETE /browse/raw/{repo}/files?path=<file>`
pub async fn browse_delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<PathQuery>,
    req: Request,
) -> Response {
    let principal = principal_of(&req);
    let repo = match browse_target(&state, &principal, &name).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let file = match path::normalize(&query.path) {
        Ok(file) if !file.is_empty() && !query.path.ends_with('/') => file,
        Ok(_) => {
            return (StatusCode::BAD_REQUEST, "path must name a file").into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let raw = Raw {
        state: &state,
        principal,
    };
    let response = upload::delete(&raw, &repo, &file, upload::Via::Browser).await;
    audit(&repo, "DELETE", &file, &principal, &response);
    response
}

fn audit(repo: &Repository, method: &str, path: &str, principal: &Principal, response: &Response) {
    tracing::info!(
        target: "forge::audit",
        method,
        repo = %repo.name,
        path,
        status = response.status().as_u16(),
        principal = %principal.audit_label(),
        "package mutation"
    );
}

/// `DELETE /admin/repositories/{name}/files?path=<path>` (admin only).
pub async fn admin_delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<PathQuery>,
) -> Response {
    let repo = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(repo)) => repo,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return crate::admin::db_error(e),
    };
    if !repo.is_raw() {
        return (
            StatusCode::BAD_REQUEST,
            "files are deleted from raw repositories",
        )
            .into_response();
    }
    if repo.kind() == RepoKind::Group {
        return (
            StatusCode::BAD_REQUEST,
            "a group holds no files of its own; delete them from its members",
        )
            .into_response();
    }
    let directory = query.path.is_empty() || query.path.ends_with('/');
    let normalized = match if directory {
        path::normalize_directory(&query.path)
    } else {
        path::normalize(&query.path)
    } {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let grace = state.config.outbox.grace();
    let result = if directory {
        delete_directory(&state, repo.id, &normalized, grace).await
    } else {
        delete_file(&state, repo.id, &normalized, grace).await
    };
    match result {
        Ok(0) if !directory => (StatusCode::NOT_FOUND, "file not found").into_response(),
        Ok(deleted) => Json(serde_json::json!({ "deleted": deleted })).into_response(),
        Err(e) => crate::admin::db_error(e),
    }
}

async fn delete_file(
    state: &AppState,
    repository_id: i64,
    path: &str,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    let mut tx = state.pool.begin().await?;
    let deleted = raw_dao::delete(&mut tx, repository_id, path, grace).await?;
    tx.commit().await?;
    Ok(u64::from(deleted))
}

/// Delete every file under `prefix`, a batch per transaction.
async fn delete_directory(
    state: &AppState,
    repository_id: i64,
    prefix: &str,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    let mut deleted = 0;
    loop {
        let mut tx = state.pool.begin().await?;
        let n = raw_dao::delete_under(&mut tx, repository_id, prefix, DELETE_BATCH, grace).await?;
        tx.commit().await?;
        deleted += n;
        if n < DELETE_BATCH as u64 {
            return Ok(deleted);
        }
    }
}
