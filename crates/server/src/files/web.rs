//! The file store's endpoints of the web UI and the admin API, for the
//! repositories of a files format (raw).
//!
//! The web UI reads listings from its format's protocol itself
//! (`/repository/<repo>/<dir>/` as JSON, with its session). Changing files through
//! the repository URL takes an API token, like every package client, so the UI changes
//! them here, with its session (whose CSRF token the principal middleware
//! checks):
//!
//! * `POST /browse/raw/{repo}/files?directory=<dir>` — a multipart upload
//!   into `<dir>`, each file part stored at its file name
//!   ([`store::receive_form`], [`store::store`]);
//! * `DELETE /browse/raw/{repo}/files?path=<file>` — delete a file.
//!
//! Both take the same permissions as the repository URL: write (and, to replace a
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
use forge_plugin::api::files;
use serde::Deserialize;

use super::store::{self, Content, Part, Upload, Via};
use super::{FileError, Files};
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

/// The repository of files `name` for a signed-in caller (`/browse` is for
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
        Ok(Some(repo))
            if state.formats.stores_files(&repo.format)
                && state.authz.can_read(principal, &repo).await =>
        {
            Ok(repo)
        }
        Ok(_) => Err((StatusCode::NOT_FOUND, "repository not found").into_response()),
        Err(e) => Err(FileError::from(e).into_response()),
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
    let directory = match files::normalize_directory(&query.directory) {
        Ok(dir) => dir,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let files = Files {
        state: &state,
        principal,
    };
    let response = match upload(&files, &repo, &directory, req).await {
        Ok(stored) => {
            let status = if stored.iter().any(|f| f.status == "created") {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (status, Json(serde_json::json!({ "files": stored }))).into_response()
        }
        Err(e) => e.into_response(),
    };
    audit(&repo, "POST", &directory, &principal, &response);
    response
}

/// Store the file parts of the form `req` carries under `directory`, each
/// at its file name.
async fn upload(
    files: &Files<'_>,
    repo: &Repository,
    directory: &str,
    req: Request,
) -> Result<Vec<store::Stored>, FileError> {
    let parts = store::receive_form(files, repo, req, Via::Browser).await?;
    let mut uploads = Vec::with_capacity(parts.len());
    for part in parts {
        match part {
            Part::File {
                name,
                content_type,
                ingested,
                ..
            } => uploads.push(Upload {
                path: files::join(directory, &name)
                    .map_err(|e| FileError::BadRequest(format!("file name {name:?}: {e}")))?,
                declared: content_type,
                content: Content::Staged(*ingested),
            }),
            Part::Text { field, .. } => {
                return Err(FileError::BadRequest(format!(
                    "unknown form field {field:?} (only files are accepted)"
                )))
            }
        }
    }
    if uploads.is_empty() {
        return Err(FileError::BadRequest("the form holds no file".into()));
    }
    store::store(files, repo, uploads, Via::Browser).await
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
    let file = match files::normalize(&query.path) {
        Ok(file) if !file.is_empty() && !query.path.ends_with('/') => file,
        Ok(_) => {
            return (StatusCode::BAD_REQUEST, "path must name a file").into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let files = Files {
        state: &state,
        principal,
    };
    let response = match store::remove(&files, &repo, &file, Via::Browser).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => FileError::NotFound.into_response(),
        Err(e) => e.into_response(),
    };
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
    if !state.formats.stores_files(&repo.format) {
        return (
            StatusCode::BAD_REQUEST,
            "files are deleted from repositories of files (raw)",
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
        files::normalize_directory(&query.path)
    } else {
        files::normalize(&query.path)
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
