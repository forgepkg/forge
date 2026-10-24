//! The file store: the repositories of a format whose descriptor says
//! `Storage::Files` (raw) hold files under paths, like Nexus' raw-hosted,
//! raw-proxy and raw-group repositories. The format's plugin owns the
//! protocol (`crates/formats/raw`, served under its mount by
//! [`crate::plugins`]); this module answers the file queries and actions it
//! asks for:
//!
//! * `file` and `fetch-file`: [`Files::locate`] — the stored file; a proxy's
//!   copy, re-validated with its upstream once it is due, or fetched from it
//!   ([`proxy`]); a group's first member, by priority, that has the path;
//! * `directory`: a page of a directory ([`listing`]);
//! * `form`, `store` and `remove`: receiving a multipart form, storing files
//!   under the deployment policy, deleting a file ([`store`]);
//! * `serve-file`: its bytes, one `Range`, `If-Range`, `If-None-Match` and
//!   `If-Modified-Since` ([`serve`]).
//!
//! The web UI's upload and delete and the admin API's directory delete are
//! here too ([`web`]).
//!
//! Paths follow [`forge_plugin::api::files`]: `..`, `.`, empty segments,
//! backslashes and encoded slashes are refused, never resolved, and so is any
//! other path a plugin names. Package selectors match paths (`pdfium/**`).
//! Files are CAS blobs, so the same content under several paths or
//! repositories is stored once (one `raw_file` row, one reference each).

pub mod listing;
pub mod proxy;
pub mod serve;
pub mod store;
pub mod web;

use std::collections::HashSet;

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use forge_core::auth::principal::Principal;
use forge_core::authz::PackageFilter;
use forge_db::model::{RepoKind, Repository};
use forge_db::{raw_dao, repository_dao};

use crate::dispatch::offline_serves_nothing;
use crate::state::AppState;
use raw_dao::RawFile;

/// A request's view of the file store: the server's state and the caller.
pub struct Files<'a> {
    pub state: &'a AppState,
    pub principal: Principal,
}

/// Why a file request failed, as its answer.
#[derive(Debug)]
pub enum FileError {
    NotFound,
    BadRequest(String),
    /// A mutation needs an API token or a workload identity.
    CredentialRequired,
    /// The caller may not do this (repository-level).
    Denied,
    Forbidden(String),
    Conflict(String),
    MethodNotAllowed(&'static str),
    TooLarge(u64),
    Unavailable(String),
    BadGateway(String),
    Internal(String),
}

impl FileError {
    /// The error's text, for logs.
    pub fn message(&self) -> String {
        match self {
            FileError::NotFound => "not found".into(),
            FileError::CredentialRequired => "API token or workload identity required".into(),
            FileError::Denied => "forbidden".into(),
            FileError::MethodNotAllowed(m) => (*m).into(),
            FileError::TooLarge(limit) => format!("larger than {limit} bytes"),
            FileError::BadRequest(m)
            | FileError::Forbidden(m)
            | FileError::Conflict(m)
            | FileError::Unavailable(m)
            | FileError::BadGateway(m)
            | FileError::Internal(m) => m.clone(),
        }
    }
}

impl From<sqlx::Error> for FileError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::PoolTimedOut => FileError::Unavailable("database busy".into()),
            e => FileError::Internal(format!("database: {e}")),
        }
    }
}

impl IntoResponse for FileError {
    fn into_response(self) -> Response {
        match self {
            FileError::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
            FileError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            FileError::CredentialRequired => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"Forge\"")],
                "API token or workload identity required",
            )
                .into_response(),
            FileError::Denied => (StatusCode::FORBIDDEN, "forbidden").into_response(),
            FileError::Forbidden(m) => (StatusCode::FORBIDDEN, m).into_response(),
            FileError::Conflict(m) => (StatusCode::CONFLICT, m).into_response(),
            FileError::MethodNotAllowed(m) => (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, "GET, HEAD")],
                m,
            )
                .into_response(),
            FileError::TooLarge(limit) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("the upload exceeds the repository's limit of {limit} bytes"),
            )
                .into_response(),
            FileError::Unavailable(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "30")],
                m,
            )
                .into_response(),
            FileError::BadGateway(m) => (StatusCode::BAD_GATEWAY, m).into_response(),
            FileError::Internal(m) => {
                tracing::error!(error = %m, "file store request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

impl Files<'_> {
    /// Find `path` in `repo` for the caller, through every one of `filters`
    /// (a group's, for its members) and `repo`'s own package filter: the
    /// stored file (a proxy's re-validated once it is due), else with
    /// `fetch` a proxy's upstream file, else (a group) the first member's
    /// that has one. A member that fails is skipped while another has the
    /// path.
    pub fn locate<'a>(
        &'a self,
        repo: &'a Repository,
        path: &'a str,
        fetch: bool,
        filters: Vec<PackageFilter>,
        depth: u32,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<RawFile>, FileError>> {
        Box::pin(async move {
            let mut filters = filters;
            filters.push(self.state.authz.package_filter(&self.principal, repo).await);
            if !filters.iter().all(|f| f.allows(path)) {
                return Ok(None);
            }
            match repo.kind() {
                RepoKind::Hosted | RepoKind::Proxy => {
                    let proxy = repo.kind() == RepoKind::Proxy;
                    if let Some(file) = raw_dao::find(&self.state.pool, repo.id, path).await? {
                        return Ok(Some(if proxy {
                            self.fresh(repo, file).await
                        } else {
                            file
                        }));
                    }
                    if proxy && fetch {
                        return self.fetch(repo, path).await;
                    }
                    Ok(None)
                }
                RepoKind::Group => {
                    let mut failure = None;
                    for member in self.serving_members(repo, depth).await? {
                        match self
                            .locate(&member, path, fetch, filters.clone(), depth + 1)
                            .await
                        {
                            Ok(Some(found)) => return Ok(Some(found)),
                            Ok(None) => {}
                            Err(e) => {
                                tracing::warn!(group = %repo.name, member = %member.name, error = %e.message(), "file group: member failed");
                                failure = Some(e);
                            }
                        }
                    }
                    failure.map_or(Ok(None), Err)
                }
            }
        })
    }

    /// The members of `group` that may serve the caller, highest priority
    /// first: repositories of the group's format the caller may read itself
    /// (reading a group grants nothing on its members), without offline hosted or group
    /// members, and without nested groups past the nesting limit or on a
    /// cycle.
    pub async fn serving_members(
        &self,
        group: &Repository,
        depth: u32,
    ) -> Result<Vec<Repository>, FileError> {
        let max_depth = self.state.config.groups.max_nesting_depth.max(1) as u32;
        if depth >= max_depth {
            return Ok(Vec::new());
        }
        let mut seen = HashSet::from([group.id]);
        let mut out = Vec::new();
        for (member, _priority) in repository_dao::group_members(&self.state.pool, group.id).await?
        {
            if member.format != group.format
                || !seen.insert(member.id)
                || offline_serves_nothing(&member)
            {
                continue;
            }
            if member.kind() == RepoKind::Group && depth + 1 >= max_depth {
                continue;
            }
            if self.state.authz.can_read(&self.principal, &member).await {
                out.push(member);
            }
        }
        Ok(out)
    }
}
