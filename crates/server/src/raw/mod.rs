//! Raw (generic file) repositories: arbitrary files under arbitrary paths,
//! like Nexus' raw-hosted, raw-proxy and raw-group repositories, served at
//! `/raw/<repo>/<path>`.
//!
//! * `GET` / `HEAD` of a file: its bytes, with `ETag` (the SHA-256),
//!   `Last-Modified`, `Content-Length` and the stored `Content-Type`; one
//!   `Range`, `If-Range`, `If-None-Match` and `If-Modified-Since` ([`serve`]).
//!   `<file>.sha256`, `.sha512`, `.sha1` and `.md5` are answered from the
//!   file's digests when no file of that name is stored.
//! * `GET` of a directory (`<dir>/`, or the root): a listing, HTML or JSON,
//!   paginated ([`listing`]).
//! * `PUT` of a file, `POST` of a multipart form to a directory, `DELETE` of
//!   a file, in hosted repositories ([`upload`]); directories are deleted
//!   through the admin API.
//! * Proxies fetch from an HTTP(S) base URL and re-validate after a maximum
//!   age ([`proxy`]); groups answer with the first member, by priority, that
//!   has the path.
//!
//! Paths are normalized ([`path`]): `..`, `.`, empty segments, backslashes
//! and encoded slashes are refused, never resolved. Package selectors match
//! paths (`pdfium/**`). Files are CAS blobs, so the same content under
//! several paths or repositories is stored once.

pub mod listing;
pub mod path;
pub mod proxy;
pub mod serve;
pub mod upload;
pub mod web;

use std::collections::HashSet;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use forge_core::auth::principal::Principal;
use forge_core::authz::{Action, PackageFilter};
use forge_db::model::{RepoKind, Repository};
use forge_db::{raw_dao, repository_dao};

use crate::dispatch::{action_for_method, authz_denied, offline_response, offline_serves_nothing};
use crate::middleware::principal_of;
use crate::state::AppState;
use listing::ListQuery;
use path::Target;
use raw_dao::RawFile;
use serve::Checksum;

/// Where raw repositories are served.
pub const MOUNT: &str = "/raw";

/// A request's view of raw repositories: the server's state and the caller.
pub struct Raw<'a> {
    pub state: &'a AppState,
    pub principal: Principal,
}

/// Why a raw request failed, as its answer.
#[derive(Debug)]
pub enum RawError {
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

impl RawError {
    /// The error's text, for logs.
    pub fn message(&self) -> String {
        match self {
            RawError::NotFound => "not found".into(),
            RawError::CredentialRequired => "API token or workload identity required".into(),
            RawError::Denied => "forbidden".into(),
            RawError::MethodNotAllowed(m) => (*m).into(),
            RawError::TooLarge(limit) => format!("larger than {limit} bytes"),
            RawError::BadRequest(m)
            | RawError::Forbidden(m)
            | RawError::Conflict(m)
            | RawError::Unavailable(m)
            | RawError::BadGateway(m)
            | RawError::Internal(m) => m.clone(),
        }
    }
}

impl From<sqlx::Error> for RawError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::PoolTimedOut => RawError::Unavailable("database busy".into()),
            e => RawError::Internal(format!("database: {e}")),
        }
    }
}

impl IntoResponse for RawError {
    fn into_response(self) -> Response {
        match self {
            RawError::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
            RawError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            RawError::CredentialRequired => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"Forge\"")],
                "API token or workload identity required",
            )
                .into_response(),
            RawError::Denied => (StatusCode::FORBIDDEN, "forbidden").into_response(),
            RawError::Forbidden(m) => (StatusCode::FORBIDDEN, m).into_response(),
            RawError::Conflict(m) => (StatusCode::CONFLICT, m).into_response(),
            RawError::MethodNotAllowed(m) => (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, "GET, HEAD")],
                m,
            )
                .into_response(),
            RawError::TooLarge(limit) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("the upload exceeds the repository's limit of {limit} bytes"),
            )
                .into_response(),
            RawError::Unavailable(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "30")],
                m,
            )
                .into_response(),
            RawError::BadGateway(m) => (StatusCode::BAD_GATEWAY, m).into_response(),
            RawError::Internal(m) => {
                tracing::error!(error = %m, "raw repository request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

/// A file a request found: stored at the path, or the file a checksum
/// sidecar is computed from.
pub enum Found {
    File(RawFile),
    Sidecar(RawFile, Checksum),
}

/// The `/raw/...` handler.
pub async fn handle(State(state): State<AppState>, req: Request<Body>) -> Response {
    let mut response = handle_request(&state, req).await;
    crate::feed::harden_response_headers(response.headers_mut());
    response
}

/// `(repository name, rest)` of a `/raw/<name>[/<rest>]` path; the rest is
/// `None` without the `/` after the name.
fn split(path: &str) -> Option<(&str, Option<&str>)> {
    let rest = path.strip_prefix(MOUNT)?.strip_prefix('/')?;
    let (name, rest) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    (!name.is_empty()).then_some((name, rest))
}

async fn handle_request(state: &AppState, req: Request<Body>) -> Response {
    let principal = principal_of(&req);
    let method = req.method().clone();
    let uri = req.uri().clone();
    let Some((name, rest)) = split(uri.path()) else {
        return (StatusCode::NOT_FOUND, "repository not found").into_response();
    };
    let repo = match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(r)) => r,
        // An unknown name answers like a repository the caller may not
        // read, except to a global admin.
        Ok(None) if state.authz.is_global_admin(&principal).await => {
            return (StatusCode::NOT_FOUND, "repository not found").into_response();
        }
        Ok(None) => return authz_denied(&principal),
        Err(e) => return RawError::from(e).into_response(),
    };
    let action = action_for_method(&method);
    let allowed = match action {
        Action::Read => state.authz.can_read(&principal, &repo).await,
        Action::Write => state.authz.can_write(&principal, &repo).await,
        Action::Delete => state.authz.can_delete(&principal, &repo).await,
        Action::Admin => false,
    };
    if !allowed {
        return authz_denied(&principal);
    }
    if !repo.is_raw() {
        return (StatusCode::NOT_FOUND, "repository is not served here").into_response();
    }
    if offline_serves_nothing(&repo) {
        return offline_response();
    }
    let Some(rest) = rest else {
        // `/raw/<repo>`: the root listing is `/raw/<repo>/`.
        if matches!(method, Method::GET | Method::HEAD) {
            let location = format!("{MOUNT}/{}/", repo.name);
            return (
                StatusCode::MOVED_PERMANENTLY,
                [(header::LOCATION, location)],
            )
                .into_response();
        }
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let target = match path::parse_request(rest) {
        Ok(target) => target,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let raw = Raw { state, principal };
    let response = match (&method, &target) {
        (&Method::GET | &Method::HEAD, Target::File(path)) => {
            raw.get(&repo, path, req.headers(), method == Method::HEAD)
                .await
        }
        (&Method::GET | &Method::HEAD, Target::Directory(dir)) => {
            let query = match ListQuery::parse(uri.query()) {
                Ok(query) => query,
                Err(e) => return e.into_response(),
            };
            match raw.list(&repo, dir, &query).await {
                Ok(Some(page)) => listing::respond(
                    &page,
                    &query,
                    listing::wants_json(req.headers(), &query),
                    method == Method::HEAD,
                ),
                Ok(None) => RawError::NotFound.into_response(),
                Err(e) => e.into_response(),
            }
        }
        (&Method::PUT, Target::File(path)) => {
            let path = path.clone();
            upload::put(&raw, &repo, &path, req).await
        }
        (&Method::PUT, Target::Directory(_)) => (
            StatusCode::BAD_REQUEST,
            "PUT uploads a file: name it in the path",
        )
            .into_response(),
        (&Method::POST, Target::Directory(dir)) => {
            let dir = dir.clone();
            upload::multipart(&raw, &repo, &dir, req, upload::Via::Protocol).await
        }
        (&Method::POST, Target::File(_)) => (
            StatusCode::BAD_REQUEST,
            "a form upload goes to a directory: end the path with /",
        )
            .into_response(),
        (&Method::DELETE, Target::File(path)) => {
            upload::delete(&raw, &repo, path, upload::Via::Protocol).await
        }
        (&Method::DELETE, Target::Directory(_)) => (
            StatusCode::BAD_REQUEST,
            "directories are deleted through the admin API (DELETE /admin/repositories/<name>/files?path=<dir>/)",
        )
            .into_response(),
        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET, HEAD, PUT, POST, DELETE")],
            "method not allowed",
        )
            .into_response(),
    };
    if action != Action::Read {
        // The same audit trail as the package feeds' mutations.
        tracing::info!(
            target: "forge::audit",
            %method,
            repo = %repo.name,
            path = %rest,
            status = response.status().as_u16(),
            principal = %principal.audit_label(),
            "package mutation"
        );
    }
    response
}

impl Raw<'_> {
    /// `GET`/`HEAD` of `path` in `repo`.
    async fn get(
        &self,
        repo: &Repository,
        path: &str,
        headers: &HeaderMap,
        head: bool,
    ) -> Response {
        match self.locate(repo, path, Vec::new(), 0).await {
            Ok(Some(Found::File(file))) => {
                serve::file(self.state, repo, &file, headers, head).await
            }
            Ok(Some(Found::Sidecar(base, checksum))) => {
                serve::sidecar(repo, path, &base, checksum, headers, head)
            }
            Ok(None) => {
                // A directory named without its `/`.
                let dir = format!("{path}/");
                match self.list(repo, &dir, &ListQuery::default()).await {
                    Ok(Some(_)) => {
                        let location = format!("{MOUNT}/{}/{}", repo.name, path::encode(&dir));
                        let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
                        if let Ok(value) = HeaderValue::from_str(&location) {
                            response.headers_mut().insert(header::LOCATION, value);
                        }
                        response
                    }
                    Ok(None) => RawError::NotFound.into_response(),
                    Err(e) => e.into_response(),
                }
            }
            Err(e) => e.into_response(),
        }
    }

    /// Find `path` in `repo` for the caller, through every one of `filters`
    /// (a group's, for its members) and `repo`'s own package filter: the
    /// stored file, else the checksum sidecar of a stored file, else (a
    /// proxy) the upstream's file, else (a group) the first member's that
    /// has one.
    pub fn locate<'a>(
        &'a self,
        repo: &'a Repository,
        path: &'a str,
        filters: Vec<PackageFilter>,
        depth: u32,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<Found>, RawError>> {
        Box::pin(async move {
            let mut filters = filters;
            filters.push(self.state.authz.package_filter(&self.principal, repo).await);
            let visible = |p: &str| filters.iter().all(|f| f.allows(p));
            let sidecar = serve::sidecar_of(path).filter(|(base, _)| visible(base));
            match repo.kind() {
                RepoKind::Hosted | RepoKind::Proxy => {
                    let proxy = repo.kind() == RepoKind::Proxy;
                    if visible(path) {
                        if let Some(file) = raw_dao::find(&self.state.pool, repo.id, path).await? {
                            let file = if proxy {
                                self.fresh(repo, file).await
                            } else {
                                file
                            };
                            return Ok(Some(Found::File(file)));
                        }
                    }
                    if let Some((base, checksum)) = sidecar {
                        if let Some(file) = raw_dao::find(&self.state.pool, repo.id, base).await? {
                            let file = if proxy {
                                self.fresh(repo, file).await
                            } else {
                                file
                            };
                            return Ok(Some(Found::Sidecar(file, checksum)));
                        }
                    }
                    if proxy && visible(path) {
                        return Ok(self.fetch(repo, path).await?.map(Found::File));
                    }
                    Ok(None)
                }
                RepoKind::Group => {
                    if !visible(path) && sidecar.is_none() {
                        return Ok(None);
                    }
                    let mut failure = None;
                    for member in self.serving_members(repo, depth).await? {
                        match self.locate(&member, path, filters.clone(), depth + 1).await {
                            Ok(Some(found)) => return Ok(Some(found)),
                            Ok(None) => {}
                            Err(e) => {
                                tracing::warn!(group = %repo.name, member = %member.name, error = %e.message(), "raw group: member failed");
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
    /// first: raw repositories the caller may read itself (reading a group
    /// grants nothing on its members), without offline hosted or group
    /// members, and without nested groups past the nesting limit or on a
    /// cycle.
    pub async fn serving_members(
        &self,
        group: &Repository,
        depth: u32,
    ) -> Result<Vec<Repository>, RawError> {
        let max_depth = self.state.config.groups.max_nesting_depth.max(1) as u32;
        if depth >= max_depth {
            return Ok(Vec::new());
        }
        let mut seen = HashSet::from([group.id]);
        let mut out = Vec::new();
        for (member, _priority) in repository_dao::group_members(&self.state.pool, group.id).await?
        {
            if !member.is_raw() || !seen.insert(member.id) || offline_serves_nothing(&member) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_split_into_repository_and_rest() {
        assert_eq!(split("/raw/bin"), Some(("bin", None)));
        assert_eq!(split("/raw/bin/"), Some(("bin", Some(""))));
        assert_eq!(split("/raw/bin/a/b.txt"), Some(("bin", Some("a/b.txt"))));
        assert_eq!(split("/raw/"), None);
        assert_eq!(split("/raw"), None);
        assert_eq!(split("/rawx/bin"), None);
    }
}
