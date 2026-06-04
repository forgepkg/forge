//! Repository dispatch for `/v3/{repo}/...` (spec §6, plan 10.3).
//!
//! A single fallback handler under `/v3/{repo}` resolves the repository row,
//! enforces authorization, then builds the per-repository NuGet router
//! ([`forge_nuget::routes::nuget_router`]) and dispatches the remaining path
//! into it. Branching on [`RepoKind`] selects the read ops (hosted / proxy /
//! group); publish routes are mounted only for hosted repos by the router
//! factory itself.
//!
//! ## Authorization
//! Resolution runs **before** dispatch:
//! * Unknown repo → **404**.
//! * Read methods (`GET`/`HEAD`) require [`can_read`]; a denied authenticated
//!   user is impossible in Slice 1 (any user can read), so a denial means an
//!   anonymous/unauthenticated caller → **401** (so a NuGet client knows to send
//!   credentials).
//! * Write methods (`PUT`/`POST`/`DELETE`) require [`can_write`]; an
//!   unauthenticated caller → **401**, an authenticated-but-disallowed caller →
//!   **403** (none in Slice 1, but the distinction is wired for §12.4).

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use forge_core::auth::principal::Principal;
use forge_core::repo::RepoKind;
use forge_db::model::Repository;
use forge_db::repository_dao;
use forge_nuget::routes::{nuget_router, RouteContext};
use tower::ServiceExt;

use crate::middleware::principal_of;
use crate::state::AppState;

/// Whether an HTTP method is a write (publish / unlist / relist / delete).
fn is_write(method: &Method) -> bool {
    matches!(method, &Method::PUT | &Method::POST | &Method::DELETE)
}

/// Strip the `/v3/{repo}` prefix from the original request path, returning the
/// remainder (always starting with `/`, e.g. `/index.json`, `/flat/x/...`).
fn subpath(uri: &Uri, repo: &str) -> String {
    let prefix = format!("/v3/{repo}");
    let path = uri.path();
    let rest = path.strip_prefix(&prefix).unwrap_or("");
    let rest = if rest.is_empty() { "/" } else { rest };
    match uri.query() {
        Some(q) => format!("{rest}?{q}"),
        None => rest.to_string(),
    }
}

/// Build a [`RouteContext`] for a resolved repository + principal.
fn route_context(
    state: &AppState,
    repo: &Repository,
    principal: Principal,
) -> Option<RouteContext> {
    let kind = repo.kind();
    let format = state.formats.for_repository(repo);
    let ops = state.read_ops_for(repo, principal).ok()?;

    // Write ops only for hosted repos; the router mounts publish routes only for
    // hosted, so proxy/group never reach a write handler.
    let write: Option<std::sync::Arc<dyn forge_core::repo::RepoWriteOps>> = match kind {
        RepoKind::Hosted => Some(std::sync::Arc::new(HostedWriteAdapter::new(
            state,
            format.clone(),
        ))),
        _ => None,
    };

    Some(RouteContext {
        repo: repo.name.clone(),
        kind,
        public_base_url: state.config.public_base_url(),
        ops,
        format,
        nupkg: state.blob_bytes(),
        write,
        max_upload_bytes: forge_nuget::routes::DEFAULT_MAX_UPLOAD_BYTES,
    })
}

/// Axum fallback handler mounted at `/v3/{repo}` (and everything under it).
pub async fn dispatch(State(state): State<AppState>, req: Request<Body>) -> Response {
    let principal = principal_of(&req);
    let method = req.method().clone();
    let uri = req.uri().clone();

    // The first path segment after /v3/ is the repository name.
    let Some(repo_name) = repo_name_from_path(uri.path()) else {
        return (StatusCode::NOT_FOUND, "repository not found").into_response();
    };

    let repo = match repository_dao::find_repository_by_name(&state.pool, &repo_name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, repo = %repo_name, "repo lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    // Authorization gate (before any handler runs).
    if is_write(&method) {
        if !state.authz.can_write(&principal, &repo).await {
            return authz_denied(&principal);
        }
    } else if !state.authz.can_read(&principal, &repo).await {
        return authz_denied(&principal);
    }

    let Some(ctx) = route_context(&state, &repo, principal) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    };

    // Dispatch the `/v3/{repo}`-stripped sub-path into the per-repo router.
    //
    // We rebuild the request from its parts rather than mutating the URI in
    // place: the outer router (`/v3/{repo}/{*rest}`) left its own matched path
    // params (`repo`, `rest`) in the request extensions, and the inner router's
    // `Path` extractors would otherwise read those stale params (causing a
    // "wrong number of path arguments" 500). Dropping the extensions clears
    // them. Method, headers (Content-Type / X-NuGet-ApiKey for publish), and
    // the body are all carried over.
    let rest = subpath(&uri, &repo.name);
    let new_uri: Uri = match rest.parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = new_uri;
    parts.extensions.clear();
    let sub_req = Request::from_parts(parts, body);

    let router = nuget_router(repo.kind(), ctx);
    match router.oneshot(sub_req).await {
        Ok(resp) => resp,
        Err(infallible) => match infallible {},
    }
}

/// Map an authorization denial to the right status: unauthenticated → 401 (send
/// credentials), authenticated-but-forbidden → 403, anonymous-denied → 401.
fn authz_denied(principal: &Principal) -> Response {
    match principal {
        // An authenticated user who is nonetheless denied (future RBAC) → 403.
        Principal::User { .. } => (StatusCode::FORBIDDEN, "forbidden").into_response(),
        // No/insufficient identity → 401 so the client knows to authenticate.
        Principal::Anonymous { .. } | Principal::Unauthenticated => {
            (StatusCode::UNAUTHORIZED, "authentication required").into_response()
        }
    }
}

/// Extract the repository name (first segment after `/v3/`).
fn repo_name_from_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/v3/")?;
    let seg = rest.split('/').next()?;
    if seg.is_empty() {
        return None;
    }
    Some(seg.to_string())
}

// ── Hosted write adapter ────────────────────────────────────────────────────

use forge_core::format::Format;
use forge_core::repo::hosted::HostedWrite;
use forge_core::repo::{DeleteOutcome, PublishOutcome, RepoWriteOps, UploadReader, WriteError};
use std::sync::Arc;

/// Bridges the object-safe [`RepoWriteOps`] trait (which takes a boxed
/// [`UploadReader`]) to [`HostedWrite`]'s generic `store_upload<R>`.
struct HostedWriteAdapter {
    inner: HostedWrite,
}

impl HostedWriteAdapter {
    fn new(state: &AppState, format: Arc<dyn Format>) -> Self {
        let inner = HostedWrite::new(
            state.pool.clone(),
            format,
            state.cas.clone(),
            state.cache_invalidator(),
            state.config.outbox.grace(),
        );
        HostedWriteAdapter { inner }
    }
}

#[async_trait::async_trait]
impl RepoWriteOps for HostedWriteAdapter {
    async fn store_upload(
        &self,
        repo: &str,
        reader: UploadReader,
        max_upload_bytes: u64,
    ) -> Result<PublishOutcome, WriteError> {
        self.inner
            .store_upload(repo, reader, max_upload_bytes)
            .await
    }

    async fn delete_component(
        &self,
        repo: &str,
        id: &str,
        version: &str,
        hard: bool,
    ) -> Result<DeleteOutcome, WriteError> {
        self.inner.delete_component(repo, id, version, hard).await
    }

    async fn relist(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<DeleteOutcome, WriteError> {
        self.inner.relist(repo, id, version).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;

    #[test]
    fn repo_name_extraction() {
        assert_eq!(
            repo_name_from_path("/v3/my-repo/index.json").as_deref(),
            Some("my-repo")
        );
        assert_eq!(
            repo_name_from_path("/v3/my-repo").as_deref(),
            Some("my-repo")
        );
        assert_eq!(repo_name_from_path("/v3/").as_deref(), None);
        assert_eq!(repo_name_from_path("/other").as_deref(), None);
    }

    #[test]
    fn subpath_strips_prefix_and_keeps_query() {
        let uri: Uri = "/v3/my-repo/query?q=foo&take=5".parse().unwrap();
        assert_eq!(subpath(&uri, "my-repo"), "/query?q=foo&take=5");
        let uri: Uri = "/v3/my-repo/index.json".parse().unwrap();
        assert_eq!(subpath(&uri, "my-repo"), "/index.json");
        let uri: Uri = "/v3/my-repo".parse().unwrap();
        assert_eq!(subpath(&uri, "my-repo"), "/");
    }

    #[test]
    fn write_methods_classified() {
        assert!(is_write(&Method::PUT));
        assert!(is_write(&Method::POST));
        assert!(is_write(&Method::DELETE));
        assert!(!is_write(&Method::GET));
        assert!(!is_write(&Method::HEAD));
    }
}
