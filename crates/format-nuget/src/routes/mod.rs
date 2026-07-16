//! NuGet V3 HTTP surface (spec §6, Appendix A).
//!
//! [`nuget_router`] builds an axum [`Router`] for one repository, mounted by
//! the server under `/v3/{repo}`. Handlers read through a [`forge_core::RepoReadOps`]
//! implementation and render the exact JSON shapes from Appendix A. All `@id`s
//! are **absolute**, built from `public_base_url + /v3/{repo}`.
//!
//! `PackagePublish` is advertised in the service index for **hosted** repos
//! only; proxy/group advertise read resources. The publish routes
//! (`PUT/DELETE/POST /package`) are mounted for hosted repos via
//! [`publish`].

pub mod flat;
pub mod index;
pub mod publish;
pub mod registration;
pub mod search;

use std::sync::Arc;

use async_trait::async_trait;
use axum::routing::{delete, get, put, MethodRouter};
use axum::Router;
use forge_core::authz::PackageFilter;
use forge_core::format::Format;
use forge_core::repo::{RepoError, RepoKind};
use forge_core::{RepoReadOps, RepoWriteOps};

/// Default maximum accepted upload size (bytes) when the server does not
/// override it. Mirrors a generous NuGet package size ceiling; the real limit
/// comes from server config (Phase 10).
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Stream the bytes of a stored `.nupkg` blob by its S3 object key.
///
/// Abstracted (like [`forge_core::repo::hosted::BlobFetch`]) so the route layer
/// is independent of the S3 client and so handler tests can stub blob bytes.
/// Slice 1 buffers the whole blob; chunked streaming is a later optimization.
#[async_trait]
pub trait NupkgBytes: Send + Sync {
    /// Read the entire blob at `s3_key` into memory.
    async fn fetch_all(&self, s3_key: &str) -> Result<Vec<u8>, RepoError>;
}

/// Everything a NuGet route handler needs for one repository.
#[derive(Clone)]
pub struct RouteContext {
    /// Repository name (the `{repo}` path segment).
    pub repo: String,
    /// Repository kind, used to decide which resources the index advertises.
    pub kind: RepoKind,
    /// Public base URL, e.g. `https://forge.example.com` (no trailing slash).
    pub public_base_url: String,
    /// Read operations backing this repository.
    pub ops: Arc<dyn RepoReadOps>,
    /// Package format, for id lowercasing and version normalization on the
    /// request path.
    pub format: Arc<dyn Format>,
    /// Byte access to stored `.nupkg` blobs.
    pub nupkg: Arc<dyn NupkgBytes>,
    /// Write operations (publish / unlist / relist / hard delete). Present only
    /// for **hosted** repositories; `None` for proxy/group, whose publish routes
    /// are never mounted.
    pub write: Option<Arc<dyn RepoWriteOps>>,
    /// Whether the authenticated principal came from a NuGet wire credential:
    /// an API token or a verified workload identity. Browser/password sessions
    /// may administer Forge but must not become package-publish credentials just
    /// because a request also carries an unrelated auth-looking header.
    pub protocol_mutations_allowed: bool,
    /// Package selector for this request's action. Read operations are also
    /// protected by a filtered [`RepoReadOps`] decorator; identifier-addressed
    /// mutations consult this value before touching their backend so excluded
    /// ids have the same 404 response as unknown ids.
    pub package_filter: PackageFilter,
    /// Maximum accepted upload size in bytes; uploads exceeding it yield 413.
    pub max_upload_bytes: u64,
}

impl RouteContext {
    /// The absolute service base `{public_base_url}/v3/{repo}` (no trailing
    /// slash). All Appendix A `@id`s are built from this.
    pub fn base(&self) -> String {
        format!(
            "{}/v3/{}",
            self.public_base_url.trim_end_matches('/'),
            self.repo
        )
    }
}

/// `GET`+`HEAD` for a handler: axum's `get(...)` already routes `HEAD` to the
/// `GET` handler (running it and discarding the body), which is exactly the
/// NuGet requirement, but we spell it out for clarity at each route.
fn get_head<H, T>(handler: H) -> MethodRouter<RouteContext>
where
    H: axum::handler::Handler<T, RouteContext>,
    T: 'static,
{
    get(handler)
}

/// Build the NuGet router for a repository of the given `kind`.
///
/// Routes (all support `GET` and `HEAD`):
/// * `/index.json` — service index
/// * `/flat/{id}/index.json` — flat-container versions
/// * `/flat/{id}/{version}/{filename}` — `.nupkg` bytes or `.nuspec` XML
/// * `/registration/{id}/index.json` — inlined registration page
/// * `/query` — search
pub fn nuget_router(kind: RepoKind, mut ctx: RouteContext) -> Router {
    // The `kind` argument is authoritative for resource advertisement.
    ctx.kind = kind;
    let mut router = Router::new()
        .route("/index.json", get_head(index::service_index))
        .route("/flat/{id}/index.json", get_head(flat::versions))
        .route("/flat/{id}/{version}/{filename}", get_head(flat::content))
        .route(
            "/registration/{id}/index.json",
            get_head(registration::index),
        )
        .route("/query", get_head(search::query));

    // PackagePublish surface — hosted only.
    if kind == RepoKind::Hosted {
        router = router
            .route("/package", put(publish::push))
            // The official NuGet client appends a trailing slash to the
            // PackagePublish `@id` before the PUT (`.../package/`); accept both.
            .route("/package/", put(publish::push))
            .route(
                "/package/{id}/{version}",
                delete(publish::unlist).post(publish::relist),
            );
    }

    router.with_state(ctx)
}

/// Map a [`RepoError`] to an HTTP response.
pub(crate) fn repo_error_response(err: RepoError) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    match err {
        RepoError::RepoNotFound(_) => {
            (StatusCode::NOT_FOUND, "repository not found").into_response()
        }
        RepoError::WrongKind { .. } => {
            (StatusCode::NOT_FOUND, "unsupported for repository").into_response()
        }
        RepoError::Db(_) | RepoError::Storage(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// Map a [`forge_core::WriteError`] to an HTTP response (spec §6 publish status
/// codes): 413 too-large, 409 conflict, 400 invalid, else the wrapped
/// [`RepoError`] mapping (404 / 500).
pub(crate) fn write_error_response(err: forge_core::WriteError) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use forge_core::WriteError;
    match err {
        WriteError::TooLarge { limit } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("upload exceeds limit of {limit} bytes"),
        )
            .into_response(),
        WriteError::Conflict { id, version } => (
            StatusCode::CONFLICT,
            format!("package {id} {version} already exists"),
        )
            .into_response(),
        WriteError::InvalidPackage(e) => {
            (StatusCode::BAD_REQUEST, format!("invalid package: {e}")).into_response()
        }
        WriteError::ForbiddenPackage { .. } => (
            StatusCode::FORBIDDEN,
            "package is outside the authorized scope",
        )
            .into_response(),
        WriteError::Repo(re) => repo_error_response(re),
    }
}
