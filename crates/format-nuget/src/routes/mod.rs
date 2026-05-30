//! NuGet V3 HTTP surface (spec §6, Appendix A).
//!
//! [`nuget_router`] builds an axum [`Router`] for one repository, mounted by
//! the server under `/v3/{repo}`. Handlers read through a [`forge_core::RepoReadOps`]
//! implementation and render the exact JSON shapes from Appendix A. All `@id`s
//! are **absolute**, built from `public_base_url + /v3/{repo}`.
//!
//! `PackagePublish` is advertised in the service index for **hosted** repos
//! only; proxy/group advertise read resources. The publish routes themselves
//! land in Phase 7.

pub mod flat;
pub mod index;
pub mod registration;
pub mod search;

use std::sync::Arc;

use async_trait::async_trait;
use axum::routing::{get, MethodRouter};
use axum::Router;
use forge_core::format::Format;
use forge_core::repo::{RepoError, RepoKind};
use forge_core::RepoReadOps;

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
    Router::new()
        .route("/index.json", get_head(index::service_index))
        .route("/flat/{id}/index.json", get_head(flat::versions))
        .route("/flat/{id}/{version}/{filename}", get_head(flat::content))
        .route(
            "/registration/{id}/index.json",
            get_head(registration::index),
        )
        .route("/query", get_head(search::query))
        .with_state(ctx)
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
