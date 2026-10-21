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
//!
//! Every response carries [`harden_response_headers`]: the feed serves
//! publisher-controlled bytes (`.nuspec` XML, package files, README-bearing
//! metadata) on the same origin as the admin UI, so a browser must never
//! render one as an active document.

pub mod flat;
pub mod index;
pub mod publish;
pub mod registration;
pub mod search;

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::Response;
use axum::routing::{delete, get, put, MethodRouter};
use axum::Router;
use forge_core::authz::PackageFilter;
use forge_core::format::Format;
use forge_core::repo::{RepoError, RepoKind};
use forge_core::{NupkgLocation, RepoReadOps, RepoWriteOps};

/// Default maximum accepted upload size (bytes) when the server does not
/// override it. Mirrors a generous NuGet package size ceiling; the real limit
/// comes from server config (`server.max_upload_bytes`).
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Allowance for multipart framing (boundaries, part headers) on top of the
/// package-size limit when bounding the raw request body.
const MULTIPART_OVERHEAD_BYTES: u64 = 1024 * 1024;

/// A package body streamed from the blob store chunk by chunk.
pub type BlobByteStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = std::io::Result<bytes::Bytes>> + Send>>;

/// Stream the bytes of a stored `.nupkg` blob.
///
/// Abstracted (like [`forge_core::repo::hosted::BlobFetch`]) so the route layer
/// is independent of the S3 client and so handler tests can stub blob bytes.
/// Packages are streamed to the client — never buffered whole in memory.
#[async_trait]
pub trait NupkgBytes: Send + Sync {
    /// Open `range` of the blob at `loc` (all of it for `None`) as a byte
    /// stream. A range is only asked for when [`Self::serves_ranges`].
    async fn open(
        &self,
        loc: &NupkgLocation,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<BlobByteStream, RepoError>;

    /// Whether [`Self::open`] serves byte ranges, so downloads answer `Range`
    /// requests (`206`). Off by default: the server enables it with the
    /// local blob cache, which serves ranges from the cached file.
    fn serves_ranges(&self) -> bool {
        false
    }
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
/// * `/registration/{id}/index.json` — registration index (inlined pages up
///   to 128 versions)
/// * `/registration/{id}/page/{lower}/{upper}.json` — one registration page
/// * `/registration/{id}/{version}.json` — registration leaf
/// * `/catalog/{id}/{version}.json` — catalog entry
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
        .route(
            "/registration/{id}/{leaf}",
            get_head(registration::leaf_document),
        )
        .route(
            "/registration/{id}/page/{lower}/{upper}",
            get_head(registration::page),
        )
        .route(
            "/catalog/{id}/{leaf}",
            get_head(registration::catalog_document),
        )
        .route("/query", get_head(search::query));

    // PackagePublish surface — hosted only.
    if kind == RepoKind::Hosted {
        // axum's extractors default to a 2 MiB request-body limit, which would
        // reject every real-sized package. The upload is streamed to a temp
        // file (never buffered), and the CAS enforces `max_upload_bytes` on
        // the package bytes; the raw body bound only adds framing slack.
        let body_limit = usize::try_from(
            ctx.max_upload_bytes
                .saturating_add(MULTIPART_OVERHEAD_BYTES),
        )
        .unwrap_or(usize::MAX);
        let push = put(publish::push).layer(DefaultBodyLimit::max(body_limit));
        router = router
            .route("/package", push.clone())
            // The official NuGet client appends a trailing slash to the
            // PackagePublish `@id` before the PUT (`.../package/`); accept both.
            .route("/package/", push)
            .route(
                "/package/{id}/{version}",
                delete(publish::unlist).post(publish::relist),
            );
    }

    router
        .with_state(ctx)
        .layer(axum::middleware::map_response(hardened))
}

/// `Content-Security-Policy` of every feed response: no subresources, no
/// script, and an opaque-origin sandbox, so even a document a browser renders
/// (e.g. a `.nuspec` opened as XML with an XHTML `<script>`) runs nothing and
/// cannot reach the admin origin's cookies or API.
pub const FEED_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; sandbox";

/// Make a feed response inert in a browser: a sandboxing CSP (always, over any
/// weaker policy), `Content-Disposition: attachment` (unless the handler named
/// a file) and `X-Content-Type-Options: nosniff`.
///
/// NuGet clients ignore all three. The server applies this to every
/// `/v3/{repo}` response, including the ones it answers before reaching this
/// router (unknown repository, 401/403).
pub fn harden_response_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(FEED_CONTENT_SECURITY_POLICY),
    );
    if !headers.contains_key(header::CONTENT_DISPOSITION) {
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment"),
        );
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

async fn hardened(mut response: Response) -> Response {
    harden_response_headers(response.headers_mut());
    response
}

/// The lowered package id of a request path, or `None` when it is not a
/// well-formed id ([`Format::validate_id`]). Every id-addressed route answers
/// such a request 404 before any backend sees it: a proxy pastes the id into
/// credentialed upstream URLs, where `/`, `..`, `?` or `#` (all reachable
/// through percent-encoding) would redirect the request.
pub(crate) fn package_id(ctx: &RouteContext, raw: &str) -> Option<String> {
    let lower = ctx.format.lower_id(raw);
    ctx.format.validate_id(&lower).ok().map(|()| lower)
}

/// The normalized version of a request path, or `None` when it is not a
/// version or is longer than any publishable one
/// ([`crate::version::MAX_VERSION_LENGTH`]). Such a request answers 404
/// before any backend sees it.
pub(crate) fn package_version(ctx: &RouteContext, raw: &str) -> Option<String> {
    if raw.trim().len() > crate::version::MAX_VERSION_LENGTH {
        return None;
    }
    ctx.format.normalize_version(raw).ok()
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
        RepoError::Busy(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "30")],
            "temporarily unavailable, try again later",
        )
            .into_response(),
        RepoError::FormatUnavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "repository format unavailable",
        )
            .into_response(),
    }
}

/// Map a [`forge_core::WriteError`] to an HTTP response (spec §6 publish status
/// codes): 413 too-large, 409 conflict, 400 invalid, else the wrapped
/// [`RepoError`] mapping (404 / 500 / 503).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A full staging budget is "try again later", not a server error.
    #[test]
    fn busy_is_503_with_retry_after() {
        let resp = repo_error_response(RepoError::Busy("staging".into()));
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER).unwrap(),
            "30"
        );
        let resp = write_error_response(forge_core::WriteError::Repo(RepoError::Busy(
            "staging".into(),
        )));
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
}
