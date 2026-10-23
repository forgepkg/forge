//! Format plugins: the built-in ones, and serving the repositories of their
//! formats under each format's mount, `{mount}/{repo}/...` (`/repository`
//! unless its `plugin.toml` names another; see `docs/format-plugins.md`).
//!
//! The dispatcher does what [`crate::dispatch`] does for the NuGet feed —
//! resolve the repository, authorize the request's action (GET/HEAD read,
//! PUT/POST write, DELETE delete), refuse an offline repository — and then
//! lets the format's plugin decide what the request is
//! ([`FormatPlugin::handle`]).
//! Everything that touches data stays here:
//!
//! * **Queries** the plugin asks for run through the same read ops as every
//!   other read ([`AppState::read_ops_for`]): package selectors, group
//!   members the caller cannot see, prefer-hosted and reserved prefixes all
//!   apply, and an id the format does not accept is unknown. A request may
//!   load at most [`MAX_QUERIES`] answers in at most [`MAX_ROUNDS`] rounds.
//! * **Downloads** are streamed from the blob store and counted, exactly as
//!   NuGet's, answering a single `Range` when the blob source serves ranges.
//! * **Publishing, unlisting, relisting and deleting** go through the hosted
//!   write path (CAS staging, size cap, selector and redeploy policy,
//!   trusted-publishing audit), and only when the request's method was
//!   authorized for that action and carries an API token or workload
//!   identity.
//! * **Responses** the plugin renders keep only the headers in
//!   [`PASSED_RESPONSE_HEADERS`] (no cookies, no CORS, no redirects off this
//!   repository) and get the feed's hardening headers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::feed::{byte_range, ByteRange, PackageBytes};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use forge_core::auth::principal::Principal;
use forge_core::authz::{Action as Permission, PackageFilter};
use forge_core::format::Format;
use forge_core::repo::{
    DeleteOutcome, RegistrationEntry, RepoError, RepoKind, RepoReadOps, RepoWriteOps, SearchParams,
    UploadReader, WriteError,
};
use forge_db::model::Repository;
use forge_db::repository_dao;
use forge_plugin::api::{
    self as protocol, Action, Answer, ChangeRequest, FormatPlugin, Loaded, PackageInfo, PackageRef,
    PublishRequest, Query, Rendered, Upload,
};
use forge_plugin::Plugin;
use futures_util::{StreamExt, TryStreamExt};
use tokio_util::io::StreamReader;

use crate::dispatch::{
    action_for_method, authz_denied, offline_response, offline_serves_nothing,
    principal_allows_protocol_mutations, HostedWriteAdapter,
};
use crate::middleware::principal_of;
use crate::state::AppState;

/// Where a plugin format's repositories are served unless its
/// `plugin.toml` names another mount.
pub const MOUNT: &str = forge_plugin::manifest::DEFAULT_MOUNT;

/// The most rounds of queries one request may load.
pub const MAX_ROUNDS: usize = 4;

/// The most query answers one request may load.
pub const MAX_QUERIES: usize = 2048;

/// Queries answered at once.
const CONCURRENT_QUERIES: usize = 16;

/// Request headers a plugin sees. Never credentials or cookies.
pub const PASSED_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "user-agent",
];

/// Response headers a plugin may set. `location` only within its repository.
pub const PASSED_RESPONSE_HEADERS: &[&str] = &[
    "allow",
    "cache-control",
    "content-disposition",
    "content-language",
    "content-type",
    "etag",
    "last-modified",
    "location",
];

/// The format plugins built into this server: crates under `plugins/<id>/`,
/// linked in and always installed (NuGet). NuGet reads archives under
/// `nuget_limits` (`[nuget]`).
pub fn builtin(nuget_limits: forge_format_nuget::NupkgLimits) -> Vec<Arc<Plugin>> {
    vec![Plugin::builtin(
        forge_format_nuget::PLUGIN_TOML,
        forge_format_nuget::Nuget::with_limits(nuget_limits),
    )
    .expect("plugins/nuget/plugin.toml is valid")]
}

/// Axum handler mounted at `/repository/{repo}` (and everything under it).
pub async fn dispatch(State(state): State<AppState>, req: Request<Body>) -> Response {
    let mut response = dispatch_request(state, req).await;
    crate::feed::harden_response_headers(response.headers_mut());
    response
}

/// `(mount, repository name, rest of the path)` of a `{mount}/{repo}/...`
/// path, for one of `mounts`; the rest starts with `/`.
fn split_path<'p>(path: &'p str, mounts: &[&str]) -> Option<(&'p str, &'p str, &'p str)> {
    mounts.iter().find_map(|mount| {
        let rest = path.strip_prefix(mount)?.strip_prefix('/')?;
        let (name, rest) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, "/"),
        };
        (!name.is_empty()).then(|| (&path[..mount.len()], name, rest))
    })
}

async fn dispatch_request(state: AppState, req: Request<Body>) -> Response {
    let principal = principal_of(&req);
    let method = req.method().clone();
    let uri = req.uri().clone();
    let mounts = state.formats.mounts();
    let Some((mount, repo_name, rest)) = split_path(uri.path(), &mounts) else {
        return (StatusCode::NOT_FOUND, "repository not found").into_response();
    };

    let repo = match repository_dao::find_repository_by_name(&state.pool, repo_name).await {
        Ok(Some(r)) => r,
        // As for the NuGet feed: an unknown name answers like a repository
        // the caller may not read, except to a global admin.
        Ok(None) if state.authz.is_global_admin(&principal).await => {
            return (StatusCode::NOT_FOUND, "repository not found").into_response();
        }
        Ok(None) => return authz_denied(&principal),
        Err(e) => {
            tracing::error!(error = %e, repo = %repo_name, "repo lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let permission = action_for_method(&method);
    let allowed = match permission {
        Permission::Read => state.authz.can_read(&principal, &repo).await,
        Permission::Write => state.authz.can_write(&principal, &repo).await,
        Permission::Delete => state.authz.can_delete(&principal, &repo).await,
        Permission::Admin => false,
    };
    if !allowed {
        return authz_denied(&principal);
    }
    if offline_serves_nothing(&repo) {
        return offline_response();
    }
    let Some(plugin) = state.formats.plugin(&repo.format) else {
        return if state.formats.is_installed(&repo.format) {
            // A built-in format has its own mount (NuGet: `/v3`, Docker:
            // `/v2`).
            (StatusCode::NOT_FOUND, "repository is not served here").into_response()
        } else {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "the repository's format is not installed on this server",
            )
                .into_response()
        };
    };
    // Each format is served under its own mount only.
    if plugin.manifest().mount != mount {
        return (StatusCode::NOT_FOUND, "repository is not served here").into_response();
    }
    let format = match state.formats.for_repository(&repo) {
        Ok(format) => format,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };
    let package_filter = state
        .authz
        .package_filter_for(&principal, &repo, permission)
        .await;
    let ops = match state.read_ops_for(&repo, principal).await {
        Ok(ops) => ops,
        Err(e) => return repo_error(e),
    };

    let target = protocol::Repository {
        name: repo.name.clone(),
        kind: match repo.kind() {
            RepoKind::Hosted => protocol::RepositoryKind::Hosted,
            RepoKind::Proxy => protocol::RepositoryKind::Proxy,
            RepoKind::Group => protocol::RepositoryKind::Group,
        },
        base_url: repository_url(&state, mount, &repo.name),
    };
    let request = protocol::Request {
        method: method.as_str().to_string(),
        path: rest.to_string(),
        query: uri.query().unwrap_or("").to_string(),
        headers: req
            .headers()
            .iter()
            .filter(|(name, _)| PASSED_REQUEST_HEADERS.contains(&name.as_str()))
            .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
            .collect(),
    };

    let ctx = Ctx {
        state: &state,
        repo: &repo,
        mount,
        principal,
        permission,
        head: method == Method::HEAD,
        headers: req.headers().clone(),
        plugin: plugin.implementation().clone(),
        format,
        ops,
        package_filter,
        target,
    };
    let handled = {
        let (target, request) = (ctx.target.clone(), request.clone());
        ctx.call(move |plugin| plugin.handle(&target, &request))
            .await
    };
    let response = match handled {
        Ok(action) => ctx.perform(action, request, req).await,
        Err(response) => response,
    };
    if permission != Permission::Read {
        // The same audit trail as the NuGet feed's package mutations.
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

/// One request's resolved repository, caller and plugin.
struct Ctx<'a> {
    state: &'a AppState,
    repo: &'a Repository,
    /// The format's mount (`/repository`).
    mount: &'a str,
    principal: Principal,
    /// What the request's method was authorized for.
    permission: Permission,
    head: bool,
    /// The request's headers, for a download's `Range`.
    headers: axum::http::HeaderMap,
    plugin: Arc<dyn FormatPlugin>,
    format: Arc<dyn Format>,
    ops: Arc<dyn RepoReadOps>,
    /// The caller's package selector for [`Self::permission`].
    package_filter: PackageFilter,
    target: protocol::Repository,
}

impl Ctx<'_> {
    /// Run a protocol call of the plugin off the async workers: rendering a
    /// large listing takes a while. A plugin that panics answers 500.
    async fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn FormatPlugin) -> R + Send + 'static,
    ) -> Result<R, Response> {
        let plugin = Arc::clone(&self.plugin);
        tokio::task::spawn_blocking(move || f(plugin.as_ref()))
            .await
            .map_err(|e| plugin_failed(self.repo, &e))
    }

    async fn perform(
        &self,
        action: Action,
        request: protocol::Request,
        req: Request<Body>,
    ) -> Response {
        match action {
            Action::Respond(response) => self.respond(response),
            Action::Load(queries) => self.render(queries, request).await,
            Action::Download(target) => {
                if self.permission != Permission::Read {
                    return refused("download");
                }
                self.download(&target).await
            }
            Action::Publish(publish) => self.publish(publish, req).await,
            Action::Unlist(change) => self.change(change, Change::Unlist).await,
            Action::Relist(change) => self.change(change, Change::Relist).await,
            Action::Delete(change) => self.change(change, Change::Delete).await,
        }
    }

    /// The canonical id the format makes of `raw`, if it is a valid id.
    fn id(&self, raw: &str) -> Option<String> {
        let id = self.format.lower_id(raw);
        self.format.validate_id(&id).ok().map(|()| id)
    }

    /// `(canonical id, normalized version)` of `target`, if both are valid.
    fn package(&self, target: &PackageRef) -> Option<(String, String)> {
        let id = self.id(&target.id)?;
        let version = self.format.normalize_version(&target.version).ok()?;
        Some((id, version))
    }

    /// Load data and let the plugin render it, round by round.
    async fn render(&self, mut queries: Vec<Query>, request: protocol::Request) -> Response {
        let mut data: Vec<Loaded> = Vec::new();
        for _ in 0..MAX_ROUNDS {
            if data.len() + queries.len() > MAX_QUERIES {
                break;
            }
            let pending: Vec<_> = queries.iter().map(|query| self.answer(query)).collect();
            let answers: Vec<Answer> = match futures_util::stream::iter(pending)
                .buffered(CONCURRENT_QUERIES)
                .try_collect()
                .await
            {
                Ok(answers) => answers,
                Err(e) => return repo_error(e),
            };
            data.extend(
                queries
                    .into_iter()
                    .zip(answers)
                    .map(|(query, answer)| Loaded { query, answer }),
            );
            let (target, req) = (self.target.clone(), request.clone());
            let rendered = self
                .call(move |plugin| {
                    let rendered = plugin.render(&target, &req, &data);
                    (rendered, data)
                })
                .await;
            match rendered {
                Ok((Rendered::Respond(response), _)) => return self.respond(response),
                Ok((Rendered::Load(more), loaded)) => {
                    data = loaded;
                    queries = more;
                }
                Err(response) => return response,
            }
        }
        tracing::warn!(
            repo = %self.repo.name,
            format = %self.repo.format,
            "format plugin asked for more data than one request may load"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "the response needs more data than one request may load",
        )
            .into_response()
    }

    async fn answer(&self, query: &Query) -> Result<Answer, RepoError> {
        let repo = &self.repo.name;
        Ok(match query {
            Query::Versions(id) => Answer::Versions(match self.id(id) {
                Some(id) => self
                    .ops
                    .list_versions(repo, &id)
                    .await?
                    .into_iter()
                    .map(|v| protocol::VersionInfo {
                        original_id: v.original_id,
                        version: v.version,
                        version_original: v.version_original,
                        listed: v.listed,
                    })
                    .collect(),
                None => Vec::new(),
            }),
            Query::Packages(id) => Answer::Packages(match self.id(id) {
                Some(id) => self
                    .ops
                    .registration(repo, &id)
                    .await?
                    .into_iter()
                    .map(|entry| self.package_info(entry))
                    .collect(),
                None => Vec::new(),
            }),
            Query::Package(target) => Answer::Package(match self.package(target) {
                Some((id, version)) => self
                    .ops
                    .registration_entry(repo, &id, &version)
                    .await?
                    .map(|entry| self.package_info(entry)),
                None => None,
            }),
            Query::PackagesOf(set) => Answer::Packages(match self.id(&set.id) {
                Some(id) => {
                    // Versions that do not normalize are not the package's.
                    let versions: Vec<String> = set
                        .versions
                        .iter()
                        .filter_map(|v| self.format.normalize_version(v).ok())
                        .collect();
                    let mut entries = if versions.is_empty() {
                        Vec::new()
                    } else {
                        self.ops.registration_entries(repo, &id, &versions).await?
                    };
                    entries.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));
                    entries
                        .into_iter()
                        .map(|entry| self.package_info(entry))
                        .collect()
                }
                None => Vec::new(),
            }),
            Query::Manifest(target) => Answer::Manifest(match self.package(target) {
                Some((id, version)) => self.ops.resolve_nuspec(repo, &id, &version).await?,
                None => None,
            }),
            Query::Search(search) => {
                // The read ops clamp `take` (0 is the default page).
                let params = SearchParams {
                    q: search.text.clone(),
                    skip: search.skip as usize,
                    take: search.take as usize,
                    prerelease: search.prerelease,
                    include_semver2: search.semver2,
                    include_upstream: search.upstream,
                };
                let result = self.ops.search(repo, &params).await?;
                Answer::Search(protocol::SearchResult {
                    total: u32::try_from(result.total_hits).unwrap_or(u32::MAX),
                    hits: result
                        .hits
                        .into_iter()
                        .map(|hit| protocol::SearchHit {
                            original_id: hit.original_id,
                            latest_version: hit.latest_version,
                            versions: hit
                                .versions
                                .into_iter()
                                .map(|v| protocol::VersionInfo {
                                    original_id: v.original_id,
                                    version: v.version,
                                    version_original: v.version_original,
                                    listed: v.listed,
                                })
                                .collect(),
                            summary: self
                                .summary(hit.manifest_summary, hit.nuspec_bytes.as_deref()),
                            total_downloads: hit
                                .total_downloads
                                .and_then(|n| u64::try_from(n).ok()),
                        })
                        .collect(),
                })
            }
        })
    }

    /// Stream a stored package, as the NuGet feed serves a `.nupkg`.
    async fn download(&self, target: &PackageRef) -> Response {
        let Some((id, version)) = self.package(target) else {
            return (StatusCode::NOT_FOUND, "package not found").into_response();
        };
        // A HEAD (a probe, a mirror tool) is not a download.
        let resolved = if self.head {
            self.ops
                .resolve_nupkg_head(&self.repo.name, &id, &version)
                .await
        } else {
            self.ops.resolve_nupkg(&self.repo.name, &id, &version).await
        };
        let location = match resolved {
            Ok(Some(location)) => location,
            Ok(None) => return (StatusCode::NOT_FOUND, "package not found").into_response(),
            Err(e) => return repo_error(e),
        };
        let size = u64::try_from(location.size).unwrap_or(0);
        let blobs = self.state.blob_bytes();
        let ranges = blobs.serves_ranges();
        let mut headers = axum::http::HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&location.content_type) {
            headers.insert(header::CONTENT_TYPE, value);
        }
        if ranges {
            headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        }
        let requested = if ranges && !self.head {
            byte_range(&self.headers, size)
        } else {
            ByteRange::Full
        };
        let (status, range) = match requested {
            ByteRange::Full => (StatusCode::OK, None),
            ByteRange::Partial(range) => {
                headers.insert(
                    header::CONTENT_RANGE,
                    numeric_header(format!("bytes {}-{}/{size}", range.start, range.end - 1)),
                );
                (StatusCode::PARTIAL_CONTENT, Some(range))
            }
            ByteRange::Unsatisfiable => {
                headers.insert(
                    header::CONTENT_RANGE,
                    numeric_header(format!("bytes */{size}")),
                );
                return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
            }
        };
        let length = range.as_ref().map_or(size, |r| r.end - r.start);
        headers.insert(header::CONTENT_LENGTH, numeric_header(length.to_string()));
        // A HEAD needs the headers only; don't open (or bill) a GET for it.
        if self.head {
            return (status, headers).into_response();
        }
        match blobs.open(&location, range).await {
            Ok(stream) => (status, headers, Body::from_stream(stream)).into_response(),
            Err(e) => repo_error(e),
        }
    }

    /// A version's metadata as the plugin sees it.
    fn package_info(&self, entry: RegistrationEntry) -> PackageInfo {
        PackageInfo {
            summary: self.summary(entry.manifest_summary, entry.nuspec_bytes.as_deref()),
            original_id: entry.original_id,
            version: entry.version,
            version_original: entry.version_original,
            listed: entry.listed,
            published: entry
                .published
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, false)),
            sha256: entry.package_sha256,
            sha512: entry.package_hash_sha512_base64,
            size: entry.package_size.and_then(|s| u64::try_from(s).ok()),
        }
    }

    /// The manifest summary stored with a version, or, for a version
    /// published before summaries were stored, the one its manifest gives.
    fn summary(
        &self,
        stored: Option<serde_json::Value>,
        manifest: Option<&[u8]>,
    ) -> Option<String> {
        stored
            .or_else(|| manifest.and_then(|m| self.format.manifest_summary(m)))
            .map(|s| s.to_string())
    }

    /// Whether this request may change packages: a hosted repository, a
    /// method authorized for `needed`, and a package-client credential.
    fn may_change(&self, needed: Permission, what: &str) -> Result<(), Response> {
        if self.permission != needed {
            return Err(refused(what));
        }
        if self.repo.kind() != RepoKind::Hosted {
            return Err((
                StatusCode::METHOD_NOT_ALLOWED,
                "packages can only be changed in hosted repositories",
            )
                .into_response());
        }
        // As for NuGet: a browser session is not a publishing credential.
        if !principal_allows_protocol_mutations(&self.principal) {
            return Err((
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"Forge\"")],
                "API token or workload identity required",
            )
                .into_response());
        }
        Ok(())
    }

    fn writer(&self) -> HostedWriteAdapter {
        HostedWriteAdapter::new(
            self.state,
            self.format.clone(),
            self.repo.id,
            self.repo.name.clone(),
            self.principal,
            self.package_filter.clone(),
            // Set by `publish` when a redeploy may replace a version.
            PackageFilter::DenyAll,
        )
    }

    async fn publish(&self, publish: PublishRequest, req: Request<Body>) -> Response {
        if let Err(response) = self.may_change(Permission::Write, "publish") {
            return response;
        }
        // A redeploy replaces a version's bytes: it takes the delete
        // permission's selector as well.
        let replace_filter = self
            .state
            .authz
            .package_filter_for(&self.principal, self.repo, Permission::Delete)
            .await;
        let writer = HostedWriteAdapter::new(
            self.state,
            self.format.clone(),
            self.repo.id,
            self.repo.name.clone(),
            self.principal,
            self.package_filter.clone(),
            replace_filter,
        );
        let limit = self.state.upload_limit(self.repo);
        let flags = UploadFlags::default();
        let reader = match &publish.upload {
            Upload::Body => body_reader(req.into_body()),
            Upload::MultipartField(name) => {
                match multipart_reader(req, Some(name), limit, &flags) {
                    Ok(reader) => reader,
                    Err(response) => return response,
                }
            }
            Upload::FirstPart => match multipart_reader(req, None, limit, &flags) {
                Ok(reader) => reader,
                Err(response) => return response,
            },
        };
        match writer.store_upload(&self.repo.name, reader, limit).await {
            Ok(_) => self.respond(publish.done),
            Err(_) if flags.too_large.load(Ordering::Relaxed) => {
                write_error(WriteError::TooLarge { limit })
            }
            Err(_) if flags.preamble.load(Ordering::Relaxed) => (
                StatusCode::BAD_REQUEST,
                "multipart body: no package part within the first 64 KiB",
            )
                .into_response(),
            Err(_) if flags.missing.load(Ordering::Relaxed) => (
                StatusCode::BAD_REQUEST,
                "multipart body: the package part is missing",
            )
                .into_response(),
            Err(e) => write_error(e),
        }
    }

    async fn change(&self, change: ChangeRequest, kind: Change) -> Response {
        let (needed, what) = match kind {
            Change::Unlist => (Permission::Delete, "unlist"),
            Change::Relist => (Permission::Write, "relist"),
            Change::Delete => (Permission::Delete, "delete"),
        };
        if let Err(response) = self.may_change(needed, what) {
            return response;
        }
        // A package outside the caller's selector answers like an unknown
        // one, as for NuGet.
        let Some((id, version)) = self
            .package(&change.target)
            .filter(|(id, _)| self.package_filter.allows(id))
        else {
            return (StatusCode::NOT_FOUND, "package not found").into_response();
        };
        let writer = self.writer();
        let outcome = match kind {
            Change::Unlist => writer.delete_component(&self.repo.name, &id, &version, false),
            Change::Delete => writer.delete_component(&self.repo.name, &id, &version, true),
            Change::Relist => writer.relist(&self.repo.name, &id, &version),
        }
        .await;
        match outcome {
            Ok(DeleteOutcome::NotFound) => {
                (StatusCode::NOT_FOUND, "package not found").into_response()
            }
            Ok(_) => self.respond(change.done),
            Err(e) => write_error(e),
        }
    }

    /// A response the plugin rendered, with only the headers it may set.
    fn respond(&self, response: protocol::Response) -> Response {
        let Some(status) = StatusCode::from_u16(response.status)
            .ok()
            .filter(|s| !s.is_informational())
        else {
            tracing::warn!(repo = %self.repo.name, status = response.status, "format plugin answered an invalid status");
            return (StatusCode::INTERNAL_SERVER_ERROR, "format plugin failed").into_response();
        };
        let mut out = Response::new(Body::empty());
        *out.status_mut() = status;
        for (name, value) in &response.headers {
            let name = name.to_ascii_lowercase();
            if !PASSED_RESPONSE_HEADERS.contains(&name.as_str()) {
                continue;
            }
            if name == "location" && !self.within_repository(value) {
                continue;
            }
            let (Ok(name), Ok(value)) = (
                header::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                continue;
            };
            out.headers_mut().append(name, value);
        }
        out.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from(response.body.len()),
        );
        if !self.head {
            *out.body_mut() = Body::from(response.body);
        }
        out
    }

    /// Whether a redirect target stays inside this repository: it starts
    /// with the repository's path or URL and has no dot segments, literal or
    /// percent-encoded (URL parsers resolve `%2e%2e` like `..`), and no
    /// backslashes (which browsers read as `/`).
    fn within_repository(&self, location: &str) -> bool {
        within(location, self.mount, &self.repo.name, &self.target.base_url)
    }
}

#[derive(Clone, Copy)]
enum Change {
    Unlist,
    Relist,
    Delete,
}

/// Why an upload stream failed, for the right status.
#[derive(Default, Clone)]
struct UploadFlags {
    too_large: Arc<AtomicBool>,
    preamble: Arc<AtomicBool>,
    missing: Arc<AtomicBool>,
}

/// The request body as the package.
fn body_reader(body: Body) -> UploadReader {
    let stream = body
        .into_data_stream()
        .map(|chunk| chunk.map_err(std::io::Error::other));
    Box::new(StreamReader::new(stream))
}

/// The multipart part named `field` (the first part for `None`) as the
/// package, streamed: the parts before it are skipped, never buffered.
fn multipart_reader(
    req: Request<Body>,
    field: Option<&str>,
    limit: u64,
    flags: &UploadFlags,
) -> Result<UploadReader, Response> {
    let Some(boundary) = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::feed::multipart_boundary)
    else {
        // As axum's multipart extractor answers (NuGet's push always has).
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid `boundary` for `multipart/form-data` request",
        )
            .into_response());
    };
    let guarded = crate::feed::preamble_guard(
        req.into_body().into_data_stream(),
        &boundary,
        flags.preamble.clone(),
    );
    // The whole body may exceed the package by the multipart framing and
    // whatever small parts precede it.
    let constraints = multer::Constraints::new().size_limit(
        multer::SizeLimit::new()
            .whole_stream(limit.saturating_add(1024 * 1024))
            .per_field(limit.saturating_add(1)),
    );
    let mut multipart = multer::Multipart::with_constraints(guarded, boundary, constraints);
    let field = field.map(str::to_string);
    let flags = flags.clone();
    let stream = async_stream::try_stream! {
        let too_large = |e: multer::Error| {
            if matches!(e, multer::Error::StreamSizeExceeded { .. } | multer::Error::FieldSizeExceeded { .. }) {
                flags.too_large.store(true, Ordering::Relaxed);
            }
            std::io::Error::other(e)
        };
        let mut found = false;
        while let Some(mut part) = multipart.next_field().await.map_err(too_large)? {
            if field.as_deref().is_some_and(|field| part.name() != Some(field)) {
                // Skip a part before the package, chunk by chunk.
                while part.chunk().await.map_err(too_large)?.is_some() {}
                continue;
            }
            found = true;
            while let Some(chunk) = part.chunk().await.map_err(too_large)? {
                yield chunk;
            }
            break;
        }
        if !found {
            flags.missing.store(true, Ordering::Relaxed);
            Err(std::io::Error::other("missing package part"))?;
        }
    };
    let stream: std::pin::Pin<Box<dyn futures_util::Stream<Item = std::io::Result<Bytes>> + Send>> =
        Box::pin(stream);
    Ok(Box::new(StreamReader::new(stream)))
}

/// The absolute URL of repository `name` served under `mount`:
/// `{public_base_url}{mount}/{name}`, the base its plugin builds URLs on and
/// the address its clients are given.
pub fn repository_url(state: &AppState, mount: &str, name: &str) -> String {
    format!(
        "{}{mount}/{name}",
        state.config.public_base_url().trim_end_matches('/')
    )
}

/// See [`Ctx::within_repository`].
fn within(location: &str, mount: &str, repo: &str, base_url: &str) -> bool {
    let path_prefix = format!("{mount}/{repo}/");
    let absolute_prefix = format!("{base_url}/");
    let lower = location.to_ascii_lowercase();
    (location.starts_with(&path_prefix) || location.starts_with(&absolute_prefix))
        && !location
            .split(['/', '?', '#'])
            .any(|seg| seg == ".." || seg == ".")
        && !lower.contains("%2e")
        && !location.contains('\\')
}

/// A header value of ASCII digits and punctuation.
fn numeric_header(value: String) -> HeaderValue {
    HeaderValue::from_str(&value).expect("ASCII header value")
}

/// A plugin returned an action the request's method was not authorized for
/// (a download for a POST, a publish for a GET).
fn refused(what: &str) -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        format!("{what} is not possible with this method"),
    )
        .into_response()
}

fn plugin_failed(repo: &Repository, e: &dyn std::fmt::Display) -> Response {
    tracing::error!(repo = %repo.name, format = %repo.format, error = %e, "format plugin failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "format plugin failed").into_response()
}

fn repo_error(e: RepoError) -> Response {
    match e {
        RepoError::RepoNotFound(_) => {
            (StatusCode::NOT_FOUND, "repository not found").into_response()
        }
        RepoError::WrongKind { .. } => {
            (StatusCode::NOT_FOUND, "unsupported for repository").into_response()
        }
        RepoError::Busy(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "30")],
            "temporarily unavailable, try again later",
        )
            .into_response(),
        RepoError::FormatUnavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "the repository's format is not installed on this server",
        )
            .into_response(),
        RepoError::Db(_) | RepoError::Storage(_) => {
            tracing::error!(error = %e, "plugin repository read failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

fn write_error(e: WriteError) -> Response {
    match e {
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
        WriteError::Repo(e) => repo_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_repository_paths() {
        let mounts = ["/repository", "/charts"];
        let split = |path| split_path(path, &mounts);
        assert_eq!(
            split("/repository/charts/index.yaml"),
            Some(("/repository", "charts", "/index.yaml"))
        );
        assert_eq!(
            split("/repository/charts"),
            Some(("/repository", "charts", "/"))
        );
        assert_eq!(
            split("/repository/charts/"),
            Some(("/repository", "charts", "/"))
        );
        assert_eq!(
            split("/repository/charts/api/charts/x/1.0.0"),
            Some(("/repository", "charts", "/api/charts/x/1.0.0"))
        );
        assert_eq!(
            split("/charts/stable/index.yaml"),
            Some(("/charts", "stable", "/index.yaml"))
        );
        assert_eq!(split("/repository/"), None);
        assert_eq!(split("/repository"), None);
        assert_eq!(split("/repositoryx/a"), None);
        assert_eq!(split("/chartsx/a"), None);
        assert_eq!(split("/v3/charts"), None);
    }

    #[test]
    fn redirects_stay_inside_the_repository() {
        let base = "https://forge.example.com/repository/charts";
        for ok in [
            "/repository/charts/index.yaml",
            "https://forge.example.com/repository/charts/charts/x/1.0.0/x-1.0.0.tgz",
        ] {
            assert!(within(ok, "/repository", "charts", base), "{ok}");
        }
        for bad in [
            "https://evil.example.com/",
            "//evil.example.com/repository/charts/x",
            "/repository/other/index.yaml",
            "/repository/charts/../../admin/users",
            "/repository/charts/%2e%2e/%2E%2E/admin",
            "/repository/charts/..",
            "/repository/charts/x\\..\\..\\admin",
            "/admin",
        ] {
            assert!(!within(bad, "/repository", "charts", base), "{bad}");
        }
    }
}
