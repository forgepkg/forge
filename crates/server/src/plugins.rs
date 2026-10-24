//! Format plugins: the built-in ones, and serving the repositories of their
//! formats under each format's mount, `{mount}/{repo}/...` (`/repository`
//! unless its descriptor names another; see `docs/format-plugins.md`).
//!
//! The dispatcher resolves the repository, authenticates the caller (an
//! `Authorization: Bearer` API token too, as npm sends it), refuses an
//! offline repository, and lets the format's plugin decide what the request
//! is ([`FormatPlugin::handle`]). It then checks the answer against what
//! the caller may do and does everything that touches data itself:
//!
//! * **Queries** the plugin asks for run through the same read ops as every
//!   other read ([`AppState::read_ops_for`]): package selectors, group
//!   members the caller cannot see, prefer-hosted and reserved prefixes all
//!   apply, and an id the format does not accept is unknown. A files
//!   format's queries go to the file store ([`crate::files`]), with the same
//!   selectors on paths. A request may load at most [`MAX_QUERIES`] answers
//!   in at most [`MAX_ROUNDS`] rounds. They, responses, downloads and
//!   forwards need read.
//! * **Downloads** are streamed from the blob store and counted, exactly as
//!   NuGet's, answering a single `Range` when the blob source serves ranges;
//!   a file is served by the file store ([`crate::files::serve`]).
//! * **Publishing and changes** (unlist, relist, delete, deprecate, tags) go
//!   through the hosted write path (CAS staging, size cap, selector and
//!   redeploy policy, trusted-publishing audit) of the repository, or of a
//!   group's writable member, with the permission each needs, never for a
//!   GET, and only with an API token or workload identity. A files format's
//!   requests are authorized by their method up front (GET and HEAD read,
//!   PUT and POST write, DELETE delete), and receiving, storing and deleting
//!   files go through the file store's write path.
//! * **Bodies** are read when the plugin asks ([`Action::ReadBody`]), bounded,
//!   for a caller with the permission their use needs.
//! * **Logins** ([`Action::Auth`]) are the host's ([`crate::cli_auth`]).
//! * **Forwards** ([`Action::Forward`]) go to the repository's upstream, or
//!   a group's first proxy member, with its credentials.
//! * **Responses** the plugin renders keep only the headers in
//!   [`PASSED_RESPONSE_HEADERS`] (no cookies, no CORS, no redirects or links
//!   off this repository) and get the feed's hardening headers.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use forge_core::auth::principal::Principal;
use forge_core::auth::token::{check_token, TokenCheck};
use forge_core::authz::Level;
use forge_core::format::Format;
use forge_core::net::upstream::{RequestClass, SpooledBody};
use forge_core::repo::{
    DeleteOutcome, RegistrationEntry, RepoError, RepoKind, RepoReadOps, RepoWriteOps, SearchParams,
    UploadReader, WriteError,
};
use forge_db::model::{DeploymentPolicy, Repository};
use forge_db::raw_dao::RawFile;
use forge_db::{component_dao, repository_dao, tag_dao, user_dao};
use forge_plugin::api::{
    self as protocol, Action, Answer, AuthRequest, BodyRequest, BodyUse, Change, ChangeSet,
    FormatPlugin, Forward, Loaded, PackageInfo, PackageRef, PublishRequest, Query, Unpacked,
    Upload,
};
use forge_plugin::Plugin;
use futures_util::{StreamExt, TryStreamExt};
use tokio_util::io::StreamReader;

use crate::dispatch::{
    authz_denied, level_for_method, offline_response, offline_serves_nothing,
    principal_allows_protocol_mutations, HostedWriteAdapter,
};
use crate::files::store::{Content, Ingested, Part, Via};
use crate::files::{FileError, Files};
use crate::middleware::principal_of;
use crate::state::AppState;

/// Where a plugin format's repositories are served unless its descriptor
/// names another mount.
pub const MOUNT: &str = forge_plugin::api::DEFAULT_MOUNT;

/// The most rounds of queries one request may load.
pub const MAX_ROUNDS: usize = 4;

/// The most query answers one request may load.
pub const MAX_QUERIES: usize = 2048;

/// Queries answered at once.
const CONCURRENT_QUERIES: usize = 16;

/// The largest body a plugin may ask for ([`Action::ReadBody`]).
pub const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// The largest body of a login ([`BodyUse::Login`]).
pub const MAX_LOGIN_BODY_BYTES: u64 = 64 * 1024;

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

/// Response headers a plugin may set. `location` and `link` only within its
/// repository.
pub const PASSED_RESPONSE_HEADERS: &[&str] = &[
    "allow",
    "cache-control",
    "content-disposition",
    "content-language",
    "content-type",
    "etag",
    "last-modified",
    "link",
    "location",
    "retry-after",
    "vary",
];

/// The format plugins built into this server: crates under
/// `crates/formats/<id>/`, linked in and always installed (Docker / OCI,
/// NuGet, npm, raw). NuGet reads archives under `nuget_limits` (`[nuget]`),
/// npm requests under `npm_limits` (`[npm]`).
pub fn builtin(
    nuget_limits: forge_format_nuget::NupkgLimits,
    npm_limits: forge_format_npm::NpmLimits,
) -> Vec<Arc<Plugin>> {
    vec![
        Plugin::builtin(forge_format_docker::Docker),
        Plugin::builtin(forge_format_nuget::Nuget::with_limits(nuget_limits)),
        Plugin::builtin(forge_format_npm::Npm::with_limits(npm_limits)),
        Plugin::builtin(forge_format_raw::Raw),
    ]
}

/// Axum handler mounted at `/repository/{repo}` (and everything under it).
pub async fn dispatch(State(state): State<AppState>, req: Request<Body>) -> Response {
    // The plugin the mount serves, for errors answered before the
    // repository (and its plugin) is known.
    let mounted =
        split_path(req.uri().path(), &state.formats.mounts()).and_then(|(mount, _, _)| {
            let mut serving = state
                .formats
                .plugins()
                .filter(|plugin| plugin.descriptor().mount == mount);
            match (serving.next(), serving.next()) {
                (Some(plugin), None) => Some(plugin.clone()),
                _ => None,
            }
        });
    let head = req.method() == Method::HEAD;
    let mut response = dispatch_request(state, req).await;
    let plugin = response
        .extensions_mut()
        .remove::<ServedBy>()
        .map(|s| s.0)
        .or(mounted);
    if let Some(plugin) = plugin {
        if !head {
            response = in_format(&plugin, response).await;
        }
    }
    crate::feed::harden_response_headers(response.headers_mut());
    response
}

/// The plugin that served a request, once its repository is known.
#[derive(Clone)]
struct ServedBy(Arc<Plugin>);

/// Marks a response the plugin (or the upstream it forwarded to) wrote.
#[derive(Clone, Copy)]
struct PluginWritten;

/// The longest host error [`in_format`] rewrites.
const MAX_ERROR_BYTES: usize = 64 * 1024;

/// A host error in the shape the format's clients read errors in
/// ([`FormatPlugin::error_response`]), keeping its status and headers.
async fn in_format(plugin: &Plugin, response: Response) -> Response {
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error())
        || response.extensions().get::<PluginWritten>().is_some()
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(message) = axum::body::to_bytes(body, MAX_ERROR_BYTES).await else {
        return (status, "internal error").into_response();
    };
    let message = String::from_utf8_lossy(&message);
    let Some(rendered) = plugin
        .implementation()
        .error_response(status.as_u16(), message.trim())
    else {
        return Response::from_parts(parts, Body::from(message.into_owned()));
    };
    let content_type = rendered
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| HeaderValue::from_str(value).ok());
    match content_type {
        Some(content_type) => parts.headers.insert(header::CONTENT_TYPE, content_type),
        None => parts.headers.remove(header::CONTENT_TYPE),
    };
    parts.headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(rendered.body.len()),
    );
    Response::from_parts(parts, Body::from(rendered.body))
}

/// `(mount, repository name, rest of the path)` of a `{mount}/{repo}/...`
/// path, for one of `mounts`; the rest starts with `/`, or is empty when the
/// path ends with the repository's name.
fn split_path<'p>(path: &'p str, mounts: &[&str]) -> Option<(&'p str, &'p str, &'p str)> {
    mounts.iter().find_map(|mount| {
        let rest = path.strip_prefix(mount)?.strip_prefix('/')?;
        let (name, rest) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        (!name.is_empty()).then(|| (&path[..mount.len()], name, rest))
    })
}

/// The caller, with an `Authorization: Bearer` API token resolved when the
/// principal middleware left it anonymous (npm sends its `_authToken` so).
/// An unknown or unusable token is refused, never read as anonymous.
async fn with_bearer(
    state: &AppState,
    headers: &HeaderMap,
    principal: Principal,
) -> Result<Principal, Response> {
    if !matches!(
        principal,
        Principal::Anonymous { .. } | Principal::Unauthenticated
    ) {
        return Ok(principal);
    }
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, token) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
        })
        .filter(|token| !token.is_empty())
    else {
        return Ok(principal);
    };
    match check_token(&state.pool, token).await {
        Ok(TokenCheck::Live(user)) => Ok(Principal::from_user(user)),
        Ok(TokenCheck::Unusable | TokenCheck::Unknown) => Err((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer realm=\"Forge\"")],
            "invalid token",
        )
            .into_response()),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "30")],
            "authentication temporarily unavailable",
        )
            .into_response()),
    }
}

async fn dispatch_request(state: AppState, req: Request<Body>) -> Response {
    let uri = req.uri().clone();
    let principal = match with_bearer(&state, req.headers(), principal_of(&req)).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
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

    let Some(plugin) = state.formats.plugin(&repo.format) else {
        return if state.formats.is_installed(&repo.format) {
            // A format without a protocol (a test's own) is served under
            // no mount.
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
    if plugin.descriptor().mount != mount {
        return (StatusCode::NOT_FOUND, "repository is not served here").into_response();
    }
    let mut response = serve(&state, req, principal, &repo, plugin.clone(), mount, rest).await;
    response.extensions_mut().insert(ServedBy(plugin));
    response
}

/// Serve `req` from `repo`, whose format `plugin` is.
async fn serve(
    state: &AppState,
    req: Request<Body>,
    principal: Principal,
    repo: &Repository,
    plugin: Arc<Plugin>,
    mount: &str,
    rest: &str,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let format = match state.formats.for_repository(repo) {
        Ok(format) => format,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };
    let stores_files = format.stores_files();
    // A files format's request is authorized by its method; a package
    // format's actions each by what they need (see `Ctx::act`).
    let level = level_for_method(&method);
    if stores_files {
        let allowed = match level {
            Level::Read => state.authz.can_read(&principal, repo).await,
            Level::Write => state.authz.can_write(&principal, repo).await,
            Level::Delete => state.authz.can_delete(&principal, repo).await,
        };
        if !allowed {
            return authz_denied(&principal);
        }
    }
    if offline_serves_nothing(repo) {
        // Only to a caller who may read it: the offline state reveals the
        // repository.
        return if state.authz.can_read(&principal, repo).await {
            offline_response()
        } else {
            authz_denied(&principal)
        };
    }
    // A files format reads the file store, never the package read ops.
    let ops = if stores_files {
        None
    } else {
        match state.read_ops_for(repo, principal.clone()).await {
            Ok(ops) => Some(ops),
            Err(e) => return repo_error(e),
        }
    };

    let target = protocol::Repository {
        name: repo.name.clone(),
        kind: match repo.kind() {
            RepoKind::Hosted => protocol::RepositoryKind::Hosted,
            RepoKind::Proxy => protocol::RepositoryKind::Proxy,
            RepoKind::Group => protocol::RepositoryKind::Group,
        },
        base_url: repository_url(state, mount, &repo.name),
        inline: stores_files && repo.inline_content(),
        reserved_prefixes: if repo.kind() == RepoKind::Group {
            repo.reserved_prefixes()
        } else {
            Vec::new()
        },
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
        body: None,
        image: None,
    };
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);

    let ctx = Ctx {
        state,
        repo,
        mount,
        principal: principal.clone(),
        method: method.clone(),
        client_ip: crate::auth::login_client_ip(state, peer, req.headers()),
        headers: req.headers().clone(),
        plugin: plugin.clone(),
        format,
        level,
        stores_files,
        ops,
        target,
        body: Mutex::new(Some(req)),
        form: Mutex::new(None),
        located: Mutex::new(HashMap::new()),
    };
    let handled = {
        let (target, request) = (ctx.target.clone(), request.clone());
        ctx.call(move |plugin| plugin.handle(&target, &request))
            .await
    };
    let response = match handled {
        Ok(action) => ctx.perform(action, request).await,
        Err(response) => response,
    };
    if !matches!(method, Method::GET | Method::HEAD) {
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
    method: Method,
    /// Where the request came from, as the login lockout sees it.
    client_ip: std::net::IpAddr,
    /// The request's headers, for a download's `Range`.
    headers: HeaderMap,
    plugin: Arc<Plugin>,
    format: Arc<dyn Format>,
    /// The level the request's method is for; a files format's request
    /// was authorized for it.
    level: Level,
    /// Whether the format's repositories hold files (its plugin asks for
    /// files, not packages).
    stores_files: bool,
    /// The package read ops; `None` for a files format.
    ops: Option<Arc<dyn RepoReadOps>>,
    target: protocol::Repository,
    /// The request, until a publish, a body or a file query reads it.
    body: Mutex<Option<Request<Body>>>,
    /// The file parts of the form the plugin had received, by their index
    /// among its parts, until a store takes them.
    form: Mutex<Option<Vec<Option<Ingested>>>>,
    /// The files queries found, by path, for serving one of them.
    located: Mutex<HashMap<String, RawFile>>,
}

impl Ctx<'_> {
    fn implementation(&self) -> Arc<dyn FormatPlugin> {
        self.plugin.implementation().clone()
    }

    fn head(&self) -> bool {
        self.method == Method::HEAD
    }

    /// Whether the request's method may change anything.
    fn mutating(&self) -> bool {
        !matches!(self.method, Method::GET | Method::HEAD)
    }

    /// Run a protocol call of the plugin off the async workers: rendering a
    /// large listing takes a while. A plugin that panics answers 500.
    async fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn FormatPlugin) -> R + Send + 'static,
    ) -> Result<R, Response> {
        let plugin = self.implementation();
        tokio::task::spawn_blocking(move || f(plugin.as_ref()))
            .await
            .map_err(|e| plugin_failed(self.repo, &e))
    }

    /// Whether the caller has `level` on `repo`.
    async fn may(&self, level: Level, repo: &Repository) -> bool {
        match level {
            Level::Read => self.state.authz.can_read(&self.principal, repo).await,
            Level::Write => self.state.authz.can_write(&self.principal, repo).await,
            Level::Delete => self.state.authz.can_delete(&self.principal, repo).await,
        }
    }

    /// The caller must read this repository.
    async fn require_read(&self) -> Result<(), Response> {
        if self.may(Level::Read, self.repo).await {
            Ok(())
        } else {
            Err(authz_denied(&self.principal))
        }
    }

    /// Do what `handle` decided.
    async fn perform(&self, action: Action, request: protocol::Request) -> Response {
        match action {
            _ if self.stores_files => match action {
                Action::Load(queries) => self.render(queries, &request).await,
                action => self.act_files(action).await,
            },
            Action::ReadBody(wanted) => self.read_body(wanted, request).await,
            Action::Publish(publish) => match self.take_body() {
                Some(req) => self.publish(publish, request, req).await,
                None => self.plugin_misused("a publish after the body was read"),
            },
            other => self.act(other, &request, false).await,
        }
    }

    /// An action of a files format's plugin: a response, or a file to serve.
    async fn act_files(&self, action: Action) -> Response {
        match action {
            Action::Respond(response) => self.respond(response),
            Action::ServeFile(path) => {
                if self.level != Level::Read {
                    return refused("serving a file");
                }
                self.serve_file(&path).await
            }
            Action::Load(_) => self.plugin_misused("a load as an action"),
            _ => self.plugin_misused("an action of the other storage"),
        }
    }

    /// The request, for the one query or action that reads its body.
    fn take_body(&self) -> Option<Request<Body>> {
        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// The plugin asked for something the contract does not allow: a bug in
    /// the plugin, answered with a server error.
    fn plugin_misused(&self, what: &str) -> Response {
        tracing::error!(repo = %self.repo.name, format = %self.repo.format, "format plugin asked for {what}");
        (StatusCode::INTERNAL_SERVER_ERROR, "format plugin failed").into_response()
    }

    /// Everything but a body or a publish, which need the request itself.
    /// `login_body`: the request's body was read as a login's, so only a
    /// login or a plain response may follow.
    async fn act(&self, action: Action, request: &protocol::Request, login_body: bool) -> Response {
        if login_body && !matches!(action, Action::Auth(_) | Action::Respond(_)) {
            return plugin_failed(self.repo, &"a login body led to another action");
        }
        match action {
            Action::Auth(auth) => self.auth(auth, request).await,
            // A login's own errors need no permission: they reveal nothing.
            Action::Respond(response) if login_body => self.respond(response),
            Action::Respond(response) => match self.require_read().await {
                Ok(()) => self.respond(response),
                Err(denied) => denied,
            },
            Action::Load(queries) => match self.require_read().await {
                Ok(()) => self.render(queries, request).await,
                Err(denied) => denied,
            },
            Action::Download(target) => {
                if self.mutating() {
                    return refused("download");
                }
                match self.require_read().await {
                    Ok(()) => self.download(&target).await,
                    Err(denied) => denied,
                }
            }
            Action::Forward(forward) => match self.require_read().await {
                Ok(()) => self.forward(forward).await,
                Err(denied) => denied,
            },
            Action::Unlist(change) => {
                self.change_one(Change::Unlist(change.target), change.done)
                    .await
            }
            Action::Relist(change) => {
                self.change_one(Change::Relist(change.target), change.done)
                    .await
            }
            Action::Delete(change) => {
                self.change_one(Change::Delete(change.target), change.done)
                    .await
            }
            Action::Change(set) => self.changes(set).await,
            Action::ReadBody(_) | Action::Publish(_) => {
                plugin_failed(self.repo, &"a body was asked for twice")
            }
            Action::ServeFile(_) => self.plugin_misused("an action of the other storage"),
            // Images are the registry's (`crate::images`).
            Action::ServeBlob { .. } | Action::ServeManifest { .. } => {
                self.plugin_misused("an image action")
            }
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
    async fn render(&self, mut queries: Vec<Query>, request: &protocol::Request) -> Response {
        let mut data: Vec<Loaded> = Vec::new();
        for _ in 0..MAX_ROUNDS {
            if data.len() + queries.len() > MAX_QUERIES {
                break;
            }
            if let Err(response) = self.check_round(&queries) {
                return response;
            }
            let pending: Vec<_> = queries.iter().map(|query| self.answer(query)).collect();
            let answers: Vec<Answer> = match futures_util::stream::iter(pending)
                .buffered(CONCURRENT_QUERIES)
                .try_collect()
                .await
            {
                Ok(answers) => answers,
                Err(response) => return response,
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
                Ok((Action::Load(more), loaded)) => {
                    data = loaded;
                    queries = more;
                }
                Ok((action, _)) if self.stores_files => return self.act_files(action).await,
                Ok((action, _)) => return Box::pin(self.act(action, request, false)).await,
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

    /// Whether a round of queries keeps to the contract: queries of the
    /// format's storage only, and a change (`form`, `store`, `remove`) alone
    /// in its round.
    fn check_round(&self, queries: &[Query]) -> Result<(), Response> {
        // Images are the registry's (`crate::images`).
        if queries.iter().any(Query::is_images) {
            return Err(self.plugin_misused("an image query"));
        }
        if queries.iter().any(|q| q.is_files() != self.stores_files) {
            return Err(self.plugin_misused("a query of the other storage"));
        }
        if queries.len() > 1 && queries.iter().any(Query::is_change) {
            return Err(self.plugin_misused("a change with other queries in its round"));
        }
        Ok(())
    }

    /// The answer to one query, or the response that ends the request
    /// instead.
    async fn answer(&self, query: &Query) -> Result<Answer, Response> {
        if query.is_files() {
            return self.answer_files(query).await;
        }
        let Some(ops) = &self.ops else {
            return Err(self.plugin_misused("packages of a files format"));
        };
        self.answer_packages(ops.as_ref(), query)
            .await
            .map_err(repo_error)
    }

    /// The answer to a files query, from the file store.
    async fn answer_files(&self, query: &Query) -> Result<Answer, Response> {
        let files = Files {
            state: self.state,
            principal: self.principal.clone(),
        };
        let failed = |e: FileError| e.into_response();
        match query {
            Query::File(path) | Query::FetchFile(path) => {
                if forge_plugin::api::files::validate_path(path).is_err() {
                    return Err(self.plugin_misused("a file at an invalid path"));
                }
                let fetch = matches!(query, Query::FetchFile(_));
                let found = files
                    .locate(self.repo, path, fetch, Vec::new(), 0)
                    .await
                    .map_err(failed)?;
                if let Some(file) = &found {
                    self.located
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(path.clone(), file.clone());
                }
                Ok(Answer::File(found.as_ref().map(file_info)))
            }
            Query::Directory(wanted) => {
                if forge_plugin::api::files::validate_directory(&wanted.directory).is_err() {
                    return Err(self.plugin_misused("an invalid directory"));
                }
                let page = files
                    .list(
                        self.repo,
                        &wanted.directory,
                        wanted.after.as_deref(),
                        wanted.limit as usize,
                    )
                    .await
                    .map_err(failed)?;
                Ok(Answer::Directory(page.map(directory_page)))
            }
            Query::Form => {
                if self.level != Level::Write {
                    return Err(refused("receiving a form"));
                }
                let Some(req) = self.take_body() else {
                    return Err(self.plugin_misused("a form after the body was read"));
                };
                let parts =
                    crate::files::store::receive_form(&files, self.repo, req, Via::Protocol)
                        .await
                        .map_err(failed)?;
                let mut staged = Vec::with_capacity(parts.len());
                let mut answer = Vec::with_capacity(parts.len());
                for part in parts {
                    match part {
                        Part::File {
                            field,
                            name,
                            content_type,
                            ingested,
                        } => {
                            answer.push(protocol::FormPart {
                                field,
                                content: protocol::FormContent::File(protocol::FormFile {
                                    name,
                                    content_type,
                                    size: ingested.stored.size,
                                }),
                            });
                            staged.push(Some(*ingested));
                        }
                        Part::Text { field, value } => {
                            answer.push(protocol::FormPart {
                                field,
                                content: protocol::FormContent::Text(value),
                            });
                            staged.push(None);
                        }
                    }
                }
                *self.form.lock().unwrap_or_else(PoisonError::into_inner) = Some(staged);
                Ok(Answer::Form(answer))
            }
            Query::Store(wanted) => {
                if self.level != Level::Write {
                    return Err(refused("storing files"));
                }
                let mut uploads = Vec::with_capacity(wanted.len());
                for file in wanted {
                    let content = match file.source {
                        protocol::FileSource::Body => match self.take_body() {
                            Some(req) => Content::Body(req),
                            None => {
                                return Err(self.plugin_misused("a store of a body already read"))
                            }
                        },
                        protocol::FileSource::Part(index) => match self.take_part(index) {
                            Some(ingested) => Content::Staged(ingested),
                            None => {
                                return Err(self.plugin_misused(
                                    "a store of a form part that is not a file it may store",
                                ))
                            }
                        },
                    };
                    uploads.push(crate::files::store::Upload {
                        path: file.path.clone(),
                        declared: file.content_type.clone(),
                        content,
                    });
                }
                let stored = crate::files::store::store(&files, self.repo, uploads, Via::Protocol)
                    .await
                    .map_err(failed)?;
                Ok(Answer::Stored(
                    stored
                        .into_iter()
                        .map(|stored| protocol::StoredFile {
                            path: stored.path,
                            size: stored.size,
                            sha256: stored.sha256,
                            status: match stored.status {
                                "created" => protocol::StoreStatus::Created,
                                "replaced" => protocol::StoreStatus::Replaced,
                                _ => protocol::StoreStatus::Unchanged,
                            },
                        })
                        .collect(),
                ))
            }
            Query::Remove(path) => {
                if self.level != Level::Delete {
                    return Err(refused("deleting a file"));
                }
                let removed = crate::files::store::remove(&files, self.repo, path, Via::Protocol)
                    .await
                    .map_err(failed)?;
                Ok(Answer::Removed(removed))
            }
            _ => Err(self.plugin_misused("a package query of a files format")),
        }
    }

    /// The staged file part `index` of the form the plugin had received,
    /// taken (a part is stored once).
    fn take_part(&self, index: u32) -> Option<Ingested> {
        self.form
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()?
            .get_mut(usize::try_from(index).ok()?)?
            .take()
    }

    /// Serve the file at `path`, as a query found it or as `fetch-file`
    /// finds it now.
    async fn serve_file(&self, path: &str) -> Response {
        let found = self
            .located
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(path)
            .cloned();
        let file = match found {
            Some(file) => file,
            None => {
                if forge_plugin::api::files::validate_path(path).is_err() {
                    return self.plugin_misused("a file at an invalid path");
                }
                let files = Files {
                    state: self.state,
                    principal: self.principal.clone(),
                };
                match files.locate(self.repo, path, true, Vec::new(), 0).await {
                    Ok(Some(file)) => file,
                    Ok(None) => return FileError::NotFound.into_response(),
                    Err(e) => return e.into_response(),
                }
            }
        };
        crate::files::serve::file(self.state, self.repo, &file, &self.headers, self.head()).await
    }

    /// The answer to a package query, through the package read ops.
    async fn answer_packages(
        &self,
        ops: &dyn RepoReadOps,
        query: &Query,
    ) -> Result<Answer, RepoError> {
        let repo = &self.repo.name;
        Ok(match query {
            Query::Versions(id) => Answer::Versions(match self.id(id) {
                Some(id) => ops
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
                Some(id) => ops
                    .registration(repo, &id)
                    .await?
                    .into_iter()
                    .map(|entry| self.package_info(entry))
                    .collect(),
                None => Vec::new(),
            }),
            Query::DatedPackages(id) => Answer::Packages(match self.id(id) {
                Some(id) => ops
                    .dated_registration(repo, &id)
                    .await?
                    .into_iter()
                    .map(|entry| self.package_info(entry))
                    .collect(),
                None => Vec::new(),
            }),
            Query::Package(target) => Answer::Package(match self.package(target) {
                Some((id, version)) => ops
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
                        ops.registration_entries(repo, &id, &versions).await?
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
                Some((id, version)) => ops.resolve_nuspec(repo, &id, &version).await?,
                None => None,
            }),
            Query::Tags(id) => Answer::Tags(match self.id(id) {
                Some(id) => ops
                    .tags(repo, &id)
                    .await?
                    .into_iter()
                    .map(|(name, version)| protocol::Tag { name, version })
                    .collect(),
                None => Vec::new(),
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
                let result = ops.search(repo, &params).await?;
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
            // Answered by `answer_files`.
            Query::File(_)
            | Query::FetchFile(_)
            | Query::Directory(_)
            | Query::Form
            | Query::Store(_)
            | Query::Remove(_) => {
                return Err(RepoError::Storage(
                    "a files query of a package format".into(),
                ))
            }
            // Refused by `check_round`.
            Query::Image(_) => {
                return Err(RepoError::Storage(
                    "an image query of a package format".into(),
                ))
            }
        })
    }

    /// Stream a stored package, as the NuGet feed serves a `.nupkg`.
    async fn download(&self, target: &PackageRef) -> Response {
        let Some((id, version)) = self.package(target) else {
            return (StatusCode::NOT_FOUND, "package not found").into_response();
        };
        let Some(ops) = &self.ops else {
            return self.plugin_misused("a package download of a files format");
        };
        // A HEAD (a probe, a mirror tool) is not a download.
        let resolved = if self.head() {
            ops.resolve_nupkg_head(&self.repo.name, &id, &version).await
        } else {
            ops.resolve_nupkg(&self.repo.name, &id, &version).await
        };
        let location = match resolved {
            Ok(Some(location)) => location,
            Ok(None) => return (StatusCode::NOT_FOUND, "package not found").into_response(),
            Err(e) => return repo_error(e),
        };
        crate::feed::serve_package(self.state, &location, &self.headers, self.head()).await
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
            deprecated: entry.deprecation,
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

    /// Where a change of `permission` to this repository's packages lands:
    /// the repository itself when it is hosted, a group's writable member
    /// (reading the group is required too), with a package-client
    /// credential, and never for a GET or HEAD.
    async fn write_target(&self, permission: Level, what: &str) -> Result<Repository, Response> {
        if !self.mutating() {
            return Err(refused(what));
        }
        let target = match self.repo.kind() {
            RepoKind::Hosted => self.repo.clone(),
            RepoKind::Proxy => {
                return Err((
                    StatusCode::METHOD_NOT_ALLOWED,
                    "packages can only be changed in hosted repositories",
                )
                    .into_response())
            }
            RepoKind::Group => {
                if !self.may(Level::Read, self.repo).await {
                    return Err(authz_denied(&self.principal));
                }
                let member = match self.repo.writable_member_id() {
                    Some(id) => repository_dao::find_repository_by_id(&self.state.pool, id)
                        .await
                        .map_err(|e| {
                            tracing::error!(error = %e, "writable member lookup failed");
                            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
                        })?
                        .filter(|m| m.kind() == RepoKind::Hosted && m.format == self.repo.format),
                    None => None,
                };
                let Some(member) = member else {
                    return Err((
                        StatusCode::METHOD_NOT_ALLOWED,
                        "this group takes no changes: its administrator can name a writable member",
                    )
                        .into_response());
                };
                if !member.online {
                    return Err(offline_response());
                }
                member
            }
        };
        if !self.may(permission, &target).await {
            return Err(authz_denied(&self.principal));
        }
        if target.deployment_policy() == DeploymentPolicy::ReadOnly {
            return Err((StatusCode::FORBIDDEN, "the repository is read-only").into_response());
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
        Ok(target)
    }

    /// The hosted write path of `target`, with the caller's selectors.
    async fn writer(
        &self,
        target: &Repository,
        format: Arc<dyn Format>,
        permission: Level,
    ) -> HostedWriteAdapter {
        let filter = self
            .state
            .authz
            .package_filter_for(&self.principal, target, permission)
            .await;
        // A redeploy replaces a version's bytes: it takes the delete
        // permission's selector as well.
        let replace_filter = self
            .state
            .authz
            .package_filter_for(&self.principal, target, Level::Delete)
            .await;
        let role_filter = self
            .state
            .authz
            .role_package_filter_for(&self.principal, target, permission)
            .await;
        let role_replace_filter = self
            .state
            .authz
            .role_package_filter_for(&self.principal, target, Level::Delete)
            .await;
        HostedWriteAdapter::new(
            self.state,
            format,
            target.id,
            target.name.clone(),
            self.principal.clone(),
            filter,
            replace_filter,
            role_filter,
            role_replace_filter,
        )
    }

    /// The username publishing, recorded by formats that keep it.
    async fn publisher(&self) -> Option<String> {
        match &self.principal {
            Principal::User { user_id, .. } => {
                user_dao::find_user_by_id(&self.state.pool, *user_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|u| u.username)
            }
            _ => None,
        }
    }

    async fn publish(
        &self,
        publish: PublishRequest,
        request: protocol::Request,
        req: Request<Body>,
    ) -> Response {
        let target = match self.write_target(Level::Write, "publish").await {
            Ok(target) => target,
            Err(response) => return response,
        };
        let format = forge_plugin::PluginFormat::new(&self.plugin);
        let expected_id = publish.id.as_deref().and_then(|id| self.id(id));
        if publish.id.is_some() && expected_id.is_none() {
            return (StatusCode::BAD_REQUEST, "invalid package id").into_response();
        }
        let upload = Arc::new(format.upload(
            publish.upload == Upload::Document,
            self.publisher().await,
            expected_id,
        ));
        let writer = self.writer(&target, upload.clone(), Level::Write).await;
        let limit = self.state.upload_limit(&target);
        if publish.upload == Upload::Document {
            return self
                .publish_document(publish, request, req, upload, writer, &target, limit)
                .await;
        }
        let flags = UploadFlags::default();
        let reader = match &publish.upload {
            Upload::Body | Upload::Document => body_reader(req.into_body()),
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
        match writer.store_upload(&target.name, reader, limit).await {
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

    /// An [`Upload::Document`]: the body streams through the plugin's
    /// [`FormatPlugin::unpack_upload`] (off the async workers) while the
    /// package it writes out is staged and stored; the document it returns
    /// reaches the parser before the package does. A body without a package
    /// is handed back to the plugin as the request's body.
    #[allow(clippy::too_many_arguments)]
    async fn publish_document(
        &self,
        publish: PublishRequest,
        request: protocol::Request,
        req: Request<Body>,
        upload: Arc<forge_plugin::UploadFormat>,
        writer: HostedWriteAdapter,
        target: &Repository,
        limit: u64,
    ) -> Response {
        let Some(document) = upload.document.clone() else {
            return plugin_failed(self.repo, &"a document upload without its document");
        };
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
        let (package_tx, package_rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
        let mut stream = req.into_body().into_data_stream();
        let pump = tokio::spawn(async move {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(std::io::Error::other);
                let failed = chunk.is_err();
                if body_tx.send(chunk).await.is_err() || failed {
                    break;
                }
            }
        });
        let plugin = self.implementation();
        let unpack = tokio::task::spawn_blocking(move || {
            let mut body = ChannelReader::new(body_rx);
            let mut package = ChannelWriter { tx: package_tx };
            let unpacked = plugin.unpack_upload(&mut body, &mut package);
            match &unpacked {
                // Before the package stream ends, so that the parser has it.
                Ok(Unpacked::Package { document: doc }) => {
                    let _ = document.set(doc.clone());
                }
                Err(e) => {
                    let _ = package
                        .tx
                        .blocking_send(Err(std::io::Error::other(e.to_string())));
                }
                Ok(Unpacked::Document(_)) => {}
            }
            drop(package);
            unpacked
        });
        let package = futures_util::stream::unfold(package_rx, |mut rx| async move {
            rx.recv().await.map(|chunk| (chunk, rx))
        });
        let reader: UploadReader = Box::new(StreamReader::new(Box::pin(package)));
        let (stored, unpacked) =
            tokio::join!(writer.store_upload(&target.name, reader, limit), unpack);
        pump.abort();
        let unpacked = match unpacked {
            Ok(unpacked) => unpacked,
            Err(e) => return plugin_failed(self.repo, &e),
        };
        match unpacked {
            Err(e) => match stored {
                // The store stopped reading a package over the upload limit
                // first, which failed the unpacking: the limit is why.
                Err(too_large @ WriteError::TooLarge { .. }) => write_error(too_large),
                _ => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
            },
            Ok(Unpacked::Document(body)) => {
                // No package: another kind of document, which the plugin
                // reads as the request's body (write was required already).
                let request = protocol::Request {
                    body: Some(body),
                    ..request
                };
                let handled = {
                    let (target, request) = (self.target.clone(), request.clone());
                    self.call(move |plugin| plugin.handle(&target, &request))
                        .await
                };
                match handled {
                    Ok(action) => self.act(action, &request, false).await,
                    Err(response) => response,
                }
            }
            Ok(Unpacked::Package { document }) => {
                if let Err(e) = stored {
                    return write_error(e);
                }
                let Some((id, version)) = upload.parsed.get().cloned() else {
                    return plugin_failed(self.repo, &"stored without its identity");
                };
                let stored = PackageRef { id, version };
                let changes = {
                    let stored = stored.clone();
                    match self
                        .call(move |plugin| plugin.published(&document, &stored))
                        .await
                    {
                        Ok(changes) => changes,
                        Err(response) => return response,
                    }
                };
                if !changes.is_empty() {
                    let set = ChangeSet {
                        changes,
                        done: publish.done.clone(),
                    };
                    let response = self.changes(set).await;
                    if !response.status().is_success() {
                        tracing::warn!(repo = %self.repo.name, package = %stored.id, version = %stored.version, status = %response.status(), "published, but its tags could not be set");
                    }
                    return response;
                }
                self.respond(publish.done)
            }
        }
    }

    /// Read the request body, as `wanted` says, and ask the plugin again
    /// with it.
    async fn read_body(&self, wanted: BodyRequest, request: protocol::Request) -> Response {
        if request.body.is_some() {
            return plugin_failed(self.repo, &"a body was asked for twice");
        }
        let Some(req) = self.take_body() else {
            return self.plugin_misused("a body after it was read");
        };
        let limit = match wanted.used_for {
            BodyUse::Login => wanted.limit.min(MAX_LOGIN_BODY_BYTES),
            BodyUse::Read => {
                if let Err(denied) = self.require_read().await {
                    return denied;
                }
                wanted.limit.min(MAX_BODY_BYTES)
            }
            BodyUse::Change => {
                let needed = level_for_method(&self.method);
                let allowed = match self.repo.kind() {
                    // A group's changes go to its writable member, checked
                    // there; reading the group comes first.
                    RepoKind::Group => self.may(Level::Read, self.repo).await,
                    _ => self.may(needed, self.repo).await,
                };
                if !self.mutating() || !allowed {
                    return authz_denied(&self.principal);
                }
                wanted.limit.min(MAX_BODY_BYTES)
            }
        };
        let gzip = req
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
        let too_large = || {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("the request body is larger than {limit} bytes"),
            )
                .into_response()
        };
        let Ok(raw) = axum::body::to_bytes(req.into_body(), limit as usize).await else {
            return too_large();
        };
        let body = if gzip {
            let inflated = tokio::task::spawn_blocking(move || {
                let mut out = Vec::new();
                flate2::read::GzDecoder::new(&raw[..])
                    .take(limit + 1)
                    .read_to_end(&mut out)
                    .map(|_| out)
            })
            .await;
            match inflated {
                Ok(Ok(out)) if out.len() as u64 <= limit => out,
                Ok(Ok(_)) => return too_large(),
                Ok(Err(_)) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "the request body is not valid gzip",
                    )
                        .into_response()
                }
                Err(e) => return plugin_failed(self.repo, &e),
            }
        } else {
            raw.to_vec()
        };
        let request = protocol::Request {
            body: Some(body),
            ..request
        };
        let handled = {
            let (target, request) = (self.target.clone(), request.clone());
            self.call(move |plugin| plugin.handle(&target, &request))
                .await
        };
        match handled {
            Ok(action) => {
                self.act(action, &request, wanted.used_for == BodyUse::Login)
                    .await
            }
            Err(response) => response,
        }
    }

    /// A login, a logout or `whoami` ([`crate::cli_auth`]), answered by the
    /// plugin.
    async fn auth(&self, auth: AuthRequest, request: &protocol::Request) -> Response {
        match crate::cli_auth::perform(
            self.state,
            self.repo,
            self.principal.clone(),
            self.client_ip,
            auth,
        )
        .await
        {
            Ok(outcome) => {
                let (target, request) = (self.target.clone(), request.clone());
                match self
                    .call(move |plugin| plugin.auth_response(&target, &request, &outcome))
                    .await
                {
                    Ok(response) => self.respond(response),
                    Err(response) => response,
                }
            }
            Err(refused) => refused,
        }
    }

    /// One change ([`Action::Unlist`], [`Action::Relist`],
    /// [`Action::Delete`]).
    async fn change_one(&self, change: Change, done: protocol::Response) -> Response {
        self.changes(ChangeSet {
            changes: vec![change],
            done,
        })
        .await
    }

    /// Make `set`'s changes in order; the first that fails answers.
    async fn changes(&self, set: ChangeSet) -> Response {
        // Every permission the set needs first: a refusal changes nothing.
        let mut checked: Vec<Level> = Vec::new();
        for change in &set.changes {
            let (needed, what) = needs(change);
            if !checked.contains(&needed) {
                if let Err(response) = self.write_target(needed, what).await {
                    return response;
                }
                checked.push(needed);
            }
        }
        for change in set.changes {
            if let Err(response) = self.change(change).await {
                return response;
            }
        }
        self.respond(set.done)
    }

    async fn change(&self, change: Change) -> Result<(), Response> {
        let not_found = || (StatusCode::NOT_FOUND, "package not found").into_response();
        let (needed, what) = needs(&change);
        let target = self.write_target(needed, what).await?;
        let filter = self
            .state
            .authz
            .package_filter_for(&self.principal, &target, needed)
            .await;
        // A package outside the caller's selector answers like an unknown
        // one, as for NuGet.
        let package = |r: &PackageRef| {
            self.package(r)
                .filter(|(id, _)| filter.allows(id))
                .ok_or_else(not_found)
        };
        let db = |e: sqlx::Error| {
            tracing::error!(error = %e, repo = %target.name, "package change failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        };
        match change {
            Change::Unlist(r) => {
                let (id, version) = package(&r)?;
                let writer = self.writer(&target, self.format.clone(), needed).await;
                outcome(
                    writer
                        .delete_component(&target.name, &id, &version, false)
                        .await,
                )
            }
            Change::Delete(r) => {
                let (id, version) = package(&r)?;
                let writer = self.writer(&target, self.format.clone(), needed).await;
                outcome(
                    writer
                        .delete_component(&target.name, &id, &version, true)
                        .await,
                )?;
                tag_dao::delete_tags(&self.state.pool, target.id, &id, Some(&version))
                    .await
                    .map_err(db)?;
                Ok(())
            }
            Change::Relist(r) => {
                let (id, version) = package(&r)?;
                let writer = self.writer(&target, self.format.clone(), needed).await;
                outcome(writer.relist(&target.name, &id, &version).await)
            }
            Change::Deprecate { target: r, message } => {
                let (id, version) = package(&r)?;
                let message = message.filter(|m| !m.is_empty());
                if component_dao::set_deprecation(
                    &self.state.pool,
                    target.id,
                    &id,
                    &version,
                    message.as_deref(),
                )
                .await
                .map_err(db)?
                {
                    Ok(())
                } else {
                    Err(not_found())
                }
            }
            Change::Tag { id, tag, version } => {
                let (id, version) = package(&PackageRef { id, version })?;
                if !valid_tag(&tag) {
                    return Err((StatusCode::BAD_REQUEST, "invalid tag").into_response());
                }
                if component_dao::find_component(&self.state.pool, target.id, &id, &version)
                    .await
                    .map_err(db)?
                    .is_none()
                {
                    return Err((
                        StatusCode::NOT_FOUND,
                        format!("version {version} of {id} not found"),
                    )
                        .into_response());
                }
                tag_dao::set_tag(&self.state.pool, target.id, &id, &tag, &version)
                    .await
                    .map_err(db)
            }
            Change::Untag { id, tag } => {
                let id = self
                    .id(&id)
                    .filter(|id| filter.allows(id))
                    .ok_or_else(not_found)?;
                if tag_dao::delete_tag(&self.state.pool, target.id, &id, &tag)
                    .await
                    .map_err(db)?
                {
                    Ok(())
                } else {
                    Err((StatusCode::NOT_FOUND, format!("{id} has no tag {tag:?}")).into_response())
                }
            }
        }
    }

    /// The proxy whose upstream a forward from `repo` goes to: the
    /// repository itself, or a group's first proxy member (by priority)
    /// the caller may read, through nested groups.
    async fn forward_source(
        &self,
        repo: &Repository,
        depth: u32,
    ) -> Result<Option<Repository>, RepoError> {
        match repo.kind() {
            RepoKind::Proxy => Ok(Some(repo.clone())),
            RepoKind::Hosted => Ok(None),
            RepoKind::Group => {
                let max = self.state.config.groups.max_nesting_depth.max(1) as u32;
                if depth >= max {
                    return Ok(None);
                }
                for (member, _) in repository_dao::group_members(&self.state.pool, repo.id).await? {
                    if member.format != repo.format || !self.may(Level::Read, &member).await {
                        continue;
                    }
                    if let Some(found) = Box::pin(self.forward_source(&member, depth + 1)).await? {
                        return Ok(Some(found));
                    }
                }
                Ok(None)
            }
        }
    }

    /// Send `forward` on to the upstream, with the proxy's credentials (to
    /// its origin only), and answer with what the upstream said.
    async fn forward(&self, forward: Forward) -> Response {
        let source = match self.forward_source(self.repo, 0).await {
            Ok(Some(source)) => source,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    "this repository has no upstream to ask: ask a proxy, or a group with one",
                )
                    .into_response()
            }
            Err(e) => return repo_error(e),
        };
        if !source.online {
            return offline_response();
        }
        if !forward.path.starts_with('/') {
            return plugin_failed(self.repo, &"a forward's path does not start with '/'");
        }
        let Some(remote) = source.remote_url.as_deref() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the proxy has no remote_url",
            )
                .into_response();
        };
        let url = format!("{}{}", remote.trim_end_matches('/'), forward.path);
        let credentials = match forge_core::repo::proxy::upstream_auth(
            &self.state.pool,
            &self.state.envelope,
            &source,
            self.format.upstream_bearer_token(),
        )
        .await
        {
            Ok(credentials) => credentials,
            Err(e) => return repo_error(e),
        };
        let auth = credentials.as_ref().map(|c| c.auth());
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(content_type) = reqwest::header::HeaderValue::from_str(&forward.content_type) {
            headers.insert(reqwest::header::CONTENT_TYPE, content_type);
        }
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        let resp = match self
            .state
            .upstream
            .send_with_body(
                reqwest::Method::POST,
                &url,
                RequestClass::Metadata,
                headers,
                auth.as_ref(),
                Some(forward.body),
            )
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(repo = %source.name, error = %e, "forward to the upstream failed");
                return (
                    StatusCode::BAD_GATEWAY,
                    "the upstream did not answer; try again later",
                )
                    .into_response();
            }
        };
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let config = self.state.upstream.config();
        let answer = match SpooledBody::read(
            resp,
            &url,
            config.max_metadata_bytes,
            config.spool_memory_bytes,
        )
        .await
        {
            Ok(answer) => answer,
            Err(e) => {
                tracing::warn!(repo = %source.name, error = %e, "forward: the upstream's answer could not be read");
                return (
                    StatusCode::BAD_GATEWAY,
                    "the upstream's answer could not be read",
                )
                    .into_response();
            }
        };
        let body = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut out = Vec::new();
            answer.into_reader()?.read_to_end(&mut out)?;
            Ok(out)
        })
        .await;
        match body {
            Ok(Ok(body)) => self.respond(protocol::Response {
                status,
                headers: vec![("content-type".into(), content_type)],
                body,
            }),
            _ => (
                StatusCode::BAD_GATEWAY,
                "the upstream's answer could not be read",
            )
                .into_response(),
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
            if name == "link" && !self.links_within_repository(value) {
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
        // A 204 or a 304 has no body, and says nothing of its length.
        if !matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED) {
            out.headers_mut().insert(
                header::CONTENT_LENGTH,
                HeaderValue::from(response.body.len()),
            );
        }
        if !self.head() {
            *out.body_mut() = Body::from(response.body);
        }
        out.extensions_mut().insert(PluginWritten);
        out
    }

    /// Whether a redirect target stays inside this repository: it starts
    /// with the repository's path or URL and has no dot segments, literal or
    /// percent-encoded (URL parsers resolve `%2e%2e` like `..`), and no
    /// backslashes (which browsers read as `/`).
    fn within_repository(&self, location: &str) -> bool {
        within(location, self.mount, &self.repo.name, &self.target.base_url)
    }

    /// Whether every target of a `Link` header (`<url>; rel=...`, comma
    /// separated) stays inside this repository.
    fn links_within_repository(&self, value: &str) -> bool {
        links_within(value, self.mount, &self.repo.name, &self.target.base_url)
    }
}

/// The permission `change` needs, and what it is called in a refusal.
fn needs(change: &Change) -> (Level, &'static str) {
    match change {
        Change::Unlist(_) => (Level::Delete, "unlist"),
        Change::Delete(_) => (Level::Delete, "delete"),
        Change::Relist(_) => (Level::Write, "relist"),
        Change::Deprecate { .. } => (Level::Write, "deprecate"),
        Change::Tag { .. } | Change::Untag { .. } => (Level::Write, "tag"),
    }
}

/// What a write path change came to.
fn outcome(result: Result<DeleteOutcome, WriteError>) -> Result<(), Response> {
    match result {
        Ok(DeleteOutcome::NotFound) => {
            Err((StatusCode::NOT_FOUND, "package not found").into_response())
        }
        Ok(_) => Ok(()),
        Err(e) => Err(write_error(e)),
    }
}

/// A tag: a short word of letters, digits, `.`, `_` and `-`.
fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The request body, as [`FormatPlugin::unpack_upload`] reads it: chunks
/// sent from the async side.
struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>,
    chunk: Bytes,
}

impl ChannelReader {
    fn new(rx: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>) -> Self {
        ChannelReader {
            rx,
            chunk: Bytes::new(),
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.chunk.is_empty() {
            match self.rx.blocking_recv() {
                Some(Ok(chunk)) => self.chunk = chunk,
                Some(Err(e)) => return Err(e),
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.chunk.len());
        out[..n].copy_from_slice(&self.chunk[..n]);
        self.chunk = self.chunk.slice(n..);
        Ok(n)
    }
}

/// The package [`FormatPlugin::unpack_upload`] writes, sent to the staging
/// on the async side.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<std::io::Result<Bytes>>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.tx
            .blocking_send(Ok(Bytes::copy_from_slice(buf)))
            .map_err(|_| std::io::Error::other("the package is no longer read"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

/// A stored file as the plugin sees it.
fn file_info(file: &RawFile) -> protocol::FileInfo {
    let time =
        |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    protocol::FileInfo {
        path: file.path.clone(),
        size: u64::try_from(file.size).unwrap_or(0),
        content_type: file.content_type.clone(),
        sha256: file.blob_sha256.clone(),
        sha512: file.sha512_base64.clone(),
        sha1: file.sha1.clone(),
        md5: file.md5.clone(),
        modified: time(file.updated_at),
        last_downloaded: file.last_downloaded_at.map(time),
    }
}

/// A page of a directory as the plugin sees it.
fn directory_page(page: crate::files::listing::Page) -> protocol::DirectoryPage {
    use crate::files::listing::EntryKind;
    protocol::DirectoryPage {
        entries: page
            .entries
            .into_iter()
            .map(|entry| match entry.kind {
                EntryKind::File(file) => protocol::DirectoryEntry::File(file_info(&file)),
                EntryKind::Directory(path) => protocol::DirectoryEntry::Directory(path),
            })
            .collect(),
        next: page.next,
    }
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

/// See [`Ctx::within_repository`]. A path may also start with the path of
/// `base_url` (a public base URL with a path of its own).
fn within(location: &str, mount: &str, repo: &str, base_url: &str) -> bool {
    let path_prefix = format!("{mount}/{repo}/");
    let absolute_prefix = format!("{base_url}/");
    let base_path_prefix = url::Url::parse(base_url)
        .ok()
        .map(|url| format!("{}/", url.path().trim_end_matches('/')));
    let lower = location.to_ascii_lowercase();
    (location.starts_with(&path_prefix)
        || location.starts_with(&absolute_prefix)
        || base_path_prefix
            .as_deref()
            .is_some_and(|prefix| prefix != "/" && location.starts_with(prefix)))
        && !location
            .split(['/', '?', '#'])
            .any(|seg| seg == ".." || seg == ".")
        && !lower.contains("%2e")
        && !location.contains('\\')
}

/// See [`Ctx::links_within_repository`]: every `<…>` of `value` is
/// [`within`] the repository, and there is one at least.
fn links_within(value: &str, mount: &str, repo: &str, base_url: &str) -> bool {
    let mut targets = 0;
    for link in value.split(',') {
        let Some(target) = link
            .trim()
            .strip_prefix('<')
            .and_then(|rest| rest.split_once('>'))
            .map(|(target, _)| target)
        else {
            return false;
        };
        if !within(target, mount, repo, base_url) {
            return false;
        }
        targets += 1;
    }
    targets > 0
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

pub(crate) fn repo_error(e: RepoError) -> Response {
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
        // An outage of the proxy's upstream, not a fault of Forge: logged as
        // a warning (the error names the upstream URL), retried by clients.
        RepoError::Upstream(_) => {
            tracing::warn!(error = %e, "proxy upstream unavailable and nothing cached answers");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "30")],
                "the upstream is unavailable, try again later",
            )
                .into_response()
        }
        // Not an outage: retrying will not help.
        RepoError::BadUpstream(_) => {
            tracing::warn!(error = %e, "proxy upstream answered unusably and nothing cached answers");
            (
                StatusCode::BAD_GATEWAY,
                "the upstream refused this proxy (are its credentials right?) or served a package \
                 it does not take",
            )
                .into_response()
        }
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

    /// The built-in formats' descriptors are checked here, not at startup: a
    /// well-formed id that is not reserved and no other format has, a free
    /// mount, kinds, asset names.
    #[test]
    fn the_builtin_formats_describe_themselves_well() {
        let plugins = builtin(Default::default(), Default::default());
        let descriptors: Vec<_> = plugins.iter().map(|p| p.descriptor()).collect();
        assert_eq!(forge_plugin::descriptor::check(&descriptors), Ok(()));
        let ids: Vec<_> = plugins.iter().map(|p| p.id()).collect();
        assert_eq!(ids, ["docker", "nuget", "npm", "raw"]);
        for plugin in &plugins {
            assert_eq!(plugin.descriptor().version, "1.0.0", "{}", plugin.id());
        }
        // Only npm sends a proxy's token as a Bearer token.
        let bearer: Vec<_> = plugins
            .iter()
            .filter(|p| p.descriptor().upstream_token == forge_plugin::api::UpstreamToken::Bearer)
            .map(|p| p.id())
            .collect();
        assert_eq!(bearer, ["npm"]);

        // The check refuses a malformed or reserved id, a second format
        // with a built-in's id (Docker's included), a second images format,
        // and invalid asset names.
        let nuget = forge_format_nuget::DESCRIPTOR;
        for id in ["NuGet", "n", "v2"] {
            let renamed = forge_plugin::Descriptor { id, ..nuget };
            assert!(
                forge_plugin::descriptor::check(&[&renamed]).is_err(),
                "{id:?}"
            );
        }
        let twin = forge_plugin::Descriptor {
            id: "nuget",
            mount: "/twin",
            ..forge_format_raw::DESCRIPTOR
        };
        let mut with_twin = descriptors.clone();
        with_twin.push(&twin);
        assert!(forge_plugin::descriptor::check(&with_twin).is_err());
        let docker_twin = forge_plugin::Descriptor {
            id: "docker",
            ..nuget
        };
        let mut with_twin = descriptors.clone();
        with_twin.push(&docker_twin);
        assert!(forge_plugin::descriptor::check(&with_twin).is_err());
        let second_images = forge_plugin::Descriptor {
            id: "oci",
            ..forge_format_docker::DESCRIPTOR
        };
        let mut with_second = descriptors.clone();
        with_second.push(&second_images);
        assert!(forge_plugin::descriptor::check(&with_second).is_err());
        let bad_assets = forge_plugin::Descriptor {
            assets: forge_plugin::api::Assets {
                package: "../package.nupkg",
                ..nuget.assets
            },
            ..nuget
        };
        assert!(forge_plugin::descriptor::check(&[&bad_assets]).is_err());
    }

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
            Some(("/repository", "charts", ""))
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
    fn links_stay_inside_the_repository() {
        let base = "https://forge.example.com/raw/bin";
        let ok = "<https://forge.example.com/raw/bin/a/?after=x>; rel=\"next\"";
        assert!(links_within(ok, "/raw", "bin", base));
        assert!(links_within(
            "</raw/bin/a/?after=x>; rel=\"next\", </raw/bin/>; rel=\"up\"",
            "/raw",
            "bin",
            base
        ));
        for bad in [
            "<https://evil.example.com/>; rel=\"next\"",
            "</raw/other/>; rel=\"next\"",
            "</raw/bin/>; rel=\"next\", <https://evil.example.com/>; rel=\"preload\"",
            "rel=\"next\"",
            "",
        ] {
            assert!(!links_within(bad, "/raw", "bin", base), "{bad}");
        }
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
        // Behind a public base URL with a path, the repository's path.
        assert!(within(
            "/forge/repository/charts/index.yaml",
            "/repository",
            "charts",
            "https://forge.example.com/forge/repository/charts"
        ));
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
