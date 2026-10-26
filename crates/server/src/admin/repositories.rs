//! Admin repository CRUD + package hard-delete.
//!
//! `upstream_password` is **write-only**: accepted on create/update, never
//! returned (responses carry a [`RepoView`] with no password field). The update
//! body's field semantics (absent = keep, `null` = clear, value = set) and the
//! credential drop on an origin change are documented on [`UpdateRepo`].
//!
//! `remote_url` on a proxy is **scheme-validated** at create/update time
//! (http/https only; private and loopback addresses are allowed) so a bad
//! upstream is rejected before any fetch. The configured host is logged on save
//! for operator visibility (the URL may point at internal addresses).
//!
//! Repository **names** are URL path segments (`/repository/{name}/…`, the SPA's
//! `/repositories/{name}`), so they are validated on create and rename (see
//! [`validate_repo_name`]).

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::format::Format;
use forge_core::net::ssrf::validate_url;
use forge_db::model::{
    DeploymentPolicy, RepoKind, Repository, CONTENT_DISPOSITION_KEY, DEPLOYMENT_POLICY_KEY,
    DOCKER_HOST_KEY, IMMUTABLE_TAGS_KEY, LATEST_MUTABLE_KEY, MAX_AGE_SECONDS_KEY,
    MAX_UPLOAD_BYTES_KEY, NUGET_FORMAT, PREFER_HOSTED_KEY, RESERVED_PREFIXES_KEY,
    WRITABLE_MEMBER_ID_KEY,
};
use forge_db::repository_dao::{self, NewRepository, RepositoryUpdate};
use forge_db::{component_dao, oci_dao, raw_dao};
use forge_plugin::api::Storage;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{db_error, double_option};
use crate::state::AppState;

/// Public, password-free view of a repository (REDACTED secrets).
#[derive(Debug, Serialize)]
pub struct RepoView {
    pub id: i64,
    pub name: String,
    pub format: String,
    pub kind: String,
    pub anonymous_read: bool,
    pub online: bool,
    pub remote_url: Option<String>,
    pub package_delay_seconds: i32,
    pub upstream_username: Option<String>,
    /// `true` when an `upstream_password` is stored; the value itself is never
    /// returned.
    pub has_upstream_password: bool,
    pub metadata_ttl_seconds: Option<i32>,
    pub not_found_ttl_seconds: Option<i32>,
    pub allow_redeploy: bool,
    /// Group dependency-confusion guard (see [`Repository::prefer_hosted`]).
    pub prefer_hosted: bool,
    /// Group: id prefixes never served from a proxy member (see
    /// [`Repository::reserved_prefixes`]).
    pub reserved_prefixes: Vec<String>,
    /// Docker: the host name this repository also answers on by itself
    /// (see [`Repository::docker_host`]).
    pub host: Option<String>,
    /// Hosted docker: pushed tags may not be moved.
    pub immutable_tags: bool,
    /// Hosted docker with immutable tags: `latest` may still be moved.
    pub latest_mutable: bool,
    /// Docker group: the hosted member pushes to the group go to, by its
    /// current name (it is stored by id).
    pub writable_member: Option<String>,
    /// Hosted: the largest push it accepts (for docker, the largest blob),
    /// `None` for the default of its format (`GET /admin/formats`).
    pub max_upload_bytes: Option<u64>,
    /// Hosted, of a files format (raw) or a package format: `allow_redeploy` |
    /// `disable_redeploy` | `read_only`.
    pub deployment_policy: Option<&'static str>,
    /// A files format (raw): `attachment` (files download) | `inline`
    /// (files display).
    pub content_disposition: Option<&'static str>,
    /// Proxy of a files format (raw): seconds a cached file is served
    /// before the upstream is asked whether it changed (`0`: never).
    pub max_age_seconds: Option<u64>,
    /// What the repository holds: `packages`, `files` (a files format: raw)
    /// or `images` (Docker).
    pub storage: &'static str,
}

impl RepoView {
    /// The view of `r`, naming its writable member as `names` (repository
    /// names by id) does; its format's repositories hold `storage`.
    fn new(r: &Repository, names: &HashMap<i64, String>, storage: Storage) -> Self {
        let stores_files = storage == Storage::Files;
        RepoView {
            id: r.id,
            name: r.name.clone(),
            format: r.format.clone(),
            kind: r.kind.clone(),
            anonymous_read: r.anonymous_read,
            online: r.online,
            remote_url: r.remote_url.clone(),
            package_delay_seconds: r.package_delay_seconds,
            upstream_username: r.upstream_username.clone(),
            has_upstream_password: r.has_upstream_password(),
            metadata_ttl_seconds: r.metadata_ttl_seconds,
            not_found_ttl_seconds: r.not_found_ttl_seconds,
            allow_redeploy: r.allow_redeploy,
            prefer_hosted: r.prefer_hosted(),
            reserved_prefixes: r.reserved_prefixes(),
            host: r.docker_host().map(str::to_string),
            immutable_tags: r.immutable_tags(),
            latest_mutable: r.immutable_tags() && r.latest_mutable(),
            writable_member: r
                .writable_member_id()
                .and_then(|id| names.get(&id).cloned()),
            max_upload_bytes: r.max_upload_bytes(),
            deployment_policy: (storage != Storage::Images && r.kind() == RepoKind::Hosted)
                .then(|| deployment_policy_of(r).as_str()),
            content_disposition: stores_files.then(|| {
                if r.inline_content() {
                    "inline"
                } else {
                    "attachment"
                }
            }),
            max_age_seconds: (stores_files && r.kind() == RepoKind::Proxy)
                .then(|| r.max_age_seconds()),
            storage: storage.as_str(),
        }
    }
}

/// The view of `r`, its writable member's current name looked up.
async fn view(state: &AppState, r: &Repository) -> sqlx::Result<RepoView> {
    let mut names = HashMap::new();
    if let Some(id) = r.writable_member_id() {
        if let Some(member) = repository_dao::find_repository_by_id(&state.pool, id).await? {
            names.insert(id, member.name);
        }
    }
    Ok(RepoView::new(r, &names, state.storage(&r.format)))
}

/// Create-repository request body. Unknown fields are rejected: a misspelled
/// `anonymous_read` or `reserved_prefixes` must not fall back to its default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRepo {
    pub name: String,
    /// `hosted` | `proxy` | `group`.
    pub kind: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub anonymous_read: bool,
    #[serde(default = "default_true")]
    pub online: bool,
    // Proxy fields:
    #[serde(default)]
    pub remote_url: Option<String>,
    #[serde(default)]
    pub package_delay_seconds: i32,
    #[serde(default)]
    pub upstream_username: Option<String>,
    #[serde(default)]
    pub upstream_password: Option<String>,
    #[serde(default)]
    pub metadata_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub not_found_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub allow_redeploy: bool,
    /// Group only: hide proxy versions of ids a hosted member has (default on).
    #[serde(default)]
    pub prefer_hosted: Option<bool>,
    /// Group only: id prefixes (e.g. `Acme.`) never served from a proxy member.
    #[serde(default)]
    pub reserved_prefixes: Option<Vec<String>>,
    /// Docker only: a host name the repository answers on by itself
    /// (host-based routing: `<host>/<image>` instead of `<server>/<repo>/<image>`).
    #[serde(default)]
    pub host: Option<String>,
    /// Hosted docker only: refuse to move an existing tag (default off).
    #[serde(default)]
    pub immutable_tags: Option<bool>,
    /// Hosted docker only: with `immutable_tags`, `latest` may still move.
    #[serde(default)]
    pub latest_mutable: Option<bool>,
    /// Docker or package group only: the hosted member of its format a
    /// push or publish to the group goes to.
    #[serde(default)]
    pub writable_member: Option<String>,
    /// Hosted only: the largest push it accepts, in bytes (for docker, the
    /// largest blob). Absent: the default of its format.
    #[serde(default)]
    pub max_upload_bytes: Option<u64>,
    /// Hosted raw or package only: `allow_redeploy`, `disable_redeploy`
    /// (default) or `read_only`. A package repository's `allow_redeploy`
    /// says the same and may not contradict it.
    #[serde(default)]
    pub deployment_policy: Option<String>,
    /// Raw only: `attachment` (default) or `inline`.
    #[serde(default)]
    pub content_disposition: Option<String>,
    /// Raw proxy only: seconds before a cached file is re-validated (`0`:
    /// never). Absent: a day.
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

/// Update-repository request body (`PUT /admin/repositories/{name}`).
/// Identity columns (`kind`, `format`) are not updatable.
///
/// Field semantics:
///
/// * `name`, `anonymous_read`, `online`, `remote_url`, `package_delay_seconds`,
///   `allow_redeploy`, `prefer_hosted`: absent (or `null`) = keep, value = set.
///   A new `name` is validated like on create.
/// * `upstream_username`, `upstream_password`, `metadata_ttl_seconds`,
///   `not_found_ttl_seconds`: **absent = keep, JSON `null` = clear, value =
///   set.** A cleared TTL falls back to the server default. A password is
///   stored sealed; clearing it removes the sealed blob.
/// * **Origin change.** When `remote_url` moves to a different origin (scheme,
///   host and port) and the request does not set a new `upstream_password`,
///   the stored `upstream_username` and password are dropped, so a private
///   feed's credentials are never sent to the new host. (A username sent in
///   the same request is still applied.) The response then carries
///   `"upstream_credentials_dropped": true` and a warning is logged.
/// * Turning `anonymous_read` off also deletes the anonymous role's unscoped
///   `read` grant on the repository, so anonymous access really ends.
/// * Docker options (`host`, `immutable_tags`, `latest_mutable`) follow the
///   same rules (`host`: `null` clears) and are refused on other formats; a
///   docker or package group's `writable_member` too (`null` clears).
/// * `max_upload_bytes` (hosted only): `null` clears it, back to the default
///   of the repository's format.
/// * Raw options (`content_disposition`, `max_age_seconds`) are refused on
///   other formats; `max_age_seconds: null` goes back to the default. A
///   hosted raw or package repository's `deployment_policy` sets its
///   policy; a package repository's `allow_redeploy` follows it (and sets
///   it, when given alone).
/// * Unknown fields are rejected (a misspelled field would otherwise keep the
///   stored value).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRepo {
    pub name: Option<String>,
    pub anonymous_read: Option<bool>,
    pub online: Option<bool>,
    pub remote_url: Option<String>,
    pub package_delay_seconds: Option<i32>,
    #[serde(default, deserialize_with = "double_option")]
    pub upstream_username: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub upstream_password: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub metadata_ttl_seconds: Option<Option<i32>>,
    #[serde(default, deserialize_with = "double_option")]
    pub not_found_ttl_seconds: Option<Option<i32>>,
    pub allow_redeploy: Option<bool>,
    /// Group only.
    pub prefer_hosted: Option<bool>,
    /// Group only; replaces the whole list (`[]` clears it).
    pub reserved_prefixes: Option<Vec<String>>,
    /// Docker only; `null` clears it.
    #[serde(default, deserialize_with = "double_option")]
    pub host: Option<Option<String>>,
    /// Hosted docker only.
    pub immutable_tags: Option<bool>,
    /// Hosted docker only.
    pub latest_mutable: Option<bool>,
    /// Docker group only; `null` clears it (pushes to the group are refused).
    #[serde(default, deserialize_with = "double_option")]
    pub writable_member: Option<Option<String>>,
    /// Hosted only; `null` clears it (the format's default applies).
    #[serde(default, deserialize_with = "double_option")]
    pub max_upload_bytes: Option<Option<u64>>,
    /// Hosted raw only.
    pub deployment_policy: Option<String>,
    /// Raw only.
    pub content_disposition: Option<String>,
    /// Raw proxy only; `null` clears it (a day).
    #[serde(default, deserialize_with = "double_option")]
    pub max_age_seconds: Option<Option<u64>>,
}

/// Update response: the [`RepoView`] plus whether this update dropped the
/// stored upstream credentials (see [`UpdateRepo`], "Origin change").
#[derive(Debug, Serialize)]
pub struct UpdatedRepoView {
    #[serde(flatten)]
    pub repo: RepoView,
    /// `true` iff `remote_url` moved to another origin without a new
    /// `upstream_password`, and stored credentials were removed.
    pub upstream_credentials_dropped: bool,
}

/// The longest accepted repository name.
const MAX_REPO_NAME_LEN: usize = 64;

/// Validate a repository name: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, and not
/// `new` (any case), which the SPA uses as its "create repository" route.
///
/// The name is a URL path segment (`/repository/{name}/…`); a name with a space, `%`
/// or `/` is stored fine but can never be reached as a feed.
fn validate_repo_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = name.len() <= MAX_REPO_NAME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid {
        return Err(format!(
            "invalid repository name {name:?}: use 1-{MAX_REPO_NAME_LEN} characters from \
             A-Z, a-z, 0-9, '.', '_' and '-', starting with a letter or digit \
             (the name is part of the feed URL)"
        ));
    }
    if name.eq_ignore_ascii_case("new") {
        return Err("repository name \"new\" is reserved".into());
    }
    Ok(())
}

/// Whether `new` points at a different origin (scheme, host, port — default
/// ports normalized) than `old`. A missing or unparsable URL on either side
/// counts as a change: stored credentials are only kept when the origin is
/// provably the same.
fn origin_changed(old: Option<&str>, new: &str) -> bool {
    match (
        old.and_then(|u| url::Url::parse(u).ok()),
        url::Url::parse(new),
    ) {
        (Some(old), Ok(new)) => old.origin() != new.origin(),
        _ => true,
    }
}

/// What an update does to the stored upstream password.
enum PasswordChange {
    Keep,
    Clear,
    Set(String),
}

fn default_format() -> String {
    NUGET_FORMAT.into()
}
fn default_true() -> bool {
    true
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

/// Scheme-validate a proxy `remote_url` (http/https only). `None` is OK at this
/// layer (proxy-without-url is rejected separately). Logs the configured host
/// (the URL may legitimately point at internal addresses; the log line gives
/// operators an audit trail of where forge was pointed).
#[allow(clippy::result_large_err)] // the Err is a ready-made axum Response
fn validate_remote_url(url: &str) -> Result<(), Response> {
    validate_url(url).map_err(|e| bad_request(format!("invalid remote_url: {e}")))?;
    if let Ok(parsed) = url::Url::parse(url) {
        // Credentials embedded in the URL would be stored, logged and returned
        // in plaintext; they belong in the write-only upstream_username /
        // upstream_password fields.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(bad_request(
                "remote_url must not embed credentials; use upstream_username / upstream_password",
            ));
        }
        tracing::info!(
            host = parsed.host_str().unwrap_or(""),
            "proxy remote_url configured"
        );
    }
    Ok(())
}

/// Longest accepted `metadata_ttl_seconds` / `not_found_ttl_seconds`: a week.
const MAX_PROXY_TTL_SECONDS: i32 = 7 * 24 * 60 * 60;

/// Longest accepted `package_delay_seconds`: a year.
const MAX_PACKAGE_DELAY_SECONDS: i32 = 365 * 24 * 60 * 60;

/// Most reserved prefixes a group may carry.
const MAX_RESERVED_PREFIXES: usize = 100;

/// Validate and normalize a group's reserved id prefixes: each is at most
/// 100 bytes, an optional trailing `*` dropped, deduplicated, and what the
/// group's format makes of it ([`Format::reserved_prefix`]: NuGet's
/// `A-Z a-z 0-9 . _ -`, lowercase; npm's `@acme` is the scope `@acme/`;
/// Docker's image-name prefixes may hold a namespace, `acme/`).
fn normalize_prefixes(raw: &[String], format: Option<&dyn Format>) -> Result<Vec<String>, String> {
    if raw.len() > MAX_RESERVED_PREFIXES {
        return Err(format!(
            "at most {MAX_RESERVED_PREFIXES} reserved_prefixes are allowed"
        ));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for prefix in raw {
        let prefix = prefix.trim();
        let prefix = prefix.strip_suffix('*').unwrap_or(prefix);
        if prefix.is_empty() || prefix.len() > 100 {
            return Err(format!(
                "reserved_prefixes: {prefix:?} must be 1-100 bytes long"
            ));
        }
        let prefix = match format {
            Some(format) => format.reserved_prefix(prefix).map_err(|e| match e {
                forge_core::domain::FormatError::InvalidPackage(m) => {
                    format!("reserved_prefixes: {m}")
                }
                e => format!("reserved_prefixes: {e}"),
            })?,
            None => {
                let valid = prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
                if !valid {
                    return Err(format!(
                        "reserved_prefixes: {prefix:?} is not a package id prefix (letters, digits, '.', '_', '-')"
                    ));
                }
                prefix.to_ascii_lowercase()
            }
        };
        if !out.contains(&prefix) {
            out.push(prefix);
        }
    }
    Ok(out)
}

/// What a hosted repository does with a publish of a version it has: the
/// stored `deployment_policy`, or, for a package repository that has none
/// yet, what `allow_redeploy` says.
fn deployment_policy_of(r: &Repository) -> DeploymentPolicy {
    if r.config.get(DEPLOYMENT_POLICY_KEY).is_some() {
        r.deployment_policy()
    } else if r.allow_redeploy {
        DeploymentPolicy::AllowRedeploy
    } else {
        DeploymentPolicy::DisableRedeploy
    }
}

/// Validate and normalize a docker repository's `host`: a lowercase DNS name
/// (no port, no scheme) other than the server's own public host.
fn normalize_docker_host(raw: &str, public_base_url: &str) -> Result<String, String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if host.len() > 253 || !host.contains('.') || !host.split('.').all(label_ok) {
        return Err(format!(
            "invalid host {raw:?}: give a DNS name such as docker.example.com (no scheme or port)"
        ));
    }
    let public_host = url::Url::parse(public_base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    if public_host.as_deref() == Some(host.as_str()) {
        return Err(
            "host must differ from the server's own host (repositories are reachable there by path)"
                .into(),
        );
    }
    Ok(host)
}

/// A group's `writable_member`: an existing hosted repository of the
/// group's `format`, whose id is stored.
async fn validate_writable_member(
    state: &AppState,
    name: &str,
    format: &str,
) -> Result<i64, Response> {
    match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(r)) if r.format == format && r.kind() == RepoKind::Hosted => Ok(r.id),
        Ok(_) => Err(bad_request(format!(
            "writable_member {name:?} must be a hosted {format} repository (and a member of the group)"
        ))),
        Err(e) => Err(db_error(e)),
    }
}

/// The unique violation of a docker host already in use.
fn is_host_conflict(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db)
        if db.code().as_deref() == Some("23505")
            && db.constraint() == Some("repository_docker_host_idx"))
}

/// Validate a repository upload limit for a repository of `kind`: hosted
/// only, more than 0, and at most what a push can stage
/// ([`crate::config::Config::max_repository_upload_bytes`]).
#[allow(clippy::result_large_err)]
fn validate_upload_limit(state: &AppState, kind: RepoKind, bytes: u64) -> Result<u64, Response> {
    if kind != RepoKind::Hosted {
        return Err(bad_request(
            "max_upload_bytes is only valid for hosted repositories",
        ));
    }
    if bytes == 0 {
        return Err(bad_request("max_upload_bytes must be greater than 0"));
    }
    if let Some(ceiling) = state.config.max_repository_upload_bytes() {
        if bytes > ceiling {
            return Err(bad_request(format!(
                "max_upload_bytes ({bytes}) is larger than a push can be staged ({ceiling} \
                 bytes: server.max_staging_bytes less nuget.max_nuspec_bytes); raise \
                 server.max_staging_bytes first"
            )));
        }
    }
    Ok(bytes)
}

/// Reject negative or absurd proxy timings. A negative TTL made every
/// unconfirmed row prunable at once (racing in-flight downloads), and an
/// unbounded not-found TTL let one request hide a package for years.
fn validate_timings(
    package_delay_seconds: i32,
    metadata_ttl_seconds: Option<i32>,
    not_found_ttl_seconds: Option<i32>,
) -> Result<(), Response> {
    if !(0..=MAX_PACKAGE_DELAY_SECONDS).contains(&package_delay_seconds) {
        return Err(bad_request(format!(
            "package_delay_seconds must be between 0 and {MAX_PACKAGE_DELAY_SECONDS}"
        )));
    }
    for (field, value) in [
        ("metadata_ttl_seconds", metadata_ttl_seconds),
        ("not_found_ttl_seconds", not_found_ttl_seconds),
    ] {
        if value.is_some_and(|v| !(0..=MAX_PROXY_TTL_SECONDS).contains(&v)) {
            return Err(bad_request(format!(
                "{field} must be between 0 and {MAX_PROXY_TTL_SECONDS}"
            )));
        }
    }
    Ok(())
}

/// `GET /admin/repositories`
pub async fn list(State(state): State<AppState>) -> Response {
    match repository_dao::list_repositories(&state.pool).await {
        Ok(repos) => {
            let names: HashMap<i64, String> =
                repos.iter().map(|r| (r.id, r.name.clone())).collect();
            let views: Vec<RepoView> = repos
                .iter()
                .map(|r| RepoView::new(r, &names, state.storage(&r.format)))
                .collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `GET /admin/repositories/{name}`
pub async fn get(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => match view(&state, &r).await {
            Ok(view) => Json(view).into_response(),
            Err(e) => db_error(e),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/repositories`
pub async fn create(State(state): State<AppState>, Json(body): Json<CreateRepo>) -> Response {
    if let Err(msg) = validate_repo_name(&body.name) {
        return bad_request(msg);
    }
    let kind = match body.kind.as_str() {
        "hosted" | "proxy" | "group" => body.kind.clone(),
        other => return bad_request(format!("invalid kind {other:?}")),
    };
    // The format must be installed: Docker, raw or a format plugin (NuGet;
    // `GET /admin/formats`), and support
    // the kind. It is fixed for the repository's lifetime.
    let Some(kinds) = state.formats.kinds(&body.format) else {
        let available: Vec<&str> = state.formats.ids().collect();
        return bad_request(format!(
            "unsupported format {:?}: available formats are {available:?}",
            body.format
        ));
    };
    // Docker serves every kind; a plugin format serves the kinds its plugin
    // names (NuGet's all three).
    if !kinds.contains(&kind.as_str()) {
        return bad_request(format!(
            "{kind} repositories are not available for format {:?}",
            body.format
        ));
    }
    let storage = state.storage(&body.format);
    let images = storage == Storage::Images;
    let files = storage == Storage::Files;
    // A package format plugin's (NuGet's, npm's): package versions.
    let package = storage == Storage::Packages && state.formats.plugin(&body.format).is_some();
    let parsed_kind = RepoKind::from(kind.as_str());
    let docker_config = match docker_options(
        &state,
        images.then_some(body.format.as_str()),
        package.then_some(body.format.as_str()),
        parsed_kind,
        &body.name,
        DockerOptions {
            host: body.host.clone().map(Some),
            immutable_tags: body.immutable_tags,
            latest_mutable: body.latest_mutable,
            writable_member: body.writable_member.clone().map(Some),
        },
        &serde_json::Map::new(),
    )
    .await
    {
        Ok(config) => config,
        Err(resp) => return resp,
    };
    if images && body.package_delay_seconds != 0 {
        return bad_request("package_delay_seconds is not supported for docker repositories");
    }
    if images && body.allow_redeploy {
        return bad_request(
            "allow_redeploy is a NuGet option; docker tags move unless immutable_tags is set",
        );
    }
    if files {
        if let Err(resp) = refuse_for_files(
            Some(body.package_delay_seconds),
            Some(body.allow_redeploy),
            Some(body.metadata_ttl_seconds),
            body.prefer_hosted.is_some() || body.reserved_prefixes.is_some(),
        ) {
            return resp;
        }
    }
    // A package repository's redeploys follow its deployment policy, when
    // it is given; `allow_redeploy` says the same.
    let policy = body
        .deployment_policy
        .as_deref()
        .and_then(DeploymentPolicy::parse);
    if package
        && body.allow_redeploy
        && policy.is_some_and(|p| p != DeploymentPolicy::AllowRedeploy)
    {
        return bad_request("allow_redeploy contradicts deployment_policy");
    }
    let allow_redeploy = match policy {
        Some(policy) if package => policy == DeploymentPolicy::AllowRedeploy,
        _ => body.allow_redeploy,
    };
    let docker_config = match file_options(
        files,
        package,
        parsed_kind,
        FileOptions {
            deployment_policy: body.deployment_policy.clone(),
            content_disposition: body.content_disposition.clone(),
            max_age_seconds: body.max_age_seconds.map(Some),
        },
        docker_config,
    ) {
        Ok(config) => config,
        Err(resp) => return resp,
    };

    // Proxy must carry a remote_url; SSRF-validate it. Non-proxies must not.
    if parsed_kind == RepoKind::Proxy {
        let Some(url) = body.remote_url.as_deref() else {
            return bad_request("proxy repository requires remote_url");
        };
        if let Err(resp) = validate_remote_url(url) {
            return resp;
        }
        if files {
            if let Err(resp) = validate_files_remote_url(url) {
                return resp;
            }
        }
    } else if body.remote_url.is_some() {
        return bad_request("remote_url is only valid for proxy repositories");
    }
    if body.prefer_hosted.is_some() && parsed_kind != RepoKind::Group {
        return bad_request("prefer_hosted is only valid for group repositories");
    }
    if body.reserved_prefixes.is_some() && parsed_kind != RepoKind::Group {
        return bad_request("reserved_prefixes is only valid for group repositories");
    }
    let reserved_prefixes = match body
        .reserved_prefixes
        .as_deref()
        .map(|p| normalize_prefixes(p, state.formats.get(&body.format).as_deref()))
    {
        Some(Err(msg)) => return bad_request(&msg),
        Some(Ok(prefixes)) => Some(prefixes),
        None => None,
    };
    if let Err(resp) = validate_timings(
        body.package_delay_seconds,
        body.metadata_ttl_seconds,
        body.not_found_ttl_seconds,
    ) {
        return resp;
    }
    let mut config = serde_json::Value::Object(docker_config);
    if let Some(bytes) = body.max_upload_bytes {
        match validate_upload_limit(&state, parsed_kind, bytes) {
            Ok(bytes) => config[MAX_UPLOAD_BYTES_KEY] = json!(bytes),
            Err(resp) => return resp,
        }
    }
    if parsed_kind == RepoKind::Group {
        config[PREFER_HOSTED_KEY] = json!(body.prefer_hosted.unwrap_or(true));
        if let Some(prefixes) = reserved_prefixes {
            config[RESERVED_PREFIXES_KEY] = json!(prefixes);
        }
    }

    // The row is created first (the AAD binds the sealed password to the row
    // id, which does not exist before the INSERT) and the password is sealed
    // below.
    let new = NewRepository {
        name: body.name.clone(),
        format: body.format.clone(),
        kind: kind.clone(),
        anonymous_read: body.anonymous_read,
        online: body.online,
        config,
        remote_url: body.remote_url.clone(),
        package_delay_seconds: body.package_delay_seconds,
        upstream_username: body.upstream_username.clone(),
        metadata_ttl_seconds: body.metadata_ttl_seconds,
        not_found_ttl_seconds: body.not_found_ttl_seconds,
        allow_redeploy,
    };

    // The row and its sealed secret commit together: a failed seal must not
    // leave a half-created repository whose retry then answers 409.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return db_error(e),
    };
    let repo = match repository_dao::insert_repository(&mut *tx, new).await {
        Ok(r) => r,
        Err(e) if is_host_conflict(&e) => {
            return (
                StatusCode::CONFLICT,
                "another docker repository already answers on this host",
            )
                .into_response()
        }
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "repository name already exists").into_response()
        }
        Err(e) => return db_error(e),
    };
    let sealed = match &body.upstream_password {
        Some(pw) => {
            if let Err(resp) =
                store_encrypted_password(&mut tx, &state.envelope, repo.id, pw.clone()).await
            {
                return resp;
            }
            true
        }
        None => false,
    };
    if let Err(e) = tx.commit().await {
        return db_error(e);
    }
    // Re-fetched so the view reflects the sealed secret.
    let repo = if sealed {
        match repository_dao::find_repository_by_id(&state.pool, repo.id).await {
            Ok(Some(r)) => r,
            Ok(None) => return db_error(sqlx::Error::RowNotFound),
            Err(e) => return db_error(e),
        }
    } else {
        repo
    };
    match view(&state, &repo).await {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(e) => db_error(e),
    }
}

/// The docker options of a create or update request (`None`: not sent;
/// `Some(None)`: cleared).
struct DockerOptions {
    host: Option<Option<String>>,
    immutable_tags: Option<bool>,
    latest_mutable: Option<bool>,
    writable_member: Option<Option<String>>,
}

impl DockerOptions {
    fn any(&self) -> bool {
        self.host.is_some()
            || self.immutable_tags.is_some()
            || self.latest_mutable.is_some()
            || self.writable_member.is_some()
    }
}

/// Validate the docker options against the repository's format and kind
/// and merge them into `existing` (its stored config object). Returns the
/// config object to store. They are the image store's: only a repository
/// of an images format (`images`: its format, Docker) takes them.
///
/// A group of a package format (`writable`: its format) takes a writable
/// member too: where its clients' publishes and changes land.
#[allow(clippy::result_large_err)]
async fn docker_options(
    state: &AppState,
    images: Option<&str>,
    writable: Option<&str>,
    kind: RepoKind,
    name: &str,
    options: DockerOptions,
    existing: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>, Response> {
    let mut config = existing.clone();
    let Some(images) = images else {
        let writable_only = options.host.is_none()
            && options.immutable_tags.is_none()
            && options.latest_mutable.is_none();
        if options.any() && !(writable_only && writable.is_some()) {
            return Err(bad_request(
                "host, immutable_tags and latest_mutable are only valid for docker repositories, writable_member for docker and package groups",
            ));
        }
        return writable_member_option(state, writable, kind, options.writable_member, config)
            .await;
    };
    // Path-based routing names an image `<repository>/<image>`: the
    // repository's name must be a valid one (a single component, as a
    // repository name has no `/`).
    let valid_name = state
        .formats
        .get(images)
        .is_some_and(|format| format.validate_id(name).is_ok());
    if !valid_name {
        return Err(bad_request(format!(
            "invalid docker repository name {name:?}: image names start with it, so use \
             lowercase letters and digits, separated by '.', '_', '__' or '-'"
        )));
    }
    if (options.immutable_tags.is_some() || options.latest_mutable.is_some())
        && kind != RepoKind::Hosted
    {
        return Err(bad_request(
            "immutable_tags and latest_mutable are only valid for hosted repositories",
        ));
    }
    match options.host {
        Some(Some(host)) => {
            let host = normalize_docker_host(&host, &state.config.public_base_url())
                .map_err(bad_request)?;
            config.insert(DOCKER_HOST_KEY.into(), json!(host));
        }
        Some(None) => {
            config.remove(DOCKER_HOST_KEY);
        }
        None => {}
    }
    if let Some(immutable) = options.immutable_tags {
        config.insert(IMMUTABLE_TAGS_KEY.into(), json!(immutable));
    }
    if let Some(latest) = options.latest_mutable {
        config.insert(LATEST_MUTABLE_KEY.into(), json!(latest));
    }
    writable_member_option(state, Some(images), kind, options.writable_member, config).await
}

/// Merge a group's `writable_member` (a hosted repository of `format`;
/// `Some(None)`: cleared) into `config`.
#[allow(clippy::result_large_err)]
async fn writable_member_option(
    state: &AppState,
    format: Option<&str>,
    kind: RepoKind,
    member: Option<Option<String>>,
    mut config: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>, Response> {
    if member.is_some() && kind != RepoKind::Group {
        return Err(bad_request(
            "writable_member is only valid for group repositories",
        ));
    }
    match (member, format) {
        (Some(Some(member)), Some(format)) => {
            let member = validate_writable_member(state, &member, format).await?;
            config.insert(WRITABLE_MEMBER_ID_KEY.into(), json!(member));
        }
        (Some(None), _) => {
            config.remove(WRITABLE_MEMBER_ID_KEY);
        }
        _ => {}
    }
    Ok(config)
}

/// The options of a files format (raw) in a create or update request
/// (`None`: not sent; for `max_age_seconds`, `Some(None)`: cleared).
struct FileOptions {
    deployment_policy: Option<String>,
    content_disposition: Option<String>,
    max_age_seconds: Option<Option<u64>>,
}

impl FileOptions {
    fn any(&self) -> bool {
        self.deployment_policy.is_some()
            || self.content_disposition.is_some()
            || self.max_age_seconds.is_some()
    }
}

/// Longest accepted `max_age_seconds`: ten years.
const MAX_FILE_MAX_AGE_SECONDS: u64 = 10 * 366 * 24 * 60 * 60;

/// Validate the files options against the repository's format and kind and
/// merge them into `config` (the config object to store). A package
/// repository (`package`) takes the deployment policy too.
#[allow(clippy::result_large_err)]
fn file_options(
    files: bool,
    package: bool,
    kind: RepoKind,
    options: FileOptions,
    mut config: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>, Response> {
    if !files {
        let policy_only =
            options.content_disposition.is_none() && options.max_age_seconds.is_none();
        if options.any() && !(policy_only && package) {
            return Err(bad_request(
                "content_disposition and max_age_seconds are only valid for repositories of files (raw), deployment_policy for those and package repositories",
            ));
        }
    }
    if let Some(policy) = options.deployment_policy {
        if kind != RepoKind::Hosted {
            return Err(bad_request(
                "deployment_policy is only valid for hosted repositories",
            ));
        }
        let Some(policy) = DeploymentPolicy::parse(&policy) else {
            return Err(bad_request(
                "deployment_policy must be allow_redeploy, disable_redeploy or read_only",
            ));
        };
        config.insert(DEPLOYMENT_POLICY_KEY.into(), json!(policy.as_str()));
    }
    if let Some(disposition) = options.content_disposition {
        if !matches!(disposition.as_str(), "attachment" | "inline") {
            return Err(bad_request(
                "content_disposition must be attachment or inline",
            ));
        }
        config.insert(CONTENT_DISPOSITION_KEY.into(), json!(disposition));
    }
    if let Some(max_age) = options.max_age_seconds {
        if kind != RepoKind::Proxy {
            return Err(bad_request(
                "max_age_seconds is only valid for proxy repositories",
            ));
        }
        match max_age {
            Some(seconds) if seconds > MAX_FILE_MAX_AGE_SECONDS => {
                return Err(bad_request(format!(
                    "max_age_seconds must be at most {MAX_FILE_MAX_AGE_SECONDS} (0: never re-validate)"
                )));
            }
            Some(seconds) => {
                config.insert(MAX_AGE_SECONDS_KEY.into(), json!(seconds));
            }
            None => {
                config.remove(MAX_AGE_SECONDS_KEY);
            }
        }
    }
    Ok(config)
}

/// The options of other formats a repository of files (raw) refuses.
#[allow(clippy::result_large_err)]
fn refuse_for_files(
    package_delay_seconds: Option<i32>,
    allow_redeploy: Option<bool>,
    metadata_ttl_seconds: Option<Option<i32>>,
    group_guard: bool,
) -> Result<(), Response> {
    if package_delay_seconds.is_some_and(|d| d != 0) {
        return Err(bad_request(
            "package_delay_seconds is not supported for repositories of files (raw)",
        ));
    }
    if allow_redeploy == Some(true) {
        return Err(bad_request(
            "allow_redeploy is a NuGet option; repositories of files (raw) have deployment_policy",
        ));
    }
    if matches!(metadata_ttl_seconds, Some(Some(_))) {
        return Err(bad_request(
            "metadata_ttl_seconds is not used by proxies of files (raw); set max_age_seconds",
        ));
    }
    if group_guard {
        return Err(bad_request(
            "a group of files (raw) serves a path from its first member that has it; prefer_hosted and reserved_prefixes do not apply",
        ));
    }
    Ok(())
}

/// A files proxy's `remote_url` is the base its paths are appended to: no
/// query or fragment.
#[allow(clippy::result_large_err)]
fn validate_files_remote_url(url: &str) -> Result<(), Response> {
    match url::Url::parse(url) {
        Ok(parsed) if parsed.query().is_some() || parsed.fragment().is_some() => Err(bad_request(
            "a proxy of files' remote_url is the base URL the files are under: no query or fragment",
        )),
        _ => Ok(()),
    }
}

/// Seal `password` under the active DEK and store it on `repo_id`
/// (`secret_dao::set_upstream_password`); map failures to a 500 response. The
/// error string carries no key material or plaintext by construction.
async fn store_encrypted_password(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    envelope: &forge_crypto::service::EnvelopeService,
    repo_id: i64,
    password: String,
) -> Result<(), Response> {
    let secret = forge_crypto::PlaintextSecret::from(password);
    forge_db::secret_dao::set_upstream_password(tx, envelope, repo_id, Some(&secret))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, repo_id, "failed to store encrypted upstream password");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to store encrypted upstream password",
            )
                .into_response()
        })
}

/// `PUT /admin/repositories/{name}`
///
/// The body and its keep / clear / set rules are documented on [`UpdateRepo`];
/// the response is an [`UpdatedRepoView`].
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateRepo>,
) -> Response {
    let existing = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return db_error(e),
    };

    // A rename must yield a reachable name; an unchanged (possibly legacy)
    // name is left alone.
    if let Some(new_name) = body.name.as_deref() {
        if new_name != existing.name {
            if let Err(msg) = validate_repo_name(new_name) {
                return bad_request(msg);
            }
        }
    }

    // Merge: each absent field keeps the existing value.
    let remote_url = match &body.remote_url {
        Some(u) => Some(u.clone()),
        None => existing.remote_url.clone(),
    };

    // Re-validate the remote_url for proxies whenever it changed.
    if existing.kind() == RepoKind::Proxy {
        if let Some(url) = remote_url.as_deref() {
            if body.remote_url.is_some() {
                if let Err(resp) = validate_remote_url(url) {
                    return resp;
                }
                if state.formats.stores_files(&existing.format) {
                    if let Err(resp) = validate_files_remote_url(url) {
                        return resp;
                    }
                }
            }
        }
    }
    if state.formats.stores_files(&existing.format) {
        if let Err(resp) = refuse_for_files(
            body.package_delay_seconds,
            body.allow_redeploy,
            body.metadata_ttl_seconds,
            body.prefer_hosted.is_some() || body.reserved_prefixes.is_some(),
        ) {
            return resp;
        }
    }

    let storage = state.storage(&existing.format);
    let images = storage == Storage::Images;
    let final_name = body.name.clone().unwrap_or_else(|| existing.name.clone());
    if images && body.package_delay_seconds.is_some_and(|d| d != 0) {
        return bad_request("package_delay_seconds is not supported for docker repositories");
    }
    if images && body.allow_redeploy == Some(true) {
        return bad_request(
            "allow_redeploy is a NuGet option; docker tags move unless immutable_tags is set",
        );
    }
    let files = storage == Storage::Files;
    let package = storage == Storage::Packages && state.formats.plugin(&existing.format).is_some();
    let stored_config = existing.config.as_object().cloned().unwrap_or_default();
    let config = match docker_options(
        &state,
        images.then_some(existing.format.as_str()),
        package.then_some(existing.format.as_str()),
        existing.kind(),
        &final_name,
        DockerOptions {
            host: body.host.clone(),
            immutable_tags: body.immutable_tags,
            latest_mutable: body.latest_mutable,
            writable_member: body.writable_member.clone(),
        },
        &stored_config,
    )
    .await
    {
        Ok(config) => config,
        Err(resp) => return resp,
    };
    // A package repository's deployment policy and `allow_redeploy` say
    // the same: setting one sets the other.
    let policy = body
        .deployment_policy
        .as_deref()
        .and_then(DeploymentPolicy::parse);
    let mut allow_redeploy = body.allow_redeploy.unwrap_or(existing.allow_redeploy);
    let mut deployment_policy = body.deployment_policy.clone();
    if package && existing.kind() == RepoKind::Hosted {
        match (policy, body.allow_redeploy) {
            (Some(policy), Some(allow)) if allow != (policy == DeploymentPolicy::AllowRedeploy) => {
                return bad_request("allow_redeploy contradicts deployment_policy");
            }
            (Some(policy), _) => allow_redeploy = policy == DeploymentPolicy::AllowRedeploy,
            (None, Some(allow)) if deployment_policy.is_none() => {
                deployment_policy = Some(
                    if allow {
                        DeploymentPolicy::AllowRedeploy
                    } else {
                        DeploymentPolicy::DisableRedeploy
                    }
                    .as_str()
                    .to_string(),
                );
            }
            _ => {}
        }
    }
    let mut config = match file_options(
        files,
        package,
        existing.kind(),
        FileOptions {
            deployment_policy,
            content_disposition: body.content_disposition.clone(),
            max_age_seconds: body.max_age_seconds,
        },
        config,
    ) {
        Ok(config) => serde_json::Value::Object(config),
        Err(resp) => return resp,
    };
    if let Some(prefer_hosted) = body.prefer_hosted {
        if existing.kind() != RepoKind::Group {
            return bad_request("prefer_hosted is only valid for group repositories");
        }
        if !config.is_object() {
            config = json!({});
        }
        config[PREFER_HOSTED_KEY] = json!(prefer_hosted);
    }
    if let Some(prefixes) = body.reserved_prefixes.as_deref() {
        if existing.kind() != RepoKind::Group {
            return bad_request("reserved_prefixes is only valid for group repositories");
        }
        let prefixes =
            match normalize_prefixes(prefixes, state.formats.get(&existing.format).as_deref()) {
                Ok(prefixes) => prefixes,
                Err(msg) => return bad_request(&msg),
            };
        if !config.is_object() {
            config = json!({});
        }
        config[RESERVED_PREFIXES_KEY] = json!(prefixes);
    }
    match body.max_upload_bytes {
        Some(Some(bytes)) => match validate_upload_limit(&state, existing.kind(), bytes) {
            Ok(bytes) => {
                if !config.is_object() {
                    config = json!({});
                }
                config[MAX_UPLOAD_BYTES_KEY] = json!(bytes);
            }
            Err(resp) => return resp,
        },
        Some(None) => {
            if let Some(map) = config.as_object_mut() {
                map.remove(MAX_UPLOAD_BYTES_KEY);
            }
        }
        None => {}
    }

    // Stored credentials belong to the upstream origin they were entered for:
    // repointing the proxy elsewhere without a new password drops them.
    let drop_credentials = body
        .remote_url
        .as_deref()
        .is_some_and(|url| origin_changed(existing.remote_url.as_deref(), url))
        && !matches!(body.upstream_password, Some(Some(_)));
    let credentials_dropped = drop_credentials
        && (existing.upstream_username.is_some() || existing.has_upstream_password());
    let upstream_username = match &body.upstream_username {
        Some(value) => value.clone(),
        None if drop_credentials => None,
        None => existing.upstream_username.clone(),
    };
    let password = match &body.upstream_password {
        Some(Some(pw)) => PasswordChange::Set(pw.clone()),
        Some(None) => PasswordChange::Clear,
        None if drop_credentials => PasswordChange::Clear,
        None => PasswordChange::Keep,
    };
    // Whether the sealed password is cleared; a new one is sealed below.
    let clear_upstream_password_enc = matches!(password, PasswordChange::Clear);

    let upd = RepositoryUpdate {
        name: body.name.clone().unwrap_or(existing.name.clone()),
        anonymous_read: body.anonymous_read.unwrap_or(existing.anonymous_read),
        online: body.online.unwrap_or(existing.online),
        config,
        remote_url,
        package_delay_seconds: body
            .package_delay_seconds
            .unwrap_or(existing.package_delay_seconds),
        upstream_username,
        clear_upstream_password_enc,
        metadata_ttl_seconds: body
            .metadata_ttl_seconds
            .unwrap_or(existing.metadata_ttl_seconds),
        not_found_ttl_seconds: body
            .not_found_ttl_seconds
            .unwrap_or(existing.not_found_ttl_seconds),
        allow_redeploy,
    };
    if let Err(resp) = validate_timings(
        upd.package_delay_seconds,
        upd.metadata_ttl_seconds,
        upd.not_found_ttl_seconds,
    ) {
        return resp;
    }

    // The metadata and a replacement secret commit together: otherwise a
    // failed seal after a committed `remote_url` change would leave the new
    // host paired with the previous host's credentials.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return db_error(e),
    };
    let updated = match repository_dao::update_repository(&mut *tx, existing.id, upd).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) if is_host_conflict(&e) => {
            return (
                StatusCode::CONFLICT,
                "another docker repository already answers on this host",
            )
                .into_response()
        }
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "repository name already exists").into_response()
        }
        Err(e) => return db_error(e),
    };

    // #65: what the proxy learned from its previous upstream (not-found
    // markers, listings, the package-delay clock) must not decide for the new
    // one.
    if existing.kind() == RepoKind::Proxy && updated.remote_url != existing.remote_url {
        if let Err(e) = forge_db::proxy_dao::reset_for_new_upstream(&mut tx, updated.id).await {
            return db_error(e);
        }
        // Its tags were the previous upstream's.
        if let Err(e) = forge_db::tag_dao::delete_repository_tags(&mut *tx, updated.id).await {
            return db_error(e);
        }
        // A docker proxy's tags name what the previous upstream served:
        // the repointed proxy starts with an empty cache. Locked first, as
        // the purge requires: a fetch from the previous upstream still
        // inserting commits before the purge (which removes it), and one
        // inserting later finds the new upstream and caches nothing
        // (`oci_dao::lock_proxy_upstream`).
        if images {
            match repository_dao::lock_repository(&mut *tx, updated.id).await {
                Ok(_) => {}
                Err(e) => return db_error(e),
            }
            if let Err(e) =
                oci_dao::purge_repository(&mut tx, updated.id, state.config.outbox.grace()).await
            {
                return db_error(e);
            }
        }
        // A files proxy's files are the previous upstream's: likewise.
        if state.formats.stores_files(&existing.format) {
            match repository_dao::lock_repository(&mut *tx, updated.id).await {
                Ok(_) => {}
                Err(e) => return db_error(e),
            }
            if let Err(e) =
                raw_dao::purge_repository(&mut tx, updated.id, state.config.outbox.grace()).await
            {
                return db_error(e);
            }
        }
    }

    // M20: the seam honours `anonymous_read` *and* the anonymous role's grants,
    // so switching the flag off must also remove the anonymous role's read
    // grant on the repository, or the repository stays anonymously readable.
    let anonymous_revoked = if existing.anonymous_read && !updated.anonymous_read {
        match forge_db::authz_dao::delete_anonymous_read_grant(&mut *tx, updated.id).await {
            Ok(removed) => removed,
            Err(e) => return db_error(e),
        }
    } else {
        false
    };

    // Seal a new password.
    let sealed = match password {
        PasswordChange::Set(pw) => {
            if let Err(resp) =
                store_encrypted_password(&mut tx, &state.envelope, updated.id, pw).await
            {
                return resp;
            }
            true
        }
        PasswordChange::Keep | PasswordChange::Clear => false,
    };
    if let Err(e) = tx.commit().await {
        return db_error(e);
    }
    // Not only the anonymous principal reads through the anonymous role: a
    // user or workload assigned that role holds its grants too, cached under
    // its own key. Drop every cached set (as other grant mutations do).
    if anonymous_revoked {
        forge_core::authz::invalidate_all(&state.cache).await;
    }
    if credentials_dropped {
        tracing::warn!(
            repository = %updated.name,
            "remote_url moved to a different origin; the stored upstream username and \
             password were dropped (send a new upstream_password to keep credentials)"
        );
    }

    // Re-fetched so the view reflects the sealed secret.
    let updated = if sealed {
        match repository_dao::find_repository_by_id(&state.pool, updated.id).await {
            Ok(Some(r)) => r,
            Ok(None) => return db_error(sqlx::Error::RowNotFound),
            Err(e) => return db_error(e),
        }
    } else {
        updated
    };
    match view(&state, &updated).await {
        Ok(repo) => Json(UpdatedRepoView {
            repo,
            upstream_credentials_dropped: credentials_dropped,
        })
        .into_response(),
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/repositories/{name}`
///
/// A raw cascade would drop a repository's `component`/`asset` rows via FK while
/// leaving the referenced `blob` ref-counts inflated and their S3 objects
/// unreclaimable. Both hosted *and* proxy repositories accumulate
/// component/asset/blob rows (a proxy persists them when it caches a package
/// downloaded from upstream — see `forge_core::repo::proxy`), so the blob
/// ref-counts must be decremented before the repository is removed regardless of
/// kind.
///
/// - **Hosted** repos refuse deletion while they still own components — the
///   admin must hard-delete its packages first (an explicit, auditable step,
///   since hosted content is uploaded and not reproducible).
/// - **Proxy** repos hold only a reconstructible upstream cache, so deletion
///   transactionally decrefs every referenced blob (enqueuing outbox deletes at
///   zero refs) and removes the components before dropping the repository.
///
/// The emptiness check (hosted) or purge (proxy) and the delete run in **one**
/// transaction that first locks the repository row `FOR UPDATE`
/// ([`repository_dao::lock_repository`]). That lock conflicts with the
/// `FOR KEY SHARE` lock a concurrent component insert takes for its foreign
/// key, so a publish or cache fill cannot commit in between and be
/// cascade-deleted without its blob decrement; an overlapping delete of the
/// same repository waits and then answers 404 without decrementing again.
///
/// A repository flagged as an owner member of a group is refused (**409**)
/// until it is unflagged. Its memberships are locked in the same transaction
/// ([`repository_dao::lock_memberships_for_delete`]), so a flag set
/// concurrently cannot be cascaded away unseen.
pub async fn delete(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let existing = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return db_error(e),
    };
    let grace = state.config.outbox.grace();
    match delete_repository_locked(&state, existing.id, existing.kind(), grace).await {
        Ok(RepoDelete::Deleted) => StatusCode::NO_CONTENT.into_response(),
        Ok(RepoDelete::NotFound) => (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Ok(RepoDelete::HasPackages) if state.formats.stores_images(&existing.format) => (
            StatusCode::CONFLICT,
            "repository still has images; delete them first (DELETE /admin/repositories/<name>/images?image=<image>)",
        )
            .into_response(),
        Ok(RepoDelete::HasPackages) if state.formats.stores_files(&existing.format) => (
            StatusCode::CONFLICT,
            "repository still has files; delete them first (DELETE /admin/repositories/<name>/files?path=)",
        )
            .into_response(),
        Ok(RepoDelete::HasPackages) => (
            StatusCode::CONFLICT,
            "repository still has packages; hard-delete them first",
        )
            .into_response(),
        Ok(RepoDelete::OwnsGroups(groups)) => (
            StatusCode::CONFLICT,
            format!(
                "repository owns the package ids of group(s) {}; unflag it as owner first",
                groups.join(", ")
            ),
        )
            .into_response(),
        Err(e) => db_error(e),
    }
}

/// Outcome of [`delete_repository_locked`].
enum RepoDelete {
    Deleted,
    NotFound,
    /// A hosted repository still owns components.
    HasPackages,
    /// The repository is flagged as an owner member of these groups:
    /// deleting it would silently return them to trusting every hosted
    /// member (see `admin::members`).
    OwnsGroups(Vec<String>),
}

/// Lock, check/purge and delete a repository in one transaction (see
/// [`delete`]).
async fn delete_repository_locked(
    state: &AppState,
    repo_id: i64,
    kind: RepoKind,
    grace: chrono::Duration,
) -> sqlx::Result<RepoDelete> {
    // A proxy delete locks its cached versions before the repository row,
    // the order a cache fill or retention eviction takes them in (see
    // `proxy_dao::lock_cached_versions`). A version a fill creates between
    // the two locks can still deadlock; Postgres then aborts one side. The
    // whole transaction rolled back, so retrying the delete is safe.
    let mut attempt = 0;
    loop {
        match delete_repository_once(state, repo_id, kind, grace).await {
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some("40P01") && attempt < 3 =>
            {
                attempt += 1;
                tracing::warn!(repo_id, attempt, "repository delete deadlocked; retrying");
            }
            other => return other,
        }
    }
}

async fn delete_repository_once(
    state: &AppState,
    repo_id: i64,
    kind: RepoKind,
    grace: chrono::Duration,
) -> sqlx::Result<RepoDelete> {
    let mut tx = state.pool.begin().await?;
    if kind != RepoKind::Hosted {
        // Before the repository row: an in-flight first download holds its
        // cached version and then needs the repository row.
        forge_db::proxy_dao::lock_cached_versions(&mut *tx, repo_id).await?;
    }
    if !repository_dao::lock_repository(&mut *tx, repo_id).await? {
        return Ok(RepoDelete::NotFound);
    }
    let owned = repository_dao::lock_memberships_for_delete(&mut *tx, repo_id).await?;
    if !owned.is_empty() {
        return Ok(RepoDelete::OwnsGroups(owned));
    }

    if kind == RepoKind::Hosted {
        // Hosted repos may still own (non-reproducible) components or image
        // manifests; require them gone first so the deletion is an explicit
        // admin action.
        if component_dao::repository_has_components(&mut *tx, repo_id).await?
            || oci_dao::repository_has_images(&mut *tx, repo_id).await?
            || raw_dao::repository_has_files(&mut *tx, repo_id).await?
        {
            return Ok(RepoDelete::HasPackages);
        }
    } else {
        // Proxy (and any non-hosted) repos: decref every blob referenced by the
        // repo's cached components so blob GC stays correct, and remove them
        // before the cascade could drop them unaccounted.
        component_dao::hard_delete_all_components(&mut tx, repo_id, grace).await?;
    }
    // Image rows (a proxy's cache; a hosted repository's leftover blobs and
    // upload sessions) and a raw proxy's files release their blob references
    // before the cascade.
    oci_dao::purge_repository(&mut tx, repo_id, grace).await?;
    raw_dao::purge_repository(&mut tx, repo_id, grace).await?;

    let deleted = repository_dao::delete_repository(&mut *tx, repo_id).await?;
    tx.commit().await?;
    Ok(if deleted {
        RepoDelete::Deleted
    } else {
        RepoDelete::NotFound
    })
}

/// `DELETE /admin/repositories/{name}/packages/{id}/{version}` — **hard delete**:
/// remove the component + its assets and decrement the referenced blobs'
/// ref-counts (enqueuing outbox deletes at zero) in one transaction.
pub async fn hard_delete_package(
    State(state): State<AppState>,
    Path((name, id, version)): Path<(String, String, String)>,
) -> Response {
    let repo = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return db_error(e),
    };
    if repo.kind() != RepoKind::Hosted {
        return (
            StatusCode::BAD_REQUEST,
            "hard delete is only supported for hosted repositories",
        )
            .into_response();
    }
    if state.formats.stores_images(&repo.format) {
        return (
            StatusCode::BAD_REQUEST,
            "delete images, manifests and tags through DELETE /admin/repositories/<name>/images?image=<image>&reference=<tag|digest>",
        )
            .into_response();
    }
    if state.formats.stores_files(&repo.format) {
        return (
            StatusCode::BAD_REQUEST,
            "delete files through DELETE /admin/repositories/<name>/files?path=<path>",
        )
            .into_response();
    }

    let format = match state.formats.for_repository(&repo) {
        Ok(format) => format,
        Err(e) => return super::format_unavailable(e),
    };
    let lower = format.lower_id(&id);
    let norm_ver = match format.normalize_version(&version) {
        Ok(v) => v,
        Err(_) => return (StatusCode::NOT_FOUND, "package not found").into_response(),
    };

    let grace = state.config.outbox.grace();
    match hard_delete(&state, repo.id, &lower, &norm_ver, grace).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "package not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// Transactionally remove a component, its assets, and decref each referenced
/// blob (enqueuing an outbox delete when a blob reaches zero refs) through
/// [`component_dao::hard_delete_component`], which locks the component row
/// first and decrements only the references it actually deleted — so two
/// overlapping hard deletes of one version decrement once (the loser gets
/// `false` → 404).
async fn hard_delete(
    state: &AppState,
    repo_id: i64,
    lower_id: &str,
    version: &str,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let mut tx = state.pool.begin().await?;
    let deleted =
        component_dao::hard_delete_component(&mut tx, repo_id, lower_id, version, grace).await?;
    tx.commit().await?;
    Ok(deleted)
}

/// Whether a `sqlx::Error` is a Postgres unique-violation (23505).
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_name_error_reads_as_one_sentence() {
        let msg = validate_repo_name("bad name").unwrap_err();
        assert!(!msg.contains("  "), "{msg}");
        assert!(msg.contains("characters from A-Z"), "{msg}");
        assert!(validate_repo_name("nuget-hosted.v3_x").is_ok());
    }
}
