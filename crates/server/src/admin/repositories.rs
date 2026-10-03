//! Admin repository CRUD + package hard-delete (plan 10.4, A12).
//!
//! `upstream_password` is **write-only**: accepted on create/update, never
//! returned (responses carry a [`RepoView`] with no password field). The update
//! body's field semantics (absent = keep, `null` = clear, value = set) and the
//! credential drop on an origin change are documented on [`UpdateRepo`].
//!
//! `remote_url` on a proxy is **scheme-validated** at create/update time
//! (http/https only — 12.7 §3.6 dropped the private-range restriction) so a bad
//! upstream is rejected before any fetch. The configured host is logged on save
//! for operator visibility (the URL may point at internal addresses).
//!
//! Repository **names** are URL path segments (`/v3/{name}/…`, the SPA's
//! `/repositories/{name}`), so they are validated on create and rename (see
//! [`validate_repo_name`]).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::net::ssrf::validate_url;
use forge_db::component_dao;
use forge_db::model::{RepoKind, Repository, PREFER_HOSTED_KEY, RESERVED_PREFIXES_KEY};
use forge_db::repository_dao::{self, NewRepository, RepositoryUpdate};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::db_error;
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
}

impl From<&Repository> for RepoView {
    fn from(r: &Repository) -> Self {
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
            // §12.5: true for an encrypted blob OR a (pre-backfill) plaintext.
            has_upstream_password: r.has_upstream_password(),
            metadata_ttl_seconds: r.metadata_ttl_seconds,
            not_found_ttl_seconds: r.not_found_ttl_seconds,
            allow_redeploy: r.allow_redeploy,
            prefer_hosted: r.prefer_hosted(),
            reserved_prefixes: r.reserved_prefixes(),
        }
    }
}

/// Create-repository request body.
#[derive(Debug, Deserialize)]
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
///   set.** A cleared TTL falls back to the server default. Clearing the
///   password removes both the plaintext column and the encrypted blob.
/// * **Origin change.** When `remote_url` moves to a different origin (scheme,
///   host and port) and the request does not set a new `upstream_password`,
///   the stored `upstream_username` and password are dropped, so a private
///   feed's credentials are never sent to the new host. (A username sent in
///   the same request is still applied.) The response then carries
///   `"upstream_credentials_dropped": true` and a warning is logged.
/// * With secret encryption enabled the plaintext `upstream_password` column
///   is always left `NULL` by an update: a new password is sealed, and a kept
///   legacy plaintext value is sealed in the same transaction.
/// * Turning `anonymous_read` off also deletes the anonymous role's unscoped
///   `read` grant on the repository (the grant migration 0007 synthesized from
///   the flag), so anonymous access really ends.
#[derive(Debug, Deserialize)]
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

/// Deserialize a field that distinguishes *absent* (`None`, through
/// `#[serde(default)]`) from JSON `null` (`Some(None)`) and a value
/// (`Some(Some(v))`).
fn double_option<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}

/// The longest accepted repository name.
const MAX_REPO_NAME_LEN: usize = 64;

/// Validate a repository name: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, and not
/// `new` (any case), which the SPA uses as its "create repository" route.
///
/// The name is a URL path segment (`/v3/{name}/…`); a name with a space, `%`
/// or `/` is stored fine but can never be reached as a feed.
fn validate_repo_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = name.len() <= MAX_REPO_NAME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid {
        return Err(format!(
            "invalid repository name {name:?}: use 1-{MAX_REPO_NAME_LEN} characters from              A-Z, a-z, 0-9, '.', '_' and '-', starting with a letter or digit              (the name is part of the feed URL)"
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
    "nuget".into()
}
fn default_true() -> bool {
    true
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

/// Scheme-validate a proxy `remote_url` (http/https only). `None` is OK at this
/// layer (proxy-without-url is rejected separately). Logs the configured host
/// (12.7 §3.6: the URL may legitimately point at internal addresses; the log
/// line gives operators an audit trail of where forge was pointed).
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

/// Validate and normalize a group's reserved id prefixes: each is a NuGet id
/// prefix (`A-Z a-z 0-9 . _ -`, at most 100 bytes, an optional trailing `*`
/// dropped), stored lowercase, deduplicated.
fn normalize_prefixes(raw: &[String]) -> Result<Vec<String>, String> {
    if raw.len() > MAX_RESERVED_PREFIXES {
        return Err(format!(
            "at most {MAX_RESERVED_PREFIXES} reserved_prefixes are allowed"
        ));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for prefix in raw {
        let prefix = prefix.trim();
        let prefix = prefix.strip_suffix('*').unwrap_or(prefix);
        let valid = !prefix.is_empty()
            && prefix.len() <= 100
            && prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !valid {
            return Err(format!(
                "reserved_prefixes: {prefix:?} is not a package id prefix (letters, digits, '.', '_', '-')"
            ));
        }
        let prefix = prefix.to_ascii_lowercase();
        if !out.contains(&prefix) {
            out.push(prefix);
        }
    }
    Ok(out)
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
            let views: Vec<RepoView> = repos.iter().map(RepoView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `GET /admin/repositories/{name}`
pub async fn get(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => Json(RepoView::from(&r)).into_response(),
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
    // Only NuGet is implemented; any other value would silently behave as
    // NuGet (the format registry has a single module).
    if body.format != "nuget" {
        return bad_request(format!(
            "unsupported format {:?}: only \"nuget\" is available",
            body.format
        ));
    }
    let parsed_kind = RepoKind::from(kind.as_str());

    // Proxy must carry a remote_url; SSRF-validate it. Non-proxies must not.
    if parsed_kind == RepoKind::Proxy {
        let Some(url) = body.remote_url.as_deref() else {
            return bad_request("proxy repository requires remote_url");
        };
        if let Err(resp) = validate_remote_url(url) {
            return resp;
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
    let reserved_prefixes = match body.reserved_prefixes.as_deref().map(normalize_prefixes) {
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
    let mut config = json!({});
    if parsed_kind == RepoKind::Group {
        config[PREFER_HOSTED_KEY] = json!(body.prefer_hosted.unwrap_or(true));
        if let Some(prefixes) = reserved_prefixes {
            config[RESERVED_PREFIXES_KEY] = json!(prefixes);
        }
    }

    // §12.5: with encryption enabled the password is NOT inserted as plaintext;
    // the row is created first (the AAD binds the ciphertext to the row id,
    // which does not exist before the INSERT) and the secret is sealed below.
    let encrypting = state.envelope.is_some();
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
        upstream_password: if encrypting {
            None
        } else {
            body.upstream_password.clone()
        },
        metadata_ttl_seconds: body.metadata_ttl_seconds,
        not_found_ttl_seconds: body.not_found_ttl_seconds,
        allow_redeploy: body.allow_redeploy,
    };

    // The row and its sealed secret commit together: a failed seal must not
    // leave a half-created repository whose retry then answers 409.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return db_error(e),
    };
    let repo = match repository_dao::insert_repository(&mut *tx, new).await {
        Ok(r) => r,
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "repository name already exists").into_response()
        }
        Err(e) => return db_error(e),
    };
    let sealed = match (&state.envelope, &body.upstream_password) {
        (Some(envelope), Some(pw)) => {
            if let Err(resp) =
                store_encrypted_password(&mut tx, envelope, repo.id, pw.clone()).await
            {
                return resp;
            }
            true
        }
        _ => false,
    };
    if let Err(e) = tx.commit().await {
        return db_error(e);
    }
    if !sealed {
        return (StatusCode::CREATED, Json(RepoView::from(&repo))).into_response();
    }
    // Re-fetch so the view reflects the sealed secret.
    match repository_dao::find_repository_by_id(&state.pool, repo.id).await {
        Ok(Some(r)) => (StatusCode::CREATED, Json(RepoView::from(&r))).into_response(),
        Ok(None) => db_error(sqlx::Error::RowNotFound),
        Err(e) => db_error(e),
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
    forge_db::secret_dao::set_upstream_password(&mut **tx, envelope, repo_id, Some(&secret))
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
            }
        }
    }

    let mut config = existing.config.clone();
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
        let prefixes = match normalize_prefixes(prefixes) {
            Ok(prefixes) => prefixes,
            Err(msg) => return bad_request(&msg),
        };
        if !config.is_object() {
            config = json!({});
        }
        config[RESERVED_PREFIXES_KEY] = json!(prefixes);
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
    // The plaintext column value, and whether the sealed blob is cleared too.
    // §12.5: with encryption enabled the plaintext column is always NULL after
    // an update — a new password is sealed below, and a kept legacy plaintext
    // value is sealed as well (it is not carried forward).
    let (upstream_password, clear_upstream_password_enc) = match (&state.envelope, &password) {
        (Some(_), PasswordChange::Clear) => (None, true),
        (Some(_), _) => (None, false),
        (None, PasswordChange::Keep) => (existing.upstream_password.clone(), false),
        (None, PasswordChange::Clear) => (None, true),
        // A stale sealed blob would shadow the new plaintext password.
        (None, PasswordChange::Set(pw)) => (Some(pw.clone()), true),
    };

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
        upstream_password,
        clear_upstream_password_enc,
        metadata_ttl_seconds: body
            .metadata_ttl_seconds
            .unwrap_or(existing.metadata_ttl_seconds),
        not_found_ttl_seconds: body
            .not_found_ttl_seconds
            .unwrap_or(existing.not_found_ttl_seconds),
        allow_redeploy: body.allow_redeploy.unwrap_or(existing.allow_redeploy),
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
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "repository name already exists").into_response()
        }
        Err(e) => return db_error(e),
    };

    // M20: the seam honours `anonymous_read` *and* the anonymous role's grants,
    // so switching the flag off must also remove the grant migration 0007
    // synthesized from it, or the repository stays anonymously readable.
    let anonymous_revoked = if existing.anonymous_read && !updated.anonymous_read {
        match forge_db::authz_dao::delete_anonymous_read_grant(&mut *tx, updated.id).await {
            Ok(removed) => removed,
            Err(e) => return db_error(e),
        }
    } else {
        false
    };

    // §12.5: seal a new password through the envelope, or re-seal a kept
    // legacy plaintext one (the update above nulled its column).
    let to_seal = match (&state.envelope, password) {
        (Some(envelope), PasswordChange::Set(pw)) => Some((envelope, pw)),
        (Some(envelope), PasswordChange::Keep) if existing.upstream_password_enc.is_none() => {
            existing.upstream_password.clone().map(|pw| (envelope, pw))
        }
        _ => None,
    };
    let sealed = to_seal.is_some();
    if let Some((envelope, pw)) = to_seal {
        if let Err(resp) = store_encrypted_password(&mut tx, envelope, updated.id, pw).await {
            return resp;
        }
    }
    if let Err(e) = tx.commit().await {
        return db_error(e);
    }
    if anonymous_revoked {
        forge_core::authz::invalidate_anonymous(&state.cache).await;
    }
    if credentials_dropped {
        tracing::warn!(
            repository = %updated.name,
            "remote_url moved to a different origin; the stored upstream username and \
             password were dropped (send a new upstream_password to keep credentials)"
        );
    }

    let respond = |r: &Repository| {
        Json(UpdatedRepoView {
            repo: RepoView::from(r),
            upstream_credentials_dropped: credentials_dropped,
        })
        .into_response()
    };
    if !sealed {
        return respond(&updated);
    }
    match repository_dao::find_repository_by_id(&state.pool, updated.id).await {
        Ok(Some(r)) => respond(&r),
        Ok(None) => db_error(sqlx::Error::RowNotFound),
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
        Ok(RepoDelete::HasPackages) => (
            StatusCode::CONFLICT,
            "repository still has packages; hard-delete them first",
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
}

/// Lock, check/purge and delete a repository in one transaction (see
/// [`delete`]).
async fn delete_repository_locked(
    state: &AppState,
    repo_id: i64,
    kind: RepoKind,
    grace: chrono::Duration,
) -> sqlx::Result<RepoDelete> {
    // A proxy delete locks the repository row before its cached versions,
    // while a concurrent cache fill or retention eviction holds a cached
    // version and then needs the repository row: Postgres resolves that
    // deadlock by aborting one side. The whole transaction rolled back, so
    // retrying the delete is safe.
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
    if !repository_dao::lock_repository(&mut *tx, repo_id).await? {
        return Ok(RepoDelete::NotFound);
    }

    if kind == RepoKind::Hosted {
        // Hosted repos may still own (non-reproducible) components; require them
        // gone first so the deletion is an explicit admin action.
        if component_dao::repository_has_components(&mut *tx, repo_id).await? {
            return Ok(RepoDelete::HasPackages);
        }
    } else {
        // Proxy (and any non-hosted) repos: decref every blob referenced by the
        // repo's cached components so blob GC stays correct, and remove them
        // before the cascade could drop them unaccounted.
        component_dao::hard_delete_all_components(&mut tx, repo_id, grace).await?;
    }

    let deleted = repository_dao::delete_repository(&mut *tx, repo_id).await?;
    tx.commit().await?;
    Ok(if deleted {
        RepoDelete::Deleted
    } else {
        RepoDelete::NotFound
    })
}

/// `DELETE /admin/repositories/{name}/packages/{id}/{version}` — **hard delete**
/// (A12): remove the component + its assets and decrement the referenced blobs'
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

    let format = state.formats.for_repository(&repo);
    let lower = format.lower_id(&id);
    let norm_ver = match format.normalize_version(&version) {
        Ok(v) => v,
        Err(_) => return (StatusCode::NOT_FOUND, "package not found").into_response(),
    };

    let grace = state.config.outbox.grace();
    match hard_delete(&state, repo.id, &lower, &norm_ver, grace).await {
        Ok(true) => {
            state
                .cache
                .invalidate(crate::state::NS_PACKAGE, &format!("{}/{lower}", repo.name))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
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
