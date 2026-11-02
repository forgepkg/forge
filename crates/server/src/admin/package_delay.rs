//! Releasing a version of a proxy repository from the package delay early.
//!
//! A proxy holds new upstream versions back for its package delay (the
//! repository's `package_delay_seconds`, or the delay of the first of its
//! `package_delay_overrides` that matches the package). An urgent version, a
//! security fix released today, can be let through without turning the delay
//! off for the whole proxy:
//!
//! * `POST /admin/repositories/{name}/packages/{id}/versions/{version}/release-delay`
//!   with `{"reason": "<why>"}` releases that version: it is served at once,
//!   while the package's other versions keep their delay. A version the proxy
//!   has not seen yet (not listed upstream so far) can be released too; the
//!   release then applies once the proxy sees it. Answers 201 with the
//!   [`ReleaseView`], or 200 with the existing one when the version was
//!   released already (the first release's reason stays).
//! * `DELETE` on the same path withdraws a release: the version waits out its
//!   delay again (204; 404 when it was not released).
//! * `GET /admin/repositories/{name}/delay-releases` lists the repository's
//!   releases, newest first.
//!
//! The reason is required. Every release and withdrawal is written to the
//! `forge::audit` log with the reason and the administrator, and the release
//! row keeps both (`released_by`, `released_at`).
//!
//! Repointing the proxy to another upstream forgets its releases: they were
//! decisions about the previous upstream's packages.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::Extension;
use chrono::{DateTime, Utc};
use forge_core::auth::principal::Principal;
use forge_db::delay_release_dao::{self, DelayRelease};
use forge_db::model::{RepoKind, Repository};
use forge_db::repository_dao;
use serde::{Deserialize, Serialize};

use super::{db_error, format_unavailable};
use crate::state::AppState;

/// Longest accepted release reason, in characters.
const MAX_REASON_CHARS: usize = 1000;

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

/// Body of `POST …/release-delay`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBody {
    /// Why the version is released early (required).
    pub reason: String,
}

/// A version released from the package delay early.
#[derive(Debug, Serialize)]
pub struct ReleaseView {
    /// The package id, lowercased as the proxy stores it.
    pub package: String,
    /// The normalized version.
    pub version: String,
    pub reason: String,
    /// The administrator who released it.
    pub released_by: String,
    pub released_at: DateTime<Utc>,
    /// Whether the proxy has seen the version upstream yet. A release of a
    /// version it has not seen applies once it does.
    pub seen: bool,
}

impl ReleaseView {
    fn new(release: DelayRelease, seen: bool) -> Self {
        ReleaseView {
            package: release.name,
            version: release.version,
            reason: release.reason,
            released_by: release.released_by,
            released_at: release.released_at,
            seen,
        }
    }
}

/// The proxy repository `name`, of a format with a package delay, or the
/// response refusing it.
async fn delayed_proxy(state: &AppState, name: &str) -> Result<Repository, Response> {
    let repo = match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "repository not found").into_response()),
        Err(e) => return Err(db_error(e)),
    };
    if repo.kind() != RepoKind::Proxy {
        return Err(bad_request(
            "only a proxy repository holds versions back for a package delay",
        ));
    }
    if let Some(what) = super::repositories::without_package_delay(state, &repo.format) {
        return Err(bad_request(format!("there is no package delay for {what}")));
    }
    Ok(repo)
}

/// The package id (lowercased) and the version (normalized) as `repo`'s
/// format stores them, or the 400 refusing them.
fn package_version(
    state: &AppState,
    repo: &Repository,
    id: &str,
    version: &str,
) -> Result<(String, String), Response> {
    let format = state
        .formats
        .for_repository(repo)
        .map_err(format_unavailable)?;
    let lower = format.lower_id(id.trim());
    if format.validate_id(&lower).is_err() {
        return Err(bad_request("not a valid package id"));
    }
    let normalized = format
        .normalize_version(version.trim())
        .map_err(|_| bad_request("not a valid version"))?;
    Ok((lower, normalized))
}

/// `POST /admin/repositories/{name}/packages/{id}/versions/{version}/release-delay`
pub async fn release(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((name, id, version)): Path<(String, String, String)>,
    Json(body): Json<ReleaseBody>,
) -> Response {
    let reason = body.reason.trim();
    if reason.is_empty() {
        return bad_request("a reason is required");
    }
    if reason.chars().count() > MAX_REASON_CHARS {
        return bad_request(format!(
            "the reason must be at most {MAX_REASON_CHARS} characters long"
        ));
    }
    let repo = match delayed_proxy(&state, &name).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    let (package, version) = match package_version(&state, &repo, &id, &version) {
        Ok(pv) => pv,
        Err(resp) => return resp,
    };
    let released_by = principal.audit_label();
    let (release, created) = match delay_release_dao::release(
        &state.pool,
        repo.id,
        &package,
        &version,
        reason,
        &released_by,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return db_error(e),
    };
    let seen = match delay_release_dao::seen(&state.pool, repo.id, &package, &version).await {
        Ok(seen) => seen,
        Err(e) => return db_error(e),
    };
    if created {
        tracing::info!(
            target: "forge::audit",
            repository = %repo.name,
            package = %package,
            version = %version,
            reason = %reason,
            seen,
            principal = %released_by,
            "version released from the package delay early"
        );
    }
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (status, Json(ReleaseView::new(release, seen))).into_response()
}

/// `DELETE /admin/repositories/{name}/packages/{id}/versions/{version}/release-delay`
pub async fn withdraw(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((name, id, version)): Path<(String, String, String)>,
) -> Response {
    let repo = match delayed_proxy(&state, &name).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    let (package, version) = match package_version(&state, &repo, &id, &version) {
        Ok(pv) => pv,
        Err(resp) => return resp,
    };
    match delay_release_dao::withdraw(&state.pool, repo.id, &package, &version).await {
        Ok(true) => {
            tracing::info!(
                target: "forge::audit",
                repository = %repo.name,
                package = %package,
                version = %version,
                principal = %principal.audit_label(),
                "early release from the package delay withdrawn"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "the version was not released early").into_response(),
        Err(e) => db_error(e),
    }
}

/// `GET /admin/repositories/{name}/delay-releases`
pub async fn list(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let repo = match delayed_proxy(&state, &name).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    match delay_release_dao::list_with_seen(&state.pool, repo.id).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|(release, seen)| ReleaseView::new(release, seen))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => db_error(e),
    }
}
