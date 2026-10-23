//! Invalidating what a proxy repository cached from its upstream.
//!
//! * `POST /admin/repositories/{name}/proxy-cache/invalidate` — makes the
//!   proxy ask its upstream again instead of answering from what it learned.
//!   An optional body `{"package": "<id>"}` (a docker proxy: an image name)
//!   limits the not-found answers and tags it forgets to that package (a
//!   raw proxy: a file, or with a trailing `/` a directory). Answers
//!   [`Invalidated`].
//!
//! What is forgotten:
//! * the upstream's "not found" answers, of the package or of every package,
//!   which are otherwise honored for `not_found_ttl_seconds`;
//! * every listing, document and verdict cached from the upstream (a
//!   rejected package, a failed search, a docker "not found"), for the whole
//!   repository and on every instance: those are keyed by the repository's
//!   `updated_at`, which this bumps. Each package's listing is therefore
//!   fetched again on its next request, as when the metadata TTL lapses;
//! * a whole-repository invalidation also makes the upstream index (NuGet's
//!   service index) due for a refresh. The previous index stays the fallback
//!   while the upstream is unreachable;
//! * a docker proxy's cached tags are re-validated on their next pull;
//! * a raw proxy's cached files are re-validated on their next download.
//!
//! What stays: downloaded packages, blobs and digest-addressed manifests
//! (removing those is retention's job), the versions the upstream listed and
//! their package-delay clock.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_db::model::RepoKind;
use forge_db::{oci_dao, proxy_dao, raw_dao, repository_dao};
use serde::{Deserialize, Serialize};

use super::{db_error, format_unavailable};
use crate::state::AppState;

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "repository not found").into_response()
}

/// Optional body of `POST …/proxy-cache/invalidate`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidateBody {
    /// The package id (a docker proxy: the image name) whose not-found
    /// answers and tags are forgotten. Absent: every package's.
    #[serde(default)]
    pub package: Option<String>,
}

/// What an invalidation removed.
#[derive(Debug, Serialize)]
pub struct Invalidated {
    /// Not-found answers removed (NuGet and Helm proxies; a docker proxy
    /// keeps its own in memory, forgotten too but not counted).
    pub not_found_cleared: u64,
    /// Tags due for re-validation (docker proxies).
    pub tags_expired: u64,
    /// Cached files due for re-validation (raw proxies).
    pub files_expired: u64,
}

/// `POST /admin/repositories/{name}/proxy-cache/invalidate`
pub async fn invalidate(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Option<Json<InvalidateBody>>,
) -> Response {
    let repo = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => return db_error(e),
    };
    if repo.kind() != RepoKind::Proxy {
        return bad_request("only a proxy repository caches what an upstream answered");
    }
    let docker = repo.is_docker();

    // The package as the proxy stores it: a docker image under Docker Hub's
    // `library/` spelling, any other id lowercased.
    let package = match body.and_then(|b| b.0.package) {
        None => None,
        Some(p) if repo.is_raw() => {
            let normalized = if p.ends_with('/') {
                crate::raw::path::normalize_directory(&p)
            } else {
                crate::raw::path::normalize(&p)
            };
            match normalized {
                Ok(path) => Some(path),
                Err(e) => return bad_request(format!("package: {e}")),
            }
        }
        Some(p) if docker => {
            if !forge_oci::reference::valid_name(&p) {
                return bad_request("package is not a valid image name");
            }
            Some(forge_oci::proxied_image(&repo, &p))
        }
        Some(p) => {
            let format = match state.formats.for_repository(&repo) {
                Ok(format) => format,
                Err(e) => return format_unavailable(e),
            };
            let lower = format.lower_id(&p);
            if format.validate_id(&lower).is_err() {
                return bad_request("package is not a valid package id");
            }
            Some(lower)
        }
    };

    match forget(&state, &repo, docker, package.as_deref()).await {
        Ok(Some(invalidated)) => {
            tracing::info!(
                repository = %repo.name,
                package = package.as_deref().unwrap_or("*"),
                not_found_cleared = invalidated.not_found_cleared,
                tags_expired = invalidated.tags_expired,
                files_expired = invalidated.files_expired,
                "proxy cache invalidated"
            );
            Json(invalidated).into_response()
        }
        Ok(None) => not_found(),
        Err(e) => db_error(e),
    }
}

/// The invalidation's writes, in one transaction: the cached-version rows
/// before the repository row, the order a repository delete takes them in.
/// `None` when the repository was deleted meanwhile.
async fn forget(
    state: &AppState,
    repo: &forge_db::model::Repository,
    docker: bool,
    package: Option<&str>,
) -> sqlx::Result<Option<Invalidated>> {
    let mut tx = state.pool.begin().await?;
    let mut invalidated = Invalidated {
        not_found_cleared: 0,
        tags_expired: 0,
        files_expired: 0,
    };
    if repo.is_raw() {
        // A file is the range of its own path; a directory, of its files.
        let prefix = package.unwrap_or("");
        invalidated.files_expired = if prefix.is_empty() || prefix.ends_with('/') {
            raw_dao::expire_checks(&mut *tx, repo.id, prefix).await?
        } else {
            raw_dao::expire_file_check(&mut *tx, repo.id, prefix).await?
        };
    } else if docker {
        invalidated.tags_expired = oci_dao::expire_tags(&mut tx, repo.id, package).await?;
    } else {
        invalidated.not_found_cleared =
            proxy_dao::clear_not_found(&mut tx, repo.id, package).await?;
        if package.is_none() {
            proxy_dao::expire_upstream_index(&mut tx, repo.id).await?;
        }
    }
    if !repository_dao::touch_repository(&mut *tx, repo.id).await? {
        return Ok(None);
    }
    tx.commit().await?;
    Ok(Some(invalidated))
}
