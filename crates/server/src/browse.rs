//! Read-side browse / search API (plan §12.6 Phase 0, §8).
//!
//! These endpoints back the SPA's browse + package-detail screens with plain
//! JSON DTOs (not the NuGet V3 protocol shapes). They are **additive** and reuse
//! the existing slice-1 read path:
//!
//! * authorization is the slice-1 [`can_read`] predicate (anonymous allowed iff
//!   `repository.anonymous_read`), evaluated against the request's
//!   [`Principal`];
//! * version visibility, group member resolution, listed/prerelease filtering,
//!   and proxy **package-delay** gating all come for free from
//!   [`AppState::read_ops_for`] + [`RepoReadOps`] — the same ops the `/v3/*`
//!   dispatcher uses, so browse can never surface a version the protocol would
//!   hide.
//!
//! ## Endpoints
//! * `GET /browse/packages` — cross-repository search, paginated
//!   (`q`, `repo`, `prerelease`, `skip`, `take`) → `{ total, items }`.
//! * `GET /browse/packages/{repo}/{id}` — package detail: visible versions with
//!   per-version metadata + dependency groups parsed from the stored `.nuspec`.
//!
//! ## Download stats
//! Slice 1 has **no** download counters in its schema (`component` has no
//! `downloads` column and there is no counter table). The plan's
//! `total_downloads` / `downloads` fields are therefore **omitted** rather than
//! emitted as misleading zeros, and the `/stats` split is not implemented. The
//! DTOs keep room for them to be added without breaking the SPA. `published_at`
//! maps to `component.created_at` (plan assumption (b)).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Duration, Utc};
use forge_core::auth::authz::can_read;
use forge_core::auth::principal::Principal;
use forge_core::repo::SearchParams;
use forge_db::model::{RepoKind, Repository};
use forge_db::{asset_dao, component_dao, repository_dao};
use serde::{Deserialize, Serialize};

use crate::admin::db_error;
use crate::middleware::principal_of;
use crate::state::AppState;

/// Canonical asset path of the stored `.nupkg` (mirrors
/// `forge_core::repo::NUPKG_ASSET_PATH`).
const NUPKG_ASSET_PATH: &str = "package.nupkg";

/// Hard cap on the cross-repo browse page size.
const MAX_TAKE: usize = 100;
/// Default browse page size.
const DEFAULT_TAKE: usize = 20;

/// Query parameters for `GET /browse/packages`.
#[derive(Debug, Deserialize)]
pub struct BrowseQuery {
    /// Free-text query (matches package id substrings). Empty matches all.
    #[serde(default)]
    pub q: String,
    /// Optional exact repository-name filter.
    #[serde(default)]
    pub repo: Option<String>,
    /// Include prerelease versions in the "latest version" computation.
    #[serde(default)]
    pub prerelease: bool,
    /// Pagination offset over the merged, sorted result set.
    #[serde(default)]
    pub skip: usize,
    /// Page size (clamped to `[1, MAX_TAKE]`; 0 ⇒ default).
    #[serde(default)]
    pub take: usize,
}

impl BrowseQuery {
    fn effective_take(&self) -> usize {
        match self.take {
            0 => DEFAULT_TAKE,
            n => n.min(MAX_TAKE),
        }
    }
}

/// One cross-repository search hit.
#[derive(Debug, Serialize)]
pub struct BrowseItem {
    /// Repository the package lives in.
    pub repo: String,
    /// Repository kind (`hosted` | `proxy` | `group`).
    pub repo_kind: String,
    /// Lowercased package id (the search/normalize key).
    pub id: String,
    /// Package id with its original casing.
    pub original_id: String,
    /// Highest-precedence visible version.
    pub latest_version: String,
    /// Whether the latest version is listed (always true for search hits, kept
    /// for forward-compatibility with unlisted-aware browse).
    pub listed: bool,
}

/// `GET /browse/packages` response.
#[derive(Debug, Serialize)]
pub struct BrowseResult {
    /// Total hits across all visible repositories (pre-paging).
    pub total: usize,
    /// The requested page.
    pub items: Vec<BrowseItem>,
}

/// `GET /browse/packages` — cross-repository search.
///
/// Iterates every repository the principal may read (honoring
/// `anonymous_read`), runs the slice-1 [`RepoReadOps::search`] on each, merges
/// the hits, then sorts + paginates the merged set. A `repo` filter restricts to
/// a single repository.
pub async fn search_packages(
    State(state): State<AppState>,
    Query(query): Query<BrowseQuery>,
    req: axum::extract::Request,
) -> Response {
    let principal = principal_of(&req);

    let repos = match repository_dao::list_repositories(&state.pool).await {
        Ok(r) => r,
        Err(e) => return db_error(e),
    };

    // Per-repo search is bounded so a single huge repo can't starve the merge;
    // we request enough to fill the requested window (`skip + take`, always ≥ 1
    // because `effective_take()` is ≥ 1), capped at the read ops' own MAX_TAKE.
    let want = query.skip.saturating_add(query.effective_take());
    let per_repo_take = want.min(forge_core::repo::SearchParams::MAX_TAKE);

    let mut all: Vec<BrowseItem> = Vec::new();
    for repo in &repos {
        if let Some(filter) = &query.repo {
            if &repo.name != filter {
                continue;
            }
        }
        if !can_read(&principal, repo).await {
            continue;
        }
        let ops = match state.read_ops_for(repo, principal) {
            Ok(o) => o,
            // A misconfigured repo (e.g. nested group) is skipped, not fatal.
            Err(_) => continue,
        };
        let params = SearchParams {
            q: query.q.clone(),
            skip: 0,
            take: per_repo_take,
            prerelease: query.prerelease,
        };
        match ops.search(&repo.name, &params).await {
            Ok(result) => {
                for hit in result.hits {
                    all.push(BrowseItem {
                        repo: repo.name.clone(),
                        repo_kind: repo.kind.clone(),
                        id: hit.original_id.to_ascii_lowercase(),
                        original_id: hit.original_id,
                        latest_version: hit.latest_version,
                        listed: true,
                    });
                }
            }
            // Skip a repo whose backend read failed (e.g. an offline proxy with
            // no cached index) rather than failing the whole browse.
            Err(_) => continue,
        }
    }

    // Stable global ordering: by id, then repo.
    all.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.repo.cmp(&b.repo)));
    let total = all.len();
    let items = all
        .into_iter()
        .skip(query.skip)
        .take(query.effective_take())
        .collect();
    Json(BrowseResult { total, items }).into_response()
}

/// Delay status of a proxy version on the detail view.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelayStatus {
    /// Past the package-delay window (or not a proxy): downloadable.
    Available,
    /// Discovered upstream but still inside the package-delay window.
    DelayedUntil,
}

/// One version on the package-detail view.
#[derive(Debug, Serialize)]
pub struct DetailVersion {
    /// Normalized version.
    pub version: String,
    /// Version as originally published.
    pub version_original: String,
    /// Whether the version is listed.
    pub listed: bool,
    /// `.nupkg` byte size, if a stored asset is known (None for not-yet-cached
    /// proxy versions or group-resolved versions).
    pub size: Option<i64>,
    /// Publish/first-seen time (`component.created_at`), if known.
    pub published_at: Option<DateTime<Utc>>,
    /// Proxy package-delay status (`null` for hosted/group versions).
    pub delay_status: Option<DelayStatus>,
    /// When a delayed proxy version becomes available (`first_seen_at + delay`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delayed_until: Option<DateTime<Utc>>,
    /// Retention status — reserved for §12.1; always `null` in slice 1.
    pub retention_status: Option<String>,
}

/// One dependency within a dependency group.
#[derive(Debug, Serialize)]
pub struct DetailDependency {
    pub id: String,
    pub range: Option<String>,
}

/// A dependency group (per target framework) for one version.
#[derive(Debug, Serialize)]
pub struct DetailDependencyGroup {
    pub target_framework: Option<String>,
    pub dependencies: Vec<DetailDependency>,
}

/// `GET /browse/packages/{repo}/{id}` response.
#[derive(Debug, Serialize)]
pub struct PackageDetail {
    pub repo: String,
    pub repo_kind: String,
    pub id: String,
    pub original_id: String,
    pub versions: Vec<DetailVersion>,
    /// Dependency groups keyed by normalized version string.
    pub dependency_groups_by_version:
        std::collections::BTreeMap<String, Vec<DetailDependencyGroup>>,
}

/// `GET /browse/packages/{repo}/{id}` — package detail.
pub async fn package_detail(
    State(state): State<AppState>,
    Path((repo_name, id)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Response {
    let principal = principal_of(&req);

    let repo = match repository_dao::find_repository_by_name(&state.pool, &repo_name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return db_error(e),
    };

    // Slice-1 read authz: a denied caller is anonymous/unauthenticated → 401.
    if !can_read(&principal, &repo).await {
        return match principal {
            Principal::User { .. } => (StatusCode::FORBIDDEN, "forbidden").into_response(),
            _ => (StatusCode::UNAUTHORIZED, "authentication required").into_response(),
        };
    }

    let format = state.formats.for_repository(&repo);
    let lower = format.lower_id(&id);

    let ops = match state.read_ops_for(&repo, principal) {
        Ok(o) => o,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };

    // Visible versions (delay-gated + group-resolved by the read ops).
    let versions = match ops.list_versions(&repo.name, &lower).await {
        Ok(v) => v,
        Err(e) => return read_err(e),
    };

    // For a proxy, also gather versions discovered upstream that are still inside
    // the package-delay window. These are intentionally absent from
    // `list_versions` (which only returns downloadable versions); we surface them
    // so the UI can render a delay badge for content that exists but is not yet
    // downloadable. A package whose *only* versions are delayed is still a real
    // package, so we must not 404 it just because `versions` is empty.
    let is_proxy = repo.kind() == RepoKind::Proxy;
    let delayed = if is_proxy {
        match delayed_proxy_versions(&state, &repo, &lower).await {
            Ok(d) => d,
            Err(e) => return db_error(e),
        }
    } else {
        Vec::new()
    };

    if versions.is_empty() && delayed.is_empty() {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    }

    // Registration entries carry the stored `.nuspec` bytes (hosted) for deps.
    let registration = match ops.registration(&repo.name, &lower).await {
        Ok(r) => r,
        Err(e) => return read_err(e),
    };

    // Original-cased id from a visible version when there is one; for a
    // delayed-only proxy package we have no cached casing yet, so fall back to
    // the requested id.
    let original_id = versions
        .first()
        .map(|v| v.original_id.clone())
        .unwrap_or_else(|| id.clone());

    let mut dependency_groups_by_version = std::collections::BTreeMap::new();
    for entry in &registration {
        let groups = entry
            .nuspec_bytes
            .as_deref()
            .and_then(|b| forge_nuget::nuspec::dependency_groups_from_nuspec(b).ok())
            .unwrap_or_default();
        let mapped: Vec<DetailDependencyGroup> = groups
            .into_iter()
            .map(|g| DetailDependencyGroup {
                target_framework: g.target_framework,
                dependencies: g
                    .dependencies
                    .into_iter()
                    .map(|d| DetailDependency {
                        id: d.id,
                        range: d.range,
                    })
                    .collect(),
            })
            .collect();
        dependency_groups_by_version.insert(entry.version.clone(), mapped);
    }

    // Per-version size / published_at from the local component row when present.
    let mut detail_versions = Vec::with_capacity(versions.len() + delayed.len());
    for v in &versions {
        let (size, published_at) =
            match component_dao::find_component(&state.pool, repo.id, &lower, &v.version).await {
                Ok(Some(comp)) => {
                    let size = asset_dao::find_asset(&state.pool, comp.id, NUPKG_ASSET_PATH)
                        .await
                        .ok()
                        .flatten()
                        .map(|a| a.size);
                    (size, Some(comp.created_at))
                }
                _ => (None, None),
            };

        // A version returned by `list_versions` on a proxy has already cleared
        // the delay window (the ops gate it), so it is `Available`. We still
        // report `delay_status` for proxies so the UI can render the badge
        // distinctly from hosted/group.
        let delay_status = if is_proxy {
            Some(DelayStatus::Available)
        } else {
            None
        };

        detail_versions.push(DetailVersion {
            version: v.version.clone(),
            version_original: v.version_original.clone(),
            listed: v.listed,
            size,
            published_at,
            delay_status,
            delayed_until: None,
            retention_status: None,
        });
    }

    // Append the still-delayed proxy versions gathered above (with their ETA) so
    // the UI can render a delay badge alongside any downloadable versions.
    detail_versions.extend(delayed);

    Json(PackageDetail {
        repo: repo.name.clone(),
        repo_kind: repo.kind.clone(),
        id: lower,
        original_id,
        versions: detail_versions,
        dependency_groups_by_version,
    })
    .into_response()
}

/// Proxy versions still inside the package-delay window: discovered upstream but
/// not yet downloadable. Returned with `delay_status = delayed_until` and a
/// `delayed_until` ETA so the UI can render a delay badge.
async fn delayed_proxy_versions(
    state: &AppState,
    repo: &Repository,
    lower_id: &str,
) -> Result<Vec<DetailVersion>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT version, listed, first_seen_at
        FROM proxy_cached_version
        WHERE repository_id = $1 AND name = $2 AND version <> '*' AND not_found = false
        "#,
        repo.id,
        lower_id,
    )
    .fetch_all(&state.pool)
    .await?;

    let now = Utc::now();
    let delay = Duration::seconds(i64::from(repo.package_delay_seconds));
    let mut out = Vec::new();
    for row in rows {
        let available_at = row.first_seen_at + delay;
        if available_at <= now {
            // Already available — surfaced by `list_versions`, skip here.
            continue;
        }
        out.push(DetailVersion {
            version: row.version.clone(),
            version_original: row.version,
            listed: row.listed,
            size: None,
            published_at: Some(row.first_seen_at),
            delay_status: Some(DelayStatus::DelayedUntil),
            delayed_until: Some(available_at),
            retention_status: None,
        });
    }
    Ok(out)
}

/// Map a [`forge_core::repo::RepoError`] from the read path to an HTTP response.
fn read_err(e: forge_core::repo::RepoError) -> Response {
    use forge_core::repo::RepoError;
    match e {
        RepoError::RepoNotFound(_) => {
            (StatusCode::NOT_FOUND, "repository not found").into_response()
        }
        other => {
            tracing::error!(error = %other, "browse read error");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// Build the `/browse` router (mounted at the top level under the principal
/// middleware; per-repo `anonymous_read` is enforced inside each handler).
pub fn browse_router() -> Router<AppState> {
    Router::new()
        .route("/browse/packages", get(search_packages))
        .route("/browse/packages/{repo}/{id}", get(package_detail))
}
