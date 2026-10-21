//! Browse API of docker repositories: the images of a repository and an
//! image's tags and manifests (digests, sizes, platforms), for the SPA.
//!
//! The same rules as the package browse apply: a signed-in user, per-repo
//! read authorization, and the caller's content selectors on image names. A
//! group lists what its members the caller may read hold, the highest
//! priority member first.
//!
//! ## Endpoints
//! * `GET /browse/images?repo=<name>&q=&skip=&take=` → `{ total, items,
//!   registry, pull_prefix }`.
//! * `GET /browse/images/{repo}/{*image}` → the image's tags and manifests,
//!   with the `docker pull` name.

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use forge_core::auth::principal::Principal;
use forge_db::model::{RepoKind, Repository};
use forge_db::{oci_dao, repository_dao};
use serde::{Deserialize, Serialize};

use crate::admin::db_error;
use crate::middleware::principal_of;
use crate::state::AppState;

/// Most images considered per repository when listing.
const MAX_IMAGES: i64 = 5000;
const DEFAULT_TAKE: usize = 50;
const MAX_TAKE: usize = 200;

#[derive(Debug, Deserialize)]
pub struct ImagesQuery {
    pub repo: String,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub skip: usize,
    #[serde(default)]
    pub take: usize,
}

/// One image of a repository listing.
#[derive(Debug, Serialize)]
pub struct ImageItem {
    pub image: String,
    pub tag_count: i64,
    pub manifest_count: i64,
    pub last_pushed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ImagesResult {
    pub total: usize,
    pub items: Vec<ImageItem>,
    /// The registry host clients log in to (`docker login <registry>`).
    pub registry: String,
    /// What image names are prefixed with: `<registry>/<repo>`, or the
    /// repository's own host.
    pub pull_prefix: String,
}

/// A tag of an image.
#[derive(Debug, Serialize)]
pub struct TagItem {
    pub tag: String,
    pub digest: String,
    pub media_type: String,
    /// Compressed size of the image's layers (for an index: of every
    /// platform's image Forge holds).
    pub size: Option<i64>,
    pub platforms: Vec<String>,
}

/// A manifest of an image.
#[derive(Debug, Serialize)]
pub struct ManifestItem {
    pub digest: String,
    pub media_type: String,
    pub artifact_type: Option<String>,
    pub subject_digest: Option<String>,
    /// The manifest's own size.
    pub manifest_size: i64,
    /// See [`TagItem::size`].
    pub size: Option<i64>,
    pub platforms: Vec<String>,
    pub tags: Vec<String>,
    /// An index's child manifests.
    pub children: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_pulled_at: Option<DateTime<Utc>>,
    /// The member repository it comes from (groups only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ImageDetail {
    pub repo: String,
    pub repo_kind: String,
    pub image: String,
    pub registry: String,
    /// `docker pull <pull_name>:<tag>`.
    pub pull_name: String,
    pub tags: Vec<TagItem>,
    pub manifests: Vec<ManifestItem>,
}

/// The registry host of the server (`host[:port]` of `public_base_url`).
fn registry_host(state: &AppState) -> String {
    url::Url::parse(&state.config.public_base_url())
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
        })
        .unwrap_or_default()
}

/// Where `repo`'s images are pulled from: its own host, or
/// `<registry>/<repo>`.
fn pull_prefix(state: &AppState, repo: &Repository) -> (String, String) {
    match repo.docker_host() {
        Some(host) => (host.to_string(), host.to_string()),
        None => {
            let registry = registry_host(state);
            (registry.clone(), format!("{registry}/{}", repo.name))
        }
    }
}

/// The readable docker repository `name`, or the response to send.
async fn readable_docker_repo(
    state: &AppState,
    principal: &Principal,
    name: &str,
) -> Result<Repository, Response> {
    if !matches!(principal, Principal::User { .. }) {
        return Err((StatusCode::UNAUTHORIZED, "authentication required").into_response());
    }
    let repo = match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(r)) if r.is_docker() => r,
        Ok(_) if state.authz.is_global_admin(principal).await => {
            return Err((StatusCode::NOT_FOUND, "repository not found").into_response())
        }
        Ok(_) => return Err((StatusCode::FORBIDDEN, "forbidden").into_response()),
        Err(e) => return Err(db_error(e)),
    };
    if !state.authz.can_read(principal, &repo).await {
        return Err((StatusCode::FORBIDDEN, "forbidden").into_response());
    }
    Ok(repo)
}

/// The repositories whose images `repo` shows the caller, in priority order:
/// itself, or a group's readable docker members (nested groups expanded).
async fn sources(
    state: &AppState,
    principal: &Principal,
    repo: &Repository,
) -> sqlx::Result<Vec<Repository>> {
    if repo.kind() != RepoKind::Group {
        return Ok(vec![repo.clone()]);
    }
    let mut out = Vec::new();
    let mut seen = HashSet::from([repo.id]);
    let mut stack = vec![(repo.clone(), 0i32)];
    let max_depth = state.config.groups.max_nesting_depth.max(1);
    while let Some((group, depth)) = stack.pop() {
        if depth >= max_depth {
            continue;
        }
        let members = repository_dao::group_members(&state.pool, group.id).await?;
        // Depth-first in priority order: push the lowest priority first.
        let mut nested = Vec::new();
        for (member, _) in members {
            if !member.is_docker() || !seen.insert(member.id) {
                continue;
            }
            if !state.authz.can_read(principal, &member).await {
                continue;
            }
            if member.kind() == RepoKind::Group {
                nested.push((member, depth + 1));
            } else {
                out.push(member);
            }
        }
        stack.extend(nested.into_iter().rev());
    }
    Ok(out)
}

/// `GET /browse/images?repo=…`
pub async fn list_images(
    State(state): State<AppState>,
    Query(query): Query<ImagesQuery>,
    req: axum::extract::Request,
) -> Response {
    let principal = principal_of(&req);
    let repo = match readable_docker_repo(&state, &principal, &query.repo).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    let sources = match sources(&state, &principal, &repo).await {
        Ok(s) => s,
        Err(e) => return db_error(e),
    };
    let mut merged: BTreeMap<String, ImageItem> = BTreeMap::new();
    for source in &sources {
        let filter = state.authz.package_filter(&principal, source).await;
        let images =
            match oci_dao::list_images(&state.pool, source.id, &query.q, 0, MAX_IMAGES).await {
                Ok(images) => images,
                Err(e) => return db_error(e),
            };
        for image in images {
            if !filter.allows(&image.image) {
                continue;
            }
            merged.entry(image.image.clone()).or_insert(ImageItem {
                image: image.image,
                tag_count: image.tag_count,
                manifest_count: image.manifest_count,
                last_pushed_at: image.last_pushed_at,
            });
        }
    }
    let take = if query.take == 0 {
        DEFAULT_TAKE
    } else {
        query.take.min(MAX_TAKE)
    };
    let total = merged.len();
    let items = merged.into_values().skip(query.skip).take(take).collect();
    let (registry, pull_prefix) = pull_prefix(&state, &repo);
    Json(ImagesResult {
        total,
        items,
        registry,
        pull_prefix,
    })
    .into_response()
}

/// `GET /browse/images/{repo}/{*image}`
pub async fn image_detail(
    State(state): State<AppState>,
    Path((repo_name, image)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Response {
    let principal = principal_of(&req);
    let repo = match readable_docker_repo(&state, &principal, &repo_name).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    if !forge_oci::reference::valid_name(&image) {
        return (StatusCode::NOT_FOUND, "image not found").into_response();
    }
    let sources = match sources(&state, &principal, &repo).await {
        Ok(s) => s,
        Err(e) => return db_error(e),
    };
    let group = repo.kind() == RepoKind::Group;
    let mut manifests: Vec<ManifestItem> = Vec::new();
    let mut seen_digests = HashSet::new();
    let mut tags: BTreeMap<String, String> = BTreeMap::new();
    for source in &sources {
        if !state
            .authz
            .package_filter(&principal, source)
            .await
            .allows(&image)
        {
            continue;
        }
        let rows = match oci_dao::image_manifests(&state.pool, source.id, &image).await {
            Ok(rows) => rows,
            Err(e) => return db_error(e),
        };
        for row in rows {
            for tag in &row.tags {
                // The highest-priority member's tag wins, as in a pull.
                tags.entry(tag.clone())
                    .or_insert_with(|| row.digest.clone());
            }
            if !seen_digests.insert(row.digest.clone()) {
                continue;
            }
            manifests.push(ManifestItem {
                digest: row.digest,
                media_type: row.media_type,
                artifact_type: row.artifact_type,
                subject_digest: row.subject_digest,
                manifest_size: row.size,
                size: row.summary.get("layers_size").and_then(|v| v.as_i64()),
                platforms: platforms(&row.summary),
                tags: row.tags,
                children: row.children,
                created_at: row.created_at,
                last_pulled_at: row.last_pulled_at,
                source: group.then(|| source.name.clone()),
            });
        }
    }
    if manifests.is_empty() {
        return (StatusCode::NOT_FOUND, "image not found").into_response();
    }
    // An index is as large as the images it lists (that Forge holds), and
    // runs on their platforms when it names none itself.
    let by_digest: HashMap<String, (Option<i64>, Vec<String>)> = manifests
        .iter()
        .map(|m| (m.digest.clone(), (m.size, m.platforms.clone())))
        .collect();
    for m in manifests.iter_mut().filter(|m| !m.children.is_empty()) {
        let children: Vec<&(Option<i64>, Vec<String>)> =
            m.children.iter().filter_map(|c| by_digest.get(c)).collect();
        let total: i64 = children.iter().filter_map(|(size, _)| *size).sum();
        if total > 0 {
            m.size = Some(total);
        }
        if m.platforms.is_empty() {
            let mut platforms: Vec<String> = children
                .iter()
                .flat_map(|(_, p)| p.iter().cloned())
                .collect();
            platforms.dedup();
            m.platforms = platforms;
        }
    }
    // Tags point at a manifest of this listing (the one pulls resolve).
    for (tag, digest) in &tags {
        if let Some(m) = manifests.iter_mut().find(|m| &m.digest == digest) {
            if !m.tags.contains(tag) {
                m.tags.push(tag.clone());
            }
        }
    }
    let tag_items = tags
        .into_iter()
        .filter_map(|(tag, digest)| {
            manifests
                .iter()
                .find(|m| m.digest == digest)
                .map(|m| TagItem {
                    tag,
                    digest,
                    media_type: m.media_type.clone(),
                    size: m.size,
                    platforms: m.platforms.clone(),
                })
        })
        .collect();
    let (registry, prefix) = pull_prefix(&state, &repo);
    Json(ImageDetail {
        repo: repo.name.clone(),
        repo_kind: repo.kind.clone(),
        pull_name: format!("{prefix}/{image}"),
        image,
        registry,
        tags: tag_items,
        manifests,
    })
    .into_response()
}

/// The platforms a manifest summary names.
fn platforms(summary: &serde_json::Value) -> Vec<String> {
    if let Some(list) = summary.get("platforms").and_then(|p| p.as_array()) {
        return list
            .iter()
            .filter_map(|p| p.as_str().map(str::to_string))
            .collect();
    }
    summary
        .get("platform")
        .and_then(|p| p.as_str())
        .map(|p| vec![p.to_string()])
        .unwrap_or_default()
}
