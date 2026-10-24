//! Browse API of docker repositories: the images of a repository and an
//! image's tags and manifests (digests, sizes, platforms), for the SPA.
//!
//! The same rules as the package browse apply: a signed-in user, per-repo
//! read authorization, the caller's content selectors on image names, and a
//! 503 for an offline hosted or group repository. A group lists what its
//! online members the caller may read hold, the highest priority member
//! first, like a pull through it.
//!
//! ## Endpoints
//! * `GET /browse/images?repo=<name>&q=&skip=&take=` → `{ total, items,
//!   registry, pull_prefix }`.
//! * `GET /browse/images/{repo}/{*image}` → the image's tags and manifests,
//!   with the `docker pull` name.
//! * `GET /browse/chart?repo=<name>&image=<image>&digest=<manifest digest>`
//!   → a Helm chart pushed as an artifact (`helm push`): its `Chart.yaml`
//!   metadata, README and default values, read from the blobs Forge holds.

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use forge_core::auth::principal::Principal;
use forge_db::model::{RepoKind, Repository};
use forge_db::{oci_dao, repository_dao};
use forge_format_docker::chart;
use forge_format_docker::manifest::{self, ManifestKind, MAX_MANIFEST_BYTES};
use forge_storage::BlobRef;
use serde::{Deserialize, Serialize};

use crate::admin::db_error;
use crate::dispatch::{offline_response, offline_serves_nothing};
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
    forge_format_docker::registry_origin(&state.config.public_base_url()).1
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
    // An offline hosted or group repository serves nothing, as in the
    // registry.
    if offline_serves_nothing(&repo) {
        return Err(offline_response());
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
            // An offline hosted or group member serves nothing through the
            // group; an offline proxy still serves its cache.
            if !member.is_docker() || offline_serves_nothing(&member) || !seen.insert(member.id) {
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
    if !forge_format_docker::reference::valid_name(&image) {
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

#[derive(Debug, Deserialize)]
pub struct ChartQuery {
    pub repo: String,
    pub image: String,
    /// The chart's manifest digest.
    pub digest: String,
}

/// A text file of a chart (README, `values.yaml`).
#[derive(Debug, Serialize)]
pub struct ChartFileView {
    pub name: String,
    pub text: String,
    /// Whether the text was cut at [`chart::MAX_FILE_TEXT`] bytes.
    pub truncated: bool,
}

impl From<chart::ChartFile> for ChartFileView {
    fn from(file: chart::ChartFile) -> Self {
        Self {
            name: file.name,
            text: file.text,
            truncated: file.truncated,
        }
    }
}

/// A Helm chart pushed as an OCI artifact.
#[derive(Debug, Serialize)]
pub struct ChartDetail {
    pub digest: String,
    /// The chart's `Chart.yaml` (name, version, appVersion, description,
    /// …), from its config blob; `None` while the blob is not stored here.
    pub metadata: Option<serde_json::Value>,
    pub readme: Option<ChartFileView>,
    pub values: Option<ChartFileView>,
    /// Whether the chart archive is stored here. A proxy stores a chart's
    /// blobs when it is first pulled, so until then it shows no README or
    /// values.
    pub archive_stored: bool,
    /// The member repository it comes from (groups only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// The chart archive layer's media types: Helm's, and the plain one of the
/// experimental OCI support of Helm before 3.8.
fn is_chart_layer(media_type: &str) -> bool {
    media_type == chart::media::CONTENT || media_type == "application/tar+gzip"
}

/// Why a stored blob could not be read.
enum ReadFailure {
    Missing,
    Response(Response),
}

/// Read the blob `digest` linked into `image` of `repo`, if it is stored and
/// at most `max` bytes.
async fn read_linked(
    state: &AppState,
    repo: &Repository,
    image: &str,
    digest: &str,
    max: i64,
) -> Result<Vec<u8>, ReadFailure> {
    let link = oci_dao::find_link(&state.pool, repo.id, image, digest)
        .await
        .map_err(|e| ReadFailure::Response(db_error(e)))?
        .ok_or(ReadFailure::Missing)?;
    if link.size > max {
        return Err(ReadFailure::Missing);
    }
    read_blob(state, &link.blob_sha256, &link.s3_key, link.size)
        .await
        .map_err(ReadFailure::Response)
}

/// Read a stored blob into memory.
async fn read_blob(
    state: &AppState,
    sha256: &str,
    s3_key: &str,
    size: i64,
) -> Result<Vec<u8>, Response> {
    let blob = BlobRef {
        sha256,
        s3_key,
        size: size.max(0) as u64,
    };
    match state.blob_store.read_all(blob).await {
        Ok(bytes) if bytes.len() as u64 == blob.size => Ok(bytes),
        Ok(bytes) => {
            tracing::error!(
                s3_key,
                read = bytes.len(),
                expected = blob.size,
                "browse: stored blob has the wrong size"
            );
            Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response())
        }
        Err(error) if error.is_unavailable() => {
            tracing::warn!(%error, "browse: object store unavailable");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "30")],
                "object store unavailable",
            )
                .into_response())
        }
        Err(error) => {
            tracing::error!(%error, s3_key, "browse: blob read failed");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response())
        }
    }
}

/// `GET /browse/chart?repo=…&image=…&digest=…`
pub async fn chart_detail(
    State(state): State<AppState>,
    Query(query): Query<ChartQuery>,
    req: axum::extract::Request,
) -> Response {
    let principal = principal_of(&req);
    let repo = match readable_docker_repo(&state, &principal, &query.repo).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    let not_found = || (StatusCode::NOT_FOUND, "chart not found").into_response();
    let image = query.image;
    if !forge_format_docker::reference::valid_name(&image)
        || forge_format_docker::digest::Digest::parse(&query.digest).is_err()
    {
        return not_found();
    }
    let sources = match sources(&state, &principal, &repo).await {
        Ok(s) => s,
        Err(e) => return db_error(e),
    };
    // The manifest the highest-priority member holds, as a pull by digest
    // resolves it.
    let mut found = None;
    for source in sources {
        if !state
            .authz
            .package_filter(&principal, &source)
            .await
            .allows(&image)
        {
            continue;
        }
        match oci_dao::find_manifest(&state.pool, source.id, &image, &query.digest).await {
            Ok(Some(row)) => {
                found = Some((source, row));
                break;
            }
            Ok(None) => {}
            Err(e) => return db_error(e),
        }
    }
    let Some((source, row)) = found else {
        return not_found();
    };
    if usize::try_from(row.size).map_or(true, |size| size > MAX_MANIFEST_BYTES) {
        return not_found();
    }
    let bytes = match read_blob(&state, &row.blob_sha256, &row.s3_key, row.size).await {
        Ok(bytes) => bytes,
        Err(resp) => return resp,
    };
    let Ok(parsed) = manifest::parse(&bytes, Some(&row.media_type)) else {
        return not_found();
    };
    let config = parsed.config.as_ref();
    let is_chart = parsed.kind == ManifestKind::Image
        && (config.is_some_and(|c| c.media_type == chart::media::CONFIG)
            || parsed.artifact_type.as_deref() == Some(chart::media::CONFIG));
    if !is_chart {
        return not_found();
    }

    let mut metadata = None;
    if let Some(config) = config.filter(|c| c.media_type == chart::media::CONFIG) {
        match read_linked(
            &state,
            &source,
            &image,
            config.digest.as_str(),
            chart::MAX_CONFIG_BYTES,
        )
        .await
        {
            Ok(bytes) => metadata = chart::metadata(&bytes),
            Err(ReadFailure::Missing) => {}
            Err(ReadFailure::Response(resp)) => return resp,
        }
    }
    let mut files = chart::ChartFiles::default();
    let mut archive_stored = false;
    if let Some(layer) = parsed.layers.iter().find(|l| is_chart_layer(&l.media_type)) {
        match read_linked(
            &state,
            &source,
            &image,
            layer.digest.as_str(),
            chart::MAX_ARCHIVE_BYTES,
        )
        .await
        {
            Ok(archive) => {
                archive_stored = true;
                files = match tokio::task::spawn_blocking(move || chart::read_files(&archive)).await
                {
                    Ok(files) => files,
                    Err(e) => {
                        tracing::error!(error = %e, "browse: reading a chart archive failed");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                            .into_response();
                    }
                };
            }
            Err(ReadFailure::Missing) => {}
            Err(ReadFailure::Response(resp)) => return resp,
        }
    }
    let group = repo.kind() == RepoKind::Group;
    Json(ChartDetail {
        digest: row.digest,
        metadata,
        readme: files.readme.map(Into::into),
        values: files.values.map(Into::into),
        archive_stored,
        source: group.then(|| source.name.clone()),
    })
    .into_response()
}
