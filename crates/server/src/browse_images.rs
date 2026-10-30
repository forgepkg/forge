//! Browse API of the repositories of an images format (Docker): the images
//! of a repository and an image's tags and manifests (digests, sizes,
//! platforms), for the SPA. It reads the image store and the summaries the
//! format made of the manifests.
//!
//! The same rules as the package browse apply: a signed-in user, per-repo
//! read authorization, the caller's content selectors on image names, and a
//! 503 for an offline hosted or group repository. A group lists what a pull
//! through it serves the caller: its own content selector applies, and its
//! guard (`reserved_prefixes`, `prefer_hosted`, owners) decides per image
//! which members serve it, as in the registry (its `GroupMembers`); the
//! highest priority member serving an image is listed first.
//!
//! ## Endpoints
//! * `GET /browse/images?repo=<name>&q=&skip=&take=` → `{ total, items,
//!   registry, pull_prefix }`.
//! * `GET /browse/images/{repo}/{*image}` → the image's tags and manifests,
//!   with the `docker pull` name.
//! * `GET /browse/chart?repo=<name>&image=<image>&digest=<manifest digest>`
//!   → a Helm chart pushed as an artifact (`helm push`): its `Chart.yaml`
//!   metadata, README and default values, read from the blobs Forge holds
//!   with the format ([`FormatPlugin::parse_manifest`],
//!   [`FormatPlugin::config_summary`], [`FormatPlugin::artifact_files`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use forge_core::auth::principal::Principal;
use forge_core::authz::PackageFilter;
use forge_db::model::{RepoKind, Repository};
use forge_db::{oci_dao, repository_dao};
use forge_plugin::api::images::{ArtifactFiles, TextFile, MAX_FILES_BYTES, MAX_MANIFEST_BYTES};
use forge_plugin::FormatPlugin;
use forge_storage::BlobRef;
use serde::{Deserialize, Serialize};

use crate::admin::db_error;
use crate::dispatch::{offline_response, offline_serves_nothing};
use crate::images::digest::ContentDigest;
use crate::images::dispatch::Caller;
use crate::images::Failure;
use crate::middleware::principal_of;
use crate::state::AppState;

/// The largest config blob read for a chart's metadata.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// The summary key under which the format keeps a chart's metadata
/// ([`FormatPlugin::config_summary`]).
const CHART_KEY: &str = "chart";

/// Rows read at a time when visibility filtering or merging needs every image.
const IMAGE_BATCH_SIZE: i64 = 1000;
const DEFAULT_TAKE: usize = 50;
const MAX_TAKE: usize = 200;
/// The most tags an image's page lists: the newest (by their manifest's
/// push). A CI that tags each build, or a proxy of an image with thousands
/// of tags upstream, makes images with tens of thousands; the page counts
/// them all ([`ImageDetail::tags_total`]).
const MAX_DETAIL_TAGS: usize = 1000;
/// The most manifests an image's page lists: those of the tags it lists,
/// then the newest others ([`ImageDetail::manifests_total`]).
const MAX_DETAIL_MANIFESTS: usize = 1000;

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
    /// At most [`MAX_DETAIL_TAGS`] of the image's tags, by name.
    pub tags: Vec<TagItem>,
    /// How many tags the image has.
    pub tags_total: usize,
    /// At most [`MAX_DETAIL_MANIFESTS`] of the image's manifests (more only
    /// when the listed tags point at more).
    pub manifests: Vec<ManifestItem>,
    /// How many manifests the image has.
    pub manifests_total: usize,
}

/// The registry host of the server (`host[:port]` of `public_base_url`).
fn registry_host(state: &AppState) -> String {
    crate::images::registry_origin(&state.config.public_base_url()).1
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

/// The readable repository `name` of an images format, with the format, or
/// the response to send.
async fn readable_images_repo(
    state: &AppState,
    principal: &Principal,
    name: &str,
) -> Result<(Repository, Arc<dyn FormatPlugin>), Response> {
    if !matches!(principal, Principal::User { .. }) {
        return Err((StatusCode::UNAUTHORIZED, "authentication required").into_response());
    }
    let repo = match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(r)) if state.formats.stores_images(&r.format) => r,
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
    let Some(plugin) = state.formats.plugin(&repo.format) else {
        return Err((StatusCode::NOT_FOUND, "repository not found").into_response());
    };
    let format = plugin.implementation().clone();
    Ok((repo, format))
}

/// The repositories whose `image` the caller sees through `repo`, highest
/// priority first, as a pull resolves it: `repo` itself, or the members of a
/// group that serve the image to the caller, its guard applied
/// ([`crate::images::Registry::serving_members`]). None when `repo`'s own
/// content selector hides the image.
async fn image_sources(
    state: &AppState,
    principal: &Principal,
    repo: &Repository,
    image: &str,
) -> Result<Vec<Repository>, Response> {
    if !state
        .authz
        .package_filter(principal, repo)
        .await
        .allows(image)
    {
        return Ok(Vec::new());
    }
    if repo.kind() != RepoKind::Group {
        return Ok(vec![repo.clone()]);
    }
    let caller = Caller {
        principal: principal.clone(),
        claims: None,
    };
    state
        .registry()
        .serving_members(&caller, repo, image, 0)
        .await
        .map_err(failure_response)
}

/// The answer to a failure of the registry's group walk.
fn failure_response(failure: Failure) -> Response {
    tracing::error!(error = %failure.message(), "browse: resolving a group's members failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// `GET /browse/images?repo=…`
pub async fn list_images(
    State(state): State<AppState>,
    Query(query): Query<ImagesQuery>,
    req: axum::extract::Request,
) -> Response {
    let principal = principal_of(&req);
    let (repo, _) = match readable_images_repo(&state, &principal, &query.repo).await {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    let take = if query.take == 0 {
        DEFAULT_TAKE
    } else {
        query.take.min(MAX_TAKE)
    };
    let page = if repo.kind() == RepoKind::Group {
        group_image_page(&state, &principal, &repo, &query, take).await
    } else {
        image_page(&state, &principal, &repo, &query, take)
            .await
            .map_err(db_error)
    };
    let (total, images) = match page {
        Ok(page) => page,
        Err(resp) => return resp,
    };
    let items = images
        .into_iter()
        .map(|image| ImageItem {
            image: image.image,
            tag_count: image.tag_count,
            manifest_count: image.manifest_count,
            last_pushed_at: image.last_pushed_at,
        })
        .collect();
    let (registry, pull_prefix) = pull_prefix(&state, &repo);
    Json(ImagesResult {
        total,
        items,
        registry,
        pull_prefix,
    })
    .into_response()
}

/// A page of the images of a hosted or proxy repository the caller may see.
async fn image_page(
    state: &AppState,
    principal: &Principal,
    repo: &Repository,
    query: &ImagesQuery,
    take: usize,
) -> sqlx::Result<(usize, Vec<oci_dao::ImageSummary>)> {
    let filter = state.authz.package_filter(principal, repo).await;
    match filter {
        PackageFilter::AllowAll => {
            let total = oci_dao::count_images(&state.pool, repo.id, &query.q).await?;
            let images = oci_dao::list_images(
                &state.pool,
                repo.id,
                &query.q,
                i64::try_from(query.skip).unwrap_or(i64::MAX),
                take as i64,
            )
            .await?;
            Ok((total as usize, images))
        }
        PackageFilter::DenyAll => Ok((0, Vec::new())),
        filter => {
            let mut images = Vec::new();
            for_each_image(state, repo.id, &query.q, |image| {
                if filter.allows(&image.image) {
                    images.push(image);
                }
            })
            .await?;
            let total = images.len();
            Ok((
                total,
                images.into_iter().skip(query.skip).take(take).collect(),
            ))
        }
    }
}

/// A page of the images a pull through `group` serves the caller: the
/// group's content selector applies, and its guard decides per image which
/// members serve it (the registry's `GroupMembers`). An image is listed
/// with the counts of the highest priority member serving it.
///
/// Each leaf's images are read a batch at a time by name (a keyset scan,
/// [`oci_dao::list_images_after`]), so a listing costs what the members
/// hold, once. Whether an owner holds an image is asked only of the images
/// a leaf that is no owner would list, a batch at a time: an owner's other
/// images are never read.
async fn group_image_page(
    state: &AppState,
    principal: &Principal,
    group: &Repository,
    query: &ImagesQuery,
    take: usize,
) -> Result<(usize, Vec<oci_dao::ImageSummary>), Response> {
    let group_filter = state.authz.package_filter(principal, group).await;
    if matches!(group_filter, PackageFilter::DenyAll) {
        return Ok((0, Vec::new()));
    }
    let members = state
        .registry()
        .group_members(principal, group, 0)
        .await
        .map_err(failure_response)?;
    let owners = members.owner_ids();
    let mut merged: BTreeMap<String, oci_dao::ImageSummary> = BTreeMap::new();
    for (position, leaf) in members.leaves() {
        // An owner serves what it holds whoever else holds it.
        let asks_owners = members.asks_owners() && !owners.contains(&leaf.id);
        let mut after = String::new();
        loop {
            let batch = oci_dao::list_images_after(
                &state.pool,
                leaf.id,
                &query.q,
                &after,
                IMAGE_BATCH_SIZE,
            )
            .await
            .map_err(db_error)?;
            let full = batch.len() as i64 == IMAGE_BATCH_SIZE;
            let Some(last) = batch.last() else {
                break;
            };
            after = last.image.clone();
            let candidates: Vec<oci_dao::ImageSummary> = batch
                .into_iter()
                .filter(|image| {
                    !merged.contains_key(&image.image) && group_filter.allows(&image.image)
                })
                .collect();
            // Owned or not makes a difference only where nothing else
            // (a reserved prefix) keeps the image to the owners already.
            let ask: Vec<String> = candidates
                .iter()
                .filter(|image| asks_owners && !members.owners_only(&image.image, false))
                .map(|image| image.image.clone())
                .collect();
            let owned: HashSet<String> = if ask.is_empty() {
                HashSet::new()
            } else {
                oci_dao::images_held(&state.pool, &owners, &ask)
                    .await
                    .map_err(db_error)?
                    .into_iter()
                    .collect()
            };
            for image in candidates {
                let owners_only = members.owners_only(&image.image, owned.contains(&image.image));
                if members.serves(position, &image.image, owners_only) {
                    merged.insert(image.image.clone(), image);
                }
            }
            if !full {
                break;
            }
        }
    }
    let total = merged.len();
    let images = merged.into_values().skip(query.skip).take(take).collect();
    Ok((total, images))
}

/// Call `each` with every image of repository `repository_id` matching
/// `q`, read [`IMAGE_BATCH_SIZE`] at a time by name.
async fn for_each_image(
    state: &AppState,
    repository_id: i64,
    q: &str,
    mut each: impl FnMut(oci_dao::ImageSummary),
) -> sqlx::Result<()> {
    let mut after = String::new();
    loop {
        let images =
            oci_dao::list_images_after(&state.pool, repository_id, q, &after, IMAGE_BATCH_SIZE)
                .await?;
        let full = images.len() as i64 == IMAGE_BATCH_SIZE;
        let Some(last) = images.last() else {
            return Ok(());
        };
        after = last.image.clone();
        images.into_iter().for_each(&mut each);
        if !full {
            return Ok(());
        }
    }
}

/// `GET /browse/images/{repo}/{*image}`
pub async fn image_detail(
    State(state): State<AppState>,
    Path((repo_name, image)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Response {
    let principal = principal_of(&req);
    let (repo, format) = match readable_images_repo(&state, &principal, &repo_name).await {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    if format.validate_id(&image).is_err() {
        return (StatusCode::NOT_FOUND, "image not found").into_response();
    }
    let sources = match image_sources(&state, &principal, &repo, &image).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let group = repo.kind() == RepoKind::Group;
    let mut manifests: Vec<ManifestItem> = Vec::new();
    let mut seen_digests = HashSet::new();
    let mut tags: BTreeMap<String, String> = BTreeMap::new();
    for source in &sources {
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
                // The tags pulls resolve to it, below: a lower priority
                // member's tag that a higher one also has is not its.
                tags: Vec::new(),
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
    let (tags, tags_total, manifests, manifests_total) = list_tags(tags, manifests);
    let (registry, prefix) = pull_prefix(&state, &repo);
    Json(ImageDetail {
        repo: repo.name.clone(),
        repo_kind: repo.kind.clone(),
        pull_name: format!("{prefix}/{image}"),
        image,
        registry,
        tags,
        tags_total,
        manifests,
        manifests_total,
    })
    .into_response()
}

/// The tags (tag → the digest pulls resolve) and manifests of an image's
/// page, each manifest badged with the tags pointing at it, with the totals
/// of both. The lists are bounded ([`MAX_DETAIL_TAGS`],
/// [`MAX_DETAIL_MANIFESTS`]; past the tag bound, a manifest is badged with
/// the listed tags only), and every lookup goes through an index by digest:
/// comparing every tag with every manifest took seconds per request for an
/// image with tens of thousands of each, on a runtime worker (#240).
fn list_tags(
    tags: BTreeMap<String, String>,
    mut manifests: Vec<ManifestItem>,
) -> (Vec<TagItem>, usize, Vec<ManifestItem>, usize) {
    let index: HashMap<&str, usize> = manifests
        .iter()
        .enumerate()
        .map(|(i, m)| (m.digest.as_str(), i))
        .collect();
    // Tags point at a manifest of this listing (the one pulls resolve).
    let mut tagged: Vec<(String, usize)> = tags
        .into_iter()
        .filter_map(|(tag, digest)| index.get(digest.as_str()).map(|&i| (tag, i)))
        .collect();
    drop(index);
    let tags_total = tagged.len();
    if tags_total > MAX_DETAIL_TAGS {
        // The newest, listed by name like the others.
        tagged.sort_by(|(a, i), (b, j)| {
            manifests[*j]
                .created_at
                .cmp(&manifests[*i].created_at)
                .then_with(|| a.cmp(b))
        });
        tagged.truncate(MAX_DETAIL_TAGS);
        tagged.sort_by(|(a, _), (b, _)| a.cmp(b));
        let listed: HashSet<&str> = tagged.iter().map(|(tag, _)| tag.as_str()).collect();
        for m in &mut manifests {
            m.tags.retain(|tag| listed.contains(tag.as_str()));
        }
    }
    let mut badges: HashSet<(usize, String)> = manifests
        .iter()
        .enumerate()
        .flat_map(|(i, m)| m.tags.iter().map(move |tag| (i, tag.clone())))
        .collect();
    for (tag, i) in &tagged {
        if badges.insert((*i, tag.clone())) {
            manifests[*i].tags.push(tag.clone());
        }
    }
    let tag_items: Vec<TagItem> = tagged
        .iter()
        .map(|(tag, i)| {
            let m = &manifests[*i];
            TagItem {
                tag: tag.clone(),
                digest: m.digest.clone(),
                media_type: m.media_type.clone(),
                size: m.size,
                platforms: m.platforms.clone(),
            }
        })
        .collect();

    let manifests_total = manifests.len();
    if manifests_total > MAX_DETAIL_MANIFESTS {
        // The listed tags' manifests, then the others in order (the highest
        // priority member's first, each newest first) up to the bound.
        let listed: HashSet<usize> = tagged.iter().map(|(_, i)| *i).collect();
        let mut room = MAX_DETAIL_MANIFESTS.saturating_sub(listed.len());
        let mut position = 0;
        manifests.retain(|_| {
            let i = position;
            position += 1;
            if listed.contains(&i) {
                return true;
            }
            if room == 0 {
                return false;
            }
            room -= 1;
            true
        });
    }
    (tag_items, tags_total, manifests, manifests_total)
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
    /// Whether the text was cut (the format bounds it).
    pub truncated: bool,
}

impl From<TextFile> for ChartFileView {
    fn from(file: TextFile) -> Self {
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
    max: u64,
) -> Result<Vec<u8>, ReadFailure> {
    let link = oci_dao::find_link(&state.pool, repo.id, image, digest)
        .await
        .map_err(|e| ReadFailure::Response(db_error(e)))?
        .ok_or(ReadFailure::Missing)?;
    if link.size.max(0) as u64 > max {
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
    let (repo, format) = match readable_images_repo(&state, &principal, &query.repo).await {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    let not_found = || (StatusCode::NOT_FOUND, "chart not found").into_response();
    let image = query.image;
    if format.validate_id(&image).is_err() || ContentDigest::parse(&query.digest).is_none() {
        return not_found();
    }
    let sources = match image_sources(&state, &principal, &repo, &image).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // The manifest the highest-priority member holds, as a pull by digest
    // resolves it.
    let mut found = None;
    for source in sources {
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
    // A chart is an artifact with files to show (its archive).
    let Ok(parsed) = format.parse_manifest(&bytes, Some(&row.media_type)) else {
        return not_found();
    };
    let Some(archive) = parsed.files else {
        return not_found();
    };

    let mut metadata = None;
    if let Some(config) = parsed.config {
        match read_linked(&state, &source, &image, &config.digest, MAX_CONFIG_BYTES).await {
            Ok(bytes) => {
                metadata = format
                    .config_summary(&config.media_type, &bytes)
                    .and_then(|part| serde_json::from_str::<serde_json::Value>(&part).ok())
                    .and_then(|mut part| part.get_mut(CHART_KEY).map(serde_json::Value::take));
            }
            Err(ReadFailure::Missing) => {}
            Err(ReadFailure::Response(resp)) => return resp,
        }
    }
    let mut files = ArtifactFiles::default();
    let mut archive_stored = false;
    match read_linked(&state, &source, &image, &archive.digest, MAX_FILES_BYTES).await {
        Ok(archive) => {
            archive_stored = true;
            files = match tokio::task::spawn_blocking(move || {
                format.artifact_files(&mut std::io::Cursor::new(archive))
            })
            .await
            {
                Ok(files) => files,
                Err(e) => {
                    tracing::error!(error = %e, "browse: reading a chart archive failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
                }
            };
        }
        Err(ReadFailure::Missing) => {}
        Err(ReadFailure::Response(resp)) => return resp,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(n: usize, tags: &[&str]) -> ManifestItem {
        ManifestItem {
            digest: format!("sha256:{n:064x}"),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: None,
            subject_digest: None,
            manifest_size: 100,
            size: Some(n as i64),
            platforms: vec!["linux/amd64".into()],
            tags: tags.iter().map(|t| t.to_string()).collect(),
            children: Vec::new(),
            created_at: DateTime::from_timestamp(1_700_000_000 + n as i64, 0).unwrap(),
            last_pulled_at: None,
            source: None,
        }
    }

    /// An image with `n` manifests (manifest `i` pushed `i` seconds after
    /// the first), each tagged `t<i>`, newest first as the store lists them.
    fn image(n: usize) -> (BTreeMap<String, String>, Vec<ManifestItem>) {
        let manifests: Vec<ManifestItem> = (0..n)
            .rev()
            .map(|i| manifest(i, &[&format!("t{i}")]))
            .collect();
        let tags = manifests
            .iter()
            .map(|m| (m.tags[0].clone(), m.digest.clone()))
            .collect();
        (tags, manifests)
    }

    #[test]
    fn tags_are_badged_and_listed_with_their_manifest() {
        // `latest` is the newest manifest's, as a pull resolves it; a tag of
        // a manifest the listing lacks is left out.
        let mut tags: BTreeMap<String, String> = BTreeMap::new();
        tags.insert("1.0".into(), manifest(1, &[]).digest);
        tags.insert("latest".into(), manifest(2, &[]).digest);
        tags.insert("gone".into(), manifest(9, &[]).digest);
        let manifests = vec![manifest(2, &[]), manifest(1, &["1.0"])];

        let (tags, tags_total, manifests, manifests_total) = list_tags(tags, manifests);

        let listed: Vec<(&str, &str)> = tags
            .iter()
            .map(|t| (t.tag.as_str(), t.digest.as_str()))
            .collect();
        assert_eq!(
            listed,
            [
                ("1.0", manifests[1].digest.as_str()),
                ("latest", manifests[0].digest.as_str())
            ]
        );
        assert_eq!(tags[1].size, Some(2));
        assert_eq!((tags_total, manifests_total), (2, 2));
        assert_eq!(manifests[0].tags, ["latest"]);
        assert_eq!(manifests[1].tags, ["1.0"], "not badged twice");
    }

    #[test]
    fn the_newest_tags_and_their_manifests_are_listed_up_to_the_bounds() {
        let n = MAX_DETAIL_TAGS + 500;
        let (tags, mut manifests) = image(n);
        // Untagged manifests, older than every tagged one.
        manifests.extend((0..MAX_DETAIL_MANIFESTS).map(|i| ManifestItem {
            created_at: DateTime::from_timestamp(1_600_000_000 + i as i64, 0).unwrap(),
            digest: format!("sha256:{:064x}", n + i),
            ..manifest(0, &[])
        }));

        let (tags, tags_total, manifests, manifests_total) = list_tags(tags, manifests);

        assert_eq!(tags_total, n);
        assert_eq!(manifests_total, n + MAX_DETAIL_MANIFESTS);
        assert_eq!(tags.len(), MAX_DETAIL_TAGS);
        // The newest tags (t500 … t1499), by name.
        let mut names: Vec<&str> = tags.iter().map(|t| t.tag.as_str()).collect();
        assert!(names.is_sorted());
        names.sort_by_key(|name| name[1..].parse::<usize>().unwrap());
        assert_eq!(names.first(), Some(&"t500"));
        assert_eq!(names.last(), Some(&format!("t{}", n - 1).as_str()));
        // Their manifests, and no other: the bound is reached.
        assert_eq!(manifests.len(), MAX_DETAIL_MANIFESTS);
        let digests: HashSet<&str> = manifests.iter().map(|m| m.digest.as_str()).collect();
        assert!(tags.iter().all(|t| digests.contains(t.digest.as_str())));
        assert!(manifests.iter().all(|m| m.tags.len() == 1));
    }

    #[test]
    fn untagged_manifests_fill_the_listing_after_the_tagged_ones() {
        let (tags, mut manifests) = image(10);
        manifests.extend((0..MAX_DETAIL_MANIFESTS).map(|i| ManifestItem {
            digest: format!("sha256:{:064x}", 10 + i),
            ..manifest(0, &[])
        }));

        let (tags, _, manifests, manifests_total) = list_tags(tags, manifests);

        assert_eq!(tags.len(), 10);
        assert_eq!(manifests_total, 10 + MAX_DETAIL_MANIFESTS);
        assert_eq!(manifests.len(), MAX_DETAIL_MANIFESTS);
        assert!(manifests[..10].iter().all(|m| m.tags.len() == 1));
    }

    /// The issue's 50,000 tagged manifests took 24 s with nested scans.
    #[test]
    fn a_large_image_is_listed_in_linear_time() {
        let (tags, manifests) = image(50_000);
        let started = std::time::Instant::now();
        let (tags, tags_total, manifests, manifests_total) = list_tags(tags, manifests);
        assert_eq!((tags_total, manifests_total), (50_000, 50_000));
        assert_eq!(
            (tags.len(), manifests.len()),
            (MAX_DETAIL_TAGS, MAX_DETAIL_MANIFESTS)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }
}
