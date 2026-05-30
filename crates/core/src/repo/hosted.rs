//! Hosted-repository read operations (spec §6, §7 "Hosted").
//!
//! Reads are served entirely from local data: `repository` → `component` →
//! `asset` → `blob`. The `.nupkg` is located via the [`NUPKG_ASSET_PATH`]
//! asset; the derived `.nuspec` via [`NUSPEC_ASSET_PATH`]. Version ordering and
//! prerelease detection are delegated to the repository's [`Format`].
//!
//! Byte-level access to stored blobs (needed to serve `.nuspec` and to feed
//! dependency extraction in the format layer) goes through the [`BlobFetch`]
//! seam so this crate stays independent of the concrete S3 client.

use std::sync::Arc;

use async_trait::async_trait;
use forge_db::repository_dao;
use forge_db::{asset_dao, component_dao};
use sqlx::PgPool;

use crate::format::Format;
use crate::repo::{
    NupkgLocation, RegistrationEntry, RepoError, RepoReadOps, SearchHit, SearchParams,
    SearchResult, VersionEntry, NUPKG_ASSET_PATH, NUSPEC_ASSET_PATH,
};

/// Fetch raw bytes of a stored blob by its S3 object key.
///
/// Implemented over `forge_storage::BlobStore` in the server wiring; abstracted
/// here so `forge-core` does not depend on the S3 client and so tests can stub
/// blob bytes.
#[async_trait]
pub trait BlobFetch: Send + Sync {
    /// Read the entire blob at `s3_key` into memory. Used only for small
    /// metadata blobs (the `.nuspec`).
    async fn fetch_all(&self, s3_key: &str) -> Result<Vec<u8>, RepoError>;
}

/// Storage-backed hosted read implementation.
pub struct HostedRepo {
    pool: PgPool,
    format: Arc<dyn Format>,
    blobs: Arc<dyn BlobFetch>,
}

impl HostedRepo {
    /// Build a hosted read facade over a pool, a package [`Format`], and a
    /// blob-byte fetcher.
    pub fn new(pool: PgPool, format: Arc<dyn Format>, blobs: Arc<dyn BlobFetch>) -> Self {
        HostedRepo {
            pool,
            format,
            blobs,
        }
    }

    /// Resolve the repository row by name, erroring if missing.
    async fn repo_id(&self, repo: &str) -> Result<i64, RepoError> {
        repository_dao::find_repository_by_name(&self.pool, repo)
            .await?
            .map(|r| r.id)
            .ok_or_else(|| RepoError::RepoNotFound(repo.to_string()))
    }

    /// Sort components ascending by version precedence using the format.
    fn sort_versions(
        &self,
        mut comps: Vec<forge_db::model::Component>,
    ) -> Vec<forge_db::model::Component> {
        comps.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));
        comps
    }
}

/// A normalized NuGet version is prerelease iff it carries a `-label` suffix.
fn is_prerelease(version: &str) -> bool {
    version.contains('-')
}

#[async_trait]
impl RepoReadOps for HostedRepo {
    async fn list_versions(&self, repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        let comps = component_dao::list_versions(&self.pool, repo_id, id).await?;
        let comps = self.sort_versions(comps);
        Ok(comps
            .into_iter()
            .map(|c| VersionEntry {
                original_id: c.original_id,
                version: c.version,
                version_original: c.version_original,
                listed: c.listed,
            })
            .collect())
    }

    async fn resolve_nupkg(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        let Some(comp) = component_dao::find_component(&self.pool, repo_id, id, version).await?
        else {
            return Ok(None);
        };
        let Some(asset) = asset_dao::find_asset(&self.pool, comp.id, NUPKG_ASSET_PATH).await?
        else {
            return Ok(None);
        };
        let Some(blob) = forge_db::blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? else {
            return Ok(None);
        };
        Ok(Some(NupkgLocation {
            blob_s3_key: blob.s3_key,
            size: asset.size,
            content_type: asset.content_type,
        }))
    }

    async fn resolve_nuspec(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        let Some(comp) = component_dao::find_component(&self.pool, repo_id, id, version).await?
        else {
            return Ok(None);
        };
        let Some(asset) = asset_dao::find_asset(&self.pool, comp.id, NUSPEC_ASSET_PATH).await?
        else {
            return Ok(None);
        };
        let Some(blob) = forge_db::blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? else {
            return Ok(None);
        };
        let bytes = self.blobs.fetch_all(&blob.s3_key).await?;
        Ok(Some(bytes))
    }

    async fn registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        let comps = component_dao::list_versions(&self.pool, repo_id, id).await?;
        let comps = self.sort_versions(comps);

        let mut out = Vec::with_capacity(comps.len());
        for c in comps {
            // The nupkg asset carries the SHA-512 used as packageHash.
            let nupkg = asset_dao::find_asset(&self.pool, c.id, NUPKG_ASSET_PATH).await?;
            let package_hash_sha512_base64 = nupkg.and_then(|a| a.sha512_base64);

            // Fetch the stored nuspec bytes (if present) for dependency
            // extraction by the format layer.
            let nuspec_bytes =
                match asset_dao::find_asset(&self.pool, c.id, NUSPEC_ASSET_PATH).await? {
                    Some(asset) => {
                        match forge_db::blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? {
                            Some(blob) => Some(self.blobs.fetch_all(&blob.s3_key).await?),
                            None => None,
                        }
                    }
                    None => None,
                };

            out.push(RegistrationEntry {
                original_id: c.original_id,
                version: c.version,
                listed: c.listed,
                package_hash_sha512_base64,
                nuspec_bytes,
            });
        }
        Ok(out)
    }

    async fn search(&self, repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        // Fetch all components for the repo, then group/filter in memory. Slice
        // 1 corpora are small; a SQL-side search is a later optimization.
        let comps = component_dao::list_components_for_repo(&self.pool, repo_id).await?;

        let q = params.q.trim().to_lowercase();

        // Group by lowercased package name (the `component.name` column is
        // already the lowercased id).
        use std::collections::BTreeMap;
        let mut by_id: BTreeMap<String, Vec<forge_db::model::Component>> = BTreeMap::new();
        for c in comps {
            // Free-text query matches the id substring (case-insensitive).
            if !q.is_empty() && !c.name.contains(&q) {
                continue;
            }
            by_id.entry(c.name.clone()).or_default().push(c);
        }

        // Build hits: filter versions by listed + prerelease, sort, keep ids
        // that still have at least one visible version.
        let mut hits: Vec<SearchHit> = Vec::new();
        for (_name, comps) in by_id {
            let comps = self.sort_versions(comps);
            let versions: Vec<VersionEntry> = comps
                .into_iter()
                .filter(|c| c.listed)
                .filter(|c| params.prerelease || !is_prerelease(&c.version))
                .map(|c| VersionEntry {
                    original_id: c.original_id,
                    version: c.version,
                    version_original: c.version_original,
                    listed: c.listed,
                })
                .collect();
            if versions.is_empty() {
                continue;
            }
            let latest = versions.last().unwrap();
            hits.push(SearchHit {
                original_id: latest.original_id.clone(),
                latest_version: latest.version.clone(),
                versions,
            });
        }

        // Stable order by id for deterministic paging.
        hits.sort_by(|a, b| {
            a.original_id
                .to_lowercase()
                .cmp(&b.original_id.to_lowercase())
        });

        let total_hits = hits.len();
        let skip = params.skip.min(total_hits);
        let take = params.effective_take();
        let page: Vec<SearchHit> = hits.into_iter().skip(skip).take(take).collect();

        Ok(SearchResult {
            total_hits,
            hits: page,
        })
    }
}
