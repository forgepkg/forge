//! Hosted-repository read and write operations.
//!
//! Reads are served entirely from local data: `repository` → `component` →
//! `asset` → `blob`. The package (the `.nupkg` for NuGet) is located via the
//! format's [`Format::package_asset_path`] asset; the derived manifest (the
//! `.nuspec`) via [`Format::manifest_asset_path`]. Version ordering and
//! prerelease detection are delegated to the repository's [`Format`].
//!
//! Byte-level access to stored blobs (needed to serve `.nuspec` and to feed
//! dependency extraction in the format layer) goes through the [`BlobFetch`]
//! seam so this crate stays independent of the concrete S3 client.

use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use forge_db::asset_dao::NewAsset;
use forge_db::component_dao::NewComponent;
use forge_db::repository_dao;
use forge_db::{asset_dao, blob_dao, component_dao};
use forge_storage::Cas;
use sqlx::PgPool;

use crate::auth::principal::Principal;
use crate::authz::PackageFilter;
use crate::format::Format;
use crate::repo::downloads::DownloadTally;
use crate::repo::{
    CacheInvalidator, DeleteOutcome, ImportOptions, ImportOutcome, NupkgLocation, PackageMutation,
    PublishAuthorizationContext, PublishOutcome, PublishPolicy, RegistrationEntry, RepoError,
    RepoReadOps, SearchHit, SearchParams, SearchQuery, SearchResult, VersionEntry, WriteError,
};

/// Fetch raw bytes of a stored blob.
///
/// Implemented over `forge_storage::BlobStore` in the server wiring; abstracted
/// here so `forge-core` does not depend on the S3 client and so tests can stub
/// blob bytes.
#[async_trait]
pub trait BlobFetch: Send + Sync {
    /// Read the entire `blob` into memory (from the local blob cache, or its
    /// S3 object). Used only for small metadata blobs (the `.nuspec`).
    async fn fetch_all(&self, blob: &forge_db::model::Blob) -> Result<Vec<u8>, RepoError>;
}

/// Storage-backed hosted read implementation.
pub struct HostedRepo {
    pool: PgPool,
    format: Arc<dyn Format>,
    blobs: Arc<dyn BlobFetch>,
    /// Counts `.nupkg` downloads and writes them in batches.
    downloads: Arc<DownloadTally>,
}

impl HostedRepo {
    /// Build a hosted read facade over a pool, a package [`Format`], and a
    /// blob-byte fetcher. It counts downloads in a tally of its own unless it
    /// is given the process's ([`Self::with_download_tally`]).
    pub fn new(pool: PgPool, format: Arc<dyn Format>, blobs: Arc<dyn BlobFetch>) -> Self {
        HostedRepo {
            downloads: DownloadTally::new(pool.clone()),
            pool,
            format,
            blobs,
        }
    }

    /// Count downloads in `downloads`, shared with the other facades.
    pub fn with_download_tally(mut self, downloads: Arc<DownloadTally>) -> Self {
        self.downloads = downloads;
        self
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

    /// Build one exact search result while applying package authorization
    /// before paging: the ids that match are listed once, filtered by the
    /// selector, counted and paged, and only the page's versions are loaded.
    /// With `enrich`, the returned page carries manifests and download totals
    /// ([`Self::enrich_hits`]); a group searches its members without and
    /// enriches only its own final page.
    async fn search_filtered(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
        enrich: bool,
    ) -> Result<SearchResult, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        let query = SearchQuery::parse(&params.q);
        // Page over ids, not versions: the filters run in SQL, the selector
        // and the query's terms on the (much shorter) id list, and versions
        // are loaded for the returned page only.
        let mut names: Vec<String> = component_dao::search_names(
            &self.pool,
            repo_id,
            query.prefilter().unwrap_or(""),
            params.prerelease,
            params.include_semver2,
        )
        .await?
        .into_iter()
        .filter(|name| filter.allows(name) && query.matches(name))
        .collect();
        // Byte order, as group results are ordered (SQL orders by the
        // database collation, which may weigh punctuation differently).
        names.sort_unstable();
        let total_hits = names.len();
        let page: Vec<String> = names
            .into_iter()
            .skip(params.skip.min(total_hits))
            .take(params.effective_take())
            .collect();

        use std::collections::HashMap;
        let mut by_id: HashMap<String, Vec<forge_db::model::Component>> = HashMap::new();
        for c in component_dao::search_versions(
            &self.pool,
            repo_id,
            &page,
            params.prerelease,
            params.include_semver2,
        )
        .await?
        {
            by_id.entry(c.name.clone()).or_default().push(c);
        }
        let mut hits: Vec<SearchHit> = Vec::with_capacity(page.len());
        for name in &page {
            let Some(comps) = by_id.remove(name) else {
                // Changed between the two queries.
                continue;
            };
            let versions: Vec<VersionEntry> = self
                .sort_versions(comps)
                .into_iter()
                .map(|c| VersionEntry {
                    original_id: c.original_id,
                    version: c.version,
                    version_original: c.version_original,
                    listed: c.listed,
                })
                .collect();
            let latest = versions.last().expect("non-empty versions");
            hits.push(SearchHit {
                original_id: latest.original_id.clone(),
                latest_version: latest.version.clone(),
                versions,
                ..Default::default()
            });
        }
        if enrich {
            self.enrich_hits(repo_id, &mut hits).await?;
        }
        Ok(SearchResult { total_hits, hits })
    }

    /// Attach the latest version's manifest and the download total to each
    /// hit of the (already paged) result.
    async fn enrich_hits(&self, repo_id: i64, hits: &mut [SearchHit]) -> Result<(), RepoError> {
        use futures_util::StreamExt;
        let names: Vec<String> = hits
            .iter()
            .map(|h| self.format.lower_id(&h.original_id))
            .collect();
        let totals: std::collections::HashMap<String, i64> =
            forge_db::download_dao::total_downloads_by_name(&self.pool, repo_id, &names)
                .await?
                .into_iter()
                .collect();
        let versions: Vec<String> = hits.iter().map(|h| h.latest_version.clone()).collect();
        // Stored summaries first (one query); only versions without one fall
        // back to fetching their manifest.
        let mut summaries: std::collections::HashMap<(String, String), serde_json::Value> =
            component_dao::manifest_summaries(&self.pool, repo_id, &names, &versions)
                .await?
                .into_iter()
                .map(|(name, version, summary)| ((name, version), summary))
                .collect();
        let wanted: Vec<(String, String)> = names
            .iter()
            .cloned()
            .zip(versions.iter().cloned())
            .filter(|key| !summaries.contains_key(key))
            .collect();
        let fetched: Vec<Option<Vec<u8>>> = futures_util::stream::iter(wanted.clone())
            .map(|(name, version)| async move { self.nuspec_of(repo_id, &name, &version).await })
            .buffered(8)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .map(|r| {
                r.unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "search: manifest fetch failed");
                    None
                })
            })
            .collect();
        let mut manifests: std::collections::HashMap<(String, String), Vec<u8>> = wanted
            .into_iter()
            .zip(fetched)
            .filter_map(|(key, bytes)| bytes.map(|b| (key, b)))
            .collect();
        for ((hit, name), version) in hits.iter_mut().zip(&names).zip(versions) {
            hit.total_downloads = Some(totals.get(name).copied().unwrap_or(0));
            let key = (name.clone(), version);
            hit.manifest_summary = summaries.remove(&key);
            hit.nuspec_bytes = manifests.remove(&key);
        }
        Ok(())
    }

    /// The registration entry of one version row. A version published before
    /// manifest summaries were stored has its manifest fetched and summarized
    /// once (off the async workers), and the summary is backfilled so later
    /// reads skip that work; if it cannot be summarized the raw manifest is
    /// handed to the format layer as before.
    async fn entry_of_row(
        &self,
        row: component_dao::RegistrationRow,
    ) -> Result<RegistrationEntry, RepoError> {
        let (manifest_summary, nuspec_bytes) = match row.manifest_summary {
            Some(summary) => (Some(summary), None),
            None => {
                let bytes = self.nuspec_of_component(row.id).await?;
                let summary = match bytes.clone() {
                    Some(bytes) => {
                        let format = self.format.clone();
                        tokio::task::spawn_blocking(move || format.manifest_summary(&bytes))
                            .await
                            .ok()
                            .flatten()
                    }
                    None => None,
                };
                match summary {
                    Some(summary) => {
                        if let Err(e) =
                            component_dao::backfill_manifest_summary(&self.pool, row.id, &summary)
                                .await
                        {
                            tracing::warn!(error = %e, component_id = row.id, "manifest summary backfill failed");
                        }
                        (Some(summary), None)
                    }
                    None => (None, bytes),
                }
            }
        };
        Ok(RegistrationEntry {
            original_id: row.original_id,
            version: row.version,
            version_original: row.version_original,
            listed: row.listed,
            package_hash_sha512_base64: row.package_hash_sha512_base64,
            package_sha256: row.package_sha256,
            package_size: row.package_size,
            nuspec_bytes,
            manifest_summary,
            published: Some(row.created_at),
            deprecation: row.deprecation,
        })
    }

    /// The stored `.nuspec` of `(id, version)`, if any.
    async fn nuspec_of(
        &self,
        repo_id: i64,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        let Some(comp) = component_dao::find_component(&self.pool, repo_id, id, version).await?
        else {
            return Ok(None);
        };
        self.nuspec_of_component(comp.id).await
    }

    /// The stored `.nuspec` of a component, if any.
    async fn nuspec_of_component(&self, component_id: i64) -> Result<Option<Vec<u8>>, RepoError> {
        let Some(asset) =
            asset_dao::find_asset(&self.pool, component_id, self.format.manifest_asset_path())
                .await?
        else {
            return Ok(None);
        };
        match forge_db::blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? {
            Some(blob) => Ok(Some(self.blobs.fetch_all(&blob).await?)),
            None => Ok(None),
        }
    }
}

impl HostedRepo {
    /// The `.nupkg` of `(id, version)` in `repo`, counted as a download when
    /// `count` ([`RepoReadOps::resolve_nupkg`] / [`RepoReadOps::resolve_nupkg_head`]).
    async fn locate_nupkg(
        &self,
        repo: &str,
        id: &str,
        version: &str,
        count: bool,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        let Some(comp) = component_dao::find_component(&self.pool, repo_id, id, version).await?
        else {
            return Ok(None);
        };
        let Some(asset) =
            asset_dao::find_asset(&self.pool, comp.id, self.format.package_asset_path()).await?
        else {
            return Ok(None);
        };
        let Some(blob) = forge_db::blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? else {
            return Ok(None);
        };

        // Download tracking: best-effort, off the hot path.
        // A resolved `.nupkg` is a download (a `HEAD` is not); it is counted
        // in memory and written in a batch, so a tracking write never blocks
        // (or fails) the response, and a burst on one version never queues
        // on its rows. Non-authoritative — failures are logged.
        if count {
            self.downloads.count_hosted(asset.id, comp.id);
        }

        Ok(Some(NupkgLocation {
            blob_sha256: blob.sha256,
            blob_s3_key: blob.s3_key,
            size: asset.size,
            content_type: asset.content_type,
        }))
    }
}

#[async_trait]
impl RepoReadOps for HostedRepo {
    async fn tags(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<std::collections::BTreeMap<String, String>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        Ok(forge_db::tag_dao::tags(&self.pool, repo_id, id).await?)
    }

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
        self.locate_nupkg(repo, id, version, true).await
    }

    async fn resolve_nupkg_head(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        self.locate_nupkg(repo, id, version, false).await
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
        let Some(asset) =
            asset_dao::find_asset(&self.pool, comp.id, self.format.manifest_asset_path()).await?
        else {
            return Ok(None);
        };
        let Some(blob) = forge_db::blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? else {
            return Ok(None);
        };
        let bytes = self.blobs.fetch_all(&blob).await?;
        Ok(Some(bytes))
    }

    async fn registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        // One query for every version's listing state, hash and stored
        // manifest summary; only versions published before summaries were
        // stored need their manifest fetched (once — see `entry_of_row`).
        let mut rows = component_dao::list_registration_rows(
            &self.pool,
            repo_id,
            id,
            self.format.package_asset_path(),
        )
        .await?;
        rows.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));
        use futures_util::StreamExt;
        futures_util::stream::iter(rows.into_iter().map(|row| self.entry_of_row(row)))
            .buffered(16)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect()
    }

    async fn registration_versions(&self, repo: &str, id: &str) -> Result<Vec<String>, RepoError> {
        // The same rows `registration` lists, without their metadata.
        Ok(self
            .list_versions(repo, id)
            .await?
            .into_iter()
            .map(|v| v.version)
            .collect())
    }

    async fn registration_entries(
        &self,
        repo: &str,
        id: &str,
        versions: &[String],
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        let rows = component_dao::list_registration_rows_for_versions(
            &self.pool,
            repo_id,
            id,
            versions,
            self.format.package_asset_path(),
        )
        .await?;
        use futures_util::StreamExt;
        futures_util::stream::iter(rows.into_iter().map(|row| self.entry_of_row(row)))
            .buffered(16)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect()
    }

    async fn registration_entry(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<RegistrationEntry>, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        match component_dao::find_registration_row(
            &self.pool,
            repo_id,
            id,
            version,
            self.format.package_asset_path(),
        )
        .await?
        {
            Some(row) => Ok(Some(self.entry_of_row(row).await?)),
            None => Ok(None),
        }
    }

    async fn search(&self, repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        self.search_filtered(repo, params, &PackageFilter::AllowAll, true)
            .await
    }

    async fn search_with_package_filter(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        self.search_filtered(repo, params, filter, true).await
    }

    async fn search_unenriched(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        self.search_filtered(repo, params, filter, false).await
    }

    async fn enrich_search_hits(
        &self,
        repo: &str,
        hits: &mut [SearchHit],
    ) -> Result<(), RepoError> {
        if hits.is_empty() {
            return Ok(());
        }
        let repo_id = self.repo_id(repo).await?;
        self.enrich_hits(repo_id, hits).await
    }
}

/// Storage-backed hosted **write** facade: publish, redeploy, delete, relist.
///
/// Writes ingest bytes through the content-addressed [`Cas`] (which records a
/// `pending` blob and uploads to S3 only on a dedup miss), then commit the blob
/// references and component/asset rows in **one** transaction so a crash never
/// leaves a half-written package. The derived `.nuspec` is stored as its own CAS
/// blob (dedup applies) so the flat-container `.nuspec` route can serve it
/// without re-opening the `.nupkg`.
pub struct HostedWrite {
    pool: PgPool,
    format: Arc<dyn Format>,
    cas: Cas,
    cache: Arc<dyn CacheInvalidator>,
    /// Grace period before a dereferenced blob's S3 object is deleted (passed to
    /// [`blob_dao::decref_and_maybe_enqueue_delete`]).
    delete_grace: Duration,
    /// Request actor and post-parse publication policy. Server requests always
    /// set this; direct core callers retain legacy allow-all behavior.
    publish_policy: Option<(Principal, Arc<dyn PublishPolicy>)>,
    /// Action-specific filter for identifier-addressed delete/relist methods.
    mutation_filter: PackageFilter,
}

impl HostedWrite {
    /// Build a hosted write facade.
    ///
    /// `delete_grace` is the deferred-delete window applied when a blob's
    /// reference count drops to zero (redeploy swap, hard delete); the outbox
    /// worker performs the S3 delete only after it elapses.
    pub fn new(
        pool: PgPool,
        format: Arc<dyn Format>,
        cas: Cas,
        cache: Arc<dyn CacheInvalidator>,
        delete_grace: Duration,
    ) -> Self {
        HostedWrite {
            pool,
            format,
            cas,
            cache,
            delete_grace,
            publish_policy: None,
            mutation_filter: PackageFilter::AllowAll,
        }
    }

    /// Attach request provenance and a post-parse/pre-CAS publication policy.
    pub fn with_publish_policy(
        mut self,
        principal: Principal,
        policy: Arc<dyn PublishPolicy>,
    ) -> Self {
        self.publish_policy = Some((principal, policy));
        self
    }

    /// Attach the action-specific package filter used by delete/relist.
    pub fn with_mutation_filter(mut self, filter: PackageFilter) -> Self {
        self.mutation_filter = filter;
        self
    }

    /// Resolve the repository row by name, erroring if missing or not hosted.
    async fn hosted_repo(&self, repo: &str) -> Result<forge_db::model::Repository, WriteError> {
        let row = repository_dao::find_repository_by_name(&self.pool, repo)
            .await
            .map_err(RepoError::from)?
            .ok_or_else(|| RepoError::RepoNotFound(repo.to_string()))?;
        if row.kind() != forge_db::model::RepoKind::Hosted {
            return Err(RepoError::WrongKind {
                name: repo.to_string(),
                kind: row.kind.clone(),
            }
            .into());
        }
        Ok(row)
    }

    /// Publish (or redeploy) a package read from `reader`.
    ///
    /// Pipeline:
    /// 1. Stage and hash the bytes locally, enforcing `max_upload_bytes`.
    /// 2. Parse the temp `.nupkg` into a [`ParsedUpload`](crate::ParsedUpload),
    ///    authorize its canonical id, then promote it into CAS. A parse failure
    ///    is [`WriteError::InvalidPackage`]; a policy denial mutates no DB/S3.
    /// 3. Store the derived `.nuspec` bytes as their own CAS blob (dedup).
    /// 4. In **one** transaction: commit + incref both blobs, insert the
    ///    `component` and the `.nupkg`/`.nuspec` assets. A duplicate
    ///    `(id, version)` is rejected with [`WriteError::Conflict`] unless the
    ///    repository has `allow_redeploy`, in which case the assets are swapped
    ///    to the new blobs and the old blobs are dereferenced in the same tx.
    /// 5. Invalidate the `(repo, id)` cache namespace.
    pub async fn store_upload<R>(
        &self,
        repo: &str,
        reader: R,
        max_upload_bytes: u64,
    ) -> Result<PublishOutcome, WriteError>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let repo_row = self.hosted_repo(repo).await?;

        // 1. Stage the .nupkg locally. Staging hashes and size-bounds the bytes
        // but deliberately does not touch the database or S3: authorization
        // needs the canonical identity extracted by the format parser first.
        let staged_nupkg = self.cas.stage(reader, max_upload_bytes).await?;
        let (_, _, published) = self
            .publish_staged(&repo_row, staged_nupkg, max_upload_bytes, None)
            .await?;
        match published {
            Published::Created => Ok(PublishOutcome::Created),
            Published::Replaced => Ok(PublishOutcome::Replaced),
            other => Err(WriteError::Repo(RepoError::Storage(format!(
                "a publish reported the import outcome {other:?}"
            )))),
        }
    }

    /// Import a package a migration staged from another registry (and
    /// verified against that registry's checksums) through the same path as
    /// a publish: parsing, the publish policy, CAS, the repository's
    /// upload limit. Unlike a publish, a version that exists is not an
    /// error: with the same bytes it is [`ImportOutcome::Identical`], with
    /// other bytes it is replaced only with [`ImportOptions::overwrite`]
    /// (even where the repository refuses redeploys) and otherwise reported
    /// as [`ImportOutcome::Conflict`]. A stored version takes the source's
    /// publish and last-download times, so retention judges it by its real
    /// age.
    pub async fn import_staged(
        &self,
        repo: &str,
        staged: forge_storage::StagedBlob,
        max_upload_bytes: u64,
        options: &ImportOptions,
    ) -> Result<ImportOutcome, WriteError> {
        let repo_row = self.hosted_repo(repo).await?;
        if staged.size > max_upload_bytes {
            return Err(WriteError::TooLarge {
                limit: max_upload_bytes,
            });
        }
        let (id, version, published) = self
            .publish_staged(&repo_row, staged, max_upload_bytes, Some(options))
            .await?;
        Ok(match published {
            Published::Created => ImportOutcome::Created { id, version },
            Published::Replaced => ImportOutcome::Replaced { id, version },
            Published::Identical => ImportOutcome::Identical { id, version },
            Published::Conflict => ImportOutcome::Conflict { id, version },
            Published::Planned { replaces } => ImportOutcome::Planned {
                id,
                version,
                replaces,
            },
        })
    }

    /// The SHA-256 of the package file of `(id, version)` in the hosted
    /// repository `repository_id`, if the version exists: what an import
    /// compares the source's checksum with before downloading anything.
    pub async fn package_sha256(
        &self,
        repository_id: i64,
        id: &str,
        version: &str,
    ) -> Result<Option<String>, WriteError> {
        let Ok(version) = self.format.normalize_version(version) else {
            return Ok(None);
        };
        let lower = self.format.lower_id(id);
        let Some(comp) = component_dao::find_component(&self.pool, repository_id, &lower, &version)
            .await
            .map_err(RepoError::from)?
        else {
            return Ok(None);
        };
        self.stored_package_sha256(&self.pool, comp.id).await
    }

    /// The SHA-256 of a component's package file.
    async fn stored_package_sha256<'e, E>(
        &self,
        executor: E,
        component_id: i64,
    ) -> Result<Option<String>, WriteError>
    where
        E: sqlx::PgExecutor<'e>,
    {
        Ok(
            asset_dao::find_asset(executor, component_id, self.format.package_asset_path())
                .await
                .map_err(RepoError::from)?
                .map(|asset| asset.blob_sha256),
        )
    }

    /// Steps 2 to 5 of [`Self::store_upload`] for a staged package; with
    /// `import`, an existing version is compared instead of refused (see
    /// [`Self::import_staged`]). Returns the package's id (original casing)
    /// and normalized version with the outcome.
    async fn publish_staged(
        &self,
        repo_row: &forge_db::model::Repository,
        staged_nupkg: forge_storage::StagedBlob,
        max_upload_bytes: u64,
        import: Option<&ImportOptions>,
    ) -> Result<(String, String, Published), WriteError> {
        let repo = repo_row.name.as_str();

        // 2. Parse the package from the temp file. parse_upload is sync and a
        //    package may be hundreds of MiB, so it runs on the blocking pool.
        //    The manifest summary stored with the version (so metadata reads
        //    never re-parse the manifest) is computed here too.
        let (parsed, manifest_summary) = {
            let format = self.format.clone();
            let path = staged_nupkg.read_path();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = std::fs::metadata(&path) {
                    return Err(WriteError::Repo(RepoError::Storage(format!(
                        "reopen temp upload: {e}"
                    ))));
                }
                let parsed = format.parse_upload_file(&path).map_err(WriteError::from)?;
                let summary = format.manifest_summary(&parsed.nuspec_bytes);
                Ok::<_, WriteError>((parsed, summary))
            })
            .await
            .map_err(|e| WriteError::Repo(RepoError::Storage(format!("parse upload: {e}"))))??
        };
        let done = |published: Published| {
            Ok((
                parsed.original_id.clone(),
                parsed.version.clone(),
                published,
            ))
        };

        let publish_context =
            self.publish_policy
                .as_ref()
                .map(|(principal, _)| PublishAuthorizationContext {
                    principal: *principal,
                    action: PackageMutation::Publish,
                    package_id: parsed.id.clone(),
                    package_version: parsed.version.clone(),
                });
        if let (Some((_, policy)), Some(context)) =
            (self.publish_policy.as_ref(), publish_context.as_ref())
        {
            policy.authorize(context).await?;
        }

        // A duplicate without redeploy is answered before anything reaches
        // S3: a CI job that re-pushes an unchanged version with
        // `--skip-duplicate` on every build would otherwise upload it each
        // time. The check in the transaction below stays the authority (a
        // concurrent first push). An import compares the bytes instead.
        let existing =
            component_dao::find_component(&self.pool, repo_row.id, &parsed.id, &parsed.version)
                .await
                .map_err(RepoError::from)?;
        match (import, existing) {
            (Some(options), Some(comp)) => {
                let stored = self.stored_package_sha256(&self.pool, comp.id).await?;
                if stored.as_deref() == Some(staged_nupkg.sha256.as_str()) {
                    return done(Published::Identical);
                }
                if !options.overwrite {
                    return done(Published::Conflict);
                }
                if options.dry_run {
                    return done(Published::Planned { replaces: true });
                }
            }
            (Some(options), None) if options.dry_run => {
                return done(Published::Planned { replaces: false });
            }
            (None, Some(_)) if !repo_row.allow_redeploy => {
                return Err(WriteError::Conflict {
                    id: parsed.original_id.clone(),
                    version: parsed.version.clone(),
                });
            }
            _ => {}
        }

        // Authorization succeeded: the staged bytes may now be promoted into
        // CAS (pending row + ingest lease + S3 object).
        let nupkg = self.cas.commit(staged_nupkg).await?;

        // 3. Store the derived nuspec as its own CAS blob (dedup applies).
        let nuspec_reader = Cursor::new(parsed.nuspec_bytes.clone());
        let nuspec = self
            .cas
            .store(nuspec_reader, max_upload_bytes)
            .await
            .map_err(|e| match e {
                forge_storage::CasError::TooLarge { .. } => {
                    // The nuspec is bounded by the parser; a too-large here means
                    // a corrupt parse, not a client overrun. Treat as invalid.
                    WriteError::InvalidPackage(crate::domain::FormatError::InvalidPackage(
                        "derived nuspec exceeds upload limit".into(),
                    ))
                }
                other => WriteError::from(other),
            })?;

        let nupkg_sha = nupkg.sha256.clone();
        let nupkg_size = i64::try_from(nupkg.size)
            .map_err(|_| RepoError::Storage("nupkg size overflow".into()))?;
        let nuspec_sha = nuspec.sha256.clone();
        let nuspec_size = i64::try_from(nuspec.size)
            .map_err(|_| RepoError::Storage("nuspec size overflow".into()))?;

        // 4. Commit references + component/asset rows in one transaction.
        let mut tx = self.pool.begin().await.map_err(RepoError::from)?;

        // Read the duplicate-check *inside* the transaction so it serializes
        // with the subsequent insert/redeploy write against concurrent pushes
        // of the same (id, version).
        let existing =
            component_dao::find_component(&mut *tx, repo_row.id, &parsed.id, &parsed.version)
                .await
                .map_err(RepoError::from)?;

        let nupkg_hash512 = nupkg.sha512_base64.clone();

        let mut component_id = existing.as_ref().map(|c| c.id);
        let replaced = match existing {
            Some(comp) => {
                match import {
                    // Stored concurrently since the check above.
                    Some(options) if !options.overwrite => {
                        let stored = self.stored_package_sha256(&mut *tx, comp.id).await?;
                        return done(if stored.as_deref() == Some(nupkg_sha.as_str()) {
                            Published::Identical
                        } else {
                            Published::Conflict
                        });
                    }
                    Some(_) => {}
                    None if !repo_row.allow_redeploy => {
                        // Duplicate and redeploy disabled → 409. Drop the tx; the
                        // pending blobs become orphans the reconciler cleans up.
                        return Err(WriteError::Conflict {
                            id: parsed.original_id.clone(),
                            version: parsed.version.clone(),
                        });
                    }
                    None => {}
                }
                // Replacing the bytes destroys the old ones: the caller must
                // also be allowed to delete this version (refusal drops the
                // tx like the 409 above).
                if let (Some((_, policy)), Some(context)) =
                    (self.publish_policy.as_ref(), publish_context.as_ref())
                {
                    policy.authorize_replace(context).await?;
                }
                // `false`: a concurrent hard delete removed the version
                // before this push could lock it, so it is a fresh insert.
                self.redeploy_in_tx(
                    &mut tx,
                    &comp,
                    &nupkg_sha,
                    nupkg.ingest_token,
                    nupkg_size,
                    &nupkg_hash512,
                    &nuspec_sha,
                    nuspec.ingest_token,
                    nuspec_size,
                    &parsed,
                )
                .await?
            }
            None => false,
        };

        let outcome = if replaced {
            Published::Replaced
        } else {
            let inserted = self
                .insert_new_in_tx(
                    &mut tx,
                    repo_row.id,
                    &nupkg_sha,
                    nupkg.ingest_token,
                    nupkg_size,
                    &nupkg_hash512,
                    &nuspec_sha,
                    nuspec.ingest_token,
                    nuspec_size,
                    &parsed,
                )
                .await;
            match inserted {
                Ok(id) => component_id = Some(id),
                // A concurrent first push of the same (id, version) won the
                // race: the duplicate check above could not lock a row that
                // did not exist yet, so the unique index decides. Report it as
                // the documented conflict, not an internal error.
                Err(WriteError::Repo(RepoError::Db(e))) if is_unique_violation(&e) => {
                    if import.is_some() {
                        return done(Published::Conflict);
                    }
                    return Err(WriteError::Conflict {
                        id: parsed.original_id.clone(),
                        version: parsed.version.clone(),
                    });
                }
                Err(e) => return Err(e),
            }
            Published::Created
        };

        if let (Some(id), Some(summary)) = (component_id, manifest_summary.as_ref()) {
            component_dao::set_manifest_summary(&mut *tx, id, summary)
                .await
                .map_err(RepoError::from)?;
        }
        if let (Some(id), Some(options)) = (component_id, import) {
            component_dao::set_imported_times(
                &mut tx,
                id,
                self.format.package_asset_path(),
                options.published_at,
                options.downloaded_at,
            )
            .await
            .map_err(RepoError::from)?;
        }

        if let (Some((_, policy)), Some(context)) =
            (self.publish_policy.as_ref(), publish_context.as_ref())
        {
            policy.record_in_transaction(context, &mut tx).await?;
        }

        tx.commit().await.map_err(RepoError::from)?;
        let principal = self
            .publish_policy
            .as_ref()
            .map_or_else(|| "internal".to_string(), |(p, _)| p.audit_label());
        match import {
            Some(options) => tracing::info!(
                target: "forge::audit",
                action = "import",
                repo,
                id = %parsed.id,
                version = %parsed.version,
                outcome = ?outcome,
                principal = %principal,
                source = %options.source,
                uploader = options.uploader.as_deref().unwrap_or(""),
                "package imported"
            ),
            None => tracing::info!(
                target: "forge::audit",
                repo,
                id = %parsed.id,
                version = %parsed.version,
                outcome = ?outcome,
                principal = %principal,
                "package published"
            ),
        }

        // 5. Invalidate the per-(repo,id) cache namespace.
        self.cache.invalidate_package(repo, &parsed.id).await;

        done(outcome)
    }

    /// Insert a brand-new component + `.nupkg`/`.nuspec` assets, increfing both
    /// blobs, all within `tx`.
    #[allow(clippy::too_many_arguments)]
    async fn insert_new_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: i64,
        nupkg_sha: &str,
        nupkg_ingest_token: uuid::Uuid,
        nupkg_size: i64,
        nupkg_hash512: &str,
        nuspec_sha: &str,
        nuspec_ingest_token: uuid::Uuid,
        nuspec_size: i64,
        parsed: &crate::ParsedUpload,
    ) -> Result<i64, WriteError> {
        blob_dao::commit_ingest_and_incref(tx, nupkg_sha, nupkg_ingest_token)
            .await
            .map_err(RepoError::from)?;
        // The nuspec may dedup onto the nupkg blob only if identical (it never
        // is), but a self-conflict is harmless: incref the (possibly same) row.
        blob_dao::commit_ingest_and_incref(tx, nuspec_sha, nuspec_ingest_token)
            .await
            .map_err(RepoError::from)?;

        let comp = component_dao::insert_component(
            &mut **tx,
            NewComponent {
                repository_id: repo_id,
                name: parsed.id.clone(),
                original_id: parsed.original_id.clone(),
                version: parsed.version.clone(),
                version_original: parsed.version_original.clone(),
                listed: parsed.listed,
            },
        )
        .await
        .map_err(RepoError::from)?;

        self.insert_assets_in_tx(
            tx,
            comp.id,
            nupkg_sha,
            nupkg_size,
            nupkg_hash512,
            nuspec_sha,
            nuspec_size,
        )
        .await?;
        Ok(comp.id)
    }

    /// Swap an existing component's `.nupkg`/`.nuspec` assets to new blobs:
    /// incref the new blobs, delete the old asset rows, decref the old blobs
    /// (enqueuing a deferred S3 delete if they hit zero), and re-insert the
    /// asset rows — all within `tx`. Idempotent re-push of identical bytes is a
    /// no-op swap (same sha → incref then decref cancels to a net zero change,
    /// leaving `ref_count` unchanged).
    #[allow(clippy::too_many_arguments)]
    async fn redeploy_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        comp: &forge_db::model::Component,
        nupkg_sha: &str,
        nupkg_ingest_token: uuid::Uuid,
        nupkg_size: i64,
        nupkg_hash512: &str,
        nuspec_sha: &str,
        nuspec_ingest_token: uuid::Uuid,
        nuspec_size: i64,
        parsed: &crate::ParsedUpload,
    ) -> Result<bool, WriteError> {
        // Lock the component row so concurrent redeploys serialize (NO advisory
        // locks — a plain row-level FOR UPDATE). A concurrent hard delete that
        // won the lock has removed the row: report that (`false`) before
        // touching any reference, so the caller inserts the version afresh.
        let locked = sqlx::query!(
            r#"SELECT id FROM component WHERE id = $1 FOR UPDATE"#,
            comp.id
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(RepoError::from)?;
        if locked.is_none() {
            return Ok(false);
        }

        // Incref the new blobs first.
        blob_dao::commit_ingest_and_incref(tx, nupkg_sha, nupkg_ingest_token)
            .await
            .map_err(RepoError::from)?;
        blob_dao::commit_ingest_and_incref(tx, nuspec_sha, nuspec_ingest_token)
            .await
            .map_err(RepoError::from)?;

        // Capture the old blob shas, delete the asset rows, decref the old blobs.
        // The `.nupkg`'s download counters carry over to the new row: a
        // redeploy is the same version, and retention and search
        // (`totalDownloads`) read them.
        let mut downloads = None;
        let package_path = self.format.package_asset_path();
        for path in [package_path, self.format.manifest_asset_path()] {
            if let Some(old) = asset_dao::find_asset(&mut **tx, comp.id, path)
                .await
                .map_err(RepoError::from)?
            {
                if path == package_path {
                    downloads = Some(
                        sqlx::query!(
                            r#"SELECT download_count, last_downloaded_at FROM asset WHERE id = $1"#,
                            old.id
                        )
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(RepoError::from)?,
                    );
                }
                sqlx::query!(r#"DELETE FROM asset WHERE id = $1"#, old.id)
                    .execute(&mut **tx)
                    .await
                    .map_err(RepoError::from)?;
                blob_dao::decref_and_maybe_enqueue_delete(tx, &old.blob_sha256, self.delete_grace)
                    .await
                    .map_err(RepoError::from)?;
            }
        }

        // Keep listed state in sync with the re-published package and bump the
        // original-casing fields in case they changed.
        sqlx::query!(
            r#"
            UPDATE component
            SET original_id = $2, version_original = $3, listed = $4, updated_at = now()
            WHERE id = $1
            "#,
            comp.id,
            parsed.original_id,
            parsed.version_original,
            parsed.listed,
        )
        .execute(&mut **tx)
        .await
        .map_err(RepoError::from)?;

        self.insert_assets_in_tx(
            tx,
            comp.id,
            nupkg_sha,
            nupkg_size,
            nupkg_hash512,
            nuspec_sha,
            nuspec_size,
        )
        .await?;
        if let Some(downloads) = downloads {
            sqlx::query!(
                r#"
                UPDATE asset SET download_count = $3, last_downloaded_at = $4
                WHERE component_id = $1 AND path = $2
                "#,
                comp.id,
                package_path,
                downloads.download_count,
                downloads.last_downloaded_at,
            )
            .execute(&mut **tx)
            .await
            .map_err(RepoError::from)?;
        }
        Ok(true)
    }

    /// Insert the package and manifest asset rows (the `.nupkg` and `.nuspec`
    /// for NuGet) for a component, at the format's asset paths.
    #[allow(clippy::too_many_arguments)]
    async fn insert_assets_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        component_id: i64,
        nupkg_sha: &str,
        nupkg_size: i64,
        nupkg_hash512: &str,
        nuspec_sha: &str,
        nuspec_size: i64,
    ) -> Result<(), WriteError> {
        // The nupkg's SHA-512 (base64), computed by the CAS during ingest, is
        // the NuGet `packageHash`.
        asset_dao::insert_asset(
            &mut **tx,
            NewAsset {
                component_id,
                path: self.format.package_asset_path().to_string(),
                content_type: self.format.package_content_type().to_string(),
                blob_sha256: nupkg_sha.to_string(),
                size: nupkg_size,
                sha512_base64: Some(nupkg_hash512.to_string()),
            },
        )
        .await
        .map_err(RepoError::from)?;

        asset_dao::insert_asset(
            &mut **tx,
            NewAsset {
                component_id,
                path: self.format.manifest_asset_path().to_string(),
                content_type: self.format.manifest_content_type().to_string(),
                blob_sha256: nuspec_sha.to_string(),
                size: nuspec_size,
                sha512_base64: None,
            },
        )
        .await
        .map_err(RepoError::from)?;

        Ok(())
    }

    /// Soft- or hard-delete a specific package version.
    ///
    /// * `hard == false` (unlist): flips `component.listed = false`. The version
    ///   stays downloadable by exact version and present in flat-container
    ///   enumeration; only search / "latest" views hide it.
    /// * `hard == true`: removes the component and **all** its assets, then
    ///   decrements each referenced blob's `ref_count` (enqueuing a deferred S3
    ///   delete when one reaches zero) — all in **one** transaction.
    ///
    /// Returns [`DeleteOutcome::NotFound`] when the version is unknown.
    pub async fn delete_component(
        &self,
        repo: &str,
        id: &str,
        version: &str,
        hard: bool,
    ) -> Result<DeleteOutcome, WriteError> {
        let repo_row = self.hosted_repo(repo).await?;
        let lower = self.format.lower_id(id);
        // A version that does not parse was never published: 404, as NuGet
        // clients expect for an unknown version, not 400.
        let Ok(norm_ver) = self.format.normalize_version(version) else {
            return Ok(DeleteOutcome::NotFound);
        };
        if !self.mutation_filter.allows(&lower) {
            return Ok(DeleteOutcome::NotFound);
        }

        if !hard {
            if !self
                .set_listed_recorded(repo_row.id, &lower, &norm_ver, false)
                .await?
            {
                return Ok(DeleteOutcome::NotFound);
            }
            self.cache.invalidate_package(repo, &lower).await;
            return Ok(DeleteOutcome::Unlisted);
        }

        // Hard delete: one transaction removing component + assets and decrefing
        // every blob the assets referenced. Begin the tx *first* and resolve the
        // component on the transaction connection so the lookup, the FOR UPDATE
        // lock, and the asset reads all see a consistent snapshot — otherwise a
        // concurrent redeploy could swap the asset blob references between the
        // read and the decref, leaking the redeployed blob and over-decrefing
        // the old one.
        let mut tx = self.pool.begin().await.map_err(RepoError::from)?;

        let Some(comp) = component_dao::find_component(&mut *tx, repo_row.id, &lower, &norm_ver)
            .await
            .map_err(RepoError::from)?
        else {
            return Ok(DeleteOutcome::NotFound);
        };

        // Lock the component row so any concurrent redeploy serializes behind
        // this hard delete (NO advisory locks — a plain row-level FOR UPDATE).
        // A concurrent delete that won the lock has already removed the row:
        // that is a plain not-found for this caller, not an internal error.
        let locked = sqlx::query!(
            r#"SELECT id FROM component WHERE id = $1 FOR UPDATE"#,
            comp.id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(RepoError::from)?;
        if locked.is_none() {
            return Ok(DeleteOutcome::NotFound);
        }

        let assets = asset_dao::assets_for_component(&mut *tx, comp.id)
            .await
            .map_err(RepoError::from)?;

        // Delete asset rows first (FK to component), decref their blobs.
        for asset in &assets {
            sqlx::query!(r#"DELETE FROM asset WHERE id = $1"#, asset.id)
                .execute(&mut *tx)
                .await
                .map_err(RepoError::from)?;
            blob_dao::decref_and_maybe_enqueue_delete(
                &mut tx,
                &asset.blob_sha256,
                self.delete_grace,
            )
            .await
            .map_err(RepoError::from)?;
        }

        component_dao::delete_component(&mut *tx, repo_row.id, &lower, &norm_ver)
            .await
            .map_err(RepoError::from)?;

        self.record_mutation(&mut tx, PackageMutation::Delete, &lower, &norm_ver)
            .await?;
        tx.commit().await.map_err(RepoError::from)?;

        self.cache.invalidate_package(repo, &lower).await;
        Ok(DeleteOutcome::Deleted)
    }

    /// Set `listed` on a version in a transaction that also runs the publish
    /// policy's fence and ledger ([`PublishPolicy::record_in_transaction`]).
    /// Returns whether the version exists.
    async fn set_listed_recorded(
        &self,
        repo_id: i64,
        lower: &str,
        version: &str,
        listed: bool,
    ) -> Result<bool, WriteError> {
        let mut tx = self.pool.begin().await.map_err(RepoError::from)?;
        let updated = component_dao::set_listed(&mut *tx, repo_id, lower, version, listed)
            .await
            .map_err(RepoError::from)?;
        if !updated {
            return Ok(false);
        }
        let action = if listed {
            PackageMutation::Relist
        } else {
            PackageMutation::Unlist
        };
        self.record_mutation(&mut tx, action, lower, version)
            .await?;
        tx.commit().await.map_err(RepoError::from)?;
        Ok(true)
    }

    /// Run the request's publish policy hook for a non-publish mutation on its
    /// open transaction (a no-op without a policy). A workload principal is
    /// fenced against its realm's current config and recorded in the ledger,
    /// exactly as for a publish.
    async fn record_mutation(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        action: PackageMutation,
        lower: &str,
        version: &str,
    ) -> Result<(), WriteError> {
        let Some((principal, policy)) = self.publish_policy.as_ref() else {
            return Ok(());
        };
        let context = PublishAuthorizationContext {
            principal: *principal,
            action,
            package_id: lower.to_string(),
            package_version: version.to_string(),
        };
        policy.record_in_transaction(&context, tx).await
    }

    /// Relist a previously unlisted version. Returns whether a row was updated.
    pub async fn relist(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<DeleteOutcome, WriteError> {
        let repo_row = self.hosted_repo(repo).await?;
        let lower = self.format.lower_id(id);
        // Unparsable: never published (404), as in `delete_component`.
        let Ok(norm_ver) = self.format.normalize_version(version) else {
            return Ok(DeleteOutcome::NotFound);
        };
        if !self.mutation_filter.allows(&lower) {
            return Ok(DeleteOutcome::NotFound);
        }
        if !self
            .set_listed_recorded(repo_row.id, &lower, &norm_ver, true)
            .await?
        {
            return Ok(DeleteOutcome::NotFound);
        }
        self.cache.invalidate_package(repo, &lower).await;
        Ok(DeleteOutcome::Relisted)
    }
}

#[async_trait]
impl crate::repo::RepoWriteOps for HostedWrite {
    async fn store_upload(
        &self,
        repo: &str,
        reader: crate::repo::UploadReader,
        max_upload_bytes: u64,
    ) -> Result<PublishOutcome, WriteError> {
        // Delegate to the inherent generic method over the boxed reader.
        HostedWrite::store_upload(self, repo, reader, max_upload_bytes).await
    }

    async fn delete_component(
        &self,
        repo: &str,
        id: &str,
        version: &str,
        hard: bool,
    ) -> Result<DeleteOutcome, WriteError> {
        HostedWrite::delete_component(self, repo, id, version, hard).await
    }

    async fn relist(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<DeleteOutcome, WriteError> {
        HostedWrite::relist(self, repo, id, version).await
    }
}

/// What [`HostedWrite::publish_staged`] did with a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Published {
    Created,
    Replaced,
    /// Import only: the version exists with the same bytes.
    Identical,
    /// Import only: the version exists with other bytes and stays.
    Conflict,
    /// Import dry run only: what would be stored.
    Planned {
        replaces: bool,
    },
}

/// Whether a `sqlx::Error` is a Postgres unique violation (SQLSTATE 23505).
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
