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
use crate::repo::{
    CacheInvalidator, DeleteOutcome, NupkgLocation, PublishAuthorizationContext, PublishOutcome,
    PublishPolicy, RegistrationEntry, RepoError, RepoReadOps, SearchHit, SearchParams, SearchQuery,
    SearchResult, VersionEntry, WriteError, NUPKG_ASSET_PATH, NUPKG_CONTENT_TYPE,
    NUSPEC_ASSET_PATH, NUSPEC_CONTENT_TYPE,
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

    /// Build one exact search result while applying package authorization
    /// before paging. Hosted search currently loads its small Slice-1 corpus in
    /// one query, so doing this here avoids reloading that corpus once per
    /// selector page. With `enrich`, the returned page carries manifests and
    /// download totals ([`Self::enrich_hits`]); a group searches its members
    /// without and enriches only its own final page.
    async fn search_filtered(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
        enrich: bool,
    ) -> Result<SearchResult, RepoError> {
        let repo_id = self.repo_id(repo).await?;
        let query = SearchQuery::parse(&params.q);
        let comps = match query.prefilter() {
            Some(sub) => {
                component_dao::list_components_for_repo_matching(&self.pool, repo_id, sub).await?
            }
            None => component_dao::list_components_for_repo(&self.pool, repo_id).await?,
        };

        use std::collections::BTreeMap;
        let mut by_id: BTreeMap<String, Vec<forge_db::model::Component>> = BTreeMap::new();
        for c in comps {
            if !filter.allows(&c.name) || !query.matches(&c.name) {
                continue;
            }
            by_id.entry(c.name.clone()).or_default().push(c);
        }

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
            let latest = versions.last().expect("non-empty versions");
            hits.push(SearchHit {
                original_id: latest.original_id.clone(),
                latest_version: latest.version.clone(),
                versions,
                ..Default::default()
            });
        }

        hits.sort_by(|a, b| {
            a.original_id
                .to_lowercase()
                .cmp(&b.original_id.to_lowercase())
        });
        let total_hits = hits.len();
        let mut hits: Vec<SearchHit> = hits
            .into_iter()
            .skip(params.skip.min(total_hits))
            .take(params.effective_take())
            .collect();
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
        let wanted: Vec<(String, String)> = names
            .iter()
            .cloned()
            .zip(hits.iter().map(|h| h.latest_version.clone()))
            .collect();
        let manifests: Vec<Option<Vec<u8>>> = futures_util::stream::iter(wanted)
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
        for ((hit, name), manifest) in hits.iter_mut().zip(&names).zip(manifests) {
            hit.total_downloads = Some(totals.get(name).copied().unwrap_or(0));
            hit.nuspec_bytes = manifest;
        }
        Ok(())
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
            asset_dao::find_asset(&self.pool, component_id, NUSPEC_ASSET_PATH).await?
        else {
            return Ok(None);
        };
        match forge_db::blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? {
            Some(blob) => Ok(Some(self.blobs.fetch_all(&blob.s3_key).await?)),
            None => Ok(None),
        }
    }
}

/// A normalized NuGet version is prerelease iff it carries a `-label` suffix.
fn is_prerelease(version: &str) -> bool {
    version.contains('-')
}

/// Fire a best-effort download-tracking bump for a served hosted `.nupkg`,
/// off the response hot path (slice 12.1 §3.7).
///
/// Spawned so the tracking write — `asset.download_count` /
/// `last_downloaded_at` + `component.last_downloaded_at` — never blocks the
/// download response and a failure is logged rather than propagated. The data
/// is non-authoritative (only feeds retention's download-sensitive criteria),
/// so an occasional lost increment under load is acceptable.
fn spawn_download_bump(pool: PgPool, asset_id: i64, component_id: i64) {
    tokio::spawn(async move {
        if let Err(e) =
            forge_db::download_dao::bump_hosted_download(&pool, asset_id, component_id).await
        {
            tracing::warn!(error = %e, asset_id, component_id, "download tracking bump failed");
        }
    });
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

        // Download tracking (slice 12.1 §3.7): best-effort, off the hot path.
        // A resolved `.nupkg` is a download; bump asynchronously so a tracking
        // write never blocks (or fails) the response. Non-authoritative —
        // failures are logged, not propagated.
        spawn_download_bump(self.pool.clone(), asset.id, comp.id);

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

        // Per-version lookups (packageHash + stored nuspec for dependency
        // extraction by the format layer) run with bounded concurrency so a
        // package with hundreds of versions does not serialize hundreds of
        // S3 round-trips.
        use futures_util::StreamExt;
        futures_util::stream::iter(comps.into_iter().map(|c| async move {
            // The nupkg asset carries the SHA-512 used as packageHash.
            let nupkg = asset_dao::find_asset(&self.pool, c.id, NUPKG_ASSET_PATH).await?;
            let package_hash_sha512_base64 = nupkg.and_then(|a| a.sha512_base64);
            let nuspec_bytes = self.nuspec_of_component(c.id).await?;
            Ok::<_, RepoError>(RegistrationEntry {
                original_id: c.original_id,
                version: c.version,
                listed: c.listed,
                package_hash_sha512_base64,
                nuspec_bytes,
                published: Some(c.created_at),
            })
        }))
        .buffered(16)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect()
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
    /// Pipeline (spec §6/§7, plan 7.1):
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

        // 2. Parse the package from the temp file. parse_upload is sync and a
        //    package may be hundreds of MiB, so it runs on the blocking pool.
        let parsed = {
            let format = self.format.clone();
            let path = staged_nupkg.temp_path.to_path_buf();
            tokio::task::spawn_blocking(move || {
                let mut file = std::fs::File::open(&path).map_err(|e| {
                    WriteError::Repo(RepoError::Storage(format!("reopen temp upload: {e}")))
                })?;
                format.parse_upload(&mut file).map_err(WriteError::from)
            })
            .await
            .map_err(|e| WriteError::Repo(RepoError::Storage(format!("parse upload: {e}"))))??
        };

        let publish_context =
            self.publish_policy
                .as_ref()
                .map(|(principal, _)| PublishAuthorizationContext {
                    principal: *principal,
                    package_id: parsed.id.clone(),
                    package_version: parsed.version.clone(),
                });
        if let (Some((_, policy)), Some(context)) =
            (self.publish_policy.as_ref(), publish_context.as_ref())
        {
            policy.authorize(context).await?;
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

        let outcome = if let Some(comp) = existing {
            if !repo_row.allow_redeploy {
                // Duplicate and redeploy disabled → 409. Drop the tx; the
                // pending blobs become orphans the reconciler cleans up.
                return Err(WriteError::Conflict {
                    id: parsed.original_id.clone(),
                    version: parsed.version.clone(),
                });
            }
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
            .await?;
            PublishOutcome::Replaced
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
                Ok(()) => {}
                // A concurrent first push of the same (id, version) won the
                // race: the duplicate check above could not lock a row that
                // did not exist yet, so the unique index decides. Report it as
                // the documented conflict, not an internal error.
                Err(WriteError::Repo(RepoError::Db(e))) if is_unique_violation(&e) => {
                    return Err(WriteError::Conflict {
                        id: parsed.original_id.clone(),
                        version: parsed.version.clone(),
                    });
                }
                Err(e) => return Err(e),
            }
            PublishOutcome::Created
        };

        if let (Some((_, policy)), Some(context)) =
            (self.publish_policy.as_ref(), publish_context.as_ref())
        {
            policy.record_in_transaction(context, &mut tx).await?;
        }

        tx.commit().await.map_err(RepoError::from)?;

        // 5. Invalidate the per-(repo,id) cache namespace.
        self.cache.invalidate_package(repo, &parsed.id).await;

        Ok(outcome)
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
    ) -> Result<(), WriteError> {
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
        .await
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
    ) -> Result<(), WriteError> {
        // Lock the component row so concurrent redeploys serialize (NO advisory
        // locks — a plain row-level FOR UPDATE).
        sqlx::query!(
            r#"SELECT id FROM component WHERE id = $1 FOR UPDATE"#,
            comp.id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(RepoError::from)?;

        // Incref the new blobs first.
        blob_dao::commit_ingest_and_incref(tx, nupkg_sha, nupkg_ingest_token)
            .await
            .map_err(RepoError::from)?;
        blob_dao::commit_ingest_and_incref(tx, nuspec_sha, nuspec_ingest_token)
            .await
            .map_err(RepoError::from)?;

        // Capture the old blob shas, delete the asset rows, decref the old blobs.
        for path in [NUPKG_ASSET_PATH, NUSPEC_ASSET_PATH] {
            if let Some(old) = asset_dao::find_asset(&mut **tx, comp.id, path)
                .await
                .map_err(RepoError::from)?
            {
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
        .await
    }

    /// Insert the canonical `.nupkg` and `.nuspec` asset rows for a component.
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
                path: NUPKG_ASSET_PATH.to_string(),
                content_type: NUPKG_CONTENT_TYPE.to_string(),
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
                path: NUSPEC_ASSET_PATH.to_string(),
                content_type: NUSPEC_CONTENT_TYPE.to_string(),
                blob_sha256: nuspec_sha.to_string(),
                size: nuspec_size,
                sha512_base64: None,
            },
        )
        .await
        .map_err(RepoError::from)?;

        Ok(())
    }

    /// Soft- or hard-delete a specific package version (plan 7.2 / A12).
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
        let norm_ver = self.format.normalize_version(version)?;
        if !self.mutation_filter.allows(&lower) {
            return Ok(DeleteOutcome::NotFound);
        }

        if !hard {
            let updated =
                component_dao::set_listed(&self.pool, repo_row.id, &lower, &norm_ver, false)
                    .await
                    .map_err(RepoError::from)?;
            if !updated {
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
        sqlx::query!(
            r#"SELECT id FROM component WHERE id = $1 FOR UPDATE"#,
            comp.id
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(RepoError::from)?;

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

        tx.commit().await.map_err(RepoError::from)?;

        self.cache.invalidate_package(repo, &lower).await;
        Ok(DeleteOutcome::Deleted)
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
        let norm_ver = self.format.normalize_version(version)?;
        if !self.mutation_filter.allows(&lower) {
            return Ok(DeleteOutcome::NotFound);
        }
        let updated = component_dao::set_listed(&self.pool, repo_row.id, &lower, &norm_ver, true)
            .await
            .map_err(RepoError::from)?;
        if !updated {
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

/// Whether a `sqlx::Error` is a Postgres unique violation (SQLSTATE 23505).
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
