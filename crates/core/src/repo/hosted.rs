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

use crate::format::Format;
use crate::repo::{
    CacheInvalidator, DeleteOutcome, NupkgLocation, PublishOutcome, RegistrationEntry, RepoError,
    RepoReadOps, SearchHit, SearchParams, SearchResult, VersionEntry, WriteError, NUPKG_ASSET_PATH,
    NUPKG_CONTENT_TYPE, NUSPEC_ASSET_PATH, NUSPEC_CONTENT_TYPE,
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
        }
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
    /// 1. Stream the bytes through [`Cas::store`], enforcing `max_upload_bytes`
    ///    (a [`forge_storage::CasError::TooLarge`] surfaces as
    ///    [`WriteError::TooLarge`] for the 413 mapping).
    /// 2. Parse the temp `.nupkg` into a [`ParsedUpload`](crate::ParsedUpload)
    ///    via the repository [`Format`]; a parse failure is
    ///    [`WriteError::InvalidPackage`].
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

        // 1. Ingest the .nupkg through the CAS (temp file kept alive for parse).
        let nupkg = self.cas.store(reader, max_upload_bytes).await?;

        // 2. Parse the package from the temp file. parse_upload is sync; the
        //    temp file is small enough that a blocking read is acceptable here.
        let parsed = {
            let mut file = std::fs::File::open(&nupkg.temp_path).map_err(|e| {
                WriteError::Repo(RepoError::Storage(format!("reopen temp upload: {e}")))
            })?;
            self.format.parse_upload(&mut file)?
        };

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

        let existing =
            component_dao::find_component(&self.pool, repo_row.id, &parsed.id, &parsed.version)
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
                nupkg_size,
                &nupkg_hash512,
                &nuspec_sha,
                nuspec_size,
                &parsed,
            )
            .await?;
            PublishOutcome::Replaced
        } else {
            self.insert_new_in_tx(
                &mut tx,
                repo_row.id,
                &nupkg_sha,
                nupkg_size,
                &nupkg_hash512,
                &nuspec_sha,
                nuspec_size,
                &parsed,
            )
            .await?;
            PublishOutcome::Created
        };

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
        nupkg_size: i64,
        nupkg_hash512: &str,
        nuspec_sha: &str,
        nuspec_size: i64,
        parsed: &crate::ParsedUpload,
    ) -> Result<(), WriteError> {
        blob_dao::commit_and_incref(tx, nupkg_sha)
            .await
            .map_err(RepoError::from)?;
        // The nuspec may dedup onto the nupkg blob only if identical (it never
        // is), but a self-conflict is harmless: incref the (possibly same) row.
        blob_dao::commit_and_incref(tx, nuspec_sha)
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
        nupkg_size: i64,
        nupkg_hash512: &str,
        nuspec_sha: &str,
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
        blob_dao::commit_and_incref(tx, nupkg_sha)
            .await
            .map_err(RepoError::from)?;
        blob_dao::commit_and_incref(tx, nuspec_sha)
            .await
            .map_err(RepoError::from)?;

        // Capture the old blob shas, delete the asset rows, decref the old blobs.
        for path in [NUPKG_ASSET_PATH, NUSPEC_ASSET_PATH] {
            if let Some(old) = asset_dao::find_asset(&self.pool, comp.id, path)
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
        // every blob the assets referenced.
        let Some(comp) = component_dao::find_component(&self.pool, repo_row.id, &lower, &norm_ver)
            .await
            .map_err(RepoError::from)?
        else {
            return Ok(DeleteOutcome::NotFound);
        };

        let assets = asset_dao::assets_for_component(&self.pool, comp.id)
            .await
            .map_err(RepoError::from)?;

        let mut tx = self.pool.begin().await.map_err(RepoError::from)?;

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
