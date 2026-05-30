//! Integration tests for hosted-repository write ops (Phase 7, Task 7.1 / 7.2).
//!
//! Drives [`forge_core::repo::hosted::HostedWrite`] against real Postgres +
//! versitygw containers: publishing the `sample.lib.1.0.0.nupkg` fixture,
//! duplicate handling (409 vs. redeploy swap with refcount accounting), and
//! soft/hard delete + relist. The read side ([`HostedRepo`]) is used to assert
//! visibility (flat-container enumeration includes unlisted; search hides it).

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use forge_core::repo::hosted::{BlobFetch, HostedRepo, HostedWrite};
use forge_core::repo::{
    CacheInvalidator, DeleteOutcome, NoopCacheInvalidator, PublishOutcome, RepoError, RepoReadOps,
    SearchParams, WriteError, NUPKG_ASSET_PATH, NUSPEC_ASSET_PATH,
};
use forge_db::repository_dao::{self, NewRepository};
use forge_nuget::NugetFormat;
use forge_storage::{BlobStore, Cas};
use sqlx::PgPool;
use tokio::sync::Mutex;

const MAX_UPLOAD: u64 = 64 * 1024 * 1024;

/// Build a minimal valid `.nupkg` (OPC zip with a `*.nuspec`) for `id@version`.
///
/// Refcount-sensitive tests use a **unique** id so their content-addressed blob
/// is not shared with any other test, keeping `ref_count` assertions
/// deterministic under parallel execution against the shared DB/bucket.
fn make_nupkg(id: &str, version: &str) -> Vec<u8> {
    make_nupkg_with(id, version, "generated test package")
}

/// A byte-distinct variant of [`make_nupkg`] (different description) that still
/// parses to the same `id@version`. Used to exercise the redeploy blob swap.
fn make_nupkg_variant(id: &str, version: &str) -> Vec<u8> {
    make_nupkg_with(id, version, "redeployed test package payload")
}

fn make_nupkg_with(id: &str, version: &str, description: &str) -> Vec<u8> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    let nuspec = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <authors>test</authors>
    <description>{description}</description>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="[13.0.1, )" />
      </group>
    </dependencies>
  </metadata>
</package>"#
    );
    let content_types = r#"<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="nuspec" ContentType="application/octet" /></Types>"#;

    let buf = Vec::new();
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(buf));
    let opts = SimpleFileOptions::default();
    zw.start_file("[Content_Types].xml", opts).unwrap();
    zw.write_all(content_types.as_bytes()).unwrap();
    zw.start_file(format!("{id}.nuspec"), opts).unwrap();
    zw.write_all(nuspec.as_bytes()).unwrap();
    zw.finish().unwrap().into_inner()
}

/// A unique package id for a test, so its blob is not shared.
fn unique_id() -> String {
    format!("Test.Pkg{}", common::unique())
}

/// A `BlobFetch` over a real versitygw [`BlobStore`], for read-side assertions.
struct StoreFetch(BlobStore);

#[async_trait]
impl BlobFetch for StoreFetch {
    async fn fetch_all(&self, s3_key: &str) -> Result<Vec<u8>, RepoError> {
        let body = self
            .0
            .get(s3_key)
            .await
            .map_err(|e| RepoError::Storage(e.to_string()))?;
        let bytes = body
            .collect()
            .await
            .map_err(|e| RepoError::Storage(e.to_string()))?
            .into_bytes();
        Ok(bytes.to_vec())
    }
}

/// Records the `(repo, id)` invalidations the write path requested.
#[derive(Default)]
struct RecordingCache(Mutex<Vec<(String, String)>>);

#[async_trait]
impl CacheInvalidator for RecordingCache {
    async fn invalidate_package(&self, repo: &str, lower_id: &str) {
        self.0
            .lock()
            .await
            .push((repo.to_string(), lower_id.to_string()));
    }
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../fixtures/nuget");
    p.push(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

async fn writer(pool: &PgPool, cas: Cas, cache: Arc<dyn CacheInvalidator>) -> HostedWrite {
    HostedWrite::new(
        pool.clone(),
        Arc::new(NugetFormat::new()),
        cas,
        cache,
        Duration::seconds(0),
    )
}

fn reader(pool: &PgPool, store: BlobStore) -> HostedRepo {
    HostedRepo::new(
        pool.clone(),
        Arc::new(NugetFormat::new()),
        Arc::new(StoreFetch(store)),
    )
}

async fn seed_repo(pool: &PgPool, allow_redeploy: bool) -> String {
    let name = format!("hosted-w-{}", common::unique());
    let mut new = NewRepository::hosted(name.clone());
    new.allow_redeploy = allow_redeploy;
    repository_dao::insert_repository(pool, new)
        .await
        .expect("insert_repository");
    name
}

async fn blob_ref_count(pool: &PgPool, sha: &str) -> Option<i64> {
    forge_db::blob_dao::get_blob(pool, sha)
        .await
        .unwrap()
        .map(|b| b.ref_count)
}

#[tokio::test]
async fn publish_creates_component_assets_and_invalidates_cache() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let cache = Arc::new(RecordingCache::default());
    let repo = seed_repo(&pool, false).await;

    let w = writer(&pool, cas, cache.clone()).await;
    let outcome = w
        .store_upload(
            &repo,
            &fixture_bytes("sample.lib.1.0.0.nupkg")[..],
            MAX_UPLOAD,
        )
        .await
        .expect("publish");
    assert_eq!(outcome, PublishOutcome::Created);

    // Cache invalidated for (repo, lowercased id).
    let calls = cache.0.lock().await.clone();
    assert_eq!(calls, vec![(repo.clone(), "sample.lib".to_string())]);

    // Read side: flat-container enumeration + nupkg byte round-trip.
    let r = reader(&pool, store.clone());
    let versions = r.list_versions(&repo, "sample.lib").await.unwrap();
    let vs: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
    assert_eq!(vs, vec!["1.2.3"]); // 1.02.3 normalizes to 1.2.3

    let loc = r
        .resolve_nupkg(&repo, "sample.lib", "1.2.3")
        .await
        .unwrap()
        .expect("nupkg present");
    assert_eq!(
        loc.size as usize,
        fixture_bytes("sample.lib.1.0.0.nupkg").len()
    );

    // Restore the original bytes via the flat container.
    let fetched = StoreFetch(store).fetch_all(&loc.blob_s3_key).await.unwrap();
    assert_eq!(fetched, fixture_bytes("sample.lib.1.0.0.nupkg"));

    // packageHash (SHA-512 base64) is recorded on the registration entry.
    let reg = r.registration(&repo, "sample.lib").await.unwrap();
    assert_eq!(reg.len(), 1);
    assert!(reg[0].package_hash_sha512_base64.is_some());
    // Derived nuspec is stored and served.
    let nuspec = r
        .resolve_nuspec(&repo, "sample.lib", "1.2.3")
        .await
        .unwrap()
        .expect("nuspec present");
    assert!(String::from_utf8(nuspec)
        .unwrap()
        .contains("<id>Sample.Lib</id>"));
}

#[tokio::test]
async fn duplicate_without_redeploy_is_conflict() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, false).await;

    let w = writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await;
    w.store_upload(
        &repo,
        &fixture_bytes("sample.lib.1.0.0.nupkg")[..],
        MAX_UPLOAD,
    )
    .await
    .expect("first publish");

    let err = w
        .store_upload(
            &repo,
            &fixture_bytes("sample.lib.1.0.0.nupkg")[..],
            MAX_UPLOAD,
        )
        .await
        .expect_err("duplicate must conflict");
    assert!(matches!(err, WriteError::Conflict { .. }));
}

#[tokio::test]
async fn too_large_upload_is_rejected() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, false).await;

    let w = writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await;
    let err = w
        .store_upload(&repo, &fixture_bytes("sample.lib.1.0.0.nupkg")[..], 8)
        .await
        .expect_err("must reject oversized upload");
    assert!(matches!(err, WriteError::TooLarge { limit: 8 }));
}

#[tokio::test]
async fn redeploy_swaps_asset_and_adjusts_refcounts() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, true).await;

    let w = writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await;

    // A unique package so the content-addressed blobs are not shared with other
    // tests; that lets us assert *exact* ref counts.
    let id = unique_id();
    let lower = id.to_lowercase();

    // Publish v1.
    w.store_upload(&repo, &make_nupkg(&id, "1.0.0")[..], MAX_UPLOAD)
        .await
        .expect("publish v1");

    let repo_id = repository_dao::find_repository_by_name(&pool, &repo)
        .await
        .unwrap()
        .unwrap()
        .id;
    let comp = forge_db::component_dao::find_component(&pool, repo_id, &lower, "1.0.0")
        .await
        .unwrap()
        .unwrap();
    let v1_nupkg = forge_db::asset_dao::find_asset(&pool, comp.id, NUPKG_ASSET_PATH)
        .await
        .unwrap()
        .unwrap();
    let v1_nuspec = forge_db::asset_dao::find_asset(&pool, comp.id, NUSPEC_ASSET_PATH)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blob_ref_count(&pool, &v1_nupkg.blob_sha256).await, Some(1));

    // Redeploy with *different* bytes (same id/version, distinct nuspec body) →
    // asset swapped to the new blob; old blob dereferenced to zero (+ deferred
    // delete enqueued), new blob at one.
    let v2_bytes = make_nupkg_variant(&id, "1.0.0");
    let outcome = w
        .store_upload(&repo, &v2_bytes[..], MAX_UPLOAD)
        .await
        .expect("redeploy");
    assert_eq!(outcome, PublishOutcome::Replaced);

    let v2_nupkg = forge_db::asset_dao::find_asset(&pool, comp.id, NUPKG_ASSET_PATH)
        .await
        .unwrap()
        .unwrap();
    // Asset now points at a *different* blob.
    assert_ne!(v2_nupkg.blob_sha256, v1_nupkg.blob_sha256);
    // Old blob dereferenced to zero, new blob at one.
    assert_eq!(blob_ref_count(&pool, &v1_nupkg.blob_sha256).await, Some(0));
    assert_eq!(blob_ref_count(&pool, &v2_nupkg.blob_sha256).await, Some(1));
    // Old nuspec also swapped (different description → different blob).
    let v2_nuspec = forge_db::asset_dao::find_asset(&pool, comp.id, NUSPEC_ASSET_PATH)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(v2_nuspec.blob_sha256, v1_nuspec.blob_sha256);
    assert_eq!(blob_ref_count(&pool, &v1_nuspec.blob_sha256).await, Some(0));

    // Deferred delete enqueued for the dropped old nupkg blob.
    let pending: i64 = sqlx::query_scalar!(
        r#"SELECT count(*) AS "c!" FROM blob_outbox WHERE sha256 = $1 AND processed_at IS NULL"#,
        v1_nupkg.blob_sha256
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending, 1);

    // Exactly one asset row per path (swap deleted + re-inserted, no dupes).
    let assets = forge_db::asset_dao::assets_for_component(&pool, comp.id)
        .await
        .unwrap();
    assert_eq!(assets.len(), 2);
}

#[tokio::test]
async fn unlist_hides_from_search_but_keeps_downloadable_and_relist_restores() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, false).await;

    let w = writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await;
    w.store_upload(
        &repo,
        &fixture_bytes("sample.lib.1.0.0.nupkg")[..],
        MAX_UPLOAD,
    )
    .await
    .expect("publish");

    let r = reader(&pool, store.clone());

    // Listed initially: appears in search.
    let res = r.search(&repo, &SearchParams::default()).await.unwrap();
    assert_eq!(res.total_hits, 1);

    // Unlist (soft delete).
    let out = w
        .delete_component(&repo, "Sample.Lib", "1.2.3", false)
        .await
        .unwrap();
    assert_eq!(out, DeleteOutcome::Unlisted);

    // Hidden from search...
    let res = r.search(&repo, &SearchParams::default()).await.unwrap();
    assert_eq!(res.total_hits, 0);
    // ...still in flat-container enumeration...
    let versions = r.list_versions(&repo, "sample.lib").await.unwrap();
    assert_eq!(versions.len(), 1);
    assert!(!versions[0].listed);
    // ...and still downloadable by exact version.
    assert!(r
        .resolve_nupkg(&repo, "sample.lib", "1.2.3")
        .await
        .unwrap()
        .is_some());

    // Relisting an unknown version → NotFound.
    let nf = w.relist(&repo, "Sample.Lib", "9.9.9").await.unwrap();
    assert_eq!(nf, DeleteOutcome::NotFound);

    // Relist restores search visibility.
    let out = w.relist(&repo, "Sample.Lib", "1.2.3").await.unwrap();
    assert_eq!(out, DeleteOutcome::Relisted);
    let res = r.search(&repo, &SearchParams::default()).await.unwrap();
    assert_eq!(res.total_hits, 1);
}

#[tokio::test]
async fn hard_delete_removes_rows_and_decrefs_blobs() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, false).await;

    let w = writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await;
    let id = unique_id();
    let lower = id.to_lowercase();
    w.store_upload(&repo, &make_nupkg(&id, "1.0.0")[..], MAX_UPLOAD)
        .await
        .expect("publish");

    let repo_id = repository_dao::find_repository_by_name(&pool, &repo)
        .await
        .unwrap()
        .unwrap()
        .id;
    let comp = forge_db::component_dao::find_component(&pool, repo_id, &lower, "1.0.0")
        .await
        .unwrap()
        .unwrap();
    let nupkg = forge_db::asset_dao::find_asset(&pool, comp.id, NUPKG_ASSET_PATH)
        .await
        .unwrap()
        .unwrap();
    // Unique package → this is the only reference.
    assert_eq!(blob_ref_count(&pool, &nupkg.blob_sha256).await, Some(1));

    let out = w.delete_component(&repo, &id, "1.0.0", true).await.unwrap();
    assert_eq!(out, DeleteOutcome::Deleted);

    // Component gone, blob dereferenced to zero, deferred delete enqueued.
    assert!(
        forge_db::component_dao::find_component(&pool, repo_id, &lower, "1.0.0")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(blob_ref_count(&pool, &nupkg.blob_sha256).await, Some(0));

    let pending: i64 = sqlx::query_scalar!(
        r#"SELECT count(*) AS "c!" FROM blob_outbox WHERE sha256 = $1 AND processed_at IS NULL"#,
        nupkg.blob_sha256
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending, 1);

    // Deleting an unknown version → NotFound.
    let nf = w.delete_component(&repo, &id, "1.0.0", true).await.unwrap();
    assert_eq!(nf, DeleteOutcome::NotFound);
}
