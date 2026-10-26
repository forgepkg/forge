//! Integration tests for hosted-repository write ops.
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
use forge_core::repo::downloads::DownloadTally;
use forge_core::repo::hosted::{BlobFetch, HostedRepo, HostedWrite};
use forge_core::repo::{
    CacheInvalidator, DeleteOutcome, NoopCacheInvalidator, PublishOutcome, RepoError, RepoReadOps,
    SearchParams, WriteError, NUPKG_ASSET_PATH, NUSPEC_ASSET_PATH,
};
use forge_db::repository_dao::{self, NewRepository};
use forge_storage::{BlobStore, Cas};
use sqlx::PgPool;
use tokio::sync::Mutex;

/// NuGet, the built-in format plugin, as the `Format` the repository code
/// works with.
fn nuget() -> forge_plugin::PluginFormat {
    let plugin = forge_plugin::Plugin::builtin(forge_format_nuget::Nuget::default());
    forge_plugin::PluginFormat::new(&plugin)
}

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
    async fn fetch_all(&self, blob: &forge_db::model::Blob) -> Result<Vec<u8>, RepoError> {
        self.fetch_key(&blob.s3_key).await
    }
}

impl StoreFetch {
    async fn fetch_key(&self, s3_key: &str) -> Result<Vec<u8>, RepoError> {
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
        Arc::new(nuget()),
        cas,
        cache,
        Duration::seconds(0),
    )
}

fn reader(pool: &PgPool, store: BlobStore) -> HostedRepo {
    HostedRepo::new(pool.clone(), Arc::new(nuget()), Arc::new(StoreFetch(store)))
        // Downloads are written in batches; write them soon in tests.
        .with_download_tally(DownloadTally::with_interval(
            pool.clone(),
            std::time::Duration::from_millis(20),
        ))
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

    // The manifest summary is stored with the version at publish, so metadata
    // reads never fetch and re-parse the manifest.
    let summary: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT c.manifest_summary FROM component c JOIN repository r ON r.id = c.repository_id \
         WHERE r.name = $1 AND c.name = 'sample.lib'",
    )
    .bind(&repo)
    .fetch_one(&pool)
    .await
    .unwrap();
    let summary = summary.expect("summary stored at publish");
    assert!(summary["metadata"].is_object(), "{summary}");

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
    let fetched = StoreFetch(store).fetch_key(&loc.blob_s3_key).await.unwrap();
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

    // #81: a duplicate with other bytes is refused before its blob is stored.
    // (Looked up by content hash: other tests add blobs concurrently.)
    let id = unique_id();
    let first = make_nupkg(&id, "1.0.0");
    let duplicate = make_nupkg_variant(&id, "1.0.0");
    let stored = |bytes: Vec<u8>| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM blob WHERE sha256 = encode(sha256($1), 'hex')",
            )
            .bind(bytes)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    w.store_upload(&repo, &first[..], MAX_UPLOAD)
        .await
        .expect("publish");
    assert_eq!(
        stored(first).await,
        1,
        "a published package's blob is found"
    );
    let err = w
        .store_upload(&repo, &duplicate[..], MAX_UPLOAD)
        .await
        .expect_err("duplicate must conflict");
    assert!(matches!(err, WriteError::Conflict { .. }));
    assert_eq!(stored(duplicate).await, 0, "nothing reached the blob store");
}

/// Simultaneous *first* pushes of one (id, version): the duplicate check cannot
/// lock a row that does not exist yet, so the unique index decides — and the
/// losers must see the documented 409 conflict, never an internal error.
#[tokio::test]
async fn concurrent_first_pushes_yield_one_create_and_conflicts() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, false).await;
    let w = Arc::new(writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await);
    let bytes = fixture_bytes("sample.lib.1.0.0.nupkg");

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (w, repo, bytes) = (w.clone(), repo.clone(), bytes.clone());
            tokio::spawn(async move { w.store_upload(&repo, &bytes[..], MAX_UPLOAD).await })
        })
        .collect();
    let (mut created, mut conflicts) = (0, 0);
    for h in handles {
        match h.await.unwrap() {
            Ok(PublishOutcome::Created) => created += 1,
            Err(WriteError::Conflict { .. }) => conflicts += 1,
            other => panic!("unexpected publish result: {other:?}"),
        }
    }
    assert_eq!((created, conflicts), (1, 7));
}

/// With `allow_redeploy`, simultaneous first pushes of one (id, version) all
/// succeed: one creates the version, the others replace it, as they would
/// a moment later (#226).
#[tokio::test]
async fn concurrent_first_pushes_with_redeploy_create_then_replace() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, true).await;
    let w = Arc::new(writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await);
    let id = unique_id();
    let bytes = make_nupkg(&id, "1.0.0");

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (w, repo, bytes) = (w.clone(), repo.clone(), bytes.clone());
            tokio::spawn(async move { w.store_upload(&repo, &bytes[..], MAX_UPLOAD).await })
        })
        .collect();
    let (mut created, mut replaced) = (0, 0);
    for h in handles {
        match h.await.unwrap() {
            Ok(PublishOutcome::Created) => created += 1,
            Ok(PublishOutcome::Replaced) => replaced += 1,
            other => panic!("unexpected publish result: {other:?}"),
        }
    }
    assert_eq!((created, replaced), (1, 7));
}

/// A first push that loses the race for the unique index to a concurrent
/// first push of the same (id, version) is retried as a redeploy where the
/// repository allows one, instead of failing with 409 (#226). The race is
/// forced: the winner's row is inserted and held uncommitted until the push
/// waits on it.
#[tokio::test]
async fn first_push_losing_the_insert_race_redeploys() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, true).await;
    let repo_id = repository_dao::find_repository_by_name(&pool, &repo)
        .await
        .unwrap()
        .unwrap()
        .id;
    let w = writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await;
    let id = unique_id();
    let lower = id.to_lowercase();

    // The winner: its version row, not committed yet.
    let mut winner = pool.begin().await.unwrap();
    let winner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *winner)
        .await
        .unwrap();
    forge_db::component_dao::insert_component(
        &mut *winner,
        forge_db::component_dao::NewComponent {
            repository_id: repo_id,
            name: lower.clone(),
            original_id: id.clone(),
            version: "1.0.0".into(),
            version_original: "1.0.0".into(),
            listed: true,
        },
    )
    .await
    .unwrap();

    // The push finds no version and waits on the unique index.
    let bytes = make_nupkg(&id, "1.0.0");
    let pusher = {
        let (repo, bytes) = (repo.clone(), bytes.clone());
        tokio::spawn(async move { w.store_upload(&repo, &bytes[..], MAX_UPLOAD).await })
    };
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
        )
        .bind(winner_pid)
        .fetch_one(&pool)
        .await
        .unwrap();
        if blocked > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    winner.commit().await.unwrap();

    let outcome = pusher
        .await
        .unwrap()
        .expect("the losing first push redeploys");
    assert_eq!(outcome, PublishOutcome::Replaced);
    let comp = forge_db::component_dao::find_component(&pool, repo_id, &lower, "1.0.0")
        .await
        .unwrap()
        .expect("the version exists");
    let nupkg = forge_db::asset_dao::find_asset(&pool, comp.id, NUPKG_ASSET_PATH)
        .await
        .unwrap()
        .expect("the redeploy stored the package");
    assert_eq!(blob_ref_count(&pool, &nupkg.blob_sha256).await, Some(1));
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
    // A version that does not parse was never published: NotFound (404),
    // not an invalid-package error (400), for unlist, delete and relist.
    for hard in [false, true] {
        let nf = w
            .delete_component(&repo, "Sample.Lib", "notaversion", hard)
            .await
            .unwrap();
        assert_eq!(nf, DeleteOutcome::NotFound);
    }
    let nf = w.relist(&repo, "Sample.Lib", "notaversion").await.unwrap();
    assert_eq!(nf, DeleteOutcome::NotFound);

    // Relist restores search visibility.
    let out = w.relist(&repo, "Sample.Lib", "1.2.3").await.unwrap();
    assert_eq!(out, DeleteOutcome::Relisted);
    let res = r.search(&repo, &SearchParams::default()).await.unwrap();
    assert_eq!(res.total_hits, 1);
}

/// A redeploy that loses the component row lock to a concurrent hard delete
/// publishes the version afresh instead of failing with an internal error.
#[tokio::test]
async fn redeploy_losing_the_row_lock_to_a_delete_creates_the_version() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, true).await;

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

    // The "delete": hold the component row lock.
    let mut deleter = pool.begin().await.unwrap();
    let deleter_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *deleter)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM component WHERE id = $1 FOR UPDATE")
        .bind(comp.id)
        .execute(&mut *deleter)
        .await
        .unwrap();

    // The redeploy blocks on that lock.
    let pusher = {
        let (repo, id) = (repo.clone(), id.clone());
        tokio::spawn(async move {
            w.store_upload(&repo, &make_nupkg(&id, "1.0.0")[..], MAX_UPLOAD)
                .await
        })
    };
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
        )
        .bind(deleter_pid)
        .fetch_one(&pool)
        .await
        .unwrap();
        if blocked > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // The delete removes the version and commits.
    sqlx::query("DELETE FROM component WHERE id = $1")
        .bind(comp.id)
        .execute(&mut *deleter)
        .await
        .unwrap();
    deleter.commit().await.unwrap();

    let outcome = pusher
        .await
        .unwrap()
        .expect("redeploy after a delete succeeds");
    assert_eq!(outcome, PublishOutcome::Created);
    assert!(
        forge_db::component_dao::find_component(&pool, repo_id, &lower, "1.0.0")
            .await
            .unwrap()
            .is_some(),
        "the version exists again"
    );
}

/// A hard delete that loses the component row lock to a concurrent delete is a
/// plain `NotFound` (404 on the wire), not an internal error, and it touches
/// no blob reference counts.
#[tokio::test]
async fn hard_delete_losing_the_row_lock_is_not_found() {
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

    // The "winner": hold the component row lock.
    let mut winner = pool.begin().await.unwrap();
    let winner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *winner)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM component WHERE id = $1 FOR UPDATE")
        .bind(comp.id)
        .execute(&mut *winner)
        .await
        .unwrap();

    // The "loser" blocks on that lock.
    let loser = {
        let (repo, id) = (repo.clone(), id.clone());
        tokio::spawn(async move { w.delete_component(&repo, &id, "1.0.0", true).await })
    };
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
        )
        .bind(winner_pid)
        .fetch_one(&pool)
        .await
        .unwrap();
        if blocked > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // The winner removes the component and commits.
    sqlx::query("DELETE FROM component WHERE id = $1")
        .bind(comp.id)
        .execute(&mut *winner)
        .await
        .unwrap();
    winner.commit().await.unwrap();

    let out = loser.await.unwrap().expect("losing delete is not an error");
    assert_eq!(out, DeleteOutcome::NotFound);
    assert_eq!(
        blob_ref_count(&pool, &nupkg.blob_sha256).await,
        Some(1),
        "the losing delete must not decrement anything"
    );
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

/// The `.nupkg` download counter of `(repo_id, lower, version)`.
async fn download_count(pool: &PgPool, repo_id: i64, lower: &str, version: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT a.download_count FROM asset a JOIN component c ON c.id = a.component_id \
         WHERE c.repository_id = $1 AND c.name = $2 AND c.version = $3 AND a.path = $4",
    )
    .bind(repo_id)
    .bind(lower)
    .bind(version)
    .bind(NUPKG_ASSET_PATH)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// #119: downloads are counted in memory and written in batches, so a burst
/// on one version neither queues one row update per download nor holds a
/// pool connection per download: while another transaction holds the
/// version's rows, a burst of downloads leaves the pool usable for other
/// reads, and once the rows are free every download is counted.
#[tokio::test]
async fn a_download_burst_on_one_version_leaves_the_pool_usable() {
    let pool = common::small_pool(4, std::time::Duration::from_secs(2)).await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, false).await;
    let w = writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await;
    let r = Arc::new(reader(&pool, store));
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

    // A transaction holding the version's asset row, as a slow writer would.
    let mut holder = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT a.id FROM asset a JOIN component c ON c.id = a.component_id \
         WHERE c.repository_id = $1 AND c.name = $2 FOR UPDATE",
    )
    .bind(repo_id)
    .bind(&lower)
    .execute(&mut *holder)
    .await
    .unwrap();

    let downloads = 40;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..downloads {
        let r = r.clone();
        let (repo, lower) = (repo.clone(), lower.clone());
        tasks.spawn(async move { r.resolve_nupkg(&repo, &lower, "1.0.0").await });
    }
    while let Some(served) = tasks.join_next().await {
        assert!(served.unwrap().unwrap().is_some());
    }
    // Let the batched write start (and wait on the held row).
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    // Other reads still get a connection.
    let versions = r.list_versions(&repo, &lower).await.expect("pool usable");
    assert_eq!(versions.len(), 1);

    holder.commit().await.unwrap();
    let mut counted = 0;
    for _ in 0..100 {
        counted = download_count(&pool, repo_id, &lower, "1.0.0").await;
        if counted == downloads {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(counted, downloads, "every download is counted");
}

/// #74: a `HEAD` on a `.nupkg` is not a download, and a redeploy keeps the
/// version's download count (retention and search read it).
#[tokio::test]
async fn head_is_not_a_download_and_a_redeploy_keeps_the_count() {
    let pool = common::pool().await;
    let store = common::blob_store().await;
    let cas = Cas::new(store.clone(), pool.clone());
    let repo = seed_repo(&pool, true).await;
    let w = writer(&pool, cas, Arc::new(NoopCacheInvalidator)).await;
    let r = reader(&pool, store);
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
    // The bump is spawned off the response path: wait for it.
    let settled = |expected: i64| {
        let pool = pool.clone();
        let lower = lower.clone();
        async move {
            for _ in 0..100 {
                if download_count(&pool, repo_id, &lower, "1.0.0").await == expected {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            false
        }
    };

    for _ in 0..3 {
        assert!(r
            .resolve_nupkg_head(&repo, &lower, "1.0.0")
            .await
            .unwrap()
            .is_some());
    }
    assert!(r
        .resolve_nupkg(&repo, &lower, "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert!(settled(1).await, "one GET, no HEADs");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(download_count(&pool, repo_id, &lower, "1.0.0").await, 1);

    w.store_upload(&repo, &make_nupkg_variant(&id, "1.0.0")[..], MAX_UPLOAD)
        .await
        .expect("redeploy");
    assert_eq!(
        download_count(&pool, repo_id, &lower, "1.0.0").await,
        1,
        "the redeployed version keeps its count"
    );
}
