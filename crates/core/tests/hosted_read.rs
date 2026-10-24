//! Integration tests for hosted-repository read ops.
//!
//! Seeds `repository` + `blob` + `component` + `asset` rows via the DAOs, then
//! drives [`forge_core::repo::hosted::HostedRepo`] through the [`RepoReadOps`]
//! trait. A stub [`BlobFetch`] returns canned nuspec bytes so no S3 is needed.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use forge_core::repo::hosted::{BlobFetch, HostedRepo};
use forge_core::repo::{RepoError, RepoReadOps, SearchParams, NUPKG_ASSET_PATH, NUSPEC_ASSET_PATH};
use forge_db::asset_dao::{self, NewAsset};
use forge_db::component_dao::{self, NewComponent};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::{blob_dao, model::Repository};
use sqlx::PgPool;

/// NuGet, the built-in format plugin, as the `Format` the repository code
/// works with.
fn nuget() -> forge_plugin::PluginFormat {
    let plugin = forge_plugin::Plugin::builtin(
        forge_format_nuget::PLUGIN_TOML,
        forge_format_nuget::Nuget::default(),
    )
    .expect("crates/formats/nuget/plugin.toml is valid");
    forge_plugin::PluginFormat::new(&plugin)
}

/// In-memory blob byte store: maps `s3_key -> bytes`.
#[derive(Default, Clone)]
struct StubBlobs {
    map: HashMap<String, Vec<u8>>,
}

#[async_trait]
impl BlobFetch for StubBlobs {
    async fn fetch_all(&self, blob: &forge_db::model::Blob) -> Result<Vec<u8>, RepoError> {
        let s3_key = &blob.s3_key;
        self.map
            .get(s3_key)
            .cloned()
            .ok_or_else(|| RepoError::RepoNotFound(format!("missing blob {s3_key}")))
    }
}

/// Build a `HostedRepo` over the pool with NuGet ordering and the stub blobs.
fn hosted(pool: &PgPool, blobs: StubBlobs) -> HostedRepo {
    HostedRepo::new(pool.clone(), Arc::new(nuget()), Arc::new(blobs))
}

/// Insert a committed blob (pending → commit_and_incref) and return its sha.
async fn seed_blob(pool: &PgPool, sha: &str, s3_key: &str, size: i64) {
    blob_dao::upsert_pending(pool, sha, size, s3_key)
        .await
        .expect("upsert_pending");
    let mut tx = pool.begin().await.expect("begin");
    blob_dao::commit_and_incref(&mut tx, sha)
        .await
        .expect("commit_and_incref");
    tx.commit().await.expect("commit");
}

/// Seed a hosted repo and return its row.
async fn seed_repo(pool: &PgPool) -> Repository {
    let name = format!("hosted-{}", common::unique());
    repository_dao::insert_repository(pool, NewRepository::hosted(name))
        .await
        .expect("insert_repository")
}

/// A simple nuspec fixture with one dependency group.
fn nuspec_xml(id: &str, version: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <description>desc</description>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="[13.0.1, )" />
      </group>
    </dependencies>
  </metadata>
</package>"#
    )
    .into_bytes()
}

/// Seed a complete (component + nupkg asset + nuspec asset + blobs) package
/// version. Returns nothing; the caller looks it up via the read ops.
#[allow(clippy::too_many_arguments)]
async fn seed_version(
    pool: &PgPool,
    blobs: &mut StubBlobs,
    repo_id: i64,
    original_id: &str,
    lower_id: &str,
    version: &str,
    listed: bool,
    sha512_b64: &str,
) {
    let suffix = common::unique();
    let nupkg_sha = format!("nupkgsha{suffix:064}");
    let nupkg_sha = nupkg_sha[..64].to_string();
    let nuspec_sha = format!("nuspcsha{suffix:064}");
    let nuspec_sha = nuspec_sha[..64].to_string();
    let nupkg_key = format!("blobs/{nupkg_sha}");
    let nuspec_key = format!("blobs/{nuspec_sha}");

    seed_blob(pool, &nupkg_sha, &nupkg_key, 1234).await;
    seed_blob(pool, &nuspec_sha, &nuspec_key, 256).await;

    // Map the nuspec blob to canned XML bytes.
    blobs
        .map
        .insert(nuspec_key.clone(), nuspec_xml(original_id, version));
    blobs
        .map
        .insert(nupkg_key.clone(), b"PK-nupkg-bytes".to_vec());

    let comp = component_dao::insert_component(
        pool,
        NewComponent {
            repository_id: repo_id,
            name: lower_id.to_string(),
            original_id: original_id.to_string(),
            version: version.to_string(),
            version_original: version.to_string(),
            listed,
        },
    )
    .await
    .expect("insert_component");

    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: comp.id,
            path: NUPKG_ASSET_PATH.to_string(),
            content_type: "application/octet-stream".to_string(),
            blob_sha256: nupkg_sha,
            size: 1234,
            sha512_base64: Some(sha512_b64.to_string()),
        },
    )
    .await
    .expect("insert nupkg asset");

    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: comp.id,
            path: NUSPEC_ASSET_PATH.to_string(),
            content_type: "application/xml".to_string(),
            blob_sha256: nuspec_sha,
            size: 256,
            sha512_base64: None,
        },
    )
    .await
    .expect("insert nuspec asset");
}

#[tokio::test]
async fn list_versions_includes_unlisted_sorted_ascending() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;

    // Seed out of order; expect ascending precedence with prerelease < release.
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Sample.Lib",
        "sample.lib",
        "2.0.0",
        true,
        "h2",
    )
    .await;
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Sample.Lib",
        "sample.lib",
        "1.0.0",
        true,
        "h1",
    )
    .await;
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Sample.Lib",
        "sample.lib",
        "2.0.0-beta1",
        false,
        "hb",
    )
    .await;

    let h = hosted(&pool, blobs);
    let versions = h.list_versions(&repo.name, "sample.lib").await.unwrap();
    let vs: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
    // Includes the unlisted prerelease; ascending precedence.
    assert_eq!(vs, vec!["1.0.0", "2.0.0-beta1", "2.0.0"]);
    // Unlisted flag preserved.
    let beta = versions
        .iter()
        .find(|v| v.version == "2.0.0-beta1")
        .unwrap();
    assert!(!beta.listed);
}

#[tokio::test]
async fn list_versions_unknown_id_is_empty() {
    let pool = common::pool().await;
    let repo = seed_repo(&pool).await;
    let h = hosted(&pool, StubBlobs::default());
    let v = h.list_versions(&repo.name, "does.not.exist").await.unwrap();
    assert!(v.is_empty());
}

#[tokio::test]
async fn list_versions_unknown_repo_errors() {
    let pool = common::pool().await;
    let h = hosted(&pool, StubBlobs::default());
    let err = h.list_versions("no-such-repo", "x").await.unwrap_err();
    assert!(matches!(err, RepoError::RepoNotFound(_)));
}

#[tokio::test]
async fn resolve_nupkg_returns_blob_key_and_size() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Sample.Lib",
        "sample.lib",
        "1.0.0",
        true,
        "h1",
    )
    .await;

    let h = hosted(&pool, blobs);
    let loc = h
        .resolve_nupkg(&repo.name, "sample.lib", "1.0.0")
        .await
        .unwrap()
        .expect("present");
    assert!(loc.blob_s3_key.starts_with("blobs/"));
    assert_eq!(loc.size, 1234);
    assert_eq!(loc.content_type, "application/octet-stream");

    // Unknown version → None.
    let none = h
        .resolve_nupkg(&repo.name, "sample.lib", "9.9.9")
        .await
        .unwrap();
    assert!(none.is_none());
}

#[tokio::test]
async fn resolve_nuspec_returns_stored_bytes() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Sample.Lib",
        "sample.lib",
        "1.0.0",
        true,
        "h1",
    )
    .await;

    let h = hosted(&pool, blobs);
    let bytes = h
        .resolve_nuspec(&repo.name, "sample.lib", "1.0.0")
        .await
        .unwrap()
        .expect("present");
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("<id>Sample.Lib</id>"));
    assert!(text.contains("Newtonsoft.Json"));
}

#[tokio::test]
async fn registration_carries_hash_listed_and_nuspec_bytes() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Sample.Lib",
        "sample.lib",
        "1.0.0",
        true,
        "HASH512",
    )
    .await;
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Sample.Lib",
        "sample.lib",
        "2.0.0-beta1",
        false,
        "HASHBETA",
    )
    .await;

    let h = hosted(&pool, blobs);
    let entries = h.registration(&repo.name, "sample.lib").await.unwrap();
    assert_eq!(entries.len(), 2);
    // Ascending; unlisted included.
    assert_eq!(entries[0].version, "1.0.0");
    assert!(entries[0].listed);
    assert_eq!(
        entries[0].package_hash_sha512_base64.as_deref(),
        Some("HASH512")
    );
    // The manifest is summarized (and the summary handed on) instead of the
    // raw bytes.
    let summary = entries[0].manifest_summary.as_ref().expect("summary");
    assert_eq!(
        summary["dependency_groups"][0]["dependencies"][0]["id"],
        serde_json::json!("Newtonsoft.Json")
    );
    assert!(entries[0].nuspec_bytes.is_none());

    assert_eq!(entries[1].version, "2.0.0-beta1");
    assert!(!entries[1].listed);
}

/// Registration reads a version's stored manifest summary: older versions
/// (no summary yet) are summarized once and backfilled, after which neither
/// the index nor a single-version lookup fetches or parses a manifest.
#[tokio::test]
async fn registration_backfills_and_then_uses_stored_manifest_summaries() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;
    for v in ["1.0.0", "1.1.0"] {
        seed_version(
            &pool,
            &mut blobs,
            repo.id,
            "Sample.Lib",
            "sample.lib",
            v,
            true,
            "H",
        )
        .await;
    }
    let first = hosted(&pool, blobs)
        .registration(&repo.name, "sample.lib")
        .await
        .unwrap();
    assert!(first.iter().all(|e| e.manifest_summary.is_some()));
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM component WHERE repository_id = $1 AND manifest_summary IS NOT NULL",
    )
    .bind(repo.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, 2, "summaries backfilled");

    // A blob store that has nothing: the stored summaries are enough.
    let h = hosted(&pool, StubBlobs::default());
    let entries = h.registration(&repo.name, "sample.lib").await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[1].manifest_summary.as_ref().unwrap()["metadata"]["description"],
        serde_json::json!("desc")
    );
    let one = h
        .registration_entry(&repo.name, "sample.lib", "1.1.0")
        .await
        .unwrap()
        .expect("single version");
    assert_eq!(one.version, "1.1.0");
    assert_eq!(one.package_hash_sha512_base64.as_deref(), Some("H"));
    assert!(h
        .registration_entry(&repo.name, "sample.lib", "9.9.9")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn search_filters_listed_and_prerelease_with_paging() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;

    // Two ids. "alpha.pkg" has a listed release + unlisted release + prerelease.
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Alpha.Pkg",
        "alpha.pkg",
        "1.0.0",
        true,
        "a1",
    )
    .await;
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Alpha.Pkg",
        "alpha.pkg",
        "1.1.0",
        false,
        "a2",
    )
    .await;
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Alpha.Pkg",
        "alpha.pkg",
        "2.0.0-rc1",
        true,
        "arc",
    )
    .await;
    // "beta.pkg" only has a prerelease that is listed.
    seed_version(
        &pool,
        &mut blobs,
        repo.id,
        "Beta.Pkg",
        "beta.pkg",
        "0.9.0-pre",
        true,
        "bp",
    )
    .await;

    let h = hosted(&pool, blobs);

    // Default (prerelease = false): alpha.pkg shows only 1.0.0 (1.1.0 unlisted,
    // 2.0.0-rc1 prerelease). beta.pkg drops out entirely (only prerelease).
    let res = h
        .search(&repo.name, &SearchParams::default())
        .await
        .unwrap();
    assert_eq!(res.total_hits, 1);
    let hit = &res.hits[0];
    assert_eq!(hit.original_id, "Alpha.Pkg");
    let vs: Vec<&str> = hit.versions.iter().map(|v| v.version.as_str()).collect();
    assert_eq!(vs, vec!["1.0.0"]);
    assert_eq!(hit.latest_version, "1.0.0");

    // prerelease = true: alpha gets 1.0.0 + 2.0.0-rc1; beta appears.
    let pre = SearchParams {
        prerelease: true,
        ..SearchParams::default()
    };
    let res = h.search(&repo.name, &pre).await.unwrap();
    assert_eq!(res.total_hits, 2);
    let alpha = res
        .hits
        .iter()
        .find(|h| h.original_id == "Alpha.Pkg")
        .unwrap();
    let vs: Vec<&str> = alpha.versions.iter().map(|v| v.version.as_str()).collect();
    assert_eq!(vs, vec!["1.0.0", "2.0.0-rc1"]);
    assert_eq!(alpha.latest_version, "2.0.0-rc1");

    // Free-text query narrows to beta.
    let q = SearchParams {
        q: "beta".into(),
        prerelease: true,
        ..SearchParams::default()
    };
    let res = h.search(&repo.name, &q).await.unwrap();
    assert_eq!(res.total_hits, 1);
    assert_eq!(res.hits[0].original_id, "Beta.Pkg");

    // Paging: skip past the only hit yields an empty page but accurate total.
    let paged = SearchParams {
        skip: 5,
        take: 10,
        prerelease: true,
        ..SearchParams::default()
    };
    let res = h.search(&repo.name, &paged).await.unwrap();
    assert_eq!(res.total_hits, 2);
    assert!(res.hits.is_empty());
}

/// Without `include_semver2` (a client sending no `semVerLevel`), SemVer 2.0.0
/// versions are dropped before counting and paging: an id left with none is
/// not a hit, pages stay full and `total_hits` counts only what is shown.
#[tokio::test]
async fn search_drops_semver2_before_paging() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;
    for (id, version) in [
        ("Sv.A", "1.0.0"),
        ("Sv.B", "1.0.0-beta.1"),
        ("Sv.C", "1.0.0"),
        ("Sv.C", "2.0.0-rc.1"),
        ("Sv.D", "2.0.0-alpha.2"),
        ("Sv.E", "1.0.0-beta1"),
    ] {
        let lower = id.to_lowercase();
        seed_version(&pool, &mut blobs, repo.id, id, &lower, version, true, "s").await;
    }
    let h = hosted(&pool, blobs);
    let search = |skip: usize, include_semver2: bool| SearchParams {
        skip,
        take: 2,
        prerelease: true,
        include_semver2,
        ..SearchParams::default()
    };

    let res = h.search(&repo.name, &search(0, false)).await.unwrap();
    assert_eq!(res.total_hits, 3, "Sv.B and Sv.D have only SemVer 2.0.0");
    let ids: Vec<&str> = res.hits.iter().map(|h| h.original_id.as_str()).collect();
    assert_eq!(ids, ["Sv.A", "Sv.C"], "a full first page");
    let vs: Vec<&str> = res.hits[1]
        .versions
        .iter()
        .map(|v| v.version.as_str())
        .collect();
    assert_eq!(vs, ["1.0.0"]);
    assert_eq!(res.hits[1].latest_version, "1.0.0");

    let res = h.search(&repo.name, &search(2, false)).await.unwrap();
    assert_eq!(res.total_hits, 3);
    let ids: Vec<&str> = res.hits.iter().map(|h| h.original_id.as_str()).collect();
    assert_eq!(
        ids,
        ["Sv.E"],
        "the next page continues where the first ended"
    );

    let res = h.search(&repo.name, &search(0, true)).await.unwrap();
    assert_eq!(res.total_hits, 5);
    assert_eq!(res.hits[1].original_id, "Sv.B");
}

#[tokio::test]
async fn search_take_is_clamped() {
    let p = SearchParams {
        take: 100_000,
        ..SearchParams::default()
    };
    assert_eq!(p.effective_take(), SearchParams::MAX_TAKE);
    let z = SearchParams {
        take: 0,
        ..SearchParams::default()
    };
    assert_eq!(z.effective_take(), SearchParams::DEFAULT_TAKE);
}

/// #66: search pages over ids: `totalHits` counts every matching id, the
/// selector applies before paging, and the page's versions are complete.
#[tokio::test]
async fn search_pages_over_ids_with_a_selector() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;
    for i in 0..6 {
        let id = format!("Pkg.{i}");
        let lower = id.to_lowercase();
        for (n, version) in ["1.0.0", "1.1.0"].into_iter().enumerate() {
            seed_version(
                &pool,
                &mut blobs,
                repo.id,
                &id,
                &lower,
                version,
                true,
                &format!("p{i}{n}"),
            )
            .await;
        }
    }
    let h = hosted(&pool, blobs);
    let page = |skip, take| SearchParams {
        q: "pkg".into(),
        skip,
        take,
        ..SearchParams::default()
    };
    let res = h.search(&repo.name, &page(2, 2)).await.unwrap();
    assert_eq!(res.total_hits, 6);
    let ids: Vec<&str> = res.hits.iter().map(|h| h.original_id.as_str()).collect();
    assert_eq!(ids, ["Pkg.2", "Pkg.3"]);
    let versions: Vec<&str> = res.hits[0]
        .versions
        .iter()
        .map(|v| v.version.as_str())
        .collect();
    assert_eq!(versions, ["1.0.0", "1.1.0"]);
    assert_eq!(res.hits[0].latest_version, "1.1.0");

    let filter = forge_core::authz::PackageFilter::Predicate(Arc::new(|id: &str| id != "pkg.3"));
    let res = h
        .search_with_package_filter(&repo.name, &page(2, 2), &filter)
        .await
        .unwrap();
    assert_eq!(res.total_hits, 5);
    let ids: Vec<&str> = res.hits.iter().map(|h| h.original_id.as_str()).collect();
    assert_eq!(ids, ["Pkg.2", "Pkg.4"]);
}

/// #81: a registration index above the inline limit needs only versions, and
/// a page only its own versions' entries; both agree with `registration`.
#[tokio::test]
async fn registration_versions_and_entries_agree_with_registration() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let repo = seed_repo(&pool).await;
    for (n, (version, listed)) in [("1.0.0", true), ("1.10.0", false), ("1.9.0", true)]
        .into_iter()
        .enumerate()
    {
        seed_version(
            &pool,
            &mut blobs,
            repo.id,
            "Reg.Pkg",
            "reg.pkg",
            version,
            listed,
            &format!("r{n}"),
        )
        .await;
    }
    let h = hosted(&pool, blobs);
    let full = h.registration(&repo.name, "reg.pkg").await.unwrap();
    let versions = h
        .registration_versions(&repo.name, "reg.pkg")
        .await
        .unwrap();
    assert_eq!(
        versions,
        full.iter().map(|e| e.version.clone()).collect::<Vec<_>>()
    );
    assert_eq!(versions, ["1.0.0", "1.9.0", "1.10.0"]);
    let mut some = h
        .registration_entries(&repo.name, "reg.pkg", &["1.10.0".into(), "9.9.9".into()])
        .await
        .unwrap();
    assert_eq!(some.len(), 1);
    let entry = some.remove(0);
    let expected = full.iter().find(|e| e.version == "1.10.0").unwrap();
    assert_eq!(entry.version, expected.version);
    assert_eq!(entry.listed, expected.listed);
    assert_eq!(
        entry.package_hash_sha512_base64,
        expected.package_hash_sha512_base64
    );
}
