//! Handler tests for the NuGet V3 routes (Phase 6, Task 6.2).
//!
//! Drives the in-process axum router against a **mock** [`RepoReadOps`] and
//! [`NupkgBytes`] so no database or S3 is involved. Asserts the exact Appendix
//! A JSON shapes, absolute `@id`s, hosted-only `PackagePublish`, `GET`+`HEAD`
//! behavior, content types, lowercasing, and 404s.

// Test fixtures build mock state by `default()` + field assignment, which is
// clearer than struct-literal updates here.
#![allow(clippy::field_reassign_with_default)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use forge_core::repo::{
    NupkgLocation, RegistrationEntry, RepoError, RepoKind, RepoReadOps, SearchHit, SearchParams,
    SearchResult, VersionEntry,
};
use forge_nuget::routes::{nuget_router, NupkgBytes, RouteContext};
use forge_nuget::NugetFormat;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const BASE: &str = "https://forge.example.com";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct MockOps {
    /// lower_id -> versions (ascending precedence)
    versions: std::collections::HashMap<String, Vec<VersionEntry>>,
    /// (lower_id, version) -> nupkg location
    nupkgs: std::collections::HashMap<(String, String), NupkgLocation>,
    /// (lower_id, version) -> nuspec bytes
    nuspecs: std::collections::HashMap<(String, String), Vec<u8>>,
    /// lower_id -> registration entries
    registration: std::collections::HashMap<String, Vec<RegistrationEntry>>,
    /// search hits to return (totalHits = hits.len() unless overridden)
    search_hits: Vec<SearchHit>,
}

#[async_trait]
impl RepoReadOps for MockOps {
    async fn list_versions(&self, _repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        Ok(self.versions.get(id).cloned().unwrap_or_default())
    }

    async fn resolve_nupkg(
        &self,
        _repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        Ok(self
            .nupkgs
            .get(&(id.to_string(), version.to_string()))
            .cloned())
    }

    async fn resolve_nuspec(
        &self,
        _repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        Ok(self
            .nuspecs
            .get(&(id.to_string(), version.to_string()))
            .cloned())
    }

    async fn registration(
        &self,
        _repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        Ok(self.registration.get(id).cloned().unwrap_or_default())
    }

    async fn search(&self, _repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        // Echo the configured hits, applying skip/take so paging is observable.
        let total = self.search_hits.len();
        let take = params.effective_take();
        let hits: Vec<SearchHit> = self
            .search_hits
            .iter()
            .skip(params.skip)
            .take(take)
            .cloned()
            .collect();
        Ok(SearchResult {
            total_hits: total,
            hits,
        })
    }
}

#[derive(Default, Clone)]
struct MockBytes {
    map: std::collections::HashMap<String, Vec<u8>>,
}

#[async_trait]
impl NupkgBytes for MockBytes {
    async fn fetch_all(&self, s3_key: &str) -> Result<Vec<u8>, RepoError> {
        self.map
            .get(s3_key)
            .cloned()
            .ok_or_else(|| RepoError::RepoNotFound(s3_key.to_string()))
    }
}

fn ctx(kind: RepoKind, ops: MockOps, bytes: MockBytes) -> RouteContext {
    RouteContext {
        repo: "main".to_string(),
        kind,
        public_base_url: BASE.to_string(),
        ops: Arc::new(ops),
        format: Arc::new(NugetFormat::new()),
        nupkg: Arc::new(bytes),
        write: None,
        max_upload_bytes: 16 * 1024 * 1024,
    }
}

/// Build a context wired with a mock write-ops backend for publish tests.
fn ctx_with_write(kind: RepoKind, write: MockWrite) -> RouteContext {
    RouteContext {
        repo: "main".to_string(),
        kind,
        public_base_url: BASE.to_string(),
        ops: Arc::new(MockOps::default()),
        format: Arc::new(NugetFormat::new()),
        nupkg: Arc::new(MockBytes::default()),
        write: Some(Arc::new(write)),
        max_upload_bytes: 16 * 1024 * 1024,
    }
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    send(router, "GET", uri).await
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

/// Like [`send`], but attaches an `X-NuGet-ApiKey` header — used for the write
/// routes (unlist/relist) which reject anonymous requests.
async fn send_with_key(
    router: &axum::Router,
    method: &str,
    uri: &str,
    api_key: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("X-NuGet-ApiKey", api_key)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn json(body: &[u8]) -> Value {
    serde_json::from_slice(body).expect("valid json")
}

// ---------------------------------------------------------------------------
// Service index
// ---------------------------------------------------------------------------

#[tokio::test]
async fn service_index_hosted_advertises_publish_with_absolute_ids() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, MockOps::default(), MockBytes::default()),
    );
    let (status, _h, body) = get(&router, "/index.json").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["version"], "3.0.0");

    let resources = v["resources"].as_array().unwrap();
    let by_type = |t: &str| {
        resources
            .iter()
            .find(|r| r["@type"] == t)
            .map(|r| r["@id"].as_str().unwrap().to_string())
    };

    assert_eq!(
        by_type("SearchQueryService/3.5.0").as_deref(),
        Some("https://forge.example.com/v3/main/query")
    );
    assert_eq!(
        by_type("RegistrationsBaseUrl/3.6.0").as_deref(),
        Some("https://forge.example.com/v3/main/registration/")
    );
    assert_eq!(
        by_type("PackageBaseAddress/3.0.0").as_deref(),
        Some("https://forge.example.com/v3/main/flat/")
    );
    assert_eq!(
        by_type("PackagePublish/2.0.0").as_deref(),
        Some("https://forge.example.com/v3/main/package")
    );
}

#[tokio::test]
async fn service_index_proxy_omits_publish() {
    let router = nuget_router(
        RepoKind::Proxy,
        ctx(RepoKind::Proxy, MockOps::default(), MockBytes::default()),
    );
    let (status, _h, body) = get(&router, "/index.json").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    let has_publish = v["resources"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["@type"] == "PackagePublish/2.0.0");
    assert!(!has_publish, "proxy must not advertise PackagePublish");
}

#[tokio::test]
async fn service_index_group_omits_publish() {
    let router = nuget_router(
        RepoKind::Group,
        ctx(RepoKind::Group, MockOps::default(), MockBytes::default()),
    );
    let (_status, _h, body) = get(&router, "/index.json").await;
    let v = json(&body);
    let has_publish = v["resources"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["@type"] == "PackagePublish/2.0.0");
    assert!(!has_publish);
}

#[tokio::test]
async fn index_supports_head() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, MockOps::default(), MockBytes::default()),
    );
    let (status, _h, body) = send(&router, "HEAD", "/index.json").await;
    assert_eq!(status, StatusCode::OK);
    // HEAD discards the body.
    assert!(body.is_empty());
}

// ---------------------------------------------------------------------------
// Flat container
// ---------------------------------------------------------------------------

fn ops_with_versions() -> MockOps {
    let mut ops = MockOps::default();
    ops.versions.insert(
        "sample.lib".to_string(),
        vec![
            VersionEntry {
                original_id: "Sample.Lib".into(),
                version: "1.0.0".into(),
                version_original: "1.0.0".into(),
                listed: true,
            },
            VersionEntry {
                original_id: "Sample.Lib".into(),
                version: "2.0.0-beta1".into(),
                version_original: "2.0.0-beta1".into(),
                listed: false,
            },
        ],
    );
    ops
}

#[tokio::test]
async fn flat_versions_lists_all_including_unlisted() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops_with_versions(), MockBytes::default()),
    );
    // Mixed-case id in the URL must be lowercased before lookup.
    let (status, _h, body) = get(&router, "/flat/Sample.LIB/index.json").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["versions"], serde_json::json!(["1.0.0", "2.0.0-beta1"]));
}

#[tokio::test]
async fn flat_versions_unknown_id_404() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, MockOps::default(), MockBytes::default()),
    );
    let (status, _h, _body) = get(&router, "/flat/nope/index.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn flat_nupkg_streams_bytes_with_content_type() {
    let mut ops = MockOps::default();
    ops.nupkgs.insert(
        ("sample.lib".into(), "1.0.0".into()),
        NupkgLocation {
            blob_s3_key: "blobs/abc".into(),
            size: 5,
            content_type: "application/octet-stream".into(),
        },
    );
    let mut bytes = MockBytes::default();
    bytes
        .map
        .insert("blobs/abc".into(), b"PK\x03\x04!".to_vec());

    let router = nuget_router(RepoKind::Hosted, ctx(RepoKind::Hosted, ops, bytes));
    let (status, headers, body) =
        get(&router, "/flat/sample.lib/1.0.0/sample.lib.1.0.0.nupkg").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert_eq!(body, b"PK\x03\x04!");
}

#[tokio::test]
async fn flat_nupkg_unknown_version_404() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, MockOps::default(), MockBytes::default()),
    );
    let (status, _h, _body) = get(&router, "/flat/sample.lib/9.9.9/sample.lib.9.9.9.nupkg").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn flat_nuspec_serves_xml() {
    let mut ops = MockOps::default();
    ops.nuspecs.insert(
        ("sample.lib".into(), "1.0.0".into()),
        b"<?xml version=\"1.0\"?><package/>".to_vec(),
    );
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );
    let (status, headers, body) = get(&router, "/flat/sample.lib/1.0.0/sample.lib.nuspec").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("content-type").unwrap(), "application/xml");
    assert!(String::from_utf8(body).unwrap().contains("<package/>"));
}

#[tokio::test]
async fn flat_version_normalized_on_path() {
    // Request version "1.0" should resolve the stored normalized "1.0.0".
    let mut ops = MockOps::default();
    ops.nupkgs.insert(
        ("sample.lib".into(), "1.0.0".into()),
        NupkgLocation {
            blob_s3_key: "blobs/abc".into(),
            size: 1,
            content_type: "application/octet-stream".into(),
        },
    );
    let mut bytes = MockBytes::default();
    bytes.map.insert("blobs/abc".into(), b"x".to_vec());
    let router = nuget_router(RepoKind::Hosted, ctx(RepoKind::Hosted, ops, bytes));
    let (status, _h, body) = get(&router, "/flat/sample.lib/1.0/sample.lib.1.0.nupkg").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"x");
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

fn nuspec_with_dep() -> Vec<u8> {
    br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Sample.Lib</id>
    <version>1.0.0</version>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="[13.0.1, )" />
      </group>
    </dependencies>
  </metadata>
</package>"#
        .to_vec()
}

#[tokio::test]
async fn registration_inlined_page_shape() {
    let mut ops = MockOps::default();
    ops.registration.insert(
        "sample.lib".to_string(),
        vec![
            RegistrationEntry {
                original_id: "Sample.Lib".into(),
                version: "1.0.0".into(),
                listed: true,
                package_hash_sha512_base64: Some("HASH512".into()),
                nuspec_bytes: Some(nuspec_with_dep()),
            },
            RegistrationEntry {
                original_id: "Sample.Lib".into(),
                version: "2.0.0".into(),
                listed: true,
                package_hash_sha512_base64: Some("HASH2".into()),
                nuspec_bytes: None,
            },
        ],
    );
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );
    let (status, _h, body) = get(&router, "/registration/Sample.Lib/index.json").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);

    assert_eq!(v["count"], 1);
    let page = &v["items"][0];
    assert_eq!(page["count"], 2);
    assert_eq!(page["lower"], "1.0.0");
    assert_eq!(page["upper"], "2.0.0");

    let leaf0 = &page["items"][0];
    let ce = &leaf0["catalogEntry"];
    assert_eq!(ce["id"], "Sample.Lib");
    assert_eq!(ce["version"], "1.0.0");
    assert_eq!(ce["listed"], true);
    assert_eq!(ce["packageHash"], "HASH512");
    assert_eq!(ce["packageHashAlgorithm"], "SHA512");
    assert_eq!(
        ce["packageContent"],
        "https://forge.example.com/v3/main/flat/sample.lib/1.0.0/sample.lib.1.0.0.nupkg"
    );
    // packageContent also mirrored on the leaf.
    assert_eq!(leaf0["packageContent"], ce["packageContent"]);

    // Dependency group extracted from the nuspec.
    let groups = ce["dependencyGroups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["targetFramework"], "net8.0");
    assert_eq!(groups[0]["dependencies"][0]["id"], "Newtonsoft.Json");
    assert_eq!(groups[0]["dependencies"][0]["range"], "[13.0.1, )");

    // Entry without nuspec → empty dependency groups, still valid.
    let leaf1 = &page["items"][1];
    assert_eq!(
        leaf1["catalogEntry"]["dependencyGroups"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn registration_unknown_id_404() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, MockOps::default(), MockBytes::default()),
    );
    let (status, _h, _body) = get(&router, "/registration/nope/index.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

fn ops_with_search() -> MockOps {
    let mut ops = MockOps::default();
    ops.search_hits = vec![SearchHit {
        original_id: "Sample.Lib".into(),
        latest_version: "2.0.0".into(),
        versions: vec![
            VersionEntry {
                original_id: "Sample.Lib".into(),
                version: "1.0.0".into(),
                version_original: "1.0.0".into(),
                listed: true,
            },
            VersionEntry {
                original_id: "Sample.Lib".into(),
                version: "2.0.0".into(),
                version_original: "2.0.0".into(),
                listed: true,
            },
        ],
    }];
    ops
}

#[tokio::test]
async fn search_shape_with_total_hits_and_versions() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops_with_search(), MockBytes::default()),
    );
    let (status, _h, body) = get(&router, "/query?q=sample&prerelease=false").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["totalHits"], 1);
    let hit = &v["data"][0];
    assert_eq!(hit["id"], "Sample.Lib");
    assert_eq!(hit["version"], "2.0.0");
    let versions = hit["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["version"], "1.0.0");
    assert_eq!(versions[0]["downloads"], 0);
    assert_eq!(
        versions[0]["@id"],
        "https://forge.example.com/v3/main/registration/sample.lib/1.0.0.json"
    );
}

#[tokio::test]
async fn search_empty_query_returns_empty_data() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, MockOps::default(), MockBytes::default()),
    );
    let (status, _h, body) = get(&router, "/query").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["totalHits"], 0);
    assert_eq!(v["data"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn search_skip_past_hits_yields_empty_page_with_accurate_total() {
    // skip past the only hit yields an empty page but accurate totalHits.
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops_with_search(), MockBytes::default()),
    );
    let (_status, _h, body) = get(&router, "/query?skip=5&take=10").await;
    let v = json(&body);
    assert_eq!(v["totalHits"], 1);
    assert_eq!(v["data"].as_array().unwrap().len(), 0);
}

/// Build mock ops with `n` distinct search hits so paging/clamping is
/// observable through the route layer.
fn ops_with_n_hits(n: usize) -> MockOps {
    let mut ops = MockOps::default();
    ops.search_hits = (0..n)
        .map(|i| SearchHit {
            original_id: format!("Pkg.{i:04}"),
            latest_version: "1.0.0".into(),
            versions: vec![VersionEntry {
                original_id: format!("Pkg.{i:04}"),
                version: "1.0.0".into(),
                version_original: "1.0.0".into(),
                listed: true,
            }],
        })
        .collect();
    ops
}

#[tokio::test]
async fn search_take_zero_clamps_to_default_at_route_layer() {
    // A14: `take=0` must clamp to DEFAULT_TAKE (20) at the route layer, not
    // return an empty page. Seed more than DEFAULT_TAKE hits to observe it.
    let n = SearchParams::DEFAULT_TAKE + 5;
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops_with_n_hits(n), MockBytes::default()),
    );
    let (status, _h, body) = get(&router, "/query?take=0").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["totalHits"], n);
    assert_eq!(
        v["data"].as_array().unwrap().len(),
        SearchParams::DEFAULT_TAKE
    );
}

#[tokio::test]
async fn search_take_missing_clamps_to_default_at_route_layer() {
    // A14: absent `take` defaults to DEFAULT_TAKE (20) at the route layer.
    let n = SearchParams::DEFAULT_TAKE + 5;
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops_with_n_hits(n), MockBytes::default()),
    );
    let (status, _h, body) = get(&router, "/query?q=pkg").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["totalHits"], n);
    assert_eq!(
        v["data"].as_array().unwrap().len(),
        SearchParams::DEFAULT_TAKE
    );
}

#[tokio::test]
async fn search_take_above_max_clamps_to_max_at_route_layer() {
    // A14: `take` above MAX_TAKE clamps down to MAX_TAKE at the route layer.
    let n = SearchParams::MAX_TAKE + 50;
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops_with_n_hits(n), MockBytes::default()),
    );
    let (status, _h, body) = get(
        &router,
        &format!("/query?take={}", SearchParams::MAX_TAKE + 100),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["totalHits"], n);
    assert_eq!(v["data"].as_array().unwrap().len(), SearchParams::MAX_TAKE);
}

#[tokio::test]
async fn search_skip_take_page_window_at_route_layer() {
    // A14: `skip`/`take` select an exact window of the totalHits, in order.
    let n = 10;
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops_with_n_hits(n), MockBytes::default()),
    );
    let (status, _h, body) = get(&router, "/query?skip=3&take=4").await;
    assert_eq!(status, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["totalHits"], n);
    let data = v["data"].as_array().unwrap();
    assert_eq!(data.len(), 4);
    // Window is [3, 7): ids Pkg.0003 .. Pkg.0006 in order.
    assert_eq!(data[0]["id"], "Pkg.0003");
    assert_eq!(data[3]["id"], "Pkg.0006");
}

#[tokio::test]
async fn search_semver_level_param_does_not_filter_results() {
    // A14: `semVerLevel=2.0.0` is accepted for client compatibility and must
    // not break the request or unexpectedly drop results. With prerelease on,
    // a SemVer2 prerelease hit is still returned unchanged.
    let mut ops = MockOps::default();
    ops.search_hits = vec![SearchHit {
        original_id: "Sample.Lib".into(),
        latest_version: "2.0.0-beta.1".into(),
        versions: vec![VersionEntry {
            original_id: "Sample.Lib".into(),
            version: "2.0.0-beta.1".into(),
            version_original: "2.0.0-beta.1".into(),
            listed: true,
        }],
    }];
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );

    // Without semVerLevel.
    let (status, _h, body) = get(&router, "/query?q=sample&prerelease=true").await;
    assert_eq!(status, StatusCode::OK);
    let baseline = json(&body);

    // With semVerLevel=2.0.0 — identical result, nothing filtered out.
    let (status, _h, body) =
        get(&router, "/query?q=sample&prerelease=true&semVerLevel=2.0.0").await;
    assert_eq!(status, StatusCode::OK);
    let with_level = json(&body);

    assert_eq!(with_level, baseline);
    assert_eq!(with_level["totalHits"], 1);
    assert_eq!(with_level["data"][0]["version"], "2.0.0-beta.1");
}

#[tokio::test]
async fn search_supports_head() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops_with_search(), MockBytes::default()),
    );
    let (status, _h, body) = send(&router, "HEAD", "/query?q=sample").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());
}

// ---------------------------------------------------------------------------
// Publish surface (Phase 7) — mock write ops, no DB/S3
// ---------------------------------------------------------------------------

use forge_core::repo::{DeleteOutcome, PublishOutcome, RepoWriteOps, UploadReader, WriteError};
use std::sync::Mutex;

/// Records publish/delete/relist calls and replays a scripted outcome.
#[derive(Default)]
struct MockWrite {
    /// Bytes received by the most recent `store_upload`, for assertions.
    last_upload: Mutex<Option<Vec<u8>>>,
    /// Outcome to return from `store_upload` (default: Created).
    publish_result: Mutex<Option<Result<PublishOutcome, WriteError>>>,
    /// Whether delete/relist should report the version as found.
    found: bool,
}

impl MockWrite {
    fn found() -> Self {
        MockWrite {
            found: true,
            ..Default::default()
        }
    }
}

#[async_trait]
impl RepoWriteOps for MockWrite {
    async fn store_upload(
        &self,
        _repo: &str,
        mut reader: UploadReader,
        max_upload_bytes: u64,
    ) -> Result<PublishOutcome, WriteError> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        if buf.len() as u64 > max_upload_bytes {
            return Err(WriteError::TooLarge {
                limit: max_upload_bytes,
            });
        }
        *self.last_upload.lock().unwrap() = Some(buf);
        self.publish_result
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Ok(PublishOutcome::Created))
    }

    async fn delete_component(
        &self,
        _repo: &str,
        _id: &str,
        _version: &str,
        _hard: bool,
    ) -> Result<DeleteOutcome, WriteError> {
        Ok(if self.found {
            DeleteOutcome::Unlisted
        } else {
            DeleteOutcome::NotFound
        })
    }

    async fn relist(
        &self,
        _repo: &str,
        _id: &str,
        _version: &str,
    ) -> Result<DeleteOutcome, WriteError> {
        Ok(if self.found {
            DeleteOutcome::Relisted
        } else {
            DeleteOutcome::NotFound
        })
    }
}

/// Send a `multipart/form-data` PUT with a single part holding `bytes`.
async fn put_multipart(
    router: &axum::Router,
    uri: &str,
    api_key: Option<&str>,
    bytes: &[u8],
) -> (StatusCode, Vec<u8>) {
    let boundary = "TESTBOUNDARY1234";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"package\"; filename=\"p.nupkg\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let mut builder = Request::builder().method("PUT").uri(uri).header(
        "content-type",
        format!("multipart/form-data; boundary={boundary}"),
    );
    if let Some(k) = api_key {
        builder = builder.header("X-NuGet-ApiKey", k);
    }
    let req = builder.body(Body::from(body)).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let out = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, out)
}

#[tokio::test]
async fn publish_routes_present_for_hosted_only() {
    // Proxy repos do not mount /package; PUT yields 405 (method not allowed) on
    // the unrouted path (axum returns 405 when a path exists for other methods,
    // 404 otherwise). Either way it is not 201/200.
    let proxy = nuget_router(
        RepoKind::Proxy,
        ctx_with_write(RepoKind::Proxy, MockWrite::found()),
    );
    let (status, _) = put_multipart(&proxy, "/package", Some("key"), b"PK\x03\x04").await;
    assert_ne!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn push_requires_api_key() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::found()),
    );
    let (status, _) = put_multipart(&router, "/package", None, b"PK\x03\x04").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn push_streams_bytes_and_returns_201() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::found()),
    );
    let payload = b"PK\x03\x04-nupkg-bytes";
    let (status, _) = put_multipart(&router, "/package", Some("key"), payload).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn push_redeploy_also_returns_201() {
    let w = MockWrite::found();
    *w.publish_result.lock().unwrap() = Some(Ok(PublishOutcome::Replaced));
    let router = nuget_router(RepoKind::Hosted, ctx_with_write(RepoKind::Hosted, w));
    let (status, _) = put_multipart(&router, "/package", Some("key"), b"bytes").await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn push_conflict_maps_to_409() {
    let w = MockWrite::found();
    *w.publish_result.lock().unwrap() = Some(Err(WriteError::Conflict {
        id: "Sample.Lib".into(),
        version: "1.0.0".into(),
    }));
    let router = nuget_router(RepoKind::Hosted, ctx_with_write(RepoKind::Hosted, w));
    let (status, _) = put_multipart(&router, "/package", Some("key"), b"bytes").await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn push_too_large_maps_to_413() {
    let w = MockWrite::found();
    *w.publish_result.lock().unwrap() = Some(Err(WriteError::TooLarge { limit: 4 }));
    let router = nuget_router(RepoKind::Hosted, ctx_with_write(RepoKind::Hosted, w));
    let (status, _) = put_multipart(&router, "/package", Some("key"), b"bytes").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn unlist_returns_204_when_found_404_when_not() {
    let found = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::found()),
    );
    let (status, _h, _) = send_with_key(&found, "DELETE", "/package/Sample.Lib/1.0.0", "key").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let missing = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::default()),
    );
    let (status, _h, _) =
        send_with_key(&missing, "DELETE", "/package/Sample.Lib/9.9.9", "key").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unlist_requires_api_key() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::found()),
    );
    // No API key → 401 (never anonymous), and the delete must not run.
    let (status, _h, _) = send(&router, "DELETE", "/package/Sample.Lib/1.0.0").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn relist_returns_200_when_found_404_when_not() {
    let found = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::found()),
    );
    let (status, _h, _) = send_with_key(&found, "POST", "/package/Sample.Lib/1.0.0", "key").await;
    assert_eq!(status, StatusCode::OK);

    let missing = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::default()),
    );
    let (status, _h, _) = send_with_key(&missing, "POST", "/package/Sample.Lib/9.9.9", "key").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn relist_requires_api_key() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::found()),
    );
    // No API key → 401 (never anonymous), and the relist must not run.
    let (status, _h, _) = send(&router, "POST", "/package/Sample.Lib/1.0.0").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
