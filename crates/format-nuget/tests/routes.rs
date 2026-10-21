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
    is_semver2, NupkgLocation, RegistrationEntry, RepoError, RepoKind, RepoReadOps, SearchHit,
    SearchParams, SearchResult, VersionEntry,
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
        // Echo the configured hits, dropping SemVer 2.0.0 versions unless
        // asked for (before paging, as core does) and applying skip/take so
        // paging is observable.
        let matching: Vec<SearchHit> = self
            .search_hits
            .iter()
            .filter_map(|hit| {
                let mut hit = hit.clone();
                hit.versions
                    .retain(|v| params.include_semver2 || !is_semver2(&v.version_original));
                hit.latest_version = hit.versions.last()?.version.clone();
                Some(hit)
            })
            .collect();
        let total = matching.len();
        let take = params.effective_take();
        let hits: Vec<SearchHit> = matching.into_iter().skip(params.skip).take(take).collect();
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
    async fn open(&self, s3_key: &str) -> Result<forge_nuget::routes::BlobByteStream, RepoError> {
        let bytes = self
            .map
            .get(s3_key)
            .cloned()
            .ok_or_else(|| RepoError::RepoNotFound(s3_key.to_string()))?;
        Ok(Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from(bytes))
        })))
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
        protocol_mutations_allowed: false,
        package_filter: forge_core::authz::PackageFilter::AllowAll,
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
        protocol_mutations_allowed: true,
        package_filter: forge_core::authz::PackageFilter::AllowAll,
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

/// A `.nuspec` is publisher-controlled XML served on the admin origin. An
/// XHTML `<script>` in it must never run there: every feed response is
/// sandboxed, script-free and a download, whatever the route or status.
#[tokio::test]
async fn feed_responses_are_sandboxed_downloads() {
    let mut ops = MockOps::default();
    ops.nuspecs.insert(
        ("evil.pkg".into(), "1.0.0".into()),
        br#"<?xml version="1.0"?><package><html:script xmlns:html="http://www.w3.org/1999/xhtml">fetch('/admin/users')</html:script></package>"#.to_vec(),
    );
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );
    for uri in [
        "/flat/evil.pkg/1.0.0/evil.pkg.nuspec",
        "/flat/evil.pkg/9.9.9/evil.pkg.nuspec",
        "/index.json",
        "/query?q=evil",
        "/no/such/route",
    ] {
        let (_status, headers, _body) = get(&router, uri).await;
        assert_eq!(
            headers
                .get("content-security-policy")
                .map(|v| v.to_str().unwrap()),
            Some("default-src 'none'; sandbox"),
            "{uri}"
        );
        assert_eq!(
            headers
                .get("content-disposition")
                .map(|v| v.to_str().unwrap()),
            Some("attachment"),
            "{uri}"
        );
        assert_eq!(
            headers
                .get("x-content-type-options")
                .map(|v| v.to_str().unwrap()),
            Some("nosniff"),
            "{uri}"
        );
    }
}

/// Ids that are not well-formed never reach the read backend (a proxy would
/// paste them into credentialed upstream URLs): every id-addressed route
/// answers 404 first, however the id is percent-encoded.
#[tokio::test]
async fn malformed_ids_are_404_before_the_backend() {
    let traversal = "x/../sample.lib".to_string();
    let mut ops = MockOps::default();
    let entry = VersionEntry {
        original_id: traversal.clone(),
        version: "1.0.0".into(),
        version_original: "1.0.0".into(),
        listed: true,
    };
    // A backend that would answer for the malformed id if asked.
    ops.versions.insert(traversal.clone(), vec![entry]);
    ops.nuspecs
        .insert((traversal.clone(), "1.0.0".into()), b"<package/>".to_vec());
    let router = nuget_router(
        RepoKind::Proxy,
        ctx(RepoKind::Proxy, ops, MockBytes::default()),
    );
    for uri in [
        "/flat/x%2F..%2Fsample.lib/index.json",
        "/flat/X%2F..%2Fsample.lib/1.0.0/x.nuspec",
        "/flat/sample.lib%3Fq%3D1/index.json",
        "/flat/sample.lib%23frag/index.json",
        "/registration/x%2F..%2Fsample.lib/index.json",
        "/registration/x%2F..%2Fsample.lib/1.0.0.json",
        "/catalog/x%2F..%2Fsample.lib/1.0.0.json",
    ] {
        let (status, _h, _b) = get(&router, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
}

/// A version longer than any publishable one answers 404 before the backend
/// is asked, on every route that reads a version from the path.
#[tokio::test]
async fn overlong_versions_are_404_before_the_backend() {
    let long = format!("1.0.0-{}", "a".repeat(59));
    let mut ops = MockOps::default();
    // A backend that would answer for the long version if asked.
    ops.nuspecs
        .insert(("sample.lib".into(), long.clone()), b"<package/>".to_vec());
    let router = nuget_router(
        RepoKind::Proxy,
        ctx(RepoKind::Proxy, ops, MockBytes::default()),
    );
    for uri in [
        format!("/flat/sample.lib/{long}/sample.lib.nuspec"),
        format!("/registration/sample.lib/{long}.json"),
        format!("/catalog/sample.lib/{long}.json"),
    ] {
        let (status, _h, _b) = get(&router, &uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
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
                manifest_summary: None,
                published: None,
            },
            RegistrationEntry {
                original_id: "Sample.Lib".into(),
                version: "2.0.0".into(),
                listed: true,
                package_hash_sha512_base64: Some("HASH2".into()),
                nuspec_bytes: None,
                manifest_summary: None,
                published: None,
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

/// Up to 128 versions the index inlines every page (of 64); beyond that the
/// index only lists the pages and each page is served on its own URL.
#[tokio::test]
async fn registration_pages_large_packages() {
    let entry = |i: usize| RegistrationEntry {
        original_id: "Big.Lib".into(),
        version: format!("1.0.{i}"),
        listed: true,
        package_hash_sha512_base64: None,
        nuspec_bytes: None,
        manifest_summary: None,
        published: None,
    };
    let mut ops = MockOps::default();
    ops.registration
        .insert("big.lib".into(), (0..200).map(entry).collect());
    ops.registration
        .insert("small.lib".into(), (0..100).map(entry).collect());
    ops.registration
        .insert("huge.lib".into(), (0..300).map(entry).collect());
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );

    let (status, _h, body) = get(&router, "/registration/small.lib/index.json").await;
    assert_eq!(status, StatusCode::OK);
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["count"], 2);
    assert_eq!(doc["items"][0]["count"], 64);
    assert_eq!(doc["items"][0]["items"].as_array().unwrap().len(), 64);
    assert_eq!(doc["items"][1]["items"].as_array().unwrap().len(), 36);

    let (status, _h, body) = get(&router, "/registration/big.lib/index.json").await;
    assert_eq!(status, StatusCode::OK);
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["count"], 4);
    let pages = doc["items"].as_array().unwrap();
    assert!(
        pages.iter().all(|p| p.get("items").is_none()),
        "pages are not inlined"
    );
    assert_eq!(pages[3]["count"], 8);
    let page_url = pages[1]["@id"].as_str().unwrap();
    assert_eq!(
        page_url,
        format!("{BASE}/v3/main/registration/big.lib/page/1.0.64/1.0.127.json")
    );
    let (status, _h, body) = get(&router, &page_url[format!("{BASE}/v3/main").len()..]).await;
    assert_eq!(status, StatusCode::OK);
    let page: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 64);
    assert_eq!(page["lower"], "1.0.64");
    for bad in [
        "/registration/big.lib/page/not-a-version/1.0.2.json",
        "/registration/nope.lib/page/1.0.0/1.0.63.json",
        // More versions than any page holds: not rendered in one response.
        "/registration/huge.lib/page/0.0.0/9.0.0.json",
    ] {
        let (status, _h, _b) = get(&router, bad).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{bad}");
    }
}

/// A page URL from an index a client cached keeps resolving after pushes and
/// deletes re-chunk the index: the page serves the versions in its range.
#[tokio::test]
async fn registration_page_urls_survive_a_rechunk() {
    let entry = |v: String| RegistrationEntry {
        original_id: "Big.Lib".into(),
        version: v,
        listed: true,
        package_hash_sha512_base64: None,
        nuspec_bytes: None,
        manifest_summary: None,
        published: None,
    };
    // As cached: 1.0.0 .. 1.0.199; the second page is 1.0.64 .. 1.0.127.
    // Now 1.0.0 is deleted and a servicing release 1.0.100-fix lands inside
    // that page's range, so every chunk boundary has moved.
    let mut versions: Vec<RegistrationEntry> =
        (1..200).map(|i| entry(format!("1.0.{i}"))).collect();
    versions.insert(99, entry("1.0.100-fix".into()));
    let mut ops = MockOps::default();
    ops.registration.insert("big.lib".into(), versions);
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );

    let (status, _h, body) = get(&router, "/registration/big.lib/page/1.0.64/1.0.127.json").await;
    assert_eq!(status, StatusCode::OK);
    let page: Value = serde_json::from_slice(&body).unwrap();
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 65, "1.0.64 ..= 1.0.127 plus 1.0.100-fix");
    assert_eq!(items[0]["catalogEntry"]["version"], "1.0.64");
    assert_eq!(items[64]["catalogEntry"]["version"], "1.0.127");
    assert_eq!(page["lower"], "1.0.64");
    assert_eq!(page["upper"], "1.0.127");
    assert_eq!(
        page["@id"],
        format!("{BASE}/v3/main/registration/big.lib/page/1.0.64/1.0.127.json")
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
        ..Default::default()
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
            ..Default::default()
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
async fn search_hides_semver2_versions_unless_semver_level_2() {
    // Protocol rule: SemVer 2.0.0 versions (dotted prerelease labels, build
    // metadata) are only returned to clients sending `semVerLevel=2.0.0`.
    // They are dropped before paging, so a legacy client's pages stay full
    // and `totalHits` counts only what it can page through.
    let hit = |id: &str, versions: &[(&str, &str)]| SearchHit {
        original_id: id.into(),
        latest_version: versions.last().unwrap().0.into(),
        versions: versions
            .iter()
            .map(|(version, original)| VersionEntry {
                original_id: id.into(),
                version: (*version).into(),
                version_original: (*original).into(),
                listed: true,
            })
            .collect(),
        ..Default::default()
    };
    let mut ops = MockOps::default();
    ops.search_hits = vec![
        hit("Only.Dotted", &[("1.0.0-beta.1", "1.0.0-beta.1")]),
        hit("Plain.One", &[("1.0.0", "1.0.0")]),
        hit("Only.Metadata", &[("2.0.0", "2.0.0+build.5")]),
        hit(
            "Sample.Lib",
            &[("1.0.0", "1.0.0"), ("2.0.0-beta.1", "2.0.0-beta.1")],
        ),
        hit("Plain.Two", &[("1.0.0", "1.0.0")]),
    ];
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );
    let ids = |v: &Value| -> Vec<String> {
        v["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap().to_string())
            .collect()
    };

    let (status, _h, body) = get(&router, "/query?prerelease=true&take=2").await;
    assert_eq!(status, StatusCode::OK);
    let legacy = json(&body);
    assert_eq!(legacy["totalHits"], 3);
    assert_eq!(ids(&legacy), ["Plain.One", "Sample.Lib"], "a full page");
    assert_eq!(legacy["data"][1]["version"], "1.0.0");
    assert_eq!(legacy["data"][1]["versions"].as_array().unwrap().len(), 1);

    let (_status, _h, body) = get(&router, "/query?prerelease=true&skip=2&take=2").await;
    let legacy = json(&body);
    assert_eq!(legacy["totalHits"], 3);
    assert_eq!(ids(&legacy), ["Plain.Two"]);

    let (status, _h, body) = get(
        &router,
        "/query?prerelease=true&skip=2&take=2&semVerLevel=2.0.0",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let modern = json(&body);
    assert_eq!(modern["totalHits"], 5);
    assert_eq!(ids(&modern), ["Only.Metadata", "Sample.Lib"]);
    assert_eq!(modern["data"][1]["version"], "2.0.0-beta.1");
    assert_eq!(modern["data"][1]["versions"].as_array().unwrap().len(), 2);
}

fn nuspec_with_metadata() -> Vec<u8> {
    br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Sample.Lib</id>
    <version>1.0.0</version>
    <authors>Alice, Bob</authors>
    <description>A sample &amp; more</description>
    <tags>json serializer</tags>
    <license type="expression">MIT</license>
    <projectUrl>https://example.com/p</projectUrl>
  </metadata>
</package>"#
        .to_vec()
}

#[tokio::test]
async fn search_hits_carry_manifest_metadata_and_downloads() {
    let mut ops = MockOps::default();
    ops.search_hits = vec![SearchHit {
        original_id: "Sample.Lib".into(),
        latest_version: "1.0.0".into(),
        versions: vec![VersionEntry {
            original_id: "Sample.Lib".into(),
            version: "1.0.0".into(),
            version_original: "1.0.0".into(),
            listed: true,
        }],
        nuspec_bytes: Some(nuspec_with_metadata()),
        manifest_summary: None,
        total_downloads: Some(42),
    }];
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );
    let (_s, _h, body) = get(&router, "/query?q=sample").await;
    let hit = &json(&body)["data"][0];
    assert_eq!(hit["description"], "A sample & more");
    assert_eq!(hit["authors"], serde_json::json!(["Alice", "Bob"]));
    assert_eq!(hit["tags"], serde_json::json!(["json", "serializer"]));
    assert_eq!(hit["licenseUrl"], "https://licenses.nuget.org/MIT");
    assert_eq!(hit["projectUrl"], "https://example.com/p");
    assert_eq!(hit["totalDownloads"], 42);
    assert_eq!(
        hit["registration"],
        "https://forge.example.com/v3/main/registration/sample.lib/index.json"
    );
}

#[tokio::test]
async fn registration_leaf_and_catalog_documents_resolve() {
    let published = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut ops = MockOps::default();
    ops.registration.insert(
        "sample.lib".to_string(),
        vec![
            RegistrationEntry {
                original_id: "Sample.Lib".into(),
                version: "1.0.0".into(),
                listed: true,
                package_hash_sha512_base64: Some("HASH".into()),
                nuspec_bytes: Some(nuspec_with_metadata()),
                manifest_summary: None,
                published: Some(published),
            },
            RegistrationEntry {
                original_id: "Sample.Lib".into(),
                version: "0.9.0".into(),
                listed: false,
                package_hash_sha512_base64: None,
                nuspec_bytes: None,
                manifest_summary: None,
                published: Some(published),
            },
        ],
    );
    let router = nuget_router(
        RepoKind::Hosted,
        ctx(RepoKind::Hosted, ops, MockBytes::default()),
    );

    let (status, _h, body) = get(&router, "/registration/sample.lib/index.json").await;
    assert_eq!(status, StatusCode::OK);
    let index = json(&body);
    let leaf = &index["items"][0]["items"][0];
    let ce = &leaf["catalogEntry"];
    assert_eq!(ce["published"], "2026-01-02T03:04:05.000+00:00");
    assert_eq!(ce["description"], "A sample & more");
    assert_eq!(ce["licenseExpression"], "MIT");
    assert_eq!(
        index["items"][0]["items"][1]["catalogEntry"]["published"], "1900-01-01T00:00:00+00:00",
        "unlisted versions use nuget.org's 1900 marker"
    );

    // The leaf @id resolves to the leaf document …
    let leaf_url = leaf["@id"].as_str().unwrap();
    let path = leaf_url
        .strip_prefix("https://forge.example.com/v3/main")
        .unwrap();
    let (status, _h, body) = get(&router, path).await;
    assert_eq!(status, StatusCode::OK);
    let doc = json(&body);
    assert_eq!(doc["listed"], true);
    assert_eq!(doc["catalogEntry"], ce["@id"]);

    // … and its catalogEntry URL to the catalog entry.
    let catalog_url = doc["catalogEntry"].as_str().unwrap();
    let path = catalog_url
        .strip_prefix("https://forge.example.com/v3/main")
        .unwrap();
    let (status, _h, body) = get(&router, path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["authors"], "Alice, Bob");

    let (status, _h, _b) = get(&router, "/registration/sample.lib/9.9.9.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn service_index_advertises_every_registration_variant() {
    let router = nuget_router(
        RepoKind::Proxy,
        ctx(RepoKind::Proxy, MockOps::default(), MockBytes::default()),
    );
    let (_s, _h, body) = get(&router, "/index.json").await;
    let types: Vec<String> = json(&body)["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["@type"].as_str().unwrap().to_string())
        .collect();
    for ty in [
        "RegistrationsBaseUrl",
        "RegistrationsBaseUrl/3.0.0-rc",
        "RegistrationsBaseUrl/3.4.0",
        "RegistrationsBaseUrl/3.6.0",
    ] {
        assert!(types.iter().any(|t| t == ty), "missing {ty}");
    }
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
    last_upload: Arc<Mutex<Option<Vec<u8>>>>,
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
        if let Err(e) = reader.read_to_end(&mut buf).await {
            return Err(WriteError::Repo(RepoError::Storage(e.to_string())));
        }
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

/// The multipart parser buffers everything before the first part in memory:
/// a body that does not reach its first part's headers within 64 KiB is
/// refused (it used to be buffered up to the whole upload limit).
#[tokio::test]
async fn push_with_an_oversized_multipart_preamble_is_refused() {
    let w = MockWrite::found();
    let last = w.last_upload.clone();
    let router = nuget_router(RepoKind::Hosted, ctx_with_write(RepoKind::Hosted, w));
    let boundary = "TESTBOUNDARY1234";
    let mut body = vec![b'x'; 1024 * 1024];
    body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"package\"; filename=\"p.nupkg\"\r\n\r\n",
    );
    body.extend_from_slice(b"PK\x03\x04-nupkg-bytes");
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let req = Request::builder()
        .method("PUT")
        .uri("/package")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("X-NuGet-ApiKey", "key")
        .body(Body::from(body))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(last.lock().unwrap().as_ref().is_none_or(Vec::is_empty));

    // A short preamble is still fine.
    let (status, _) = put_multipart(&router, "/package", Some("key"), b"PK\x03\x04").await;
    assert_eq!(status, StatusCode::CREATED);
}

/// The preamble guard finds the boundary and the part headers when they are
/// split across chunks, down to one byte per chunk.
#[tokio::test]
async fn push_trickled_byte_by_byte_is_accepted() {
    let w = MockWrite::found();
    let last = w.last_upload.clone();
    let router = nuget_router(RepoKind::Hosted, ctx_with_write(RepoKind::Hosted, w));
    let boundary = "TESTBOUNDARY1234";
    let mut body = b"preamble\r\n".to_vec();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"package\"; filename=\"p.nupkg\"\r\n\r\n",
    );
    body.extend_from_slice(b"PK\x03\x04-nupkg-bytes");
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = body
        .into_iter()
        .map(|b| Ok(bytes::Bytes::from(vec![b])))
        .collect();
    let req = Request::builder()
        .method("PUT")
        .uri("/package")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("X-NuGet-ApiKey", "key")
        .body(Body::from_stream(futures_util::stream::iter(chunks)))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        last.lock().unwrap().as_deref(),
        Some(&b"PK\x03\x04-nupkg-bytes"[..])
    );
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
async fn push_rejects_non_protocol_principal_even_with_auth_header() {
    let mut context = ctx_with_write(RepoKind::Hosted, MockWrite::found());
    context.protocol_mutations_allowed = false;
    let router = nuget_router(RepoKind::Hosted, context);
    let (status, body) =
        put_multipart(&router, "/package", Some("unrelated-header"), b"PK\x03\x04").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "API token or workload identity required"
    );
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

/// Regression: axum's extractor default (2 MiB) used to reject every
/// real-sized push with a 500. A multi-MiB package must stream through.
#[tokio::test]
async fn push_larger_than_axum_default_limit_succeeds() {
    let w = MockWrite::found();
    let last = w.last_upload.clone();
    let router = nuget_router(RepoKind::Hosted, ctx_with_write(RepoKind::Hosted, w));
    let payload = vec![0x5a_u8; 3 * 1024 * 1024 + 17];
    let (status, _) = put_multipart(&router, "/package", Some("key"), &payload).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        last.lock().unwrap().as_ref().map(Vec::len),
        Some(payload.len())
    );
}

/// A body beyond `max_upload_bytes` + framing slack trips the request-body
/// limit mid-stream; that must surface as 413, not as a storage error.
#[tokio::test]
async fn push_over_body_limit_maps_to_413() {
    let router = nuget_router(
        RepoKind::Hosted,
        ctx_with_write(RepoKind::Hosted, MockWrite::found()),
    );
    let payload = vec![0x5a_u8; 18 * 1024 * 1024];
    let (status, _) = put_multipart(&router, "/package", Some("key"), &payload).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn selector_denied_push_maps_to_403() {
    let w = MockWrite::found();
    *w.publish_result.lock().unwrap() = Some(Err(WriteError::ForbiddenPackage {
        id: "Other.Lib".into(),
    }));
    let router = nuget_router(RepoKind::Hosted, ctx_with_write(RepoKind::Hosted, w));
    let (status, _) = put_multipart(&router, "/package", Some("key"), b"bytes").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
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

#[tokio::test]
async fn selector_excluded_identifier_mutations_are_404() {
    let mut ctx = ctx_with_write(RepoKind::Hosted, MockWrite::found());
    ctx.package_filter = forge_core::authz::PackageFilter::DenyAll;
    let router = nuget_router(RepoKind::Hosted, ctx);

    let (delete_status, _, _) =
        send_with_key(&router, "DELETE", "/package/Hidden.Lib/1.0.0", "key").await;
    assert_eq!(delete_status, StatusCode::NOT_FOUND);

    let (relist_status, _, _) =
        send_with_key(&router, "POST", "/package/Hidden.Lib/1.0.0", "key").await;
    assert_eq!(relist_status, StatusCode::NOT_FOUND);
}
