//! Integration tests for proxy-repository read ops (Phase 8).
//!
//! Drives [`forge_core::repo::proxy::ProxyRepo`] against real Postgres +
//! versitygw containers, with an **in-process mock upstream NuGet feed** (an
//! axum server) so we can assert upstream hit counts deterministically:
//!
//! * **cache-on-demand** — a 2nd download is served locally (upstream nupkg
//!   fetched exactly once); a 2nd index resolution within the metadata TTL does
//!   not re-fetch the service index.
//! * **singleflight** — two concurrent first-time downloads of the same version
//!   both succeed and converge on a single cached blob (the row lock is held
//!   only for the short state-decision and finalize transactions, never across
//!   the upstream fetch / CAS PUT, so the dedup is best-effort: at least one
//!   upstream fetch happens and, once cached, further reads make none).
//! * **package delay** — a discovered version is hidden from enumeration and
//!   404s on direct download inside the delay window, then becomes visible; the
//!   delay-404 is NOT written to the negative cache.
//! * **genuine 404** — an unknown id is negatively cached (no re-fetch within
//!   the not-found TTL).

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use forge_cache::Cache;
use forge_core::repo::proxy::ProxyRepo;
use forge_core::repo::RepoReadOps;
use forge_db::repository_dao::{self, NewRepository};
use forge_nuget::NugetFormat;
use sqlx::PgPool;
use tokio::net::TcpListener;

// ── Mock upstream NuGet V3 feed ─────────────────────────────────────────────

/// Shared mock state: the package corpus + per-resource hit counters.
struct MockState {
    base: String,
    /// `lower_id -> (version -> nupkg bytes)`.
    packages: HashMap<String, HashMap<String, Vec<u8>>>,
    index_hits: AtomicUsize,
    flat_index_hits: AtomicUsize,
    nupkg_hits: AtomicUsize,
    nuspec_hits: AtomicUsize,
    /// When set, every route requires this `Authorization` header value.
    required_auth: Option<String>,
}

impl MockState {
    fn authorized(&self, headers: &axum::http::HeaderMap) -> bool {
        match &self.required_auth {
            None => true,
            Some(expected) => {
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    == Some(expected.as_str())
            }
        }
    }
}

/// A running mock upstream feed; holds the server task and exposes its base URL.
struct MockUpstream {
    base: String,
    state: Arc<MockState>,
    _task: tokio::task::JoinHandle<()>,
}

impl MockUpstream {
    fn index_hits(&self) -> usize {
        self.state.index_hits.load(Ordering::SeqCst)
    }
    fn nupkg_hits(&self) -> usize {
        self.state.nupkg_hits.load(Ordering::SeqCst)
    }
    fn flat_index_hits(&self) -> usize {
        self.state.flat_index_hits.load(Ordering::SeqCst)
    }
    fn nuspec_hits(&self) -> usize {
        self.state.nuspec_hits.load(Ordering::SeqCst)
    }
}

async fn serve_index(
    State(st): State<Arc<MockState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !st.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    st.index_hits.fetch_add(1, Ordering::SeqCst);
    let body = serde_json::json!({
        "version": "3.0.0",
        "resources": [
            { "@id": format!("{}/flat/", st.base), "@type": "PackageBaseAddress/3.0.0" },
            { "@id": format!("{}/registration/", st.base), "@type": "RegistrationsBaseUrl/3.6.0" },
            { "@id": format!("{}/query", st.base), "@type": "SearchQueryService/3.5.0" },
        ]
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

async fn serve_flat_index(
    State(st): State<Arc<MockState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !st.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    st.flat_index_hits.fetch_add(1, Ordering::SeqCst);
    match st.packages.get(&id) {
        Some(vers) => {
            let mut versions: Vec<String> = vers.keys().cloned().collect();
            versions.sort();
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "versions": versions })),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_nupkg(
    State(st): State<Arc<MockState>>,
    headers: axum::http::HeaderMap,
    Path((id, version, file)): Path<(String, String, String)>,
) -> impl IntoResponse {
    if !st.authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if file.ends_with(".nuspec") {
        st.nuspec_hits.fetch_add(1, Ordering::SeqCst);
        return match st.packages.get(&id).and_then(|v| v.get(&version)) {
            Some(bytes) => (StatusCode::OK, nuspec_of(bytes)).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    st.nupkg_hits.fetch_add(1, Ordering::SeqCst);
    match st.packages.get(&id).and_then(|v| v.get(&version)) {
        Some(bytes) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Extract the `.nuspec` entry from a `.nupkg` (zip) archive.
fn nuspec_of(nupkg: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(nupkg)).expect("nupkg zip");
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).unwrap();
        if entry.name().ends_with(".nuspec") && !entry.name().contains('/') {
            let mut out = Vec::new();
            entry.read_to_end(&mut out).unwrap();
            return out;
        }
    }
    panic!("fixture has no nuspec");
}

/// Boot the mock upstream feed on an ephemeral loopback port.
async fn start_mock(packages: HashMap<String, HashMap<String, Vec<u8>>>) -> MockUpstream {
    start_mock_with_auth(packages, None).await
}

/// Like [`start_mock`], but every route answers 401 unless the request carries
/// `Authorization: <required_auth>`.
async fn start_mock_with_auth(
    packages: HashMap<String, HashMap<String, Vec<u8>>>,
    required_auth: Option<String>,
) -> MockUpstream {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind mock upstream");
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");

    let state = Arc::new(MockState {
        base: base.clone(),
        packages,
        index_hits: AtomicUsize::new(0),
        flat_index_hits: AtomicUsize::new(0),
        nupkg_hits: AtomicUsize::new(0),
        nuspec_hits: AtomicUsize::new(0),
        required_auth,
    });

    let app = Router::new()
        .route("/index.json", get(serve_index))
        .route("/flat/{id}/index.json", get(serve_flat_index))
        .route("/flat/{id}/{version}/{file}", get(serve_nupkg))
        .with_state(state.clone());

    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock upstream serve");
    });

    MockUpstream {
        base,
        state,
        _task: task,
    }
}

// ── Test fixtures ───────────────────────────────────────────────────────────

fn sample_nupkg() -> Vec<u8> {
    fixture_bytes("sample.lib.1.0.0.nupkg")
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../fixtures/nuget");
    p.push(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

/// Create a proxy repository pointing at `remote_url` (loopback mocks are fine
/// since 12.7 §3.6 — only the scheme is checked) with the given delay.
async fn make_proxy(
    pool: &PgPool,
    remote_url: &str,
    package_delay_seconds: i32,
    online: bool,
) -> String {
    let name = format!("proxy{}", common::unique());
    let mut new = NewRepository::proxy(name.clone());
    new.remote_url = Some(remote_url.to_string());
    new.package_delay_seconds = package_delay_seconds;
    new.online = online;
    new.metadata_ttl_seconds = Some(600);
    new.not_found_ttl_seconds = Some(600);
    repository_dao::insert_repository(pool, new)
        .await
        .expect("insert proxy repository");
    name
}

fn proxy_repo(pool: &PgPool, cas: forge_storage::Cas, cache: Cache) -> ProxyRepo {
    ProxyRepo::new(pool.clone(), Arc::new(NugetFormat::new()), cas, cache)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cache_on_demand_fetches_upstream_once() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let cache = Cache::l1_only(128);

    let mut corpus = HashMap::new();
    let mut vers = HashMap::new();
    vers.insert("1.2.3".to_string(), sample_nupkg());
    corpus.insert("sample.lib".to_string(), vers);
    let mock = start_mock(corpus).await;

    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, cache);

    // First download: fetches upstream.
    let loc = px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap();
    assert!(loc.is_some(), "first download should resolve a local nupkg");
    assert_eq!(
        mock.nupkg_hits(),
        1,
        "first download must hit upstream once"
    );

    // Second download: served locally, no upstream nupkg fetch.
    let loc2 = px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap();
    assert!(loc2.is_some());
    assert_eq!(
        mock.nupkg_hits(),
        1,
        "second download must be served locally (no extra upstream fetch)"
    );

    // The service index was resolved once and cached (TTL not elapsed).
    assert_eq!(
        mock.index_hits(),
        1,
        "service index must be fetched once within the metadata TTL"
    );
}

/// Two concurrent first-time downloads of the same version both succeed and
/// converge on a single cached blob.
///
/// The `proxy_cached_version` row lock is held only for the short state-decision
/// and finalize transactions, never across the upstream fetch / CAS PUT
/// (Addendum A7 — never hold a DB tx across a network/S3 call). The singleflight
/// is therefore *best-effort*: under contention more than one caller may fetch
/// from upstream, but the CAS is content-addressed and the finalize tx re-checks
/// `downloaded`, so the writers converge on an identical cached row — and
/// steady-state reads make zero further upstream calls.
#[tokio::test]
async fn singleflight_concurrent_first_downloads_converge() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let cache = Cache::l1_only(128);

    let mut corpus = HashMap::new();
    let mut vers = HashMap::new();
    vers.insert("1.2.3".to_string(), sample_nupkg());
    corpus.insert("sample.lib".to_string(), vers);
    let mock = start_mock(corpus).await;

    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = Arc::new(proxy_repo(&pool, cas, cache));

    // Pre-resolve the index so both racers compete only on the nupkg row lock.
    let r1 = repo.clone();
    let r2 = repo.clone();
    let p1 = px.clone();
    let p2 = px.clone();
    let h1 = tokio::spawn(async move { p1.resolve_nupkg(&r1, "Sample.Lib", "1.2.3").await });
    let h2 = tokio::spawn(async move { p2.resolve_nupkg(&r2, "Sample.Lib", "1.2.3").await });

    let (a, b) = (h1.await.unwrap().unwrap(), h2.await.unwrap().unwrap());
    assert!(
        a.is_some() && b.is_some(),
        "both concurrent reads get bytes"
    );

    let after_race = mock.nupkg_hits();
    assert_eq!(
        after_race, 1,
        "concurrent first downloads in one process collapse to one upstream fetch"
    );

    // Both racers converge on the same cached blob (CAS dedup by sha).
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.blob_s3_key, b.blob_s3_key);

    // The version is now cached; a subsequent read is served locally and makes
    // NO further upstream calls.
    let again = px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .expect("cached version is served locally");
    assert_eq!(again.blob_s3_key, a.blob_s3_key);
    assert_eq!(
        mock.nupkg_hits(),
        after_race,
        "once cached, further reads do not hit upstream"
    );
}

#[tokio::test]
async fn package_delay_hides_then_reveals() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let cache = Cache::l1_only(128);

    let mut corpus = HashMap::new();
    let mut vers = HashMap::new();
    vers.insert("1.2.3".to_string(), sample_nupkg());
    corpus.insert("sample.lib".to_string(), vers);
    let mock = start_mock(corpus).await;

    // 1-second delay window.
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 1, true).await;
    let px = proxy_repo(&pool, cas, cache);

    // Inside the window: hidden from enumeration, 404 on direct download.
    let versions = px.list_versions(&repo, "Sample.Lib").await.unwrap();
    assert!(
        versions.is_empty(),
        "version must be hidden inside the delay window, got {versions:?}"
    );
    let dl = px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap();
    assert!(
        dl.is_none(),
        "direct download must 404 inside the delay window"
    );

    // The delay-404 must NOT have written the negative cache: the row is present
    // but not_found stays false.
    let row = forge_db::proxy_dao::get_cached_version(
        &pool,
        repo_id(&pool, &repo).await,
        "sample.lib",
        "1.2.3",
    )
    .await
    .unwrap()
    .expect("a cached-version row should exist after discovery");
    assert!(
        !row.not_found,
        "delay-gated 404 must never set the negative cache"
    );

    // After the window elapses, it becomes visible and downloadable.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let versions = px.list_versions(&repo, "Sample.Lib").await.unwrap();
    assert_eq!(
        versions.len(),
        1,
        "version must surface after the delay window"
    );
    let dl = px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap();
    assert!(dl.is_some(), "download must succeed after the delay window");
}

#[tokio::test]
async fn genuine_404_is_negatively_cached() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let cache = Cache::l1_only(128);

    // Empty corpus → every id is a genuine upstream 404.
    let mock = start_mock(HashMap::new()).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, cache);

    let v1 = px.list_versions(&repo, "Missing.Pkg").await.unwrap();
    assert!(v1.is_empty());
    let hits_after_first = mock.state.flat_index_hits.load(Ordering::SeqCst);
    assert_eq!(
        hits_after_first, 1,
        "first lookup hits the upstream flat index"
    );

    // Second lookup within the not-found TTL must NOT re-hit upstream.
    let v2 = px.list_versions(&repo, "Missing.Pkg").await.unwrap();
    assert!(v2.is_empty());
    assert_eq!(
        mock.state.flat_index_hits.load(Ordering::SeqCst),
        hits_after_first,
        "genuine 404 must be negatively cached (no upstream re-fetch within TTL)"
    );
}

#[tokio::test]
async fn offline_serves_only_cached() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let cache = Cache::l1_only(128);

    let mut corpus = HashMap::new();
    let mut vers = HashMap::new();
    vers.insert("1.2.3".to_string(), sample_nupkg());
    corpus.insert("sample.lib".to_string(), vers);
    let mock = start_mock(corpus).await;

    // Online proxy: warm the cache.
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas.clone(), cache.clone());
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .is_some());

    // Flip the repo offline.
    sqlx::query!(
        r#"UPDATE repository SET online = false WHERE name = $1"#,
        repo
    )
    .execute(&pool)
    .await
    .unwrap();

    let px_offline = proxy_repo(&pool, cas, Cache::l1_only(128));
    // Cached version still served.
    assert!(px_offline
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .is_some());
    // An uncached version is not fetched while offline.
    assert!(px_offline
        .resolve_nupkg(&repo, "Sample.Lib", "9.9.9")
        .await
        .unwrap()
        .is_none());
}

/// Helper: resolve a repo's id by name.
async fn repo_id(pool: &PgPool, name: &str) -> i64 {
    repository_dao::find_repository_by_name(pool, name)
        .await
        .unwrap()
        .unwrap()
        .id
}

fn sample_corpus(version: &str) -> HashMap<String, HashMap<String, Vec<u8>>> {
    let mut corpus = HashMap::new();
    let mut vers = HashMap::new();
    vers.insert(version.to_string(), sample_nupkg());
    corpus.insert("sample.lib".to_string(), vers);
    corpus
}

/// A private upstream (Azure Artifacts, GitHub Packages, Nexus, …) demands
/// credentials on *every* resource, including the service index and the
/// version listing — not only on the package download.
#[tokio::test]
async fn credentialed_upstream_gets_basic_auth_on_every_request() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let expected = format!(
        "Basic {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "svc:s3cret")
    );
    let mock = start_mock_with_auth(sample_corpus("1.2.3"), Some(expected)).await;

    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    sqlx::query!(
        r#"UPDATE repository SET upstream_username = 'svc', upstream_password = 's3cret' WHERE name = $1"#,
        repo
    )
    .execute(&pool)
    .await
    .unwrap();
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    let versions = px.list_versions(&repo, "Sample.Lib").await.unwrap();
    assert_eq!(versions.len(), 1, "listing must authenticate");
    assert!(px
        .resolve_nuspec(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .is_some());
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .is_some());
    assert_eq!(mock.index_hits(), 1);
    assert_eq!(mock.nupkg_hits(), 1);
}

/// Without credentials the same upstream is a hard error, never a silent
/// empty listing that clients would treat as "package does not exist".
#[tokio::test]
async fn unauthorized_upstream_is_an_error_not_an_empty_listing() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock_with_auth(sample_corpus("1.2.3"), Some("Basic x".into())).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert!(px.list_versions(&repo, "Sample.Lib").await.is_err());
}

/// An upstream serving package bytes whose manifest names a different
/// identity than the requested path must not be cached under that path.
#[tokio::test]
async fn upstream_identity_mismatch_is_rejected() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    // The fixture's manifest says 1.2.3; serve it as 1.0.0.
    let mock = start_mock(sample_corpus("1.0.0")).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    let err = px
        .resolve_nupkg(&repo, "Sample.Lib", "1.0.0")
        .await
        .expect_err("mismatched identity must fail");
    assert!(err.to_string().contains("identifies as"), "{err}");
}

/// The per-package version listing is fetched at most once per metadata TTL.
#[tokio::test]
async fn version_listing_is_cached_for_the_metadata_ttl() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(sample_corpus("1.2.3")).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    for _ in 0..3 {
        assert_eq!(
            px.list_versions(&repo, "Sample.Lib").await.unwrap().len(),
            1
        );
        assert_eq!(px.registration(&repo, "Sample.Lib").await.unwrap().len(), 1);
    }
    assert_eq!(mock.flat_index_hits(), 1);
}

/// `.nuspec` is served from upstream before the package is cached (no full
/// download) and from the local copy afterwards.
#[tokio::test]
async fn nuspec_served_before_and_after_download() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(sample_corpus("1.2.3")).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let blobs: Arc<dyn forge_core::repo::hosted::BlobFetch> =
        Arc::new(StoreBlobs(common::blob_store().await));
    let px = proxy_repo(&pool, cas, Cache::l1_only(128)).with_blob_fetch(blobs);

    let upstream = px
        .resolve_nuspec(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .expect("upstream nuspec");
    assert!(String::from_utf8_lossy(&upstream).contains("<id>Sample.Lib</id>"));
    assert_eq!(mock.nupkg_hits(), 0, "no package download for a manifest");
    assert_eq!(mock.nuspec_hits(), 1);

    px.resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .expect("download");
    let local = px
        .resolve_nuspec(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .expect("local nuspec");
    assert_eq!(local, upstream);
    assert_eq!(
        mock.nuspec_hits(),
        1,
        "downloaded manifest is served locally"
    );

    // Registration now carries the manifest (dependency groups).
    let reg = px.registration(&repo, "Sample.Lib").await.unwrap();
    assert!(reg[0].nuspec_bytes.is_some());
    assert!(reg[0].package_hash_sha512_base64.is_some());

    // Unknown versions stay 404 without touching the manifest endpoint.
    assert!(px
        .resolve_nuspec(&repo, "Sample.Lib", "9.9.9")
        .await
        .unwrap()
        .is_none());
    assert_eq!(mock.nuspec_hits(), 1);
}

/// `BlobFetch` over the shared test bucket.
struct StoreBlobs(forge_storage::BlobStore);

#[async_trait::async_trait]
impl forge_core::repo::hosted::BlobFetch for StoreBlobs {
    async fn fetch_all(&self, s3_key: &str) -> Result<Vec<u8>, forge_core::repo::RepoError> {
        let body = self
            .0
            .get(s3_key)
            .await
            .map_err(|e| forge_core::repo::RepoError::Storage(e.to_string()))?;
        Ok(body
            .collect()
            .await
            .map_err(|e| forge_core::repo::RepoError::Storage(e.to_string()))?
            .into_bytes()
            .to_vec())
    }
}
