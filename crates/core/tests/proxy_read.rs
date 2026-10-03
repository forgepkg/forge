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
//!   the not-found TTL); a version marker hides a listed version only within
//!   the TTL, an upstream listing clears it, and a version known only from a
//!   (failed or 404) download attempt is never listed.
//! * **self-healing cache** — a downloaded version whose local copy vanished
//!   is fetched again.
//! * **verified upstream bytes** — a mis-identified upstream `.nuspec` is not
//!   served; a rejected package is not re-downloaded on every retry.
//! * **upstream registration** — listed / published / dependency groups of
//!   versions not downloaded yet, bounded page fetches, flat-view fallback.

mod common;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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

/// `lower_id -> (version -> nupkg bytes)`.
type Corpus = HashMap<String, HashMap<String, Vec<u8>>>;

/// Shared mock state: the package corpus + per-resource hit counters, plus
/// knobs to script misbehaving upstreams.
struct MockState {
    base: String,
    packages: Mutex<Corpus>,
    index_hits: AtomicUsize,
    flat_index_hits: AtomicUsize,
    nupkg_hits: AtomicUsize,
    nuspec_hits: AtomicUsize,
    registration_hits: AtomicUsize,
    registration_page_hits: AtomicUsize,
    /// When set, every route requires this `Authorization` header value.
    required_auth: Option<String>,
    /// `(lower_id, version)` whose `.nupkg` answers 500 (a transient failure).
    failing: Mutex<HashSet<(String, String)>>,
    /// `(lower_id, version)` whose `.nupkg` answers 404 although listed.
    missing: Mutex<HashSet<(String, String)>>,
    /// `(lower_id, version)` whose `.nuspec` is served as these bytes.
    nuspec_override: Mutex<HashMap<(String, String), Vec<u8>>>,
    /// `lower_id -> registration index document`.
    registrations: Mutex<HashMap<String, serde_json::Value>>,
    /// `"{lower_id}/{file}" -> registration page document`.
    registration_pages: Mutex<HashMap<String, serde_json::Value>>,
    /// `lower_id -> flat-container listing document` served instead of the
    /// corpus's.
    flat_index_override: Mutex<HashMap<String, serde_json::Value>>,
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

    fn package(&self, id: &str, version: &str) -> Option<Vec<u8>> {
        self.packages
            .lock()
            .unwrap()
            .get(id)
            .and_then(|v| v.get(version))
            .cloned()
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
    fn registration_hits(&self) -> usize {
        self.state.registration_hits.load(Ordering::SeqCst)
    }
    fn registration_page_hits(&self) -> usize {
        self.state.registration_page_hits.load(Ordering::SeqCst)
    }
    /// Publish (or replace) a version upstream.
    fn publish(&self, lower_id: &str, version: &str, bytes: Vec<u8>) {
        self.state
            .packages
            .lock()
            .unwrap()
            .entry(lower_id.to_string())
            .or_default()
            .insert(version.to_string(), bytes);
    }
    /// Delete a version upstream (gone from the listing and the flat container).
    fn unpublish(&self, lower_id: &str, version: &str) {
        if let Some(versions) = self.state.packages.lock().unwrap().get_mut(lower_id) {
            versions.remove(version);
        }
    }

    fn fail_nupkg(&self, lower_id: &str, version: &str) {
        self.state
            .failing
            .lock()
            .unwrap()
            .insert((lower_id.to_string(), version.to_string()));
    }
    fn miss_nupkg(&self, lower_id: &str, version: &str) {
        self.state
            .missing
            .lock()
            .unwrap()
            .insert((lower_id.to_string(), version.to_string()));
    }
    fn override_nuspec(&self, lower_id: &str, version: &str, bytes: Vec<u8>) {
        self.state
            .nuspec_override
            .lock()
            .unwrap()
            .insert((lower_id.to_string(), version.to_string()), bytes);
    }
    fn set_registration(&self, lower_id: &str, doc: serde_json::Value) {
        self.state
            .registrations
            .lock()
            .unwrap()
            .insert(lower_id.to_string(), doc);
    }
    fn set_registration_page(&self, lower_id: &str, file: &str, doc: serde_json::Value) {
        self.state
            .registration_pages
            .lock()
            .unwrap()
            .insert(format!("{lower_id}/{file}"), doc);
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
    if let Some(doc) = st.flat_index_override.lock().unwrap().get(&id) {
        return (StatusCode::OK, axum::Json(doc.clone())).into_response();
    }
    let versions = st
        .packages
        .lock()
        .unwrap()
        .get(&id)
        .map(|vers| vers.keys().cloned().collect::<Vec<_>>());
    match versions {
        Some(mut versions) => {
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
    let key = (id.clone(), version.clone());
    if file.ends_with(".nuspec") {
        st.nuspec_hits.fetch_add(1, Ordering::SeqCst);
        if let Some(bytes) = st.nuspec_override.lock().unwrap().get(&key) {
            return (StatusCode::OK, bytes.clone()).into_response();
        }
        return match st.package(&id, &version) {
            Some(bytes) => (StatusCode::OK, nuspec_of(&bytes)).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    st.nupkg_hits.fetch_add(1, Ordering::SeqCst);
    if st.failing.lock().unwrap().contains(&key) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if st.missing.lock().unwrap().contains(&key) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match st.package(&id, &version) {
        Some(bytes) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_registration(
    State(st): State<Arc<MockState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    st.registration_hits.fetch_add(1, Ordering::SeqCst);
    match st.registrations.lock().unwrap().get(&id) {
        Some(doc) => (StatusCode::OK, axum::Json(doc.clone())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_registration_page(
    State(st): State<Arc<MockState>>,
    Path((id, file)): Path<(String, String)>,
) -> impl IntoResponse {
    st.registration_page_hits.fetch_add(1, Ordering::SeqCst);
    match st
        .registration_pages
        .lock()
        .unwrap()
        .get(&format!("{id}/{file}"))
    {
        Some(doc) => (StatusCode::OK, axum::Json(doc.clone())).into_response(),
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
async fn start_mock(packages: Corpus) -> MockUpstream {
    start_mock_with_auth(packages, None).await
}

/// Like [`start_mock`], but every route answers 401 unless the request carries
/// `Authorization: <required_auth>`.
async fn start_mock_with_auth(packages: Corpus, required_auth: Option<String>) -> MockUpstream {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind mock upstream");
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");

    let state = Arc::new(MockState {
        base: base.clone(),
        packages: Mutex::new(packages),
        index_hits: AtomicUsize::new(0),
        flat_index_hits: AtomicUsize::new(0),
        nupkg_hits: AtomicUsize::new(0),
        nuspec_hits: AtomicUsize::new(0),
        registration_hits: AtomicUsize::new(0),
        registration_page_hits: AtomicUsize::new(0),
        required_auth,
        failing: Mutex::default(),
        missing: Mutex::default(),
        nuspec_override: Mutex::default(),
        registrations: Mutex::default(),
        registration_pages: Mutex::default(),
        flat_index_override: Mutex::default(),
    });

    let app = Router::new()
        .route("/index.json", get(serve_index))
        .route("/flat/{id}/index.json", get(serve_flat_index))
        .route("/flat/{id}/{version}/{file}", get(serve_nupkg))
        .route("/registration/{id}/index.json", get(serve_registration))
        .route(
            "/registration/{id}/page/{file}",
            get(serve_registration_page),
        )
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

/// A package id is pasted into credentialed upstream URLs. Ids that are not
/// well-formed (`/`, `..`, `?`, `#` — reachable through percent-encoding on
/// the feed routes) never reach the upstream and are never recorded, whatever
/// read operation (or group fan-out) carries them.
#[tokio::test]
async fn malformed_ids_never_reach_the_upstream() {
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

    for id in [
        "x/../sample.lib",
        "../flat/sample.lib",
        "sample.lib/index.json?",
        "sample.lib#",
        "sample%2elib",
        "",
    ] {
        assert!(
            px.list_versions(&repo, id).await.unwrap().is_empty(),
            "{id:?}"
        );
        assert!(
            px.registration(&repo, id).await.unwrap().is_empty(),
            "{id:?}"
        );
        assert!(
            px.resolve_nupkg(&repo, id, "1.2.3")
                .await
                .unwrap()
                .is_none(),
            "{id:?}"
        );
        assert!(
            px.resolve_nuspec(&repo, id, "1.2.3")
                .await
                .unwrap()
                .is_none(),
            "{id:?}"
        );
    }
    assert_eq!(
        mock.flat_index_hits(),
        0,
        "no listing request for a malformed id"
    );
    assert_eq!(mock.nupkg_hits(), 0);
    assert_eq!(mock.nuspec_hits(), 0);
    assert_eq!(mock.registration_hits(), 0);
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM proxy_cached_version v JOIN repository r ON r.id = v.repository_id \
         WHERE r.name = $1",
    )
    .bind(&repo)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 0, "nothing recorded under a malformed id");

    // The well-formed id still works.
    assert_eq!(
        px.list_versions(&repo, "Sample.Lib").await.unwrap().len(),
        1
    );
}

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

fn sample_corpus(version: &str) -> Corpus {
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

    // Registration now carries the manifest (dependency groups), as the
    // summary stored at download: no manifest read per request.
    let reg = px.registration(&repo, "Sample.Lib").await.unwrap();
    assert!(reg[0].manifest_summary.is_some());
    assert!(reg[0].nuspec_bytes.is_none());
    assert!(reg[0].package_hash_sha512_base64.is_some());

    // A version cached before summaries were stored is summarized from its
    // local manifest once, and the summary is backfilled.
    let cleared = sqlx::query(
        "UPDATE component SET manifest_summary = NULL \
         WHERE name = 'sample.lib' AND version = '1.2.3' \
           AND repository_id = (SELECT id FROM repository WHERE name = $1)",
    )
    .bind(&repo)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(cleared.rows_affected(), 1);
    let reg = px.registration(&repo, "Sample.Lib").await.unwrap();
    assert_eq!(reg[0].manifest_summary, reg_summary(&pool, &repo).await);
    assert!(reg[0].manifest_summary.is_some(), "backfilled");
    assert_eq!(mock.nuspec_hits(), 1, "from the local copy, not upstream");

    // Unknown versions stay 404 without touching the manifest endpoint.
    assert!(px
        .resolve_nuspec(&repo, "Sample.Lib", "9.9.9")
        .await
        .unwrap()
        .is_none());
    assert_eq!(mock.nuspec_hits(), 1);
}

/// The stored manifest summary of `sample.lib` 1.2.3 in proxy `repo`.
async fn reg_summary(pool: &sqlx::PgPool, repo: &str) -> Option<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT manifest_summary FROM component \
         WHERE name = 'sample.lib' AND version = '1.2.3' \
           AND repository_id = (SELECT id FROM repository WHERE name = $1)",
    )
    .bind(repo)
    .fetch_one(pool)
    .await
    .unwrap()
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

// ── Listing visibility, self-healing cache, verified upstream bytes ─────────

/// A minimal `.nupkg` for `id@version`.
fn make_nupkg(id: &str, version: &str) -> Vec<u8> {
    use std::io::Write;
    let nuspec = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <authors>test</authors>
    <description>generated test package</description>
  </metadata>
</package>"#
    );
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zw.start_file(
        format!("{id}.nuspec"),
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zw.write_all(nuspec.as_bytes()).unwrap();
    zw.finish().unwrap().into_inner()
}

/// A corpus of one package with generated `versions`.
fn corpus_of(id: &str, versions: &[&str]) -> Corpus {
    let mut corpus = Corpus::new();
    let entry = corpus.entry(id.to_lowercase()).or_default();
    for v in versions {
        entry.insert(v.to_string(), make_nupkg(id, v));
    }
    corpus
}

fn versions_of(entries: &[forge_core::repo::VersionEntry]) -> Vec<String> {
    entries.iter().map(|v| v.version.clone()).collect()
}

/// Versions of the single search hit for `q` (empty when there is no hit).
async fn searched_versions(px: &ProxyRepo, repo: &str, q: &str) -> Vec<String> {
    let result = px
        .search(
            repo,
            &forge_core::repo::SearchParams {
                q: q.to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    result
        .hits
        .first()
        .map(|h| versions_of(&h.versions))
        .unwrap_or_default()
}

/// H3: requesting a version before it is released plants a not-found marker;
/// once the upstream publishes it, the next listing refresh must clear the
/// marker (even within `not_found_ttl`) so `index.json`, registration and
/// search offer the release — and it downloads.
#[tokio::test]
async fn planted_not_found_marker_is_cleared_by_a_later_listing() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;

    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "2.0.0")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"]
    );

    // The release appears upstream; a fresh cache stands in for an expired
    // metadata TTL (the not-found TTL of 600 s has NOT elapsed).
    mock.publish("contoso.lib", "2.0.0", make_nupkg("Contoso.Lib", "2.0.0"));
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.0.0"],
        "an upstream listing containing the version clears its marker"
    );
    assert_eq!(
        px.registration(&repo, "Contoso.Lib").await.unwrap().len(),
        2
    );
    assert_eq!(
        searched_versions(&px, &repo, "contoso").await,
        ["1.0.0", "2.0.0"]
    );
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "2.0.0")
        .await
        .unwrap()
        .is_some());
}

/// H3 follow-up: a version deleted upstream (e.g. a malicious release pulled
/// from nuget.org) leaves the listings at the next refresh, instead of
/// reappearing every `not_found_ttl`; it comes back if the upstream lists it
/// again.
#[tokio::test]
async fn versions_deleted_upstream_leave_the_listings() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0", "2.1.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.1.0"]
    );

    mock.unpublish("contoso.lib", "2.1.0");
    // A fresh cache stands in for an expired metadata TTL.
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"],
        "the deleted version is retired"
    );
    assert_eq!(
        px.registration(&repo, "Contoso.Lib").await.unwrap().len(),
        1
    );
    assert_eq!(searched_versions(&px, &repo, "contoso").await, ["1.0.0"]);
    // Even once the not-found TTL would have expired.
    sqlx::query(
        "UPDATE proxy_cached_version SET not_found_at = now() - interval '2 hours' \
         WHERE name = 'contoso.lib'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"]
    );

    mock.publish("contoso.lib", "2.1.0", make_nupkg("Contoso.Lib", "2.1.0"));
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.1.0"],
        "listed again, visible again"
    );
}

/// Search applies every listing condition (prerelease, the package delay, a
/// live not-found marker) in SQL and pages over ids, loading versions for the
/// returned page only.
#[tokio::test]
async fn search_applies_listing_conditions_and_pages_over_ids() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mut corpus = corpus_of("Contoso.A", &["1.0.0", "2.0.0-beta"]);
    corpus.extend(corpus_of("Contoso.B", &["1.0.0"]));
    corpus.extend(corpus_of("Contoso.C", &["3.0.0-rc.1"]));
    corpus.extend(corpus_of("Contoso.D", &["1.0.0"]));
    let mock = start_mock(corpus).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 3600, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    for id in ["Contoso.A", "Contoso.B", "Contoso.C", "Contoso.D"] {
        px.list_versions(&repo, id).await.unwrap();
    }
    let search = |q: &str, prerelease: bool, skip: usize, take: usize| {
        let params = forge_core::repo::SearchParams {
            q: q.to_string(),
            skip,
            take,
            prerelease,
        };
        let px = &px;
        let repo = repo.clone();
        async move {
            let result = px.search(&repo, &params).await.unwrap();
            let hits: Vec<(String, Vec<String>)> = result
                .hits
                .iter()
                .map(|h| (h.original_id.clone(), versions_of(&h.versions)))
                .collect();
            (result.total_hits, hits)
        }
    };

    // Everything was first seen just now: inside the one-hour delay.
    assert_eq!(search("contoso", true, 0, 20).await.0, 0);
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = now() - interval '2 hours' \
         WHERE repository_id = (SELECT id FROM repository WHERE name = $1) \
           AND name <> 'contoso.d'",
    )
    .bind(&repo)
    .execute(&pool)
    .await
    .unwrap();

    // Prerelease versions only when asked for; an id with nothing else drops.
    let (total, hits) = search("contoso", false, 0, 20).await;
    assert_eq!(total, 2);
    assert_eq!(
        hits,
        [
            ("contoso.a".to_string(), vec!["1.0.0".to_string()]),
            ("contoso.b".to_string(), vec!["1.0.0".to_string()]),
        ]
    );
    let (total, hits) = search("contoso", true, 0, 20).await;
    assert_eq!(total, 3, "contoso.d is still inside its delay");
    assert_eq!(hits[0].1, ["1.0.0", "2.0.0-beta"]);

    // Paging counts every hit and returns only the page.
    let (total, hits) = search("", true, 1, 1).await;
    assert_eq!(total, 3);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].0, "contoso.b");

    // A live not-found marker hides a version; an expired one does not.
    let mark = |age: &'static str| {
        let pool = pool.clone();
        let repo = repo.clone();
        async move {
            sqlx::query(
                "UPDATE proxy_cached_version \
                 SET not_found = true, not_found_at = now() - $2::text::interval \
                 WHERE repository_id = (SELECT id FROM repository WHERE name = $1) \
                   AND name = 'contoso.b'",
            )
            .bind(&repo)
            .bind(age)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    mark("1 second").await;
    assert_eq!(search("contoso.b", true, 0, 20).await.0, 0);
    mark("30 days").await;
    assert_eq!(search("contoso.b", true, 0, 20).await.0, 1);
}

/// A degraded upstream answering a package's listing with an empty
/// `versions` array, or a document without one, retires nothing: what is
/// cached stays listed and downloadable (before, every version, downloaded
/// ones included, was flagged deleted upstream until the next good listing).
#[tokio::test]
async fn an_empty_or_malformed_listing_retires_nothing() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0", "2.1.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.1.0"]
    );
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "2.1.0")
        .await
        .unwrap()
        .is_some());

    for doc in [
        serde_json::json!({ "versions": [] }),
        serde_json::json!({ "error": "mirror offline" }),
    ] {
        mock.state
            .flat_index_override
            .lock()
            .unwrap()
            .insert("contoso.lib".into(), doc.clone());
        // A fresh cache stands in for an expired metadata TTL.
        let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
        assert_eq!(
            versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
            ["1.0.0", "2.1.0"],
            "{doc}"
        );
        assert!(
            px.resolve_nupkg(&repo, "Contoso.Lib", "2.1.0")
                .await
                .unwrap()
                .is_some(),
            "{doc}"
        );
    }
}

/// H3 follow-up: the package-level not-found marker (`*`) is cleared as soon
/// as the package is downloaded, and an expired one is pruned like any other
/// unconfirmed row (before, every request for a random id left a permanent
/// row, and the marker hid a newly published package from listings even
/// after it had been downloaded).
#[tokio::test]
async fn package_marker_is_cleared_by_a_download_and_pruned_when_expired() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let rid = repo_id(&pool, &repo).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));

    assert!(px
        .list_versions(&repo, "Contoso.Next")
        .await
        .unwrap()
        .is_empty());
    let marker = |name: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT confirmed FROM proxy_cached_version \
                 WHERE repository_id = $1 AND name = $2 AND version = '*'",
            )
            .bind(rid)
            .bind(name)
            .fetch_optional(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(
        marker("contoso.next").await,
        Some(false),
        "an unconfirmed marker"
    );

    // The package is published and downloaded: its listing is visible again
    // although the marker's TTL has not elapsed.
    mock.publish("contoso.next", "1.0.0", make_nupkg("Contoso.Next", "1.0.0"));
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Next", "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        marker("contoso.next").await,
        None,
        "the download cleared the marker"
    );
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Next").await.unwrap()),
        ["1.0.0"]
    );

    // An expired marker of an id that never appears is pruned.
    assert!(px
        .list_versions(&repo, "Contoso.Ghost")
        .await
        .unwrap()
        .is_empty());
    sqlx::query(
        "UPDATE proxy_cached_version SET not_found_at = now() - interval '2 hours' \
         WHERE repository_id = $1 AND name = 'contoso.ghost'",
    )
    .bind(rid)
    .execute(&pool)
    .await
    .unwrap();
    forge_db::proxy_dao::prune_unconfirmed(&pool, 600, 10_000)
        .await
        .unwrap();
    assert_eq!(marker("contoso.ghost").await, None, "expired marker pruned");
}

/// Review follow-up: inside the package-delay window the proxy never fetches
/// the package from upstream (before, a reader could prefetch a quarantined
/// release, which was then served from the cache after the window without
/// asking the upstream again).
#[tokio::test]
async fn downloads_inside_the_delay_window_never_reach_the_upstream() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 3600, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "1.0.0")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        mock.nupkg_hits(),
        0,
        "no upstream download inside the delay"
    );
    let row = forge_db::proxy_dao::get_cached_version(
        &pool,
        repo_id(&pool, &repo).await,
        "contoso.lib",
        "1.0.0",
    )
    .await
    .unwrap()
    .expect("the listing confirmed the version (its delay clock runs)");
    assert!(!row.downloaded);
}

/// H3: a download attempt that fails with an upstream 5xx must not leave a
/// phantom version behind for floating ranges to resolve to.
#[tokio::test]
async fn failed_download_does_not_list_a_phantom_version() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    mock.fail_nupkg("contoso.lib", "9.9.9");
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "9.9.9")
        .await
        .is_err());
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"]
    );
    let reg = px.registration(&repo, "Contoso.Lib").await.unwrap();
    assert_eq!(reg.len(), 1, "{reg:?}");
    assert_eq!(searched_versions(&px, &repo, "contoso").await, ["1.0.0"]);
}

/// H3: a not-found marker on a listed version hides it from listings only
/// within `not_found_ttl`.
#[tokio::test]
async fn listings_honour_not_found_only_within_the_ttl() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0", "1.1.0"])).await;
    // Listed upstream, but the package itself 404s (e.g. replication lag).
    mock.miss_nupkg("contoso.lib", "1.1.0");
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "1.1.0"]
    );
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "1.1.0")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"],
        "a live marker hides the version"
    );

    sqlx::query(
        "UPDATE proxy_cached_version SET not_found_at = now() - interval '2 hours' \
         WHERE name = 'contoso.lib' AND version = '1.1.0'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "1.1.0"],
        "an expired marker hides nothing (the listing is still cached)"
    );
    assert_eq!(
        px.registration(&repo, "Contoso.Lib").await.unwrap().len(),
        2
    );
}

/// H3: a row planted by an early request must not count towards the package
/// delay of the release that later appears: its delay window starts at the
/// first upstream confirmation.
#[tokio::test]
async fn planted_row_does_not_shorten_the_package_delay() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 3600, true).await;

    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "2.0.0")
        .await
        .unwrap()
        .is_none());
    // Pretend the request happened long ago.
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = now() - interval '2 hours' \
         WHERE name = 'contoso.lib' AND version = '2.0.0'",
    )
    .execute(&pool)
    .await
    .unwrap();

    mock.publish("contoso.lib", "2.0.0", make_nupkg("Contoso.Lib", "2.0.0"));
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert!(
        px.list_versions(&repo, "Contoso.Lib")
            .await
            .unwrap()
            .is_empty(),
        "both versions are inside the delay window"
    );
    let row = forge_db::proxy_dao::get_cached_version(
        &pool,
        repo_id(&pool, &repo).await,
        "contoso.lib",
        "2.0.0",
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!row.not_found);
    assert!(
        chrono::Utc::now() - row.first_seen_at < chrono::Duration::minutes(5),
        "the delay window restarts at the first upstream sighting, got {}",
        row.first_seen_at
    );
}

/// H2: a row marked downloaded whose local copy was deleted (retention) is
/// fetched again instead of 404ing forever; a row whose `downloaded` flag was
/// reset (proxy eviction) is re-fetched too. `first_seen_at` survives both.
#[tokio::test]
async fn missing_local_copy_is_fetched_again() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(sample_corpus("1.2.3")).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 3600, true).await;
    let repo_id = repo_id(&pool, &repo).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    // Discover and clear the delay window.
    assert!(px
        .list_versions(&repo, "Sample.Lib")
        .await
        .unwrap()
        .is_empty());
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = now() - interval '2 hours' \
         WHERE repository_id = $1",
    )
    .bind(repo_id)
    .execute(&pool)
    .await
    .unwrap();
    let first_seen = |pool: PgPool| async move {
        forge_db::proxy_dao::get_cached_version(&pool, repo_id, "sample.lib", "1.2.3")
            .await
            .unwrap()
            .unwrap()
    };
    let before = first_seen(pool.clone()).await.first_seen_at;
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .is_some());
    assert_eq!(mock.nupkg_hits(), 1);

    // Retention hard-deleted the component but left the row `downloaded`.
    sqlx::query("DELETE FROM component WHERE repository_id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        px.resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
            .await
            .unwrap()
            .is_some(),
        "a vanished local copy is re-fetched"
    );
    assert_eq!(mock.nupkg_hits(), 2);
    let row = first_seen(pool.clone()).await;
    assert!(row.downloaded);
    assert_eq!(row.first_seen_at, before);
    // Served locally again afterwards.
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .is_some());
    assert_eq!(mock.nupkg_hits(), 2);

    // Eviction that keeps the row but resets `downloaded`.
    sqlx::query("DELETE FROM component WHERE repository_id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxy_cached_version SET downloaded = false WHERE repository_id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Sample.Lib").await.unwrap()),
        ["1.2.3"],
        "an evicted version stays listed (no new delay window)"
    );
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .is_some());
    assert_eq!(mock.nupkg_hits(), 3);
    assert_eq!(first_seen(pool).await.first_seen_at, before);
}

/// M9: an upstream package rejected for its content (here: not a zip) is
/// remembered, so client retries fail fast instead of re-downloading it.
#[tokio::test]
async fn rejected_upstream_package_is_not_downloaded_on_every_retry() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mut corpus = Corpus::new();
    corpus
        .entry("broken.pkg".into())
        .or_default()
        .insert("1.0.0".into(), b"definitely not a zip".to_vec());
    let mock = start_mock(corpus).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    let first = px
        .resolve_nupkg(&repo, "Broken.Pkg", "1.0.0")
        .await
        .expect_err("unparseable package");
    assert!(
        first.to_string().contains("parse upstream nupkg"),
        "{first}"
    );
    assert_eq!(mock.nupkg_hits(), 1);

    let again = px
        .resolve_nupkg(&repo, "Broken.Pkg", "1.0.0")
        .await
        .expect_err("still rejected");
    assert!(again.to_string().contains("rejected recently"), "{again}");
    assert_eq!(mock.nupkg_hits(), 1, "no second download within the TTL");
}

/// M10: an upstream `.nuspec` is served only when it is a manifest of exactly
/// the requested identity; otherwise the proxy falls back to the (verified)
/// package and serves its manifest.
#[tokio::test]
async fn upstream_nuspec_must_name_the_requested_package() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let blobs: Arc<dyn forge_core::repo::hosted::BlobFetch> =
        Arc::new(StoreBlobs(common::blob_store().await));

    let genuine = nuspec_of(&sample_nupkg());
    for bogus in [
        nuspec_of(&make_nupkg("Evil.Pkg", "1.2.3")),
        nuspec_of(&make_nupkg("Sample.Lib", "6.6.6")),
        br#"{"Code":"Success","AccessKeyId":"ASIA..."}"#.to_vec(),
    ] {
        let mock = start_mock(sample_corpus("1.2.3")).await;
        mock.override_nuspec("sample.lib", "1.2.3", bogus.clone());
        let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
        let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128)).with_blob_fetch(blobs.clone());

        let served = px
            .resolve_nuspec(&repo, "Sample.Lib", "1.2.3")
            .await
            .unwrap()
            .expect("manifest from the verified package");
        assert_ne!(served, bogus);
        assert_eq!(served, genuine);
        assert_eq!(mock.nupkg_hits(), 1, "fell back to the package");
    }
}

/// M11: registration of versions not downloaded yet takes `listed`,
/// `published` and the dependency groups from the upstream registration; the
/// listing state also reaches the flat index and search. Cached for the TTL.
#[tokio::test]
async fn registration_uses_upstream_metadata_for_versions_not_downloaded() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0", "2.0.0"])).await;
    mock.set_registration(
        "contoso.lib",
        serde_json::json!({
            "count": 1,
            "items": [{
                "@id": format!("{}/registration/contoso.lib/index.json#page/1.0.0/2.0.0", mock.base),
                "lower": "1.0.0",
                "upper": "2.0.0",
                "count": 2,
                "items": [
                    { "catalogEntry": {
                        "id": "Contoso.Lib", "version": "1.0.0", "listed": false,
                        "published": "1900-01-01T00:00:00+00:00", "dependencyGroups": []
                    } },
                    { "catalogEntry": {
                        "id": "Contoso.Lib", "version": "2.0.0",
                        "published": "2026-05-01T10:00:00+00:00",
                        "dependencyGroups": [ {
                            "targetFramework": "net8.0",
                            "dependencies": [ { "id": "Newtonsoft.Json", "range": "[13.0.1, )" } ]
                        } ]
                    } }
                ]
            }]
        }),
    );
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    let reg = px.registration(&repo, "Contoso.Lib").await.unwrap();
    assert_eq!(reg.len(), 2);
    assert_eq!(reg[0].version, "1.0.0");
    assert!(!reg[0].listed, "upstream-unlisted version is unlisted");
    assert!(reg[1].listed);
    assert_eq!(reg[1].original_id, "Contoso.Lib");
    assert_eq!(
        reg[1].published,
        Some("2026-05-01T10:00:00Z".parse().unwrap())
    );
    let groups = forge_nuget::nuspec::dependency_groups_from_nuspec(
        reg[1].nuspec_bytes.as_deref().expect("dependency groups"),
    )
    .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].target_framework.as_deref(), Some("net8.0"));
    assert_eq!(groups[0].dependencies[0].id, "Newtonsoft.Json");
    assert_eq!(
        groups[0].dependencies[0].range.as_deref(),
        Some("[13.0.1, )")
    );
    assert_eq!(mock.nupkg_hits(), 0, "no package download for metadata");

    // The listing state is persisted for the flat index and search.
    let listed: Vec<(String, bool)> = px
        .list_versions(&repo, "Contoso.Lib")
        .await
        .unwrap()
        .into_iter()
        .map(|v| (v.version, v.listed))
        .collect();
    assert_eq!(
        listed,
        [("1.0.0".to_string(), false), ("2.0.0".to_string(), true)]
    );
    assert_eq!(searched_versions(&px, &repo, "contoso").await, ["2.0.0"]);

    // Cached for the metadata TTL.
    px.registration(&repo, "Contoso.Lib").await.unwrap();
    assert_eq!(mock.registration_hits(), 1);
}

/// M11: non-inlined registration pages are fetched newest first and bounded
/// per request; older versions keep the flat-container view. Pages are cached.
#[tokio::test]
async fn registration_pages_are_fetched_bounded_and_cached() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let versions: Vec<String> = (1..=12).map(|n| format!("{n}.0.0")).collect();
    let refs: Vec<&str> = versions.iter().map(String::as_str).collect();
    let mock = start_mock(corpus_of("Contoso.Lib", &refs)).await;
    let pages: Vec<serde_json::Value> = versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "@id": format!("{}/registration/contoso.lib/page/{v}.json", mock.base),
                "lower": v, "upper": v, "count": 1,
            })
        })
        .collect();
    mock.set_registration(
        "contoso.lib",
        serde_json::json!({ "count": pages.len(), "items": pages }),
    );
    for v in &versions {
        mock.set_registration_page(
            "contoso.lib",
            &format!("{v}.json"),
            serde_json::json!({ "items": [ { "catalogEntry": {
                "id": "Contoso.Lib", "version": v, "listed": true,
                "dependencyGroups": [ { "dependencies": [ { "id": format!("Dep.{v}") } ] } ]
            } } ] }),
        );
    }
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    let reg = px.registration(&repo, "Contoso.Lib").await.unwrap();
    assert_eq!(reg.len(), 12);
    assert_eq!(mock.registration_page_hits(), 10, "bounded page fetches");
    let with_deps: Vec<&str> = reg
        .iter()
        .filter(|e| e.nuspec_bytes.is_some())
        .map(|e| e.version.as_str())
        .collect();
    assert_eq!(with_deps.len(), 10);
    assert!(!with_deps.contains(&"1.0.0") && !with_deps.contains(&"2.0.0"));
    let newest = forge_nuget::nuspec::dependency_groups_from_nuspec(
        reg[11].nuspec_bytes.as_deref().unwrap(),
    )
    .unwrap();
    assert_eq!(newest[0].target_framework, None);
    assert_eq!(newest[0].dependencies[0].id, "Dep.12.0.0");

    px.registration(&repo, "Contoso.Lib").await.unwrap();
    assert_eq!(mock.registration_page_hits(), 10, "pages are cached");
    assert_eq!(mock.registration_hits(), 1);
}

/// M11: without an upstream registration the flat-container view is served
/// (listed, no dependency groups), as before.
#[tokio::test]
async fn registration_without_upstream_registration_keeps_the_flat_view() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    let reg = px.registration(&repo, "Contoso.Lib").await.unwrap();
    assert_eq!(reg.len(), 1);
    assert!(reg[0].listed);
    assert!(reg[0].nuspec_bytes.is_none());
    assert!(reg[0].published.is_none());
    assert_eq!(mock.registration_hits(), 1);
}

/// L8: ids are lowercased like NuGet clients do (`ToLowerInvariant`), so a
/// package with non-ASCII capitals resolves upstream and caches.
#[tokio::test]
async fn unicode_package_ids_resolve_like_nuget_clients() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Ünicode.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    assert_eq!(
        versions_of(&px.list_versions(&repo, "Ünicode.Lib").await.unwrap()),
        ["1.0.0"]
    );
    assert!(px
        .resolve_nupkg(&repo, "ÜNICODE.LIB", "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert!(px
        .resolve_nupkg(&repo, "ünicode.lib", "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert_eq!(mock.nupkg_hits(), 1, "both spellings hit one cached copy");
}
