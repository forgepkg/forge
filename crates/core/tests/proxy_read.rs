//! Integration tests for proxy-repository read ops.
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
//! * **where requests go** — a format's fetches and package URLs reach the
//!   `remote_url`'s origin and the origins the upstream's documents name,
//!   nothing else (#233): a scripted format plays a plugin that wants to read
//!   an internal service.

mod common;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use forge_cache::Cache;
use forge_core::repo::proxy::ProxyRepo;
use forge_core::repo::RepoReadOps;
use forge_core::{Format, FormatError, ParsedUpload, ReadSeek};
use forge_db::repository_dao::{self, NewRepository};
use forge_plugin_api::{
    Fetch, FetchResult, Fetched, Freshness, Remote, UpstreamAnswer, UpstreamOp, UpstreamStep,
};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::Notify;

/// NuGet, the built-in format plugin, as the `Format` the repository code
/// works with.
fn nuget() -> forge_plugin::PluginFormat {
    let plugin = forge_plugin::Plugin::builtin(
        forge_format_nuget::PLUGIN_TOML,
        forge_format_nuget::Nuget::default(),
    )
    .expect("plugins/nuget/plugin.toml is valid");
    forge_plugin::PluginFormat::new(&plugin)
}

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
    /// `file -> catalog entry document`.
    catalog: Mutex<HashMap<String, serde_json::Value>>,
    catalog_hits: AtomicUsize,
    /// `lower_id -> flat-container listing document` served instead of the
    /// corpus's.
    flat_index_override: Mutex<HashMap<String, serde_json::Value>>,
    /// The service index served instead of the real one.
    index_override: Mutex<Option<serde_json::Value>>,
    /// When set, a `.nupkg` request signals the first `Notify` on arrival and
    /// answers only once the second is notified (a slow download).
    hold_nupkg: Mutex<Option<(Arc<Notify>, Arc<Notify>)>>,
    /// The search service's answer; `None` answers 404.
    search: Mutex<Option<(StatusCode, serde_json::Value)>>,
    /// The query strings the search service received.
    search_queries: Mutex<Vec<String>>,
    /// When set, every flat-container listing answers 503 (an outage).
    listings_fail: AtomicBool,
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
    /// Serve `doc` as the service index from now on.
    fn override_index(&self, doc: serde_json::Value) {
        *self.state.index_override.lock().unwrap() = Some(doc);
    }
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
    fn catalog_hits(&self) -> usize {
        self.state.catalog_hits.load(Ordering::SeqCst)
    }
    /// Serve `doc` as the catalog entry at `{base}/catalog/{file}`.
    fn set_catalog_entry(&self, file: &str, doc: serde_json::Value) {
        self.state
            .catalog
            .lock()
            .unwrap()
            .insert(file.to_string(), doc);
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
    /// Hold every `.nupkg` response: returns `(arrived, release)`.
    fn hold_nupkgs(&self) -> (Arc<Notify>, Arc<Notify>) {
        let gates = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        *self.state.hold_nupkg.lock().unwrap() = Some(gates.clone());
        gates
    }
    /// Answer search requests with `status` and these results.
    fn set_search(&self, status: StatusCode, data: Vec<serde_json::Value>, total_hits: usize) {
        *self.state.search.lock().unwrap() = Some((
            status,
            serde_json::json!({ "totalHits": total_hits, "data": data }),
        ));
    }
    fn search_queries(&self) -> Vec<String> {
        self.state.search_queries.lock().unwrap().clone()
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
    if let Some(doc) = st.index_override.lock().unwrap().clone() {
        return (StatusCode::OK, axum::Json(doc)).into_response();
    }
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

async fn serve_search(State(st): State<Arc<MockState>>, uri: axum::http::Uri) -> impl IntoResponse {
    st.search_queries
        .lock()
        .unwrap()
        .push(uri.query().unwrap_or_default().to_string());
    match st.search.lock().unwrap().clone() {
        Some((status, doc)) => (status, axum::Json(doc)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
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
    if st.listings_fail.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
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
    let hold = st.hold_nupkg.lock().unwrap().clone();
    if let Some((arrived, release)) = hold {
        arrived.notify_one();
        release.notified().await;
    }
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

async fn serve_catalog(
    State(st): State<Arc<MockState>>,
    Path(file): Path<String>,
) -> impl IntoResponse {
    st.catalog_hits.fetch_add(1, Ordering::SeqCst);
    match st.catalog.lock().unwrap().get(&file) {
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
        let name = entry.name().unwrap().into_owned();
        if name.ends_with(".nuspec") && !name.contains('/') {
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
        catalog: Mutex::default(),
        catalog_hits: AtomicUsize::new(0),
        flat_index_override: Mutex::default(),
        index_override: Mutex::default(),
        hold_nupkg: Mutex::default(),
        search: Mutex::default(),
        search_queries: Mutex::default(),
        listings_fail: AtomicBool::new(false),
    });

    let app = Router::new()
        .route("/index.json", get(serve_index))
        .route("/query", get(serve_search))
        .route("/flat/{id}/index.json", get(serve_flat_index))
        .route("/flat/{id}/{version}/{file}", get(serve_nupkg))
        .route("/registration/{id}/index.json", get(serve_registration))
        .route(
            "/registration/{id}/page/{file}",
            get(serve_registration_page),
        )
        .route("/catalog/{file}", get(serve_catalog))
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

/// Create a proxy repository pointing at `remote_url` (loopback mocks are fine:
/// only the scheme is checked) with the given delay.
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
    ProxyRepo::new(pool.clone(), Arc::new(nuget()), cas, cache)
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
/// (no DB transaction is ever held across a network/S3 call). The singleflight
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

/// Requests a mock upstream has answered, per resource.
fn upstream_hits(mock: &MockUpstream) -> [usize; 6] {
    [
        mock.index_hits(),
        mock.flat_index_hits(),
        mock.nuspec_hits(),
        mock.nupkg_hits(),
        mock.registration_hits(),
        mock.registration_page_hits(),
    ]
}

/// Point proxy `repo` at another upstream, as the admin update does: the new
/// URL (bumping `updated_at`), and in the same transaction the reset of what
/// the proxy learned from the previous one.
async fn repoint(pool: &PgPool, repo: &str, remote_url: &str) {
    let id = repo_id(pool, repo).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE repository SET remote_url = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(remote_url)
        .execute(&mut *tx)
        .await
        .unwrap();
    forge_db::proxy_dao::reset_for_new_upstream(&mut tx, id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// #77: the package delay and the not-found TTL count on the database's
/// clock, which writes `first_seen_at` and `not_found_at`. Here it runs an
/// hour ahead of the application's.
#[tokio::test]
async fn proxy_delay_and_not_found_ttl_run_on_the_database_clock() {
    let pool = common::pool_with_clock_ahead().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let backdate = |column: &'static str, minutes: i32, repo: String| {
        let pool = pool.clone();
        async move {
            let sql = match column {
                "first_seen_at" => {
                    "UPDATE proxy_cached_version SET first_seen_at = now() - make_interval(mins => $2) \
                     WHERE repository_id = (SELECT id FROM repository WHERE name = $1)"
                }
                _ => {
                    "UPDATE proxy_cached_version SET not_found_at = now() - make_interval(mins => $2) \
                     WHERE repository_id = (SELECT id FROM repository WHERE name = $1)"
                }
            };
            sqlx::query(sql)
                .bind(repo)
                .bind(minutes)
                .execute(&pool)
                .await
                .unwrap();
        }
    };

    // A 30-minute delay. (A column default reads the real clock, not the
    // skewed `now()`, so the first sighting is stamped explicitly.)
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 1800, true).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    px.list_versions(&repo, "Contoso.Lib").await.unwrap();
    backdate("first_seen_at", 0, repo.clone()).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert!(
        px.list_versions(&repo, "Contoso.Lib")
            .await
            .unwrap()
            .is_empty(),
        "just seen: inside the delay"
    );
    // First seen 31 minutes ago on the database's clock.
    backdate("first_seen_at", 31, repo.clone()).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"],
        "past the delay on the database's clock"
    );

    // A 10-minute not-found TTL, marked 11 minutes ago.
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert!(px
        .list_versions(&repo, "Fabrikam.Lib")
        .await
        .unwrap()
        .is_empty());
    mock.state
        .packages
        .lock()
        .unwrap()
        .extend(corpus_of("Fabrikam.Lib", &["2.0.0"]));
    backdate("not_found_at", 11, repo.clone()).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Fabrikam.Lib").await.unwrap()),
        ["2.0.0"],
        "the marker expired on the database's clock"
    );
}

/// #222: the answer "the upstream does not know this id" is cached for the
/// metadata TTL, but stands only while the id's not-found marker does. With
/// a `not_found_ttl_seconds` shorter than the metadata TTL (0 included), a
/// package published upstream meanwhile is listed through the same cache
/// once its marker expired, and not before.
#[tokio::test]
async fn an_expired_not_found_marker_hides_nothing_through_the_cache() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(Corpus::new()).await;
    for not_found_ttl in [30, 0] {
        let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
        sqlx::query(
            "UPDATE repository SET metadata_ttl_seconds = 3600, not_found_ttl_seconds = $2 \
             WHERE name = $1",
        )
        .bind(&repo)
        .bind(not_found_ttl)
        .execute(&pool)
        .await
        .unwrap();
        let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
        let id = format!("Acme.Lib{not_found_ttl}");
        assert!(px.list_versions(&repo, &id).await.unwrap().is_empty());
        mock.state
            .packages
            .lock()
            .unwrap()
            .extend(corpus_of(&id, &["1.0.0"]));
        if not_found_ttl > 0 {
            assert!(
                px.list_versions(&repo, &id).await.unwrap().is_empty(),
                "the marker still stands"
            );
            sqlx::query(
                "UPDATE proxy_cached_version SET not_found_at = now() - interval '31 seconds' \
                 WHERE repository_id = (SELECT id FROM repository WHERE name = $1)",
            )
            .bind(&repo)
            .execute(&pool)
            .await
            .unwrap();
        }
        assert_eq!(
            versions_of(&px.list_versions(&repo, &id).await.unwrap()),
            ["1.0.0"],
            "not_found_ttl_seconds = {not_found_ttl}"
        );
    }
}

/// #223: after an upstream version listing fails, the proxy answers the
/// listings of ids it has cached versions of from its cache, without asking
/// the upstream again, for a while: during an outage, a restore of cached
/// packages does not wait for the upstream on every listing. An id with
/// nothing cached still asks it.
#[tokio::test]
async fn a_failed_listing_serves_cached_ids_without_asking_again() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mut corpus = corpus_of("Contoso.A", &["1.0.0"]);
    corpus.extend(corpus_of("Contoso.B", &["2.0.0"]));
    let mock = start_mock(corpus).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    // Every listing asks the upstream (no metadata TTL).
    sqlx::query("UPDATE repository SET metadata_ttl_seconds = 0 WHERE name = $1")
        .bind(&repo)
        .execute(&pool)
        .await
        .unwrap();
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    let listed = |id: &'static str| {
        let px = &px;
        let repo = repo.clone();
        async move { versions_of(&px.list_versions(&repo, id).await.unwrap()) }
    };
    assert_eq!(listed("Contoso.A").await, ["1.0.0"]);
    assert_eq!(listed("Contoso.B").await, ["2.0.0"]);
    assert_eq!(listed("Contoso.A").await, ["1.0.0"]);
    let asked = mock.flat_index_hits();
    assert_eq!(asked, 3, "no metadata TTL: every listing asks");

    mock.state.listings_fail.store(true, Ordering::SeqCst);
    assert_eq!(
        listed("Contoso.A").await,
        ["1.0.0"],
        "served from the cache"
    );
    assert_eq!(mock.flat_index_hits(), asked + 1);
    assert_eq!(listed("Contoso.B").await, ["2.0.0"]);
    assert_eq!(listed("Contoso.A").await, ["1.0.0"]);
    assert_eq!(mock.flat_index_hits(), asked + 1, "not asked again");

    assert!(px.list_versions(&repo, "Contoso.C").await.is_err());
    assert_eq!(mock.flat_index_hits(), asked + 2, "nothing cached: asked");
}

/// #76: a service index without `PackageBaseAddress` (a captive portal, a
/// gateway's error page) is an upstream failure. It never replaces the last
/// good index, and without one the proxy errors instead of answering every id
/// with an authoritative "not found".
#[tokio::test]
async fn service_index_without_a_package_base_address_is_an_upstream_failure() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let id = repo_id(&pool, &repo).await;
    let stale = || async {
        sqlx::query(
            "UPDATE proxy_upstream_index SET fetched_at = now() - interval '2 hours' \
             WHERE repository_id = $1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    };

    // A good index first, then the upstream answers an empty one.
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"]
    );
    mock.override_index(serde_json::json!({"version": "3.0.0", "resources": []}));
    stale().await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "New.Lib").await.unwrap()),
        Vec::<String>::new(),
        "the stale good index is still used: the upstream says New.Lib is unknown"
    );
    let stored = forge_db::proxy_dao::get_upstream_index(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored.resources["package_base_address"].is_string(),
        "the empty index was not stored: {:?}",
        stored.resources
    );
    assert!(
        px.resolve_nupkg(&repo, "Contoso.Lib", "1.0.0")
            .await
            .unwrap()
            .is_some(),
        "downloads keep going to the last good package base address"
    );

    // No good index at all: an error, never an empty answer.
    let fresh = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    fresh.override_index(serde_json::json!({}));
    let repo = make_proxy(&pool, &format!("{}/index.json", fresh.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert!(px.list_versions(&repo, "Contoso.Lib").await.is_err());
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "1.0.0")
        .await
        .is_err());
    assert!(
        forge_db::proxy_dao::get_upstream_index(&pool, repo_id(&pool, &repo).await)
            .await
            .unwrap()
            .is_none()
    );
}

/// #65: a repointed proxy forgets the previous upstream's per-version state.
/// A package-level not-found marker the old upstream caused does not keep
/// answering 404 for the new one, and a version the old upstream listed long
/// ago waits out the package delay again before the new upstream's bytes are
/// served.
#[tokio::test]
async fn repointed_proxy_forgets_the_previous_upstreams_markers_and_delay_clock() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;

    // Not-found marker.
    let old = start_mock(corpus_of("Other.Lib", &["1.0.0"])).await;
    let new = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", old.base), 0, true).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert!(px
        .list_versions(&repo, "Contoso.Lib")
        .await
        .unwrap()
        .is_empty());
    repoint(&pool, &repo, &format!("{}/index.json", new.base)).await;
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"],
        "the old upstream's not-found marker must not hide the new upstream's package"
    );
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "1.0.0")
        .await
        .unwrap()
        .is_some());

    // Package delay: the old upstream listed 1.0.0 two hours ago, past the
    // one-hour delay; the new upstream's 1.0.0 is a different package.
    let old = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let new = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", old.base), 3600, true).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert!(px
        .list_versions(&repo, "Contoso.Lib")
        .await
        .unwrap()
        .is_empty());
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = now() - interval '2 hours' \
         WHERE repository_id = $1",
    )
    .bind(repo_id(&pool, &repo).await)
    .execute(&pool)
    .await
    .unwrap();
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"],
        "the old upstream's version cleared the delay"
    );
    repoint(&pool, &repo, &format!("{}/index.json", new.base)).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert!(
        px.list_versions(&repo, "Contoso.Lib")
            .await
            .unwrap()
            .is_empty(),
        "the new upstream's version waits out the delay"
    );
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "1.0.0")
        .await
        .unwrap()
        .is_none());
    assert_eq!(new.nupkg_hits(), 0, "nothing downloaded inside the delay");
}

/// #105: pointing a proxy back to its previous upstream within the metadata
/// TTL lists that upstream's versions again. The repoint deleted the rows of
/// the versions not downloaded yet, and the first period's "listing
/// refreshed" marker (keyed by the upstream) used to be still valid, so the
/// flat index stayed empty until the TTL ran out.
#[tokio::test]
async fn repointing_back_within_the_metadata_ttl_lists_the_versions_again() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let a = start_mock(corpus_of("Contoso.Lib", &["1.0.0", "2.0.0"])).await;
    let b = start_mock(corpus_of("Other.Lib", &["1.0.0"])).await;
    let a_url = format!("{}/index.json", a.base);
    let repo = make_proxy(&pool, &a_url, 0, true).await;
    // One cache across the repoints, as on a running instance.
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.0.0"]
    );
    repoint(&pool, &repo, &format!("{}/index.json", b.base)).await;
    assert!(px
        .list_versions(&repo, "Contoso.Lib")
        .await
        .unwrap()
        .is_empty());
    repoint(&pool, &repo, &a_url).await;
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.0.0"],
        "the previous upstream's versions are listed again at once"
    );
}

/// #13: repointing a proxy (`remote_url`) takes effect at once. Nothing more
/// is requested from the previous upstream: not through its persisted service
/// index (fresh or stale), nor through the listings, manifests and
/// registrations cached from it. A failing new upstream is an error, not a
/// silent fallback to the previous upstream's index.
#[tokio::test]
async fn repointed_proxy_never_fetches_from_the_previous_upstream() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let old = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let new = start_mock(corpus_of("Contoso.Lib", &["1.0.0", "2.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", old.base), 0, true).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));

    // Warm every upstream cache from the old feed.
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"]
    );
    assert_eq!(
        px.registration(&repo, "Contoso.Lib").await.unwrap().len(),
        1
    );
    assert!(px
        .resolve_nuspec(&repo, "Contoso.Lib", "1.0.0")
        .await
        .unwrap()
        .is_some());
    let from_old = upstream_hits(&old);

    // Same instance and cache, well within the metadata TTL.
    repoint(&pool, &repo, &format!("{}/index.json", new.base)).await;
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.0.0"],
        "the new upstream's listing"
    );
    assert_eq!(
        px.registration(&repo, "Contoso.Lib").await.unwrap().len(),
        2
    );
    assert!(px
        .resolve_nuspec(&repo, "Contoso.Lib", "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "2.0.0")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        upstream_hits(&old),
        from_old,
        "nothing more from the old feed"
    );
    assert_eq!(upstream_hits(&new), [1, 1, 1, 1, 1, 0]);

    // The proxy is repointed at a failing upstream (it demands credentials
    // the proxy lacks), while the previous feed's index row is still fresh,
    // and once it is stale.
    let failing =
        start_mock_with_auth(corpus_of("Contoso.Lib", &["3.0.0"]), Some("Basic x".into())).await;
    repoint(&pool, &repo, &format!("{}/index.json", failing.base)).await;
    let from_new = upstream_hits(&new);
    for stale in [false, true] {
        if stale {
            sqlx::query(
                "UPDATE proxy_upstream_index SET fetched_at = now() - interval '2 hours' \
                 WHERE repository_id = $1",
            )
            .bind(repo_id(&pool, &repo).await)
            .execute(&pool)
            .await
            .unwrap();
        }
        // A fresh cache: another instance, or the metadata TTL elapsed.
        let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
        assert!(
            px.resolve_nupkg(&repo, "Contoso.Lib", "3.0.0")
                .await
                .is_err(),
            "stale: {stale}"
        );
        // 2.0.0 was downloaded; 1.0.0 was only listed by the previous
        // upstream, which the proxy no longer asks for it (#65).
        assert_eq!(
            versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
            ["2.0.0"],
            "versions cached locally are still served (stale: {stale})"
        );
    }
    assert_eq!(upstream_hits(&old), from_old);
    assert_eq!(
        upstream_hits(&new),
        from_new,
        "nothing from the previous feed"
    );
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
    async fn fetch_all(
        &self,
        blob: &forge_db::model::Blob,
    ) -> Result<Vec<u8>, forge_core::repo::RepoError> {
        let body = self
            .0
            .get(&blob.s3_key)
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
/// from nuget.org) leaves the listings once a refresh at least one metadata
/// TTL after the first listing without it confirms the deletion, instead of
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
    // A fresh cache stands in for an expired metadata TTL. One listing
    // without the version is no deletion yet (it may be partial)...
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.1.0"],
        "one listing without the version does not retire it"
    );
    // ...one a metadata TTL (600 s) later is.
    sqlx::query(
        "UPDATE proxy_cached_version SET missing_since = missing_since - interval '11 minutes' \
         WHERE repository_id = (SELECT id FROM repository WHERE name = $1) \
           AND missing_since IS NOT NULL",
    )
    .bind(&repo)
    .execute(&pool)
    .await
    .unwrap();
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

/// An upstream that serves a partial listing for a while (a Forge group
/// whose proxy member's upstream is briefly down answers with its other
/// members' versions) retires nothing: the versions it left out stay listed,
/// and once the upstream lists them again nothing is pending.
#[tokio::test]
async fn a_partial_listing_during_an_upstream_incident_retires_nothing() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0", "2.0.0", "3.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.0.0", "3.0.0"]
    );

    // The incident: only 1.0.0 is listed.
    mock.unpublish("contoso.lib", "2.0.0");
    mock.unpublish("contoso.lib", "3.0.0");
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.0.0", "3.0.0"]
    );
    assert_eq!(
        searched_versions(&px, &repo, "contoso").await,
        ["1.0.0", "2.0.0", "3.0.0"]
    );

    // Recovered by the next refresh: nothing is left pending, so a later
    // partial listing starts counting afresh.
    mock.publish("contoso.lib", "2.0.0", make_nupkg("Contoso.Lib", "2.0.0"));
    mock.publish("contoso.lib", "3.0.0", make_nupkg("Contoso.Lib", "3.0.0"));
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.0.0", "3.0.0"]
    );
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM proxy_cached_version \
         WHERE repository_id = (SELECT id FROM repository WHERE name = $1) \
           AND (missing_since IS NOT NULL OR upstream_missing)",
    )
    .bind(&repo)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending, 0);
}

/// Search applies every listing condition (prerelease, SemVer 2.0.0, the
/// package delay, a live not-found marker) in SQL and pages over ids, loading
/// versions for the returned page only.
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
            include_semver2: true,
            include_upstream: true,
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

    // Without SemVer 2.0.0, contoso.c (only `3.0.0-rc.1`) is neither counted
    // nor paged over; `2.0.0-beta` is SemVer 1 and stays.
    for (skip, take, expected) in [
        (0, 20, vec!["contoso.a", "contoso.b"]),
        (1, 1, vec!["contoso.b"]),
    ] {
        let params = forge_core::repo::SearchParams {
            q: String::new(),
            skip,
            take,
            prerelease: true,
            include_semver2: false,
            include_upstream: true,
        };
        let result = px.search(&repo, &params).await.unwrap();
        assert_eq!(result.total_hits, 2);
        let ids: Vec<&str> = result.hits.iter().map(|h| h.original_id.as_str()).collect();
        assert_eq!(ids, expected);
        if skip == 0 {
            assert_eq!(
                versions_of(&result.hits[0].versions),
                ["1.0.0", "2.0.0-beta"]
            );
        }
    }

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

/// `len` lowercase letters and digits that PostgreSQL cannot compress, so
/// that an index entry holding them is as long as they are.
fn incompressible(len: usize) -> String {
    use sha2::Digest;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut block = sha2::Sha256::digest(b"incompressible");
    let mut out = String::with_capacity(len);
    while out.len() < len {
        out.extend(
            block
                .iter()
                .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
                .take(len - out.len()),
        );
        block = sha2::Sha256::digest(&block[..]);
    }
    out
}

/// #231: an upstream listing with a version longer than the host takes
/// (here a multi-kilobyte prerelease, which NuGet's listing parser accepts)
/// lists the package's other versions. The long one is never recorded: its
/// index entry failed the whole listing's insert, so the listing failed.
#[tokio::test]
async fn versions_longer_than_the_host_takes_are_left_out_of_a_listing() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let huge = format!("2.0.0-{}", incompressible(4096));
    mock.state.flat_index_override.lock().unwrap().insert(
        "contoso.lib".into(),
        serde_json::json!({ "versions": ["1.0.0", huge] }),
    );
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"]
    );
    assert_eq!(
        px.registration_versions(&repo, "Contoso.Lib")
            .await
            .unwrap(),
        ["1.0.0"]
    );
    let long_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM proxy_cached_version WHERE repository_id = $1 \
         AND length(version) > 256",
    )
    .bind(repo_id(&pool, &repo).await)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(long_rows, 0);
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

/// #23: the reconciler prunes unconfirmed rows while a first-time download of
/// a version no listing confirmed (a client fetching it by URL) can still be
/// fetching; with `not_found_ttl_seconds = 0` the row is prunable at once. The
/// download creates its row again and succeeds, instead of answering 500 after
/// it stored the package.
#[tokio::test]
async fn prune_during_a_first_download_does_not_fail_it() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0"])).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let rid = repo_id(&pool, &repo).await;
    sqlx::query("UPDATE repository SET not_found_ttl_seconds = 0 WHERE id = $1")
        .bind(rid)
        .execute(&pool)
        .await
        .unwrap();
    let (arrived, release) = mock.hold_nupkgs();
    let px = Arc::new(proxy_repo(&pool, cas, Cache::l1_only(128)));

    let download = {
        let (px, repo) = (px.clone(), repo.clone());
        tokio::spawn(async move { px.resolve_nupkg(&repo, "Contoso.Lib", "1.0.0").await })
    };
    arrived.notified().await;
    let row = || {
        let pool = pool.clone();
        async move {
            forge_db::proxy_dao::get_cached_version(&pool, rid, "contoso.lib", "1.0.0")
                .await
                .unwrap()
        }
    };
    assert!(row().await.is_some(), "the download's unconfirmed row");
    forge_db::proxy_dao::prune_unconfirmed(&pool, 600, 1_000_000)
        .await
        .unwrap();
    assert!(row().await.is_none(), "pruned while the download fetches");

    release.notify_one();
    let loc = download.await.unwrap().expect("the download succeeds");
    assert!(loc.is_some());
    assert!(row().await.expect("created again").downloaded);
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"]
    );
    assert_eq!(mock.nupkg_hits(), 1);
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
    // Not downloaded: the dependency groups come from the upstream
    // registration, as a manifest summary.
    assert!(reg[1].nuspec_bytes.is_none());
    let groups = forge_format_nuget::nuspec::summary_of(
        Some(reg[1].manifest_summary.as_ref().expect("dependency groups")),
        None,
    )
    .dependency_groups;
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
        .filter(|e| e.manifest_summary.is_some())
        .map(|e| e.version.as_str())
        .collect();
    assert_eq!(with_deps.len(), 10);
    assert!(!with_deps.contains(&"1.0.0") && !with_deps.contains(&"2.0.0"));
    let newest = forge_format_nuget::nuspec::summary_of(reg[11].manifest_summary.as_ref(), None)
        .dependency_groups;
    assert_eq!(newest[0].target_framework, None);
    assert_eq!(newest[0].dependencies[0].id, "Dep.12.0.0");

    px.registration(&repo, "Contoso.Lib").await.unwrap();
    assert_eq!(mock.registration_page_hits(), 10, "pages are cached");
    assert_eq!(mock.registration_hits(), 1);

    // A registration page or leaf asks for its own versions only, so the
    // old versions get their pages too: no package is too long for its
    // oldest versions' dependencies, listing state and publish date.
    let old = px
        .registration_entries(&repo, "Contoso.Lib", &["1.0.0".into(), "2.0.0".into()])
        .await
        .unwrap();
    assert_eq!(old.len(), 2);
    assert!(old.iter().all(|e| e.manifest_summary.is_some()), "{old:?}");
    assert_eq!(mock.registration_page_hits(), 12);
    let leaf = px
        .registration_entry(&repo, "Contoso.Lib", "1.0.0")
        .await
        .unwrap()
        .expect("leaf");
    assert!(leaf.manifest_summary.is_some());
    // The versions alone (an index that does not inline its leaves) need no
    // upstream registration at all.
    assert_eq!(
        px.registration_versions(&repo, "Contoso.Lib")
            .await
            .unwrap(),
        versions
    );
    assert_eq!(mock.registration_page_hits(), 12);
    assert_eq!(mock.registration_hits(), 1);
}

/// Proxy search answers with the package id as the package spells it, not
/// the lowercased one the cache rows hold: from a downloaded version's
/// manifest, else from the upstream registration.
#[tokio::test]
async fn proxy_search_shows_the_ids_original_casing() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mut corpus = corpus_of("Contoso.Downloaded", &["1.0.0"]);
    corpus.extend(corpus_of("Contoso.Registered", &["1.0.0"]));
    corpus.extend(corpus_of("Contoso.Listed", &["1.0.0"]));
    let mock = start_mock(corpus).await;
    mock.set_registration(
        "contoso.registered",
        serde_json::json!({ "count": 1, "items": [ {
            "lower": "1.0.0", "upper": "1.0.0", "count": 1,
            "items": [ { "catalogEntry": {
                "id": "Contoso.Registered", "version": "1.0.0", "listed": true
            } } ]
        } ] }),
    );
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert!(px
        .resolve_nupkg(&repo, "contoso.downloaded", "1.0.0")
        .await
        .unwrap()
        .is_some());
    px.registration(&repo, "contoso.registered").await.unwrap();
    px.list_versions(&repo, "contoso.listed").await.unwrap();

    let params = forge_core::repo::SearchParams {
        q: "contoso".into(),
        skip: 0,
        take: 20,
        prerelease: true,
        include_semver2: true,
        include_upstream: true,
    };
    let ids: Vec<String> = px
        .search(&repo, &params)
        .await
        .unwrap()
        .hits
        .into_iter()
        .map(|h| h.original_id)
        .collect();
    // Known neither way: the lowercased id, as before.
    assert_eq!(
        ids,
        ["Contoso.Downloaded", "contoso.listed", "Contoso.Registered"]
    );
}

/// The package delay quarantines new releases: a version the upstream
/// published long ago is served at its first sighting (every version of a
/// package the proxy has not served before, all of them on a fresh install),
/// while a recent release waits out the delay. Only a listed version's
/// plausible publish time counts: nuget.org dates unlisted versions 1900.
#[tokio::test]
async fn the_package_delay_counts_from_the_upstream_publish_time() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of(
        "Contoso.Lib",
        &["1.0.0", "2.0.0", "3.0.0", "4.0.0"],
    ))
    .await;
    let five_minutes_ago = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    let tomorrow = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    mock.set_registration(
        "contoso.lib",
        serde_json::json!({ "count": 1, "items": [ {
            "lower": "1.0.0", "upper": "4.0.0", "count": 4,
            "items": [
                { "catalogEntry": { "id": "Contoso.Lib", "version": "1.0.0", "listed": true,
                                    "published": "2020-02-03T04:05:06+00:00" } },
                { "catalogEntry": { "id": "Contoso.Lib", "version": "2.0.0", "listed": true,
                                    "published": five_minutes_ago } },
                { "catalogEntry": { "id": "Contoso.Lib", "version": "3.0.0", "listed": false,
                                    "published": "1900-01-01T00:00:00+00:00" } },
                { "catalogEntry": { "id": "Contoso.Lib", "version": "4.0.0", "listed": true,
                                    "published": tomorrow } }
            ]
        } ] }),
    );
    // A one-hour delay.
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 3600, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"],
        "only the old release is out of quarantine"
    );
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "1.0.0")
        .await
        .unwrap()
        .is_some());
    for version in ["2.0.0", "3.0.0", "4.0.0"] {
        assert!(
            px.resolve_nupkg(&repo, "Contoso.Lib", version)
                .await
                .unwrap()
                .is_none(),
            "{version} is still inside the delay"
        );
    }

    // The recent release clears the delay an hour after it was published,
    // the others an hour after their first sighting.
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = first_seen_at - interval '56 minutes' \
         WHERE repository_id = (SELECT id FROM repository WHERE name = $1)",
    )
    .bind(&repo)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0", "2.0.0"]
    );
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

// ── Upstream search (#112) ──────────────────────────────────────────────────

/// One upstream search result: `id` listing `versions` (ascending), with
/// metadata and URLs of the upstream's own.
fn search_entry(id: &str, versions: &[&str]) -> serde_json::Value {
    let lower = id.to_lowercase();
    serde_json::json!({
        "@id": format!("https://upstream.example/registration/{lower}/index.json"),
        "@type": "Package",
        "registration": format!("https://upstream.example/registration/{lower}/index.json"),
        "id": id,
        "version": versions.last().unwrap(),
        "description": format!("{id} from upstream"),
        "authors": ["Upstream Author"],
        "totalDownloads": 42,
        "versions": versions
            .iter()
            .map(|v| serde_json::json!({
                "version": v,
                "downloads": 1,
                "@id": format!("https://upstream.example/registration/{lower}/{v}.json"),
            }))
            .collect::<Vec<_>>(),
    })
}

fn hit_versions(hit: &forge_core::repo::SearchHit) -> Vec<&str> {
    hit.versions.iter().map(|v| v.version.as_str()).collect()
}

/// Record a `proxy_cached_version` row as the listing and download paths do.
async fn record_version(
    pool: &PgPool,
    repo: &str,
    name: &str,
    version: &str,
    first_seen_ago_secs: i64,
    not_found: bool,
) {
    sqlx::query(
        "INSERT INTO proxy_cached_version
             (repository_id, name, version, first_seen_at, not_found, not_found_at)
         VALUES ($1, $2, $3, now() - make_interval(secs => $4::float8), $5,
                 CASE WHEN $5 THEN now() END)",
    )
    .bind(repo_id(pool, repo).await)
    .bind(name)
    .bind(version)
    .bind(first_seen_ago_secs as f64)
    .bind(not_found)
    .execute(pool)
    .await
    .unwrap();
}

/// #112: a proxy search reaches the upstream's search service, so a package
/// nobody has restored yet is found. Parameters are forwarded, versions are
/// filtered like local ones, malformed ids are dropped, and the answer is
/// cached for the metadata TTL.
#[tokio::test]
async fn search_finds_packages_only_the_upstream_knows() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(HashMap::new()).await;
    mock.set_search(
        StatusCode::OK,
        vec![
            search_entry(
                "Never.Restored",
                &["1.0.0", "1.1.0", "2.0.0-beta", "2.0.0-beta.1"],
            ),
            search_entry("bad/id", &["1.0.0"]),
        ],
        1234,
    );
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    let params = forge_core::repo::SearchParams {
        q: "never".into(),
        take: 5,
        ..Default::default()
    };
    let result = px.search(&repo, &params).await.unwrap();
    assert_eq!(result.hits.len(), 1, "the malformed id is dropped");
    let hit = &result.hits[0];
    assert_eq!(hit.original_id, "Never.Restored");
    assert_eq!(
        hit_versions(hit),
        ["1.0.0", "1.1.0"],
        "no prereleases asked for"
    );
    assert_eq!(hit.latest_version, "1.1.0");
    assert_eq!(hit.total_downloads, Some(42));
    assert_eq!(
        hit.manifest_summary.as_ref().unwrap()["metadata"]["description"],
        "Never.Restored from upstream"
    );
    assert_eq!(
        result.total_hits, 1233,
        "the upstream's total, less the dropped id"
    );

    let queries = mock.search_queries();
    assert_eq!(queries.len(), 1);
    for part in [
        "q=never",
        "skip=0",
        "take=5",
        "prerelease=false",
        "semVerLevel=2.0.0",
    ] {
        assert!(
            queries[0].split('&').any(|p| p == part),
            "{part} in {}",
            queries[0]
        );
    }
    px.search(&repo, &params).await.unwrap();
    assert_eq!(
        mock.search_queries().len(),
        1,
        "cached for the metadata TTL"
    );

    // Prereleases, with and without SemVer 2.0.0.
    let legacy = forge_core::repo::SearchParams {
        prerelease: true,
        include_semver2: false,
        ..params.clone()
    };
    let result = px.search(&repo, &legacy).await.unwrap();
    assert_eq!(
        hit_versions(&result.hits[0]),
        ["1.0.0", "1.1.0", "2.0.0-beta"]
    );
    assert!(mock.search_queries()[1].contains("semVerLevel=1.0.0"));
    let modern = forge_core::repo::SearchParams {
        prerelease: true,
        ..params
    };
    let result = px.search(&repo, &modern).await.unwrap();
    assert_eq!(
        hit_versions(&result.hits[0]),
        ["1.0.0", "1.1.0", "2.0.0-beta", "2.0.0-beta.1"]
    );

    // Nothing is recorded or downloaded by a search.
    assert_eq!(mock.flat_index_hits() + mock.nupkg_hits(), 0);
}

/// #112: when the upstream has no search service, or its search fails, the
/// proxy searches its cached packages and answers.
#[tokio::test]
async fn search_falls_back_to_cached_packages_when_the_upstream_search_fails() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(sample_corpus("1.0.0")).await;
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "sample.lib").await.unwrap()),
        ["1.0.0"]
    );

    let params = forge_core::repo::SearchParams {
        q: "sample".into(),
        ..Default::default()
    };
    // The search service answers 404 (then 500): the cache answers, and for
    // a minute after a failure the upstream search is not tried again.
    for status in [None, Some(StatusCode::INTERNAL_SERVER_ERROR)] {
        if let Some(status) = status {
            mock.set_search(status, vec![search_entry("Other.Lib", &["1.0.0"])], 1);
        }
        let result = px.search(&repo, &params).await.unwrap();
        assert_eq!(result.total_hits, 1);
        assert_eq!(result.hits[0].original_id.to_lowercase(), "sample.lib");
    }
    assert_eq!(
        mock.search_queries().len(),
        1,
        "backed off after the failure"
    );

    // An offline proxy never asks.
    let offline = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, false).await;
    mock.set_search(
        StatusCode::OK,
        vec![search_entry("Other.Lib", &["1.0.0"])],
        1,
    );
    let result = px.search(&offline, &params).await.unwrap();
    assert!(result.hits.is_empty());
    assert_eq!(mock.search_queries().len(), 1);
}

/// #112: upstream hits honor the caller's package filter, live not-found
/// markers (on a version or the whole id), and the package delay: a version
/// the proxy has not recorded, or that is still inside the delay, is hidden.
#[tokio::test]
async fn upstream_search_hits_honour_markers_the_delay_and_the_package_filter() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(HashMap::new()).await;
    mock.set_search(
        StatusCode::OK,
        vec![
            search_entry("Marked.Lib", &["1.0.0", "2.0.0"]),
            search_entry("Gone.Lib", &["1.0.0"]),
            search_entry("Seen.Lib", &["1.0.0", "2.0.0"]),
            search_entry("Fresh.Lib", &["1.0.0"]),
            search_entry("Hidden.Lib", &["1.0.0"]),
        ],
        5,
    );
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    let filter =
        forge_core::authz::PackageFilter::Predicate(Arc::new(|id: &str| id != "Hidden.Lib"));
    let params = forge_core::repo::SearchParams::default();

    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    record_version(&pool, &repo, "marked.lib", "2.0.0", 0, true).await;
    record_version(&pool, &repo, "gone.lib", "*", 0, true).await;
    let result = px
        .search_with_package_filter(&repo, &params, &filter)
        .await
        .unwrap();
    let found: Vec<(&str, Vec<&str>)> = result
        .hits
        .iter()
        .map(|hit| (hit.original_id.as_str(), hit_versions(hit)))
        .collect();
    assert_eq!(
        found,
        [
            ("Marked.Lib", vec!["1.0.0"]),
            ("Seen.Lib", vec!["1.0.0", "2.0.0"]),
            ("Fresh.Lib", vec!["1.0.0"]),
        ]
    );
    assert_eq!(result.total_hits, 3);

    // The upstream's total counts what the filter hides too: a filtered
    // caller is told only what it sees, plus one while more may follow.
    mock.set_search(
        StatusCode::OK,
        vec![
            search_entry("Seen.Lib", &["1.0.0"]),
            search_entry("Hidden.Lib", &["1.0.0"]),
        ],
        1000,
    );
    let page = forge_core::repo::SearchParams {
        take: 2,
        ..forge_core::repo::SearchParams::default()
    };
    let result = px
        .search_with_package_filter(&repo, &page, &filter)
        .await
        .unwrap();
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.total_hits, 2);
    let result = px
        .search_with_package_filter(&repo, &page, &forge_core::authz::PackageFilter::AllowAll)
        .await
        .unwrap();
    assert_eq!(
        result.total_hits, 1000,
        "an unfiltered caller gets the upstream's"
    );

    // With a delay of an hour, only what the proxy saw over an hour ago.
    let delayed = make_proxy(&pool, &format!("{}/index.json", mock.base), 3600, true).await;
    record_version(&pool, &delayed, "seen.lib", "1.0.0", 7200, false).await;
    record_version(&pool, &delayed, "seen.lib", "2.0.0", 60, false).await;
    let result = px.search(&delayed, &params).await.unwrap();
    let found: Vec<(&str, Vec<&str>)> = result
        .hits
        .iter()
        .map(|hit| (hit.original_id.as_str(), hit_versions(hit)))
        .collect();
    assert_eq!(found, [("Seen.Lib", vec!["1.0.0"])]);
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

/// #111: an unlisted version counts from when its catalog entry says the
/// upstream created it, not from its first sighting: nuget.org dates
/// unlisted versions 1900 in the registration, which never counts, so a
/// pinned version released years ago and unlisted since used to sit out the
/// whole delay (restores failed with NU1102). A version created recently
/// and unlisted at once still waits, and one without a catalog entry keeps
/// its first sighting.
#[tokio::test]
async fn an_old_unlisted_version_is_dated_from_its_catalog_entry() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Contoso.Lib", &["1.0.0", "2.0.0", "3.0.0"])).await;
    let five_minutes_ago = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    let unlisted = |version: &str, catalog: Option<&str>| {
        let mut entry = serde_json::json!({
            "id": "Contoso.Lib", "version": version, "listed": false,
            "published": "1900-01-01T00:00:00+00:00"
        });
        if let Some(file) = catalog {
            entry["@id"] = serde_json::json!(format!("{}/catalog/{file}", mock.base));
        }
        serde_json::json!({ "catalogEntry": entry })
    };
    mock.set_registration(
        "contoso.lib",
        serde_json::json!({ "count": 1, "items": [ {
            "lower": "1.0.0", "upper": "3.0.0", "count": 3,
            "items": [
                unlisted("1.0.0", Some("old.json")),
                unlisted("2.0.0", Some("recent.json")),
                unlisted("3.0.0", None),
            ]
        } ] }),
    );
    mock.set_catalog_entry(
        "old.json",
        serde_json::json!({ "created": "2019-04-05T06:07:08+00:00",
                            "published": "1900-01-01T00:00:00+00:00" }),
    );
    mock.set_catalog_entry(
        "recent.json",
        serde_json::json!({ "created": five_minutes_ago,
                            "published": "1900-01-01T00:00:00+00:00" }),
    );
    // A one-hour delay.
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 3600, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    assert_eq!(
        versions_of(&px.list_versions(&repo, "Contoso.Lib").await.unwrap()),
        ["1.0.0"],
        "only the old unlisted version is out of quarantine"
    );
    assert!(px
        .resolve_nupkg(&repo, "Contoso.Lib", "1.0.0")
        .await
        .unwrap()
        .is_some());
    for version in ["2.0.0", "3.0.0"] {
        assert!(
            px.resolve_nupkg(&repo, "Contoso.Lib", version)
                .await
                .unwrap()
                .is_none(),
            "{version} is still inside the delay"
        );
    }
    assert_eq!(mock.catalog_hits(), 2, "one read per catalog entry");
}

/// #111: dating the delay reads every registration page that covers a
/// version still inside it, not only the newest ten (640 versions on
/// nuget.org): an old version of a package with more versions than that is
/// served at its first sighting too.
#[tokio::test]
async fn the_delay_of_old_versions_beyond_ten_pages_is_dated_too() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("Big.Lib", &["1.0.0"])).await;
    let pages = 12;
    let versions: Vec<String> = (0..pages)
        .flat_map(|page| (0..64).map(move |i| format!("1.{page}.{i}")))
        .collect();
    mock.state.flat_index_override.lock().unwrap().insert(
        "big.lib".into(),
        serde_json::json!({ "versions": versions }),
    );
    let items: Vec<serde_json::Value> = (0..pages)
        .map(|page| {
            let file = format!("{page}.json");
            mock.set_registration_page(
                "big.lib",
                &file,
                serde_json::json!({ "items": (0..64).map(|i| serde_json::json!({
                    "catalogEntry": { "id": "Big.Lib", "version": format!("1.{page}.{i}"),
                                      "listed": true,
                                      "published": "2019-01-01T00:00:00+00:00" }
                })).collect::<Vec<_>>() }),
            );
            serde_json::json!({
                "@id": format!("{}/registration/big.lib/page/{file}", mock.base),
                "lower": format!("1.{page}.0"), "upper": format!("1.{page}.63"), "count": 64
            })
        })
        .collect();
    mock.set_registration(
        "big.lib",
        serde_json::json!({ "count": pages, "items": items }),
    );
    // A one-hour delay.
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 3600, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    let listed = versions_of(&px.list_versions(&repo, "Big.Lib").await.unwrap());
    assert_eq!(listed.len(), versions.len(), "every old version is listed");
    assert!(px
        .resolve_nupkg(&repo, "Big.Lib", "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert_eq!(mock.registration_page_hits(), pages);
}

/// #108: each upstream version keeps the casing it was pushed with
/// (`jquery`, `jQuery`), and the casing recorded for search is the newest
/// version's, on every read: taking any leaf of a map made it flip between
/// reads and rewrote the rows each time.
#[tokio::test]
async fn the_recorded_id_casing_is_the_newest_versions() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(corpus_of("jQuery", &["1.0.0", "1.5.0", "2.0.0"])).await;
    let leaf = |id: &str, version: &str| serde_json::json!({ "catalogEntry": { "id": id, "version": version, "listed": true } });
    mock.set_registration(
        "jquery",
        serde_json::json!({ "count": 1, "items": [ {
            "lower": "1.0.0", "upper": "2.0.0", "count": 3,
            "items": [ leaf("jquery", "1.0.0"), leaf("JQUERY", "1.5.0"), leaf("jQuery", "2.0.0") ]
        } ] }),
    );
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let repo_id = repo_id(&pool, &repo).await;
    for read in 0..10 {
        let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
        px.registration(&repo, "jquery").await.unwrap();
        let recorded: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT DISTINCT original_id FROM proxy_cached_version \
             WHERE repository_id = $1 AND name = 'jquery' AND version <> '*'",
        )
        .bind(repo_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(recorded, [Some("jQuery".to_string())], "read {read}");
    }
}

// ── Where a format's requests go (#233) ─────────────────────────────────────

/// A format's upstream side as a test scripts it: given NuGet (to delegate
/// to), the remote, the operation, and everything fetched so far.
type Script = dyn Fn(&dyn Format, &Remote, &UpstreamOp, &[FetchResult]) -> Result<UpstreamStep, FormatError>
    + Send
    + Sync;

/// NuGet with a scripted upstream side: a format plugin that wants to read
/// what Forge's network position reaches.
struct Scripted {
    nuget: forge_plugin::PluginFormat,
    script: Box<Script>,
}

impl Format for Scripted {
    fn id(&self) -> &'static str {
        "nuget"
    }
    fn parse_upload(&self, file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        self.nuget.parse_upload(file)
    }
    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        self.nuget.normalize_version(raw)
    }
    fn compare_versions(&self, a: &str, b: &str) -> std::cmp::Ordering {
        self.nuget.compare_versions(a, b)
    }
    fn lower_id(&self, id: &str) -> String {
        self.nuget.lower_id(id)
    }
    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        self.nuget.validate_id(id)
    }
    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        (self.script)(&self.nuget, remote, op, fetched)
    }
}

/// A proxy facade whose format's upstream side is `script`.
fn scripted_proxy(
    pool: &PgPool,
    cas: forge_storage::Cas,
    script: impl Fn(&dyn Format, &Remote, &UpstreamOp, &[FetchResult]) -> Result<UpstreamStep, FormatError>
        + Send
        + Sync
        + 'static,
) -> ProxyRepo {
    let format = Scripted {
        nuget: nuget(),
        script: Box::new(script),
    };
    ProxyRepo::new(pool.clone(), Arc::new(format), cas, Cache::l1_only(128))
}

/// NuGet's own upstream side, with its resolved index changed by `edit`.
fn nuget_with_index(
    edit: impl Fn(&mut serde_json::Value) + Send + Sync + 'static,
) -> impl Fn(&dyn Format, &Remote, &UpstreamOp, &[FetchResult]) -> Result<UpstreamStep, FormatError>
       + Send
       + Sync
       + 'static {
    move |nuget, remote, op, fetched| {
        Ok(match nuget.upstream(remote, op, fetched)? {
            UpstreamStep::Done(UpstreamAnswer::Index(index)) => {
                let mut index: serde_json::Value = serde_json::from_str(&index).unwrap();
                edit(&mut index);
                UpstreamStep::Done(UpstreamAnswer::Index(index.to_string()))
            }
            step => step,
        })
    }
}

/// A service on Forge's network that trusts its position: it answers any
/// GET with a secret.
async fn internal_service() -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_string(r#"{"secret": "internal"}"#),
        )
        .mount(&server)
        .await;
    server
}

/// How many requests `server` received.
async fn requests_to(server: &wiremock::MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .len()
}

/// #233: a format plugin's requests reach only the upstream's origin and the
/// origins its documents name. A plugin asking for an internal service's URL
/// gets a failure, and nothing is sent; a package URL there is not
/// downloaded.
#[tokio::test]
async fn a_format_cannot_reach_an_origin_its_upstream_does_not_name() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(sample_corpus("1.2.3")).await;
    let internal = internal_service().await;
    let secret = format!("{}/_search?q=*", internal.uri());
    let evil = format!("{}/sample.lib.1.2.3.nupkg", internal.uri());
    let seen: Arc<Mutex<Option<Fetched>>> = Arc::default();
    let px = {
        let (secret, seen) = (secret.clone(), seen.clone());
        scripted_proxy(&pool, cas, move |nuget, remote, op, fetched| match op {
            // The listing reads the internal service first, then lists
            // what the upstream lists, as NuGet does.
            UpstreamOp::Versions(_) if fetched.is_empty() => Ok(UpstreamStep::Fetch(vec![Fetch {
                url: secret.clone(),
                freshness: Freshness::Metadata,
            }])),
            UpstreamOp::Versions(_) => {
                *seen.lock().unwrap() = fetched
                    .iter()
                    .find(|f| f.fetch.url == secret)
                    .map(|f| f.outcome.clone());
                nuget.upstream(remote, op, fetched)
            }
            UpstreamOp::Package(_) => Ok(UpstreamStep::Done(UpstreamAnswer::Package(evil.clone()))),
            _ => nuget.upstream(remote, op, fetched),
        })
    };
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;

    assert_eq!(
        versions_of(&px.list_versions(&repo, "Sample.Lib").await.unwrap()),
        ["1.2.3"],
        "what the upstream lists is still listed"
    );
    match seen.lock().unwrap().clone() {
        Some(Fetched::Failed(reason)) => assert!(reason.contains("not sent"), "{reason}"),
        other => panic!("the internal service's answer reached the format: {other:?}"),
    }
    let err = px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .expect_err("a package URL on the internal service is not downloaded");
    assert!(err.to_string().contains("not downloaded"), "{err}");
    assert_eq!(requests_to(&internal).await, 0, "nothing reached it");
    assert_eq!(mock.nupkg_hits(), 0);
}

/// #233: a format's index is its own making, so a URL in it names no origin.
/// A plugin cannot point its index at an internal service, nor write the
/// origins the host records beside it.
#[tokio::test]
async fn a_formats_index_names_no_origin() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let mock = start_mock(sample_corpus("1.2.3")).await;
    let internal = internal_service().await;
    let flat = format!("{}/flat/", internal.uri());

    // The service index, with the flat container moved to the internal
    // service.
    let px = scripted_proxy(&pool, cas.clone(), {
        let flat = flat.clone();
        nuget_with_index(move |index| index["package_base_address"] = flat.clone().into())
    });
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    assert!(px.list_versions(&repo, "Sample.Lib").await.is_err());
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .is_err());
    assert_eq!(mock.index_hits(), 1);

    // And the internal service among the origins the host records.
    let px = scripted_proxy(&pool, cas, {
        let (flat, named) = (flat.clone(), serde_json::json!([internal.uri()]));
        nuget_with_index(move |index| {
            index["package_base_address"] = flat.clone().into();
            index["named_origins"] = named.clone();
        })
    });
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let err = px
        .list_versions(&repo, "Sample.Lib")
        .await
        .expect_err("an index using the host's keys is refused");
    assert!(err.to_string().contains("a key the host keeps"), "{err}");
    assert!(
        forge_db::proxy_dao::get_upstream_index(&pool, repo_id(&pool, &repo).await)
            .await
            .unwrap()
            .is_none(),
        "nothing was stored"
    );
    assert_eq!(requests_to(&internal).await, 0, "nothing reached it");
}

/// #233: a service index may put its resources on other hosts, and a
/// document fetched from one may name yet another (a registration page):
/// their origins are reached. The origins the service index names are
/// recorded with the index for every later operation.
#[tokio::test]
async fn origins_the_upstreams_documents_name_are_reached() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    // The service index and the registration; the flat container; a
    // registration page: three origins.
    let feed = start_mock(Corpus::new()).await;
    let cdn = start_mock(sample_corpus("1.2.3")).await;
    let pages = start_mock(Corpus::new()).await;
    feed.override_index(serde_json::json!({
        "version": "3.0.0",
        "resources": [
            { "@id": format!("{}/flat/", cdn.base), "@type": "PackageBaseAddress/3.0.0" },
            { "@id": format!("{}/registration/", feed.base), "@type": "RegistrationsBaseUrl/3.6.0" },
        ]
    }));
    feed.set_registration(
        "sample.lib",
        serde_json::json!({ "count": 1, "items": [ {
            "@id": format!("{}/registration/sample.lib/page/1.json", pages.base),
            "lower": "1.2.3", "upper": "1.2.3", "count": 1,
        } ] }),
    );
    pages.set_registration_page(
        "sample.lib",
        "1.json",
        serde_json::json!({ "items": [ { "catalogEntry": {
            "id": "Sample.Lib", "version": "1.2.3", "listed": true,
            "published": "2026-05-01T10:00:00+00:00", "dependencyGroups": []
        } } ] }),
    );
    let repo = make_proxy(&pool, &format!("{}/index.json", feed.base), 0, true).await;
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));

    assert_eq!(
        versions_of(&px.list_versions(&repo, "Sample.Lib").await.unwrap()),
        ["1.2.3"]
    );
    let reg = px.registration(&repo, "Sample.Lib").await.unwrap();
    assert_eq!(
        reg[0].published,
        Some("2026-05-01T10:00:00Z".parse().unwrap()),
        "the registration page was read"
    );
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .unwrap()
        .is_some());
    assert_eq!((cdn.flat_index_hits(), cdn.nupkg_hits()), (1, 1));
    assert_eq!(feed.registration_hits(), 1);
    assert_eq!(pages.registration_page_hits(), 1);

    let stored = forge_db::proxy_dao::get_upstream_index(&pool, repo_id(&pool, &repo).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.resources["named_origins"],
        serde_json::json!([cdn.base]),
        "the service index's other origin, not the remote_url's"
    );
}

/// #233: an index kept before the host recorded the origins its documents
/// name is resolved again at its next use, however fresh, and never trusted
/// to name any: while its upstream fails, it serves with the `remote_url`'s
/// origin alone.
#[tokio::test]
async fn an_index_kept_without_its_origins_is_resolved_again() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let internal = internal_service().await;
    // As the previous release kept a format's index: the flat container on
    // another host, without the origins its documents named.
    let kept = |remote_url: &str| {
        serde_json::json!({
            "remote_url": remote_url,
            "package_base_address": format!("{}/flat/", internal.uri()),
            "registrations_base_url": null,
            "search_query_service": null,
        })
    };

    // The upstream answers an unusable service index: the kept one is the
    // last good index, and reaches the remote_url's origin only.
    let failing = start_mock(sample_corpus("1.2.3")).await;
    failing.override_index(serde_json::json!({}));
    let url = format!("{}/index.json", failing.base);
    let repo = make_proxy(&pool, &url, 0, true).await;
    forge_db::proxy_dao::set_upstream_index(&pool, repo_id(&pool, &repo).await, kept(&url), None)
        .await
        .unwrap();
    let px = proxy_repo(&pool, cas.clone(), Cache::l1_only(128));
    assert!(px.list_versions(&repo, "Sample.Lib").await.is_err());
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.2.3")
        .await
        .is_err());
    assert_eq!(failing.index_hits(), 1, "the kept index was not fresh");

    // A good upstream: resolved again, with its origins.
    let good = start_mock(sample_corpus("1.2.3")).await;
    let url = format!("{}/index.json", good.base);
    let repo = make_proxy(&pool, &url, 0, true).await;
    let id = repo_id(&pool, &repo).await;
    forge_db::proxy_dao::set_upstream_index(&pool, id, kept(&url), None)
        .await
        .unwrap();
    let px = proxy_repo(&pool, cas, Cache::l1_only(128));
    assert_eq!(
        versions_of(&px.list_versions(&repo, "Sample.Lib").await.unwrap()),
        ["1.2.3"]
    );
    assert_eq!(good.index_hits(), 1);
    let stored = forge_db::proxy_dao::get_upstream_index(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.resources["package_base_address"],
        format!("{}/flat/", good.base)
    );
    assert_eq!(stored.resources["named_origins"], serde_json::json!([]));
    assert_eq!(requests_to(&internal).await, 0, "nothing reached it");
}
