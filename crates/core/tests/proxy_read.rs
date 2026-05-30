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
//!   trigger exactly ONE upstream nupkg fetch (row-lock, not advisory lock).
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
}

async fn serve_index(State(st): State<Arc<MockState>>) -> impl IntoResponse {
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
    Path(id): Path<String>,
) -> impl IntoResponse {
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
    Path((id, version, _file)): Path<(String, String, String)>,
) -> impl IntoResponse {
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

/// Boot the mock upstream feed on an ephemeral loopback port.
async fn start_mock(packages: HashMap<String, HashMap<String, Vec<u8>>>) -> MockUpstream {
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

/// Create a proxy repository pointing at `remote_url`, with `allow_private_upstream`
/// so the SSRF guard permits the loopback mock, and the given delay.
async fn make_proxy(
    pool: &PgPool,
    remote_url: &str,
    package_delay_seconds: i32,
    online: bool,
) -> String {
    let name = format!("proxy{}", common::unique());
    let mut new = NewRepository::proxy(name.clone());
    new.remote_url = Some(remote_url.to_string());
    new.allow_private_upstream = true;
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
    vers.insert("1.0.0".to_string(), sample_nupkg());
    corpus.insert("sample.lib".to_string(), vers);
    let mock = start_mock(corpus).await;

    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas, cache);

    // First download: fetches upstream.
    let loc = px
        .resolve_nupkg(&repo, "Sample.Lib", "1.0.0")
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
        .resolve_nupkg(&repo, "Sample.Lib", "1.0.0")
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

#[tokio::test]
async fn singleflight_concurrent_first_downloads_fetch_once() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let cache = Cache::l1_only(128);

    let mut corpus = HashMap::new();
    let mut vers = HashMap::new();
    vers.insert("1.0.0".to_string(), sample_nupkg());
    corpus.insert("sample.lib".to_string(), vers);
    let mock = start_mock(corpus).await;

    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = Arc::new(proxy_repo(&pool, cas, cache));

    // Pre-resolve the index so both racers compete only on the nupkg row lock.
    let r1 = repo.clone();
    let r2 = repo.clone();
    let p1 = px.clone();
    let p2 = px.clone();
    let h1 = tokio::spawn(async move { p1.resolve_nupkg(&r1, "Sample.Lib", "1.0.0").await });
    let h2 = tokio::spawn(async move { p2.resolve_nupkg(&r2, "Sample.Lib", "1.0.0").await });

    let (a, b) = (h1.await.unwrap().unwrap(), h2.await.unwrap().unwrap());
    assert!(
        a.is_some() && b.is_some(),
        "both concurrent reads get bytes"
    );
    assert_eq!(
        mock.nupkg_hits(),
        1,
        "row-lock singleflight must collapse concurrent first downloads to ONE upstream fetch"
    );

    // The blob landed exactly once.
    assert_eq!(a.unwrap().blob_s3_key, b.unwrap().blob_s3_key);
}

#[tokio::test]
async fn package_delay_hides_then_reveals() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let cache = Cache::l1_only(128);

    let mut corpus = HashMap::new();
    let mut vers = HashMap::new();
    vers.insert("1.0.0".to_string(), sample_nupkg());
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
        .resolve_nupkg(&repo, "Sample.Lib", "1.0.0")
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
        "1.0.0",
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
        .resolve_nupkg(&repo, "Sample.Lib", "1.0.0")
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
    vers.insert("1.0.0".to_string(), sample_nupkg());
    corpus.insert("sample.lib".to_string(), vers);
    let mock = start_mock(corpus).await;

    // Online proxy: warm the cache.
    let repo = make_proxy(&pool, &format!("{}/index.json", mock.base), 0, true).await;
    let px = proxy_repo(&pool, cas.clone(), cache.clone());
    assert!(px
        .resolve_nupkg(&repo, "Sample.Lib", "1.0.0")
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
        .resolve_nupkg(&repo, "Sample.Lib", "1.0.0")
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
