//! In-process mock upstream NuGet V3 feed for proxy e2e scenarios.
//!
//! Serves a service index advertising `PackageBaseAddress/3.0.0`,
//! `RegistrationsBaseUrl`, and `SearchQueryService`, plus the flat-container
//! version index and nupkg content. Every resource increments a hit counter so
//! tests can assert exact upstream fetch counts (cache-on-demand, singleflight,
//! genuine-404 negative caching).
//!
//! The corpus is `lower_id -> { version -> nupkg bytes }`. Unknown ids return
//! `404` (a genuine upstream miss). `.nuspec` requests serve the manifest
//! inside the package, and the registration index inlines every version with
//! the dependency groups of its manifest, like nuget.org does for small
//! packages. [`MockUpstream::publish`] adds versions while the feed runs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;

/// One package in the mock corpus: an id plus its versions and bytes.
pub struct UpstreamPackage {
    /// The package id as the upstream advertises it (the mock lowercases it for
    /// matching, mirroring the flat container's `lower_id` convention).
    pub id: String,
    /// `version -> nupkg bytes`.
    pub versions: HashMap<String, Vec<u8>>,
}

impl UpstreamPackage {
    /// A single-version package from raw nupkg bytes.
    pub fn single(id: &str, version: &str, bytes: Vec<u8>) -> Self {
        let mut versions = HashMap::new();
        versions.insert(version.to_string(), bytes);
        UpstreamPackage {
            id: id.to_string(),
            versions,
        }
    }
}

/// Shared mock state: the corpus + per-resource hit counters.
struct MockState {
    base: String,
    /// `lower_id -> { version -> bytes }`.
    packages: Mutex<HashMap<String, HashMap<String, Vec<u8>>>>,
    /// `lower_id -> id as published`.
    ids: Mutex<HashMap<String, String>>,
    /// `(lower_id, version) -> publish time` the registration reports: when
    /// the version was added to the mock (a fresh release), unless a test
    /// set another one.
    published: Mutex<HashMap<(String, String), String>>,
    index_hits: AtomicUsize,
    flat_index_hits: AtomicUsize,
    nupkg_hits: AtomicUsize,
    nuspec_hits: AtomicUsize,
    registration_hits: AtomicUsize,
}

impl MockState {
    fn package(&self, lower_id: &str, version: &str) -> Option<Vec<u8>> {
        self.packages
            .lock()
            .unwrap()
            .get(lower_id)
            .and_then(|v| v.get(version))
            .cloned()
    }
}

/// The `.nuspec` entry of a `.nupkg`, if it has one at its root.
fn nuspec_of(nupkg: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(nupkg)).ok()?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).ok()?;
        let name = entry.name().ok()?.to_ascii_lowercase();
        if name.ends_with(".nuspec") && !name.contains('/') {
            let mut out = Vec::new();
            entry.read_to_end(&mut out).ok()?;
            return Some(out);
        }
    }
    None
}

/// A running mock upstream feed; holds the server task and exposes its base URL.
pub struct MockUpstream {
    base: String,
    state: Arc<MockState>,
    _task: tokio::task::JoinHandle<()>,
}

impl MockUpstream {
    /// Boot the mock feed on an ephemeral loopback port with the given corpus.
    pub async fn start(packages: Vec<UpstreamPackage>) -> MockUpstream {
        let mut corpus: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
        let mut ids = HashMap::new();
        let mut published = HashMap::new();
        let now = chrono::Utc::now().to_rfc3339();
        for p in packages {
            let lower = p.id.to_lowercase();
            for version in p.versions.keys() {
                published.insert((lower.clone(), version.clone()), now.clone());
            }
            ids.insert(lower.clone(), p.id.clone());
            corpus.insert(lower, p.versions);
        }

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind mock upstream");
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");

        let state = Arc::new(MockState {
            base: base.clone(),
            packages: Mutex::new(corpus),
            ids: Mutex::new(ids),
            published: Mutex::new(published),
            index_hits: AtomicUsize::new(0),
            flat_index_hits: AtomicUsize::new(0),
            nupkg_hits: AtomicUsize::new(0),
            nuspec_hits: AtomicUsize::new(0),
            registration_hits: AtomicUsize::new(0),
        });

        let app = Router::new()
            .route("/index.json", get(serve_index))
            .route("/flat/{id}/index.json", get(serve_flat_index))
            .route("/flat/{id}/{version}/{file}", get(serve_nupkg))
            .route("/registration/{id}/index.json", get(serve_registration))
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

    /// The base URL of the mock feed (no trailing slash).
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The service-index URL to configure as a proxy's `remote_url`.
    pub fn index_url(&self) -> String {
        format!("{}/index.json", self.base)
    }

    /// Number of times the service index was fetched.
    pub fn index_hits(&self) -> usize {
        self.state.index_hits.load(Ordering::SeqCst)
    }

    /// Number of times the flat version index was fetched.
    pub fn flat_index_hits(&self) -> usize {
        self.state.flat_index_hits.load(Ordering::SeqCst)
    }

    /// Number of times a nupkg was fetched from upstream.
    pub fn nupkg_hits(&self) -> usize {
        self.state.nupkg_hits.load(Ordering::SeqCst)
    }

    /// Number of times a `.nuspec` was fetched from upstream.
    pub fn nuspec_hits(&self) -> usize {
        self.state.nuspec_hits.load(Ordering::SeqCst)
    }

    /// Number of times the registration index was fetched.
    pub fn registration_hits(&self) -> usize {
        self.state.registration_hits.load(Ordering::SeqCst)
    }

    /// Publish (or replace) `version` of `id` while the feed is running.
    pub fn publish(&self, id: &str, version: &str, bytes: Vec<u8>) {
        let lower = id.to_lowercase();
        self.state
            .ids
            .lock()
            .unwrap()
            .entry(lower.clone())
            .or_insert_with(|| id.to_string());
        self.state
            .packages
            .lock()
            .unwrap()
            .entry(lower.clone())
            .or_default()
            .insert(version.to_string(), bytes);
        self.state.published.lock().unwrap().insert(
            (lower, version.to_string()),
            chrono::Utc::now().to_rfc3339(),
        );
    }

    /// Report `version` of `id` as published at `at` (RFC 3339) from now on.
    pub fn set_published(&self, id: &str, version: &str, at: &str) {
        self.state
            .published
            .lock()
            .unwrap()
            .insert((id.to_lowercase(), version.to_string()), at.to_string());
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
    let versions = st
        .packages
        .lock()
        .unwrap()
        .get(&id.to_lowercase())
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
    Path((id, version, file)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let bytes = st.package(&id.to_lowercase(), &version);
    if file.to_ascii_lowercase().ends_with(".nuspec") {
        st.nuspec_hits.fetch_add(1, Ordering::SeqCst);
        return match bytes.as_deref().and_then(nuspec_of) {
            Some(nuspec) => (
                StatusCode::OK,
                [("content-type", "application/xml")],
                nuspec,
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    st.nupkg_hits.fetch_add(1, Ordering::SeqCst);
    match bytes {
        Some(bytes) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The registration `dependencyGroups` of a package's manifest.
fn dependency_groups_json(nupkg: &[u8]) -> serde_json::Value {
    let groups = nuspec_of(nupkg)
        .and_then(|n| forge_nuget::nuspec::dependency_groups_from_nuspec(&n).ok())
        .unwrap_or_default();
    serde_json::Value::Array(
        groups
            .into_iter()
            .map(|g| {
                let deps: Vec<_> = g
                    .dependencies
                    .into_iter()
                    .map(|d| serde_json::json!({ "id": d.id, "range": d.range }))
                    .collect();
                let mut group = serde_json::json!({ "dependencies": deps });
                if let Some(tfm) = g.target_framework {
                    group["targetFramework"] = serde_json::Value::String(tfm);
                }
                group
            })
            .collect(),
    )
}

async fn serve_registration(
    State(st): State<Arc<MockState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    st.registration_hits.fetch_add(1, Ordering::SeqCst);
    let lower = id.to_lowercase();
    let original = st
        .ids
        .lock()
        .unwrap()
        .get(&lower)
        .cloned()
        .unwrap_or_else(|| id.clone());
    let packages = st.packages.lock().unwrap().get(&lower).cloned();
    let published = st.published.lock().unwrap().clone();
    match packages {
        Some(vers) => {
            let items: Vec<_> = vers
                .iter()
                .map(|(v, bytes)| {
                    let at = published.get(&(lower.clone(), v.clone()));
                    serde_json::json!({
                        "catalogEntry": {
                            "id": original,
                            "version": v,
                            "listed": true,
                            "published": at,
                            "dependencyGroups": dependency_groups_json(bytes),
                        },
                        "packageContent":
                            format!("{}/flat/{lower}/{v}/{lower}.{v}.nupkg", st.base),
                    })
                })
                .collect();
            let body = serde_json::json!({
                "count": 1,
                "items": [ { "count": items.len(), "items": items } ],
            });
            (StatusCode::OK, axum::Json(body)).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
