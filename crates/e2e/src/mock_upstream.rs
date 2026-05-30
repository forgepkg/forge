//! In-process mock upstream NuGet V3 feed for proxy e2e scenarios.
//!
//! Serves a service index advertising `PackageBaseAddress/3.0.0`,
//! `RegistrationsBaseUrl`, and `SearchQueryService`, plus the flat-container
//! version index and nupkg content. Every resource increments a hit counter so
//! tests can assert exact upstream fetch counts (cache-on-demand, singleflight,
//! genuine-404 negative caching).
//!
//! The corpus is `lower_id -> { version -> nupkg bytes }`. Unknown ids return
//! `404` (a genuine upstream miss).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
    packages: HashMap<String, HashMap<String, Vec<u8>>>,
    index_hits: AtomicUsize,
    flat_index_hits: AtomicUsize,
    nupkg_hits: AtomicUsize,
    registration_hits: AtomicUsize,
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
        for p in packages {
            corpus.insert(p.id.to_lowercase(), p.versions);
        }

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind mock upstream");
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");

        let state = Arc::new(MockState {
            base: base.clone(),
            packages: corpus,
            index_hits: AtomicUsize::new(0),
            flat_index_hits: AtomicUsize::new(0),
            nupkg_hits: AtomicUsize::new(0),
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

    /// Number of times the registration index was fetched.
    pub fn registration_hits(&self) -> usize {
        self.state.registration_hits.load(Ordering::SeqCst)
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
    match st.packages.get(&id.to_lowercase()) {
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
    match st
        .packages
        .get(&id.to_lowercase())
        .and_then(|v| v.get(&version))
    {
        Some(bytes) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes.clone(),
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
    let lower = id.to_lowercase();
    match st.packages.get(&lower) {
        Some(vers) => {
            let items: Vec<_> = vers
                .keys()
                .map(|v| {
                    serde_json::json!({
                        "catalogEntry": {
                            "id": id,
                            "version": v,
                            "listed": true,
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
