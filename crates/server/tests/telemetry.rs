//! Integration tests of the OpenTelemetry export, through in-memory
//! exporters on the providers `main` would build ([`Telemetry`]): the
//! metrics move with a NuGet push and restore, a docker push and pull, and a
//! proxy's miss then hit, and no attribute carries a package id, a version,
//! an image, a tag, a username or a path; a request joins the trace its
//! `traceparent` names, with the proxy lookup, the upstream request (which
//! carries the trace on) and the S3 operations beneath it; no span holds the
//! secrets of an npm web login; and a log record written while handling a
//! request carries its trace. Requires Docker
//! (Postgres + versitygw via the shared harness), or
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`.
//!
//! The tests of this binary share one set of providers, as a process does:
//! a test asserts on its own repositories' series, on a shared series that
//! grew, or on the spans of a trace of its own.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use common::{unique, TestServer};
use forge_server::telemetry::{AcquireTimes, Telemetry, ACQUIRE_TARGET};
use opentelemetry::trace::{SpanId, SpanKind, TraceId};
use opentelemetry::KeyValue;
use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};
use sha2::Digest as _;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

// ── The providers ───────────────────────────────────────────────────────────

/// The process's providers, exporting to memory.
struct Export {
    meter: SdkMeterProvider,
    metrics: InMemoryMetricExporter,
    spans: InMemorySpanExporter,
    logs: InMemoryLogExporter,
    /// Collections reset the metric exporter: one at a time.
    collecting: Mutex<()>,
}

/// Set up the providers and the `tracing` subscriber, once per process, as
/// `main` does.
fn export() -> &'static Export {
    static EXPORT: OnceLock<Export> = OnceLock::new();
    EXPORT.get_or_init(|| {
        let metrics = InMemoryMetricExporter::default();
        let spans = InMemorySpanExporter::default();
        let logs = InMemoryLogExporter::default();
        let meter = SdkMeterProvider::builder()
            .with_resource(forge_server::telemetry::resource())
            .with_reader(PeriodicReader::builder(metrics.clone()).build())
            .build();
        let telemetry = Telemetry::from_providers(
            Some(meter.clone()),
            Some(
                SdkTracerProvider::builder()
                    .with_simple_exporter(spans.clone())
                    .build(),
            ),
            Some(
                SdkLoggerProvider::builder()
                    .with_simple_exporter(logs.clone())
                    .build(),
            ),
        );
        telemetry.install();
        let subscriber = tracing_subscriber::registry()
            .with(telemetry.layers())
            .with(
                AcquireTimes.with_filter(
                    tracing_subscriber::filter::Targets::new()
                        .with_target(ACQUIRE_TARGET, tracing::Level::TRACE),
                ),
            );
        tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");
        Export {
            meter,
            metrics,
            spans,
            logs,
            collecting: Mutex::new(()),
        }
    })
}

/// Server starts. Each checks its bucket, an `S3.HeadBucket` span, so a test
/// counting those spans holds this exclusively.
static STARTS: LazyLock<tokio::sync::RwLock<()>> = LazyLock::new(Default::default);

/// Start a test server whose state the metrics read.
async fn start() -> TestServer {
    let admin = format!("admin{}@example.com", unique());
    start_with(common::ServerOpts {
        bootstrap_admin: Some((admin, "adminpw".into())),
        ..Default::default()
    })
    .await
}

/// [`start`] a server with `opts`.
async fn start_with(opts: common::ServerOpts) -> TestServer {
    export();
    let _starting = STARTS.read().await;
    let srv = common::start_with(common::pool().await, opts).await;
    forge_server::telemetry::install_live_source(&srv.state);
    srv
}

// ── Reading the metrics ─────────────────────────────────────────────────────

/// A data point: its attributes, its value (a histogram's sum) and, for a
/// histogram, its count.
#[derive(Debug)]
struct Point {
    attributes: BTreeMap<String, String>,
    value: f64,
    count: u64,
}

/// One collection: every metric's data points by name.
#[derive(Debug)]
struct Metrics(BTreeMap<String, Vec<Point>>);

impl Metrics {
    fn points<'a>(
        &'a self,
        name: &str,
        attributes: &'a [(&'a str, &'a str)],
    ) -> impl Iterator<Item = &'a Point> + 'a {
        self.0.get(name).into_iter().flatten().filter(move |p| {
            attributes
                .iter()
                .all(|(k, v)| p.attributes.get(*k).is_some_and(|x| x == v))
        })
    }

    /// The sum of the values of `name`'s points carrying `attributes`.
    fn sum(&self, name: &str, attributes: &[(&str, &str)]) -> f64 {
        self.points(name, attributes).map(|p| p.value).sum()
    }

    /// The sum of the counts of histogram `name`'s points carrying
    /// `attributes`.
    fn count(&self, name: &str, attributes: &[(&str, &str)]) -> u64 {
        self.points(name, attributes).map(|p| p.count).sum()
    }

    fn has(&self, name: &str) -> bool {
        self.0.get(name).is_some_and(|points| !points.is_empty())
    }
}

/// Collect the metrics, as an export would.
fn collect() -> Metrics {
    let export = export();
    let _one = export.collecting.lock().unwrap();
    export.metrics.reset();
    export.meter.force_flush().expect("flush the metrics");
    let batches = export.metrics.get_finished_metrics().expect("metrics");
    // Cumulative: the latest collection holds every series.
    let latest = batches.last().expect("a collection");
    let mut out: BTreeMap<String, Vec<Point>> = BTreeMap::new();
    let attributes = |kvs: &mut dyn Iterator<Item = &KeyValue>| {
        kvs.map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<BTreeMap<_, _>>()
    };
    for scope in latest.scope_metrics() {
        for metric in scope.metrics() {
            let points = out.entry(metric.name().to_string()).or_default();
            macro_rules! points {
                ($data:expr) => {
                    match $data {
                        MetricData::Gauge(g) => {
                            for p in g.data_points() {
                                points.push(Point {
                                    attributes: attributes(&mut p.attributes()),
                                    value: p.value() as f64,
                                    count: 0,
                                });
                            }
                        }
                        MetricData::Sum(s) => {
                            for p in s.data_points() {
                                points.push(Point {
                                    attributes: attributes(&mut p.attributes()),
                                    value: p.value() as f64,
                                    count: 0,
                                });
                            }
                        }
                        MetricData::Histogram(h) => {
                            for p in h.data_points() {
                                points.push(Point {
                                    attributes: attributes(&mut p.attributes()),
                                    value: p.sum() as f64,
                                    count: p.count(),
                                });
                            }
                        }
                        MetricData::ExponentialHistogram(_) => {}
                    }
                };
            }
            match metric.data() {
                AggregatedMetrics::F64(d) => points!(d),
                AggregatedMetrics::U64(d) => points!(d),
                AggregatedMetrics::I64(d) => points!(d),
            }
        }
    }
    Metrics(out)
}

// ── Reading the traces and logs ─────────────────────────────────────────────

/// A W3C `traceparent` of a trace of the test's own, and its ids.
fn traceparent() -> (String, TraceId, SpanId) {
    let trace = format!("{:032x}", rand::random::<u128>() | 1);
    let span = format!("{:016x}", rand::random::<u64>() | 1);
    (
        format!("00-{trace}-{span}-01"),
        TraceId::from_hex(&trace).unwrap(),
        SpanId::from_hex(&span).unwrap(),
    )
}

/// The exported spans of trace `trace`.
fn spans_of(trace: TraceId) -> Vec<SpanData> {
    export()
        .spans
        .get_finished_spans()
        .expect("spans")
        .into_iter()
        .filter(|s| s.span_context.trace_id() == trace)
        .collect()
}

/// Poll `found` until it finds something: a request's span ends, and is
/// exported, once the server dropped its response body, which can be just
/// after the client read it.
async fn eventually<T>(what: &str, found: impl Fn() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(found) = found() {
            return found;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("never exported: {what}");
}

fn attribute(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.to_string())
}

/// Whether `span` descends from the span `ancestor` among `spans`.
fn descends(spans: &[SpanData], span: &SpanData, ancestor: SpanId) -> bool {
    let mut parent = span.parent_span_id;
    for _ in 0..spans.len() {
        if parent == ancestor {
            return true;
        }
        match spans.iter().find(|s| s.span_context.span_id() == parent) {
            Some(next) => parent = next.parent_span_id,
            None => return false,
        }
    }
    false
}

// ── Talking to the server ───────────────────────────────────────────────────

async fn create_repo(srv: &TestServer, body: Value) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(u, Some(p))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
}

/// Push a `.nupkg` of `id` `version` to hosted `repo`.
async fn nuget_push(srv: &TestServer, token: &str, repo: &str, id: &str, version: &str) {
    let part =
        reqwest::multipart::Part::bytes(common::make_nupkg(id, version)).file_name("package.nupkg");
    let resp = srv
        .client()
        .put(format!("{}/repository/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", token)
        .multipart(reqwest::multipart::Form::new().part("package", part))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
}

/// Restore `id` `version` from `repo`, as `dotnet restore` does: the
/// version listing, then the package; each request with `traceparent`.
async fn nuget_restore_traced(
    srv: &TestServer,
    token: &str,
    repo: &str,
    id: &str,
    version: &str,
    traceparent: Option<&str>,
) -> Vec<StatusCode> {
    let (user, _) = srv.admin_basic();
    let lower = id.to_lowercase();
    let base = format!("{}/repository/{repo}/flat/{lower}", srv.base_url);
    let mut statuses = Vec::new();
    for url in [
        format!("{base}/index.json"),
        format!("{base}/{version}/{lower}.{version}.nupkg"),
    ] {
        let mut request = srv.client().get(&url).basic_auth(&user, Some(token));
        if let Some(traceparent) = traceparent {
            request = request.header("traceparent", traceparent);
        }
        let resp = request.send().await.unwrap();
        statuses.push(resp.status());
        resp.bytes().await.unwrap();
    }
    statuses
}

async fn nuget_restore(srv: &TestServer, token: &str, repo: &str, id: &str, version: &str) {
    let statuses = nuget_restore_traced(srv, token, repo, id, version, None).await;
    assert_eq!(statuses, [StatusCode::OK, StatusCode::OK], "restore {id}");
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// A registry client for `name` with a pull and push token.
struct Oci {
    base: String,
    client: reqwest::Client,
    bearer: String,
}

impl Oci {
    async fn new(srv: &TestServer, token: &str, name: &str) -> Oci {
        let (user, _) = srv.admin_basic();
        let resp = srv
            .client()
            .get(format!("{}/v2/token", srv.base_url))
            .query(&[
                ("service", "test.local".to_string()),
                ("scope", format!("repository:{name}:pull,push")),
            ])
            .basic_auth(user, Some(token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "token");
        let body: Value = resp.json().await.unwrap();
        Oci {
            base: srv.base_url.clone(),
            client: srv.client(),
            bearer: format!("Bearer {}", body["token"].as_str().unwrap()),
        }
    }

    /// Push a single-layer image as `name:tag`; returns the layer's digest.
    async fn push(&self, name: &str, tag: &str) -> String {
        let config = json!({"architecture": "amd64", "os": "linux"})
            .to_string()
            .into_bytes();
        let layer: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        for blob in [&config, &layer] {
            let resp = self
                .client
                .post(format!("{}/v2/{name}/blobs/uploads/", self.base))
                .query(&[("digest", sha(blob))])
                .header(AUTHORIZATION, &self.bearer)
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(blob.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 201, "blob push");
        }
        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": sha(&config), "size": config.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": sha(&layer), "size": layer.len()}],
        })
        .to_string();
        let resp = self
            .client
            .put(format!("{}/v2/{name}/manifests/{tag}", self.base))
            .header(AUTHORIZATION, &self.bearer)
            .header(CONTENT_TYPE, OCI_MANIFEST)
            .body(manifest)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
        sha(&layer)
    }

    async fn get(&self, name: &str, path: &str) -> StatusCode {
        let resp = self
            .client
            .get(format!("{}/v2/{name}/{path}", self.base))
            .header(AUTHORIZATION, &self.bearer)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        resp.bytes().await.unwrap();
        status
    }
}

/// An upstream NuGet V3 feed holding `1.0.0` of every id; counts the
/// package downloads it serves and keeps the `traceparent`s it is sent. An
/// id starting with `mismatch` is answered with another id's package.
struct Feed {
    base: String,
    downloads: AtomicUsize,
    traceparents: Mutex<Vec<String>>,
}

async fn start_feed() -> Arc<Feed> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let feed = Arc::new(Feed {
        base: format!("http://{}", listener.local_addr().unwrap()),
        downloads: AtomicUsize::new(0),
        traceparents: Mutex::new(Vec::new()),
    });
    fn keep(feed: &Feed, headers: &HeaderMap) {
        if let Some(tp) = headers.get("traceparent").and_then(|v| v.to_str().ok()) {
            feed.traceparents.lock().unwrap().push(tp.to_string());
        }
    }
    async fn index(State(feed): State<Arc<Feed>>, headers: HeaderMap) -> Json<Value> {
        keep(&feed, &headers);
        Json(json!({
            "version": "3.0.0",
            "resources": [
                {"@id": format!("{}/flat/", feed.base), "@type": "PackageBaseAddress/3.0.0"},
            ],
        }))
    }
    async fn versions(State(feed): State<Arc<Feed>>, headers: HeaderMap) -> Json<Value> {
        keep(&feed, &headers);
        Json(json!({"versions": ["1.0.0"]}))
    }
    async fn package(
        State(feed): State<Arc<Feed>>,
        headers: HeaderMap,
        Path((id, version, _file)): Path<(String, String, String)>,
    ) -> Response {
        keep(&feed, &headers);
        feed.downloads.fetch_add(1, Ordering::SeqCst);
        let id = if id.starts_with("mismatch") {
            format!("other{id}")
        } else {
            id
        };
        common::make_nupkg(&id, &version).into_response()
    }
    let app = Router::new()
        .route("/index.json", get(index))
        .route("/flat/{id}/index.json", get(versions))
        .route("/flat/{id}/{version}/{file}", get(package))
        .with_state(feed.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    feed
}

/// Create a NuGet proxy of `feed` named `name`.
async fn create_proxy(srv: &TestServer, name: &str, feed: &Feed) {
    create_repo(
        srv,
        json!({
            "name": name, "kind": "proxy",
            "remote_url": format!("{}/index.json", feed.base),
            "package_delay_seconds": 0,
        }),
    )
    .await;
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_move_with_pushes_pulls_and_proxy_lookups() {
    let srv = start().await;
    let token = srv.admin_token().await;
    let u = unique();
    let (hosted, proxy, docker) = (
        format!("mhosted{u}"),
        format!("mproxy{u}"),
        format!("mdocker{u}"),
    );
    let feed = start_feed().await;
    create_repo(&srv, json!({"name": hosted, "kind": "hosted"})).await;
    create_proxy(&srv, &proxy, &feed).await;
    create_repo(
        &srv,
        json!({"name": docker, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let before = collect();

    // NuGet: a push and a restore.
    let id = format!("Metrics.Pkg{u}");
    nuget_push(&srv, &token, &hosted, &id, "1.2.3").await;
    nuget_restore(&srv, &token, &hosted, &id, "1.2.3").await;

    // Docker: a push and a pull.
    let name = format!("{docker}/team/app");
    let oci = Oci::new(&srv, &token, &name).await;
    let layer = oci.push(&name, "1.0").await;
    assert_eq!(oci.get(&name, "manifests/1.0").await, 200);
    assert_eq!(oci.get(&name, &format!("blobs/{layer}")).await, 200);

    // A proxy: a miss (fetched from the upstream), then a hit.
    let proxied = format!("Upstream.Pkg{u}");
    nuget_restore(&srv, &token, &proxy, &proxied, "1.0.0").await;
    nuget_restore(&srv, &token, &proxy, &proxied, "1.0.0").await;
    assert_eq!(feed.downloads.load(Ordering::SeqCst), 1, "fetched once");

    // A password over Basic signs in through the local realm.
    let (user, password) = srv.admin_password_basic();
    let resp = srv
        .client()
        .get(format!("{}/repository/{hosted}/index.json", srv.base_url))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    forge_server::telemetry::count_inventory(&srv.state)
        .await
        .expect("count the inventory");
    let after = collect();
    let grew = |name: &str, attributes: &[(&str, &str)]| {
        let (b, a) = (
            before.count(name, attributes) as f64 + before.sum(name, attributes),
            after.count(name, attributes) as f64 + after.sum(name, attributes),
        );
        assert!(a > b, "{name} {attributes:?}: {b} → {a}\n{after:#?}");
    };

    // HTTP, by surface.
    let request = "http.server.request.duration";
    for (surface, method, status) in [
        ("nuget", "PUT", "201"),
        ("nuget", "GET", "200"),
        ("oci", "PUT", "201"),
        ("oci", "GET", "200"),
    ] {
        grew(
            request,
            &[
                ("forge.surface", surface),
                ("http.request.method", method),
                ("http.response.status_code", status),
            ],
        );
    }
    grew(
        "http.server.response.body.size",
        &[("forge.surface", "oci")],
    );
    grew(
        "http.server.response.body.size",
        &[("forge.surface", "nuget")],
    );
    assert!(after.has("http.server.active_requests"));

    // The proxy: one lookup fetched the package, the next one hit.
    let lookups = |kind: &str, outcome: &str| {
        after.sum(
            "forge.proxy.lookups",
            &[
                ("forge.repository", &proxy),
                ("forge.proxy.kind", kind),
                ("forge.proxy.outcome", outcome),
            ],
        )
    };
    assert_eq!(lookups("package", "fetched"), 1.0, "{after:#?}");
    assert!(lookups("package", "hit") >= 1.0, "{after:#?}");
    assert!(lookups("metadata", "fetched") >= 1.0, "{after:#?}");
    assert!(
        after.count(
            "http.client.request.duration",
            &[
                ("forge.repository", &proxy),
                ("http.response.status_code", "200")
            ]
        ) >= 3,
        "the service index, the listing and the package: {after:#?}"
    );
    assert!(
        after.sum(
            "forge.proxy.upstream.fetched",
            &[("forge.repository", &proxy)]
        ) > 0.0
    );

    // Storage, the cache and the connection pool.
    grew("forge.s3.operation.duration", &[]);
    grew("forge.cache.lookups", &[]);
    assert!(after.has("db.client.connection.count"), "{after:#?}");
    assert!(after.has("db.client.connection.max"));

    // Sign-ins.
    grew(
        "forge.auth.sign_ins",
        &[
            ("forge.auth.realm_type", "local"),
            ("forge.auth.outcome", "success"),
        ],
    );

    // The inventory.
    assert_eq!(
        after.sum(
            "forge.repository.versions",
            &[("forge.repository", &hosted)]
        ),
        1.0,
        "{after:#?}"
    );
    assert!(after.sum("forge.repository.size", &[("forge.repository", &hosted)]) > 0.0);
    assert_eq!(
        after.sum(
            "forge.repository.versions",
            &[("forge.repository", &docker)]
        ),
        1.0,
        "one tag"
    );
    assert!(
        after.sum(
            "forge.repositories",
            &[
                ("forge.repository.format", "nuget"),
                ("forge.repository.kind", "proxy")
            ]
        ) >= 1.0
    );
    assert!(
        after.sum(
            "forge.repositories",
            &[
                ("forge.repository.format", "docker"),
                ("forge.repository.kind", "hosted")
            ]
        ) >= 1.0
    );
    assert!(after.has("forge.outbox.pending"));
    assert!(after.has("forge.outbox.oldest_due.age"));
}

/// No metric attribute carries what a client names: a package id or
/// version, an image or a tag, a username, a path. Each is pushed, pulled
/// or tried with a marker no repository name contains; no attribute may
/// show one, and every attribute must be one
/// [`forge_telemetry::ATTRIBUTE_KEYS`] lists.
#[tokio::test]
async fn no_metric_attribute_carries_a_package_image_user_or_path() {
    let srv = start().await;
    let token = srv.admin_token().await;
    let u = unique();
    let (hosted, docker) = (format!("lbhosted{u}"), format!("lbdocker{u}"));
    create_repo(&srv, json!({"name": hosted, "kind": "hosted"})).await;
    create_repo(
        &srv,
        json!({"name": docker, "kind": "hosted", "format": "docker"}),
    )
    .await;

    let id = format!("Mrkpkg.Id{u}");
    let version = format!("9.8.7-mrkver{u}");
    nuget_push(&srv, &token, &hosted, &id, &version).await;
    nuget_restore(&srv, &token, &hosted, &id, &version).await;
    let (user, _) = srv.admin_basic();
    let missing = srv
        .client()
        .get(format!(
            "{}/repository/{hosted}/flat/mrkpath{u}/index.json",
            srv.base_url
        ))
        .basic_auth(&user, Some(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    let name = format!("{docker}/mrkimage{u}");
    let oci = Oci::new(&srv, &token, &name).await;
    oci.push(&name, &format!("mrktag{u}")).await;
    assert_eq!(oci.get(&name, &format!("manifests/mrktag{u}")).await, 200);

    let resp = srv
        .client()
        .post(format!("{}/auth/login", srv.base_url))
        .json(&json!({"username": format!("mrkuser{u}@example.com"), "password": "wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    forge_server::telemetry::count_inventory(&srv.state)
        .await
        .expect("count the inventory");
    let metrics = collect();
    let repositories: BTreeSet<String> = sqlx::query_scalar("SELECT name FROM repository")
        .fetch_all(&srv.pool)
        .await
        .unwrap()
        .into_iter()
        .collect();
    for (metric, points) in &metrics.0 {
        for point in points {
            for (key, value) in &point.attributes {
                assert!(
                    forge_telemetry::ATTRIBUTE_KEYS.contains(&key.as_str()),
                    "{metric}: attribute {key:?} is not one of forge_telemetry::ATTRIBUTE_KEYS"
                );
                let lower = value.to_lowercase();
                for marker in [
                    "mrkpkg", "mrkver", "mrkpath", "mrkimage", "mrktag", "mrkuser",
                ] {
                    assert!(
                        !lower.contains(marker),
                        "{metric}: {key}={value:?} carries {marker:?}"
                    );
                }
                if key == "forge.repository" {
                    assert!(
                        repositories.contains(value),
                        "{metric}: forge.repository={value:?} names no repository"
                    );
                }
            }
        }
    }
    // The repositories of this test are there by name.
    assert!(
        metrics.sum(
            "forge.repository.versions",
            &[("forge.repository", &hosted)]
        ) >= 1.0
    );
}

/// A request joins the trace its `traceparent` names; the proxy lookup, the
/// upstream requests and the S3 operations it makes are spans beneath it,
/// and the upstream is sent the trace. Health probes make no spans, nor
/// does what they do.
#[tokio::test]
async fn a_request_joins_the_callers_trace_down_to_the_upstream_and_s3() {
    let srv = start().await;
    let token = srv.admin_token().await;
    let u = unique();
    let proxy = format!("tproxy{u}");
    let feed = start_feed().await;
    create_proxy(&srv, &proxy, &feed).await;
    let id = format!("Traced.Pkg{u}");

    let (traceparent, trace, caller) = traceparent();
    let statuses =
        nuget_restore_traced(&srv, &token, &proxy, &id, "1.0.0", Some(&traceparent)).await;
    assert_eq!(statuses, [StatusCode::OK, StatusCode::OK]);
    let head_buckets = || {
        export()
            .spans
            .get_finished_spans()
            .unwrap()
            .iter()
            .filter(|s| s.name == "S3.HeadBucket")
            .count()
    };
    // No server starts (and checks its bucket) while they are counted.
    let no_starts = STARTS.write().await;
    let before = head_buckets();
    for probe in ["healthz", "readyz"] {
        let resp = srv
            .client()
            .get(format!("{}/{probe}", srv.base_url))
            .header("traceparent", &traceparent)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        resp.bytes().await.unwrap();
    }
    // The readiness check's S3 call made no span either.
    assert_eq!(head_buckets(), before);
    drop(no_starts);

    let spans = eventually("the requests' spans", || {
        let spans = spans_of(trace);
        let servers = spans
            .iter()
            .filter(|s| s.span_kind == SpanKind::Server)
            .count();
        (servers >= 2).then_some(spans)
    })
    .await;
    let servers: Vec<&SpanData> = spans
        .iter()
        .filter(|s| s.span_kind == SpanKind::Server)
        .collect();
    assert_eq!(
        servers.len(),
        2,
        "the listing and the package, not the probe: {spans:#?}"
    );
    for server in &servers {
        assert_eq!(
            server.parent_span_id, caller,
            "a child of the caller's span"
        );
        assert!(server.parent_span_is_remote);
        assert!(
            server.name.starts_with("GET /repository/"),
            "{}",
            server.name
        );
        assert_eq!(attribute(server, "forge.surface").as_deref(), Some("nuget"));
        assert_eq!(
            attribute(server, "http.response.status_code").as_deref(),
            Some("200")
        );
    }
    let package = servers
        .iter()
        .find(|s| attribute(s, "url.path").is_some_and(|p| p.ends_with(".nupkg")))
        .expect("the package request's span");

    // The lookup, beneath the request.
    let lookup = spans
        .iter()
        .find(|s| s.name == "proxy package")
        .unwrap_or_else(|| panic!("a proxy package span: {spans:#?}"));
    assert!(descends(&spans, lookup, package.span_context.span_id()));
    assert_eq!(
        attribute(lookup, "forge.repository").as_deref(),
        Some(proxy.as_str())
    );
    assert_eq!(
        attribute(lookup, "forge.proxy.outcome").as_deref(),
        Some("fetched")
    );

    // The upstream request, beneath the lookup, sent the trace on.
    let upstream = spans
        .iter()
        .find(|s| {
            s.span_kind == SpanKind::Client
                && attribute(s, "url.full").is_some_and(|url| url.ends_with(".nupkg"))
        })
        .unwrap_or_else(|| panic!("the upstream download's span: {spans:#?}"));
    assert!(descends(&spans, upstream, lookup.span_context.span_id()));
    assert!(attribute(upstream, "url.full")
        .unwrap()
        .starts_with(&feed.base));
    let sent = feed.traceparents.lock().unwrap().clone();
    let expected = format!("00-{}-{}-01", trace, upstream.span_context.span_id());
    assert!(sent.contains(&expected), "{expected} not in {sent:?}");

    // The package's S3 write, beneath the request.
    let s3 = spans
        .iter()
        .filter(|s| attribute(s, "rpc.service").as_deref() == Some("S3"))
        .collect::<Vec<_>>();
    assert!(!s3.is_empty(), "S3 spans: {spans:#?}");
    for span in &s3 {
        assert_eq!(span.span_kind, SpanKind::Client);
        assert!(descends(&spans, span, caller), "{span:#?}");
    }

    // No probe span, in any trace.
    let probes = export()
        .spans
        .get_finished_spans()
        .unwrap()
        .into_iter()
        .filter(|s| {
            s.name == "health probe"
                || attribute(s, "url.path").is_some_and(|p| p == "/healthz" || p == "/readyz")
        })
        .count();
    assert_eq!(probes, 0);
}

/// An npm web login's secrets travel in paths: the login's page and the API
/// behind it carry the one that approves it, the URL the client polls the
/// one that collects the user's token. No span holds either.
#[tokio::test]
async fn no_span_holds_the_secrets_of_a_web_login() {
    // A web login is approved in the web UI: without it, none starts.
    let assets = tempfile::tempdir().unwrap();
    std::fs::write(assets.path().join("index.html"), "<html></html>").unwrap();
    let srv = start_with(common::ServerOpts {
        bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
        web_assets_dir: Some(assets.path().display().to_string()),
        ..Default::default()
    })
    .await;
    let repo = format!("tnpm{}", unique());
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;

    let (traceparent, trace, _) = traceparent();
    let started: Value = srv
        .client()
        .post(format!("{}/repository/{repo}/-/v1/login", srv.base_url))
        .header("traceparent", &traceparent)
        .json(&json!({"hostname": "laptop"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let secret_of = |url: &Value| url.as_str().unwrap().rsplit('/').next().unwrap().to_owned();
    let login = secret_of(&started["loginUrl"]);
    let done = secret_of(&started["doneUrl"]);
    for path in [
        format!("/repository/{repo}/-/v1/login/done/{done}"),
        format!("/auth/cli-login/{login}"),
        format!("/cli-login/{login}"),
    ] {
        let resp = srv
            .client()
            .get(format!("{}{path}", srv.base_url))
            .header("traceparent", &traceparent)
            .send()
            .await
            .unwrap();
        resp.bytes().await.unwrap();
    }

    let spans = eventually("the login's spans", || {
        let spans = spans_of(trace);
        let servers = spans
            .iter()
            .filter(|s| s.span_kind == SpanKind::Server)
            .count();
        (servers >= 4).then_some(spans)
    })
    .await;
    for span in &spans {
        let holds = |text: &str| text.contains(&login) || text.contains(&done);
        assert!(!holds(&span.name), "{span:#?}");
        assert!(
            !span
                .attributes
                .iter()
                .any(|kv| holds(&kv.value.to_string())),
            "{span:#?}"
        );
    }
    let paths: BTreeSet<String> = spans
        .iter()
        .filter_map(|s| attribute(s, "url.path"))
        .collect();
    let expected: BTreeSet<String> = [
        format!("/repository/{repo}/-/v1/login"),
        format!("/repository/{repo}/-/v1/login/done/{{secret}}"),
        "/auth/cli-login/{secret}".to_owned(),
        "/cli-login/{secret}".to_owned(),
    ]
    .into();
    assert_eq!(paths, expected);
}

/// A log record written while a request is handled carries its trace and
/// span.
#[tokio::test]
async fn a_log_record_carries_the_trace_of_its_request() {
    let srv = start().await;
    let token = srv.admin_token().await;
    let u = unique();
    let proxy = format!("lproxy{u}");
    let feed = start_feed().await;
    create_proxy(&srv, &proxy, &feed).await;

    // The upstream answers another id's package: rejected, with a warning.
    let id = format!("mismatch{u}");
    let (traceparent, trace, _) = traceparent();
    let statuses =
        nuget_restore_traced(&srv, &token, &proxy, &id, "1.0.0", Some(&traceparent)).await;
    assert_eq!(statuses[0], StatusCode::OK);
    assert_ne!(statuses[1], StatusCode::OK);

    let rejected = eventually("the rejection's log record", || {
        export()
            .logs
            .get_emitted_logs()
            .expect("logs")
            .into_iter()
            .find(|log| {
                log.record
                    .trace_context()
                    .is_some_and(|ctx| ctx.trace_id == trace)
                    && log.record.body().is_some_and(|body| {
                        format!("{body:?}").contains("rejected upstream package")
                    })
            })
    })
    .await;
    assert_eq!(
        rejected.record.severity_number(),
        Some(opentelemetry::logs::Severity::Warn)
    );
    let span = rejected.record.trace_context().unwrap().span_id;
    eventually("the record's span", || {
        spans_of(trace)
            .iter()
            .any(|s| s.span_context.span_id() == span)
            .then_some(())
    })
    .await;
}
