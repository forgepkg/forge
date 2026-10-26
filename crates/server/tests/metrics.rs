//! Integration tests of the Prometheus metrics (`GET /metrics` on the
//! metrics listener): served on their own listener only, behind the
//! optional bearer token; the counters move with a NuGet push and restore,
//! a docker push and pull, and a proxy's miss then hit; and no label carries
//! a package id, a version, an image, a tag, a username or a path. Requires
//! Docker (Postgres + versitygw via the shared harness), or
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`.
//!
//! Every test binary shares one process-wide registry, so a test asserts on
//! series of its own repositories, or that a shared series grew.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use common::{unique, ServerOpts, TestServer};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};
use sha2::Digest as _;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

// ── Reading the exposition ──────────────────────────────────────────────────

/// One scrape: every sample, keyed by its series as printed
/// (`name{label="value",…}`).
struct Scrape {
    text: String,
    samples: HashMap<String, f64>,
}

impl Scrape {
    /// The value of `series`, `0` when absent.
    fn get(&self, series: &str) -> f64 {
        self.samples.get(series).copied().unwrap_or(0.0)
    }

    /// The sum of every series of metric `name` (labels any).
    fn sum(&self, name: &str) -> f64 {
        self.samples
            .iter()
            .filter(|(series, _)| {
                series
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('{'))
            })
            .map(|(_, v)| v)
            .sum()
    }

    /// Every `(label name, value)` of every sample.
    fn labels(&self) -> Vec<(String, String)> {
        let mut labels = Vec::new();
        for series in self.samples.keys() {
            let Some(open) = series.find('{') else {
                continue;
            };
            let mut rest = &series[open + 1..series.len() - 1];
            while let Some(eq) = rest.find("=\"") {
                let name = rest[..eq].trim_start_matches(',').to_string();
                let value = &rest[eq + 2..];
                let end = value.find('"').expect("closing quote");
                labels.push((name, value[..end].to_string()));
                rest = &value[end + 1..];
            }
        }
        labels
    }
}

async fn scrape(srv: &TestServer) -> Scrape {
    let resp = srv.client().get(&srv.metrics_url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()[CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/openmetrics-text"),
        "{:?}",
        resp.headers()[CONTENT_TYPE]
    );
    let text = resp.text().await.unwrap();
    assert!(text.ends_with("# EOF\n"), "{text}");
    let samples = text
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let (series, value) = line.rsplit_once(' ').expect("a sample: series value");
            (series.to_string(), value.parse::<f64>().expect("a number"))
        })
        .collect();
    Scrape { text, samples }
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
/// version listing, then the package.
async fn nuget_restore(srv: &TestServer, token: &str, repo: &str, id: &str, version: &str) {
    let (user, _) = srv.admin_basic();
    let lower = id.to_lowercase();
    let base = format!("{}/repository/{repo}/flat/{lower}", srv.base_url);
    for url in [
        format!("{base}/index.json"),
        format!("{base}/{version}/{lower}.{version}.nupkg"),
    ] {
        let resp = srv
            .client()
            .get(&url)
            .basic_auth(&user, Some(token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{url}: {}", resp.text().await.unwrap());
    }
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
/// package downloads it serves.
struct Feed {
    base: String,
    downloads: AtomicUsize,
}

async fn start_feed() -> Arc<Feed> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let feed = Arc::new(Feed {
        base: format!("http://{}", listener.local_addr().unwrap()),
        downloads: AtomicUsize::new(0),
    });
    async fn index(State(feed): State<Arc<Feed>>) -> Json<Value> {
        Json(json!({
            "version": "3.0.0",
            "resources": [
                {"@id": format!("{}/flat/", feed.base), "@type": "PackageBaseAddress/3.0.0"},
            ],
        }))
    }
    async fn versions() -> Json<Value> {
        Json(json!({"versions": ["1.0.0"]}))
    }
    async fn package(
        State(feed): State<Arc<Feed>>,
        Path((id, version, _file)): Path<(String, String, String)>,
    ) -> Response {
        feed.downloads.fetch_add(1, Ordering::SeqCst);
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

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_are_served_on_their_own_listener_only() {
    let srv = common::start().await;
    let resp = srv
        .client()
        .get(format!("{}/metrics", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "the main listener serves no metrics");
    assert!(!resp.text().await.unwrap().contains("forge_http_requests"));

    let scraped = scrape(&srv).await;
    assert!(
        scraped.get("forge_http_requests_total{surface=\"ui\",method=\"GET\",status=\"4xx\"}")
            >= 1.0,
        "the main listener's answer was counted:\n{}",
        scraped.text
    );
    assert!(scraped
        .samples
        .contains_key("forge_db_pool_connections{state=\"idle\"}"));
    assert!(scraped
        .samples
        .contains_key("forge_db_pool_max_connections"));
    // Nothing else is served there.
    let other = srv.metrics_url.replace("/metrics", "/admin/users");
    let resp = srv.client().get(other).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn a_metrics_token_is_required_once_configured() {
    let token = "metrics-token-0123456789";
    let srv = common::start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            server_extra: Some(format!("metrics_token = \"{token}\"")),
            ..Default::default()
        },
    )
    .await;
    let client = srv.client();
    for presented in [None, Some("wrong-token-0123456789"), Some("")] {
        let mut request = client.get(&srv.metrics_url);
        if let Some(presented) = presented {
            request = request.bearer_auth(presented);
        }
        let resp = request.send().await.unwrap();
        assert_eq!(resp.status(), 401, "{presented:?}");
        assert_eq!(resp.headers()["www-authenticate"], "Bearer");
    }
    let resp = client
        .get(&srv.metrics_url)
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().ends_with("# EOF\n"));
}

#[tokio::test]
async fn counters_move_with_pushes_pulls_and_proxy_lookups() {
    let srv = common::start().await;
    let token = srv.admin_token().await;
    let u = unique();
    let (hosted, proxy, docker) = (
        format!("mhosted{u}"),
        format!("mproxy{u}"),
        format!("mdocker{u}"),
    );
    let feed = start_feed().await;
    create_repo(&srv, json!({"name": hosted, "kind": "hosted"})).await;
    create_repo(
        &srv,
        json!({
            "name": proxy, "kind": "proxy",
            "remote_url": format!("{}/index.json", feed.base),
            "package_delay_seconds": 0,
        }),
    )
    .await;
    create_repo(
        &srv,
        json!({"name": docker, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let before = scrape(&srv).await;

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

    forge_server::metrics::count_inventory(&srv.state)
        .await
        .expect("count the inventory");
    let after = scrape(&srv).await;
    let grew = |series: &str| {
        let (b, a) = (before.get(series), after.get(series));
        assert!(a > b, "{series}: {b} → {a}\n{}", after.text);
    };
    let grew_sum = |name: &str| {
        let (b, a) = (before.sum(name), after.sum(name));
        assert!(a > b, "{name}: {b} → {a}\n{}", after.text);
    };

    // HTTP, by surface.
    grew("forge_http_requests_total{surface=\"nuget\",method=\"PUT\",status=\"2xx\"}");
    grew("forge_http_requests_total{surface=\"nuget\",method=\"GET\",status=\"2xx\"}");
    grew("forge_http_requests_total{surface=\"oci\",method=\"PUT\",status=\"2xx\"}");
    grew("forge_http_requests_total{surface=\"oci\",method=\"GET\",status=\"2xx\"}");
    grew(
        "forge_http_request_duration_seconds_count{surface=\"oci\",method=\"GET\",status=\"2xx\"}",
    );
    grew("forge_http_response_bytes_total{surface=\"oci\"}");
    grew("forge_http_response_bytes_total{surface=\"nuget\"}");

    // The proxy: one lookup fetched the package, the next one hit.
    let lookups = |kind: &str, outcome: &str| {
        after.get(&format!(
            "forge_proxy_lookups_total{{repo=\"{proxy}\",kind=\"{kind}\",outcome=\"{outcome}\"}}"
        ))
    };
    assert_eq!(lookups("package", "fetched"), 1.0, "{}", after.text);
    assert!(lookups("package", "hit") >= 1.0, "{}", after.text);
    assert!(lookups("metadata", "fetched") >= 1.0, "{}", after.text);
    assert!(
        after.get(&format!(
            "forge_proxy_upstream_requests_total{{repo=\"{proxy}\",status=\"2xx\"}}"
        )) >= 3.0,
        "the service index, the listing and the package: {}",
        after.text
    );
    assert!(
        after.get(&format!(
            "forge_proxy_upstream_request_duration_seconds_count{{repo=\"{proxy}\"}}"
        )) >= 3.0
    );
    assert!(
        after.get(&format!(
            "forge_proxy_upstream_bytes_total{{repo=\"{proxy}\"}}"
        )) > 0.0
    );

    // Storage and the cache.
    grew_sum("forge_s3_operations_total");
    grew_sum("forge_s3_operation_duration_seconds_count");
    grew_sum("forge_cache_lookups_total");

    // Sign-ins.
    grew("forge_auth_sign_ins_total{realm_type=\"local\",outcome=\"success\"}");

    // The inventory.
    assert_eq!(
        after.get(&format!("forge_repository_versions{{repo=\"{hosted}\"}}")),
        1.0,
        "{}",
        after.text
    );
    assert!(
        after.get(&format!(
            "forge_repository_stored_bytes{{repo=\"{hosted}\"}}"
        )) > 0.0
    );
    assert_eq!(
        after.get(&format!("forge_repository_versions{{repo=\"{docker}\"}}")),
        1.0,
        "one tag"
    );
    assert!(after.get("forge_repositories{format=\"nuget\",kind=\"proxy\"}") >= 1.0);
    assert!(after.get("forge_repositories{format=\"docker\",kind=\"hosted\"}") >= 1.0);
    assert!(after.samples.contains_key("forge_outbox_pending"));
    assert!(after
        .samples
        .contains_key("forge_outbox_oldest_due_age_seconds"));
}

/// No label carries what a client names: a package id or version, an image
/// or a tag, a username, a path. Each is pushed, pulled or tried with a
/// marker no repository name contains; the scrape must not show any, and
/// every label must be one [`forge_metrics::LABEL_NAMES`] lists.
#[tokio::test]
async fn no_label_carries_a_package_image_user_or_path() {
    let srv = common::start().await;
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

    forge_server::metrics::count_inventory(&srv.state)
        .await
        .expect("count the inventory");
    let scraped = scrape(&srv).await;
    let text = scraped.text.to_lowercase();
    for marker in [
        "mrkpkg", "mrkver", "mrkpath", "mrkimage", "mrktag", "mrkuser",
    ] {
        assert!(
            !text.contains(marker),
            "a label carries {marker:?}:\n{}",
            scraped.text
        );
    }
    let repositories: Vec<String> = sqlx::query_scalar("SELECT name FROM repository")
        .fetch_all(&srv.pool)
        .await
        .unwrap();
    for (label, value) in scraped.labels() {
        assert!(
            forge_metrics::LABEL_NAMES.contains(&label.as_str()),
            "label {label:?} is not one of forge_metrics::LABEL_NAMES"
        );
        if label == "repo" {
            assert!(
                value.is_empty() || repositories.contains(&value),
                "repo={value:?} names no repository"
            );
        }
    }
    // The repositories of this test are there by name.
    assert!(scraped.text.contains(&format!("repo=\"{hosted}\"")));
}
