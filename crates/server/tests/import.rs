//! Imports (`crates/server/src/import`) against a mock source that speaks
//! the formats' own protocols under Nexus' paths, a NuGet v3 feed at
//! `/repository/<name>/index.json` and a registry at
//! `/repository/<name>/v2/`, with Basic authentication, and the real
//! worker:
//!
//! * NuGet: bytes are identical, publish times are kept (nuget.org's
//!   `1900-01-01` is none), the password is deleted once the import
//!   completes, and a second run copies only what is new, downloading only
//!   what the feed lists no SHA-512 for; the previous request form (a Nexus
//!   server and repository) is accepted;
//! * retention does not delete what was just imported;
//! * killing the worker mid-import and starting it again resumes without
//!   duplicating anything, through a search that pages like Nexus' (its
//!   total is the page's);
//! * every conflict policy (skip, overwrite, fail) and the dry run;
//! * a failed item is retried on its own (with the password again);
//!   cancelling and resuming; the preflight's refusals;
//! * an import that names its packages or images, from a source without a
//!   search or a catalog;
//! * Docker: the catalog paged, a multi-platform index with its children, a
//!   cosign signature tag, and a referrer from the referrers API or, without
//!   it, through the referrers tag schema, digests kept;
//! * an import stored before imports read the formats' protocols lists and
//!   resumes;
//! * with `[crypto]`, the password is sealed at rest.

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::{DateTime, Utc};
use common::{make_nupkg, make_nupkg_with_payload, ServerOpts, TestServer};
use forge_server::import::ImportWorker;
use serde_json::{json, Value};
use sha2::Digest;

const USER: &str = "migrator";
const PASSWORD: &str = "source-secret";
const SERVER: &str = "Nexus/3.70.1-02 (OSS)";

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";
const LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256(bytes))
}

fn sha512_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
}

// ── The mock source ─────────────────────────────────────────────────────────

/// A package version of a feed.
#[derive(Clone)]
struct Package {
    id: String,
    version: String,
    bytes: Vec<u8>,
    published: String,
    listed: bool,
    /// The registration lists the package's SHA-512 (as Forge and nuget.org
    /// do; Nexus does not).
    hash_listed: bool,
}

/// The images of a registry.
#[derive(Default)]
struct Images {
    /// image → tag → digest.
    tags: BTreeMap<String, BTreeMap<String, String>>,
    /// image → digest → (media type, bytes).
    manifests: BTreeMap<String, HashMap<String, (String, Vec<u8>)>>,
    /// image → digest → bytes.
    blobs: HashMap<String, HashMap<String, Vec<u8>>>,
}

#[derive(Default)]
struct SourceState {
    /// feed → its packages, in the order they were added.
    feeds: HashMap<String, Vec<Package>>,
    registries: HashMap<String, Images>,
    /// Feeds whose service index lists no search.
    no_search: HashSet<String>,
    /// Registries serving no catalog, and none serving the referrers API.
    no_catalog: HashSet<String>,
    no_referrers: HashSet<String>,
    /// Entries a search, catalog or tag list page holds at most.
    page_size: usize,
    /// A search reports the hits of the page it answers as its total, as
    /// Nexus does.
    page_totals: bool,
    /// `<feed>/<lower id>/<version>` served with these bytes instead.
    corrupt: HashMap<String, Vec<u8>>,
    /// Package downloads, by `<feed>/<lower id>/<version>`.
    downloads: HashMap<String, usize>,
    /// Slows every package download.
    delay: Duration,
}

#[derive(Clone)]
struct Source {
    url: String,
    state: Arc<Mutex<SourceState>>,
}

impl Source {
    async fn start() -> Self {
        let state = Arc::new(Mutex::new(SourceState {
            page_size: 2,
            ..Default::default()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new()
            .fallback(serve)
            .with_state((state.clone(), url.clone()));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Source { url, state }
    }

    fn with<R>(&self, f: impl FnOnce(&mut SourceState) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    /// The service index of the feed `name`.
    fn feed_url(&self, name: &str) -> String {
        format!("{}/repository/{name}/index.json", self.url)
    }

    /// The registry API of `name`.
    fn registry_url(&self, name: &str) -> String {
        format!("{}/repository/{name}", self.url)
    }

    /// Add (or replace) a package version.
    fn nuget(&self, feed: &str, id: &str, version: &str, bytes: Vec<u8>, published: &str) {
        self.package(
            feed,
            Package {
                id: id.into(),
                version: version.into(),
                bytes,
                published: published.into(),
                listed: true,
                hash_listed: true,
            },
        );
    }

    fn package(&self, feed: &str, package: Package) {
        self.with(|s| {
            let list = s.feeds.entry(feed.into()).or_default();
            list.retain(|p| !(p.id == package.id && p.version == package.version));
            list.push(package);
        });
    }

    fn downloads(&self, feed: &str, id: &str, version: &str) -> usize {
        self.with(|s| {
            s.downloads
                .get(&format!("{feed}/{}/{version}", id.to_lowercase()))
                .copied()
                .unwrap_or(0)
        })
    }

    fn blob(&self, registry: &str, image: &str, bytes: &[u8]) {
        self.with(|s| {
            s.registries
                .entry(registry.into())
                .or_default()
                .blobs
                .entry(image.into())
                .or_default()
                .insert(digest(bytes), bytes.to_vec());
        });
    }

    /// A manifest pushed by digest.
    fn manifest(&self, registry: &str, image: &str, media_type: &str, bytes: &[u8]) {
        self.with(|s| {
            s.registries
                .entry(registry.into())
                .or_default()
                .manifests
                .entry(image.into())
                .or_default()
                .insert(digest(bytes), (media_type.into(), bytes.to_vec()));
        });
    }

    /// A manifest pushed by tag.
    fn tag(&self, registry: &str, image: &str, tag: &str, media_type: &str, bytes: &[u8]) {
        self.manifest(registry, image, media_type, bytes);
        self.with(|s| {
            s.registries
                .entry(registry.into())
                .or_default()
                .tags
                .entry(image.into())
                .or_default()
                .insert(tag.into(), digest(bytes));
        });
    }
}

/// `items` after `last`, at most `n` (and the page size), and whether more
/// follow.
fn page_after<'a>(
    items: impl Iterator<Item = &'a String>,
    query: &HashMap<String, String>,
    page_size: usize,
) -> (Vec<String>, bool) {
    let n = query
        .get("n")
        .and_then(|n| n.parse().ok())
        .unwrap_or(usize::MAX)
        .min(page_size);
    let mut after: Vec<String> = items
        .filter(|item| {
            query
                .get("last")
                .is_none_or(|last| item.as_str() > last.as_str())
        })
        .cloned()
        .collect();
    after.sort();
    let more = after.len() > n;
    after.truncate(n);
    (after, more)
}

/// The `Link` to the page after `listed` of a listing at `path`.
fn next_link(path: &str, listed: &[String], more: bool, n: usize) -> Option<HeaderValue> {
    let last = listed.last().filter(|_| more)?;
    let last: String = url::form_urlencoded::byte_serialize(last.as_bytes()).collect();
    HeaderValue::from_str(&format!("<{path}?n={n}&last={last}>; rel=\"next\"")).ok()
}

fn json_response(body: Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn serve(
    State((state, base)): State<(Arc<Mutex<SourceState>>, String)>,
    req: Request,
) -> Response {
    let mut response = answer(&state, &base, req).await;
    response
        .headers_mut()
        .insert(header::SERVER, HeaderValue::from_static(SERVER));
    response
}

async fn answer(state: &Mutex<SourceState>, base: &str, req: Request) -> Response {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASSWORD}"))
    );
    if req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(expected.as_str())
    {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"Source\"")],
        )
            .into_response();
    }
    let path = req.uri().path().to_string();
    let query: HashMap<String, String> =
        url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let Some(rest) = path.strip_prefix("/repository/") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (repo, inner) = rest.split_once('/').unwrap_or((rest, ""));
    if let Some(api) = inner.strip_prefix("v2/") {
        return registry(state, repo, api, &query);
    }
    let feed_base = format!("{base}/repository/{repo}");
    let delay = state.lock().unwrap().delay;
    if inner.ends_with(".nupkg") {
        tokio::time::sleep(delay).await;
    }
    let mut s = state.lock().unwrap();
    let Some(packages) = s.feeds.get(repo).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let lower_ids: Vec<String> = {
        let mut ids: Vec<String> = Vec::new();
        for p in &packages {
            if !ids.iter().any(|id| id.eq_ignore_ascii_case(&p.id)) {
                ids.push(p.id.clone());
            }
        }
        ids
    };
    match inner {
        "index.json" => {
            let mut resources = vec![
                json!({"@id": format!("{feed_base}/flat/"), "@type": "PackageBaseAddress/3.0.0"}),
                json!({"@id": format!("{feed_base}/registration/"), "@type": "RegistrationsBaseUrl/3.6.0"}),
            ];
            if !s.no_search.contains(repo) {
                resources.push(
                    json!({"@id": format!("{feed_base}/query"), "@type": "SearchQueryService/3.5.0"}),
                );
            }
            json_response(json!({"version": "3.0.0", "resources": resources}))
        }
        "query" if !s.no_search.contains(repo) => {
            // A search finds a package by its listed versions.
            let found: Vec<&String> = lower_ids
                .iter()
                .filter(|id| {
                    packages
                        .iter()
                        .any(|p| p.listed && p.id.eq_ignore_ascii_case(id))
                })
                .collect();
            let skip: usize = query.get("skip").and_then(|v| v.parse().ok()).unwrap_or(0);
            let take: usize = query.get("take").and_then(|v| v.parse().ok()).unwrap_or(20);
            let data: Vec<Value> = found
                .iter()
                .skip(skip)
                .take(take.min(s.page_size))
                .map(|id| {
                    let versions: Vec<Value> = packages
                        .iter()
                        .filter(|p| p.listed && p.id.eq_ignore_ascii_case(id))
                        .map(|p| json!({"version": p.version}))
                        .collect();
                    json!({"id": id, "version": versions.last().unwrap()["version"], "versions": versions})
                })
                .collect();
            let total = if s.page_totals {
                data.len()
            } else {
                found.len()
            };
            json_response(json!({"totalHits": total, "data": data}))
        }
        _ => {
            let parts: Vec<&str> = inner.split('/').collect();
            let of = |lower: &str| -> Vec<&Package> {
                packages
                    .iter()
                    .filter(|p| p.id.to_lowercase() == lower)
                    .collect()
            };
            match parts.as_slice() {
                ["flat", lower, "index.json"] => {
                    let versions: Vec<String> =
                        of(lower).iter().map(|p| p.version.to_lowercase()).collect();
                    if versions.is_empty() {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    json_response(json!({"versions": versions}))
                }
                ["flat", lower, version, file] if *file == format!("{lower}.{version}.nupkg") => {
                    let Some(package) = of(lower)
                        .into_iter()
                        .find(|p| p.version.eq_ignore_ascii_case(version))
                    else {
                        return StatusCode::NOT_FOUND.into_response();
                    };
                    let key = format!("{repo}/{lower}/{version}");
                    *s.downloads.entry(key.clone()).or_default() += 1;
                    s.corrupt
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| package.bytes.clone())
                        .into_response()
                }
                ["registration", lower, "index.json"] => {
                    let leaves: Vec<Value> = of(lower)
                        .iter()
                        .map(|p| {
                            let mut entry = json!({
                                "id": p.id, "version": p.version,
                                "published": p.published, "listed": p.listed,
                            });
                            if p.hash_listed {
                                entry["packageHash"] = json!(sha512_base64(&p.bytes));
                                entry["packageHashAlgorithm"] = json!("SHA512");
                            }
                            json!({"catalogEntry": entry})
                        })
                        .collect();
                    if leaves.is_empty() {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    json_response(
                        json!({"count": 1, "items": [{"count": leaves.len(), "items": leaves}]}),
                    )
                }
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }
}

/// The registry API of `repo`, at `/repository/<repo>/v2/<api>`.
fn registry(
    state: &Mutex<SourceState>,
    repo: &str,
    api: &str,
    query: &HashMap<String, String>,
) -> Response {
    let s = state.lock().unwrap();
    let Some(images) = s.registries.get(repo) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let prefix = format!("/repository/{repo}/v2");
    if api.is_empty() {
        return json_response(json!({}));
    }
    if api == "_catalog" {
        if s.no_catalog.contains(repo) {
            return StatusCode::NOT_FOUND.into_response();
        }
        let names: Vec<String> = images
            .manifests
            .keys()
            .filter(|image| images.tags.contains_key(*image))
            .cloned()
            .collect();
        let (listed, more) = page_after(names.iter(), query, s.page_size);
        let mut response = json_response(json!({"repositories": listed}));
        if let Some(link) = next_link(&format!("{prefix}/_catalog"), &listed, more, s.page_size) {
            response.headers_mut().insert(header::LINK, link);
        }
        return response;
    }
    if let Some(image) = api.strip_suffix("/tags/list") {
        let Some(tags) = images.tags.get(image) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let (listed, more) = page_after(tags.keys(), query, s.page_size);
        let mut response = json_response(json!({"name": image, "tags": listed}));
        if let Some(link) = next_link(
            &format!("{prefix}/{image}/tags/list"),
            &listed,
            more,
            s.page_size,
        ) {
            response.headers_mut().insert(header::LINK, link);
        }
        return response;
    }
    if let Some((image, subject)) = api.split_once("/referrers/") {
        if s.no_referrers.contains(repo) {
            return StatusCode::NOT_FOUND.into_response();
        }
        let manifests: Vec<Value> = images
            .manifests
            .get(image)
            .into_iter()
            .flatten()
            .filter_map(|(d, (media_type, bytes))| {
                let parsed: Value = serde_json::from_slice(bytes).ok()?;
                (parsed["subject"]["digest"] == subject).then(|| {
                    json!({
                        "mediaType": media_type, "digest": d, "size": bytes.len(),
                        "artifactType": parsed.get("artifactType").cloned().unwrap_or(json!(OCI_EMPTY)),
                    })
                })
            })
            .collect();
        return (
            [(header::CONTENT_TYPE, OCI_INDEX)],
            json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests}).to_string(),
        )
            .into_response();
    }
    if let Some((image, reference)) = api.split_once("/manifests/") {
        let d = images
            .tags
            .get(image)
            .and_then(|tags| tags.get(reference))
            .cloned()
            .unwrap_or_else(|| reference.to_string());
        return match images.manifests.get(image).and_then(|m| m.get(&d)) {
            Some((media_type, bytes)) => (
                [
                    (header::CONTENT_TYPE, media_type.clone()),
                    (
                        header::HeaderName::from_static("docker-content-digest"),
                        d.clone(),
                    ),
                ],
                bytes.clone(),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    if let Some((image, d)) = api.split_once("/blobs/") {
        return match images.blobs.get(image).and_then(|b| b.get(d)) {
            Some(bytes) => bytes.clone().into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    StatusCode::NOT_FOUND.into_response()
}

// ── Forge helpers ───────────────────────────────────────────────────────────

/// A server over a database of its own, so no other test's worker runs its
/// imports.
async fn forge() -> TestServer {
    common::start_with(
        common::fresh_pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            ..Default::default()
        },
    )
    .await
}

async fn admin(
    srv: &TestServer,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    let mut req = srv
        .client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(u, Some(p));
    if let Some(body) = body {
        req = req.json(&body);
    }
    req.send().await.unwrap()
}

async fn create_repo(srv: &TestServer, body: Value) {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        "/admin/repositories",
        Some(body),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
}

/// Start an import into `repo`; returns its id.
async fn start(srv: &TestServer, repo: &str, body: Value) -> i64 {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports"),
        Some(body),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["state"], "queued");
    view["id"].as_i64().unwrap()
}

/// An import of the feed or registry at `url`, with the credentials.
fn from(url: String) -> Value {
    json!({
        "url": url,
        "username": USER,
        "password": PASSWORD,
    })
}

async fn get_import(srv: &TestServer, repo: &str, id: i64) -> Value {
    admin(
        srv,
        reqwest::Method::GET,
        &format!("/admin/repositories/{repo}/imports/{id}"),
        None,
    )
    .await
    .json()
    .await
    .unwrap()
}

/// Run the worker until the import has ended.
async fn run(srv: &TestServer, repo: &str, id: i64) -> Value {
    for _ in 0..200 {
        ImportWorker::new(srv.state.clone()).tick().await.unwrap();
        let view = get_import(srv, repo, id).await;
        if !matches!(view["state"].as_str(), Some("queued" | "running")) {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("import {id} did not end");
}

async fn items(srv: &TestServer, repo: &str, id: i64, state: Option<&str>) -> Vec<Value> {
    let mut path = format!("/admin/repositories/{repo}/imports/{id}/items");
    if let Some(state) = state {
        path.push_str(&format!("?state={state}"));
    }
    admin(srv, reqwest::Method::GET, &path, None)
        .await
        .json()
        .await
        .unwrap()
}

async fn nupkg(srv: &TestServer, repo: &str, id: &str, version: &str) -> Option<Vec<u8>> {
    let (u, p) = srv.admin_basic();
    let lower = id.to_lowercase();
    let resp = srv
        .client()
        .get(format!(
            "{}/repository/{repo}/flat/{lower}/{version}/{lower}.{version}.nupkg",
            srv.base_url
        ))
        .basic_auth(u, Some(p))
        .send()
        .await
        .unwrap();
    (resp.status() == 200).then_some(resp.bytes().await.unwrap().to_vec())
}

/// `(created_at, last_downloaded_at)` of a version Forge holds.
async fn times(
    srv: &TestServer,
    repo: &str,
    lower: &str,
    version: &str,
) -> (DateTime<Utc>, Option<DateTime<Utc>>) {
    let row = sqlx::query!(
        r#"
        SELECT c.created_at, c.last_downloaded_at
        FROM component c JOIN repository r ON r.id = c.repository_id
        WHERE r.name = $1 AND c.name = $2 AND c.version = $3
        "#,
        repo,
        lower,
        version
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    (row.created_at, row.last_downloaded_at)
}

fn repo_name(prefix: &str) -> String {
    format!("{prefix}{}", common::unique())
}

// ── NuGet ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn nuget_import_keeps_bytes_and_dates_and_a_second_run_copies_only_what_is_new() {
    let srv = forge().await;
    let source = Source::start().await;
    let core = make_nupkg("Acme.Core", "1.0.0");
    source.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        core.clone(),
        "2021-03-04T05:06:07.000+00:00",
    );
    source.nuget(
        "nuget-hosted",
        "Acme.Web",
        "2.0.0",
        make_nupkg("Acme.Web", "2.0.0"),
        "2022-01-01T00:00:00.000+00:00",
    );
    // An unlisted version, with nuget.org's placeholder date.
    source.package(
        "nuget-hosted",
        Package {
            id: "Acme.Web".into(),
            version: "1.0.0-beta".into(),
            bytes: make_nupkg("Acme.Web", "1.0.0-beta"),
            published: "1900-01-01T00:00:00+00:00".into(),
            listed: false,
            hash_listed: true,
        },
    );
    // A feed that lists no checksum (Nexus).
    source.package(
        "nuget-hosted",
        Package {
            id: "Acme.Old".into(),
            version: "0.1.0".into(),
            bytes: make_nupkg("Acme.Old", "0.1.0"),
            published: "2019-05-06T07:08:09.000+00:00".into(),
            listed: true,
            hash_listed: false,
        },
    );

    let repo = repo_name("nuget-import");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let started = Utc::now();
    let id = start(&srv, &repo, from(source.feed_url("nuget-hosted"))).await;
    let queued = get_import(&srv, &repo, id).await;
    assert_eq!(queued["url"], source.feed_url("nuget-hosted"));
    assert_eq!(queued["source_server"], SERVER);
    // The search finds the three packages with a listed version.
    assert_eq!(queued["source_total"], 3);
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 4, "{done}");
    assert_eq!(done["progress"]["found"], 4);
    // The password is gone once the import completed.
    assert_eq!(done["has_password"], false);
    let sealed = sqlx::query_scalar!(
        "SELECT password_enc FROM repository_import WHERE id = $1",
        id
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert!(sealed.is_none());

    // Bytes and dates: the publish time is the feed's; a version without one
    // (the placeholder) is created now; each counts as downloaded at its
    // import, which the feed cannot say.
    assert_eq!(
        nupkg(&srv, &repo, "Acme.Core", "1.0.0").await.unwrap(),
        core
    );
    let (created, downloaded) = times(&srv, &repo, "acme.core", "1.0.0").await;
    assert_eq!(created.to_rfc3339(), "2021-03-04T05:06:07+00:00");
    assert!(downloaded.unwrap() >= started);
    let (created, downloaded) = times(&srv, &repo, "acme.web", "1.0.0-beta").await;
    assert!(created >= started, "{created}");
    assert!(downloaded.unwrap() >= started);
    let listed = items(&srv, &repo, id, None).await;
    let core_item = listed.iter().find(|i| i["name"] == "Acme.Core").unwrap();
    assert_eq!(core_item["published_at"], "2021-03-04T05:06:07Z");
    let beta = listed
        .iter()
        .find(|i| i["version"] == "1.0.0-beta")
        .unwrap();
    assert_eq!(beta["published_at"], Value::Null);

    // Run it again, in the request form of a Nexus server and repository,
    // after a new version appeared: only that one is copied, and nothing is
    // downloaded for what the feed lists a SHA-512 of.
    source.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.1.0",
        make_nupkg("Acme.Core", "1.1.0"),
        "2025-01-01T00:00:00.000+00:00",
    );
    let mut legacy = from(source.url.clone());
    legacy["repository"] = json!("nuget-hosted");
    let again = start(&srv, &repo, legacy).await;
    let done = run(&srv, &repo, again).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["url"], source.feed_url("nuget-hosted"));
    assert_eq!(done["progress"]["imported"], 1, "{done}");
    assert_eq!(done["progress"]["identical"], 4);
    assert!(nupkg(&srv, &repo, "Acme.Core", "1.1.0").await.is_some());
    assert_eq!(source.downloads("nuget-hosted", "Acme.Core", "1.0.0"), 1);
    assert_eq!(
        source.downloads("nuget-hosted", "Acme.Web", "1.0.0-beta"),
        1
    );
    assert_eq!(source.downloads("nuget-hosted", "Acme.Old", "0.1.0"), 2);
}

#[tokio::test]
async fn retention_keeps_what_was_just_imported() {
    let srv = forge().await;
    let source = Source::start().await;
    for version in ["1.0.0", "2.0.0"] {
        source.nuget(
            "nuget-hosted",
            "Acme.Core",
            version,
            make_nupkg("Acme.Core", version),
            "2019-01-01T00:00:00.000+00:00",
        );
    }
    let repo = repo_name("nuget-retained");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = start(&srv, &repo, from(source.feed_url("nuget-hosted"))).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["progress"]["imported"], 2, "{done}");

    // Published years ago and never downloaded from Forge: without the
    // import counting as a download, 1.0.0 would go at once.
    let policy = json!({
        "version": 1, "enabled": true, "dry_run_only": false,
        "rules": [{
            "id": "stale", "action": "hard_delete", "release_type": "any",
            "criteria": {"keep_last_n": 1, "not_downloaded_for_days": 30}
        }]
    });
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{repo}/retention"),
        Some(json!({"policy": policy})),
    )
    .await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let preview: Value = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/retention/preview"),
        Some(json!({})),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(preview["counts"]["evaluated"], 2, "{preview}");
    assert_eq!(preview["counts"]["deleted"], 0, "{preview}");
}

#[tokio::test]
async fn a_killed_import_resumes_without_duplicating_anything() {
    let srv = forge().await;
    let source = Source::start().await;
    for i in 0..6 {
        let id = format!("Acme.Part{i}");
        source.nuget(
            "nuget-hosted",
            &id,
            "1.0.0",
            make_nupkg(&id, "1.0.0"),
            "2021-01-01T00:00:00.000+00:00",
        );
    }
    source.with(|s| {
        s.page_size = 1;
        s.page_totals = true;
        s.delay = Duration::from_millis(300);
    });
    let repo = repo_name("nuget-resume");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let mut body = from(source.feed_url("nuget-hosted"));
    body["concurrency"] = json!(1);
    let id = start(&srv, &repo, body).await;

    // Kill the worker once a couple of packages are in.
    let worker = {
        let state = srv.state.clone();
        tokio::spawn(async move { ImportWorker::new(state).tick().await })
    };
    for _ in 0..200 {
        if get_import(&srv, &repo, id).await["progress"]["imported"].as_i64() >= Some(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    worker.abort();
    let _ = worker.await;
    let killed = get_import(&srv, &repo, id).await;
    assert_eq!(killed["state"], "running");
    assert!(killed["progress"]["pending"].as_i64() > Some(0), "{killed}");

    // Its lease expires; the next worker takes over where it stopped.
    sqlx::query!(
        "UPDATE repository_import SET locked_until = now() - interval '1 second' WHERE id = $1",
        id
    )
    .execute(&srv.pool)
    .await
    .unwrap();
    source.with(|s| s.delay = Duration::ZERO);
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["found"], 6);
    // The search reported one package a page; the walk counted them all.
    assert_eq!(done["source_total"], 6);
    assert_eq!(
        done["progress"]["imported"].as_i64().unwrap()
            + done["progress"]["identical"].as_i64().unwrap(),
        6
    );
    let versions = sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM component c JOIN repository r ON r.id = c.repository_id WHERE r.name = $1"#,
        repo
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(versions, 6);
    // Every package blob is referenced once.
    let shared = sqlx::query_scalar!(
        r#"
        SELECT count(*) AS "n!" FROM blob b
        WHERE b.ref_count <> (SELECT count(*) FROM asset a WHERE a.blob_sha256 = b.sha256)
          AND EXISTS (SELECT 1 FROM asset a JOIN component c ON c.id = a.component_id
                      JOIN repository r ON r.id = c.repository_id
                      WHERE a.blob_sha256 = b.sha256 AND r.name = $1)
        "#,
        repo
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(shared, 0);
}

#[tokio::test]
async fn conflict_policies_and_the_dry_run() {
    let srv = forge().await;
    let source = Source::start().await;
    // The feed and Forge hold different bytes for Acme.Core 1.0.0.
    let theirs = make_nupkg_with_payload("Acme.Core", "1.0.0", 64);
    source.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        theirs.clone(),
        "2021-01-01T00:00:00.000+00:00",
    );
    source.nuget(
        "nuget-hosted",
        "Acme.Same",
        "1.0.0",
        make_nupkg("Acme.Same", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    source.nuget(
        "nuget-hosted",
        "Acme.New",
        "1.0.0",
        make_nupkg("Acme.New", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );

    let repo = repo_name("nuget-conflict");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let ours = make_nupkg("Acme.Core", "1.0.0");
    let token = srv.admin_token().await;
    for pkg in [ours.clone(), make_nupkg("Acme.Same", "1.0.0")] {
        let resp = srv
            .client()
            .put(format!("{}/repository/{repo}/package", srv.base_url))
            .header("X-NuGet-ApiKey", &token)
            .multipart(reqwest::multipart::Form::new().part(
                "package",
                reqwest::multipart::Part::bytes(pkg).file_name("p.nupkg"),
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
    }

    // Dry run: counted and decided from the feed's SHA-512s, nothing written,
    // nothing downloaded.
    let mut body = from(source.feed_url("nuget-hosted"));
    body["dry_run"] = json!(true);
    let id = start(&srv, &repo, body).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    let p = &done["progress"];
    assert_eq!(
        (
            p["planned"].as_i64(),
            p["identical"].as_i64(),
            p["conflict"].as_i64()
        ),
        (Some(1), Some(1), Some(1)),
        "{p}"
    );
    assert_eq!(p["bytes_copied"], 0);
    assert!(source.with(|s| s.downloads.is_empty()));
    assert!(nupkg(&srv, &repo, "Acme.New", "1.0.0").await.is_none());
    let conflicts = items(&srv, &repo, id, Some("conflict")).await;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["name"], "Acme.Core");

    // skip: reported, Forge keeps its bytes.
    let id = start(&srv, &repo, from(source.feed_url("nuget-hosted"))).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["progress"]["conflict"], 1);
    assert_eq!(done["progress"]["imported"], 1);
    assert_eq!(
        nupkg(&srv, &repo, "Acme.Core", "1.0.0").await.unwrap(),
        ours
    );

    // fail: the import fails on the conflict, and says which.
    let mut body = from(source.feed_url("nuget-hosted"));
    body["on_conflict"] = json!("fail");
    let id = start(&srv, &repo, body).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "failed");
    assert!(
        done["last_error"]
            .as_str()
            .unwrap()
            .contains("Acme.Core 1.0.0"),
        "{done}"
    );
    assert_eq!(
        done["has_password"], true,
        "a failed import keeps its password"
    );

    // overwrite: the feed's bytes replace Forge's, though the repository
    // refuses redeploys.
    let mut body = from(source.feed_url("nuget-hosted"));
    body["on_conflict"] = json!("overwrite");
    let id = start(&srv, &repo, body).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["replaced"], 1);
    assert_eq!(
        nupkg(&srv, &repo, "Acme.Core", "1.0.0").await.unwrap(),
        theirs
    );
}

#[tokio::test]
async fn a_failed_item_is_retried_on_its_own() {
    let srv = forge().await;
    let source = Source::start().await;
    source.nuget(
        "nuget-hosted",
        "Acme.Good",
        "1.0.0",
        make_nupkg("Acme.Good", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    let bad = make_nupkg("Acme.Bad", "1.0.0");
    source.nuget(
        "nuget-hosted",
        "Acme.Bad",
        "1.0.0",
        bad.clone(),
        "2021-01-01T00:00:00.000+00:00",
    );
    let mut corrupt = bad.clone();
    corrupt[10] ^= 0xff;
    source.with(|s| {
        s.corrupt
            .insert("nuget-hosted/acme.bad/1.0.0".into(), corrupt)
    });

    let repo = repo_name("nuget-retry");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = start(&srv, &repo, from(source.feed_url("nuget-hosted"))).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["progress"]["failed"], 1);
    let failed = items(&srv, &repo, id, Some("failed")).await;
    assert!(
        failed[0]["detail"]
            .as_str()
            .unwrap()
            .contains("does not match the SHA-512 the feed lists"),
        "{failed:?}"
    );
    assert!(nupkg(&srv, &repo, "Acme.Bad", "1.0.0").await.is_none());

    // The completed import no longer holds the password.
    source.with(|s| s.corrupt.clear());
    let resume_path = format!("/admin/repositories/{repo}/imports/{id}/resume");
    let resume = |body: Value| admin(&srv, reqwest::Method::POST, &resume_path, Some(body));
    assert_eq!(resume(json!({"retry_failed": true})).await.status(), 400);
    assert_eq!(resume(json!({})).await.status(), 400, "nothing to resume");
    let resp = resume(json!({"retry_failed": true, "password": PASSWORD})).await;
    assert_eq!(resp.status(), 200);
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(
        (
            done["progress"]["failed"].as_i64(),
            done["progress"]["imported"].as_i64()
        ),
        (Some(0), Some(2))
    );
    assert_eq!(nupkg(&srv, &repo, "Acme.Bad", "1.0.0").await.unwrap(), bad);
    let retried = items(&srv, &repo, id, Some("imported")).await;
    assert_eq!(
        retried.iter().find(|i| i["name"] == "Acme.Bad").unwrap()["attempts"],
        2
    );
}

#[tokio::test]
async fn cancel_resume_delete_and_one_import_at_a_time() {
    let srv = forge().await;
    let source = Source::start().await;
    source.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        make_nupkg("Acme.Core", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    let repo = repo_name("nuget-cancel");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = start(&srv, &repo, from(source.feed_url("nuget-hosted"))).await;

    let second = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports"),
        Some(from(source.feed_url("nuget-hosted"))),
    )
    .await;
    assert_eq!(second.status(), 409);
    let busy = admin(
        &srv,
        reqwest::Method::DELETE,
        &format!("/admin/repositories/{repo}/imports/{id}"),
        None,
    )
    .await;
    assert_eq!(busy.status(), 409);

    let cancelled = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports/{id}/cancel"),
        None,
    )
    .await;
    assert_eq!(cancelled.status(), 200);
    let view: Value = cancelled.json().await.unwrap();
    assert_eq!(view["state"], "cancelled");
    assert_eq!(view["has_password"], true);
    assert!(ImportWorker::new(srv.state.clone())
        .tick()
        .await
        .unwrap()
        .is_none());

    let resumed = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports/{id}/resume"),
        None,
    )
    .await;
    assert_eq!(resumed.status(), 200);
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["progress"]["imported"], 1);

    let deleted = admin(
        &srv,
        reqwest::Method::DELETE,
        &format!("/admin/repositories/{repo}/imports/{id}"),
        None,
    )
    .await;
    assert_eq!(deleted.status(), 204);
    let gone = admin(
        &srv,
        reqwest::Method::GET,
        &format!("/admin/repositories/{repo}/imports/{id}"),
        None,
    )
    .await;
    assert_eq!(gone.status(), 404);
}

#[tokio::test]
async fn the_preflight_refuses_what_cannot_be_imported() {
    let srv = forge().await;
    let source = Source::start().await;
    source.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        make_nupkg("Acme.Core", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    source.nuget(
        "nuget-nosearch",
        "Acme.Core",
        "1.0.0",
        make_nupkg("Acme.Core", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    source.with(|s| s.no_search.insert("nuget-nosearch".into()));
    source.tag("docker-hosted", "app", "1.0", OCI_MANIFEST, b"{}");
    source.with(|s| s.no_catalog.insert("docker-hosted".into()));
    let repo = repo_name("nuget-preflight");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let proxy = repo_name("nuget-proxy");
    create_repo(&srv, json!({"name": proxy, "kind": "proxy", "remote_url": "https://api.nuget.org/v3/index.json"})).await;
    let images = repo_name("docker-preflight");
    create_repo(
        &srv,
        json!({"name": images, "kind": "hosted", "format": "docker"}),
    )
    .await;

    let attempt = |target: String, body: Value| {
        let srv = &srv;
        async move {
            let resp = admin(
                srv,
                reqwest::Method::POST,
                &format!("/admin/repositories/{target}/imports"),
                Some(body),
            )
            .await;
            (resp.status().as_u16(), resp.text().await.unwrap())
        }
    };
    let mut wrong = from(source.feed_url("nuget-hosted"));
    wrong["password"] = json!("wrong");
    let (status, text) = attempt(repo.clone(), wrong).await;
    assert_eq!(status, 400);
    assert!(text.contains("refused the credentials"), "{text}");
    let (status, text) = attempt(repo.clone(), from(source.feed_url("nope"))).await;
    assert_eq!(status, 400);
    assert!(text.contains("404"), "{text}");
    let (status, _) = attempt(
        repo.clone(),
        json!({"url": "http://127.0.0.1:1/index.json"}),
    )
    .await;
    assert_eq!(status, 502);
    let (status, text) = attempt(repo.clone(), from(source.feed_url("nuget-nosearch"))).await;
    assert_eq!(status, 400);
    assert!(text.contains("offers no search"), "{text}");
    let mut invalid = from(source.feed_url("nuget-hosted"));
    invalid["names"] = json!(["Acme.Core", "../admin"]);
    let (status, text) = attempt(repo.clone(), invalid).await;
    assert_eq!(status, 400);
    assert!(text.contains("../admin"), "{text}");
    let (status, text) = attempt(images.clone(), from(source.registry_url("docker-hosted"))).await;
    assert_eq!(status, 400);
    assert!(text.contains("serves no catalog"), "{text}");
    let (status, _) = attempt(proxy, from(source.feed_url("nuget-hosted"))).await;
    assert_eq!(status, 400);
    let mut stray = from(source.url.clone());
    stray["repository"] = json!("nuget-hosted");
    stray["registry_url"] = json!("http://nexus:8082");
    let (status, _) = attempt(repo.clone(), stray).await;
    assert_eq!(status, 400, "registry_url is for Docker only");
    let mut orphan = from(source.registry_url("docker-hosted"));
    orphan["registry_url"] = json!("http://nexus:8082");
    let (status, _) = attempt(images, orphan).await;
    assert_eq!(status, 400, "registry_url goes with repository");
    let (status, _) = attempt(
        repo,
        json!({"url": source.feed_url("nuget-hosted"), "username": USER}),
    )
    .await;
    assert_eq!(status, 400, "a username without a password");
}

#[tokio::test]
async fn named_packages_and_images_come_from_a_source_without_search_or_catalog() {
    let srv = forge().await;
    let source = Source::start().await;
    for version in ["1.0.0", "1.1.0"] {
        source.nuget(
            "nuget-hosted",
            "Acme.Core",
            version,
            make_nupkg("Acme.Core", version),
            "2021-01-01T00:00:00.000+00:00",
        );
    }
    source.nuget(
        "nuget-hosted",
        "Acme.Other",
        "1.0.0",
        make_nupkg("Acme.Other", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    let cfg = config("amd64");
    let layer = b"the layer".to_vec();
    source.blob("docker-hosted", "team/app", &cfg);
    source.blob("docker-hosted", "team/app", &layer);
    source.tag(
        "docker-hosted",
        "team/app",
        "1.0",
        OCI_MANIFEST,
        &image(&cfg, &layer),
    );
    source.with(|s| {
        s.no_search.insert("nuget-hosted".into());
        s.no_catalog.insert("docker-hosted".into());
    });

    let repo = repo_name("nuget-named");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let mut body = from(source.feed_url("nuget-hosted"));
    body["names"] = json!(["Acme.Core", "Acme.Missing", "acme.core"]);
    let id = start(&srv, &repo, body).await;
    let queued = get_import(&srv, &repo, id).await;
    assert_eq!(queued["names"], json!(["Acme.Core", "Acme.Missing"]));
    assert_eq!(queued["source_total"], Value::Null);
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 2, "{done}");
    let failed = items(&srv, &repo, id, Some("failed")).await;
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["name"], "Acme.Missing");
    assert!(
        failed[0]["detail"].as_str().unwrap().contains("no package"),
        "{failed:?}"
    );
    assert!(nupkg(&srv, &repo, "Acme.Other", "1.0.0").await.is_none());

    let images = repo_name("docker-named");
    create_repo(
        &srv,
        json!({"name": images, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let mut body = from(source.registry_url("docker-hosted"));
    body["names"] = json!(["team/app", "team/gone"]);
    let id = start(&srv, &images, body).await;
    let done = run(&srv, &images, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 1, "{done}");
    assert_eq!(done["progress"]["failed"], 1, "{done}");
}

// ── Docker ──────────────────────────────────────────────────────────────────

fn config(arch: &str) -> Vec<u8> {
    json!({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}})
        .to_string()
        .into_bytes()
}

fn image(config: &[u8], layer: &[u8]) -> Vec<u8> {
    json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": digest(config), "size": config.len()},
        "layers": [{"mediaType": LAYER, "digest": digest(layer), "size": layer.len()}],
    })
    .to_string()
    .into_bytes()
}

/// An artifact (an SBOM) referring to `subject`, its blobs pushed.
fn sbom(source: &Source, registry: &str, name: &str, subject: &Value) -> Vec<u8> {
    let empty = b"{}".to_vec();
    source.blob(registry, name, &empty);
    json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/spdx+json",
        "config": {"mediaType": OCI_EMPTY, "digest": digest(&empty), "size": 2},
        "layers": [{"mediaType": OCI_EMPTY, "digest": digest(&empty), "size": 2}],
        "subject": subject,
    })
    .to_string()
    .into_bytes()
}

/// A two-platform index of `name`, its children pushed by digest; returns
/// the index and its children's descriptors.
fn two_platforms(source: &Source, registry: &str, name: &str) -> (Vec<u8>, Vec<Value>) {
    let mut children = Vec::new();
    for arch in ["amd64", "arm64"] {
        let cfg = config(arch);
        let layer = format!("layer of {name} for {arch}").into_bytes();
        source.blob(registry, name, &cfg);
        source.blob(registry, name, &layer);
        let manifest = image(&cfg, &layer);
        source.manifest(registry, name, OCI_MANIFEST, &manifest);
        children.push(json!({"mediaType": OCI_MANIFEST, "digest": digest(&manifest), "size": manifest.len(), "platform": {"architecture": arch, "os": "linux"}}));
    }
    let index = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": children})
        .to_string()
        .into_bytes();
    (index, children)
}

async fn repository_id(srv: &TestServer, repo: &str) -> i64 {
    forge_db::repository_dao::find_repository_by_name(&srv.pool, repo)
        .await
        .unwrap()
        .unwrap()
        .id
}

#[tokio::test]
async fn docker_import_walks_the_catalog_and_copies_indexes_signatures_and_referrers() {
    let srv = forge().await;
    let source = Source::start().await;
    let name = "team/app";

    let (index, children) = two_platforms(&source, "docker-hosted", name);
    source.tag("docker-hosted", name, "1.0", OCI_INDEX, &index);

    // A cosign signature under its tag (it refers to the index by its tag's
    // name only), and an SBOM pushed by digest, listed by the referrers API.
    let payload = b"signature payload".to_vec();
    source.blob("docker-hosted", name, &payload);
    let empty = b"{}".to_vec();
    source.blob("docker-hosted", name, &empty);
    let signature = json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_EMPTY, "digest": digest(&empty), "size": 2},
        "layers": [{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": digest(&payload), "size": payload.len()}],
    })
    .to_string()
    .into_bytes();
    let sig_tag = format!("sha256-{}.sig", sha256(&index));
    source.tag("docker-hosted", name, &sig_tag, OCI_MANIFEST, &signature);
    let subject = json!({"mediaType": OCI_INDEX, "digest": digest(&index), "size": index.len()});
    let sbom = sbom(&source, "docker-hosted", name, &subject);
    source.manifest("docker-hosted", name, OCI_MANIFEST, &sbom);
    // An untagged image that refers to nothing: not copied.
    let stray_cfg = config("s390x");
    source.blob("docker-hosted", name, &stray_cfg);
    let stray = image(&stray_cfg, &empty);
    source.manifest("docker-hosted", name, OCI_MANIFEST, &stray);
    // More images than a catalog page holds.
    for other in ["team/base", "tools/cli"] {
        let cfg = config("amd64");
        let layer = format!("layer of {other}").into_bytes();
        source.blob("docker-hosted", other, &cfg);
        source.blob("docker-hosted", other, &layer);
        source.tag(
            "docker-hosted",
            other,
            "latest",
            OCI_MANIFEST,
            &image(&cfg, &layer),
        );
    }

    let repo = repo_name("docker-import");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let started = Utc::now();
    let id = start(&srv, &repo, from(source.registry_url("docker-hosted"))).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["source_server"], SERVER);
    // Four tags and the SBOM; the children came with the index and the
    // stray manifest is listed nowhere.
    assert_eq!(done["progress"]["imported"], 5, "{done}");
    assert_eq!(done["progress"]["failed"], 0);

    let repo_id = repository_id(&srv, &repo).await;
    let tagged = forge_db::oci_dao::find_tag(&srv.pool, repo_id, name, "1.0")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tagged.manifest.digest, digest(&index));
    // The registry API says nothing of when a tag was pushed: it is created
    // at its import.
    assert!(tagged.updated_at >= started, "{}", tagged.updated_at);
    assert!(
        tagged.manifest.created_at >= started,
        "{}",
        tagged.manifest.created_at
    );
    for child in &children {
        let d = child["digest"].as_str().unwrap();
        assert!(
            forge_db::oci_dao::find_manifest(&srv.pool, repo_id, name, d)
                .await
                .unwrap()
                .is_some()
        );
    }
    for other in ["team/base", "tools/cli"] {
        assert!(
            forge_db::oci_dao::find_tag(&srv.pool, repo_id, other, "latest")
                .await
                .unwrap()
                .is_some(),
            "{other}"
        );
    }
    let sig = forge_db::oci_dao::find_tag(&srv.pool, repo_id, name, &sig_tag)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sig.manifest.digest, digest(&signature));
    let referrers = forge_db::oci_dao::list_referrers(&srv.pool, repo_id, name, &digest(&index))
        .await
        .unwrap();
    let referrer_digests: Vec<String> = referrers.iter().map(|r| r.digest.clone()).collect();
    assert_eq!(referrer_digests, vec![digest(&sbom)]);
    assert!(
        forge_db::oci_dao::find_manifest(&srv.pool, repo_id, name, &digest(&stray))
            .await
            .unwrap()
            .is_none()
    );

    // Pulled through the registry, the index is byte for byte the source's.
    let token = srv.admin_token().await;
    let (user, _) = srv.admin_basic();
    let bearer: Value = srv
        .client()
        .get(format!("{}/v2/token", srv.base_url))
        .query(&[
            ("service", "test.local"),
            ("scope", &format!("repository:{repo}/{name}:pull")),
        ])
        .basic_auth(user, Some(token))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pulled = srv
        .client()
        .get(format!("{}/v2/{repo}/{name}/manifests/1.0", srv.base_url))
        .bearer_auth(bearer["token"].as_str().unwrap())
        .header("accept", OCI_INDEX)
        .send()
        .await
        .unwrap();
    assert_eq!(pulled.status(), 200);
    assert_eq!(pulled.bytes().await.unwrap().to_vec(), index);

    // A second run finds everything in place.
    let again = start(&srv, &repo, from(source.registry_url("docker-hosted"))).await;
    let done = run(&srv, &repo, again).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["progress"]["imported"], 0, "{done}");
    assert_eq!(done["progress"]["identical"], 5, "{done}");
}

#[tokio::test]
async fn without_the_referrers_api_a_referrer_comes_through_the_tag_schema() {
    let srv = forge().await;
    let source = Source::start().await;
    let name = "team/app";
    let (index, _) = two_platforms(&source, "docker-hosted", name);
    source.tag("docker-hosted", name, "1.0", OCI_INDEX, &index);
    // What an OCI 1.1 client (`oras attach`) pushes to a registry without
    // the referrers API: the referrer by digest, and an index of the
    // subject's referrers under the tag `sha256-<subject>`.
    let subject = json!({"mediaType": OCI_INDEX, "digest": digest(&index), "size": index.len()});
    let sbom = sbom(&source, "docker-hosted", name, &subject);
    source.manifest("docker-hosted", name, OCI_MANIFEST, &sbom);
    let referrers = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [
        {"mediaType": OCI_MANIFEST, "digest": digest(&sbom), "size": sbom.len(), "artifactType": "application/spdx+json"}
    ]})
    .to_string()
    .into_bytes();
    source.tag(
        "docker-hosted",
        name,
        &format!("sha256-{}", sha256(&index)),
        OCI_INDEX,
        &referrers,
    );
    source.with(|s| s.no_referrers.insert("docker-hosted".into()));

    let repo = repo_name("docker-tag-schema");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let id = start(&srv, &repo, from(source.registry_url("docker-hosted"))).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 2, "{done}");
    let repo_id = repository_id(&srv, &repo).await;
    let found = forge_db::oci_dao::list_referrers(&srv.pool, repo_id, name, &digest(&index))
        .await
        .unwrap();
    assert_eq!(
        found.iter().map(|r| r.digest.clone()).collect::<Vec<_>>(),
        vec![digest(&sbom)]
    );
}

// ── Upgrades ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_import_stored_before_the_upgrade_lists_and_resumes() {
    let srv = forge().await;
    let source = Source::start().await;
    for id in ["Acme.Core", "Acme.Web"] {
        source.nuget(
            "nuget-hosted",
            id,
            "1.0.0",
            make_nupkg(id, "1.0.0"),
            "2021-01-01T00:00:00.000+00:00",
        );
    }
    let repo = repo_name("nuget-legacy");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let repo_id = repository_id(&srv, &repo).await;
    let (admin_name, _) = srv.admin_basic();
    let admin_id = sqlx::query_scalar!("SELECT id FROM app_user WHERE username = $1", admin_name)
        .fetch_one(&srv.pool)
        .await
        .unwrap();

    // What the upgrade leaves of an import of a Nexus server and repository
    // that failed while it scanned: its scan starts again, and an item it had
    // found (in the shape the Nexus REST API listed it) is still pending.
    let id = sqlx::query_scalar!(
        r#"
        INSERT INTO repository_import
            (repository_id, url, source_repository, username, on_conflict, concurrency,
             dry_run, state, phase, scan_listing, source_server, created_by, last_error)
        VALUES ($1, $2, 'nuget-hosted', $3, 'skip', 2, false, 'failed', 'scan', 'search',
                'Nexus/3.70.1-02 (OSS)', $4, 'Nexus is unreachable')
        RETURNING id
        "#,
        repo_id,
        source.url,
        USER,
        admin_id
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    sqlx::query!(
        r#"
        INSERT INTO repository_import_item (import_id, kind, name, version, state, source)
        VALUES ($1, 'component', 'Acme.Core', '1.0.0', 'pending', $2)
        "#,
        id,
        json!({"name": "Acme.Core", "version": "1.0.0", "assets": [
            {"path": "Acme.Core/1.0.0", "checksum": {"sha1": "00"}}
        ]})
    )
    .execute(&srv.pool)
    .await
    .unwrap();
    {
        let mut tx = srv.pool.begin().await.unwrap();
        forge_db::secret_dao::set_import_password(
            &mut tx,
            &srv.state.envelope,
            id,
            &forge_crypto::PlaintextSecret::from(PASSWORD.to_string()),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let listed: Vec<Value> = admin(
        &srv,
        reqwest::Method::GET,
        &format!("/admin/repositories/{repo}/imports"),
        None,
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["url"], source.feed_url("nuget-hosted"));
    assert_eq!(listed[0]["source_server"], "Nexus/3.70.1-02 (OSS)");
    assert_eq!(listed[0]["progress"]["pending"], 1);

    let resumed = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports/{id}/resume"),
        None,
    )
    .await;
    assert_eq!(resumed.status(), 200, "{}", resumed.text().await.unwrap());
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["found"], 2);
    assert_eq!(done["progress"]["imported"], 2, "{done}");
    assert!(nupkg(&srv, &repo, "Acme.Core", "1.0.0").await.is_some());
    assert!(nupkg(&srv, &repo, "Acme.Web", "1.0.0").await.is_some());
}

// ── Secret encryption ───────────────────────────────────────────────────────

#[tokio::test]
async fn the_password_is_sealed_at_rest() {
    let srv = forge().await;
    let source = Source::start().await;
    source.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        make_nupkg("Acme.Core", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    let repo = repo_name("nuget-sealed");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = start(&srv, &repo, from(source.feed_url("nuget-hosted"))).await;
    let sealed = sqlx::query_scalar!(
        "SELECT password_enc FROM repository_import WHERE id = $1",
        id
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap()
    .expect("sealed password");
    assert!(!sealed
        .windows(PASSWORD.len())
        .any(|w| w == PASSWORD.as_bytes()));

    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 1);
}
