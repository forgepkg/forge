//! Imports from Nexus (`crates/server/src/nexus_import`), against a mock of
//! the Nexus 3 REST API and registry API that answers like Nexus 3.70 does
//! (its paging, its asset objects with a repeated `blobCreated` key, Basic
//! authentication) and the real worker:
//!
//! * NuGet: bytes are identical, publish and last-download times and the
//!   uploader are kept, the password is deleted once the import completes,
//!   and a second run copies only what is new;
//! * killing the worker mid-import and starting it again resumes without
//!   duplicating anything;
//! * every conflict policy (skip, overwrite, fail) and the dry run;
//! * a failed item is retried on its own (with the password again);
//!   cancelling and resuming; the preflight's refusals;
//! * Docker: a multi-platform index with its children, a cosign signature
//!   tag and an SBOM Nexus holds by digest only, digests kept;
//! * with `[crypto]`, the password is sealed at rest.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use common::{make_nupkg, make_nupkg_with_payload, ServerOpts, TestServer};
use forge_server::nexus_import::ImportWorker;
use serde_json::{json, Value};
use sha2::Digest;

const USER: &str = "migrator";
const PASSWORD: &str = "nexus-secret";

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256(bytes))
}

// ── The mock Nexus ──────────────────────────────────────────────────────────

/// An asset of the mock.
#[derive(Clone)]
struct Asset {
    path: String,
    content_type: String,
    bytes: Vec<u8>,
    created: String,
    modified: String,
    downloaded: Option<String>,
    /// Older Nexus versions list only SHA-1 (and MD5).
    sha1_only: bool,
}

impl Asset {
    fn new(path: &str, content_type: &str, bytes: Vec<u8>, created: &str) -> Self {
        Asset {
            path: path.into(),
            content_type: content_type.into(),
            bytes,
            created: created.into(),
            modified: created.into(),
            downloaded: None,
            sha1_only: false,
        }
    }

    /// The asset object as Nexus 3.70 writes it, `blobCreated` twice.
    fn json(&self, repository: &str) -> String {
        let checksum = if self.sha1_only {
            json!({ "sha1": hex::encode(sha1::Sha1::digest(&self.bytes)) })
        } else {
            json!({
                "sha1": hex::encode(sha1::Sha1::digest(&self.bytes)),
                "sha512": hex::encode(sha2::Sha512::digest(&self.bytes)),
                "sha256": sha256(&self.bytes),
            })
        };
        format!(
            r#"{{"downloadUrl":"http://nexus.public.example/repository/{repository}/{path}","path":{path_json},"id":"x","repository":"{repository}","checksum":{checksum},"contentType":{ct},"lastModified":"{modified}","lastDownloaded":{downloaded},"uploader":"jdoe","uploaderIp":"10.0.0.1","fileSize":{size},"blobCreated":null,"blobCreated":"{created}"}}"#,
            path = self.path,
            path_json = json!(self.path),
            ct = json!(self.content_type),
            modified = self.modified,
            downloaded = self
                .downloaded
                .as_ref()
                .map_or("null".to_string(), |d| format!("\"{d}\"")),
            size = self.bytes.len(),
            created = self.created,
        )
    }
}

#[derive(Default)]
struct NexusState {
    /// `(name, format, type)`.
    repos: Vec<(String, String, String)>,
    /// repository → `(name, version, assets)`, in listing order.
    components: HashMap<String, Vec<(String, String, Vec<Asset>)>>,
    /// repository → assets the asset listing shows besides the components'
    /// (Docker blobs, manifests held by digest).
    loose: HashMap<String, Vec<Asset>>,
    /// `<repo>/<image>/manifests/<reference>` and
    /// `<repo>/<image>/blobs/<digest>` → (content type, bytes).
    registry: HashMap<String, (String, Vec<u8>)>,
    page_size: usize,
    /// `<repo>/<path>` served with these bytes instead.
    corrupt: HashMap<String, Vec<u8>>,
    /// Slows every content download.
    delay: Duration,
}

#[derive(Clone)]
struct Nexus {
    url: String,
    state: Arc<Mutex<NexusState>>,
}

impl Nexus {
    async fn start() -> Self {
        let state = Arc::new(Mutex::new(NexusState {
            page_size: 2,
            ..Default::default()
        }));
        let app = axum::Router::new()
            .fallback(serve)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Nexus {
            url: format!("http://{addr}"),
            state,
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut NexusState) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    fn repo(&self, name: &str, format: &str, kind: &str) {
        self.with(|s| s.repos.push((name.into(), format.into(), kind.into())));
    }

    /// A NuGet package at `<id>/<version>`, as Nexus stores it.
    fn nuget(&self, repo: &str, id: &str, version: &str, bytes: Vec<u8>, created: &str) -> Asset {
        let asset = Asset::new(
            &format!("{id}/{version}"),
            "application/zip",
            bytes,
            created,
        );
        self.component(repo, id, version, asset.clone());
        asset
    }

    fn component(&self, repo: &str, name: &str, version: &str, asset: Asset) {
        self.with(|s| {
            let list = s.components.entry(repo.into()).or_default();
            match list.iter_mut().find(|(n, v, _)| n == name && v == version) {
                Some((_, _, assets)) => *assets = vec![asset],
                None => list.push((name.into(), version.into(), vec![asset])),
            }
        });
    }

    fn blob(&self, repo: &str, image: &str, bytes: &[u8]) {
        let d = digest(bytes);
        self.with(|s| {
            s.registry.insert(
                format!("{repo}/{image}/blobs/{d}"),
                ("application/octet-stream".into(), bytes.to_vec()),
            );
            s.loose.entry(repo.into()).or_default().push(Asset::new(
                &format!("v2/-/blobs/{d}"),
                "application/octet-stream",
                bytes.to_vec(),
                "2022-01-01T00:00:00.000+00:00",
            ));
        });
    }

    /// A manifest pushed by digest (listed by the asset listing only).
    fn manifest_by_digest(&self, repo: &str, image: &str, media_type: &str, bytes: &[u8]) {
        let d = digest(bytes);
        self.with(|s| {
            s.registry.insert(
                format!("{repo}/{image}/manifests/{d}"),
                (media_type.into(), bytes.to_vec()),
            );
            s.loose.entry(repo.into()).or_default().push(Asset::new(
                &format!("v2/{image}/manifests/{d}"),
                media_type,
                bytes.to_vec(),
                "2022-01-01T00:00:00.000+00:00",
            ));
        });
    }

    /// A tag (a component whose asset is the tag's manifest).
    fn tag(
        &self,
        repo: &str,
        image: &str,
        tag: &str,
        media_type: &str,
        bytes: &[u8],
        modified: &str,
    ) {
        self.manifest_by_digest(repo, image, media_type, bytes);
        self.with(|s| {
            s.registry.insert(
                format!("{repo}/{image}/manifests/{tag}"),
                (media_type.into(), bytes.to_vec()),
            );
        });
        let mut asset = Asset::new(
            &format!("v2/{image}/manifests/{tag}"),
            media_type,
            bytes.to_vec(),
            "2022-01-01T00:00:00.000+00:00",
        );
        asset.modified = modified.into();
        self.component(repo, image, tag, asset);
    }
}

fn page(items: Vec<String>, token: Option<&String>, size: usize) -> String {
    let start: usize = token.and_then(|t| t.parse().ok()).unwrap_or(0);
    let end = (start + size).min(items.len());
    let next = if end < items.len() {
        format!("\"{end}\"")
    } else {
        "null".into()
    };
    format!(
        r#"{{"items":[{}],"continuationToken":{next}}}"#,
        items[start.min(end)..end].join(",")
    )
}

async fn serve(State(state): State<Arc<Mutex<NexusState>>>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let query: HashMap<String, String> =
        url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    if path == "/service/rest/v1/status" {
        return ([(header::SERVER, "Nexus/3.70.1-02 (OSS)")], "").into_response();
    }
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
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"Sonatype Nexus Repository Manager\"",
            )],
        )
            .into_response();
    }
    let json_response =
        |body: String| ([(header::CONTENT_TYPE, "application/json")], body).into_response();
    let repository = query.get("repository").cloned().unwrap_or_default();
    match path.as_str() {
        "/service/rest/v1/repositories" => {
            let s = state.lock().unwrap();
            let list: Vec<Value> = s
                .repos
                .iter()
                .map(|(name, format, kind)| json!({"name": name, "format": format, "type": kind, "url": "", "attributes": {}}))
                .collect();
            return json_response(Value::Array(list).to_string());
        }
        "/service/rest/v1/components" => {
            let s = state.lock().unwrap();
            let items: Vec<String> = s
                .components
                .get(&repository)
                .into_iter()
                .flatten()
                .map(|(name, version, assets)| {
                    format!(
                        r#"{{"id":"c","repository":"{repository}","format":"x","group":null,"name":{},"version":{},"assets":[{}]}}"#,
                        json!(name),
                        json!(version),
                        assets.iter().map(|a| a.json(&repository)).collect::<Vec<_>>().join(",")
                    )
                })
                .collect();
            return json_response(page(items, query.get("continuationToken"), s.page_size));
        }
        "/service/rest/v1/assets" => {
            let s = state.lock().unwrap();
            let items: Vec<String> = s
                .components
                .get(&repository)
                .into_iter()
                .flatten()
                .flat_map(|(_, _, assets)| assets.iter())
                .chain(s.loose.get(&repository).into_iter().flatten())
                .map(|a| a.json(&repository))
                .collect();
            return json_response(page(items, query.get("continuationToken"), s.page_size));
        }
        _ => {}
    }
    let Some(rest) = path.strip_prefix("/repository/") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (repo, inner) = rest.split_once('/').unwrap_or((rest, ""));
    let delay = state.lock().unwrap().delay;
    tokio::time::sleep(delay).await;
    let s = state.lock().unwrap();
    if let Some(registry_path) = inner.strip_prefix("v2/") {
        if registry_path.is_empty() {
            return json_response("{}".into());
        }
        return match s.registry.get(&format!("{repo}/{registry_path}")) {
            Some((content_type, bytes)) => (
                [
                    (header::CONTENT_TYPE, content_type.clone()),
                    (
                        header::HeaderName::from_static("docker-content-digest"),
                        digest(bytes),
                    ),
                ],
                bytes.clone(),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let path = percent_decode(inner);
    if let Some(bytes) = s.corrupt.get(&format!("{repo}/{path}")) {
        return bytes.clone().into_response();
    }
    s.components
        .get(repo)
        .into_iter()
        .flatten()
        .flat_map(|(_, _, assets)| assets.iter())
        .find(|a| a.path == path)
        .map(|a| a.bytes.clone().into_response())
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

/// Decode `%XX` escapes of a request path.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (bytes[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Forge helpers ───────────────────────────────────────────────────────────

/// A server over a database of its own, so no other test's worker runs its
/// imports.
async fn forge(crypto_block: Option<String>) -> TestServer {
    common::start_with(
        common::fresh_pool().await,
        ServerOpts {
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            crypto_block,
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

fn source(nexus: &Nexus, repository: &str) -> Value {
    json!({
        "url": nexus.url,
        "repository": repository,
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
            "{}/v3/{repo}/flat/{lower}/{version}/{lower}.{version}.nupkg",
            srv.base_url
        ))
        .basic_auth(u, Some(p))
        .send()
        .await
        .unwrap();
    (resp.status() == 200).then_some(resp.bytes().await.unwrap().to_vec())
}

fn repo_name(prefix: &str) -> String {
    format!("{prefix}{}", common::unique())
}

// ── NuGet ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn nuget_import_keeps_bytes_and_dates_and_a_second_run_copies_only_what_is_new() {
    let srv = forge(None).await;
    let nexus = Nexus::start().await;
    nexus.repo("nuget-hosted", "nuget", "hosted");
    let core = make_nupkg("Acme.Core", "1.0.0");
    let mut asset = nexus.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        core.clone(),
        "2021-03-04T05:06:07.000+00:00",
    );
    asset.downloaded = Some("2024-02-03T04:05:06.000+00:00".into());
    nexus.component("nuget-hosted", "Acme.Core", "1.0.0", asset);
    nexus.nuget(
        "nuget-hosted",
        "Acme.Web",
        "2.0.0",
        make_nupkg("Acme.Web", "2.0.0"),
        "2022-01-01T00:00:00.000+00:00",
    );
    // An older Nexus lists no SHA-256: the download is checked against SHA-1.
    let mut old = Asset::new(
        "Acme.Old/0.1.0",
        "application/zip",
        make_nupkg("Acme.Old", "0.1.0"),
        "2019-05-06T07:08:09.000+00:00",
    );
    old.sha1_only = true;
    nexus.component("nuget-hosted", "Acme.Old", "0.1.0", old);

    let repo = repo_name("nuget-import");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = start(&srv, &repo, source(&nexus, "nuget-hosted")).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 3);
    assert_eq!(done["progress"]["found"], 3);
    assert_eq!(done["progress"]["assets"], 3);
    assert_eq!(done["nexus_version"], "Nexus/3.70.1-02 (OSS)");
    // The password is gone once the import completed.
    assert_eq!(done["has_password"], false);
    let row = sqlx::query!(
        "SELECT password, password_enc FROM nexus_import WHERE id = $1",
        id
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert!(row.password.is_none() && row.password_enc.is_none());

    // Bytes and dates.
    assert_eq!(
        nupkg(&srv, &repo, "Acme.Core", "1.0.0").await.unwrap(),
        core
    );
    let times = sqlx::query!(
        r#"
        SELECT c.created_at, c.last_downloaded_at
        FROM component c JOIN repository r ON r.id = c.repository_id
        WHERE r.name = $1 AND c.name = 'acme.core'
        "#,
        repo
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(times.created_at.to_rfc3339(), "2021-03-04T05:06:07+00:00");
    // (The download above counts too, but it is later.)
    assert!(times.last_downloaded_at.unwrap() > times.created_at);
    let listed = items(&srv, &repo, id, None).await;
    let core_item = listed.iter().find(|i| i["name"] == "Acme.Core").unwrap();
    assert_eq!(core_item["uploader"], "jdoe");
    assert_eq!(core_item["downloaded_at"], "2024-02-03T04:05:06Z");

    // Run it again after a new version appeared in Nexus: only that one is
    // copied, and nothing is downloaded for the rest.
    nexus.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.1.0",
        make_nupkg("Acme.Core", "1.1.0"),
        "2025-01-01T00:00:00.000+00:00",
    );
    let again = start(&srv, &repo, source(&nexus, "nuget-hosted")).await;
    let done = run(&srv, &repo, again).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["progress"]["imported"], 1, "{done}");
    // Acme.Old (SHA-1 only) is downloaded to compare; the other two are not.
    assert_eq!(done["progress"]["identical"], 3);
    assert!(nupkg(&srv, &repo, "Acme.Core", "1.1.0").await.is_some());
}

#[tokio::test]
async fn a_killed_import_resumes_without_duplicating_anything() {
    let srv = forge(None).await;
    let nexus = Nexus::start().await;
    nexus.repo("nuget-hosted", "nuget", "hosted");
    for i in 0..6 {
        let id = format!("Acme.Part{i}");
        nexus.nuget(
            "nuget-hosted",
            &id,
            "1.0.0",
            make_nupkg(&id, "1.0.0"),
            "2021-01-01T00:00:00.000+00:00",
        );
    }
    nexus.with(|s| {
        s.page_size = 1;
        s.delay = Duration::from_millis(300);
    });
    let repo = repo_name("nuget-resume");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let mut body = source(&nexus, "nuget-hosted");
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
        "UPDATE nexus_import SET locked_until = now() - interval '1 second' WHERE id = $1",
        id
    )
    .execute(&srv.pool)
    .await
    .unwrap();
    nexus.with(|s| s.delay = Duration::ZERO);
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["found"], 6);
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
    let srv = forge(None).await;
    let nexus = Nexus::start().await;
    nexus.repo("nuget-hosted", "nuget", "hosted");
    // Nexus and Forge hold different bytes for Acme.Core 1.0.0.
    let theirs = make_nupkg_with_payload("Acme.Core", "1.0.0", 64);
    nexus.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        theirs.clone(),
        "2021-01-01T00:00:00.000+00:00",
    );
    nexus.nuget(
        "nuget-hosted",
        "Acme.Same",
        "1.0.0",
        make_nupkg("Acme.Same", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    nexus.nuget(
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
            .put(format!("{}/v3/{repo}/package", srv.base_url))
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

    // Dry run: counted and decided, nothing written, nothing downloaded.
    let mut body = source(&nexus, "nuget-hosted");
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
    assert_eq!(p["planned_size"], make_nupkg("Acme.New", "1.0.0").len());
    assert_eq!(p["bytes_copied"], 0);
    assert!(nupkg(&srv, &repo, "Acme.New", "1.0.0").await.is_none());
    let conflicts = items(&srv, &repo, id, Some("conflict")).await;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["name"], "Acme.Core");

    // skip: reported, Forge keeps its bytes.
    let id = start(&srv, &repo, source(&nexus, "nuget-hosted")).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["progress"]["conflict"], 1);
    assert_eq!(done["progress"]["imported"], 1);
    assert_eq!(
        nupkg(&srv, &repo, "Acme.Core", "1.0.0").await.unwrap(),
        ours
    );

    // fail: the import fails on the conflict, and says which.
    let mut body = source(&nexus, "nuget-hosted");
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

    // overwrite: Nexus' bytes replace Forge's, though the repository refuses
    // redeploys.
    let mut body = source(&nexus, "nuget-hosted");
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
    let srv = forge(None).await;
    let nexus = Nexus::start().await;
    nexus.repo("nuget-hosted", "nuget", "hosted");
    nexus.nuget(
        "nuget-hosted",
        "Acme.Good",
        "1.0.0",
        make_nupkg("Acme.Good", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    let bad = make_nupkg("Acme.Bad", "1.0.0");
    nexus.nuget(
        "nuget-hosted",
        "Acme.Bad",
        "1.0.0",
        bad.clone(),
        "2021-01-01T00:00:00.000+00:00",
    );
    let mut corrupt = bad.clone();
    corrupt[10] ^= 0xff;
    nexus.with(|s| {
        s.corrupt
            .insert("nuget-hosted/Acme.Bad/1.0.0".into(), corrupt)
    });

    let repo = repo_name("nuget-retry");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = start(&srv, &repo, source(&nexus, "nuget-hosted")).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["progress"]["failed"], 1);
    let failed = items(&srv, &repo, id, Some("failed")).await;
    assert!(
        failed[0]["detail"]
            .as_str()
            .unwrap()
            .contains("does not match its SHA-256"),
        "{failed:?}"
    );
    assert!(nupkg(&srv, &repo, "Acme.Bad", "1.0.0").await.is_none());

    // The completed import no longer holds the password.
    nexus.with(|s| s.corrupt.clear());
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
    let srv = forge(None).await;
    let nexus = Nexus::start().await;
    nexus.repo("nuget-hosted", "nuget", "hosted");
    nexus.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        make_nupkg("Acme.Core", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    let repo = repo_name("nuget-cancel");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = start(&srv, &repo, source(&nexus, "nuget-hosted")).await;

    let second = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports"),
        Some(source(&nexus, "nuget-hosted")),
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
    let srv = forge(None).await;
    let nexus = Nexus::start().await;
    nexus.repo("nuget-hosted", "nuget", "hosted");
    nexus.repo("nuget-proxy", "nuget", "proxy");
    nexus.repo("helm-hosted", "helm", "hosted");
    let repo = repo_name("nuget-preflight");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let proxy = repo_name("nuget-proxy");
    create_repo(&srv, json!({"name": proxy, "kind": "proxy", "remote_url": "https://api.nuget.org/v3/index.json"})).await;

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
    let (status, text) = attempt(repo.clone(), source(&nexus, "nuget-proxy")).await;
    assert_eq!(status, 400);
    assert!(text.contains("proxy repository in Nexus"), "{text}");
    let (status, text) = attempt(repo.clone(), source(&nexus, "helm-hosted")).await;
    assert_eq!(status, 400);
    assert!(text.contains("helm repository in Nexus"), "{text}");
    let (status, text) = attempt(repo.clone(), source(&nexus, "nope")).await;
    assert_eq!(status, 400);
    assert!(text.contains("no repository nope"), "{text}");
    let mut wrong = source(&nexus, "nuget-hosted");
    wrong["password"] = json!("wrong");
    let (status, text) = attempt(repo.clone(), wrong).await;
    assert_eq!(status, 400);
    assert!(text.contains("refused the credentials"), "{text}");
    let (status, _) = attempt(
        repo.clone(),
        json!({"url": "http://127.0.0.1:1", "repository": "nuget-hosted"}),
    )
    .await;
    assert_eq!(status, 502);
    let (status, _) = attempt(proxy, source(&nexus, "nuget-hosted")).await;
    assert_eq!(status, 400);
    let mut stray = source(&nexus, "nuget-hosted");
    stray["registry_url"] = json!("http://nexus:8082");
    let (status, _) = attempt(repo.clone(), stray).await;
    assert_eq!(status, 400, "registry_url is for Docker only");
    let (status, _) = attempt(
        repo,
        json!({"url": nexus.url, "repository": "nuget-hosted", "username": USER}),
    )
    .await;
    assert_eq!(status, 400, "a username without a password");
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

#[tokio::test]
async fn docker_import_copies_indexes_signatures_and_referrers_with_their_digests() {
    let srv = forge(None).await;
    let nexus = Nexus::start().await;
    nexus.repo("docker-hosted", "docker", "hosted");
    let name = "team/app";

    // A two-platform index; its children Nexus holds by digest only.
    let mut children = Vec::new();
    for arch in ["amd64", "arm64"] {
        let cfg = config(arch);
        let layer = format!("layer of {arch}").into_bytes();
        nexus.blob("docker-hosted", name, &cfg);
        nexus.blob("docker-hosted", name, &layer);
        let manifest = image(&cfg, &layer);
        nexus.manifest_by_digest("docker-hosted", name, OCI_MANIFEST, &manifest);
        children.push(json!({"mediaType": OCI_MANIFEST, "digest": digest(&manifest), "size": manifest.len(), "platform": {"architecture": arch, "os": "linux"}}));
    }
    let index = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": children})
        .to_string()
        .into_bytes();
    nexus.tag(
        "docker-hosted",
        name,
        "1.0",
        OCI_INDEX,
        &index,
        "2023-04-05T06:07:08.000+00:00",
    );

    // A cosign signature under its tag, and an SBOM pushed by digest.
    let empty = b"{}".to_vec();
    nexus.blob("docker-hosted", name, &empty);
    let payload = b"signature payload".to_vec();
    nexus.blob("docker-hosted", name, &payload);
    let subject = json!({"mediaType": OCI_INDEX, "digest": digest(&index), "size": index.len()});
    let signature = json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(&empty), "size": 2},
        "layers": [{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": digest(&payload), "size": payload.len()}],
        "subject": subject,
    })
    .to_string()
    .into_bytes();
    let sig_tag = format!("sha256-{}.sig", sha256(&index));
    nexus.tag(
        "docker-hosted",
        name,
        &sig_tag,
        OCI_MANIFEST,
        &signature,
        "2023-04-05T06:08:00.000+00:00",
    );
    let sbom = json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/spdx+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(&empty), "size": 2},
        "layers": [{"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(&empty), "size": 2}],
        "subject": subject,
    })
    .to_string()
    .into_bytes();
    nexus.manifest_by_digest("docker-hosted", name, OCI_MANIFEST, &sbom);
    // An untagged image that refers to nothing: not copied.
    let stray_cfg = config("s390x");
    nexus.blob("docker-hosted", name, &stray_cfg);
    let stray = image(&stray_cfg, &empty);
    nexus.manifest_by_digest("docker-hosted", name, OCI_MANIFEST, &stray);

    let repo = repo_name("docker-import");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let id = start(&srv, &repo, source(&nexus, "docker-hosted")).await;
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    // Two tags and the SBOM; the signature is a tag; the children came with
    // the index and the stray manifest is no referrer.
    assert_eq!(done["progress"]["imported"], 3, "{done}");
    assert_eq!(done["progress"]["failed"], 0);

    let repo_id = forge_db::repository_dao::find_repository_by_name(&srv.pool, &repo)
        .await
        .unwrap()
        .unwrap()
        .id;
    let tagged = forge_db::oci_dao::find_tag(&srv.pool, repo_id, name, "1.0")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tagged.manifest.digest, digest(&index));
    assert_eq!(tagged.updated_at.to_rfc3339(), "2023-04-05T06:07:08+00:00");
    for child in &children {
        let d = child["digest"].as_str().unwrap();
        assert!(
            forge_db::oci_dao::find_manifest(&srv.pool, repo_id, name, d)
                .await
                .unwrap()
                .is_some()
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
    let mut referrer_digests: Vec<String> = referrers.iter().map(|r| r.digest.clone()).collect();
    referrer_digests.sort();
    let mut expected = vec![digest(&signature), digest(&sbom)];
    expected.sort();
    assert_eq!(referrer_digests, expected);
    assert!(
        forge_db::oci_dao::find_manifest(&srv.pool, repo_id, name, &digest(&stray))
            .await
            .unwrap()
            .is_none()
    );
    assert!(items(&srv, &repo, id, None)
        .await
        .iter()
        .all(|i| i["version"] != digest(&stray).as_str()));

    // Pulled through the registry, the index is byte for byte Nexus'.
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
    let again = start(&srv, &repo, source(&nexus, "docker-hosted")).await;
    let done = run(&srv, &repo, again).await;
    assert_eq!(done["state"], "completed");
    assert_eq!(done["progress"]["imported"], 0, "{done}");
    assert_eq!(done["progress"]["bytes_copied"], 0);
}

// ── Secret encryption ───────────────────────────────────────────────────────

#[tokio::test]
async fn with_crypto_the_password_is_sealed_at_rest() {
    const VAR: &str = "FORGE_TEST_NEXUS_IMPORT_ROOT_KEY";
    std::env::set_var(VAR, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    let srv = forge(Some(format!(
        "[crypto]\n[crypto.root]\nprovider = \"env\"\nroot_key_env = \"{VAR}\"\n[crypto.rotation]\nenabled = false\n"
    )))
    .await;
    let nexus = Nexus::start().await;
    nexus.repo("nuget-hosted", "nuget", "hosted");
    nexus.nuget(
        "nuget-hosted",
        "Acme.Core",
        "1.0.0",
        make_nupkg("Acme.Core", "1.0.0"),
        "2021-01-01T00:00:00.000+00:00",
    );
    let repo = repo_name("nuget-sealed");
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = start(&srv, &repo, source(&nexus, "nuget-hosted")).await;
    let row = sqlx::query!(
        "SELECT password, password_enc FROM nexus_import WHERE id = $1",
        id
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert!(row.password.is_none());
    let sealed = row.password_enc.expect("sealed password");
    assert!(!sealed
        .windows(PASSWORD.len())
        .any(|w| w == PASSWORD.as_bytes()));
    assert!(forge_db::secret_dao::sealed_secrets_present(&srv.pool)
        .await
        .unwrap());

    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 1);
}
