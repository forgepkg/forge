//! Imports of raw repositories (`crates/server/src/import/raw.rs`) against a
//! mock source with Basic authentication that serves the three kinds of
//! source an import reads, and the real worker:
//!
//! * Nexus' asset listing (`/service/rest/v1/assets`, paged with
//!   `continuationToken`) of a repository at `/repository/<name>`: bytes,
//!   content types, upload times (`blobCreated`), last downloads
//!   (`lastDownloaded`, else the import's) and uploaders arrive; every path
//!   Forge refuses fails as its own item and the import completes; a file
//!   that does not match its SHA-512 fails; retention does not take what
//!   was just imported for unused; a second run copies only what is new,
//!   and a changed file follows `on_conflict` (skip, overwrite, fail),
//!   decided from the listed SHA-256 without a download; the previous
//!   request form (a Nexus server and repository) is accepted;
//! * another Forge's JSON listing, walked a directory at a time with
//!   `after`: a dry run reports the files, their size and the conflicts and
//!   writes nothing (`overwrite` plans the replacement); a walk stopped in a
//!   directory resumes there;
//! * a plain web server without a listing, through named paths: a file is
//!   checked against its `.sha256` sidecar, where it has one; a named file
//!   the source does not have fails, and is looked for again when retried;
//! * the preflight's refusals.
//!
//! The same flows run against a real Nexus 3, another Forge and nginx in
//! `crates/e2e/tests/raw_import.rs`.

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::{DateTime, Utc};
use common::{ServerOpts, TestServer};
use forge_server::import::ImportWorker;
use serde_json::{json, Value};
use sha2::Digest;

const USER: &str = "migrator";
const PASSWORD: &str = "source-secret";
const NEXUS: &str = "Nexus/3.70.1-02 (OSS)";

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn time(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

// ── The mock source ─────────────────────────────────────────────────────────

/// A file of the source.
#[derive(Clone)]
struct File {
    bytes: Vec<u8>,
    content_type: String,
    /// When it was stored: Nexus' `blobCreated`, a Forge's `last_modified`,
    /// a web server's `Last-Modified`.
    created: DateTime<Utc>,
    downloaded: Option<DateTime<Utc>>,
    uploader: Option<String>,
}

fn file(bytes: &[u8], content_type: &str, created: &str) -> File {
    File {
        bytes: bytes.to_vec(),
        content_type: content_type.into(),
        created: time(created),
        downloaded: None,
        uploader: None,
    }
}

#[derive(Default)]
struct SourceState {
    /// Nexus raw repositories: name → path → file.
    nexus: HashMap<String, BTreeMap<String, File>>,
    /// Forge raw repositories: name → path → file.
    forge: HashMap<String, BTreeMap<String, File>>,
    /// The plain web server's files under `/plain/`, sidecars included.
    plain: BTreeMap<String, File>,
    /// Served instead of the listed bytes, by `<repo>/<path>`.
    corrupt: HashMap<String, Vec<u8>>,
    /// Downloads of a file's bytes, by `<repo>/<path>` (`plain/<path>`).
    downloads: HashMap<String, usize>,
    /// Listing requests, by `<repo>/<dir>`.
    listings: HashMap<String, usize>,
    /// Directories whose listing refuses the credentials, by `<repo>/<dir>`.
    refused_listings: HashSet<String>,
    /// Entries a page of a listing holds at most.
    page_size: usize,
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
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Source { url, state }
    }

    fn with<R>(&self, f: impl FnOnce(&mut SourceState) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    fn repository(&self, name: &str) -> String {
        format!("{}/repository/{name}", self.url)
    }

    fn nexus(&self, repo: &str, path: &str, file: File) {
        self.with(|s| {
            s.nexus
                .entry(repo.into())
                .or_default()
                .insert(path.into(), file)
        });
    }

    fn forge(&self, repo: &str, path: &str, file: File) {
        self.with(|s| {
            s.forge
                .entry(repo.into())
                .or_default()
                .insert(path.into(), file)
        });
    }

    fn plain(&self, path: &str, file: File) {
        self.with(|s| s.plain.insert(path.into(), file));
    }

    fn downloads(&self, key: &str) -> usize {
        self.with(|s| s.downloads.get(key).copied().unwrap_or(0))
    }

    fn listings(&self, key: &str) -> usize {
        self.with(|s| s.listings.get(key).copied().unwrap_or(0))
    }
}

fn json_response(body: Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn decode(path: &str) -> Option<String> {
    percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()
        .map(|p| p.into_owned())
}

/// A time as Nexus writes it (milliseconds).
fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// A time as Forge's listing writes it (as precise as it is).
fn forge_time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

async fn serve(State(state): State<Arc<Mutex<SourceState>>>, req: Request) -> Response {
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
    let get = req.method() == Method::GET;
    let mut s = state.lock().unwrap();
    let page_size = s.page_size;

    if path == "/service/rest/v1/assets" {
        let Some(files) = query.get("repository").and_then(|r| s.nexus.get(r)) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let start: usize = query
            .get("continuationToken")
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        let items: Vec<Value> = files
            .iter()
            .skip(start)
            .take(page_size)
            .map(|(path, f)| {
                json!({
                    "downloadUrl": format!("http://nexus.internal:8081/repository/x/{path}"),
                    "path": path,
                    "format": "raw",
                    "checksum": {
                        "sha1": hex::encode(sha1::Sha1::digest(&f.bytes)),
                        "sha256": sha256(&f.bytes).to_uppercase(),
                        "sha512": hex::encode(sha2::Sha512::digest(&f.bytes)),
                    },
                    "contentType": f.content_type,
                    "lastModified": rfc3339(f.created + chrono::Duration::seconds(1)),
                    "lastDownloaded": f.downloaded.map(rfc3339),
                    "uploader": f.uploader,
                    "fileSize": f.bytes.len(),
                    "blobCreated": rfc3339(f.created),
                })
            })
            .collect();
        let next = (start + page_size < files.len()).then(|| (start + page_size).to_string());
        let mut response = json_response(json!({"items": items, "continuationToken": next}));
        response
            .headers_mut()
            .insert(header::SERVER, HeaderValue::from_static(NEXUS));
        return response;
    }

    let (key, files, nexus) = if let Some(rest) = path.strip_prefix("/repository/") {
        let (repo, inner) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(inner) = decode(inner) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        if inner.is_empty() || inner.ends_with('/') {
            // A Forge lists its directories as JSON; Nexus does not.
            if !s.forge.contains_key(repo)
                || query.get("format").map(String::as_str) != Some("json")
            {
                return StatusCode::NOT_FOUND.into_response();
            }
            let key = format!("{repo}/{inner}");
            *s.listings.entry(key.clone()).or_default() += 1;
            if s.refused_listings.contains(&key) {
                return StatusCode::FORBIDDEN.into_response();
            }
            return listing(&s.forge[repo], &inner, &query, page_size);
        }
        let nexus = s.nexus.contains_key(repo);
        let files = s.nexus.get(repo).or_else(|| s.forge.get(repo));
        (
            format!("{repo}/{inner}"),
            files.and_then(|f| f.get(&inner)).cloned(),
            nexus,
        )
    } else if let Some(rest) = path.strip_prefix("/plain/") {
        let Some(inner) = decode(rest) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        (
            format!("plain/{inner}"),
            s.plain.get(&inner).cloned(),
            false,
        )
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(file) = files else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if get {
        *s.downloads.entry(key.clone()).or_default() += 1;
    }
    let bytes = s.corrupt.get(&key).cloned().unwrap_or(file.bytes);
    let mut response = (
        [
            (header::CONTENT_TYPE, file.content_type.clone()),
            (
                header::LAST_MODIFIED,
                file.created.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            ),
        ],
        bytes,
    )
        .into_response();
    if nexus {
        response
            .headers_mut()
            .insert(header::SERVER, HeaderValue::from_static(NEXUS));
    }
    response
}

/// A page of a Forge's JSON listing of `dir` (`""` or ending in `/`).
fn listing(
    files: &BTreeMap<String, File>,
    dir: &str,
    query: &HashMap<String, String>,
    page_size: usize,
) -> Response {
    let mut entries: BTreeMap<String, Value> = BTreeMap::new();
    for (path, f) in files {
        let Some(rest) = path.strip_prefix(dir) else {
            continue;
        };
        match rest.split_once('/') {
            Some((sub, _)) => {
                let name = format!("{sub}/");
                entries.insert(
                    name.clone(),
                    json!({"name": name, "path": format!("{dir}{name}"), "type": "directory"}),
                );
            }
            None => {
                entries.insert(
                    rest.to_string(),
                    json!({
                        "name": rest, "path": path, "type": "file", "size": f.bytes.len(),
                        "content_type": f.content_type, "sha256": sha256(&f.bytes),
                        "last_modified": forge_time(f.created),
                        "last_downloaded": f.downloaded.map(forge_time),
                    }),
                );
            }
        }
    }
    if entries.is_empty() && !dir.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let limit = query
        .get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(100usize)
        .min(page_size);
    let after = query.get("after").cloned().unwrap_or_default();
    let mut page: Vec<(String, Value)> = entries
        .into_iter()
        .filter(|(name, _)| after.is_empty() || name.as_str() > after.as_str())
        .collect();
    let more = page.len() > limit;
    page.truncate(limit);
    let next = page.last().filter(|_| more).map(|(name, _)| name.clone());
    json_response(json!({
        "repository": "source", "path": dir,
        "entries": page.into_iter().map(|(_, e)| e).collect::<Vec<_>>(),
        "next": next,
    }))
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

async fn raw_repo(srv: &TestServer, body: Value) -> i64 {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        "/admin/repositories",
        Some(body),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap()
}

async fn hosted(srv: &TestServer, name: &str) -> i64 {
    raw_repo(
        srv,
        json!({"name": name, "kind": "hosted", "format": "raw"}),
    )
    .await
}

/// Ask for an import into `repo`.
async fn request(srv: &TestServer, repo: &str, body: Value) -> reqwest::Response {
    admin(
        srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports"),
        Some(body),
    )
    .await
}

/// Start an import into `repo`; returns its view.
async fn start(srv: &TestServer, repo: &str, body: Value) -> Value {
    let resp = request(srv, repo, body).await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["state"], "queued");
    view
}

/// An import of `url`, with the credentials.
fn from(url: String) -> Value {
    json!({"url": url, "username": USER, "password": PASSWORD})
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

/// Start an import and run it to its end.
async fn import(srv: &TestServer, repo: &str, body: Value) -> Value {
    let id = start(srv, repo, body).await["id"].as_i64().unwrap();
    run(srv, repo, id).await
}

async fn items(srv: &TestServer, repo: &str, id: i64, state: Option<&str>) -> Vec<Value> {
    let mut path = format!("/admin/repositories/{repo}/imports/{id}/items?limit=1000");
    if let Some(state) = state {
        path.push_str(&format!("&state={state}"));
    }
    admin(srv, reqwest::Method::GET, &path, None)
        .await
        .json()
        .await
        .unwrap()
}

/// The item of `path`.
fn item<'a>(items: &'a [Value], path: &str) -> &'a Value {
    items
        .iter()
        .find(|i| i["name"] == path)
        .unwrap_or_else(|| panic!("no item {path} in {items:?}"))
}

/// GET `path` of Forge's `repo`: its status, `Content-Type` and bytes.
async fn fetch(srv: &TestServer, repo: &str, path: &str) -> (u16, String, Vec<u8>) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/repository/{repo}/{}",
            srv.base_url,
            forge_plugin::api::files::encode(path)
        ))
        .basic_auth(u, Some(p))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, content_type, resp.bytes().await.unwrap().to_vec())
}

/// PUT `bytes` to `path` of Forge's `repo`.
async fn put(srv: &TestServer, repo: &str, path: &str, bytes: &[u8]) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .put(format!(
            "{}/repository/{repo}/{}",
            srv.base_url,
            forge_plugin::api::files::encode(path)
        ))
        .basic_auth(u, Some(p))
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "PUT {path}: {}", resp.status());
}

/// `(created_at, updated_at, last_downloaded_at)` of a file Forge holds.
async fn times(
    srv: &TestServer,
    repo_id: i64,
    path: &str,
) -> (DateTime<Utc>, DateTime<Utc>, Option<DateTime<Utc>>) {
    sqlx::query_as(
        "SELECT created_at, updated_at, last_downloaded_at FROM raw_file WHERE repository_id = $1 AND path = $2",
    )
    .bind(repo_id)
    .bind(path)
    .fetch_one(&srv.pool)
    .await
    .unwrap()
}

async fn file_count(srv: &TestServer, repo_id: i64) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM raw_file WHERE repository_id = $1")
        .bind(repo_id)
        .fetch_one(&srv.pool)
        .await
        .unwrap()
}

fn repo_name(prefix: &str) -> String {
    format!("{prefix}{}", common::unique())
}

fn assert_recent(t: Option<DateTime<Utc>>) {
    let t = t.expect("a time");
    assert!(
        (Utc::now() - t).num_seconds().abs() < 120,
        "{t} is not about now"
    );
}

// ── Nexus' asset listing ────────────────────────────────────────────────────

#[tokio::test]
async fn raw_import_from_nexus_keeps_bytes_types_times_and_uploaders() {
    let srv = forge().await;
    let source = Source::start().await;
    let readme = File {
        downloaded: Some(time("2022-01-02T03:04:05.678Z")),
        uploader: Some("alice".into()),
        ..file(b"read me\n", "text/plain", "2021-03-04T05:06:07.123Z")
    };
    let guide = File {
        uploader: Some("bob".into()),
        ..file(b"a guide", "text/markdown", "2023-06-07T08:09:10.000Z")
    };
    let tool = file(
        b"\x1f\x8b binary tool",
        "application/x-gzip",
        "2024-01-01T00:00:00.000Z",
    );
    let data = file(
        b"{\"a\": 1}",
        "application/json",
        "2024-02-02T00:00:00.000Z",
    );
    for (path, f) in [
        ("docs/readme.txt", &readme),
        ("docs/guides/a b ü.txt", &guide),
        ("bin/tool-1.0.tgz", &tool),
        ("deep/a/b/c/data.json", &data),
    ] {
        source.nexus("raw-hosted", path, f.clone());
    }
    // Paths Forge refuses, and a file that is not what Nexus lists.
    let long = format!("odd/{}.txt", "x".repeat(300));
    for path in [
        "odd/back\\slash.txt",
        "odd//empty.txt",
        "odd/../up.txt",
        "odd/bell\u{7}.txt",
        long.as_str(),
        "bad/corrupt.bin",
    ] {
        source.nexus(
            "raw-hosted",
            path,
            file(b"odd", "text/plain", "2024-01-01T00:00:00Z"),
        );
    }
    source.with(|s| {
        s.corrupt
            .insert("raw-hosted/bad/corrupt.bin".into(), b"ODD".to_vec())
    });

    let repo = repo_name("rawcopy");
    let repo_id = hosted(&srv, &repo).await;
    let first = start(&srv, &repo, from(source.repository("raw-hosted"))).await;
    assert_eq!(first["listing"], "assets", "{first}");
    assert_eq!(first["source_server"], NEXUS, "{first}");
    let id = first["id"].as_i64().unwrap();
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["found"], 10, "{done}");
    assert_eq!(done["progress"]["imported"], 4, "{done}");
    assert_eq!(done["progress"]["failed"], 6, "{done}");
    assert_eq!(
        done["progress"]["bytes_copied"],
        (readme.bytes.len() + guide.bytes.len() + tool.bytes.len() + data.bytes.len()) as i64,
        "{done}"
    );
    assert!(!done["has_password"].as_bool().unwrap());

    // Every file arrives with its times (before a download here bumps its
    // last download) ...
    let imported = [
        ("docs/readme.txt", &readme),
        ("docs/guides/a b ü.txt", &guide),
        ("bin/tool-1.0.tgz", &tool),
        ("deep/a/b/c/data.json", &data),
    ];
    for (path, f) in imported {
        let (created, updated, downloaded) = times(&srv, repo_id, path).await;
        assert_eq!(created, f.created, "{path}");
        assert_eq!(updated, f.created, "{path}");
        match f.downloaded {
            Some(at) => assert_eq!(downloaded, Some(at), "{path}"),
            // No last download at the source: downloaded at the import.
            None => assert_recent(downloaded),
        }
    }
    let all = items(&srv, &repo, id, None).await;
    assert!(all
        .iter()
        .all(|i| i["kind"] == "file" && i["version"] == ""));
    let readme_item = item(&all, "docs/readme.txt");
    assert_eq!(readme_item["state"], "imported");
    assert_eq!(readme_item["uploader"], "alice");
    assert_eq!(readme_item["size"], readme.bytes.len());
    assert_eq!(
        item(&all, "docs/readme.txt")["published_at"]
            .as_str()
            .map(time),
        Some(readme.created)
    );

    // Each path Forge refuses fails as its own item, with the reason.
    let failed = items(&srv, &repo, id, Some("failed")).await;
    for (path, reason) in [
        ("odd/back\\slash.txt", "backslashes"),
        ("odd//empty.txt", "empty segment"),
        ("odd/../up.txt", "`..` segments"),
        ("odd/bell\\u{7}.txt", "control characters"),
        (long.as_str(), "longer than 255 bytes"),
    ] {
        let detail = item(&failed, path)["detail"].as_str().unwrap().to_string();
        assert!(
            detail.starts_with("Forge refuses the path") && detail.contains(reason),
            "{path}: {detail}"
        );
    }
    let corrupt = item(&failed, "bad/corrupt.bin")["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        corrupt.contains("does not match the SHA-512 the source lists"),
        "{corrupt}"
    );
    assert_eq!(fetch(&srv, &repo, "bad/corrupt.bin").await.0, 404);

    // Retention does not take what was just imported for unused: only the
    // file Nexus last served in 2022 is selected.
    let preview: Value = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/retention/preview"),
        Some(json!({"policy": {"version": 1, "rules": [
            {"id": "cold", "not_downloaded_for_days": 30}
        ]}})),
    )
    .await
    .json()
    .await
    .unwrap();
    let doomed: Vec<&str> = preview["file_decisions"]
        .as_array()
        .unwrap_or_else(|| panic!("{preview}"))
        .iter()
        .map(|d| d["path"].as_str().unwrap())
        .collect();
    assert_eq!(doomed, ["docs/readme.txt"], "{preview}");

    // ... with its bytes and content type, and its `.sha256` sidecar is
    // Nexus' SHA-256.
    for (path, f) in imported {
        let (status, content_type, bytes) = fetch(&srv, &repo, path).await;
        assert_eq!(status, 200, "{path}");
        assert_eq!(bytes, f.bytes, "{path}");
        assert_eq!(content_type, f.content_type, "{path}");
        let (_, _, sidecar) = fetch(&srv, &repo, &format!("{path}.sha256")).await;
        let sidecar = String::from_utf8(sidecar).unwrap();
        assert!(sidecar.starts_with(&sha256(&f.bytes)), "{path}: {sidecar}");
    }

    // A second run copies only what is new; a changed file is a conflict,
    // decided from Nexus' SHA-256 without downloading it.
    source.nexus(
        "raw-hosted",
        "docs/new.txt",
        file(b"new", "text/plain", "2025-01-01T00:00:00Z"),
    );
    let tool2 = file(
        b"\x1f\x8b binary tool, rebuilt",
        "application/x-gzip",
        "2025-02-02T00:00:00.000Z",
    );
    source.nexus("raw-hosted", "bin/tool-1.0.tgz", tool2.clone());
    let done = import(&srv, &repo, from(source.repository("raw-hosted"))).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 1, "{done}");
    assert_eq!(done["progress"]["identical"], 3, "{done}");
    assert_eq!(done["progress"]["conflict"], 1, "{done}");
    assert_eq!(done["progress"]["failed"], 6, "{done}");
    assert_eq!(done["progress"]["bytes_copied"], 3, "{done}");
    let second = done["id"].as_i64().unwrap();
    let conflict = items(&srv, &repo, second, Some("conflict")).await;
    assert_eq!(conflict[0]["name"], "bin/tool-1.0.tgz");
    assert_eq!(conflict[0]["detail"], "Forge has other bytes at this path");
    assert_eq!(source.downloads("raw-hosted/docs/readme.txt"), 1);
    assert_eq!(source.downloads("raw-hosted/bin/tool-1.0.tgz"), 1);
    assert_eq!(source.downloads("raw-hosted/docs/new.txt"), 1);
    assert_eq!(fetch(&srv, &repo, "bin/tool-1.0.tgz").await.2, tool.bytes);

    // `overwrite`, in the request form of a Nexus server and repository:
    // the changed file is replaced, and takes Nexus' upload time.
    let mut legacy = from(source.url.clone());
    legacy["repository"] = json!("raw-hosted");
    legacy["on_conflict"] = json!("overwrite");
    let done = import(&srv, &repo, legacy).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["url"], source.repository("raw-hosted"), "{done}");
    assert_eq!(done["progress"]["replaced"], 1, "{done}");
    assert_eq!(done["progress"]["identical"], 4, "{done}");
    assert_eq!(fetch(&srv, &repo, "bin/tool-1.0.tgz").await.2, tool2.bytes);
    let (_, updated, _) = times(&srv, repo_id, "bin/tool-1.0.tgz").await;
    assert_eq!(updated, tool2.created);

    // `fail`: a changed file fails the import.
    source.nexus(
        "raw-hosted",
        "docs/readme.txt",
        file(b"read me, changed\n", "text/plain", "2025-03-03T00:00:00Z"),
    );
    let mut failing = from(source.repository("raw-hosted"));
    failing["on_conflict"] = json!("fail");
    let done = import(&srv, &repo, failing).await;
    assert_eq!(done["state"], "failed", "{done}");
    assert!(
        done["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("docs/readme.txt")),
        "{done}"
    );
    assert_eq!(fetch(&srv, &repo, "docs/readme.txt").await.2, readme.bytes);
}

// ── Another Forge's listing ─────────────────────────────────────────────────

#[tokio::test]
async fn raw_dry_run_reports_files_sizes_and_conflicts_and_a_walk_resumes() {
    let srv = forge().await;
    let source = Source::start().await;
    let files = [
        ("a.txt", "text/plain"),
        ("dir1/b.txt", "text/plain"),
        ("dir1/sub/c.bin", "application/octet-stream"),
        ("dir1/sub/d d.bin", "application/octet-stream"),
        ("dir1/sub/e.json", "application/json"),
        ("dir1/zz.txt", "text/plain"),
        ("dir2/f.txt", "text/plain"),
        ("z.txt", "text/plain"),
    ];
    for (i, (path, content_type)) in files.iter().enumerate() {
        source.forge(
            "binaries",
            path,
            File {
                downloaded: (i == 1).then(|| time("2025-05-05T05:05:05.123456Z")),
                ..file(
                    format!("the bytes of {path}").as_bytes(),
                    content_type,
                    &format!("2024-0{}-01T10:00:00.123456Z", i + 1),
                )
            },
        );
    }
    let repo = repo_name("rawdry");
    let repo_id = hosted(&srv, &repo).await;
    // Forge holds a.txt as the source does, and z.txt with other bytes.
    put(&srv, &repo, "a.txt", b"the bytes of a.txt").await;
    put(&srv, &repo, "z.txt", b"other bytes").await;

    let mut dry = from(source.repository("binaries"));
    dry["dry_run"] = json!(true);
    let view = start(&srv, &repo, dry.clone()).await;
    assert_eq!(view["listing"], "directories", "{view}");
    let done = run(&srv, &repo, view["id"].as_i64().unwrap()).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["planned"], 6, "{done}");
    assert_eq!(done["progress"]["identical"], 1, "{done}");
    assert_eq!(done["progress"]["conflict"], 1, "{done}");
    let planned_size: usize = files[1..7]
        .iter()
        .map(|(path, _)| format!("the bytes of {path}").len())
        .sum();
    assert_eq!(done["progress"]["planned_size"], planned_size, "{done}");
    assert_eq!(done["progress"]["bytes_copied"], 0, "{done}");
    // Nothing was written, nor downloaded.
    assert_eq!(file_count(&srv, repo_id).await, 2);
    assert_eq!(source.with(|s| s.downloads.len()), 0);

    // With `overwrite`, the dry run plans the replacement.
    dry["on_conflict"] = json!("overwrite");
    let done = import(&srv, &repo, dry).await;
    assert_eq!(done["progress"]["planned"], 7, "{done}");
    let planned = items(&srv, &repo, done["id"].as_i64().unwrap(), Some("planned")).await;
    assert_eq!(
        item(&planned, "z.txt")["detail"],
        "would replace the file Forge has with other bytes"
    );
    assert_eq!(file_count(&srv, repo_id).await, 2);

    // The import stops in dir2/ (its listing refuses the credentials) ...
    source.with(|s| s.refused_listings.insert("binaries/dir2/".into()));
    let view = start(&srv, &repo, from(source.repository("binaries"))).await;
    let id = view["id"].as_i64().unwrap();
    let stopped = run(&srv, &repo, id).await;
    assert_eq!(stopped["state"], "failed", "{stopped}");
    assert_eq!(stopped["phase"], "scan", "{stopped}");
    assert!(
        stopped["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("refused the credentials")),
        "{stopped}"
    );
    let dir1_listings = source.listings("binaries/dir1/");
    // ... and resumes there: dir1/ is not listed again.
    source.with(|s| s.refused_listings.clear());
    let resumed = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports/{id}/resume"),
        Some(json!({})),
    )
    .await;
    assert_eq!(resumed.status(), 200, "{}", resumed.text().await.unwrap());
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(source.listings("binaries/dir1/"), dir1_listings);
    assert_eq!(done["progress"]["found"], 8, "{done}");
    assert_eq!(done["progress"]["imported"], 6, "{done}");
    assert_eq!(done["progress"]["identical"], 1, "{done}");
    assert_eq!(done["progress"]["conflict"], 1, "{done}");

    for (i, (path, content_type)) in files.iter().enumerate().take(7).skip(1) {
        // The times first: a download here bumps the last download.
        let (_, updated, downloaded) = times(&srv, repo_id, path).await;
        let (status, served_type, bytes) = fetch(&srv, &repo, path).await;
        assert_eq!(status, 200, "{path}");
        assert_eq!(bytes, format!("the bytes of {path}").into_bytes(), "{path}");
        // A type that only says "bytes" is the extension's, as on upload.
        if *content_type != "application/octet-stream" {
            assert_eq!(served_type, *content_type, "{path}");
        }
        assert_eq!(
            updated,
            time(&format!("2024-0{}-01T10:00:00.123456Z", i + 1)),
            "{path}"
        );
        if i == 1 {
            assert_eq!(downloaded, Some(time("2025-05-05T05:05:05.123456Z")));
        } else {
            assert_recent(downloaded);
        }
    }
    // Each file was downloaded once.
    assert!(
        source.with(|s| s.downloads.values().all(|&n| n == 1)),
        "{:?}",
        source.with(|s| s.downloads.clone())
    );

    // A second run downloads nothing: Forge has every file with the
    // SHA-256 the listing names.
    let done = import(&srv, &repo, from(source.repository("binaries"))).await;
    assert_eq!(done["progress"]["identical"], 7, "{done}");
    assert_eq!(done["progress"]["bytes_copied"], 0, "{done}");
}

// ── Named paths of a plain web server ───────────────────────────────────────

#[tokio::test]
async fn raw_import_of_named_paths_checks_sha256_sidecars() {
    let srv = forge().await;
    let source = Source::start().await;
    let tool = file(b"tool bytes", "application/gzip", "2024-04-04T04:04:04Z");
    let notes = file(b"release notes", "text/plain", "2024-05-05T05:05:05Z");
    let bad = file(
        b"bad bytes",
        "application/octet-stream",
        "2024-06-06T06:06:06Z",
    );
    source.plain("releases/1.0/tool.tgz", tool.clone());
    source.plain(
        "releases/1.0/tool.tgz.sha256",
        file(
            format!("{}  tool.tgz\n", sha256(&tool.bytes)).as_bytes(),
            "text/plain",
            "2024-04-04T04:04:04Z",
        ),
    );
    source.plain("releases/1.0/notes ü.txt", notes.clone());
    source.plain("releases/1.0/bad.bin", bad.clone());
    source.plain(
        "releases/1.0/bad.bin.sha256",
        file(
            sha256(b"other").as_bytes(),
            "text/plain",
            "2024-06-06T06:06:06Z",
        ),
    );

    let repo = repo_name("rawnamed");
    let repo_id = hosted(&srv, &repo).await;
    let url = format!("{}/plain", source.url);

    // Without a listing, the import names its paths.
    let resp = request(&srv, &repo, from(url.clone())).await;
    assert_eq!(resp.status(), 400);
    let text = resp.text().await.unwrap();
    assert!(text.contains("lists no files"), "{text}");

    let mut body = from(url.clone());
    body["names"] = json!([
        "releases/1.0/tool.tgz",
        "/releases/1.0/tool.tgz",
        "releases/1.0/notes ü.txt",
        "releases/1.0/bad.bin",
        "releases/1.0/missing.txt",
    ]);
    let view = start(&srv, &repo, body.clone()).await;
    assert_eq!(view["listing"], "names", "{view}");
    assert_eq!(view["names"].as_array().unwrap().len(), 4, "{view}");
    let id = view["id"].as_i64().unwrap();
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 2, "{done}");
    assert_eq!(done["progress"]["failed"], 2, "{done}");
    let failed = items(&srv, &repo, id, Some("failed")).await;
    let detail = item(&failed, "releases/1.0/bad.bin")["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        detail.contains("does not match the SHA-256 its .sha256 sidecar holds"),
        "{detail}"
    );
    assert_eq!(
        item(&failed, "releases/1.0/missing.txt")["detail"],
        "the source has no file at this path"
    );
    for (path, f) in [
        ("releases/1.0/tool.tgz", &tool),
        ("releases/1.0/notes ü.txt", &notes),
    ] {
        // `Last-Modified` is the upload time; the last download the import's.
        let (_, updated, downloaded) = times(&srv, repo_id, path).await;
        assert_eq!(updated, f.created, "{path}");
        assert_recent(downloaded);
        let (status, content_type, bytes) = fetch(&srv, &repo, path).await;
        assert_eq!((status, bytes), (200, f.bytes.clone()), "{path}");
        assert_eq!(content_type, f.content_type, "{path}");
    }

    // A second run: the file with a sidecar is identical without a download,
    // the one without is downloaded and compared.
    let done = import(&srv, &repo, body).await;
    assert_eq!(done["progress"]["identical"], 2, "{done}");
    assert_eq!(
        done["progress"]["bytes_copied"],
        notes.bytes.len() as i64,
        "{done}"
    );
    assert_eq!(source.downloads("plain/releases/1.0/tool.tgz"), 1);
    assert_eq!(source.downloads("plain/releases/1.0/notes ü.txt"), 2);

    // A named file the source has since is found when its item is retried.
    let missing = file(b"here now", "text/plain", "2024-07-07T07:07:07Z");
    source.plain("releases/1.0/missing.txt", missing.clone());
    let resumed = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports/{id}/resume"),
        Some(json!({"retry_failed": true, "password": PASSWORD})),
    )
    .await;
    assert_eq!(resumed.status(), 200, "{}", resumed.text().await.unwrap());
    let done = run(&srv, &repo, id).await;
    assert_eq!(done["progress"]["imported"], 3, "{done}");
    assert_eq!(done["progress"]["failed"], 1, "{done}");
    assert_eq!(
        fetch(&srv, &repo, "releases/1.0/missing.txt").await.2,
        missing.bytes
    );
}

// ── The preflight ───────────────────────────────────────────────────────────

#[tokio::test]
async fn raw_import_preflight_refusals() {
    let srv = forge().await;
    let source = Source::start().await;
    source.nexus(
        "raw-hosted",
        "a.txt",
        file(b"a", "text/plain", "2024-01-01T00:00:00Z"),
    );
    let repo = repo_name("rawpre");
    hosted(&srv, &repo).await;
    let refused = |resp: reqwest::Response, status: u16, text: &'static str| async move {
        assert_eq!(resp.status(), status);
        let body = resp.text().await.unwrap();
        assert!(body.contains(text), "{body}");
    };

    // Wrong credentials.
    let mut body = from(source.repository("raw-hosted"));
    body["password"] = json!("wrong");
    refused(
        request(&srv, &repo, body).await,
        400,
        "refused the credentials",
    )
    .await;
    // An unreachable source.
    refused(
        request(
            &srv,
            &repo,
            json!({"url": "http://127.0.0.1:9/repository/x"}),
        )
        .await,
        502,
        "unreachable",
    )
    .await;
    // Paths Forge refuses, and a directory.
    for (name, text) in [
        ("a/../b.txt", "Forge refuses the path"),
        ("a\\b.txt", "Forge refuses the path"),
        ("releases/", "is a directory"),
    ] {
        let mut body = from(source.repository("raw-hosted"));
        body["names"] = json!([name]);
        refused(request(&srv, &repo, body).await, 400, text).await;
    }
    // A named import whose first file refuses the credentials.
    let mut body = json!({"url": format!("{}/plain", source.url), "names": ["a.txt"]});
    refused(
        request(&srv, &repo, body.clone()).await,
        400,
        "refused the credentials",
    )
    .await;
    body["username"] = json!(USER);
    body["password"] = json!(PASSWORD);
    assert_eq!(request(&srv, &repo, body).await.status(), 201);

    // A read-only repository, and a proxy.
    let read_only = repo_name("rawro");
    raw_repo(
        &srv,
        json!({"name": read_only, "kind": "hosted", "format": "raw", "deployment_policy": "read_only"}),
    )
    .await;
    refused(
        request(&srv, &read_only, from(source.repository("raw-hosted"))).await,
        400,
        "read-only",
    )
    .await;
    let proxy = repo_name("rawproxy");
    raw_repo(
        &srv,
        json!({"name": proxy, "kind": "proxy", "format": "raw", "remote_url": source.url}),
    )
    .await;
    refused(
        request(&srv, &proxy, from(source.repository("raw-hosted"))).await,
        400,
        "imports go to a hosted repository",
    )
    .await;
}
