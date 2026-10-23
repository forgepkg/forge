//! Integration tests of raw (generic file) repositories (`/raw`): hosted
//! uploads, downloads with ranges, validators and checksum sidecars, the
//! deployment policy, listings, path traversal, proxies (redirects to a
//! second host, re-validation, misses, an unreachable upstream), groups,
//! package selectors on paths, multipart and web UI uploads, the admin API
//! and retention. Requires Docker (Postgres + versitygw via the shared
//! harness), or `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`.
//!
//! The same flows run with the real `curl` in CI (`.github/scripts/raw-e2e.sh`).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use common::{unique, TestServer};
use serde_json::{json, Value};
use sha2::Digest as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// `POST /admin/repositories` with `body`, expecting `status`.
async fn admin_create(srv: &TestServer, body: Value) -> Response {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (StatusCode::from_u16(status.as_u16()).unwrap(), text).into_response()
}

async fn create(srv: &TestServer, body: Value) -> Value {
    let resp = admin_create(srv, body.clone()).await;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create {body}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

async fn update(srv: &TestServer, name: &str, body: Value) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    srv.client()
        .put(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// A client for one repository, authenticated with an API token.
struct Files {
    base: String,
    client: reqwest::Client,
    token: Option<(String, String)>,
}

impl Files {
    async fn new(srv: &TestServer, repo: &str) -> Self {
        let token = srv.admin_token().await;
        Files {
            base: format!("{}/raw/{repo}", srv.base_url),
            client: srv.client(),
            token: Some((srv.admin_user.clone().unwrap(), token)),
        }
    }

    fn anonymous(&self) -> Self {
        Files {
            base: self.base.clone(),
            client: self.client.clone(),
            token: None,
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let rb = self.client.request(method, format!("{}/{path}", self.base));
        match &self.token {
            Some((u, t)) => rb.basic_auth(u, Some(t)),
            None => rb,
        }
    }

    async fn put(&self, path: &str, body: &[u8]) -> reqwest::StatusCode {
        self.req(reqwest::Method::PUT, path)
            .body(body.to_vec())
            .send()
            .await
            .unwrap()
            .status()
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.req(reqwest::Method::GET, path).send().await.unwrap()
    }

    async fn text(&self, path: &str) -> (reqwest::StatusCode, String) {
        let resp = self.get(path).await;
        (resp.status(), resp.text().await.unwrap())
    }

    async fn json(&self, path: &str) -> Value {
        let resp = self
            .req(reqwest::Method::GET, path)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "listing {path}");
        resp.json().await.unwrap()
    }
}

fn names(listing: &Value) -> Vec<String> {
    listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn hosted_files_upload_download_and_redeploy() {
    let srv = common::start().await;
    let name = format!("bin{}", unique());
    let repo = create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "raw"}),
    )
    .await;
    assert_eq!(repo["deployment_policy"], "disable_redeploy");
    assert_eq!(repo["content_disposition"], "attachment");
    let files = Files::new(&srv, &name).await;
    let path = "pdfium/7350/pdfium-linux-x64.tgz";
    let content = b"0123456789abcdef".to_vec();

    // Unauthenticated, and with a browser session: refused.
    assert_eq!(files.anonymous().put(path, &content).await, 401);
    let (u, p) = srv.admin_password_basic();
    let session = srv.login(&u, &p).await;
    let resp = session
        .apply(files.client.put(format!("{}/{path}", files.base)))
        .body(content.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "a session is not a publishing credential"
    );

    assert_eq!(files.put(path, &content).await, 201);

    // The download, its validators and type.
    let resp = files.get(path).await;
    assert_eq!(resp.status(), 200);
    let headers = resp.headers().clone();
    let etag = headers[header::ETAG].to_str().unwrap().to_string();
    assert_eq!(etag, format!("\"{}\"", sha256(&content)));
    assert!(headers.contains_key(header::LAST_MODIFIED));
    assert_eq!(headers[header::CONTENT_LENGTH], "16");
    assert_eq!(headers[header::ACCEPT_RANGES], "bytes");
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"pdfium-linux-x64.tgz\""
    );
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        "default-src 'none'; sandbox"
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), content.as_slice());

    // A range, a resumed download, and a stale If-Range.
    let resp = files
        .req(reqwest::Method::GET, path)
        .header(header::RANGE, "bytes=10-")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()[header::CONTENT_RANGE], "bytes 10-15/16");
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"abcdef");
    let resp = files
        .req(reqwest::Method::GET, path)
        .header(header::RANGE, "bytes=0-3")
        .header(header::IF_RANGE, "\"stale\"")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = files
        .req(reqwest::Method::GET, path)
        .header(header::RANGE, "bytes=99-")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers()[header::CONTENT_RANGE], "bytes */16");

    // Conditional requests.
    let resp = files
        .req(reqwest::Method::GET, path)
        .header(header::IF_NONE_MATCH, &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 304);
    let resp = files
        .req(reqwest::Method::GET, path)
        .header(
            header::IF_MODIFIED_SINCE,
            headers[header::LAST_MODIFIED].clone(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 304);
    let resp = files.req(reqwest::Method::HEAD, path).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()[header::CONTENT_LENGTH], "16");

    // Checksum sidecars, as `sha256sum -c` reads them.
    let (status, text) = files.text(&format!("{path}.sha256")).await;
    assert_eq!(status, 200);
    assert_eq!(
        text,
        format!("{}  pdfium-linux-x64.tgz\n", sha256(&content))
    );
    let (_, sha1) = files.text(&format!("{path}.sha1")).await;
    assert_eq!(
        sha1,
        format!(
            "{}  pdfium-linux-x64.tgz\n",
            hex::encode(sha1::Sha1::digest(&content))
        )
    );
    let (_, sha512) = files.text(&format!("{path}.sha512")).await;
    assert_eq!(
        sha512,
        format!(
            "{}  pdfium-linux-x64.tgz\n",
            hex::encode(sha2::Sha512::digest(&content))
        )
    );
    let (status, md5) = files.text(&format!("{path}.md5")).await;
    assert_eq!(status, 200);
    assert_eq!(md5.len(), 32 + 2 + "pdfium-linux-x64.tgz\n".len());
    assert_eq!(
        files.get("pdfium/7350/missing.tgz.sha256").await.status(),
        404
    );

    // Redeploy: refused by default, the same content is accepted as is.
    assert_eq!(files.put(path, b"other").await, 409);
    assert_eq!(files.put(path, &content).await, 204);
    let resp = update(&srv, &name, json!({"deployment_policy": "allow_redeploy"})).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(files.put(path, b"other").await, 204);
    assert_eq!(
        files.text(path).await,
        (reqwest::StatusCode::OK, "other".into())
    );
    let resp = update(&srv, &name, json!({"deployment_policy": "read_only"})).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(files.put("new.bin", b"x").await, 405);
    let resp = files
        .req(reqwest::Method::DELETE, path)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);
    assert_eq!(files.get(path).await.status(), 200, "still readable");
    update(
        &srv,
        &name,
        json!({"deployment_policy": "disable_redeploy"}),
    )
    .await;

    // Listings: JSON, HTML, the root, and a directory named without its `/`.
    assert_eq!(files.put("pdfium/README.txt", b"readme").await, 201);
    let root = files.json("").await;
    assert_eq!(names(&root), ["pdfium/"]);
    let dir = files.json("pdfium/").await;
    assert_eq!(names(&dir), ["7350/", "README.txt"]);
    let readme = &dir["entries"][1];
    assert_eq!(readme["type"], "file");
    assert_eq!(readme["size"], 6);
    assert_eq!(readme["content_type"], "text/plain");
    assert_eq!(readme["sha256"], sha256(b"readme"));
    let resp = files.get("pdfium/").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()[header::CONTENT_DISPOSITION], "inline");
    let html = resp.text().await.unwrap();
    assert!(
        html.contains("<a href=\"README.txt\">README.txt</a>"),
        "{html}"
    );
    assert!(html.contains("<a href=\"../\">"), "{html}");
    let resp = srv
        .client()
        .get(format!("{}/pdfium", files.base))
        .basic_auth(&u, Some(&files.token.as_ref().unwrap().1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "redirected to pdfium/");
    assert!(resp.url().path().ends_with("/pdfium/"));
    assert_eq!(files.get("nothing/").await.status(), 404);

    // Paginated.
    for i in 0..5 {
        files.put(&format!("many/f{i}"), b"x").await;
    }
    let page = files.json("many/?limit=2").await;
    assert_eq!(names(&page), ["f0", "f1"]);
    assert_eq!(page["next"], "f1");
    let page = files.json("many/?limit=2&after=f3").await;
    assert_eq!(names(&page), ["f4"]);
    assert!(page["next"].is_null());

    // Delete.
    let resp = files
        .req(reqwest::Method::DELETE, "pdfium/README.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(files.get("pdfium/README.txt").await.status(), 404);
    let resp = files
        .req(reqwest::Method::DELETE, "pdfium/README.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // A repository with files is not deleted until they are.
    let (au, ap) = srv.admin_basic();
    let resp = srv
        .client()
        .delete(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let resp = srv
        .client()
        .delete(format!(
            "{}/admin/repositories/{name}/files?path=",
            srv.base_url
        ))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let deleted: Value = resp.json().await.unwrap();
    assert_eq!(deleted["deleted"], 6);
    let resp = srv
        .client()
        .delete(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// Send one request with the path exactly as given (HTTP clients normalize
/// `..` and `%2e%2e` away) and return its status.
async fn raw_status(srv: &TestServer, method: &str, path: &str, auth: &str) -> u16 {
    let addr = srv.base_url.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic {auth}\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    text.split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status in {text:?}"))
}

#[tokio::test]
async fn path_traversal_is_refused() {
    use base64::Engine as _;
    let srv = common::start().await;
    let name = format!("trav{}", unique());
    create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "raw"}),
    )
    .await;
    let files = Files::new(&srv, &name).await;
    assert_eq!(files.put("safe/file.txt", b"ok").await, 201);
    let (u, t) = files.token.clone().unwrap();
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{t}"));

    for path in [
        "../x",
        "safe/../safe/file.txt",
        "%2e%2e/x",
        "%2E%2E/safe/file.txt",
        "safe/%2e%2e/safe/file.txt",
        ".%2e/x",
        "safe/./file.txt",
        "safe//file.txt",
        "//etc/passwd",
        "safe%2ffile.txt",
        "safe%5cfile.txt",
        "..%5cx",
        "safe%00file.txt",
    ] {
        for method in ["GET", "PUT", "DELETE"] {
            let status = raw_status(&srv, method, &format!("/raw/{name}/{path}"), &auth).await;
            assert_eq!(status, 400, "{method} {path}");
        }
    }
    // A backslash hyper lets through is refused like its encoded form; one
    // it does not is refused before the handler.
    let status = raw_status(&srv, "PUT", &format!("/raw/{name}/a\\b"), &auth).await;
    assert_eq!(status, 400);
    // Nothing was stored outside, and the file is untouched.
    assert_eq!(names(&files.json("").await), ["safe/"]);
    assert_eq!(names(&files.json("safe/").await), ["file.txt"]);
    // The repository name itself cannot climb out either.
    let status = raw_status(&srv, "GET", "/raw/../admin/repositories", &auth).await;
    assert_ne!(status, 200);
}

// ── Proxies ─────────────────────────────────────────────────────────────────

/// What the mock upstreams saw and serve.
#[derive(Default)]
struct Upstream {
    /// Requests to the first host, and whether they carried credentials.
    first: AtomicUsize,
    first_auth: Mutex<Vec<bool>>,
    /// Requests to the second host, with their `If-None-Match` and whether
    /// they carried credentials.
    second: AtomicUsize,
    second_seen: Mutex<Vec<(Option<String>, bool)>>,
    /// The asset the second host serves, and its version.
    content: Mutex<Vec<u8>>,
    version: AtomicUsize,
    /// Answer 503 to everything.
    down: std::sync::atomic::AtomicBool,
}

async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

/// A release host that redirects downloads to an asset host on another
/// origin, like GitHub's `releases/download/` to
/// `objects.githubusercontent.com`.
async fn mock_upstreams(state: Arc<Upstream>) -> String {
    let assets = {
        let state = state.clone();
        axum::Router::new().route(
            "/assets/{*name}",
            axum::routing::get(move |headers: HeaderMap| {
                let state = state.clone();
                async move {
                    state.second.fetch_add(1, Ordering::SeqCst);
                    state.second_seen.lock().unwrap().push((
                        headers
                            .get(header::IF_NONE_MATCH)
                            .map(|v| v.to_str().unwrap().to_string()),
                        headers.contains_key(header::AUTHORIZATION),
                    ));
                    if state.down.load(Ordering::SeqCst) {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    let etag = format!("\"v{}\"", state.version.load(Ordering::SeqCst));
                    if headers
                        .get(header::IF_NONE_MATCH)
                        .is_some_and(|v| v == etag.as_str())
                    {
                        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
                    }
                    let body = state.content.lock().unwrap().clone();
                    (
                        [
                            (header::ETAG, etag),
                            (header::CONTENT_TYPE, "application/octet-stream".into()),
                        ],
                        body,
                    )
                        .into_response()
                }
            }),
        )
    };
    let assets = serve(assets).await;
    let releases = axum::Router::new().route(
        "/releases/download/{*rest}",
        axum::routing::get(
            move |axum::extract::Path(rest): axum::extract::Path<String>, headers: HeaderMap| {
                let state = state.clone();
                let assets = assets.clone();
                async move {
                    state.first.fetch_add(1, Ordering::SeqCst);
                    state
                        .first_auth
                        .lock()
                        .unwrap()
                        .push(headers.contains_key(header::AUTHORIZATION));
                    if state.down.load(Ordering::SeqCst) {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    if rest.ends_with("missing.bin") {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, format!("{assets}/assets/{rest}?sig=x"))],
                    )
                        .into_response()
                }
            },
        ),
    );
    serve(releases).await
}

#[tokio::test]
async fn proxies_follow_redirects_revalidate_and_survive_the_upstream() {
    let srv = common::start().await;
    let upstream = Arc::new(Upstream::default());
    *upstream.content.lock().unwrap() = b"release asset v1".to_vec();
    upstream.version.store(1, Ordering::SeqCst);
    let base = mock_upstreams(upstream.clone()).await;

    let name = format!("rawproxy{}", unique());
    let repo = create(
        &srv,
        json!({
            "name": name, "kind": "proxy", "format": "raw",
            "remote_url": format!("{base}/releases/download/"),
            "upstream_username": "u", "upstream_password": "p",
            "not_found_ttl_seconds": 60,
        }),
    )
    .await;
    assert_eq!(repo["max_age_seconds"], 86400);
    let files = Files::new(&srv, &name).await;
    let path = "chromium/7350/pdfium-linux-x64.tgz";

    // First download: through the redirect; cached after.
    let (status, body) = files.text(path).await;
    assert_eq!(status, 200);
    assert_eq!(body, "release asset v1");
    let (status, body) = files.text(path).await;
    assert_eq!(
        (status, body.as_str()),
        (reqwest::StatusCode::OK, "release asset v1")
    );
    assert_eq!(upstream.first.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.second.load(Ordering::SeqCst), 1);
    // Credentials went to the configured origin only.
    assert_eq!(*upstream.first_auth.lock().unwrap(), [true]);
    assert_eq!(upstream.second_seen.lock().unwrap()[0], (None, false));
    // Ranges and sidecars of a cached file.
    let resp = files
        .req(reqwest::Method::GET, path)
        .header(header::RANGE, "bytes=8-")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.text().await.unwrap(), "asset v1");
    let (_, sidecar) = files.text(&format!("{path}.sha256")).await;
    assert!(
        sidecar.starts_with(&sha256(b"release asset v1")),
        "{sidecar}"
    );
    // The listing shows what is cached.
    assert_eq!(
        names(&files.json("chromium/7350/").await),
        ["pdfium-linux-x64.tgz"]
    );

    // Past its maximum age a file is re-validated: unchanged (304) ...
    let resp = update(&srv, &name, json!({"max_age_seconds": 1})).await;
    assert_eq!(resp.status(), 200);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body) = files.text(path).await;
    assert_eq!(body, "release asset v1");
    assert_eq!(
        upstream
            .second_seen
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .0
            .as_deref(),
        Some("\"v1\""),
        "a conditional request"
    );
    // ... then changed upstream.
    *upstream.content.lock().unwrap() = b"release asset v2".to_vec();
    upstream.version.store(2, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body) = files.text(path).await;
    assert_eq!(body, "release asset v2");

    // While the upstream is down, the cached copy is served.
    upstream.down.store(true, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, body) = files.text(path).await;
    assert_eq!(
        (status, body.as_str()),
        (reqwest::StatusCode::OK, "release asset v2")
    );
    // A file it never cached is a gateway error.
    assert_eq!(files.get("chromium/other.bin").await.status(), 502);
    upstream.down.store(false, Ordering::SeqCst);

    // A miss is remembered.
    let before = upstream.first.load(Ordering::SeqCst);
    assert_eq!(files.get("chromium/missing.bin").await.status(), 404);
    assert_eq!(files.get("chromium/missing.bin").await.status(), 404);
    assert_eq!(upstream.first.load(Ordering::SeqCst), before + 1);
    // Invalidating the cache forgets it.
    let (au, ap) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!(
            "{}/admin/repositories/{name}/proxy-cache/invalidate",
            srv.base_url
        ))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let invalidated: Value = resp.json().await.unwrap();
    assert_eq!(invalidated["files_expired"], 1);
    assert_eq!(files.get("chromium/missing.bin").await.status(), 404);
    assert_eq!(
        upstream.first.load(Ordering::SeqCst),
        before + 2,
        "asked again"
    );

    // Uploads go to hosted repositories only.
    assert_eq!(files.put("chromium/up.bin", b"x").await, 405);

    // `max_age_seconds: 0` never asks again.
    update(&srv, &name, json!({"max_age_seconds": 0})).await;
    let before = upstream.second.load(Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    files.text(path).await;
    assert_eq!(upstream.second.load(Ordering::SeqCst), before);

    // Repointing the proxy drops what the previous upstream served.
    let resp = update(
        &srv,
        &name,
        json!({"remote_url": format!("{base}/releases/download/other/")}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let root = files.json("").await;
    assert!(names(&root).is_empty(), "{root}");
}

// ── Groups ──────────────────────────────────────────────────────────────────

async fn add_member(srv: &TestServer, group: &str, member: &str, priority: i32) -> u16 {
    let (u, p) = srv.admin_basic();
    srv.client()
        .post(format!(
            "{}/admin/repositories/{group}/members",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"member": member, "priority": priority}))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn groups_fall_through_their_members_by_priority() {
    let srv = common::start().await;
    let n = unique();
    let (first, second, group) = (format!("ga{n}"), format!("gb{n}"), format!("g{n}"));
    for name in [&first, &second] {
        create(
            &srv,
            json!({"name": name, "kind": "hosted", "format": "raw"}),
        )
        .await;
    }
    let upstream = Arc::new(Upstream::default());
    *upstream.content.lock().unwrap() = b"from the proxy".to_vec();
    let base = mock_upstreams(upstream.clone()).await;
    let proxy = format!("gp{n}");
    create(
        &srv,
        json!({"name": proxy, "kind": "proxy", "format": "raw",
               "remote_url": format!("{base}/releases/download/")}),
    )
    .await;
    create(
        &srv,
        json!({"name": group, "kind": "group", "format": "raw"}),
    )
    .await;
    assert_eq!(add_member(&srv, &group, &first, 100).await, 201);
    assert_eq!(add_member(&srv, &group, &second, 50).await, 201);
    assert_eq!(add_member(&srv, &group, &proxy, 10).await, 201);

    let a = Files::new(&srv, &first).await;
    let b = Files::new(&srv, &second).await;
    a.put("shared.txt", b"first").await;
    b.put("shared.txt", b"second").await;
    b.put("only-second.txt", b"second only").await;
    b.put("dir/in-second.txt", b"x").await;
    a.put("dir/in-first.txt", b"y").await;

    let g = Files::new(&srv, &group).await;
    assert_eq!(g.text("shared.txt").await.1, "first");
    assert_eq!(g.text("only-second.txt").await.1, "second only");
    assert_eq!(g.text("from/upstream.bin").await.1, "from the proxy");
    let (status, sidecar) = g.text("only-second.txt.sha256").await;
    assert_eq!(status, 200);
    assert!(sidecar.starts_with(&sha256(b"second only")));
    // No member has it (the proxy's upstream answers 404).
    assert_eq!(g.get("nowhere/missing.bin").await.status(), 404);
    // Listings merge the members'.
    assert_eq!(
        names(&g.json("").await),
        ["dir/", "from/", "only-second.txt", "shared.txt"]
    );
    assert_eq!(
        names(&g.json("dir/").await),
        ["in-first.txt", "in-second.txt"]
    );
    // A merged listing pages too.
    let page = g.json("?limit=2").await;
    assert_eq!(names(&page), ["dir/", "from/"]);
    let page = g
        .json(&format!(
            "?limit=2&after={}",
            page["next"].as_str().unwrap()
        ))
        .await;
    assert_eq!(names(&page), ["only-second.txt", "shared.txt"]);
    // A group takes no uploads.
    assert_eq!(g.put("x.txt", b"x").await, 405);

    // An offline member is skipped.
    update(&srv, &first, json!({"online": false})).await;
    assert_eq!(g.text("shared.txt").await.1, "second");
    update(&srv, &first, json!({"online": true})).await;

    // Members share the group's format.
    let nuget = format!("gn{n}");
    create(&srv, json!({"name": nuget, "kind": "hosted"})).await;
    assert!(add_member(&srv, &group, &nuget, 5).await >= 400);
}

// ── Selectors, forms, the web UI and the admin API ──────────────────────────

#[tokio::test]
async fn selectors_scope_paths() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let name = format!("sel{}", unique());
    create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "raw"}),
    )
    .await;
    let files = Files::new(&srv, &name).await;
    files.put("pdfium/a.tgz", b"a").await;
    files.put("secret/b.tgz", b"b").await;
    files.put("mixed/visible/c.tgz", b"c").await;
    files.put("mixed/hidden.bin", b"d").await;

    // A user who may read `pdfium/**` and `**/*.tgz` outside `secret/`.
    let username = format!("reader{}@example.com", unique());
    let user_id = srv.create_user(&username, "pw12345678-raw", "reader").await;
    let selector: Value = client
        .post(format!("{}/admin/content-selectors", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": format!("s{}", unique()), "includes": ["pdfium/**", "**/*.tgz"], "excludes": ["secret/**"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role: Value = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": format!("r{}", unique())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = client
        .put(format!(
            "{}/admin/roles/{}/grants",
            srv.base_url, role["id"]
        ))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"repository": name, "action": "read", "selector_id": selector["id"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    client
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role_id": role["id"]}))
        .send()
        .await
        .unwrap();
    let session = srv.login(&username, "pw12345678-raw").await;
    let get = |path: String| {
        session
            .apply(client.get(format!("{}/raw/{name}/{path}", srv.base_url)))
            .header(header::ACCEPT, "application/json")
            .send()
    };
    assert_eq!(get("pdfium/a.tgz".into()).await.unwrap().status(), 200);
    assert_eq!(get("secret/b.tgz".into()).await.unwrap().status(), 404);
    assert_eq!(
        get("secret/b.tgz.sha256".into()).await.unwrap().status(),
        404
    );
    assert_eq!(get("mixed/hidden.bin".into()).await.unwrap().status(), 404);
    let root: Value = get(String::new()).await.unwrap().json().await.unwrap();
    assert_eq!(names(&root), ["mixed/", "pdfium/"]);
    let mixed: Value = get("mixed/".into()).await.unwrap().json().await.unwrap();
    assert_eq!(names(&mixed), ["visible/"]);
}

#[tokio::test]
async fn forms_the_web_ui_and_the_admin_api() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let name = format!("form{}", unique());
    create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "raw", "max_upload_bytes": 64}),
    )
    .await;
    let files = Files::new(&srv, &name).await;

    // A form of two files into a directory, one named the Nexus way.
    let form = reqwest::multipart::Form::new()
        .text("raw.directory", "sub")
        .part(
            "raw.asset1",
            reqwest::multipart::Part::bytes(b"one".to_vec()).file_name("local-name.bin"),
        )
        .text("raw.asset1.filename", "renamed.bin")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"{}".to_vec()).file_name("data.json"),
        );
    let resp = files
        .req(reqwest::Method::POST, "dir/")
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let stored: Value = resp.json().await.unwrap();
    let paths: Vec<&str> = stored["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["dir/sub/renamed.bin", "dir/sub/data.json"]);
    let resp = files.get("dir/sub/data.json").await;
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");

    // All or nothing: one existing file refuses the whole form.
    let form = reqwest::multipart::Form::new()
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"new".to_vec()).file_name("fresh.bin"),
        )
        .part(
            "file2",
            reqwest::multipart::Part::bytes(b"changed".to_vec()).file_name("data.json"),
        );
    let resp = files
        .req(reqwest::Method::POST, "dir/sub/")
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    assert_eq!(files.get("dir/sub/fresh.bin").await.status(), 404);
    // A bad file name, and an upload over the repository's limit.
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(b"x".to_vec()).file_name("../x"),
    );
    let resp = files
        .req(reqwest::Method::POST, "dir/")
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(files.put("big.bin", &[0u8; 65]).await, 413);

    // The web UI uploads and deletes with its session (and CSRF token).
    let (u, p) = srv.admin_password_basic();
    let session = srv.login(&u, &p).await;
    let url = format!(
        "{}/browse/raw/{name}/files?directory=web/uploads",
        srv.base_url
    );
    let form = || {
        reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(b"web".to_vec()).file_name("w.txt"),
        )
    };
    let resp = client
        .post(&url)
        .header("cookie", &session.cookie)
        .multipart(form())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "no CSRF token");
    let resp = session
        .apply(client.post(&url))
        .multipart(form())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert_eq!(files.text("web/uploads/w.txt").await.1, "web");
    let resp = session
        .apply(client.delete(format!(
            "{}/browse/raw/{name}/files?path=web/uploads/w.txt",
            srv.base_url
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(files.get("web/uploads/w.txt").await.status(), 404);

    // The admin API deletes a directory.
    let resp = client
        .delete(format!(
            "{}/admin/repositories/{name}/files?path=dir/",
            srv.base_url
        ))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.json::<Value>().await.unwrap()["deleted"], 2);
    assert_eq!(files.get("dir/").await.status(), 404);

    // Formats: raw is installed with all three kinds, and its options are
    // its own.
    let formats: Value = client
        .get(format!("{}/admin/formats", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let raw = formats
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "raw")
        .expect("raw listed");
    assert_eq!(raw["mount"], "/raw");
    assert_eq!(raw["kinds"], json!(["hosted", "proxy", "group"]));
    for (body, why) in [
        (
            json!({"name": format!("x{}", unique()), "kind": "hosted", "deployment_policy": "read_only"}),
            "a raw option on nuget",
        ),
        (
            json!({"name": format!("x{}", unique()), "kind": "hosted", "format": "raw", "allow_redeploy": true}),
            "nuget's option on raw",
        ),
        (
            json!({"name": format!("x{}", unique()), "kind": "proxy", "format": "raw", "remote_url": "https://example.com/?q=1"}),
            "a remote_url with a query",
        ),
        (
            json!({"name": format!("x{}", unique()), "kind": "hosted", "format": "raw", "max_age_seconds": 5}),
            "max_age_seconds on a hosted repository",
        ),
        (
            json!({"name": format!("x{}", unique()), "kind": "hosted", "format": "raw", "deployment_policy": "sometimes"}),
            "an unknown policy",
        ),
    ] {
        let resp = admin_create(&srv, body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{why}");
    }
}

#[tokio::test]
async fn retention_deletes_old_files_and_keeps_the_newest() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let name = format!("ret{}", unique());
    let repo = create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "raw"}),
    )
    .await;
    let files = Files::new(&srv, &name).await;
    for i in 1..=3 {
        files
            .put(&format!("nightly/build-{i}.zip"), format!("{i}").as_bytes())
            .await;
        files
            .put(&format!("release/r{i}.zip"), format!("r{i}").as_bytes())
            .await;
    }
    // Deployed in order, days apart.
    for (i, days) in [(1, 30), (2, 20), (3, 10)] {
        for path in [
            format!("nightly/build-{i}.zip"),
            format!("release/r{i}.zip"),
        ] {
            sqlx::query(
                "UPDATE raw_file SET updated_at = now() - make_interval(days => $3) WHERE repository_id = $1 AND path = $2",
            )
            .bind(repo["id"].as_i64().unwrap())
            .bind(&path)
            .bind(days)
            .execute(&srv.pool)
            .await
            .unwrap();
        }
    }
    let policy = json!({"version": 1, "rules": [
        {"id": "nightly", "path_prefix": "nightly/", "keep_newest_per_directory": 1},
        {"id": "old", "older_than_days": 25},
    ]});
    let resp = srv
        .client()
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"policy": policy}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let preview: Value = srv
        .client()
        .post(format!(
            "{}/admin/repositories/{name}/retention/preview",
            srv.base_url
        ))
        .basic_auth(&au, Some(&ap))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut doomed: Vec<&str> = preview["file_decisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["path"].as_str().unwrap())
        .collect();
    doomed.sort_unstable();
    assert_eq!(
        doomed,
        [
            "nightly/build-1.zip",
            "nightly/build-2.zip",
            "release/r1.zip"
        ]
    );
    assert_eq!(preview["counts"]["evaluated"], 6);

    // Applied by a run (fenced by its lease, as the worker runs it).
    let run_id = uuid::Uuid::new_v4();
    let decisions: Vec<forge_core::retention::files::FileDecision> = {
        let policy: forge_core::retention::files::FileRetentionPolicy =
            serde_json::from_value(policy.clone()).unwrap();
        let now = forge_db::db_now(&srv.pool).await.unwrap();
        forge_core::retention::files::evaluate_repository(
            &srv.pool,
            repo["id"].as_i64().unwrap(),
            now,
            &policy,
        )
        .await
        .unwrap()
        .0
    };
    let summary = forge_core::retention::files::apply_files(
        &srv.pool,
        repo["id"].as_i64().unwrap(),
        run_id,
        &decisions,
        chrono::Duration::zero(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.deleted, 3);
    assert_eq!(names(&files.json("nightly/").await), ["build-3.zip"]);
    assert_eq!(names(&files.json("release/").await), ["r2.zip", "r3.zip"]);
}
