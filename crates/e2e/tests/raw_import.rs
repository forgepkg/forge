//! E2E: imports of raw repositories from real sources:
//!
//! * a Nexus Repository 3 OSS container (`sonatype/nexus3`): a raw-hosted
//!   repository read through Nexus' asset listing (its REST API), with
//!   nested directories, a file name with a space and a non-ASCII
//!   character, more files than a page of the listing holds and a path
//!   Forge refuses. Every file arrives with its bytes, content type and
//!   creation time (`blobCreated`), its `.sha256` sidecar in Forge is
//!   Nexus' SHA-256, a file Nexus served has Nexus' last download, and its
//!   uploader is the item's. A dry run reports the files, their size and
//!   the refused path and writes nothing; a second run copies only the new
//!   file, a changed one is a conflict, and `overwrite` replaces it;
//! * another Forge: a raw repository read through its JSON listing, with
//!   more files in a directory than a page of it holds; upload times and
//!   last downloads carry over, and a second run downloads nothing;
//! * nginx, a web server without a listing: named paths, a file checked
//!   against its `.sha256` sidecar, one whose sidecar does not match, and
//!   one the server does not have.
//!
//! The conflict policies, resuming a walk and the preflight's refusals are
//! covered against a mock source in `crates/server/tests/raw_import.rs`.
//! Gated behind `forge-e2e`; Nexus takes a minute or two to start.

#![cfg(feature = "forge-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use forge_e2e::{StackBuilder, TestServer};
use forge_server::import::ImportWorker;
use serde_json::{json, Value};
use sha2::Digest;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const NEXUS_IMAGE: &str = "mirror.gcr.io/sonatype/nexus3";
const NEXUS_TAG: &str = "3.70.1";
/// With `NEXUS_SECURITY_RANDOMPASSWORD=false`, Nexus' admin password.
const ADMIN: (&str, &str) = ("admin", "admin123");

const NGINX_IMAGE: &str = "mirror.gcr.io/library/nginx";
const NGINX_TAG: &str = "1.27.5-alpine";

/// More files than a page of Nexus' asset listing holds.
const BULK_FILES: usize = 25;

/// More files in one directory than a page of Forge's listing holds (the
/// import asks for 100).
const FORGE_BULK: usize = 105;

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// `base` with `path` appended, each segment percent-encoded.
fn url_of(base: &str, path: &str) -> String {
    let mut url = url::Url::parse(&format!("{}/", base.trim_end_matches('/'))).unwrap();
    {
        let mut segments = url.path_segments_mut().unwrap();
        segments.pop_if_empty();
        segments.extend(path.split('/'));
    }
    url.to_string()
}

fn time(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

fn assert_recent(t: Option<DateTime<Utc>>) {
    let t = t.expect("a time");
    assert!(
        (Utc::now() - t).num_seconds().abs() < 300,
        "{t} is not about now"
    );
}

// ── Nexus ───────────────────────────────────────────────────────────────────

/// A Nexus with its REST API and repositories at `url`.
struct Nexus {
    url: String,
    client: reqwest::Client,
}

impl Nexus {
    async fn start() -> (Self, testcontainers::ContainerAsync<GenericImage>) {
        let container = GenericImage::new(NEXUS_IMAGE, NEXUS_TAG)
            .with_exposed_port(8081.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Started Sonatype Nexus"))
            .with_env_var("NEXUS_SECURITY_RANDOMPASSWORD", "false")
            .with_env_var(
                "INSTALL4J_ADD_VM_PARAMS",
                "-Xms512m -Xmx1g -XX:MaxDirectMemorySize=1g",
            )
            .with_startup_timeout(Duration::from_secs(600))
            .start()
            .await
            .expect("start nexus (is Docker running?)");
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(8081).await.unwrap();
        let nexus = Nexus {
            url: format!("http://{host}:{port}"),
            client: reqwest::Client::new(),
        };
        for _ in 0..300 {
            let up = nexus
                .client
                .get(format!("{}/service/rest/v1/status/writable", nexus.url))
                .send()
                .await
                .is_ok_and(|r| r.status() == 200);
            if up {
                return (nexus, container);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!("nexus never became writable");
    }

    fn request(&self, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
        self.client
            .request(method, url)
            .basic_auth(ADMIN.0, Some(ADMIN.1))
    }

    async fn create_raw_hosted(&self, name: &str) {
        let body = json!({
            "name": name, "online": true,
            "storage": {"blobStoreName": "default", "strictContentTypeValidation": false, "writePolicy": "allow"},
        });
        let resp = self
            .request(
                reqwest::Method::POST,
                format!("{}/service/rest/v1/repositories/raw/hosted", self.url),
            )
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    }

    fn repository(&self, name: &str) -> String {
        format!("{}/repository/{name}", self.url)
    }

    /// PUT a file into the raw repository `repo`; returns the status.
    async fn put(&self, repo: &str, path: &str, bytes: &[u8]) -> reqwest::StatusCode {
        self.request(reqwest::Method::PUT, url_of(&self.repository(repo), path))
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap()
            .status()
    }

    async fn get(&self, repo: &str, path: &str) -> Vec<u8> {
        let resp = self
            .request(reqwest::Method::GET, url_of(&self.repository(repo), path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "GET {path}");
        resp.bytes().await.unwrap().to_vec()
    }

    /// Every asset of `repo` by path, and how many pages the listing took.
    async fn assets(&self, repo: &str) -> (BTreeMap<String, Value>, usize) {
        let mut assets = BTreeMap::new();
        let mut token: Option<String> = None;
        let mut pages = 0;
        loop {
            let mut url = format!("{}/service/rest/v1/assets?repository={repo}", self.url);
            if let Some(token) = &token {
                url.push_str(&format!("&continuationToken={token}"));
            }
            let page: Value = self
                .request(reqwest::Method::GET, url)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            pages += 1;
            for asset in page["items"].as_array().unwrap() {
                let path = asset["path"].as_str().unwrap();
                assets.insert(
                    path.strip_prefix('/').unwrap_or(path).to_string(),
                    asset.clone(),
                );
            }
            match page["continuationToken"].as_str() {
                Some(next) => token = Some(next.to_string()),
                None => return (assets, pages),
            }
        }
    }
}

// ── Forge ───────────────────────────────────────────────────────────────────

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

async fn raw_hosted(srv: &TestServer, name: &str) -> i64 {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        "/admin/repositories",
        Some(json!({"name": name, "kind": "hosted", "format": "raw"})),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap()
}

/// Start an import into `repo` and run it to its end.
async fn import(srv: &TestServer, repo: &str, body: Value) -> Value {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports"),
        Some(body),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    for _ in 0..1200 {
        ImportWorker::new(srv.state.clone()).tick().await.unwrap();
        let view: Value = admin(
            srv,
            reqwest::Method::GET,
            &format!("/admin/repositories/{repo}/imports/{id}"),
            None,
        )
        .await
        .json()
        .await
        .unwrap();
        if !matches!(view["state"].as_str(), Some("queued" | "running")) {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("import into {repo} did not end");
}

async fn items(srv: &TestServer, repo: &str, id: &Value, state: &str) -> Vec<Value> {
    admin(
        srv,
        reqwest::Method::GET,
        &format!(
            "/admin/repositories/{repo}/imports/{}/items?state={state}&limit=1000",
            id.as_i64().unwrap()
        ),
        None,
    )
    .await
    .json()
    .await
    .unwrap()
}

/// GET `path` of Forge's `repo`: its `Content-Type` and bytes.
async fn fetch(srv: &TestServer, repo: &str, path: &str) -> (String, Vec<u8>) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(url_of(&format!("{}/repository/{repo}", srv.base_url), path))
        .basic_auth(u, Some(p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "GET {repo}/{path}");
    let content_type = resp.headers()["content-type"].to_str().unwrap().to_string();
    (content_type, resp.bytes().await.unwrap().to_vec())
}

async fn put(srv: &TestServer, repo: &str, path: &str, bytes: &[u8]) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .put(url_of(&format!("{}/repository/{repo}", srv.base_url), path))
        .basic_auth(u, Some(p))
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "PUT {path}");
}

/// A file Forge holds: `(updated_at, last_downloaded_at, content_type)`.
async fn stored(
    srv: &TestServer,
    repo_id: i64,
    path: &str,
) -> (DateTime<Utc>, Option<DateTime<Utc>>, String) {
    sqlx::query_as(
        "SELECT updated_at, last_downloaded_at, content_type FROM raw_file WHERE repository_id = $1 AND path = $2",
    )
    .bind(repo_id)
    .bind(path)
    .fetch_optional(&srv.pool)
    .await
    .unwrap()
    .unwrap_or_else(|| panic!("Forge has no {path}"))
}

async fn file_count(srv: &TestServer, repo_id: i64) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM raw_file WHERE repository_id = $1")
        .bind(repo_id)
        .fetch_one(&srv.pool)
        .await
        .unwrap()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_import_from_a_real_nexus() {
    let (nexus, _container) = Nexus::start().await;
    nexus.create_raw_hosted("raw-hosted").await;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert("docs/readme.txt".into(), b"read me\n".to_vec());
    files.insert("docs/guides/a b \u{fc}.txt".into(), b"a guide".to_vec());
    files.insert("deep/a/b/c/data.json".into(), b"{\"a\": 1}".to_vec());
    files.insert("bin/tool-1.0.tgz".into(), b"\x1f\x8b tool".to_vec());
    for i in 0..BULK_FILES {
        files.insert(
            format!("bulk/file-{i:02}.bin"),
            format!("bulk file {i}").into_bytes(),
        );
    }
    for (path, bytes) in &files {
        assert_eq!(nexus.put("raw-hosted", path, bytes).await, 201, "{path}");
    }
    // A segment Forge refuses (over 255 bytes), which Nexus stores.
    let refused = format!("odd/{}.txt", "x".repeat(300));
    assert_eq!(nexus.put("raw-hosted", &refused, b"odd").await, 201);
    // Nexus serves one file before the import: its last download is set.
    nexus.get("raw-hosted", "docs/readme.txt").await;
    let mut assets = BTreeMap::new();
    for _ in 0..60 {
        let (listed, pages) = nexus.assets("raw-hosted").await;
        assert!(pages > 1, "the listing took {pages} page");
        eprintln!(
            "Nexus' asset listing: {} assets in {pages} pages",
            listed.len()
        );
        assets = listed;
        if assets["docs/readme.txt"]["lastDownloaded"].is_string() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(assets.len(), files.len() + 1);
    assert!(assets["docs/readme.txt"]["lastDownloaded"].is_string());

    let srv = StackBuilder::default().start().await;
    let repo_id = raw_hosted(&srv, "raw-copy").await;
    let credentials = |url: String| json!({"url": url, "username": ADMIN.0, "password": ADMIN.1});

    // A dry run: the files, their size and the refused path; nothing is
    // written.
    let mut dry = credentials(nexus.repository("raw-hosted"));
    dry["dry_run"] = json!(true);
    let done = import(&srv, "raw-copy", dry).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["listing"], "assets", "{done}");
    assert!(
        done["source_server"]
            .as_str()
            .is_some_and(|s| s.starts_with("Nexus/")),
        "{done}"
    );
    assert_eq!(done["progress"]["planned"], files.len(), "{done}");
    assert_eq!(done["progress"]["failed"], 1, "{done}");
    let total: usize = files.values().map(Vec::len).sum();
    assert_eq!(done["progress"]["planned_size"], total, "{done}");
    assert_eq!(file_count(&srv, repo_id).await, 0);

    // The import.
    let done = import(
        &srv,
        "raw-copy",
        credentials(nexus.repository("raw-hosted")),
    )
    .await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], files.len(), "{done}");
    assert_eq!(done["progress"]["bytes_copied"], total, "{done}");
    let failed = items(&srv, "raw-copy", &done["id"], "failed").await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["name"], refused.as_str());
    assert!(
        failed[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("longer than 255 bytes")),
        "{failed:?}"
    );
    let imported = items(&srv, "raw-copy", &done["id"], "imported").await;
    assert!(
        imported.iter().all(|i| i["uploader"] == "admin"),
        "{imported:?}"
    );

    // Times first (a download here moves the last download), then bytes,
    // content types and sidecars.
    for path in files.keys() {
        let asset = &assets[path];
        let (updated, downloaded, _) = stored(&srv, repo_id, path).await;
        assert_eq!(
            updated,
            time(asset["blobCreated"].as_str().unwrap()),
            "{path}"
        );
        match asset["lastDownloaded"].as_str() {
            Some(at) => assert_eq!(downloaded, Some(time(at)), "{path}"),
            None => assert_recent(downloaded),
        }
    }
    for (path, bytes) in &files {
        let asset = &assets[path];
        let (content_type, served) = fetch(&srv, "raw-copy", path).await;
        assert_eq!(&served, bytes, "{path}");
        let nexus_type = asset["contentType"].as_str().unwrap();
        if nexus_type != "application/octet-stream" {
            assert_eq!(content_type, nexus_type, "{path}");
        }
        let (_, sidecar) = fetch(&srv, "raw-copy", &format!("{path}.sha256")).await;
        let nexus_sha256 = asset["checksum"]["sha256"].as_str().unwrap();
        assert!(
            String::from_utf8(sidecar)
                .unwrap()
                .starts_with(&nexus_sha256.to_lowercase()),
            "{path}"
        );
        assert_eq!(nexus_sha256.to_lowercase(), sha256(bytes), "{path}");
    }

    // A second run copies only the new file; the changed one is a
    // conflict, decided from Nexus' SHA-256.
    assert_eq!(nexus.put("raw-hosted", "docs/new.txt", b"new").await, 201);
    let rebuilt = b"\x1f\x8b tool, rebuilt".to_vec();
    assert_eq!(
        nexus.put("raw-hosted", "bin/tool-1.0.tgz", &rebuilt).await,
        201
    );
    let done = import(
        &srv,
        "raw-copy",
        credentials(nexus.repository("raw-hosted")),
    )
    .await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 1, "{done}");
    assert_eq!(done["progress"]["conflict"], 1, "{done}");
    assert_eq!(done["progress"]["identical"], files.len() - 1, "{done}");
    assert_eq!(done["progress"]["failed"], 1, "{done}");
    assert_eq!(done["progress"]["bytes_copied"], 3, "{done}");
    assert_eq!(
        fetch(&srv, "raw-copy", "bin/tool-1.0.tgz").await.1,
        files["bin/tool-1.0.tgz"]
    );

    // `overwrite`, in the request form of a Nexus server and repository.
    let mut legacy = credentials(nexus.url.clone());
    legacy["repository"] = json!("raw-hosted");
    legacy["on_conflict"] = json!("overwrite");
    let done = import(&srv, "raw-copy", legacy).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["replaced"], 1, "{done}");
    assert_eq!(done["progress"]["identical"], files.len(), "{done}");
    assert_eq!(fetch(&srv, "raw-copy", "bin/tool-1.0.tgz").await.1, rebuilt);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_import_from_another_forge() {
    let srv = StackBuilder::default().start().await;
    let source_id = raw_hosted(&srv, "raw-source").await;
    let copy_id = raw_hosted(&srv, "raw-forge-copy").await;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert("README.txt".into(), b"read me".to_vec());
    files.insert("docs/a b \u{fc}.txt".into(), b"a guide".to_vec());
    files.insert("deep/a/b/c/data.json".into(), b"{\"a\": 1}".to_vec());
    for i in 0..FORGE_BULK {
        files.insert(
            format!("bulk/file-{i:03}.bin"),
            format!("bulk file {i}").into_bytes(),
        );
    }
    files.insert("bulk/sub/last.txt".into(), b"after the bulk".to_vec());
    for (path, bytes) in &files {
        put(&srv, "raw-source", path, bytes).await;
    }
    // A download in the source: its last download carries over.
    fetch(&srv, "raw-source", "README.txt").await;
    let mut source_downloaded = None;
    for _ in 0..50 {
        source_downloaded = stored(&srv, source_id, "README.txt").await.1;
        if source_downloaded.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(source_downloaded.is_some());

    // The source's times as the import finds them (its downloads from the
    // source are downloads too).
    let mut source_times = BTreeMap::new();
    for path in files.keys() {
        source_times.insert(path.clone(), stored(&srv, source_id, path).await);
    }

    let (user, token) = srv.admin_basic();
    let body = json!({
        "url": format!("{}/repository/raw-source", srv.base_url),
        "username": user,
        "password": token,
    });
    let done = import(&srv, "raw-forge-copy", body.clone()).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["listing"], "directories", "{done}");
    assert_eq!(done["progress"]["imported"], files.len(), "{done}");
    assert_eq!(done["progress"]["failed"], 0, "{done}");

    for (path, source) in &source_times {
        let copy = stored(&srv, copy_id, path).await;
        assert_eq!(copy.0, source.0, "{path}: the upload time");
        assert_eq!(copy.2, source.2, "{path}: the content type");
        match source.1 {
            Some(at) => assert_eq!(copy.1, Some(at), "{path}"),
            None => assert_recent(copy.1),
        }
    }
    for (path, bytes) in &files {
        assert_eq!(
            &fetch(&srv, "raw-forge-copy", path).await.1,
            bytes,
            "{path}"
        );
    }

    // Forge lists each file's SHA-256: a second run downloads nothing.
    let done = import(&srv, "raw-forge-copy", body).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["identical"], files.len(), "{done}");
    assert_eq!(done["progress"]["bytes_copied"], 0, "{done}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_import_of_named_paths_from_a_web_server() {
    let root = "/usr/share/nginx/html/releases/1.0";
    let tool = b"\x1f\x8b the tool".to_vec();
    let notes = b"release notes".to_vec();
    let bad = b"bad bytes".to_vec();
    let container = GenericImage::new(NGINX_IMAGE, NGINX_TAG)
        .with_exposed_port(80.tcp())
        .with_wait_for(WaitFor::Nothing)
        .with_copy_to(format!("{root}/tool.tgz"), tool.clone())
        .with_copy_to(
            format!("{root}/tool.tgz.sha256"),
            format!("{}  tool.tgz\n", sha256(&tool)).into_bytes(),
        )
        .with_copy_to(format!("{root}/notes en \u{fc}.txt"), notes.clone())
        .with_copy_to(format!("{root}/bad.bin"), bad.clone())
        .with_copy_to(
            format!("{root}/bad.bin.sha256"),
            sha256(b"other bytes").into_bytes(),
        )
        // The files' times, which nginx serves as `Last-Modified`.
        .with_cmd(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("touch -d '2024-05-06 07:08:09' {root}/* && exec nginx -g 'daemon off;'"),
        ])
        .start()
        .await
        .expect("start nginx (is Docker running?)");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(80).await.unwrap();
    let url = format!("http://{host}:{port}");
    let client = reqwest::Client::new();
    for _ in 0..100 {
        let up = client
            .get(format!("{url}/releases/1.0/tool.tgz"))
            .send()
            .await
            .is_ok_and(|r| r.status() == 200);
        if up {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let srv = StackBuilder::default().start().await;
    let repo_id = raw_hosted(&srv, "raw-named").await;
    // nginx serves no listing: the import names its paths.
    let resp = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/repositories/raw-named/imports",
        Some(json!({"url": url})),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = json!({
        "url": url,
        "names": [
            "releases/1.0/tool.tgz",
            "releases/1.0/notes en \u{fc}.txt",
            "releases/1.0/bad.bin",
            "releases/1.0/missing.txt",
        ],
    });
    let done = import(&srv, "raw-named", body.clone()).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["listing"], "names", "{done}");
    assert_eq!(done["progress"]["imported"], 2, "{done}");
    assert_eq!(done["progress"]["failed"], 2, "{done}");
    let failed = items(&srv, "raw-named", &done["id"], "failed").await;
    let detail = |path: &str| {
        failed
            .iter()
            .find(|i| i["name"] == path)
            .unwrap_or_else(|| panic!("{path} in {failed:?}"))["detail"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert!(
        detail("releases/1.0/bad.bin").contains("its .sha256 sidecar"),
        "{failed:?}"
    );
    assert_eq!(
        detail("releases/1.0/missing.txt"),
        "the source has no file at this path"
    );

    for (path, bytes, nginx_type) in [
        ("releases/1.0/tool.tgz", &tool, "application/octet-stream"),
        ("releases/1.0/notes en \u{fc}.txt", &notes, "text/plain"),
    ] {
        let (updated, downloaded, _) = stored(&srv, repo_id, path).await;
        assert_eq!(updated, time("2024-05-06T07:08:09Z"), "{path}");
        assert_recent(downloaded);
        let (content_type, served) = fetch(&srv, "raw-named", path).await;
        assert_eq!(&served, bytes, "{path}");
        if nginx_type != "application/octet-stream" {
            assert_eq!(content_type, nginx_type, "{path}");
        }
    }

    // A second run: the file with a sidecar is identical without a download,
    // the one without is downloaded and compared.
    let done = import(&srv, "raw-named", body).await;
    assert_eq!(done["progress"]["identical"], 2, "{done}");
    assert_eq!(done["progress"]["bytes_copied"], notes.len(), "{done}");
}
