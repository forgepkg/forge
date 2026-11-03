//! Imports of apt repositories (`crates/server/src/import/apt.rs`) with the
//! real worker, from:
//!
//! * another Forge's apt hosted repository: its `InRelease` is checked
//!   against the public key the import is given (a key that did not sign it
//!   is refused before anything is stored), its indexes are read from their
//!   `by-hash` copies, the packages of two architectures and an `all` one
//!   arrive with their bytes in the components they were in; a second run
//!   downloads nothing, and a newer version comes alone;
//! * a static repository a mock web server serves (`Release` and
//!   `Release.gpg`, as `apt-ftparchive` and `gpg -abs` make them, with
//!   Basic authentication): a package keeps the component the source lists
//!   it in, whatever its `Section` says; a `Packages` entry whose size or
//!   SHA-256 does not match its `.deb` fails that item, as do one the
//!   source does not have and one whose `Filename` is outside the
//!   repository, and the import completes; a `Filename` that starts with
//!   `./` (`dpkg-scanpackages ./pool`) is resolved below the repository; an index that does not match
//!   `Release` fails the scan; a version Forge holds with other bytes
//!   follows `on_conflict`, decided without a download; a dry run writes
//!   nothing;
//! * the preflight's refusals.
//!
//! A real Nexus and a static repository made with `dpkg-scanpackages` and
//! `apt-ftparchive`, then `apt-get install` from Forge, run in
//! `crates/e2e/tests/import.rs`.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use common::{unique, ServerOpts, TestServer};
use forge_server::import::ImportWorker;
use forge_server::indexes::signing::{self, Key};
use serde_json::{json, Value};
use sha2::Digest;

const USER: &str = "migrator";
const PASSWORD: &str = "source-secret";

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

// ── Packages ────────────────────────────────────────────────────────────────

/// A binary package of `control`, its control member gzip-compressed.
fn deb_of(control: &str) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(control.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "./control", control.as_bytes())
        .unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar.into_inner().unwrap()).unwrap();
    let control_tar = gz.finish().unwrap();
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in [
        ("debian-binary", b"2.0\n".to_vec()),
        ("control.tar.gz", control_tar),
        ("data.tar", control.as_bytes().repeat(3)),
    ] {
        out.extend_from_slice(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                name,
                0,
                0,
                0,
                100644,
                data.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

fn control(name: &str, version: &str, arch: &str, section: &str, note: &str) -> String {
    format!(
        "Package: {name}\nVersion: {version}\nArchitecture: {arch}\n\
         Maintainer: Forge <forge@example.com>\nSection: {section}\n\
         Description: {name} for the import tests\n {note}\n"
    )
}

fn deb(name: &str, version: &str, arch: &str, section: &str) -> Vec<u8> {
    deb_of(&control(name, version, arch, section, "It greets."))
}

// ── A static repository, served by a mock web server ────────────────────────

/// What the mock web server serves below `/debian/`, and what it saw.
#[derive(Default)]
struct Served {
    files: BTreeMap<String, Vec<u8>>,
    /// GETs of each path.
    gets: HashMap<String, usize>,
}

#[derive(Clone)]
struct Mirror {
    url: String,
    state: Arc<Mutex<Served>>,
}

async fn serve(State(state): State<Arc<Mutex<Served>>>, req: Request) -> Response {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASSWORD}"))
    );
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .is_some_and(|v| v.as_bytes() == expected.as_bytes());
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"mirror\"")],
        )
            .into_response();
    }
    let path = req.uri().path();
    let Some(path) = path.strip_prefix("/debian/") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = percent_encoding::percent_decode_str(path)
        .decode_utf8_lossy()
        .into_owned();
    let mut state = state.lock().unwrap();
    *state.gets.entry(path.clone()).or_default() += 1;
    match state.files.get(&path) {
        Some(bytes) => bytes.clone().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

impl Mirror {
    async fn start() -> Self {
        let state = Arc::new(Mutex::new(Served::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/debian", listener.local_addr().unwrap());
        let app = axum::Router::new()
            .fallback(serve)
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Mirror { url, state }
    }

    fn put(&self, path: &str, bytes: Vec<u8>) {
        self.state.lock().unwrap().files.insert(path.into(), bytes);
    }

    fn remove(&self, path: &str) {
        self.state.lock().unwrap().files.remove(path);
    }

    fn gets(&self, path: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .gets
            .get(path)
            .copied()
            .unwrap_or(0)
    }

    /// GETs of the pool's files.
    fn pool_gets(&self) -> usize {
        let state = self.state.lock().unwrap();
        state
            .gets
            .iter()
            .filter(|(path, _)| path.starts_with("pool/"))
            .map(|(_, n)| n)
            .sum()
    }

    /// The `Packages` index (gzip) of `component` and `arch`, its entries
    /// `stanzas`.
    fn index(&self, component: &str, arch: &str, stanzas: &[String]) {
        let text = stanzas.join("\n");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(text.as_bytes()).unwrap();
        self.put(
            &format!("dists/bookworm/{component}/binary-{arch}/Packages.gz"),
            gz.finish().unwrap(),
        );
    }

    /// `Release`, listing every index file, and `Release.gpg` signed by
    /// `key` (none without one).
    fn release(&self, key: Option<&Key>) {
        let files: Vec<(String, Vec<u8>)> = {
            let state = self.state.lock().unwrap();
            state
                .files
                .iter()
                .filter_map(|(path, bytes)| {
                    let rest = path.strip_prefix("dists/bookworm/")?;
                    (rest.contains('/')).then(|| (rest.to_string(), bytes.clone()))
                })
                .collect()
        };
        let mut release = String::from(
            "Origin: Static\nLabel: Static\nSuite: stable\nCodename: bookworm\n\
             Architectures: amd64 arm64\nComponents: main contrib\nSHA256:\n",
        );
        for (path, bytes) in &files {
            release.push_str(&format!(" {} {} {path}\n", sha256(bytes), bytes.len()));
        }
        if let Some(key) = key {
            let signature =
                signing::sign_detached(std::slice::from_ref(key), release.as_bytes()).unwrap();
            self.put("dists/bookworm/Release.gpg", signature.into_bytes());
        }
        self.put("dists/bookworm/Release", release.into_bytes());
    }
}

/// A `Packages` entry of `control` at `filename`, listing `size` and
/// `sha256`.
fn stanza(control: &str, filename: &str, size: usize, sha256: &str) -> String {
    format!("{control}Filename: {filename}\nSize: {size}\nSHA256: {sha256}\n")
}

// ── Forge ───────────────────────────────────────────────────────────────────

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

/// An apt hosted repository of distribution `bookworm`.
async fn apt_repo(srv: &TestServer, name: &str) {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        "/admin/repositories",
        Some(json!({
            "name": name, "kind": "hosted", "format": "apt",
            "options": {"distribution": "bookworm"},
        })),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
}

/// Upload `package` to `repo` as Nexus' clients do.
async fn upload(srv: &TestServer, repo: &str, package: &[u8]) {
    let resp = srv
        .client()
        .post(format!("{}/repository/{repo}/", srv.base_url))
        .basic_auth(
            srv.admin_user.clone().unwrap(),
            Some(srv.admin_token().await),
        )
        .header("content-type", "multipart/form-data")
        .body(package.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
}

/// GET `path` of `repo`: status and body.
async fn fetch(srv: &TestServer, repo: &str, path: &str) -> (u16, Vec<u8>) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}/repository/{repo}/{path}", srv.base_url))
        .basic_auth(u, Some(p))
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.bytes().await.unwrap().to_vec())
}

async fn text(srv: &TestServer, repo: &str, path: &str) -> String {
    let (status, body) = fetch(srv, repo, path).await;
    assert_eq!(status, 200, "GET {repo}/{path}");
    String::from_utf8(body).unwrap()
}

/// The armored public key of `repo`.
async fn public_key(srv: &TestServer, repo: &str) -> String {
    text(srv, repo, "key.asc").await
}

async fn request(srv: &TestServer, repo: &str, body: Value) -> reqwest::Response {
    admin(
        srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports"),
        Some(body),
    )
    .await
}

async fn get_import(srv: &TestServer, repo: &str, id: i64) -> Value {
    let resp = admin(
        srv,
        reqwest::Method::GET,
        &format!("/admin/repositories/{repo}/imports/{id}"),
        None,
    )
    .await;
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

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

/// Start an import of `body` into `repo` and run it to its end.
async fn import(srv: &TestServer, repo: &str, body: Value) -> Value {
    let resp = request(srv, repo, body).await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["state"], "queued");
    run(srv, repo, view["id"].as_i64().unwrap()).await
}

async fn items(srv: &TestServer, repo: &str, id: i64) -> Vec<Value> {
    let resp = admin(
        srv,
        reqwest::Method::GET,
        &format!("/admin/repositories/{repo}/imports/{id}/items?limit=1000"),
        None,
    )
    .await;
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

fn item<'a>(items: &'a [Value], name: &str) -> &'a Value {
    items
        .iter()
        .find(|i| i["name"] == name)
        .unwrap_or_else(|| panic!("{name} in {items:?}"))
}

/// The package names a `Packages` index of `repo` lists.
async fn listed(srv: &TestServer, repo: &str, component: &str, arch: &str) -> Vec<String> {
    let (status, body) = fetch(
        srv,
        repo,
        &format!("dists/bookworm/{component}/binary-{arch}/Packages"),
    )
    .await;
    if status == 404 {
        return Vec::new();
    }
    assert_eq!(status, 200);
    String::from_utf8(body)
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_prefix("Package: ").map(str::to_string))
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn apt_import_from_another_forge_checks_its_release_and_keeps_components() {
    let srv = forge().await;
    let n = unique();
    let (src, dst, other) = (
        format!("apt-src-{n}"),
        format!("apt-dst-{n}"),
        format!("apt-other-{n}"),
    );
    for repo in [&src, &dst, &other] {
        apt_repo(&srv, repo).await;
    }
    let hello_amd64 = deb("hello", "1.0-1", "amd64", "utils");
    let hello_arm64 = deb("hello", "1.0-1", "arm64", "utils");
    let tool = deb("tool", "2.0", "all", "contrib/net");
    for package in [&hello_amd64, &hello_arm64, &tool] {
        upload(&srv, &src, package).await;
    }
    let (user, token) = srv.admin_basic();
    let source = json!({
        "url": format!("{}/repository/{src}/", srv.base_url),
        "public_key": public_key(&srv, &src).await,
        "username": user, "password": token,
    });

    // A key that did not sign the source's Release: refused, nothing stored.
    let mut wrong = source.clone();
    wrong["public_key"] = json!(public_key(&srv, &other).await);
    let resp = request(&srv, &dst, wrong).await;
    assert_eq!(resp.status(), 400);
    let refusal = resp.text().await.unwrap();
    assert!(
        refusal.contains("is not signed by the public key"),
        "{refusal}"
    );

    let done = import(&srv, &dst, source.clone()).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["listing"], "release", "{done}");
    // The repository's own distribution, by default.
    assert_eq!(done["distribution"], "bookworm", "{done}");
    // tool:all is listed under every architecture, and copied once.
    assert_eq!(done["progress"]["imported"], 3, "{done}");
    assert_eq!(done["progress"]["failed"], 0, "{done}");
    let id = done["id"].as_i64().unwrap();
    let found = items(&srv, &dst, id).await;
    assert_eq!(item(&found, "hello:amd64")["version"], "1.0-1");
    assert_eq!(item(&found, "tool:all")["size"], tool.len());

    // The same components, and the same bytes.
    assert_eq!(listed(&srv, &dst, "main", "amd64").await, ["hello"]);
    assert_eq!(listed(&srv, &dst, "main", "arm64").await, ["hello"]);
    assert_eq!(listed(&srv, &dst, "contrib", "amd64").await, ["tool"]);
    assert_eq!(
        fetch(&srv, &dst, "pool/main/h/hello/hello_1.0-1_arm64.deb")
            .await
            .1,
        hello_arm64
    );
    assert_eq!(
        fetch(&srv, &dst, "pool/contrib/t/tool/tool_2.0_all.deb")
            .await
            .1,
        tool
    );

    // A second run downloads nothing.
    let again = import(&srv, &dst, source.clone()).await;
    assert_eq!(again["state"], "completed", "{again}");
    assert_eq!(again["progress"]["identical"], 3, "{again}");
    assert_eq!(again["progress"]["bytes_copied"], 0, "{again}");

    // A newer version comes alone.
    let newer = deb("hello", "1.1-1", "amd64", "utils");
    upload(&srv, &src, &newer).await;
    let last = import(&srv, &dst, source).await;
    assert_eq!(last["state"], "completed", "{last}");
    assert_eq!(last["progress"]["imported"], 1, "{last}");
    assert_eq!(last["progress"]["identical"], 3, "{last}");
    assert_eq!(last["progress"]["bytes_copied"], newer.len(), "{last}");
    assert_eq!(
        fetch(&srv, &dst, "pool/main/h/hello/hello_1.1-1_amd64.deb")
            .await
            .1,
        newer
    );
}

#[tokio::test]
async fn apt_import_from_a_static_repository_checks_every_package_and_index() {
    let srv = forge().await;
    let mirror = Mirror::start().await;
    let key = Key::generate("Static <static@example.com>").unwrap();
    let armored = key.info().unwrap().public_key;

    // `moved`: in main at the source, though its Section names contrib.
    let moved_control = control("moved", "1.0", "amd64", "contrib/net", "Moved.");
    let moved = deb_of(&moved_control);
    let fine = deb("fine", "1:2.0-1", "arm64", "utils");
    let fine_control = control("fine", "1:2.0-1", "arm64", "utils", "It greets.");
    let short = deb("short", "1.0", "amd64", "utils");
    let corrupt = deb("corrupt", "1.0", "amd64", "utils");
    let gone = deb("gone", "1.0", "amd64", "utils");
    let paths = [
        ("moved", "pool/main/m/moved/moved_1.0_amd64.deb"),
        ("fine", "pool/main/f/fine/fine_2.0-1_arm64.deb"),
        ("short", "pool/main/s/short/short_1.0_amd64.deb"),
        ("corrupt", "pool/main/c/corrupt/corrupt_1.0_amd64.deb"),
    ];
    let pool: HashMap<&str, &str> = paths.into_iter().collect();
    mirror.put(pool["moved"], moved.clone());
    mirror.put(pool["fine"], fine.clone());
    mirror.put(pool["short"], short.clone());
    mirror.put(pool["corrupt"], corrupt.clone());
    mirror.index(
        "main",
        "amd64",
        &[
            stanza(&moved_control, pool["moved"], moved.len(), &sha256(&moved)),
            stanza(
                &control("short", "1.0", "amd64", "utils", "It greets."),
                pool["short"],
                short.len() + 1,
                &sha256(&short),
            ),
            stanza(
                &control("corrupt", "1.0", "amd64", "utils", "It greets."),
                pool["corrupt"],
                corrupt.len(),
                &sha256(b"other bytes"),
            ),
            stanza(
                &control("gone", "1.0", "amd64", "utils", "It greets."),
                "pool/main/g/gone/gone_1.0_amd64.deb",
                gone.len(),
                &sha256(&gone),
            ),
            stanza(
                &control("outside", "1.0", "amd64", "utils", "It greets."),
                "../outside_1.0_amd64.deb",
                10,
                &sha256(b"x"),
            ),
        ],
    );
    // `fine`'s Filename starts with `./`, as `dpkg-scanpackages ./pool`
    // writes it: apt resolves it below the repository.
    let dotted = format!("./{}", pool["fine"]);
    mirror.index(
        "main",
        "arm64",
        &[stanza(&fine_control, &dotted, fine.len(), &sha256(&fine))],
    );
    mirror.release(Some(&key));

    let dst = format!("apt-static-{}", unique());
    apt_repo(&srv, &dst).await;
    let source = json!({
        "url": mirror.url, "distribution": "bookworm", "public_key": armored,
        "username": USER, "password": PASSWORD,
    });

    // A dry run decides every package from the index and downloads none.
    let mut dry = source.clone();
    dry["dry_run"] = json!(true);
    let planned = import(&srv, &dst, dry).await;
    assert_eq!(planned["state"], "completed", "{planned}");
    assert_eq!(planned["progress"]["planned"], 5, "{planned}");
    assert_eq!(planned["progress"]["failed"], 1, "{planned}");
    assert_eq!(mirror.pool_gets(), 0);
    assert!(listed(&srv, &dst, "main", "amd64").await.is_empty());

    let done = import(&srv, &dst, source.clone()).await;
    // The packages that fail are items of their own: the import completes.
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 2, "{done}");
    assert_eq!(done["progress"]["failed"], 4, "{done}");
    let found = items(&srv, &dst, done["id"].as_i64().unwrap()).await;
    let detail = |name: &str| item(&found, name)["detail"].as_str().unwrap().to_string();
    assert!(
        detail("short:amd64").contains("the index lists"),
        "{found:?}"
    );
    assert!(detail("corrupt:amd64").contains("SHA-256"), "{found:?}");
    assert!(detail("gone:amd64").contains("has no package"), "{found:?}");
    assert!(
        detail("outside:amd64").contains("no path below"),
        "{found:?}"
    );
    assert_eq!(item(&found, "fine:arm64")["version"], "1:2.0-1");
    assert_eq!(item(&found, "fine:arm64")["state"], "imported", "{found:?}");
    assert_eq!(mirror.gets(pool["fine"]), 1);

    // `moved` stays in main, where the source lists it.
    assert_eq!(listed(&srv, &dst, "main", "amd64").await, ["moved"]);
    assert!(listed(&srv, &dst, "contrib", "amd64").await.is_empty());
    assert_eq!(listed(&srv, &dst, "main", "arm64").await, ["fine"]);
    assert_eq!(
        fetch(&srv, &dst, "pool/main/m/moved/moved_1.0_amd64.deb")
            .await
            .1,
        moved
    );
    assert_eq!(
        fetch(&srv, &dst, "pool/main/f/fine/fine_1:2.0-1_arm64.deb")
            .await
            .1,
        fine
    );

    // The source rebuilt `moved` with other bytes under the same version:
    // a conflict, decided from the index without a download.
    let rebuilt_control = control("moved", "1.0", "amd64", "contrib/net", "Rebuilt.");
    let rebuilt = deb_of(&rebuilt_control);
    mirror.put(pool["moved"], rebuilt.clone());
    mirror.remove(pool["corrupt"]);
    mirror.index(
        "main",
        "amd64",
        &[stanza(
            &rebuilt_control,
            pool["moved"],
            rebuilt.len(),
            &sha256(&rebuilt),
        )],
    );
    mirror.release(Some(&key));
    let moved_gets = mirror.gets(pool["moved"]);
    let skipped = import(&srv, &dst, source.clone()).await;
    assert_eq!(skipped["state"], "completed", "{skipped}");
    assert_eq!(skipped["progress"]["conflict"], 1, "{skipped}");
    assert_eq!(skipped["progress"]["identical"], 1, "{skipped}");
    assert_eq!(mirror.gets(pool["moved"]), moved_gets);
    let mut overwrite = source.clone();
    overwrite["on_conflict"] = json!("overwrite");
    let replaced = import(&srv, &dst, overwrite).await;
    assert_eq!(replaced["progress"]["replaced"], 1, "{replaced}");
    assert_eq!(
        fetch(&srv, &dst, "pool/main/m/moved/moved_1.0_amd64.deb")
            .await
            .1,
        rebuilt
    );
    let mut fail = source.clone();
    fail["on_conflict"] = json!("fail");
    mirror.put(pool["moved"], moved.clone());
    mirror.index(
        "main",
        "amd64",
        &[stanza(
            &moved_control,
            pool["moved"],
            moved.len(),
            &sha256(&moved),
        )],
    );
    mirror.release(Some(&key));
    let failed = import(&srv, &dst, fail).await;
    assert_eq!(failed["state"], "failed", "{failed}");
    assert!(
        failed["last_error"]
            .as_str()
            .unwrap()
            .contains("moved:amd64 1.0"),
        "{failed}"
    );

    // An index that does not match Release fails the scan.
    mirror.index(
        "main",
        "arm64",
        &[stanza(
            &fine_control,
            pool["fine"],
            fine.len(),
            &sha256(&fine),
        )],
    );
    let mut stale =
        mirror.state.lock().unwrap().files["dists/bookworm/main/binary-arm64/Packages.gz"].clone();
    stale.extend_from_slice(b"\0");
    mirror.release(Some(&key));
    mirror.put("dists/bookworm/main/binary-arm64/Packages.gz", stale);
    let broken = import(&srv, &dst, source.clone()).await;
    assert_eq!(broken["state"], "failed", "{broken}");
    let error = broken["last_error"].as_str().unwrap();
    assert!(error.contains("does not match Release"), "{error}");

    // A Release without a signature, when the import has a key: refused.
    mirror.remove("dists/bookworm/Release.gpg");
    let resp = request(&srv, &dst, source.clone()).await;
    assert_eq!(resp.status(), 400);
    let refusal = resp.text().await.unwrap();
    assert!(refusal.contains("is not signed"), "{refusal}");
    // Without the key, it is read as it is.
    let mut unsigned = source;
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("public_key")
        .unwrap();
    let resp = request(&srv, &dst, unsigned).await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
}

#[tokio::test]
async fn apt_import_preflight_refusals() {
    let srv = forge().await;
    let mirror = Mirror::start().await;
    mirror.release(None);
    let n = unique();
    let dst = format!("apt-refusals-{n}");
    apt_repo(&srv, &dst).await;
    let base = json!({"url": mirror.url, "username": USER, "password": PASSWORD});
    let refused = |body: Value, status: u16, says: &'static str| {
        let srv = &srv;
        let dst = &dst;
        async move {
            let resp = request(srv, dst, body.clone()).await;
            assert_eq!(resp.status(), status, "{body}");
            let text = resp.text().await.unwrap();
            assert!(text.contains(says), "{body}: {text}");
        }
    };
    let with = |field: &str, value: Value| {
        let mut body = base.clone();
        body[field] = value;
        body
    };
    refused(with("names", json!(["hello"])), 400, "leave names out").await;
    refused(
        with("distribution", json!("../x")),
        400,
        "not a distribution",
    )
    .await;
    refused(with("public_key", json!("not a key")), 400, "public_key").await;
    refused(
        with("distribution", json!("trixie")),
        400,
        "is trixie one of its distributions",
    )
    .await;
    refused(
        with("password", json!("wrong")),
        400,
        "refused the credentials",
    )
    .await;
    // The repository's own distribution, whose Release is served: accepted.
    let resp = request(&srv, &dst, base.clone()).await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let queued: Value = resp.json().await.unwrap();

    // Frozen after the import was queued: the run fails, writing nothing,
    // and a further import is refused.
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{dst}"),
        Some(json!({"deployment_policy": "read_only"})),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let done = run(&srv, &dst, queued["id"].as_i64().unwrap()).await;
    assert_eq!(done["state"], "failed", "{done}");
    assert!(
        done["last_error"].as_str().unwrap().contains("read_only"),
        "{done}"
    );
    assert!(items(&srv, &dst, queued["id"].as_i64().unwrap())
        .await
        .is_empty());
    refused(base.clone(), 409, "read_only").await;

    // distribution and public_key are apt's alone.
    let raw = format!("raw-{n}");
    let resp = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/repositories",
        Some(json!({"name": raw, "kind": "hosted", "format": "raw"})),
    )
    .await;
    assert_eq!(resp.status(), 201);
    let resp = request(&srv, &raw, with("distribution", json!("bookworm"))).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("apt repositories only"));
}
