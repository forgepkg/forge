//! Integration tests of apt repositories (`/repository/{repo}`): uploads
//! (Nexus' raw body, a form, `PUT`), the redeploy policy, the signed indexes
//! (`InRelease`, `Release.gpg`, `Packages` and their `by-hash` copies),
//! downloads and deletes from the pool, path traversal, package selectors,
//! signing key rotation and import, the format's options, and proxies of a
//! mock mirror (files served unchanged, packages checked against the
//! upstream's index, the cache while the upstream is down). Requires Docker
//! (Postgres + versitygw via the shared harness), or
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`.
//!
//! The same flows run with the real `apt-get` and `gpgv` in CI
//! (`.github/scripts/apt-e2e.sh`).

mod common;

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::response::IntoResponse;
use common::{unique, TestServer};
use pgp::composed::{CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey};
use serde_json::{json, Value};
use sha2::Digest as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// A binary package of `control` (a whole control file), its control
/// member gzip-compressed, with a small data member.
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

fn deb(name: &str, version: &str, arch: &str, section: &str) -> Vec<u8> {
    deb_of(&format!(
        "Package: {name}\nVersion: {version}\nArchitecture: {arch}\nMaintainer: Forge <forge@example.com>\n\
         Section: {section}\nDepends: libc6 (>= 2.34)\nDescription: {name} for the tests\n It greets.\n"
    ))
}

/// `POST /admin/repositories` with `body`: status and body.
async fn admin_create(srv: &TestServer, body: Value) -> (StatusCode, String) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap();
    (resp.status(), resp.text().await.unwrap())
}

async fn create(srv: &TestServer, body: Value) -> Value {
    let (status, text) = admin_create(srv, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "create {body}: {text}");
    serde_json::from_str(&text).unwrap()
}

/// An admin API call with the admin's token: status and body.
async fn admin(
    srv: &TestServer,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, String) {
    let (u, p) = srv.admin_basic();
    let mut rb = srv
        .client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(&u, Some(&p));
    if let Some(body) = body {
        rb = rb.json(&body);
    }
    let resp = rb.send().await.unwrap();
    (resp.status(), resp.text().await.unwrap())
}

/// A client of one repository, authenticated with an API token.
struct Apt {
    base: String,
    client: reqwest::Client,
    user: String,
    token: String,
}

impl Apt {
    async fn new(srv: &TestServer, repo: &str) -> Self {
        Apt {
            base: format!("{}/repository/{repo}", srv.base_url),
            client: srv.client(),
            user: srv.admin_user.clone().unwrap(),
            token: srv.admin_token().await,
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}/{path}", self.base))
            .basic_auth(&self.user, Some(&self.token))
    }

    async fn get(&self, path: &str) -> (StatusCode, Vec<u8>) {
        let resp = self.req(reqwest::Method::GET, path).send().await.unwrap();
        (resp.status(), resp.bytes().await.unwrap().to_vec())
    }

    async fn text(&self, path: &str) -> String {
        let (status, body) = self.get(path).await;
        assert_eq!(status, StatusCode::OK, "GET {path}");
        String::from_utf8(body).unwrap()
    }

    /// Nexus' upload: the package as the body of a POST to the repository,
    /// whatever its content type says.
    async fn post(&self, package: &[u8]) -> (StatusCode, String) {
        let resp = self
            .req(reqwest::Method::POST, "")
            .header("content-type", "multipart/form-data")
            .body(package.to_vec())
            .send()
            .await
            .unwrap();
        (resp.status(), resp.text().await.unwrap())
    }
}

/// The repository's public keys, from the admin API.
async fn keys(srv: &TestServer, repo: &str) -> Vec<Value> {
    let (status, text) = admin(
        srv,
        reqwest::Method::GET,
        &format!("/admin/repositories/{repo}/signing-keys"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn public(key: &Value) -> SignedPublicKey {
    SignedPublicKey::from_string(key["public_key"].as_str().unwrap())
        .unwrap()
        .0
}

/// `InRelease`'s signatures, and the `Release` text they sign.
fn in_release(text: &str) -> (CleartextSignedMessage, String) {
    let (message, _) = CleartextSignedMessage::from_string(text).unwrap();
    let signed = message.signed_text().replace("\r\n", "\n");
    (message, signed)
}

/// `Release`'s `SHA256` entries: (sha256, size, path).
fn release_entries(release: &str) -> Vec<(String, u64, String)> {
    release
        .split("SHA256:\n")
        .nth(1)
        .unwrap()
        .lines()
        .take_while(|l| l.starts_with(' '))
        .map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            (
                parts[0].to_string(),
                parts[1].parse().unwrap(),
                parts[2].to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn options_are_checked() {
    let srv = common::start().await;
    let name = format!("aptopt{}", unique());
    let (status, text) = admin_create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "apt"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(text.contains("distribution"), "{text}");
    for (options, why) in [
        (json!({"distribution": "a/b"}), "distribution"),
        (
            json!({"distribution": "bookworm", "codename": "x"}),
            "no option",
        ),
    ] {
        let (status, text) = admin_create(
            &srv,
            json!({"name": name, "kind": "hosted", "format": "apt", "options": options}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{options}");
        assert!(text.contains(why), "{text}");
    }
    // A proxy has no package delay: its indexes are the upstream's.
    let (status, text) = admin_create(
        &srv,
        json!({"name": name, "kind": "proxy", "format": "apt", "remote_url": "http://127.0.0.1:9/debian",
               "package_delay_seconds": 3600, "options": {"distribution": "bookworm"}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(text.contains("package_delay_seconds"), "{text}");
    // Other formats have no options.
    let (status, _) = admin_create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "raw", "options": {"distribution": "x"}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let repo = create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "apt", "options": {"distribution": " bookworm "}}),
    )
    .await;
    assert_eq!(repo["options"], json!({"distribution": "bookworm"}));
    // An update changes it; a required option cannot be cleared.
    let (status, text) = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{name}"),
        Some(json!({"options": {"distribution": "trixie"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains("\"distribution\":\"trixie\""), "{text}");
    let (status, _) = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{name}"),
        Some(json!({"options": {"distribution": null}})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The formats listing names the option.
    let (_, formats) = admin(&srv, reqwest::Method::GET, "/admin/formats", None).await;
    let formats: Value = serde_json::from_str(&formats).unwrap();
    let apt = formats
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "apt")
        .unwrap();
    assert_eq!(apt["options"][0]["name"], "distribution");
    assert_eq!(apt["signed_indexes"], true);
    assert_eq!(apt["kinds"], json!(["hosted", "proxy"]));
}

#[tokio::test]
async fn hosted_repositories_publish_signed_indexes() {
    let srv = common::start().await;
    let name = format!("apt{}", unique());
    create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "apt", "options": {"distribution": "bookworm"}}),
    )
    .await;
    let apt = Apt::new(&srv, &name).await;

    // Nexus' upload, a form and a PUT.
    let hello = deb("hello", "1.0-1", "amd64", "utils");
    let (status, text) = apt.post(&hello).await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    let form = reqwest::multipart::Form::new().part(
        "package",
        reqwest::multipart::Part::bytes(deb("hello", "1.0-1", "arm64", "utils"))
            .file_name("hello_1.0-1_arm64.deb"),
    );
    let resp = apt
        .req(reqwest::Method::POST, "")
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let tool = deb("tool", "2:3.0~rc1", "all", "contrib/net");
    let resp = apt
        .req(reqwest::Method::PUT, "tool.deb")
        .body(tool.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    // A redeploy is refused; so is what is not a package.
    assert_eq!(apt.post(&hello).await.0, StatusCode::CONFLICT);
    let (status, text) = apt.post(b"not a package").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    let (status, _) = apt
        .post(&deb_of(
            "Package: Bad_Name\nVersion: 1\nArchitecture: amd64\n",
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // InRelease is Release, signed with the repository's key.
    let keys = keys(&srv, &name).await;
    assert_eq!(keys.len(), 1);
    let key = public(&keys[0]);
    let (message, signed) = in_release(&apt.text("dists/bookworm/InRelease").await);
    message.verify(&key).unwrap();
    let release = apt.text("dists/bookworm/Release").await;
    assert_eq!(signed.trim_end(), release.trim_end());
    assert!(release.contains("Suite: bookworm\n"), "{release}");
    assert!(
        release.contains("Architectures: all amd64 arm64\n"),
        "{release}"
    );
    assert!(release.contains("Components: contrib main\n"), "{release}");
    assert!(release.contains("Acquire-By-Hash: yes\n"), "{release}");
    let (status, detached) = apt.get("dists/bookworm/Release.gpg").await;
    assert_eq!(status, StatusCode::OK);
    let (signatures, _) = DetachedSignature::from_armor_many(&detached[..]).unwrap();
    let signatures: Vec<DetachedSignature> = signatures.collect::<Result<_, _>>().unwrap();
    assert_eq!(signatures.len(), 1);
    signatures[0].verify(&key, release.as_bytes()).unwrap();

    // Every file Release names is there, by name and by hash.
    let entries = release_entries(&release);
    assert_eq!(entries.len(), 2 * 3 * 3);
    for (sha, size, path) in &entries {
        let (status, named) = apt.get(&format!("dists/bookworm/{path}")).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(
            (sha256(&named), named.len() as u64),
            (sha.clone(), *size),
            "{path}"
        );
        let dir = path.rsplit_once('/').unwrap().0;
        let (status, by_hash) = apt
            .get(&format!("dists/bookworm/{dir}/by-hash/SHA256/{sha}"))
            .await;
        assert_eq!(status, StatusCode::OK, "{path} by hash");
        assert_eq!(by_hash, named);
    }
    let packages = apt.text("dists/bookworm/main/binary-amd64/Packages").await;
    assert!(packages.contains("Package: hello\n"), "{packages}");
    assert!(
        packages.contains(&format!(
            "Filename: pool/main/h/hello/hello_1.0-1_amd64.deb\nSize: {}\nSHA256: {}\n",
            hello.len(),
            sha256(&hello)
        )),
        "{packages}"
    );
    let contrib = apt
        .text("dists/bookworm/contrib/binary-amd64/Packages")
        .await;
    assert!(
        contrib.contains("Filename: pool/contrib/t/tool/tool_2:3.0~rc1_all.deb\n"),
        "{contrib}"
    );
    let mut gz = Vec::new();
    flate2::read::GzDecoder::new(
        &apt.get("dists/bookworm/main/binary-amd64/Packages.gz")
            .await
            .1[..],
    )
    .read_to_end(&mut gz)
    .unwrap();
    assert_eq!(String::from_utf8(gz).unwrap(), packages);

    // Downloads from the pool, at the package's path only.
    let (status, body) = apt.get("pool/main/h/hello/hello_1.0-1_amd64.deb").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, hello);
    let (status, body) = apt
        .get("pool/contrib/t/tool/tool_2%3a3.0~rc1_all.deb")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, tool);
    for wrong in [
        "pool/contrib/h/hello/hello_1.0-1_amd64.deb",
        "pool/main/x/hello/hello_1.0-1_amd64.deb",
        "pool/main/h/hello/hello_9.9_amd64.deb",
        "pool/main/h/hello/hello.deb",
        "dists/bullseye/InRelease",
        "dists/bookworm/main/binary-s390x/Packages",
    ] {
        assert_eq!(apt.get(wrong).await.0, StatusCode::NOT_FOUND, "{wrong}");
    }

    // A new version makes a new index; the older one's by-hash copies stay.
    let old_hash = &entries
        .iter()
        .find(|(_, _, p)| p == "main/binary-amd64/Packages")
        .unwrap()
        .0;
    let (status, _) = apt.post(&deb("hello", "1.1-1", "amd64", "utils")).await;
    assert_eq!(status, StatusCode::CREATED);
    let newer = apt.text("dists/bookworm/main/binary-amd64/Packages").await;
    assert!(newer.contains("Version: 1.0-1\n") && newer.contains("Version: 1.1-1\n"));
    assert!(
        newer.find("Version: 1.0-1").unwrap() < newer.find("Version: 1.1-1").unwrap(),
        "versions in Debian order"
    );
    let (status, older) = apt
        .get(&format!(
            "dists/bookworm/main/binary-amd64/by-hash/SHA256/{old_hash}"
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8(older).unwrap(), packages);

    // DELETE of a pool file deletes the version, and the index follows.
    let resp = apt
        .req(
            reqwest::Method::DELETE,
            "pool/main/h/hello/hello_1.0-1_amd64.deb",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let after = apt.text("dists/bookworm/main/binary-amd64/Packages").await;
    assert!(!after.contains("Version: 1.0-1\n"), "{after}");
    assert_eq!(
        apt.get("pool/main/h/hello/hello_1.0-1_amd64.deb").await.0,
        StatusCode::NOT_FOUND
    );

    // The web UI's browse lists every version, `-` or not.
    let (u, p) = srv.admin_basic();
    let browse: Value = srv
        .client()
        .get(format!("{}/browse/packages?repo={name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = browse["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"hello:amd64"), "{browse}");
}

/// Send `method path` as it is (no client-side normalization).
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
    let name = format!("apttrav{}", unique());
    create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "apt", "options": {"distribution": "bookworm"}}),
    )
    .await;
    let apt = Apt::new(&srv, &name).await;
    assert_eq!(
        apt.post(&deb("hello", "1.0", "amd64", "utils")).await.0,
        StatusCode::CREATED
    );
    let auth =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", apt.user, apt.token));
    for (method, path) in [
        ("GET", "dists/bookworm/../../../etc/passwd"),
        ("GET", "dists/%2e%2e/bookworm/InRelease"),
        ("GET", "pool/main/h/hello/%2e%2e/hello_1.0_amd64.deb"),
        ("GET", "pool/main/h%2Fhello/hello_1.0_amd64.deb"),
        ("GET", "pool//main/h/hello/hello_1.0_amd64.deb"),
        ("GET", "pool/main/h/hello/..%5chello_1.0_amd64.deb"),
        ("PUT", "..%2fx.deb"),
        ("PUT", "%2e%2e/x.deb"),
        ("DELETE", "pool/main/h/hello/%2e%2e/hello_1.0_amd64.deb"),
    ] {
        let status = raw_status(&srv, method, &format!("/repository/{name}/{path}"), &auth).await;
        assert!(
            status == 400 || status == 404,
            "{method} {path} answered {status}"
        );
    }
    // The package is untouched.
    assert_eq!(
        apt.get("pool/main/h/hello/hello_1.0_amd64.deb").await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn signing_keys_rotate() {
    let srv = common::start().await;
    let name = format!("aptkeys{}", unique());
    create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "apt", "options": {"distribution": "stable"}}),
    )
    .await;
    let apt = Apt::new(&srv, &name).await;
    assert_eq!(
        apt.post(&deb("hello", "1.0", "amd64", "utils")).await.0,
        StatusCode::CREATED
    );
    let old = keys(&srv, &name).await.remove(0);
    let path = format!("/admin/repositories/{name}/signing-keys");

    // A second key: both sign until the older is deleted.
    let (status, text) = admin(&srv, reqwest::Method::POST, &path, Some(json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    let new: Value = serde_json::from_str(&text).unwrap();
    assert!(new.get("secret_key").is_none());
    let (message, _) = in_release(&apt.text("dists/stable/InRelease").await);
    assert_eq!(message.signatures().len(), 2);
    message.verify(&public(&old)).unwrap();
    message.verify(&public(&new)).unwrap();
    let release = apt.text("dists/stable/Release").await;
    let (_, detached) = apt.get("dists/stable/Release.gpg").await;
    let (signatures, _) = DetachedSignature::from_armor_many(&detached[..]).unwrap();
    assert_eq!(signatures.count(), 2);
    let _ = release;
    // key.asc holds both keys.
    let armored = apt.text("key.asc").await;
    let (keyring, _) = SignedPublicKey::from_armor_many(armored.as_bytes()).unwrap();
    assert_eq!(keyring.count(), 2);

    // The older key goes; the last key stays.
    let fingerprint = old["fingerprint"].as_str().unwrap();
    let (status, _) = admin(
        &srv,
        reqwest::Method::DELETE,
        &format!("{path}/{fingerprint}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = admin(
        &srv,
        reqwest::Method::DELETE,
        &format!("{path}/{}", new["fingerprint"].as_str().unwrap()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (message, _) = in_release(&apt.text("dists/stable/InRelease").await);
    assert_eq!(message.signatures().len(), 1);
    message.verify(&public(&new)).unwrap();
    assert!(message.verify(&public(&old)).is_err());

    // An imported key signs too; importing it twice conflicts.
    let imported = forge_server::indexes::signing::Key::generate("Imported <i@example.com>")
        .unwrap()
        .to_sealable()
        .unwrap();
    let (status, text) = admin(
        &srv,
        reqwest::Method::POST,
        &path,
        Some(json!({"secret_key": imported})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    let (status, _) = admin(
        &srv,
        reqwest::Method::POST,
        &path,
        Some(json!({"secret_key": imported})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, text) = admin(
        &srv,
        reqwest::Method::POST,
        &path,
        Some(json!({"secret_key": "not a key"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    let (message, _) = in_release(&apt.text("dists/stable/InRelease").await);
    assert_eq!(message.signatures().len(), 2);

    // Proxies have no keys.
    let proxy = format!("aptkeysproxy{}", unique());
    create(
        &srv,
        json!({"name": proxy, "kind": "proxy", "format": "apt", "remote_url": "http://127.0.0.1:9/debian",
               "options": {"distribution": "bookworm"}}),
    )
    .await;
    let (status, _) = admin(
        &srv,
        reqwest::Method::GET,
        &format!("/admin/repositories/{proxy}/signing-keys"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn package_selectors_limit_downloads() {
    let srv = common::start().await;
    let name = format!("aptsel{}", unique());
    create(
        &srv,
        json!({"name": name, "kind": "hosted", "format": "apt", "options": {"distribution": "bookworm"}}),
    )
    .await;
    let apt = Apt::new(&srv, &name).await;
    for package in ["internal-tool", "other-tool"] {
        assert_eq!(
            apt.post(&deb(package, "1.0", "amd64", "utils")).await.0,
            StatusCode::CREATED
        );
    }
    let caller = srv.caller().await;
    let selector = srv.create_selector(&["internal-*"]).await;
    srv.grant_role(caller.id, &[(&name, "read", Some(selector))])
        .await;
    let get = |path: String| {
        let client = srv.client();
        let caller = &caller;
        async move {
            client
                .get(path)
                .basic_auth(&caller.username, Some(&caller.token))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    let base = format!("{}/repository/{name}", srv.base_url);
    assert_eq!(
        get(format!(
            "{base}/pool/main/i/internal-tool/internal-tool_1.0_amd64.deb"
        ))
        .await,
        StatusCode::OK
    );
    assert_eq!(
        get(format!(
            "{base}/pool/main/o/other-tool/other-tool_1.0_amd64.deb"
        ))
        .await,
        StatusCode::NOT_FOUND
    );
    // The signed index is everyone's who reads the repository.
    assert_eq!(
        get(format!("{base}/dists/bookworm/InRelease")).await,
        StatusCode::OK
    );
}

// ── Proxies ─────────────────────────────────────────────────────────────────

/// A mock mirror: `/debian/dists/bookworm/...` and `/debian/pool/...`.
#[derive(Default)]
struct Mirror {
    files: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    /// Requests per path.
    seen: Mutex<std::collections::HashMap<String, usize>>,
    down: AtomicBool,
    requests: AtomicUsize,
}

async fn mirror(state: Arc<Mirror>) -> String {
    let router = axum::Router::new().route(
        "/{*path}",
        axum::routing::get(
            move |axum::extract::Path(path): axum::extract::Path<String>| {
                let state = state.clone();
                async move {
                    state.requests.fetch_add(1, Ordering::SeqCst);
                    *state.seen.lock().unwrap().entry(path.clone()).or_default() += 1;
                    if state.down.load(Ordering::SeqCst) {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    match state.files.lock().unwrap().get(&path) {
                        Some(body) => body.clone().into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn proxies_serve_the_upstream_unchanged() {
    let srv = common::start().await;
    let state = Arc::new(Mirror::default());
    let url = mirror(state.clone()).await;
    let hello = deb("hello", "2.10-3", "amd64", "devel");
    let bad = deb("bad", "1.0", "amd64", "devel");
    let in_release =
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\n".to_vec();
    let packages = format!(
        "Package: hello\nVersion: 2.10-3\nFilename: pool/main/h/hello/hello_2.10-3_amd64.deb\nSize: {}\nSHA256: {}\n\n\
         Package: bad\nVersion: 1.0\nFilename: pool/main/b/bad/bad_1.0_amd64.deb\nSize: {}\nSHA256: {}\n",
        hello.len(),
        sha256(&hello),
        bad.len(),
        "0".repeat(64)
    );
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(packages.as_bytes()).unwrap();
    let packages_gz = gz.finish().unwrap();
    {
        let mut files = state.files.lock().unwrap();
        files.insert("debian/dists/bookworm/InRelease".into(), in_release.clone());
        files.insert(
            "debian/dists/bookworm/main/binary-amd64/Packages.gz".into(),
            packages_gz.clone(),
        );
        files.insert(
            format!(
                "debian/dists/bookworm/main/binary-amd64/by-hash/SHA256/{}",
                sha256(&packages_gz)
            ),
            packages_gz.clone(),
        );
        files.insert(
            "debian/pool/main/h/hello/hello_2.10-3_amd64.deb".into(),
            hello.clone(),
        );
        files.insert("debian/pool/main/b/bad/bad_1.0_amd64.deb".into(), bad);
        // A by-hash copy whose content is not its hash.
        files.insert(
            format!(
                "debian/dists/bookworm/main/binary-amd64/by-hash/SHA256/{}",
                "1".repeat(64)
            ),
            b"forged".to_vec(),
        );
    }
    let name = format!("aptproxy{}", unique());
    create(
        &srv,
        json!({"name": name, "kind": "proxy", "format": "apt", "remote_url": format!("{url}/debian/"),
               "metadata_ttl_seconds": 1, "options": {"distribution": "bookworm"}}),
    )
    .await;
    let apt = Apt::new(&srv, &name).await;

    // The upstream's files, unchanged.
    let (status, body) = apt.get("dists/bookworm/InRelease").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, in_release);
    let (status, body) = apt
        .get(&format!(
            "dists/bookworm/main/binary-amd64/by-hash/SHA256/{}",
            sha256(&packages_gz)
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, packages_gz);
    let (status, body) = apt.get("pool/main/h/hello/hello_2.10-3_amd64.deb").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, hello);
    // Another distribution is not this proxy's.
    assert_eq!(
        apt.get("dists/bullseye/InRelease").await.0,
        StatusCode::NOT_FOUND
    );
    // A package or a by-hash copy that is not what the index says is refused.
    assert_eq!(
        apt.get("pool/main/b/bad/bad_1.0_amd64.deb").await.0,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        apt.get(&format!(
            "dists/bookworm/main/binary-amd64/by-hash/SHA256/{}",
            "1".repeat(64)
        ))
        .await
        .0,
        StatusCode::BAD_GATEWAY
    );
    // Uploads go to hosted repositories.
    assert_eq!(apt.post(&hello).await.0, StatusCode::METHOD_NOT_ALLOWED);

    // Down: what was cached is served, the metadata TTL past or not, and a
    // package is never asked for again.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    state.down.store(true, Ordering::SeqCst);
    let (status, body) = apt.get("dists/bookworm/InRelease").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, in_release);
    let before = state.requests.load(Ordering::SeqCst);
    let (status, body) = apt.get("pool/main/h/hello/hello_2.10-3_amd64.deb").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, hello);
    assert_eq!(state.requests.load(Ordering::SeqCst), before);
    assert_eq!(
        state.seen.lock().unwrap()["debian/pool/main/h/hello/hello_2.10-3_amd64.deb"],
        1
    );
}
