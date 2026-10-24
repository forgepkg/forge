//! Integration tests of npm repositories (`/repository`): publishing and the
//! packument documents, the redeploy policy, dist-tags, deprecation and
//! unpublishing, access levels and content selectors, Bearer tokens,
//! `npm login` (legacy and web) and `npm logout`, proxies of a mock
//! registry (caching, stale serving, integrity checks, the publication
//! delay, Bearer credentials), groups (merging, the reserved-scope and
//! prefer-hosted guards, the writable member), `npm audit` and retention.
//! Requires Docker (Postgres + versitygw via the shared harness), or
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`.
//!
//! The same flows run with the real `npm` and `pnpm` in CI
//! (`.github/scripts/npm-e2e.sh`).

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use common::{unique, TestServer};
use forge_format_npm::integrity::Digests;
use serde_json::{json, Value};

const ABBREVIATED: &str = "application/vnd.npm.install-v1+json";

/// `POST /admin/repositories`, expecting 201.
async fn create(srv: &TestServer, body: Value) -> Value {
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
    assert_eq!(status, 201, "create {body}: {text}");
    serde_json::from_str(&text).unwrap()
}

async fn admin(
    srv: &TestServer,
    method: reqwest::Method,
    path: &str,
    body: Value,
) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    srv.client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn add_member(srv: &TestServer, group: &str, member: &str, priority: i32) {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{group}/members"),
        json!({"member": member, "priority": priority}),
    )
    .await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
}

/// A gzip-compressed npm tarball of `name@version`.
fn tgz(name: &str, version: &str) -> Vec<u8> {
    let package_json = json!({"name": name, "version": version, "main": "index.js"}).to_string();
    let index = format!("module.exports = {:?};", format!("{name}@{version}"));
    forge_format_npm::tarball::build(&[
        ("package/package.json", package_json.as_bytes()),
        ("package/index.js", index.as_bytes()),
        ("package/README.md", format!("# {name}").as_bytes()),
    ])
}

/// The body `npm publish` sends for `name@version` with `tarball`, tagged
/// `tags`.
fn publish_body(name: &str, version: &str, tarball: &[u8], tags: &[&str]) -> Value {
    let d = Digests::of(tarball).unwrap();
    let unscoped = name.rsplit('/').next().unwrap();
    let file = format!("{unscoped}-{version}.tgz");
    let dist_tags: serde_json::Map<String, Value> = tags
        .iter()
        .map(|t| (t.to_string(), json!(version)))
        .collect();
    json!({
        "_id": name,
        "name": name,
        "description": format!("{name} for tests"),
        "dist-tags": dist_tags,
        "versions": {version: {
            "name": name, "version": version, "main": "index.js",
            "description": format!("{name} for tests"),
            "readme": format!("# {name}\n\nversion {version}"),
            "dependencies": {"left-pad": "^1.3.0"},
            "_id": format!("{name}@{version}"),
            "dist": {"integrity": d.integrity(), "shasum": d.sha1_hex, "tarball": format!("http://localhost/{file}")}
        }},
        "access": null,
        "_attachments": {file: {
            "content_type": "application/octet-stream",
            "data": base64::engine::general_purpose::STANDARD.encode(tarball),
            "length": tarball.len()
        }}
    })
}

/// An npm client of one repository, authenticated with a Bearer token.
struct Npm {
    base: String,
    root: String,
    client: reqwest::Client,
    token: Option<String>,
}

/// The escaped form of a package name in a URL (`@scope%2fname`).
fn escaped(name: &str) -> String {
    name.replacen('/', "%2f", 1)
}

impl Npm {
    fn new(srv: &TestServer, repo: &str, token: Option<String>) -> Self {
        Npm {
            base: format!("{}/repository/{repo}", srv.base_url),
            root: srv.base_url.clone(),
            client: srv.client(),
            token,
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let rb = self.client.request(method, format!("{}/{path}", self.base));
        match &self.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
    }

    async fn publish(&self, name: &str, version: &str, tags: &[&str]) -> reqwest::Response {
        self.publish_tarball(name, version, &tgz(name, version), tags)
            .await
    }

    async fn publish_tarball(
        &self,
        name: &str,
        version: &str,
        tarball: &[u8],
        tags: &[&str],
    ) -> reqwest::Response {
        self.req(reqwest::Method::PUT, &escaped(name))
            .json(&publish_body(name, version, tarball, tags))
            .send()
            .await
            .unwrap()
    }

    /// The packument of `name` (abbreviated or full), with its status.
    async fn packument(&self, name: &str, abbreviated: bool) -> (StatusCode, Value) {
        let accept = if abbreviated {
            format!("{ABBREVIATED}; q=1.0, application/json; q=0.8, */*")
        } else {
            "application/json".into()
        };
        let resp = self
            .req(reqwest::Method::GET, &escaped(name))
            .header("accept", accept)
            .send()
            .await
            .unwrap();
        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn ok_packument(&self, name: &str, abbreviated: bool) -> Value {
        let (status, doc) = self.packument(name, abbreviated).await;
        assert_eq!(status, 200, "packument of {name}: {doc}");
        doc
    }

    /// GET a URL the repository served (a tarball's), on the test server.
    async fn fetch(&self, url: &str) -> reqwest::Response {
        let path = url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
            .unwrap();
        let rb = self.client.get(format!("{}{path}", self.root));
        match &self.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
        .send()
        .await
        .unwrap()
    }
}

async fn token_of(srv: &TestServer, username: &str, password: &str) -> String {
    let session = srv.login(username, password).await;
    let resp = session
        .apply(
            srv.client()
                .post(format!("{}/admin/me/tokens", srv.base_url)),
        )
        .json(&json!({"name": "npm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    resp.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn publishes_and_serves_packuments_and_tarballs() {
    let srv = common::start().await;
    let repo = format!("npm{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));

    // Unpublished: 404, as npm expects.
    assert_eq!(npm.packument("@acme/ui", true).await.0, 404);
    let resp = npm.publish("@acme/ui", "1.0.0", &["latest"]).await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let resp = npm.publish("@acme/ui", "1.1.0-beta.1", &["beta"]).await;
    assert_eq!(resp.status(), 201);
    assert_eq!(
        npm.publish("plain-pkg", "0.1.0", &["latest"])
            .await
            .status(),
        201
    );

    // Abbreviated metadata: what installs need, tarballs on this repository.
    let resp = npm
        .req(reqwest::Method::GET, "@acme%2Fui")
        .header("accept", ABBREVIATED)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["content-type"], ABBREVIATED);
    let corgi: Value = resp.json().await.unwrap();
    assert_eq!(corgi["name"], "@acme/ui");
    assert_eq!(
        corgi["dist-tags"],
        json!({"latest": "1.0.0", "beta": "1.1.0-beta.1"})
    );
    let v = &corgi["versions"]["1.0.0"];
    assert_eq!(v["dependencies"], json!({"left-pad": "^1.3.0"}));
    assert!(v.get("readme").is_none() && v.get("description").is_none());
    let tarball_url = v["dist"]["tarball"].as_str().unwrap();
    assert!(
        tarball_url.ends_with(&format!("/repository/{repo}/@acme/ui/-/ui-1.0.0.tgz")),
        "{tarball_url}"
    );
    let bytes = npm.fetch(tarball_url).await.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), tgz("@acme/ui", "1.0.0").as_slice());
    let digests = Digests::of(bytes.as_ref()).unwrap();
    assert_eq!(v["dist"]["integrity"], digests.integrity());
    assert_eq!(v["dist"]["shasum"], digests.sha1_hex);
    assert_eq!(v["dist"]["fileCount"], 3);

    // The full document: README, publish times, the publisher.
    let full = npm.ok_packument("@acme/ui", false).await;
    assert_eq!(full["_id"], "@acme/ui");
    assert_eq!(full["readme"], "# @acme/ui\n\nversion 1.0.0");
    assert!(full["time"]["1.0.0"].is_string() && full["time"]["created"].is_string());
    assert_eq!(
        full["versions"]["1.0.0"]["_npmUser"]["name"],
        srv.admin_user.clone().unwrap()
    );
    assert_eq!(full["description"], "@acme/ui for tests");
    // The unencoded scoped path, a version and a tag.
    let resp = npm
        .req(reqwest::Method::GET, "@acme/ui/beta")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.json::<Value>().await.unwrap()["version"],
        "1.1.0-beta.1"
    );
    let resp = npm
        .req(reqwest::Method::GET, "@acme/ui/1.0.0")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        npm.req(reqwest::Method::GET, "@acme/ui/9.9.9")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // A tarball of a version that does not exist, a HEAD.
    assert_eq!(
        npm.req(reqwest::Method::GET, "@acme/ui/-/ui-9.9.9.tgz")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let head = npm
        .req(reqwest::Method::HEAD, "@acme/ui/-/ui-1.0.0.tgz")
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(
        head.headers()["content-length"],
        bytes.len().to_string().as_str()
    );

    // A version is published once.
    let resp = npm.publish("@acme/ui", "1.0.0", &["latest"]).await;
    assert_eq!(resp.status(), 409);
    assert!(resp.json::<Value>().await.unwrap()["error"]
        .as_str()
        .unwrap()
        .contains("1.0.0"));

    // Ping, search, whoami.
    assert_eq!(
        npm.req(reqwest::Method::GET, "-/ping")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let found: Value = npm
        .req(reqwest::Method::GET, "-/v1/search?text=acme&size=5")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(found["total"], 1, "{found}");
    assert_eq!(found["objects"][0]["package"]["name"], "@acme/ui");
    assert_eq!(found["objects"][0]["package"]["scope"], "acme");
    assert!(found["objects"][0]["package"]["maintainers"].is_array());
    let me: Value = npm
        .req(reqwest::Method::GET, "-/whoami")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["username"], srv.admin_user.clone().unwrap());
}

#[tokio::test]
async fn refuses_publishes_that_do_not_hold_up() {
    let srv = common::start().await;
    let repo = format!("npm{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));

    // The integrity claimed is not the tarball's.
    let mut body = publish_body("a-pkg", "1.0.0", &tgz("a-pkg", "1.0.0"), &["latest"]);
    body["versions"]["1.0.0"]["dist"]["integrity"] =
        json!(Digests::of(&b"x"[..]).unwrap().integrity());
    let resp = npm
        .req(reqwest::Method::PUT, "a-pkg")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "{}", resp.text().await.unwrap());
    // The tarball is another version than the document says.
    let other = tgz("a-pkg", "2.0.0");
    let resp = npm
        .publish_tarball("a-pkg", "1.0.0", &other, &["latest"])
        .await;
    assert_eq!(resp.status(), 400);
    // The URL names another package than the document.
    let body = publish_body("b-pkg", "1.0.0", &tgz("b-pkg", "1.0.0"), &["latest"]);
    let resp = npm
        .req(reqwest::Method::PUT, "a-pkg")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // A name new packages may not take.
    let resp = npm.publish("Upper-Case", "1.0.0", &["latest"]).await;
    assert_eq!(resp.status(), 400);
    // Not JSON.
    let resp = npm
        .req(reqwest::Method::PUT, "a-pkg")
        .body("{\"name\": ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // Nothing was stored.
    assert_eq!(npm.packument("a-pkg", true).await.0, 404);

    // Larger than the repository's upload limit.
    let small = format!("small{}", unique());
    create(
        &srv,
        json!({"name": small, "kind": "hosted", "format": "npm", "max_upload_bytes": 64}),
    )
    .await;
    let resp = Npm::new(&srv, &small, npm.token.clone())
        .publish("c-pkg", "1.0.0", &["latest"])
        .await;
    assert_eq!(resp.status(), 413);
    // Also when the store gives up long before the document ends.
    let mut noise = vec![0u8; 2 * 1024 * 1024];
    let mut x: u32 = 0x2545_f491;
    for byte in &mut noise {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *byte = x as u8;
    }
    let package_json = json!({"name": "big-pkg", "version": "1.0.0"}).to_string();
    let big = forge_format_npm::tarball::build(&[
        ("package/package.json", package_json.as_bytes()),
        ("package/noise.bin", &noise),
    ]);
    let resp = Npm::new(&srv, &small, npm.token.clone())
        .publish_tarball("big-pkg", "1.0.0", &big, &["latest"])
        .await;
    assert_eq!(resp.status(), 413);

    // Publishing needs a token: no credentials, a session without CSRF, a
    // reader's token.
    let anon = Npm::new(&srv, &repo, None);
    assert_eq!(
        anon.publish("d-pkg", "1.0.0", &["latest"]).await.status(),
        401
    );
    let reader = format!("reader{}@example.com", unique());
    srv.create_user(&reader, "reader-password-1", "reader")
        .await;
    let reader_npm = Npm::new(
        &srv,
        &repo,
        Some(token_of(&srv, &reader, "reader-password-1").await),
    );
    assert_eq!(
        reader_npm
            .publish("d-pkg", "1.0.0", &["latest"])
            .await
            .status(),
        403
    );
    assert_eq!(npm.packument("d-pkg", true).await.0, 404);
    // An unknown token is refused, never read as anonymous.
    let bogus = Npm::new(&srv, &repo, Some("not-a-token".into()));
    let resp = bogus
        .req(reqwest::Method::GET, "a-pkg")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(resp.headers()["content-type"], "application/json");
    assert!(resp.headers().contains_key("www-authenticate"));
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"error": "invalid token"})
    );
}

#[tokio::test]
async fn the_deployment_policy_decides_on_republishing() {
    let srv = common::start().await;
    let token = srv.admin_token().await;
    let repo = format!("npm{}", unique());
    let view = create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm", "deployment_policy": "allow_redeploy"}),
    )
    .await;
    assert_eq!(view["deployment_policy"], "allow_redeploy");
    assert_eq!(view["allow_redeploy"], true);
    let npm = Npm::new(&srv, &repo, Some(token));
    assert_eq!(npm.publish("pkg", "1.0.0", &["latest"]).await.status(), 201);
    assert_eq!(npm.publish("pkg", "1.0.0", &["latest"]).await.status(), 201);

    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{repo}"),
        json!({"deployment_policy": "read_only"}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(npm.publish("pkg", "1.0.1", &["latest"]).await.status(), 403);
    assert_eq!(npm.packument("pkg", true).await.0, 200, "still readable");
    // allow_redeploy says the same as the deployment policy, and may not
    // contradict it.
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{repo}"),
        json!({"allow_redeploy": true, "deployment_policy": "read_only"}),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{repo}"),
        json!({"allow_redeploy": true}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["deployment_policy"], "allow_redeploy");
}

#[tokio::test]
async fn dist_tags_deprecations_and_unpublishing() {
    let srv = common::start().await;
    let repo = format!("npm{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));
    for (v, tags) in [
        ("1.0.0", vec!["latest"]),
        ("1.1.0", vec!["next"]),
        ("2.0.0", vec!["latest"]),
    ] {
        assert_eq!(npm.publish("@acme/tags", v, &tags).await.status(), 201);
    }
    let tags = |npm: &Npm| {
        let rb = npm.req(reqwest::Method::GET, "-/package/@acme%2ftags/dist-tags");
        async move { rb.send().await.unwrap().json::<Value>().await.unwrap() }
    };
    assert_eq!(
        tags(&npm).await,
        json!({"latest": "2.0.0", "next": "1.1.0"})
    );

    // npm dist-tag add / rm.
    let resp = npm
        .req(
            reqwest::Method::PUT,
            "-/package/@acme%2ftags/dist-tags/stable",
        )
        .json(&json!("1.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    for (tag, version, status) in [("1.x", "1.0.0", 400), ("other", "9.9.9", 404)] {
        let resp = npm
            .req(
                reqwest::Method::PUT,
                &format!("-/package/@acme%2ftags/dist-tags/{tag}"),
            )
            .json(&json!(version))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), status, "{tag}");
    }
    let resp = npm
        .req(
            reqwest::Method::DELETE,
            "-/package/@acme%2ftags/dist-tags/next",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = npm
        .req(
            reqwest::Method::DELETE,
            "-/package/@acme%2ftags/dist-tags/latest",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(
        tags(&npm).await,
        json!({"latest": "2.0.0", "stable": "1.0.0"})
    );

    // npm deprecate: the full packument, PUT back with `deprecated` set.
    let mut doc = npm.ok_packument("@acme/tags", false).await;
    doc["versions"]["1.0.0"]["deprecated"] = json!("use 2.x");
    let resp = npm
        .req(reqwest::Method::PUT, "@acme%2ftags")
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let corgi = npm.ok_packument("@acme/tags", true).await;
    assert_eq!(corgi["versions"]["1.0.0"]["deprecated"], "use 2.x");
    assert!(corgi["versions"]["2.0.0"].get("deprecated").is_none());
    // And undeprecated with an empty message.
    doc["versions"]["1.0.0"]["deprecated"] = json!("");
    npm.req(reqwest::Method::PUT, "@acme%2ftags")
        .json(&doc)
        .send()
        .await
        .unwrap();
    let corgi = npm.ok_packument("@acme/tags", true).await;
    assert!(corgi["versions"]["1.0.0"].get("deprecated").is_none());

    // npm unpublish <version>: the packument without it, PUT to `-rev`,
    // then the tarball's DELETE, which may find it gone already.
    let mut doc = npm.ok_packument("@acme/tags", false).await;
    let rev = doc["_rev"].as_str().unwrap().to_string();
    doc["versions"].as_object_mut().unwrap().remove("1.0.0");
    doc["dist-tags"].as_object_mut().unwrap().remove("stable");
    let resp = npm
        .req(reqwest::Method::PUT, &format!("@acme%2ftags/-rev/{rev}"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = npm
        .req(
            reqwest::Method::DELETE,
            &format!("@acme/tags/-/tags-1.0.0.tgz/-rev/{rev}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let corgi = npm.ok_packument("@acme/tags", true).await;
    let versions: Vec<&String> = corgi["versions"].as_object().unwrap().keys().collect();
    assert_eq!(versions, ["1.1.0", "2.0.0"]);
    assert_eq!(corgi["dist-tags"], json!({"latest": "2.0.0"}));
    // A version's tarball DELETE unpublishes it too.
    let resp = npm
        .req(
            reqwest::Method::DELETE,
            "@acme/tags/-/tags-1.1.0.tgz/-rev/1-x",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // npm unpublish of the package.
    let resp = npm
        .req(reqwest::Method::DELETE, "@acme%2ftags/-rev/1-x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(npm.packument("@acme/tags", true).await.0, 404);
    // Republishing it starts over with a `latest`.
    assert_eq!(
        npm.publish("@acme/tags", "3.0.0", &["beta"]).await.status(),
        201
    );
    assert_eq!(
        tags(&npm).await,
        json!({"beta": "3.0.0", "latest": "3.0.0"})
    );
    // A version unpublished may be published again.
    assert_eq!(
        npm.publish("@acme/tags", "1.0.0", &["old"]).await.status(),
        201
    );
    assert_eq!(
        tags(&npm).await,
        json!({"beta": "3.0.0", "latest": "3.0.0", "old": "1.0.0"})
    );
}

#[tokio::test]
async fn unpublishing_takes_the_delete_level() {
    let srv = common::start().await;
    let repo = format!("npm{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let admin_npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));
    for v in ["1.0.0", "2.0.0"] {
        assert_eq!(admin_npm.publish("pkg", v, &["latest"]).await.status(), 201);
    }
    let writer = format!("writer{}@example.com", unique());
    srv.create_user(&writer, "writer-password-1", "writer")
        .await;
    let npm = Npm::new(
        &srv,
        &repo,
        Some(token_of(&srv, &writer, "writer-password-1").await),
    );
    // A writer deprecates and moves tags, but removes no version.
    let mut doc = npm.ok_packument("pkg", false).await;
    doc["versions"]["1.0.0"]["deprecated"] = json!("old");
    assert_eq!(
        npm.req(reqwest::Method::PUT, "pkg")
            .json(&doc)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    doc["versions"].as_object_mut().unwrap().remove("1.0.0");
    assert_eq!(
        npm.req(reqwest::Method::PUT, "pkg/-rev/1")
            .json(&doc)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        npm.req(reqwest::Method::DELETE, "pkg/-rev/1")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        npm.ok_packument("pkg", true).await["versions"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    // A document that leaves no version is an unpublish, which has its own
    // request.
    doc["versions"] = json!({});
    assert_eq!(
        admin_npm
            .req(reqwest::Method::PUT, "pkg/-rev/1")
            .json(&doc)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        admin_npm.ok_packument("pkg", true).await["versions"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn a_selector_on_a_write_grant_scopes_publishes_and_reads() {
    let srv = common::start().await;
    let repo = format!("npm{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let admin_npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));
    for name in ["@acme/ui", "outside"] {
        assert_eq!(
            admin_npm.publish(name, "1.0.0", &["latest"]).await.status(),
            201
        );
    }

    // A user whose one grant is `write` on `@acme/*` of this repository.
    let username = format!("acme{}@example.com", unique());
    let user_id = srv
        .create_user(&username, "acme-password-1", "reader")
        .await;
    let selector: Value = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/content-selectors",
        json!({"name": format!("s{}", unique()), "includes": ["@acme/*"], "excludes": []}),
    )
    .await
    .json()
    .await
    .unwrap();
    let role: Value = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/roles",
        json!({"name": format!("r{}", unique())}),
    )
    .await
    .json()
    .await
    .unwrap();
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/roles/{}/grants", role["id"]),
        json!({"repository": repo, "level": "write", "selector_id": selector["id"]}),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/users/{user_id}/roles"),
        json!({"role_id": role["id"]}),
    )
    .await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let npm = Npm::new(
        &srv,
        &repo,
        Some(token_of(&srv, &username, "acme-password-1").await),
    );

    // It publishes and changes the scope's packages...
    assert_eq!(
        npm.publish("@acme/widget", "1.0.0", &["latest"])
            .await
            .status(),
        201
    );
    let resp = npm
        .req(reqwest::Method::PUT, "-/package/@acme%2fui/dist-tags/next")
        .json(&json!("1.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    // ...and reads them only: the selector filters reads too.
    npm.ok_packument("@acme/ui", true).await;
    assert_eq!(npm.packument("outside", true).await.0, 404);
    assert_eq!(npm.packument("outside", false).await.0, 404);
    assert_eq!(
        npm.req(reqwest::Method::GET, "outside/-/outside-1.0.0.tgz")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let found: Value = npm
        .req(reqwest::Method::GET, "-/v1/search?text=e&size=20")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut names: Vec<&str> = found["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["package"]["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["@acme/ui", "@acme/widget"], "{found}");

    // Nothing outside the scope: no publish, no tag, no deprecation.
    let resp = npm.publish("outside", "2.0.0", &["latest"]).await;
    assert_eq!(resp.status(), 403, "{}", resp.text().await.unwrap());
    let resp = npm
        .req(reqwest::Method::PUT, "-/package/outside/dist-tags/next")
        .json(&json!("1.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let mut doc = admin_npm.ok_packument("outside", false).await;
    doc["versions"]["1.0.0"]["deprecated"] = json!("old");
    let resp = npm
        .req(reqwest::Method::PUT, "outside")
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let full = admin_npm.ok_packument("outside", false).await;
    assert_eq!(full["dist-tags"], json!({"latest": "1.0.0"}));
    assert!(
        full["versions"]["1.0.0"].get("deprecated").is_none(),
        "{full}"
    );
}

#[tokio::test]
async fn npm_login_legacy_and_web_and_logout() {
    let assets = tempfile::tempdir().unwrap();
    std::fs::write(assets.path().join("index.html"), "<html></html>").unwrap();
    let admin_user = format!("admin{}@example.com", unique());
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((admin_user.clone(), "adminpw".into())),
            web_assets_dir: Some(assets.path().display().to_string()),
            ..Default::default()
        },
    )
    .await;
    let repo = format!("npm{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let user = format!("dev{}@example.com", unique());
    srv.create_user(&user, "dev-password-123", "writer").await;
    let anon = Npm::new(&srv, &repo, None);
    let path = format!("-/user/org.couchdb.user:{}", user.replace('@', "%40"));

    // Legacy: the password through the realm chain, a token back.
    let resp = anon
        .req(reqwest::Method::PUT, &path)
        .json(&json!({"_id": format!("org.couchdb.user:{user}"), "name": user, "password": "wrong", "type": "user", "roles": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let resp = anon
        .req(reqwest::Method::PUT, &path)
        .json(&json!({"name": user, "password": "dev-password-123", "type": "user", "roles": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    let legacy = Npm::new(
        &srv,
        &repo,
        Some(body["token"].as_str().unwrap().to_string()),
    );
    assert_eq!(
        legacy
            .publish("logged-in", "1.0.0", &["latest"])
            .await
            .status(),
        201
    );
    let me: Value = legacy
        .req(reqwest::Method::GET, "-/whoami")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["username"], user.as_str());

    // Web: login and done URLs; the done URL waits for the browser.
    let start: Value = anon
        .req(reqwest::Method::POST, "-/v1/login")
        .json(&json!({"hostname": "laptop"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_url = start["loginUrl"].as_str().unwrap();
    let done_url = start["doneUrl"].as_str().unwrap();
    assert!(
        login_url.starts_with("http://test.local/cli-login/"),
        "{login_url}"
    );
    let secret = login_url.rsplit('/').next().unwrap();
    let pending = anon.fetch(done_url).await;
    assert_eq!(pending.status(), 202);
    assert!(pending.headers().contains_key("retry-after"));
    let session = srv.login(&user, "dev-password-123").await;
    let info: Value = session
        .apply(
            srv.client()
                .get(format!("{}/auth/cli-login/{secret}", srv.base_url)),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["repository"], repo.as_str());
    assert_eq!(info["hostname"], "laptop");
    // Approving takes the session's CSRF token.
    let resp = srv
        .client()
        .post(format!("{}/auth/cli-login/{secret}", srv.base_url))
        .header("cookie", &session.cookie)
        .json(&json!({"approve": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = session
        .apply(
            srv.client()
                .post(format!("{}/auth/cli-login/{secret}", srv.base_url)),
        )
        .json(&json!({"approve": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let done: Value = anon.fetch(done_url).await.json().await.unwrap();
    let web_token = done["token"].as_str().unwrap().to_string();
    assert_eq!(anon.fetch(done_url).await.status(), 404, "collected once");
    let web = Npm::new(&srv, &repo, Some(web_token.clone()));
    let me: Value = web
        .req(reqwest::Method::GET, "-/whoami")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["username"], user.as_str());

    // Both tokens are the user's, with a lifetime, listed on their page.
    let tokens: Value = session
        .apply(srv.client().get(format!("{}/auth/tokens", srv.base_url)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = tokens
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&format!("npm login ({repo})").as_str()),
        "{names:?}"
    );
    assert!(
        names.contains(&format!("npm login ({repo}) on laptop").as_str()),
        "{names:?}"
    );
    assert!(tokens
        .as_array()
        .unwrap()
        .iter()
        .all(|t| t["expires_at"].is_string()));

    // A refused web login collects nothing.
    let start: Value = anon
        .req(reqwest::Method::POST, "-/v1/login")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let secret = start["loginUrl"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let resp = session
        .apply(
            srv.client()
                .post(format!("{}/auth/cli-login/{secret}", srv.base_url)),
        )
        .json(&json!({"approve": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(
        anon.fetch(start["doneUrl"].as_str().unwrap())
            .await
            .status(),
        404
    );

    // npm logout revokes the token it presents, and only the caller's own.
    let resp = legacy
        .req(
            reqwest::Method::DELETE,
            &format!("-/user/token/{web_token}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the same user's token");
    assert_eq!(
        web.req(reqwest::Method::GET, "-/whoami")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let admin_npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));
    let resp = admin_npm
        .req(
            reqwest::Method::DELETE,
            &format!("-/user/token/{}", legacy.token.clone().unwrap()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "another user's token");
    assert_eq!(
        legacy
            .req(reqwest::Method::GET, "-/whoami")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

/// A mock npm registry.
#[derive(Default)]
struct Upstream {
    packuments: Mutex<HashMap<String, Value>>,
    tarballs: Mutex<HashMap<String, Vec<u8>>>,
    packument_hits: AtomicUsize,
    tarball_hits: AtomicUsize,
    down: AtomicBool,
    /// The Bearer token every request must carry, if any.
    token: Mutex<Option<String>>,
    /// Authorization headers seen, by path.
    auth: Mutex<Vec<(String, Option<String>)>>,
    audits: Mutex<Vec<Value>>,
}

impl Upstream {
    /// Serve `name` with `versions` (version, published), its tarballs at
    /// `{base}/tarballs/...`.
    fn publish(&self, base: &str, name: &str, versions: &[(&str, &str)], latest: &str) {
        let mut doc_versions = serde_json::Map::new();
        let mut time = serde_json::Map::new();
        for (version, published) in versions {
            let tarball = tgz(name, version);
            let d = Digests::of(&tarball[..]).unwrap();
            let file = format!("{}-{version}.tgz", name.rsplit('/').next().unwrap());
            let path = format!("/tarballs/{}/{file}", name.replace('/', "_"));
            self.tarballs.lock().unwrap().insert(path.clone(), tarball);
            doc_versions.insert(
                version.to_string(),
                json!({"name": name, "version": version, "readme": "per-version readme",
                       "dist": {"tarball": format!("{base}{path}"), "integrity": d.integrity(), "shasum": d.sha1_hex}}),
            );
            time.insert(version.to_string(), json!(published));
        }
        self.packuments.lock().unwrap().insert(
            name.to_string(),
            json!({"_id": name, "name": name, "dist-tags": {"latest": latest},
                   "versions": doc_versions, "time": time, "readme": format!("# {name} upstream"),
                   "users": {"someone": true}}),
        );
    }
}

async fn serve_upstream(upstream: Arc<Upstream>) -> String {
    async fn handle(
        axum::extract::State(up): axum::extract::State<Arc<Upstream>>,
        method: axum::http::Method,
        uri: axum::http::Uri,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Response {
        let path = uri.path().to_string();
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        up.auth.lock().unwrap().push((path.clone(), auth.clone()));
        if up.down.load(Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if let Some(token) = up.token.lock().unwrap().clone() {
            if auth.as_deref() != Some(format!("Bearer {token}").as_str()) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
        if method == axum::http::Method::POST && path.starts_with("/-/npm/v1/security/") {
            up.audits
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&body).unwrap_or(Value::Null));
            return axum::Json(json!({"left-pad": [{"id": 1, "severity": "high"}]}))
                .into_response();
        }
        if let Some(tarball) = up.tarballs.lock().unwrap().get(&path).cloned() {
            up.tarball_hits.fetch_add(1, Ordering::SeqCst);
            return tarball.into_response();
        }
        let name = percent_encoding::percent_decode_str(path.trim_start_matches('/'))
            .decode_utf8_lossy()
            .to_string();
        up.packument_hits.fetch_add(1, Ordering::SeqCst);
        match up.packuments.lock().unwrap().get(&name) {
            Some(doc) => axum::Json(doc.clone()).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "not found"})),
            )
                .into_response(),
        }
    }
    let router = axum::Router::new().fallback(handle).with_state(upstream);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    base
}

#[tokio::test]
async fn a_proxy_caches_verifies_and_serves_stale() {
    let srv = common::start().await;
    let upstream = Arc::new(Upstream::default());
    let base = serve_upstream(upstream.clone()).await;
    upstream.publish(
        &base,
        "left-pad",
        &[
            ("1.2.0", "2016-01-01T00:00:00.000Z"),
            ("1.3.0", "2018-04-09T01:57:31.231Z"),
        ],
        "1.3.0",
    );
    upstream.publish(
        &base,
        "@types/x",
        &[("1.0.0", "2020-01-01T00:00:00.000Z")],
        "1.0.0",
    );
    let repo = format!("proxy{}", unique());
    create(&srv, json!({"name": repo, "kind": "proxy", "format": "npm", "remote_url": base, "metadata_ttl_seconds": 3600})).await;
    let npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));

    let corgi = npm.ok_packument("left-pad", true).await;
    assert_eq!(corgi["dist-tags"], json!({"latest": "1.3.0"}));
    let url = corgi["versions"]["1.3.0"]["dist"]["tarball"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        url.contains(&format!("/repository/{repo}/left-pad/-/left-pad-1.3.0.tgz")),
        "{url}"
    );
    let full = npm.ok_packument("left-pad", false).await;
    assert_eq!(full["readme"], "# left-pad upstream");
    assert!(full["versions"]["1.3.0"].get("readme").is_none());
    assert_eq!(full["time"]["1.3.0"], "2018-04-09T01:57:31.231Z");
    assert!(corgi.get("time").is_none());
    // Within the TTL the upstream is asked once for each document: the
    // abbreviated one installs read, the full one with the publish times.
    npm.ok_packument("left-pad", true).await;
    npm.ok_packument("left-pad", false).await;
    assert_eq!(upstream.packument_hits.load(Ordering::SeqCst), 2);
    let scoped = npm.ok_packument("@types/x", true).await;
    assert_eq!(scoped["name"], "@types/x");

    // A tarball is downloaded once, checked, and kept.
    let bytes = npm.fetch(&url).await.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), tgz("left-pad", "1.3.0").as_slice());
    npm.fetch(&url).await.bytes().await.unwrap();
    assert_eq!(upstream.tarball_hits.load(Ordering::SeqCst), 1);

    // The upstream goes down: the packument and the cached tarball are
    // still served (after the TTL: the proxy is invalidated).
    upstream.down.store(true, Ordering::SeqCst);
    let resp = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/proxy-cache/invalidate"),
        json!({}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let stale = npm.ok_packument("left-pad", true).await;
    assert_eq!(stale["dist-tags"], json!({"latest": "1.3.0"}));
    assert!(
        upstream.packument_hits.load(Ordering::SeqCst) >= 2,
        "it asked again"
    );
    assert_eq!(npm.fetch(&url).await.status(), 200);
    // A tarball never downloaded cannot be served now: try again later.
    let resp = npm
        .req(reqwest::Method::GET, "left-pad/-/left-pad-1.2.0.tgz")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    assert!(resp.headers().contains_key("retry-after"));
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("upstream"),
        "{body}"
    );
    upstream.down.store(false, Ordering::SeqCst);

    // An unknown package is remembered as such.
    assert_eq!(npm.packument("nope", true).await.0, 404);
    let hits = upstream.packument_hits.load(Ordering::SeqCst);
    assert_eq!(npm.packument("nope", true).await.0, 404);
    assert_eq!(upstream.packument_hits.load(Ordering::SeqCst), hits);

    // A tarball that is not what its packument says is refused.
    upstream.publish(
        &base,
        "tampered",
        &[("1.0.0", "2020-01-01T00:00:00.000Z")],
        "1.0.0",
    );
    upstream.tarballs.lock().unwrap().insert(
        "/tarballs/tampered/tampered-1.0.0.tgz".into(),
        tgz("tampered", "6.6.6"),
    );
    let resp = npm
        .req(reqwest::Method::GET, "tampered/-/tampered-1.0.0.tgz")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM component c JOIN repository r ON r.id = c.repository_id WHERE r.name = $1 AND c.name = 'tampered'")
        .bind(&repo)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);

    // A proxy is read-only.
    assert_eq!(
        npm.publish("left-pad", "9.0.0", &["latest"]).await.status(),
        405
    );
}

#[tokio::test]
async fn a_proxy_holds_back_versions_inside_the_publication_delay() {
    let srv = common::start().await;
    let upstream = Arc::new(Upstream::default());
    let base = serve_upstream(upstream.clone()).await;
    let recent = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    upstream.publish(
        &base,
        "fresh",
        &[
            ("1.0.0", "2020-01-01T00:00:00.000Z"),
            ("1.1.0", "2021-01-01T00:00:00.000Z"),
            ("2.0.0", &recent),
        ],
        "2.0.0",
    );
    let repo = format!("proxy{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "proxy", "format": "npm", "remote_url": base, "package_delay_seconds": 86400}),
    )
    .await;
    let npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));
    let corgi = npm.ok_packument("fresh", true).await;
    let versions: Vec<&String> = corgi["versions"].as_object().unwrap().keys().collect();
    assert_eq!(versions, ["1.0.0", "1.1.0"]);
    assert_eq!(corgi["dist-tags"], json!({"latest": "1.1.0"}));
    let resp = npm
        .req(reqwest::Method::GET, "fresh/-/fresh-2.0.0.tgz")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(upstream.tarball_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_proxy_sends_its_token_to_its_upstream_only() {
    let srv = common::start().await;
    let upstream = Arc::new(Upstream::default());
    let base = serve_upstream(upstream.clone()).await;
    // The tarballs live on another origin (localhost, not 127.0.0.1).
    let other = base.replace("127.0.0.1", "localhost");
    upstream.publish(
        &other,
        "private-pkg",
        &[("1.0.0", "2020-01-01T00:00:00.000Z")],
        "1.0.0",
    );
    let repo = format!("proxy{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "proxy", "format": "npm", "remote_url": base, "upstream_password": "upstream-token"}),
    )
    .await;
    let npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));
    let corgi = npm.ok_packument("private-pkg", true).await;
    let url = corgi["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(npm.fetch(&url).await.status(), 200);
    let seen = upstream.auth.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|(p, a)| p == "/private-pkg" && a.as_deref() == Some("Bearer upstream-token")),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|(p, a)| p.starts_with("/tarballs/") && a.is_none()),
        "no token off-origin: {seen:?}"
    );

    // An upstream that wants it: a proxy without it fails, one with it
    // serves.
    *upstream.token.lock().unwrap() = Some("upstream-token".into());
    upstream.publish(
        &base,
        "guarded",
        &[("1.0.0", "2020-01-01T00:00:00.000Z")],
        "1.0.0",
    );
    assert_eq!(npm.packument("guarded", true).await.0, 200);
    let open = format!("open{}", unique());
    create(
        &srv,
        json!({"name": open, "kind": "proxy", "format": "npm", "remote_url": base}),
    )
    .await;
    assert_eq!(
        Npm::new(&srv, &open, npm.token.clone())
            .packument("guarded", true)
            .await
            .0,
        502
    );
}

#[tokio::test]
async fn a_group_merges_and_keeps_internal_scopes_internal() {
    let srv = common::start().await;
    let token = srv.admin_token().await;
    let upstream = Arc::new(Upstream::default());
    let base = serve_upstream(upstream.clone()).await;
    // A public registry that claims an internal scope and an internal name.
    upstream.publish(
        &base,
        "@acme/ui",
        &[
            ("1.0.0", "2020-01-01T00:00:00.000Z"),
            ("99.0.0", "2020-02-01T00:00:00.000Z"),
        ],
        "99.0.0",
    );
    upstream.publish(
        &base,
        "@acme/not-yet-internal",
        &[("1.0.0", "2020-01-01T00:00:00.000Z")],
        "1.0.0",
    );
    upstream.publish(
        &base,
        "internal-lib",
        &[("5.0.0", "2020-01-01T00:00:00.000Z")],
        "5.0.0",
    );
    upstream.publish(
        &base,
        "left-pad",
        &[("1.3.0", "2018-01-01T00:00:00.000Z")],
        "1.3.0",
    );
    let n = unique();
    let (hosted, proxy, group) = (format!("hosted{n}"), format!("proxy{n}"), format!("all{n}"));
    create(
        &srv,
        json!({"name": hosted, "kind": "hosted", "format": "npm"}),
    )
    .await;
    create(
        &srv,
        json!({"name": proxy, "kind": "proxy", "format": "npm", "remote_url": base}),
    )
    .await;
    let view = create(
        &srv,
        json!({"name": group, "kind": "group", "format": "npm", "reserved_prefixes": ["@acme"]}),
    )
    .await;
    assert_eq!(view["reserved_prefixes"], json!(["@acme/"]));
    add_member(&srv, &group, &hosted, 10).await;
    add_member(&srv, &group, &proxy, 5).await;
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{group}"),
        json!({"writable_member": hosted}),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let internal = Npm::new(&srv, &hosted, Some(token.clone()));
    assert_eq!(
        internal
            .publish("@acme/ui", "1.0.0", &["latest"])
            .await
            .status(),
        201
    );
    assert_eq!(
        internal
            .publish("internal-lib", "1.0.0", &["latest"])
            .await
            .status(),
        201
    );
    let npm = Npm::new(&srv, &group, Some(token.clone()));

    // The scope is reserved: the public 99.0.0 never appears, nor a scoped
    // package no hosted member has yet.
    let ui = npm.ok_packument("@acme/ui", true).await;
    let versions: Vec<&String> = ui["versions"].as_object().unwrap().keys().collect();
    assert_eq!(versions, ["1.0.0"]);
    assert_eq!(ui["dist-tags"], json!({"latest": "1.0.0"}));
    let url = ui["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap();
    assert!(
        url.contains(&format!("/repository/{group}/@acme/ui/-/ui-1.0.0.tgz")),
        "{url}"
    );
    assert_eq!(
        npm.fetch(url).await.bytes().await.unwrap().as_ref(),
        tgz("@acme/ui", "1.0.0").as_slice()
    );
    assert_eq!(npm.packument("@acme/not-yet-internal", true).await.0, 404);
    assert_eq!(
        npm.req(reqwest::Method::GET, "@acme/ui/-/ui-99.0.0.tgz")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // Prefer hosted: an internal name a hosted member has is not mixed with
    // the public one.
    let lib = npm.ok_packument("internal-lib", true).await;
    assert_eq!(
        lib["versions"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["1.0.0"]
    );
    // A public package comes from the proxy, with its tags.
    let pad = npm.ok_packument("left-pad", true).await;
    assert_eq!(pad["dist-tags"], json!({"latest": "1.3.0"}));
    let url = pad["versions"]["1.3.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    assert!(
        url.contains(&format!("/repository/{group}/left-pad/")),
        "{url}"
    );
    assert_eq!(npm.fetch(url).await.status(), 200);

    // Publishing to the group lands in its writable member.
    assert_eq!(
        npm.publish("@acme/ui", "1.1.0", &["latest"]).await.status(),
        201
    );
    let ui = internal.ok_packument("@acme/ui", true).await;
    assert_eq!(ui["dist-tags"], json!({"latest": "1.1.0"}));

    // npm audit through the group goes to the proxy's upstream, without the
    // internal scope's packages.
    let resp = npm
        .req(reqwest::Method::POST, "-/npm/v1/security/advisories/bulk")
        .json(&json!({"@acme/ui": ["1.1.0"], "left-pad": ["1.3.0"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["left-pad"][0]["severity"],
        "high"
    );
    assert_eq!(
        upstream.audits.lock().unwrap().clone(),
        vec![json!({"left-pad": ["1.3.0"]})]
    );
    // A hosted repository has no audit source.
    let resp = internal
        .req(reqwest::Method::POST, "-/npm/v1/security/advisories/bulk")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn retention_never_deletes_a_tagged_version() {
    let srv = common::start().await;
    let repo = format!("npm{}", unique());
    let view = create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let npm = Npm::new(&srv, &repo, Some(srv.admin_token().await));
    for v in ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"] {
        assert_eq!(npm.publish("kept", v, &["latest"]).await.status(), 201);
    }
    // `legacy` holds an old version; `latest` is the newest.
    let resp = npm
        .req(reqwest::Method::PUT, "-/package/kept/dist-tags/legacy")
        .json(&json!("1.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    // Two days old, so that a one-day trigger takes them all.
    sqlx::query(
        "UPDATE component SET created_at = now() - interval '2 days' WHERE repository_id = $1",
    )
    .bind(view["id"].as_i64().unwrap())
    .execute(&srv.pool)
    .await
    .unwrap();
    let policy = json!({"policy": {"version": 1, "rules": [{"id": "keep-two", "action": "hard_delete", "criteria": {"keep_last_n": 2, "older_than_days": 1}}]}});
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/admin/repositories/{repo}/retention"),
        policy,
    )
    .await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let preview: Value = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/retention/preview"),
        json!({}),
    )
    .await
    .json()
    .await
    .unwrap();
    let mut previewed: Vec<&str> = preview["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["version"].as_str().unwrap())
        .collect();
    previewed.sort();
    assert_eq!(previewed, ["1.1.0", "1.2.0"], "{preview}");
    assert_eq!(
        admin(
            &srv,
            reqwest::Method::POST,
            &format!("/admin/repositories/{repo}/retention/run"),
            json!({})
        )
        .await
        .status(),
        202
    );
    let worker = forge_core::retention::RetentionWorker::new(
        srv.pool.clone(),
        forge_server::state::RegistryResolver(srv.state.formats.clone()),
        Arc::new(forge_core::repo::NoopCacheInvalidator),
        forge_core::retention::RetentionConfig::default(),
    );
    let summary = worker
        .tick_repo(view["id"].as_i64().unwrap())
        .await
        .unwrap()
        .expect("a run");
    assert_eq!(summary.deleted, 2, "{summary:?}");
    let corgi = npm.ok_packument("kept", true).await;
    let versions: Vec<&String> = corgi["versions"].as_object().unwrap().keys().collect();
    assert_eq!(versions, ["1.0.0", "1.3.0", "1.4.0"]);
    assert_eq!(
        corgi["dist-tags"],
        json!({"latest": "1.4.0", "legacy": "1.0.0"})
    );
}

#[tokio::test]
async fn routes_only_npm_repositories() {
    let srv = common::start().await;
    let nuget = format!("nuget{}", unique());
    create(&srv, json!({"name": nuget, "kind": "hosted"})).await;
    let token = srv.admin_token().await;
    let npm = Npm::new(&srv, &nuget, Some(token.clone()));
    assert_eq!(npm.packument("left-pad", true).await.0, 404);
    let missing = Npm::new(&srv, "no-such-repo", None);
    assert_eq!(missing.packument("left-pad", true).await.0, 401);
    let repo = format!("npm{}", unique());
    create(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let npm = Npm::new(&srv, &repo, Some(token));
    for bad in ["..%2f..%2fadmin", "%2e%2e", "a%2fb", "-/nope"] {
        let status = npm
            .req(reqwest::Method::GET, bad)
            .send()
            .await
            .unwrap()
            .status();
        assert!(status == 404 || status == 400, "{bad}: {status}");
    }
    // The format is listed with its kinds and storage.
    let formats: Value = admin(&srv, reqwest::Method::GET, "/admin/formats", json!({}))
        .await
        .json()
        .await
        .unwrap();
    let npm_format = formats
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "npm")
        .expect("npm listed");
    assert!(npm_format.get("mount").is_none());
    assert_eq!(npm_format["kinds"], json!(["hosted", "proxy", "group"]));
}
