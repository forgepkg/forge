//! Alias base URLs (`server.alias_base_urls`, #312): a request whose `Host`
//! names an alias is answered with the client protocols' URLs on that alias
//! (NuGet, npm, the registry's token realm and service), a `Host` that is no
//! alias keeps today's URLs on `server.public_base_url`, browser surfaces stay
//! on the public URL, the admin API and startup refuse a docker repository
//! host of an alias, and an alias is one of the server's own names for the
//! trusted-header realms.
//!
//! The test servers listen on loopback; a request names the host it is for
//! with the `Host` header, as a reverse proxy that keeps `Host` forwards it.
//! The same flows with real clients (dotnet, docker, helm) are in
//! `crates/e2e/tests/alias_hosts.rs`.
//!
//! Requires Docker (Postgres + S3 testcontainers) on the host.

mod common;

use base64::Engine as _;
use common::{unique, ServerOpts, TestServer};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST, LOCATION, WWW_AUTHENTICATE};
use reqwest::{Method, RequestBuilder, StatusCode};
use serde_json::{json, Value};
use sha2::Digest as _;

/// `server.public_base_url` of the test servers.
const PUBLIC: &str = "http://forge.test";

/// `server.alias_base_urls` of the test servers.
const ALIASES: &str = r#"alias_base_urls = ["https://nexus.test", "http://old.test:8081"]"#;

/// A server on [`PUBLIC`] with the [`ALIASES`], `server_extra` lines further
/// in its `[server]` section.
async fn start(opts: ServerOpts) -> TestServer {
    let server_extra = match &opts.server_extra {
        Some(extra) => format!("{ALIASES}\n{extra}"),
        None => ALIASES.to_string(),
    };
    common::start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            public_base_url: Some(PUBLIC.into()),
            server_extra: Some(server_extra),
            ..opts
        },
    )
    .await
}

/// A request to `path` as a client addressing `host` sends it.
fn on(srv: &TestServer, method: Method, host: &str, path: &str) -> RequestBuilder {
    srv.client()
        .request(method, format!("{}{path}", srv.base_url))
        .header(HOST, host)
}

/// An admin API call; returns the status and the body (JSON, or text).
async fn admin(srv: &TestServer, method: Method, path: &str, body: Value) -> (StatusCode, Value) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn create_repo(srv: &TestServer, body: Value) {
    let (status, created) = admin(srv, Method::POST, "/admin/repositories", body).await;
    assert_eq!(status, 201, "{created}");
}

/// Every string in `value`, recursively.
fn strings(value: &Value) -> Vec<&str> {
    match value {
        Value::String(s) => vec![s.as_str()],
        Value::Array(items) => items.iter().flat_map(strings).collect(),
        Value::Object(map) => map.values().flat_map(strings).collect(),
        _ => Vec::new(),
    }
}

/// The absolute URLs of `value`.
fn urls(value: &Value) -> Vec<&str> {
    strings(value)
        .into_iter()
        .filter(|s| s.starts_with("http://") || s.starts_with("https://"))
        .collect()
}

#[tokio::test]
async fn nuget_urls_follow_the_alias_the_request_named() {
    let srv = start(ServerOpts::default()).await;
    let repo = format!("nuget{}", unique());
    create_repo(&srv, json!({"name": repo, "kind": "hosted"})).await;
    let id = format!("Alias.Pkg{}", unique());
    let part = reqwest::multipart::Part::bytes(common::make_nupkg(&id, "1.0.0"))
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let resp = on(
        &srv,
        Method::PUT,
        "nexus.test",
        &format!("/repository/{repo}/package"),
    )
    .header("X-NuGet-ApiKey", srv.admin_token().await)
    .multipart(reqwest::multipart::Form::new().part("package", part))
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 201, "a push through the alias");

    let (u, p) = srv.admin_basic();
    let fetch = |host: &'static str, path: String| {
        let rb = on(&srv, Method::GET, host, &path).basic_auth(&u, Some(&p));
        async move {
            let resp = rb.send().await.unwrap();
            assert_eq!(resp.status(), 200, "{host} {path}");
            resp.json::<Value>().await.unwrap()
        }
    };
    let index = format!("/repository/{repo}/index.json");
    let registration = format!(
        "/repository/{repo}/registration/{}/index.json",
        id.to_lowercase()
    );
    for (host, base) in [
        // An alias, whatever the case, a trailing dot or the port.
        ("nexus.test", "https://nexus.test"),
        ("NEXUS.test.:443", "https://nexus.test"),
        // The port is the alias's own (a proxy may drop it from `Host`).
        ("old.test", "http://old.test:8081"),
        ("old.test:8081", "http://old.test:8081"),
        // The public host, and a host that is no alias: today's URLs.
        ("forge.test", PUBLIC),
        ("evil.test", PUBLIC),
    ] {
        let prefix = format!("{base}/repository/{repo}/");
        for path in [&index, &registration] {
            let doc = fetch(host, path.clone()).await;
            let found = urls(&doc);
            assert!(!found.is_empty(), "{host} {path}: {doc}");
            for url in found {
                assert!(url.starts_with(&prefix), "{host} {path}: {url}");
            }
        }
    }
}

/// A gzip-compressed npm tarball of `name@version`.
fn tgz(name: &str, version: &str) -> Vec<u8> {
    let package_json = json!({"name": name, "version": version}).to_string();
    forge_format_npm::tarball::build(&[("package/package.json", package_json.as_bytes())])
}

#[tokio::test]
async fn npm_urls_follow_the_alias_and_the_browser_stays_on_the_public_url() {
    let srv = start(ServerOpts::default()).await;
    let repo = format!("npm{}", unique());
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "npm"}),
    )
    .await;
    let token = srv.admin_token().await;
    let tarball = tgz("aliased", "1.0.0");
    let digests = forge_format_npm::integrity::Digests::of(tarball.as_slice()).unwrap();
    let resp = on(
        &srv,
        Method::PUT,
        "nexus.test",
        &format!("/repository/{repo}/aliased"),
    )
    .bearer_auth(&token)
    .json(&json!({
        "_id": "aliased",
        "name": "aliased",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "name": "aliased", "version": "1.0.0", "_id": "aliased@1.0.0",
            "dist": {"integrity": digests.integrity(), "shasum": digests.sha1_hex,
                     "tarball": "http://localhost/aliased-1.0.0.tgz"}
        }},
        "_attachments": {"aliased-1.0.0.tgz": {
            "content_type": "application/octet-stream",
            "data": base64::engine::general_purpose::STANDARD.encode(&tarball),
            "length": tarball.len()
        }}
    }))
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    for (host, base) in [("nexus.test", "https://nexus.test"), ("evil.test", PUBLIC)] {
        let doc: Value = on(
            &srv,
            Method::GET,
            host,
            &format!("/repository/{repo}/aliased"),
        )
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(
            doc["versions"]["1.0.0"]["dist"]["tarball"],
            format!("{base}/repository/{repo}/aliased/-/aliased-1.0.0.tgz"),
            "{host}"
        );
    }

    // `npm login --auth-type=web` through the alias: npm polls the alias,
    // the browser signs in on the public URL.
    let start: Value = on(
        &srv,
        Method::POST,
        "nexus.test",
        &format!("/repository/{repo}/-/v1/login"),
    )
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
        login_url.starts_with(&format!("{PUBLIC}/cli-login/")),
        "{login_url}"
    );
    assert!(
        done_url.starts_with(&format!(
            "https://nexus.test/repository/{repo}/-/v1/login/done/"
        )),
        "{done_url}"
    );

    // The connect snippets of the web UI name the public URL whatever host
    // the browser API was asked on.
    let session = srv.login(srv.admin_user.as_ref().unwrap(), "adminpw").await;
    let listed: Value = session
        .apply(on(&srv, Method::GET, "nexus.test", "/browse/repos"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ours = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == repo.as_str())
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(ours["url"], format!("{PUBLIC}/repository/{repo}"));
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// A registry token for `scope`, asked for on `host`.
async fn registry_token(srv: &TestServer, host: &str, scope: &str, password: &str) -> String {
    let resp = on(srv, Method::GET, host, "/v2/token")
        .query(&[("scope", scope)])
        .basic_auth(srv.admin_user.as_ref().unwrap(), Some(password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "token on {host}");
    let body: Value = resp.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn the_registry_challenges_and_serves_an_alias_on_the_alias() {
    let srv = start(ServerOpts::default()).await;
    let repo = format!("dock{}", unique());
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let password = srv.admin_token().await;

    // The challenge names the token service of the host the client asked:
    // the alias (with the alias's port), else the public host.
    for (host, realm, service) in [
        ("nexus.test", "https://nexus.test/v2/token", "nexus.test"),
        ("Nexus.Test.", "https://nexus.test/v2/token", "nexus.test"),
        ("old.test", "http://old.test:8081/v2/token", "old.test:8081"),
        ("forge.test", "http://forge.test/v2/token", "forge.test"),
        ("evil.test", "http://forge.test/v2/token", "forge.test"),
    ] {
        let resp = on(&srv, Method::GET, host, "/v2/").send().await.unwrap();
        assert_eq!(resp.status(), 401, "{host}");
        assert_eq!(
            resp.headers()[WWW_AUTHENTICATE],
            format!("Bearer realm=\"{realm}\",service=\"{service}\"").as_str(),
            "{host}"
        );
    }
    // So does the challenge of credentials the middleware refused.
    let resp = on(&srv, Method::GET, "nexus.test", "/v2/token")
        .basic_auth(srv.admin_user.as_ref().unwrap(), Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let challenge = resp.headers()[WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        challenge.contains("realm=\"https://nexus.test/v2/token\""),
        "{challenge}"
    );

    // Push and pull by path through the alias, with a token issued there.
    let name = format!("{repo}/app");
    let scope = format!("repository:{name}:pull,push");
    let token = registry_token(&srv, "nexus.test", &scope, &password).await;
    let bearer = format!("Bearer {token}");
    let config = json!({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}})
        .to_string()
        .into_bytes();
    let layer = b"an alias layer".to_vec();
    for blob in [&config, &layer] {
        let resp = on(
            &srv,
            Method::POST,
            "nexus.test",
            &format!("/v2/{name}/blobs/uploads/"),
        )
        .query(&[("digest", sha(blob))])
        .header(AUTHORIZATION, &bearer)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(blob.clone())
        .send()
        .await
        .unwrap();
        assert_eq!(resp.status(), 201, "blob push through the alias");
        let location = resp.headers()[LOCATION].to_str().unwrap();
        assert!(location.starts_with("/v2/"), "{location}");
    }
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(&config), "size": config.len()},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": sha(&layer), "size": layer.len()}],
    })
    .to_string()
    .into_bytes();
    let resp = on(
        &srv,
        Method::PUT,
        "nexus.test",
        &format!("/v2/{name}/manifests/1"),
    )
    .header(AUTHORIZATION, &bearer)
    .header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
    .body(manifest.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let resp = on(
        &srv,
        Method::GET,
        "nexus.test",
        &format!("/v2/{name}/manifests/1"),
    )
    .header(AUTHORIZATION, &bearer)
    .header("accept", "application/vnd.oci.image.manifest.v1+json")
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["docker-content-digest"],
        sha(&manifest).as_str()
    );

    // A token is for the host it was issued on: the alias's is refused on
    // the public host and on another alias, and the public host's on the
    // alias.
    for host in ["forge.test", "old.test"] {
        let resp = on(&srv, Method::GET, host, &format!("/v2/{name}/manifests/1"))
            .header(AUTHORIZATION, &bearer)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "the alias's token on {host}");
    }
    let public = registry_token(&srv, "forge.test", &scope, &password).await;
    let resp = on(
        &srv,
        Method::GET,
        "nexus.test",
        &format!("/v2/{name}/manifests/1"),
    )
    .header(AUTHORIZATION, format!("Bearer {public}"))
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 401, "the public host's token on the alias");
    let resp = on(
        &srv,
        Method::GET,
        "forge.test",
        &format!("/v2/{name}/manifests/1"),
    )
    .header(AUTHORIZATION, format!("Bearer {public}"))
    .header("accept", "application/vnd.oci.image.manifest.v1+json")
    .send()
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "path routing on the public host as before"
    );
}

#[tokio::test]
async fn a_docker_repository_host_may_not_be_an_alias() {
    let srv = start(ServerOpts::default()).await;
    let repo = format!("dock{}", unique());
    for host in ["nexus.test", "NEXUS.test.", "old.test"] {
        let (status, body) = admin(
            &srv,
            Method::POST,
            "/admin/repositories",
            json!({"name": repo, "kind": "hosted", "format": "docker", "host": host}),
        )
        .await;
        assert_eq!(status, 400, "{host}: {body}");
        let message = body.as_str().unwrap_or_default();
        assert!(
            message.contains("server.alias_base_urls"),
            "{host}: {message}"
        );
    }
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let (status, body) = admin(
        &srv,
        Method::PUT,
        &format!("/admin/repositories/{repo}"),
        json!({"host": "nexus.test"}),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    // The administrators see the names Admin -> System lists.
    let (status, addresses) = admin(&srv, Method::GET, "/admin/addresses", Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(
        addresses,
        json!({
            "public_base_url": PUBLIC,
            "alias_base_urls": ["https://nexus.test", "http://old.test:8081"],
        })
    );
    // Another host name is fine.
    let host = format!("{repo}.registry.test");
    let (status, body) = admin(
        &srv,
        Method::PUT,
        &format!("/admin/repositories/{repo}"),
        json!({"host": host}),
    )
    .await;
    assert!(status.is_success(), "{body}");
}

#[tokio::test]
async fn startup_refuses_an_alias_a_docker_repository_has_as_its_host() {
    // A repository's host stored while the server had no such alias.
    let before = common::start().await;
    let repo = format!("dock{}", unique());
    let host = format!("{repo}.registry.test");
    create_repo(
        &before,
        json!({"name": repo, "kind": "hosted", "format": "docker", "host": host}),
    )
    .await;

    let with_alias = |alias: String| ServerOpts {
        bootstrap_admin: None,
        server_extra: Some(format!("alias_base_urls = [{alias:?}]")),
        ..Default::default()
    };
    let after = common::start_with(
        common::pool().await,
        with_alias(format!("https://{}", host.to_uppercase())),
    )
    .await;
    let err = forge_server::app::check_alias_hosts(&after.state)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("server.alias_base_urls") && err.contains(&repo),
        "{err}"
    );

    let other = common::start_with(
        common::pool().await,
        with_alias(format!("https://other-{host}")),
    )
    .await;
    forge_server::app::check_alias_hosts(&other.state)
        .await
        .expect("no repository has that host");
}

#[tokio::test]
async fn a_web_ui_page_on_an_alias_redirects_to_the_public_url() {
    let assets = tempfile::tempdir().unwrap();
    std::fs::write(
        assets.path().join("index.html"),
        "<!doctype html><title>Forge</title>",
    )
    .unwrap();
    let srv = start(ServerOpts {
        web_assets_dir: Some(assets.path().to_string_lossy().into_owned()),
        ..Default::default()
    })
    .await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let get = |host: &str, path: &str| {
        client
            .get(format!("{}{path}", srv.base_url))
            .header(HOST, host)
            .send()
    };

    for path in ["/", "/manage/repositories?page=2", "/repos/x"] {
        let resp = get("nexus.test", path).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND, "{path}");
        assert_eq!(
            resp.headers()[LOCATION],
            format!("{PUBLIC}{path}").as_str(),
            "{path}"
        );
        // Served as before on the public host and on a host that is no alias.
        for host in ["forge.test", "evil.test"] {
            let resp = get(host, path).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{host} {path}");
        }
    }
    // The APIs are not redirected: a client of the admin API or a feed on
    // the alias gets its answer there.
    assert_eq!(get("nexus.test", "/admin/me").await.unwrap().status(), 401);
    assert_eq!(get("nexus.test", "/healthz").await.unwrap().status(), 200);
}

/// A trusted-header realm; returns the user and secret header names.
async fn trusted_header_realm(srv: &TestServer, secret: &str) -> (String, String, String) {
    let n = unique();
    let (user_header, secret_header) = (format!("X-User-{n}"), format!("X-Proxy-Secret-{n}"));
    let name = format!("proxy-{n}");
    let (status, body) = admin(
        srv,
        Method::POST,
        "/admin/realms",
        json!({
            "kind": "trusted_header",
            "name": name,
            "config": {"username_header": user_header, "secret_header": secret_header, "secret": secret},
        }),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    (name, user_header, secret_header)
}

#[tokio::test]
async fn an_alias_is_one_of_the_servers_own_names_for_trusted_headers() {
    // The test client is the trusted proxy; no host in `allowed_hosts`.
    let srv = start(ServerOpts {
        auth_extra: Some(r#"trusted_proxy_cidrs = ["127.0.0.1"]"#.into()),
        ..Default::default()
    })
    .await;
    let secret = "the-proxys-secret-0123456789abcdef";
    let (realm, user_header, secret_header) = trusted_header_realm(&srv, secret).await;
    let alice = format!("alice{}@example.com", unique());
    let (status, body) = admin(
        &srv,
        Method::POST,
        "/admin/users",
        json!({"username": alice, "realm": realm, "role": "reader"}),
    )
    .await;
    assert_eq!(status, 201, "{body}");

    let me = |host: &str| {
        on(&srv, Method::GET, host, "/admin/me")
            .header(&secret_header, secret)
            .header(&user_header, &alice)
            .send()
    };
    for host in ["nexus.test", "old.test:8081", "forge.test"] {
        let resp = me(host).await.unwrap();
        assert_eq!(resp.status(), 200, "{host}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["user"]["username"], alice.as_str(), "{host}");
    }
    // A host that is none of the server's names: a DNS-rebinding page.
    assert_eq!(me("rebind.attacker.example").await.unwrap().status(), 401);
}
