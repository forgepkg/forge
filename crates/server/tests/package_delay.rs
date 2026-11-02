//! E2E: a NuGet proxy's package-delay overrides and versions released from
//! the delay early (#184). The flat index, registration, search, downloads
//! and the browse API honour the delay of each package (its override's, or
//! the repository's default), a released version is served at once, and
//! editing the overrides or a content selector they name takes effect
//! without waiting for the metadata TTL. Requires Docker (or
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`).

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// The upstream feed: a service index naming only its flat container, and
/// the versions of each id in [`Feed::versions`].
struct Feed {
    base: String,
    versions: Mutex<HashMap<String, Vec<String>>>,
}

impl Feed {
    fn publish(&self, id: &str, version: &str) {
        self.versions
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_default()
            .push(version.to_string());
    }
}

async fn start_feed(packages: &[(&str, &str)]) -> Arc<Feed> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind feed");
    let feed = Arc::new(Feed {
        base: format!("http://{}", listener.local_addr().unwrap()),
        versions: Mutex::new(HashMap::new()),
    });
    for (id, version) in packages {
        feed.publish(id, version);
    }
    let app = Router::new()
        .route("/index.json", get(feed_index))
        .route("/flat/{id}/index.json", get(feed_versions))
        .route("/flat/{id}/{version}/{file}", get(feed_package))
        .with_state(feed.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve feed");
    });
    feed
}

async fn feed_index(State(feed): State<Arc<Feed>>) -> Json<Value> {
    Json(json!({
        "version": "3.0.0",
        "resources": [
            {"@id": format!("{}/flat/", feed.base), "@type": "PackageBaseAddress/3.0.0"},
        ],
    }))
}

async fn feed_versions(State(feed): State<Arc<Feed>>, Path(id): Path<String>) -> Response {
    match feed.versions.lock().unwrap().get(&id) {
        Some(versions) => Json(json!({"versions": versions})).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn feed_package(
    State(feed): State<Arc<Feed>>,
    Path((id, version, file)): Path<(String, String, String)>,
) -> Response {
    let known = feed
        .versions
        .lock()
        .unwrap()
        .get(&id)
        .is_some_and(|v| v.contains(&version));
    if known && file.ends_with(".nupkg") {
        common::make_nupkg(&id, &version).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// The admin and feed calls of one test, as the bootstrap admin.
struct Client<'a> {
    srv: &'a common::TestServer,
    client: reqwest::Client,
    user: String,
    secret: String,
}

impl<'a> Client<'a> {
    fn new(srv: &'a common::TestServer) -> Self {
        let (user, secret) = srv.admin_basic();
        Client {
            srv,
            client: srv.client(),
            user,
            secret,
        }
    }

    async fn send(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.srv.base_url))
            .basic_auth(&self.user, Some(&self.secret));
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        self.send(reqwest::Method::POST, path, Some(body)).await
    }

    async fn put(&self, path: &str, body: Value) -> (u16, Value) {
        self.send(reqwest::Method::PUT, path, Some(body)).await
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        self.send(reqwest::Method::GET, path, None).await
    }

    /// The versions the proxy's flat index lists for `id` (none on a 404).
    async fn flat(&self, repo: &str, id: &str) -> Vec<String> {
        let (status, body) = self
            .get(&format!("/repository/{repo}/flat/{id}/index.json"))
            .await;
        match status {
            404 => Vec::new(),
            200 => serde_json::from_value(body["versions"].clone()).unwrap(),
            other => panic!("flat index of {id}: {other} {body}"),
        }
    }

    /// The status of a download of `id` `version`.
    async fn download(&self, repo: &str, id: &str, version: &str) -> u16 {
        let resp = self
            .client
            .get(format!(
                "{}/repository/{repo}/flat/{id}/{version}/{id}.{version}.nupkg",
                self.srv.base_url
            ))
            .basic_auth(&self.user, Some(&self.secret))
            .send()
            .await
            .unwrap();
        resp.status().as_u16()
    }

    /// The versions the registration index lists for `id` (none on a 404).
    async fn registration(&self, repo: &str, id: &str) -> Vec<String> {
        let (status, body) = self
            .get(&format!("/repository/{repo}/registration/{id}/index.json"))
            .await;
        match status {
            404 => Vec::new(),
            200 => body["items"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|page| page["items"].as_array().cloned().unwrap_or_default())
                .map(|leaf| {
                    leaf["catalogEntry"]["version"]
                        .as_str()
                        .unwrap()
                        .to_string()
                })
                .collect(),
            other => panic!("registration of {id}: {other} {body}"),
        }
    }

    /// The ids (lowercased) a search of the proxy finds.
    async fn search(&self, repo: &str) -> Vec<String> {
        let (status, body) = self
            .get(&format!("/repository/{repo}/query?q=lib&prerelease=true"))
            .await;
        assert_eq!(status, 200, "{body}");
        let mut ids: Vec<String> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hit| hit["id"].as_str().unwrap().to_lowercase())
            .collect();
        ids.sort();
        ids
    }

    async fn release(&self, repo: &str, id: &str, version: &str, reason: &str) -> (u16, Value) {
        self.post(
            &format!("/admin/repositories/{repo}/packages/{id}/versions/{version}/release-delay"),
            json!({"reason": reason}),
        )
        .await
    }
}

#[tokio::test]
async fn overrides_and_early_releases_gate_a_nuget_proxy() {
    let srv = common::start().await;
    let c = Client::new(&srv);
    let feed = start_feed(&[
        ("trusted.lib", "1.0.0"),
        ("plain.lib", "1.0.0"),
        ("risky.lib", "1.0.0"),
    ])
    .await;
    let selector = format!("trusted{}", common::unique());
    let (status, body) = c
        .post(
            "/admin/content-selectors",
            json!({"name": selector, "includes": ["trusted.*"]}),
        )
        .await;
    assert_eq!(status, 201, "{body}");

    // An hour for every package, except the selector's (none) and the
    // risky ones (two weeks); the first match decides.
    let proxy = format!("pdprox{}", common::unique());
    let overrides = json!([
        {"selector": selector, "delay_seconds": 0},
        {"pattern": "Risky.*", "delay_seconds": 1_209_600},
    ]);
    let (status, view) = c
        .post(
            "/admin/repositories",
            json!({
                "name": proxy,
                "kind": "proxy",
                "remote_url": format!("{}/index.json", feed.base),
                "package_delay_seconds": 3600,
                "metadata_ttl_seconds": 3600,
                "package_delay_overrides": overrides,
            }),
        )
        .await;
    assert_eq!(status, 201, "{view}");
    assert_eq!(view["package_delay_overrides"], overrides);

    // The selector's package passes at once; the others wait.
    assert_eq!(c.flat(&proxy, "trusted.lib").await, ["1.0.0"]);
    assert!(c.flat(&proxy, "plain.lib").await.is_empty());
    assert!(c.flat(&proxy, "risky.lib").await.is_empty());
    assert_eq!(c.download(&proxy, "trusted.lib", "1.0.0").await, 200);
    assert_eq!(c.download(&proxy, "plain.lib", "1.0.0").await, 404);
    assert_eq!(c.registration(&proxy, "trusted.lib").await, ["1.0.0"]);
    assert!(c.registration(&proxy, "plain.lib").await.is_empty());
    assert_eq!(c.search(&proxy).await, ["trusted.lib"]);

    // The browse API says which delay applies, and why.
    let (status, detail) = c
        .get(&format!("/browse/packages/{proxy}/trusted.lib"))
        .await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(
        detail["package_delay"],
        json!({"delay_seconds": 0, "source": {"kind": "selector", "name": selector}})
    );
    let (status, detail) = c.get(&format!("/browse/packages/{proxy}/plain.lib")).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(
        detail["package_delay"],
        json!({"delay_seconds": 3600, "source": {"kind": "default"}})
    );
    assert_eq!(detail["versions"][0]["delay_status"], "delayed_until");

    // Releasing one version early needs a reason.
    let (status, _) = c.release(&proxy, "plain.lib", "1.0.0", "  ").await;
    assert_eq!(status, 400);
    let (status, release) = c
        .release(
            &proxy,
            "Plain.Lib",
            "1.0.0",
            "CVE-2026-0001: the fix must ship today",
        )
        .await;
    assert_eq!(status, 201, "{release}");
    assert_eq!(release["package"], "plain.lib");
    assert_eq!(release["version"], "1.0.0");
    assert_eq!(release["reason"], "CVE-2026-0001: the fix must ship today");
    assert_eq!(release["seen"], true);
    assert!(release["released_by"]
        .as_str()
        .is_some_and(|by| !by.is_empty()));
    // Again: the first release stays.
    let (status, again) = c.release(&proxy, "plain.lib", "1.0.0", "other").await;
    assert_eq!(status, 200);
    assert_eq!(again["reason"], release["reason"]);

    // Exactly that version is served now, everywhere.
    assert_eq!(c.flat(&proxy, "plain.lib").await, ["1.0.0"]);
    assert_eq!(c.download(&proxy, "plain.lib", "1.0.0").await, 200);
    assert_eq!(c.registration(&proxy, "plain.lib").await, ["1.0.0"]);
    assert_eq!(c.search(&proxy).await, ["plain.lib", "trusted.lib"]);
    let (_, detail) = c.get(&format!("/browse/packages/{proxy}/plain.lib")).await;
    assert_eq!(detail["versions"][0]["delay_status"], "available");
    assert!(detail["versions"][0]["delay_released_at"].is_string());

    // A version not seen upstream yet can be released by name; it applies
    // once the proxy sees it.
    let (status, pending) = c
        .release(
            &proxy,
            "risky.lib",
            "2.0.0",
            "the vendor's hotfix, verified",
        )
        .await;
    assert_eq!(status, 201, "{pending}");
    assert_eq!(pending["seen"], false);

    // Two hours later: the default delay is over, the risky one is not.
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = first_seen_at - interval '2 hours' \
         WHERE repository_id = (SELECT id FROM repository WHERE name = $1)",
    )
    .bind(&proxy)
    .execute(&srv.pool)
    .await
    .unwrap();
    feed.publish("risky.lib", "2.0.0");
    feed.publish("trusted.lib", "1.1.0");
    let (status, _) = c
        .post(
            &format!("/admin/repositories/{proxy}/proxy-cache/invalidate"),
            json!({}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(c.flat(&proxy, "risky.lib").await, ["2.0.0"]);
    assert_eq!(c.download(&proxy, "risky.lib", "2.0.0").await, 200);
    assert_eq!(c.download(&proxy, "risky.lib", "1.0.0").await, 404);
    assert_eq!(c.flat(&proxy, "trusted.lib").await, ["1.0.0", "1.1.0"]);
    assert_eq!(
        c.search(&proxy).await,
        ["plain.lib", "risky.lib", "trusted.lib"]
    );
    let (status, releases) = c
        .get(&format!("/admin/repositories/{proxy}/delay-releases"))
        .await;
    assert_eq!(status, 200);
    let releases = releases.as_array().unwrap();
    assert_eq!(releases.len(), 2, "{releases:?}");
    assert!(releases.iter().all(|r| r["seen"] == true), "{releases:?}");

    // Withdrawn, the version waits out its delay again.
    let path =
        format!("/admin/repositories/{proxy}/packages/risky.lib/versions/2.0.0/release-delay");
    let (status, _) = c.send(reqwest::Method::DELETE, &path, None).await;
    assert_eq!(status, 204);
    let (status, _) = c.send(reqwest::Method::DELETE, &path, None).await;
    assert_eq!(status, 404);
    assert!(c.flat(&proxy, "risky.lib").await.is_empty());

    // A selector an override names is not deleted.
    let (_, selectors) = c.get("/admin/content-selectors").await;
    let selector_id = selectors
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == selector)
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (status, body) = c
        .send(
            reqwest::Method::DELETE,
            &format!("/admin/content-selectors/{selector_id}"),
            None,
        )
        .await;
    assert_eq!(status, 409);
    assert!(body.as_str().unwrap().contains(&proxy), "{body}");

    // Editing the overrides takes effect at once, without waiting for the
    // metadata TTL: the risky package is exempted, the trusted one has the
    // default again (its 1.1.0 was first seen less than an hour ago).
    let (status, view) = c
        .put(
            &format!("/admin/repositories/{proxy}"),
            json!({"package_delay_overrides": [{"pattern": "risky.*", "delay_seconds": 0}]}),
        )
        .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(c.flat(&proxy, "risky.lib").await, ["1.0.0", "2.0.0"]);
    assert_eq!(c.flat(&proxy, "trusted.lib").await, ["1.0.0"]);

    // So does editing a selector an override names.
    let (status, _) = c
        .put(
            &format!("/admin/repositories/{proxy}"),
            json!({"package_delay_overrides": [{"selector": selector, "delay_seconds": 0}]}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(c.flat(&proxy, "trusted.lib").await, ["1.0.0", "1.1.0"]);
    let (status, _) = c
        .send(
            reqwest::Method::PATCH,
            &format!("/admin/content-selectors/{selector_id}"),
            Some(json!({"includes": ["risky.*"]})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(c.flat(&proxy, "trusted.lib").await, ["1.0.0"]);
    assert_eq!(c.flat(&proxy, "risky.lib").await, ["1.0.0", "2.0.0"]);

    // Cleared, the selector can go.
    let (status, _) = c
        .put(
            &format!("/admin/repositories/{proxy}"),
            json!({"package_delay_overrides": []}),
        )
        .await;
    assert_eq!(status, 200);
    let (status, _) = c
        .send(
            reqwest::Method::DELETE,
            &format!("/admin/content-selectors/{selector_id}"),
            None,
        )
        .await;
    assert_eq!(status, 204);
}

#[tokio::test]
async fn package_delay_overrides_and_releases_are_validated() {
    let srv = common::start().await;
    let c = Client::new(&srv);
    let proxy = |overrides: Value| {
        json!({
            "name": format!("pdval{}", common::unique()),
            "kind": "proxy",
            "remote_url": "https://api.nuget.org/v3/index.json",
            "package_delay_overrides": overrides,
        })
    };
    for (overrides, why) in [
        (
            json!([{"selector": "no-such-selector", "delay_seconds": 0}]),
            "unknown selector",
        ),
        (
            json!([{"pattern": "a[", "delay_seconds": 0}]),
            "invalid glob",
        ),
        (
            json!([{"pattern": "", "delay_seconds": 0}]),
            "empty pattern",
        ),
        (
            json!([{"pattern": "a.*", "delay_seconds": -1}]),
            "negative delay",
        ),
        (
            json!([{"pattern": "a.*", "delay_seconds": 31_536_001}]),
            "over a year",
        ),
        (
            json!([{"pattern": "a.*", "delay_seconds": 99_999_999_999_i64}]),
            "far too large",
        ),
        (
            json!([{"selector": "x", "pattern": "a.*", "delay_seconds": 0}]),
            "both a selector and a pattern",
        ),
        (json!([{"delay_seconds": 0}]), "neither"),
    ] {
        let (status, body) = c.post("/admin/repositories", proxy(overrides)).await;
        assert_eq!(status, 400, "{why}: {body}");
    }

    // Only a proxy with a package delay takes overrides.
    let (status, _) = c
        .post(
            "/admin/repositories",
            json!({
                "name": format!("pdhost{}", common::unique()),
                "kind": "hosted",
                "package_delay_overrides": [{"pattern": "a.*", "delay_seconds": 0}],
            }),
        )
        .await;
    assert_eq!(status, 400, "hosted");
    let (status, _) = c
        .post(
            "/admin/repositories",
            json!({
                "name": format!("pddock{}", common::unique()),
                "kind": "proxy",
                "format": "docker",
                "remote_url": "https://registry-1.docker.io",
                "package_delay_overrides": [{"pattern": "a.*", "delay_seconds": 0}],
            }),
        )
        .await;
    assert_eq!(status, 400, "docker");

    // A valid one is stored; an update is validated as well.
    let body = proxy(json!([{"pattern": " Acme.* ", "delay_seconds": 0}]));
    let name = body["name"].as_str().unwrap().to_string();
    let (status, view) = c.post("/admin/repositories", body).await;
    assert_eq!(status, 201, "{view}");
    assert_eq!(
        view["package_delay_overrides"],
        json!([{"pattern": "Acme.*", "delay_seconds": 0}])
    );
    let (status, _) = c
        .put(
            &format!("/admin/repositories/{name}"),
            json!({"package_delay_overrides": [{"pattern": "a.*", "delay_seconds": -5}]}),
        )
        .await;
    assert_eq!(status, 400);
    let (_, view) = c.get(&format!("/admin/repositories/{name}")).await;
    assert_eq!(
        view["package_delay_overrides"],
        json!([{"pattern": "Acme.*", "delay_seconds": 0}]),
        "a refused update keeps the overrides"
    );

    // Releases: only proxies with a package delay, valid ids and versions.
    let hosted = format!("pdrel{}", common::unique());
    let (status, _) = c
        .post(
            "/admin/repositories",
            json!({"name": hosted, "kind": "hosted"}),
        )
        .await;
    assert_eq!(status, 201);
    let (status, _) = c.release(&hosted, "a.b", "1.0.0", "why").await;
    assert_eq!(status, 400, "hosted");
    let (status, _) = c.release("no-such-repo", "a.b", "1.0.0", "why").await;
    assert_eq!(status, 404);
    let (status, _) = c.release(&name, "a.b", "not a version", "why").await;
    assert_eq!(status, 400, "invalid version");
    let (status, _) = c.release(&name, "a.b", "1.0.0", &"x".repeat(1001)).await;
    assert_eq!(status, 400, "reason too long");
}
