//! E2E: a Forge proxy in front of a Forge group whose public proxy member
//! cannot reach its upstream (#14). An id only that member could serve is
//! "unknown", not "absent": the group answers a retryable 5xx instead of a
//! 404, so the downstream proxy records no package-wide not-found and serves
//! the package as soon as the upstream is back. Requires Docker (or
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`).

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// The in-process feeds the test server talks to.
struct Feeds {
    base: String,
    /// The group's real base (`{server}/v3/{group}`).
    group_base: String,
    /// While set, the public feed answers every request with 503.
    down: AtomicBool,
}

/// Serve two stand-ins on one loopback port:
/// * `/feed/…` — the public feed behind the group's proxy member, holding
///   `Public.Lib 1.0.0` (503 while [`Feeds::down`] is set);
/// * `/group/index.json` — the group's service index pointing at the server's
///   real address. The harness advertises `http://test.local`, which the
///   downstream proxy could not reach.
async fn start_feeds(group_base: String) -> Arc<Feeds> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind feeds");
    let feeds = Arc::new(Feeds {
        base: format!("http://{}", listener.local_addr().unwrap()),
        group_base,
        down: AtomicBool::new(true),
    });
    let app = Router::new()
        .route("/feed/index.json", get(feed_index))
        .route("/feed/flat/{id}/index.json", get(feed_versions))
        .route("/group/index.json", get(group_index))
        .with_state(feeds.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve feeds");
    });
    feeds
}

async fn feed_index(State(feeds): State<Arc<Feeds>>) -> Response {
    if feeds.down.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(json!({
        "version": "3.0.0",
        "resources": [
            {"@id": format!("{}/feed/flat/", feeds.base), "@type": "PackageBaseAddress/3.0.0"},
        ],
    }))
    .into_response()
}

async fn feed_versions(State(feeds): State<Arc<Feeds>>, Path(id): Path<String>) -> Response {
    if feeds.down.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    match id.as_str() {
        "public.lib" => Json(json!({"versions": ["1.0.0"]})).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn group_index(State(feeds): State<Arc<Feeds>>) -> Response {
    Json(json!({
        "version": "3.0.0",
        "resources": [
            {"@id": format!("{}/flat/", feeds.group_base), "@type": "PackageBaseAddress/3.0.0"},
            {"@id": format!("{}/registration/", feeds.group_base), "@type": "RegistrationsBaseUrl/3.6.0"},
        ],
    }))
    .into_response()
}

#[tokio::test]
async fn downstream_proxy_does_not_cache_a_miss_while_a_group_member_is_failing() {
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            ..Default::default()
        },
    )
    .await;
    srv.set_auth_settings(serde_json::json!({"anonymous_mode": "all"}))
        .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let (hosted, public, group, downstream) = (
        format!("ghost{s}"),
        format!("gpub{s}"),
        format!("ggrp{s}"),
        format!("gdown{s}"),
    );
    let feeds = start_feeds(format!("{}/v3/{group}", srv.base_url)).await;

    // Group G = hosted H (answers, has nothing) + proxy P of the public feed;
    // D proxies G, reading it anonymously like a second Forge would.
    let proxy = |remote_url: String| {
        json!({
            "kind": "proxy",
            "anonymous_read": true,
            "remote_url": remote_url,
            "package_delay_seconds": 0,
            "metadata_ttl_seconds": 600,
            "not_found_ttl_seconds": 600,
        })
    };
    for (name, mut body) in [
        (&hosted, json!({"kind": "hosted", "anonymous_read": true})),
        (&public, proxy(format!("{}/feed/index.json", feeds.base))),
        (&group, json!({"kind": "group", "anonymous_read": true})),
        (
            &downstream,
            proxy(format!("{}/group/index.json", feeds.base)),
        ),
    ] {
        body["name"] = json!(name);
        let resp = client
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    }
    for (member, priority) in [(&hosted, 20), (&public, 10)] {
        let resp = client
            .post(format!(
                "{}/admin/repositories/{group}/members",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p))
            .json(&json!({"member": member, "priority": priority}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    }
    let get = |path: String| {
        client
            .get(format!("{}/v3/{path}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .send()
    };

    // The public feed is down: the group cannot tell whether the id exists.
    for path in [
        format!("{group}/flat/public.lib/index.json"),
        format!("{group}/registration/public.lib/index.json"),
        format!("{group}/registration/public.lib/1.0.0.json"),
        format!("{downstream}/flat/public.lib/index.json"),
    ] {
        let status = get(path.clone()).await.unwrap().status();
        assert!(
            status.is_server_error(),
            "{path}: a failing member makes an empty answer an error, got {status}"
        );
    }

    // The feed recovers. Had the group answered 404, the downstream proxy
    // would keep answering 404 for `not_found_ttl_seconds`.
    feeds.down.store(false, Ordering::SeqCst);
    for path in [
        format!("{group}/flat/public.lib/index.json"),
        format!("{downstream}/flat/public.lib/index.json"),
    ] {
        let resp = get(path.clone()).await.unwrap();
        assert_eq!(resp.status(), 200, "{path}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["versions"], json!(["1.0.0"]), "{path}");
    }

    // A genuine miss is still a 404 through both.
    for path in [
        format!("{group}/flat/no.such.package/index.json"),
        format!("{downstream}/flat/no.such.package/index.json"),
    ] {
        assert_eq!(get(path.clone()).await.unwrap().status(), 404, "{path}");
    }
}

/// #283: a proxy whose upstream cannot be reached, with nothing cached for
/// the request, answers 503 with `Retry-After` (an upstream outage), not 500
/// (a fault of Forge); so does a group whose member it is. What is answered
/// locally (NuGet's service index) is still served.
#[tokio::test]
async fn a_proxy_of_an_unreachable_upstream_answers_503() {
    // Nothing listens on the port: connection refused.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let creds = (srv.admin_user.clone().unwrap(), srv.admin_token().await);
    let client = srv.client();
    let s = common::unique();
    let (nuget, group) = (format!("ndown{s}"), format!("gdown{s}"));
    for body in [
        json!({ "name": nuget, "kind": "proxy", "remote_url": format!("http://{closed}/v3/index.json") }),
        json!({ "name": group, "kind": "group" }),
    ] {
        let resp = client
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    }
    let resp = client
        .post(format!(
            "{}/admin/repositories/{group}/members",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({ "member": nuget, "priority": 10 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    let get = |path: String| {
        client
            .get(format!("{}{path}", srv.base_url))
            .basic_auth(&creds.0, Some(&creds.1))
            .send()
    };
    for path in [
        format!("/v3/{nuget}/flat/sample.lib/index.json"),
        format!("/v3/{nuget}/registration/sample.lib/index.json"),
        format!("/v3/{nuget}/flat/sample.lib/1.0.0/sample.lib.1.0.0.nupkg"),
        format!("/v3/{group}/flat/sample.lib/index.json"),
        format!("/v3/{group}/registration/sample.lib/index.json"),
    ] {
        let resp = get(path.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(resp.headers()["retry-after"], "30", "{path}");
    }
    let resp = get(format!("/v3/{nuget}/index.json")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
