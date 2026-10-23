//! Integration tests for the static SPA serving layer (plan §12.6 Phase 1).
//!
//! Verifies the correctness properties the serving model depends on:
//! * the API routers (`/admin/*`, `/browse/*`, `/v3/*`) are **not** shadowed by
//!   the SPA fallback;
//! * unknown (client-side) paths fall back to `index.html` so TanStack Router
//!   can resolve deep links — including the admin UI under `/manage/*` — but a
//!   missing hashed asset under `/assets/` and an unknown path under an API
//!   prefix are a 404;
//! * `index.html` is `no-cache`, hashed assets are `immutable`;
//! * every request under `/admin/...`, a browser navigation included, reaches
//!   the admin API.
//!
//! Requires Docker (Postgres + versitygw via the shared harness).

mod common;

use std::fs;

use common::{start_with, ServerOpts};

/// Write a recognizable `index.html` + a real asset file into a temp dir and
/// return its path (leaked so it outlives the server for the test's duration).
fn build_fake_spa() -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_string_lossy().to_string();
    fs::write(
        dir.path().join("index.html"),
        "<!doctype html><html><head><title>forge-spa</title></head><body><div id=\"root\"></div></body></html>",
    )
    .expect("write index.html");
    let assets = dir.path().join("assets");
    fs::create_dir_all(&assets).expect("assets dir");
    fs::write(assets.join("app.js"), "console.log('forge');").expect("write app.js");
    // Leak the TempDir guard so the files survive for the test process.
    std::mem::forget(dir);
    path
}

#[tokio::test]
async fn spa_serving_and_api_precedence() {
    let assets_dir = build_fake_spa();
    let admin = format!("admin{}", common::unique());
    let server = start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((admin, "adminpw".into())),
            web_assets_dir: Some(assets_dir),
            ..Default::default()
        },
    )
    .await;
    let client = server.client();

    // 1. `GET /` serves the SPA shell.
    let res = client
        .get(format!("{}/", server.base_url))
        .send()
        .await
        .expect("GET /");
    let status = res.status();
    let body = res.text().await.expect("body");
    assert_eq!(status, reqwest::StatusCode::OK, "GET / body: {body}");
    assert!(
        body.contains("forge-spa"),
        "GET / should serve index.html: {body}"
    );

    // 2. An unknown client-side route falls back to index.html (SPA history
    //    fallback) so the router can resolve it client-side.
    let res = client
        .get(format!("{}/repositories/anything", server.base_url))
        .send()
        .await
        .expect("GET deep link");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body = res.text().await.expect("body");
    assert!(
        body.contains("forge-spa"),
        "deep link should fall back to index.html: {body}"
    );

    // 3. A real asset file is served as itself (not the index fallback).
    let res = client
        .get(format!("{}/assets/app.js", server.base_url))
        .send()
        .await
        .expect("GET asset");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body = res.text().await.expect("body");
    assert!(body.contains("console.log('forge')"), "asset body: {body}");

    // 4. The API is NOT shadowed by the SPA fallback: `/admin/me` without
    //    credentials returns 401 (the endpoint), not index.html.
    let res = client
        .get(format!("{}/admin/me", server.base_url))
        .send()
        .await
        .expect("GET /admin/me");
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body = res.text().await.expect("body");
    assert!(
        !body.contains("forge-spa"),
        "/admin/me must hit the API, not the SPA fallback: {body}"
    );

    // 5. `/admin/me` WITH admin credentials returns the identity JSON.
    let (u, p) = server.admin_basic();
    let me: serde_json::Value = client
        .get(format!("{}/admin/me", server.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .expect("GET /admin/me authed")
        .json()
        .await
        .expect("json");
    assert_eq!(me["is_admin"], serde_json::json!(true));
    assert_eq!(me["user"]["username"], serde_json::json!(u));

    // 6. A path under an API prefix that no route matches is a 404, never the
    //    SPA shell (a script calling a mistyped endpoint must not see 200).
    for path in [
        "/admin/does-not-exist",
        "/admin/repositories/x/y/z/w",
        "/auth/does-not-exist",
        "/browse/does-not-exist",
        "/v3",
        "/v3/",
    ] {
        for authed in [false, true] {
            let mut req = client.get(format!("{}{path}", server.base_url));
            if authed {
                req = req.basic_auth(&u, Some(&p));
            }
            let res = req.send().await.expect("GET unknown API path");
            assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND, "{path}");
            let body = res.text().await.expect("body");
            assert!(!body.contains("forge-spa"), "{path}: {body}");
        }
    }
    // A UI path that merely starts with the same letters is still the SPA.
    let res = client
        .get(format!("{}/administrator", server.base_url))
        .send()
        .await
        .expect("GET /administrator");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

/// The `Cache-Control` header of a response, as a string.
fn cache_control(res: &reqwest::Response) -> Option<String> {
    res.headers()
        .get(reqwest::header::CACHE_CONTROL)
        .map(|v| v.to_str().expect("ascii cache-control").to_string())
}

/// Request headers for one case, as `(name, value)` pairs.
type Headers = &'static [(&'static str, &'static str)];

/// A browser's top-level navigation headers (Chrome).
const NAV_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

#[tokio::test]
async fn spa_cache_headers_missing_assets_and_admin_ui_paths() {
    let assets_dir = build_fake_spa();
    let admin = format!("admin{}", common::unique());
    let server = start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((admin, "adminpw".into())),
            web_assets_dir: Some(assets_dir),
            ..Default::default()
        },
    )
    .await;
    // Redirects are asserted, not followed.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let base = &server.base_url;

    // 1. index.html (root and SPA fallback) must be revalidated on every use.
    for path in ["/", "/repos/anything", "/manage/repositories"] {
        let res = client
            .get(format!("{base}{path}"))
            .send()
            .await
            .expect("GET shell");
        assert_eq!(res.status(), reqwest::StatusCode::OK, "{path}");
        assert_eq!(cache_control(&res).as_deref(), Some("no-cache"), "{path}");
        let body = res.text().await.expect("body");
        assert!(
            body.contains("forge-spa"),
            "{path} serves index.html: {body}"
        );
    }

    // 2. Hashed assets are cacheable forever.
    let res = client
        .get(format!("{base}/assets/app.js"))
        .send()
        .await
        .expect("GET asset");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    assert_eq!(
        cache_control(&res).as_deref(),
        Some("public, max-age=31536000, immutable")
    );

    // 3. A missing asset (e.g. last deploy's chunk) is a 404, not index.html.
    let res = client
        .get(format!("{base}/assets/app-0ld.js"))
        .send()
        .await
        .expect("GET missing asset");
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(cache_control(&res).as_deref(), Some("no-cache"));
    let body = res.text().await.expect("body");
    assert!(!body.contains("forge-spa"), "missing asset body: {body}");

    // 4. Admin UI deep links under /manage are served by the SPA.
    for path in [
        "/manage",
        "/manage/repositories/nuget",
        "/manage/repositories/all/members",
        "/manage/users/5",
        "/manage/realms/new",
    ] {
        let res = client
            .get(format!("{base}{path}"))
            .header("sec-fetch-dest", "document")
            .header("accept", NAV_ACCEPT)
            .send()
            .await
            .expect("GET /manage deep link");
        assert_eq!(res.status(), reqwest::StatusCode::OK, "{path}");
        let body = res.text().await.expect("body");
        assert!(body.contains("forge-spa"), "{path}: {body}");
    }

    // 5. Every request under /admin reaches the admin API, browser
    //    navigations included: 401 without credentials, JSON with them.
    let api_cases: [(&str, Headers); 5] = [
        ("/admin/repositories", &[("accept", "application/json")]),
        (
            "/admin/repositories?tab=2",
            &[("sec-fetch-dest", "document"), ("accept", NAV_ACCEPT)],
        ),
        ("/admin/users/5", &[("accept", NAV_ACCEPT)]),
        ("/admin/users/5", &[("accept", "*/*")]),
        ("/admin/me", &[("sec-fetch-dest", "document")]),
    ];
    for (path, headers) in api_cases {
        let mut req = client.get(format!("{base}{path}"));
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let res = req.send().await.expect("GET admin API");
        assert_eq!(
            res.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path} {headers:?}"
        );
    }
    let (u, p) = server.admin_basic();
    let res = client
        .get(format!("{base}/admin/repositories"))
        .basic_auth(&u, Some(&p))
        .header("accept", "application/json")
        .send()
        .await
        .expect("GET /admin/repositories authed");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let repos: serde_json::Value = res.json().await.expect("json");
    assert!(repos.is_array(), "API returns the repository list: {repos}");
}
