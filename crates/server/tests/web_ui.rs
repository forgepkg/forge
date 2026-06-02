//! Integration tests for the static SPA serving layer (plan §12.6 Phase 1).
//!
//! Verifies the two correctness properties the serving model depends on:
//! * the API routers (`/admin/*`, `/browse/*`, `/v3/*`) are **not** shadowed by
//!   the SPA fallback;
//! * unknown (client-side) paths fall back to `index.html` so TanStack Router
//!   can resolve deep links.
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
}
