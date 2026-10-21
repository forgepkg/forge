//! #112: proxy and group search reach the proxy upstream's search service, so
//! a package nobody has restored through Forge yet is found, with every URL
//! pointing at Forge. Requires Docker (or `FORGE_TEST_DATABASE_URL` /
//! `FORGE_TEST_S3_ENDPOINT`).

mod common;

use std::collections::HashMap;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// One upstream search result: `id` listing `versions`, with URLs of the
/// upstream's own.
fn search_entry(id: &str, versions: &[&str]) -> Value {
    let lower = id.to_lowercase();
    json!({
        "@id": format!("https://upstream.example/registration/{lower}/index.json"),
        "@type": "Package",
        "registration": format!("https://upstream.example/registration/{lower}/index.json"),
        "id": id,
        "version": versions.last().unwrap(),
        "description": format!("{id} from upstream"),
        "authors": ["Upstream Author"],
        "totalDownloads": 42,
        "versions": versions
            .iter()
            .map(|v| json!({
                "version": v,
                "downloads": 1,
                "@id": format!("https://upstream.example/registration/{lower}/{v}.json"),
            }))
            .collect::<Vec<_>>(),
    })
}

/// Serve an upstream feed whose search service knows three packages none of
/// which has been restored, and return its base URL.
async fn start_feed() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind feed");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            "/index.json",
            get(|State(base): State<String>| async move {
                Json(json!({
                    "version": "3.0.0",
                    "resources": [
                        {"@id": format!("{base}/flat/"), "@type": "PackageBaseAddress/3.0.0"},
                        {"@id": format!("{base}/query"), "@type": "SearchQueryService/3.5.0"},
                    ],
                }))
            }),
        )
        .route(
            "/query",
            get(|| async {
                Json(json!({
                    "totalHits": 3,
                    "data": [
                        search_entry("Upstream.Only", &["1.0.0", "1.1.0"]),
                        search_entry("Shared.Lib", &["9.9.9"]),
                        search_entry("Acme.Internal", &["1.0.0"]),
                    ],
                }))
            }),
        )
        .with_state(base.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve feed");
    });
    base
}

/// `id -> versions` of a search response.
fn hits(body: &Value) -> HashMap<String, Vec<String>> {
    body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| {
            let versions = hit["versions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["version"].as_str().unwrap().to_string())
                .collect();
            (hit["id"].as_str().unwrap().to_string(), versions)
        })
        .collect()
}

/// The search hit for `id`.
fn hit<'a>(body: &'a Value, id: &str) -> &'a Value {
    body["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hit| hit["id"] == id)
        .unwrap_or_else(|| panic!("{id} in {body}"))
}

#[tokio::test]
async fn proxy_and_group_search_find_packages_only_the_upstream_knows() {
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            ..Default::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let (hosted, proxy, group) = (format!("shost{s}"), format!("sprox{s}"), format!("sgrp{s}"));
    let feed = start_feed().await;

    // Group G = hosted H (holds Shared.Lib) + proxy P of the feed; G
    // reserves `acme.` for internal packages.
    for body in [
        json!({"name": hosted, "kind": "hosted"}),
        json!({
            "name": proxy,
            "kind": "proxy",
            "remote_url": format!("{feed}/index.json"),
            "package_delay_seconds": 0,
            "metadata_ttl_seconds": 600,
            "not_found_ttl_seconds": 600,
        }),
        json!({"name": group, "kind": "group", "reserved_prefixes": ["acme."]}),
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
    for (member, priority) in [(&hosted, 20), (&proxy, 10)] {
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
    let part = reqwest::multipart::Part::bytes(common::make_nupkg("Shared.Lib", "1.0.0"))
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let resp = client
        .put(format!("{}/v3/{hosted}/package", srv.base_url))
        .header("X-NuGet-ApiKey", srv.admin_token().await)
        .multipart(reqwest::multipart::Form::new().part("package", part))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let search = |repo: String| {
        let request = client
            .get(format!(
                "{}/v3/{repo}/query?q=lib&semVerLevel=2.0.0",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p));
        async move {
            let resp = request.send().await.unwrap();
            assert_eq!(resp.status(), 200);
            resp.json::<Value>().await.unwrap()
        }
    };

    // The proxy finds all three, linked to Forge rather than the upstream.
    let body = search(proxy.clone()).await;
    assert_eq!(body["totalHits"], 3);
    assert_eq!(hits(&body).len(), 3, "{body}");
    let only = hit(&body, "Upstream.Only");
    let registration =
        format!("http://test.local/v3/{proxy}/registration/upstream.only/index.json");
    assert_eq!(only["@id"], registration);
    assert_eq!(only["registration"], registration);
    assert_eq!(
        only["versions"][1]["@id"],
        format!("http://test.local/v3/{proxy}/registration/upstream.only/1.1.0.json")
    );
    assert_eq!(only["description"], "Upstream.Only from upstream");
    assert_eq!(only["totalDownloads"], 42);
    assert!(
        !body.to_string().contains("upstream.example"),
        "no upstream URL is passed on: {body}"
    );

    // The group merges them with the hosted member: the hosted Shared.Lib
    // hides the proxied one (prefer-hosted), and the reserved prefix keeps
    // the proxy's Acme.Internal out.
    let body = search(group.clone()).await;
    let found = hits(&body);
    assert_eq!(found.len(), 2, "{body}");
    assert_eq!(found["Upstream.Only"], ["1.0.0", "1.1.0"]);
    assert_eq!(found["Shared.Lib"], ["1.0.0"]);
    let only = hit(&body, "Upstream.Only");
    assert_eq!(
        only["@id"],
        format!("http://test.local/v3/{group}/registration/upstream.only/index.json")
    );
    assert_eq!(only["description"], "Upstream.Only from upstream");

    // Browse lists what Forge holds, and the proxy has cached nothing yet.
    let resp = client
        .get(format!(
            "{}/browse/packages?q=lib&repo={proxy}",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["total"], 0, "{body}");
}
