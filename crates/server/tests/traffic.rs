//! E2E: the traffic statistics (Admin → Traffic). Requires Docker
//! (Postgres + versitygw via the shared harness), or
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`.
//!
//! Requests are counted with what the layers know of them (the repository,
//! the client address, the account), written to the object store by a flush
//! and read back by the admin API: the overview, a client's view with its
//! request log, and the settings.

mod common;

use common::{unique, TestServer};
use forge_traffic::TrafficSettings;
use reqwest::StatusCode;
use serde_json::{json, Value};

async fn server() -> TestServer {
    common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            ..Default::default()
        },
    )
    .await
}

async fn admin_get(srv: &TestServer, path: &str) -> (StatusCode, Value) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}{path}", srv.base_url))
        .basic_auth(&u, Some(&p))
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

async fn put_settings(srv: &TestServer, body: Value) -> (StatusCode, Value) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .put(format!("{}/admin/settings/traffic", srv.base_url))
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

#[tokio::test]
async fn requests_are_counted_written_and_read_back() {
    let srv = server().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    let name = format!("traffic{}", unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": name, "kind": "hosted", "format": "raw"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "{}",
        resp.text().await.unwrap()
    );

    // Two answers from the repository, one refused, a health probe that is
    // not counted, and a repository that does not exist (its name is not
    // recorded).
    let file = format!("{}/repository/{name}/dir/hello.txt", srv.base_url);
    let resp = client
        .put(&file)
        .basic_auth(&u, Some(&p))
        .header("user-agent", "curl/8.10")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "upload: {}", resp.status());
    let resp = client
        .get(&file)
        .basic_auth(&u, Some(&p))
        .header("user-agent", "curl/8.10")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "hello");
    let resp = client.get(&file).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    client
        .get(format!("{}/healthz", srv.base_url))
        .send()
        .await
        .unwrap();
    client
        .get(format!(
            "{}/repository/no-such-{}/x",
            srv.base_url,
            unique()
        ))
        .send()
        .await
        .unwrap();

    // What a minute's flush writes, written now.
    let traffic = &srv.state.traffic;
    let report = traffic.flush_all(&TrafficSettings::default()).await;
    assert_eq!(report.failures, 0, "{report:?}");
    assert!(report.log_rows >= 5, "{report:?}");
    let instance = traffic.instance.to_string();

    let (status, overview) = admin_get(
        &srv,
        &format!("/admin/traffic?range=1h&instance={instance}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{overview}");
    assert_eq!(overview["resolution"], "minute");
    assert!(
        overview["instances"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == instance.as_str()),
        "{overview}"
    );
    let repositories = overview["repositories"].as_array().unwrap();
    assert_eq!(
        repositories.len(),
        1,
        "only the repository that exists: {overview}"
    );
    assert_eq!(repositories[0]["name"], name.as_str());
    assert_eq!(repositories[0]["requests"], 3);
    assert_eq!(repositories[0]["client_errors"], 1);
    let surfaces: Vec<&str> = overview["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["surface"].as_str().unwrap())
        .collect();
    assert!(surfaces.contains(&"plugin_raw"), "{surfaces:?}");
    assert!(!surfaces.contains(&"health"), "{surfaces:?}");
    assert!(overview["totals"]["denied"].as_u64().unwrap() >= 1);
    let client_row = &overview["clients"][0];
    assert_eq!(client_row["network"], "127.0.0.1");
    assert_eq!(overview["recording"]["enabled"], true);

    // Only this repository's counts.
    let (_, only) = admin_get(
        &srv,
        &format!("/admin/traffic?range=1h&instance={instance}&repository={name}"),
    )
    .await;
    assert_eq!(only["totals"]["requests"], 3);

    // The client's view: its requests in the request log, newest first.
    let (status, detail) = admin_get(
        &srv,
        &format!("/admin/traffic/client?network=127.0.0.1&range=1h&instance={instance}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert!(detail["log"]["matched"].as_u64().unwrap() >= 5, "{detail}");
    let entries = detail["log"]["entries"].as_array().unwrap();
    let get = entries
        .iter()
        .find(|e| e["method"] == "GET" && e["status"] == 200 && e["repository"] == name.as_str())
        .expect("the download is in the log");
    assert_eq!(get["path"], format!("/repository/{name}/dir/hello.txt"));
    assert_eq!(get["user_agent"], "curl/8.10");
    assert_eq!(get["bytes"], 5);
    assert_eq!(get["account"], "token");
    assert_eq!(get["username"], u.as_str());

    let (status, _) = admin_get(&srv, "/admin/traffic/client?range=1h").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "network is required");
    let (status, _) = admin_get(&srv, "/admin/traffic?range=2h").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Admins only.
    let resp = client
        .get(format!("{}/admin/traffic", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn settings_switch_parts_off_and_are_checked() {
    let srv = server().await;
    let (status, settings) = admin_get(&srv, "/admin/settings/traffic").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<TrafficSettings>(settings).unwrap(),
        TrafficSettings::default()
    );

    let (status, settings) = put_settings(
        &srv,
        json!({"request_log": false, "client_retention_days": 7}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    assert_eq!(settings["request_log"], false);
    assert_eq!(settings["client_retention_days"], 7);
    assert_eq!(settings["client_addresses"], true, "untouched");
    assert!(
        !srv.state.traffic.recorder.logs_requests(),
        "applied at once"
    );

    let (status, _) = put_settings(&srv, json!({"request_log_retention_days": 0})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = put_settings(&srv, json!({"unknown": true})).await;
    assert!(status.is_client_error());

    let (_, settings) = admin_get(&srv, "/admin/settings/traffic").await;
    assert_eq!(settings["request_log"], false, "stored");
}
