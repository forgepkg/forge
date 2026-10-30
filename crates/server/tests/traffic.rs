//! E2E: the traffic statistics (Admin → Traffic). Requires Docker
//! (Postgres + versitygw via the shared harness), or
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`.
//!
//! Requests are counted by day, repository and client network, written to
//! the object store by a flush and read back by the admin API; the
//! geolocation databases are downloaded from a mock of MaxMind's download
//! service, stored in the bucket and used to locate the clients.

mod common;

use common::{unique, TestServer};
use forge_traffic::testing::{asn_db, country_db};
use forge_traffic::TrafficSettings;
use reqwest::StatusCode;
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn server(extra_toml: Option<String>) -> TestServer {
    common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            extra_toml,
            ..Default::default()
        },
    )
    .await
}

async fn admin(
    srv: &TestServer,
    verb: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (u, p) = srv.admin_basic();
    let url = format!("{}{path}", srv.base_url);
    let client = srv.client();
    let request = match verb {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "POST" => client.post(url),
        "DELETE" => client.delete(url),
        _ => unreachable!(),
    };
    let request = match body {
        Some(body) => request.json(&body),
        None => request,
    };
    let resp = request.basic_auth(&u, Some(&p)).send().await.unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn create_raw(srv: &TestServer) -> String {
    let name = format!("traffic{}", unique());
    let (status, body) = admin(
        srv,
        "POST",
        "/admin/repositories",
        Some(json!({"name": name, "kind": "hosted", "format": "raw"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    name
}

/// A `.tar.gz` holding `database` as MaxMind ships it.
fn archive(edition: &str, database: &[u8]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(database.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(
        &mut header,
        format!("{edition}_20261030/{edition}.mmdb"),
        database,
    )
    .unwrap();
    let tar = tar.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar).unwrap();
    gz.finish().unwrap()
}

#[tokio::test]
async fn requests_are_counted_by_day_repository_and_client() {
    let srv = server(None).await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let name = create_raw(&srv).await;

    // Three requests to the repository, a health probe that is not counted,
    // and a repository that does not exist (its name is not recorded).
    let file = format!("{}/repository/{name}/dir/hello.txt", srv.base_url);
    let resp = client
        .put(&file)
        .basic_auth(&u, Some(&p))
        .body("hello")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "upload: {}", resp.status());
    let resp = client
        .get(&file)
        .basic_auth(&u, Some(&p))
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
    let report = traffic
        .flush(&TrafficSettings::default(), chrono::Utc::now())
        .await;
    assert_eq!(report.failures, 0, "{report:?}");
    let instance = traffic.instance.to_string();

    let (status, overview) = admin(
        &srv,
        "GET",
        &format!("/admin/traffic?range=today&instance={instance}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{overview}");
    assert!(
        overview["instances"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == instance.as_str()),
        "{overview}"
    );
    assert_eq!(overview["days"].as_array().unwrap().len(), 1);
    let repositories = overview["repositories"].as_array().unwrap();
    let repo = repositories
        .iter()
        .find(|r| r["name"] == name.as_str())
        .expect("the repository is listed");
    assert_eq!(repo["requests"], 3);
    assert_eq!(repo["clients"], 1);
    assert!(
        repositories
            .iter()
            .all(|r| !r["name"].as_str().unwrap().starts_with("no-such-")),
        "only repositories that exist: {overview}"
    );
    let top = &overview["clients"][0];
    assert_eq!(top["network"], "127.0.0.1");
    assert_eq!(top["repositories"][0], name.as_str());
    assert_eq!(overview["recording"]["countries"], false, "no database yet");

    // One repository's requests, then the requests to none.
    let (_, only) = admin(
        &srv,
        "GET",
        &format!("/admin/traffic?range=today&instance={instance}&repository={name}"),
        None,
    )
    .await;
    assert_eq!(only["totals"]["requests"], 3);
    assert!(
        only["totals"]["bytes"].as_u64().unwrap() >= 5,
        "the response bodies, the download's included: {only}"
    );
    let (_, none) = admin(
        &srv,
        "GET",
        &format!("/admin/traffic?range=today&instance={instance}&repository=-"),
        None,
    )
    .await;
    assert!(none["totals"]["requests"].as_u64().unwrap() >= 2, "{none}");
    assert!(none["repositories"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["name"] == ""));

    let (status, _) = admin(&srv, "GET", "/admin/traffic?range=2h", None).await;
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
async fn settings_are_checked_and_applied() {
    let srv = server(None).await;
    let (status, settings) = admin(&srv, "GET", "/admin/settings/traffic", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<TrafficSettings>(settings).unwrap(),
        TrafficSettings::default()
    );

    let (status, settings) = admin(
        &srv,
        "PUT",
        "/admin/settings/traffic",
        Some(json!({"enabled": false, "retention_days": 30})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    assert_eq!(settings["retention_days"], 30);
    assert_eq!(settings["client_addresses"], true, "untouched");
    assert!(!srv.state.traffic.recorder.enabled(), "applied at once");

    let (status, _) = admin(
        &srv,
        "PUT",
        "/admin/settings/traffic",
        Some(json!({"retention_days": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = admin(
        &srv,
        "PUT",
        "/admin/settings/traffic",
        Some(json!({"unknown": true})),
    )
    .await;
    assert!(status.is_client_error());
    let (_, settings) = admin(&srv, "GET", "/admin/settings/traffic", None).await;
    assert_eq!(settings["enabled"], false, "stored");
}

#[tokio::test]
async fn maxmind_databases_are_downloaded_and_locate_clients() {
    let maxmind = MockServer::start().await;
    // "1234:secret", as MaxMind's download expects it.
    let auth = "Basic MTIzNDpzZWNyZXQ=";
    for (edition, database) in [
        ("GeoLite2-Country", country_db(&[("127.0.0.0/8", "DE")])),
        (
            "GeoLite2-ASN",
            asn_db(&[("127.0.0.0/8", 64_500, "Example AS")]),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/geoip/databases/{edition}/download")))
            .and(header("authorization", auth))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive(edition, &database)))
            .mount(&maxmind)
            .await;
    }
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid license key"))
        .mount(&maxmind)
        .await;
    let srv = server(Some(format!(
        "[traffic]\nmaxmind_url = \"{}\"\n",
        maxmind.uri()
    )))
    .await;

    let (status, view) = admin(&srv, "GET", "/admin/traffic/geoip", None).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["maxmind"]["license_key_set"], false);
    let (status, _) = admin(&srv, "POST", "/admin/traffic/geoip/update", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "no credentials yet");
    let (status, _) = admin(
        &srv,
        "PUT",
        "/admin/traffic/geoip",
        Some(json!({"account_id": "1234"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a license key is needed");

    // A wrong key: the download fails and says why.
    let (status, view) = admin(
        &srv,
        "PUT",
        "/admin/traffic/geoip",
        Some(json!({"account_id": "1234", "license_key": "wrong"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["maxmind"]["license_key_set"], true);
    assert!(
        view["maxmind"].get("license_key").is_none(),
        "never answered"
    );
    let (_, view) = admin(&srv, "POST", "/admin/traffic/geoip/update", None).await;
    assert!(
        view["maxmind"]["last_error"]
            .as_str()
            .unwrap()
            .contains("refused the account ID or the license key"),
        "{view}"
    );
    let sealed = forge_db::authz_dao::get_setting(&srv.pool, "traffic_maxmind_license_key")
        .await
        .unwrap()
        .unwrap();
    assert!(
        sealed.starts_with("sealed:") && !sealed.contains("wrong"),
        "sealed at rest"
    );

    // The right key (the account ID alone keeps it otherwise).
    admin(
        &srv,
        "PUT",
        "/admin/traffic/geoip",
        Some(json!({"account_id": "1234", "license_key": "secret"})),
    )
    .await;
    let (status, view) = admin(&srv, "POST", "/admin/traffic/geoip/update", None).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["maxmind"]["last_error"], Value::Null, "{view}");
    assert_eq!(view["country"]["database_type"], "GeoLite2-Country");
    assert_eq!(view["asn"]["database_type"], "GeoLite2-ASN");

    // A request is now located.
    let name = create_raw(&srv).await;
    srv.client()
        .get(format!("{}/repository/{name}/x", srv.base_url))
        .send()
        .await
        .unwrap();
    let traffic = &srv.state.traffic;
    traffic
        .flush(&TrafficSettings::default(), chrono::Utc::now())
        .await;
    let instance = traffic.instance.to_string();
    let (_, overview) = admin(
        &srv,
        "GET",
        &format!("/admin/traffic?range=today&instance={instance}&country=DE"),
        None,
    )
    .await;
    assert!(
        overview["totals"]["requests"].as_u64().unwrap() >= 1,
        "{overview}"
    );
    assert_eq!(overview["countries"][0]["country"], "DE");
    assert_eq!(overview["asns"][0]["asn"], 64_500);
    assert_eq!(overview["asns"][0]["org"], "Example AS");
    assert_eq!(overview["clients"][0]["country"], "DE");
    assert_eq!(overview["recording"]["countries"], true);

    // Turned off: the credentials and the databases are gone.
    let (status, _) = admin(&srv, "DELETE", "/admin/traffic/geoip", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, view) = admin(&srv, "GET", "/admin/traffic/geoip", None).await;
    assert_eq!(view["country"], Value::Null);
    assert_eq!(view["maxmind"]["license_key_set"], false);
}
