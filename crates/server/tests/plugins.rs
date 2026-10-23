//! Format plugins end to end: the built-in Helm plugin (`plugins/helm`), its
//! repositories created through the admin API and used through
//! `/repository/{repo}` the way Helm clients use a chart repository — and the
//! same crate built as a WebAssembly component, loaded at startup.

mod common;

use std::io::Write;

use common::{start_with, unique, ServerOpts, TestServer};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::Digest;

/// The format id the Helm component is installed under (the built-in Helm
/// plugin holds `helm`).
const WASM_HELM: &str = "helm-wasm";

/// The `[plugins]` block loading the Helm plugin built as a component,
/// served under a mount of its own (`/charts`).
fn wasm_helm_plugins_block() -> String {
    let dir = forge_plugin::testing::example_plugin_with("helm", WASM_HELM, "mount = \"/charts\"");
    let sha = forge_plugin::testing::component_sha256(&dir);
    let parent = dir.parent().expect("plugin directory parent");
    format!("[plugins]\ndir = {parent:?}\n\n[plugins.formats]\n{WASM_HELM} = \"sha256:{sha}\"\n")
}

async fn start_helm(opts: ServerOpts) -> TestServer {
    start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            ..opts
        },
    )
    .await
}

/// A gzipped chart archive declaring `name` at `version`.
fn chart(name: &str, version: &str) -> Vec<u8> {
    chart_with_values(name, version, "replicas: 1\n")
}

/// [`chart`] with `values` as its `values.yaml`.
fn chart_with_values(name: &str, version: &str, values: &str) -> Vec<u8> {
    chart_archive(
        name,
        &format!("apiVersion: v2\nname: {name}\nversion: {version}\ndescription: {name} chart\n"),
        values,
    )
}

/// A gzipped chart archive of the chart `name` with `chart_yaml` as its
/// Chart.yaml.
fn chart_archive(name: &str, chart_yaml: &str, values: &str) -> Vec<u8> {
    tgz(&[
        (&format!("{name}/values.yaml"), values),
        (&format!("{name}/Chart.yaml"), chart_yaml),
    ])
}

/// A gzipped ustar archive of `(path, contents)` entries.
fn tgz(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (path, data) in entries {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&header);
        tar.extend_from_slice(data.as_bytes());
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.extend_from_slice(&[0u8; 1024]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

async fn create_repo(srv: &TestServer, body: Value) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    srv.client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// Create a hosted Helm repository and return its name.
async fn helm_repo(srv: &TestServer, anonymous_read: bool) -> String {
    hosted_repo(srv, "helm", anonymous_read).await
}

/// Create a hosted repository of `format` and return its name.
async fn hosted_repo(srv: &TestServer, format: &str, anonymous_read: bool) -> String {
    let name = format!("charts{}", unique());
    let resp = create_repo(
        srv,
        json!({ "name": name, "kind": "hosted", "format": format, "anonymous_read": anonymous_read }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "{}",
        resp.text().await.unwrap()
    );
    name
}

/// The admin's username and an API token: what `helm repo add --username
/// --password` would be given.
async fn credentials(srv: &TestServer) -> (String, String) {
    (srv.admin_user.clone().unwrap(), srv.admin_token().await)
}

async fn push(
    srv: &TestServer,
    repo: &str,
    creds: &(String, String),
    body: Vec<u8>,
) -> reqwest::Response {
    push_at(srv, "/repository", repo, creds, body).await
}

/// [`push`] to a repository served under `mount`.
async fn push_at(
    srv: &TestServer,
    mount: &str,
    repo: &str,
    creds: &(String, String),
    body: Vec<u8>,
) -> reqwest::Response {
    srv.client()
        .post(format!("{}{mount}/{repo}/api/charts", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .body(body)
        .send()
        .await
        .unwrap()
}

async fn get_index(
    srv: &TestServer,
    repo: &str,
    creds: Option<&(String, String)>,
) -> reqwest::Response {
    get_index_at(srv, "/repository", repo, creds).await
}

/// [`get_index`] of a repository served under `mount`.
async fn get_index_at(
    srv: &TestServer,
    mount: &str,
    repo: &str,
    creds: Option<&(String, String)>,
) -> reqwest::Response {
    let req = srv
        .client()
        .get(format!("{}{mount}/{repo}/index.yaml", srv.base_url));
    let req = match creds {
        Some((u, p)) => req.basic_auth(u, Some(p)),
        None => req,
    };
    req.send().await.unwrap()
}

#[tokio::test]
async fn a_helm_repository_round_trip() {
    let srv = start_helm(ServerOpts::default()).await;
    let repo = helm_repo(&srv, false).await;
    let creds = credentials(&srv).await;

    // Publish: the raw body, and the multipart field `helm cm-push` sends.
    let first = chart("Demo", "v1.0");
    let resp = push(&srv, &repo, &creds, first.clone()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({ "saved": true })
    );
    let form = reqwest::multipart::Form::new()
        .text("note", "skipped before the chart")
        .part(
            "chart",
            reqwest::multipart::Part::bytes(chart("Demo", "1.1.0")).file_name("Demo-1.1.0.tgz"),
        );
    let resp = srv
        .client()
        .post(format!("{}/repository/{repo}/api/charts", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "{}",
        resp.text().await.unwrap()
    );

    // The same version again (names match case-insensitively), and
    // something that is not a chart.
    let resp = push(&srv, &repo, &creds, chart("demo", "1.0.0")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let resp = push(&srv, &repo, &creds, b"not a chart".to_vec()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.text().await.unwrap().contains("not a chart archive"));
    // A chart that Helm would install as another one: Helm loads the last
    // Chart.yaml of an archive.
    let twin = tgz(&[
        (
            "demo/Chart.yaml",
            "apiVersion: v2\nname: demo\nversion: 3.0.0\n",
        ),
        (
            "evil/Chart.yaml",
            "apiVersion: v2\nname: evil\nversion: 6.6.6\n",
        ),
    ]);
    let resp = push(&srv, &repo, &creds, twin).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp
        .text()
        .await
        .unwrap()
        .contains("more than one top-level directory"));

    // The index lists both versions, newest first, as published.
    let resp = get_index(&srv, &repo, Some(&creds)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    let index: Value = resp.json().await.unwrap();
    let entries = index["entries"]["Demo"].as_array().expect("Demo entries");
    let versions: Vec<&str> = entries
        .iter()
        .map(|e| e["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.1.0", "v1.0"]);
    assert_eq!(entries[1]["description"], "Demo chart");
    assert_eq!(
        entries[1]["digest"],
        hex::encode(sha2::Sha256::digest(&first)),
        "the digest is the stored package's SHA-256"
    );

    // The URL the index points at serves the chart, streamed by the host.
    let url = entries[1]["urls"][0].as_str().unwrap();
    let path = url
        .strip_prefix("http://test.local")
        .expect("absolute URL on the public base");
    let resp = srv
        .client()
        .get(format!("{}{path}", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), first.as_slice());
    let resp = srv
        .client()
        .head(format!("{}{path}", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-length"], first.len().to_string());

    // The ChartMuseum listing of one chart.
    let resp = srv
        .client()
        .get(format!(
            "{}/repository/{repo}/api/charts/demo",
            srv.base_url
        ))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.json::<Value>()
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Delete a version: gone from the index and from downloads.
    let resp = srv
        .client()
        .delete(format!(
            "{}/repository/{repo}/api/charts/demo/1.0.0",
            srv.base_url
        ))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let index: Value = get_index(&srv, &repo, Some(&creds))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(index["entries"]["Demo"].as_array().unwrap().len(), 1);
    let resp = srv
        .client()
        .get(format!("{}{path}", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = srv
        .client()
        .delete(format!(
            "{}/repository/{repo}/api/charts/demo/1.0.0",
            srv.base_url
        ))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // The package detail of the web UI reads the plugin's summary.
    let session = srv
        .login(
            &srv.admin_user.clone().unwrap(),
            &srv.admin_pass.clone().unwrap(),
        )
        .await;
    let detail: Value = session
        .apply(
            srv.client()
                .get(format!("{}/browse/packages/{repo}/demo", srv.base_url)),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["original_id"], "Demo");
    assert_eq!(detail["versions"].as_array().unwrap().len(), 1);
}

/// #318: a holder of the built-in `writer` role uploads a new chart to a
/// hosted Helm repository and reads it back, but cannot delete a version.
#[tokio::test]
async fn a_writer_uploads_charts_but_deletes_none() {
    let srv = start_helm(ServerOpts::default()).await;
    let repo = helm_repo(&srv, false).await;
    let (au, ap) = srv.admin_basic();
    let username = format!("charts-writer{}@example.com", unique());
    let user_id = srv
        .create_user(&username, "pw12345678-charts", "reader")
        .await;
    let resp = srv
        .client()
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({ "role": "writer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let token: Value = srv
        .client()
        .post(format!("{}/admin/users/{user_id}/tokens", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({ "name": "ci" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let creds = (username, token["token"].as_str().unwrap().to_string());

    let resp = push(&srv, &repo, &creds, chart("Fresh", "0.1.0")).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "{}",
        resp.text().await.unwrap()
    );
    let index: Value = get_index(&srv, &repo, Some(&creds))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(index["entries"]["Fresh"].as_array().unwrap().len(), 1);
    let resp = srv
        .client()
        .delete(format!(
            "{}/repository/{repo}/api/charts/fresh/0.1.0",
            srv.base_url
        ))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn plugin_repositories_are_authorized_like_feeds() {
    let srv = start_with(
        common::fresh_pool().await,
        ServerOpts {
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            ..Default::default()
        },
    )
    .await;
    srv.set_auth_settings(serde_json::json!({"anonymous_mode": "all"}))
        .await;
    let private = helm_repo(&srv, false).await;
    let public = helm_repo(&srv, true).await;
    let creds = credentials(&srv).await;
    let resp = push(&srv, &public, &creds, chart("web", "1.0.0")).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Reading: anonymous only where anonymous reads are allowed.
    let resp = get_index(&srv, &private, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key("www-authenticate"));
    let resp = get_index(&srv, &public, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let index: Value = resp.json().await.unwrap();
    assert!(index["entries"]["web"].is_array());
    // An unknown repository answers like one the caller may not read.
    let resp = index_of_unknown(&srv).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Writing: never anonymously, and never with a password (a browser
    // credential), only with an API token.
    let resp = srv
        .client()
        .post(format!("{}/repository/{public}/api/charts", srv.base_url))
        .body(chart("web", "2.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let (user, password) = srv.admin_password_basic();
    let resp = push(&srv, &public, &(user, password), chart("web", "2.0.0")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.text().await.unwrap().contains("API token"));
}

async fn index_of_unknown(srv: &TestServer) -> reqwest::Response {
    get_index(srv, &format!("missing{}", unique()), None).await
}

#[tokio::test]
async fn formats_keep_to_their_own_mounts_and_kinds() {
    let srv = start_helm(ServerOpts::default()).await;
    let creds = credentials(&srv).await;
    let charts = helm_repo(&srv, false).await;
    let nuget = format!("nuget{}", unique());
    let resp = create_repo(&srv, json!({ "name": nuget, "kind": "hosted" })).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // A Helm repository is not a NuGet feed, and the other way around.
    let resp = srv
        .client()
        .get(format!("{}/v3/{charts}/index.json", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = get_index(&srv, &nuget, Some(&creds)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // The admin API lists what can be created.
    let (u, p) = srv.admin_basic();
    let formats: Value = srv
        .client()
        .get(format!("{}/admin/formats", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(formats[0]["id"], "nuget");
    assert_eq!(formats[1]["id"], "docker");
    assert_eq!(formats[2]["id"], "helm");
    assert_eq!(formats[2]["builtin"], true);
    assert_eq!(formats[2]["kinds"], json!(["hosted", "proxy", "group"]));
    assert_eq!(formats[2]["mount"], "/repository");
    assert!(formats[2].get("sha256").is_none());

    // A proxy needs its upstream; unknown formats are refused.
    let resp = create_repo(
        &srv,
        json!({ "name": format!("p{}", unique()), "kind": "proxy", "format": "helm" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = create_repo(
        &srv,
        json!({ "name": format!("n{}", unique()), "kind": "hosted", "format": "npm" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.text().await.unwrap().contains("helm"));

    // A group serves one format: a NuGet member is refused, a Helm one is
    // served through the group.
    let group = format!("group{}", unique());
    let resp = create_repo(
        &srv,
        json!({ "name": group, "kind": "group", "format": "helm" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let add = |member: String, priority: i32| {
        srv.client()
            .post(format!(
                "{}/admin/repositories/{group}/members",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p))
            .json(&json!({ "member": member, "priority": priority }))
            .send()
    };
    assert_eq!(
        add(nuget.clone(), 1).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        add(charts.clone(), 1).await.unwrap().status(),
        StatusCode::CREATED
    );
    let resp = push(&srv, &charts, &creds, chart("api", "3.2.1")).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let index: Value = get_index(&srv, &group, Some(&creds))
        .await
        .json()
        .await
        .unwrap();
    let url = index["entries"]["api"][0]["urls"][0]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        url.contains(&format!("/repository/{group}/charts/api/3.2.1/")),
        "{url}"
    );
    let resp = srv
        .client()
        .get(url.replace("http://test.local", &srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // A group publishes nothing.
    let resp = push(&srv, &group, &creds, chart("api", "3.2.2")).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn a_repository_has_an_upload_limit_of_its_own() {
    let srv = start_helm(ServerOpts::default()).await;
    let name = format!("charts{}", unique());
    let resp = create_repo(
        &srv,
        json!({ "name": name, "kind": "hosted", "format": "helm", "max_upload_bytes": 1048576 }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let creds = credentials(&srv).await;
    let resp = push(&srv, &name, &creds, chart("small", "1.0.0")).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "{}",
        resp.text().await.unwrap()
    );
    let resp = push(&srv, &name, &creds, vec![0u8; 2 * 1024 * 1024]).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        resp.text().await.unwrap(),
        "upload exceeds limit of 1048576 bytes"
    );
}

#[tokio::test]
async fn a_repository_whose_plugin_is_missing_is_unavailable() {
    // A server without the plugin, over a repository created with it.
    let srv = common::start().await;
    let name = format!("orphan{}", unique());
    let mut row = forge_db::repository_dao::NewRepository::hosted(name.clone());
    row.format = WASM_HELM.into();
    forge_db::repository_dao::insert_repository(&srv.pool, row)
        .await
        .expect("insert repository");
    let (u, p) = srv.admin_basic();
    let resp = get_index(&srv, &name, Some(&(u.clone(), p.clone()))).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let resp = srv
        .client()
        .delete(format!(
            "{}/admin/repositories/{name}/packages/demo/1.0.0",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// The Helm crate built as a WebAssembly component serves its repositories
/// exactly as the built-in one does: one contract, two ways to run it.
#[tokio::test]
async fn a_webassembly_plugin_serves_like_a_builtin_one() {
    let srv = start_helm(ServerOpts {
        plugins_block: Some(wasm_helm_plugins_block()),
        ..Default::default()
    })
    .await;
    let creds = credentials(&srv).await;
    let (u, p) = srv.admin_basic();
    let formats: Value = srv
        .client()
        .get(format!("{}/admin/formats", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let wasm = formats
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == WASM_HELM)
        .expect("the component is listed");
    assert_eq!(wasm["builtin"], false);
    assert_eq!(wasm["sha256"].as_str().map(str::len), Some(64));

    assert_eq!(wasm["mount"], "/charts");

    let repo = hosted_repo(&srv, WASM_HELM, false).await;
    let package = chart("Demo", "v1.0");
    let resp = push_at(&srv, "/charts", &repo, &creds, package.clone()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = push_at(&srv, "/charts", &repo, &creds, package.clone()).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let resp = push_at(&srv, "/charts", &repo, &creds, b"not a chart".to_vec()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Served under its own mount only.
    let resp = get_index(&srv, &repo, Some(&creds)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let index: Value = get_index_at(&srv, "/charts", &repo, Some(&creds))
        .await
        .json()
        .await
        .unwrap();
    let entry = &index["entries"]["Demo"][0];
    assert_eq!(entry["version"], "v1.0");
    assert_eq!(entry["digest"], hex::encode(sha2::Sha256::digest(&package)));
    let url = entry["urls"][0].as_str().unwrap();
    assert!(url.contains(&format!("/charts/{repo}/charts/")), "{url}");
    let resp = srv
        .client()
        .get(url.replace("http://test.local", &srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), package.as_slice());
}

/// A WebAssembly plugin never replaces a built-in format.
#[test]
fn a_component_cannot_take_a_builtin_format_id() {
    let dir = forge_plugin::testing::example_plugin("helm");
    let plugin = forge_plugin::Plugin::load(
        &dir,
        &forge_plugin::testing::component_sha256(&dir),
        &forge_plugin::HostLimits::default(),
    )
    .unwrap();
    let err = forge_server::state::FormatRegistry::new(Default::default())
        .with_plugin(plugin)
        .err()
        .expect("helm is taken");
    assert!(err.contains("built into this server"), "{err}");
}

/// A chart repository upstream of a Helm proxy, serving `index.yaml` and
/// chart archives under `/stable`, and counting chart downloads.
struct ChartUpstream {
    base: String,
    charts: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    downloads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ChartUpstream {
    async fn start(index: String) -> Self {
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use std::sync::atomic::Ordering;

        type Shared = (
            String,
            std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
            std::sync::Arc<std::sync::atomic::AtomicUsize>,
        );
        let charts = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let downloads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let app = axum::Router::new()
            .route(
                "/stable/index.yaml",
                axum::routing::get(|State((index, _, _)): State<Shared>| async move { index }),
            )
            .route(
                "/stable/charts/{file}",
                axum::routing::get(
                    |State((_, charts, downloads)): State<Shared>, Path(file): Path<String>| async move {
                        match charts.lock().unwrap().get(&file).cloned() {
                            Some(bytes) => {
                                downloads.fetch_add(1, Ordering::SeqCst);
                                bytes.into_response()
                            }
                            None => StatusCode::NOT_FOUND.into_response(),
                        }
                    },
                ),
            )
            .with_state((index, charts.clone(), downloads.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/stable", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        ChartUpstream {
            base,
            charts,
            downloads,
        }
    }

    fn publish(&self, file: &str, bytes: Vec<u8>) {
        self.charts.lock().unwrap().insert(file.into(), bytes);
    }

    fn downloads(&self) -> usize {
        self.downloads.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Check `index` against the types Helm gives an index's fields (its
/// `repo.ChartVersion` and `chart.Metadata`). Helm reads a JSON index with
/// Go's `encoding/json` and refuses the whole index when one value has
/// another type; fields it does not know it ignores.
fn assert_helm_types(index: &Value) {
    const STRINGS: &[&str] = &[
        "name",
        "home",
        "version",
        "description",
        "icon",
        "apiVersion",
        "condition",
        "tags",
        "appVersion",
        "kubeVersion",
        "type",
        "created",
        "digest",
    ];
    let strings = |v: &Value| v.as_array().is_some_and(|a| a.iter().all(Value::is_string));
    let fields = |v: &Value, strs: &[&str], lists: &[&str], bools: &[&str], any: &[&str]| {
        v.as_object().is_some_and(|o| {
            o.iter().all(|(k, v)| {
                (strs.contains(&k.as_str()) && v.is_string())
                    || (lists.contains(&k.as_str()) && strings(v))
                    || (bools.contains(&k.as_str()) && v.is_boolean())
                    || (any.contains(&k.as_str()) && v.is_array())
            })
        })
    };
    assert!(index["apiVersion"].is_string());
    for (chart, versions) in index["entries"].as_object().expect("entries") {
        for version in versions.as_array().expect("versions") {
            for (key, value) in version.as_object().expect("a chart version") {
                let ok = match key.as_str() {
                    key if STRINGS.contains(&key) => value.is_string(),
                    "sources" | "keywords" | "urls" => strings(value),
                    "deprecated" | "removed" => value.is_boolean(),
                    "annotations" => value
                        .as_object()
                        .is_some_and(|m| m.values().all(Value::is_string)),
                    "maintainers" => value.as_array().is_some_and(|a| {
                        a.iter()
                            .all(|m| fields(m, &["name", "email", "url"], &[], &[], &[]))
                    }),
                    "dependencies" => value.as_array().is_some_and(|a| {
                        a.iter().all(|d| {
                            fields(
                                d,
                                &["name", "version", "repository", "condition", "alias"],
                                &["tags"],
                                &["enabled"],
                                &["import-values"],
                            )
                        })
                    }),
                    _ => true,
                };
                assert!(ok, "{chart}: Helm cannot read {key} = {value}");
            }
        }
    }
}

/// A Chart.yaml (or an upstream's YAML index) may hold a number or a
/// boolean where Helm wants a string, as Helm's YAML reader accepts: the
/// index lists it as a string, so it does not break the index (#206).
#[tokio::test]
async fn an_index_lists_scalars_as_the_strings_helm_reads() {
    const QUIRKS: &str = concat!(
        "appVersion: 2\n",
        "kubeVersion: 1.30\n",
        "icon: 7\n",
        "keywords: [web, 8, true]\n",
        "annotations:\n",
        "  artifacthub.io/prerelease: false\n",
        "  revision: 3\n",
        "  nested: {a: b}\n",
        "maintainers:\n",
        "  - name: 42\n",
        "    email: ops@example.com\n",
        "    extra: [x]\n",
        "dependencies:\n",
        "  - name: redis\n",
        "    version: 18\n",
        "    repository: https://charts.example\n",
        "    enabled: true\n",
        "    tags: [cache, 1]\n",
        "    import-values: [data]\n",
        "deprecated: false\n",
        "home: {not: a string}\n",
        "sources: just-one\n",
    );
    let upstream_index = format!(
        "apiVersion: v1\nentries:\n  quirky:\n    - apiVersion: v2\n      name: quirky\n      \
         version: 1.0.0\n      urls: [charts/quirky-1.0.0.tgz]\n{}",
        QUIRKS
            .lines()
            .map(|l| format!("      {l}\n"))
            .collect::<String>()
    );
    let upstream = ChartUpstream::start(upstream_index).await;

    let srv = start_helm(ServerOpts::default()).await;
    let creds = credentials(&srv).await;
    let hosted = helm_repo(&srv, false).await;
    let archive = chart_archive(
        "quirks",
        &format!("apiVersion: v2\nname: quirks\nversion: 0.1.0\n{QUIRKS}"),
        "replicas: 1\n",
    );
    let resp = push(&srv, &hosted, &creds, archive).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "{}",
        resp.text().await.unwrap()
    );
    let proxy = format!("proxy{}", unique());
    let resp = create_repo(
        &srv,
        json!({ "name": proxy, "kind": "proxy", "format": "helm", "remote_url": upstream.base }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let group = format!("group{}", unique());
    let resp = create_repo(
        &srv,
        json!({ "name": group, "kind": "group", "format": "helm" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let (u, p) = srv.admin_basic();
    for (member, priority) in [(&hosted, 10), (&proxy, 1)] {
        let resp = srv
            .client()
            .post(format!(
                "{}/admin/repositories/{group}/members",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p))
            .json(&json!({ "member": member, "priority": priority }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    }

    for (repo, chart) in [
        (&hosted, "quirks"),
        (&proxy, "quirky"),
        (&group, "quirks"),
        (&group, "quirky"),
    ] {
        let resp = get_index(&srv, repo, Some(&creds)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let index: Value = resp.json().await.unwrap();
        assert_helm_types(&index);
        let entry = &index["entries"][chart][0];
        assert_eq!(entry["appVersion"], "2", "{repo}: {entry}");
        assert_eq!(entry["kubeVersion"], "1.30");
        assert_eq!(entry["keywords"], json!(["web", "8", "true"]));
        assert_eq!(entry["annotations"]["artifacthub.io/prerelease"], "false");
        assert_eq!(entry["annotations"]["revision"], "3");
        assert!(entry["annotations"].get("nested").is_none());
        assert_eq!(
            entry["maintainers"][0],
            json!({"name": "42", "email": "ops@example.com"})
        );
        assert_eq!(entry["dependencies"][0]["version"], "18");
        assert_eq!(entry["dependencies"][0]["tags"], json!(["cache", "1"]));
        assert_eq!(entry["dependencies"][0]["enabled"], true);
        assert_eq!(entry["deprecated"], false);
        assert!(entry.get("home").is_none() && entry.get("sources").is_none());
    }
}

/// A Helm proxy lists its upstream's charts in its index, serves each from
/// the upstream once and from its cache after, and publishes nothing.
#[tokio::test]
async fn a_helm_proxy_serves_its_upstreams_charts() {
    let index = "apiVersion: v1\nentries:\n  demo:\n    - apiVersion: v2\n      name: demo\n      version: 1.0.0\n      description: demo chart\n      urls: [charts/demo-1.0.0.tgz]\n  other:\n    - apiVersion: v2\n      name: other\n      version: 2.0.0\n      urls: [charts/other-2.0.0.tgz]\n  twin:\n    - apiVersion: v2\n      name: twin\n      version: 1.0.0\n      urls: [charts/twin-1.0.0.tgz]\n".to_string();
    let upstream = ChartUpstream::start(index).await;
    let demo = chart("demo", "1.0.0");
    upstream.publish("demo-1.0.0.tgz", demo.clone());
    // Helm would install it as `evil` 6.6.6, its last Chart.yaml.
    upstream.publish(
        "twin-1.0.0.tgz",
        tgz(&[
            (
                "twin/Chart.yaml",
                "apiVersion: v2\nname: twin\nversion: 1.0.0\n",
            ),
            (
                "twin/Chart.yaml",
                "apiVersion: v2\nname: evil\nversion: 6.6.6\n",
            ),
        ]),
    );

    let srv = start_helm(ServerOpts::default()).await;
    let creds = credentials(&srv).await;
    let proxy = format!("proxy{}", unique());
    let resp = create_repo(
        &srv,
        json!({ "name": proxy, "kind": "proxy", "format": "helm", "remote_url": upstream.base }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "{}",
        resp.text().await.unwrap()
    );

    // The index lists the upstream's charts, nothing downloaded yet.
    let resp = get_index(&srv, &proxy, Some(&creds)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let index: Value = resp.json().await.unwrap();
    assert_eq!(index["entries"]["other"][0]["version"], "2.0.0");
    let url = index["entries"]["demo"][0]["urls"][0]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        url.ends_with(&format!(
            "/repository/{proxy}/charts/demo/1.0.0/demo-1.0.0.tgz"
        )),
        "{url}"
    );
    assert_eq!(index["entries"]["demo"][0]["description"], "demo chart");
    assert_eq!(upstream.downloads(), 0);

    // The chart comes from the upstream once, then from the cache.
    let get = |url: String| {
        srv.client()
            .get(url.replace("http://test.local", &srv.base_url))
            .basic_auth(&creds.0, Some(&creds.1))
            .send()
    };
    for _ in 0..2 {
        let resp = get(url.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.bytes().await.unwrap().as_ref(), demo.as_slice());
    }
    assert_eq!(upstream.downloads(), 1);

    // A version the upstream does not have is not found.
    let resp = get(format!(
        "{}/repository/{proxy}/charts/other/2.0.0/other-2.0.0.tgz",
        srv.base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // A chart that is not what Helm would install is not cached.
    let resp = get(format!(
        "{}/repository/{proxy}/charts/twin/1.0.0/twin-1.0.0.tgz",
        srv.base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(upstream.downloads(), 2);

    // The ChartMuseum view of one chart, from the upstream's index.
    let resp = get(format!(
        "{}/repository/{proxy}/api/charts/demo",
        srv.base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let versions: Value = resp.json().await.unwrap();
    assert_eq!(versions[0]["version"], "1.0.0");

    // A proxy publishes nothing.
    let resp = push(&srv, &proxy, &creds, chart("demo", "1.0.1")).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}
