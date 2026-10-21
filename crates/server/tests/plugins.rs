//! Format plugins end to end: the built-in Helm plugin (`plugins/helm`), its
//! repositories created through the admin API and used through
//! `/repository/{repo}` the way Helm clients use a chart repository — and the
//! same crate built as a WebAssembly component, loaded at startup.

mod common;

use std::io::Write;
use std::sync::Arc;

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
            bootstrap_admin: Some((format!("admin{}", unique()), "adminpw".into())),
            ..opts
        },
    )
    .await
}

/// A gzipped chart archive declaring `name` at `version`.
fn chart(name: &str, version: &str) -> Vec<u8> {
    let entries: [(String, String); 2] = [
        (format!("{name}/values.yaml"), "replicas: 1\n".into()),
        (
            format!("{name}/Chart.yaml"),
            format!(
                "apiVersion: v2\nname: {name}\nversion: {version}\ndescription: {name} chart\n"
            ),
        ),
    ];
    let mut tar = Vec::new();
    for (path, data) in &entries {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
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

#[tokio::test]
async fn plugin_repositories_are_authorized_like_feeds() {
    let srv = start_helm(ServerOpts {
        anonymous_mode: "all".into(),
        ..Default::default()
    })
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
    assert_eq!(formats[2]["kinds"], json!(["hosted", "group"]));
    assert_eq!(formats[2]["mount"], "/repository");
    assert!(formats[2].get("sha256").is_none());

    // Plugin formats have no proxies; unknown formats are refused.
    let resp = create_repo(
        &srv,
        json!({ "name": format!("p{}", unique()), "kind": "proxy", "format": "helm",
                "remote_url": "https://charts.example.com" }),
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
async fn uploads_are_bounded_by_the_server_limit() {
    let srv = start_helm(ServerOpts {
        server_extra: Some("max_upload_bytes = 1024".into()),
        ..Default::default()
    })
    .await;
    let repo = helm_repo(&srv, false).await;
    let creds = credentials(&srv).await;
    let resp = push(&srv, &repo, &creds, vec![0u8; 64 * 1024]).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
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
    let nuget: Arc<dyn forge_core::format::Format> = Arc::new(forge_nuget::NugetFormat::default());
    let err = forge_server::state::FormatRegistry::new(nuget)
        .with_plugin(plugin)
        .err()
        .expect("helm is taken");
    assert!(err.contains("built into this server"), "{err}");
}
