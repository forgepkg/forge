//! The host side of the plugin contract, through a small native test plugin
//! (`probe`) that serves its own mount and reports what the host answers:
//! mounts and kinds, asset names, first-part uploads, ranged downloads, the
//! queries (`packages-of`, search options, publish times, summaries,
//! download totals) and mutations outside the caller's package selector.

mod common;

use std::cmp::Ordering;
use std::io::Read;
use std::sync::Arc;

use common::{start_with, unique, ServerOpts, TestServer};
use forge_plugin::api::{
    Action, Answer, Assets, ChangeRequest, Descriptor, FormatError, FormatPlugin, Loaded,
    PackageInfo, PackageRef, PackageSource, PackageVersions, ParsedPackage, PublishRequest, Query,
    Repository, RepositoryKind, Request, Response, SearchQuery, Storage, Upload, UpstreamToken,
};
use forge_plugin::Plugin;
use reqwest::StatusCode;
use serde_json::{json, Value};

const PROBE: Descriptor = Descriptor {
    id: "probe",
    name: "Probe",
    version: "0.0.1",
    description: "Reports what the host answers.",
    mount: "/probe",
    kinds: &[RepositoryKind::Hosted],
    storage: Storage::Packages,
    assets: Assets {
        package: "probe.bin",
        package_type: "application/x-probe",
        manifest: "probe.txt",
        manifest_type: "text/plain",
    },
    upstream_token: UpstreamToken::None,
};

/// A package is text whose first line is `<id> <version>`.
struct Probe;

fn version_key(v: &str) -> (Vec<u64>, bool, String) {
    let (release, pre) = v.split_once('-').unwrap_or((v, ""));
    let numbers = release.split('.').map(|n| n.parse().unwrap_or(0)).collect();
    (numbers, pre.is_empty(), pre.to_string())
}

fn package_info_json(p: &PackageInfo) -> Value {
    json!({
        "id": p.original_id,
        "version": p.version,
        "listed": p.listed,
        "published": p.published,
        "sha256": p.sha256,
        "size": p.size,
        "summary": p.summary,
    })
}

impl FormatPlugin for Probe {
    fn descriptor(&self) -> &'static Descriptor {
        &PROBE
    }

    fn canonical_id(&self, id: &str) -> String {
        id.to_ascii_lowercase()
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        let ok = (1..=64).contains(&id.len())
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        ok.then_some(())
            .ok_or_else(|| FormatError::InvalidId(id.into()))
    }

    fn normalize_version(&self, version: &str) -> Result<String, FormatError> {
        let (release, _) = version.split_once('-').unwrap_or((version, ""));
        let ok = !release.is_empty()
            && release
                .split('.')
                .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        ok.then(|| version.to_ascii_lowercase())
            .ok_or_else(|| FormatError::InvalidVersion(version.into()))
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        version_key(a).cmp(&version_key(b))
    }

    fn parse_package(&self, package: &mut dyn PackageSource) -> Result<ParsedPackage, FormatError> {
        let mut text = String::new();
        package
            .take(4096)
            .read_to_string(&mut text)
            .map_err(|e| FormatError::InvalidPackage(e.to_string()))?;
        let first = text.lines().next().unwrap_or("");
        let Some((id, version)) = first.split_once(' ') else {
            return Err(FormatError::InvalidPackage(
                "no `<id> <version>` line".into(),
            ));
        };
        self.validate_id(&id.to_ascii_lowercase())?;
        Ok(ParsedPackage {
            id: id.to_ascii_lowercase(),
            original_id: id.into(),
            version: self.normalize_version(version)?,
            version_original: version.into(),
            listed: true,
            manifest: first.as_bytes().to_vec(),
            dependencies: Vec::new(),
        })
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<String> {
        Some(json!({ "description": String::from_utf8_lossy(manifest) }).to_string())
    }

    fn handle(&self, _repo: &Repository, req: &Request) -> Action {
        let segments = req.segments().unwrap_or_default();
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        let read = matches!(req.method.as_str(), "GET" | "HEAD");
        let target = |id: &str, version: &str| PackageRef {
            id: id.into(),
            version: version.into(),
        };
        match (req.method.as_str(), segments.as_slice()) {
            ("PUT", ["upload"]) => Action::Publish(PublishRequest {
                upload: Upload::FirstPart,
                id: None,
                done: Response::text(201, "saved"),
            }),
            ("POST", ["upload"]) => Action::Publish(PublishRequest {
                upload: Upload::Body,
                id: None,
                done: Response::text(201, "saved"),
            }),
            (_, ["files", id, version]) if read => Action::Download(target(id, version)),
            ("DELETE", ["files", id, version]) => Action::Delete(ChangeRequest {
                target: target(id, version),
                done: Response::text(204, ""),
            }),
            (_, ["packages-of", id]) if read => {
                Action::Load(vec![Query::PackagesOf(PackageVersions {
                    id: (*id).into(),
                    versions: req
                        .query_pairs()
                        .into_iter()
                        .filter(|(k, _)| k == "v")
                        .map(|(_, v)| v)
                        .collect(),
                })])
            }
            (_, ["search"]) if read => {
                let flag = |name: &str| req.query_param(name).is_some_and(|v| v == "true");
                Action::Load(vec![Query::Search(SearchQuery {
                    text: req.query_param("q").unwrap_or_default(),
                    skip: 0,
                    take: req
                        .query_param("take")
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(0),
                    prerelease: flag("prerelease"),
                    semver2: flag("semver2"),
                    upstream: false,
                })])
            }
            _ => Action::Respond(Response::text(404, "nothing here")),
        }
    }

    fn render(&self, _repo: &Repository, _req: &Request, data: &[Loaded]) -> Action {
        let answers: Vec<Value> = data
            .iter()
            .map(|loaded| match &loaded.answer {
                Answer::Packages(packages) => {
                    json!(packages.iter().map(package_info_json).collect::<Vec<_>>())
                }
                Answer::Search(result) => json!({
                    "total": result.total,
                    "hits": result.hits.iter().map(|h| json!({
                        "id": h.original_id,
                        "latest": h.latest_version,
                        "versions": h.versions.iter().map(|v| v.version.clone()).collect::<Vec<_>>(),
                        "summary": h.summary,
                        "downloads": h.total_downloads,
                    })).collect::<Vec<_>>(),
                }),
                other => json!(format!("{other:?}")),
            })
            .collect();
        Action::Respond(Response::new(
            200,
            "application/json",
            Value::Array(answers).to_string(),
        ))
    }
}

async fn start_probe(extra_toml: Option<String>) -> TestServer {
    start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            extra_plugins: vec![Plugin::builtin(Probe)],
            extra_toml,
            ..Default::default()
        },
    )
    .await
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

async fn probe_repo(srv: &TestServer) -> String {
    let name = format!("probe{}", unique());
    let resp = create_repo(
        srv,
        json!({ "name": name, "kind": "hosted", "format": "probe" }),
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

/// The admin's username and an API token.
async fn credentials(srv: &TestServer) -> (String, String) {
    (srv.admin_user.clone().unwrap(), srv.admin_token().await)
}

async fn upload(
    srv: &TestServer,
    repo: &str,
    creds: &(String, String),
    package: &str,
) -> StatusCode {
    srv.client()
        .post(format!("{}/probe/{repo}/upload", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .body(package.to_string())
        .send()
        .await
        .unwrap()
        .status()
}

async fn get_json(srv: &TestServer, url: &str, creds: &(String, String)) -> Value {
    let resp = srv
        .client()
        .get(format!("{}{url}", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{url}");
    resp.json().await.unwrap()
}

#[tokio::test]
async fn a_format_is_served_under_its_own_mount_and_kinds() {
    let srv = start_probe(None).await;
    let creds = credentials(&srv).await;
    let repo = probe_repo(&srv).await;

    let resp = srv
        .client()
        .get(format!("{}/probe/{repo}/nothing", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.text().await.unwrap(), "nothing here");
    // Not under another format's mount, and the other way around.
    for url in [
        format!("/repository/{repo}/nothing"),
        format!("/v3/{repo}/index.json"),
    ] {
        let resp = srv
            .client()
            .get(format!("{}{url}", srv.base_url))
            .basic_auth(&creds.0, Some(&creds.1))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{url}");
        assert_ne!(resp.text().await.unwrap(), "nothing here", "{url}");
    }
    let feed = format!("feed{}", unique());
    let resp = create_repo(
        &srv,
        json!({ "name": feed, "kind": "hosted", "format": "nuget" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = srv
        .client()
        .get(format!("{}/probe/{feed}/nothing", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.text().await.unwrap(), "repository is not served here");

    // Only the kinds the plugin names.
    let resp = create_repo(
        &srv,
        json!({ "name": format!("g{}", unique()), "kind": "group", "format": "probe" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.text().await.unwrap().contains("group repositories"));

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
    let probe = formats
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "probe")
        .unwrap();
    assert_eq!(probe["mount"], "/probe");
    assert_eq!(probe["kinds"], json!(["hosted"]));
    let nuget = formats
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "nuget")
        .unwrap();
    assert_eq!(nuget["mount"], "/v3");
}

/// A repository of a format the server does not have (its plugin removed
/// since) answers 503 under a plugin's mount, and so does an administrator's
/// delete of one of its versions: it is never read as another format.
#[tokio::test]
async fn a_repository_whose_format_is_missing_is_unavailable() {
    let srv = start_probe(None).await;
    let name = format!("orphan{}", unique());
    let mut row = forge_db::repository_dao::NewRepository::hosted(name.clone());
    row.format = "gone".into();
    forge_db::repository_dao::insert_repository(&srv.pool, row)
        .await
        .expect("insert repository");
    let (u, p) = srv.admin_basic();
    for (method, url) in [
        (reqwest::Method::GET, format!("/probe/{name}/nothing")),
        (
            reqwest::Method::DELETE,
            format!("/admin/repositories/{name}/packages/demo/1.0.0"),
        ),
    ] {
        let resp = srv
            .client()
            .request(method, format!("{}{url}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{url}");
    }
}

#[tokio::test]
async fn uploads_take_the_first_part_and_assets_their_names() {
    let srv = start_probe(None).await;
    let creds = credentials(&srv).await;
    let repo = probe_repo(&srv).await;

    // The first part, whatever its name; the later ones are not read.
    let form = reqwest::multipart::Form::new()
        .part(
            "whatever",
            reqwest::multipart::Part::bytes(b"Demo 1.0.0\nbody".to_vec()).file_name("demo.bin"),
        )
        .text("note", "ignored");
    let resp = srv
        .client()
        .put(format!("{}/probe/{repo}/upload", srv.base_url))
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

    let resp = srv
        .client()
        .get(format!("{}/probe/{repo}/files/demo/1.0.0", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "application/x-probe");
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"Demo 1.0.0\nbody");

    // Stored under the plugin's asset names.
    let paths: Vec<String> = sqlx::query_scalar(
        "SELECT a.path FROM asset a JOIN component c ON c.id = a.component_id \
         JOIN repository r ON r.id = c.repository_id WHERE r.name = $1 ORDER BY a.path",
    )
    .bind(&repo)
    .fetch_all(&srv.pool)
    .await
    .unwrap();
    assert_eq!(paths, ["probe.bin", "probe.txt"]);

    let resp = srv
        .client()
        .get(format!("{}/browse/packages/{repo}/demo", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let detail: Value = resp.json().await.unwrap();
    assert_eq!(detail["description"], json!("Demo 1.0.0"));
    assert_eq!(
        detail["versions"][0]["size"],
        json!("Demo 1.0.0\nbody".len())
    );
}

#[tokio::test]
async fn downloads_answer_a_range() {
    let cache = tempfile::tempdir().unwrap();
    let srv = start_probe(Some(format!(
        "[blob_cache]\npath = {:?}\n",
        cache.path().display().to_string()
    )))
    .await;
    let creds = credentials(&srv).await;
    let repo = probe_repo(&srv).await;
    assert_eq!(
        upload(&srv, &repo, &creds, "Demo 1.0.0\n0123456789").await,
        StatusCode::CREATED
    );
    let url = format!("{}/probe/{repo}/files/demo/1.0.0", srv.base_url);
    let get = |range: &'static str| {
        srv.client()
            .get(&url)
            .basic_auth(&creds.0, Some(&creds.1))
            .header("range", range)
            .send()
    };
    let resp = get("bytes=11-14").await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers()["content-range"], "bytes 11-14/21");
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"0123");
    let resp = get("bytes=21-").await.unwrap();
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(resp.headers()["content-range"], "bytes */21");
    // Several ranges: the whole package.
    let resp = get("bytes=0-1,4-5").await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().len(), 21);
    // A HEAD ignores the range and advertises support.
    let resp = srv
        .client()
        .head(&url)
        .basic_auth(&creds.0, Some(&creds.1))
        .header("range", "bytes=11-14")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
    assert_eq!(resp.headers()["content-length"], "21");
}

/// Without the local blob cache, downloads ignore a `Range` and advertise
/// none.
#[tokio::test]
async fn downloads_ignore_a_range_without_the_blob_cache() {
    let srv = start_probe(None).await;
    let creds = credentials(&srv).await;
    let repo = probe_repo(&srv).await;
    assert_eq!(
        upload(&srv, &repo, &creds, "Demo 1.0.0\n0123456789").await,
        StatusCode::CREATED
    );
    let resp = srv
        .client()
        .get(format!("{}/probe/{repo}/files/demo/1.0.0", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .header("range", "bytes=11-14")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.headers().contains_key("accept-ranges"));
    assert!(!resp.headers().contains_key("content-range"));
    assert_eq!(resp.bytes().await.unwrap().len(), 21);
}

#[tokio::test]
async fn queries_answer_what_the_repository_holds() {
    let srv = start_probe(None).await;
    let creds = credentials(&srv).await;
    let repo = probe_repo(&srv).await;
    for package in [
        "Demo 1.0.0",
        "Demo 2.0.0",
        "Demo 1.10.0",
        "Demo 3.0.0-rc.1",
        "Other 0.1.0",
    ] {
        assert_eq!(
            upload(&srv, &repo, &creds, package).await,
            StatusCode::CREATED,
            "{package}"
        );
    }

    // Some versions, ascending, the unknown and malformed ones left out.
    let answer = get_json(
        &srv,
        &format!("/probe/{repo}/packages-of/DEMO?v=2.0.0&v=1.0.0&v=9.9.9&v=x&v=1.10.0"),
        &creds,
    )
    .await;
    let packages = answer[0].as_array().unwrap();
    let versions: Vec<&str> = packages
        .iter()
        .map(|p| p["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.0.0", "1.10.0", "2.0.0"]);
    let published = packages[0]["published"].as_str().unwrap();
    // RFC 3339, UTC, milliseconds.
    assert_eq!(
        published.len(),
        "2026-10-21T12:00:00.000+00:00".len(),
        "{published}"
    );
    assert!(published.ends_with("+00:00"), "{published}");
    assert_eq!(&published[19..20], ".", "{published}");
    assert_eq!(
        packages[0]["summary"],
        json!(r#"{"description":"Demo 1.0.0"}"#)
    );
    assert_eq!(packages[0]["size"], json!("Demo 1.0.0".len()));
    assert_eq!(packages[0]["sha256"].as_str().map(str::len), Some(64));

    // Search: SemVer 2.0.0 versions only when asked for; take 0 is the
    // default page; downloads are counted.
    let answer = get_json(
        &srv,
        &format!("/probe/{repo}/search?q=demo&prerelease=true"),
        &creds,
    )
    .await;
    let hit = &answer[0]["hits"][0];
    assert_eq!(hit["versions"], json!(["1.0.0", "1.10.0", "2.0.0"]));
    assert_eq!(hit["downloads"], json!(0));
    assert_eq!(hit["summary"], json!(r#"{"description":"Demo 2.0.0"}"#));
    let answer = get_json(
        &srv,
        &format!("/probe/{repo}/search?q=demo&prerelease=true&semver2=true"),
        &creds,
    )
    .await;
    assert_eq!(
        answer[0]["hits"][0]["versions"],
        json!(["1.0.0", "1.10.0", "2.0.0", "3.0.0-rc.1"])
    );
    let answer = get_json(&srv, &format!("/probe/{repo}/search?take=0"), &creds).await;
    assert_eq!(answer[0]["total"], json!(2));
    assert_eq!(answer[0]["hits"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn mutations_outside_the_selector_are_unknown() {
    let srv = start_probe(None).await;
    let creds = credentials(&srv).await;
    let repo = probe_repo(&srv).await;
    for package in ["Allowed-one 1.0.0", "Other 1.0.0"] {
        assert_eq!(
            upload(&srv, &repo, &creds, package).await,
            StatusCode::CREATED
        );
    }

    // A user whose role may delete `allowed-*` only.
    let (u, p) = srv.admin_basic();
    let admin = |method: reqwest::Method, path: &str, body: Value| {
        srv.client()
            .request(method, format!("{}{path}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
    };
    let username = format!("deleter{}@example.com", unique());
    let user_id = srv.create_user(&username, "pw-0123456789", "reader").await;
    let selector: Value = admin(
        reqwest::Method::POST,
        "/admin/content-selectors",
        json!({ "name": format!("allowed{}", unique()), "includes": ["allowed-*"], "excludes": [] }),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let role: Value = admin(
        reqwest::Method::POST,
        "/admin/roles",
        json!({ "name": format!("deleters{}", unique()) }),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let role_id = role["id"].as_i64().unwrap();
    let resp = admin(
        reqwest::Method::PUT,
        &format!("/admin/roles/{role_id}/grants"),
        json!({ "repository": repo, "level": "delete", "selector_id": selector["id"] }),
    )
    .await
    .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let resp = admin(
        reqwest::Method::PUT,
        &format!("/admin/users/{user_id}/roles"),
        json!({ "role_id": role_id }),
    )
    .await
    .unwrap();
    assert!(resp.status().is_success());
    let token: Value = admin(
        reqwest::Method::POST,
        &format!("/admin/users/{user_id}/tokens"),
        json!({ "name": "deleter" }),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let token = token["token"].as_str().unwrap().to_string();

    let delete = |id: &'static str| {
        srv.client()
            .delete(format!("{}/probe/{repo}/files/{id}/1.0.0", srv.base_url))
            .basic_auth(&username, Some(&token))
            .send()
    };
    // Outside the selector: as unknown as a package that does not exist.
    assert_eq!(
        delete("other").await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete("allowed-one").await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    // The other package is still there.
    let resp = srv
        .client()
        .get(format!("{}/probe/{repo}/files/other/1.0.0", srv.base_url))
        .basic_auth(&creds.0, Some(&creds.1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// The probe is a valid built-in plugin; nothing in it relies on the server.
#[test]
fn the_probe_is_a_plugin() {
    let plugin = Plugin::builtin(Probe);
    assert_eq!(plugin.descriptor().mount, "/probe");
    assert_eq!(
        forge_plugin::descriptor::check(&[plugin.descriptor()]),
        Ok(())
    );
    let _: Arc<dyn FormatPlugin> = plugin.implementation().clone();
}
