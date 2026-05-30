//! E2E: repository dispatch + authorization + hosted publish/read round-trip
//! through the full HTTP stack (plan 10.3). Requires Docker.

mod common;

use common::ServerOpts;
use serde_json::Value;

/// Unknown repository → 404 from the dispatcher.
#[tokio::test]
async fn unknown_repo_is_404() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}/v3/does-not-exist/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// With `anonymous_mode = off`, an unauthenticated read of a non-anon repo is
/// 401; an admin (authenticated) read succeeds and the service index advertises
/// `PackagePublish` for a hosted repo.
#[tokio::test]
async fn read_authz_and_service_index() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("hosted{}", common::unique());

    // Create a hosted repo (not anonymous_read).
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Anonymous read → 401 (anon mode off).
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anon read of non-anon repo must be 401");

    // Authenticated read → 200, with PackagePublish advertised (hosted).
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let types: Vec<&str> = body["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["@type"].as_str().unwrap())
        .collect();
    assert!(
        types.iter().any(|t| t.starts_with("PackagePublish")),
        "hosted service index must advertise PackagePublish; got {types:?}"
    );
    // Absolute @id from public_base_url.
    let first_id = body["resources"][0]["@id"].as_str().unwrap();
    assert!(
        first_id.starts_with("http://test.local/v3/"),
        "got {first_id}"
    );
}

/// Push to a hosted repo via the NuGet PUT /package multipart endpoint, then
/// restore the same bytes via the flat container and enumerate versions.
#[tokio::test]
async fn hosted_publish_and_restore() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("pub{}", common::unique());
    let id = format!("My.Pkg{}", common::unique());
    let lower = id.to_lowercase();

    client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();

    let bytes = common::make_nupkg(&id, "1.0.0");
    let api_key = srv.admin_token().await;

    // PUT /package as multipart/form-data with the raw .nupkg as the first part.
    // NuGet clients authenticate publish with the X-NuGet-ApiKey header.
    let part = reqwest::multipart::Part::bytes(bytes.clone())
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("package", part);
    let resp = client
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", &api_key)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "publish must return 201");

    // Anonymous push must be rejected even though the read may be allowed.
    let part = reqwest::multipart::Part::bytes(bytes.clone())
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("package", part);
    let resp = client
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anonymous push must be 401");

    // Flat-container version listing.
    let resp = client
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["versions"], serde_json::json!(["1.0.0"]));

    // Download the .nupkg bytes back and compare.
    let resp = client
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/1.0.0/{lower}.1.0.0.nupkg",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let downloaded = resp.bytes().await.unwrap();
    assert_eq!(downloaded.as_ref(), bytes.as_slice(), "round-trip bytes");
}

/// Anonymous read succeeds when the repo is `anonymous_read` and the server is
/// in `anonymous_mode = all`.
#[tokio::test]
async fn anonymous_read_when_allowed() {
    let srv = common::start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "all".into(),
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            ..Default::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("anon{}", common::unique());

    client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted", "anonymous_read": true}))
        .send()
        .await
        .unwrap();

    // No credentials, anon mode all + anonymous_read → 200.
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "anonymous read should be allowed");
}
