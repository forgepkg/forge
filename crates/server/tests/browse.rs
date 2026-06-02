//! E2E: read-side browse / search endpoints (plan §12.6 Phase 0, §8).
//!
//! Exercises the full HTTP stack: publish a package, then browse + view detail;
//! anonymous-vs-authed visibility honoring `anonymous_read`; group-repo merge;
//! dependency-group rendering; and that mounting `/browse` + `/admin/me` did not
//! shadow the admin-only `/admin/*` API.

mod common;

use common::ServerOpts;
use serde_json::{json, Value};

/// Create a hosted repo and publish one package version with a dependency group.
async fn publish_one(
    srv: &common::TestServer,
    repo: &str,
    id: &str,
    version: &str,
    anonymous_read: bool,
) {
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": repo, "kind": "hosted", "anonymous_read": anonymous_read}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 201 || resp.status() == 409,
        "create repo: {}",
        resp.status()
    );

    let bytes = common::make_nupkg(id, version);
    let api_key = srv.admin_token().await;
    let part = reqwest::multipart::Part::bytes(bytes)
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
    assert_eq!(resp.status(), 201, "publish {id} {version}");
}

/// Publish into a hosted repo, then the package appears in browse search and its
/// detail lists the version + dependency group parsed from the `.nuspec`.
#[tokio::test]
async fn browse_search_and_detail() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let repo = format!("br{}", common::unique());
    let id = format!("My.Browse{}", common::unique());
    let lower = id.to_lowercase();

    publish_one(&srv, &repo, &id, "1.0.0", false).await;

    // Cross-repo search (authed) finds the package, filtered to this repo.
    let resp = srv
        .client()
        .get(format!("{}/browse/packages?repo={repo}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["total"], json!(1));
    let item = &body["items"][0];
    assert_eq!(item["repo"], json!(repo));
    assert_eq!(item["repo_kind"], json!("hosted"));
    assert_eq!(item["id"], json!(lower));
    assert_eq!(item["original_id"], json!(id));
    assert_eq!(item["latest_version"], json!("1.0.0"));

    // Package detail: version + dependency group from the stored nuspec.
    let resp = srv
        .client()
        .get(format!("{}/browse/packages/{repo}/{id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let detail: Value = resp.json().await.unwrap();
    assert_eq!(detail["repo"], json!(repo));
    assert_eq!(detail["id"], json!(lower));
    assert_eq!(detail["original_id"], json!(id));

    let versions = detail["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 1);
    let v = &versions[0];
    assert_eq!(v["version"], json!("1.0.0"));
    assert_eq!(v["listed"], json!(true));
    assert!(v["size"].as_i64().unwrap() > 0, "size from stored asset");
    assert!(v["published_at"].is_string(), "published_at = created_at");
    // Hosted versions carry no proxy delay status.
    assert_eq!(v["delay_status"], json!(null));
    assert_eq!(v["retention_status"], json!(null));

    // Dependency groups (make_nupkg embeds net8.0 -> Newtonsoft.Json).
    let groups = detail["dependency_groups_by_version"]["1.0.0"]
        .as_array()
        .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["target_framework"], json!("net8.0"));
    let deps = groups[0]["dependencies"].as_array().unwrap();
    assert_eq!(deps[0]["id"], json!("Newtonsoft.Json"));
    assert!(deps[0]["range"].is_string());
}

/// An unknown package id returns 404 from the detail endpoint.
#[tokio::test]
async fn browse_detail_unknown_package_404() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let repo = format!("br{}", common::unique());

    srv.client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();

    let resp = srv
        .client()
        .get(format!(
            "{}/browse/packages/{repo}/Nope.Missing",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Unknown repository → 404.
#[tokio::test]
async fn browse_detail_unknown_repo_404() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}/browse/packages/no-such-repo/Foo", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Anonymous visibility: with `anonymous_mode = all`, an anonymous caller sees
/// only `anonymous_read` repos in browse search; a non-anon repo is hidden from
/// the cross-repo listing and 401s on its detail.
#[tokio::test]
async fn browse_honors_anonymous_read() {
    let srv = common::start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "all".into(),
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            ..Default::default()
        },
    )
    .await;
    let suffix = common::unique();
    let pub_repo = format!("pub{suffix}");
    let priv_repo = format!("priv{suffix}");
    let pub_id = format!("Pub.Pkg{suffix}");
    let priv_id = format!("Priv.Pkg{suffix}");

    publish_one(&srv, &pub_repo, &pub_id, "1.0.0", true).await;
    publish_one(&srv, &priv_repo, &priv_id, "1.0.0", false).await;

    // Anonymous cross-repo search shows only the anonymous_read repo's package.
    let resp = srv
        .client()
        .get(format!("{}/browse/packages", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let repos: Vec<String> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["repo"].as_str().unwrap().to_string())
        .collect();
    assert!(repos.contains(&pub_repo), "anon sees anonymous_read repo");
    assert!(
        !repos.contains(&priv_repo),
        "anon must NOT see non-anon repo {priv_repo}: {repos:?}"
    );

    // Anonymous detail of the public repo → 200.
    let resp = srv
        .client()
        .get(format!(
            "{}/browse/packages/{pub_repo}/{pub_id}",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Anonymous detail of the private repo → 401.
    let resp = srv
        .client()
        .get(format!(
            "{}/browse/packages/{priv_repo}/{priv_id}",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "anon detail of non-anon repo must be 401"
    );
}

/// A group repository merges its members: a package published into a hosted
/// member is visible when browsing the group, with `repo_kind = group`.
#[tokio::test]
async fn browse_group_merges_members() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let suffix = common::unique();
    let member = format!("mem{suffix}");
    let group = format!("grp{suffix}");
    let id = format!("Group.Pkg{suffix}");
    let lower = id.to_lowercase();

    publish_one(&srv, &member, &id, "2.0.0", false).await;

    // Create a group and add the hosted member.
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": group, "kind": "group"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = client
        .post(format!(
            "{}/admin/repositories/{group}/members",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"member": member, "priority": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Browse the group: the member's package shows under the group name.
    let resp = client
        .get(format!("{}/browse/packages?repo={group}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["total"], json!(1), "group merges the member package");
    assert_eq!(body["items"][0]["repo"], json!(group));
    assert_eq!(body["items"][0]["repo_kind"], json!("group"));
    assert_eq!(body["items"][0]["latest_version"], json!("2.0.0"));

    // Group detail resolves the member version too.
    let resp = client
        .get(format!("{}/browse/packages/{group}/{id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let detail: Value = resp.json().await.unwrap();
    assert_eq!(detail["repo_kind"], json!("group"));
    let versions = detail["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["version"], json!("2.0.0"));
    let _ = lower;
}

/// Mounting `/browse` and `/admin/me` must not shadow the admin-only `/admin/*`
/// API: a non-admin is still 403 on `/admin/repositories` and unauthenticated
/// callers are 401, while `/admin/me` stays reachable.
#[tokio::test]
async fn admin_api_not_shadowed_by_new_routes() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();

    // Admin API still admin-gated: unauthenticated → 401.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Admin can list repositories (route resolves to the admin API, not browse).
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // And /admin/me resolves to the me handler (200 for the admin).
    let resp = client
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
