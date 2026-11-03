//! E2E: read-side browse / search endpoints.
//!
//! Exercises the full HTTP stack: publish a package, then browse + view detail;
//! the signed-in-users-only rule (anonymous browse is 401 even for
//! `anonymous_read` repos — those stay readable on their repository feed only);
//! the `/browse/repos` folder root; group-repo merge; dependency-group
//! rendering; a proxy's and a group's package page read from the cache,
//! refreshed off the request and on Refresh (#836); and that mounting
//! `/browse` + `/admin/me` did not shadow the admin-only `/admin/*` API.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
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

    // Under RBAC, anonymous read flows through a grant on the built-in
    // `anonymous` role (what the RBAC data migration converted the
    // `anonymous_read` flag into), not the column. Seed that grant directly,
    // mirroring the migration, so the repository feed serves the repo anonymously.
    if anonymous_read {
        let repo_id = forge_db::repository_dao::find_repository_by_name(&srv.pool, repo)
            .await
            .unwrap()
            .expect("repo created")
            .id;
        let anon_role = forge_db::authz_dao::role_id_by_name(&srv.pool, "anonymous")
            .await
            .unwrap()
            .expect("anonymous role seeded");
        forge_db::authz_dao::add_grant(&srv.pool, anon_role, Some(repo_id), "read", None)
            .await
            .unwrap();
    }

    let bytes = common::make_nupkg(id, version);
    let api_key = srv.admin_token().await;
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("package", part);
    let resp = client
        .put(format!("{}/repository/{repo}/package", srv.base_url))
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

/// With more packages than `take`, `total` counts all of them, not just the
/// requested window, so the SPA's paginator can move past the first page. A
/// single repository pages in its backend; a cross-repo search merges, and
/// its totals add up across repositories.
#[tokio::test]
async fn browse_pages_past_take() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let suffix = common::unique();
    let repo = format!("pg{suffix}");
    let other = format!("pgo{suffix}");
    let prefix = format!("Paged{suffix}");
    for n in 0..7 {
        publish_one(&srv, &repo, &format!("{prefix}.P{n}"), "1.0.0", false).await;
    }
    for n in 0..3 {
        publish_one(&srv, &other, &format!("{prefix}.Q{n}"), "1.0.0", false).await;
    }

    let page = |query: String| {
        let srv = &srv;
        let (u, p) = (u.clone(), p.clone());
        async move {
            let resp = srv
                .client()
                .get(format!("{}/browse/packages?{query}", srv.base_url))
                .basic_auth(&u, Some(&p))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: Value = resp.json().await.unwrap();
            let ids: Vec<String> = body["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["original_id"].as_str().unwrap().to_string())
                .collect();
            (body["total"].as_u64().unwrap(), ids)
        }
    };
    let ids =
        |names: &[&str]| -> Vec<String> { names.iter().map(|n| format!("{prefix}.{n}")).collect() };

    // One repository (the SPA's case).
    assert_eq!(
        page(format!("repo={repo}&take=3")).await,
        (7, ids(&["P0", "P1", "P2"]))
    );
    assert_eq!(
        page(format!("repo={repo}&skip=3&take=3")).await,
        (7, ids(&["P3", "P4", "P5"]))
    );
    assert_eq!(
        page(format!("repo={repo}&skip=6&take=3")).await,
        (7, ids(&["P6"]))
    );

    // Across repositories: the merged window spans both.
    assert_eq!(
        page(format!("q={prefix}&take=3")).await,
        (10, ids(&["P0", "P1", "P2"]))
    );
    assert_eq!(
        page(format!("q={prefix}&skip=5&take=3")).await,
        (10, ids(&["P5", "P6", "Q0"]))
    );
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

/// Browsing is for signed-in users only: even with `anonymous_mode = all` and
/// an `anonymous_read` repo, an anonymous caller gets 401 from every `/browse`
/// endpoint, while the same repo stays anonymously readable on its repository feed.
#[tokio::test]
async fn browse_requires_login() {
    let srv = common::start_with(
        common::fresh_pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            ..Default::default()
        },
    )
    .await;
    srv.set_auth_settings(serde_json::json!({"anonymous_mode": "all"}))
        .await;
    let (u, p) = srv.admin_basic();
    let suffix = common::unique();
    let pub_repo = format!("pub{suffix}");
    let pub_id = format!("Pub.Pkg{suffix}");

    publish_one(&srv, &pub_repo, &pub_id, "1.0.0", true).await;

    // Anonymous search / detail / repo list → 401, anonymous_read or not.
    for url in [
        format!("{}/browse/packages", srv.base_url),
        format!("{}/browse/packages/{pub_repo}/{pub_id}", srv.base_url),
        format!("{}/browse/repos", srv.base_url),
    ] {
        let resp = srv.client().get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 401, "anonymous {url} must be 401");
    }
    // Refresh from upstream too (#836).
    let resp = srv
        .client()
        .post(format!(
            "{}/browse/packages/{pub_repo}/{pub_id}/refresh",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anonymous refresh must be 401");

    // The same anonymous caller can still read the repo through the NuGet feed.
    let resp = srv
        .client()
        .get(format!("{}/repository/{pub_repo}/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "anonymous_read still applies to repository feeds"
    );

    // A signed-in user browses normally.
    let resp = srv
        .client()
        .get(format!("{}/browse/packages?repo={pub_repo}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["total"], json!(1));
}

/// `/browse/repos` lists the repositories the signed-in caller may read,
/// sorted by name, with their kinds.
#[tokio::test]
async fn browse_repos_folder_root() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let suffix = common::unique();
    let repo = format!("root{suffix}");
    let id = format!("Root.Pkg{suffix}");

    publish_one(&srv, &repo, &id, "1.0.0", false).await;

    let resp = srv
        .client()
        .get(format!("{}/browse/repos", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let repos = body.as_array().unwrap();
    let entry = repos
        .iter()
        .find(|r| r["name"] == json!(repo))
        .expect("created repo listed in /browse/repos");
    assert_eq!(entry["kind"], json!("hosted"));
    assert_eq!(entry["online"], json!(true));
    // The id, which a token's scope names repositories by.
    let admin: Value = srv
        .client()
        .get(format!("{}/admin/repositories/{repo}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(entry["id"], admin["id"]);

    // Sorted by name.
    let names: Vec<&str> = repos.iter().map(|r| r["name"].as_str().unwrap()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "repo folder list is sorted by name");
}

/// `/browse/repos` names each repository's client URL under the shared
/// repository prefix, and `format` keeps one format's repositories.
#[tokio::test]
async fn browse_repos_by_format_with_client_urls() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let suffix = common::unique();
    let created: Vec<(String, &str)> = vec![
        (format!("nu{suffix}"), "nuget"),
        (format!("files{suffix}"), "raw"),
        (format!("images{suffix}"), "docker"),
    ];
    for (name, format) in &created {
        let resp = srv
            .client()
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&json!({"name": name, "kind": "hosted", "format": format}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "create {format} repository");
    }
    let list = |query: &'static str| {
        let srv = &srv;
        let (u, p) = (u.clone(), p.clone());
        async move {
            let resp = srv
                .client()
                .get(format!("{}/browse/repos{query}", srv.base_url))
                .basic_auth(&u, Some(&p))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            resp.json::<Value>().await.unwrap()
        }
    };
    let all = list("").await;
    let entry = |name: &str| {
        all.as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == json!(name))
            .cloned()
            .expect("listed")
    };
    let nuget = entry(&created[0].0);
    assert_eq!(nuget["format"], "nuget");
    assert_eq!(
        nuget["url"],
        format!("http://test.local/repository/{}", created[0].0)
    );
    let raw = entry(&created[1].0);
    assert_eq!(raw["format"], "raw");
    assert_eq!(
        raw["url"],
        format!("http://test.local/repository/{}", created[1].0)
    );
    assert!(nuget.get("registry").is_none(), "{nuget}");
    assert!(nuget.get("pull_prefix").is_none(), "{nuget}");
    let docker = entry(&created[2].0);
    assert_eq!(docker["format"], "docker");
    assert!(docker.get("url").is_none(), "{docker}");
    // A docker repository names the registry `docker login` takes and the
    // image prefix, for the web UI's token snippets.
    assert_eq!(docker["registry"], "test.local", "{docker}");
    assert_eq!(
        docker["pull_prefix"],
        format!("test.local/{}", created[2].0),
        "{docker}"
    );

    let files = list("?format=raw").await;
    let files = files.as_array().unwrap();
    assert!(files.iter().all(|r| r["format"] == "raw"), "{files:?}");
    assert!(files.iter().any(|r| r["name"] == json!(created[1].0)));
    assert!(list("?format=npm").await.as_array().unwrap().is_empty());
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

/// A group's browse reaches every id its members hold, past each member's
/// first 1,000, and counts them all (#536): here a proxy whose cache lists
/// 1,500 ids (seeded in SQL) and a hosted member that owns one of them.
#[tokio::test]
async fn a_group_browses_every_cached_id_of_its_proxy() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let suffix = common::unique();
    let hosted = format!("bigh{suffix}");
    let proxy = format!("bigp{suffix}");
    let group = format!("bigg{suffix}");
    let prefix = format!("Big{suffix}");
    let id = |n: usize| format!("{prefix}.P{n:04}");

    publish_one(&srv, &hosted, &id(1490), "9.0.0", false).await;
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": proxy, "kind": "proxy",
                      "remote_url": "https://feed.example/v3/index.json"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let proxy_id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    sqlx::query(
        "INSERT INTO proxy_cached_version
             (repository_id, name, version, first_seen_at, original_id)
         SELECT $1, lower(id), v, now() - interval '1 day', id
         FROM (SELECT $2 || '.P' || lpad(n::text, 4, '0') AS id
               FROM generate_series(0, 1499) AS n) AS ids,
              unnest(ARRAY['1.0.0', '1.1.0', '1.2.0']) AS v",
    )
    .bind(proxy_id)
    .bind(&prefix)
    .execute(&srv.pool)
    .await
    .unwrap();
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": group, "kind": "group"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    for (member, priority) in [(&hosted, 100), (&proxy, 10)] {
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
        assert_eq!(resp.status(), 201);
    }

    let page = |query: String| {
        let (client, srv, group) = (&client, &srv, &group);
        let (u, p) = (u.clone(), p.clone());
        async move {
            let resp = client
                .get(format!(
                    "{}/browse/packages?repo={group}&{query}",
                    srv.base_url
                ))
                .basic_auth(&u, Some(&p))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: Value = resp.json().await.unwrap();
            let items: Vec<(String, String)> = body["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    (
                        item["original_id"].as_str().unwrap().to_string(),
                        item["latest_version"].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            (body["total"].as_u64().unwrap(), items)
        }
    };
    let expected = |range: std::ops::Range<usize>| -> Vec<(String, String)> {
        range
            .map(|n| {
                let version = if n == 1490 { "9.0.0" } else { "1.2.0" };
                (id(n), version.to_string())
            })
            .collect()
    };

    assert_eq!(page("take=20".into()).await, (1500, expected(0..20)));
    assert_eq!(
        page("skip=1480&take=20".into()).await,
        (1500, expected(1480..1500)),
        "the cache's ids past 1,000, the owned one from the hosted member"
    );
    assert_eq!(
        page(format!("q={}&take=5", id(1495).to_lowercase())).await,
        (1, expected(1495..1496))
    );
}

/// A NuGet group shows a caller what it could read from its members
/// directly, no more (#648): with a member it may not read, a selector on
/// the group's grant or one on a member's, a hidden package has no flat
/// container, download or registration (404), and the feed's search and
/// the browse API leave it out, their counts too.
#[tokio::test]
async fn a_group_shows_a_caller_only_the_packages_it_may_read() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let n = common::unique();
    let (a, b, group) = (format!("va{n}"), format!("vb{n}"), format!("vg{n}"));
    // Indexed like `GroupCaller::sees`.
    let ids = [
        "Vis.Public.A",
        "Vis.Secret.A",
        "Vis.Public.B",
        "Vis.Secret.B",
    ];
    for (i, id) in ids.iter().enumerate() {
        publish_one(&srv, if i < 2 { &a } else { &b }, id, "1.0.0", false).await;
    }
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": group, "kind": "group"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    for (member, priority) in [(&a, 10), (&b, 5)] {
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
        assert_eq!(resp.status(), 201);
    }

    for common::GroupCaller {
        label,
        caller,
        sees,
    } in srv.group_callers(&group, &a, &b, &["vis.public.*"]).await
    {
        let get = |path: String| {
            caller
                .apply(client.get(format!("{}{path}", srv.base_url)))
                .send()
        };
        let mut visible = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let lower = id.to_lowercase();
            let expected = if sees[i] { 200 } else { 404 };
            for path in [
                format!("/repository/{group}/flat/{lower}/index.json"),
                format!("/repository/{group}/flat/{lower}/1.0.0/{lower}.1.0.0.nupkg"),
                format!("/repository/{group}/registration/{lower}/index.json"),
                format!("/browse/packages/{group}/{id}"),
            ] {
                let resp = get(path.clone()).await.unwrap();
                assert_eq!(resp.status(), expected, "{label}: {path}");
            }
            if sees[i] {
                visible.push(id.to_string());
            }
        }
        visible.sort_unstable();
        let search: Value = get(format!(
            "/repository/{group}/query?q=&prerelease=true&take=20"
        ))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        let mut found: Vec<String> = search["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hit| hit["id"].as_str().unwrap().to_string())
            .collect();
        found.sort_unstable();
        assert_eq!(found, visible, "{label}: {search}");
        assert_eq!(search["totalHits"], visible.len(), "{label}: {search}");
        let listed: Value = get(format!("/browse/packages?repo={group}&take=20"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let mut found: Vec<String> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["original_id"].as_str().unwrap().to_string())
            .collect();
        found.sort_unstable();
        assert_eq!(found, visible, "{label}: {listed}");
        assert_eq!(listed["total"], visible.len(), "{label}: {listed}");
    }
}

/// An offline hosted or group repository serves nothing through browse either,
/// as on its feed (#73): its search and package detail answer 503 with
/// `Retry-After`, a merged search leaves it out, and `/browse/repos` flags it.
/// An offline proxy still browses what it cached.
#[tokio::test]
async fn browse_offline_hosted_and_group_answer_503() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let hosted = format!("boffh{s}");
    let group = format!("boffg{s}");
    let proxy = format!("boffp{s}");
    let id = format!("Off.Browse{s}");

    publish_one(&srv, &hosted, &id, "1.0.0", false).await;
    for body in [
        json!({"name": group, "kind": "group"}),
        json!({"name": proxy, "kind": "proxy",
               "remote_url": "https://api.nuget.org/v3/index.json"}),
    ] {
        let resp = client
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{body}");
    }
    let resp = client
        .post(format!(
            "{}/admin/repositories/{group}/members",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"member": hosted, "priority": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let get = |path: String| {
        client
            .get(format!("{}{path}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .send()
    };
    let merged_has_id = |body: &Value| {
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["original_id"] == json!(id))
    };
    let merged: Value = get(format!("/browse/packages?q={id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(merged_has_id(&merged), "online: {merged}");

    for repo in [&hosted, &group, &proxy] {
        let resp = client
            .put(format!("{}/admin/repositories/{repo}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&json!({"online": false}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    for repo in [&hosted, &group] {
        for path in [
            format!("/browse/packages?repo={repo}"),
            format!("/browse/packages/{repo}/{id}"),
        ] {
            let resp = get(path.clone()).await.unwrap();
            assert_eq!(resp.status(), 503, "{path}");
            assert!(resp.headers().contains_key("retry-after"), "{path}");
        }
    }
    let merged: Value = get(format!("/browse/packages?q={id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!merged_has_id(&merged), "offline repos left out: {merged}");
    let resp = get(format!("/browse/packages?repo={proxy}")).await.unwrap();
    assert_eq!(resp.status(), 200, "an offline proxy browses its cache");

    let repos: Value = get("/browse/repos".into())
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for repo in [&hosted, &group, &proxy] {
        let entry = repos
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == json!(repo))
            .expect("offline repositories are still listed");
        assert_eq!(entry["online"], json!(false), "{repo}");
    }
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

/// A NuGet upstream for the package page's tests (#836): a flat container, a
/// registration with each version's dependency on `Dep.Lib`, and the `.nuspec` and
/// `.nupkg` of its versions. It records the path of every request, and holds
/// them all while it is closed.
struct Upstream {
    base: String,
    /// Package id as published → its versions.
    packages: Mutex<HashMap<String, Vec<String>>>,
    requests: Mutex<Vec<String>>,
    open: tokio::sync::watch::Sender<bool>,
}

impl Upstream {
    async fn start(packages: &[(&str, &str)]) -> Arc<Upstream> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream = Arc::new(Upstream {
            base: format!("http://{}", listener.local_addr().unwrap()),
            packages: Mutex::new(HashMap::new()),
            requests: Mutex::new(Vec::new()),
            open: tokio::sync::watch::channel(true).0,
        });
        for (id, version) in packages {
            upstream.publish(id, version);
        }
        let app = Router::new()
            .route("/index.json", get(upstream_index))
            .route("/flat/{id}/index.json", get(upstream_versions))
            .route("/flat/{id}/{version}/{file}", get(upstream_file))
            .route("/registration/{id}/index.json", get(upstream_registration))
            .with_state(upstream.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve upstream");
        });
        upstream
    }

    fn publish(&self, id: &str, version: &str) {
        self.packages
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_default()
            .push(version.to_string());
    }

    /// The package published as `lower` (any casing), with its versions.
    fn package(&self, lower: &str) -> Option<(String, Vec<String>)> {
        self.packages
            .lock()
            .unwrap()
            .iter()
            .find(|(id, _)| id.to_lowercase() == lower)
            .map(|(id, versions)| (id.clone(), versions.clone()))
    }

    /// Hold every request until [`Self::open`] (`false`), or let them through.
    fn set_open(&self, open: bool) {
        self.open.send_replace(open);
    }

    /// Every request so far.
    fn total(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// Wait (ten seconds at most) until it has had more than `seen` requests.
    async fn asked_beyond(&self, seen: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while self.total() <= seen {
            assert!(tokio::time::Instant::now() < deadline, "never asked");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The requests that named package `lower`.
    fn requests_for(&self, lower: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.contains(&format!("/{lower}/")))
            .count()
    }

    async fn record(&self, path: String) {
        self.requests.lock().unwrap().push(path);
        let mut open = self.open.subscribe();
        let _ = open.wait_for(|open| *open).await;
    }
}

async fn upstream_index(State(up): State<Arc<Upstream>>) -> Json<Value> {
    up.record("/index.json".into()).await;
    Json(json!({
        "version": "3.0.0",
        "resources": [
            {"@id": format!("{}/flat/", up.base), "@type": "PackageBaseAddress/3.0.0"},
            {"@id": format!("{}/registration/", up.base), "@type": "RegistrationsBaseUrl/3.6.0"},
        ],
    }))
}

async fn upstream_versions(State(up): State<Arc<Upstream>>, Path(id): Path<String>) -> Response {
    up.record(format!("/flat/{id}/index.json")).await;
    match up.package(&id) {
        Some((_, versions)) => Json(json!({"versions": versions})).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upstream_registration(
    State(up): State<Arc<Upstream>>,
    Path(id): Path<String>,
) -> Response {
    up.record(format!("/registration/{id}/index.json")).await;
    let Some((original, versions)) = up.package(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let leaves: Vec<Value> = versions
        .iter()
        .map(|v| {
            json!({
                "@id": format!("{}/registration/{id}/{v}.json", up.base),
                "catalogEntry": {
                    "id": original,
                    "version": v,
                    "listed": true,
                    "dependencyGroups": [{
                        "targetFramework": "net8.0",
                        "dependencies": [{"id": "Dep.Lib", "range": "[1.0.0, )"}],
                    }],
                },
                "packageContent": format!("{}/flat/{id}/{v}/{id}.{v}.nupkg", up.base),
            })
        })
        .collect();
    Json(json!({
        "count": 1,
        "items": [{
            "@id": format!("{}/registration/{id}/index.json#page", up.base),
            "lower": versions.first(),
            "upper": versions.last(),
            "count": leaves.len(),
            "items": leaves,
        }],
    }))
    .into_response()
}

async fn upstream_file(
    State(up): State<Arc<Upstream>>,
    Path((id, version, file)): Path<(String, String, String)>,
) -> Response {
    up.record(format!("/flat/{id}/{version}/{file}")).await;
    let Some((original, versions)) = up.package(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !versions.contains(&version) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if file.ends_with(".nupkg") {
        common::make_nupkg(&original, &version).into_response()
    } else if file.ends_with(".nuspec") {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{original}</id>
    <version>{version}</version>
    <authors>test</authors>
    <description>{original} from upstream</description>
  </metadata>
</package>"#
        )
        .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Create proxy `name` of `upstream` (no package delay, an hour's metadata
/// TTL) as the bootstrap admin.
async fn create_proxy(srv: &common::TestServer, name: &str, upstream: &Upstream) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": format!("{}/index.json", upstream.base),
            "package_delay_seconds": 0,
            "metadata_ttl_seconds": 3600,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create proxy {name}");
}

/// `GET` (or `POST`, for a refresh) `path` as the bootstrap admin; the
/// status and the JSON body (`null` when there is none). Fails the test if
/// it takes ten seconds.
async fn admin_send(srv: &common::TestServer, method: reqwest::Method, path: &str) -> (u16, Value) {
    let (u, p) = srv.admin_basic();
    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        srv.client()
            .request(method, format!("{}{path}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .send(),
    )
    .await
    .unwrap_or_else(|_| panic!("{path} took ten seconds"))
    .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The dependency ids of `version` on a package detail.
fn dependencies_of(detail: &Value, version: &str) -> Vec<String> {
    detail["dependency_groups_by_version"][version]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|group| {
            group["dependencies"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .map(|dep| dep["id"].as_str().unwrap().to_string())
        .collect()
}

/// The versions of a package detail.
fn versions_of(detail: &Value) -> Vec<String> {
    detail["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap().to_string())
        .collect()
}

/// Ask `path` (a package page) until its versions are `want`, for ten seconds.
async fn page_until(srv: &common::TestServer, path: &str, want: &[&str]) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let (status, detail) = admin_send(srv, reqwest::Method::GET, path).await;
        if status == 200 && versions_of(&detail) == want {
            return detail;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{path} never listed {want:?}: {status} {detail}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The cached-version rows a proxy holds of a package.
async fn cached_rows(srv: &common::TestServer, proxy: &str, lower: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM proxy_cached_version v JOIN repository r ON r.id = v.repository_id
         WHERE r.name = $1 AND v.name = $2",
    )
    .bind(proxy)
    .bind(lower)
    .fetch_one(&srv.pool)
    .await
    .unwrap()
}

/// A proxy's package page answers from what Forge holds (#836): with the
/// dependencies of the registration a client fetched, and when the upstream
/// listed the package, but without asking the upstream on the request, also
/// once the listing is stale (here: older than a cache invalidation), and
/// without discovering a package it holds nothing of. A stale page starts a
/// refresh off the request, once, and the next look shows what it found.
#[tokio::test]
async fn a_proxy_package_page_answers_from_the_cache_and_refreshes_off_the_request() {
    let srv = common::start().await;
    let upstream = Upstream::start(&[("Cached.Lib", "1.0.0"), ("Uncached.Lib", "1.0.0")]).await;
    let proxy = format!("cachep{}", common::unique());
    create_proxy(&srv, &proxy, &upstream).await;

    // A client restores Cached.Lib: its listing and registration are cached.
    for path in [
        format!("/repository/{proxy}/flat/cached.lib/index.json"),
        format!("/repository/{proxy}/registration/cached.lib/index.json"),
    ] {
        let (status, body) = admin_send(&srv, reqwest::Method::GET, &path).await;
        assert_eq!(status, 200, "{path}: {body}");
    }
    let asked = upstream.requests_for("cached.lib");
    assert!(asked > 0);

    let page = format!("/browse/packages/{proxy}/Cached.Lib");
    let (status, detail) = admin_send(&srv, reqwest::Method::GET, &page).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(versions_of(&detail), ["1.0.0"]);
    assert_eq!(dependencies_of(&detail, "1.0.0"), ["Dep.Lib"], "{detail}");
    let cached_at = detail["cached_at"].as_str().expect("cached_at").to_string();
    assert!(detail.get("refreshing").is_none(), "fresh: {detail}");
    assert_eq!(
        upstream.requests_for("cached.lib"),
        asked,
        "the page asked the upstream"
    );

    // A version published since shows once the listing is refreshed, not
    // before: the page asks nothing within the TTL.
    upstream.publish("Cached.Lib", "2.0.0");
    let (_, detail) = admin_send(&srv, reqwest::Method::GET, &page).await;
    assert_eq!(versions_of(&detail), ["1.0.0"]);
    assert_eq!(upstream.requests_for("cached.lib"), asked);

    // A package the proxy holds nothing of is not found, and looking at its
    // page neither asks the upstream nor records it.
    let (status, _) = admin_send(
        &srv,
        reqwest::Method::GET,
        &format!("/browse/packages/{proxy}/Uncached.Lib"),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(upstream.requests_for("uncached.lib"), 0);
    assert_eq!(cached_rows(&srv, &proxy, "uncached.lib").await, 0);

    // Past an invalidation the listing is stale: the page answers from the
    // cache and starts a refresh off the request. While the upstream holds
    // that refresh's request, the page still answers at once, and starts no
    // other.
    let (status, _) = admin_send(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{proxy}/proxy-cache/invalidate"),
    )
    .await;
    assert_eq!(status, 200);
    upstream.set_open(false);
    let seen = upstream.total();
    let (status, detail) = admin_send(&srv, reqwest::Method::GET, &page).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(versions_of(&detail), ["1.0.0"]);
    assert_eq!(detail["refreshing"], true, "{detail}");
    upstream.asked_beyond(seen).await;
    let held = upstream.total();
    let (status, detail) = admin_send(&srv, reqwest::Method::GET, &page).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(versions_of(&detail), ["1.0.0"]);
    assert_eq!(detail["refreshing"], true, "{detail}");
    assert_eq!(upstream.total(), held, "a second refresh");

    // Once the upstream answers, the page shows the new version.
    upstream.set_open(true);
    page_until(&srv, &page, &["1.0.0", "2.0.0"]).await;
    // Once the refresh is done (it fetches the registration and tags after
    // the listing), the page is fresh again: no other refresh starts.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let (_, detail) = admin_send(&srv, reqwest::Method::GET, &page).await;
        if detail.get("refreshing").is_none() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "still refreshing: {detail}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let done = upstream.total();
    let (_, detail) = admin_send(&srv, reqwest::Method::GET, &page).await;
    assert!(detail.get("refreshing").is_none(), "{detail}");
    assert!(
        detail["cached_at"].as_str().unwrap() > cached_at.as_str(),
        "{detail}"
    );
    assert_eq!(dependencies_of(&detail, "2.0.0"), ["Dep.Lib"], "{detail}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(upstream.total(), done, "a refresh of a fresh page");
}

/// **Refresh from upstream** asks the upstream now, and answers the
/// refreshed page: any reader of the proxy may, and it finds a package the
/// proxy held nothing of (#836). A caller who may not read the proxy may not,
/// and a package the upstream does not have stays not found.
#[tokio::test]
async fn refresh_from_upstream_needs_only_read_access() {
    let srv = common::start().await;
    let upstream = Upstream::start(&[("Fresh.Lib", "1.0.0")]).await;
    let proxy = format!("refrp{}", common::unique());
    create_proxy(&srv, &proxy, &upstream).await;
    let reader = srv.caller().await;
    srv.grant_role(reader.id, &[(proxy.as_str(), "read", None)])
        .await;
    let stranger = srv.caller().await;

    let refresh = |caller: &common::Caller, id: &str| {
        caller
            .apply(srv.client().post(format!(
                "{}/browse/packages/{proxy}/{id}/refresh",
                srv.base_url
            )))
            .send()
    };
    let resp = refresh(&stranger, "Fresh.Lib").await.unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(upstream.requests_for("fresh.lib"), 0);

    let resp = refresh(&reader, "Fresh.Lib").await.unwrap();
    assert_eq!(resp.status(), 200);
    let detail: Value = resp.json().await.unwrap();
    assert_eq!(versions_of(&detail), ["1.0.0"], "{detail}");
    assert_eq!(dependencies_of(&detail, "1.0.0"), ["Dep.Lib"], "{detail}");
    assert!(detail["cached_at"].is_string(), "{detail}");
    assert!(upstream.requests_for("fresh.lib") > 0);

    // The page has it now, from the cache.
    let resp = reader
        .apply(srv.client().get(format!(
            "{}/browse/packages/{proxy}/fresh.lib",
            srv.base_url
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = refresh(&reader, "Missing.Lib").await.unwrap();
    assert_eq!(resp.status(), 404);
}

/// A group's package page reads its proxy member from the cache too (#836):
/// a package the proxy holds nothing of is not found through the group and
/// is not asked for, the age of the page is the member's listing, a stale
/// member is refreshed off the request, and Refresh on the group asks the
/// members.
#[tokio::test]
async fn a_group_package_page_reads_its_proxy_members_from_the_cache() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let upstream = Upstream::start(&[("Group.Lib", "1.0.0"), ("Later.Lib", "1.0.0")]).await;
    let suffix = common::unique();
    let proxy = format!("cgp{suffix}");
    let group = format!("cgg{suffix}");
    create_proxy(&srv, &proxy, &upstream).await;
    let client = srv.client();
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
        .json(&json!({"member": proxy, "priority": 10}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // A client restores Group.Lib through the group.
    let (status, _) = admin_send(
        &srv,
        reqwest::Method::GET,
        &format!("/repository/{group}/flat/group.lib/index.json"),
    )
    .await;
    assert_eq!(status, 200);
    let asked = upstream.requests_for("group.lib");

    let page = format!("/browse/packages/{group}/Group.Lib");
    let (status, detail) = admin_send(&srv, reqwest::Method::GET, &page).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(versions_of(&detail), ["1.0.0"]);
    assert!(detail["cached_at"].is_string(), "{detail}");
    assert!(detail.get("refreshing").is_none(), "{detail}");
    assert_eq!(upstream.requests_for("group.lib"), asked);

    let later = format!("/browse/packages/{group}/Later.Lib");
    let (status, _) = admin_send(&srv, reqwest::Method::GET, &later).await;
    assert_eq!(status, 404);
    assert_eq!(upstream.requests_for("later.lib"), 0);
    assert_eq!(cached_rows(&srv, &proxy, "later.lib").await, 0);

    // A stale member is refreshed off the group page's request.
    upstream.publish("Group.Lib", "2.0.0");
    let (status, _) = admin_send(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{proxy}/proxy-cache/invalidate"),
    )
    .await;
    assert_eq!(status, 200);
    upstream.set_open(false);
    let seen = upstream.total();
    let (status, detail) = admin_send(&srv, reqwest::Method::GET, &page).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(versions_of(&detail), ["1.0.0"]);
    assert_eq!(detail["refreshing"], true, "{detail}");
    upstream.asked_beyond(seen).await;
    let (status, _) = admin_send(&srv, reqwest::Method::GET, &page).await;
    assert_eq!(status, 200);
    upstream.set_open(true);
    page_until(&srv, &page, &["1.0.0", "2.0.0"]).await;

    // Refresh on the group asks its members for a package they lacked.
    let (status, detail) =
        admin_send(&srv, reqwest::Method::POST, &format!("{later}/refresh")).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(versions_of(&detail), ["1.0.0"]);
    assert!(upstream.requests_for("later.lib") > 0);
}
