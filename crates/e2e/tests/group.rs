//! E2E: group repository — ordered resolution (highest priority wins for an
//! overlapping version), union enumeration across members, identity-aware
//! mixed-anonymity filtering (spec §9), and the prefer-hosted
//! dependency-confusion guard for callers who cannot see the hosted copy.
//! Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use forge_e2e::{
    make_nupkg, make_nupkg_with_desc, start_stack, AnonMode, MockUpstream, StackBuilder,
    TestServer, UpstreamPackage,
};
use reqwest::StatusCode;
use serde_json::Value;

/// Two hosted members share an overlapping version with **different bytes**; the
/// higher-priority member wins the download. Enumeration is the **union** of all
/// versions across members.
#[tokio::test]
async fn ordered_resolution_and_union_enumeration() {
    let srv = start_stack().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    let id = "Shared.Lib";
    let lower = id.to_lowercase();

    // Members + group.
    for repo in ["grp-low", "grp-high"] {
        assert_eq!(
            srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted"}))
                .await
                .status(),
            201
        );
    }
    assert_eq!(
        srv.create_repo(serde_json::json!({"name": "grp", "kind": "group"}))
            .await
            .status(),
        201
    );
    // Higher integer priority wins.
    assert_eq!(srv.add_member("grp", "grp-low", 10).await.status(), 201);
    assert_eq!(srv.add_member("grp", "grp-high", 20).await.status(), 201);

    // Overlapping version 1.0.0 in both members, with distinct bytes.
    let low_bytes = make_nupkg_with_desc(id, "1.0.0", "from-low-priority-member");
    let high_bytes = make_nupkg_with_desc(id, "1.0.0", "from-high-priority-member");
    assert_eq!(srv.push_nupkg("grp-low", low_bytes).await.status(), 201);
    assert_eq!(
        srv.push_nupkg("grp-high", high_bytes.clone())
            .await
            .status(),
        201
    );
    // A version unique to the low member, to prove union enumeration.
    assert_eq!(
        srv.push_nupkg("grp-low", make_nupkg(id, "0.9.0"))
            .await
            .status(),
        201
    );

    // Union enumeration via the group: both versions present.
    let resp = client
        .get(format!("{}/v3/grp/flat/{lower}/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let mut versions: Vec<String> = body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    versions.sort();
    assert_eq!(
        versions,
        vec!["0.9.0".to_string(), "1.0.0".to_string()],
        "group enumerates the union of member versions"
    );

    // Ordered download: the high-priority member's bytes win for 1.0.0.
    let resp = client
        .get(format!(
            "{}/v3/grp/flat/{lower}/1.0.0/{lower}.1.0.0.nupkg",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let downloaded = resp.bytes().await.unwrap();
    assert_eq!(
        downloaded.as_ref(),
        high_bytes.as_slice(),
        "highest-priority member wins the overlapping-version download"
    );
}

/// A mixed-anonymity group exposes only its `anonymous_read` members to an
/// anonymous caller; an authenticated caller sees the union of all members.
#[tokio::test]
async fn mixed_anon_group_filters_members() {
    // anonymous_mode = all so anonymous reads of anonymous_read repos are
    // permitted at the dispatch layer.
    let srv = StackBuilder::default().anon(AnonMode::All).start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    let id = "Mixed.Lib";
    let lower = id.to_lowercase();

    // Public member (anonymous_read), private member (auth-only), public group.
    assert_eq!(
        srv.create_repo(
            serde_json::json!({"name": "m-pub", "kind": "hosted", "anonymous_read": true})
        )
        .await
        .status(),
        201
    );
    assert_eq!(
        srv.create_repo(
            serde_json::json!({"name": "m-priv", "kind": "hosted", "anonymous_read": false})
        )
        .await
        .status(),
        201
    );
    assert_eq!(
        srv.create_repo(
            serde_json::json!({"name": "mgrp", "kind": "group", "anonymous_read": true})
        )
        .await
        .status(),
        201
    );
    assert_eq!(srv.add_member("mgrp", "m-pub", 10).await.status(), 201);
    assert_eq!(srv.add_member("mgrp", "m-priv", 20).await.status(), 201);

    // §12.4 RBAC: anonymous read flows through anonymous-role grants (what the
    // data migration converts the slice-1 anonymous_read flag into). Grant the
    // group and the *public* member only — `m-priv` is deliberately ungranted,
    // so the identity-aware group filter hides it from the anonymous caller.
    srv.grant_anonymous_read("mgrp").await;
    srv.grant_anonymous_read("m-pub").await;

    assert_eq!(
        srv.push_nupkg("m-pub", make_nupkg(id, "1.0.0"))
            .await
            .status(),
        201
    );
    assert_eq!(
        srv.push_nupkg("m-priv", make_nupkg(id, "2.0.0"))
            .await
            .status(),
        201
    );

    // Anonymous caller: only the public member's version is visible.
    let resp = client
        .get(format!("{}/v3/mgrp/flat/{lower}/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "anonymous read of anon group");
    let body: Value = resp.json().await.unwrap();
    let versions: Vec<String> = body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        versions,
        vec!["1.0.0".to_string()],
        "anonymous caller sees only the anonymous_read member's versions"
    );

    // The private member's version 2.0.0 is hidden from the anonymous caller.
    let resp = client
        .get(format!(
            "{}/v3/mgrp/flat/{lower}/2.0.0/{lower}.2.0.0.nupkg",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "private member's version is not downloadable anonymously via the group"
    );

    // Authenticated caller sees the union of both members.
    let resp = client
        .get(format!("{}/v3/mgrp/flat/{lower}/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let mut versions: Vec<String> = body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    versions.sort();
    assert_eq!(
        versions,
        vec!["1.0.0".to_string(), "2.0.0".to_string()],
        "authenticated caller sees the union of all members"
    );
}

// ── prefer_hosted against callers who cannot see the hosted copy (B2) ──────

/// The internal id owned by the private hosted member, and the attacker's
/// higher version of it on the public feed.
const INTERNAL_ID: &str = "Contoso.Internal";
const ATTACKER_VERSION: &str = "99.0.0";

/// A mixed-anonymity group in the documented layout: an anonymous group, a
/// private hosted member owning [`INTERNAL_ID`] `1.0.0`, and an anonymous
/// proxy (ranked *above* the hosted member) whose upstream serves
/// [`ATTACKER_VERSION`] of the same id plus an unrelated public package. The
/// proxy's local cache is warmed through the proxy itself so its search index
/// knows both ids. Returns the mock so it outlives the test body.
async fn shadowed_internal_group(srv: &TestServer) -> MockUpstream {
    let mock = MockUpstream::start(vec![
        UpstreamPackage::single(
            INTERNAL_ID,
            ATTACKER_VERSION,
            make_nupkg_with_desc(INTERNAL_ID, ATTACKER_VERSION, "attacker"),
        ),
        UpstreamPackage::single("Public.Lib", "1.0.0", make_nupkg("Public.Lib", "1.0.0")),
    ])
    .await;

    assert_eq!(
        srv.create_repo(
            serde_json::json!({"name": "dc-priv", "kind": "hosted", "anonymous_read": false})
        )
        .await
        .status(),
        201
    );
    assert_eq!(
        srv.create_repo(serde_json::json!({
            "name": "dc-pub",
            "kind": "proxy",
            "anonymous_read": true,
            "remote_url": mock.index_url(),
            "package_delay_seconds": 0,
            "metadata_ttl_seconds": 600,
            "not_found_ttl_seconds": 600,
        }))
        .await
        .status(),
        201
    );
    assert_eq!(
        srv.create_repo(
            serde_json::json!({"name": "dc-grp", "kind": "group", "anonymous_read": true})
        )
        .await
        .status(),
        201
    );
    assert_eq!(srv.add_member("dc-grp", "dc-pub", 20).await.status(), 201);
    assert_eq!(srv.add_member("dc-grp", "dc-priv", 10).await.status(), 201);
    srv.grant_anonymous_read("dc-grp").await;
    srv.grant_anonymous_read("dc-pub").await;

    assert_eq!(
        srv.push_nupkg("dc-priv", make_nupkg(INTERNAL_ID, "1.0.0"))
            .await
            .status(),
        201
    );

    // The upstream really serves the shadow: reading the proxy directly lists
    // it (and records both ids in the proxy's search index).
    let (u, p) = srv.admin_basic();
    for (lower, version) in [
        (INTERNAL_ID.to_lowercase(), ATTACKER_VERSION),
        ("public.lib".to_string(), "1.0.0"),
    ] {
        let body: Value = srv
            .client()
            .get(format!(
                "{}/v3/dc-pub/flat/{lower}/index.json",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["versions"], serde_json::json!([version]));
    }
    mock
}

/// Assert that `auth` (a request decorator) never receives the proxy's version
/// of [`INTERNAL_ID`] through the group: flat index, nupkg, nuspec,
/// registration and search all look like an unknown package. The unrelated
/// public package still comes through the proxy.
async fn assert_shadow_not_served(
    srv: &TestServer,
    who: &str,
    auth: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
) {
    let lower = INTERNAL_ID.to_lowercase();
    let v = ATTACKER_VERSION;
    let get = |path: String| auth(srv.client().get(format!("{}{path}", srv.base_url))).send();

    for path in [
        format!("/v3/dc-grp/flat/{lower}/index.json"),
        format!("/v3/dc-grp/flat/{lower}/{v}/{lower}.{v}.nupkg"),
        format!("/v3/dc-grp/flat/{lower}/{v}/{lower}.nuspec"),
        format!("/v3/dc-grp/registration/{lower}/index.json"),
        format!("/v3/dc-grp/registration/{lower}/{v}.json"),
    ] {
        assert_eq!(
            get(path.clone()).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "{who}: {path} must look absent, never serve the proxy's shadow"
        );
    }

    for q in ["contoso", ""] {
        let search: Value = get(format!("/v3/dc-grp/query?q={q}&prerelease=true"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let ids: Vec<&str> = search["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hit| hit["id"].as_str().unwrap())
            .collect();
        assert!(
            !ids.iter().any(|id| id.eq_ignore_ascii_case(INTERNAL_ID)),
            "{who}: /query?q={q} must not list the proxy's shadow: {search}"
        );
        assert_eq!(
            search["totalHits"].as_u64().unwrap() as usize,
            ids.len(),
            "{who}: totalHits must not count the dropped hit"
        );
    }

    let resp = get("/v3/dc-grp/flat/public.lib/index.json".to_string())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "{who}: ids no hosted member owns are still proxied"
    );
}

/// Anonymous callers of a mixed-anonymity group cannot see the private hosted
/// copy of an internal id; they must get 404 for it, not the public proxy's
/// higher version. Authenticated callers still get the hosted copy only.
#[tokio::test]
async fn prefer_hosted_shields_internal_id_from_anonymous_callers() {
    let srv = StackBuilder::default().anon(AnonMode::All).start().await;
    let _mock = shadowed_internal_group(&srv).await;

    assert_shadow_not_served(&srv, "anonymous", |req| req).await;

    // The admin sees the hosted member: its version only, never the shadow.
    let (u, p) = srv.admin_basic();
    let lower = INTERNAL_ID.to_lowercase();
    let body: Value = srv
        .client()
        .get(format!(
            "{}/v3/dc-grp/flat/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["versions"], serde_json::json!(["1.0.0"]));
    let search: Value = srv
        .client()
        .get(format!("{}/v3/dc-grp/query?q=contoso", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(search["totalHits"], 1);
    assert_eq!(search["data"][0]["id"], INTERNAL_ID);
    assert_eq!(search["data"][0]["version"], "1.0.0");
    // The hosted hit is enriched on the group's final page (manifest metadata).
    assert_eq!(search["data"][0]["description"], "generated test package");

    // Once the public package is cached, its proxied hit is enriched through
    // the proxy member on the group's final page as well.
    let resp = srv
        .client()
        .get(format!(
            "{}/v3/dc-grp/flat/public.lib/1.0.0/public.lib.1.0.0.nupkg",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let search: Value = srv
        .client()
        .get(format!("{}/v3/dc-grp/query?q=public", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(search["totalHits"], 1);
    assert_eq!(search["data"][0]["id"], "public.lib");
    assert_eq!(search["data"][0]["description"], "generated test package");
}

/// A token whose read grant on the hosted member is selector-scoped away from
/// the internal id is shielded the same way.
#[tokio::test]
async fn prefer_hosted_shields_internal_id_from_selector_scoped_tokens() {
    let srv = StackBuilder::default().anon(AnonMode::All).start().await;
    let _mock = shadowed_internal_group(&srv).await;

    let selector = srv
        .create_content_selector("dc-public-only", &["public.*"], &[])
        .await;
    let user = srv.create_user("dc-scoped", "pw").await;
    let role = srv.create_role("dc-scoped-reader").await;
    for (repo, selector) in [
        ("dc-grp", None),
        ("dc-pub", None),
        ("dc-priv", Some(selector)),
    ] {
        assert_eq!(
            srv.add_grant(role, Some(repo), "read", selector)
                .await
                .status(),
            201
        );
    }
    assert_eq!(srv.assign_role(user, role).await.status(), 204);
    let token = srv.issue_token(user, None).await;

    assert_shadow_not_served(&srv, "selector-scoped token", |req| {
        req.header("X-NuGet-ApiKey", &token)
    })
    .await;
}
