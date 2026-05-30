//! E2E: group repository — ordered resolution (highest priority wins for an
//! overlapping version), union enumeration across members, and identity-aware
//! mixed-anonymity filtering (spec §9). Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use forge_e2e::{make_nupkg, make_nupkg_with_desc, start_stack, AnonMode, StackBuilder};
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
