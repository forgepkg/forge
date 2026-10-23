//! E2E: hosted repository — push → restore, registration + search, SHA512
//! `packageHash`, and unlist/relist. Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use base64::Engine;
use forge_e2e::{make_nupkg, start_stack};
use serde_json::Value;
use sha2::{Digest, Sha512};

/// Push a package to a hosted repo, restore the exact bytes via the flat
/// container, and verify the SHA512 `packageHash` in the registration index
/// matches the uploaded bytes. Also asserts the package shows up in search.
#[tokio::test]
async fn push_restore_registration_search_and_hash() {
    let srv = start_stack().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = "hosted-main";
    let id = "My.Awesome.Lib";
    let lower = id.to_lowercase();

    let resp = srv
        .create_repo(serde_json::json!({"name": repo, "kind": "hosted"}))
        .await;
    assert_eq!(resp.status(), 201, "create repo");

    let bytes = make_nupkg(id, "1.2.3");
    let resp = srv.push_nupkg(repo, bytes.clone()).await;
    assert_eq!(resp.status(), 201, "publish must return 201");

    // ── Flat-container version list + byte round-trip ──
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
    assert_eq!(body["versions"], serde_json::json!(["1.2.3"]));

    let resp = client
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/1.2.3/{lower}.1.2.3.nupkg",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let downloaded = resp.bytes().await.unwrap();
    assert_eq!(downloaded.as_ref(), bytes.as_slice(), "round-trip bytes");

    // ── Registration index: SHA512 packageHash matches the uploaded bytes ──
    let resp = client
        .get(format!(
            "{}/v3/{repo}/registration/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let reg: Value = resp.json().await.unwrap();
    let entry = find_catalog_entry(&reg).expect("a catalogEntry for 1.2.3");
    assert_eq!(entry["version"], serde_json::json!("1.2.3"));
    assert_eq!(entry["packageHashAlgorithm"], serde_json::json!("SHA512"));

    let expected = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes));
    assert_eq!(
        entry["packageHash"].as_str().unwrap(),
        expected,
        "registration packageHash must be the base64 SHA512 of the nupkg"
    );

    // ── Search returns the package ──
    let resp = client
        .get(format!("{}/v3/{repo}/query?q={id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let search: Value = resp.json().await.unwrap();
    assert!(
        search["totalHits"].as_u64().unwrap() >= 1,
        "search must find the package: {search}"
    );
    let ids: Vec<&str> = search["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["id"].as_str().unwrap())
        .collect();
    assert!(ids.iter().any(|i| i.eq_ignore_ascii_case(id)), "{ids:?}");
}

/// Unlisting hides the version from search but keeps it downloadable by exact
/// version; relisting restores its search visibility.
#[tokio::test]
async fn unlist_hides_from_search_then_relist() {
    let srv = start_stack().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = "hosted-unlist";
    let id = "Unlist.Pkg";
    let lower = id.to_lowercase();

    srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted"}))
        .await;
    let bytes = make_nupkg(id, "2.0.0");
    assert_eq!(srv.push_nupkg(repo, bytes.clone()).await.status(), 201);

    let search_hits = |srv_url: String, u: String, p: String, client: reqwest::Client| async move {
        let search: Value = client
            .get(format!("{srv_url}/v3/{repo}/query?q={id}"))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        search["totalHits"].as_u64().unwrap()
    };

    assert!(
        search_hits(srv.base_url.clone(), u.clone(), p.clone(), client.clone()).await >= 1,
        "listed package is searchable"
    );

    // Unlist (DELETE on the package version).
    let resp = client
        .delete(format!("{}/v3/{repo}/package/{id}/2.0.0", srv.base_url))
        .header("X-NuGet-ApiKey", &srv.admin_token)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "unlist status {}",
        resp.status()
    );

    assert_eq!(
        search_hits(srv.base_url.clone(), u.clone(), p.clone(), client.clone()).await,
        0,
        "unlisted package must be hidden from search"
    );

    // Still downloadable by exact version.
    let resp = client
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/2.0.0/{lower}.2.0.0.nupkg",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "unlisted version still downloadable");
    assert_eq!(resp.bytes().await.unwrap().as_ref(), bytes.as_slice());

    // Relist (POST) restores search visibility.
    let resp = client
        .post(format!("{}/v3/{repo}/package/{id}/2.0.0", srv.base_url))
        .header("X-NuGet-ApiKey", &srv.admin_token)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "relist status {}",
        resp.status()
    );

    assert!(
        search_hits(srv.base_url.clone(), u, p, client).await >= 1,
        "relisted package is searchable again"
    );
}

/// Find the first `catalogEntry` in a registration index document.
fn find_catalog_entry(reg: &Value) -> Option<&Value> {
    reg["items"]
        .as_array()?
        .iter()
        .find_map(|page| page["items"].as_array())
        .and_then(|items| items.first())
        .map(|item| &item["catalogEntry"])
}
