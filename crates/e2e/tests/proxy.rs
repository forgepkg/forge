//! E2E: proxy repository — cache-on-demand, singleflight (row lock),
//! package-delay hidden→visible, and genuine upstream-404 negative caching,
//! driven through the full HTTP stack against an in-process mock upstream feed
//! (spec §9). Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::sync::Arc;

use forge_e2e::{make_nupkg, start_stack, MockUpstream, TestServer, UpstreamPackage};
use serde_json::Value;

/// Create a proxy repo over `remote_url`, allowing the private (loopback) mock
/// upstream and the given package delay.
async fn create_proxy(srv: &TestServer, name: &str, remote_url: &str, delay_seconds: i32) {
    let resp = srv
        .create_repo(serde_json::json!({
            "name": name,
            "kind": "proxy",
            "remote_url": remote_url,
            "allow_private_upstream": true,
            "package_delay_seconds": delay_seconds,
            "metadata_ttl_seconds": 600,
            "not_found_ttl_seconds": 600,
        }))
        .await;
    assert_eq!(resp.status(), 201, "create proxy repo");
}

async fn download(srv: &TestServer, repo: &str, lower: &str, version: &str) -> reqwest::StatusCode {
    let (u, p) = srv.admin_basic();
    srv.client()
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/{version}/{lower}.{version}.nupkg",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .status()
}

async fn list_versions(srv: &TestServer, repo: &str, lower: &str) -> Vec<String> {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    if resp.status() == 404 {
        return Vec::new();
    }
    let body: Value = resp.json().await.unwrap();
    body["versions"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// First download fetches upstream once; a second is served from the CAS (no
/// extra upstream nupkg fetch); the service index is fetched once within TTL.
#[tokio::test]
async fn cache_on_demand_fetches_upstream_once() {
    let srv = start_stack().await;
    let nupkg = make_nupkg("Sample.Lib", "1.0.0");
    let mock =
        MockUpstream::start(vec![UpstreamPackage::single("sample.lib", "1.0.0", nupkg)]).await;
    create_proxy(&srv, "px-cache", &mock.index_url(), 0).await;

    assert_eq!(download(&srv, "px-cache", "sample.lib", "1.0.0").await, 200);
    assert_eq!(mock.nupkg_hits(), 1, "first download hits upstream once");

    assert_eq!(download(&srv, "px-cache", "sample.lib", "1.0.0").await, 200);
    assert_eq!(
        mock.nupkg_hits(),
        1,
        "second download served from CAS, no extra upstream fetch"
    );
    assert_eq!(
        mock.index_hits(),
        1,
        "service index fetched once within metadata TTL"
    );
}

/// Two concurrent first-time downloads of the same version both succeed and
/// converge on a single cached copy.
///
/// The `proxy_cached_version` row lock is held only for the short state-decision
/// and finalize transactions, never across the upstream fetch / CAS PUT
/// (Addendum A7 — never hold a DB tx across a network/S3 call). The singleflight
/// is therefore *best-effort*: under contention more than one caller may fetch
/// from upstream, but the CAS is content-addressed and the finalize tx re-checks
/// `downloaded`, so the writers converge on identical state — a single cached
/// row — and steady-state reads make zero further upstream calls.
#[tokio::test]
async fn singleflight_concurrent_first_downloads_converge() {
    let srv = Arc::new(start_stack().await);
    let nupkg = make_nupkg("Race.Lib", "1.0.0");
    let mock = MockUpstream::start(vec![UpstreamPackage::single("race.lib", "1.0.0", nupkg)]).await;
    create_proxy(&srv, "px-race", &mock.index_url(), 0).await;

    let s1 = srv.clone();
    let s2 = srv.clone();
    let h1 = tokio::spawn(async move { download(&s1, "px-race", "race.lib", "1.0.0").await });
    let h2 = tokio::spawn(async move { download(&s2, "px-race", "race.lib", "1.0.0").await });
    let (a, b) = (h1.await.unwrap(), h2.await.unwrap());

    assert_eq!(a, 200);
    assert_eq!(b, 200);

    let after_race = mock.nupkg_hits();
    assert!(
        after_race >= 1,
        "concurrent first downloads must hit upstream at least once"
    );

    // The version is now cached; subsequent reads converge on the local copy
    // and make NO further upstream calls.
    assert_eq!(download(&srv, "px-race", "race.lib", "1.0.0").await, 200);
    assert_eq!(
        mock.nupkg_hits(),
        after_race,
        "once cached, further reads do not hit upstream"
    );
}

/// Inside the package-delay window a discovered version is hidden from
/// enumeration and 404s on direct download; after the window it becomes visible
/// and downloadable. The delay-404 must NOT be negatively cached.
#[tokio::test]
async fn package_delay_hides_then_reveals() {
    let srv = start_stack().await;
    let nupkg = make_nupkg("Delay.Lib", "1.0.0");
    let mock =
        MockUpstream::start(vec![UpstreamPackage::single("delay.lib", "1.0.0", nupkg)]).await;
    create_proxy(&srv, "px-delay", &mock.index_url(), 1).await;

    // Inside the 1s window: hidden + 404.
    assert!(
        list_versions(&srv, "px-delay", "delay.lib")
            .await
            .is_empty(),
        "version hidden inside delay window"
    );
    assert_eq!(
        download(&srv, "px-delay", "delay.lib", "1.0.0").await,
        404,
        "direct download 404s inside delay window"
    );

    // After the window: visible + downloadable.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert_eq!(
        list_versions(&srv, "px-delay", "delay.lib").await,
        vec!["1.0.0".to_string()],
        "version surfaces after delay window"
    );
    assert_eq!(
        download(&srv, "px-delay", "delay.lib", "1.0.0").await,
        200,
        "download succeeds after delay window (delay-404 was not negatively cached)"
    );
}

/// A genuine upstream 404 (unknown id) is negatively cached: a second lookup
/// within the not-found TTL does not re-hit the upstream flat index.
#[tokio::test]
async fn genuine_404_is_negatively_cached() {
    let srv = start_stack().await;
    // Empty corpus → every id is a genuine upstream 404.
    let mock = MockUpstream::start(vec![]).await;
    create_proxy(&srv, "px-404", &mock.index_url(), 0).await;

    assert!(list_versions(&srv, "px-404", "missing.pkg")
        .await
        .is_empty());
    let after_first = mock.flat_index_hits();
    assert_eq!(after_first, 1, "first lookup hits upstream flat index");

    assert!(list_versions(&srv, "px-404", "missing.pkg")
        .await
        .is_empty());
    assert_eq!(
        mock.flat_index_hits(),
        after_first,
        "genuine 404 negatively cached — no upstream re-fetch within TTL"
    );
}
