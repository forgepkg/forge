//! E2E: proxy repository — cache-on-demand, singleflight (row lock),
//! package-delay hidden→visible, genuine upstream-404 negative caching (and a
//! planted marker not hiding a later release), verified upstream manifests and
//! upstream registration metadata, driven through the full HTTP stack against
//! an in-process mock upstream feed. Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::sync::Arc;

use forge_e2e::{make_nupkg, start_stack, MockUpstream, TestServer, UpstreamPackage};
use serde_json::Value;

/// Create a proxy repo over `remote_url`, allowing the private (loopback) mock
/// upstream and the given package delay.
async fn create_proxy(srv: &TestServer, name: &str, remote_url: &str, delay_seconds: i32) {
    create_proxy_with_ttl(srv, name, remote_url, delay_seconds, 600).await;
}

async fn create_proxy_with_ttl(
    srv: &TestServer,
    name: &str,
    remote_url: &str,
    delay_seconds: i32,
    metadata_ttl_seconds: i32,
) {
    let resp = srv
        .create_repo(serde_json::json!({
            "name": name,
            "kind": "proxy",
            "remote_url": remote_url,
            "package_delay_seconds": delay_seconds,
            "metadata_ttl_seconds": metadata_ttl_seconds,
            "not_found_ttl_seconds": 600,
        }))
        .await;
    assert_eq!(resp.status(), 201, "create proxy repo");
}

/// GET `path` (below `/v3/{repo}`) as the admin.
async fn get_v3(srv: &TestServer, repo: &str, path: &str) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    srv.client()
        .get(format!("{}/v3/{repo}/{path}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
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
/// (no DB transaction is ever held across a network/S3 call). The singleflight
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
    // Large delay window so the "inside window" assertions are immune to
    // CI-runner slowness — a tiny (1s) window can elapse between discovery and
    // the download check on a loaded runner, which made this test flaky.
    create_proxy(&srv, "px-delay", &mock.index_url(), 3600).await;

    // Inside the window: discovery records first_seen_at; hidden + 404.
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

    // Simulate the window elapsing DETERMINISTICALLY (no real sleep): backdate
    // the discovered version's first_seen_at past the delay. This also proves
    // the in-window 404 was NOT negatively cached — the next download must
    // succeed by fetching from upstream.
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = now() - interval '2 hours' WHERE name = $1",
    )
    .bind("delay.lib")
    .execute(&srv.pool)
    .await
    .expect("backdate proxy_cached_version.first_seen_at");

    // After the window: visible + downloadable.
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

/// H3: a reader requesting a version before it is released plants a
/// not-found marker; once the upstream publishes the version, the next
/// listing refresh must offer it (and it downloads) although the marker's
/// not-found TTL (600 s) has not elapsed.
#[tokio::test]
async fn planted_not_found_marker_does_not_hide_a_later_release() {
    let srv = start_stack().await;
    let mock = MockUpstream::start(vec![UpstreamPackage::single(
        "Future.Lib",
        "1.0.0",
        make_nupkg("Future.Lib", "1.0.0"),
    )])
    .await;
    // 1 s metadata TTL so the listing refreshes after the release.
    create_proxy_with_ttl(&srv, "px-future", &mock.index_url(), 0, 1).await;

    assert_eq!(
        download(&srv, "px-future", "future.lib", "2.0.0").await,
        404
    );
    assert_eq!(
        list_versions(&srv, "px-future", "future.lib").await,
        vec!["1.0.0".to_string()],
        "the 404'd version is not listed"
    );

    mock.publish("Future.Lib", "2.0.0", make_nupkg("Future.Lib", "2.0.0"));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert_eq!(
        list_versions(&srv, "px-future", "future.lib").await,
        vec!["1.0.0".to_string(), "2.0.0".to_string()],
        "the release surfaces on the next listing refresh"
    );
    assert_eq!(
        download(&srv, "px-future", "future.lib", "2.0.0").await,
        200
    );
}

/// M10: the upstream `.nuspec` is served (verified) without downloading the
/// package; M11: the registration of a version not downloaded yet carries the
/// upstream's dependency groups.
#[tokio::test]
async fn upstream_metadata_is_served_before_download() {
    let srv = start_stack().await;
    let mock = MockUpstream::start(vec![UpstreamPackage::single(
        "Meta.Lib",
        "1.0.0",
        make_nupkg("Meta.Lib", "1.0.0"),
    )])
    .await;
    create_proxy(&srv, "px-meta", &mock.index_url(), 0).await;

    let resp = get_v3(&srv, "px-meta", "flat/meta.lib/1.0.0/meta.lib.nuspec").await;
    assert_eq!(resp.status(), 200);
    let nuspec = resp.text().await.unwrap();
    assert!(nuspec.contains("<id>Meta.Lib</id>"), "{nuspec}");
    assert_eq!(mock.nuspec_hits(), 1);

    mock.set_published("Meta.Lib", "1.0.0", "2026-01-01T00:00:00+00:00");
    let resp = get_v3(&srv, "px-meta", "registration/meta.lib/index.json").await;
    assert_eq!(resp.status(), 200);
    let reg: Value = resp.json().await.unwrap();
    let entry = &reg["items"][0]["items"][0]["catalogEntry"];
    assert_eq!(entry["id"], "Meta.Lib");
    assert_eq!(entry["listed"], true);
    assert_eq!(
        entry["dependencyGroups"][0]["targetFramework"], "net8.0",
        "{entry}"
    );
    assert_eq!(
        entry["dependencyGroups"][0]["dependencies"][0]["id"],
        "Newtonsoft.Json"
    );
    assert!(entry["published"]
        .as_str()
        .is_some_and(|p| p.starts_with("2026-01-01")));
    assert_eq!(mock.nupkg_hits(), 0, "metadata needs no package download");
}
