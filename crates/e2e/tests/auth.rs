//! E2E: authentication / authorization — anonymous modes (off / allowlist /
//! all), allowed vs denied client IP, admin gating + bootstrap, and the
//! scheme-only outbound guard on a proxy upstream URL. Gated behind
//! `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use forge_e2e::{start_stack, AnonMode, StackBuilder};

/// An IP not in the allowlist (used to prove denial).
const DENIED_IP: &str = "198.51.100.7";
/// An IP inside the configured allowlist CIDR.
const ALLOWED_IP: &str = "203.0.113.7";

/// `anonymous_mode = off`: every read of a (even anonymous_read) repo without
/// credentials is 401; with credentials it succeeds.
#[tokio::test]
async fn anon_mode_off_requires_auth() {
    let srv = start_stack().await; // default AnonMode::Off
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    srv.create_repo(
        serde_json::json!({"name": "off-repo", "kind": "hosted", "anonymous_read": true}),
    )
    .await;

    let resp = client
        .get(format!("{}/repository/off-repo/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anon read denied with mode=off");

    let resp = client
        .get(format!("{}/repository/off-repo/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "authenticated read succeeds");
}

/// `anonymous_mode = all`: anonymous reads of an `anonymous_read` repo succeed,
/// but a repo without `anonymous_read` still requires auth.
#[tokio::test]
async fn anon_mode_all_allows_anonymous_read_repos() {
    let srv = StackBuilder::default().anon(AnonMode::All).start().await;
    let client = srv.client();

    srv.create_repo(
        serde_json::json!({"name": "all-pub", "kind": "hosted", "anonymous_read": true}),
    )
    .await;
    srv.grant_anonymous_read("all-pub").await;
    srv.create_repo(
        serde_json::json!({"name": "all-priv", "kind": "hosted", "anonymous_read": false}),
    )
    .await;

    let resp = client
        .get(format!("{}/repository/all-pub/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "anon read of anonymous_read repo");

    let resp = client
        .get(format!("{}/repository/all-priv/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "non-anonymous_read repo still requires auth even with mode=all"
    );
}

/// `anonymous_mode = allowlist`: an anonymous read of an `anonymous_read` repo
/// is permitted from an allowed IP and denied from any other IP. The client IP
/// is taken from `X-Forwarded-For` because the harness trusts loopback.
#[tokio::test]
async fn anon_mode_allowlist_gates_by_ip() {
    let srv = StackBuilder::default()
        .anon(AnonMode::Allowlist(vec!["203.0.113.0/24".into()]))
        .start()
        .await;
    let client = srv.client();

    srv.create_repo(
        serde_json::json!({"name": "al-repo", "kind": "hosted", "anonymous_read": true}),
    )
    .await;
    srv.grant_anonymous_read("al-repo").await;

    // Allowed IP → 200.
    let resp = client
        .get(format!("{}/repository/al-repo/index.json", srv.base_url))
        .header("X-Forwarded-For", ALLOWED_IP)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "anon read from allowlisted IP");

    // Denied IP → 401.
    let resp = client
        .get(format!("{}/repository/al-repo/index.json", srv.base_url))
        .header("X-Forwarded-For", DENIED_IP)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "anon read from non-allowlisted IP denied"
    );
}

/// A malformed `X-Forwarded-For` never makes a client look like the trusted
/// proxy. The harness's peer (loopback) is a trusted proxy and is itself on
/// the allowlist, as an nginx in a private network on an allowlist of
/// `[private]` is. nginx appends the real client to the line the client sent,
/// so an unreadable byte in the client's part must not hide it, and a hop the
/// walk cannot read must not fall back to the proxy's address.
#[tokio::test]
async fn malformed_forwarded_for_is_never_allowlisted_as_the_proxy() {
    let srv = StackBuilder::default()
        .anon(AnonMode::Allowlist(vec!["loopback".into()]))
        .start()
        .await;
    let client = srv.client();
    srv.create_repo(
        serde_json::json!({"name": "xff-repo", "kind": "hosted", "anonymous_read": true}),
    )
    .await;
    srv.grant_anonymous_read("xff-repo").await;
    let url = format!("{}/repository/xff-repo/index.json", srv.base_url);

    // The proxy host itself (no forwarded hop) is allowlisted.
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "request from the allowlisted proxy itself"
    );

    let denied = DENIED_IP.as_bytes();
    for (value, why) in [
        (
            [&b"\xff, "[..], denied].concat(),
            "nginx: unreadable client part",
        ),
        ([denied, &b", \xff"[..]].concat(), "unreadable hop reached"),
        ([denied, &b", "[..]].concat(), "empty hop reached"),
    ] {
        let resp = client
            .get(&url)
            .header(
                "X-Forwarded-For",
                reqwest::header::HeaderValue::from_bytes(&value).unwrap(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "{why}: {value:?}");
    }
}

/// The admin API requires an admin principal; the bootstrap admin works, and a
/// non-admin user is forbidden (403).
#[tokio::test]
async fn admin_api_requires_admin_and_bootstrap_works() {
    let srv = start_stack().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // Bootstrap admin works: list users.
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "bootstrap admin can use the admin API");

    // Unauthenticated admin call → 401.
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "unauthenticated admin call is 401");

    // Create a non-admin user, then assert it is forbidden from the admin API.
    srv.create_user("alice@example.com", "alicepw-e2e-12").await;

    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth("alice@example.com", Some("alicepw-e2e-12"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "non-admin user forbidden from admin API"
    );
}

/// Outbound guard: a proxy `remote_url` is only scheme-checked — a non-http(s)
/// scheme is rejected, while private/loopback addresses are permitted (upstream
/// config is admin-only).
#[tokio::test]
async fn remote_url_scheme_checked_private_allowed() {
    let srv = start_stack().await;

    // A non-http(s) scheme → rejected.
    let resp = srv
        .create_repo(serde_json::json!({
            "name": "scheme-proxy",
            "kind": "proxy",
            "remote_url": "ftp://example.com/index.json",
        }))
        .await;
    assert!(
        resp.status().is_client_error(),
        "non-http scheme must be rejected (got {})",
        resp.status()
    );

    // A loopback upstream is accepted (no allow_private_upstream flag exists
    // anymore — the column and the restriction are gone).
    let resp = srv
        .create_repo(serde_json::json!({
            "name": "loopback-proxy",
            "kind": "proxy",
            "remote_url": "http://127.0.0.1:9/index.json",
        }))
        .await;
    assert!(
        resp.status().is_success(),
        "loopback remote_url must be accepted (got {})",
        resp.status()
    );
}
