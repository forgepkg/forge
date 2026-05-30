//! E2E: authentication / authorization — anonymous modes (off / allowlist /
//! all), allowed vs denied client IP, admin gating + bootstrap, and SSRF
//! rejection of a private upstream (spec §9). Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use forge_e2e::{start_stack, AnonMode, StackBuilder};
use serde_json::Value;

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
        .get(format!("{}/v3/off-repo/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anon read denied with mode=off");

    let resp = client
        .get(format!("{}/v3/off-repo/index.json", srv.base_url))
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
    srv.create_repo(
        serde_json::json!({"name": "all-priv", "kind": "hosted", "anonymous_read": false}),
    )
    .await;

    let resp = client
        .get(format!("{}/v3/all-pub/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "anon read of anonymous_read repo");

    let resp = client
        .get(format!("{}/v3/all-priv/index.json", srv.base_url))
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

    // Allowed IP → 200.
    let resp = client
        .get(format!("{}/v3/al-repo/index.json", srv.base_url))
        .header("X-Forwarded-For", ALLOWED_IP)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "anon read from allowlisted IP");

    // Denied IP → 401.
    let resp = client
        .get(format!("{}/v3/al-repo/index.json", srv.base_url))
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
    let body: Value = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"username": "alice", "password": "alicepw", "is_admin": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["username"], serde_json::json!("alice"));

    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth("alice", Some("alicepw"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "non-admin user forbidden from admin API"
    );
}

/// SSRF: creating a proxy whose `remote_url` resolves to a private/loopback
/// address is rejected by default (no `allow_private_upstream`).
#[tokio::test]
async fn ssrf_private_upstream_rejected_by_default() {
    let srv = start_stack().await;

    // Loopback upstream without allow_private_upstream → rejected.
    let resp = srv
        .create_repo(serde_json::json!({
            "name": "ssrf-proxy",
            "kind": "proxy",
            "remote_url": "http://127.0.0.1:9/index.json",
        }))
        .await;
    assert!(
        resp.status().is_client_error(),
        "private remote_url must be rejected (got {})",
        resp.status()
    );

    // A link-local / cloud-metadata address is also rejected.
    let resp = srv
        .create_repo(serde_json::json!({
            "name": "ssrf-meta",
            "kind": "proxy",
            "remote_url": "http://169.254.169.254/latest/meta-data/",
        }))
        .await;
    assert!(
        resp.status().is_client_error(),
        "cloud-metadata remote_url must be rejected (got {})",
        resp.status()
    );
}
