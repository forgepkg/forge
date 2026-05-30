//! E2E: admin API gating, bootstrap admin, repository/user/token/member CRUD,
//! password redaction, SSRF rejection, nested-group + duplicate-priority
//! rejection (plan 10.4). Requires Docker (Postgres + versitygw).

mod common;

use serde_json::{json, Value};

/// The bootstrap admin can authenticate (basic) and list repositories; the
/// admin API requires admin (anonymous → 401).
#[tokio::test]
async fn bootstrap_admin_and_gating() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // No credentials → 401.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anonymous admin call must be 401");

    // Bootstrap admin via basic auth → 200.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin basic auth must succeed");
    let repos: Value = resp.json().await.unwrap();
    // Shared test DB: just assert a well-formed array (other parallel tests may
    // have created repos).
    assert!(repos.is_array(), "repositories list must be a JSON array");
}

/// A non-admin user is forbidden (403) from the admin API.
#[tokio::test]
async fn non_admin_forbidden() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let suffix = common::unique();
    let username = format!("plain{suffix}");

    // Admin creates a non-admin user.
    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": username, "password": "pw123456", "is_admin": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // That user authenticates (password basic) but is forbidden from admin.
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&username, Some("pw123456"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin must be 403");
}

/// Create a proxy repository; `upstream_password` is accepted but REDACTED in
/// all responses (write-only).
#[tokio::test]
async fn proxy_password_is_write_only_and_redacted() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let name = format!("proxy{}", common::unique());

    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": "https://api.nuget.org/v3/index.json",
            "upstream_username": "svc",
            "upstream_password": "s3cret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "proxy create should succeed");
    let body: Value = resp.json().await.unwrap();
    // No password field anywhere; only a boolean flag.
    assert_eq!(body["has_upstream_password"], json!(true));
    assert!(body.get("upstream_password").is_none());
    assert_eq!(body["upstream_username"], json!("svc"));

    // GET also redacts.
    let resp = client
        .get(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("upstream_password").is_none());
    assert_eq!(body["has_upstream_password"], json!(true));
}

/// Creating a proxy whose `remote_url` resolves to a private address is
/// rejected by the SSRF guard (400) by default.
#[tokio::test]
async fn ssrf_private_remote_url_rejected() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let name = format!("ssrf{}", common::unique());

    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": "http://127.0.0.1:6379/index.json",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "private remote_url must be rejected");
}

/// Token issue returns the plaintext **once**; the issued token then
/// authenticates against the admin API; revoke disables it.
#[tokio::test]
async fn token_issue_use_and_revoke() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // Find the admin user's id.
    let users: Value = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["username"] == json!(u))
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    // Issue a token.
    let resp = client
        .post(format!("{}/admin/users/{admin_id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "ci"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    let token_id = body["id"].as_i64().unwrap();
    assert!(!token.is_empty());

    // The token authenticates via the X-NuGet-ApiKey header on the admin API.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "issued token should authenticate");

    // Revoke it.
    let resp = client
        .delete(format!("{}/admin/tokens/{token_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Now the token is rejected (present-but-invalid → 401).
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "revoked token must be rejected");
}

/// Group membership: nested-group members and duplicate priorities are
/// rejected; a hosted member is accepted.
#[tokio::test]
async fn group_member_validation() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let group = format!("grp{s}");
    let group2 = format!("grp2_{s}");
    let hosted = format!("host{s}");

    let create = |name: &str, kind: &str| {
        let url = format!("{}/admin/repositories", srv.base_url);
        let (u, p) = (u.clone(), p.clone());
        let body = json!({"name": name, "kind": kind});
        let client = client.clone();
        async move {
            client
                .post(url)
                .basic_auth(&u, Some(&p))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    assert_eq!(create(&group, "group").await, 201);
    assert_eq!(create(&group2, "group").await, 201);
    assert_eq!(create(&hosted, "hosted").await, 201);

    let add = |member: &str, priority: i32| {
        let url = format!("{}/admin/repositories/{group}/members", srv.base_url);
        let (u, p) = (u.clone(), p.clone());
        let body = json!({"member": member, "priority": priority});
        let client = client.clone();
        async move {
            client
                .post(url)
                .basic_auth(&u, Some(&p))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    // Hosted member at priority 10 → created.
    assert_eq!(add(&hosted, 10).await, 201);
    // Nested group member → 400.
    assert_eq!(add(&group2, 20).await, 400, "nested group must be rejected");
    // Duplicate priority → 409.
    assert_eq!(
        add(&hosted, 10).await,
        409,
        "duplicate priority/member must be rejected"
    );
}
