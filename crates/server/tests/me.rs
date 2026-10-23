//! E2E: `GET /admin/me` identity + capabilities.
//!
//! Verifies the endpoint is reachable by *any* authenticated user (not only
//! admins — it lives outside the admin `require_admin` gate), returns the right
//! `is_admin` flag + capability list, and rejects unauthenticated / anonymous
//! callers with 401.

mod common;

use serde_json::{json, Value};

/// The bootstrap admin sees `is_admin: true` and the admin capability set.
#[tokio::test]
async fn me_returns_admin_identity() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();

    let resp = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    assert_eq!(body["user"]["username"], json!(u));
    assert_eq!(body["user"]["is_admin"], json!(true));
    assert_eq!(body["user"]["active"], json!(true));
    assert_eq!(body["is_admin"], json!(true));
    let caps: Vec<String> = body["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert!(caps.contains(&"repo.read".to_string()));
    assert!(caps.contains(&"repo.admin".to_string()));
}

/// A non-admin user can call `/admin/me` (it is NOT admin-gated) and sees
/// `is_admin: false` with only the reader capability.
#[tokio::test]
async fn me_reachable_by_non_admin() {
    let srv = common::start().await;
    let client = srv.client();
    let username = format!("plain{}@example.com", common::unique());

    srv.create_user(&username, "pw123456-me12", "reader").await;

    // The non-admin is forbidden from the admin API but CAN read /admin/me.
    let resp = client
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&username, Some("pw123456-me12"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "non-admin may read /admin/me");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["is_admin"], json!(false));
    let caps: Vec<String> = body["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(caps, vec!["repo.read".to_string()]);

    // Sanity: the same user is still 403 on the admin API.
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&username, Some("pw123456-me12"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

/// `/admin/me` reports the **effective** RBAC verdict: a user created as a
/// non-admin and given the built-in `admin` role afterwards is an admin to
/// the SPA too (the admin API already treats it as one).
#[tokio::test]
async fn me_reflects_the_admin_role() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let username = format!("rbacadmin{}@example.com", common::unique());

    let id = srv.create_user(&username, "pw123456-me12", "reader").await;
    let resp = client
        .put(format!("{}/admin/users/{id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role": "admin"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "assign admin role");

    let body: Value = client
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&username, Some("pw123456-me12"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["is_admin"], json!(true), "admin role ⇒ admin");
    assert!(body["capabilities"]
        .as_array()
        .unwrap()
        .contains(&json!("user.admin")));
}

/// #318: a holder of the built-in `writer` role may publish to every
/// repository, which `/admin/me` reports as `repo.write` (no admin
/// capability), so the SPA can show push instructions.
#[tokio::test]
async fn me_shows_repo_write_to_a_writer() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let username = format!("writer{}@example.com", common::unique());

    let id = srv.create_user(&username, "pw123456-me12", "reader").await;
    let resp = client
        .put(format!("{}/admin/users/{id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role": "writer"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "assign writer role");

    let body: Value = client
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&username, Some("pw123456-me12"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["is_admin"], json!(false));
    assert_eq!(body["capabilities"], json!(["repo.read", "repo.write"]));
}

/// An unauthenticated caller (no credentials, anon mode off) gets 401.
#[tokio::test]
async fn me_unauthenticated_is_401() {
    let srv = common::start().await;
    let resp = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// An anonymous caller (anon mode all) is still not a *user*, so `/admin/me`
/// returns 401 — the SPA treats this as "no session".
#[tokio::test]
async fn me_anonymous_is_401() {
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            anonymous_mode: "all".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            ..Default::default()
        },
    )
    .await;
    let resp = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "anonymous principal is not a user session"
    );
}

/// A token authenticates `/admin/me` (X-NuGet-ApiKey path). The reported
/// capabilities are the *token's*: an admin's unscoped token is not an admin
/// credential (B4), so `is_admin` is `false` for it and `true` only for a token
/// whose scope names `admin`.
#[tokio::test]
async fn me_with_token() {
    let srv = common::start().await;
    let token = srv.admin_token().await;
    let resp = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["user"]["username"], json!(srv.admin_basic().0));
    assert_eq!(
        body["is_admin"],
        json!(false),
        "unscoped token is not admin"
    );

    // An explicitly admin-scoped token reports admin.
    let (u, p) = srv.admin_basic();
    let admin_id = body["user"]["id"].as_i64().expect("user id");
    let created: Value = srv
        .client()
        .post(format!("{}/admin/users/{admin_id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "automation", "scope": {"actions": ["admin"]}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .header("X-NuGet-ApiKey", created["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["is_admin"], json!(true), "admin-scoped token is admin");
}
