//! E2E: the 12.7 auth-realm surface — login options, identifier-first
//! `/auth/identify`, the password `/auth/login` (session mint + cookie),
//! logout, and the `/admin/realms` CRUD with write-only secrets.
//!
//! Requires Docker (Postgres testcontainer) on the host.

mod common;

use serde_json::{json, Value};

/// Extract the `forge_session=...` cookie pair from a login response.
fn session_cookie(resp: &reqwest::Response) -> String {
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .expect("login sets the session cookie")
        .to_str()
        .unwrap();
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("SameSite=Lax"), "{set_cookie}");
    set_cookie.split(';').next().unwrap().to_string()
}

/// Default install: identifier-first mode, password login on (local realm),
/// no OIDC button.
#[tokio::test]
async fn login_options_reflect_default_realms() {
    let srv = common::start().await;
    let resp = srv
        .client()
        .get(format!("{}/auth/login-options", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["mode"], json!("identifier_first"));
    assert_eq!(body["password"], json!(true));
    assert_eq!(body["oidc"], json!([]));
}

/// `/auth/identify` answers `password` for known and unknown identifiers
/// alike (anti-enumeration: the decision is realm config, never user rows).
#[tokio::test]
async fn identify_does_not_reveal_account_existence() {
    let srv = common::start().await;
    let (admin, _) = srv.admin_basic();
    let client = srv.client();

    let mut answers = Vec::new();
    for username in [admin.as_str(), "no-such-user-xyz"] {
        let resp = client
            .post(format!("{}/auth/identify", srv.base_url))
            .json(&json!({ "username": username }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        answers.push(resp.json::<Value>().await.unwrap());
    }
    assert_eq!(
        answers[0], answers[1],
        "identical decision for known/unknown"
    );
    assert_eq!(answers[0]["mode"], json!("password"));
}

/// Password login mints a session: the cookie authenticates `/auth/me`, the
/// CSRF token guards logout, and a wrong password is a uniform 401.
#[tokio::test]
async fn password_login_session_round_trip() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();

    // Wrong password → uniform 401, no cookie.
    let resp = client
        .post(format!("{}/auth/login", srv.base_url))
        .json(&json!({ "username": admin, "password": "wrong" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().get("set-cookie").is_none());

    // Correct password → 200 + cookie + identity body with the CSRF token.
    let resp = client
        .post(format!("{}/auth/login", srv.base_url))
        .json(&json!({ "username": admin, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cookie = session_cookie(&resp);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["username"], json!(admin));
    assert_eq!(body["is_admin"], json!(true));
    let csrf = body["csrf_token"].as_str().expect("csrf token").to_string();

    // The session cookie authenticates /auth/me (no Basic header) …
    let resp = client
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let me: Value = resp.json().await.unwrap();
    assert_eq!(me["username"], json!(admin));

    // … and the admin API too (the principal middleware mounts the session
    // source independent of OIDC since 12.7).
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "session cookie reaches the admin API");

    // Logout requires the CSRF token; after it the session is dead.
    let resp = client
        .post(format!("{}/auth/logout", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "logout without csrf is refused");
    let resp = client
        .post(format!("{}/auth/logout", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "revoked session no longer authenticates"
    );
}

/// `/admin/realms` CRUD: the seeded local realm is listed and protected,
/// secrets are write-only (redacted to `<key>_set` markers), invalid configs
/// are 400, and reorder demands the complete id set.
#[tokio::test]
async fn admin_realm_crud_with_write_only_secrets() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let name = format!("nexus{}", common::unique());

    // Unauthenticated → 401.
    let resp = client
        .get(format!("{}/admin/realms", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Seeded local realm present.
    let resp = client
        .get(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let realms: Vec<Value> = resp.json().await.unwrap();
    let local = realms
        .iter()
        .find(|r| r["kind"] == json!("local"))
        .expect("seeded local realm");
    let local_id = local["id"].as_i64().unwrap();

    // Missing key_pepper → 400 with a message.
    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "credential_forwarding",
            "name": name,
            "config": { "url": "https://nexus.internal/status" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Valid create → 201; the secret comes back redacted.
    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "credential_forwarding",
            "name": name,
            "config": { "url": "https://nexus.internal/status", "key_pepper": "s3cret" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: Value = resp.json().await.unwrap();
    let realm_id = created["id"].as_i64().unwrap();
    assert!(
        created["config"].get("key_pepper").is_none(),
        "secret redacted"
    );
    assert_eq!(created["config"]["key_pepper_set"], json!(true));

    // Update without the secret keeps it stored (marker stays true).
    let resp = client
        .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "config": { "url": "https://nexus2.internal/status", "key_pepper": "" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: Value = resp.json().await.unwrap();
    assert_eq!(
        updated["config"]["url"],
        json!("https://nexus2.internal/status")
    );
    assert_eq!(updated["config"]["key_pepper_set"], json!(true));

    // The local realm cannot be deleted.
    let resp = client
        .delete(format!("{}/admin/realms/{local_id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Reorder must list every realm id exactly once.
    let resp = client
        .put(format!("{}/admin/realms/order", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "order": [realm_id] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "partial order rejected");

    // Full reorder: promote the new realm above local.
    let resp = client
        .get(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    let realms: Vec<Value> = resp.json().await.unwrap();
    let mut order: Vec<i64> = realms.iter().map(|r| r["id"].as_i64().unwrap()).collect();
    order.retain(|id| *id != realm_id);
    order.insert(0, realm_id);
    let resp = client
        .put(format!("{}/admin/realms/order", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "order": order }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let reordered: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(reordered[0]["id"].as_i64().unwrap(), realm_id);

    // Cleanup: delete the test realm.
    let resp = client
        .delete(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}
