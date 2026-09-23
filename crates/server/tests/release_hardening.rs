//! E2E regressions for the 0.1.0 release blockers:
//! * a dead session cookie never locks the browser out (login, pages) and is
//!   cleared on the response;
//! * a cross-site browser mutation is refused even with cached Basic
//!   credentials (which the CSRF token does not cover);
//! * removing the built-in `admin` role actually revokes admin, including for
//!   users that also carry the legacy `is_admin` flag;
//! * a deleted bootstrap admin is not re-created on restart.
//!
//! Requires Postgres + an S3 gateway (testcontainers, or the
//! `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT` overrides).

mod common;

use serde_json::{json, Value};

async fn login(srv: &common::TestServer, username: &str, password: &str) -> reqwest::Response {
    srv.client()
        .post(format!("{}/auth/login", srv.base_url))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .unwrap()
}

fn cookie_pair(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("set-cookie")
        .expect("set-cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn clears_session_cookie(resp: &reqwest::Response) -> bool {
    resp.headers().get_all("set-cookie").iter().any(|v| {
        let v = v.to_str().unwrap_or_default();
        v.starts_with("forge_session=;") && v.contains("Max-Age=0")
    })
}

#[tokio::test]
async fn dead_session_cookie_does_not_lock_out_login_and_is_cleared() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();

    // Log in, then revoke the session server-side (the same end state as an
    // idle-expired one) by logging out.
    let resp = login(&srv, &admin, &password).await;
    assert_eq!(resp.status(), 200);
    let cookie = cookie_pair(&resp);
    let me: Value = client
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf = me["csrf_token"].as_str().unwrap().to_string();
    let resp = client
        .post(format!("{}/auth/logout", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The browser still sends the dead cookie (and a forged one). Public
    // pages answer normally and the cookie is cleared…
    for stale in [cookie.clone(), "forge_session=never-issued".to_string()] {
        let resp = client
            .get(format!("{}/auth/login-options", srv.base_url))
            .header("cookie", &stale)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "login options reachable with {stale}");
        assert!(clears_session_cookie(&resp), "dead cookie cleared");
    }

    // …protected APIs treat it as signed out, not as bad credentials on every
    // route…
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // …and signing in again works while the dead cookie rides along.
    let resp = client
        .post(format!("{}/auth/login", srv.base_url))
        .header("cookie", &cookie)
        .json(&json!({ "username": admin, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "login is not blocked by a stale cookie");
    let fresh = cookie_pair(&resp);
    assert_ne!(fresh, cookie);
    assert_ne!(
        fresh, "forge_session=",
        "the fresh cookie is not the clearing one"
    );
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .header("cookie", &fresh)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "fresh session works");
}

#[tokio::test]
async fn cross_site_browser_mutations_are_refused_even_with_basic() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();

    for (header, value) in [
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://attacker.example"),
    ] {
        let resp = client
            .post(format!("{}/admin/roles", srv.base_url))
            .basic_auth(&admin, Some(&password))
            .header(header, value)
            .json(&json!({ "name": format!("xs{}", common::unique()), "description": "" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{header}: {value}");
    }

    // Non-browser clients (no fetch metadata) and same-origin requests pass.
    for extra in [None, Some(("sec-fetch-site", "same-origin"))] {
        let mut req = client
            .post(format!("{}/admin/roles", srv.base_url))
            .basic_auth(&admin, Some(&password))
            .json(&json!({ "name": format!("ok{}", common::unique()), "description": "" }));
        if let Some((h, v)) = extra {
            req = req.header(h, v);
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), 201, "{extra:?}");
    }
}

#[tokio::test]
async fn removing_the_admin_role_revokes_admin() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();

    // A user created as admin holds the role and the legacy flag.
    let username = format!("second-admin{}", common::unique());
    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "username": username, "password": "pw-second", "is_admin": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let user: Value = resp.json().await.unwrap();
    let user_id = user["id"].as_i64().unwrap();

    let roles: Vec<Value> = client
        .get(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_role = roles
        .iter()
        .find(|r| r["name"] == json!("admin"))
        .expect("admin created via the API holds the admin role");
    let admin_role_id = admin_role["id"].as_i64().unwrap();

    let as_user = |path: &str| {
        client
            .get(format!("{}{path}", srv.base_url))
            .basic_auth(&username, Some("pw-second"))
            .send()
    };
    assert_eq!(as_user("/admin/users").await.unwrap().status(), 200);

    let resp = client
        .delete(format!(
            "{}/admin/users/{user_id}/roles/{admin_role_id}",
            srv.base_url
        ))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    assert_eq!(
        as_user("/admin/users").await.unwrap().status(),
        403,
        "admin rights are gone once the admin role is removed"
    );
    let flag = forge_db::user_dao::find_user_by_id(&srv.pool, user_id)
        .await
        .unwrap()
        .unwrap()
        .is_admin;
    assert!(!flag, "legacy is_admin flag cleared with the role");

    // Re-assigning the role restores admin (and the flag stays in step).
    let resp = client
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(as_user("/admin/users").await.unwrap().status(), 200);
}

#[tokio::test]
async fn deleted_bootstrap_admin_is_not_recreated_on_restart() {
    let name = format!("boot{}", common::unique());
    let opts = || common::ServerOpts {
        bootstrap_admin: Some((name.clone(), "bootpw".into())),
        ..Default::default()
    };
    let pool = common::pool().await;
    let srv = common::start_with(pool.clone(), opts()).await;
    let user = forge_db::user_dao::find_user_by_username(&pool, &name)
        .await
        .unwrap()
        .expect("bootstrap admin created on first start");
    assert!(forge_db::user_dao::delete_user(&pool, user.id)
        .await
        .unwrap());
    drop(srv);

    let _restarted = common::start_with(pool.clone(), opts()).await;
    assert!(
        forge_db::user_dao::find_user_by_username(&pool, &name)
            .await
            .unwrap()
            .is_none(),
        "a deleted bootstrap admin stays deleted"
    );
}

#[tokio::test]
async fn responses_carry_browser_hardening_headers_and_version_is_exposed() {
    let srv = common::start().await;
    let resp = srv
        .client()
        .get(format!("{}/version", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("content-security-policy", "frame-ancestors 'none'"),
        ("referrer-policy", "same-origin"),
    ] {
        assert_eq!(
            resp.headers().get(name).and_then(|v| v.to_str().ok()),
            Some(value),
            "{name}"
        );
    }
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["version"], json!(env!("CARGO_PKG_VERSION")));
}

#[tokio::test]
async fn repository_formats_other_than_nuget_are_rejected() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "name": format!("npm{}", common::unique()), "kind": "hosted", "format": "npm" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
