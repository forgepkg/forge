//! The sign-in and anonymous-access policy (#294): `GET`/`PUT
//! /admin/settings/auth`, applied without a restart, and by every instance
//! within the cache TTL. Requires Docker. Each test has a database of its
//! own: the settings are install-wide.

mod common;

use std::time::{Duration, Instant};

use common::{ServerOpts, TestServer};
use serde_json::{json, Value};

/// A server on a database of its own.
async fn start(opts: ServerOpts) -> TestServer {
    common::start_with(
        common::fresh_pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            ..opts
        },
    )
    .await
}

/// `PUT /admin/settings/auth` as the admin.
async fn put_settings(srv: &TestServer, body: Value) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    srv.client()
        .put(format!("{}/admin/settings/auth", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// `GET /admin/settings/auth` as the admin.
async fn get_settings(srv: &TestServer) -> Value {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}/admin/settings/auth", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

/// Create a hosted repository as the admin.
async fn create_repo(srv: &TestServer, anonymous_read: bool) -> String {
    let (u, p) = srv.admin_basic();
    let name = format!("set{}", common::unique());
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": name, "kind": "hosted", "anonymous_read": anonymous_read}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    name
}

/// A user without any grant, with a password.
async fn make_user(srv: &TestServer) -> (i64, String, String) {
    let username = format!("plain{}@example.com", common::unique());
    let password = "pw123456-plain".to_string();
    let id = srv.create_user(&username, &password, "reader").await;
    (id, username, password)
}

/// The status of reading `repo`'s service index, with `basic` credentials
/// or none.
async fn read_index(srv: &TestServer, repo: &str, basic: Option<(&str, &str)>) -> u16 {
    let mut req = srv
        .client()
        .get(format!("{}/repository/{repo}/index.json", srv.base_url));
    if let Some((u, p)) = basic {
        req = req.basic_auth(u, Some(p));
    }
    req.send().await.unwrap().status().as_u16()
}

/// The login screen's mode (`GET /auth/login-options`).
async fn login_mode(srv: &TestServer) -> String {
    let options: Value = srv
        .client()
        .get(format!("{}/auth/login-options", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    options["mode"].as_str().expect("mode").to_string()
}

/// Admins read and change the settings; a change names only what it changes,
/// and a wrong value is refused with what is wrong, leaving the stored ones
/// alone.
#[tokio::test]
async fn admins_read_and_change_the_settings_and_wrong_values_are_refused() {
    let srv = start(ServerOpts::default()).await;
    // The harness's database starts with password Basic on, the rest at
    // the defaults.
    assert_eq!(
        get_settings(&srv).await,
        json!({
            "anonymous_mode": "off",
            "login_mode": "identifier_first",
            "allow_password_basic": true,
            "session_idle_ttl_seconds": 28800,
            "session_absolute_ttl_seconds": 604800,
            "login_max_failures": 10,
            "login_failure_window_seconds": 300,
        })
    );

    // Admin only.
    let url = format!("{}/admin/settings/auth", srv.base_url);
    let resp = srv.client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let (_, username, password) = make_user(&srv).await;
    let session = srv.login(&username, &password).await;
    let resp = session.apply(srv.client().get(&url)).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let resp = session
        .apply(srv.client().put(&url))
        .json(&json!({"anonymous_mode": "all"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    assert_eq!(login_mode(&srv).await, "identifier_first");
    let resp = put_settings(&srv, json!({"login_mode": "combined"})).await;
    assert_eq!(resp.status(), 200);
    let saved: Value = resp.json().await.unwrap();
    assert_eq!(saved["login_mode"], "combined");
    assert_eq!(saved["allow_password_basic"], true, "left out, kept");
    assert_eq!(get_settings(&srv).await, saved);
    assert_eq!(login_mode(&srv).await, "combined", "applied at once");

    for (body, message) in [
        (
            json!({"anonymous_mode": "allowlist"}),
            "unknown anonymous_mode \"allowlist\" (expected off|all)",
        ),
        (
            json!({"login_mode": "both"}),
            "unknown login_mode \"both\" (expected identifier_first|combined)",
        ),
        (
            json!({"session_idle_ttl_seconds": 0}),
            "session_idle_ttl_seconds must be between 1 and 315360000 (10 years), got 0",
        ),
        (
            json!({"session_absolute_ttl_seconds": 315360001u64}),
            "session_absolute_ttl_seconds must be between 1 and 315360000 (10 years), got 315360001",
        ),
        (
            json!({"login_failure_window_seconds": 0}),
            "login_failure_window_seconds must be between 1 and 86400 (a day), got 0",
        ),
    ] {
        let resp = put_settings(&srv, body.clone()).await;
        assert_eq!(resp.status(), 400, "{body}");
        assert_eq!(resp.text().await.unwrap(), message, "{body}");
    }
    // An unknown field is refused, not dropped.
    for body in [
        json!({"anonymous": "all"}),
        json!({"anonymous_ip_allowlist": ["10.0.0.0/8"]}),
    ] {
        let resp = put_settings(&srv, body.clone()).await;
        assert_eq!(resp.status(), 422, "{body}");
    }
    assert_eq!(
        get_settings(&srv).await,
        saved,
        "nothing refused was stored"
    );
}

/// The anonymous mode decides who reads an `anonymous_read` repository
/// without credentials, at once: off, and all (signed-in users then read it
/// too).
#[tokio::test]
async fn anonymous_access_follows_the_setting_without_a_restart() {
    let srv = start(ServerOpts::default()).await;
    let public = create_repo(&srv, true).await;
    let private = create_repo(&srv, false).await;
    let (_, username, password) = make_user(&srv).await;
    let user = Some((username.as_str(), password.as_str()));

    assert_eq!(read_index(&srv, &public, None).await, 401);
    assert_eq!(read_index(&srv, &public, user).await, 403);

    assert_eq!(
        put_settings(&srv, json!({"anonymous_mode": "all"}))
            .await
            .status(),
        200
    );
    assert_eq!(read_index(&srv, &public, None).await, 200);
    assert_eq!(read_index(&srv, &private, None).await, 401);
    // A signed-in user without grants reads what anyone may.
    assert_eq!(read_index(&srv, &public, user).await, 200);
    assert_eq!(read_index(&srv, &private, user).await, 403);

    put_settings(&srv, json!({"anonymous_mode": "off"})).await;
    assert_eq!(read_index(&srv, &public, None).await, 401);
    // Off again, the public reach is gone for signed-in users too.
    assert_eq!(read_index(&srv, &public, user).await, 403);
}

/// Password Basic, the session lifetimes and the lockout apply to the next
/// request after a change.
#[tokio::test]
async fn password_basic_sessions_and_lockout_follow_the_settings() {
    let srv = start(ServerOpts::default()).await;
    let private = create_repo(&srv, false).await;
    let (admin, admin_password) = srv.admin_password_basic();
    let (_, admin_token) = srv.admin_basic();

    // Password Basic: on in the harness, then off. A token keeps working.
    assert_eq!(
        read_index(&srv, &private, Some((&admin, &admin_password))).await,
        200
    );
    put_settings(&srv, json!({"allow_password_basic": false})).await;
    assert_eq!(
        read_index(&srv, &private, Some((&admin, &admin_password))).await,
        401
    );
    assert_eq!(
        read_index(&srv, &private, Some((&admin, &admin_token))).await,
        200
    );

    // Session lifetimes: a sign-in after the change gets them.
    put_settings(
        &srv,
        json!({"session_idle_ttl_seconds": 600, "session_absolute_ttl_seconds": 3600}),
    )
    .await;
    let (user_id, username, password) = make_user(&srv).await;
    let resp = srv
        .client()
        .post(format!("{}/auth/login", srv.base_url))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cookie = resp.headers()["set-cookie"].to_str().unwrap().to_string();
    let max_age: i64 = cookie
        .split("; ")
        .find_map(|attr| attr.strip_prefix("Max-Age="))
        .expect("Max-Age")
        .parse()
        .unwrap();
    assert!((3590..=3600).contains(&max_age), "{cookie}");
    let (idle, absolute): (f64, f64) = sqlx::query_as(
        "SELECT EXTRACT(EPOCH FROM idle_expiry - created_at)::float8, \
                EXTRACT(EPOCH FROM absolute_expiry - created_at)::float8 \
         FROM session WHERE user_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!((idle.round(), absolute.round()), (600.0, 3600.0));

    // The lockout: two failures, then 429 for the window.
    put_settings(
        &srv,
        json!({"login_max_failures": 2, "login_failure_window_seconds": 120}),
    )
    .await;
    let login = |password: &'static str| {
        srv.client()
            .post(format!("{}/auth/login", srv.base_url))
            .json(&json!({"username": username, "password": password}))
            .send()
    };
    for _ in 0..2 {
        assert_eq!(login("wrong").await.unwrap().status(), 401);
    }
    let resp = login("wrong").await.unwrap();
    assert_eq!(resp.status(), 429);
    assert_eq!(resp.headers()["retry-after"], "120");
    // Turning the lockout off lets the right password in again.
    put_settings(&srv, json!({"login_max_failures": 0})).await;
    assert_eq!(login("pw123456-plain").await.unwrap().status(), 200);
}

/// A change on one instance reaches another within its cache TTL, without a
/// restart.
#[tokio::test]
async fn other_instances_follow_a_change_within_the_cache_ttl() {
    let pool = common::fresh_pool().await;
    let opts = || ServerOpts {
        bootstrap_admin: Some(("admin@example.com".into(), "adminpw".into())),
        auth_extra: Some("realm_cache_ttl_seconds = 1".into()),
        ..Default::default()
    };
    let a = common::start_with(pool.clone(), opts()).await;
    let b = common::start_with(pool, opts()).await;
    let public = create_repo(&a, true).await;
    // Both instances hold the current settings.
    assert_eq!(read_index(&a, &public, None).await, 401);
    assert_eq!(read_index(&b, &public, None).await, 401);
    assert_eq!(login_mode(&b).await, "identifier_first");

    put_settings(
        &a,
        json!({"anonymous_mode": "all", "login_mode": "combined"}),
    )
    .await;
    assert_eq!(read_index(&a, &public, None).await, 200, "at once here");
    let deadline = Instant::now() + Duration::from_secs(10);
    while read_index(&b, &public, None).await != 200 {
        assert!(
            Instant::now() < deadline,
            "the other instance never followed"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(login_mode(&b).await, "combined");
}
