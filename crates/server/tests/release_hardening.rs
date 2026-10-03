//! E2E regressions for the 0.1.0 release blockers:
//! * a dead session cookie never locks the browser out (login, pages) and is
//!   cleared on the response;
//! * a cross-site browser mutation is refused even with cached Basic
//!   credentials (which the CSRF token does not cover);
//! * removing the built-in `admin` role actually revokes admin, including for
//!   users that also carry the legacy `is_admin` flag;
//! * a deleted bootstrap admin is not re-created on restart — including one
//!   whose account existed before the "created once" marker was recorded;
//! * an existing bootstrap account still using the placeholder password is
//!   detected at boot;
//! * a bootstrap-admin block without a password starts the server with no
//!   bootstrap admin (review M15: the documented "remove the password" step).
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
    let (admin, password) = srv.admin_password_basic();
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
        .json(&json!({ "username": admin, "password": srv.admin_pass.as_deref().unwrap() }))
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
async fn duplicate_session_cookies_authenticate_nothing() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_password_basic();
    let client = srv.client();
    let mine = cookie_pair(&login(&srv, &admin, &password).await);
    // A second, equally valid session stands in for one planted by a sibling
    // subdomain or for a narrower path (cookie tossing).
    let planted = cookie_pair(&login(&srv, &admin, &password).await);
    assert_ne!(mine, planted);

    let me = |cookie: String| {
        let req = client
            .get(format!("{}/admin/users", srv.base_url))
            .header("cookie", cookie);
        async move { req.send().await.unwrap() }
    };
    assert_eq!(me(mine.clone()).await.status(), 200);
    for both in [
        format!("{mine}; {planted}"),
        format!("{planted}; {mine}"),
        format!("{mine}; {mine}"),
    ] {
        let resp = me(both.clone()).await;
        assert_eq!(resp.status(), 401, "{both}");
        // Neither cookie is cleared: that would drop the browser's own
        // session and leave only the planted one.
        assert!(!clears_session_cookie(&resp));
    }
    let resp = client
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", format!("{mine}; {planted}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "/auth/me refuses an ambiguous session");
}

#[tokio::test]
async fn https_deployments_use_host_prefixed_cookies() {
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            public_base_url: Some("https://forge.example".into()),
            ..Default::default()
        },
    )
    .await;
    let (admin, password) = srv.admin_password_basic();
    let resp = login(&srv, &admin, &password).await;
    assert_eq!(resp.status(), 200);
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        set_cookie.starts_with("__Host-forge_session=")
            && set_cookie.contains("; Secure")
            && set_cookie.contains("Path=/;")
            && !set_cookie.contains("Domain"),
        "{set_cookie}"
    );
    let pair = cookie_pair(&resp);
    let secret = pair.split_once('=').unwrap().1;

    let status = |cookie: String| {
        let req = srv
            .client()
            .get(format!("{}/admin/users", srv.base_url))
            .header("cookie", cookie);
        async move { req.send().await.unwrap().status() }
    };
    assert_eq!(status(pair.clone()).await, 200);
    // The unprefixed name — which any sibling subdomain could set — is not a
    // session cookie on an https deployment.
    assert_eq!(status(format!("forge_session={secret}")).await, 401);
}

/// API responses and credentialed feed responses are never stored by a
/// cache; feed responses say what they vary on; and a plain-http deployment
/// sends no HSTS.
#[tokio::test]
async fn api_and_credentialed_feed_responses_are_not_cached() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("cache{}", common::unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert_eq!(
        resp.headers()["cache-control"],
        "private, no-store",
        "admin API"
    );
    let header = |resp: &reqwest::Response, name: &str| {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };

    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        header(&resp, "cache-control").as_deref(),
        Some("private, no-store")
    );
    let vary = header(&resp, "vary").unwrap_or_default();
    for name in ["Authorization", "Cookie", "X-NuGet-ApiKey"] {
        assert!(vary.contains(name), "Vary {vary:?} lacks {name}");
    }
    assert!(header(&resp, "strict-transport-security").is_none());

    // Without credentials the feed answer may be cached, but only per Vary.
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert!(header(&resp, "cache-control").is_none());
    assert!(header(&resp, "vary").is_some_and(|v| v.contains("Authorization")));

    let resp = client
        .get(format!("{}/auth/login-options", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        header(&resp, "cache-control").as_deref(),
        Some("private, no-store")
    );
}

#[tokio::test]
async fn https_deployments_send_hsts() {
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            public_base_url: Some("https://forge.example".into()),
            ..Default::default()
        },
    )
    .await;
    let resp = srv
        .client()
        .get(format!("{}/auth/login-options", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers()
            .get("strict-transport-security")
            .map(|v| v.to_str().unwrap()),
        Some("max-age=31536000")
    );
}

/// A client trickling its request headers, or stalling its request body, is
/// cut off instead of holding a connection and a task open forever.
#[tokio::test]
async fn slow_headers_and_stalled_bodies_are_cut_off() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            server_extra: Some(
                "header_read_timeout_seconds = 1\nbody_idle_timeout_seconds = 1".into(),
            ),
            ..Default::default()
        },
    )
    .await;
    let addr = srv.base_url.trim_start_matches("http://").to_string();
    for (what, request) in [
        (
            "slow headers",
            "GET /health HTTP/1.1\r\nHost: x\r\n".to_string(),
        ),
        (
            "stalled body",
            "POST /auth/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
             Content-Length: 100\r\n\r\n{\"username\":"
                .to_string(),
        ),
    ] {
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let ended = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut buf),
        )
        .await;
        assert!(ended.is_ok(), "{what}: the server kept the request open");
    }
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

    let session = srv.login(&username, "pw-second").await;
    let as_user = |path: &str| {
        session
            .apply(client.get(format!("{}{path}", srv.base_url)))
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

/// Review L7(a): when the bootstrap username already exists at boot (an
/// install that predates the marker, or a boot that crashed between creating
/// the account and recording the marker), the marker is recorded then — so
/// deleting the account afterwards still sticks across restarts.
#[tokio::test]
async fn bootstrap_marker_is_recorded_for_a_preexisting_account() {
    let name = format!("bootpre{}", common::unique());
    let pool = common::pool().await;
    // The account exists, but no marker was ever written for it.
    let user = forge_db::user_dao::insert_user(
        &pool,
        forge_db::user_dao::NewUser::local(name.clone(), "$argon2id$unused".into(), true, true),
    )
    .await
    .unwrap();
    let marker = format!("{}:{name}", forge_server::app::BOOTSTRAP_ADMIN_CREATED_KEY);
    assert!(forge_db::authz_dao::get_setting(&pool, &marker)
        .await
        .unwrap()
        .is_none());

    let opts = || common::ServerOpts {
        bootstrap_admin: Some((name.clone(), "bootpw".into())),
        ..Default::default()
    };
    let srv = common::start_with(pool.clone(), opts()).await;
    assert_eq!(
        forge_db::authz_dao::get_setting(&pool, &marker)
            .await
            .unwrap(),
        Some(user.id.to_string()),
        "boot records the marker for an existing bootstrap account"
    );
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
        "the deleted pre-marker bootstrap admin stays deleted"
    );
}

/// Review L7(a): boot detects an existing bootstrap account that still
/// accepts the shipped placeholder password (it logs a loud warning; startup
/// is not refused since there is no password-change flow).
#[tokio::test]
async fn placeholder_bootstrap_password_is_detected() {
    use argon2::PasswordHasher;
    let hash = |pw: &str| {
        argon2::Argon2::default()
            .hash_password(pw.as_bytes())
            .unwrap()
            .to_string()
    };
    let user = |password_hash: Option<String>| forge_db::model::AppUser {
        id: 1,
        username: "admin".into(),
        password_hash,
        is_admin: true,
        active: true,
        auth_source: "local".into(),
        external_subject: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    assert!(forge_server::app::has_placeholder_password(&user(Some(hash("changeme")))).await);
    assert!(!forge_server::app::has_placeholder_password(&user(Some(hash("a-real-secret")))).await);
    assert!(!forge_server::app::has_placeholder_password(&user(None)).await);
    assert!(!forge_server::app::has_placeholder_password(&user(Some("garbage".into()))).await);

    // An existing placeholder account does not stop the server from booting.
    let name = format!("bootph{}", common::unique());
    let pool = common::pool().await;
    forge_db::user_dao::insert_user(
        &pool,
        forge_db::user_dao::NewUser::local(name.clone(), hash("changeme"), true, true),
    )
    .await
    .unwrap();
    let srv = common::start_with(
        pool.clone(),
        common::ServerOpts {
            bootstrap_admin: Some((name.clone(), "rotated-in-config".into())),
            ..Default::default()
        },
    )
    .await;
    let resp = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&name, Some("changeme"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "startup is not refused");
}

/// Review M15: following the deployment guide ("remove the password from the
/// environment") leaves a bootstrap-admin block without a password. That must
/// start normally and simply create no bootstrap admin.
#[tokio::test]
async fn bootstrap_block_without_password_starts_without_a_bootstrap_admin() {
    let name = format!("nopw{}", common::unique());
    let pool = common::pool().await;
    let srv = common::start_with(
        pool.clone(),
        common::ServerOpts {
            bootstrap_admin: Some((name.clone(), String::new())),
            ..Default::default()
        },
    )
    .await;
    assert!(srv.state.config.auth.bootstrap_admin.is_none());
    let resp = srv
        .client()
        .get(format!("{}/healthz", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        forge_db::user_dao::find_user_by_username(&pool, &name)
            .await
            .unwrap()
            .is_none(),
        "no password configured means no bootstrap admin"
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
