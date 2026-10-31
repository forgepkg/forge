//! Integration tests of the device authorization grant (RFC 8628, #649):
//! `POST /auth/device/code`, `POST /auth/device/token`, the discovery
//! document (`/.well-known/oauth-authorization-server`) and the API of the
//! web UI's `/device` page (`/auth/device/lookup`, `/auth/device/decide`).
//!
//! Covers a pending request, `slow_down`, expiry, denial and approval, a
//! token collected once (and what it is), the scope, unknown clients and
//! malformed requests (always RFC 6749 JSON), the rate limit on guessing
//! codes per network and per session, and the settings that turn the
//! device login off and set its interval. Requires Docker (Postgres +
//! versitygw via the shared harness), or `FORGE_TEST_DATABASE_URL` /
//! `FORGE_TEST_S3_ENDPOINT`.

mod common;

use common::{fresh_pool, start_with, unique, BrowserSession, ServerOpts, TestServer};
use reqwest::StatusCode;
use serde_json::{json, Value};

const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// A server that believes `X-Forwarded-For` from the test client, so a test
/// can come from several networks.
async fn start() -> TestServer {
    start_on(common::pool().await).await
}

async fn start_on(pool: sqlx::PgPool) -> TestServer {
    start_with(
        pool,
        ServerOpts {
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            auth_extra: Some("trusted_proxy_cidrs = [\"127.0.0.1/32\", \"::1/128\"]".into()),
            ..Default::default()
        },
    )
    .await
}

/// `POST <path>` with a form body: the status, the `Cache-Control` and the
/// JSON answer (every answer of these endpoints is JSON).
async fn post_form(srv: &TestServer, path: &str, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let resp = srv
        .client()
        .post(format!("{}{path}", srv.base_url))
        .form(form)
        .send()
        .await
        .unwrap();
    answer(resp).await
}

async fn answer(resp: reqwest::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let cache_control = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        cache_control.contains("no-store"),
        "{status}: cache-control {cache_control:?}"
    );
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let text = resp.text().await.unwrap();
    assert!(
        content_type.starts_with("application/json"),
        "{status}: {content_type:?} {text}"
    );
    (status, serde_json::from_str(&text).unwrap())
}

/// Start a device login of `client_id` (optionally with `scope`), expecting
/// success.
async fn start_login(srv: &TestServer, client_id: &str, scope: Option<&str>) -> Value {
    let mut form = vec![("client_id", client_id)];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    let (status, body) = post_form(srv, "/auth/device/code", &form).await;
    assert_eq!(status, 200, "{body}");
    body
}

/// Poll the token endpoint once.
async fn poll(srv: &TestServer, client_id: &str, device_code: &str) -> (StatusCode, Value) {
    post_form(
        srv,
        "/auth/device/token",
        &[
            ("grant_type", GRANT),
            ("client_id", client_id),
            ("device_code", device_code),
        ],
    )
    .await
}

/// Expect an RFC 6749 §5.2 error.
fn assert_error(answer: (StatusCode, Value), error: &str) {
    let (status, body) = answer;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], error, "{body}");
    assert!(body["error_description"].is_string(), "{body}");
}

/// A new user (a `role` account), signed in.
async fn signed_in(srv: &TestServer, role: &str) -> (i64, String, BrowserSession) {
    let username = format!("dev{}@example.com", unique());
    let password = "device-login-password";
    let id = srv.create_user(&username, password, role).await;
    let session = srv.login(&username, password).await;
    (id, username, session)
}

/// `POST /auth/device/lookup` from `ip`.
async fn lookup(
    srv: &TestServer,
    session: &BrowserSession,
    code: &str,
    ip: &str,
) -> reqwest::Response {
    session
        .apply(
            srv.client()
                .post(format!("{}/auth/device/lookup", srv.base_url)),
        )
        .header("x-forwarded-for", ip)
        .json(&json!({"user_code": code}))
        .send()
        .await
        .unwrap()
}

/// `POST /auth/device/decide` from `ip`.
async fn decide(
    srv: &TestServer,
    session: &BrowserSession,
    code: &str,
    approve: bool,
    ip: &str,
) -> reqwest::Response {
    session
        .apply(
            srv.client()
                .post(format!("{}/auth/device/decide", srv.base_url)),
        )
        .header("x-forwarded-for", ip)
        .json(&json!({"user_code": code, "approve": approve}))
        .send()
        .await
        .unwrap()
}

/// The interval stored for the request with `user_code` (`BCDF-GHJK`).
async fn stored_interval(srv: &TestServer, user_code: &str) -> i32 {
    sqlx::query_scalar("SELECT interval_seconds FROM device_authorization WHERE user_code = $1")
        .bind(user_code.replace('-', ""))
        .fetch_one(&srv.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_discovery_document_names_the_endpoints() {
    let srv = start().await;
    let resp = srv
        .client()
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    assert_eq!(doc["issuer"], "http://test.local");
    assert_eq!(
        doc["device_authorization_endpoint"],
        "http://test.local/auth/device/code"
    );
    assert_eq!(doc["token_endpoint"], "http://test.local/auth/device/token");
    assert_eq!(doc["grant_types_supported"], json!([GRANT]));
    assert_eq!(
        doc["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
}

/// Pending, `slow_down`, approval, the token collected once, and what it is.
#[tokio::test]
async fn an_approved_login_collects_its_token_once() {
    let srv = start().await;
    let started = start_login(&srv, "docker-credential-forge", None).await;
    let device_code = started["device_code"].as_str().unwrap().to_string();
    let user_code = started["user_code"].as_str().unwrap().to_string();
    assert_eq!(user_code.len(), 9, "{user_code}");
    assert_eq!(&user_code[4..5], "-");
    assert!(user_code
        .chars()
        .all(|c| c == '-' || "BCDFGHJKLMNPQRSTVWXZ".contains(c)));
    assert_eq!(started["verification_uri"], "http://test.local/device");
    assert_eq!(
        started["verification_uri_complete"],
        format!("http://test.local/device?code={user_code}")
    );
    assert_eq!(
        started["expires_in"], 600,
        "cli_login.web_login_ttl_seconds"
    );
    assert_eq!(started["interval"], 5);
    // Only the device code's hash is stored.
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM device_authorization \
         WHERE device_code_hash = $1 AND client_id = 'docker-credential-forge'",
    )
    .bind(forge_core::auth::hash_token(&device_code))
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(stored, 1);

    // Pending; polled again at once, slow down: five more seconds, each time.
    assert_error(
        poll(&srv, "docker-credential-forge", &device_code).await,
        "authorization_pending",
    );
    assert_error(
        poll(&srv, "docker-credential-forge", &device_code).await,
        "slow_down",
    );
    assert_eq!(stored_interval(&srv, &user_code).await, 10);
    assert_error(
        poll(&srv, "docker-credential-forge", &device_code).await,
        "slow_down",
    );
    assert_eq!(stored_interval(&srv, &user_code).await, 15);

    // The /device page: a signed-in user looks the code up, in any spelling.
    let (_, username, session) = signed_in(&srv, "reader").await;
    let typed = user_code.replace('-', "").to_lowercase();
    let resp = lookup(&srv, &session, &typed, "198.51.100.7").await;
    assert_eq!(resp.status(), 200);
    let shown: Value = resp.json().await.unwrap();
    assert_eq!(shown["user_code"], user_code.as_str());
    assert_eq!(shown["client_id"], "docker-credential-forge");
    assert_eq!(shown["client_name"], "Docker credential helper");
    assert_eq!(shown["scope"], Value::Null, "the user's rights");
    assert_eq!(
        shown["client_ip"], "127.0.0.1",
        "where the client asked from"
    );
    assert!(shown["created_at"].is_string() && shown["expires_at"].is_string());
    // It takes the session's CSRF token, and a session.
    let resp = srv
        .client()
        .post(format!("{}/auth/device/lookup", srv.base_url))
        .header("cookie", &session.cookie)
        .json(&json!({"user_code": user_code}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = srv
        .client()
        .post(format!("{}/auth/device/lookup", srv.base_url))
        .json(&json!({"user_code": user_code}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Approved: the next poll, however soon, gets the token; then never again.
    let resp = decide(&srv, &session, &user_code, true, "198.51.100.7").await;
    assert_eq!(resp.status(), 204);
    let (status, token) = poll(&srv, "docker-credential-forge", &device_code).await;
    assert_eq!(status, 200, "{token}");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["username"], username.as_str());
    assert!(token.get("refresh_token").is_none(), "no refresh token");
    assert!(token.get("scope").is_none(), "{token}");
    let expires_in = token["expires_in"].as_i64().unwrap();
    assert!(
        (90 * 86400 - 60..=90 * 86400).contains(&expires_in),
        "cli_login.token_lifetime_days: {expires_in}"
    );
    let secret = token["access_token"].as_str().unwrap().to_string();
    assert_error(
        poll(&srv, "docker-credential-forge", &device_code).await,
        "expired_token",
    );
    // The request is no longer pending.
    let resp = lookup(&srv, &session, &user_code, "198.51.100.7").await;
    assert_eq!(resp.status(), 404);
    assert_eq!(
        decide(&srv, &session, &user_code, true, "198.51.100.7")
            .await
            .status(),
        404
    );

    // The token is the user's: it signs in, and their tokens page lists it,
    // named after the client and the host, with its lifetime.
    let me: Value = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&username, Some(&secret))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["user"]["username"], username.as_str());
    let tokens: Value = session
        .apply(
            srv.client()
                .get(format!("{}/admin/me/tokens", srv.base_url)),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let minted: Vec<&Value> = tokens
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["name"] == "docker-credential-forge login (test.local)")
        .collect();
    assert_eq!(minted.len(), 1, "{tokens}");
    assert!(minted[0]["expires_at"].is_string());
    assert_eq!(minted[0]["scope"], Value::Null);
    // ...and revocable there.
    let id = minted[0]["id"].as_i64().unwrap();
    let resp = session
        .apply(
            srv.client()
                .delete(format!("{}/admin/me/tokens/{id}", srv.base_url)),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&username, Some(&secret))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// A denied login answers `access_denied`, and mints nothing.
#[tokio::test]
async fn a_denied_login_is_access_denied() {
    let srv = start().await;
    let started = start_login(&srv, "forge-cli", None).await;
    let device_code = started["device_code"].as_str().unwrap();
    let user_code = started["user_code"].as_str().unwrap();
    let (_, _, session) = signed_in(&srv, "reader").await;
    let resp = decide(&srv, &session, user_code, false, "198.51.100.8").await;
    assert_eq!(resp.status(), 204);
    for _ in 0..2 {
        assert_error(poll(&srv, "forge-cli", device_code).await, "access_denied");
    }
    // Decided: it cannot be approved after all.
    assert_eq!(
        decide(&srv, &session, user_code, true, "198.51.100.8")
            .await
            .status(),
        404
    );
    assert_error(poll(&srv, "forge-cli", device_code).await, "access_denied");
}

/// A request past its lifetime answers `expired_token`, cannot be approved,
/// and the auth reaper removes it.
#[tokio::test]
async fn an_expired_login_is_expired_and_reaped() {
    let srv = start().await;
    let started = start_login(&srv, "nuget-plugin-forge", None).await;
    let device_code = started["device_code"].as_str().unwrap();
    let user_code = started["user_code"].as_str().unwrap();
    sqlx::query(
        "UPDATE device_authorization SET expires_at = now() - interval '1 second' \
         WHERE user_code = $1",
    )
    .bind(user_code.replace('-', ""))
    .execute(&srv.pool)
    .await
    .unwrap();
    assert_error(
        poll(&srv, "nuget-plugin-forge", device_code).await,
        "expired_token",
    );
    let (_, _, session) = signed_in(&srv, "reader").await;
    assert_eq!(
        lookup(&srv, &session, user_code, "198.51.100.9")
            .await
            .status(),
        404
    );
    assert_eq!(
        decide(&srv, &session, user_code, true, "198.51.100.9")
            .await
            .status(),
        404
    );
    assert!(
        forge_db::device_auth_dao::delete_expired(&srv.pool)
            .await
            .unwrap()
            >= 1
    );
    assert_error(
        poll(&srv, "nuget-plugin-forge", device_code).await,
        "invalid_grant",
    );
}

/// Only Forge's helpers are clients; every refusal is RFC 6749 JSON, also
/// with a header the credential chain would refuse.
#[tokio::test]
async fn unknown_clients_and_malformed_requests_get_oauth_errors() {
    let srv = start().await;
    assert_error(
        post_form(&srv, "/auth/device/code", &[("client_id", "curl")]).await,
        "invalid_client",
    );
    assert_error(
        post_form(&srv, "/auth/device/code", &[]).await,
        "invalid_request",
    );
    for scope in ["admin", "repository:a/b", "write openid"] {
        assert_error(
            post_form(
                &srv,
                "/auth/device/code",
                &[("client_id", "forge-cli"), ("scope", scope)],
            )
            .await,
            "invalid_scope",
        );
    }
    // A JSON body is no form.
    let resp = srv
        .client()
        .post(format!("{}/auth/device/code", srv.base_url))
        .json(&json!({"client_id": "forge-cli"}))
        .send()
        .await
        .unwrap();
    assert_error(answer(resp).await, "invalid_request");
    // A repeated parameter.
    let resp = srv
        .client()
        .post(format!("{}/auth/device/code", srv.base_url))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("client_id=forge-cli&client_id=forge-cli")
        .send()
        .await
        .unwrap();
    assert_error(answer(resp).await, "invalid_request");

    let started = start_login(&srv, "forge-cli", None).await;
    let device_code = started["device_code"].as_str().unwrap();
    assert_error(poll(&srv, "curl", device_code).await, "invalid_client");
    assert_error(
        poll(&srv, "docker-credential-forge", device_code).await,
        "invalid_grant",
    );
    assert_error(
        poll(&srv, "forge-cli", "not-a-device-code").await,
        "invalid_grant",
    );
    assert_error(
        post_form(
            &srv,
            "/auth/device/token",
            &[("client_id", "forge-cli"), ("device_code", device_code)],
        )
        .await,
        "invalid_request",
    );
    // No refresh token is issued, and no other grant is served.
    assert_error(
        post_form(
            &srv,
            "/auth/device/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", "forge-cli"),
                ("refresh_token", "x"),
            ],
        )
        .await,
        "unsupported_grant_type",
    );
    assert_error(
        post_form(
            &srv,
            "/auth/device/token",
            &[("grant_type", GRANT), ("client_id", "forge-cli")],
        )
        .await,
        "invalid_request",
    );
    // Credentials the chain would refuse do not turn the answer into its
    // plain-text 401.
    let resp = srv
        .client()
        .post(format!("{}/auth/device/token", srv.base_url))
        .basic_auth("forge-cli", Some("wrong"))
        .form(&[
            ("grant_type", GRANT),
            ("client_id", "forge-cli"),
            ("device_code", device_code),
        ])
        .send()
        .await
        .unwrap();
    assert_error(answer(resp).await, "authorization_pending");
}

/// A scope narrows the token: its level and repositories by name (a name
/// no repository has reaches nothing).
#[tokio::test]
async fn a_scope_narrows_the_token() {
    let srv = start().await;
    let repo = format!("dev-raw-{}", unique());
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": repo, "kind": "hosted", "format": "raw"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let repo_id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();

    let scope = format!("repository:{repo} read repository:no-such-repo");
    let started = start_login(&srv, "forge-cli", Some(&scope)).await;
    let device_code = started["device_code"].as_str().unwrap();
    let user_code = started["user_code"].as_str().unwrap();
    let (_, _, session) = signed_in(&srv, "writer").await;
    let shown: Value = lookup(&srv, &session, user_code, "198.51.100.10")
        .await
        .json()
        .await
        .unwrap();
    let mut repositories = vec![repo.clone(), "no-such-repo".to_string()];
    repositories.sort();
    assert_eq!(
        shown["scope"],
        json!({"level": "read", "repositories": repositories})
    );
    assert_eq!(
        decide(&srv, &session, user_code, true, "198.51.100.10")
            .await
            .status(),
        204
    );
    let (status, token) = poll(&srv, "forge-cli", device_code).await;
    assert_eq!(status, 200, "{token}");
    assert_eq!(
        token["scope"],
        format!("read repository:{}", repositories.join(" repository:"))
    );
    let tokens: Value = session
        .apply(
            srv.client()
                .get(format!("{}/admin/me/tokens", srv.base_url)),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let minted = tokens
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "forge-cli login (test.local)")
        .expect("the minted token");
    assert_eq!(
        minted["scope"],
        json!({"level": "read", "repositories": [repo_id]})
    );
}

/// Guessing codes is cut off: ten wrong codes per network and per session,
/// after which even the right code is refused, from that network with any
/// session and in that session from any network.
#[tokio::test]
async fn guessing_a_code_is_cut_off_by_the_rate_limit() {
    let srv = start().await;
    let started = start_login(&srv, "forge-cli", None).await;
    let user_code = started["user_code"].as_str().unwrap().to_string();
    let (_, _, guesser) = signed_in(&srv, "reader").await;
    let (_, _, other) = signed_in(&srv, "reader").await;
    let wrong = if user_code == "BBBB-BBBB" {
        "CCCC-CCCC"
    } else {
        "BBBB-BBBB"
    };

    // A malformed code is refused unseen, and never counted.
    for _ in 0..12 {
        let resp = lookup(&srv, &guesser, "1234", "203.0.113.1").await;
        assert_eq!(resp.status(), 400);
    }
    for _ in 0..10 {
        let resp = lookup(&srv, &guesser, wrong, "203.0.113.1").await;
        assert_eq!(resp.status(), 404);
    }
    let refused = lookup(&srv, &guesser, &user_code, "203.0.113.1").await;
    assert_eq!(refused.status(), 429);
    assert!(refused.headers().contains_key("retry-after"));
    assert_eq!(
        decide(&srv, &guesser, &user_code, true, "203.0.113.1")
            .await
            .status(),
        429,
        "deciding is code entry too"
    );
    // The session from another network: still cut off.
    assert_eq!(
        lookup(&srv, &guesser, &user_code, "203.0.113.2")
            .await
            .status(),
        429
    );
    // The network with another session: cut off too.
    assert_eq!(
        lookup(&srv, &other, &user_code, "203.0.113.1")
            .await
            .status(),
        429
    );
    // Another session from another network finds the code.
    assert_eq!(
        lookup(&srv, &other, &user_code, "203.0.113.2")
            .await
            .status(),
        200
    );
    // Finding a code clears no failure: the guesser stays cut off.
    assert_eq!(
        lookup(&srv, &guesser, &user_code, "203.0.113.1")
            .await
            .status(),
        429
    );
}

/// The device login is an auth setting: it can be turned off, and the
/// polling interval set (Admin → Settings).
#[tokio::test]
async fn the_settings_turn_the_device_login_off_and_set_its_interval() {
    let srv = start_on(fresh_pool().await).await;
    let started = start_login(&srv, "forge-cli", None).await;
    let device_code = started["device_code"].as_str().unwrap().to_string();

    let saved = srv
        .set_auth_settings(json!({"device_poll_interval_seconds": 7}))
        .await;
    assert_eq!(saved.device_poll_interval_seconds, 7);
    assert!(saved.device_login);
    assert_eq!(start_login(&srv, "forge-cli", None).await["interval"], 7);

    srv.set_auth_settings(json!({"device_login": false})).await;
    assert_error(
        post_form(&srv, "/auth/device/code", &[("client_id", "forge-cli")]).await,
        "unauthorized_client",
    );
    assert_error(
        poll(&srv, "forge-cli", &device_code).await,
        "unauthorized_client",
    );
    // The discovery document stays: a client learns why from the endpoint.
    let resp = srv
        .client()
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    srv.set_auth_settings(json!({"device_login": true})).await;
    assert_error(
        poll(&srv, "forge-cli", &device_code).await,
        "authorization_pending",
    );
}
