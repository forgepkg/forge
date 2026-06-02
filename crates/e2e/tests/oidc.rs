//! E2E: OIDC / Microsoft Entra interactive login (slice 12.2 Phase 6).
//!
//! Drives the **real** forge server(s) over HTTP against a real Postgres
//! testcontainer + an in-process mock OIDC IdP (`MockOidc`: discovery + JWKS +
//! an authorize endpoint that 302s straight back to the forge callback + a token
//! endpoint signing a test ID token). Covers the plan §5 scenarios:
//!
//! 1. `login → callback` success creates a session; `/auth/me` shows the user.
//! 2. unknown `state` rejected; `nonce` mismatch rejected.
//! 3. **cross-instance**: a callback completed by a *different* server instance
//!    than the one that started login succeeds (shared `oidc_flow` in Postgres).
//! 4. session **logout** revokes the cookie cluster-wide.
//! 5. a session-authenticated user **mints a repository token** and uses it as
//!    `X-NuGet-ApiKey` against a real NuGet repo endpoint.
//!
//! Requires Docker.

#![cfg(feature = "forge-e2e")]

use forge_e2e::{make_nupkg, MockOidc, StackBuilder, TestServer};
use serde_json::{json, Value};

const CLIENT_ID: &str = "forge-e2e-client";

/// A reqwest client that does NOT follow redirects (so we can read the 302s).
fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

/// Start a single OIDC-enabled stack against `idp`.
async fn start_oidc_stack(idp: &MockOidc) -> TestServer {
    let issuer = idp.issuer().to_string();
    let client_id = CLIENT_ID.to_string();
    StackBuilder::default()
        .bootstrap_admin("root", "rootpw")
        .with_oidc(move |base| oidc_block(&issuer, &client_id, base))
        .start()
        .await
}

/// The `[oidc]` block (standalone copy of `MockOidc::oidc_block`, so the same
/// closure can be cloned for a peer with its own base URL).
fn oidc_block(issuer: &str, client_id: &str, public_base_url: &str) -> String {
    format!(
        r#"
[oidc]
issuer = "{issuer}"
client_id = "{client_id}"
client_secret = "shh-secret"
redirect_url = "{public_base_url}/auth/oidc/callback"
allow_private_issuer = true
admin_groups = ["forge-admins"]
admin_claim = "roles"
session_idle_ttl_seconds = 28800
session_absolute_ttl_seconds = 604800
"#,
    )
}

/// Extract the `state` query param from an authorize URL.
fn state_from_url(url: &str) -> String {
    url::Url::parse(url)
        .expect("authorize url")
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("state param")
}

/// Peek the nonce stored on a live `oidc_flow` row (without consuming it).
async fn peek_nonce(pool: &sqlx::PgPool, state: &str) -> String {
    sqlx::query_scalar::<_, String>("SELECT nonce FROM oidc_flow WHERE state = $1")
        .bind(state)
        .fetch_one(pool)
        .await
        .expect("flow row")
}

/// Extract the `forge_session` cookie value from a Set-Cookie header.
fn session_cookie_from(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.trim().strip_prefix("forge_session="))
        .map(str::to_string)
        .expect("forge_session cookie")
}

/// `GET /auth/oidc/login` on `srv`, returning `(state, nonce)` for the new flow.
async fn begin_login(srv: &TestServer) -> (String, String) {
    let resp = no_redirect_client()
        .get(format!("{}/auth/oidc/login", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302, "login redirects to IdP");
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = state_from_url(location);
    let nonce = peek_nonce(&srv.pool, &state).await;
    (state, nonce)
}

/// Hit `GET /auth/oidc/callback` on `srv` with the given `state`, returning the
/// response (caller asserts status / reads the Set-Cookie).
async fn callback(srv: &TestServer, state: &str) -> reqwest::Response {
    no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=mock-code&state={state}",
            srv.base_url
        ))
        .send()
        .await
        .unwrap()
}

// ── 1. happy path: login → callback → session → /auth/me ─────────────────────

#[tokio::test]
async fn login_callback_creates_session_and_me_shows_user() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let srv = start_oidc_stack(&idp).await;

    let (state, nonce) = begin_login(&srv).await;
    // Mark the user an admin via the roles claim → is_admin.
    idp.set_next_id_token(idp.id_claims("sub-alice", "alice", &nonce, json!(["forge-admins"])))
        .await;

    let resp = callback(&srv, &state).await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/",
        "default post-login target"
    );
    let cookie = session_cookie_from(
        resp.headers()
            .get("set-cookie")
            .expect("session cookie")
            .to_str()
            .unwrap(),
    );

    // /auth/me recognises the session and reflects the admin role claim.
    let me: Value = no_redirect_client()
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["username"], json!("alice"));
    assert_eq!(me["is_admin"], json!(true), "roles claim granted admin");
    assert!(me["csrf_token"].as_str().is_some_and(|s| !s.is_empty()));
}

// ── 2. state / nonce rejection ───────────────────────────────────────────────

#[tokio::test]
async fn unknown_and_replayed_state_rejected() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let srv = start_oidc_stack(&idp).await;

    // Never-issued state → 400 (no oidc_flow row).
    let resp = callback(&srv, "never-issued-state").await;
    assert_eq!(resp.status(), 400, "unknown state rejected");
    assert!(resp.headers().get("set-cookie").is_none());

    // A once-used state cannot be replayed (the row is consumed single-use).
    let (state, nonce) = begin_login(&srv).await;
    idp.set_next_id_token(idp.id_claims("sub-bob", "bob", &nonce, json!([])))
        .await;
    let first = callback(&srv, &state).await;
    assert_eq!(first.status(), 302, "first callback succeeds");
    // Replay the same state → the flow row is gone → 400.
    idp.set_next_id_token(idp.id_claims("sub-bob", "bob", &nonce, json!([])))
        .await;
    let replay = callback(&srv, &state).await;
    assert_eq!(replay.status(), 400, "replayed state rejected");
}

#[tokio::test]
async fn nonce_mismatch_rejected() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let srv = start_oidc_stack(&idp).await;

    let (state, _real_nonce) = begin_login(&srv).await;
    // The IdP issues a token with a WRONG nonce → verification fails.
    idp.set_next_id_token(idp.id_claims("sub-carol", "carol", "not-the-nonce", json!([])))
        .await;
    let resp = callback(&srv, &state).await;
    assert_eq!(resp.status(), 400, "nonce mismatch rejected");
    assert!(resp.headers().get("set-cookie").is_none());
}

// ── 3. cross-instance callback (the headline scale-out scenario) ─────────────

#[tokio::test]
async fn callback_completed_by_different_instance_succeeds() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let issuer = idp.issuer().to_string();

    // Instance A starts the login (writes oidc_flow to the shared Postgres).
    let srv_a = start_oidc_stack(&idp).await;
    // Instance B shares the DB + the same OIDC provider.
    let issuer_b = issuer.clone();
    let srv_b = srv_a
        .spawn_peer_with_oidc(move |base| oidc_block(&issuer_b, CLIENT_ID, base))
        .await;

    let (state, nonce) = begin_login(&srv_a).await;
    idp.set_next_id_token(idp.id_claims("sub-dave", "dave", &nonce, json!([])))
        .await;

    // The callback lands on B — which never saw the login leg. It consumes the
    // shared oidc_flow row, completes the flow, and sets a session cookie.
    let resp = callback(&srv_b, &state).await;
    assert_eq!(
        resp.status(),
        302,
        "B completes a flow that A started (shared oidc_flow)"
    );
    let cookie = session_cookie_from(
        resp.headers()
            .get("set-cookie")
            .expect("B sets the session cookie")
            .to_str()
            .unwrap(),
    );

    // The session created on B is immediately recognised on BOTH instances
    // (the session row is the shared authority).
    for (label, srv) in [("A", &srv_a), ("B", &srv_b)] {
        let resp = no_redirect_client()
            .get(format!("{}/auth/me", srv.base_url))
            .header("cookie", format!("forge_session={cookie}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "instance {label} recognises the cross-instance session"
        );
        let me: Value = resp.json().await.unwrap();
        assert_eq!(me["username"], json!("dave"));
    }
}

// ── 4. logout revokes cluster-wide ───────────────────────────────────────────

#[tokio::test]
async fn logout_revokes_session_everywhere() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let issuer = idp.issuer().to_string();
    let srv_a = start_oidc_stack(&idp).await;
    let issuer_b = issuer.clone();
    let srv_b = srv_a
        .spawn_peer_with_oidc(move |base| oidc_block(&issuer_b, CLIENT_ID, base))
        .await;

    let (state, nonce) = begin_login(&srv_a).await;
    idp.set_next_id_token(idp.id_claims("sub-erin", "erin", &nonce, json!([])))
        .await;
    let resp = callback(&srv_a, &state).await;
    let cookie = session_cookie_from(resp.headers().get("set-cookie").unwrap().to_str().unwrap());

    // Read the per-session CSRF token from /auth/me.
    let me: Value = no_redirect_client()
        .get(format!("{}/auth/me", srv_a.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf = me["csrf_token"].as_str().unwrap().to_string();

    // Logout on A (CSRF required) → 200.
    let resp = no_redirect_client()
        .post(format!("{}/auth/logout", srv_a.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "logout succeeds with CSRF");

    // The revoked session is rejected on the OTHER instance too.
    let resp = no_redirect_client()
        .get(format!("{}/auth/me", srv_b.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "revoked session rejected on peer instance"
    );
}

// ── 6. JWKS rotation: kid-miss refetch validates; retired key rejected ───────

#[tokio::test]
async fn jwks_rotation_kid_miss_refetch_then_retired_key_rejected() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let srv = start_oidc_stack(&idp).await;

    // First login warms the JWKS cache with key "k1".
    let (state, nonce) = begin_login(&srv).await;
    idp.set_next_id_token(idp.id_claims("sub-grace", "grace", &nonce, json!([])))
        .await;
    assert_eq!(callback(&srv, &state).await.status(), 302, "warm-up login");

    // The IdP rotates its signing key (publishes only the new "k2" in JWKS).
    idp.rotate_key("k2").await;

    // A token signed with the NEW key validates via the kid-miss forced refetch.
    let (state, nonce) = begin_login(&srv).await;
    idp.set_next_id_token(idp.id_claims("sub-grace", "grace", &nonce, json!([])))
        .await;
    let resp = callback(&srv, &state).await;
    assert_eq!(
        resp.status(),
        302,
        "token signed with the rotated key validates (kid-miss refetch)"
    );

    // A token signed with a key whose kid is NOT in the JWKS is rejected.
    let (state, nonce) = begin_login(&srv).await;
    idp.set_next_id_token_with_unknown_key(idp.id_claims("sub-grace", "grace", &nonce, json!([])))
        .await;
    let resp = callback(&srv, &state).await;
    assert_eq!(
        resp.status(),
        400,
        "token signed by an unknown/retired key is rejected"
    );
}

// ── 5. session-authenticated token minting → usable as a NuGet API key ───────

#[tokio::test]
async fn session_minted_token_authenticates_nuget_endpoint() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let srv = start_oidc_stack(&idp).await;

    // Log in as an admin (so the minted token can publish + read).
    let (state, nonce) = begin_login(&srv).await;
    idp.set_next_id_token(idp.id_claims("sub-frank", "frank", &nonce, json!(["forge-admins"])))
        .await;
    let resp = callback(&srv, &state).await;
    let cookie = session_cookie_from(resp.headers().get("set-cookie").unwrap().to_str().unwrap());
    let me: Value = no_redirect_client()
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf = me["csrf_token"].as_str().unwrap().to_string();

    // Mint a repository token via the session-authenticated endpoint.
    let created: Value = no_redirect_client()
        .post(format!("{}/auth/tokens", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .header("x-csrf-token", &csrf)
        .json(&json!({"name": "ci-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = created["token"]
        .as_str()
        .expect("plaintext token")
        .to_string();

    // Create a hosted repo (as the bootstrap admin) and publish to it with the
    // session-minted key, proving it is a real slice-1 token.
    let repo = "oidc-minted";
    let resp = srv
        .create_repo(json!({"name": repo, "kind": "hosted", "anonymous_read": false}))
        .await;
    assert!(resp.status().is_success(), "repo created");

    let push = no_redirect_client()
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", &api_key)
        .multipart(
            reqwest::multipart::Form::new().part(
                "package",
                reqwest::multipart::Part::bytes(make_nupkg("Mint.Pkg", "1.0.0"))
                    .file_name("package.nupkg")
                    .mime_str("application/octet-stream")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert!(
        push.status().is_success(),
        "session-minted token publishes a package (got {})",
        push.status()
    );

    // And the same key reads the service index.
    let read = no_redirect_client()
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .header("X-NuGet-ApiKey", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), 200, "session-minted token reads the repo");
}
