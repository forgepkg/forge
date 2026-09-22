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
//! 6. **session expiry** (plan §5 scenario 6): a session created with a tiny
//!    idle TTL is accepted while fresh and `401`s on the next request once it
//!    lapses (the validity predicate is evaluated on read, in SQL).
//! 7. **auth reaper** (plan §5 Phase-6 requirement): against a running stack
//!    with the wired reaper worker, expired `oidc_flow` rows and dead
//!    (expired/revoked) `session` rows are deleted while the live ones survive
//!    and stay usable.
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
    oidc_block_with_ttls(issuer, client_id, public_base_url, 28800, 604800)
}

/// Like [`oidc_block`] but with caller-chosen session TTLs, so a test can inject
/// a deliberately tiny idle/absolute lifetime (plan §5 scenario 6: a short-TTL
/// session is rejected on the next request once it lapses).
fn oidc_block_with_ttls(
    issuer: &str,
    client_id: &str,
    public_base_url: &str,
    idle_ttl_seconds: u64,
    absolute_ttl_seconds: u64,
) -> String {
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
session_idle_ttl_seconds = {idle_ttl_seconds}
session_absolute_ttl_seconds = {absolute_ttl_seconds}
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
/// response (caller asserts status / reads the Set-Cookie). Presents the
/// pre-auth `forge_oidc_flow` cookie the login leg sets (the same browser), so
/// any instance can verify it without shared memory.
async fn callback(srv: &TestServer, state: &str) -> reqwest::Response {
    no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=mock-code&state={state}",
            srv.base_url
        ))
        .header(
            "cookie",
            format!(
                "forge_oidc_flow={}",
                forge_core::oidc::browser_binding(state)
            ),
        )
        .send()
        .await
        .unwrap()
}

/// Whether a response set a `forge_session` cookie (the flow cookie is always
/// cleared on the callback, so "no Set-Cookie at all" is not the signal).
fn sets_session_cookie(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .any(|v| v.to_str().is_ok_and(|v| v.starts_with("forge_session=")))
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
    assert!(!sets_session_cookie(&resp));

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
    assert!(!sets_session_cookie(&resp));
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

// ── 6a. session expiry: a short-TTL session is 401 on the next request ────────

#[tokio::test]
async fn short_ttl_session_is_rejected_after_it_lapses() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let issuer = idp.issuer().to_string();
    let client_id = CLIENT_ID.to_string();
    // Idle TTL of 1s: the session is valid right after login but lapses within a
    // second. (Absolute TTL is comfortably long so we isolate the idle path.)
    let srv = StackBuilder::default()
        .bootstrap_admin("root", "rootpw")
        .with_oidc(move |base| oidc_block_with_ttls(&issuer, &client_id, base, 1, 604800))
        .start()
        .await;

    let (state, nonce) = begin_login(&srv).await;
    idp.set_next_id_token(idp.id_claims("sub-heidi", "heidi", &nonce, json!([])))
        .await;
    let resp = callback(&srv, &state).await;
    assert_eq!(resp.status(), 302, "login succeeds");
    let cookie = session_cookie_from(resp.headers().get("set-cookie").unwrap().to_str().unwrap());

    // While fresh, the session authenticates /auth/me.
    let fresh = no_redirect_client()
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), 200, "fresh short-TTL session is accepted");

    // Wait past the 1s idle TTL. The validity predicate is enforced in SQL
    // (`now() < idle_expiry`), so the next request with the same cookie is 401 —
    // no reaper involvement needed; expiry is evaluated on read.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let lapsed = no_redirect_client()
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        lapsed.status(),
        401,
        "an idle-expired session is rejected on the next request"
    );
}

// ── 6b. reaper: deletes expired oidc_flow/session rows, leaves valid ones ─────

/// Count live `oidc_flow` rows for a given `state` (0 or 1).
async fn flow_exists(pool: &sqlx::PgPool, state: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM oidc_flow WHERE state = $1")
        .bind(state)
        .fetch_one(pool)
        .await
        .expect("count flow")
        > 0
}

/// Whether a `session` row with the given id still exists.
async fn session_exists(pool: &sqlx::PgPool, id: i64) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM session WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count session")
        > 0
}

#[tokio::test]
async fn reaper_removes_expired_flows_and_sessions_keeps_valid() {
    use forge_core::auth::token::hash_token;
    use forge_db::oidc_flow_dao::{self, NewOidcFlow};
    use forge_db::session_dao::{self, NewSession};

    let idp = MockOidc::start(CLIENT_ID).await;
    // Workers on: this stack actually spawns the wired auth reaper loop. The
    // sweep is driven directly below (the live worker cadence is ~60s, too slow
    // for a deterministic test), exercising the exact DAO calls the loop runs
    // against a real migrated Postgres + a running server instance.
    let srv = StackBuilder::default()
        .bootstrap_admin("root", "rootpw")
        .workers(true)
        .with_oidc({
            let issuer = idp.issuer().to_string();
            move |base| oidc_block(&issuer, CLIENT_ID, base)
        })
        .start()
        .await;
    let pool = srv.pool.clone();

    // --- oidc_flow: one live (unexpired) row + one already-expired row. ---
    // The live one comes from a real begin_login (so it is a genuine flow row).
    let (live_state, _nonce) = begin_login(&srv).await;
    // The expired one is inserted directly with a past `expires_at`.
    let expired_state = "expired-state-reaper-test".to_string();
    oidc_flow_dao::begin(
        &pool,
        NewOidcFlow {
            state: expired_state.clone(),
            nonce: "n".into(),
            pkce_verifier: "v".into(),
            redirect_to: "/".into(),
            expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
        },
    )
    .await
    .expect("insert expired flow");

    assert!(flow_exists(&pool, &live_state).await, "live flow present");
    assert!(
        flow_exists(&pool, &expired_state).await,
        "expired flow present before reap"
    );

    // --- session: one live row (via a real login) + one expired + one revoked. ---
    let (state, nonce) = begin_login(&srv).await;
    idp.set_next_id_token(idp.id_claims("sub-ivan", "ivan", &nonce, json!([])))
        .await;
    let resp = callback(&srv, &state).await;
    assert_eq!(resp.status(), 302, "live-session login succeeds");
    let live_cookie =
        session_cookie_from(resp.headers().get("set-cookie").unwrap().to_str().unwrap());
    let (live_session_id, live_user_id) =
        sqlx::query_as::<_, (i64, i64)>("SELECT id, user_id FROM session WHERE token_hash = $1")
            .bind(hash_token(&live_cookie))
            .fetch_one(&pool)
            .await
            .expect("live session row");

    let now = chrono::Utc::now();
    // An idle/absolute-expired session (both expiries in the past).
    let expired_session = session_dao::create(
        &pool,
        NewSession {
            user_id: live_user_id,
            external_identity_id: None,
            token_hash: hash_token("expired-cookie"),
            csrf_secret: "c".into(),
            user_agent_hash: None,
            idle_expiry: now - chrono::Duration::hours(1),
            absolute_expiry: now - chrono::Duration::hours(1),
        },
    )
    .await
    .expect("insert expired session");
    // A revoked-but-not-yet-expired session.
    let revoked_session = session_dao::create(
        &pool,
        NewSession {
            user_id: live_user_id,
            external_identity_id: None,
            token_hash: hash_token("revoked-cookie"),
            csrf_secret: "c".into(),
            user_agent_hash: None,
            idle_expiry: now + chrono::Duration::hours(8),
            absolute_expiry: now + chrono::Duration::days(7),
        },
    )
    .await
    .expect("insert revoked session");
    assert!(
        session_dao::revoke(&pool, revoked_session.id)
            .await
            .expect("revoke"),
        "session revoked"
    );

    // --- tick the reaper: exactly the two DELETEs the wired worker loop runs. ---
    let flows_reaped = oidc_flow_dao::reap_expired(&pool).await.expect("flow reap");
    let sessions_reaped = session_dao::reap_expired(&pool)
        .await
        .expect("session reap");
    assert!(flows_reaped >= 1, "at least the expired flow was reaped");
    assert!(
        sessions_reaped >= 2,
        "at least the expired + revoked sessions were reaped"
    );

    // --- expired/dead rows gone; valid rows survive. ---
    assert!(
        !flow_exists(&pool, &expired_state).await,
        "expired flow deleted by reaper"
    );
    assert!(
        flow_exists(&pool, &live_state).await,
        "valid flow survives the reaper"
    );
    assert!(
        !session_exists(&pool, expired_session.id).await,
        "expired session deleted by reaper"
    );
    assert!(
        !session_exists(&pool, revoked_session.id).await,
        "revoked session deleted by reaper"
    );
    assert!(
        session_exists(&pool, live_session_id).await,
        "valid session row survives the reaper"
    );

    // The surviving session is still usable end-to-end on the live server.
    let me = no_redirect_client()
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", format!("forge_session={live_cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), 200, "the reaper left the valid session usable");
}
