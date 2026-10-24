//! E2E: credential-forwarding authentication.
//!
//! Drives the **real** forge server(s) over HTTP against a real Postgres
//! testcontainer + an in-process mock HTTP Basic upstream (`MockBasicUpstream`:
//! a Nexus status/whoami stand-in that validates Basic credentials, advertises
//! the user's roles, counts the requests it receives, and can be flipped
//! `down`). The forge server's `upstream-basic` provider forwards the user's
//! `username:password` to this mock; a validated-credential cache absorbs the
//! per-request fan-out. The realm creates no accounts: each test creates its
//! accounts through `POST /admin/users` with the realm, named by a UPN whose
//! local part is the upstream's account. Covers these scenarios:
//!
//! 1. a login signs in only an account an administrator created
//!    (`auth_source='upstream-basic'`, NULL `password_hash`), forwarding the
//!    local part of its name; another domain's name with the same local part
//!    signs in nothing.
//! 2. wrong password → 401, a negative verdict cached.
//! 3. a second identical request within TTL is served from cache **without** a
//!    second upstream call (asserted via the mock's hit counter).
//! 4. cache TTL expiry triggers a re-check (a second upstream call).
//! 5. provider ordering: a **local** user authenticates without hitting the
//!    upstream at all (`["local-password","upstream-basic"]`).
//! 6. upstream **down** → fail-closed (401), not granted; a cached positive
//!    within TTL still works; nothing negative cached for the outage.
//! 7. the stored `validated_credential` row holds an HMAC, never the plaintext
//!    password (dump the table + `app_user`, assert no plaintext substring).
//! 8. admin `reauth` purges the cached verdict → the next request re-forwards.
//! 9. `required_groups` gate: a user lacking the required group is rejected
//!    despite a valid password.
//! 11. an SSO-style upstream that 302s every credential to a 200 login page is
//!     never trusted: the redirect is not followed and the login fails closed.
//! 12. admin deactivation cuts a federated user off: verdicts purged, logins
//!     refused even though the upstream still accepts the password, and a
//!     login does not reactivate the account.
//! 13. deleting a user purges its cached verdicts, and the account stays gone.
//!
//! Requires Docker.

#![cfg(feature = "forge-e2e")]

use forge_e2e::{MockBasicUpstream, StackBuilder, TestServer};
use serde_json::Value;

/// The single upstream-valid end user used across the happy-path scenarios:
/// `UP_NAME` is the upstream's account, `UP_USER` Forge's (a UPN with that
/// local part).
const UP_NAME: &str = "nexus-alice";
const UP_USER: &str = "nexus-alice@example.com";
const UP_PASS: &str = "s3cr3t-upstream-pw";

/// The realm the stack imports the `[auth.upstream_basic]` block into.
const REALM: &str = "upstream-basic";

/// Start a stack with the `["local-password","upstream-basic"]` chain pointed at
/// `mock`, with the given cache TTLs and (optional) group gate.
async fn start_credforward_stack(
    mock: &MockBasicUpstream,
    positive_ttl: u64,
    negative_ttl: u64,
    required_groups: &[&str],
    admin_group: &str,
) -> TestServer {
    let block = mock.upstream_basic_block(
        &["local-password", "upstream-basic"],
        positive_ttl,
        negative_ttl,
        required_groups,
        admin_group,
    );
    StackBuilder::default()
        .bootstrap_admin("root@example.com", "rootpw")
        .with_upstream_basic(block)
        .start()
        .await
}

/// Create the forwarded account `username` of the stack's realm as its
/// bootstrap admin, returning its id.
async fn create_account(srv: &TestServer, username: &str) -> i64 {
    let (admin_u, admin_p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&admin_u, Some(&admin_p))
        .json(&serde_json::json!({ "username": username, "realm": REALM }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let user: Value = resp.json().await.unwrap();
    user["id"].as_i64().expect("the account's id")
}

/// `GET /admin/me` with HTTP Basic — the un-gated identity endpoint, so a
/// non-admin upstream user can prove it authenticated.
async fn me_basic(srv: &TestServer, user: &str, pass: &str) -> reqwest::Response {
    srv.client()
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(user, Some(pass))
        .send()
        .await
        .unwrap()
}

/// Look up an `app_user` row's `(auth_source, password_hash, holds the
/// built-in admin role)`.
async fn user_row(pool: &sqlx::PgPool, username: &str) -> Option<(String, Option<String>, bool)> {
    sqlx::query_as::<_, (String, Option<String>, bool)>(
        "SELECT u.auth_source, u.password_hash, EXISTS (
             SELECT 1 FROM user_role ur JOIN role r ON r.id = ur.role_id
             WHERE ur.user_id = u.id AND r.name = 'admin')
         FROM app_user u WHERE u.username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .expect("query app_user")
}

/// Count `validated_credential` rows for a username (any provider) and the
/// number that are positive verdicts.
async fn verdict_counts(pool: &sqlx::PgPool, username: &str) -> (i64, i64) {
    sqlx::query_as::<_, (i64, i64)>(
        "SELECT count(*), count(*) FILTER (WHERE verdict) \
         FROM validated_credential WHERE username = $1",
    )
    .bind(username)
    .fetch_one(pool)
    .await
    .expect("count verdicts")
}

// ── 1. a login signs in the account an administrator created ─────────────────

#[tokio::test]
async fn upstream_login_signs_in_only_a_created_account() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec!["nuget-users"])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;

    // The upstream accepts the password, but the realm creates no accounts.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 401);
    assert_eq!(mock.hits(), 1, "the credential was forwarded");
    assert!(
        user_row(&srv.pool, UP_USER).await.is_none(),
        "no account created by a login"
    );

    // Once an administrator created the account, the same login signs it in
    // (from the verdict the first request cached).
    create_account(&srv, UP_USER).await;
    let resp = me_basic(&srv, UP_USER, UP_PASS).await;
    assert_eq!(resp.status(), 200, "upstream-valid login is accepted");
    let me: Value = resp.json().await.unwrap();
    assert_eq!(me["user"]["username"], serde_json::json!(UP_USER));
    assert_eq!(
        me["is_admin"],
        serde_json::json!(false),
        "no admin_group mapping ⇒ not admin"
    );
    assert_eq!(mock.hits(), 1, "exactly one upstream forward");

    // The account has upstream provenance + NULL password.
    let (auth_source, password_hash, is_admin) =
        user_row(&srv.pool, UP_USER).await.expect("the account");
    assert_eq!(auth_source, "upstream-basic");
    assert!(
        password_hash.is_none(),
        "upstream user has no local password hash"
    );
    assert!(!is_admin);

    // A positive verdict was cached.
    let (total, positive) = verdict_counts(&srv.pool, UP_USER).await;
    assert_eq!((total, positive), (1, 1), "one positive verdict cached");

    // The upstream only sees the local part: another domain's name with the
    // same local part is accepted upstream but names no account.
    let other = format!("{UP_NAME}@other.example");
    assert_eq!(me_basic(&srv, &other, UP_PASS).await.status(), 401);
    assert_eq!(mock.hits(), 2, "forwarded as {UP_NAME}");
    assert!(user_row(&srv.pool, &other).await.is_none());
    // A name that is no UPN names no account and is not forwarded.
    assert_eq!(me_basic(&srv, UP_NAME, UP_PASS).await.status(), 401);
    assert_eq!(mock.hits(), 2, "never forwarded");
}

// ── 2. wrong password → 401, no user, negative cached ────────────────────────

#[tokio::test]
async fn wrong_password_is_rejected_and_negatively_cached() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;

    let resp = me_basic(&srv, UP_USER, "wrong-password").await;
    assert_eq!(resp.status(), 401, "wrong password rejected");
    assert_eq!(mock.hits(), 1, "the bad credential was forwarded once");

    let (total, positive) = verdict_counts(&srv.pool, UP_USER).await;
    assert_eq!(
        (total, positive),
        (1, 0),
        "one negative verdict cached, no positive"
    );
}

// ── 3. cache hit avoids a second upstream call ───────────────────────────────

#[tokio::test]
async fn second_identical_request_served_from_cache() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;

    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(mock.hits(), 1, "first request forwards");

    // Same credential again, well within the 300s positive TTL.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(
        mock.hits(),
        1,
        "second identical request is a cache hit — no extra upstream call"
    );
}

// ── 4. cache TTL expiry forces a re-check ────────────────────────────────────

#[tokio::test]
async fn ttl_expiry_triggers_a_recheck() {
    // Short positive TTL, but with headroom: two debug-build round-trips take
    // ~1s on a busy CI runner (the suite runs its stacks in parallel), so a 1s
    // TTL could lapse before the "still cached" request lands.
    const TTL: std::time::Duration = std::time::Duration::from_secs(5);
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, TTL.as_secs(), 30, &[], "").await;
    create_account(&srv, UP_USER).await;

    // The verdict is written during this request, so it expires somewhere in
    // (sent + TTL, answered + TTL].
    let sent = tokio::time::Instant::now();
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    let answered = tokio::time::Instant::now();
    assert_eq!(mock.hits(), 1, "first request forwards");

    // A back-to-back request is still cached.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert!(
        sent.elapsed() < TTL,
        "second request must land before the TTL could have lapsed"
    );
    assert_eq!(mock.hits(), 1, "still cached pre-expiry");

    // After the TTL lapses the cached verdict is stale → re-forward.
    tokio::time::sleep_until(answered + TTL + std::time::Duration::from_millis(500)).await;
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(
        mock.hits(),
        2,
        "an expired positive verdict triggers a fresh upstream call"
    );
}

// ── 5. provider ordering: a local user never hits the upstream ───────────────

#[tokio::test]
async fn local_user_authenticates_without_hitting_upstream() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    let (admin_u, admin_p) = srv.admin_basic();

    // Create a *local* (password) user via the admin API.
    srv.create_user("local-bob@example.com", "bobpw-e2e-local")
        .await;
    let hits_before = mock.hits();

    // local-bob authenticates via the FIRST provider (local-password); since the
    // chain stops at the first Authenticated, the upstream is never consulted.
    let resp = me_basic(&srv, "local-bob@example.com", "bobpw-e2e-local").await;
    assert_eq!(resp.status(), 200, "local user authenticates");
    assert_eq!(
        mock.hits(),
        hits_before,
        "local-password short-circuits the chain — no upstream forward"
    );

    // And the bootstrap admin (also local) likewise never touches the upstream.
    let resp = me_basic(&srv, &admin_u, &admin_p).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(mock.hits(), hits_before, "bootstrap admin stays local");
}

// ── 6. upstream down → fail closed; cached positive still works ──────────────

#[tokio::test]
async fn upstream_outage_fails_closed_but_cached_positive_survives() {
    // Long positive TTL so a pre-outage success stays cached across the outage.
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;

    // Warm a positive verdict for UP_USER while the upstream is healthy.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(mock.hits(), 1);

    // Take the upstream down.
    mock.set_down(true);

    // A user with NO cached verdict cannot be validated → fail-closed 401.
    let resp = me_basic(&srv, "never-seen-user@example.com", "whatever").await;
    assert_eq!(
        resp.status(),
        401,
        "an uncached credential during an outage is denied (fail closed)"
    );
    assert!(
        user_row(&srv.pool, "never-seen-user@example.com")
            .await
            .is_none(),
        "fail-closed grants nothing"
    );
    // The outage (503) is never negatively cached.
    let (total, _) = verdict_counts(&srv.pool, "never-seen-user@example.com").await;
    assert_eq!(total, 0, "an outage caches nothing (positive or negative)");

    // The previously-cached positive for UP_USER still authenticates within TTL.
    let resp = me_basic(&srv, UP_USER, UP_PASS).await;
    assert_eq!(
        resp.status(),
        200,
        "a cached positive survives the outage within its TTL"
    );
}

// ── 7. plaintext password is never stored ────────────────────────────────────

#[tokio::test]
async fn plaintext_password_never_stored() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;

    // One success + one failure, so both a positive and a negative row exist.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(
        me_basic(&srv, UP_USER, "totally-wrong-pw").await.status(),
        401
    );

    // Dump every text-ish column of validated_credential and assert the
    // plaintext appears nowhere (the cache key is an HMAC, hex-encoded).
    let rows = sqlx::query_as::<_, (String, String, String, bool)>(
        "SELECT provider_id, username, cred_hmac, verdict FROM validated_credential",
    )
    .fetch_all(&srv.pool)
    .await
    .expect("dump validated_credential");
    assert!(!rows.is_empty(), "there are cached verdicts to inspect");
    for (provider, username, cred_hmac, _verdict) in &rows {
        assert!(
            !provider.contains(UP_PASS)
                && !username.contains(UP_PASS)
                && !cred_hmac.contains(UP_PASS)
                && !cred_hmac.contains("totally-wrong-pw"),
            "no plaintext password in validated_credential row \
             (provider={provider}, username={username}, cred_hmac={cred_hmac})"
        );
        // The HMAC-SHA256 hex is exactly 64 chars and is not the password.
        assert_eq!(cred_hmac.len(), 64, "cred_hmac is a hex SHA256 digest");
        assert_ne!(cred_hmac, UP_PASS);
    }

    // The app_user likewise has no plaintext (NULL password_hash).
    let (_src, password_hash, _admin) = user_row(&srv.pool, UP_USER).await.expect("the account");
    assert!(
        password_hash.is_none(),
        "upstream user stores no password hash at all (NULL), let alone plaintext"
    );
}

// ── 8. reauth purges the cached verdict ──────────────────────────────────────

#[tokio::test]
async fn reauth_forces_a_reforward() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;
    let (admin_u, admin_p) = srv.admin_basic();

    // Warm a positive verdict.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(mock.hits(), 1, "second request was a cache hit");

    let user_id = sqlx::query_scalar::<_, i64>("SELECT id FROM app_user WHERE username = $1")
        .bind(UP_USER)
        .fetch_one(&srv.pool)
        .await
        .expect("the account's id");

    // Admin forces re-auth: purges the cached verdict + broadcasts invalidation.
    let resp = srv
        .client()
        .post(format!("{}/admin/users/{user_id}/reauth", srv.base_url))
        .basic_auth(&admin_u, Some(&admin_p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "reauth returns 204");

    // The verdict rows for the user are gone.
    let (total, _) = verdict_counts(&srv.pool, UP_USER).await;
    assert_eq!(total, 0, "reauth purged the cached verdict rows");

    // The next request re-forwards to the upstream (a fresh hit).
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(
        mock.hits(),
        2,
        "after reauth the next request re-validates upstream"
    );
}

// ── 8b. reauth is admin-only ──────────────────────────────────────────────────

#[tokio::test]
async fn reauth_requires_admin() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;

    // The upstream (non-admin) user signs in.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    let user_id = sqlx::query_scalar::<_, i64>("SELECT id FROM app_user WHERE username = $1")
        .bind(UP_USER)
        .fetch_one(&srv.pool)
        .await
        .expect("the account's id");

    // The upstream user is NOT an admin → forbidden from the admin reauth action.
    let resp = srv
        .client()
        .post(format!("{}/admin/users/{user_id}/reauth", srv.base_url))
        .basic_auth(UP_USER, Some(UP_PASS))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin cannot force reauth");
}

// ── 9. required_groups gate rejects despite a valid password ─────────────────

#[tokio::test]
async fn required_group_gate_rejects_valid_password_without_group() {
    // The upstream knows TWO users: one in `nuget-users`, one without it.
    let mock = MockBasicUpstream::start(vec![
        ("in-group", "pw1", vec!["nuget-users", "dev"]),
        ("out-group", "pw2", vec!["dev"]),
    ])
    .await;
    // Gate on `nuget-users`.
    let srv = start_credforward_stack(&mock, 300, 30, &["nuget-users"], "").await;
    create_account(&srv, "in-group@example.com").await;
    create_account(&srv, "out-group@example.com").await;

    // The in-group user is accepted.
    let resp = me_basic(&srv, "in-group@example.com", "pw1").await;
    assert_eq!(
        resp.status(),
        200,
        "user with the required group is accepted"
    );

    // The out-of-group user is rejected DESPITE a valid upstream password.
    let resp = me_basic(&srv, "out-group@example.com", "pw2").await;
    assert_eq!(
        resp.status(),
        401,
        "valid password but missing required group → rejected"
    );
}

// ── 9b. admin_group maps to is_admin on login ────────────────────────────────

#[tokio::test]
async fn admin_group_grants_admin_on_login() {
    let mock = MockBasicUpstream::start(vec![
        ("up-admin", "apw", vec!["nx-admin", "dev"]),
        ("up-plain", "ppw", vec!["dev"]),
    ])
    .await;
    // No required gate, but map the `nx-admin` upstream group to forge admin.
    let srv = start_credforward_stack(&mock, 300, 30, &[], "nx-admin").await;
    create_account(&srv, "up-admin@example.com").await;
    create_account(&srv, "up-plain@example.com").await;

    assert_eq!(
        me_basic(&srv, "up-admin@example.com", "apw").await.status(),
        200
    );
    let (_src, _ph, is_admin) = user_row(&srv.pool, "up-admin@example.com")
        .await
        .expect("the account");
    assert!(
        is_admin,
        "the admin_group mapping granted is_admin on login"
    );

    assert_eq!(
        me_basic(&srv, "up-plain@example.com", "ppw").await.status(),
        200
    );
    let (_src, _ph, is_admin) = user_row(&srv.pool, "up-plain@example.com")
        .await
        .expect("the account");
    assert!(!is_admin, "a user without the admin group is not an admin");
}

// ── 10. scale-out: cross-instance reauth invalidates the peer's cache ────────

#[tokio::test]
async fn cross_instance_reauth_invalidates_peer_cache() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let block = mock.upstream_basic_block(&["local-password", "upstream-basic"], 300, 30, &[], "");
    // Two instances sharing the same Postgres (the authoritative
    // validated_credential store) + the same upstream block. Redis (L2 + the
    // pub/sub backplane) is required so a reauth on A drops B's in-process L1
    // entry — without the backplane B would keep serving its own cached verdict
    // until its TTL lapsed.
    let srv_a = StackBuilder::default()
        .bootstrap_admin("root@example.com", "rootpw")
        .with_redis()
        .with_upstream_basic(block.clone())
        .start()
        .await;
    let srv_b = srv_a.spawn_peer_with_upstream_basic(block).await;
    let (admin_u, admin_p) = srv_a.admin_basic();
    create_account(&srv_a, UP_USER).await;

    // Authenticate on A (warms a positive verdict in the shared table).
    assert_eq!(me_basic(&srv_a, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(mock.hits(), 1, "A forwarded once");

    // B serves the SAME credential from the shared cache — no extra forward.
    assert_eq!(me_basic(&srv_b, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(
        mock.hits(),
        1,
        "B reads the shared validated_credential — no second forward"
    );

    // Admin forces reauth on A; the shared row is deleted + invalidation fires.
    let user_id = sqlx::query_scalar::<_, i64>("SELECT id FROM app_user WHERE username = $1")
        .bind(UP_USER)
        .fetch_one(&srv_a.pool)
        .await
        .expect("the account's id");
    let resp = srv_a
        .client()
        .post(format!("{}/admin/users/{user_id}/reauth", srv_a.base_url))
        .basic_auth(&admin_u, Some(&admin_p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "reauth on A succeeds");

    // The backplane pub/sub drop of B's L1 entry is asynchronous; give the
    // subscriber a moment to apply it before asserting B re-forwards.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // The next request on B must re-forward (its cached verdict is invalidated).
    assert_eq!(me_basic(&srv_b, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(
        mock.hits(),
        2,
        "B re-forwards after the cross-instance reauth invalidation"
    );
}

// ── 11. SSO redirect is never a valid verdict ─────────────────────────────────

#[tokio::test]
async fn redirecting_upstream_fails_closed() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, "sso-victim@example.com").await;
    mock.set_redirect(true);

    let resp = me_basic(&srv, "sso-victim@example.com", "any-password-at-all").await;
    assert_eq!(
        resp.status(),
        401,
        "a 302 to a 200 login page must not authenticate"
    );
    assert_eq!(mock.hits(), 1, "the credential was forwarded once");
    assert_eq!(
        mock.login_page_hits(),
        0,
        "the redirect is not followed (the password never reaches the login page)"
    );
    let (total, _) = verdict_counts(&srv.pool, "sso-victim@example.com").await;
    assert_eq!(
        total, 0,
        "a redirect is treated as unavailable: nothing cached"
    );
}

/// `PATCH /admin/users/{id}` as the stack's bootstrap admin.
async fn set_active(srv: &TestServer, user_id: i64, active: bool) -> reqwest::Response {
    let (admin_u, admin_p) = srv.admin_basic();
    srv.client()
        .patch(format!("{}/admin/users/{user_id}", srv.base_url))
        .basic_auth(&admin_u, Some(&admin_p))
        .json(&serde_json::json!({ "active": active }))
        .send()
        .await
        .unwrap()
}

async fn user_id(pool: &sqlx::PgPool, username: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT id FROM app_user WHERE username = $1")
        .bind(username)
        .fetch_one(pool)
        .await
        .expect("the account's id")
}

// ── 12. deactivation cuts a federated user off ────────────────────────────────

#[tokio::test]
async fn deactivated_upstream_user_is_cut_off_and_not_resurrected() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;

    // Warm a positive verdict (and a browser session).
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    let resp = srv
        .client()
        .post(format!("{}/auth/login", srv.base_url))
        .json(&serde_json::json!({ "username": UP_USER, "password": UP_PASS }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "browser login works before deactivation"
    );
    let id = user_id(&srv.pool, UP_USER).await;
    assert_eq!(verdict_counts(&srv.pool, UP_USER).await.1, 1);

    let resp = set_active(&srv, id, false).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        verdict_counts(&srv.pool, UP_USER).await.0,
        0,
        "deactivation purges the user's cached verdicts"
    );
    let live_sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM session WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(live_sessions, 0, "deactivation revokes the user's sessions");

    // The upstream still accepts the password, but forge refuses the account.
    let hits_before = mock.hits();
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 401);
    assert_eq!(
        mock.hits(),
        hits_before + 1,
        "the purged verdict forced a fresh upstream validation"
    );
    let resp = srv
        .client()
        .post(format!("{}/auth/login", srv.base_url))
        .json(&serde_json::json!({ "username": UP_USER, "password": UP_PASS }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "no browser session for a deactivated user"
    );
    let active: bool = sqlx::query_scalar("SELECT active FROM app_user WHERE id = $1")
        .bind(id)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert!(
        !active,
        "a valid upstream login must not reactivate the account"
    );

    // Reactivation lets the user back in.
    assert_eq!(set_active(&srv, id, true).await.status(), 200);
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
}

// ── 13. deleting a user purges its cached verdicts ────────────────────────────

#[tokio::test]
async fn delete_user_purges_cached_verdicts() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;
    let (admin_u, admin_p) = srv.admin_basic();

    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(verdict_counts(&srv.pool, UP_USER).await.1, 1);
    let id = user_id(&srv.pool, UP_USER).await;

    let resp = srv
        .client()
        .delete(format!("{}/admin/users/{id}", srv.base_url))
        .basic_auth(&admin_u, Some(&admin_p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(
        verdict_counts(&srv.pool, UP_USER).await.0,
        0,
        "no cached verdict outlives the deleted account"
    );

    // The next login re-validates upstream, and signs in nothing: the realm
    // does not re-create the account.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 401);
    assert_eq!(mock.hits(), 2, "the deleted user's verdict was not reused");
    assert!(user_row(&srv.pool, UP_USER).await.is_none());
}

// ── 14. a realm edit retires the verdicts cached under the old config ────────

#[tokio::test]
async fn realm_edit_retires_cached_verdicts() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec!["dev"])]).await;
    let srv = start_credforward_stack(&mock, 300, 30, &[], "").await;
    create_account(&srv, UP_USER).await;
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 200);
    assert_eq!(mock.hits(), 1);

    // Tighten the realm: only `nuget-users` may sign in.
    let (admin_u, admin_p) = srv.admin_basic();
    let realms: Vec<Value> = srv
        .client()
        .get(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin_u, Some(&admin_p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let realm = realms
        .iter()
        .find(|r| r["kind"] == "credential_forwarding")
        .expect("the imported credential-forwarding realm");
    let mut config = realm["config"].clone();
    config["groups_path"] = serde_json::json!("roles");
    config["required_groups"] = serde_json::json!(["nuget-users"]);
    let resp = srv
        .client()
        .patch(format!("{}/admin/realms/{}", srv.base_url, realm["id"]))
        .basic_auth(&admin_u, Some(&admin_p))
        .json(&serde_json::json!({ "config": config }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    // The verdict cached under the old policy (300 s left) no longer counts:
    // the credential is re-checked under the new one and refused.
    assert_eq!(me_basic(&srv, UP_USER, UP_PASS).await.status(), 401);
    assert_eq!(mock.hits(), 2, "re-forwarded under the edited realm");
}

// ── 15. an upstream demotion takes effect at once ───────────────────────────

#[tokio::test]
async fn upstream_demotion_drops_admin_and_ends_sessions_at_once() {
    const TTL: std::time::Duration = std::time::Duration::from_secs(2);
    let mock = MockBasicUpstream::start(vec![("up-admin", "apw", vec!["nx-admin"])]).await;
    let block = mock.upstream_basic_block(
        &["local-password", "upstream-basic"],
        TTL.as_secs(),
        1,
        &[],
        "nx-admin",
    );
    // A long authorization-cache TTL: only an explicit invalidation can make
    // the demotion visible within this test.
    let srv = StackBuilder::default()
        .bootstrap_admin("root@example.com", "rootpw")
        .with_upstream_basic(block)
        .cache_ttl_seconds(300)
        .start()
        .await;
    create_account(&srv, "up-admin@example.com").await;
    assert_eq!(
        srv.create_repo(serde_json::json!({
            "name": "locked", "kind": "hosted", "anonymous_read": false
        }))
        .await
        .status(),
        201
    );
    let read_locked = || async {
        srv.client()
            .get(format!("{}/repository/locked/index.json", srv.base_url))
            .basic_auth("up-admin@example.com", Some("apw"))
            .send()
            .await
            .unwrap()
            .status()
    };

    // An upstream admin: a browser session, and the feed via Basic (warming
    // the cached authorization set with admin).
    let login = srv
        .client()
        .post(format!("{}/auth/login", srv.base_url))
        .json(&serde_json::json!({ "username": "up-admin@example.com", "password": "apw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    let cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(read_locked().await, 200, "an admin reads every repository");
    let session_alive = || async {
        srv.client()
            .get(format!("{}/auth/me", srv.base_url))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .status()
            == 200
    };
    assert!(session_alive().await);

    // The upstream drops the admin group; once the verdict expires the next
    // request re-forwards and sees it.
    mock.set_groups("up-admin", &["dev"]);
    tokio::time::sleep(TTL + std::time::Duration::from_millis(500)).await;
    let status = read_locked().await;
    assert!(
        status.is_client_error(),
        "the demoting request itself is no longer an admin's ({status})"
    );
    let (_src, _ph, is_admin) = user_row(&srv.pool, "up-admin@example.com").await.unwrap();
    assert!(!is_admin);
    assert!(
        !session_alive().await,
        "the session opened as an admin is ended"
    );
}
