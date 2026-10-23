//! E2E: the auth-realm surface — login options, identifier-first
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
        .json(&json!({ "username": admin, "password": srv.admin_pass.as_deref().unwrap() }))
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
    // source independent of OIDC).
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "session cookie reaches the admin API");

    // Every cookie-authenticated mutation needs the CSRF token, whichever
    // router family serves it (admin API, self-service tokens, /v3 dispatch).
    for (method, path) in [
        (reqwest::Method::POST, "/admin/roles"),
        (reqwest::Method::POST, "/admin/me/tokens"),
        (reqwest::Method::DELETE, "/admin/tokens/999999"),
        (reqwest::Method::PUT, "/v3/no-such-repo/package"),
    ] {
        let resp = client
            .request(method.clone(), format!("{}{path}", srv.base_url))
            .header("cookie", &cookie)
            .json(&json!({ "name": format!("csrf{}", common::unique()) }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{method} {path} without csrf");
    }
    // With the token the same self-service mutation goes through.
    let resp = client
        .post(format!("{}/admin/me/tokens", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({ "name": "with-csrf" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "csrf-bearing mutation accepted");
    // …but not as a form post (JSON content type required).
    let resp = client
        .post(format!("{}/admin/me/tokens", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("name=form")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 415);
    // Basic-authenticated mutations are exempt (not an ambient credential).
    let resp = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "name": format!("basic{}", common::unique()), "description": "" }))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 403, "basic auth needs no csrf token");

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

/// B3: an oversized username is a uniform 401 that never reaches the chain or
/// the lockout map (which used to pin every presented username in memory).
#[tokio::test]
async fn oversized_login_username_is_refused_without_growing_the_lockout_map() {
    let srv = common::start().await;
    let client = srv.client();
    let login = format!("{}/auth/login", srv.base_url);

    let huge = "x".repeat(64 * 1024);
    for _ in 0..3 {
        let resp = client
            .post(&login)
            .json(&json!({ "username": huge, "password": "pw" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(resp.text().await.unwrap(), "invalid credentials");
    }
    assert_eq!(
        srv.state.login_throttle.tracked(),
        0,
        "oversized usernames never enter the lockout map"
    );

    // A normal-sized failed attempt is tracked (the measurement is live).
    let resp = client
        .post(&login)
        .json(&json!({ "username": format!("ghost{}", common::unique()), "password": "pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(srv.state.login_throttle.tracked(), 1);
}

/// Review 2026-10-20 M2: a `:` in the form-login username is never forwarded.
/// The upstream would split `mallory:abc` / `def` into `mallory` / `abc:def`
/// (RFC 7617) and vouch for Mallory, while Forge signed in the account
/// `mallory:abc@example.com`, getting around her deactivation.
#[tokio::test]
async fn form_login_with_a_colon_is_not_forwarded() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // The upstream knows her by the local part of her account's name.
    let local = format!("mallory{}", common::unique());
    let mallory = format!("{local}@example.com");
    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        let raw = format!("{user}:{password}");
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    };
    // Mallory's real upstream password is `abc:def`. Only her own login
    // below may reach the upstream.
    Mock::given(method("GET"))
        .and(path("/status"))
        .and(header("authorization", basic(&local, "abc:def").as_str()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .expect(0)
        .mount(&upstream)
        .await;

    // Its own database: an enabled forwarding realm would join the login
    // chains of every other test sharing one.
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let login = format!("{}/auth/login", srv.base_url);

    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "credential_forwarding",
            "name": "nexus",
            "config": {
                "url": format!("{}/status", upstream.uri()),
                "key_pepper": "pepper",
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "username": mallory, "realm": "nexus" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    // The realm is live: Mallory signs in to her account...
    let resp = client
        .post(&login)
        .json(&json!({ "username": mallory, "password": "abc:def" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let me: Value = resp.json().await.unwrap();
    let mallory_id = me["user_id"].as_i64().unwrap();

    // ...and is then deactivated.
    let resp = client
        .patch(format!("{}/admin/users/{mallory_id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "active": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let tracked = srv.state.login_throttle.tracked();
    let alias = format!("{local}:abc@example.com");
    let resp = client
        .post(&login)
        .json(&json!({ "username": alias, "password": "def" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(resp.text().await.unwrap(), "invalid credentials");
    assert!(
        forge_db::user_dao::find_user_by_username(&srv.pool, &alias)
            .await
            .unwrap()
            .is_none(),
        "no alias account is created"
    );
    assert_eq!(
        srv.state.login_throttle.tracked(),
        tracked,
        "the refused name never enters the lockout map"
    );
    // `upstream` drops at end of test and verifies that only Mallory's own
    // login was forwarded.
}

/// A locked (IP, username) pair is a 429 whose `Retry-After` is the failure
/// window, so the sign-in page can say how long to wait.
#[tokio::test]
async fn login_lockout_is_429_with_retry_after() {
    let srv = common::start().await;
    let client = srv.client();
    let login = format!("{}/auth/login", srv.base_url);
    let username = format!("ghost{}@example.com", common::unique());

    let max = srv.state.config.auth.login_max_failures;
    for _ in 0..max {
        let resp = client
            .post(&login)
            .json(&json!({ "username": username, "password": "pw" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }
    let resp = client
        .post(&login)
        .json(&json!({ "username": username, "password": "pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let retry_after = resp
        .headers()
        .get("retry-after")
        .expect("Retry-After on a lockout")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        retry_after,
        srv.state
            .config
            .auth
            .login_failure_window_seconds
            .to_string()
    );
}

/// `/admin/realms` CRUD: the seeded local realm is listed and protected,
/// secrets are write-only (redacted to `<key>_set` markers), invalid configs
/// are 400, and reorder demands the complete id set. Its own database, since
/// the reorder rewrites every realm's row, also the ones other tests hold.
#[tokio::test]
async fn admin_realm_crud_with_write_only_secrets() {
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
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

    // Valid create → 201; the secret comes back redacted. Created disabled:
    // the tests of this binary share one database, and an enabled realm for
    // an unresolvable upstream would join their login chains, turning their
    // failed logins into uncounted outages (the lockout tests then saw 401
    // instead of 429).
    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "credential_forwarding",
            "name": name,
            "enabled": false,
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

/// An `oidc` realm with `client_authentication = "federated_credential"`
/// needs no client secret: forge publishes itself as the OIDC issuer of its
/// client assertions (created with the realm), and the realm shows what the
/// IdP's federated credential must name.
#[tokio::test]
async fn a_federated_credential_realm_needs_no_secret_and_publishes_the_issuer() {
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let discovery_url = format!("{}/.well-known/openid-configuration", srv.base_url);

    // Forge has signed nothing yet: no issuer.
    let resp = client.get(&discovery_url).send().await.unwrap();
    assert_eq!(resp.status(), 404);

    let issuer = "https://login.microsoftonline.com/tenant-id/v2.0";
    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "oidc",
            "name": format!("entra{}", common::unique()),
            "enabled": false,
            "config": {
                "issuer": issuer,
                "client_id": "app-id",
                "client_authentication": "federated_credential",
                // Not kept: nothing would send it.
                "client_secret": "unused",
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: Value = resp.json().await.unwrap();
    let realm_id = created["id"].as_i64().unwrap();
    assert_eq!(created["config"]["client_secret_set"], json!(false));
    assert_eq!(
        created["config"]["client_authentication"],
        json!("federated_credential")
    );
    assert_eq!(
        created["federated_credential"],
        json!({
            "issuer": "http://test.local",
            "subject": format!("app-id@{issuer}"),
            "audience": "api://AzureADTokenExchange",
        })
    );

    // Saving the realm published the issuer, unauthenticated.
    let resp = client.get(&discovery_url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("public")));
    let discovery: Value = resp.json().await.unwrap();
    assert_eq!(discovery["issuer"], json!("http://test.local"));
    assert_eq!(
        discovery["jwks_uri"],
        json!("http://test.local/.well-known/jwks.json")
    );
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        json!(["RS256"])
    );
    let jwks: Value = client
        .get(format!("{}/.well-known/jwks.json", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys = jwks["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], json!("RSA"));
    assert_eq!(keys[0]["use"], json!("sig"));
    assert_eq!(keys[0]["alg"], json!("RS256"));
    assert!(keys[0].get("d").is_none(), "public parts only");

    // A sovereign cloud's audience.
    let resp = client
        .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "config": {
                "issuer": issuer,
                "client_id": "app-id",
                "client_authentication": "federated_credential",
                "assertion_audience": " api://AzureADTokenExchangeUSGov ",
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: Value = resp.json().await.unwrap();
    assert_eq!(
        updated["federated_credential"]["audience"],
        json!("api://AzureADTokenExchangeUSGov")
    );

    // Back to a client secret: one must be supplied.
    let secret_config = json!({ "issuer": issuer, "client_id": "app-id" });
    let resp = client
        .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "config": secret_config }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let mut with_secret = secret_config.clone();
    with_secret["client_secret"] = json!("s3cret");
    let resp = client
        .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "config": with_secret }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: Value = resp.json().await.unwrap();
    assert_eq!(updated["config"]["client_secret_set"], json!(true));
    assert!(updated.get("federated_credential").is_none(), "{updated}");
    assert!(updated["config"].get("client_authentication").is_none());

    let resp = client
        .delete(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// Instances share the issuer keys: the first creates them, the others pick
/// them up, and a due rotation is done once (compare-and-swap) and then
/// published by every instance before the new key signs.
#[tokio::test]
async fn instances_share_and_rotate_the_issuer_keys() {
    use forge_core::oidc::assertion::{IssuerKeySet, KEY_ACTIVATION, KEY_ROTATION};
    use forge_server::auth::{AssertionIssuer, ISSUER_KEYS_SETTING};

    let pool = common::fresh_pool().await;
    let a = AssertionIssuer::new(pool.clone(), None, "https://forge.test/".into());
    let b = AssertionIssuer::new(pool.clone(), None, "https://forge.test".into());
    assert_eq!(a.issuer(), "https://forge.test");
    let kids = |keys: &IssuerKeySet| {
        keys.keys()
            .iter()
            .map(|k| k.kid().to_string())
            .collect::<Vec<_>>()
    };

    assert!(a.published().await.unwrap().is_none());
    let created = a.ensure().await.unwrap();
    // `b` asked recently and found nothing: it asks again after a moment.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let seen = b.published().await.unwrap().expect("b sees a's keys");
    assert_eq!(kids(&created), kids(&seen));
    assert_eq!(kids(&b.ensure().await.unwrap()), kids(&created));

    // Age the stored keys past a rotation.
    let stored = forge_db::authz_dao::get_setting(&pool, ISSUER_KEYS_SETTING)
        .await
        .unwrap()
        .expect("stored keys");
    let old = IssuerKeySet::generate(chrono::Utc::now() - KEY_ROTATION).unwrap();
    forge_db::secret_dao::store_secret_setting(
        &pool,
        None,
        ISSUER_KEYS_SETTING,
        &forge_crypto::PlaintextSecret::from(old.to_stored()),
        Some(&stored),
    )
    .await
    .unwrap()
    .expect("replaced");

    a.refresh().await.unwrap();
    let rotated = a.published().await.unwrap().unwrap();
    assert_eq!(
        rotated.keys().len(),
        2,
        "a fresh key in front of the old one"
    );
    assert_eq!(rotated.keys()[1].kid(), old.keys()[0].kid());
    // The new key is published, but the old one signs until it is old enough.
    let now = chrono::Utc::now();
    assert_eq!(rotated.signing_key(now).kid(), old.keys()[0].kid());
    assert_eq!(
        rotated.signing_key(now + KEY_ACTIVATION).kid(),
        rotated.keys()[0].kid()
    );

    // `b` rotates nothing more: it picks up `a`'s rotation.
    b.refresh().await.unwrap();
    assert_eq!(kids(&b.published().await.unwrap().unwrap()), kids(&rotated));
    a.refresh().await.unwrap();
    assert_eq!(kids(&a.published().await.unwrap().unwrap()), kids(&rotated));
}

/// #71: an API token Forge issued is never tried as a password, even when it
/// cannot be used (its owner is deactivated, it expired or was revoked): a
/// credential-forwarding realm would send the live secret upstream on every
/// request of a client that still stores it. The same holds for a token
/// pasted into the web login form.
#[tokio::test]
async fn an_unusable_token_sent_as_the_basic_password_is_never_forwarded() {
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&upstream)
        .await;

    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "credential_forwarding",
            "name": "nexus",
            "config": {"url": format!("{}/status", upstream.uri()), "key_pepper": "pepper"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    // A forwarded (password-less) account of the realm that owns three tokens.
    let realm = forge_db::auth_realm_dao::find_realm_by_name(&srv.pool, "nexus")
        .await
        .unwrap()
        .expect("the realm");
    let username = format!("fed{}@example.com", common::unique());
    let user = forge_db::user_dao::insert_forwarded_user(&srv.pool, &username, realm.id, true)
        .await
        .unwrap();
    let mint = |expires_at: Option<chrono::DateTime<chrono::Utc>>| {
        let pool = srv.pool.clone();
        async move {
            let secret = forge_core::auth::generate_token_secret();
            let token = forge_db::token_dao::insert_token(
                &pool,
                forge_db::token_dao::NewToken {
                    user_id: user.id,
                    name: "ci".into(),
                    token_hash: forge_core::auth::hash_token(&secret),
                    expires_at,
                    minted_with_forwarded_credential: false,
                },
            )
            .await
            .unwrap();
            (secret, token.id)
        }
    };
    let (live, _) = mint(None).await;
    let (expired, _) = mint(Some(chrono::Utc::now() - chrono::Duration::hours(1))).await;
    let (revoked, revoked_id) = mint(None).await;
    forge_db::token_dao::revoke_token(&srv.pool, revoked_id)
        .await
        .unwrap();

    let feed = format!("{}/admin/me", srv.base_url);
    let get = |secret: String| {
        let client = client.clone();
        let username = username.clone();
        let feed = feed.clone();
        async move {
            client
                .get(&feed)
                .basic_auth(&username, Some(&secret))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    // The web login form refuses a token as the password, live or not, and
    // forwards none of them either.
    for secret in [&live, &expired, &revoked] {
        let resp = client
            .post(format!("{}/auth/login", srv.base_url))
            .json(&json!({ "username": username, "password": secret }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "a token is no password");
    }
    assert_ne!(get(live.clone()).await, 401, "the live token signs in");
    assert_eq!(get(expired).await, 401);
    assert_eq!(get(revoked).await, 401);

    let resp = client
        .patch(format!("{}/admin/users/{}", srv.base_url, user.id))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "active": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(get(live).await, 401, "a deactivated owner's token");
    // Dropping `upstream` verifies it received no request.
}

/// A credential-forwarding realm that fails to build makes no upstream call,
/// so the local provider in front of it must equalize an unknown username's
/// timing with the dummy argon2 verification itself. Before, it skipped
/// unknown names whenever a forwarding realm was *enabled*, so they were
/// answered at once while known names took a full verification. A limiter
/// with no free slot shows whether a verification was attempted: it answers
/// unavailable instead of skipping.
#[tokio::test]
async fn unknown_names_pay_the_dummy_hash_while_the_forwarding_realm_is_broken() {
    use figment::providers::Format as _;
    use forge_core::auth::{ChainOutcome, PasswordCredential, PasswordHashLimiter};
    use std::sync::Arc;

    let pool = common::fresh_pool().await;
    let config: forge_server::config::Config = forge_server::config::Config::from_figment(
        figment::Figment::new().merge(figment::providers::Toml::string(
            r#"
            [server]
            bind = "127.0.0.1:0"
            public_base_url = "http://test.local"
            [database]
            url = "postgres://forge:forge@localhost/forge"
            [s3]
            endpoint = "http://localhost:7070"
            bucket = "forge"
            access_key = "test"
            secret_key = "test"
            "#,
        )),
    )
    .expect("valid config");
    // Enabled after `local`, but plain http to a non-loopback host without
    // `allow_http`: the snapshot skips it (fail closed).
    let priority = forge_db::auth_realm_dao::next_priority(&pool)
        .await
        .unwrap();
    forge_db::auth_realm_dao::insert_realm(
        &pool,
        forge_db::auth_realm_dao::NewAuthRealm {
            kind: "credential_forwarding".into(),
            name: "broken-forward".into(),
            enabled: true,
            priority,
            config: json!({"url": "http://nexus.invalid/status", "key_pepper": "p"}),
        },
    )
    .await
    .expect("insert realm");

    let no_slot = Arc::new(PasswordHashLimiter::from_semaphore(
        Arc::new(tokio::sync::Semaphore::new(0)),
        std::time::Duration::from_millis(10),
    ));
    let issuer =
        forge_server::auth::AssertionIssuer::new(pool.clone(), None, config.public_base_url());
    let realms = forge_server::auth::RealmAuth::new(
        pool.clone(),
        forge_cache::Cache::l1_only(100),
        Arc::new(config),
        issuer,
    )
    .with_password_limiter(no_slot);
    let snapshot = realms.snapshot().await.expect("snapshot");
    let chain = snapshot.chain.as_ref().expect("local realm");
    assert_eq!(chain.provider_ids().len(), 1, "{:?}", chain.provider_ids());

    let outcome = chain
        .authenticate(&PasswordCredential {
            username: &format!("nobody-{}", common::unique()),
            password: "whatever",
            client_ip: "127.0.0.1".parse().unwrap(),
        })
        .await;
    assert!(
        matches!(outcome, ChainOutcome::Unavailable),
        "the dummy verification was not attempted: {outcome:?}"
    );
}

/// The last enabled realm people sign in with interactively (local or OIDC)
/// cannot be disabled or deleted: without one, every password and OIDC
/// login fails, and the admin UI is reachable again only with an
/// admin-scoped token or SQL. Its own database, since it disables `local`.
#[tokio::test]
async fn the_last_interactive_realm_cannot_be_disabled_or_deleted() {
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let realms_url = format!("{}/admin/realms", srv.base_url);
    let patch = |id: i64, body: Value| {
        client
            .patch(format!("{realms_url}/{id}"))
            .basic_auth(&admin, Some(&password))
            .json(&body)
            .send()
    };
    let realms: Vec<Value> = client
        .get(&realms_url)
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let local_id = realms.iter().find(|r| r["kind"] == "local").unwrap()["id"]
        .as_i64()
        .unwrap();

    // Only `local`: refused, and it stays enabled.
    let resp = patch(local_id, json!({"enabled": false})).await.unwrap();
    assert_eq!(resp.status(), 409);
    assert_eq!(
        resp.text().await.unwrap(),
        "no enabled realm to sign in with would remain (local or OIDC); enable another one first"
    );
    let local: Value = client
        .get(format!("{realms_url}/{local_id}"))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(local["enabled"], true);

    // A non-interactive realm does not count.
    let resp = client
        .post(&realms_url)
        .basic_auth(&admin, Some(&password))
        .json(&json!({"kind": "credential_forwarding", "name": "nexus",
                      "config": {"url": "https://nexus.invalid/status", "key_pepper": "p"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = patch(local_id, json!({"enabled": false})).await.unwrap();
    assert_eq!(resp.status(), 409);

    // With an enabled OIDC realm, `local` can be disabled...
    let resp = client
        .post(&realms_url)
        .basic_auth(&admin, Some(&password))
        .json(&json!({"kind": "oidc", "name": "entra", "config": {
            "issuer": "https://login.microsoftonline.com/tid/v2.0",
            "client_id": "cid",
            "client_secret": "shh",
        }}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let oidc_id = client
        .get(&realms_url)
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap()
        .json::<Vec<Value>>()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r["kind"] == "oidc")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let resp = patch(local_id, json!({"enabled": false})).await.unwrap();
    assert_eq!(resp.status(), 200);
    // ...and then the OIDC realm is the last one: neither disabled nor deleted.
    let resp = patch(oidc_id, json!({"enabled": false})).await.unwrap();
    assert_eq!(resp.status(), 409);
    let resp = client
        .delete(format!("{realms_url}/{oidc_id}"))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    // Other edits of it still work.
    let resp = patch(oidc_id, json!({"name": "entra-id"})).await.unwrap();
    assert_eq!(resp.status(), 200);

    // With `local` back on, the OIDC realm can go.
    let resp = patch(local_id, json!({"enabled": true})).await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .delete(format!("{realms_url}/{oidc_id}"))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// A PATCH merges its body over the realm it read and writes the whole row
/// back. A change committed in between (another admin's config edit, a
/// reorder) used to be overwritten silently; the write is now a
/// compare-and-set and the PATCH answers 409. Its own database: the lock wait
/// it waits for must be its own PATCH's, not another test's realm write.
#[tokio::test]
async fn a_realm_patch_never_undoes_a_concurrent_change() {
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let name = format!("nexus{}", common::unique());
    // Disabled: it must not join the shared database's login chain.
    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(
            &json!({"kind": "credential_forwarding", "name": name, "enabled": false,
                      "config": {"url": "https://nexus.invalid/status", "key_pepper": "p"}}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();

    // Hold the row so the PATCH, having read it, waits at its write...
    let mut other = srv.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_realm WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *other)
        .await
        .unwrap();
    let rename = tokio::spawn({
        let client = client.clone();
        let url = format!("{}/admin/realms/{id}", srv.base_url);
        let (admin, password) = (admin.clone(), password.clone());
        let renamed = format!("{name}-renamed");
        async move {
            let resp = client
                .patch(url)
                .basic_auth(&admin, Some(&password))
                .json(&json!({"name": renamed}))
                .send()
                .await
                .unwrap();
            (resp.status(), resp.text().await.unwrap())
        }
    });
    common::wait_for_lock_wait(&srv.pool, &["%UPDATE auth_realm SET%"]).await;
    // ...while another change of the realm commits.
    sqlx::query(
        "UPDATE auth_realm SET config = config || '{\"required_groups\": [\"forge\"]}', \
         updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *other)
    .await
    .unwrap();
    other.commit().await.unwrap();

    let (status, body) = rename.await.unwrap();
    assert_eq!(status, 409, "{body}");
    let realm: Value = client
        .get(format!("{}/admin/realms/{id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(realm["config"]["required_groups"], json!(["forge"]));
    assert_eq!(realm["name"], json!(name));
}

/// The realm ids a reorder must list, in their current order.
async fn realm_order(srv: &common::TestServer) -> Vec<i64> {
    let (admin, password) = srv.admin_basic();
    let realms: Vec<Value> = srv
        .client()
        .get(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    realms.iter().map(|r| r["id"].as_i64().unwrap()).collect()
}

/// Send `PUT /admin/realms/order` in the background.
fn spawn_reorder(
    srv: &common::TestServer,
    order: Vec<i64>,
) -> tokio::task::JoinHandle<(reqwest::StatusCode, String)> {
    let client = srv.client();
    let url = format!("{}/admin/realms/order", srv.base_url);
    let (admin, password) = srv.admin_basic();
    tokio::spawn(async move {
        let resp = client
            .put(url)
            .basic_auth(&admin, Some(&password))
            .json(&json!({ "order": order }))
            .send()
            .await
            .unwrap();
        (resp.status(), resp.text().await.unwrap())
    })
}

/// A realm created while a reorder runs used to take a priority the reorder
/// also assigned, and the reorder answered 500 at commit. The reorder now
/// waits for the create and answers 409 (its order no longer lists every
/// realm). Its own database: it locks the realm table.
#[tokio::test]
async fn a_reorder_racing_a_realm_create_answers_409() {
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let order = realm_order(&srv).await;

    // A realm create that has inserted but not committed...
    let mut create = srv.pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO auth_realm (kind, name, enabled, priority, config) \
         SELECT 'credential_forwarding', $1, false, max(priority) + 10, \
                '{\"url\": \"https://nexus.invalid/status\"}'::jsonb \
         FROM auth_realm",
    )
    .bind(format!("racer{}", common::unique()))
    .execute(&mut *create)
    .await
    .unwrap();
    // ...when the reorder of the realms it read starts.
    let reorder = spawn_reorder(&srv, order.clone());
    common::wait_for_lock_wait(&srv.pool, &["%LOCK TABLE auth_realm%"]).await;
    create.commit().await.unwrap();

    let (status, body) = reorder.await.unwrap();
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("reload"), "{body}");
    // Nothing was reordered, and a current order goes through.
    let now = realm_order(&srv).await;
    assert_eq!(now[..order.len()], order[..]);
    let (status, body) = spawn_reorder(&srv, now.into_iter().rev().collect())
        .await
        .unwrap();
    assert_eq!(status, 200, "{body}");
}

/// A reorder and a realm change that locks the interactive realms (as
/// disabling an OIDC realm does) used to deadlock, and PostgreSQL aborted the
/// reorder with a 500. The reorder now waits for the other change and then
/// applies. Its own database: it locks the realm table.
#[tokio::test]
async fn a_reorder_waits_for_a_realm_change_instead_of_deadlocking() {
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(
            &json!({"kind": "credential_forwarding", "name": format!("fwd{}", common::unique()),
                      "enabled": false,
                      "config": {"url": "https://nexus.invalid/status", "key_pepper": "p"}}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    let order: Vec<i64> = realm_order(&srv).await.into_iter().rev().collect();

    // Another change holds the interactive realms, as the last-realm guard
    // takes them, and is about to update a realm...
    let mut other = srv.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_realm WHERE kind IN ('local', 'oidc') ORDER BY id FOR UPDATE")
        .execute(&mut *other)
        .await
        .unwrap();
    let reorder = spawn_reorder(&srv, order.clone());
    common::wait_for_lock_wait(&srv.pool, &["%LOCK TABLE auth_realm%"]).await;
    // ...which it can still do while the reorder waits.
    sqlx::query("UPDATE auth_realm SET updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *other)
        .await
        .unwrap();
    other.commit().await.unwrap();

    let (status, body) = reorder.await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(realm_order(&srv).await, order);
}

/// A credential-forwarding realm that keeps password hashes
/// (`capture_password_hash`, migration 0035): an accepted login keeps one,
/// turning the option off deletes them, `captured_password_only` signs the
/// accounts in with them while the upstream is never asked, and the accounts
/// can then be switched to local ones that keep signing in with the same
/// password.
#[tokio::test]
async fn kept_password_hashes_carry_a_realm_past_its_upstream() {
    use wiremock::matchers::{any, header};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    };
    // The accounts' names; the upstream knows them by their local parts.
    let alice = format!("alice{}@example.com", common::unique());
    let bob = format!("bob{}@example.com", common::unique());
    let local = |user: &str| {
        forge_db::username::upn_local_part(user)
            .unwrap()
            .to_string()
    };
    let upstream = MockServer::start().await;
    let accepting = || async {
        for (user, password) in [(local(&alice), "alice-pw"), (local(&bob), "bob-pw")] {
            Mock::given(header("authorization", basic(&user, password).as_str()))
                .respond_with(ResponseTemplate::new(200))
                .mount(&upstream)
                .await;
        }
        Mock::given(any())
            .respond_with(ResponseTemplate::new(401))
            .mount(&upstream)
            .await;
    };
    accepting().await;

    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let url = format!("{}/status", upstream.uri());
    let login = |user: String, password: &'static str| {
        let client = client.clone();
        let url = format!("{}/auth/login", srv.base_url);
        async move {
            client
                .post(url)
                .json(&json!({ "username": user, "password": password }))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    let admin_call = |method: reqwest::Method, path: String, body: Option<Value>| {
        let client = client.clone();
        let url = format!("{}{path}", srv.base_url);
        let (admin, password) = (admin.clone(), password.clone());
        async move {
            let mut req = client
                .request(method, url)
                .basic_auth(&admin, Some(&password));
            if let Some(body) = body {
                req = req.json(&body);
            }
            let resp = req.send().await.unwrap();
            let status = resp.status();
            let text = resp.text().await.unwrap();
            (
                status,
                serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text)),
            )
        }
    };
    let config = |extra: Value| {
        let mut config = json!({ "url": url, "key_pepper": "pepper" });
        config
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        config
    };

    // Stopping forwarding without keeping hashes is refused.
    let (status, body) = admin_call(
        reqwest::Method::POST,
        "/admin/realms".into(),
        Some(json!({
            "kind": "credential_forwarding",
            "name": "nexus-only",
            "config": config(json!({ "captured_password_only": true })),
        })),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.to_string().contains("capture_password_hash"), "{body}");

    let (status, realm) = admin_call(
        reqwest::Method::POST,
        "/admin/realms".into(),
        Some(json!({
            "kind": "credential_forwarding",
            "name": "nexus",
            "config": config(json!({ "capture_password_hash": true })),
        })),
    )
    .await;
    assert_eq!(status, 201, "{realm}");
    assert_eq!(realm["config"]["capture_password_hash"], json!(true));
    let realm_id = realm["id"].as_i64().unwrap();
    let realm_path = format!("/admin/realms/{realm_id}");
    // The realm creates no accounts: an administrator creates them.
    for user in [&alice, &bob] {
        let (status, body) = admin_call(
            reqwest::Method::POST,
            "/admin/users".into(),
            Some(json!({ "username": user, "realm": "nexus" })),
        )
        .await;
        assert_eq!(status, 201, "{body}");
    }
    let counts = || {
        admin_call(
            reqwest::Method::GET,
            format!("{realm_path}/captured-passwords"),
            None,
        )
    };

    assert_eq!(login(alice.clone(), "alice-pw").await, 200);
    assert_eq!(login(bob.clone(), "wrong").await, 401);
    assert_eq!(
        counts().await,
        (
            reqwest::StatusCode::OK,
            json!({ "accounts": 2, "captured": 1 })
        )
    );
    let (_, users) = admin_call(reqwest::Method::GET, "/admin/users".into(), None).await;
    let alice_view = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == json!(alice))
        .expect("alice")
        .clone();
    assert_eq!(alice_view["auth_source"], json!("upstream-basic"));
    assert!(
        alice_view["captured_password_at"].is_string(),
        "{alice_view}"
    );

    // Turning the option off deletes the kept hashes...
    let (status, body) = admin_call(
        reqwest::Method::PATCH,
        realm_path.clone(),
        Some(json!({ "config": config(json!({})) })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(counts().await.1, json!({ "accounts": 2, "captured": 0 }));
    // ...and turning it on again keeps them from each account's next upstream
    // check on. Alice's verdict from before is cached again (the config is
    // the one it was cached under), so her login keeps nothing until a
    // re-authentication makes it ask the upstream.
    let (status, body) = admin_call(
        reqwest::Method::PATCH,
        realm_path.clone(),
        Some(json!({ "config": config(json!({ "capture_password_hash": true })) })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(login(alice.clone(), "alice-pw").await, 200);
    assert_eq!(login(bob.clone(), "bob-pw").await, 200);
    assert_eq!(counts().await.1, json!({ "accounts": 2, "captured": 1 }));
    let alice_id = alice_view["id"].as_i64().unwrap();
    let (status, _) = admin_call(
        reqwest::Method::POST,
        format!("/admin/users/{alice_id}/reauth"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(login(alice.clone(), "alice-pw").await, 200);
    assert_eq!(counts().await.1, json!({ "accounts": 2, "captured": 2 }));

    // Stop forwarding: the upstream must not be asked any more.
    let (status, body) = admin_call(
        reqwest::Method::PATCH,
        realm_path.clone(),
        Some(json!({ "config": config(json!({
            "capture_password_hash": true,
            "captured_password_only": true,
        })) })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    upstream.reset().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&upstream)
        .await;
    assert_eq!(login(alice.clone(), "alice-pw").await, 200);
    assert_eq!(login(alice.clone(), "wrong").await, 401);
    assert_eq!(
        login(format!("carol{}@example.com", common::unique()), "x").await,
        401
    );
    // Basic auth on the wire works the same way.
    let resp = client
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&bob, Some("bob-pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["user"]["username"],
        json!(bob)
    );

    // Only a forwarded account with a kept password converts.
    let admin_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == json!(admin))
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (status, _) = admin_call(
        reqwest::Method::POST,
        format!("/admin/users/{admin_id}/convert-to-local"),
        None,
    )
    .await;
    assert_eq!(status, 409);
    let (status, _) = admin_call(
        reqwest::Method::POST,
        "/admin/users/0/convert-to-local".into(),
        None,
    )
    .await;
    assert_eq!(status, 404);

    // One account, then the rest of the realm.
    let (status, view) = admin_call(
        reqwest::Method::POST,
        format!("/admin/users/{alice_id}/convert-to-local"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["auth_source"], json!("local"));
    assert_eq!(view["captured_password_at"], Value::Null);
    let (status, body) = admin_call(
        reqwest::Method::POST,
        format!("{realm_path}/convert-to-local"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!({ "converted": 1, "remaining": 0 }));

    // Local accounts now, signing in with the same passwords; the upstream is
    // still never asked (the mock verifies on drop).
    for (user, pw) in [(&alice, "alice-pw"), (&bob, "bob-pw")] {
        assert_eq!(login(user.clone(), pw).await, 200, "{user}");
        let account = forge_db::user_dao::find_user_by_username(&srv.pool, user)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.auth_source, "local");
    }
}
