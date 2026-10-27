//! E2E: the trusted-header realm (#506) — a request is authenticated as the
//! account a header of the proxy in front names, when the proxy proves
//! itself with the realm's secret, from a trusted peer, for this server's
//! own host name.
//!
//! The test servers listen on loopback, so `127.0.0.1` is the socket peer of
//! every request: listing it in `auth.trusted_proxy_cidrs` makes the test
//! client the trusted proxy.
//!
//! Requires Docker (Postgres + S3 testcontainers) on the host.

mod common;

use reqwest::{RequestBuilder, StatusCode};
use serde_json::{json, Value};

use common::{ServerOpts, TestServer};

/// The secret the test proxy proves itself with.
const SECRET: &str = "the-proxys-secret-0123456789abcdef";

/// The 401 body of credentials that are present but invalid.
const INVALID: &str = "invalid credentials";

/// The 401 body of a request without credentials (`/admin/me`).
const ANONYMOUS: &str = "authentication required";

/// A server behind the test client as its trusted proxy, addressed as
/// `127.0.0.1` (one of its own host names).
async fn proxied() -> TestServer {
    common::start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            auth_extra: Some(r#"trusted_proxy_cidrs = ["127.0.0.1"]"#.into()),
            server_extra: Some(r#"allowed_hosts = ["127.0.0.1"]"#.into()),
            ..Default::default()
        },
    )
    .await
}

/// A trusted-header realm of the test, with header names of its own (the
/// test servers share one database, and so their realms).
struct Realm {
    id: i64,
    name: String,
    user_header: String,
    secret_header: String,
}

impl Realm {
    /// `rb` as the proxy sends it for `username`.
    fn named(&self, rb: RequestBuilder, username: &str) -> RequestBuilder {
        rb.header(&self.secret_header, SECRET)
            .header(&self.user_header, username)
    }
}

/// Create a trusted-header realm through the admin API.
async fn create_realm(srv: &TestServer, auto_provision: bool) -> Realm {
    let n = common::unique();
    let (user_header, secret_header) = (format!("X-User-{n}"), format!("X-Proxy-Secret-{n}"));
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "kind": "trusted_header",
            "name": format!("proxy-{n}"),
            "config": {
                "username_header": user_header,
                "secret_header": secret_header,
                "secret": SECRET,
                "auto_provision": auto_provision,
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    // The secret is write-only: never in a response.
    assert!(body["config"].get("secret").is_none(), "{body}");
    assert_eq!(body["config"]["secret_set"], json!(true));
    assert_eq!(
        body["config"]["username_header"],
        json!(user_header.to_lowercase())
    );
    Realm {
        id: body["id"].as_i64().unwrap(),
        name: body["name"].as_str().unwrap().to_string(),
        user_header,
        secret_header,
    }
}

/// Create an account of `realm` through the admin API, as `role`.
async fn create_account(srv: &TestServer, realm: &Realm, username: &str, role: &str) -> i64 {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"username": username, "realm": realm.name, "role": role}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["auth_source"], json!("trusted-header"));
    assert_eq!(body["invitation"], Value::Null);
    body["id"].as_i64().unwrap()
}

/// `GET /admin/me` as `rb` sends it: the status, and the body (JSON or text).
async fn me(rb: RequestBuilder) -> (StatusCode, Value) {
    let resp = rb.send().await.unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

fn me_request(srv: &TestServer) -> RequestBuilder {
    srv.client().get(format!("{}/admin/me", srv.base_url))
}

#[tokio::test]
async fn the_headers_authenticate_an_account_of_the_realm() {
    let srv = proxied().await;
    let realm = create_realm(&srv, false).await;
    let alice = format!("alice{}@example.com", common::unique());
    let id = create_account(&srv, &realm, &alice, "reader").await;

    let (status, body) = me(realm.named(me_request(&srv), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["id"], json!(id));
    assert_eq!(body["user"]["username"], json!(alice));
    // Names are compared in their canonical form.
    let (status, body) =
        me(realm.named(me_request(&srv), &format!(" {} ", alice.to_uppercase()))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["id"], json!(id));

    // A shared cache keeps nothing the headers authenticated: they are
    // credentials no cache varies on.
    let feed = format!("{}/repository/no-such-repo/index.json", srv.base_url);
    let resp = realm
        .named(srv.client().get(&feed), &alice)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["cache-control"], "private, no-store");
    let resp = srv.client().get(&feed).send().await.unwrap();
    assert!(resp.headers().get("cache-control").is_none());

    // Without `auto_provision` the realm names only the accounts created for it.
    let bob = format!("bob{}@example.com", common::unique());
    assert_eq!(
        me(realm.named(me_request(&srv), &bob)).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );

    // A deactivated account is refused.
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .patch(format!("{}/admin/users/{id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"active": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        me(realm.named(me_request(&srv), &alice)).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );
}

#[tokio::test]
async fn auto_provision_creates_a_users_account() {
    let srv = proxied().await;
    let realm = create_realm(&srv, true).await;
    let carol = format!("carol{}@example.com", common::unique());

    let (status, first) = me(realm.named(me_request(&srv), &carol)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["user"]["username"], json!(carol));
    // The account it created gets no administrator, and no role at all.
    assert_eq!(first["is_admin"], json!(false));
    assert_eq!(first["capabilities"], json!(["repo.read"]));
    let (status, again) = me(realm.named(me_request(&srv), &carol)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["user"]["id"], first["user"]["id"]);

    let user = forge_db::user_dao::find_user_by_username(&srv.pool, &carol)
        .await
        .unwrap()
        .expect("the account was created");
    assert_eq!(user.auth_source, "trusted-header");
    assert!(user.password_hash.is_none());
    let realm_id: Option<i64> = sqlx::query_scalar("SELECT realm_id FROM app_user WHERE id = $1")
        .bind(user.id)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(realm_id, Some(realm.id));

    // Every account is named by a UPN; so is every account a realm creates.
    assert_eq!(
        me(realm.named(me_request(&srv), "not-a-upn")).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );
}

#[tokio::test]
async fn refused_headers_are_a_401_never_anonymous() {
    let srv = proxied().await;
    // It creates accounts: a refused name is refused for whose it is, not
    // for being unknown.
    let realm = create_realm(&srv, true).await;
    let other = create_realm(&srv, true).await;
    let n = common::unique();
    let dave = format!("dave{n}@example.com");
    create_account(&srv, &other, &dave, "reader").await;
    let oidc = format!("olga{n}@example.com");
    forge_db::user_dao::insert_user(
        &srv.pool,
        forge_db::user_dao::NewUser {
            username: oidc.clone(),
            password_hash: None,
            active: true,
            auth_source: "oidc".into(),
            external_subject: Some(format!("sub-{n}")),
        },
    )
    .await
    .unwrap();
    let local = srv.admin_user.clone().unwrap();
    let erin = format!("erin{n}@example.com");

    // No headers: the anonymous policy decides (anonymous mode is off).
    assert_eq!(
        me(me_request(&srv)).await,
        (StatusCode::UNAUTHORIZED, json!(ANONYMOUS))
    );

    let cases: Vec<(&str, RequestBuilder)> = vec![
        (
            "a wrong secret",
            me_request(&srv)
                .header(&realm.secret_header, "the-proxys-secret-0123456789abcdeX")
                .header(&realm.user_header, &erin),
        ),
        (
            "no secret",
            me_request(&srv).header(&realm.user_header, &erin),
        ),
        (
            "the secret twice",
            realm
                .named(me_request(&srv), &erin)
                .header(&realm.secret_header, SECRET),
        ),
        (
            "no username",
            me_request(&srv).header(&realm.secret_header, SECRET),
        ),
        ("an empty username", realm.named(me_request(&srv), "  ")),
        (
            "two usernames",
            realm
                .named(me_request(&srv), &erin)
                .header(&realm.user_header, &dave),
        ),
        ("a local account", realm.named(me_request(&srv), &local)),
        ("an OIDC account", realm.named(me_request(&srv), &oidc)),
        (
            "an account of another realm",
            realm.named(me_request(&srv), &dave),
        ),
        // The reserved workload-identity name.
        ("a reserved name", realm.named(me_request(&srv), "oidc")),
    ];
    for (case, rb) in cases {
        assert_eq!(
            me(rb).await,
            (StatusCode::UNAUTHORIZED, json!(INVALID)),
            "{case}"
        );
    }
    // None of the refused names got an account of the realm.
    for name in [&local, &oidc, &dave] {
        let found = forge_db::user_dao::find_trusted_header_user(&srv.pool, name, realm.id)
            .await
            .unwrap();
        assert!(found.is_none(), "{name}");
    }
    assert!(forge_db::user_dao::find_user_by_username(&srv.pool, &erin)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn headers_from_an_untrusted_peer_or_a_foreign_host_are_ignored() {
    // No trusted proxies: the headers are the client's own word.
    let srv = common::start().await;
    let realm = create_realm(&srv, false).await;
    let alice = format!("alice{}@example.com", common::unique());
    create_account(&srv, &realm, &alice, "reader").await;
    for rb in [
        realm.named(me_request(&srv), &alice),
        me_request(&srv)
            .header(&realm.secret_header, "wrong")
            .header(&realm.user_header, &alice),
    ] {
        assert_eq!(me(rb).await, (StatusCode::UNAUTHORIZED, json!(ANONYMOUS)));
    }

    // From the trusted proxy, but under a host name that is not this
    // server's: a DNS-rebinding page.
    let srv = proxied().await;
    let realm = create_realm(&srv, false).await;
    let bob = format!("bob{}@example.com", common::unique());
    create_account(&srv, &realm, &bob, "reader").await;
    let (status, _) = me(realm.named(me_request(&srv), &bob)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        me(realm
            .named(me_request(&srv), &bob)
            .header("host", "rebind.attacker.example"))
        .await,
        (StatusCode::UNAUTHORIZED, json!(ANONYMOUS))
    );
}

#[tokio::test]
async fn a_cross_site_mutation_is_refused_and_the_headers_mint_no_tokens() {
    let srv = proxied().await;
    let realm = create_realm(&srv, false).await;
    let alice = format!("alice{}@example.com", common::unique());
    create_account(&srv, &realm, &alice, "reader").await;
    let mint = |site: &'static str| {
        realm
            .named(
                srv.client()
                    .post(format!("{}/admin/me/tokens", srv.base_url)),
                &alice,
            )
            .header("sec-fetch-site", site)
            .json(&json!({"name": "from the headers"}))
    };

    let resp = mint("cross-site").send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.text().await.unwrap(), "cross-site request refused");

    // The same request from Forge's own page reaches the handler, which
    // takes no proxy's headers for minting a token.
    let resp = mint("same-origin").send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("the headers of the proxy"),
        "refused by the token endpoint"
    );
}

#[tokio::test]
async fn the_headers_never_make_an_administrator_and_own_credentials_win() {
    let srv = proxied().await;
    let realm = create_realm(&srv, false).await;
    let n = common::unique();
    let root = format!("root{n}@example.com");
    let (u, p) = srv.admin_basic();

    // An account of the realm never holds the admin role (#547), neither
    // created as an administrator nor made one later: holding it, it would
    // count as an administrator the headers never make it.
    let resp = srv
        .client()
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"username": root, "realm": realm.name, "role": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let root_id = create_account(&srv, &realm, &root, "writer").await;
    let resp = srv
        .client()
        .put(format!("{}/admin/users/{root_id}/roles", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"role": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The headers make no administrator either.
    let (status, body) = me(realm.named(me_request(&srv), &root)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["is_admin"], json!(false));
    let resp = realm
        .named(
            srv.client().get(format!("{}/admin/users", srv.base_url)),
            &root,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // A token of the request's own wins over the headers…
    let other = format!("frank{n}@example.com");
    let other_id = create_account(&srv, &realm, &other, "reader").await;
    let token: Value = srv
        .client()
        .post(format!("{}/admin/users/{other_id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "frank's"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token["token"].as_str().unwrap();
    let (status, body) = me(realm
        .named(me_request(&srv), &root)
        .header("X-NuGet-ApiKey", token))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["id"], json!(other_id));
    assert_ne!(other_id, root_id);

    // …and one that is refused is never replaced by the account the headers
    // name.
    assert_eq!(
        me(realm
            .named(me_request(&srv), &root)
            .header("X-NuGet-ApiKey", "not-a-token"))
        .await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );
}

/// npm's `_authToken`, a Bearer API token, is the request's own credential
/// (#555): it wins over the headers on `/repository`, and one that is
/// refused is a 401, never the account the headers name.
#[tokio::test]
async fn a_bearer_token_of_the_requests_own_wins_over_the_headers() {
    let srv = proxied().await;
    let realm = create_realm(&srv, false).await;
    let n = common::unique();
    let office = format!("office{n}@example.com");
    create_account(&srv, &realm, &office, "reader").await;
    let ci = format!("ci{n}@example.com");
    let ci_id = create_account(&srv, &realm, &ci, "writer").await;
    let (u, p) = srv.admin_basic();
    let repo = format!("npm{n}");
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": repo, "kind": "hosted", "format": "npm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token: Value = srv
        .client()
        .post(format!("{}/admin/users/{ci_id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "ci"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token["token"].as_str().unwrap();
    let whoami = || {
        realm.named(
            srv.client()
                .get(format!("{}/repository/{repo}/-/whoami", srv.base_url)),
            &office,
        )
    };

    // The headers alone name the network's account…
    let (status, body) = me(whoami()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["username"], json!(office));
    // …a Bearer token of the request's own wins…
    let (status, body) = me(whoami().bearer_auth(token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["username"], json!(ci));
    // …and one that is refused, unknown or revoked, is a 401.
    let (status, _) = me(whoami().bearer_auth("not-a-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let tokens: Value = srv
        .client()
        .get(format!("{}/admin/users/{ci_id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token_id = tokens[0]["id"].as_i64().unwrap();
    let resp = srv
        .client()
        .delete(format!("{}/admin/tokens/{token_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let (status, _) = me(whoami().bearer_auth(token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_update_keeps_the_stored_secret() {
    let srv = proxied().await;
    let realm = create_realm(&srv, false).await;
    let (u, p) = srv.admin_basic();
    // The edit form sends the redacted view back, without the secret.
    let resp = srv
        .client()
        .patch(format!("{}/admin/realms/{}", srv.base_url, realm.id))
        .basic_auth(&u, Some(&p))
        .json(&json!({"config": {
            "username_header": realm.user_header,
            "secret_header": realm.secret_header,
            "secret_set": true,
            "auto_provision": true,
        }}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["config"].get("secret").is_none(), "{body}");
    assert_eq!(body["config"]["secret_set"], json!(true));

    // The stored secret still proves the proxy, and the realm now creates
    // the accounts it names.
    let gina = format!("gina{}@example.com", common::unique());
    let (status, body) = me(realm.named(me_request(&srv), &gina)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A secret too short to guess is refused.
    let resp = srv
        .client()
        .patch(format!("{}/admin/realms/{}", srv.base_url, realm.id))
        .basic_auth(&u, Some(&p))
        .json(&json!({"config": {
            "username_header": realm.user_header,
            "secret_header": realm.secret_header,
            "secret": "short",
        }}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// The trusted-header realms are asked for every request a trusted proxy
/// forwards, health probes included: once the realm snapshot is due, the one
/// at hand serves while a rebuild runs, so an unreachable database does not
/// hold them all up. Only with no snapshot at all does the check wait (and
/// fail) for one.
#[tokio::test]
async fn past_its_ttl_the_snapshot_at_hand_serves_while_the_database_is_gone() {
    use figment::providers::Format as _;
    use std::sync::Arc;

    // A pool of its own: closing it stands for the database going away.
    let pool = common::pool().await;
    let config = forge_server::config::Config::from_figment(figment::Figment::new().merge(
        figment::providers::Toml::string(
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
            [auth]
            realm_cache_ttl_seconds = 1
            [crypto.root]
            provider = "env"
            "#,
        ),
    ))
    .expect("valid config");
    let envelope = common::envelope(&pool).await;
    let issuer = forge_server::auth::AssertionIssuer::new(
        pool.clone(),
        envelope.clone(),
        config.public_base_url(),
    );
    let settings = Arc::new(forge_server::auth::AuthSettingsCache::new(
        pool.clone(),
        std::time::Duration::from_secs(10),
    ));
    let realms = Arc::new(forge_server::auth::RealmAuth::new(
        pool.clone(),
        forge_cache::Cache::l1_only(100),
        Arc::new(config),
        issuer,
        settings,
        envelope,
    ));

    let built = realms.current_or_stale().await.expect("built");
    pool.close().await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(realms.snapshot().await.is_err(), "the database is gone");
    let at_hand = realms
        .current_or_stale()
        .await
        .expect("the snapshot at hand");
    assert!(Arc::ptr_eq(&built, &at_hand));

    realms.invalidate().await;
    assert!(
        realms.current_or_stale().await.is_err(),
        "with nothing at hand it waits for a rebuild"
    );
}

/// A feed request the headers name but RBAC denies is challenged like an
/// anonymous one (#556): it carried no credential of its own, and NuGet
/// sends the credentials of its `nuget.config` only after a 401 challenge.
#[tokio::test]
async fn a_denied_request_the_headers_name_is_challenged() {
    let srv = proxied().await;
    let realm = create_realm(&srv, false).await;
    let n = common::unique();
    let office = format!("office{n}@example.com");
    create_account(&srv, &realm, &office, "reader").await;
    let (u, p) = srv.admin_basic();
    let feed = format!("private{n}");
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": feed, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let index = || {
        realm.named(
            srv.client()
                .get(format!("{}/repository/{feed}/index.json", srv.base_url)),
            &office,
        )
    };

    let resp = index().send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers()["www-authenticate"], "Basic realm=\"Forge\"");
    // The client's own credentials (an API token), sent after the
    // challenge, win.
    let resp = index().basic_auth(&u, Some(&p)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
