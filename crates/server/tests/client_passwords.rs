//! Passwords from clients are accepted per realm (#647): a realm's
//! `accept_client_passwords` decides whether its users may send their
//! password from a client (HTTP Basic on the feeds and `/v2/token`,
//! `npm login --auth-type=legacy`). The browser login takes every realm's
//! passwords, and an API token works whatever the realms say. Requires
//! Docker. Each test has a database of its own: the realms are install-wide.

mod common;

use base64::Engine;
use common::{ServerOpts, TestServer};
use serde_json::{json, Value};
use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

/// The local part of the credential-forwarding realm's account.
const FORWARDED: &str = "fwd";

/// The password the mock upstream accepts for [`FORWARDED`].
const UPSTREAM_PASSWORD: &str = "upstream-pw-1";

/// The file every test reads from the raw repository.
const RAW_FILE: &str = "hello.txt";

/// An admin API request, with the admin's token over Basic.
fn admin(srv: &TestServer, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
    let (user, token) = srv.admin_basic();
    srv.client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(user, Some(token))
}

/// `user:password` of a Basic `authorization` header.
fn basic_credentials(request: &wiremock::Request) -> Option<String> {
    let encoded = request
        .headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?
        .to_string();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    String::from_utf8(decoded).ok()
}

/// A server on a database of its own, with a credential-forwarding realm
/// `nexus` over a mock upstream that accepts [`FORWARDED`] /
/// [`UPSTREAM_PASSWORD`], that realm's account `fwd@example.com` (a writer),
/// and hosted NuGet, raw and npm repositories nobody reads anonymously. The
/// local realm accepts no passwords from clients, its default.
struct Setup {
    srv: TestServer,
    upstream: MockServer,
    forwarded: String,
    nuget: String,
    raw: String,
    npm: String,
}

impl Setup {
    async fn new() -> Setup {
        let upstream = MockServer::start().await;
        let accepted = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{FORWARDED}:{UPSTREAM_PASSWORD}"))
        );
        Mock::given(matchers::header("authorization", accepted.as_str()))
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream)
            .await;
        Mock::given(matchers::any())
            .respond_with(ResponseTemplate::new(401))
            .mount(&upstream)
            .await;

        let srv = common::start_with(
            common::fresh_pool().await,
            ServerOpts {
                bootstrap_admin: Some((
                    format!("admin{}@example.com", common::unique()),
                    "adminpw".into(),
                )),
                ..Default::default()
            },
        )
        .await;
        srv.set_local_client_passwords(false).await;
        let resp = admin(&srv, reqwest::Method::POST, "/admin/realms")
            .json(&json!({
                "kind": "credential_forwarding",
                "name": "nexus",
                "config": {"url": format!("{}/status", upstream.uri()), "key_pepper": "pepper"},
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
        let forwarded = format!("{FORWARDED}@example.com");
        let resp = admin(&srv, reqwest::Method::POST, "/admin/users")
            .json(&json!({"username": forwarded, "role": "writer", "realm": "nexus"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

        let suffix = common::unique();
        let (nuget, raw, npm) = (
            format!("nuget{suffix}"),
            format!("raw{suffix}"),
            format!("npm{suffix}"),
        );
        for (name, format) in [(&nuget, "nuget"), (&raw, "raw"), (&npm, "npm")] {
            let resp = admin(&srv, reqwest::Method::POST, "/admin/repositories")
                .json(&json!({"name": name, "kind": "hosted", "format": format}))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
        }
        let resp = admin(
            &srv,
            reqwest::Method::PUT,
            &format!("/repository/{raw}/{RAW_FILE}"),
        )
        .body("hello")
        .send()
        .await
        .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
        Setup {
            srv,
            upstream,
            forwarded,
            nuget,
            raw,
            npm,
        }
    }

    /// The status and body of every client sign-in with `username` and
    /// `secret`: a NuGet and a raw read with Basic, `docker login`'s token
    /// request, and `npm login --auth-type=legacy`.
    async fn clients(&self, username: &str, secret: &str) -> Vec<(&'static str, u16, String)> {
        let srv = &self.srv;
        let client = srv.client();
        let basic = |url: String| client.get(url).basic_auth(username, Some(secret));
        let requests = [
            (
                "nuget",
                basic(format!(
                    "{}/repository/{}/index.json",
                    srv.base_url, self.nuget
                )),
            ),
            (
                "raw",
                basic(format!(
                    "{}/repository/{}/{RAW_FILE}",
                    srv.base_url, self.raw
                )),
            ),
            (
                "docker login",
                basic(format!(
                    "{}/v2/token?account={username}&service=test.local",
                    srv.base_url
                )),
            ),
            (
                "npm login",
                client
                    .put(format!(
                        "{}/repository/{}/-/user/org.couchdb.user:{}",
                        srv.base_url,
                        self.npm,
                        username.replace('@', "%40")
                    ))
                    .json(&json!({"name": username, "password": secret, "type": "user"})),
            ),
        ];
        let mut answers = Vec::new();
        for (what, request) in requests {
            let resp = request.send().await.unwrap();
            let status = resp.status().as_u16();
            answers.push((what, status, resp.text().await.unwrap()));
        }
        answers
    }

    /// Every client sign-in with `username` and `secret` is let in, or none.
    async fn assert_clients(&self, username: &str, secret: &str, accepted: bool) {
        for (what, status, body) in self.clients(username, secret).await {
            let expected = match (accepted, what) {
                (false, _) => 401,
                (true, "npm login") => 201,
                (true, _) => 200,
            };
            assert_eq!(status, expected, "{username} with {what}: {body}");
        }
    }

    /// How many upstream requests named the account `local_part`.
    async fn forwarded_for(&self, local_part: &str) -> usize {
        let prefix = format!("{local_part}:");
        self.upstream
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(basic_credentials)
            .filter(|credentials| credentials.starts_with(&prefix))
            .count()
    }

    /// The id of the realm `name`.
    async fn realm_id(&self, name: &str) -> i64 {
        forge_db::auth_realm_dao::find_realm_by_name(&self.srv.pool, name)
            .await
            .unwrap()
            .expect("the realm")
            .id
    }

    /// The config of realm `id`, as the admin API shows it.
    async fn realm_config(&self, id: i64) -> Value {
        let realm: Value = admin(
            &self.srv,
            reqwest::Method::GET,
            &format!("/admin/realms/{id}"),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        realm["config"].clone()
    }

    /// Set `accept_client_passwords` on realm `name` through the admin API
    /// (Admin → Authentication), keeping the rest of its config.
    async fn set_flag(&self, name: &str, accept: bool) {
        let id = self.realm_id(name).await;
        let mut config = self.realm_config(id).await;
        config["accept_client_passwords"] = json!(accept);
        let resp = admin(
            &self.srv,
            reqwest::Method::PATCH,
            &format!("/admin/realms/{id}"),
        )
        .json(&json!({ "config": config }))
        .send()
        .await
        .unwrap();
        assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    }
}

/// The issue's case: a credential-forwarding realm accepts its users'
/// passwords from every client, the local realm (closed by default) none of
/// its users', whose token keeps working and whose password never reaches
/// the upstream. The browser login takes both.
#[tokio::test]
async fn a_forwarding_realm_takes_client_passwords_and_a_closed_local_realm_none() {
    let setup = Setup::new().await;
    let srv = &setup.srv;
    let (admin_user, admin_password) = srv.admin_password_basic();
    let (_, admin_token) = srv.admin_basic();
    let admin_local = admin_user.split('@').next().unwrap().to_string();

    setup
        .assert_clients(&setup.forwarded, UPSTREAM_PASSWORD, true)
        .await;
    setup
        .assert_clients(&setup.forwarded, "not-the-password", false)
        .await;

    // The local user's password is refused by every client, with the answer
    // a wrong one gets, and is never sent upstream.
    let right = setup.clients(&admin_user, &admin_password).await;
    let wrong = setup.clients(&admin_user, "not-the-password").await;
    assert_eq!(
        right, wrong,
        "a closed realm's password answers like a wrong one"
    );
    for (what, status, _) in &right {
        assert_eq!(*status, 401, "{what}");
    }
    assert_eq!(
        setup.forwarded_for(&admin_local).await,
        0,
        "no local password reaches the upstream"
    );

    // Its API token works on the feeds and for `docker login`. (`npm login`
    // takes a password only: npm sends the token itself.)
    for (what, status, body) in setup.clients(&admin_user, &admin_token).await {
        if what != "npm login" {
            assert_eq!(status, 200, "{what}: {body}");
        }
    }
    let resp = srv
        .client()
        .get(format!(
            "{}/repository/{}/-/whoami",
            srv.base_url, setup.npm
        ))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "npm with the token");

    // The browser login takes both realms' passwords.
    srv.login(&admin_user, &admin_password).await;
    srv.login(&setup.forwarded, UPSTREAM_PASSWORD).await;
}

/// Each realm's flag follows its admin edits at once: the local realm opened
/// takes its users' passwords from clients, the forwarding realm closed
/// takes none (its users then sign their clients in with tokens, which the
/// browser login gets them), and with no realm open the path is off.
#[tokio::test]
async fn each_realm_opens_and_closes_its_own_passwords() {
    let setup = Setup::new().await;
    let srv = &setup.srv;
    let (admin_user, admin_password) = srv.admin_password_basic();

    setup.set_flag("local", true).await;
    setup
        .assert_clients(&admin_user, &admin_password, true)
        .await;
    setup
        .assert_clients(&setup.forwarded, UPSTREAM_PASSWORD, true)
        .await;

    setup.set_flag("nexus", false).await;
    setup
        .assert_clients(&admin_user, &admin_password, true)
        .await;
    let before = setup.forwarded_for(FORWARDED).await;
    setup
        .assert_clients(&setup.forwarded, UPSTREAM_PASSWORD, false)
        .await;
    assert_eq!(
        setup.forwarded_for(FORWARDED).await,
        before,
        "a closed forwarding realm forwards no client's password"
    );
    srv.login(&setup.forwarded, UPSTREAM_PASSWORD).await;

    setup.set_flag("local", false).await;
    setup
        .assert_clients(&admin_user, &admin_password, false)
        .await;
    srv.login(&admin_user, &admin_password).await;
}

/// The admin API shows and validates the flag: the local realm's is off and
/// a credential-forwarding realm's on until set, and the local realm takes
/// no other config.
#[tokio::test]
async fn the_admin_api_takes_the_flag_on_the_password_realms() {
    let setup = Setup::new().await;
    let local = setup.realm_id("local").await;
    let nexus = setup.realm_id("nexus").await;
    assert_eq!(
        setup.realm_config(local).await["accept_client_passwords"],
        false
    );
    assert_eq!(
        setup.realm_config(nexus).await["accept_client_passwords"],
        true
    );

    for body in [
        json!({"config": {"accept_client_passwords": "yes"}}),
        json!({"config": {"accept_client_password": true}}),
    ] {
        let resp = admin(
            &setup.srv,
            reqwest::Method::PATCH,
            &format!("/admin/realms/{local}"),
        )
        .json(&body)
        .send()
        .await
        .unwrap();
        assert_eq!(resp.status(), 400, "{body}");
    }
    assert_eq!(
        setup.realm_config(local).await["accept_client_passwords"],
        false
    );
}

/// The upgrade (`0006_realm_client_passwords.sql`) gives the local realm the
/// install-wide `allow_password_basic` it had, and leaves a forwarding
/// realm's config as it was (it accepts client passwords by default).
#[tokio::test]
async fn the_upgrade_carries_allow_password_basic_onto_the_local_realm() {
    const MIGRATION: &str = include_str!("../../../migrations/0006_realm_client_passwords.sql");
    let pool = common::fresh_pool().await;
    let forwarding = json!({"url": "https://nexus.example/status", "method": "GET"});
    sqlx::query(
        "INSERT INTO auth_realm (kind, name, priority, config) \
         VALUES ('credential_forwarding', 'nexus', 50, $1)",
    )
    .bind(&forwarding)
    .execute(&pool)
    .await
    .unwrap();
    for (stored, accepts) in [
        (
            Some(r#"{"anonymous_mode":"off","allow_password_basic":true}"#),
            true,
        ),
        (
            Some(r#"{"anonymous_mode":"off","allow_password_basic":false}"#),
            false,
        ),
        (Some(r#"{"anonymous_mode":"all"}"#), false),
        (None, false),
    ] {
        sqlx::query("UPDATE auth_realm SET config = '{}' WHERE kind = 'local'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM forge_setting WHERE key = 'auth_settings'")
            .execute(&pool)
            .await
            .unwrap();
        if let Some(stored) = stored {
            forge_db::authz_dao::set_setting(&pool, "auth_settings", stored)
                .await
                .unwrap();
        }
        sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();
        let (local, nexus): (Value, Value) = sqlx::query_as(
            "SELECT (SELECT config FROM auth_realm WHERE kind = 'local'), \
                    (SELECT config FROM auth_realm WHERE name = 'nexus')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            local,
            json!({"accept_client_passwords": accepts}),
            "{stored:?}"
        );
        assert_eq!(nexus, forwarding, "{stored:?}");
        // The settings document still loads.
        forge_server::auth::load_auth_settings(&pool).await.unwrap();
    }
}
