//! E2E: service accounts (#508) — accounts for machines and networks that
//! nobody signs in to. They authenticate with the API tokens an administrator
//! issues for them, or through the trusted-header realm they belong to, and
//! never hold the `admin` role.
//!
//! The test servers listen on loopback, so `127.0.0.1` is the socket peer of
//! every request: listing it in `auth.trusted_proxy_cidrs` makes the test
//! client the trusted proxy of the trusted-header realms.
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

/// A server with a database of its own (its auth settings change), behind
/// the test client as its trusted proxy, addressed as `127.0.0.1`.
async fn server() -> TestServer {
    common::start_with(
        common::fresh_pool().await,
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

/// `rb` as the bootstrap admin sends it (an admin-scoped token).
fn as_admin(srv: &TestServer, rb: RequestBuilder) -> RequestBuilder {
    let (u, p) = srv.admin_basic();
    rb.basic_auth(u, Some(p))
}

/// `(status, body)` of a response: JSON, or the text as a JSON string.
async fn answer(rb: RequestBuilder) -> (StatusCode, Value) {
    let resp = rb.send().await.unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// `POST /admin/users` with `body`, as the admin.
async fn create(srv: &TestServer, body: Value) -> (StatusCode, Value) {
    answer(as_admin(
        srv,
        srv.client()
            .post(format!("{}/admin/users", srv.base_url))
            .json(&body),
    ))
    .await
}

/// Create a service account named `username` of `realm` (or of none) and
/// return its view.
async fn create_service_account(srv: &TestServer, username: &str, realm: Option<&str>) -> Value {
    let (status, body) = create(
        srv,
        json!({
            "username": username,
            "kind": "service",
            "description": "  The build agents; owner: platform  ",
            "realm": realm,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

/// `PATCH /admin/users/{id}` with `body`, as the admin.
async fn patch(srv: &TestServer, id: i64, body: Value) -> (StatusCode, Value) {
    answer(as_admin(
        srv,
        srv.client()
            .patch(format!("{}/admin/users/{id}", srv.base_url))
            .json(&body),
    ))
    .await
}

/// `GET /admin/users` (with `query`), as the admin.
async fn list(srv: &TestServer, query: &str) -> Vec<Value> {
    let (status, body) = answer(as_admin(
        srv,
        srv.client()
            .get(format!("{}/admin/users{query}", srv.base_url)),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body.as_array().unwrap().clone()
}

/// Issue an API token for `id` as the admin; its plaintext secret.
async fn issue_token(srv: &TestServer, id: i64, body: Value) -> String {
    let (status, body) = answer(as_admin(
        srv,
        srv.client()
            .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
            .json(&body),
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["token"].as_str().unwrap().to_string()
}

fn me_request(srv: &TestServer) -> RequestBuilder {
    srv.client().get(format!("{}/admin/me", srv.base_url))
}

/// A trusted-header realm of the test.
struct Realm {
    name: String,
    user_header: String,
    secret_header: String,
}

impl Realm {
    /// `rb` as the realm's proxy sends it for `username`.
    fn named(&self, rb: RequestBuilder, username: &str) -> RequestBuilder {
        rb.header(&self.secret_header, SECRET)
            .header(&self.user_header, username)
    }
}

/// Create a trusted-header realm through the admin API.
async fn create_realm(srv: &TestServer, auto_provision: bool) -> Realm {
    let n = common::unique();
    let (user_header, secret_header) = (format!("X-User-{n}"), format!("X-Proxy-Secret-{n}"));
    let (status, body) = answer(as_admin(
        srv,
        srv.client()
            .post(format!("{}/admin/realms", srv.base_url))
            .json(&json!({
                "kind": "trusted_header",
                "name": format!("proxy-{n}"),
                "config": {
                    "username_header": user_header,
                    "secret_header": secret_header,
                    "secret": SECRET,
                    "auto_provision": auto_provision,
                },
            })),
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Realm {
        name: body["name"].as_str().unwrap().to_string(),
        user_header,
        secret_header,
    }
}

#[tokio::test]
async fn the_admin_api_creates_lists_and_updates_service_accounts() {
    let srv = server().await;
    let realm = create_realm(&srv, false).await;
    let name = format!("ci{}@example.com", common::unique());

    let created = create_service_account(&srv, &name, None).await;
    let id = created["id"].as_i64().unwrap();
    assert_eq!(created["kind"], json!("service"));
    assert_eq!(created["auth_source"], json!("service"));
    assert_eq!(
        created["description"],
        json!("The build agents; owner: platform")
    );
    assert_eq!(created["realm"], Value::Null);
    assert_eq!(created["email"], Value::Null);
    assert_eq!(created["invitation"], Value::Null);
    assert_eq!(created["status"], json!("active"));
    assert_eq!(created["is_admin"], json!(false));
    assert_eq!(created["last_used_at"], Value::Null);

    // The list filter.
    let services = list(&srv, "?kind=service").await;
    assert!(services.iter().any(|u| u["id"] == json!(id)));
    assert!(services.iter().all(|u| u["kind"] == json!("service")));
    let users = list(&srv, "?kind=user").await;
    assert!(users.iter().all(|u| u["kind"] == json!("user")));
    assert!(!users.iter().any(|u| u["id"] == json!(id)));
    assert!(list(&srv, "").await.iter().any(|u| u["id"] == json!(id)));

    // What a service account never has: an email, the admin role, a realm
    // of another kind, a name that is no UPN or that another account holds.
    let other = format!("other{}@example.com", common::unique());
    for (body, why) in [
        (
            json!({"username": other, "kind": "service", "email": other}),
            "no email address",
        ),
        (
            json!({"username": other, "kind": "service", "role": "admin"}),
            "cannot hold the admin role",
        ),
        (
            json!({"username": other, "kind": "service", "realm": "no-such-realm"}),
            "no trusted-header realm",
        ),
        (json!({"username": "ci-runners", "kind": "service"}), "UPN"),
        (
            json!({"username": other, "description": "a person"}),
            "only a service account has a description",
        ),
        (
            json!({"username": other, "kind": "service", "description": "x".repeat(1001)}),
            "at most 1000 characters",
        ),
    ] {
        let (status, answer) = create(&srv, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert!(answer.as_str().unwrap().contains(why), "{body}: {answer}");
    }
    let (status, _) = create(&srv, json!({"username": name, "kind": "service"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "the name space is shared");
    let (admin, _) = srv.admin_basic();
    let (status, _) = create(&srv, json!({"username": admin, "kind": "service"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "a user's name is taken too");

    // Its description and realm are set later; `null` clears them.
    let (status, body) = patch(
        &srv,
        id,
        json!({"description": "CI of the web team", "realm": realm.name}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["description"], json!("CI of the web team"));
    assert_eq!(body["realm"], json!(realm.name));
    let (status, body) = patch(&srv, id, json!({"description": null, "realm": null})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["description"], Value::Null);
    assert_eq!(body["realm"], Value::Null);
    let (status, _) = patch(&srv, id, json!({"realm": "no-such-realm"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A user's description and realm are not set here.
    let users = list(&srv, "?kind=user").await;
    let admin_id = users
        .iter()
        .find(|u| u["username"] == json!(admin))
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (status, _) = patch(&srv, admin_id, json!({"description": "a person"})).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Nobody signs in to it: no invitation, no sign-out everywhere, no switch
    // to a local password.
    for path in ["invitation", "reauth", "convert-to-local"] {
        let (status, body) = answer(as_admin(
            &srv,
            srv.client()
                .post(format!("{}/admin/users/{id}/{path}", srv.base_url))
                .json(&json!({})),
        ))
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}: {body}");
    }

    // It holds roles, but never `admin`.
    let assign = |role: &str| {
        as_admin(
            &srv,
            srv.client()
                .put(format!("{}/admin/users/{id}/roles", srv.base_url))
                .json(&json!({"role": role})),
        )
    };
    let (status, body) = answer(assign("admin")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body
        .as_str()
        .unwrap()
        .contains("cannot hold the admin role"));
    let (status, body) = answer(assign("writer")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let services = list(&srv, "?kind=service").await;
    let view = services.iter().find(|u| u["id"] == json!(id)).unwrap();
    assert_eq!(view["roles"], json!(["writer"]));
}

#[tokio::test]
async fn nobody_signs_in_to_a_service_account_but_its_tokens_work() {
    let srv = server().await;
    srv.set_auth_settings(json!({"allow_password_basic": true}))
        .await;
    let name = format!("ci{}@example.com", common::unique());
    let id = create_service_account(&srv, &name, None).await["id"]
        .as_i64()
        .unwrap();

    // Not through the login screen, nor with a password over Basic.
    for password in ["", "a-guess-of-a-password"] {
        let (status, _) = answer(
            srv.client()
                .post(format!("{}/auth/login", srv.base_url))
                .json(&json!({"username": name, "password": password})),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "login with {password:?}");
    }
    assert_eq!(
        answer(me_request(&srv).basic_auth(&name, Some("a-guess-of-a-password"))).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );

    // The tokens an administrator issues for it work, as an API key and as
    // the Basic password, and record when it was last used.
    let secret = issue_token(&srv, id, json!({"name": "pipeline"})).await;
    for rb in [
        me_request(&srv).header("X-NuGet-ApiKey", &secret),
        me_request(&srv).basic_auth(&name, Some(&secret)),
        me_request(&srv).basic_auth("anything", Some(&secret)),
    ] {
        let (status, body) = answer(rb).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["user"]["id"], json!(id));
        assert_eq!(body["is_admin"], json!(false));
    }
    let services = list(&srv, "?kind=service").await;
    let view = services.iter().find(|u| u["id"] == json!(id)).unwrap();
    assert!(view["last_used_at"].is_string(), "{view}");

    // Even a token with the admin scope does not make it an administrator.
    let scoped = issue_token(&srv, id, json!({"name": "ops", "scope": {"admin": true}})).await;
    let (status, _) = answer(
        srv.client()
            .get(format!("{}/admin/users", srv.base_url))
            .header("X-NuGet-ApiKey", &scoped),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Deactivating it stops its tokens; reactivating it lets them work again.
    let (status, body) = patch(&srv, id, json!({"active": false})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], json!("inactive"));
    let (status, _) = answer(me_request(&srv).header("X-NuGet-ApiKey", &secret)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = patch(&srv, id, json!({"active": true})).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = answer(me_request(&srv).header("X-NuGet-ApiKey", &secret)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn only_its_own_trusted_header_realm_names_a_service_account() {
    let srv = server().await;
    let own = create_realm(&srv, false).await;
    // A realm that provisions accounts cannot take the name over either.
    let other = create_realm(&srv, true).await;
    let lan = format!("office-lan{}@example.com", common::unique());
    let id = create_service_account(&srv, &lan, Some(&own.name)).await["id"]
        .as_i64()
        .unwrap();
    let tokens_only = format!("ci{}@example.com", common::unique());
    create_service_account(&srv, &tokens_only, None).await;

    let (status, body) = answer(own.named(me_request(&srv), &lan)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["id"], json!(id));
    // It is no administrator, and the headers reach no admin API anyway.
    assert_eq!(body["is_admin"], json!(false));
    let services = list(&srv, "?kind=service").await;
    let view = services.iter().find(|u| u["id"] == json!(id)).unwrap();
    assert_eq!(view["realm"], json!(own.name));
    assert!(view["last_used_at"].is_string(), "{view}");

    // Another realm never names it, nor does any realm name a service
    // account of no realm.
    assert_eq!(
        answer(other.named(me_request(&srv), &lan)).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );
    assert_eq!(
        answer(own.named(me_request(&srv), &tokens_only)).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );
    assert_eq!(
        answer(other.named(me_request(&srv), &tokens_only)).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );

    // Moved to the other realm, that one names it, and its former one no
    // longer does.
    let (status, body) = patch(&srv, id, json!({"realm": other.name})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = answer(other.named(me_request(&srv), &lan)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["id"], json!(id));
    assert_eq!(
        answer(own.named(me_request(&srv), &lan)).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );

    // Deactivated, no realm names it.
    let (status, _) = patch(&srv, id, json!({"active": false})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        answer(other.named(me_request(&srv), &lan)).await,
        (StatusCode::UNAUTHORIZED, json!(INVALID))
    );
}
