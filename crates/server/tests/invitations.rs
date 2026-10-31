//! Inviting users (#322): `POST /admin/users` creates a local account
//! without a password and emails its user a link (through a real mailpit,
//! `mirror.gcr.io/axllent/mailpit`, on loopback), with which they choose the
//! password once. An invited account signs in by no path, not even through a
//! credential-forwarding realm after `local`; a new invitation replaces the
//! old one, and revoking it, deactivating or deleting the account kills its
//! link. Without an email service the link is handed to the administrator.

mod common;

use std::time::Duration;

use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const MAILPIT_IMAGE: &str = "mirror.gcr.io/axllent/mailpit";
const MAILPIT_TAG: &str = "v1.27.11";
const INVALID: &str =
    "This invitation is invalid or has expired; ask your administrator for a new one.";

/// A mailpit taking plain SMTP (on loopback, which Forge allows without TLS).
struct Mailpit {
    smtp_port: u16,
    api: String,
    _container: ContainerAsync<GenericImage>,
}

impl Mailpit {
    async fn start() -> Mailpit {
        let container = GenericImage::new(MAILPIT_IMAGE, MAILPIT_TAG)
            .with_exposed_port(1025.tcp())
            .with_exposed_port(8025.tcp())
            .with_wait_for(WaitFor::message_on_stdout("accessible via"))
            .with_env_var("MP_DISABLE_VERSION_CHECK", "true")
            .start()
            .await
            .expect("start mailpit (is Docker running?)");
        let host = container.get_host().await.unwrap();
        Mailpit {
            smtp_port: container.get_host_port_ipv4(1025).await.unwrap(),
            api: format!(
                "http://{host}:{}/api/v1",
                container.get_host_port_ipv4(8025).await.unwrap()
            ),
            _container: container,
        }
    }

    /// The text of the only message sent to `to`.
    async fn text_to(&self, to: &str) -> String {
        for _ in 0..50 {
            let body: Value = reqwest::get(format!("{}/messages", self.api))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let found = body["messages"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|m| m["To"][0]["Address"] == json!(to))
                .cloned();
            if let Some(message) = found {
                assert_eq!(message["Subject"], "Your Forge account");
                let full: Value = reqwest::get(format!(
                    "{}/message/{}",
                    self.api,
                    message["ID"].as_str().unwrap()
                ))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
                return full["Text"].as_str().unwrap().to_string();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("mailpit never received a message to {to}");
    }
}

/// A server on a database of its own: email settings and realms are
/// install-wide.
async fn server() -> common::TestServer {
    common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await
}

async fn admin(
    srv: &common::TestServer,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> (reqwest::StatusCode, Value) {
    let (u, p) = srv.admin_basic();
    let req = srv
        .client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(&u, Some(&p));
    let resp = match body {
        Some(body) => req.json(&body),
        None => req,
    }
    .send()
    .await
    .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn post_auth(
    srv: &common::TestServer,
    path: &str,
    body: Value,
) -> (reqwest::StatusCode, Value) {
    let resp = srv
        .client()
        .post(format!("{}{path}", srv.base_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// The token of an invitation link.
fn token_of(link: &str) -> String {
    link.split_once("/invite#")
        .expect("an invitation link")
        .1
        .to_string()
}

/// Whether the invitation `token` is live (`/auth/invitations/lookup`).
async fn live(srv: &common::TestServer, token: &str) -> bool {
    let (status, body) = post_auth(srv, "/auth/invitations/lookup", json!({"token": token})).await;
    match status.as_u16() {
        200 => true,
        400 => {
            assert_eq!(body["error"], INVALID);
            false
        }
        other => panic!("lookup answered {other}: {body}"),
    }
}

async fn user_view(srv: &common::TestServer, id: i64) -> Value {
    let (status, users) = admin(srv, reqwest::Method::GET, "/admin/users", None).await;
    assert_eq!(status, 200);
    users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == json!(id))
        .cloned()
        .expect("listed")
}

async fn login(srv: &common::TestServer, username: &str, password: &str) -> reqwest::StatusCode {
    post_auth(
        srv,
        "/auth/login",
        json!({"username": username, "password": password}),
    )
    .await
    .0
}

/// The invitation goes out by email; its link names the account, takes a
/// password of at least 12 characters once, and the user signs in.
#[tokio::test]
async fn an_emailed_invitation_sets_the_password_once() {
    let mailpit = Mailpit::start().await;
    let srv = server().await;
    let (status, body) = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(json!({
            "from_address": "forge@example.com",
            "invitation_ttl_hours": 24,
            "transport": {"kind": "smtp", "host": "127.0.0.1", "port": mailpit.smtp_port, "tls": "none"},
        })),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let username = format!("alice{}@example.com", common::unique());
    let inbox = format!("alice.mail{}@example.org", common::unique());
    let (status, created) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/users",
        Some(json!({"username": username, "email": inbox, "role": "writer"})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["status"], "invited");
    assert_eq!(created["email"], json!(inbox));
    assert_eq!(created["roles"], json!(["writer"]));
    assert_eq!(created["invitation"]["email_sent"], json!(true));
    assert_eq!(created["invitation"]["link"], Value::Null, "{created}");
    let expires: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(created["invitation"]["expires_at"].clone()).unwrap();
    let lifetime = expires - chrono::Utc::now();
    assert!(lifetime > chrono::Duration::hours(23) && lifetime <= chrono::Duration::hours(24));
    let id = created["id"].as_i64().unwrap();
    let view = user_view(&srv, id).await;
    assert_eq!(view["status"], "invited");
    assert!(view["invitation"]["sent_at"].is_string(), "{view}");

    let text = mailpit.text_to(&inbox).await;
    assert!(text.contains(&username), "{text}");
    let link = text
        .split_whitespace()
        .find(|w| w.starts_with("http://test.local/invite#"))
        .unwrap_or_else(|| panic!("no link in {text}"));
    let token = token_of(link);
    // Only the hash is stored.
    let stored: String =
        sqlx::query_scalar("SELECT token_hash FROM user_invitation WHERE user_id = $1")
            .bind(id)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert_ne!(stored, token);

    let (status, found) =
        post_auth(&srv, "/auth/invitations/lookup", json!({"token": token})).await;
    assert_eq!(status, 200);
    assert_eq!(found["username"], json!(username));

    // Not signed in before, with any password.
    assert_eq!(login(&srv, &username, "whatever-password").await, 401);

    let (status, body) = post_auth(
        &srv,
        "/auth/invitations/accept",
        json!({"token": token, "password": "too-short"}),
    )
    .await;
    assert_eq!(status, 400);
    assert!(body["error"].as_str().unwrap().contains("12"), "{body}");
    let (status, body) = post_auth(
        &srv,
        "/auth/invitations/accept",
        json!({"token": token, "password": "a-long-enough-password"}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["username"], json!(username));

    assert_eq!(login(&srv, &username, "a-long-enough-password").await, 200);
    let view = user_view(&srv, id).await;
    assert_eq!(view["status"], "active");
    assert_eq!(view["invitation"], Value::Null);

    // Once.
    let (status, body) = post_auth(
        &srv,
        "/auth/invitations/accept",
        json!({"token": token, "password": "another-long-password"}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], INVALID);
    assert!(!live(&srv, &token).await);
    assert_eq!(login(&srv, &username, "a-long-enough-password").await, 200);

    // An account whose user chose a password is invited no more.
    let (status, _) = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/users/{id}/invitation"),
        None,
    )
    .await;
    assert_eq!(status, 409);
}

/// A new invitation replaces the old one, and revoking it, deactivating or
/// deleting the account, or its expiry, kills the link. Without an email
/// service the link is handed over.
#[tokio::test]
async fn links_die_with_replacement_revocation_deactivation_expiry_and_deletion() {
    let srv = server().await;
    let username = format!("bob{}@example.com", common::unique());
    let (status, created) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/users",
        Some(json!({"username": username})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["invitation"]["email_sent"], json!(false));
    assert_eq!(
        created["invitation"]["error"],
        "no email service is configured"
    );
    assert_eq!(
        created["invitation"]["email"],
        json!(username),
        "the username by default"
    );
    let first = token_of(created["invitation"]["link"].as_str().unwrap());
    let id = created["id"].as_i64().unwrap();
    let invite = |body: Option<Value>| {
        let srv = &srv;
        async move {
            admin(
                srv,
                reqwest::Method::POST,
                &format!("/admin/users/{id}/invitation"),
                body,
            )
            .await
        }
    };

    // "Copy invitation link": a new link, the old one dead.
    let (status, copied) = invite(Some(json!({"send_email": false}))).await;
    assert_eq!(status, 200, "{copied}");
    assert_eq!(copied["error"], Value::Null);
    let second = token_of(copied["link"].as_str().unwrap());
    assert!(!live(&srv, &first).await);
    assert!(live(&srv, &second).await);

    // "Resend" to another address, with no email service: the link again.
    let (status, resent) = invite(Some(json!({"email": "bob.home@example.org"}))).await;
    assert_eq!(status, 200);
    assert_eq!(resent["email_sent"], json!(false));
    assert_eq!(resent["email"], "bob.home@example.org");
    let third = token_of(resent["link"].as_str().unwrap());
    assert!(!live(&srv, &second).await);
    assert_eq!(user_view(&srv, id).await["email"], "bob.home@example.org");

    // Revoked.
    let (status, _) = admin(
        &srv,
        reqwest::Method::DELETE,
        &format!("/admin/users/{id}/invitation"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(!live(&srv, &third).await);
    assert_eq!(user_view(&srv, id).await["status"], "invitation_expired");
    let (status, _) = admin(
        &srv,
        reqwest::Method::DELETE,
        &format!("/admin/users/{id}/invitation"),
        None,
    )
    .await;
    assert_eq!(status, 404);

    // Expired.
    let (_, made) = invite(None).await;
    let fourth = token_of(made["link"].as_str().unwrap());
    sqlx::query(
        "UPDATE user_invitation SET expires_at = now() - interval '1 second' WHERE user_id = $1",
    )
    .bind(id)
    .execute(&srv.pool)
    .await
    .unwrap();
    assert!(!live(&srv, &fourth).await);
    let (status, body) = post_auth(
        &srv,
        "/auth/invitations/accept",
        json!({"token": fourth, "password": "a-long-enough-password"}),
    )
    .await;
    assert_eq!(
        (status.as_u16(), body["error"].clone()),
        (400, json!(INVALID))
    );
    assert_eq!(user_view(&srv, id).await["status"], "invitation_expired");

    // Deactivated: the link dies, and no new one is made until reactivated.
    let (_, made) = invite(None).await;
    let fifth = token_of(made["link"].as_str().unwrap());
    let (status, _) = admin(
        &srv,
        reqwest::Method::PATCH,
        &format!("/admin/users/{id}"),
        Some(json!({"active": false})),
    )
    .await;
    assert_eq!(status, 200);
    assert!(!live(&srv, &fifth).await);
    assert_eq!(user_view(&srv, id).await["status"], "inactive");
    let (status, _) = invite(None).await;
    assert_eq!(status, 409);
    let (status, _) = admin(
        &srv,
        reqwest::Method::PATCH,
        &format!("/admin/users/{id}"),
        Some(json!({"active": true})),
    )
    .await;
    assert_eq!(status, 200);
    assert!(!live(&srv, &fifth).await, "reactivating revives no link");
    assert_eq!(user_view(&srv, id).await["status"], "invitation_expired");

    // Deleted.
    let (_, made) = invite(None).await;
    let sixth = token_of(made["link"].as_str().unwrap());
    assert!(live(&srv, &sixth).await);
    let (status, _) = admin(
        &srv,
        reqwest::Method::DELETE,
        &format!("/admin/users/{id}"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(!live(&srv, &sixth).await);
    let (status, _) = invite(None).await;
    assert_eq!(status, 404);
}

/// An invited account signs in by no path: not with any password at the
/// login, not over Basic, and not through a credential-forwarding realm after
/// `local` whose upstream accepts everything (nothing is forwarded); no
/// forwarded account can take its name.
#[tokio::test]
async fn an_invited_account_signs_in_by_no_path() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let srv = server().await;
    let (status, body) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/realms",
        Some(json!({
            "kind": "credential_forwarding",
            "name": "directory",
            "config": {"url": format!("{}/status", upstream.uri()), "key_pepper": "pepper"},
        })),
    )
    .await;
    assert_eq!(status, 201, "{body}");

    let username = format!("carol{}@example.com", common::unique());
    let (status, created) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/users",
        Some(json!({"username": username})),
    )
    .await;
    assert_eq!(status, 201, "{created}");

    for password in ["", "anything-the-upstream-takes", "a"] {
        if !password.is_empty() {
            assert_eq!(login(&srv, &username, password).await, 401, "{password:?}");
        }
        let resp = srv
            .client()
            .get(format!("{}/admin/me", srv.base_url))
            .basic_auth(&username, Some(password))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "Basic {password:?}");
    }
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "an invited account's password is never forwarded"
    );

    // The name is the local account's.
    let (status, _) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/users",
        Some(json!({"username": username, "realm": "directory"})),
    )
    .await;
    assert_eq!(status, 409);

    // Once its user chose the password, it signs in.
    let token = token_of(created["invitation"]["link"].as_str().unwrap());
    let resp = srv.accept_invitation(&token, "carols-own-password").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(login(&srv, &username, "carols-own-password").await, 200);
}

/// `POST /admin/users` takes no password; it checks the name, the address and
/// the role, and an account of a forwarding realm gets no invitation.
#[tokio::test]
async fn creating_a_user_takes_no_password() {
    let upstream = MockServer::start().await;
    let srv = server().await;
    let n = common::unique();

    let (status, body) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/users",
        Some(json!({"username": format!("dave{n}@example.com"), "password": "a-long-enough-password"})),
    )
    .await;
    assert!(status.is_client_error(), "{status}");
    assert!(body.to_string().contains("password"), "{body}");

    for (body, needle) in [
        (json!({"username": format!("dave{n}")}), "invalid username"),
        (
            json!({"username": format!("dave{n}@example.com"), "email": "not an address"}),
            "not an email address",
        ),
    ] {
        let (status, answer) = admin(&srv, reqwest::Method::POST, "/admin/users", Some(body)).await;
        assert_eq!(status, 400, "{answer}");
        assert!(answer.as_str().unwrap().contains(needle), "{answer}");
    }
    let (status, _) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/users",
        Some(json!({"username": format!("dave{n}@example.com"), "role": "owner"})),
    )
    .await;
    assert!(status.is_client_error());

    // An administrator.
    let (status, created) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/users",
        Some(json!({"username": format!("erin{n}@example.com"), "role": "admin"})),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(created["is_admin"], json!(true));

    // A forwarding realm's account: its address kept, no invitation.
    let (status, _) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/realms",
        Some(json!({
            "kind": "credential_forwarding",
            "name": "directory",
            "config": {"url": format!("{}/status", upstream.uri()), "key_pepper": "pepper"},
        })),
    )
    .await;
    assert_eq!(status, 201);
    let (status, created) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/users",
        Some(json!({
            "username": format!("frank{n}@example.com"),
            "email": "frank@example.org",
            "realm": "directory",
        })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["invitation"], Value::Null);
    assert_eq!(created["status"], "active");
    assert_eq!(created["email"], "frank@example.org");
    let (status, _) = admin(
        &srv,
        reqwest::Method::POST,
        &format!("/admin/users/{}/invitation", created["id"]),
        None,
    )
    .await;
    assert_eq!(status, 409, "only local accounts are invited");
}

/// `POST /admin/users/{id}/invitation/accept` (#653): an administrator
/// accepts an invited account's invitation for its user, with a password
/// they set, whether a live invitation waits or not. The user signs in with
/// it, the account is active, and the old link answers as invalid. The
/// password follows the invitation page's rules (400); an account that is
/// not an active invited local one is refused (409), and no account is 404.
#[tokio::test]
async fn an_administrator_accepts_an_invitation_with_a_password_they_set() {
    let upstream = MockServer::start().await;
    let srv = server().await;
    let n = common::unique();
    let accept = |id: i64, password: &str| {
        let srv = &srv;
        let body = json!({ "password": password });
        async move {
            admin(
                srv,
                reqwest::Method::POST,
                &format!("/admin/users/{id}/invitation/accept"),
                Some(body),
            )
            .await
        }
    };
    let create = |body: Value| {
        let srv = &srv;
        async move {
            let (status, created) =
                admin(srv, reqwest::Method::POST, "/admin/users", Some(body)).await;
            assert_eq!(status, 201, "{created}");
            created
        }
    };

    // A live invitation waits.
    let username = format!("gina{n}@example.com");
    let created = create(json!({ "username": username })).await;
    let id = created["id"].as_i64().unwrap();
    let token = token_of(created["invitation"]["link"].as_str().unwrap());
    assert_eq!(created["status"], "invited");

    // The invitation page's rules.
    let (status, body) = accept(id, "too-short").await;
    assert_eq!(status, 400, "{body}");
    assert!(body.as_str().unwrap().contains("12"), "{body}");
    let (status, body) = accept(id, &"x".repeat(1025)).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.as_str().unwrap().contains("1024"), "{body}");
    assert_eq!(user_view(&srv, id).await["status"], "invited");
    assert!(
        live(&srv, &token).await,
        "a refused password changes nothing"
    );

    let (status, view) = accept(id, "set-by-the-administrator").await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["id"], json!(id));
    assert_eq!(view["status"], "active");
    assert_eq!(view["invitation"], Value::Null);
    assert_eq!(user_view(&srv, id).await["status"], "active");
    assert_eq!(
        login(&srv, &username, "set-by-the-administrator").await,
        200
    );
    let accepted_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT accepted_at FROM user_invitation WHERE user_id = $1")
            .bind(id)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert!(accepted_at.is_some(), "the invitation is marked accepted");

    // The old link answers as invalid.
    assert!(!live(&srv, &token).await);
    let resp = srv.accept_invitation(&token, "the-users-own-choice").await;
    assert_eq!(resp.status(), 400);
    assert_eq!(login(&srv, &username, "the-users-own-choice").await, 401);

    // Its user has a password now: once only.
    let (status, _) = accept(id, "another-long-password").await;
    assert_eq!(status, 409);
    assert_eq!(
        login(&srv, &username, "set-by-the-administrator").await,
        200
    );

    // The invitation expired.
    let expired = format!("hank{n}@example.com");
    let created = create(json!({ "username": expired })).await;
    let expired_id = created["id"].as_i64().unwrap();
    sqlx::query(
        "UPDATE user_invitation SET expires_at = now() - interval '1 second' WHERE user_id = $1",
    )
    .bind(expired_id)
    .execute(&srv.pool)
    .await
    .unwrap();
    assert_eq!(
        user_view(&srv, expired_id).await["status"],
        "invitation_expired"
    );
    let (status, view) = accept(expired_id, "set-after-it-expired").await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["status"], "active");
    assert_eq!(login(&srv, &expired, "set-after-it-expired").await, 200);

    // No invitation at all: revoked.
    let revoked = format!("iris{n}@example.com");
    let created = create(json!({ "username": revoked })).await;
    let revoked_id = created["id"].as_i64().unwrap();
    let (status, _) = admin(
        &srv,
        reqwest::Method::DELETE,
        &format!("/admin/users/{revoked_id}/invitation"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, view) = accept(revoked_id, "set-without-a-link").await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["status"], "active");
    assert_eq!(login(&srv, &revoked, "set-without-a-link").await, 200);

    // A deactivated invited account: refused, and still invited.
    let inactive = format!("jack{n}@example.com");
    let created = create(json!({ "username": inactive })).await;
    let inactive_id = created["id"].as_i64().unwrap();
    let (status, _) = admin(
        &srv,
        reqwest::Method::PATCH,
        &format!("/admin/users/{inactive_id}"),
        Some(json!({"active": false})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = accept(inactive_id, "set-while-deactivated").await;
    assert_eq!(status, 409);
    let (status, _) = admin(
        &srv,
        reqwest::Method::PATCH,
        &format!("/admin/users/{inactive_id}"),
        Some(json!({"active": true})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        user_view(&srv, inactive_id).await["status"],
        "invitation_expired"
    );
    assert_eq!(login(&srv, &inactive, "set-while-deactivated").await, 401);

    // An account of another realm, a service account, the administrator.
    let (status, _) = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/realms",
        Some(json!({
            "kind": "credential_forwarding",
            "name": "directory",
            "config": {"url": format!("{}/status", upstream.uri()), "key_pepper": "pepper"},
        })),
    )
    .await;
    assert_eq!(status, 201);
    let forwarded = create(json!({
        "username": format!("kate{n}@example.com"),
        "realm": "directory",
    }))
    .await;
    let service = create(json!({
        "username": format!("ci{n}@example.com"),
        "kind": "service",
        "description": "The build agents",
    }))
    .await;
    let (admin_name, _) = srv.admin_basic();
    let admin_id = {
        let (status, users) = admin(&srv, reqwest::Method::GET, "/admin/users", None).await;
        assert_eq!(status, 200);
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["username"] == json!(admin_name))
            .expect("the administrator is listed")["id"]
            .as_i64()
            .unwrap()
    };
    for id in [
        forwarded["id"].as_i64().unwrap(),
        service["id"].as_i64().unwrap(),
        admin_id,
    ] {
        let (status, body) = accept(id, "not-for-this-account").await;
        assert_eq!(status, 409, "{id}: {body}");
    }

    // No account.
    let (status, _) = accept(i64::MAX, "for-nobody-at-all").await;
    assert_eq!(status, 404);
}

/// Failed lookups and acceptances are throttled per client network.
#[tokio::test]
async fn invitation_failures_are_throttled() {
    let srv = server().await;
    let mut statuses = Vec::new();
    for i in 0..12 {
        let (status, _) = post_auth(
            &srv,
            "/auth/invitations/lookup",
            json!({"token": format!("guess-{i}")}),
        )
        .await;
        statuses.push(status.as_u16());
    }
    assert_eq!(&statuses[..10], &[400; 10]);
    assert_eq!(&statuses[10..], &[429, 429]);
}
