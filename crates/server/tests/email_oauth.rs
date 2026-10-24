//! SMTP with OAuth (#321), against a mock authorization server (`wiremock`)
//! and an SMTP server in this test that checks the SASL `OAUTHBEARER` or
//! `XOAUTH2` token: Forge registers itself (RFC 7591) or uses a client
//! entered by hand, the mailbox authorizes it by the code flow with PKCE or
//! the device flow, access tokens come from the refresh token (rotated and
//! stored) or the client credentials grant, and a refused refresh, a refused
//! token and a changed issuer each end as they should.

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const MAILBOX: &str = "forge@example.com";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// --- an SMTP server that takes OAuth tokens ---------------------------------

#[derive(Default)]
struct SmtpLog {
    /// Each `AUTH`: the mechanism and its decoded initial response.
    auths: Vec<(String, String)>,
    /// The client's response to a refusal's challenge.
    dummies: Vec<String>,
    messages: Vec<String>,
}

/// An SMTP server on loopback offering `mechanisms`, accepting the tokens in
/// `accepted`.
struct FakeSmtp {
    port: u16,
    log: Arc<Mutex<SmtpLog>>,
    accepted: Arc<Mutex<HashSet<String>>>,
}

impl FakeSmtp {
    async fn start(mechanisms: &'static str) -> FakeSmtp {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(SmtpLog::default()));
        let accepted = Arc::new(Mutex::new(HashSet::new()));
        let (l, a) = (log.clone(), accepted.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(smtp_session(stream, mechanisms, l.clone(), a.clone()));
            }
        });
        FakeSmtp {
            port,
            log,
            accepted,
        }
    }

    fn accept(&self, token: &str) {
        self.accepted.lock().unwrap().insert(token.to_string());
    }

    fn auths(&self) -> Vec<(String, String)> {
        self.log.lock().unwrap().auths.clone()
    }

    fn messages(&self) -> Vec<String> {
        self.log.lock().unwrap().messages.clone()
    }
}

async fn smtp_session(
    stream: TcpStream,
    mechanisms: &str,
    log: Arc<Mutex<SmtpLog>>,
    accepted: Arc<Mutex<HashSet<String>>>,
) {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    write.write_all(b"220 fake.test ESMTP\r\n").await.unwrap();
    let mut authenticated = false;
    while let Ok(Some(line)) = lines.next_line().await {
        let upper = line.to_ascii_uppercase();
        let reply = if upper.starts_with("EHLO") {
            format!("250-fake.test\r\n250-AUTH {mechanisms}\r\n250 8BITMIME\r\n")
        } else if let Some(rest) = line.strip_prefix("AUTH ") {
            let (mechanism, initial) = rest.split_once(' ').unwrap_or((rest, ""));
            let decoded = String::from_utf8(B64.decode(initial).unwrap()).unwrap();
            log.lock()
                .unwrap()
                .auths
                .push((mechanism.to_ascii_uppercase(), decoded.clone()));
            let token = decoded
                .split('\x01')
                .find_map(|kv| kv.strip_prefix("auth=Bearer "))
                .unwrap_or_default()
                .to_string();
            if accepted.lock().unwrap().contains(&token) {
                authenticated = true;
                "235 2.7.0 Authentication successful\r\n".to_string()
            } else {
                // RFC 7628 §3.2.2: the error as a challenge, then a 535.
                let status = B64.encode(r#"{"status":"invalid_token","schemes":"bearer"}"#);
                write
                    .write_all(format!("334 {status}\r\n").as_bytes())
                    .await
                    .unwrap();
                let dummy = lines.next_line().await.unwrap().unwrap_or_default();
                log.lock().unwrap().dummies.push(dummy);
                "535 5.7.8 Authentication credentials invalid\r\n".to_string()
            }
        } else if upper.starts_with("MAIL FROM") {
            if authenticated {
                "250 2.1.0 OK\r\n".to_string()
            } else {
                "530 5.7.0 Authentication required\r\n".to_string()
            }
        } else if upper.starts_with("RCPT TO") {
            "250 2.1.5 OK\r\n".to_string()
        } else if upper == "DATA" {
            write.write_all(b"354 Go ahead\r\n").await.unwrap();
            let mut message = String::new();
            while let Ok(Some(l)) = lines.next_line().await {
                if l == "." {
                    break;
                }
                message.push_str(&l);
                message.push('\n');
            }
            log.lock().unwrap().messages.push(message);
            "250 2.0.0 Queued\r\n".to_string()
        } else if upper == "QUIT" {
            let _ = write.write_all(b"221 2.0.0 Bye\r\n").await;
            return;
        } else if upper == "RSET" || upper == "NOOP" {
            "250 2.0.0 OK\r\n".to_string()
        } else {
            "502 5.5.2 Unknown command\r\n".to_string()
        };
        if write.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

// --- the authorization server -----------------------------------------------

/// A mock authorization server publishing RFC 8414 metadata, with a
/// registration endpoint when `registration`.
async fn auth_server(registration: bool) -> MockServer {
    let server = MockServer::start().await;
    let uri = server.uri();
    let mut metadata = json!({
        "issuer": uri,
        "authorization_endpoint": format!("{uri}/authorize"),
        "token_endpoint": format!("{uri}/token"),
        "device_authorization_endpoint": format!("{uri}/device"),
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
    });
    if registration {
        metadata["registration_endpoint"] = json!(format!("{uri}/register"));
    }
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(&server)
        .await;
    server
}

/// Registration (with the initial access token `iat-1`) and its deletion.
async fn mount_registration(server: &MockServer, client_id: &str) {
    Mock::given(method("POST"))
        .and(path("/register"))
        .and(header("authorization", "Bearer iat-1"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "client_id": client_id,
            "client_secret": "client-s3cret",
            "registration_client_uri": format!("{}/register/{client_id}", server.uri()),
            "registration_access_token": "reg-token",
        })))
        .mount(server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("/register/{client_id}")))
        .and(header("authorization", "Bearer reg-token"))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

fn tokens(access: &str, refresh: Option<&str>) -> ResponseTemplate {
    let mut body = json!({"access_token": access, "token_type": "Bearer", "expires_in": 3600});
    if let Some(refresh) = refresh {
        body["refresh_token"] = json!(refresh);
    }
    ResponseTemplate::new(200).set_body_json(body)
}

/// The token endpoint, for one `grant_type`.
fn token_grant(grant: &str) -> wiremock::MockBuilder {
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains(format!(
            "grant_type={}",
            url::form_urlencoded::byte_serialize(grant.as_bytes()).collect::<String>()
        )))
}

async fn requests_to(server: &MockServer, method: &str, path: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .expect("recorded")
        .into_iter()
        .filter(|r| r.method.as_str() == method && r.url.path() == path)
        .collect()
}

fn form(request: &Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect()
}

// --- Forge --------------------------------------------------------------------

async fn admin(
    srv: &common::TestServer,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    let req = srv
        .client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(&u, Some(&p));
    match body {
        Some(body) => req.json(&body),
        None => req,
    }
    .send()
    .await
    .unwrap()
}

async fn admin_json(
    srv: &common::TestServer,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> (reqwest::StatusCode, Value) {
    let resp = admin(srv, method, path, body).await;
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// A server on a database of its own (email settings are install-wide).
async fn server() -> common::TestServer {
    common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await
}

fn oauth_settings(issuer: &str, smtp_port: u16, extra: Value) -> Value {
    let mut transport = json!({
        "kind": "smtp_oauth",
        "host": "127.0.0.1",
        "port": smtp_port,
        "tls": "none",
        "issuer": issuer,
        "username": MAILBOX,
        "scope": "smtp",
    });
    transport
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json!({"from_address": MAILBOX, "from_name": "Forge", "transport": transport})
}

async fn put_settings(srv: &common::TestServer, settings: Value) -> Value {
    let (status, view) = admin_json(
        srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(settings),
    )
    .await;
    assert_eq!(status, 200, "{view}");
    view
}

async fn get_settings(srv: &common::TestServer) -> Value {
    let (status, view) = admin_json(srv, reqwest::Method::GET, "/admin/settings/email", None).await;
    assert_eq!(status, 200, "{view}");
    view
}

async fn test_send(srv: &common::TestServer) -> (reqwest::StatusCode, Value) {
    admin_json(
        srv,
        reqwest::Method::POST,
        "/admin/settings/email/test",
        Some(json!({"to": "someone@example.org"})),
    )
    .await
}

async fn register(srv: &common::TestServer) -> Value {
    let (status, view) = admin_json(
        srv,
        reqwest::Method::POST,
        "/admin/settings/email/oauth/register",
        Some(json!({"initial_access_token": "iat-1"})),
    )
    .await;
    assert_eq!(status, 200, "{view}");
    view
}

/// The stored transport, secrets and all.
async fn stored_transport(srv: &common::TestServer) -> Value {
    let stored = forge_server::email::load_stored(&srv.state.pool, &srv.state.envelope)
        .await
        .unwrap()
        .expect("stored");
    serde_json::to_value(&stored.config).unwrap()["transport"].clone()
}

/// Start the code flow: the authorization URL's query and the flow cookie.
async fn start_code_flow(srv: &common::TestServer) -> (HashMap<String, String>, String) {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        "/admin/settings/email/oauth/authorize",
        Some(json!({"method": "authorization_code"})),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let set_cookie = resp.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(
        set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"),
        "{set_cookie}"
    );
    assert!(
        set_cookie.contains("Path=/admin/settings/email/oauth"),
        "{set_cookie}"
    );
    let cookie = set_cookie.split(';').next().unwrap().to_string();
    let body: Value = resp.json().await.unwrap();
    let url = url::Url::parse(body["authorization_url"].as_str().unwrap()).unwrap();
    (url.query_pairs().into_owned().collect(), cookie)
}

/// The authorization server sending the browser back: where Forge sends it
/// on, and the cookie it sets.
async fn callback(
    srv: &common::TestServer,
    query: &str,
    cookie: Option<&str>,
) -> (String, Option<String>) {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let (u, p) = srv.admin_basic();
    let mut req = client
        .get(format!(
            "{}/admin/settings/email/oauth/callback?{query}",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p));
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 302);
    (
        resp.headers()["location"].to_str().unwrap().to_string(),
        resp.headers()
            .get("set-cookie")
            .map(|v| v.to_str().unwrap().to_string()),
    )
}

/// Authorize Forge by the code flow; the token endpoint gives `refresh`.
async fn authorize_by_code(srv: &common::TestServer, auth: &MockServer, refresh: &str) {
    token_grant("authorization_code")
        .respond_with(tokens("access-0", Some(refresh)))
        .up_to_n_times(1)
        .mount(auth)
        .await;
    let (query, cookie) = start_code_flow(srv).await;
    let (location, _) = callback(
        srv,
        &format!("code=code-1&state={}", query["state"]),
        Some(&cookie),
    )
    .await;
    assert_eq!(location, "/manage/settings/email?oauth=authorized");
}

/// Forge registers itself, the mailbox authorizes it in the browser (PKCE),
/// and mail goes out with OAUTHBEARER on a refreshed token, the rotated
/// refresh token stored; no secret is ever returned.
#[tokio::test]
async fn registers_authorizes_by_code_and_sends_with_oauthbearer() {
    let smtp = FakeSmtp::start("PLAIN OAUTHBEARER XOAUTH2").await;
    let auth = auth_server(true).await;
    mount_registration(&auth, "forge-client").await;
    let srv = server().await;

    let view = put_settings(&srv, oauth_settings(&auth.uri(), smtp.port, json!({}))).await;
    assert_eq!(view["transport"]["kind"], "smtp_oauth");
    assert_eq!(
        view["oauth_redirect_uri"],
        "http://test.local/admin/settings/email/oauth/callback"
    );
    assert!(view["transport"].get("client_id").is_none(), "{view}");
    assert_eq!(view["transport"]["refresh_token_set"], json!(false));

    // Nothing to send with yet.
    let (status, body) = test_send(&srv).await;
    assert_eq!(status, 502, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("needs authorization"),
        "{body}"
    );

    let view = register(&srv).await;
    assert_eq!(view["transport"]["client_id"], "forge-client");
    assert_eq!(view["transport"]["registered"], json!(true));
    assert_eq!(view["transport"]["client_secret_set"], json!(true));
    assert_eq!(
        view["transport"]["registration_access_token_set"],
        json!(true)
    );
    for secret in ["client-s3cret", "reg-token", "iat-1"] {
        assert!(!view.to_string().contains(secret), "{view}");
    }
    let registered = requests_to(&auth, "POST", "/register").await;
    assert_eq!(registered.len(), 1);
    let request: Value = serde_json::from_slice(&registered[0].body).unwrap();
    assert_eq!(request["client_name"], "Forge (http://test.local)");
    assert_eq!(
        request["redirect_uris"],
        json!(["http://test.local/admin/settings/email/oauth/callback"])
    );
    assert_eq!(
        request["grant_types"],
        json!([
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "client_credentials"
        ])
    );
    assert_eq!(request["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(request["scope"], "smtp");

    token_grant("authorization_code")
        .respond_with(tokens("access-1", Some("refresh-1")))
        .expect(1)
        .mount(&auth)
        .await;
    token_grant("refresh_token")
        .respond_with(tokens("access-2", Some("refresh-2")))
        .expect(1)
        .mount(&auth)
        .await;

    let (query, cookie) = start_code_flow(&srv).await;
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], "forge-client");
    assert_eq!(
        query["redirect_uri"],
        "http://test.local/admin/settings/email/oauth/callback"
    );
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["login_hint"], MAILBOX);
    assert_eq!(query["scope"], "smtp");

    // RFC 9207: the issuer the server names is the flow's.
    let (location, cleared) = callback(
        &srv,
        &format!(
            "code=code-1&state={}&iss={}",
            query["state"],
            url::form_urlencoded::byte_serialize(auth.uri().as_bytes()).collect::<String>()
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(location, "/manage/settings/email?oauth=authorized");
    assert!(cleared.unwrap().contains("Max-Age=0"));

    // The exchange: the client's Basic credentials, the code, the PKCE
    // verifier of the challenge, the redirect URI.
    let exchange = requests_to(&auth, "POST", "/token").await;
    let exchange = exchange
        .iter()
        .find(|r| form(r)["grant_type"] == "authorization_code")
        .unwrap();
    assert_eq!(
        exchange.headers["authorization"].to_str().unwrap(),
        format!("Basic {}", B64.encode("forge-client:client-s3cret"))
    );
    let exchange = form(exchange);
    assert_eq!(exchange["client_id"], "forge-client");
    assert_eq!(exchange["code"], "code-1");
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(exchange["code_verifier"].as_bytes())),
        query["code_challenge"]
    );
    assert_eq!(exchange["redirect_uri"], query["redirect_uri"]);

    let view = get_settings(&srv).await;
    assert_eq!(view["transport"]["grant"], "refresh_token");
    assert_eq!(view["transport"]["refresh_token_set"], json!(true));
    assert!(!view.to_string().contains("refresh-1"));

    // Two sends, one refresh: the second reuses the access token.
    smtp.accept("access-2");
    for _ in 0..2 {
        let (status, body) = test_send(&srv).await;
        assert_eq!(status, 200, "{body}");
    }
    let auths = smtp.auths();
    assert_eq!(auths.len(), 2);
    assert_eq!(auths[0].0, "OAUTHBEARER");
    assert_eq!(
        auths[0].1,
        format!(
            "n,a={MAILBOX},\x01host=127.0.0.1\x01port={}\x01auth=Bearer access-2\x01\x01",
            smtp.port
        )
    );
    let messages = smtp.messages();
    assert_eq!(messages.len(), 2);
    assert!(
        messages[0].contains("To: someone@example.org"),
        "{}",
        messages[0]
    );
    let refresh = requests_to(&auth, "POST", "/token").await;
    let refresh = refresh
        .iter()
        .find(|r| form(r)["grant_type"] == "refresh_token")
        .unwrap();
    assert_eq!(form(refresh)["refresh_token"], "refresh-1");

    // The rotated refresh token is the one stored now.
    assert_eq!(stored_transport(&srv).await["refresh_token"], "refresh-2");

    // A state is used once.
    let (location, _) = callback(
        &srv,
        &format!("code=code-1&state={}", query["state"]),
        Some(&cookie),
    )
    .await;
    assert_eq!(location, "/manage/settings/email?oauth=expired");
}

/// The callback completes only in the browser that started the flow, and
/// reports a mailbox that declined.
#[tokio::test]
async fn the_callback_is_bound_to_the_browser() {
    let smtp = FakeSmtp::start("OAUTHBEARER").await;
    let auth = auth_server(true).await;
    mount_registration(&auth, "forge-client").await;
    let srv = server().await;
    put_settings(&srv, oauth_settings(&auth.uri(), smtp.port, json!({}))).await;
    register(&srv).await;

    // Another browser (no cookie, or another one).
    for cookie in [None, Some("forge_email_oauth=planted")] {
        let (query, _) = start_code_flow(&srv).await;
        let (location, _) = callback(
            &srv,
            &format!("code=code-1&state={}", query["state"]),
            cookie,
        )
        .await;
        assert_eq!(location, "/manage/settings/email?oauth=other_session");
    }

    // The mailbox declined: the OAuth error code is passed on, its
    // description is not.
    let (query, cookie) = start_code_flow(&srv).await;
    let (location, _) = callback(
        &srv,
        &format!(
            "error=access_denied&error_description=Go+to+evil.example&state={}",
            query["state"]
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        location,
        "/manage/settings/email?oauth=refused&error=access_denied"
    );

    // Another server's answer (a mix-up, RFC 9207).
    let (query, cookie) = start_code_flow(&srv).await;
    let (location, _) = callback(
        &srv,
        &format!(
            "code=code-1&state={}&iss=https%3A%2F%2Fevil.example",
            query["state"]
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(location, "/manage/settings/email?oauth=wrong_issuer");

    // Unknown state.
    let (location, _) = callback(&srv, "code=x&state=nope", Some(&cookie)).await;
    assert_eq!(location, "/manage/settings/email?oauth=expired");

    // No token request was made for any of them.
    assert!(requests_to(&auth, "POST", "/token").await.is_empty());
    assert_eq!(get_settings(&srv).await["transport"]["grant"], Value::Null);
}

/// A client entered by hand (no registration endpoint), authorized by the
/// device flow; a server that offers only XOAUTH2 gets that.
#[tokio::test]
async fn the_device_flow_authorizes_a_client_entered_by_hand() {
    let smtp = FakeSmtp::start("LOGIN XOAUTH2").await;
    let auth = auth_server(false).await;
    let srv = server().await;
    let view = put_settings(
        &srv,
        oauth_settings(
            &auth.uri(),
            smtp.port,
            json!({"client_id": "manual-client", "client_secret": "manual-s3cret"}),
        ),
    )
    .await;
    assert_eq!(view["transport"]["client_id"], "manual-client");
    assert_eq!(view["transport"]["client_secret_set"], json!(true));
    assert!(view["transport"].get("registered").is_none(), "{view}");

    // Nothing to register with.
    let (status, body) = admin_json(
        &srv,
        reqwest::Method::POST,
        "/admin/settings/email/oauth/register",
        None,
    )
    .await;
    assert_eq!(status, 409, "{body}");

    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dev-1",
            "user_code": "WDJB-MJHT",
            "verification_uri": format!("{}/device-ui", auth.uri()),
            "verification_uri_complete": "javascript:alert(1)",
            "expires_in": 600,
            "interval": 1,
        })))
        .expect(1)
        .mount(&auth)
        .await;
    token_grant("urn:ietf:params:oauth:grant-type:device_code")
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"error": "authorization_pending"})),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&auth)
        .await;
    token_grant("urn:ietf:params:oauth:grant-type:device_code")
        .respond_with(tokens("access-d", Some("refresh-d")))
        .with_priority(2)
        .mount(&auth)
        .await;
    token_grant("refresh_token")
        .respond_with(tokens("access-x", None))
        .mount(&auth)
        .await;

    let (status, start) = admin_json(
        &srv,
        reqwest::Method::POST,
        "/admin/settings/email/oauth/authorize",
        Some(json!({"method": "device"})),
    )
    .await;
    assert_eq!(status, 200, "{start}");
    assert_eq!(start["user_code"], "WDJB-MJHT");
    assert_eq!(
        start["verification_uri"],
        format!("{}/device-ui", auth.uri())
    );
    // Shown as a link: only a web URL is passed on.
    assert_eq!(start["verification_uri_complete"], Value::Null);
    assert_eq!(start["interval"], 1);
    let poll = format!(
        "/admin/settings/email/oauth/device/{}",
        start["flow_id"].as_str().unwrap()
    );

    // Pending at the server; then not due yet (no request); then done.
    let (_, body) = admin_json(&srv, reqwest::Method::POST, &poll, None).await;
    assert_eq!(body["status"], "pending", "{body}");
    let (_, body) = admin_json(&srv, reqwest::Method::POST, &poll, None).await;
    assert_eq!(body["status"], "pending", "{body}");
    let device_polls = |requests: Vec<Request>| {
        requests
            .iter()
            .filter(|r| form(r)["grant_type"].ends_with("device_code"))
            .count()
    };
    assert_eq!(device_polls(requests_to(&auth, "POST", "/token").await), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (_, body) = admin_json(&srv, reqwest::Method::POST, &poll, None).await;
    assert_eq!(body["status"], "authorized", "{body}");
    assert_eq!(body["settings"]["transport"]["grant"], "refresh_token");

    // The poll's client authentication and device code.
    let token_requests = requests_to(&auth, "POST", "/token").await;
    let last = token_requests.last().unwrap();
    assert_eq!(
        last.headers["authorization"].to_str().unwrap(),
        format!("Basic {}", B64.encode("manual-client:manual-s3cret"))
    );
    assert_eq!(form(last)["device_code"], "dev-1");
    // Also in the form: Stalwart reads the device grant's client from there.
    assert_eq!(form(last)["client_id"], "manual-client");

    // The flow is gone.
    let (status, _) = admin_json(&srv, reqwest::Method::POST, &poll, None).await;
    assert_eq!(status, 404);

    smtp.accept("access-x");
    let (status, body) = test_send(&srv).await;
    assert_eq!(status, 200, "{body}");
    let auths = smtp.auths();
    assert_eq!(
        auths,
        [(
            "XOAUTH2".to_string(),
            format!("user={MAILBOX}\x01auth=Bearer access-x\x01\x01")
        )]
    );
    // No rotation: the refresh token stays.
    assert_eq!(stored_transport(&srv).await["refresh_token"], "refresh-d");
}

/// A refused refresh (`invalid_grant`) asks for authorization again, on the
/// settings page and in the send's error, and is not retried.
#[tokio::test]
async fn a_refused_refresh_asks_for_authorization_again() {
    let smtp = FakeSmtp::start("OAUTHBEARER").await;
    let auth = auth_server(true).await;
    mount_registration(&auth, "forge-client").await;
    let srv = server().await;
    put_settings(&srv, oauth_settings(&auth.uri(), smtp.port, json!({}))).await;
    register(&srv).await;
    authorize_by_code(&srv, &auth, "refresh-1").await;
    token_grant("refresh_token")
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "refresh token revoked",
        })))
        .expect(1)
        .mount(&auth)
        .await;

    for _ in 0..2 {
        let (status, body) = test_send(&srv).await;
        assert_eq!(status, 502, "{body}");
        let error = body["error"].as_str().unwrap();
        assert!(error.contains("needs authorization"), "{error}");
        assert!(error.contains("refresh token revoked"), "{error}");
    }
    let view = get_settings(&srv).await;
    assert!(
        view["transport"]["authorization_error"]
            .as_str()
            .unwrap()
            .contains("invalid_grant"),
        "{view}"
    );
    assert!(smtp.auths().is_empty());

    // Authorizing again clears it.
    authorize_by_code(&srv, &auth, "refresh-2").await;
    let view = get_settings(&srv).await;
    assert_eq!(view["transport"]["authorization_error"], Value::Null);
}

/// The client credentials grant: no mailbox to authorize; a token the mail
/// server refuses is dropped, and the next send gets a new one.
#[tokio::test]
async fn client_credentials_and_a_refused_token() {
    let smtp = FakeSmtp::start("OAUTHBEARER").await;
    let auth = auth_server(true).await;
    mount_registration(&auth, "forge-client").await;
    let srv = server().await;
    put_settings(&srv, oauth_settings(&auth.uri(), smtp.port, json!({}))).await;
    register(&srv).await;
    token_grant("client_credentials")
        .respond_with(tokens("cc-0", None))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&auth)
        .await;
    token_grant("client_credentials")
        .respond_with(tokens("cc-1", None))
        .up_to_n_times(1)
        .with_priority(2)
        .mount(&auth)
        .await;
    token_grant("client_credentials")
        .respond_with(tokens("cc-2", None))
        .with_priority(3)
        .mount(&auth)
        .await;

    let (status, body) = admin_json(
        &srv,
        reqwest::Method::POST,
        "/admin/settings/email/oauth/authorize",
        Some(json!({"method": "client_credentials"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["transport"]["grant"], "client_credentials");
    let cc = requests_to(&auth, "POST", "/token").await;
    assert_eq!(form(&cc[0])["scope"], "smtp");

    // cc-1 is refused: the challenge's status is reported, the exchange
    // ended with RFC 7628's dummy response.
    smtp.accept("cc-2");
    let (status, body) = test_send(&srv).await;
    assert_eq!(status, 502, "{body}");
    let error = body["error"].as_str().unwrap();
    assert!(
        error.contains("refused the access token (OAUTHBEARER)"),
        "{error}"
    );
    assert!(error.contains("invalid_token"), "{error}");
    assert_eq!(smtp.log.lock().unwrap().dummies, ["AQ=="]);

    let (status, body) = test_send(&srv).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(smtp.messages().len(), 1);
}

/// Forge's registration goes when the issuer changes, when the client is
/// forgotten, and with the settings; a save keeps it for the same issuer and
/// never takes the OAuth state from its body.
#[tokio::test]
async fn forges_registration_follows_the_settings() {
    let smtp = FakeSmtp::start("OAUTHBEARER").await;
    let first = auth_server(true).await;
    mount_registration(&first, "client-a").await;
    let second = auth_server(true).await;
    mount_registration(&second, "client-b").await;
    let srv = server().await;

    put_settings(&srv, oauth_settings(&first.uri(), smtp.port, json!({}))).await;
    register(&srv).await;
    authorize_by_code(&srv, &first, "refresh-a").await;

    // The same issuer and mailbox: kept, whatever the body claims.
    let view = put_settings(
        &srv,
        oauth_settings(
            &first.uri(),
            smtp.port,
            json!({"grant": "client_credentials", "refresh_token": "planted"}),
        ),
    )
    .await;
    assert_eq!(view["transport"]["client_id"], "client-a");
    assert_eq!(view["transport"]["grant"], "refresh_token");
    assert_eq!(stored_transport(&srv).await["refresh_token"], "refresh-a");
    assert!(requests_to(&first, "DELETE", "/register/client-a")
        .await
        .is_empty());

    // Another mailbox: the client stays, the authorization goes.
    let mut other = oauth_settings(&first.uri(), smtp.port, json!({}));
    other["transport"]["username"] = json!("other@example.com");
    let view = put_settings(&srv, other).await;
    assert_eq!(view["transport"]["client_id"], "client-a");
    assert_eq!(view["transport"]["grant"], Value::Null);
    assert_eq!(view["transport"]["refresh_token_set"], json!(false));

    // Another issuer: the registration at the first is deleted.
    let view = put_settings(&srv, oauth_settings(&second.uri(), smtp.port, json!({}))).await;
    assert!(view["transport"].get("client_id").is_none(), "{view}");
    assert_eq!(
        requests_to(&first, "DELETE", "/register/client-a")
            .await
            .len(),
        1
    );

    // Forgetting the client deletes its registration.
    register(&srv).await;
    let (status, view) = admin_json(
        &srv,
        reqwest::Method::DELETE,
        "/admin/settings/email/oauth/client",
        None,
    )
    .await;
    assert_eq!(status, 200, "{view}");
    assert!(view["transport"].get("client_id").is_none(), "{view}");
    assert_eq!(
        requests_to(&second, "DELETE", "/register/client-b")
            .await
            .len(),
        1
    );

    // And so does deleting the settings.
    register(&srv).await;
    let resp = admin(&srv, reqwest::Method::DELETE, "/admin/settings/email", None).await;
    assert_eq!(resp.status(), 204);
    assert_eq!(
        requests_to(&second, "DELETE", "/register/client-b")
            .await
            .len(),
        2
    );
}

/// A server like Stalwart: registration takes an account (HTTP Basic, never
/// stored) and offers no RFC 7592 management, so Forge says which client to
/// remove there once it no longer uses it.
#[tokio::test]
async fn registers_with_an_account_and_names_a_client_it_cannot_delete() {
    let smtp = FakeSmtp::start("OAUTHBEARER").await;
    let auth = auth_server(true).await;
    let basic = format!("Basic {}", B64.encode("admin:adm1n-pw"));
    Mock::given(method("POST"))
        .and(path("/register"))
        .and(header("authorization", basic.as_str()))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "client_id": "stalwart-client",
            "client_secret": "client-s3cret",
            "client_id_issued_at": 1792764805,
            "client_secret_expires_at": 0,
        })))
        .mount(&auth)
        .await;
    let srv = server().await;
    put_settings(&srv, oauth_settings(&auth.uri(), smtp.port, json!({}))).await;

    // Half an account, or both kinds of authentication: refused.
    for body in [
        json!({"username": "admin"}),
        json!({"initial_access_token": "t", "username": "admin", "password": "p"}),
    ] {
        let (status, _) = admin_json(
            &srv,
            reqwest::Method::POST,
            "/admin/settings/email/oauth/register",
            Some(body),
        )
        .await;
        assert_eq!(status, 400);
    }

    let (status, view) = admin_json(
        &srv,
        reqwest::Method::POST,
        "/admin/settings/email/oauth/register",
        Some(json!({"username": "admin", "password": "adm1n-pw"})),
    )
    .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["transport"]["client_id"], "stalwart-client");
    assert_eq!(view["transport"]["registered"], json!(true));
    assert!(view["transport"].get("registration_client_uri").is_none());
    assert_eq!(view["warning"], Value::Null);
    assert!(!view.to_string().contains("adm1n-pw"));
    assert!(!stored_transport(&srv)
        .await
        .to_string()
        .contains("adm1n-pw"));

    // Another issuer: the client stays at the first server, and the save
    // names it.
    let other = auth_server(false).await;
    let view = put_settings(&srv, oauth_settings(&other.uri(), smtp.port, json!({}))).await;
    assert!(
        view["warning"]
            .as_str()
            .unwrap()
            .contains("stalwart-client"),
        "{view}"
    );
}

/// The transport's own checks.
#[tokio::test]
async fn settings_are_checked() {
    let srv = server().await;
    for (transport, needle) in [
        (
            json!({"host": "mail.example.com", "tls": "none"}),
            "unencrypted",
        ),
        (
            json!({"issuer": "http://idp.example.com"}),
            "transport.issuer must be an https URL",
        ),
        (
            json!({"issuer": "https://user:pw@idp.example.com"}),
            "credentials",
        ),
        (json!({"username": " "}), "transport.username"),
        (
            json!({"client_secret": "s"}),
            "transport.client_secret needs a transport.client_id",
        ),
    ] {
        let settings = oauth_settings("https://idp.example.com", 587, transport);
        let (status, body) = admin_json(
            &srv,
            reqwest::Method::PUT,
            "/admin/settings/email",
            Some(settings),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.as_str().unwrap().contains(needle), "{body}");
    }

    // OAuth on other transports answers 409.
    let (status, _) = admin_json(
        &srv,
        reqwest::Method::POST,
        "/admin/settings/email/oauth/register",
        None,
    )
    .await;
    assert_eq!(status, 409);
}
