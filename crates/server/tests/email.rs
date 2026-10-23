//! The email service (#319): `/admin/settings/email` and sending through a
//! real SMTP server, mailpit (`mirror.gcr.io/axllent/mailpit`), over
//! STARTTLS and implicit TLS, with and without AUTH, and to a plain relay on
//! loopback.
//!
//! TLS certificates are always verified against the system roots. This test
//! binary makes a throwaway CA and a `localhost` certificate for mailpit and
//! points the system roots at that CA (`SSL_CERT_FILE`, which the platform
//! verifier reads on Linux), so nothing in the server is relaxed for tests.

mod common;

use std::sync::OnceLock;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

const MAILPIT_IMAGE: &str = "mirror.gcr.io/axllent/mailpit";
const MAILPIT_TAG: &str = "v1.27.11";
const SMTP_USER: &str = "forge";
const SMTP_PASSWORD: &str = "smtp-pw-1";

/// The test CA's server certificate and key for `localhost`, PEM.
struct TestTls {
    cert_pem: String,
    key_pem: String,
    _dir: tempfile::TempDir,
}

/// Make the test PKI once, and trust its CA as the system roots of this
/// process.
fn test_tls() -> &'static TestTls {
    static TLS: OnceLock<TestTls> = OnceLock::new();
    TLS.get_or_init(|| {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Forge test SMTP CA");
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        params.distinguished_name.push(DnType::CommonName, "localhost");
        let cert = params.signed_by(&key, &ca).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, ca.pem()).unwrap();
        // rustls-native-certs (behind the platform verifier) loads only this
        // file as the system roots.
        std::env::set_var("SSL_CERT_FILE", &ca_file);
        TestTls {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            _dir: dir,
        }
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ServerTls {
    Plain,
    Starttls,
    Implicit,
}

/// A running mailpit: its SMTP port and its HTTP API.
struct Mailpit {
    smtp_port: u16,
    api: String,
    _container: ContainerAsync<GenericImage>,
}

impl Mailpit {
    async fn start(tls: ServerTls, auth: bool) -> Mailpit {
        let pki = test_tls();
        let mut args: Vec<String> = Vec::new();
        if tls != ServerTls::Plain {
            args.extend(
                [
                    "--smtp-tls-cert",
                    "/certs/server.pem",
                    "--smtp-tls-key",
                    "/certs/server.key",
                ]
                .map(String::from),
            );
            args.push(
                match tls {
                    ServerTls::Starttls => "--smtp-require-starttls",
                    _ => "--smtp-require-tls",
                }
                .to_string(),
            );
        }
        let mut image = GenericImage::new(MAILPIT_IMAGE, MAILPIT_TAG)
            .with_exposed_port(1025.tcp())
            .with_exposed_port(8025.tcp())
            .with_wait_for(WaitFor::message_on_stdout("accessible via"))
            .with_copy_to("/certs/server.pem", pki.cert_pem.clone().into_bytes())
            .with_copy_to("/certs/server.key", pki.key_pem.clone().into_bytes())
            .with_env_var("MP_DISABLE_VERSION_CHECK", "true");
        if auth {
            image = image.with_env_var("MP_SMTP_AUTH", format!("{SMTP_USER}:{SMTP_PASSWORD}"));
            if tls == ServerTls::Plain {
                args.push("--smtp-auth-allow-insecure".into());
            }
        }
        let container = image
            .with_cmd(args)
            .start()
            .await
            .expect("start mailpit (is Docker running?)");
        let host = container.get_host().await.unwrap();
        let smtp_port = container.get_host_port_ipv4(1025).await.unwrap();
        let api_port = container.get_host_port_ipv4(8025).await.unwrap();
        Mailpit {
            smtp_port,
            api: format!("http://{host}:{api_port}/api/v1"),
            _container: container,
        }
    }

    /// The messages mailpit received, newest first, waiting up to a few
    /// seconds for `count` of them.
    async fn messages(&self, count: usize) -> Vec<Value> {
        for _ in 0..50 {
            let body: Value = reqwest::get(format!("{}/messages", self.api))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let messages = body["messages"].as_array().cloned().unwrap_or_default();
            if messages.len() >= count {
                return messages;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("mailpit never received {count} message(s)");
    }

    /// One message with its bodies.
    async fn message(&self, id: &str) -> Value {
        reqwest::get(format!("{}/message/{id}", self.api))
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
}

/// The settings document for `mailpit`'s SMTP port on `localhost`.
fn smtp_settings(port: u16, tls: &str, auth: Option<&str>) -> Value {
    let mut transport = json!({"kind": "smtp", "host": "localhost", "port": port, "tls": tls});
    if let Some(password) = auth {
        transport["username"] = json!(SMTP_USER);
        transport["password"] = json!(password);
    }
    json!({
        "from_address": "forge@example.com",
        "from_name": "Forge",
        "reply_to": "help@example.com",
        "transport": transport,
    })
}

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

/// Email settings are install-wide: each test runs on a database of its own.
async fn server() -> common::TestServer {
    test_tls();
    common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await
}

/// Mail goes out over STARTTLS and implicit TLS, authenticated and not: the
/// test message arrives with its sender, `Reply-To`, both bodies and a link
/// to the instance, and the settings page reports the send.
#[tokio::test]
async fn sends_over_starttls_and_implicit_tls_with_and_without_auth() {
    let srv = server().await;
    for (tls, server_tls, auth) in [
        ("starttls", ServerTls::Starttls, true),
        ("starttls", ServerTls::Starttls, false),
        ("implicit", ServerTls::Implicit, true),
        ("implicit", ServerTls::Implicit, false),
    ] {
        let mailpit = Mailpit::start(server_tls, auth).await;
        let settings = smtp_settings(mailpit.smtp_port, tls, auth.then_some(SMTP_PASSWORD));
        let resp = admin(&srv, reqwest::Method::PUT, "/admin/settings/email", Some(settings)).await;
        assert_eq!(resp.status(), 200, "{tls}/{auth}: {}", resp.text().await.unwrap());
        let view: Value = resp.json().await.unwrap();
        assert_eq!(view["transport"]["password_set"], json!(auth));

        let resp = admin(
            &srv,
            reqwest::Method::POST,
            "/admin/settings/email/test",
            Some(json!({"to": "Someone@Example.com"})),
        )
        .await;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap();
        assert_eq!(status, 200, "{tls}/{auth}: {body}");
        assert_eq!(body["sent"], json!(true));

        let messages = mailpit.messages(1).await;
        assert_eq!(messages.len(), 1);
        let summary = &messages[0];
        assert_eq!(summary["Subject"], "Forge test email");
        assert_eq!(summary["From"]["Address"], "forge@example.com");
        assert_eq!(summary["From"]["Name"], "Forge");
        assert!(summary["To"][0]["Address"]
            .as_str()
            .unwrap()
            .eq_ignore_ascii_case("someone@example.com"));
        assert_eq!(summary["ReplyTo"][0]["Address"], "help@example.com");
        let message = mailpit.message(summary["ID"].as_str().unwrap()).await;
        assert!(message["Text"].as_str().unwrap().contains("http://test.local"));
        assert!(message["HTML"]
            .as_str()
            .unwrap()
            .contains("href=\"http://test.local\""));

        let view: Value = admin(&srv, reqwest::Method::GET, "/admin/settings/email", None)
            .await
            .json()
            .await
            .unwrap();
        assert!(view["last_success_at"].is_string(), "{view}");
        assert_eq!(view["last_failure"], Value::Null);
    }
}

/// Without TLS Forge connects only to a loopback relay; that one works.
#[tokio::test]
async fn sends_to_a_plain_relay_on_loopback_only() {
    let srv = server().await;
    let relay = Mailpit::start(ServerTls::Plain, false).await;
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(smtp_settings(relay.smtp_port, "none", None)),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let resp = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/settings/email/test",
        Some(json!({"to": "relay@example.com"})),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(relay.messages(1).await[0]["To"][0]["Address"], "relay@example.com");

    let mut remote = smtp_settings(relay.smtp_port, "none", None);
    remote["transport"]["host"] = json!("smtp.example.com");
    let resp = admin(&srv, reqwest::Method::PUT, "/admin/settings/email", Some(remote)).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("loopback"));
}

/// A send that fails answers 502 with the server's error, and the settings
/// page shows it: a wrong password, a server without STARTTLS, a plaintext
/// server for implicit TLS.
#[tokio::test]
async fn a_failed_send_reports_the_server_error() {
    let srv = server().await;
    let test_send = || {
        admin(
            &srv,
            reqwest::Method::POST,
            "/admin/settings/email/test",
            Some(json!({"to": "someone@example.com"})),
        )
    };

    let authed = Mailpit::start(ServerTls::Starttls, true).await;
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(smtp_settings(authed.smtp_port, "starttls", Some("wrong"))),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let resp = test_send().await;
    assert_eq!(resp.status(), 502);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["sent"], json!(false));
    let error = body["error"].as_str().unwrap().to_string();
    assert!(error.contains("535") || error.to_lowercase().contains("auth"), "{error}");
    assert!(!error.contains("wrong"), "the password is never echoed: {error}");
    let view: Value = admin(&srv, reqwest::Method::GET, "/admin/settings/email", None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(view["last_failure"]["error"], json!(error));
    assert!(view["last_failure"]["at"].is_string());

    // STARTTLS is required, not opportunistic.
    let plain = Mailpit::start(ServerTls::Plain, false).await;
    admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(smtp_settings(plain.smtp_port, "starttls", None)),
    )
    .await;
    let resp = test_send().await;
    assert_eq!(resp.status(), 502);
    let error: Value = resp.json().await.unwrap();
    assert!(
        error["error"].as_str().unwrap().to_lowercase().contains("tls"),
        "{error}"
    );
    admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(smtp_settings(plain.smtp_port, "implicit", None)),
    )
    .await;
    assert_eq!(test_send().await.status(), 502);
    assert!(
        plain
            .messages(0)
            .await
            .is_empty(),
        "nothing went out unencrypted"
    );
}

/// The settings round trip without their secrets: a missing PUT keeps the
/// stored password unless the host or username changes, DELETE turns email
/// off, and the test send defaults to the calling admin's address.
#[tokio::test]
async fn settings_keep_their_secret_write_only() {
    let srv = server().await;
    let get = || async {
        admin(&srv, reqwest::Method::GET, "/admin/settings/email", None)
            .await
            .json::<Value>()
            .await
            .unwrap()
    };
    assert_eq!(get().await, json!({"configured": false}));
    let resp = admin(&srv, reqwest::Method::POST, "/admin/settings/email/test", None).await;
    assert_eq!(resp.status(), 409, "nothing to test yet");

    let mailpit = Mailpit::start(ServerTls::Starttls, true).await;
    let settings = smtp_settings(mailpit.smtp_port, "starttls", Some(SMTP_PASSWORD));
    assert_eq!(
        admin(&srv, reqwest::Method::PUT, "/admin/settings/email", Some(settings.clone()))
            .await
            .status(),
        200
    );
    let view = get().await;
    assert_eq!(view["configured"], json!(true));
    assert_eq!(view["enabled"], json!(true));
    assert_eq!(view["invitation_ttl_hours"], json!(72));
    assert_eq!(view["transport"]["password_set"], json!(true));
    assert!(view["transport"].get("password").is_none());
    assert!(!view.to_string().contains(SMTP_PASSWORD));

    // Without [crypto] the password is in the stored config; the API still
    // never returns it.
    let stored: Value = sqlx::query_scalar("SELECT config FROM email_settings")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(stored["transport"]["password"], json!(SMTP_PASSWORD));

    // An update without the password keeps it...
    let mut update = settings.clone();
    update["transport"].as_object_mut().unwrap().remove("password");
    update["from_name"] = json!("Forge registry");
    update["invitation_ttl_hours"] = json!(24);
    let resp = admin(&srv, reqwest::Method::PUT, "/admin/settings/email", Some(update.clone())).await;
    assert_eq!(resp.status(), 200);
    // ... and the test send goes to the calling admin's address, their UPN.
    let resp = admin(&srv, reqwest::Method::POST, "/admin/settings/email/test", None).await;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["to"], json!(srv.admin_user.clone().unwrap()));
    let messages = mailpit.messages(1).await;
    assert_eq!(messages[0]["From"]["Name"], "Forge registry");

    // A new host or username needs the password again.
    let mut moved = update.clone();
    moved["transport"]["username"] = json!("someone-else");
    let resp = admin(&srv, reqwest::Method::PUT, "/admin/settings/email", Some(moved)).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("transport.password is required"));

    // Turned off: kept, not used by the mailer.
    let mut off = update.clone();
    off["enabled"] = json!(false);
    assert_eq!(
        admin(&srv, reqwest::Method::PUT, "/admin/settings/email", Some(off))
            .await
            .status(),
        200
    );
    assert_eq!(get().await["enabled"], json!(false));
    assert!(!srv.state.mailer.is_configured().await);

    // Bad input is a 400 naming the setting; an unknown field is refused.
    for (field, value, needle) in [
        ("from_address", json!("nope"), "from_address"),
        ("invitation_ttl_hours", json!(0), "invitation_ttl_hours"),
    ] {
        let mut bad = update.clone();
        bad[field] = value;
        let resp = admin(&srv, reqwest::Method::PUT, "/admin/settings/email", Some(bad)).await;
        assert_eq!(resp.status(), 400);
        assert!(resp.text().await.unwrap().contains(needle));
    }
    let mut unknown = update.clone();
    unknown["smtp_password"] = json!("x");
    let resp = admin(&srv, reqwest::Method::PUT, "/admin/settings/email", Some(unknown)).await;
    assert!(resp.status().is_client_error());

    assert_eq!(
        admin(&srv, reqwest::Method::DELETE, "/admin/settings/email", None)
            .await
            .status(),
        204
    );
    assert_eq!(get().await, json!({"configured": false}));
    assert!(!srv.state.mailer.is_configured().await);
}

/// With `[crypto]` the password is sealed at rest, and the settings still
/// work.
#[tokio::test]
async fn the_password_is_sealed_at_rest_with_crypto() {
    std::env::set_var(
        "FORGE_TEST_EMAIL_ROOT_KEY",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    );
    test_tls();
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            crypto_block: Some(
                "[crypto]\n[crypto.root]\nprovider = \"env\"\n\
                 root_key_env = \"FORGE_TEST_EMAIL_ROOT_KEY\"\n\
                 [crypto.rotation]\nenabled = false\n"
                    .into(),
            ),
            ..Default::default()
        },
    )
    .await;
    let mailpit = Mailpit::start(ServerTls::Implicit, true).await;
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(smtp_settings(mailpit.smtp_port, "implicit", Some(SMTP_PASSWORD))),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let (config, sealed): (Value, Option<Vec<u8>>) =
        sqlx::query_as("SELECT config, secrets_enc FROM email_settings")
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert!(config["transport"].get("password").is_none(), "{config}");
    let sealed = sealed.expect("sealed");
    assert!(!String::from_utf8_lossy(&sealed).contains(SMTP_PASSWORD));

    let resp = admin(
        &srv,
        reqwest::Method::POST,
        "/admin/settings/email/test",
        Some(json!({"to": "sealed@example.com"})),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    assert_eq!(mailpit.messages(1).await[0]["To"][0]["Address"], "sealed@example.com");
    // The mailer opens it too.
    assert!(srv.state.mailer.is_configured().await);
}

/// A change applies without a restart: the instance that took it at once,
/// another one within `auth.realm_cache_ttl_seconds`.
#[tokio::test]
async fn other_instances_pick_a_change_up_within_the_cache_ttl() {
    let pool = common::fresh_pool().await;
    let srv = common::start_with(pool.clone(), common::ServerOpts::default()).await;
    let peer = common::start_with(
        pool,
        common::ServerOpts {
            bootstrap_admin: None,
            ..Default::default()
        },
    )
    .await;
    assert!(!srv.state.mailer.is_configured().await);
    assert!(!peer.state.mailer.is_configured().await);

    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(smtp_settings(2525, "none", None)),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert!(srv.state.mailer.is_configured().await, "at once here");
    let ttl = srv.state.config.auth.realm_cache_ttl_seconds.max(1);
    let deadline = std::time::Instant::now() + Duration::from_secs(ttl + 5);
    while !peer.state.mailer.is_configured().await {
        assert!(std::time::Instant::now() < deadline, "the peer never converged");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
