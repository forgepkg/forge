//! Route-level integration tests for the slice-12.2 `/auth` surface (Phase 5).
//!
//! Drives the **real** forge server over HTTP against a real Postgres
//! testcontainer + an in-process mock OIDC IdP (wiremock serving
//! discovery/JWKS/token, signing a self-issued ID token with a throwaway RSA
//! key). Verifies:
//!   * `GET /auth/oidc/login` 302s to the IdP authorize URL and writes an
//!     `oidc_flow` row (state/nonce/PKCE), with the open-redirect guard on
//!     `redirect_to`;
//!   * `GET /auth/oidc/callback` happy path sets a `forge_session` cookie and
//!     302s to the validated relative target; the cookie authenticates
//!     `GET /admin/me` (proving `SessionCookieSource` is wired into the
//!     principal chain);
//!   * an unknown `state` is rejected (302 to `/login?error=oidc_failed`);
//!   * `POST /auth/logout` clears the cookie + revokes the session (CSRF
//!     enforced), after which the cookie no longer authenticates;
//!   * an IdP whose issuer ends in `/` (Auth0-style) completes the login
//!     (review L7(b)).
//!
//! Requires Docker.

mod common;

/// Every test seeds the same `[oidc]`-imported auth realm row (one per
/// database) with its own mock IdP; run them one at a time so a parallel test
/// cannot swap the issuer under another's login flow.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{start_with, ServerOpts};

/// Throwaway RSA signer for the mock IdP (mirrors the forge-core OIDC harness).
struct TestSigner {
    private_pem: String,
    kid: String,
    jwk: Value,
}

impl TestSigner {
    fn new(kid: &str) -> Self {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let public_key = RsaPublicKey::from(&private_key);
        let n =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let private_pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("pkcs1 pem")
            .to_string();
        let jwk = json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e,
        });
        Self {
            private_pem,
            kid: kid.to_string(),
            jwk,
        }
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        let key = EncodingKey::from_rsa_pem(self.private_pem.as_bytes()).expect("enc key");
        encode(&header, claims, &key).expect("sign jwt")
    }
}

const CLIENT_ID: &str = "client-abc";

/// Mock IdP: discovery + JWKS mounted at start; token endpoint mounted per-login
/// so the test controls the claims/nonce.
struct MockIdp {
    server: MockServer,
    issuer: String,
    signer: TestSigner,
}

impl MockIdp {
    async fn start() -> Self {
        Self::start_with_issuer_suffix("").await
    }

    /// Like [`Self::start`], but the IdP's issuer identifier is its base URL
    /// plus `suffix` (e.g. `"/"` for an Auth0-style `https://tenant/` issuer):
    /// discovery advertises it, and [`Self::issuer`] (used in tokens and the
    /// `[oidc]` block) carries it.
    async fn start_with_issuer_suffix(suffix: &str) -> Self {
        let server = MockServer::start().await;
        let base = server.uri();
        let issuer = format!("{base}{suffix}");
        let signer = TestSigner::new("k1");

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "jwks_uri": format!("{base}/jwks"),
                "end_session_endpoint": format!("{base}/logout"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [signer.jwk] })))
            .mount(&server)
            .await;

        Self {
            server,
            issuer,
            signer,
        }
    }

    /// The `[oidc]` TOML block pointing at this mock; `allow_private_issuer`
    /// lets the SSRF-guarded client reach the loopback mock.
    fn oidc_block(&self) -> String {
        format!(
            r#"
[oidc]
issuer = "{issuer}"
client_id = "{CLIENT_ID}"
client_secret = "shh-secret"
redirect_url = "http://test.local/auth/oidc/callback"
allow_private_issuer = true
admin_groups = ["forge-admins"]
admin_claim = "roles"
"#,
            issuer = self.issuer,
        )
    }

    /// The `[oidc]` block of a client that authenticates with forge's own
    /// client assertions (an Entra federated identity credential).
    fn federated_oidc_block(&self) -> String {
        format!(
            r#"
[oidc]
issuer = "{issuer}"
client_id = "{CLIENT_ID}"
client_authentication = "federated_credential"
redirect_url = "http://test.local/auth/oidc/callback"
allow_private_issuer = true
"#,
            issuer = self.issuer,
        )
    }

    /// Mount a one-shot token endpoint returning an ID token with `claims`.
    async fn mount_token_with_claims(&self, claims: Value) {
        let id_token = self.signer.sign(&claims);
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "opaque-access",
                "token_type": "Bearer",
                "id_token": id_token,
            })))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }
}

/// Standard ID-token claim set.
fn id_claims(issuer: &str, sub: &str, username: &str, nonce: &str, roles: Value) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "sub": sub,
        "iss": issuer,
        "aud": CLIENT_ID,
        "exp": now + 3600,
        "nbf": now - 10,
        "iat": now - 10,
        "nonce": nonce,
        "azp": CLIENT_ID,
        "preferred_username": username,
        "email": format!("{username}@corp.example"),
        "name": format!("User {username}"),
        "roles": roles,
    })
}

/// A reqwest client that does NOT follow redirects (so we can assert 302s).
fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

/// A refused callback answers 302 to the SPA's login page with a generic
/// error code (never a bare text body, never the IdP's error detail).
fn assert_login_error(resp: &reqwest::Response, code: &str) {
    assert_eq!(resp.status(), 302, "refused sign-in redirects");
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some(format!("/login?error={code}").as_str())
    );
}

/// Peek the nonce stored on a live `oidc_flow` row (without consuming it).
async fn peek_nonce(pool: &sqlx::PgPool, state: &str) -> String {
    sqlx::query!("SELECT nonce FROM oidc_flow WHERE state = $1", state)
        .fetch_one(pool)
        .await
        .expect("flow row")
        .nonce
}

/// Extract the `state` query param from an authorize URL.
fn state_from_url(url: &str) -> String {
    let parsed = url::Url::parse(url).expect("authorize url");
    parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("state param")
}

/// The `Cookie` header value replaying the pre-auth `forge_oidc_flow` cookie
/// the login leg set (the callback requires it: login-CSRF binding).
fn flow_cookie_header(resp: &reqwest::Response) -> String {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| {
            v.split(';')
                .next()
                .filter(|kv| kv.starts_with("forge_oidc_flow="))
        })
        .map(str::to_string)
        .expect("forge_oidc_flow cookie set on the login leg")
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

// ── login ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_redirects_to_idp_and_writes_flow_row() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "off".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;

    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/login?redirect_to=/browse",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with(&format!("{}/authorize", idp.issuer)),
        "redirects to IdP authorize: {location}"
    );
    assert!(location.contains("code_challenge_method=S256"));
    // No session cookie is set on the login leg (state lives in the DB); only
    // the short-lived HttpOnly pre-auth cookie binding the flow to this browser.
    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(set_cookies.len(), 1, "{set_cookies:?}");
    assert!(set_cookies[0].starts_with("forge_oidc_flow="));
    assert!(set_cookies[0].contains("HttpOnly"));
    assert!(set_cookies[0].contains("SameSite=Lax"));

    // The oidc_flow row exists with the sanitized redirect target.
    let state = state_from_url(&location);
    let row = sqlx::query!("SELECT redirect_to FROM oidc_flow WHERE state = $1", state)
        .fetch_one(&srv.pool)
        .await
        .expect("flow row present");
    assert_eq!(row.redirect_to, "/browse");
}

#[tokio::test]
async fn login_rejects_open_redirect_target() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;

    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/login?redirect_to=https://evil.example",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = state_from_url(location);
    // The open-redirect target is normalised to "/".
    let row = sqlx::query!("SELECT redirect_to FROM oidc_flow WHERE state = $1", state)
        .fetch_one(&srv.pool)
        .await
        .expect("flow row");
    assert_eq!(row.redirect_to, "/", "absolute URL normalised to root");
}

// ── callback happy path + /admin/me ──────────────────────────────────────────

#[tokio::test]
async fn callback_sets_session_cookie_and_me_recognises_it() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let pool = common::pool().await;
    let srv = start_with(
        pool.clone(),
        ServerOpts {
            anonymous_mode: "off".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let n = common::unique();
    let username = format!("alice-{n}@example.com");
    let sub = format!("sub-{n}");

    // 1. Login → authorize URL + state.
    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/login?redirect_to=/browse",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = state_from_url(location);
    let flow = flow_cookie_header(&resp);

    // 2. The IdP echoes the flow's nonce so the token verifies; user is admin.
    let nonce = peek_nonce(&srv.pool, &state).await;
    idp.mount_token_with_claims(id_claims(
        &idp.issuer,
        &sub,
        &username,
        &nonce,
        json!(["forge-admins"]),
    ))
    .await;

    // 3. Callback → 302 to the validated target + a session cookie.
    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=the-code&state={state}",
            srv.base_url
        ))
        .header("cookie", &flow)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302, "callback redirects after login");
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/browse"
    );
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .expect("session cookie set")
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    let cookie = session_cookie_from(&set_cookie);

    // 4. The cookie authenticates /admin/me as the provisioned admin user.
    let resp = no_redirect_client()
        .get(format!("{}/admin/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "session cookie authenticates /admin/me");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["user"]["username"], json!(username));
    assert_eq!(body["is_admin"], json!(true), "roles claim granted admin");
}

/// #317: a first OIDC login whose username claim holds no UPN creates no
/// account; the browser is sent to the login page with the reason and the
/// claim it came from.
#[tokio::test]
async fn callback_refuses_a_new_account_without_a_upn_and_names_the_claim() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "off".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let n = common::unique();
    let username = format!("bare-{n}");

    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/login?redirect_to=/browse",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = state_from_url(location);
    let flow = flow_cookie_header(&resp);
    let nonce = peek_nonce(&srv.pool, &state).await;
    idp.mount_token_with_claims(id_claims(
        &idp.issuer,
        &format!("sub-{n}"),
        &username,
        &nonce,
        json!([]),
    ))
    .await;

    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=the-code&state={state}",
            srv.base_url
        ))
        .header("cookie", &flow)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/login?error=username_not_upn&claim=preferred_username"
    );
    assert!(resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .all(|c| !c.to_str().unwrap().starts_with("forge_session=")));
    assert!(
        forge_db::user_dao::find_user_by_username(&srv.pool, &username)
            .await
            .unwrap()
            .is_none()
    );
}

/// A realm with `client_authentication = "federated_credential"` signs in
/// without a client secret: the token request carries a client assertion
/// that verifies against the JWKS forge publishes as its issuer, and names
/// the subject and audience an Entra federated credential expects.
#[tokio::test]
async fn federated_credential_login_presents_a_forge_signed_client_assertion() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    // Its own database: the issuer keys are install-wide.
    let srv = start_with(
        common::fresh_pool().await,
        ServerOpts {
            anonymous_mode: "off".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.federated_oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let client = no_redirect_client();
    let n = common::unique();

    let resp = client
        .get(format!(
            "{}/auth/oidc/login?redirect_to=/browse",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    let state = state_from_url(resp.headers().get("location").unwrap().to_str().unwrap());
    let flow = flow_cookie_header(&resp);
    let nonce = peek_nonce(&srv.pool, &state).await;
    // Only a token request authenticated by a client assertion gets a token.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": idp.signer.sign(&id_claims(
                &idp.issuer,
                &format!("sub-{n}"),
                &format!("dora-{n}@example.com"),
                &nonce,
                json!([]),
            )),
        })))
        .mount(&idp.server)
        .await;

    let resp = client
        .get(format!(
            "{}/auth/oidc/callback?code=the-code&state={state}",
            srv.base_url
        ))
        .header("cookie", &flow)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302);
    assert_eq!(resp.headers().get("location").unwrap(), "/browse");
    assert!(resp.headers().get("set-cookie").is_some(), "signed in");

    // The assertion the IdP received.
    let requests = idp.server.received_requests().await.expect("recorded");
    let body = &requests
        .iter()
        .find(|r| r.url.path() == "/token")
        .expect("token request")
        .body;
    let form: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(body).into_owned().collect();
    assert!(!form.contains_key("client_secret"), "{form:?}");
    assert_eq!(form["client_id"], CLIENT_ID);
    let assertion = &form["client_assertion"];

    // Verified as the IdP does: discovery → JWKS → the key named by `kid`.
    let discovery: Value = client
        .get(format!("{}/.well-known/openid-configuration", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["issuer"], json!("http://test.local"));
    let jwks: Value = client
        .get(format!("{}/.well-known/jwks.json", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kid = jsonwebtoken::decode_header(assertion)
        .unwrap()
        .kid
        .expect("kid");
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == json!(kid))
        .expect("signing key published");
    let key = jsonwebtoken::DecodingKey::from_rsa_components(
        jwk["n"].as_str().unwrap(),
        jwk["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
    validation.set_issuer(&["http://test.local"]);
    validation.set_audience(&["api://AzureADTokenExchange"]);
    validation.sub = Some(format!("{CLIENT_ID}@{}", idp.issuer.trim_end_matches('/')));
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = jsonwebtoken::decode::<Value>(assertion, &key, &validation)
        .expect("the assertion verifies against forge's JWKS")
        .claims;
    assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
}

/// Review L7(b): an issuer that ends in `/` (Auth0: `https://tenant.auth0.com/`)
/// used to fail every login — the verifier compared the token's `iss` against
/// the slash-stripped cache-key form. The full browser flow must now succeed
/// and link the identity under the issuer exactly as the IdP spells it.
#[tokio::test]
async fn callback_accepts_trailing_slash_issuer() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start_with_issuer_suffix("/").await;
    assert!(idp.issuer.ends_with('/'));
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let n = common::unique();
    let username = format!("slash-{n}@example.com");
    let sub = format!("sub-slash-{n}");

    let resp = no_redirect_client()
        .get(format!("{}/auth/oidc/login", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = state_from_url(location);
    let flow = flow_cookie_header(&resp);
    let nonce = peek_nonce(&srv.pool, &state).await;
    idp.mount_token_with_claims(id_claims(&idp.issuer, &sub, &username, &nonce, json!([])))
        .await;

    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=the-code&state={state}",
            srv.base_url
        ))
        .header("cookie", &flow)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302, "trailing-slash issuer login completes");
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .expect("session cookie set")
        .to_str()
        .unwrap()
        .to_string();
    let cookie = session_cookie_from(&set_cookie);
    let resp = no_redirect_client()
        .get(format!("{}/admin/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["user"]["username"],
        json!(username)
    );

    let linked_issuer: String =
        sqlx::query_scalar("SELECT issuer FROM external_identity WHERE subject = $1")
            .bind(&sub)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert_eq!(
        linked_issuer, idp.issuer,
        "linked under the IdP's exact issuer"
    );
}

#[tokio::test]
async fn callback_rejects_unknown_state() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;

    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=x&state=never-issued",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_login_error(&resp, "oidc_failed");
    assert!(resp.headers().get("set-cookie").is_none());
}

#[tokio::test]
async fn callback_from_another_browser_is_rejected() {
    let _serial = SERIAL.lock().await;
    // Login CSRF / session swap: the attacker starts a flow in their browser and
    // lures the victim to the callback. The victim has no flow cookie → 400, no
    // session, and the flow row survives for the real initiator.
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let resp = no_redirect_client()
        .get(format!("{}/auth/oidc/login", srv.base_url))
        .send()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = state_from_url(location);

    for cookie in [None, Some("forge_oidc_flow=forged")] {
        let mut req = no_redirect_client().get(format!(
            "{}/auth/oidc/callback?code=c&state={state}",
            srv.base_url
        ));
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        let resp = req.send().await.unwrap();
        assert_login_error(&resp, "oidc_failed");
        assert!(resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .all(|v| !v.to_str().unwrap().starts_with("forge_session=")));
    }
    let still = sqlx::query!("SELECT state FROM oidc_flow WHERE state = $1", state)
        .fetch_optional(&srv.pool)
        .await
        .unwrap();
    assert!(
        still.is_some(),
        "flow row not consumed by a forged callback"
    );
}

// ── logout ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_revokes_session_and_clears_cookie() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let n = common::unique();

    // Complete a login to obtain a session cookie.
    let resp = no_redirect_client()
        .get(format!("{}/auth/oidc/login", srv.base_url))
        .send()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = state_from_url(location);
    let flow = flow_cookie_header(&resp);
    let nonce = peek_nonce(&srv.pool, &state).await;
    idp.mount_token_with_claims(id_claims(
        &idp.issuer,
        &format!("sub-{n}"),
        &format!("loguser-{n}@example.com"),
        &nonce,
        json!([]),
    ))
    .await;
    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=c&state={state}",
            srv.base_url
        ))
        .header("cookie", &flow)
        .send()
        .await
        .unwrap();
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cookie = session_cookie_from(&set_cookie);

    // Read the session's CSRF secret (the UI gets it from a who-am-I; here we
    // read the row directly to exercise the server-side double-submit check).
    // The session is stored under sha256(cookie_secret), mirroring the token
    // model.
    let token_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(cookie.as_bytes()))
    };
    let csrf: String = sqlx::query_scalar!(
        "SELECT csrf_secret FROM session WHERE token_hash = $1",
        token_hash
    )
    .fetch_one(&srv.pool)
    .await
    .expect("session row");

    // A logout WITHOUT the CSRF token is rejected (403).
    let resp = no_redirect_client()
        .post(format!("{}/auth/logout", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "logout without CSRF token is rejected");

    // With the CSRF token it succeeds, clears the cookie, and revokes.
    let resp = no_redirect_client()
        .post(format!("{}/auth/logout", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cleared = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(cleared.contains("Max-Age=0"), "cookie cleared: {cleared}");

    // The old cookie no longer authenticates (session revoked) → 401.
    let resp = no_redirect_client()
        .get(format!("{}/admin/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "revoked session cookie is rejected");
}

// ── /auth/me + /auth/tokens (session-authenticated) ──────────────────────────

/// Drive a full login and return `(session_cookie, csrf_token)` for the
/// provisioned user. Shared by the /auth/me + token-minting tests.
async fn login_and_get_cookie(
    idp: &MockIdp,
    srv: &common::TestServer,
    sub: &str,
    username: &str,
    roles: Value,
) -> (String, String) {
    let resp = no_redirect_client()
        .get(format!("{}/auth/oidc/login", srv.base_url))
        .send()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = state_from_url(location);
    let flow = flow_cookie_header(&resp);
    let nonce = peek_nonce(&srv.pool, &state).await;
    idp.mount_token_with_claims(id_claims(&idp.issuer, sub, username, &nonce, roles))
        .await;
    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=c&state={state}",
            srv.base_url
        ))
        .header("cookie", &flow)
        .send()
        .await
        .unwrap();
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cookie = session_cookie_from(&set_cookie);

    // /auth/me returns the per-session CSRF token the UI echoes on mutations.
    let me: Value = no_redirect_client()
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf = me["csrf_token"].as_str().expect("csrf token").to_string();
    (cookie, csrf)
}

#[tokio::test]
async fn auth_me_returns_identity_and_csrf_token() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "off".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let n = common::unique();
    let username = format!("meuser-{n}@example.com");

    // Unauthenticated /auth/me → 401.
    let resp = no_redirect_client()
        .get(format!("{}/auth/me", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "no cookie → 401");

    let (cookie, csrf) =
        login_and_get_cookie(&idp, &srv, &format!("sub-{n}"), &username, json!([])).await;

    let body: Value = no_redirect_client()
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["username"], json!(username));
    assert_eq!(body["is_admin"], json!(false), "no admin role claim");
    assert!(!csrf.is_empty(), "csrf token present");
}

#[tokio::test]
async fn session_can_mint_and_revoke_repository_token() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "off".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let n = common::unique();
    let (cookie, csrf) = login_and_get_cookie(
        &idp,
        &srv,
        &format!("sub-{n}"),
        &format!("minter-{n}@example.com"),
        json!([]),
    )
    .await;

    // Minting WITHOUT the CSRF token is rejected (403).
    let resp = no_redirect_client()
        .post(format!("{}/auth/tokens", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .json(&json!({"name": "ci"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "token mint without CSRF rejected");

    // With CSRF → 201 + a one-time plaintext token.
    let created: Value = {
        let resp = no_redirect_client()
            .post(format!("{}/auth/tokens", srv.base_url))
            .header("cookie", format!("forge_session={cookie}"))
            .header("x-csrf-token", &csrf)
            .json(&json!({"name": "ci"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        resp.json().await.unwrap()
    };
    let token_id = created["id"].as_i64().expect("token id");
    let plaintext = created["token"].as_str().expect("plaintext token");
    assert!(!plaintext.is_empty());

    // It appears in the session user's token list (no secret leaked).
    let list: Value = no_redirect_client()
        .get(format!("{}/auth/tokens", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = list.as_array().unwrap();
    assert!(arr.iter().any(|t| t["id"].as_i64() == Some(token_id)));
    assert!(
        arr.iter().all(|t| t.get("token").is_none()),
        "list never returns the secret"
    );

    // Revoke (CSRF required) → 204; a second revoke → 404 (idempotent-ish).
    let resp = no_redirect_client()
        .delete(format!("{}/auth/tokens/{token_id}", srv.base_url))
        .header("cookie", format!("forge_session={cookie}"))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "owned token revoked");
}

// ── OIDC disabled ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn auth_routes_absent_when_oidc_disabled() {
    let _serial = SERIAL.lock().await;
    // No oidc_block ⇒ no OIDC runtime ⇒ /auth/oidc/login is not mounted.
    // Realms seeded by earlier tests persist in the shared database; remove
    // them so this test sees an install without OIDC (a later test's boot
    // re-imports its `[oidc]` block into a fresh row).
    let pool = common::pool().await;
    sqlx::query("DELETE FROM auth_realm WHERE kind = 'oidc'")
        .execute(&pool)
        .await
        .unwrap();
    let srv = common::start().await;
    let resp = no_redirect_client()
        .get(format!("{}/auth/oidc/login", srv.base_url))
        .send()
        .await
        .unwrap();
    // Web UI is disabled in the default harness, so an unmounted route 404s.
    assert_eq!(resp.status(), 404);
}

/// The realm's allow-gate: a token that does not carry an allowed value of a
/// required claim (here: another tenant of a multi-tenant app) is refused —
/// sent back to the login page with `not_permitted` and no session; an
/// allowed one signs in.
#[tokio::test]
async fn required_claims_gate_the_callback() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "off".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(format!(
                "{}[oidc.required_claims]\ntid = [\"tenant-a\"]\n",
                idp.oidc_block()
            )),
            ..Default::default()
        },
    )
    .await;

    for (tid, allowed) in [("tenant-b", false), ("tenant-a", true)] {
        let n = common::unique();
        let resp = no_redirect_client()
            .get(format!("{}/auth/oidc/login", srv.base_url))
            .send()
            .await
            .unwrap();
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let state = state_from_url(location);
        let flow = flow_cookie_header(&resp);
        let nonce = peek_nonce(&srv.pool, &state).await;
        let mut claims = id_claims(
            &idp.issuer,
            &format!("sub-{n}"),
            &format!("guest-{n}@example.com"),
            &nonce,
            json!([]),
        );
        claims["tid"] = json!(tid);
        idp.mount_token_with_claims(claims).await;
        let resp = no_redirect_client()
            .get(format!(
                "{}/auth/oidc/callback?code=c&state={state}",
                srv.base_url
            ))
            .header("cookie", &flow)
            .send()
            .await
            .unwrap();
        if !allowed {
            assert_login_error(&resp, "not_permitted");
        }
        assert_eq!(resp.status(), 302, "tid = {tid}");
        let sets_session = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap_or("").starts_with("forge_session="));
        assert_eq!(sets_session, allowed, "tid = {tid}");
    }
}

/// Starting an OIDC login stores a flow row, so starts are rate-limited per
/// client network (before any other work, configured realm or not).
#[tokio::test]
async fn oidc_login_starts_are_rate_limited() {
    let srv = common::start().await;
    let client = no_redirect_client();
    let limit = srv.state.config.auth.oidc_login_starts_per_minute;
    for _ in 0..limit {
        let resp = client
            .get(format!("{}/auth/oidc/login", srv.base_url))
            .send()
            .await
            .unwrap();
        assert_ne!(resp.status(), 429);
    }
    let resp = client
        .get(format!("{}/auth/oidc/login", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    assert!(resp.headers().get("retry-after").is_some());
}

#[tokio::test]
async fn idp_demotion_ends_sessions_opened_as_admin() {
    let _serial = SERIAL.lock().await;
    let idp = MockIdp::start().await;
    let srv = start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "off".into(),
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            oidc_block: Some(idp.oidc_block()),
            ..Default::default()
        },
    )
    .await;
    let n = common::unique();
    let (sub, username) = (format!("sub-{n}"), format!("demoted-{n}@example.com"));
    let me = |cookie: String| {
        let req = no_redirect_client()
            .get(format!("{}/auth/me", srv.base_url))
            .header("cookie", format!("forge_session={cookie}"));
        async move { req.send().await.unwrap() }
    };

    let (as_admin, _) =
        login_and_get_cookie(&idp, &srv, &sub, &username, json!(["forge-admins"])).await;
    let body: Value = me(as_admin.clone()).await.json().await.unwrap();
    assert_eq!(body["is_admin"], json!(true));

    // The IdP no longer lists the admin group: the next login demotes, and
    // the session opened as an admin ends with it.
    let (demoted, _) = login_and_get_cookie(&idp, &srv, &sub, &username, json!([])).await;
    assert_eq!(me(as_admin).await.status(), 401);
    let body: Value = me(demoted).await.json().await.unwrap();
    assert_eq!(body["is_admin"], json!(false));
}
