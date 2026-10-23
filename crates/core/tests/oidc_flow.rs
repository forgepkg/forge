//! Integration tests for the OIDC **core service layer** against a real
//! Postgres testcontainer plus an in-process mock IdP (wiremock serving
//! discovery / JWKS / token endpoints, signing self-issued ID tokens with a
//! throwaway RSA key).
//!
//! These exercise the logic above the DAOs (the single-use / nonce properties of
//! the DAOs themselves are covered by `forge-db`'s `oidc.rs`):
//!   * `begin_login` persists an `oidc_flow` row and returns a PKCE/state/nonce
//!     authorize URL;
//!   * `complete_login` consumes the flow (single-use: a replayed callback
//!     fails), exchanges the code, and verifies the ID token (nonce mismatch is
//!     rejected);
//!   * `resolve_user` provisions on first login, links by username, recomputes
//!     the `admin` role from the group/role claim, and rejects inactive users;
//!   * concurrent first logins for one identity all resolve to the single
//!     linked account and leave no orphan accounts behind (review L7(c));
//!   * `SessionService` round-trips create → validate → revoke and rotates.
//!
//! Requires Docker.

mod common;

use base64::Engine;
use chrono::Duration as ChronoDuration;
use forge_cache::Cache;
use forge_core::oidc::{
    self, begin_login, complete_login, map_claims, CallbackParams, ClaimMapping, ClientAssertion,
    ClientAuth, ClientParams, FlowError, OidcMetadataClient, ResolvePolicy,
};
use forge_core::session::SessionService;
use forge_db::oidc_flow_dao;
use forge_db::user_dao::{self, NewUser};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{pool, unique};

/// A throwaway RSA signer for the mock IdP: signs ID tokens and publishes its
/// public half as a JWK.
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

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A mock IdP: discovery + JWKS mounted; the token endpoint serves a *fixed*
/// signed ID token (the test sets the claims/nonce so it can assert acceptance
/// or rejection).
struct MockIdp {
    server: MockServer,
    issuer: String,
    signer: TestSigner,
}

impl MockIdp {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "end_session_endpoint": format!("{issuer}/logout"),
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

    /// Mount the token endpoint to return an ID token carrying `claims`.
    ///
    /// Scoped to a single response (`up_to_n_times(1)`) so successive logins in
    /// one test each get *their own* token: wiremock serves the first mounted
    /// mock that still has a response left, so a stale earlier token never wins.
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

    fn meta(&self) -> OidcMetadataClient {
        OidcMetadataClient::new(
            self.issuer.clone(),
            reqwest::Client::new(),
            Cache::l1_only(64),
        )
    }

    fn client(&self) -> ClientParams {
        ClientParams {
            client_id: "client-abc".into(),
            auth: ClientAuth::Secret("shh-secret".into()),
            redirect_url: "https://forge.test/auth/oidc/callback".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            leeway_seconds: 60,
        }
    }
}

/// Standard claim set for a login as `username` with the given roles + nonce.
fn id_claims(issuer: &str, sub: &str, username: &str, nonce: &str, roles: Value) -> Value {
    json!({
        "sub": sub,
        "iss": issuer,
        "aud": "client-abc",
        "exp": now() + 3600,
        "nbf": now() - 10,
        "iat": now() - 10,
        "nonce": nonce,
        "azp": "client-abc",
        "preferred_username": username,
        "email": format!("{username}@corp.example"),
        "name": format!("User {username}"),
        "roles": roles,
    })
}

fn admin_mapping() -> ClaimMapping {
    ClaimMapping {
        username_claim: "preferred_username".into(),
        email_claim: "email".into(),
        display_name_claim: "name".into(),
        admin_claim: "roles".into(),
        admin_groups: vec!["forge-admins".into()],
        required_claims: Default::default(),
    }
}

// ── begin_login ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn begin_login_persists_flow_and_builds_authorize_url() {
    let pool = pool().await;
    let idp = MockIdp::start().await;

    let begun = begin_login(&pool, &idp.meta(), &idp.client(), "/packages")
        .await
        .expect("begin_login");

    // The authorize URL points at the IdP and carries the PKCE/state/nonce.
    assert!(begun
        .authorize_url
        .starts_with(&format!("{}/authorize", idp.issuer)));
    assert!(begun.authorize_url.contains("code_challenge_method=S256"));
    assert!(begun
        .authorize_url
        .contains(&format!("state={}", begun.state)));
    // The client secret must never appear in a redirect URL.
    assert!(!begun.authorize_url.contains("shh-secret"));

    // The flow row exists and is consumable exactly once.
    let consumed = oidc_flow_dao::consume(&pool, &begun.state)
        .await
        .expect("consume")
        .expect("row present");
    assert_eq!(consumed.redirect_to, "/packages");
    // Second consume returns nothing (single-use).
    assert!(oidc_flow_dao::consume(&pool, &begun.state)
        .await
        .expect("consume2")
        .is_none());
}

// ── complete_login ────────────────────────────────────────────────────────────

#[tokio::test]
async fn complete_login_happy_path_then_replay_fails() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let sub = format!("sub-{n}");

    let begun = begin_login(&pool, &idp.meta(), &idp.client(), "/home")
        .await
        .expect("begin");

    // The IdP issues a token whose nonce matches the flow's nonce. We must read
    // the nonce the begin step generated; it is stored on the (now still-present)
    // flow row — peek it without consuming by re-deriving from a fresh begin is
    // wrong, so fetch it directly.
    let nonce = peek_nonce(&pool, &begun.state).await;
    idp.mount_token_with_claims(id_claims(
        &idp.issuer,
        &sub,
        &format!("alice-{n}"),
        &nonce,
        json!(["forge-admins"]),
    ))
    .await;

    let validated = complete_login(
        &pool,
        &idp.meta(),
        &idp.client(),
        &CallbackParams {
            code: Some("the-code".into()),
            state: Some(begun.state.clone()),
            browser_binding: Some(oidc::browser_binding(&begun.state)),
            ..Default::default()
        },
    )
    .await
    .expect("complete_login");

    assert_eq!(validated.subject, sub);
    assert_eq!(validated.issuer, idp.issuer);
    assert_eq!(validated.redirect_to, "/home");

    // Replaying the same callback fails — the flow row was consumed.
    let replay = complete_login(
        &pool,
        &idp.meta(),
        &idp.client(),
        &CallbackParams {
            code: Some("the-code".into()),
            state: Some(begun.state.clone()),
            browser_binding: Some(oidc::browser_binding(&begun.state)),
            ..Default::default()
        },
    )
    .await;
    assert!(
        matches!(replay, Err(FlowError::UnknownState)),
        "got {replay:?}"
    );
}

/// A client assertion signer that hands out a fixed assertion, or fails.
struct FixedAssertion(Result<&'static str, &'static str>);

#[async_trait::async_trait]
impl ClientAssertion for FixedAssertion {
    async fn client_assertion(&self) -> Result<String, String> {
        self.0.map(str::to_string).map_err(str::to_string)
    }
}

#[tokio::test]
async fn complete_login_authenticates_with_a_client_assertion_instead_of_a_secret() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let client = ClientParams {
        auth: ClientAuth::Assertion(std::sync::Arc::new(FixedAssertion(Ok(
            "signed.client.assertion",
        )))),
        ..idp.client()
    };

    let begun = begin_login(&pool, &idp.meta(), &client, "/")
        .await
        .expect("begin");
    let nonce = peek_nonce(&pool, &begun.state).await;
    // Only a request carrying the assertion gets an ID token.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        ))
        .and(body_string_contains("client_assertion=signed.client.assertion"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": idp.signer.sign(&id_claims(
                &idp.issuer,
                &format!("sub-{n}"),
                &format!("carol-{n}"),
                &nonce,
                json!([]),
            )),
        })))
        .mount(&idp.server)
        .await;

    let validated = complete_login(
        &pool,
        &idp.meta(),
        &client,
        &CallbackParams {
            code: Some("the-code".into()),
            state: Some(begun.state.clone()),
            browser_binding: Some(oidc::browser_binding(&begun.state)),
            ..Default::default()
        },
    )
    .await
    .expect("complete_login with a client assertion");
    assert_eq!(validated.subject, format!("sub-{n}"));

    let requests = idp.server.received_requests().await.expect("recorded");
    let token_request = requests
        .iter()
        .find(|r| r.url.path() == "/token")
        .expect("token request");
    let body = String::from_utf8_lossy(&token_request.body);
    assert!(!body.contains("client_secret"), "{body}");
}

#[tokio::test]
async fn complete_login_fails_without_calling_the_idp_when_the_assertion_cannot_be_signed() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let client = ClientParams {
        auth: ClientAuth::Assertion(std::sync::Arc::new(FixedAssertion(Err("no keys")))),
        ..idp.client()
    };
    let begun = begin_login(&pool, &idp.meta(), &client, "/")
        .await
        .expect("begin");

    let result = complete_login(
        &pool,
        &idp.meta(),
        &client,
        &CallbackParams {
            code: Some("the-code".into()),
            state: Some(begun.state.clone()),
            browser_binding: Some(oidc::browser_binding(&begun.state)),
            ..Default::default()
        },
    )
    .await;
    assert!(
        matches!(&result, Err(FlowError::ClientAssertion(e)) if e == "no keys"),
        "got {result:?}"
    );
    let requests = idp.server.received_requests().await.expect("recorded");
    assert!(requests.iter().all(|r| r.url.path() != "/token"));
}

#[tokio::test]
async fn complete_login_rejects_nonce_mismatch() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();

    let begun = begin_login(&pool, &idp.meta(), &idp.client(), "/")
        .await
        .expect("begin");

    // Token carries a DIFFERENT nonce than the flow's.
    idp.mount_token_with_claims(id_claims(
        &idp.issuer,
        &format!("sub-{n}"),
        &format!("bob-{n}"),
        "a-totally-different-nonce",
        json!([]),
    ))
    .await;

    let res = complete_login(
        &pool,
        &idp.meta(),
        &idp.client(),
        &CallbackParams {
            code: Some("c".into()),
            state: Some(begun.state.clone()),
            browser_binding: Some(oidc::browser_binding(&begun.state)),
            ..Default::default()
        },
    )
    .await;
    assert!(
        matches!(res, Err(FlowError::Oidc(oidc::OidcError::NonceMismatch))),
        "got {res:?}"
    );
}

#[tokio::test]
async fn complete_login_unknown_state_rejected() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let res = complete_login(
        &pool,
        &idp.meta(),
        &idp.client(),
        &CallbackParams {
            code: Some("c".into()),
            state: Some("never-issued-state".into()),
            browser_binding: Some(oidc::browser_binding("never-issued-state")),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(res, Err(FlowError::UnknownState)), "got {res:?}");
}

#[tokio::test]
async fn complete_login_rejects_other_browser_without_consuming_flow() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let begun = begin_login(&pool, &idp.meta(), &idp.client(), "/")
        .await
        .expect("begin");

    // A victim's browser lured to the attacker's callback URL carries no (or a
    // different flow's) binding cookie: rejected before anything is consumed.
    for binding in [None, Some(oidc::browser_binding("some-other-state"))] {
        let res = complete_login(
            &pool,
            &idp.meta(),
            &idp.client(),
            &CallbackParams {
                code: Some("c".into()),
                state: Some(begun.state.clone()),
                browser_binding: binding,
                ..Default::default()
            },
        )
        .await;
        assert!(
            matches!(res, Err(FlowError::BrowserMismatch)),
            "got {res:?}"
        );
    }

    // The legitimate browser can still complete its own flow.
    let nonce = peek_nonce(&pool, &begun.state).await;
    idp.mount_token_with_claims(id_claims(
        &idp.issuer,
        &format!("sub-{n}"),
        &format!("bound-{n}"),
        &nonce,
        json!([]),
    ))
    .await;
    complete_login(
        &pool,
        &idp.meta(),
        &idp.client(),
        &CallbackParams {
            code: Some("c".into()),
            state: Some(begun.state.clone()),
            browser_binding: Some(oidc::browser_binding(&begun.state)),
            ..Default::default()
        },
    )
    .await
    .expect("bound browser completes");
}

#[tokio::test]
async fn complete_login_surfaces_provider_error() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let res = complete_login(
        &pool,
        &idp.meta(),
        &idp.client(),
        &CallbackParams {
            error: Some("access_denied".into()),
            error_description: Some("user cancelled".into()),
            state: Some("s".into()),
            browser_binding: Some(oidc::browser_binding("s")),
            ..Default::default()
        },
    )
    .await;
    match res {
        Err(FlowError::Provider { error, .. }) => assert_eq!(error, "access_denied"),
        other => panic!("expected provider error, got {other:?}"),
    }
}

/// An `error` callback that is not bound to this browser's flow is a
/// browser mismatch: its `error`/`error_description` text is anyone's, so it
/// is never surfaced (or logged) as the IdP's answer.
#[tokio::test]
async fn unbound_provider_error_is_a_browser_mismatch() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let res = complete_login(
        &pool,
        &idp.meta(),
        &idp.client(),
        &CallbackParams {
            error: Some("access_denied\nforged log line".into()),
            error_description: Some("x".repeat(100_000)),
            state: Some("s".into()),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(res, Err(FlowError::BrowserMismatch)), "{res:?}");
}

// ── resolve_user ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn resolve_user_auto_provisions_then_relinks_same_user() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let sub = format!("sub-{n}");
    let username = format!("newbie-{n}@example.com");

    let validated = run_login(&pool, &idp, &sub, &username, json!(["forge-admins"])).await;
    let mapped = map_claims(&validated.claims, &admin_mapping());
    assert!(mapped.is_admin, "roles claim grants admin");

    let user = oidc::resolve_user(&pool, &validated, &mapped, &ResolvePolicy::default())
        .await
        .expect("provision");
    assert_eq!(user.username, username);
    assert!(forge_db::authz_dao::user_has_role(&pool, user.id, "admin")
        .await
        .unwrap());
    let first_id = user.id;

    // A second login for the same (issuer, sub) loads the SAME user (no dup),
    // and dropping the admin role revokes admin on next login.
    let validated2 = run_login(&pool, &idp, &sub, &username, json!(["user"])).await;
    let mapped2 = map_claims(&validated2.claims, &admin_mapping());
    assert!(!mapped2.is_admin);
    let user2 = oidc::resolve_user(&pool, &validated2, &mapped2, &ResolvePolicy::default())
        .await
        .expect("relink");
    assert_eq!(user2.id, first_id, "same app_user, not a duplicate");
    assert!(
        !forge_db::authz_dao::user_has_role(&pool, user2.id, "admin")
            .await
            .unwrap(),
        "admin recomputed/revoked on login"
    );
}

#[tokio::test]
async fn resolve_user_never_links_password_or_admin_account_by_username() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let username = format!("bootstrap-admin-{n}@example.com");

    // Pre-create a local user (a bootstrap admin) with this username.
    let local = user_dao::insert_user(
        &pool,
        NewUser::local(username.clone(), "argon2-hash".into(), true),
    )
    .await
    .expect("local user");
    forge_db::authz_dao::sync_admin_role(&pool, local.id, true)
        .await
        .unwrap();

    let validated = run_login(
        &pool,
        &idp,
        &format!("sub-{n}"),
        &username,
        json!(["forge-admins"]),
    )
    .await;
    let mapped = map_claims(&validated.claims, &admin_mapping());
    // Default policy (no linking) and even explicit linking: never linked to a
    // password account / admin — a fresh, suffixed user is provisioned.
    for link in [false, true] {
        let policy = ResolvePolicy {
            auto_provision: true,
            link_existing_by_username: link,
        };
        let user = oidc::resolve_user(&pool, &validated, &mapped, &policy)
            .await
            .expect("provisioned separately");
        assert_ne!(user.id, local.id, "never linked to the local admin");
        assert_ne!(user.username, username);
    }
    let still_local = user_dao::find_user_by_id(&pool, local.id)
        .await
        .unwrap()
        .unwrap();
    assert!(still_local.password_hash.is_some());
}

/// #317: every account is named by a UPN. A username claim that is none
/// refuses the login and names the claim; an identity linked before 1.2
/// keeps signing in to its account, renamed `<name>@example.com` at the
/// upgrade, whatever its claim says.
#[tokio::test]
async fn provisioning_needs_a_upn_and_names_the_claim() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let username = format!("legacy-{n}");

    let validated = run_login(&pool, &idp, &format!("sub-{n}"), &username, json!([])).await;
    let mapped = map_claims(&validated.claims, &admin_mapping());
    assert_eq!(mapped.username, username);
    assert_eq!(mapped.username_claim, "preferred_username");
    let err = oidc::resolve_user(&pool, &validated, &mapped, &ResolvePolicy::default())
        .await
        .expect_err("no account for a non-UPN name");
    assert!(
        matches!(&err, oidc::ResolveError::NotUpn { claim } if claim == "preferred_username"),
        "{err:?}"
    );
    assert!(user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .is_none());

    // The same identity, linked before 1.2 to an account of that name, which
    // the upgrade renamed, still resolves to it.
    let legacy_id: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash, active, auth_source, external_subject) \
         VALUES ($1, NULL, true, 'oidc', $2) RETURNING id",
    )
    .bind(forge_db::user_dao::legacy_upn(&username, ""))
    .bind(format!("sub-{n}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    forge_db::external_identity_dao::link(
        &pool,
        legacy_id,
        &validated.issuer,
        &validated.subject,
        Default::default(),
    )
    .await
    .unwrap();
    let user = oidc::resolve_user(&pool, &validated, &mapped, &ResolvePolicy::default())
        .await
        .expect("the linked account signs in");
    assert_eq!(user.id, legacy_id);

    // A claim chain that falls back to `sub` names it.
    let mapping = ClaimMapping {
        username_claim: "upn".into(),
        ..admin_mapping()
    };
    let other = run_login(&pool, &idp, &format!("sub-other-{n}"), &username, json!([])).await;
    let mapped = map_claims(&other.claims, &mapping);
    assert_eq!(mapped.username_claim, "sub");
    let err = oidc::resolve_user(&pool, &other, &mapped, &ResolvePolicy::default())
        .await
        .expect_err("`sub` is no UPN either");
    assert!(
        matches!(&err, oidc::ResolveError::NotUpn { claim } if claim == "sub"),
        "{err:?}"
    );
}

#[tokio::test]
async fn resolve_user_links_passwordless_non_admin_when_enabled() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let username = format!("linkable-{n}@example.com");

    // A passwordless, non-admin account no other credential owns (an OIDC
    // account whose identity link was removed).
    let existing = user_dao::insert_user(
        &pool,
        NewUser {
            username: username.clone(),
            password_hash: None,
            active: true,
            auth_source: "oidc".into(),
            external_subject: None,
        },
    )
    .await
    .expect("user");

    let validated = run_login(&pool, &idp, &format!("sub-{n}"), &username, json!([])).await;
    let mapped = map_claims(&validated.claims, &admin_mapping());

    // Default policy: not linked.
    let default = oidc::resolve_user(&pool, &validated, &mapped, &ResolvePolicy::default())
        .await
        .expect("provision");
    assert_ne!(default.id, existing.id, "linking by username is opt-in");

    let validated2 = run_login(&pool, &idp, &format!("sub2-{n}"), &username, json!([])).await;
    let mapped2 = map_claims(&validated2.claims, &admin_mapping());
    let linked = oidc::resolve_user(
        &pool,
        &validated2,
        &mapped2,
        &ResolvePolicy {
            auto_provision: true,
            link_existing_by_username: true,
        },
    )
    .await
    .expect("link");
    assert_eq!(
        linked.id, existing.id,
        "explicit opt-in links the safe target"
    );
}

/// #322: an invited local account (no password yet: its user is to choose
/// one from the invitation) is never linked by username, so an IdP account
/// claiming its name cannot take it over with its role.
#[tokio::test]
async fn resolve_user_never_links_an_invited_account() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let name = format!("invited-{n}@example.com");
    let invited = forge_db::invitation_dao::insert_invited_user(&pool, &name, &name)
        .await
        .expect("invited user");
    let validated = run_login(&pool, &idp, &format!("sub-i-{n}"), &name, json!([])).await;
    let mapped = map_claims(&validated.claims, &admin_mapping());
    let user = oidc::resolve_user(
        &pool,
        &validated,
        &mapped,
        &ResolvePolicy {
            auto_provision: true,
            link_existing_by_username: true,
        },
    )
    .await
    .expect("provisioned separately");
    assert_ne!(
        user.id, invited.id,
        "an invited account is never linked by name"
    );
    assert!(
        !forge_db::external_identity_dao::user_has_identity(&pool, invited.id)
            .await
            .unwrap()
    );
}

/// Linking by username never takes over an account another credential owns:
/// a credential-forwarding account, or an account already linked to an IdP
/// identity (of another person, possibly at another issuer).
#[tokio::test]
async fn resolve_user_never_links_upstream_or_already_linked_accounts() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let link = ResolvePolicy {
        auto_provision: true,
        link_existing_by_username: true,
    };

    let upstream_name = format!("directory-{n}@example.com");
    let upstream = user_dao::insert_user(
        &pool,
        NewUser {
            username: upstream_name.clone(),
            password_hash: None,
            active: true,
            auth_source: "upstream-basic".into(),
            external_subject: Some(upstream_name.clone()),
        },
    )
    .await
    .expect("upstream user");
    let validated = run_login(
        &pool,
        &idp,
        &format!("sub-u-{n}"),
        &upstream_name,
        json!([]),
    )
    .await;
    let mapped = map_claims(&validated.claims, &admin_mapping());
    let user = oidc::resolve_user(&pool, &validated, &mapped, &link)
        .await
        .expect("provisioned separately");
    assert_ne!(
        user.id, upstream.id,
        "a directory account is never linked by name"
    );

    // Victim signs in once (linked to sub-victim); an attacker whose IdP
    // account claims the same preferred_username gets a separate account.
    let victim_name = format!("victim-{n}@example.com");
    let v = run_login(
        &pool,
        &idp,
        &format!("sub-victim-{n}"),
        &victim_name,
        json!([]),
    )
    .await;
    let victim = oidc::resolve_user(&pool, &v, &map_claims(&v.claims, &admin_mapping()), &link)
        .await
        .expect("victim provisioned");
    let a = run_login(
        &pool,
        &idp,
        &format!("sub-attacker-{n}"),
        &victim_name,
        json!([]),
    )
    .await;
    let attacker = oidc::resolve_user(&pool, &a, &map_claims(&a.claims, &admin_mapping()), &link)
        .await
        .expect("attacker provisioned separately");
    assert_ne!(
        attacker.id, victim.id,
        "an account already linked to an identity is never linked to another"
    );
}

#[tokio::test]
async fn resolve_user_demotion_removes_admin_role() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let sub = format!("sub-demote-{n}");
    let username = format!("demote-{n}@example.com");

    let validated = run_login(&pool, &idp, &sub, &username, json!(["forge-admins"])).await;
    let mapped = map_claims(&validated.claims, &admin_mapping());
    let user = oidc::resolve_user(&pool, &validated, &mapped, &ResolvePolicy::default())
        .await
        .expect("provision");
    assert!(forge_db::authz_dao::user_has_role(&pool, user.id, "admin")
        .await
        .unwrap());

    let validated2 = run_login(&pool, &idp, &sub, &username, json!(["user"])).await;
    let mapped2 = map_claims(&validated2.claims, &admin_mapping());
    let user2 = oidc::resolve_user(&pool, &validated2, &mapped2, &ResolvePolicy::default())
        .await
        .expect("relogin");
    assert!(
        !forge_db::authz_dao::user_has_role(&pool, user2.id, "admin")
            .await
            .unwrap(),
        "demotion removes the admin role"
    );
}

#[tokio::test]
async fn resolve_user_rejects_when_no_provision_and_no_match() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();

    let validated = run_login(
        &pool,
        &idp,
        &format!("sub-{n}"),
        &format!("ghost-{n}"),
        json!([]),
    )
    .await;
    let mapped = map_claims(&validated.claims, &admin_mapping());
    let res = oidc::resolve_user(
        &pool,
        &validated,
        &mapped,
        &ResolvePolicy {
            auto_provision: false,
            link_existing_by_username: false,
        },
    )
    .await;
    assert!(
        matches!(res, Err(oidc::ResolveError::NotProvisioned)),
        "got {res:?}"
    );
}

#[tokio::test]
async fn resolve_user_rejects_inactive_linked_user() {
    let pool = pool().await;
    let idp = MockIdp::start().await;
    let n = unique();
    let sub = format!("sub-{n}");
    let username = format!("disabled-{n}@example.com");

    // Provision via a first login, then deactivate the account locally; the
    // (issuer, subject) link finds it and the active check rejects the login.
    let validated = run_login(&pool, &idp, &sub, &username, json!([])).await;
    let mapped = map_claims(&validated.claims, &admin_mapping());
    let user = oidc::resolve_user(&pool, &validated, &mapped, &ResolvePolicy::default())
        .await
        .expect("provision");
    sqlx::query("UPDATE app_user SET active = false WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("deactivate");

    let validated2 = run_login(&pool, &idp, &sub, &username, json!([])).await;
    let res = oidc::resolve_user(&pool, &validated2, &mapped, &ResolvePolicy::default()).await;
    assert!(
        matches!(res, Err(oidc::ResolveError::Inactive)),
        "got {res:?}"
    );
}

/// Review L7(c): concurrent first logins for the same new `(issuer, subject)`
/// all miss the link lookup and provision. Exactly one account wins the
/// unique link; every caller must come back with THAT account (a session is
/// minted for whatever `resolve_user` returns), and the duplicates it
/// provisioned must be gone — no orphan accounts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_logins_resolve_to_the_linked_account_without_orphans() {
    let pool = pool().await;
    let idp = MockIdp::start().await;

    for round in 0..3 {
        let n = unique();
        let sub = format!("sub-race-{n}");
        let username = format!("racer-{n}@example.com");
        let validated = run_login(&pool, &idp, &sub, &username, json!([])).await;
        let mapped = map_claims(&validated.claims, &admin_mapping());

        let results = futures_util::future::join_all((0..8).map(|_| {
            let (pool, validated, mapped) = (pool.clone(), validated.clone(), mapped.clone());
            tokio::spawn(async move {
                oidc::resolve_user(&pool, &validated, &mapped, &ResolvePolicy::default()).await
            })
        }))
        .await;
        let ids: Vec<i64> = results
            .into_iter()
            .map(|r| {
                r.unwrap()
                    .expect("every concurrent first login resolves")
                    .id
            })
            .collect();

        let linked: i64 = sqlx::query_scalar(
            "SELECT user_id FROM external_identity WHERE issuer = $1 AND subject = $2",
        )
        .bind(&validated.issuer)
        .bind(&sub)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            ids.iter().all(|id| *id == linked),
            "round {round}: every login resolves to the linked account {linked}, got {ids:?}"
        );
        let accounts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM app_user WHERE auth_source = 'oidc' AND external_subject = $1",
        )
        .bind(&sub)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            accounts, 1,
            "round {round}: no orphan accounts are left behind"
        );
    }
}

// ── SessionService ────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_create_validate_revoke_round_trip() {
    let pool = pool().await;
    let n = unique();
    let user = user_dao::insert_user(
        &pool,
        NewUser::local(format!("sess-user-{n}@example.com"), "x".into(), true),
    )
    .await
    .expect("user");

    let svc = SessionService::new(
        pool.clone(),
        ChronoDuration::hours(8),
        ChronoDuration::days(7),
    );

    let issued = svc
        .create_for_user(user.id, None, None)
        .await
        .expect("create");
    // The cookie secret is plaintext; the row stores only its hash.
    assert_ne!(issued.cookie_secret, issued.session.token_hash);

    // Validate by the plaintext cookie secret.
    let found = svc
        .validate(&issued.cookie_secret)
        .await
        .expect("validate")
        .expect("session present");
    assert_eq!(found.id, issued.session.id);
    assert_eq!(found.user_id, user.id);

    // A bogus cookie validates to nothing.
    assert!(svc
        .validate("not-a-real-secret")
        .await
        .expect("v")
        .is_none());

    // Revoke → no longer valid.
    assert!(svc.revoke(issued.session.id).await.expect("revoke"));
    assert!(svc
        .validate(&issued.cookie_secret)
        .await
        .expect("v")
        .is_none());
}

#[tokio::test]
async fn session_rotate_issues_new_and_revokes_old() {
    let pool = pool().await;
    let n = unique();
    let user = user_dao::insert_user(
        &pool,
        NewUser::local(format!("rot-user-{n}@example.com"), "x".into(), true),
    )
    .await
    .expect("user");

    let svc = SessionService::new(
        pool.clone(),
        ChronoDuration::hours(8),
        ChronoDuration::days(7),
    );
    let first = svc
        .create_for_user(user.id, None, None)
        .await
        .expect("create");
    let rotated = svc.rotate(&first.session).await.expect("rotate");

    assert_ne!(rotated.session.id, first.session.id);
    assert_ne!(rotated.cookie_secret, first.cookie_secret);
    // Old cookie no longer validates; new one does.
    assert!(svc
        .validate(&first.cookie_secret)
        .await
        .expect("v")
        .is_none());
    assert!(svc
        .validate(&rotated.cookie_secret)
        .await
        .expect("v")
        .is_some());
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Peek the nonce stored on a live `oidc_flow` row (without consuming it), so a
/// test can make the mock IdP echo the matching nonce.
async fn peek_nonce(pool: &sqlx::PgPool, state: &str) -> String {
    let row = sqlx::query!("SELECT nonce FROM oidc_flow WHERE state = $1", state)
        .fetch_one(pool)
        .await
        .expect("flow row");
    row.nonce
}

/// Run a full begin → complete login against the mock IdP, returning the
/// validated login. The IdP is configured to echo the flow's nonce so the token
/// verifies.
async fn run_login(
    pool: &sqlx::PgPool,
    idp: &MockIdp,
    sub: &str,
    username: &str,
    roles: Value,
) -> oidc::ValidatedLogin {
    let begun = begin_login(pool, &idp.meta(), &idp.client(), "/")
        .await
        .expect("begin");
    let nonce = peek_nonce(pool, &begun.state).await;
    // Each login mounts its own token response keyed on this server; wiremock
    // matches the most-recently-mounted matching mock, so set claims fresh.
    idp.mount_token_with_claims(id_claims(&idp.issuer, sub, username, &nonce, roles))
        .await;
    complete_login(
        pool,
        &idp.meta(),
        &idp.client(),
        &CallbackParams {
            code: Some("code".into()),
            state: Some(begun.state.clone()),
            browser_binding: Some(oidc::browser_binding(&begun.state)),
            ..Default::default()
        },
    )
    .await
    .expect("complete")
}
