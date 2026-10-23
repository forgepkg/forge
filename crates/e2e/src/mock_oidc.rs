//! In-process mock OpenID Connect provider for the OIDC e2e scenarios.
//!
//! A tiny axum app served on an ephemeral loopback port that plays the IdP:
//!
//! * `GET /.well-known/openid-configuration` — discovery (issuer + authorize /
//!   token / jwks / end_session endpoints).
//! * `GET /jwks` — the public RSA key (the `kid` the ID tokens are signed with),
//!   plus any extra retired/rotated keys the test adds.
//! * `GET /authorize` — immediately `302`s back to the forge `redirect_uri`,
//!   echoing the `state` with a canned `code` (simulating an already-authenticated
//!   user — no real login UI).
//! * `POST /token` — returns a signed ID token whose claims are taken from the
//!   per-flow script the test installed (keyed by the PKCE-bound nothing — the
//!   test sets the *next* token's claims explicitly so it controls
//!   nonce/`aud`/expiry/`kid`).
//!
//! Because the forge server reaches this over its **SSRF-guarded** HTTP client,
//! the stack must set `oidc.allow_private_issuer = true` (the plain-http issuer
//! is otherwise blocked) — [`MockOidc::oidc_block`] does that.
//!
//! The mock signs ID tokens with a throwaway RSA key it holds; `kid` rotation is
//! supported by [`MockOidc::rotate_key`] (publishes a new `kid` and signs with
//! it) so the JWKS kid-miss refetch path can be exercised.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// A throwaway RSA signer + its published JWK.
#[derive(Clone)]
struct Signer {
    private_pem: String,
    kid: String,
    jwk: Value,
}

impl Signer {
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

/// Mutable IdP state shared with the axum handlers.
struct Inner {
    issuer: String,
    /// Emit only issuer + JWKS metadata, matching non-interactive providers
    /// such as GitHub Actions that have no browser authorize/token endpoints.
    workload_only_discovery: bool,
    /// The active signer (latest after any rotation).
    signer: Signer,
    /// Every key the JWKS advertises (current + any explicitly retained).
    published_jwks: Vec<Value>,
    /// Claims the **next** `/token` call signs and returns. The test installs
    /// this right before triggering the callback.
    next_id_token_claims: Option<Value>,
    /// Override which signer to use for the next token (e.g. a retired key whose
    /// `kid` is no longer in the JWKS). `None` ⇒ the active signer.
    next_signer: Option<Signer>,
}

/// A running in-process mock OIDC provider.
pub struct MockOidc {
    base_url: String,
    client_id: String,
    inner: Arc<Mutex<Inner>>,
    handle: JoinHandle<()>,
}

impl Drop for MockOidc {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Clone)]
struct AppCtx {
    inner: Arc<Mutex<Inner>>,
}

impl MockOidc {
    /// Start the mock IdP for the given OAuth `client_id`, bound to an ephemeral
    /// loopback port. The issuer is `http://127.0.0.1:<port>`.
    pub async fn start(client_id: &str) -> Self {
        Self::start_with_discovery(client_id, false).await
    }

    /// Start a workload-only issuer whose discovery document contains no
    /// interactive OAuth endpoints (the GitHub Actions metadata shape).
    pub async fn start_workload_only(client_id: &str) -> Self {
        Self::start_with_discovery(client_id, true).await
    }

    /// Start a workload-only issuer that a container can reach: it listens on
    /// every interface and its issuer is `http://{host}:<port>`, with `host`
    /// the name the container knows the test host by (e.g.
    /// `host.docker.internal`, mapped to the Docker host gateway).
    pub async fn start_workload_only_on_host(client_id: &str, host: &str) -> Self {
        Self::start_on(client_id, true, "0.0.0.0:0", Some(host)).await
    }

    async fn start_with_discovery(client_id: &str, workload_only_discovery: bool) -> Self {
        Self::start_on(client_id, workload_only_discovery, "127.0.0.1:0", None).await
    }

    /// Bind `bind`; the issuer is `http://<host or bound address>:<port>`.
    async fn start_on(
        client_id: &str,
        workload_only_discovery: bool,
        bind: &str,
        host: Option<&str>,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .expect("bind mock idp");
        let addr = listener.local_addr().expect("idp addr");
        let issuer = match host {
            Some(host) => format!("http://{host}:{}", addr.port()),
            None => format!("http://{addr}"),
        };
        let signer = Signer::new("k1");

        let inner = Arc::new(Mutex::new(Inner {
            issuer: issuer.clone(),
            workload_only_discovery,
            published_jwks: vec![signer.jwk.clone()],
            signer,
            next_id_token_claims: None,
            next_signer: None,
        }));

        let ctx = AppCtx {
            inner: inner.clone(),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(ctx);

        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .ok();
        });

        Self {
            base_url: issuer,
            client_id: client_id.to_string(),
            inner,
            handle,
        }
    }

    /// The issuer URL (also the discovery host).
    pub fn issuer(&self) -> &str {
        &self.base_url
    }

    /// The `[oidc]` TOML block pointing the stack at this mock. `admin_groups`
    /// grants `is_admin` to the `forge-admins` role/group; `allow_private_issuer`
    /// lets the SSRF-guarded client reach the loopback mock over plain http.
    pub fn oidc_block(&self, public_base_url: &str) -> String {
        format!(
            r#"
[oidc]
issuer = "{issuer}"
client_id = "{client_id}"
client_secret = "shh-secret"
redirect_url = "{public_base_url}/auth/oidc/callback"
allow_private_issuer = true
admin_groups = ["forge-admins"]
admin_claim = "roles"
session_idle_ttl_seconds = 28800
session_absolute_ttl_seconds = 604800
"#,
            issuer = self.base_url,
            client_id = self.client_id,
        )
    }

    /// Install the claims the **next** `/token` call returns. Tests set this
    /// after reading the flow's `nonce` from Postgres so the ID token verifies.
    pub async fn set_next_id_token(&self, claims: Value) {
        let mut inner = self.inner.lock().await;
        inner.next_id_token_claims = Some(claims);
        inner.next_signer = None;
    }

    /// Like [`set_next_id_token`](Self::set_next_id_token) but signs with a
    /// caller-supplied signer (used to sign with a **retired** key after
    /// rotation to prove such a token is rejected).
    async fn set_next_id_token_signed_with(&self, claims: Value, signer: Signer) {
        let mut inner = self.inner.lock().await;
        inner.next_id_token_claims = Some(claims);
        inner.next_signer = Some(signer);
    }

    /// Build a standard ID-token claim set for this issuer/client.
    pub fn id_claims(&self, sub: &str, username: &str, nonce: &str, roles: Value) -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "sub": sub,
            "iss": self.base_url,
            "aud": self.client_id,
            "exp": now + 3600,
            "nbf": now - 10,
            "iat": now - 10,
            "nonce": nonce,
            "azp": self.client_id,
            "preferred_username": username,
            "email": format!("{username}@corp.example"),
            "name": format!("User {username}"),
            "roles": roles,
        })
    }

    /// Sign an arbitrary claim set with the active key and return the compact
    /// JWT. Used by WIF e2e scenarios where a workload presents its `id_token`
    /// directly (there is no `/token` exchange).
    pub async fn sign_token(&self, claims: Value) -> String {
        self.inner.lock().await.signer.sign(&claims)
    }

    /// Sign `claims` with a throwaway key whose `kid` is **not** in the published
    /// JWKS — a bad/unknown-signature token for negative WIF tests.
    pub async fn sign_token_unknown_key(&self, claims: Value) -> String {
        Signer::new("wif-unknown").sign(&claims)
    }

    /// Build a WIF-style claim set: `iss` = this issuer, the given `aud`, a fresh
    /// `exp`/`nbf`/`iat`, plus any extra claims (e.g. `project_path`) merged in.
    /// No `nonce` (WIF is non-interactive).
    pub fn wif_claims(&self, sub: &str, aud: &str, extra: Value) -> Value {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "sub": sub,
            "iss": self.base_url,
            "aud": aud,
            "exp": now + 3600,
            "nbf": now - 10,
            "iat": now,
            "jti": format!("mock-{now}-{:016x}", rand::random::<u64>()),
        });
        if let (Some(obj), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        claims
    }

    /// Rotate the signing key: snapshot the **old** signer (so a test can still
    /// sign a token with the now-retired key), publish only the **new** key in
    /// the JWKS, and make it the active signer. Returns the retired signer's
    /// behaviour through [`Self::set_next_id_token_with_retired_key`].
    pub async fn rotate_key(&self, new_kid: &str) {
        let new_signer = Signer::new(new_kid);
        let mut inner = self.inner.lock().await;
        // Publish ONLY the new key — the old kid is now a miss in the JWKS.
        inner.published_jwks = vec![new_signer.jwk.clone()];
        inner.signer = new_signer;
    }

    /// Sign the next token with a freshly-generated key whose `kid` is **not** in
    /// the published JWKS (simulating a token signed by a retired/unknown key).
    /// The forge verifier should reject it after a kid-miss refetch fails to find
    /// the key.
    pub async fn set_next_id_token_with_unknown_key(&self, claims: Value) {
        let retired = Signer::new("retired-unknown");
        self.set_next_id_token_signed_with(claims, retired).await;
    }
}

async fn discovery(State(ctx): State<AppCtx>) -> Response {
    let inner = ctx.inner.lock().await;
    let issuer = inner.issuer.clone();
    let body = if inner.workload_only_discovery {
        json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })
    } else {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "end_session_endpoint": format!("{issuer}/logout"),
        })
    };
    Json(body).into_response()
}

async fn jwks(State(ctx): State<AppCtx>) -> Response {
    let keys = ctx.inner.lock().await.published_jwks.clone();
    Json(json!({ "keys": keys })).into_response()
}

/// Authorize query: we only echo `state` + `redirect_uri` back.
#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    state: String,
    redirect_uri: String,
}

/// `GET /authorize` — 302 straight back to the forge callback with a canned
/// `code` and the echoed `state` (no login UI; the user is "already signed in").
async fn authorize(Query(q): Query<AuthorizeQuery>) -> Response {
    let sep = if q.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = format!("{}{sep}code=mock-code&state={}", q.redirect_uri, q.state);
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

/// `POST /token` — return the test-scripted ID token. The test must have called
/// `set_next_id_token` first (otherwise we 400, surfacing a test wiring bug).
async fn token(State(ctx): State<AppCtx>) -> Response {
    let mut inner = ctx.inner.lock().await;
    let Some(claims) = inner.next_id_token_claims.take() else {
        return (StatusCode::BAD_REQUEST, "no scripted id_token").into_response();
    };
    let signer = inner
        .next_signer
        .take()
        .unwrap_or_else(|| inner.signer.clone());
    let id_token = signer.sign(&claims);
    Json(json!({
        "access_token": "opaque-access",
        "token_type": "Bearer",
        "id_token": id_token,
    }))
    .into_response()
}
