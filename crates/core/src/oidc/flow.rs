//! Authorization-code + PKCE flow.
//!
//! Two halves, each correct across instances because **all** ephemeral state is
//! persisted in Postgres (`oidc_flow`), never in process memory:
//!
//! * [`begin_login`] — generate `state` / `nonce` / PKCE `code_verifier`,
//!   compute the S256 `code_challenge`, persist an `oidc_flow` row, and return
//!   the IdP **authorize URL** to redirect the browser to. Nothing is held in
//!   memory.
//! * [`complete_login`] — atomically **consume** the `oidc_flow` row by `state`
//!   (`DELETE … RETURNING`, single-use / replay-safe), exchange the `code` at the
//!   token endpoint (sending the PKCE verifier back verbatim), and verify the
//!   returned ID token (signature + `iss`/`aud`/`exp`/`nbf` + `nonce`) against
//!   the cached JWKS. A callback can therefore be completed by a **different**
//!   instance than the one that began the login.
//!
//! ## Browser binding (login CSRF)
//!
//! The `oidc_flow` row alone proves only that *some* browser started the flow.
//! Without more, an attacker could start a login with their own IdP account and
//! lure a victim's browser to the callback URL, logging the victim into the
//! attacker's account (session swap / login CSRF). The server therefore sets a
//! short-lived, `HttpOnly`, `SameSite=Lax` pre-auth cookie holding
//! [`browser_binding`]`(state)` when the login starts, and [`complete_login`]
//! refuses a callback whose presented cookie does not match the echoed `state`
//! (constant time) — **before** the row is consumed, so a forged callback cannot
//! burn a legitimate flow. The binding is derived from `state` itself, so no
//! extra column is needed and any instance can verify it.
//!
//! ## PKCE without an extra crate
//!
//! The `code_verifier` is a 256-bit URL-safe base64 (no-pad) CSPRNG string and
//! the `code_challenge` is `base64url(sha256(verifier))` — both built here from
//! `rand` + `sha2` + `base64` (existing dependencies). No `oauth2` /
//! `openidconnect` crate is pulled: the flow is small, fully under our control
//! (so we choose where state lives — Postgres), and consistent with the
//! ID-token verifier ([`super::jwks`]) that also uses `jsonwebtoken` directly
//! rather than the heavier `openidconnect`.

use base64::Engine;
use chrono::Duration as ChronoDuration;
use forge_db::oidc_flow_dao::{self, NewOidcFlow};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use url::Url;

use super::jwks::{IdTokenClaims, OidcError, OidcMetadataClient, VerifyParams};

/// How long an `oidc_flow` row stays valid before it is reaped / rejected.
const FLOW_TTL: ChronoDuration = ChronoDuration::minutes(10);

/// Errors raised while driving the authorization-code flow.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// A discovery/JWKS fetch or ID-token verification failed.
    #[error(transparent)]
    Oidc(#[from] OidcError),
    /// The IdP redirected back with an `error` parameter instead of a `code`.
    #[error("oidc provider returned error {error}: {description:?}")]
    Provider {
        /// The OAuth `error` code (e.g. `access_denied`).
        error: String,
        /// The optional human-readable `error_description`.
        description: Option<String>,
    },
    /// The `state` did not match any live `oidc_flow` row (unknown, expired, or
    /// already consumed — i.e. replayed). This is the CSRF defense for the
    /// callback.
    #[error("oidc flow state is unknown, expired, or already used")]
    UnknownState,
    /// The callback's browser did not present the pre-auth binding cookie for
    /// this `state` (missing or mismatched): the flow was started in a
    /// different browser (login CSRF / session swap).
    #[error("oidc flow was not started by this browser")]
    BrowserMismatch,
    /// The token endpoint call failed at the transport / status level.
    #[error("oidc token exchange http error: {0}")]
    TokenHttp(String),
    /// The token endpoint response could not be parsed or omitted `id_token`.
    #[error("oidc token exchange response invalid: {0}")]
    TokenResponse(String),
    /// The client assertion for the token request could not be signed.
    #[error("oidc client assertion unavailable: {0}")]
    ClientAssertion(String),
    /// A database error while persisting/consuming the flow row.
    #[error("oidc flow db error: {0}")]
    Db(String),
}

/// Static parameters of the configured client needed to drive the flow.
///
/// Built by the server from its `OidcConfig`; kept separate from
/// [`super::OidcMetadataClient`] (which owns discovery/JWKS/verification) so the
/// flow functions stay pure given a DB handle + a metadata client.
#[derive(Clone, Debug)]
pub struct ClientParams {
    /// OAuth client (application) id; also the expected ID-token `aud`.
    pub client_id: String,
    /// How the client authenticates at the token endpoint.
    pub auth: ClientAuth,
    /// Absolute redirect URL registered with the IdP
    /// (`{public_base_url}/auth/oidc/callback`).
    pub redirect_url: String,
    /// Requested scopes (must include `openid`).
    pub scopes: Vec<String>,
    /// Clock-skew leeway (seconds) for ID-token `exp`/`nbf`/`iat`.
    pub leeway_seconds: u64,
}

/// How the client authenticates at the token endpoint. Either credential is
/// sent only there, over the no-redirect, https-only TLS client.
#[derive(Clone)]
pub enum ClientAuth {
    /// The OAuth client secret, in the request body (`client_secret_post`).
    /// **Never logged** — the manual [`std::fmt::Debug`] impl below redacts
    /// it.
    Secret(String),
    /// A JWT client assertion (RFC 7523) signed per token request, e.g. one
    /// forge issues itself ([`super::assertion`]) for an Entra federated
    /// identity credential.
    Assertion(std::sync::Arc<dyn ClientAssertion>),
}

/// Manual `Debug` that **redacts the client secret** so a stray `{:?}` (a log
/// line, a `dbg!`, an error wrapper) can never spill it — defense in depth on
/// top of the "never logged" discipline, mirroring `OidcConfig`'s treatment.
impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientAuth::Secret(_) => f.write_str("Secret(<redacted>)"),
            ClientAuth::Assertion(_) => f.write_str("Assertion"),
        }
    }
}

/// Signs the `client_assertion` of a token request.
#[async_trait::async_trait]
pub trait ClientAssertion: Send + Sync {
    /// A freshly signed assertion (a compact JWS).
    async fn client_assertion(&self) -> Result<String, String>;
}

/// The outcome of [`begin_login`]: the URL to 302 the browser to, plus the
/// `state` that was persisted (handy for tests / logging — it is **not** a
/// secret on its own, the row is single-use).
#[derive(Debug, Clone)]
pub struct BeginLogin {
    /// Fully-built IdP authorize URL (browser is redirected here).
    pub authorize_url: String,
    /// The `state` value persisted in `oidc_flow` and echoed by the IdP.
    pub state: String,
}

/// A successfully verified login, ready for identity resolution
/// ([`super::resolve_user`]). Holds the validated claims and the post-login
/// redirect target recovered from the consumed `oidc_flow` row.
#[derive(Debug, Clone)]
pub struct ValidatedLogin {
    /// `iss` of the ID token, verbatim (already validated to equal the
    /// discovered issuer, which matches the configured one up to a trailing
    /// slash).
    pub issuer: String,
    /// `sub` of the ID token — the stable identity join key.
    pub subject: String,
    /// All verified ID-token claims (for claim → user mapping).
    pub claims: IdTokenClaims,
    /// The validated, relative post-login redirect path from the flow row.
    pub redirect_to: String,
}

/// Begin a login: generate state/nonce/PKCE, persist the `oidc_flow` row, and
/// return the IdP authorize URL.
///
/// `redirect_to` is the (already open-redirect-validated by the caller) relative
/// path to send the user to after login; it is persisted so the completing
/// instance — possibly a *different* one — can honor it.
pub async fn begin_login(
    pool: &PgPool,
    meta: &OidcMetadataClient,
    client: &ClientParams,
    redirect_to: &str,
) -> Result<BeginLogin, FlowError> {
    let discovery = meta.discovery().await?;

    let state = random_token();
    let nonce = random_token();
    let code_verifier = random_token();
    let code_challenge = s256_challenge(&code_verifier);

    // Persist BEFORE redirecting: the row is the only record of this flow, shared
    // across instances. Generating the URL after the insert means a failed insert
    // never sends the browser to the IdP for a flow we can't complete. The expiry
    // is on the database's clock, which the callback's lookup compares it with.
    let now = forge_db::db_now(pool)
        .await
        .map_err(|e| FlowError::Db(e.to_string()))?;
    oidc_flow_dao::begin(
        pool,
        NewOidcFlow {
            state: state.clone(),
            nonce: nonce.clone(),
            pkce_verifier: code_verifier,
            redirect_to: redirect_to.to_string(),
            expires_at: now + FLOW_TTL,
        },
    )
    .await
    .map_err(|e| FlowError::Db(e.to_string()))?;

    let authorize_url = build_authorize_url(
        &discovery.authorization_endpoint,
        client,
        &state,
        &nonce,
        &code_challenge,
    )
    .map_err(|e| FlowError::TokenResponse(format!("bad authorize endpoint: {e}")))?;

    Ok(BeginLogin {
        authorize_url,
        state,
    })
}

/// The pre-auth cookie value that binds a flow to the browser that began it:
/// `base64url(sha256("forge-oidc-flow\0" || state))`. Set by the server at
/// login start; [`complete_login`] requires it back (see module docs).
pub fn browser_binding(state: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"forge-oidc-flow\0");
    hasher.update(state.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Constant-time check that `presented` is the binding for `state`.
fn browser_binding_matches(state: &str, presented: &str) -> bool {
    browser_binding(state)
        .as_bytes()
        .ct_eq(presented.as_bytes())
        .unwrap_u8()
        == 1
}

/// Parameters echoed by the IdP on the callback.
#[derive(Debug, Clone, Default)]
pub struct CallbackParams {
    /// The `code` to exchange (present on success).
    pub code: Option<String>,
    /// The `state` to match against `oidc_flow` (always present).
    pub state: Option<String>,
    /// An OAuth `error` code (present on failure).
    pub error: Option<String>,
    /// An optional human-readable error description.
    pub error_description: Option<String>,
    /// The pre-auth binding cookie the callback's browser presented (see
    /// [`browser_binding`]). Required: a missing/mismatched value is rejected.
    pub browser_binding: Option<String>,
}

/// Complete a login from the callback parameters.
///
/// 1. If the IdP signalled an `error`, surface it.
/// 2. Require the browser's pre-auth binding cookie to match `state`
///    ([`FlowError::BrowserMismatch`] otherwise) — before anything is consumed.
/// 3. Atomically **consume** the `oidc_flow` row by `state` (single-use; an
///    unknown/expired/replayed state yields [`FlowError::UnknownState`]).
/// 4. Exchange `code` + the row's PKCE verifier at the token endpoint.
/// 5. Verify the returned `id_token` (signature + claims + the row's `nonce`).
///
/// Returns the validated claims + the persisted redirect target. Pure given the
/// injected `pool` / `meta` / `client` — so it is testable with a mock token
/// endpoint and a self-signed token, and any instance can run it.
pub async fn complete_login(
    pool: &PgPool,
    meta: &OidcMetadataClient,
    client: &ClientParams,
    params: &CallbackParams,
) -> Result<ValidatedLogin, FlowError> {
    let state = params.state.as_deref().ok_or(FlowError::UnknownState)?;

    // 1. The flow must have been started by this browser (login CSRF defense).
    //    Checked before the consume so a forged callback can't burn the row,
    //    and before an IdP-signalled error is surfaced: an unbound callback's
    //    `error`/`error_description` are anyone's text, not the IdP's.
    match params.browser_binding.as_deref() {
        Some(presented) if browser_binding_matches(state, presented) => {}
        _ => return Err(FlowError::BrowserMismatch),
    }

    // 2. IdP-signalled error (the flow is spent either way).
    if let Some(error) = &params.error {
        let _ = oidc_flow_dao::consume(pool, state).await;
        return Err(FlowError::Provider {
            error: error.clone(),
            description: params.error_description.clone(),
        });
    }

    // 3. Single-use consume. A replayed state finds nothing here.
    let flow = oidc_flow_dao::consume(pool, state)
        .await
        .map_err(|e| FlowError::Db(e.to_string()))?
        .ok_or(FlowError::UnknownState)?;

    let code = params
        .code
        .as_deref()
        .ok_or_else(|| FlowError::TokenResponse("callback had no code and no error".into()))?;

    // 4. Exchange the code (PKCE verifier sent verbatim).
    let discovery = meta.discovery().await?;
    let id_token = exchange_code(
        meta,
        &discovery.token_endpoint,
        client,
        code,
        &flow.pkce_verifier,
    )
    .await?;

    // 5. Verify signature + registered claims + this flow's nonce.
    let verified = meta
        .verify_id_token(
            &id_token,
            &VerifyParams {
                audience: client.client_id.clone(),
                nonce: Some(flow.nonce.clone()),
                leeway_seconds: client.leeway_seconds,
            },
        )
        .await?;

    Ok(ValidatedLogin {
        issuer: verified.issuer,
        subject: verified.subject,
        claims: verified.claims,
        redirect_to: flow.redirect_to,
    })
}

/// The subset of an OAuth token-endpoint response we use. We only need the
/// `id_token`; access/refresh tokens are intentionally **not** persisted.
#[derive(Debug, serde::Deserialize)]
struct TokenEndpointResponse {
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Largest token-endpoint response read into memory.
const MAX_TOKEN_RESPONSE_BYTES: usize = 1024 * 1024;

/// POST the authorization-code grant to the token endpoint and return the raw
/// `id_token` JWS. Uses the metadata client's no-redirect HTTP client.
async fn exchange_code(
    meta: &OidcMetadataClient,
    token_endpoint: &str,
    client: &ClientParams,
    code: &str,
    pkce_verifier: &str,
) -> Result<String, FlowError> {
    // Outlives `form`, which borrows it.
    let assertion: String;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", client.redirect_url.as_str()),
        ("client_id", client.client_id.as_str()),
        ("code_verifier", pkce_verifier),
    ];
    match &client.auth {
        ClientAuth::Secret(secret) => form.push(("client_secret", secret.as_str())),
        ClientAuth::Assertion(signer) => {
            assertion = signer
                .client_assertion()
                .await
                .map_err(FlowError::ClientAssertion)?;
            form.push((
                "client_assertion_type",
                super::assertion::CLIENT_ASSERTION_TYPE,
            ));
            form.push(("client_assertion", assertion.as_str()));
        }
    }

    let resp = meta
        .http_client()
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| FlowError::TokenHttp(e.to_string()))?;

    let status = resp.status();
    // A redirect is never followed (the request body carries the client
    // credential); report it rather than parsing the 3xx body.
    if status.is_redirection() {
        return Err(FlowError::TokenHttp(format!(
            "status {status} (redirects are not followed)"
        )));
    }
    let bytes = super::jwks::read_capped(resp, MAX_TOKEN_RESPONSE_BYTES)
        .await
        .map_err(|e| match e {
            super::jwks::ReadCappedError::TooLarge => {
                FlowError::TokenResponse("token response too large".into())
            }
            super::jwks::ReadCappedError::Read(e) => {
                FlowError::TokenHttp(format!("read body: {e}"))
            }
        })?;
    let parsed: TokenEndpointResponse = serde_json::from_slice(&bytes)
        .map_err(|e| FlowError::TokenResponse(format!("parse: {e}")))?;

    if let Some(error) = parsed.error {
        // Surface the OAuth error; never echo the client credential or full body.
        return Err(FlowError::Provider {
            error,
            description: parsed.error_description,
        });
    }
    if !status.is_success() {
        return Err(FlowError::TokenHttp(format!("status {status}")));
    }
    parsed
        .id_token
        .ok_or_else(|| FlowError::TokenResponse("token response had no id_token".into()))
}

/// Build the IdP authorize URL with the standard OIDC code-flow query params.
fn build_authorize_url(
    authorization_endpoint: &str,
    client: &ClientParams,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> Result<String, url::ParseError> {
    let mut url = Url::parse(authorization_endpoint)?;
    {
        let scopes = client.scopes.join(" ");
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", &client.client_id);
        q.append_pair("redirect_uri", &client.redirect_url);
        q.append_pair("scope", &scopes);
        q.append_pair("state", state);
        q.append_pair("nonce", nonce);
        q.append_pair("code_challenge", code_challenge);
        q.append_pair("code_challenge_method", "S256");
    }
    Ok(url.to_string())
}

/// A fresh 256-bit URL-safe base64 (no-pad) CSPRNG token, used for `state`,
/// `nonce`, and the PKCE `code_verifier`. (A 43-char no-pad base64url string is a
/// valid PKCE verifier per RFC 7636.)
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute the PKCE S256 challenge: `base64url(sha256(verifier))`, no padding.
fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_binding_is_state_specific_and_checked_in_constant_time() {
        let b = browser_binding("state-a");
        assert!(browser_binding_matches("state-a", &b));
        assert!(!browser_binding_matches("state-b", &b));
        assert!(!browser_binding_matches("state-a", ""));
        assert!(
            !browser_binding_matches("state-a", "state-a"),
            "not the raw state"
        );
        assert_eq!(
            b,
            browser_binding("state-a"),
            "deterministic across instances"
        );
    }

    #[test]
    fn s256_challenge_matches_rfc7636_example() {
        // RFC 7636 Appendix B worked example.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = s256_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn random_token_is_unique_and_32_bytes() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&a)
            .expect("valid base64url");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn authorize_url_has_pkce_and_state_params() {
        let client = ClientParams {
            client_id: "client-abc".into(),
            auth: ClientAuth::Secret("shh".into()),
            redirect_url: "https://forge.test/auth/oidc/callback".into(),
            scopes: vec!["openid".into(), "profile".into()],
            leeway_seconds: 60,
        };
        let url = build_authorize_url(
            "https://idp.test/authorize",
            &client,
            "the-state",
            "the-nonce",
            "the-challenge",
        )
        .unwrap();
        let parsed = Url::parse(&url).unwrap();
        let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["client_id"], "client-abc");
        assert_eq!(pairs["state"], "the-state");
        assert_eq!(pairs["nonce"], "the-nonce");
        assert_eq!(pairs["code_challenge"], "the-challenge");
        assert_eq!(pairs["code_challenge_method"], "S256");
        assert_eq!(pairs["scope"], "openid profile");
        assert_eq!(pairs["redirect_uri"], client.redirect_url);
        // The secret is never in the authorize URL.
        assert!(!url.contains("shh"));
    }

    #[test]
    fn client_params_debug_redacts_secret() {
        let client = ClientParams {
            client_id: "client-abc".into(),
            auth: ClientAuth::Secret("super-secret-value".into()),
            redirect_url: "https://forge.test/auth/oidc/callback".into(),
            scopes: vec!["openid".into()],
            leeway_seconds: 60,
        };
        let dbg = format!("{client:?}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(!dbg.contains("super-secret-value"), "{dbg}");
        // Non-secret fields are still visible for diagnostics.
        assert!(dbg.contains("client-abc"));
    }
}
