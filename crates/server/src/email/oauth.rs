//! The OAuth side of the `smtp_oauth` transport (#321): Forge as an OAuth
//! client of the mail server's own authorization server (Stalwart, for one),
//! holding a token an administrator authorized once instead of a mailbox
//! password.
//!
//! * **Discovery**: `/.well-known/oauth-authorization-server` (RFC 8414),
//!   else `/.well-known/openid-configuration`; the document's `issuer` must
//!   be the configured one, and every endpoint `https` (or `http` to a
//!   loopback host).
//! * **Registration** (RFC 7591, managed by RFC 7592 when the server says
//!   where): Forge registers itself as a confidential client
//!   (`client_secret_basic`) for the code, refresh and (when offered) device
//!   and client-credentials grants. The registration is authenticated as the
//!   server wants it: an initial access token, an account (HTTP Basic, as
//!   Stalwart takes one with the right to register clients), or nothing.
//!   Without a registration endpoint the administrator enters a client.
//! * **Tokens**: the authorization code exchange (with the PKCE verifier),
//!   the device grant (RFC 8628), the refresh grant and the client
//!   credentials grant.
//!
//! [`OauthTokens`] keeps each instance's access token until shortly before it
//! expires, and writes a rotated refresh token, or the failure of a refresh
//! (the mailbox must authorize Forge again), back to the settings.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use forge_crypto::service::EnvelopeService;
use forge_db::email_settings_dao;
use forge_db::secret_dao;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::settings::{check_oauth_url, EmailConfig, OauthGrant, SmtpOauthConfig, TransportConfig};

/// How long one request to the authorization server may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A cached access token is dropped this long before it expires.
const TOKEN_MARGIN: Duration = Duration::from_secs(60);

/// The most of an error body reported.
const MAX_ERROR_BYTES: usize = 2048;

/// The most of a response body read.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// The callback's path: the redirect URI is `server.public_base_url` and
/// this.
pub const CALLBACK_PATH: &str = "/admin/settings/email/oauth/callback";

/// The device grant's `grant_type` (RFC 8628).
pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The authorization server's metadata, as far as Forge uses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

impl AuthServerMetadata {
    /// Whether the server issues tokens by the client credentials grant.
    pub fn offers_client_credentials(&self) -> bool {
        self.grant_types_supported
            .iter()
            .any(|g| g == "client_credentials")
    }

    /// Whether the device grant is available.
    pub fn offers_device(&self) -> bool {
        self.device_authorization_endpoint.is_some()
    }
}

/// A client Forge authenticates as at the token endpoint.
#[derive(Debug, Clone)]
pub struct OauthClient {
    pub client_id: String,
    pub client_secret: Option<String>,
}

impl OauthClient {
    /// The client of `config`, once it has one.
    pub fn of(config: &SmtpOauthConfig) -> Option<OauthClient> {
        Some(OauthClient {
            client_id: config.client_id.clone()?,
            client_secret: config.client_secret.clone(),
        })
    }
}

/// A registration (RFC 7591): the client and how to manage it (RFC 7592).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub registration_client_uri: Option<String>,
    pub registration_access_token: Option<String>,
}

/// A token endpoint's answer.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// A refused token request: the OAuth `error` (RFC 6749 §5.2) and the text
/// to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenError {
    pub error: Option<String>,
    pub message: String,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// A started device authorization (RFC 8628 §3.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    #[serde(default)]
    pub interval: Option<u64>,
}

/// One poll of a device authorization.
#[derive(Debug)]
pub enum DevicePoll {
    /// The mailbox has not decided yet.
    Pending,
    /// Poll less often.
    SlowDown,
    /// Authorized.
    Done(TokenSet),
    /// Refused, expired or failed: the OAuth `error`, and the text.
    Failed(Option<String>, String),
}

/// The HTTP client for authorization servers: no redirects, bounded time.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("forge/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("the OAuth HTTP client builds")
}

/// `text` cut to [`MAX_ERROR_BYTES`] at a character boundary.
fn clip(text: &str) -> &str {
    let mut end = text.len().min(MAX_ERROR_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

async fn body_text(response: reqwest::Response) -> String {
    let bytes = response.bytes().await.unwrap_or_default();
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_BODY_BYTES)]).into_owned()
}

/// The well-known metadata URLs for `issuer`, in the order they are tried:
/// RFC 8414's (the well-known segment between host and path), then OIDC's
/// (appended to the issuer).
pub fn metadata_urls(issuer: &str) -> Result<Vec<String>, String> {
    let url = url::Url::parse(issuer).map_err(|_| "the issuer is not a URL".to_string())?;
    let origin = url.origin().ascii_serialization();
    let path = url.path().trim_end_matches('/');
    Ok(vec![
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ),
    ])
}

/// Read and check `issuer`'s metadata (module docs).
pub async fn discover(http: &reqwest::Client, issuer: &str) -> Result<AuthServerMetadata, String> {
    let issuer = issuer.trim_end_matches('/');
    let mut last_error = String::new();
    for url in metadata_urls(issuer)? {
        let response = match http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_error = format!("{url} could not be reached: {}", super::smtp::describe(&e));
                continue;
            }
        };
        if !response.status().is_success() {
            last_error = format!("{url} answered {}", response.status().as_u16());
            continue;
        }
        let body = body_text(response).await;
        let metadata: AuthServerMetadata = serde_json::from_str(&body)
            .map_err(|e| format!("{url} is not authorization server metadata: {e}"))?;
        if metadata.issuer.trim_end_matches('/') != issuer {
            return Err(format!(
                "{url} names the issuer {:?}, not {issuer:?}",
                metadata.issuer
            ));
        }
        for (field, value) in [
            ("token_endpoint", Some(&metadata.token_endpoint)),
            (
                "authorization_endpoint",
                metadata.authorization_endpoint.as_ref(),
            ),
            (
                "registration_endpoint",
                metadata.registration_endpoint.as_ref(),
            ),
            (
                "device_authorization_endpoint",
                metadata.device_authorization_endpoint.as_ref(),
            ),
        ] {
            if let Some(value) = value {
                check_oauth_url(field, value).map_err(|e| format!("the metadata's {e}"))?;
            }
        }
        return Ok(metadata);
    }
    Err(format!(
        "no authorization server metadata at {issuer}: {last_error}"
    ))
}

/// The client metadata Forge registers with.
pub fn registration_request(
    metadata: &AuthServerMetadata,
    public_base_url: &str,
    redirect_uri: &str,
    scope: Option<&str>,
) -> JsonValue {
    let mut grant_types = vec!["authorization_code", "refresh_token"];
    if metadata.offers_device() {
        grant_types.push(DEVICE_GRANT);
    }
    if metadata.offers_client_credentials() {
        grant_types.push("client_credentials");
    }
    let mut body = json!({
        "client_name": format!("Forge ({})", public_base_url.trim_end_matches('/')),
        "redirect_uris": [redirect_uri],
        "grant_types": grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    body
}

/// How a registration request is authenticated (used for it only, never
/// stored).
#[derive(Debug, Clone, Copy)]
pub enum RegistrationAuth<'a> {
    /// The server takes registrations from anyone.
    None,
    /// An initial access token (RFC 7591 §3).
    Bearer(&'a str),
    /// An account allowed to register clients (HTTP Basic).
    Basic(&'a str, &'a str),
}

/// Register Forge (RFC 7591), authenticated with `auth`.
pub async fn register(
    http: &reqwest::Client,
    metadata: &AuthServerMetadata,
    request: &JsonValue,
    auth: RegistrationAuth<'_>,
) -> Result<Registration, String> {
    let endpoint = metadata
        .registration_endpoint
        .as_deref()
        .ok_or("the authorization server offers no registration; enter a client by hand")?;
    let mut req = http.post(endpoint).json(request);
    req = match auth {
        RegistrationAuth::None => req,
        RegistrationAuth::Bearer(token) => req.bearer_auth(token),
        RegistrationAuth::Basic(username, password) => req.basic_auth(username, Some(password)),
    };
    let response = req.send().await.map_err(|e| {
        format!(
            "the registration endpoint could not be reached: {}",
            super::smtp::describe(&e)
        )
    })?;
    let status = response.status();
    let body = body_text(response).await;
    if !status.is_success() {
        return Err(oauth_error("the registration was refused", status, &body));
    }
    #[derive(Deserialize)]
    struct Registered {
        client_id: String,
        #[serde(default)]
        client_secret: Option<String>,
        #[serde(default)]
        registration_client_uri: Option<String>,
        #[serde(default)]
        registration_access_token: Option<String>,
    }
    let registered: Registered = serde_json::from_str(&body)
        .map_err(|e| format!("the registration answer has no client: {e}"))?;
    if let Some(uri) = &registered.registration_client_uri {
        check_oauth_url("registration_client_uri", uri)
            .map_err(|e| format!("the registration's {e}"))?;
    }
    Ok(Registration {
        client_id: registered.client_id,
        client_secret: registered.client_secret,
        registration_client_uri: registered.registration_client_uri,
        registration_access_token: registered.registration_access_token,
    })
}

/// Delete a registration (RFC 7592 §2.3). Best effort for the caller; the
/// error says why it failed.
pub async fn delete_registration(
    http: &reqwest::Client,
    uri: &str,
    access_token: &str,
) -> Result<(), String> {
    let response = http
        .delete(uri)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("{uri} could not be reached: {}", super::smtp::describe(&e)))?;
    let status = response.status();
    if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
        return Ok(());
    }
    let body = body_text(response).await;
    Err(oauth_error(
        "the registration was not deleted",
        status,
        &body,
    ))
}

/// The authorization URL of the code flow: PKCE S256, `state`, and the
/// mailbox as `login_hint`.
pub fn authorization_url(
    metadata: &AuthServerMetadata,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    pkce_challenge: &str,
    scope: Option<&str>,
    login_hint: &str,
) -> Result<String, String> {
    let endpoint = metadata
        .authorization_endpoint
        .as_deref()
        .ok_or("the authorization server has no authorization endpoint; use the device flow")?;
    let mut url = url::Url::parse(endpoint).map_err(|e| format!("authorization_endpoint: {e}"))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("state", state);
        q.append_pair("code_challenge", pkce_challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("login_hint", login_hint);
        if let Some(scope) = scope {
            q.append_pair("scope", scope);
        }
    }
    Ok(url.to_string())
}

/// A fresh 256-bit URL-safe token (`state`, the PKCE verifier, the flow
/// cookie).
pub fn random_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The PKCE S256 challenge of `verifier`.
pub fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `application/x-www-form-urlencoded` value encoding, for the client's
/// Basic credentials (RFC 6749 §2.3.1).
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// A token request with `client`'s credentials: `client_secret_basic`, or
/// none for a client without a secret. The client id is in the form either
/// way (RFC 6749 §3.2.1 allows it; Stalwart reads the device grant's from
/// there only).
async fn token_request(
    http: &reqwest::Client,
    metadata: &AuthServerMetadata,
    client: &OauthClient,
    mut form: Vec<(&'static str, String)>,
) -> Result<TokenSet, TokenError> {
    let mut req = http.post(&metadata.token_endpoint);
    if let Some(secret) = &client.client_secret {
        let basic = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            form_encode(&client.client_id),
            form_encode(secret)
        ));
        req = req.header(reqwest::header::AUTHORIZATION, format!("Basic {basic}"));
    }
    form.push(("client_id", client.client_id.clone()));
    let response = req.form(&form).send().await.map_err(|e| TokenError {
        error: None,
        message: format!(
            "the token endpoint could not be reached: {}",
            super::smtp::describe(&e)
        ),
    })?;
    let status = response.status();
    let body = body_text(response).await;
    if !status.is_success() {
        let error = serde_json::from_str::<JsonValue>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(JsonValue::as_str).map(String::from));
        return Err(TokenError {
            error,
            message: oauth_error("the token request was refused", status, &body),
        });
    }
    serde_json::from_str(&body).map_err(|_| TokenError {
        error: None,
        message: "the token endpoint answered without an access token".to_string(),
    })
}

/// Exchange an authorization `code` (with its PKCE `verifier`).
pub async fn exchange_code(
    http: &reqwest::Client,
    metadata: &AuthServerMetadata,
    client: &OauthClient,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenSet, TokenError> {
    token_request(
        http,
        metadata,
        client,
        vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("code_verifier", verifier.to_string()),
        ],
    )
    .await
}

/// Refresh with `refresh_token`.
pub async fn refresh(
    http: &reqwest::Client,
    metadata: &AuthServerMetadata,
    client: &OauthClient,
    refresh_token: &str,
) -> Result<TokenSet, TokenError> {
    token_request(
        http,
        metadata,
        client,
        vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
        ],
    )
    .await
}

/// A token for the client itself (client credentials grant).
pub async fn client_credentials(
    http: &reqwest::Client,
    metadata: &AuthServerMetadata,
    client: &OauthClient,
    scope: Option<&str>,
) -> Result<TokenSet, TokenError> {
    let mut form = vec![("grant_type", "client_credentials".to_string())];
    if let Some(scope) = scope {
        form.push(("scope", scope.to_string()));
    }
    token_request(http, metadata, client, form).await
}

/// Start a device authorization (RFC 8628 §3.1).
pub async fn start_device(
    http: &reqwest::Client,
    metadata: &AuthServerMetadata,
    client: &OauthClient,
    scope: Option<&str>,
) -> Result<DeviceStart, String> {
    let endpoint = metadata
        .device_authorization_endpoint
        .as_deref()
        .ok_or("the authorization server offers no device authorization")?;
    let mut form = vec![("client_id", client.client_id.clone())];
    if let Some(scope) = scope {
        form.push(("scope", scope.to_string()));
    }
    let mut req = http.post(endpoint);
    if let Some(secret) = &client.client_secret {
        req = req.basic_auth(form_encode(&client.client_id), Some(form_encode(secret)));
    }
    let response = req.form(&form).send().await.map_err(|e| {
        format!(
            "the device authorization endpoint could not be reached: {}",
            super::smtp::describe(&e)
        )
    })?;
    let status = response.status();
    let body = body_text(response).await;
    if !status.is_success() {
        return Err(oauth_error(
            "the device authorization was refused",
            status,
            &body,
        ));
    }
    serde_json::from_str(&body).map_err(|e| format!("the device authorization answer: {e}"))
}

/// Poll a device authorization once (RFC 8628 §3.4, §3.5).
pub async fn poll_device(
    http: &reqwest::Client,
    metadata: &AuthServerMetadata,
    client: &OauthClient,
    device_code: &str,
) -> DevicePoll {
    match token_request(
        http,
        metadata,
        client,
        vec![
            ("grant_type", DEVICE_GRANT.to_string()),
            ("device_code", device_code.to_string()),
        ],
    )
    .await
    {
        Ok(tokens) => DevicePoll::Done(tokens),
        Err(e) => match e.error.as_deref() {
            Some("authorization_pending") => DevicePoll::Pending,
            Some("slow_down") => DevicePoll::SlowDown,
            _ => DevicePoll::Failed(e.error, e.message),
        },
    }
}

/// A refused OAuth request: `what`, the status, and the server's `error`
/// and `error_description` when it sent them.
fn oauth_error(what: &str, status: reqwest::StatusCode, body: &str) -> String {
    let parsed: Option<JsonValue> = serde_json::from_str(body).ok();
    let error = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(JsonValue::as_str);
    let description = parsed
        .as_ref()
        .and_then(|v| v.get("error_description"))
        .and_then(JsonValue::as_str);
    match (error, description) {
        (Some(error), Some(description)) => format!(
            "{what} ({} {error}): {}",
            status.as_u16(),
            clip(description)
        ),
        (Some(error), None) => format!("{what} ({} {error})", status.as_u16()),
        _ if body.trim().is_empty() => format!("{what} ({})", status.as_u16()),
        _ => format!("{what} ({}): {}", status.as_u16(), clip(body.trim())),
    }
}

struct CachedToken {
    access_token: String,
    expires: Instant,
}

struct CachedMetadata {
    metadata: AuthServerMetadata,
    fetched: Instant,
}

/// How long discovered metadata is reused.
const METADATA_TTL: Duration = Duration::from_secs(300);

/// Advisory-lock key serializing refreshes across instances, so that two
/// never spend the same refresh token (with rotation, the second would be
/// refused). The value is arbitrary but fixed: ASCII `"forgeeml"` as a
/// big-endian i64, apart from [`crate::crypto::ROTATION_LOCK_KEY`].
pub const REFRESH_LOCK_KEY: i64 = 0x666f_7267_6565_6d6c;

/// Each instance's access tokens and metadata for the `smtp_oauth`
/// transport (module docs).
pub struct OauthTokens {
    http: reqwest::Client,
    pool: PgPool,
    envelope: Arc<EnvelopeService>,
    tokens: tokio::sync::Mutex<HashMap<String, CachedToken>>,
    metadata: tokio::sync::Mutex<HashMap<String, CachedMetadata>>,
}

/// Why no access token could be had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessError {
    /// The mailbox must authorize Forge (again): the settings page says so.
    AuthorizationNeeded(String),
    /// Anything else (the server unreachable, a refused client).
    Failed(String),
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessError::AuthorizationNeeded(why) => write!(
                f,
                "the email service needs authorization: an administrator must authorize \
                 Forge on the email settings page ({why})"
            ),
            AccessError::Failed(why) => f.write_str(why),
        }
    }
}

impl OauthTokens {
    pub fn new(pool: PgPool, envelope: Arc<EnvelopeService>) -> Self {
        OauthTokens {
            http: http_client(),
            pool,
            envelope,
            tokens: tokio::sync::Mutex::new(HashMap::new()),
            metadata: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The HTTP client for authorization servers.
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// `issuer`'s metadata, reused for [`METADATA_TTL`].
    pub async fn metadata(&self, issuer: &str) -> Result<AuthServerMetadata, String> {
        let mut cache = self.metadata.lock().await;
        if let Some(cached) = cache.get(issuer) {
            if cached.fetched.elapsed() < METADATA_TTL {
                return Ok(cached.metadata.clone());
            }
        }
        let metadata = discover(&self.http, issuer).await?;
        cache.insert(
            issuer.to_string(),
            CachedMetadata {
                metadata: metadata.clone(),
                fetched: Instant::now(),
            },
        );
        Ok(metadata)
    }

    /// Drop every cached token and metadata document (the settings changed).
    pub async fn clear(&self) {
        self.tokens.lock().await.clear();
        self.metadata.lock().await.clear();
    }

    /// Drop `oauth`'s cached access token (the mail server refused it).
    pub async fn forget(&self, oauth: &SmtpOauthConfig) {
        self.tokens.lock().await.remove(&token_key(oauth));
    }

    /// An access token for `oauth`: the cached one, a new one by the client
    /// credentials grant, or a refreshed one (see [`Self::refresh_stored`]).
    pub async fn access_token(&self, oauth: &SmtpOauthConfig) -> Result<String, AccessError> {
        let Some(client) = OauthClient::of(oauth) else {
            return Err(AccessError::AuthorizationNeeded(
                "Forge has no OAuth client yet: register it, or enter a client".to_string(),
            ));
        };
        let key = token_key(oauth);
        let mut tokens = self.tokens.lock().await;
        if let Some(cached) = tokens.get(&key) {
            if Instant::now() < cached.expires {
                return Ok(cached.access_token.clone());
            }
        }
        let set = match oauth.grant {
            Some(OauthGrant::ClientCredentials) => {
                let metadata = self
                    .metadata(&oauth.issuer)
                    .await
                    .map_err(AccessError::Failed)?;
                client_credentials(&self.http, &metadata, &client, oauth.scope.as_deref())
                    .await
                    .map_err(|e| AccessError::Failed(e.message))?
            }
            Some(OauthGrant::RefreshToken) => self.refresh_stored(oauth).await?,
            None => {
                return Err(AccessError::AuthorizationNeeded(
                    "the mailbox has not authorized Forge yet".to_string(),
                ))
            }
        };
        let lifetime = Duration::from_secs(set.expires_in.unwrap_or(300));
        tokens.insert(
            key,
            CachedToken {
                access_token: set.access_token.clone(),
                expires: Instant::now() + lifetime.saturating_sub(TOKEN_MARGIN),
            },
        );
        Ok(set.access_token)
    }

    /// Refresh with the refresh token as stored now (not as `oauth`, a
    /// snapshot, has it: another instance may have rotated it), one instance
    /// at a time ([`REFRESH_LOCK_KEY`]). A rotated refresh token is stored;
    /// a refused one (`invalid_grant`) marks the settings as needing
    /// authorization.
    async fn refresh_stored(&self, oauth: &SmtpOauthConfig) -> Result<TokenSet, AccessError> {
        let db = |e: sqlx::Error| AccessError::Failed(format!("database error: {e}"));
        let mut lock = forge_db::begin(&self.pool).await.map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(REFRESH_LOCK_KEY)
            .execute(&mut *lock)
            .await
            .map_err(db)?;
        let stored = self
            .read_stored(oauth)
            .await?
            .ok_or_else(|| AccessError::Failed("the email settings changed; send again".into()))?;
        if let Some(why) = &stored.authorization_error {
            return Err(AccessError::AuthorizationNeeded(why.clone()));
        }
        let (Some(client), Some(used)) = (OauthClient::of(&stored), stored.refresh_token.clone())
        else {
            return Err(AccessError::AuthorizationNeeded(
                "no refresh token is stored".to_string(),
            ));
        };
        let metadata = self
            .metadata(&stored.issuer)
            .await
            .map_err(AccessError::Failed)?;
        let result = match refresh(&self.http, &metadata, &client, &used).await {
            Ok(set) => {
                if let Some(rotated) = set.refresh_token.clone().filter(|r| *r != used) {
                    self.store_state(oauth, |t| {
                        if t.refresh_token.as_deref() != Some(&used) {
                            return false;
                        }
                        t.refresh_token = Some(rotated.clone());
                        true
                    })
                    .await;
                }
                Ok(set)
            }
            // The grant is gone (revoked, expired): only a new authorization
            // helps.
            Err(e) if e.error.as_deref() == Some("invalid_grant") => {
                self.store_state(oauth, |t| {
                    if t.refresh_token.as_deref() != Some(&used) {
                        return false;
                    }
                    t.authorization_error = Some(e.message.clone());
                    true
                })
                .await;
                Err(AccessError::AuthorizationNeeded(e.message))
            }
            Err(e) => Err(AccessError::Failed(e.message)),
        };
        lock.commit().await.map_err(db)?;
        result
    }

    /// The stored `smtp_oauth` transport, when it is still `oauth`'s (same
    /// issuer, client and mailbox).
    async fn read_stored(
        &self,
        oauth: &SmtpOauthConfig,
    ) -> Result<Option<SmtpOauthConfig>, AccessError> {
        Ok(self
            .read_row(oauth)
            .await?
            .map(|(_, config)| match config.transport {
                TransportConfig::SmtpOauth(stored) => stored,
                _ => unreachable!("read_row returns smtp_oauth settings"),
            }))
    }

    async fn read_row(
        &self,
        oauth: &SmtpOauthConfig,
    ) -> Result<Option<(email_settings_dao::EmailSettingsRow, EmailConfig)>, AccessError> {
        let row = email_settings_dao::get(&self.pool)
            .await
            .map_err(|e| AccessError::Failed(format!("database error: {e}")))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let doc = secret_dao::email_config(&self.envelope, &row)
            .await
            .map_err(|e| AccessError::Failed(format!("the email settings cannot be read: {e}")))?;
        let config: EmailConfig = serde_json::from_value(doc)
            .map_err(|e| AccessError::Failed(format!("the email settings are malformed: {e}")))?;
        let same = matches!(
            &config.transport,
            TransportConfig::SmtpOauth(stored) if same_authorization(stored, oauth)
        );
        Ok(same.then_some((row, config)))
    }

    /// Change Forge's OAuth state in the stored settings with `change`, as
    /// long as they are still the ones `oauth` was read from (same issuer,
    /// client and mailbox) and `change` agrees. Best effort: a failure is
    /// logged.
    async fn store_state(
        &self,
        oauth: &SmtpOauthConfig,
        change: impl Fn(&mut SmtpOauthConfig) -> bool,
    ) {
        for _ in 0..3 {
            let (row, mut config) = match self.read_row(oauth).await {
                Ok(Some(found)) => found,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(error = %e, "email OAuth state not stored");
                    return;
                }
            };
            let TransportConfig::SmtpOauth(stored) = &mut config.transport else {
                return;
            };
            if !change(stored) {
                return;
            }
            let doc = match serde_json::to_value(&config) {
                Ok(doc) => doc,
                Err(e) => {
                    tracing::warn!(error = %e, "email OAuth state not stored");
                    return;
                }
            };
            match secret_dao::update_email_settings(&self.pool, &self.envelope, &row, &doc).await {
                Ok(Some(_)) => return,
                // Changed meanwhile: read it again.
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "email OAuth state not stored");
                    return;
                }
            }
        }
        tracing::warn!("email OAuth state not stored: the settings kept changing");
    }
}

/// Whether `a` and `b` are the same authorization's settings: the same
/// issuer, client and mailbox.
pub fn same_authorization(a: &SmtpOauthConfig, b: &SmtpOauthConfig) -> bool {
    a.issuer == b.issuer && a.client_id == b.client_id && a.username == b.username
}

/// The cache key of `oauth`'s access token: its issuer, client and
/// credential, mailbox, scope and grant (not the refresh token, which
/// rotates under the snapshot).
fn token_key(oauth: &SmtpOauthConfig) -> String {
    let secret = oauth
        .client_secret
        .as_deref()
        .map(|s| hex::encode(Sha256::digest(s.as_bytes())))
        .unwrap_or_default();
    format!(
        "{}\n{}\n{secret}\n{}\n{}\n{:?}",
        oauth.issuer,
        oauth.client_id.as_deref().unwrap_or(""),
        oauth.username,
        oauth.scope.as_deref().unwrap_or(""),
        oauth.grant
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_urls_follow_rfc_8414_then_oidc() {
        assert_eq!(
            metadata_urls("https://mail.example.com").unwrap(),
            [
                "https://mail.example.com/.well-known/oauth-authorization-server",
                "https://mail.example.com/.well-known/openid-configuration",
            ]
        );
        assert_eq!(
            metadata_urls("https://idp.example.com/tenant/a").unwrap(),
            [
                "https://idp.example.com/.well-known/oauth-authorization-server/tenant/a",
                "https://idp.example.com/tenant/a/.well-known/openid-configuration",
            ]
        );
    }

    #[test]
    fn registration_asks_for_the_grants_the_server_offers() {
        let mut metadata = AuthServerMetadata {
            issuer: "https://mail.example.com".into(),
            authorization_endpoint: Some("https://mail.example.com/authorize".into()),
            token_endpoint: "https://mail.example.com/token".into(),
            registration_endpoint: Some("https://mail.example.com/register".into()),
            device_authorization_endpoint: None,
            grant_types_supported: vec![],
            scopes_supported: vec![],
        };
        let request = registration_request(
            &metadata,
            "https://forge.example.com/",
            "https://forge.example.com/admin/settings/email/oauth/callback",
            None,
        );
        assert_eq!(request["client_name"], "Forge (https://forge.example.com)");
        assert_eq!(
            request["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(request["token_endpoint_auth_method"], "client_secret_basic");
        assert!(request.get("scope").is_none());

        metadata.device_authorization_endpoint = Some("https://mail.example.com/device".into());
        metadata.grant_types_supported = vec!["client_credentials".into()];
        let request = registration_request(&metadata, "https://f", "https://f/cb", Some("smtp"));
        assert_eq!(
            request["grant_types"],
            json!([
                "authorization_code",
                "refresh_token",
                DEVICE_GRANT,
                "client_credentials"
            ])
        );
        assert_eq!(request["scope"], "smtp");
    }

    #[test]
    fn pkce_matches_rfc_7636() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn oauth_errors_name_the_error_and_description() {
        assert_eq!(
            oauth_error(
                "the token request was refused",
                reqwest::StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_grant","error_description":"refresh token revoked"}"#
            ),
            "the token request was refused (400 invalid_grant): refresh token revoked"
        );
        assert_eq!(
            oauth_error("x", reqwest::StatusCode::UNAUTHORIZED, ""),
            "x (401)"
        );
    }
}
