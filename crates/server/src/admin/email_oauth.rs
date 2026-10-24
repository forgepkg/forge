//! The OAuth of the email service's `smtp_oauth` transport (#321), on
//! **Admin → Settings → Email**: Forge registers itself with the mail
//! server's authorization server, and the mailbox authorizes it once.
//!
//! * `POST /admin/settings/email/oauth/register` — discover the authorization
//!   server and register Forge as a client (RFC 7591), authenticated as the
//!   server wants: an `initial_access_token`, an account (`username` and
//!   `password`, HTTP Basic: Stalwart takes one with the right to register
//!   clients), or nothing. They are used for this request only, never
//!   stored. A registration Forge made before is deleted (RFC 7592), or named
//!   in `warning` when the server offers no way to.
//! * `DELETE /admin/settings/email/oauth/client` — forget the client and its
//!   authorization, deleting Forge's registration.
//! * `POST /admin/settings/email/oauth/authorize` — `{"method": …}`:
//!   * `authorization_code`: answers the `authorization_url` to open (PKCE,
//!     the mailbox as `login_hint`) and sets a flow cookie binding it to this
//!     browser. The authorization server sends the browser back to
//!     `GET /admin/settings/email/oauth/callback`, which stores the
//!     authorization and redirects to the settings page with
//!     `?oauth=authorized`, or `?oauth=<failure>` (and the OAuth `error`
//!     code; descriptions are only logged).
//!   * `device`: the device grant (RFC 8628). Answers the code to enter and
//!     where; the page then polls `POST
//!     /admin/settings/email/oauth/device/{id}` until it is authorized.
//!   * `client_credentials`: a token for the client itself, when the server
//!     issues those; nothing to authorize.
//!
//! The client Forge registered and the authorization are Forge's: `PUT
//! /admin/settings/email` keeps them for the same issuer and mailbox, and
//! never takes them from its body. A flow completes only for the
//! administrator who started it, and only while the settings are still the
//! ones it authorizes.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::Extension;
use chrono::Utc;
use forge_core::auth::principal::Principal;
use forge_core::auth::unique_cookie_value;
use forge_db::email_oauth_flow_dao::{self, EmailOauthFlow, FlowTarget};
use forge_db::secret_dao::{self, SecretDbError};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::db_error;
use super::email::view;
use crate::email::oauth::{
    self, AuthServerMetadata, DevicePoll, OauthClient, RegistrationAuth, TokenSet,
};
use crate::email::settings::check_oauth_url;
use crate::email::{self, OauthGrant, SmtpOauthConfig, StoredEmail, TransportConfig};
use crate::state::AppState;

/// The flow cookie on a plain-http deployment, scoped to the callback.
const FLOW_COOKIE: &str = "forge_email_oauth";

/// The flow cookie on an HTTPS deployment: `__Host-` (it cannot be planted
/// from a sibling subdomain), which requires `Path=/`.
const SECURE_FLOW_COOKIE: &str = "__Host-forge_email_oauth";

/// How long an authorization code flow may take, and its cookie live.
const CODE_FLOW_SECS: i64 = 600;

/// The longest device authorization Forge waits for.
const MAX_DEVICE_SECS: u64 = 1800;

/// Where the callback sends the browser.
const SETTINGS_PAGE: &str = "/manage/settings/email";

fn flow_cookie_name(secure: bool) -> &'static str {
    if secure {
        SECURE_FLOW_COOKIE
    } else {
        FLOW_COOKIE
    }
}

fn flow_cookie_attributes(secure: bool) -> &'static str {
    if secure {
        "Path=/; HttpOnly; SameSite=Lax; Secure"
    } else {
        "Path=/admin/settings/email/oauth; HttpOnly; SameSite=Lax"
    }
}

/// The hash of a flow cookie, as the flow row keeps it.
fn binding_hash(cookie: &str) -> String {
    hex::encode(Sha256::digest(cookie.as_bytes()))
}

fn conflict(message: impl Into<String>) -> Response {
    (StatusCode::CONFLICT, message.into()).into_response()
}

fn bad_gateway(error: impl Into<String>) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": error.into()})),
    )
        .into_response()
}

fn internal() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// The stored settings and their `smtp_oauth` transport.
async fn load_oauth(state: &AppState) -> Result<(StoredEmail, SmtpOauthConfig), Response> {
    let stored = match email::load_stored(&state.pool, &state.envelope).await {
        Ok(Some(stored)) => stored,
        Ok(None) => return Err(conflict("no email service is configured")),
        Err(e) => {
            tracing::error!(error = %e, "email settings unreadable");
            return Err(internal());
        }
    };
    if stored.secrets_unreadable {
        return Err(conflict(
            "the stored email secrets do not decrypt; save the settings again",
        ));
    }
    let TransportConfig::SmtpOauth(oauth) = &stored.config.transport else {
        return Err(conflict(
            "the email transport is not SMTP with OAuth: save it as smtp_oauth first",
        ));
    };
    let oauth = oauth.clone();
    Ok((stored, oauth))
}

/// The authorization server of `oauth`, or the 502 that says why not.
async fn metadata(
    state: &AppState,
    oauth: &SmtpOauthConfig,
) -> Result<AuthServerMetadata, Response> {
    state
        .mailer
        .oauth()
        .metadata(&oauth.issuer)
        .await
        .map_err(bad_gateway)
}

/// Why Forge's OAuth state was not stored.
enum StoreError {
    /// The settings are no longer the ones it was for.
    Changed,
    /// The database or the encryption failed (logged).
    Failed,
}

impl StoreError {
    fn response(&self) -> Response {
        match self {
            StoreError::Changed => conflict("the email settings changed meanwhile; try again"),
            StoreError::Failed => internal(),
        }
    }
}

/// Apply `change` to the stored `smtp_oauth` transport while it is still the
/// one of `expected` (same issuer, client and mailbox), reading it again
/// after a concurrent write. Drops this instance's snapshot.
async fn update_oauth(
    state: &AppState,
    expected: &SmtpOauthConfig,
    change: impl Fn(&mut SmtpOauthConfig),
) -> Result<StoredEmail, StoreError> {
    for _ in 0..3 {
        let stored = match email::load_stored(&state.pool, &state.envelope).await {
            Ok(Some(stored)) if !stored.secrets_unreadable => stored,
            Ok(_) => return Err(StoreError::Changed),
            Err(e) => {
                tracing::error!(error = %e, "email settings unreadable");
                return Err(StoreError::Failed);
            }
        };
        let mut config = stored.config.clone();
        let TransportConfig::SmtpOauth(current) = &mut config.transport else {
            return Err(StoreError::Changed);
        };
        if !oauth::same_authorization(current, expected) {
            return Err(StoreError::Changed);
        }
        change(current);
        let doc = serde_json::to_value(&config).map_err(|e| {
            tracing::error!(error = %e, "email settings did not serialize");
            StoreError::Failed
        })?;
        match secret_dao::update_email_settings(&state.pool, &state.envelope, &stored.row, &doc)
            .await
        {
            Ok(Some(row)) => {
                state.mailer.invalidate().await;
                return Ok(StoredEmail {
                    row,
                    config,
                    secrets_unreadable: false,
                });
            }
            Ok(None) => continue,
            Err(SecretDbError::Db(e)) => {
                tracing::error!(error = %e, "email OAuth state not stored");
                return Err(StoreError::Failed);
            }
            Err(e) => {
                tracing::error!(error = %e, "email settings secret encryption failed");
                return Err(StoreError::Failed);
            }
        }
    }
    Err(StoreError::Changed)
}

/// Forget the authorization (a new client needs its own).
fn clear_authorization(oauth: &mut SmtpOauthConfig) {
    oauth.grant = None;
    oauth.refresh_token = None;
    oauth.authorization_error = None;
}

/// Delete Forge's registration of `oauth` at the authorization server (RFC
/// 7592), when it made one. Returns why that failed, or that the server
/// offers no way to: the client then stays registered there, for the
/// server's administrator to remove.
pub(super) async fn release_registration(
    state: &AppState,
    oauth: &SmtpOauthConfig,
) -> Option<String> {
    let (Some(uri), Some(token)) = (
        &oauth.registration_client_uri,
        &oauth.registration_access_token,
    ) else {
        return oauth.registered.then(|| {
            format!(
                "the authorization server offers no way to delete Forge's client {} \
                 (RFC 7592): remove it there",
                oauth.client_id.as_deref().unwrap_or_default()
            )
        });
    };
    match oauth::delete_registration(state.mailer.oauth().http(), uri, token).await {
        Ok(()) => {
            tracing::info!(issuer = %oauth.issuer, "Forge's email OAuth registration deleted");
            None
        }
        Err(e) => {
            tracing::warn!(issuer = %oauth.issuer, error = %e, "Forge's email OAuth registration not deleted");
            Some(e)
        }
    }
}

/// Drop the flows in progress (the settings they authorize changed).
pub(super) async fn drop_flows(state: &AppState) {
    if let Err(e) = email_oauth_flow_dao::delete_all(&state.pool).await {
        tracing::warn!(error = %e, "email OAuth flows not deleted");
    }
}

/// `POST /admin/settings/email/oauth/register` body: how the registration
/// is authenticated, when the server wants it to be.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterBody {
    /// The authorization server's initial access token (RFC 7591 §3).
    #[serde(default)]
    pub initial_access_token: Option<String>,
    /// An account allowed to register clients, sent with HTTP Basic.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// `POST /admin/settings/email/oauth/register`
pub async fn register(State(state): State<AppState>, body: Option<Json<RegisterBody>>) -> Response {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let (_, oauth) = match load_oauth(&state).await {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    let metadata = match metadata(&state, &oauth).await {
        Ok(metadata) => metadata,
        Err(resp) => return resp,
    };
    if metadata.registration_endpoint.is_none() {
        return conflict(
            "the authorization server offers no client registration (RFC 7591): register a \
             client for Forge there and enter its client id and secret",
        );
    }
    let request = oauth::registration_request(
        &metadata,
        state.mailer.public_base_url(),
        &state.mailer.oauth_redirect_uri(),
        oauth.scope.as_deref(),
    );
    let blank_to_none = |v: &Option<String>| v.clone().filter(|v| !v.trim().is_empty());
    let initial_access_token = blank_to_none(&body.initial_access_token);
    let username = blank_to_none(&body.username);
    let password = body.password.clone().filter(|p| !p.is_empty());
    let auth = match (&initial_access_token, &username, &password) {
        (None, None, None) => RegistrationAuth::None,
        (Some(token), None, None) => RegistrationAuth::Bearer(token.trim()),
        (None, Some(username), Some(password)) => {
            RegistrationAuth::Basic(username.trim(), password)
        }
        (None, _, _) => {
            return (
                StatusCode::BAD_REQUEST,
                "an account to register with needs both username and password",
            )
                .into_response()
        }
        (Some(_), _, _) => {
            return (
                StatusCode::BAD_REQUEST,
                "authenticate the registration with an initial access token or an account, \
                 not both",
            )
                .into_response()
        }
    };
    let registration =
        match oauth::register(state.mailer.oauth().http(), &metadata, &request, auth).await {
            Ok(registration) => registration,
            Err(e) => return bad_gateway(e),
        };
    let new = registration.clone();
    let stored = update_oauth(&state, &oauth, move |t| {
        t.client_id = Some(new.client_id.clone());
        t.client_secret = new.client_secret.clone();
        t.registered = true;
        t.registration_client_uri = new.registration_client_uri.clone();
        t.registration_access_token = new.registration_access_token.clone();
        clear_authorization(t);
    })
    .await;
    match stored {
        Ok(stored) => {
            // The client registered before, if Forge made it, goes.
            let warning = if oauth.registered && oauth.client_id.is_some() {
                release_registration(&state, &oauth).await
            } else {
                None
            };
            drop_flows(&state).await;
            tracing::info!(
                issuer = %oauth.issuer,
                client_id = %registration.client_id,
                "Forge registered with the email authorization server"
            );
            let mut doc = view(&stored, &state.mailer);
            doc["warning"] = json!(warning);
            Json(doc).into_response()
        }
        Err(e) => {
            // Not kept: the registration just made goes again.
            let made = SmtpOauthConfig {
                client_id: Some(registration.client_id),
                registered: true,
                registration_client_uri: registration.registration_client_uri,
                registration_access_token: registration.registration_access_token,
                ..oauth
            };
            release_registration(&state, &made).await;
            e.response()
        }
    }
}

/// `DELETE /admin/settings/email/oauth/client`
pub async fn forget_client(State(state): State<AppState>) -> Response {
    let (_, oauth) = match load_oauth(&state).await {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    let stored = update_oauth(&state, &oauth, |t| {
        t.client_id = None;
        t.client_secret = None;
        t.registered = false;
        t.registration_client_uri = None;
        t.registration_access_token = None;
        clear_authorization(t);
    })
    .await;
    match stored {
        Ok(stored) => {
            let warning = release_registration(&state, &oauth).await;
            drop_flows(&state).await;
            let mut doc = view(&stored, &state.mailer);
            doc["warning"] = json!(warning);
            Json(doc).into_response()
        }
        Err(e) => e.response(),
    }
}

/// How the mailbox authorizes Forge.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizeMethod {
    /// In this browser, by the authorization code flow with PKCE.
    AuthorizationCode,
    /// With a code entered on another device (RFC 8628).
    Device,
    /// No mailbox: the client credentials grant.
    ClientCredentials,
}

/// `POST /admin/settings/email/oauth/authorize` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeBody {
    pub method: AuthorizeMethod,
}

/// `POST /admin/settings/email/oauth/authorize`
pub async fn authorize(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<AuthorizeBody>,
) -> Response {
    let Principal::User { user_id, .. } = principal else {
        return (
            StatusCode::FORBIDDEN,
            "authorizing the email service takes an administrator's sign-in",
        )
            .into_response();
    };
    let (_, oauth) = match load_oauth(&state).await {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    let Some(client) = OauthClient::of(&oauth) else {
        return conflict("Forge has no OAuth client yet: register it, or enter a client");
    };
    let metadata = match metadata(&state, &oauth).await {
        Ok(metadata) => metadata,
        Err(resp) => return resp,
    };
    let target = FlowTarget {
        user_id,
        issuer: oauth.issuer.clone(),
        client_id: client.client_id.clone(),
        username: oauth.username.clone(),
    };
    let http = state.mailer.oauth().http();
    let scope = oauth.scope.as_deref();
    match body.method {
        AuthorizeMethod::AuthorizationCode => {
            let flow_state = oauth::random_token();
            let verifier = oauth::random_token();
            let binding = oauth::random_token();
            let url = match oauth::authorization_url(
                &metadata,
                &client.client_id,
                &state.mailer.oauth_redirect_uri(),
                &flow_state,
                &oauth::pkce_challenge(&verifier),
                scope,
                &oauth.username,
            ) {
                Ok(url) => url,
                Err(e) => return conflict(e),
            };
            if let Err(e) = email_oauth_flow_dao::begin_code(
                &state.pool,
                &target,
                &flow_state,
                &binding_hash(&binding),
                &verifier,
                Utc::now() + chrono::Duration::seconds(CODE_FLOW_SECS),
            )
            .await
            {
                return db_error(e);
            }
            let cookie = format!(
                "{}={binding}; {}; Max-Age={CODE_FLOW_SECS}",
                flow_cookie_name(state.cookie_secure),
                flow_cookie_attributes(state.cookie_secure),
            );
            (
                [(header::SET_COOKIE, cookie)],
                Json(json!({"authorization_url": url})),
            )
                .into_response()
        }
        AuthorizeMethod::Device => {
            let start = match oauth::start_device(http, &metadata, &client, scope).await {
                Ok(start) => start,
                Err(e) => return bad_gateway(e),
            };
            // Shown as links: web URLs only.
            if let Err(e) = check_oauth_url("verification_uri", &start.verification_uri) {
                return bad_gateway(format!("the device authorization's {e}"));
            }
            let complete = start
                .verification_uri_complete
                .filter(|u| check_oauth_url("verification_uri_complete", u).is_ok());
            let interval = start.interval.unwrap_or(5).clamp(1, 60);
            let lifetime = start.expires_in.clamp(1, MAX_DEVICE_SECS);
            let flow = match email_oauth_flow_dao::begin_device(
                &state.pool,
                &target,
                &start.device_code,
                interval as i32,
                Utc::now() + chrono::Duration::seconds(lifetime as i64),
            )
            .await
            {
                Ok(flow) => flow,
                Err(e) => return db_error(e),
            };
            Json(json!({
                "flow_id": flow.id,
                "user_code": start.user_code,
                "verification_uri": start.verification_uri,
                "verification_uri_complete": complete,
                "expires_in": lifetime,
                "interval": interval,
            }))
            .into_response()
        }
        AuthorizeMethod::ClientCredentials => {
            if let Err(e) = oauth::client_credentials(http, &metadata, &client, scope).await {
                return bad_gateway(e.message);
            }
            match update_oauth(&state, &oauth, |t| {
                clear_authorization(t);
                t.grant = Some(OauthGrant::ClientCredentials);
            })
            .await
            {
                Ok(stored) => {
                    tracing::info!(issuer = %oauth.issuer, "email OAuth uses the client credentials grant");
                    Json(json!({"settings": view(&stored, &state.mailer)})).into_response()
                }
                Err(e) => e.response(),
            }
        }
    }
}

/// Whether `flow` authorizes `oauth`.
fn flow_matches(flow: &EmailOauthFlow, oauth: &SmtpOauthConfig) -> bool {
    flow.issuer == oauth.issuer
        && Some(&flow.client_id) == oauth.client_id.as_ref()
        && flow.username == oauth.username
}

/// Store the authorization `tokens` gave for `oauth`.
async fn store_authorization(
    state: &AppState,
    oauth: &SmtpOauthConfig,
    tokens: TokenSet,
) -> Result<StoredEmail, Failure> {
    let Some(refresh_token) = tokens.refresh_token else {
        return Err(Failure::NoRefreshToken);
    };
    let stored = update_oauth(state, oauth, |t| {
        clear_authorization(t);
        t.grant = Some(OauthGrant::RefreshToken);
        t.refresh_token = Some(refresh_token.clone());
    })
    .await
    .map_err(|e| match e {
        StoreError::Changed => Failure::Changed,
        StoreError::Failed => Failure::Unavailable,
    })?;
    tracing::info!(issuer = %oauth.issuer, "the email mailbox authorized Forge");
    Ok(stored)
}

/// Why an authorization did not complete, as the settings page names it.
#[derive(Debug)]
enum Failure {
    /// Unknown, expired or used state.
    Expired,
    /// Another administrator's or another browser's flow.
    OtherSession,
    /// The authorization server refused (the mailbox declined): its `error`.
    Refused(Option<String>),
    /// The answer names another issuer than the flow's (RFC 9207).
    WrongIssuer,
    /// The settings changed while it ran.
    Changed,
    /// No refresh token came: Forge could not send after the access token
    /// expires.
    NoRefreshToken,
    /// The code exchange or the poll failed: the token endpoint's `error`,
    /// and the text logged.
    TokenFailed(Option<String>, String),
    /// The settings could not be read or written.
    Unavailable,
}

impl Failure {
    fn code(&self) -> &'static str {
        match self {
            Failure::Expired => "expired",
            Failure::OtherSession => "other_session",
            Failure::Refused(_) => "refused",
            Failure::WrongIssuer => "wrong_issuer",
            Failure::Changed => "changed",
            Failure::NoRefreshToken => "no_refresh_token",
            Failure::TokenFailed(..) => "token_failed",
            Failure::Unavailable => "unavailable",
        }
    }

    /// The OAuth error code, when it is one (RFC 6749 §5.2: `%x20-21 /
    /// %x23-5B / %x5D-7E`, kept to `[a-z0-9_]` here).
    fn error(&self) -> Option<&str> {
        let error = match self {
            Failure::Refused(e) | Failure::TokenFailed(e, _) => e.as_deref()?,
            _ => return None,
        };
        (error.len() <= 64
            && error
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
        .then_some(error)
    }

    /// The text for the device flow's page and the log.
    fn message(&self) -> String {
        match self {
            Failure::Expired => "the authorization expired; start it again".into(),
            Failure::OtherSession => {
                "the authorization was started by another sign-in or browser; start it again".into()
            }
            Failure::Refused(e) => format!(
                "the authorization server refused{}",
                e.as_deref().map(|e| format!(" ({e})")).unwrap_or_default()
            ),
            Failure::WrongIssuer => {
                "the answer came from another authorization server than the settings name".into()
            }
            Failure::Changed => {
                "the email settings changed during the authorization; start it again".into()
            }
            Failure::NoRefreshToken => "the authorization server issued no refresh token: \
                 allow Forge's client the refresh_token grant (some servers want the \
                 offline_access scope)"
                .into(),
            Failure::TokenFailed(_, text) => text.clone(),
            Failure::Unavailable => "the authorization could not be stored".into(),
        }
    }
}

/// `GET /admin/settings/email/oauth/callback` query.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
    /// The issuer, from a server that says (RFC 9207).
    #[serde(default)]
    pub iss: Option<String>,
}

/// `GET /admin/settings/email/oauth/callback`: complete the authorization
/// code flow and send the browser back to the settings page. The flow cookie
/// is cleared whatever the outcome.
pub async fn callback(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    // A duplicated cookie is ambiguous (one may be planted): no binding.
    let cookie = unique_cookie_value(&headers, flow_cookie_name(state.cookie_secure))
        .ok()
        .flatten()
        .filter(|v| !v.is_empty());
    let outcome = callback_inner(&state, &principal, cookie.as_deref(), query).await;
    // Built after the await: the serializer is not `Send`.
    let mut location = url::form_urlencoded::Serializer::new(String::new());
    match outcome {
        Ok(()) => {
            location.append_pair("oauth", "authorized");
        }
        Err(failure) => {
            tracing::warn!(
                failure = failure.code(),
                error = %failure.message(),
                "email OAuth authorization did not complete"
            );
            location.append_pair("oauth", failure.code());
            if let Some(error) = failure.error() {
                location.append_pair("error", error);
            }
        }
    }
    let mut resp = (
        StatusCode::FOUND,
        [(
            header::LOCATION,
            format!("{SETTINGS_PAGE}?{}", location.finish()),
        )],
    )
        .into_response();
    if cookie.is_some() {
        let clear = format!(
            "{}=; {}; Max-Age=0",
            flow_cookie_name(state.cookie_secure),
            flow_cookie_attributes(state.cookie_secure),
        );
        if let Ok(v) = clear.parse() {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

async fn callback_inner(
    state: &AppState,
    principal: &Principal,
    cookie: Option<&str>,
    query: CallbackQuery,
) -> Result<(), Failure> {
    let flow_state = query
        .state
        .filter(|s| !s.is_empty())
        .ok_or(Failure::Expired)?;
    let flow = email_oauth_flow_dao::take_code(&state.pool, &flow_state)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "email OAuth flow unreadable");
            Failure::Unavailable
        })?
        .ok_or(Failure::Expired)?;
    let same_user =
        matches!(principal, Principal::User { user_id, .. } if *user_id == flow.user_id);
    let same_browser = match (cookie, flow.browser_binding.as_deref()) {
        (Some(cookie), Some(binding)) => {
            bool::from(binding_hash(cookie).as_bytes().ct_eq(binding.as_bytes()))
        }
        _ => false,
    };
    if !same_user || !same_browser {
        return Err(Failure::OtherSession);
    }
    // An answer from another authorization server than the flow's (a mix-up,
    // RFC 9207) is not taken.
    if let Some(iss) = &query.iss {
        if iss.trim_end_matches('/') != flow.issuer.trim_end_matches('/') {
            return Err(Failure::WrongIssuer);
        }
    }
    if let Some(error) = query.error {
        if let Some(description) = &query.error_description {
            tracing::info!(%error, description = %description.chars().take(512).collect::<String>(), "the email authorization server refused");
        }
        return Err(Failure::Refused(Some(error)));
    }
    let code = query
        .code
        .filter(|c| !c.is_empty())
        .ok_or(Failure::Refused(None))?;
    let (_, oauth) = load_oauth(state).await.map_err(|_| Failure::Changed)?;
    if !flow_matches(&flow, &oauth) {
        return Err(Failure::Changed);
    }
    let client = OauthClient::of(&oauth).ok_or(Failure::Changed)?;
    let metadata = state
        .mailer
        .oauth()
        .metadata(&oauth.issuer)
        .await
        .map_err(|e| Failure::TokenFailed(None, e))?;
    let tokens = oauth::exchange_code(
        state.mailer.oauth().http(),
        &metadata,
        &client,
        &code,
        flow.pkce_verifier.as_deref().unwrap_or_default(),
        &state.mailer.oauth_redirect_uri(),
    )
    .await
    .map_err(|e| Failure::TokenFailed(e.error, e.message))?;
    store_authorization(state, &oauth, tokens).await?;
    Ok(())
}

/// `POST /admin/settings/email/oauth/device/{id}`: poll a device
/// authorization. Answers `{"status": "pending"}`, `{"status":
/// "authorized", "settings": …}` or `{"status": "failed", "error": …}`.
pub async fn poll_device(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    let Principal::User { user_id, .. } = principal else {
        return (StatusCode::NOT_FOUND, "no such authorization").into_response();
    };
    let pending = || Json(json!({"status": "pending"})).into_response();
    let failed = |failure: Failure| {
        tracing::warn!(failure = failure.code(), error = %failure.message(), "email OAuth device authorization did not complete");
        Json(json!({"status": "failed", "failure": failure.code(), "error": failure.message()}))
            .into_response()
    };
    let flow = match email_oauth_flow_dao::claim_device_poll(&state.pool, id, user_id).await {
        Ok(flow) => flow,
        Err(e) => return db_error(e),
    };
    let Some(flow) = flow else {
        // Not due yet, or gone.
        return match email_oauth_flow_dao::get_device(&state.pool, id, user_id).await {
            Ok(Some(flow)) if flow.expires_at > Utc::now() => pending(),
            Ok(Some(flow)) => {
                let _ = email_oauth_flow_dao::delete(&state.pool, flow.id).await;
                failed(Failure::Expired)
            }
            Ok(None) => (StatusCode::NOT_FOUND, "no such authorization").into_response(),
            Err(e) => db_error(e),
        };
    };
    let finish = || async {
        if let Err(e) = email_oauth_flow_dao::delete(&state.pool, flow.id).await {
            tracing::warn!(error = %e, "email OAuth flow not deleted");
        }
    };
    let oauth = match load_oauth(&state).await {
        Ok((_, oauth)) if flow_matches(&flow, &oauth) => oauth,
        _ => {
            finish().await;
            return failed(Failure::Changed);
        }
    };
    let Some(client) = OauthClient::of(&oauth) else {
        finish().await;
        return failed(Failure::Changed);
    };
    let metadata = match state.mailer.oauth().metadata(&oauth.issuer).await {
        Ok(metadata) => metadata,
        // Unreachable for now: poll again later.
        Err(e) => return failed_soft(e),
    };
    match oauth::poll_device(
        state.mailer.oauth().http(),
        &metadata,
        &client,
        flow.device_code.as_deref().unwrap_or_default(),
    )
    .await
    {
        DevicePoll::Pending => pending(),
        DevicePoll::SlowDown => {
            if let Err(e) = email_oauth_flow_dao::slow_down(&state.pool, flow.id).await {
                tracing::warn!(error = %e, "email OAuth flow not slowed down");
            }
            pending()
        }
        DevicePoll::Done(tokens) => {
            finish().await;
            match store_authorization(&state, &oauth, tokens).await {
                Ok(stored) => Json(json!({
                    "status": "authorized",
                    "settings": view(&stored, &state.mailer),
                }))
                .into_response(),
                Err(failure) => failed(failure),
            }
        }
        DevicePoll::Failed(error, text) => {
            finish().await;
            failed(match error.as_deref() {
                Some("access_denied") => Failure::Refused(error),
                Some("expired_token") => Failure::Expired,
                _ => Failure::TokenFailed(error, text),
            })
        }
    }
}

/// A poll that could not reach the authorization server: still pending, with
/// why.
fn failed_soft(error: String) -> Response {
    tracing::warn!(%error, "email OAuth device poll did not reach the authorization server");
    Json(json!({"status": "pending", "error": error})).into_response()
}
