//! The device authorization grant (RFC 8628, #649): how a command-line
//! client signs in through the browser. Forge's helpers use it: `forge
//! login`, `docker-credential-forge` and `nuget-plugin-forge` (the Docker CLI
//! has no browser login for a registry other than Docker Hub, so for Docker
//! it is the only way to an OIDC or Entra sign-in).
//!
//! * `POST /auth/device/code` (RFC 8628 §3.1–3.2) takes a `client_id` and an
//!   optional `scope` and answers a `device_code`, the `user_code` the user
//!   types on the web UI's `/device` page (also linked with the code filled
//!   in, `verification_uri_complete`), `expires_in` and `interval`.
//! * `POST /auth/device/token` (§3.4–3.5), with `grant_type
//!   urn:ietf:params:oauth:grant-type:device_code`, answers
//!   `authorization_pending` until the user decides, `slow_down` (and five
//!   more seconds of interval) when polled sooner than the interval,
//!   `access_denied`, `expired_token`, or, once, the token. Errors are RFC
//!   6749 §5.2 JSON.
//! * `GET /.well-known/oauth-authorization-server` (RFC 8414) names both
//!   endpoints, so a client finds everything from the server URL alone.
//! * `POST /auth/device/lookup` and `/auth/device/decide` serve the `/device`
//!   page: a signed-in user's browser session looks a code up, sees which
//!   client asks for what, from where and since when, and approves or denies
//!   it. A code filled in from a link is never approved without that click
//!   (§5.4, remote phishing). The page signs in through the whole realm
//!   chain like every page of the web UI.
//!
//! Forge has no client registration: only its helpers' fixed client ids are
//! accepted ([`CLIENTS`]), so the page names the client truthfully; any other
//! is `invalid_client`. No refresh token is issued: the token minted is a
//! long-lived API token of the approving user, as the npm web login's
//! ([`crate::cli_auth`]), lasting `cli_login.token_lifetime_days`, named
//! after the client and the host and listed and revocable on the user's
//! tokens page. A `scope` narrows it ([`DeviceScope`]); without one it
//! carries the user's rights.
//!
//! The device code is a 256-bit secret of which only the SHA-256 is stored.
//! The user code is eight letters of an alphabet without vowels or
//! look-alikes (§6.1), typed in any case, with or without its hyphen. Code
//! entry is limited per client network and per browser session
//! ([`AppState::device_code_throttle`]: ten wrong codes per five minutes,
//! counted by each instance), so a pending code cannot be guessed within its
//! lifetime, `cli_login.web_login_ttl_seconds`. Requests, decisions and
//! mints are audit-logged (`forge::audit`). The auth settings switch the
//! device login off and set the polling interval (**Admin → Settings**).

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::{DateTime, Utc};
use forge_core::auth::token::{generate_token_secret, hash_token};
use forge_core::auth::{AttemptRefused, LoginAttempt, LoginThrottle};
use forge_core::authz::{Level, TokenScope};
use forge_db::device_auth_dao::{
    self, DeviceAuthorization, NewDeviceAuthorization, PollState, PolledRequest,
};
use forge_db::{repository_dao, token_dao, user_dao};
use serde::{Deserialize, Serialize};

use super::{login_client_ip, require_session_csrf, ActiveSession, SessionAuthCtx};
use crate::middleware::principal::auth_unavailable;
use crate::state::AppState;

/// The device authorization endpoint (RFC 8628 §3.1).
pub const DEVICE_CODE_PATH: &str = "/auth/device/code";

/// The token endpoint of the device grant (RFC 8628 §3.4).
pub const DEVICE_TOKEN_PATH: &str = "/auth/device/token";

/// The authorization server metadata (RFC 8414 §3).
pub const AUTHORIZATION_SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

/// The `/device` page's lookup of a code.
const LOOKUP_PATH: &str = "/auth/device/lookup";

/// The `/device` page's approval or denial.
const DECIDE_PATH: &str = "/auth/device/decide";

/// The web UI page the user enters the code on (`verification_uri`).
pub const VERIFICATION_PATH: &str = "/device";

/// The `grant_type` of the device grant.
pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The clients that may ask, by their fixed client ids, with the name the
/// `/device` page shows: Forge's own helpers.
pub const CLIENTS: [(&str, &str); 3] = [
    ("forge-cli", "Forge CLI"),
    ("docker-credential-forge", "Docker credential helper"),
    ("nuget-plugin-forge", "NuGet credential provider"),
];

/// The user code's alphabet: consonants only, so no word and no look-alike
/// (RFC 8628 §6.1): 20^8, about 2.6 * 10^10 codes.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Letters in a user code (shown `BCDF-GHJK`).
const USER_CODE_LEN: usize = 8;

/// How much `slow_down` raises a request's interval (RFC 8628 §3.5).
const SLOW_DOWN_STEP_SECONDS: i32 = 5;

/// The interval `slow_down` raises a request's to at most.
const MAX_INTERVAL_SECONDS: i32 = 3600;

/// The largest request body of these endpoints (a form or a JSON object of
/// a few short fields).
const MAX_BODY_BYTES: usize = 8 * 1024;

/// The longest `scope` accepted.
const MAX_SCOPE_BYTES: usize = 1024;

/// The most repositories a `scope` names.
const MAX_SCOPE_REPOSITORIES: usize = 32;

/// The longest repository name (the admin API's rule).
const MAX_REPOSITORY_NAME: usize = 64;

/// How many user codes are drawn before giving up (each collides with a
/// stored one with a chance of a few in a billion).
const USER_CODE_DRAWS: usize = 5;

/// The key a client network's wrong codes are counted under.
const CODE_ENTRY_NETWORK_KEY: &str = "\u{0}device-code";

/// The address a session's wrong codes are counted under, wherever they
/// come from: the session is the key.
const CODE_ENTRY_SESSION_IP: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// The routes of the device grant.
pub(super) fn device_router() -> Router<AppState> {
    Router::new()
        .route(DEVICE_CODE_PATH, post(device_authorization))
        .route(DEVICE_TOKEN_PATH, post(device_token))
        .route(LOOKUP_PATH, post(lookup))
        .route(DECIDE_PATH, post(decide))
        .route(AUTHORIZATION_SERVER_METADATA_PATH, get(metadata))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// The name the `/device` page shows for `client_id`, `None` for a client
/// Forge does not know.
pub fn client_name(client_id: &str) -> Option<&'static str> {
    CLIENTS
        .iter()
        .find(|(id, _)| *id == client_id)
        .map(|(_, name)| *name)
}

// ── codes ───────────────────────────────────────────────────────────────────

/// A fresh user code (normalized: eight letters, no hyphen).
fn generate_user_code() -> String {
    (0..USER_CODE_LEN)
        .map(|_| USER_CODE_ALPHABET[rand::random_range(0..USER_CODE_ALPHABET.len())] as char)
        .collect()
}

/// `raw` as a stored user code: in any case, with or without the hyphen and
/// surrounding spaces. `None` when it cannot be one.
pub fn normalize_user_code(raw: &str) -> Option<String> {
    let code: String = raw
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == USER_CODE_LEN && code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
        .then_some(code)
}

/// A normalized user code as it is shown and typed: `BCDF-GHJK`.
pub fn display_user_code(code: &str) -> String {
    match (code.get(..4), code.get(4..)) {
        (Some(head), Some(tail)) if !tail.is_empty() => format!("{head}-{tail}"),
        _ => code.to_string(),
    }
}

// ── scope ───────────────────────────────────────────────────────────────────

/// What a device login's `scope` asks for, mapped onto the token scope
/// ([`TokenScope`]): space-separated `read`, `write` or `delete` (the
/// token's level; the highest one named wins) and `repository:<name>` (the
/// repositories it reaches, by name). Without a level the token keeps its
/// owner's levels; without a repository it reaches every one its owner may.
/// An empty scope is none: the token carries the user's rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceScope {
    /// The level, `None`: the owner's.
    pub level: Option<Level>,
    /// The repositories, sorted; empty: every one the owner may reach.
    pub repositories: Vec<String>,
}

impl DeviceScope {
    /// Parse a `scope` parameter; `Ok(None)` for an empty one. The error is
    /// the `error_description` of `invalid_scope` (it never echoes the
    /// value).
    pub fn parse(raw: &str) -> Result<Option<Self>, &'static str> {
        if raw.len() > MAX_SCOPE_BYTES {
            return Err("the scope is too long");
        }
        let mut level: Option<Level> = None;
        let mut repositories = BTreeSet::new();
        // RFC 6749 §3.3: scope tokens are delimited by spaces.
        for item in raw.split(' ').filter(|item| !item.is_empty()) {
            if let Some(named) = Level::parse(item) {
                level = level.max(Some(named));
            } else if let Some(name) = item.strip_prefix("repository:") {
                if !is_repository_name(name) {
                    return Err("a repository scope names no valid repository name");
                }
                repositories.insert(name.to_string());
            } else {
                return Err(
                    "unknown scope value: expected read, write, delete or repository:<name>",
                );
            }
        }
        if repositories.len() > MAX_SCOPE_REPOSITORIES {
            return Err("the scope names too many repositories (at most 32)");
        }
        if level.is_none() && repositories.is_empty() {
            return Ok(None);
        }
        Ok(Some(DeviceScope {
            level,
            repositories: repositories.into_iter().collect(),
        }))
    }

    /// The token scope: the repositories by id. A name no repository has
    /// reaches nothing (a scope only ever narrows).
    async fn token_scope(&self, state: &AppState) -> sqlx::Result<TokenScope> {
        let repositories = if self.repositories.is_empty() {
            None
        } else {
            let mut ids = Vec::with_capacity(self.repositories.len());
            for name in &self.repositories {
                match repository_dao::find_repository_by_name(&state.pool, name).await? {
                    Some(repo) => ids.push(repo.id),
                    None => tracing::info!(
                        repository = %name,
                        "device login: the scope names a repository that does not exist"
                    ),
                }
            }
            Some(ids)
        };
        Ok(TokenScope {
            level: self.level,
            admin: false,
            repositories,
        })
    }
}

/// The normalized form, which [`DeviceScope::parse`] reads back: the level
/// first, then the repositories.
impl fmt::Display for DeviceScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut items: Vec<String> = Vec::new();
        if let Some(level) = self.level {
            items.push(level.as_str().to_string());
        }
        items.extend(self.repositories.iter().map(|r| format!("repository:{r}")));
        f.write_str(&items.join(" "))
    }
}

/// Whether `name` can be a repository's name (the admin API's rule:
/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).
fn is_repository_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= MAX_REPOSITORY_NAME
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

// ── OAuth answers ───────────────────────────────────────────────────────────

/// An RFC 6749 §5.2 error: JSON, never stored by a cache.
fn oauth_error(status: StatusCode, error: &'static str, description: &'static str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({"error": error, "error_description": description})),
    )
        .into_response()
}

/// A `400` with `error`.
fn bad_request(error: &'static str, description: &'static str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, error, description)
}

/// Forge could not answer (its database failed): `503`, try again.
fn oauth_unavailable(e: &sqlx::Error) -> Response {
    forge_db::observe_error(e);
    tracing::error!(error = %e, "device login failed");
    let mut resp = oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "the server cannot answer now; try again",
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, header::HeaderValue::from_static("30"));
    resp
}

/// A JSON answer that no cache keeps (RFC 6749 §5.1).
fn no_store<T: Serialize>(body: T) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

/// The parameters of a form-encoded OAuth request (RFC 6749 §3.2): each at
/// most once, and one sent without a value as if it were left out.
fn form_params(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<HashMap<String, String>, Response> {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| {
            mime.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return Err(bad_request(
            "invalid_request",
            "send the parameters as application/x-www-form-urlencoded",
        ));
    }
    let body =
        body.map_err(|_| bad_request("invalid_request", "the request body is unreadable"))?;
    let mut params = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        if value.is_empty() {
            continue;
        }
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(bad_request("invalid_request", "a parameter is repeated"));
        }
    }
    Ok(params)
}

/// The request's `client_id`, one of [`CLIENTS`].
fn client_of(params: &HashMap<String, String>) -> Result<&'static str, Response> {
    let Some(client_id) = params.get("client_id") else {
        return Err(bad_request("invalid_request", "client_id is required"));
    };
    CLIENTS
        .iter()
        .map(|(id, _)| *id)
        .find(|id| id == client_id)
        .ok_or_else(|| {
            bad_request(
                "invalid_client",
                "unknown client_id: Forge accepts forge-cli, docker-credential-forge and \
                 nuget-plugin-forge",
            )
        })
}

/// The device login is switched off (**Admin → Settings**).
fn turned_off() -> Response {
    bad_request(
        "unauthorized_client",
        "the device login is turned off on this server",
    )
}

// ── POST /auth/device/code ──────────────────────────────────────────────────

/// The device authorization response (RFC 8628 §3.2).
#[derive(Debug, Serialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

/// `POST /auth/device/code` — start a device login.
async fn device_authorization(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let params = match form_params(&headers, body) {
        Ok(params) => params,
        Err(resp) => return resp,
    };
    let settings = state.auth_settings.current().await;
    if !settings.settings.device_login {
        return turned_off();
    }
    let client_id = match client_of(&params) {
        Ok(client_id) => client_id,
        Err(resp) => return resp,
    };
    let scope = match params.get("scope").map(|raw| DeviceScope::parse(raw)) {
        None => None,
        Some(Ok(scope)) => scope,
        Some(Err(why)) => return bad_request("invalid_scope", why),
    };
    // Starting a login is free for anyone and stores a row: bounded per
    // client network, as OIDC and npm web logins are.
    let client_ip = login_client_ip(&state, connect.map(|Extension(ci)| ci.0), &headers);
    if !state.oidc_login_starts.allow(client_ip) {
        let mut resp = oauth_error(
            StatusCode::TOO_MANY_REQUESTS,
            "slow_down",
            "too many logins started from this network; try again later",
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
        return resp;
    }

    let interval = settings.settings.device_poll_interval_seconds;
    let ttl = state.config.cli_login.web_login_ttl_seconds;
    let device_code = generate_token_secret();
    let device_code_hash = hash_token(&device_code);
    let scope = scope.map(|scope| scope.to_string());
    let client_ip = client_ip.to_string();
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
    for _ in 0..USER_CODE_DRAWS {
        let user_code = generate_user_code();
        let inserted = device_auth_dao::insert(
            &state.pool,
            NewDeviceAuthorization {
                device_code_hash: &device_code_hash,
                user_code: &user_code,
                client_id,
                scope: scope.as_deref(),
                client_ip: Some(&client_ip),
                interval_seconds: interval as i32,
                expires_at,
            },
        )
        .await;
        let id = match inserted {
            Ok(Some(id)) => id,
            // Another request holds the code: draw again.
            Ok(None) => continue,
            Err(e) => return oauth_unavailable(&e),
        };
        tracing::info!(
            target: "forge::audit",
            request_id = id,
            client = client_id,
            scope = scope.as_deref().unwrap_or(""),
            ip = %client_ip,
            "device login requested"
        );
        let base = state.config.public_base_url();
        let user_code = display_user_code(&user_code);
        return no_store(DeviceAuthorizationResponse {
            device_code,
            verification_uri: format!("{base}{VERIFICATION_PATH}"),
            verification_uri_complete: format!("{base}{VERIFICATION_PATH}?code={user_code}"),
            user_code,
            expires_in: ttl,
            interval,
        });
    }
    tracing::error!("device login: no free user code in {USER_CODE_DRAWS} draws");
    let mut resp = oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "the server cannot answer now; try again",
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, header::HeaderValue::from_static("5"));
    resp
}

// ── POST /auth/device/token ─────────────────────────────────────────────────

/// The access token response (RFC 6749 §5.1).
#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    /// Seconds until the token expires; left out for one that never does.
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<i64>,
    /// The scope the token was minted for; left out for an unscoped one.
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    /// Forge's own addition: whose token it is, the username a client such
    /// as `docker login` sends with it.
    username: String,
}

/// `POST /auth/device/token` — a client polls its device login.
async fn device_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let params = match form_params(&headers, body) {
        Ok(params) => params,
        Err(resp) => return resp,
    };
    match params.get("grant_type").map(String::as_str) {
        None => return bad_request("invalid_request", "grant_type is required"),
        Some(DEVICE_CODE_GRANT) => {}
        // No other grant, a refresh token's included: none is issued.
        Some(_) => {
            return bad_request(
                "unsupported_grant_type",
                "only the device code grant is supported",
            )
        }
    }
    if !state.auth_settings.current().await.settings.device_login {
        return turned_off();
    }
    let client_id = match client_of(&params) {
        Ok(client_id) => client_id,
        Err(resp) => return resp,
    };
    let Some(device_code) = params.get("device_code") else {
        return bad_request("invalid_request", "device_code is required");
    };
    poll(&state, client_id, device_code).await
}

/// Answer a poll of `device_code` by `client_id`. The request's row is
/// locked for the answer, so two polls of one code are answered one after
/// the other, and the token is minted in the transaction that marks the
/// request collected: it is answered once, and a failure leaves the
/// approval to collect on the next poll.
async fn poll(state: &AppState, client_id: &str, device_code: &str) -> Response {
    let mut tx = match forge_db::begin(&state.pool).await {
        Ok(tx) => tx,
        Err(e) => return oauth_unavailable(&e),
    };
    let request = match device_auth_dao::lock_for_poll(&mut tx, &hash_token(device_code)).await {
        Ok(Some(request)) => request,
        Ok(None) => return bad_request("invalid_grant", "unknown device_code"),
        Err(e) => return oauth_unavailable(&e),
    };
    if request.client_id != client_id {
        return bad_request(
            "invalid_grant",
            "the device_code was issued to another client",
        );
    }
    match request.state {
        PollState::Expired => bad_request(
            "expired_token",
            "the device_code expired or its token was collected; start a new login",
        ),
        PollState::Denied => bad_request("access_denied", "the user denied the login"),
        PollState::Pending => {
            let (interval, error, description) = if request.too_fast {
                (
                    request
                        .interval_seconds
                        .saturating_add(SLOW_DOWN_STEP_SECONDS)
                        .min(MAX_INTERVAL_SECONDS),
                    "slow_down",
                    "polled sooner than the interval; wait five seconds longer from now on",
                )
            } else {
                (
                    request.interval_seconds,
                    "authorization_pending",
                    "waiting for the user to approve the login",
                )
            };
            let recorded = device_auth_dao::record_poll(&mut tx, request.id, interval).await;
            if let Err(e) = recorded {
                return oauth_unavailable(&e);
            }
            if let Err(e) = tx.commit().await {
                return oauth_unavailable(&e);
            }
            bad_request(error, description)
        }
        PollState::Approved { user_id } => collect(state, tx, &request, user_id).await,
    }
}

/// Mint the token of an approved request, in its poll's transaction `tx`.
async fn collect(
    state: &AppState,
    mut tx: sqlx::Transaction<'static, sqlx::Postgres>,
    request: &PolledRequest,
    user_id: i64,
) -> Response {
    let user = match user_dao::find_user_by_id(&state.pool, user_id).await {
        Ok(user) => user.filter(|u| u.active),
        Err(e) => return oauth_unavailable(&e),
    };
    let Some(user) = user else {
        // Deactivated since it approved: no token, and none later.
        let collected = device_auth_dao::mark_collected(&mut tx, request.id).await;
        if let Err(e) = collected {
            return oauth_unavailable(&e);
        }
        if let Err(e) = tx.commit().await {
            return oauth_unavailable(&e);
        }
        tracing::info!(
            target: "forge::audit",
            user_id,
            request_id = request.id,
            client = %request.client_id,
            "device login refused: the account is not active"
        );
        return bad_request("access_denied", "the approving account is not active");
    };
    let scope = match request.scope.as_deref().map(DeviceScope::parse) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(scope))) => Some(scope),
        Some(Err(why)) => {
            // Stored normalized, so this is a bug: never mint wider.
            tracing::error!(
                request_id = request.id,
                why,
                "device login: stored scope unreadable"
            );
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the login's scope cannot be read",
            );
        }
    };
    let token_scope = match &scope {
        None => None,
        Some(scope) => match scope.token_scope(state).await {
            Ok(token_scope) => Some(token_scope),
            Err(e) => return oauth_unavailable(&e),
        },
    };
    let scope_json = match token_scope.as_ref().map(serde_json::to_value).transpose() {
        Ok(json) => json,
        Err(e) => {
            tracing::error!(error = %e, "device login: serializing the token scope failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the token's scope cannot be stored",
            );
        }
    };
    let secret = generate_token_secret();
    let name = format!(
        "{} login ({})",
        request.client_id,
        host_of(&state.config.public_base_url())
    );
    let new = crate::cli_auth::login_token(state, &user, name, &secret);
    let token = match token_dao::insert_scoped_token(&mut *tx, new, scope_json.as_ref()).await {
        Ok(token) => token,
        Err(e) => return oauth_unavailable(&e),
    };
    if let Err(e) = device_auth_dao::mark_collected(&mut tx, request.id).await {
        return oauth_unavailable(&e);
    }
    if let Err(e) = tx.commit().await {
        return oauth_unavailable(&e);
    }
    tracing::info!(
        target: "forge::audit",
        user_id,
        token_id = token.id,
        request_id = request.id,
        client = %request.client_id,
        scope = request.scope.as_deref().unwrap_or(""),
        "device login: token minted"
    );
    no_store(TokenResponse {
        access_token: secret,
        token_type: "Bearer",
        expires_in: token
            .expires_at
            .map(|at| (at - Utc::now()).num_seconds().max(0)),
        scope: scope.map(|scope| scope.to_string()),
        username: user.username,
    })
}

/// The host (and port) of the public base URL, which a device login's
/// token is named after.
fn host_of(public_base_url: &str) -> String {
    url::Url::parse(public_base_url)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?.to_string();
            Some(match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            })
        })
        .unwrap_or_else(|| public_base_url.to_string())
}

// ── GET /.well-known/oauth-authorization-server ─────────────────────────────

/// `GET /.well-known/oauth-authorization-server` — the authorization server
/// metadata (RFC 8414): where a client starts a device login and polls it.
async fn metadata(State(state): State<AppState>) -> Response {
    let base = state.config.public_base_url();
    Json(serde_json::json!({
        "issuer": base,
        "device_authorization_endpoint": format!("{base}{DEVICE_CODE_PATH}"),
        "token_endpoint": format!("{base}{DEVICE_TOKEN_PATH}"),
        "grant_types_supported": [DEVICE_CODE_GRANT],
        "response_types_supported": [],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["read", "write", "delete"],
    }))
    .into_response()
}

// ── the /device page: POST /auth/device/lookup and /auth/device/decide ──────

/// What the `/device` page shows of a pending request.
#[derive(Debug, Serialize)]
struct DeviceRequestView {
    /// The code, as the client's terminal shows it (`BCDF-GHJK`).
    user_code: String,
    client_id: String,
    /// The client's name ([`CLIENTS`]).
    client_name: Option<&'static str>,
    /// What the token may do; `null`: the user's rights.
    scope: Option<ScopeView>,
    /// Where the client asked from.
    client_ip: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// A request's scope on the `/device` page.
#[derive(Debug, Serialize)]
struct ScopeView {
    /// The level; `null`: the user's levels.
    level: Option<Level>,
    /// The repositories; empty: every one the user may reach.
    repositories: Vec<String>,
}

impl From<DeviceAuthorization> for DeviceRequestView {
    fn from(request: DeviceAuthorization) -> Self {
        let scope = request
            .scope
            .as_deref()
            .and_then(|raw| DeviceScope::parse(raw).ok().flatten())
            .map(|scope| ScopeView {
                level: scope.level,
                repositories: scope.repositories,
            });
        DeviceRequestView {
            user_code: display_user_code(&request.user_code),
            client_name: client_name(&request.client_id),
            client_id: request.client_id,
            scope,
            client_ip: request.client_ip,
            created_at: request.created_at,
            expires_at: request.expires_at,
        }
    }
}

/// `POST /auth/device/lookup` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupBody {
    user_code: String,
}

/// `POST /auth/device/decide` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideBody {
    user_code: String,
    /// `true` signs the client in as the session's user; `false` denies it.
    approve: bool,
}

/// One code entry, counted against the client network and the browser
/// session ([`AppState::device_code_throttle`]). A code that names no
/// pending request counts as a failure for both; a found one counts as
/// nothing, so finding one's own code never clears the failures.
struct CodeEntry<'a> {
    network: LoginAttempt<'a>,
    session: LoginAttempt<'a>,
}

impl<'a> CodeEntry<'a> {
    async fn begin(
        throttle: &'a LoginThrottle,
        client_ip: IpAddr,
        session_id: i64,
    ) -> Result<Self, Response> {
        let network = throttle
            .begin(client_ip, CODE_ENTRY_NETWORK_KEY)
            .await
            .map_err(|refused| too_many_codes(throttle, refused))?;
        let session = match throttle
            .begin(
                CODE_ENTRY_SESSION_IP,
                &format!("\u{0}device-session:{session_id}"),
            )
            .await
        {
            Ok(session) => session,
            Err(refused) => {
                network.released();
                return Err(too_many_codes(throttle, refused));
            }
        };
        Ok(CodeEntry { network, session })
    }

    /// The code named no pending request.
    fn failed(self) {
        self.network.failed();
        self.session.failed();
    }

    /// The code was found, or Forge could not tell.
    fn released(self) {
        self.network.released();
        self.session.released();
    }
}

/// `429`: too many wrong codes from this network or session.
fn too_many_codes(throttle: &LoginThrottle, refused: AttemptRefused) -> Response {
    let retry_after = match refused {
        AttemptRefused::Locked => throttle.current_limits().1.as_secs().max(1),
        AttemptRefused::Busy => 1,
    };
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string())],
        "too many wrong codes; try again later",
    )
        .into_response()
}

/// `400`: no code can look like this.
fn malformed_code() -> Response {
    (
        StatusCode::BAD_REQUEST,
        "a code is eight letters, such as BCDF-GHJK",
    )
        .into_response()
}

/// `404`: no pending request has this code.
fn not_pending() -> Response {
    (
        StatusCode::NOT_FOUND,
        "no login is waiting for this code: it is mistyped, expired or answered already",
    )
        .into_response()
}

/// `POST /auth/device/lookup` — the pending request a code names, for the
/// signed-in user's `/device` page (CSRF-protected, like every POST of a
/// session). 404 when none is pending; 429 after too many wrong codes.
async fn lookup(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<LookupBody>,
) -> Response {
    let rt = SessionAuthCtx::of(&state);
    let ActiveSession { session, .. } = match require_session_csrf(&rt, &headers).await {
        Ok(active) => active,
        Err(e) => return e.into_response(),
    };
    let Some(code) = normalize_user_code(&body.user_code) else {
        return malformed_code();
    };
    let client_ip = login_client_ip(&state, connect.map(|Extension(ci)| ci.0), &headers);
    let entry = match CodeEntry::begin(&state.device_code_throttle, client_ip, session.id).await {
        Ok(entry) => entry,
        Err(resp) => return resp,
    };
    match device_auth_dao::find_pending(&state.pool, &code).await {
        Ok(Some(request)) => {
            entry.released();
            Json(DeviceRequestView::from(request)).into_response()
        }
        Ok(None) => {
            entry.failed();
            not_pending()
        }
        Err(e) => {
            entry.released();
            tracing::error!(error = %e, "device login lookup failed");
            auth_unavailable()
        }
    }
}

/// `POST /auth/device/decide` — approve (sign the client in as the session's
/// user) or deny the pending request a code names (CSRF-protected). The
/// client collects its token on its next poll. 204, 404 when none is
/// pending, 429 after too many wrong codes.
async fn decide(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<DecideBody>,
) -> Response {
    let rt = SessionAuthCtx::of(&state);
    let ActiveSession { session, user } = match require_session_csrf(&rt, &headers).await {
        Ok(active) => active,
        Err(e) => return e.into_response(),
    };
    let Some(code) = normalize_user_code(&body.user_code) else {
        return malformed_code();
    };
    let client_ip = login_client_ip(&state, connect.map(|Extension(ci)| ci.0), &headers);
    let entry = match CodeEntry::begin(&state.device_code_throttle, client_ip, session.id).await {
        Ok(entry) => entry,
        Err(resp) => return resp,
    };
    let approved_by = body.approve.then_some(user.id);
    match device_auth_dao::decide(&state.pool, &code, approved_by).await {
        Ok(Some(request)) => {
            entry.released();
            tracing::info!(
                target: "forge::audit",
                user_id = user.id,
                request_id = request.id,
                client = %request.client_id,
                scope = request.scope.as_deref().unwrap_or(""),
                ip = %client_ip,
                approved = body.approve,
                "device login decided"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(None) => {
            entry.failed();
            not_pending()
        }
        Err(e) => {
            entry.released();
            tracing::error!(error = %e, "device login decision failed");
            auth_unavailable()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_use_the_alphabet_and_read_back_in_any_spelling() {
        for _ in 0..100 {
            let code = generate_user_code();
            assert_eq!(code.len(), USER_CODE_LEN);
            assert!(
                code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)),
                "{code}"
            );
            assert_eq!(normalize_user_code(&code).as_deref(), Some(code.as_str()));
            let shown = display_user_code(&code);
            assert_eq!(shown.len(), USER_CODE_LEN + 1);
            assert_eq!(&shown[4..5], "-");
            assert_eq!(normalize_user_code(&shown).as_deref(), Some(code.as_str()));
            let typed = format!(" {} ", shown.to_ascii_lowercase());
            assert_eq!(normalize_user_code(&typed).as_deref(), Some(code.as_str()));
        }
        assert_eq!(display_user_code("BCDFGHJK"), "BCDF-GHJK");
        assert_eq!(
            normalize_user_code("bcdf ghjk").as_deref(),
            Some("BCDFGHJK")
        );
        // No vowel, no digit, no look-alike; never seven or nine letters.
        for bad in [
            "",
            "BCDF-GHJ",
            "BCDF-GHJKL",
            "BCDF-GHJA",
            "BCDF-GHJ0",
            "BCDF-GHJ1",
            "BCDFGHJÄ",
        ] {
            assert_eq!(normalize_user_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_scope_maps_onto_level_and_repositories() {
        assert_eq!(DeviceScope::parse(""), Ok(None));
        assert_eq!(DeviceScope::parse("  "), Ok(None));
        let scope = DeviceScope::parse("read  repository:npm-all write repository:b.c_d")
            .unwrap()
            .unwrap();
        assert_eq!(scope.level, Some(Level::Write), "the highest level named");
        assert_eq!(scope.repositories, ["b.c_d", "npm-all"]);
        assert_eq!(
            scope.to_string(),
            "write repository:b.c_d repository:npm-all"
        );
        assert_eq!(
            DeviceScope::parse(&scope.to_string()),
            Ok(Some(scope)),
            "the normalized form reads back"
        );
        let repos_only = DeviceScope::parse("repository:x repository:x")
            .unwrap()
            .unwrap();
        assert_eq!(repos_only.level, None);
        assert_eq!(repos_only.repositories, ["x"]);
        assert_eq!(
            DeviceScope::parse("delete").unwrap().unwrap().to_string(),
            "delete"
        );
        for bad in [
            "admin",
            "openid",
            "repository:",
            "repository:-x",
            "repository:a/b",
            "read\twrite",
            "Read",
        ] {
            assert!(DeviceScope::parse(bad).is_err(), "{bad:?}");
        }
        let many = (0..33)
            .map(|i| format!("repository:r{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(DeviceScope::parse(&many).is_err());
        assert!(DeviceScope::parse(&"read ".repeat(300)).is_err());
    }

    #[test]
    fn only_forges_helpers_are_clients() {
        let params = |id: &str| HashMap::from([("client_id".to_string(), id.to_string())]);
        for (id, name) in CLIENTS {
            assert_eq!(client_of(&params(id)).ok(), Some(id));
            assert_eq!(client_name(id), Some(name));
        }
        assert_eq!(client_of(&params("curl")).unwrap_err().status(), 400);
        assert_eq!(client_of(&HashMap::new()).unwrap_err().status(), 400);
        assert_eq!(client_name("curl"), None);
    }

    #[test]
    fn form_parameters_are_form_encoded_and_unique() {
        let form = |content_type: &str, body: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
            form_params(&headers, Ok(Bytes::from_static(body.as_bytes())))
        };
        let params = form(
            "application/x-www-form-urlencoded; charset=UTF-8",
            "client_id=forge-cli&scope=read+repository%3Aa&empty=",
        )
        .unwrap();
        assert_eq!(params["client_id"], "forge-cli");
        assert_eq!(params["scope"], "read repository:a");
        assert!(
            !params.contains_key("empty"),
            "a parameter without a value is left out"
        );
        assert!(form("application/json", "{}").is_err());
        assert!(form("application/x-www-form-urlencoded", "a=1&a=2").is_err());
    }

    #[test]
    fn tokens_are_named_after_the_host() {
        assert_eq!(host_of("https://forge.example.com"), "forge.example.com");
        assert_eq!(host_of("http://127.0.0.1:8421"), "127.0.0.1:8421");
    }
}
