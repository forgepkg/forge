//! Browser login + session surface: local-password and OIDC logins through the
//! DB-backed auth realms.
//!
//! This module wires the `core` OIDC flow + session service into the server
//! and owns the login UX endpoints:
//!
//! * [`RealmAuth`] (see [`realms`]) — the DB-driven source of truth: the
//!   password chain and the [`OidcRuntime`] are rebuilt from `auth_realm` rows
//!   (snapshot-cached), so admin edits apply at runtime.
//! * [`OidcRuntime`] — the auth-code+PKCE flow runtime (discovery/JWKS client,
//!   claim mapping, resolve policy, sessions), built per enabled `oidc` realm.
//! * [`auth_router`] — the `/auth/...` browser endpoints, always mounted:
//!   * `POST /auth/login`         — username/password through the realm chain;
//!     mints the session cookie (uniform 401 — no user-exists oracle).
//!   * `POST /auth/identify`      — identifier-first routing,
//!     decided ONLY by public realm config (anti-enumeration).
//!   * `GET  /auth/login-options` — what the login screen should render.
//!   * `GET  /auth/oidc/login`    — start the auth-code+PKCE flow (302 → IdP,
//!     with the optional `login_hint` the login screen sends); 404 when no
//!     enabled oidc realm exists.
//!   * `GET  /auth/oidc/callback` — complete it, set the session cookie, 302 to a
//!     validated relative target.
//!   * `POST /auth/logout`        — revoke the session + clear the cookie (CSRF
//!     protected via the per-session double-submit secret).
//!   * `POST /auth/invitations/lookup` / `…/accept` — an invited user's link
//!     (#322, [`crate::invitations`]): whose account it is, and choosing its
//!     password. Failures are throttled per client network.
//!   * `POST /auth/device/code`, `/auth/device/token`, `…/lookup`,
//!     `…/decide` and `GET /.well-known/oauth-authorization-server` — the
//!     device authorization grant (RFC 8628) of command-line clients and the
//!     web UI's `/device` page that approves it ([`device`]).
//!
//! All ephemeral flow state and the sessions live in Postgres (`oidc_flow` /
//! `session`), so any instance can complete a callback another started, and a
//! revocation is visible cluster-wide on the next request. Sessions are
//! OIDC-independent: `/auth/me`, `/auth/tokens` and logout work for
//! local-password logins too.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Router};
use chrono::{DateTime, Utc};
use forge_cache::Cache;
use forge_core::auth::chain::{provision_and_map, ChainOutcome};
use forge_core::auth::client_ip::{forwarded_for, resolve_client_ip};
use forge_core::auth::login_throttle::{username_for_log, AttemptRefused, MAX_USERNAME_BYTES};
use forge_core::auth::session_source::{session_cookie_name, unique_cookie_value};
use forge_core::auth::token::{check_token, generate_token_secret, hash_token, TokenCheck};
use forge_core::auth::PasswordCredential;
use forge_core::net::ssrf::outbound_metadata_client;
use forge_core::oidc::{
    begin_login, browser_binding, complete_login, map_claims, resolve_user, CallbackParams,
    ClaimMapping, ClientAuth, ClientParams, OidcMetadataClient, ResolveError, ResolvePolicy,
};
use forge_core::session::{csrf_token_matches, IssuedSession, SessionService};
use forge_db::model::{AppUser, Session};
use forge_db::token_dao::{self, NewToken};
use forge_db::{external_identity_dao, user_dao};
use serde::{Deserialize, Serialize};

use crate::config::OidcConfig;
use crate::middleware::principal::auth_unavailable;
use crate::state::AppState;

mod device;
mod issuer;
mod realms;
mod redirect;
mod settings;
mod token_exchange;
mod trusted_header;
mod wif;

pub use device::{
    AUTHORIZATION_SERVER_METADATA_PATH, DEVICE_CODE_GRANT, DEVICE_CODE_PATH, DEVICE_TOKEN_PATH,
};
pub use issuer::{
    issuer_router, spawn_issuer_refresh, AssertionIssuer, DISCOVERY_PATH, ISSUER_KEYS_SETTING,
    JWKS_PATH,
};
pub(crate) use realms::normalize_endpoint_hosts;
pub use realms::{
    federated_credential, forget_seed, merge_secrets, redact_config, secret_keys, seed_auth_realms,
    validate_config, FederatedCredential, OidcRealmRuntime, RealmAuth, RealmSnapshot,
    KIND_CRED_FORWARD, KIND_LOCAL, KIND_OIDC, KIND_TRUSTED_HEADER, KIND_WORKLOAD_IDENTITY,
};
pub use redirect::sanitize_redirect_to;
pub use settings::{
    load as load_auth_settings, AnonymousMode, AuthSettings, AuthSettingsCache, AuthSettingsUpdate,
    CurrentAuthSettings, LoginMode, SaveError, AUTH_SETTINGS_KEY,
};
pub(crate) use token_exchange::NPM_TOKEN_EXCHANGE_PATH;
pub use token_exchange::{token_exchange_router, TOKEN_EXCHANGE_PATH};
pub use trusted_header::{TrustedHeaderRealm, TrustedHeaderSource};
pub(crate) use wif::{realm_current_now, workload_identity_config_sha256};
pub use wif::{validate_trusted_publisher_conditions, ClaimCondition, WorkloadIdentitySource};

/// Everything the `/auth` handlers need, assembled once at startup. Cheap to
/// clone (the metadata client + session service are `Arc`/pool-backed).
#[derive(Clone)]
pub struct OidcRuntime {
    /// Discovery/JWKS fetcher + ID-token verifier.
    meta: OidcMetadataClient,
    /// Static OAuth client params for the flow.
    client: ClientParams,
    /// Claim → user mapping config.
    mapping: ClaimMapping,
    /// Provision / link policy.
    policy: ResolvePolicy,
    /// Server-side session lifecycle.
    sessions: SessionService,
    /// Whether the session cookie is marked `Secure` (driven by the public
    /// base URL scheme — `https` ⇒ secure).
    cookie_secure: bool,
}

impl OidcRuntime {
    /// Build the runtime from the validated `[oidc]` config + whether a login
    /// creates an unknown user's account (`auto_provision`, the realm's own
    /// setting: the `[oidc]` block has none) + how the client authenticates
    /// at the token endpoint (`auth`; the config's `client_secret` is not
    /// read) + the session service a login signs in with + the public base
    /// URL (which decides the cookie `Secure` attribute) + the shared cache.
    ///
    /// The HTTP client follows no redirects and is https-only unless the realm
    /// allows a plain-http development issuer (see
    /// [`outbound_metadata_client`]); it serves discovery/JWKS/token calls.
    pub fn build(
        oidc: &OidcConfig,
        auto_provision: bool,
        auth: ClientAuth,
        sessions: SessionService,
        public_base_url: &str,
        cache: Cache,
    ) -> anyhow::Result<Self> {
        let http = outbound_metadata_client(oidc.allow_private_issuer)
            .map_err(|e| anyhow::anyhow!("build oidc http client: {e}"))?;
        let meta = OidcMetadataClient::new(oidc.issuer.clone(), http, cache)
            .with_endpoint_hosts(oidc.endpoint_hosts.clone());

        let client = ClientParams {
            client_id: oidc.client_id.clone(),
            auth,
            redirect_url: oidc.redirect_url.clone(),
            scopes: oidc.effective_scopes(),
            leeway_seconds: oidc.clock_skew_seconds,
        };
        let mapping = ClaimMapping {
            username_claim: oidc.username_claim.clone(),
            email_claim: oidc.email_claim.clone(),
            display_name_claim: oidc.display_name_claim.clone(),
            admin_claim: oidc.admin_claim.clone(),
            admin_groups: oidc.admin_groups.clone(),
            required_claims: oidc.required_claims.clone(),
        };
        let policy = ResolvePolicy {
            auto_provision,
            link_existing_by_username: oidc.link_existing_by_username,
        };
        let cookie_secure = public_base_url.trim().starts_with("https://");

        Ok(Self {
            meta,
            client,
            mapping,
            policy,
            sessions,
            cookie_secure,
        })
    }

    /// The session service (used to register the cookie principal source).
    pub fn sessions(&self) -> &SessionService {
        &self.sessions
    }
}

/// Query params for `GET /auth/oidc/login`.
#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Optional post-login relative path; sanitized to defeat open redirects.
    #[serde(default)]
    pub redirect_to: Option<String>,
    /// Optional account the user means to sign in as (the identifier typed
    /// on the login screen, or a remembered account's): passed to the IdP as
    /// `login_hint` once [`sanitize_login_hint`] accepts it.
    #[serde(default)]
    pub login_hint: Option<String>,
}

/// Longest accepted `login_hint` (bytes): an email address or UPN fits many
/// times over.
pub const MAX_LOGIN_HINT_BYTES: usize = 256;

/// The `login_hint` to pass to the IdP: `raw` trimmed, when it is not empty,
/// at most [`MAX_LOGIN_HINT_BYTES`] and free of control characters. Anything
/// else is dropped rather than refused: the hint only saves the user typing
/// their account at the IdP again, and the sign-in works without it.
fn sanitize_login_hint(raw: Option<&str>) -> Option<&str> {
    let hint = raw.map(str::trim).filter(|h| !h.is_empty())?;
    if hint.len() > MAX_LOGIN_HINT_BYTES || hint.chars().any(char::is_control) {
        // It is an email address: never above debug, and only its size.
        tracing::debug!(bytes = hint.len(), "oidc login_hint dropped");
        return None;
    }
    Some(hint)
}

/// Build the `/auth` router. Always mounted: sessions exist for local
/// password logins too, and the OIDC endpoints answer 404/503 by themselves
/// when no enabled `oidc` realm is configured.
pub fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(password_login))
        .route("/auth/identify", post(identify))
        .route("/auth/login-options", get(login_options))
        .route("/auth/oidc/login", get(oidc_login))
        .route("/auth/oidc/callback", get(oidc_callback))
        .route("/auth/logout", post(logout))
        .route("/auth/invitations/lookup", post(lookup_invitation))
        .route("/auth/invitations/accept", post(accept_invitation))
        .route("/auth/me", get(me))
        .route("/auth/tokens", get(list_tokens).post(create_token))
        .route("/auth/tokens/{id}", delete(revoke_token))
        .route(
            "/auth/cli-login/{secret}",
            get(cli_login_info).post(cli_login_decide),
        )
        // The device authorization grant (RFC 8628) and its discovery
        // document, see [`device`].
        .merge(device::device_router())
}

/// Resolve the realm snapshot or produce the fail-closed error response.
async fn snapshot_or_resp(state: &AppState) -> Result<Arc<realms::RealmSnapshot>, Response> {
    state.realms.snapshot().await.map_err(|e| {
        tracing::error!(error = %e, "realm snapshot failed");
        auth_unavailable()
    })
}

/// At most this much of a value goes into a log line.
const MAX_LOGGED_CHARS: usize = 256;

/// `value` cut to [`MAX_LOGGED_CHARS`] characters (log it with `?` so control
/// characters are escaped).
fn bounded_for_log(value: &str) -> String {
    match value.char_indices().nth(MAX_LOGGED_CHARS) {
        Some((cut, _)) => format!("{}…", &value[..cut]),
        None => value.to_string(),
    }
}

/// `GET /auth/oidc/login` — begin the auth-code + PKCE flow and 302 to the IdP.
///
/// Every call stores a flow row, so starts are rate-limited per client
/// network (`auth.oidc_login_starts_per_minute`, keyed like the login
/// lockout: IPv6 by /64) before any work happens.
async fn oidc_login(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Response {
    let client_ip = login_client_ip(&state, connect.map(|Extension(ci)| ci.0), &headers);
    if !state.oidc_login_starts.allow(client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "too many sign-in attempts; try again later",
        )
            .into_response();
    }
    let snap = match snapshot_or_resp(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let Some(orr) = snap.oidc() else {
        return (StatusCode::NOT_FOUND, "oidc not configured").into_response();
    };
    let rt = &orr.runtime;
    let redirect_to = sanitize_redirect_to(q.redirect_to.as_deref());
    let login_hint = sanitize_login_hint(q.login_hint.as_deref());

    match begin_login(&state.pool, &rt.meta, &rt.client, &redirect_to, login_hint).await {
        // Bind the flow to this browser: the callback must present the cookie.
        Ok(begun) => (
            StatusCode::FOUND,
            [
                (header::LOCATION, begun.authorize_url),
                (
                    header::SET_COOKIE,
                    set_flow_cookie_value(&browser_binding(&begun.state), rt.cookie_secure),
                ),
            ],
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "oidc begin_login failed");
            (StatusCode::BAD_GATEWAY, "oidc login could not be started").into_response()
        }
    }
}

/// Query params the IdP echoes on `GET /auth/oidc/callback`. Maps into the
/// `core` [`CallbackParams`] (kept serde-free in `core`).
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
}

/// `GET /auth/oidc/callback` — complete the flow, set the cookie, 302 to target
/// (or, when the sign-in is refused, to the login page with an error code).
///
/// The browser must present the pre-auth flow cookie set by
/// `GET /auth/oidc/login` (login-CSRF defense); it is cleared on every outcome.
async fn oidc_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // A duplicated flow cookie is ambiguous (one may be planted): no binding.
    let flow_cookie = unique_cookie_value(&headers, flow_cookie_name(state.cookie_secure))
        .ok()
        .flatten()
        .filter(|v| !v.is_empty());
    let mut resp = oidc_callback_inner(&state, q, flow_cookie.clone()).await;
    record_oidc_sign_in(&resp);
    if flow_cookie.is_some() {
        // Single-use: drop the pre-auth cookie whatever the outcome.
        if let Ok(v) = clear_flow_cookie_value(state.cookie_secure).parse() {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

/// Count an OIDC callback in the sign-in metrics by its answer: a redirect
/// to the login page ([`login_failed`]) refused the sign-in, any other one
/// completed it, a `5xx` failed it. A `404` (no OIDC realm) is no sign-in.
fn record_oidc_sign_in(resp: &Response) {
    use forge_telemetry::auth::{sign_in, RealmType, SignInOutcome};
    let status = resp.status();
    let outcome = if status == StatusCode::FOUND {
        let refused = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|location| location.starts_with("/login?"));
        if refused {
            SignInOutcome::Rejected
        } else {
            SignInOutcome::Success
        }
    } else if status.is_server_error() {
        SignInOutcome::Error
    } else if status == StatusCode::NOT_FOUND {
        return;
    } else {
        SignInOutcome::Rejected
    };
    sign_in(RealmType::Oidc, outcome);
}

/// Why an OIDC sign-in was refused, as the SPA's login page names it.
#[derive(Debug, Clone)]
enum LoginFailure {
    /// The callback did not validate (state, binding, code exchange, token),
    /// or the IdP answered with an error such as a cancelled sign-in.
    OidcFailed,
    /// The token was valid but the user may not sign in: the realm's required
    /// claims are missing, auto-provisioning is off, or the account is
    /// inactive.
    NotPermitted,
    /// A new account would be provisioned, but the username the realm's claim
    /// chain resolved is not a UPN. The claim it came from is passed on
    /// (`&claim=`): it names realm configuration, not anything the user or the
    /// IdP's token chose.
    UsernameNotUpn { claim: String },
}

impl LoginFailure {
    fn code(&self) -> &'static str {
        match self {
            LoginFailure::OidcFailed => "oidc_failed",
            LoginFailure::NotPermitted => "not_permitted",
            LoginFailure::UsernameNotUpn { .. } => "username_not_upn",
        }
    }
}

/// Send a refused OIDC sign-in back to the SPA's login page,
/// `/login?error=<code>`, which explains it and offers to try again. The
/// browser arrives at the callback straight from the IdP, so a bare text
/// body left the user on a dead end. The code is generic: the IdP's
/// `error_description` is never passed on (it is only logged, bounded).
fn login_failed(failure: LoginFailure) -> Response {
    let mut location = url::form_urlencoded::Serializer::new(String::new());
    location.append_pair("error", failure.code());
    if let LoginFailure::UsernameNotUpn { claim } = &failure {
        location.append_pair("claim", claim);
    }
    (
        StatusCode::FOUND,
        [(header::LOCATION, format!("/login?{}", location.finish()))],
    )
        .into_response()
}

/// The callback proper; [`oidc_callback`] wraps it to clear the flow cookie.
async fn oidc_callback_inner(
    state: &AppState,
    q: CallbackQuery,
    flow_cookie: Option<String>,
) -> Response {
    let snap = match snapshot_or_resp(state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let Some(orr) = snap.oidc() else {
        return (StatusCode::NOT_FOUND, "oidc not configured").into_response();
    };
    let rt = &orr.runtime;

    let params = CallbackParams {
        code: q.code,
        state: q.state,
        error: q.error,
        error_description: q.error_description,
        browser_binding: flow_cookie,
    };

    let validated = match complete_login(&state.pool, &rt.meta, &rt.client, &params).await {
        Ok(v) => v,
        Err(e) => {
            // Generic message; never echo the OAuth error detail or secrets.
            // The text can carry IdP- (or, before the binding check, anyone-)
            // supplied `error_description`: bounded and `?`-escaped, so it
            // cannot forge log lines or flood the log.
            tracing::warn!(error = ?bounded_for_log(&e.to_string()), "oidc callback failed");
            return login_failed(LoginFailure::OidcFailed);
        }
    };

    // The realm's allow-gate (e.g. one tenant of a multi-tenant app).
    if !forge_core::oidc::claims::claims_allowed(&validated.claims, &rt.mapping) {
        tracing::warn!(
            issuer = %validated.issuer,
            "oidc login refused: the token does not carry the realm's required claims"
        );
        return login_failed(LoginFailure::NotPermitted);
    }

    let mapped = map_claims(&validated.claims, &rt.mapping);
    let user = match resolve_user(&state.pool, &validated, &mapped, &rt.policy).await {
        Ok(u) => u,
        Err(ResolveError::NotUpn { claim }) => {
            tracing::warn!(
                %claim,
                "oidc login refused: a new account needs a UPN, and the claim does not hold one"
            );
            return login_failed(LoginFailure::UsernameNotUpn { claim });
        }
        Err(e) => {
            tracing::warn!(error = %e, "oidc user resolution failed");
            return login_failed(LoginFailure::NotPermitted);
        }
    };
    if mapped.admin_managed {
        // The login may have granted/revoked the admin role: drop the cached
        // effective set so the new session sees it immediately.
        forge_core::authz::invalidate_user(&state.cache, user.id).await;
    }

    // Link the session to the identity that signed in (`/auth/me` reports its
    // display name). Display only, so a failed lookup leaves it unlinked.
    let identity_id = external_identity_dao::find_by_issuer_subject(
        &state.pool,
        &validated.issuer,
        &validated.subject,
    )
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "oidc identity lookup failed");
        None
    })
    .map(|identity| identity.id);

    // Create a fresh session (login always mints a new row — fixation-proof).
    let issued = match rt
        .sessions
        .create_for_user(user.id, identity_id, None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session creation failed");
            return auth_unavailable();
        }
    };

    // Re-validate the post-login target (it came from the flow row, which the
    // login endpoint already sanitized, but defense in depth).
    let target = sanitize_redirect_to(Some(&validated.redirect_to));

    (
        StatusCode::FOUND,
        [
            (header::LOCATION, target),
            (
                header::SET_COOKIE,
                set_cookie_value(&issued, rt.cookie_secure),
            ),
        ],
    )
        .into_response()
}

/// Logout response body (echoes nothing sensitive).
#[derive(Debug, serde::Serialize)]
struct LogoutResult {
    revoked: bool,
}

/// `POST /auth/logout` — revoke the current session + clear the cookie.
///
/// CSRF-protected: the caller must echo the session's `csrf_secret` in the
/// `X-CSRF-Token` header (double-submit). A request without a session
/// cookie is a no-op `204`.
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Sessions are minted by BOTH the local login endpoint and OIDC, so
    // logout works whenever sessions do — independent of any oidc realm.
    let rt = SessionAuthCtx::of(&state);

    let Ok(Some(secret)) = unique_cookie_value(&headers, session_cookie_name(rt.cookie_secure))
    else {
        // No (single) session to revoke; clearing a non-existent cookie is
        // harmless.
        return StatusCode::NO_CONTENT.into_response();
    };

    let session = match rt.sessions.validate(&secret).await {
        Ok(Some(s)) => s,
        // Unknown/expired cookie: still clear it client-side.
        Ok(None) => {
            return (
                StatusCode::NO_CONTENT,
                [(header::SET_COOKIE, clear_cookie_value(rt.cookie_secure))],
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "logout session validate failed");
            return auth_unavailable();
        }
    };

    // CSRF double-submit check against the session's stored secret.
    let presented = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !csrf_token_matches(presented, &session.csrf_secret) {
        return (StatusCode::FORBIDDEN, "missing or invalid csrf token").into_response();
    }

    // Revoke server-side BEFORE clearing the cookie. If the DB revoke fails the
    // session is still live cluster-wide, so we must NOT tell the client it has
    // logged out (and must not clear its cookie as if it had): surface a 503 so
    // the client knows the logout did not take effect and can retry. Silently
    // returning 200 here would leave a live session an attacker holding the
    // cookie could keep using.
    let revoked = match rt.sessions.revoke(session.id).await {
        Ok(revoked) => revoked,
        Err(e) => {
            tracing::error!(error = %e, session_id = session.id, "logout session revoke failed");
            return auth_unavailable();
        }
    };

    (
        StatusCode::OK,
        [(header::SET_COOKIE, clear_cookie_value(rt.cookie_secure))],
        Json(LogoutResult { revoked }),
    )
        .into_response()
}

// ── session-authenticated endpoints (/auth/me, /auth/tokens) ─────────────────
//
// These endpoints are cookie-authenticated (not token/basic): they re-validate
// the `forge_session` cookie through the session service so they can read the
// session's `csrf_secret` directly. Reusing the principal-middleware extension
// would not expose the session row (only a `Principal::User`), and the CSRF
// double-submit secret is bound to the session, so a direct validate is the
// clean seam. Mutating endpoints additionally enforce the double-submit token.

/// Why a session-authenticated request could not proceed.
enum SessionAuthError {
    /// No cookie / unknown / expired / revoked session → 401.
    Unauthorized,
    /// Cookie valid but the `X-CSRF-Token` is missing or wrong → 403.
    CsrfFailed,
    /// The database failed while validating → 503 with `Retry-After`.
    Unavailable,
}

impl IntoResponse for SessionAuthError {
    fn into_response(self) -> Response {
        match self {
            SessionAuthError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "authentication required").into_response()
            }
            SessionAuthError::CsrfFailed => {
                (StatusCode::FORBIDDEN, "missing or invalid csrf token").into_response()
            }
            SessionAuthError::Unavailable => auth_unavailable(),
        }
    }
}

/// What the session-authenticated endpoints need: the shared session service,
/// the pool (to read the session user's live account state) and the
/// cookie-security bit. OIDC-independent (local password logins mint sessions
/// too).
struct SessionAuthCtx {
    sessions: SessionService,
    pool: sqlx::PgPool,
    cookie_secure: bool,
}

impl SessionAuthCtx {
    fn of(state: &AppState) -> Self {
        SessionAuthCtx {
            sessions: state.sessions.clone(),
            pool: state.pool.clone(),
            cookie_secure: state.cookie_secure,
        }
    }
}

/// A live session whose user still exists and is active.
struct ActiveSession {
    session: Session,
    user: AppUser,
}

/// Validate the session cookie and return the live session row plus
/// its user's **current** row. A session of a deactivated (or deleted) user is
/// refused like an unknown cookie: deactivation must cut off a signed-in
/// browser immediately, not when the session expires. None of the error
/// variants leaks whether the cookie was malformed vs unknown vs inactive.
async fn require_session(
    rt: &SessionAuthCtx,
    headers: &HeaderMap,
) -> Result<ActiveSession, SessionAuthError> {
    // Two session cookies are ambiguous: neither proves a session.
    let Some(secret) = unique_cookie_value(headers, session_cookie_name(rt.cookie_secure))
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
    else {
        return Err(SessionAuthError::Unauthorized);
    };
    let session = match rt.sessions.validate(&secret).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(SessionAuthError::Unauthorized),
        Err(e) => {
            tracing::warn!(error = %e, "session validate failed");
            return Err(SessionAuthError::Unavailable);
        }
    };
    match user_dao::find_user_by_id(&rt.pool, session.user_id).await {
        Ok(Some(user)) if user.active => Ok(ActiveSession { session, user }),
        Ok(_) => Err(SessionAuthError::Unauthorized),
        Err(e) => {
            tracing::warn!(error = %e, "session user lookup failed");
            Err(SessionAuthError::Unavailable)
        }
    }
}

/// Like [`require_session`] but also enforces the double-submit CSRF token
/// (`X-CSRF-Token` must equal the session's stored `csrf_secret`). Use on every
/// state-changing cookie-authenticated endpoint.
async fn require_session_csrf(
    rt: &SessionAuthCtx,
    headers: &HeaderMap,
) -> Result<ActiveSession, SessionAuthError> {
    let active = require_session(rt, headers).await?;
    let presented = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !csrf_token_matches(presented, &active.session.csrf_secret) {
        return Err(SessionAuthError::CsrfFailed);
    }
    Ok(active)
}

/// `GET /auth/me` who-am-I body for the SPA. Carries the per-session
/// `csrf_token` the UI must echo on mutating requests.
#[derive(Debug, Serialize)]
struct AuthMe {
    user_id: i64,
    username: String,
    /// The name the identity provider gave for the user, for a session an
    /// OIDC sign-in opened (`null` otherwise, and when it sent none). Display
    /// only: the login screen's remembered accounts show it.
    display_name: Option<String>,
    is_admin: bool,
    /// Per-session double-submit CSRF secret (echo it in `X-CSRF-Token`).
    csrf_token: String,
}

/// `GET /auth/me` — identity for the logged-in browser session. `401` if the
/// cookie is missing/invalid. Unlike `/admin/me` (which accepts any principal
/// incl. token/basic), this is **cookie-only** and additionally returns the
/// CSRF token, so the SPA can bootstrap its mutating-request defense.
async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rt = SessionAuthCtx::of(&state);
    // `require_session` reflects the live user row (deactivation); report the
    // effective RBAC admin verdict (the `admin` role).
    let ActiveSession { session, user: u } = match require_session(&rt, &headers).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let is_admin = state
        .authz
        .is_global_admin(&forge_core::auth::Principal::User {
            user_id: u.id,
            token_id: None,
            method: forge_core::auth::AuthMethod::Session,
        })
        .await;
    let display_name = match session.external_identity_id {
        Some(id) => external_identity_dao::display_name(&state.pool, id)
            .await
            .unwrap_or_else(|e| {
                // Display only: answer without it rather than fail the session.
                tracing::warn!(error = %e, "display name lookup failed");
                None
            }),
        None => None,
    };
    Json(AuthMe {
        user_id: u.id,
        username: u.username,
        display_name,
        is_admin,
        csrf_token: session.csrf_secret,
    })
    .into_response()
}

/// Token metadata view (never includes the secret or its hash).
#[derive(Debug, Serialize)]
struct TokenView {
    id: i64,
    name: String,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<&forge_db::model::Token> for TokenView {
    fn from(t: &forge_db::model::Token) -> Self {
        TokenView {
            id: t.id,
            name: t.name.clone(),
            expires_at: t.expires_at,
            revoked_at: t.revoked_at,
            last_used_at: t.last_used_at,
            created_at: t.created_at,
        }
    }
}

/// `POST /auth/tokens` request body. Unknown fields are rejected, so a `scope`
/// (supported by `POST /admin/me/tokens`) is refused rather than silently
/// dropped, which would mint an unscoped token.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTokenBody {
    name: String,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

/// `POST /auth/tokens` response — the only time the plaintext `token` appears.
#[derive(Debug, Serialize)]
struct CreatedToken {
    #[serde(flatten)]
    view: TokenView,
    /// Plaintext secret — store it now; it cannot be retrieved again.
    token: String,
}

/// `GET /auth/tokens` — list the logged-in (active) user's repository tokens
/// (no secret).
async fn list_tokens(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rt = SessionAuthCtx::of(&state);
    let ActiveSession { user, .. } = match require_session(&rt, &headers).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    match token_dao::list_tokens_for_user(&state.pool, user.id).await {
        Ok(tokens) => {
            let views: Vec<TokenView> = tokens.iter().map(TokenView::from).collect();
            Json(views).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "auth/tokens list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response()
        }
    }
}

/// `POST /auth/tokens` — mint an API token for the **session's** user
/// (CSRF-protected; refused for a deactivated user). Delegates to the same
/// hash-only token model the admin API uses; the plaintext is returned once.
async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateTokenBody>,
) -> Response {
    let rt = SessionAuthCtx::of(&state);
    let ActiveSession { user, .. } = match require_session_csrf(&rt, &headers).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    let secret = generate_token_secret();
    let token_hash = hash_token(&secret);
    let new = NewToken {
        user_id: user.id,
        name: body.name,
        token_hash,
        expires_at: body.expires_at,
        // An upstream-basic account's session came from credential
        // forwarding; an admin-forced reauth revokes such tokens.
        minted_with_forwarded_credential: user.auth_source == "upstream-basic",
    };
    match token_dao::insert_token(&state.pool, new).await {
        Ok(t) => (
            StatusCode::CREATED,
            Json(CreatedToken {
                view: TokenView::from(&t),
                token: secret,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "auth/tokens create failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response()
        }
    }
}

/// `DELETE /auth/tokens/{id}` — revoke one of the session user's own tokens
/// (CSRF-protected). A token belonging to a different user yields `404` (we do
/// not reveal that the id exists).
async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let rt = SessionAuthCtx::of(&state);
    let ActiveSession { user, .. } = match require_session_csrf(&rt, &headers).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    // Enforce ownership: the token must exist AND belong to the session's user.
    match token_dao::find_token_by_id(&state.pool, id).await {
        Ok(Some(t)) if t.user_id == user.id => {}
        Ok(_) => return (StatusCode::NOT_FOUND, "token not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "auth/tokens lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    }

    match token_dao::revoke_token(&state.pool, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "token not found or already revoked").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "auth/tokens revoke failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response()
        }
    }
}

// ── CLI logins in the browser (`npm login`, see `crate::cli_auth`) ──────────

/// `GET /auth/cli-login/{secret}` answer: what the approval page shows of a
/// pending CLI login.
#[derive(Debug, Serialize)]
struct CliLoginView {
    /// The client: the repository's format (`npm`).
    client: String,
    /// The repository the CLI logs in to.
    repository: String,
    /// The host name the CLI reported.
    hostname: Option<String>,
    /// Where the request came from.
    client_ip: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// `GET /auth/cli-login/{secret}` — the pending CLI login whose login URL
/// carries `secret`, for the signed-in user's approval page. 404 once it
/// expired, was decided or never existed.
async fn cli_login_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(secret): Path<String>,
) -> Response {
    let rt = SessionAuthCtx::of(&state);
    if let Err(e) = require_session(&rt, &headers).await {
        return e.into_response();
    }
    let login = match forge_db::cli_login_dao::find(&state.pool, &hash_token(&secret)).await {
        Ok(Some(login)) if login.user_id.is_none() => login,
        Ok(_) => return (StatusCode::NOT_FOUND, "no such login request").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "cli login lookup failed");
            return auth_unavailable();
        }
    };
    let repository =
        match forge_db::repository_dao::find_repository_by_id(&state.pool, login.repository_id)
            .await
        {
            Ok(Some(repo)) => repo.name,
            Ok(None) => return (StatusCode::NOT_FOUND, "no such login request").into_response(),
            Err(e) => {
                tracing::error!(error = %e, "cli login repository lookup failed");
                return auth_unavailable();
            }
        };
    Json(CliLoginView {
        client: login.client,
        repository,
        hostname: login.hostname,
        client_ip: login.client_ip,
        created_at: login.created_at,
        expires_at: login.expires_at,
    })
    .into_response()
}

/// `POST /auth/cli-login/{secret}` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliLoginDecision {
    /// `true` signs the CLI in as the session's user; `false` refuses it.
    approve: bool,
}

/// `POST /auth/cli-login/{secret}` — approve (or refuse) a pending CLI
/// login as the session's user (CSRF-protected). The CLI collects its token
/// on its next poll. 204, or 404 when the request is gone.
async fn cli_login_decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(secret): Path<String>,
    Json(body): Json<CliLoginDecision>,
) -> Response {
    let rt = SessionAuthCtx::of(&state);
    let ActiveSession { user, .. } = match require_session_csrf(&rt, &headers).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let hash = hash_token(&secret);
    let decided = if body.approve {
        forge_db::cli_login_dao::approve(&state.pool, &hash, user.id).await
    } else {
        forge_db::cli_login_dao::deny(&state.pool, &hash).await
    };
    match decided {
        Ok(true) => {
            tracing::info!(
                target: "forge::audit",
                user_id = user.id,
                approved = body.approve,
                "cli login decided"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such login request").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "cli login decision failed");
            auth_unavailable()
        }
    }
}

// ── password login + identifier-first UX ────────────────────────────────────

/// `POST /auth/login` request body.
#[derive(Debug, Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

/// Why a password login was refused ([`verify_password_login`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginRefusal {
    /// Wrong credentials, or none the chain accepts: a uniform 401.
    Invalid,
    /// The lockout holds the `(client IP, username)` pair: 429, with how
    /// many seconds to wait.
    Throttled { retry_after: u64 },
    /// Forge could not decide (its database failed): 503.
    Unavailable,
}

impl IntoResponse for LoginRefusal {
    fn into_response(self) -> Response {
        match self {
            LoginRefusal::Invalid => {
                (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
            }
            LoginRefusal::Throttled { retry_after } => (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                "too many failed sign-in attempts; try again later",
            )
                .into_response(),
            LoginRefusal::Unavailable => auth_unavailable(),
        }
    }
}

/// Who sends the password [`verify_password_login`] checks, which picks the
/// realm chain that checks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordFrom {
    /// The browser login: every password-capable realm
    /// ([`RealmSnapshot::chain`]).
    Browser,
    /// A client (`npm login --auth-type=legacy`): only the realms that accept
    /// passwords from clients ([`RealmSnapshot::client_chain`]).
    Client,
}

/// Check a username and password as a login does: through the realm chain
/// `from` picks (local and credential-forwarding realms, in priority order),
/// under the login lockout, and never for a secret that is a token Forge
/// issued. Returns the signed-in user and the canonical username.
/// `POST /auth/login` signs in through it as [`PasswordFrom::Browser`],
/// `npm login --auth-type=legacy` as [`PasswordFrom::Client`].
pub(crate) async fn verify_password_login(
    state: &AppState,
    client_ip: IpAddr,
    username: &str,
    password: &str,
    from: PasswordFrom,
) -> Result<(forge_core::auth::principal::UserPrincipal, String), LoginRefusal> {
    let snap = snapshot_or_resp(state)
        .await
        .map_err(|_| LoginRefusal::Unavailable)?;
    let chain = match from {
        PasswordFrom::Browser => snap.chain.clone(),
        PasswordFrom::Client => snap.client_chain.clone(),
    };
    let Some(chain) = chain else {
        // No enabled password-capable realm (for a client: none that accepts
        // passwords from clients). Uniform denial (the UI learns whether to
        // even offer the form from /auth/login-options).
        return Err(LoginRefusal::Invalid);
    };
    if username.len() > MAX_USERNAME_BYTES || password.is_empty() {
        return Err(LoginRefusal::Invalid);
    }
    // The lockout, the chain and the account lookup all key on the canonical
    // username (trimmed, NFC, lowercased). A name with a `:` cannot sign in
    // with a password (a forwarding realm's upstream would split it, and Basic
    // cannot carry one); like an oversized one it is never counted.
    let Ok(username) = forge_core::auth::canonical_password_username(username) else {
        return Err(LoginRefusal::Invalid);
    };

    // Reserve the attempt against the (IP, username) lockout budget before
    // running the chain; a locked pair is refused without any provider work
    // (no argon2, nothing forwarded upstream).
    let attempt = match state.login_throttle.begin(client_ip, &username).await {
        Ok(attempt) => attempt,
        Err(refused) => {
            let username = username_for_log(&username);
            // `Retry-After` (seconds) lets the UI say how long to wait: a
            // locked pair clears within one failure window (an upper bound),
            // a pair saturated by in-flight attempts within moments.
            let retry_after = match refused {
                AttemptRefused::Locked => {
                    tracing::warn!(%username, ip = %client_ip, "password login throttled");
                    state.login_throttle.current_limits().1.as_secs().max(1)
                }
                AttemptRefused::Busy => {
                    tracing::warn!(%username, ip = %client_ip, "password login: too many concurrent attempts");
                    1
                }
            };
            return Err(LoginRefusal::Throttled { retry_after });
        }
    };
    // A token Forge issued is never a password, even one that cannot be used
    // now. As on the wire Basic path it is not run through the chain (a
    // credential-forwarding realm would send it upstream), and it does not
    // sign in either: a session carries its owner's rights, not the token's
    // scope. The same holds for a workload API key.
    if forge_core::auth::is_workload_key(password) {
        attempt.failed();
        return Err(LoginRefusal::Invalid);
    }
    match check_token(&state.pool, password).await {
        Ok(TokenCheck::Unknown) => {}
        Ok(TokenCheck::Live(_) | TokenCheck::Unusable) => {
            attempt.failed();
            return Err(LoginRefusal::Invalid);
        }
        Err(_) => {
            attempt.released();
            return Err(LoginRefusal::Unavailable);
        }
    }
    let cred = PasswordCredential {
        username: &username,
        password,
        client_ip,
    };
    let identity = match chain.authenticate(&cred).await {
        ChainOutcome::Authenticated { identity, .. } => identity,
        // Uniform wire response for rejected / outage / unknown (fail-closed;
        // upstream health goes to logs, not to the caller). An outage (or an
        // argon2 overload) is not the caller's fault and does not count
        // towards the lockout.
        ChainOutcome::Unavailable => {
            attempt.released();
            return Err(LoginRefusal::Invalid);
        }
        // Forge's own database failed: not a verdict on the credentials.
        ChainOutcome::Failed => {
            attempt.released();
            return Err(LoginRefusal::Unavailable);
        }
        ChainOutcome::Rejected | ChainOutcome::NoCredentials => {
            attempt.failed();
            return Err(LoginRefusal::Invalid);
        }
    };

    let principal = match provision_and_map(&state.pool, &identity).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            attempt.failed();
            return Err(LoginRefusal::Invalid);
        }
        Err(e) => {
            tracing::error!(error = %e, "login principal mapping failed");
            attempt.released();
            return Err(LoginRefusal::Unavailable);
        }
    };
    attempt.succeeded();
    if identity.admin_authoritative {
        // The upstream may just have granted/revoked admin: drop the cached
        // effective set so the new session sees it immediately.
        forge_core::authz::invalidate_user(&state.cache, principal.user_id).await;
    }
    Ok((principal, username))
}

/// `POST /auth/login` — authenticate a username/password through the realm
/// chain (local + credential-forwarding realms, in priority order) and mint a
/// browser session.
///
/// This is the form-login counterpart of the wire Basic path, with the same
/// fail-closed semantics, but it runs the chain of **every** password-capable
/// realm: a realm's `accept_client_passwords` governs only the passwords
/// clients send (it is how a local user gets a token). The
/// response mirrors `/auth/me` so the SPA can bootstrap immediately; failures
/// are a uniform 401 (no username-exists oracle). A username over
/// [`MAX_USERNAME_BYTES`], or one containing `:`, is refused the same way
/// before any lookup or lockout bookkeeping (it is never counted, so it cannot
/// grow the lockout map).
async fn password_login(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let client_ip = login_client_ip(&state, connect.map(|Extension(ci)| ci.0), &headers);
    let (principal, username) = match verify_password_login(
        &state,
        client_ip,
        &body.username,
        &body.password,
        PasswordFrom::Browser,
    )
    .await
    {
        Ok(verified) => verified,
        Err(refusal) => return refusal.into_response(),
    };

    // Fresh session per login (fixation-proof), same as the OIDC callback.
    let issued = match state
        .sessions
        .create_for_user(principal.user_id, None, None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session creation failed");
            return auth_unavailable();
        }
    };

    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            set_cookie_value(&issued, state.cookie_secure),
        )],
        Json(AuthMe {
            user_id: principal.user_id,
            username,
            display_name: None,
            is_admin: state
                .authz
                .is_global_admin(&forge_core::auth::Principal::from_user(principal))
                .await,
            csrf_token: issued.session.csrf_secret.clone(),
        }),
    )
        .into_response()
}

/// The key the invitation throttle counts a client network's failures under
/// (the throttle is the login lockout's, keyed by network and this).
const INVITATION_THROTTLE_KEY: &str = "\u{0}invitation";

/// `POST /auth/invitations/lookup` and `…/accept` body: the token from the
/// link's fragment (and the password to choose).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationBody {
    token: String,
    #[serde(default)]
    password: Option<String>,
}

/// The one answer for a token that does not work.
fn invalid_invitation() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": crate::invitations::INVALID_INVITATION})),
    )
        .into_response()
}

fn invitation_throttled(state: &AppState) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(
            header::RETRY_AFTER,
            state
                .invitation_throttle
                .current_limits()
                .1
                .as_secs()
                .max(1)
                .to_string(),
        )],
        "too many failed attempts; try again later",
    )
        .into_response()
}

/// `POST /auth/invitations/lookup`: whose account a live invitation is
/// for, so the page can name it. **400** with the generic answer otherwise.
async fn lookup_invitation(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<InvitationBody>,
) -> Response {
    let client_ip = login_client_ip(&state, connect.map(|Extension(ci)| ci.0), &headers);
    let Ok(attempt) = state
        .invitation_throttle
        .begin(client_ip, INVITATION_THROTTLE_KEY)
        .await
    else {
        return invitation_throttled(&state);
    };
    let hash = crate::invitations::token_hash(&body.token);
    match forge_db::invitation_dao::find_live(&state.pool, &hash).await {
        Ok(Some((username, expires_at))) => {
            attempt.released();
            Json(serde_json::json!({"username": username, "expires_at": expires_at}))
                .into_response()
        }
        Ok(None) => {
            attempt.failed();
            invalid_invitation()
        }
        Err(e) => {
            attempt.released();
            tracing::error!(error = %e, "invitation lookup failed");
            auth_unavailable()
        }
    }
}

/// `POST /auth/invitations/accept`: choose the invited account's password.
/// **200** `{"username"}` (the page then sends the browser to sign in);
/// **400** for a password that is too short or too long, or with the generic
/// answer for a token that does not work.
async fn accept_invitation(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<InvitationBody>,
) -> Response {
    let Some(password) = body.password else {
        return (StatusCode::BAD_REQUEST, "a password is required").into_response();
    };
    if let Err(why) = crate::invitations::check_password(&password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": why})),
        )
            .into_response();
    }
    let client_ip = login_client_ip(&state, connect.map(|Extension(ci)| ci.0), &headers);
    let Ok(attempt) = state
        .invitation_throttle
        .begin(client_ip, INVITATION_THROTTLE_KEY)
        .await
    else {
        return invitation_throttled(&state);
    };
    let hash = crate::invitations::token_hash(&body.token);
    // Before the argon2 work: an unknown token costs none.
    match forge_db::invitation_dao::find_live(&state.pool, &hash).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            attempt.failed();
            return invalid_invitation();
        }
        Err(e) => {
            attempt.released();
            tracing::error!(error = %e, "invitation lookup failed");
            return auth_unavailable();
        }
    }
    let password_hash = match crate::admin::hash_password(password).await {
        Ok(hash) => hash,
        Err(resp) => {
            attempt.released();
            return resp;
        }
    };
    match forge_db::invitation_dao::accept(&state.pool, &hash, &password_hash).await {
        Ok(Some(user)) => {
            attempt.released();
            tracing::info!(
                user_id = user.id,
                "invitation accepted: the password is set"
            );
            Json(serde_json::json!({"username": user.username})).into_response()
        }
        // Accepted, replaced or revoked meanwhile.
        Ok(None) => {
            attempt.failed();
            invalid_invitation()
        }
        Err(e) => {
            attempt.released();
            tracing::error!(error = %e, "invitation acceptance failed");
            auth_unavailable()
        }
    }
}

/// Resolve the client IP for the lockout key and the login audit trail: honors
/// every `X-Forwarded-For` line behind the configured trusted proxies and
/// canonicalizes IPv4-mapped addresses, mirroring the principal middleware.
/// Loopback when no connect info is available (in-process router tests).
pub(crate) fn login_client_ip(
    state: &AppState,
    connect: Option<SocketAddr>,
    headers: &HeaderMap,
) -> IpAddr {
    let peer = connect
        .map(|addr| addr.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let xff = forwarded_for(headers);
    let trusted = state.config.trusted_proxy_cidrs().unwrap_or_default();
    resolve_client_ip(peer, xff.as_deref(), &trusted)
}

/// `POST /auth/identify` request body.
#[derive(Debug, Deserialize)]
struct IdentifyBody {
    username: String,
}

/// `POST /auth/identify` response: how the login UI should proceed for this
/// identifier.
#[derive(Debug, Serialize)]
struct IdentifyResult {
    /// `password` → show the password prompt; `oidc_redirect` → navigate to
    /// `login_url` (which 302s to the IdP).
    mode: &'static str,
    /// The realm the decision routed to (display only).
    realm: String,
    /// Where to go for `oidc_redirect` (starts the auth-code flow).
    #[serde(skip_serializing_if = "Option::is_none")]
    login_url: Option<String>,
}

/// `POST /auth/identify` — identifier-first routing.
///
/// **Anti-enumeration:** the decision is a pure function of *public realm
/// configuration* (an OIDC realm's `login_domains` rule), never of whether an
/// `app_user` exists — an unknown identifier gets the same `password` answer
/// as a real local user.
async fn identify(State(state): State<AppState>, Json(body): Json<IdentifyBody>) -> Response {
    let snap = match snapshot_or_resp(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let domain = body
        .username
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase());
    if let (Some(domain), Some(orr)) = (domain, snap.oidc()) {
        if orr.login_domains.iter().any(|d| d == &domain) {
            return Json(IdentifyResult {
                mode: "oidc_redirect",
                realm: orr.realm_name.clone(),
                login_url: Some("/auth/oidc/login".to_string()),
            })
            .into_response();
        }
    }

    // No domain rule matched. Default to the password prompt against the
    // ordered password realms — unless none is enabled and OIDC is the only
    // way in, in which case identifier-first can only mean "go to the IdP".
    if snap.chain.is_none() {
        if let Some(orr) = snap.oidc() {
            return Json(IdentifyResult {
                mode: "oidc_redirect",
                realm: orr.realm_name.clone(),
                login_url: Some("/auth/oidc/login".to_string()),
            })
            .into_response();
        }
    }
    let realm = snap
        .realms
        .iter()
        .find(|r| r.enabled && matches!(r.kind.as_str(), KIND_LOCAL | KIND_CRED_FORWARD))
        .map(|r| r.name.clone())
        .unwrap_or_else(|| "local".to_string());
    Json(IdentifyResult {
        mode: "password",
        realm,
        login_url: None,
    })
    .into_response()
}

/// One OIDC login option in [`LoginOptions`].
#[derive(Debug, Serialize)]
struct OidcLoginOption {
    name: String,
    label: String,
    login_url: String,
}

/// `GET /auth/login-options` response: what the login screen should render.
#[derive(Debug, Serialize)]
struct LoginOptions {
    /// `identifier_first` | `combined` (the `login_mode` auth setting).
    mode: &'static str,
    /// Whether any password-capable realm is enabled (show the password form).
    password: bool,
    /// Enabled OIDC realm buttons (at most one).
    oidc: Vec<OidcLoginOption>,
    /// Whether the login screen remembers the accounts signed in on the
    /// device and offers them (the `remember_accounts` auth setting). The
    /// accounts are kept in the browser only; the server never lists any.
    remember_accounts: bool,
}

/// `GET /auth/login-options` — public, unauthenticated: the login screen asks
/// this before rendering. Exposes only realm *presence* and labels, never
/// configuration.
async fn login_options(State(state): State<AppState>) -> Response {
    let snap = match snapshot_or_resp(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let oidc = snap
        .oidc()
        .map(|orr| {
            vec![OidcLoginOption {
                name: orr.realm_name.clone(),
                label: orr.label.clone(),
                login_url: "/auth/oidc/login".to_string(),
            }]
        })
        .unwrap_or_default();
    let settings = &state.auth_settings.current().await.settings;
    Json(LoginOptions {
        mode: settings.login_mode.as_str(),
        password: snap.chain.is_some(),
        oidc,
        remember_accounts: settings.remember_accounts,
    })
    .into_response()
}

/// Build the `Set-Cookie` value that installs the session cookie.
///
/// Attributes: `HttpOnly` (no JS access), `SameSite=Lax` (so the post-IdP
/// top-level redirect carries it), `Path=/`, host-only (no `Domain`), and on
/// an HTTPS deployment `Secure` under the `__Host-` name
/// ([`session_cookie_name`]). `Max-Age` matches the session's absolute
/// lifetime so the browser drops it around when the server would.
fn set_cookie_value(issued: &IssuedSession, secure: bool) -> String {
    let max_age = (issued.session.absolute_expiry - issued.session.created_at)
        .num_seconds()
        .max(0);
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure_attr}",
        name = session_cookie_name(secure),
        value = issued.cookie_secret,
    )
}

/// Build the `Set-Cookie` value that clears the session cookie (`Max-Age=0`).
fn clear_cookie_value(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure_attr}",
        name = session_cookie_name(secure)
    )
}

/// Pre-auth cookie binding an OIDC flow to the browser that started it, on a
/// plain-http (development) deployment; scoped to `/auth/oidc`.
const OIDC_FLOW_COOKIE: &str = "forge_oidc_flow";

/// The flow cookie on an HTTPS deployment: `__Host-` (so it cannot be planted
/// from a sibling subdomain), which requires `Path=/`.
const SECURE_OIDC_FLOW_COOKIE: &str = "__Host-forge_oidc_flow";

/// `Max-Age` of the pre-auth flow cookie (matches the flow row's 10 min TTL).
const OIDC_FLOW_COOKIE_MAX_AGE: i64 = 600;

/// The flow cookie's name and path for a deployment.
fn flow_cookie_name(secure: bool) -> &'static str {
    if secure {
        SECURE_OIDC_FLOW_COOKIE
    } else {
        OIDC_FLOW_COOKIE
    }
}

fn flow_cookie_attributes(secure: bool) -> &'static str {
    if secure {
        "Path=/; HttpOnly; SameSite=Lax; Secure"
    } else {
        "Path=/auth/oidc; HttpOnly; SameSite=Lax"
    }
}

/// Build the `Set-Cookie` value for the pre-auth flow cookie: `HttpOnly`,
/// `SameSite=Lax` (sent on the IdP's top-level redirect back), short-lived,
/// `__Host-` + `Secure` on HTTPS deployments (scoped to `/auth/oidc` on plain
/// http, where the prefix is unavailable).
fn set_flow_cookie_value(binding: &str, secure: bool) -> String {
    format!(
        "{name}={binding}; {attributes}; Max-Age={OIDC_FLOW_COOKIE_MAX_AGE}",
        name = flow_cookie_name(secure),
        attributes = flow_cookie_attributes(secure),
    )
}

/// Build the `Set-Cookie` value that clears the pre-auth flow cookie.
fn clear_flow_cookie_value(secure: bool) -> String {
    format!(
        "{name}=; {attributes}; Max-Age=0",
        name = flow_cookie_name(secure),
        attributes = flow_cookie_attributes(secure),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_has_security_attributes() {
        use chrono::{Duration, Utc};
        use forge_db::model::Session;
        let now = Utc::now();
        let session = Session {
            id: 1,
            user_id: 7,
            external_identity_id: None,
            token_hash: "h".into(),
            csrf_secret: "c".into(),
            user_agent_hash: None,
            created_at: now,
            last_seen_at: now,
            idle_expiry: now + Duration::hours(8),
            absolute_expiry: now + Duration::days(7),
            revoked_at: None,
        };
        let issued = IssuedSession {
            session,
            cookie_secret: "the-secret".into(),
        };
        let secure = set_cookie_value(&issued, true);
        // HTTPS: the `__Host-` name, which browsers bind to this host.
        assert!(secure.starts_with("__Host-forge_session=the-secret;"));
        assert!(!secure.contains("Domain"));
        assert!(secure.contains("HttpOnly"));
        assert!(secure.contains("SameSite=Lax"));
        assert!(secure.contains("Path=/"));
        assert!(secure.contains("Secure"));
        assert!(secure.contains("Max-Age="));
        // Plain-HTTP deployment omits Secure (so dev over http works).
        let insecure = set_cookie_value(&issued, false);
        assert!(insecure.starts_with("forge_session=the-secret;"));
        assert!(!insecure.contains("Secure"));
    }

    #[test]
    fn flow_cookie_is_short_lived_http_only_and_scoped() {
        // HTTPS: `__Host-` (Secure, host-only, Path=/).
        let v = set_flow_cookie_value("bind", true);
        assert!(v.starts_with("__Host-forge_oidc_flow=bind;"));
        assert!(v.contains("HttpOnly"));
        assert!(v.contains("SameSite=Lax"));
        assert!(v.contains("Path=/;"));
        assert!(v.contains("Max-Age=600"));
        assert!(v.contains("Secure"));
        assert!(!v.contains("Domain"));
        // Plain http: no prefix possible, so scope it to the OIDC paths.
        let v = set_flow_cookie_value("bind", false);
        assert!(v.starts_with("forge_oidc_flow=bind;"));
        assert!(v.contains("Path=/auth/oidc"));
        assert!(!v.contains("Secure"));
        let clear = clear_flow_cookie_value(false);
        assert!(clear.starts_with("forge_oidc_flow=;"));
        assert!(clear.contains("Max-Age=0"));
        let clear = clear_flow_cookie_value(true);
        assert!(clear.starts_with("__Host-forge_oidc_flow=;"));
        assert!(clear.contains("Path=/;"));
    }

    #[test]
    fn login_hint_is_bounded_and_printable() {
        assert_eq!(sanitize_login_hint(None), None);
        assert_eq!(sanitize_login_hint(Some("")), None);
        assert_eq!(sanitize_login_hint(Some("   ")), None);
        assert_eq!(
            sanitize_login_hint(Some(" alice@corp.example ")),
            Some("alice@corp.example")
        );
        // Not ASCII-only: a UPN may hold any printable character.
        assert_eq!(
            sanitize_login_hint(Some("jürgen@bücher.example")),
            Some("jürgen@bücher.example")
        );
        for bad in ["alice\n@corp.example", "alice\u{0}", "a\tb", "\u{7f}x"] {
            assert_eq!(sanitize_login_hint(Some(bad)), None, "{bad:?}");
        }
        let fits = "a".repeat(MAX_LOGIN_HINT_BYTES);
        assert_eq!(sanitize_login_hint(Some(&fits)), Some(fits.as_str()));
        let long = "a".repeat(MAX_LOGIN_HINT_BYTES + 1);
        assert_eq!(sanitize_login_hint(Some(&long)), None);
    }

    #[test]
    fn clear_cookie_expires_immediately() {
        let v = clear_cookie_value(true);
        assert!(v.starts_with("__Host-forge_session=;"));
        assert!(v.contains("Max-Age=0"));
        assert!(v.contains("HttpOnly"));
        assert!(clear_cookie_value(false).starts_with("forge_session=;"));
    }
}
