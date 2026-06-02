//! Interactive OIDC login surface (slice 12.2, Phase 5).
//!
//! This module wires the `core` OIDC flow + session service into the server:
//!
//! * [`OidcRuntime`] — built once at startup from the `[oidc]` config; holds the
//!   discovery/JWKS metadata client, the static client params, the claim-mapping
//!   and resolve policy, and the [`SessionService`]. Stored as an optional field
//!   on [`crate::state::AppState`] (absent means OIDC is disabled and no
//!   `/auth/oidc/*` routes are mounted).
//! * [`auth_router`] — the `/auth/...` browser endpoints:
//!   * `GET  /auth/oidc/login`    — start the auth-code+PKCE flow (302 → IdP).
//!   * `GET  /auth/oidc/callback` — complete it, set the session cookie, 302 to a
//!     validated relative target.
//!   * `POST /auth/logout`        — revoke the session + clear the cookie (CSRF
//!     protected via the per-session double-submit secret).
//!
//! All ephemeral flow state and the sessions live in Postgres (`oidc_flow` /
//! `session`), so any instance can complete a callback another started, and a
//! revocation is visible cluster-wide on the next request.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use forge_cache::Cache;
use forge_core::auth::session_source::{cookie_value, SESSION_COOKIE};
use forge_core::net::ssrf::{guarded_client, SystemResolver};
use forge_core::oidc::{
    begin_login, complete_login, map_claims, resolve_user, CallbackParams, ClaimMapping,
    ClientParams, OidcMetadataClient, ResolvePolicy,
};
use forge_core::session::{csrf_token_matches, IssuedSession, SessionService};
use serde::Deserialize;

use crate::config::OidcConfig;
use crate::state::AppState;

mod redirect;

pub use redirect::sanitize_redirect_to;

/// Everything the `/auth` handlers need, assembled once at startup. Cheap to
/// clone (the metadata client + session service are `Arc`/pool-backed).
#[derive(Clone)]
pub struct OidcRuntime {
    /// Discovery/JWKS fetcher + ID-token verifier (Phase 2).
    meta: OidcMetadataClient,
    /// Static OAuth client params for the flow (Phase 3).
    client: ClientParams,
    /// Claim → user mapping config (Phase 3).
    mapping: ClaimMapping,
    /// Provision / link policy (Phase 3).
    policy: ResolvePolicy,
    /// Server-side session lifecycle (Phase 4).
    sessions: SessionService,
    /// Whether the session cookie is marked `Secure` (driven by the public
    /// base URL scheme — `https` ⇒ secure).
    cookie_secure: bool,
}

impl OidcRuntime {
    /// Build the runtime from the validated `[oidc]` config + the DB pool + the
    /// public base URL (which decides the cookie `Secure` attribute) + the
    /// shared cache.
    ///
    /// The HTTP client is the slice-1 SSRF-guarded `reqwest` client (private
    /// ranges blocked) so discovery/JWKS/token calls share the proxy's posture.
    pub fn build(
        oidc: &OidcConfig,
        pool: sqlx::PgPool,
        public_base_url: &str,
        cache: Cache,
    ) -> anyhow::Result<Self> {
        let http = guarded_client(Arc::new(SystemResolver), oidc.allow_private_issuer)
            .map_err(|e| anyhow::anyhow!("build oidc http client: {e}"))?;
        let meta = OidcMetadataClient::new(oidc.issuer.clone(), http, cache);

        let client = ClientParams {
            client_id: oidc.client_id.clone(),
            client_secret: oidc.client_secret.clone(),
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
        };
        let policy = ResolvePolicy {
            auto_provision: oidc.auto_provision,
            link_existing_by_username: oidc.link_existing_by_username,
        };
        let cookie_secure = public_base_url.trim().starts_with("https://");
        let sessions = SessionService::new(
            pool,
            chrono::Duration::seconds(oidc.session_idle_ttl_seconds as i64),
            chrono::Duration::seconds(oidc.session_absolute_ttl_seconds as i64),
        );

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
}

/// Build the `/auth` router. Mounted only when OIDC is configured.
pub fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/auth/oidc/login", get(oidc_login))
        .route("/auth/oidc/callback", get(oidc_callback))
        .route("/auth/logout", post(logout))
}

/// `GET /auth/oidc/login` — begin the auth-code + PKCE flow and 302 to the IdP.
async fn oidc_login(State(state): State<AppState>, Query(q): Query<LoginQuery>) -> Response {
    let Some(rt) = state.oidc.as_ref() else {
        return (StatusCode::NOT_FOUND, "oidc not configured").into_response();
    };
    let redirect_to = sanitize_redirect_to(q.redirect_to.as_deref());

    match begin_login(&state.pool, &rt.meta, &rt.client, &redirect_to).await {
        Ok(begun) => (StatusCode::FOUND, [(header::LOCATION, begun.authorize_url)]).into_response(),
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

/// `GET /auth/oidc/callback` — complete the flow, set the cookie, 302 to target.
async fn oidc_callback(State(state): State<AppState>, Query(q): Query<CallbackQuery>) -> Response {
    let Some(rt) = state.oidc.as_ref() else {
        return (StatusCode::NOT_FOUND, "oidc not configured").into_response();
    };

    let params = CallbackParams {
        code: q.code,
        state: q.state,
        error: q.error,
        error_description: q.error_description,
    };

    let validated = match complete_login(&state.pool, &rt.meta, &rt.client, &params).await {
        Ok(v) => v,
        Err(e) => {
            // Generic message; never echo the OAuth error detail or secrets.
            tracing::warn!(error = %e, "oidc callback failed");
            return (StatusCode::BAD_REQUEST, "oidc login failed").into_response();
        }
    };

    let mapped = map_claims(&validated.claims, &rt.mapping);
    let user = match resolve_user(&state.pool, &validated, &mapped, &rt.policy).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "oidc user resolution failed");
            return (StatusCode::FORBIDDEN, "login not permitted").into_response();
        }
    };

    // Create a fresh session (login always mints a new row — fixation-proof).
    let issued = match rt.sessions.create_for_user(user.id, None, None).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session creation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
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
/// `X-CSRF-Token` header (double-submit, §3.8). A request without a session
/// cookie is a no-op `204`.
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(rt) = state.oidc.as_ref() else {
        return (StatusCode::NOT_FOUND, "oidc not configured").into_response();
    };

    let Some(secret) = cookie_value(&headers, SESSION_COOKIE) else {
        // No session to revoke; clearing a non-existent cookie is harmless.
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
            return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
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

    let revoked = rt.sessions.revoke(session.id).await.unwrap_or(false);

    (
        StatusCode::OK,
        [(header::SET_COOKIE, clear_cookie_value(rt.cookie_secure))],
        Json(LogoutResult { revoked }),
    )
        .into_response()
}

/// Build the `Set-Cookie` value that installs the session cookie.
///
/// Attributes: `HttpOnly` (no JS access), `SameSite=Lax` (so the post-IdP
/// top-level redirect carries it), `Path=/`, host-only (no `Domain`), and
/// `Secure` when the deployment is HTTPS. `Max-Age` matches the session's
/// absolute lifetime so the browser drops it around when the server would.
fn set_cookie_value(issued: &IssuedSession, secure: bool) -> String {
    let max_age = (issued.session.absolute_expiry - issued.session.created_at)
        .num_seconds()
        .max(0);
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure_attr}",
        value = issued.cookie_secret,
    )
}

/// Build the `Set-Cookie` value that clears the session cookie (`Max-Age=0`).
fn clear_cookie_value(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure_attr}")
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
        assert!(secure.contains("forge_session=the-secret"));
        assert!(secure.contains("HttpOnly"));
        assert!(secure.contains("SameSite=Lax"));
        assert!(secure.contains("Path=/"));
        assert!(secure.contains("Secure"));
        assert!(secure.contains("Max-Age="));
        // Plain-HTTP deployment omits Secure (so dev over http works).
        let insecure = set_cookie_value(&issued, false);
        assert!(!insecure.contains("Secure"));
    }

    #[test]
    fn clear_cookie_expires_immediately() {
        let v = clear_cookie_value(true);
        assert!(v.contains("forge_session=;"));
        assert!(v.contains("Max-Age=0"));
        assert!(v.contains("HttpOnly"));
    }
}
