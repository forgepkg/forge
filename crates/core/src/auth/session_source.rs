//! Session-cookie principal source (slice 12.2, §3.7 / Phase 5).
//!
//! This is the integration point that lets the slice-1 ordered
//! [`PrincipalSource`] chain authenticate **browser** callers carrying a
//! `forge_session` cookie, *in addition to* the existing token-header / HTTP
//! Basic sources. It is appended to the chain in
//! `forge_server::app::principal_layer`.
//!
//! ## How it fits the trait
//!
//! [`PrincipalSource::resolve`] is handed the request headers; the session
//! cookie travels in the standard `Cookie` request header, so reading it here
//! needs no new trait surface. We parse the `forge_session` value out of the
//! `Cookie` header, validate it against the shared Postgres via
//! [`SessionService::validate`] (the session row is the authority — an unknown
//! or tampered cookie simply hashes to a missing row), and on a hit yield a
//! [`Principal::User`] reflecting the session's user + *current* `is_admin`.
//!
//! ## Security semantics
//!
//! * A **missing** `forge_session` cookie ⇒ [`SourceOutcome::NoCredentials`]
//!   (so token/basic still get their turn, and the anonymous policy applies if
//!   nothing authenticates).
//! * A **present but invalid/expired/revoked** cookie ⇒ [`SourceOutcome::Invalid`]
//!   — bad credentials are never downgraded to anonymous (mirrors the token
//!   path; [`resolve_principal`](super::token::resolve_principal) turns any
//!   `Invalid` into a 401).
//! * The `is_admin` flag comes from the **live `app_user` row** looked up by the
//!   session's `user_id`, not a value cached on the session, so an admin
//!   grant/revoke takes effect without re-login (a deactivated user is rejected).

use std::net::IpAddr;

use http::HeaderMap;
use sqlx::PgPool;

use super::principal::Principal;
use super::token::{PrincipalSource, SourceOutcome};
use crate::session::SessionService;

/// The cookie name carrying the opaque session secret.
pub const SESSION_COOKIE: &str = "forge_session";

/// Resolves the `forge_session` cookie into a [`Principal::User`] via the
/// [`SessionService`] over the shared Postgres.
pub struct SessionCookieSource {
    sessions: SessionService,
    pool: PgPool,
}

impl SessionCookieSource {
    /// Build a source over the session service + pool (the pool is used to read
    /// the live `app_user` row for the current `is_admin`/`active` flags).
    pub fn new(sessions: SessionService, pool: PgPool) -> Self {
        Self { sessions, pool }
    }
}

#[async_trait::async_trait]
impl PrincipalSource for SessionCookieSource {
    /// The browser sends the cookie on its own: mutations need CSRF proof.
    fn is_ambient(&self) -> bool {
        true
    }

    async fn resolve(&self, headers: &HeaderMap, _peer_ip: IpAddr) -> SourceOutcome {
        // No `Cookie` header, or no `forge_session` within it → not our turn.
        let Some(secret) = cookie_value(headers, SESSION_COOKIE) else {
            return SourceOutcome::NoCredentials;
        };
        if secret.is_empty() {
            return SourceOutcome::NoCredentials;
        }

        // Validate against the authoritative session row.
        let session = match self.sessions.validate(&secret).await {
            Ok(Some(s)) => s,
            // Unknown / expired / revoked cookie: credentials were presented but
            // rejected — Invalid, never downgraded to anonymous.
            Ok(None) => return SourceOutcome::Invalid,
            Err(e) => {
                tracing::warn!(error = %e, "session validation failed");
                return SourceOutcome::Invalid;
            }
        };

        // Reflect the *current* user state (admin grant/revoke, deactivation)
        // rather than anything cached on the session row.
        match forge_db::user_dao::find_user_by_id(&self.pool, session.user_id).await {
            Ok(Some(user)) if user.active => SourceOutcome::Authenticated(Principal::User {
                user_id: user.id,
                token_id: None,
                is_admin: user.is_admin,
            }),
            // The session points at a vanished or deactivated user: reject.
            Ok(_) => SourceOutcome::Invalid,
            Err(e) => {
                tracing::warn!(error = %e, "session user lookup failed");
                SourceOutcome::Invalid
            }
        }
    }
}

/// Extract a single cookie's value from the (possibly multi-valued) `Cookie`
/// request header(s).
///
/// The `Cookie` header is a `; `-separated list of `name=value` pairs; a client
/// may also send multiple `Cookie` headers. We scan all of them and return the
/// first `name`-matching value, trimmed. Returns `None` if absent.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for header in headers.get_all(http::header::COOKIE) {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::COOKIE;

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, value.parse().unwrap());
        h
    }

    #[test]
    fn extracts_named_cookie() {
        let h = headers_with_cookie("a=1; forge_session=secret-xyz; b=2");
        assert_eq!(
            cookie_value(&h, SESSION_COOKIE).as_deref(),
            Some("secret-xyz")
        );
    }

    #[test]
    fn missing_cookie_is_none() {
        let h = headers_with_cookie("a=1; b=2");
        assert_eq!(cookie_value(&h, SESSION_COOKIE), None);
    }

    #[test]
    fn no_cookie_header_is_none() {
        assert_eq!(cookie_value(&HeaderMap::new(), SESSION_COOKIE), None);
    }

    #[test]
    fn handles_multiple_cookie_headers() {
        let mut h = HeaderMap::new();
        h.append(COOKIE, "a=1".parse().unwrap());
        h.append(COOKIE, "forge_session=zzz".parse().unwrap());
        assert_eq!(cookie_value(&h, SESSION_COOKIE).as_deref(), Some("zzz"));
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let h = headers_with_cookie("forge_session = padded ");
        assert_eq!(cookie_value(&h, SESSION_COOKIE).as_deref(), Some("padded"));
    }

    #[test]
    fn first_match_wins_on_duplicate() {
        let h = headers_with_cookie("forge_session=first; forge_session=second");
        assert_eq!(cookie_value(&h, SESSION_COOKIE).as_deref(), Some("first"));
    }
}
