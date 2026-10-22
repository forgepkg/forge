//! Session-cookie principal source.
//!
//! This is the integration point that lets the ordered
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
//! * A **present but invalid/expired/revoked** cookie, or one whose user is gone
//!   or deactivated ⇒ [`SourceOutcome::Stale`]: the browser attaches it on its
//!   own, so it proves nothing; the request continues as anonymous /
//!   unauthenticated and the dead cookie is cleared.
//! * A database error while checking the cookie ⇒ [`SourceOutcome::Unavailable`]
//!   — fail closed with 503 (mirrors the token path), never a 401 for a session
//!   that may well be live.
//! * The `is_admin` flag comes from the **live `app_user` row** looked up by the
//!   session's `user_id`, not a value cached on the session, so an admin
//!   grant/revoke takes effect without re-login (a deactivated user is rejected).

use std::net::IpAddr;

use http::HeaderMap;
use sqlx::PgPool;

use super::principal::Principal;
use super::token::{PrincipalSource, SourceOutcome};
use crate::session::SessionService;

/// The cookie name carrying the opaque session secret on a plain-http
/// (development) deployment.
pub const SESSION_COOKIE: &str = "forge_session";

/// The session cookie's name on an https deployment. Browsers accept a
/// `__Host-` cookie only when it is `Secure`, host-only (no `Domain`) and
/// `Path=/`, so a sibling subdomain or a plain-http response cannot plant
/// one (cookie tossing / session fixation).
pub const SECURE_SESSION_COOKIE: &str = "__Host-forge_session";

/// The session cookie's name for a deployment (`secure`: served over https).
pub fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        SECURE_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    }
}

/// Resolves the session cookie into a [`Principal::User`] via the
/// [`SessionService`] over the shared Postgres.
pub struct SessionCookieSource {
    sessions: SessionService,
    pool: PgPool,
    cookie_name: &'static str,
}

impl SessionCookieSource {
    /// Build a source over the session service + pool (the pool is used to read
    /// the live `app_user` row for the current `is_admin`/`active` flags).
    /// `secure` selects the cookie name ([`session_cookie_name`]).
    pub fn new(sessions: SessionService, pool: PgPool, secure: bool) -> Self {
        Self {
            sessions,
            pool,
            cookie_name: session_cookie_name(secure),
        }
    }
}

#[async_trait::async_trait]
impl PrincipalSource for SessionCookieSource {
    /// The browser sends the cookie on its own: mutations need CSRF proof.
    fn is_ambient(&self) -> bool {
        true
    }

    async fn resolve(&self, headers: &HeaderMap, _peer_ip: IpAddr) -> SourceOutcome {
        // No `Cookie` header, or no session cookie within it → not our turn.
        // Two session cookies are ambiguous (one may have been planted for a
        // narrower path or a parent domain): use neither, and do not clear
        // either — clearing would drop the browser's own and keep the planted
        // one.
        let secret = match unique_cookie_value(headers, self.cookie_name) {
            Ok(Some(secret)) => secret,
            Ok(None) => return SourceOutcome::NoCredentials,
            Err(DuplicateCookie) => {
                tracing::warn!(
                    cookie = self.cookie_name,
                    "request carries more than one session cookie; ignoring them"
                );
                return SourceOutcome::NoCredentials;
            }
        };
        if secret.is_empty() {
            return SourceOutcome::NoCredentials;
        }

        // Validate against the authoritative session row.
        let session = match self.sessions.validate(&secret).await {
            Ok(Some(s)) => s,
            // Unknown / expired / revoked cookie: the browser sent it on its
            // own, so it proves nothing — Stale (treated as no credentials and
            // cleared by the middleware), not a 401 that would lock the user out
            // of the login page itself.
            Ok(None) => return SourceOutcome::Stale,
            // Infrastructure failure: fail closed (503, not a 401 for a
            // session that may well be live).
            Err(e) => {
                tracing::warn!(error = %e, "session validation failed");
                return SourceOutcome::Unavailable;
            }
        };

        // Reflect the *current* user state (admin grant/revoke, deactivation)
        // rather than anything cached on the session row.
        match forge_db::user_dao::find_user_by_id(&self.pool, session.user_id).await {
            Ok(Some(user)) if user.active => SourceOutcome::Authenticated(Principal::User {
                user_id: user.id,
                token_id: None,
                is_admin: user.is_admin,
                method: crate::auth::AuthMethod::Session,
            }),
            // The session points at a vanished or deactivated user: it grants
            // nothing, so clear it like an expired one.
            Ok(_) => SourceOutcome::Stale,
            Err(e) => {
                tracing::warn!(error = %e, "session user lookup failed");
                SourceOutcome::Unavailable
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

/// More than one cookie of the same name in a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateCookie;

/// The value of the only cookie called `name`, `Ok(None)` when absent, or
/// [`DuplicateCookie`] when the request carries it more than once — which a
/// browser does when another site on a parent domain, or a response for a
/// narrower path, set a cookie of the same name. Credentials must not pick
/// one of them.
pub fn unique_cookie_value(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, DuplicateCookie> {
    let mut found = None;
    for header in headers.get_all(http::header::COOKIE) {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=') {
                if k.trim() == name && found.replace(v.trim().to_string()).is_some() {
                    return Err(DuplicateCookie);
                }
            }
        }
    }
    Ok(found)
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

    #[tokio::test]
    async fn session_lookup_error_is_unavailable_not_invalid() {
        // A closed pool fails every query, as an exhausted or unreachable one
        // does: the cookie could not be checked, so fail closed with 503
        // rather than a 401 for a session that may be live.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://forge@localhost/forge")
            .expect("lazy pool");
        pool.close().await;
        let sessions = SessionService::new(
            pool.clone(),
            chrono::Duration::hours(1),
            chrono::Duration::hours(8),
        );
        let source = SessionCookieSource::new(sessions, pool, false);
        assert_eq!(
            source
                .resolve(
                    &headers_with_cookie("forge_session=secret-xyz"),
                    "127.0.0.1".parse().unwrap()
                )
                .await,
            SourceOutcome::Unavailable
        );
    }

    #[test]
    fn unique_cookie_value_refuses_duplicates() {
        let h = headers_with_cookie("a=1; forge_session=only");
        assert_eq!(
            unique_cookie_value(&h, SESSION_COOKIE),
            Ok(Some("only".into()))
        );
        assert_eq!(
            unique_cookie_value(&headers_with_cookie("a=1"), SESSION_COOKIE),
            Ok(None)
        );
        let h = headers_with_cookie("forge_session=mine; forge_session=planted");
        assert_eq!(
            unique_cookie_value(&h, SESSION_COOKIE),
            Err(DuplicateCookie)
        );
        // Across several `Cookie` headers too.
        let mut h = headers_with_cookie("forge_session=mine");
        h.append(COOKIE, "forge_session=planted".parse().unwrap());
        assert_eq!(
            unique_cookie_value(&h, SESSION_COOKIE),
            Err(DuplicateCookie)
        );
        // The prefixed name is a different cookie.
        let h = headers_with_cookie("forge_session=x; __Host-forge_session=y");
        assert_eq!(
            unique_cookie_value(&h, session_cookie_name(true)),
            Ok(Some("y".into()))
        );
    }
}
