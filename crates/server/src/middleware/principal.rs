//! Principal-resolution middleware (spec §5, plan 10.2).
//!
//! Runs an **ordered** list of [`PrincipalSource`]s (token header, then HTTP
//! Basic) against each request, resolves the client IP behind trusted proxies,
//! and attaches the resulting [`Principal`] as a request extension for
//! downstream handlers (repo dispatch, admin API).
//!
//! Security rules (enforced by [`forge_core::auth::token::resolve_principal`]):
//! * The first source that authenticates wins.
//! * If any source reports credentials were **present but invalid**, the request
//!   is rejected with **401** — bad credentials are never downgraded to
//!   anonymous.
//! * With no credentials, the anonymous policy decides between
//!   [`Principal::Anonymous`] and [`Principal::Unauthenticated`]; the latter is
//!   still passed downstream (authorization, not authentication, returns 401/403
//!   for protected resources).
//!
//! ## CSRF (cookie-authenticated mutations)
//! A request authenticated by an **ambient** credential (the `forge_session`
//! cookie, which the browser attaches on its own) that is not a safe method
//! (anything but GET/HEAD/OPTIONS/TRACE) must carry the session's
//! double-submit token in `X-CSRF-Token`, or it is refused with **403** before
//! any handler runs. This covers every router family (`/admin/**`,
//! `/admin/me/tokens`, `/browse`, cookie-authenticated `/v3` mutations) in one
//! place. Requests authenticated by an explicit credential (API key, Basic,
//! workload JWT) cannot be forged cross-site and are exempt, as are the
//! pre-session login endpoints ([`CSRF_EXEMPT_PATHS`]).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use forge_core::auth::client_ip::{resolve_client_ip, AnonPolicy};
use forge_core::auth::principal::Principal;
use forge_core::auth::session_source::{cookie_value, SESSION_COOKIE};
use forge_core::auth::token::{resolve_principal_with_origin, AuthError, PrincipalSource};
use forge_core::session::{csrf_token_matches, SessionService};
use ipnet::IpNet;

/// The header carrying the per-session double-submit CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Pre-session endpoints exempt from the CSRF layer: they authenticate a *new*
/// login from the request body and never act on the presented session, so a
/// stale cookie in the browser must not block signing in again. (Both require
/// a JSON body, which a cross-site form cannot send without a CORS preflight.)
pub const CSRF_EXEMPT_PATHS: &[&str] = &["/auth/login", "/auth/identify"];

/// Everything the middleware needs, shared via the router layer.
///
/// Built once at startup from the config + pool and cloned per request.
#[derive(Clone)]
pub struct PrincipalLayer {
    /// Ordered credential sources (token header first, then Basic).
    pub sources: Arc<Vec<Box<dyn PrincipalSource>>>,
    /// Trusted proxy CIDRs for `X-Forwarded-For` resolution.
    pub trusted_proxies: Arc<Vec<IpNet>>,
    /// Anonymous-access policy.
    pub anon: Arc<AnonPolicy>,
    /// Session service used to check the CSRF token of cookie-authenticated
    /// mutations. `None` ⇒ such requests are refused (fail closed).
    pub sessions: Option<SessionService>,
}

/// Resolve the socket peer for a request.
///
/// Prefers axum's [`ConnectInfo`] (set when the app is served with
/// `into_make_service_with_connect_info`); falls back to loopback if absent
/// (e.g. in-process tower tests that don't set it — those exercise the auth
/// chain, not IP policy).
fn peer_ip<B>(req: &Request<B>) -> IpAddr {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

/// Axum middleware: resolve and attach a [`Principal`] extension.
pub async fn attach_principal(
    State(layer): State<PrincipalLayer>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let peer = peer_ip(&req);

    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let client_ip = resolve_client_ip(peer, xff.as_deref(), &layer.trusted_proxies);

    let resolved =
        match resolve_principal_with_origin(&layer.sources, req.headers(), client_ip, &layer.anon)
            .await
        {
            Ok(r) => r,
            Err(AuthError::Unauthorized) => {
                return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
            }
        };

    if resolved.ambient && !req.method().is_safe() && !CSRF_EXEMPT_PATHS.contains(&req.uri().path())
    {
        if let Err(denied) = check_csrf(layer.sessions.as_ref(), req.headers()).await {
            return denied;
        }
    }

    req.extensions_mut().insert(resolved.principal);
    next.run(req).await
}

/// Enforce the double-submit CSRF token for a cookie-authenticated mutation:
/// `X-CSRF-Token` must equal the presented session's stored `csrf_secret`
/// (constant-time). Missing / wrong token → 403.
async fn check_csrf(
    sessions: Option<&SessionService>,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let forbidden = || (StatusCode::FORBIDDEN, "missing or invalid csrf token").into_response();
    let (Some(sessions), Some(secret)) = (sessions, cookie_value(headers, SESSION_COOKIE)) else {
        return Err(forbidden());
    };
    let presented = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match sessions.validate(&secret).await {
        Ok(Some(session)) if csrf_token_matches(presented, &session.csrf_secret) => Ok(()),
        Ok(_) => Err(forbidden()),
        Err(e) => {
            tracing::warn!(error = %e, "csrf session validate failed");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response())
        }
    }
}

/// Extractor-free helper: read the [`Principal`] a prior `attach_principal`
/// layer placed on the request. Panics only if the layer is missing (a wiring
/// bug), which is preferable to silently treating every caller as anonymous.
pub fn principal_of<B>(req: &Request<B>) -> Principal {
    *req.extensions()
        .get::<Principal>()
        .expect("principal extension missing; attach_principal layer not mounted")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use forge_core::auth::token::SourceOutcome;
    use http::header::AUTHORIZATION;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// A stub source returning a fixed outcome, gated on whether the request
    /// carried an auth header (so "no credentials" is realistic).
    struct StubSource {
        outcome: SourceOutcome,
        /// Only emit `outcome` when the `Authorization` header is present;
        /// otherwise report `NoCredentials`.
        require_header: bool,
    }

    #[async_trait::async_trait]
    impl PrincipalSource for StubSource {
        async fn resolve(&self, headers: &http::HeaderMap, _ip: IpAddr) -> SourceOutcome {
            if self.require_header && !headers.contains_key(AUTHORIZATION) {
                return SourceOutcome::NoCredentials;
            }
            self.outcome
        }
    }

    /// Build a tiny app whose single handler echoes the resolved principal.
    fn app(layer: PrincipalLayer) -> Router {
        async fn echo(req: Request<Body>) -> Response {
            let p = principal_of(&req);
            let label = match p {
                Principal::User { is_admin, .. } => format!("user:{is_admin}"),
                Principal::Workload { role_id, .. } => format!("workload:{role_id}"),
                Principal::Anonymous { .. } => "anonymous".to_string(),
                Principal::Unauthenticated => "unauthenticated".to_string(),
            };
            label.into_response()
        }
        Router::new()
            .route("/", get(echo))
            .layer(axum::middleware::from_fn_with_state(
                layer.clone(),
                attach_principal,
            ))
            .with_state(layer)
    }

    fn layer(sources: Vec<Box<dyn PrincipalSource>>, anon: AnonPolicy) -> PrincipalLayer {
        PrincipalLayer {
            sources: Arc::new(sources),
            trusted_proxies: Arc::new(vec![]),
            anon: Arc::new(anon),
            sessions: None,
        }
    }

    /// A stub *ambient* (cookie-like) source: authenticates whenever a
    /// `forge_session` cookie is present.
    struct AmbientStub;

    #[async_trait::async_trait]
    impl PrincipalSource for AmbientStub {
        async fn resolve(&self, headers: &http::HeaderMap, _ip: IpAddr) -> SourceOutcome {
            if cookie_value(headers, SESSION_COOKIE).is_some() {
                SourceOutcome::Authenticated(Principal::User {
                    user_id: 1,
                    token_id: None,
                    is_admin: true,
                })
            } else {
                SourceOutcome::NoCredentials
            }
        }
        fn is_ambient(&self) -> bool {
            true
        }
    }

    fn post_app(layer: PrincipalLayer) -> Router {
        Router::new()
            .route("/admin/thing", axum::routing::post(|| async { "done" }))
            .route("/auth/login", axum::routing::post(|| async { "login" }))
            .route("/admin/thing", get(|| async { "read" }))
            .layer(axum::middleware::from_fn_with_state(
                layer.clone(),
                attach_principal,
            ))
            .with_state(layer)
    }

    #[tokio::test]
    async fn cookie_authenticated_mutation_without_csrf_is_forbidden() {
        // No session service wired (fail closed) and no token: every
        // cookie-authenticated mutation is refused before the handler runs.
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(AmbientStub)];
        let app = post_app(layer(sources, AnonPolicy::Off));
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/admin/thing")
                        .header("cookie", "forge_session=s")
                        .header(CSRF_HEADER, "whatever")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method}");
        }
    }

    #[tokio::test]
    async fn cookie_reads_and_login_are_not_csrf_gated() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(AmbientStub)];
        let app = post_app(layer(sources, AnonPolicy::Off));
        let read = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/thing")
                    .header("cookie", "forge_session=s")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK, "safe methods pass");
        let login = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("cookie", "forge_session=s")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK, "login endpoint exempt");
    }

    #[tokio::test]
    async fn explicit_credential_mutation_is_csrf_exempt() {
        // Basic/API-key style (non-ambient) source wins: no CSRF token needed,
        // even if a session cookie rides along.
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource {
                outcome: SourceOutcome::Authenticated(Principal::User {
                    user_id: 2,
                    token_id: Some(9),
                    is_admin: false,
                }),
                require_header: true,
            }),
            Box::new(AmbientStub),
        ];
        let app = post_app(layer(sources, AnonPolicy::Off));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/thing")
                    .header(AUTHORIZATION, "Basic x")
                    .header("cookie", "forge_session=s")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    async fn body_string(resp: Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn authenticated_source_attaches_user() {
        let authed = Principal::User {
            user_id: 1,
            token_id: Some(2),
            is_admin: true,
        };
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(StubSource {
            outcome: SourceOutcome::Authenticated(authed),
            require_header: true,
        })];
        let app = app(layer(sources, AnonPolicy::Off));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(AUTHORIZATION, "Basic x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "user:true");
    }

    #[tokio::test]
    async fn invalid_credentials_yield_401() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(StubSource {
            outcome: SourceOutcome::Invalid,
            require_header: true,
        })];
        let app = app(layer(sources, AnonPolicy::All));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(AUTHORIZATION, "Basic bad")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Even though anon=All would otherwise allow anonymous, bad creds → 401.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_credentials_anonymous_when_allowed() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(StubSource {
            outcome: SourceOutcome::NoCredentials,
            require_header: true,
        })];
        let app = app(layer(sources, AnonPolicy::All));
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "anonymous");
    }

    #[tokio::test]
    async fn no_credentials_unauthenticated_when_anon_off() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(StubSource {
            outcome: SourceOutcome::NoCredentials,
            require_header: true,
        })];
        let app = app(layer(sources, AnonPolicy::Off));
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Unauthenticated is still passed downstream; authz decides 401/403.
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "unauthenticated");
    }
}
