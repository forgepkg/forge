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
//!
//! Independently of the credential, a state-changing request that a browser
//! labels as cross-site (`Sec-Fetch-Site`, or a foreign `Origin`) is refused
//! with **403** before authentication — this covers Basic credentials a
//! browser cached from the `/v3` login prompt, which the token cannot.
//!
//! ## Stale session cookies
//! A session cookie that no longer names a live session is treated as absent
//! (anonymous policy applies) and cleared on the response, so an expired
//! session never locks the browser out of the login page or the SPA.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
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
    /// Whether cookies are issued with `Secure` (HTTPS deployment); used when
    /// clearing a stale session cookie.
    pub cookie_secure: bool,
    /// The deployment's own origin (`scheme://host[:port]` of
    /// `server.public_base_url`), accepted as a same-origin `Origin` header.
    pub public_origin: Option<String>,
}

/// Refuse a state-changing request a **browser** marked as cross-site.
///
/// The session-cookie CSRF token does not cover credentials a browser caches
/// and replays on its own — HTTP Basic typed into the native prompt `/v3`
/// raises, in particular — so a cross-site `<form>` could otherwise drive a
/// body-less admin POST with them. Browsers label every request with
/// `Sec-Fetch-Site` (and send `Origin` on non-GET requests); NuGet clients and
/// other non-browser callers send neither and are unaffected.
///
/// * `Sec-Fetch-Site` present: only `same-origin` and `none` (user-initiated)
///   pass — `same-site` is refused too, since a sibling subdomain is not
///   necessarily trusted.
/// * Otherwise (older browsers): an `Origin` header must match the configured
///   public origin or the request's own `Host`; `Origin: null` is refused.
fn cross_site_browser_request(headers: &HeaderMap, public_origin: Option<&str>) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return !matches!(site.trim(), "same-origin" | "none");
    }
    let Some(origin) = headers.get(header::ORIGIN) else {
        return false;
    };
    let Ok(origin) = origin.to_str() else {
        return true;
    };
    let origin = origin.trim().trim_end_matches('/');
    if public_origin.is_some_and(|p| p.eq_ignore_ascii_case(origin)) {
        return false;
    }
    let Ok(parsed) = url::Url::parse(origin) else {
        return true; // includes the opaque `null` origin
    };
    let Some(host) = parsed.host_str() else {
        return true;
    };
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let request_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    !request_host.eq_ignore_ascii_case(&authority)
}

/// The `scheme://host[:port]` origin of a base URL, if it parses.
pub fn origin_of(base_url: &str) -> Option<String> {
    let url = url::Url::parse(base_url).ok()?;
    match url.origin() {
        o @ url::Origin::Tuple(..) => Some(o.ascii_serialization()),
        url::Origin::Opaque(_) => None,
    }
}

/// `Set-Cookie` value that clears the session cookie.
fn clear_session_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure_attr}")
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

    if !req.method().is_safe()
        && cross_site_browser_request(req.headers(), layer.public_origin.as_deref())
    {
        return (StatusCode::FORBIDDEN, "cross-site request refused").into_response();
    }

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
    let mut resp = next.run(req).await;
    // A dead session cookie continues as anonymous/unauthenticated; drop it
    // from the browser so it stops riding along — unless the handler set the
    // cookie itself (a fresh login on this very request).
    if resolved.stale_ambient && !resp.headers().contains_key(header::SET_COOKIE) {
        if let Ok(v) = HeaderValue::from_str(&clear_session_cookie(layer.cookie_secure)) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
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
            cookie_secure: false,
            public_origin: Some("https://forge.example".into()),
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

    /// A cookie source whose session has expired.
    struct StaleCookieStub;

    #[async_trait::async_trait]
    impl PrincipalSource for StaleCookieStub {
        async fn resolve(&self, headers: &http::HeaderMap, _ip: IpAddr) -> SourceOutcome {
            if cookie_value(headers, SESSION_COOKIE).is_some() {
                SourceOutcome::Stale
            } else {
                SourceOutcome::NoCredentials
            }
        }
        fn is_ambient(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn stale_session_cookie_does_not_block_login_or_pages_and_is_cleared() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(StaleCookieStub)];
        let app = post_app(layer(sources, AnonPolicy::Off));
        for (method, uri, want) in [
            ("POST", "/auth/login", "login"),
            ("GET", "/admin/thing", "read"),
        ] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("cookie", "forge_session=expired")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{method} {uri}");
            let cleared = resp
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(
                cleared.starts_with("forge_session=;") && cleared.contains("Max-Age=0"),
                "stale cookie cleared on {uri}: {cleared}"
            );
            assert_eq!(body_string(resp).await, want);
        }
    }

    #[tokio::test]
    async fn stale_session_cookie_mutation_is_not_authenticated() {
        // A dead cookie downgrades to Unauthenticated; the (admin) handler's own
        // authz then refuses it. Here the handler is unguarded, so just check the
        // principal the handler would see.
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(StaleCookieStub)];
        let resp = app(layer(sources, AnonPolicy::Off))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", "forge_session=expired")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_string(resp).await, "unauthenticated");
    }

    #[tokio::test]
    async fn cross_site_browser_mutations_are_refused_before_auth() {
        // Basic credentials a browser cached from the `/v3` prompt are replayed
        // on a cross-site form POST; the fetch-metadata / Origin check stops it
        // even though Basic is CSRF-token exempt.
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(StubSource {
            outcome: SourceOutcome::Authenticated(Principal::User {
                user_id: 1,
                token_id: None,
                is_admin: true,
            }),
            require_header: true,
        })];
        let app = post_app(layer(sources, AnonPolicy::Off));
        let send = |headers: Vec<(&'static str, &'static str)>| {
            let app = app.clone();
            async move {
                let mut b = Request::builder()
                    .method("POST")
                    .uri("/admin/thing")
                    .header(AUTHORIZATION, "Basic x")
                    .header(header::HOST, "forge.internal:8421");
                for (k, v) in headers {
                    b = b.header(k, v);
                }
                app.oneshot(b.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status()
            }
        };
        // Refused.
        for h in [
            vec![("sec-fetch-site", "cross-site")],
            vec![("sec-fetch-site", "same-site")],
            vec![("origin", "https://evil.example")],
            vec![("origin", "null")],
        ] {
            assert_eq!(send(h.clone()).await, StatusCode::FORBIDDEN, "{h:?}");
        }
        // Allowed: non-browser client, same-origin fetch metadata, the public
        // origin, and an Origin matching the request's own Host.
        for h in [
            vec![],
            vec![("sec-fetch-site", "same-origin")],
            vec![("origin", "https://forge.example")],
            vec![("origin", "http://forge.internal:8421")],
        ] {
            assert_eq!(send(h.clone()).await, StatusCode::OK, "{h:?}");
        }
    }

    #[test]
    fn origin_of_strips_path_and_default_port() {
        assert_eq!(
            origin_of("https://forge.example/some/path").as_deref(),
            Some("https://forge.example")
        );
        assert_eq!(
            origin_of("http://localhost:8421").as_deref(),
            Some("http://localhost:8421")
        );
        assert_eq!(origin_of("not a url"), None);
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
