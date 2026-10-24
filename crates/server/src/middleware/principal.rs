//! Principal-resolution middleware.
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
//! * If a source could not **check** the credentials (a database error looking
//!   up a token or session, a workload token's issuer that cannot be
//!   reached), the request fails closed with **503** and `Retry-After`: not
//!   anonymous, and not a 401 that would make a client discard a credential
//!   that may be valid. The CSRF check of a cookie-authenticated mutation
//!   answers the same when the session cannot be read.
//! * With no credentials, the anonymous policy decides between
//!   [`Principal::Anonymous`] and [`Principal::Unauthenticated`]; the latter is
//!   still passed downstream (authorization, not authentication, returns 401/403
//!   for protected resources). The policy is the one administrators set
//!   ([`crate::auth::AuthSettings`]): every request asks for it, which also
//!   keeps this instance's copy of the auth settings current
//!   ([`AnonSource::Settings`]).
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
//! ## Client IP and DNS rebinding
//! The client IP is resolved from the socket peer and **every**
//! `X-Forwarded-For` line behind the trusted proxies, with IPv4-mapped IPv6
//! addresses canonicalized ([`forge_core::auth::client_ip`]). A client whose
//! forwarded address is malformed is unknown and never allowlisted. The IP-allowlist
//! anonymous grant (anonymous mode `allowlist`) additionally requires the
//! request's `Host` to name this server (the host of `server.public_base_url`
//! or an entry of `server.allowed_hosts`): a DNS-rebinding page in an internal
//! user's browser reaches the server from an allowlisted IP but under its own
//! host name, and such a request is treated as unauthenticated instead.
//! Requests with credentials, and handlers that ignore the principal (health
//! probes), do not depend on the host.
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
use forge_core::auth::client_ip::{forwarded_for, resolve_client, AnonPolicy};
use forge_core::auth::principal::Principal;
use forge_core::auth::session_source::{session_cookie_name, unique_cookie_value};
use forge_core::auth::token::{resolve_principal_with_origin, AuthError, PrincipalSource};
use forge_core::session::{csrf_token_matches, SessionService};
use ipnet::IpNet;

use crate::auth::AuthSettingsCache;

/// The header carrying the per-session double-submit CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Pre-session endpoints exempt from the CSRF layer: they authenticate a *new*
/// login from the request body and never act on the presented session, so a
/// stale cookie in the browser must not block signing in again. (Both require
/// a JSON body, which a cross-site form cannot send without a CORS preflight.)
pub const CSRF_EXEMPT_PATHS: &[&str] = &[
    "/auth/login",
    "/auth/identify",
    "/auth/invitations/lookup",
    "/auth/invitations/accept",
];

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
    pub anon: AnonSource,
    /// Session service used to check the CSRF token of cookie-authenticated
    /// mutations. `None` ⇒ such requests are refused (fail closed).
    pub sessions: Option<SessionService>,
    /// Whether cookies are issued with `Secure` (HTTPS deployment); used when
    /// clearing a stale session cookie.
    pub cookie_secure: bool,
    /// The deployment's own origin (`scheme://host[:port]` of
    /// `server.public_base_url`), accepted as a same-origin `Origin` header.
    pub public_origin: Option<String>,
    /// Normalized host names ([`allowed_hosts`]) a request's `Host` must name
    /// for the IP-allowlist anonymous grant to apply (DNS-rebinding guard).
    pub allowed_hosts: Arc<Vec<String>>,
}

/// Where [`attach_principal`] gets the anonymous-access policy.
#[derive(Clone)]
pub enum AnonSource {
    /// This policy, always.
    Fixed(Arc<AnonPolicy>),
    /// The auth settings' anonymous mode and allowlist, as this instance has
    /// them; asking re-reads them once they are due.
    Settings(Arc<AuthSettingsCache>),
}

impl From<AnonPolicy> for AnonSource {
    fn from(policy: AnonPolicy) -> Self {
        AnonSource::Fixed(Arc::new(policy))
    }
}

/// The lowercase host of an authority (`host[:port]`, IPv6 in brackets),
/// without port or trailing dot; `None` if it does not parse.
fn normalize_host(authority: &str) -> Option<String> {
    let authority: http::uri::Authority = authority.trim().parse().ok()?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// The host names a request may address for the IP-allowlist anonymous grant:
/// the host of `public_base_url` plus each `extra` entry (`host` or
/// `host:port`; the port is ignored — a rebinding page cannot present this
/// server's host name, whatever the port). An unparsable entry is an error.
pub fn allowed_hosts(public_base_url: &str, extra: &[String]) -> Result<Vec<String>, String> {
    let mut hosts = Vec::with_capacity(extra.len() + 1);
    if let Some(host) = url::Url::parse(public_base_url)
        .ok()
        .and_then(|u| u.host_str().and_then(normalize_host))
    {
        hosts.push(host);
    }
    for entry in extra {
        match normalize_host(entry) {
            Some(host) => hosts.push(host),
            None => return Err(format!("invalid server.allowed_hosts entry {entry:?}")),
        }
    }
    Ok(hosts)
}

/// Whether the request addresses one of `allowed` (its `Host` header, or the
/// URI authority of an HTTP/2 request). A missing or unparsable host never
/// matches.
fn host_is_allowed<B>(req: &Request<B>, allowed: &[String]) -> bool {
    let host = match req.headers().get(header::HOST) {
        Some(value) => value.to_str().ok().and_then(normalize_host),
        None => req
            .uri()
            .authority()
            .and_then(|a| normalize_host(a.as_str())),
    };
    host.is_some_and(|host| allowed.contains(&host))
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
    format!(
        "{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure_attr}",
        name = session_cookie_name(secure)
    )
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

    // npm's exchange authenticates its ****** including JSON refusals.
    // Do not let the ordinary credential chain reject it with a plain-text 401.
    if req.method() == axum::http::Method::POST
        && req
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .is_some_and(|path| path.as_str() == crate::auth::NPM_TOKEN_EXCHANGE_PATH)
    {
        return next.run(req).await;
    }

    let xff = forwarded_for(req.headers());
    let client = resolve_client(peer, xff.as_deref(), &layer.trusted_proxies);
    let client_ip = client.ip;

    let settings;
    let policy = match &layer.anon {
        AnonSource::Fixed(policy) => policy.as_ref(),
        AnonSource::Settings(cache) => {
            settings = cache.current().await;
            &settings.anon
        }
    };
    // DNS-rebinding guard: the IP-allowlist grant applies only to requests
    // addressing this server by one of its own host names. It never applies to
    // a client whose address a malformed `X-Forwarded-For` hid: its `ip` is
    // the proxy's own.
    let anon = match policy.for_client(client) {
        AnonPolicy::Allowlist(_) if !host_is_allowed(&req, &layer.allowed_hosts) => {
            &AnonPolicy::Off
        }
        policy => policy,
    };

    let resolved =
        match resolve_principal_with_origin(&layer.sources, req.headers(), client_ip, anon).await {
            Ok(r) => r,
            Err(AuthError::Unauthorized) => {
                return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
            }
            Err(AuthError::Unavailable) => return auth_unavailable(),
        };

    if resolved.ambient && !req.method().is_safe() && !CSRF_EXEMPT_PATHS.contains(&req.uri().path())
    {
        if let Err(denied) =
            check_csrf(layer.sessions.as_ref(), req.headers(), layer.cookie_secure).await
        {
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
    cookie_secure: bool,
) -> Result<(), Response> {
    let forbidden = || (StatusCode::FORBIDDEN, "missing or invalid csrf token").into_response();
    let secret = unique_cookie_value(headers, session_cookie_name(cookie_secure))
        .ok()
        .flatten();
    let (Some(sessions), Some(secret)) = (sessions, secret) else {
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
            Err(auth_unavailable())
        }
    }
}

/// `Retry-After` (seconds) of [`auth_unavailable`].
const AUTH_RETRY_AFTER_SECS: &str = "10";

/// The **503** answer when authentication could not reach what it depends on
/// (the database, a workload token's issuer): no verdict on the credentials,
/// so a client retries instead of discarding them as wrong.
pub(crate) fn auth_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, AUTH_RETRY_AFTER_SECS)],
        "authentication temporarily unavailable",
    )
        .into_response()
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
    use forge_core::auth::session_source::{cookie_value, SESSION_COOKIE};
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
                Principal::User { user_id, .. } => format!("user:{user_id}"),
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
            anon: anon.into(),
            sessions: None,
            cookie_secure: false,
            public_origin: Some("https://forge.example".into()),
            allowed_hosts: Arc::new(
                allowed_hosts("https://forge.example", &["forge.internal".into()]).unwrap(),
            ),
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
                    method: forge_core::auth::AuthMethod::Password,
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
                    method: forge_core::auth::AuthMethod::Token,
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
                method: forge_core::auth::AuthMethod::Password,
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

    #[test]
    fn allowed_hosts_normalize_case_port_and_trailing_dot() {
        assert_eq!(
            allowed_hosts(
                "https://Forge.Example:8443/base",
                &[
                    "forge.internal:8421".into(),
                    "[::1]".into(),
                    "Mirror.Local.".into()
                ]
            )
            .unwrap(),
            vec!["forge.example", "forge.internal", "[::1]", "mirror.local"]
        );
        assert!(allowed_hosts("https://forge.example", &["a/b c".into()]).is_err());
        assert_eq!(normalize_host("[::1]:8421").as_deref(), Some("[::1]"));
    }

    #[tokio::test]
    async fn ip_allowlist_anonymous_requires_a_known_host() {
        // L7 (DNS rebinding): an allowlisted peer (loopback here) that names a
        // foreign host is not served anonymously; this server's own names are.
        let anon = AnonPolicy::allowlist_from_tokens(["loopback"]).unwrap();
        let app = app(layer(
            vec![Box::new(StubSource {
                outcome: SourceOutcome::NoCredentials,
                require_header: true,
            })],
            anon,
        ));
        let principal_for = |host: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut b = Request::builder().uri("/");
                if let Some(host) = host {
                    b = b.header(header::HOST, host);
                }
                body_string(app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap()).await
            }
        };
        for host in ["forge.example", "FORGE.example:443", "forge.internal:8421"] {
            assert_eq!(principal_for(Some(host)).await, "anonymous", "{host}");
        }
        for host in [
            Some("rebind.attacker.example"),
            Some("forge.example.evil"),
            None,
        ] {
            assert_eq!(principal_for(host).await, "unauthenticated", "{host:?}");
        }
    }

    #[tokio::test]
    async fn foreign_host_does_not_affect_other_policies_or_credentials() {
        // `all` grants regardless of host; credentials never depend on it.
        let anon_all = app(layer(
            vec![Box::new(StubSource {
                outcome: SourceOutcome::NoCredentials,
                require_header: true,
            })],
            AnonPolicy::All,
        ));
        let resp = anon_all
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "rebind.attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_string(resp).await, "anonymous");

        let authed = app(layer(
            vec![Box::new(StubSource {
                outcome: SourceOutcome::Authenticated(Principal::User {
                    user_id: 1,
                    token_id: Some(2),
                    method: forge_core::auth::AuthMethod::Token,
                }),
                require_header: true,
            })],
            AnonPolicy::allowlist_from_tokens(["loopback"]).unwrap(),
        ));
        let resp = authed
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "rebind.attacker.example")
                    .header(AUTHORIZATION, "Basic x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_string(resp).await, "user:1");
    }

    /// Echoes the resolved principal's IP (anonymous) for the XFF tests.
    fn ip_app(layer: PrincipalLayer) -> Router {
        async fn echo_ip(req: Request<Body>) -> Response {
            match principal_of(&req) {
                Principal::Anonymous { ip } => ip.to_string(),
                _ => "unauthenticated".to_string(),
            }
            .into_response()
        }
        Router::new()
            .route("/", get(echo_ip))
            .layer(axum::middleware::from_fn_with_state(
                layer.clone(),
                attach_principal,
            ))
            .with_state(layer)
    }

    #[tokio::test]
    async fn every_xff_line_is_walked_and_mapped_peers_are_canonical() {
        // M12: the client's own XFF line comes first; the trusted proxy (the
        // loopback peer here) appends the real client as a second line.
        let mut l = layer(
            vec![Box::new(StubSource {
                outcome: SourceOutcome::NoCredentials,
                require_header: true,
            })],
            AnonPolicy::All,
        );
        l.trusted_proxies = Arc::new(vec!["127.0.0.0/8".parse().unwrap()]);
        let resp = ip_app(l.clone())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-forwarded-for", "192.0.2.1")
                    .header("x-forwarded-for", "198.51.100.7")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_string(resp).await, "198.51.100.7");

        // An IPv4-mapped trusted peer is recognized as the IPv4 proxy.
        let mut req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", "::ffff:198.51.100.8")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "::ffff:127.0.0.1".parse().unwrap(),
            40000,
        )));
        let resp = ip_app(l).oneshot(req).await.unwrap();
        assert_eq!(body_string(resp).await, "198.51.100.8");
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
            method: forge_core::auth::AuthMethod::Token,
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
        assert_eq!(body_string(resp).await, "user:1");
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
    async fn npm_exchange_checks_its_own_credentials_but_not_cross_site_requests() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(StubSource {
            outcome: SourceOutcome::Invalid,
            require_header: true,
        })];
        let app = Router::new()
            .route(
                crate::auth::NPM_TOKEN_EXCHANGE_PATH,
                axum::routing::post(|| async {
                    (
                        StatusCode::UNAUTHORIZED,
                        axum::Json(serde_json::json!({"error": "exchange refused"})),
                    )
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                layer(sources, AnonPolicy::Off),
                attach_principal,
            ));
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/-/npm/v1/oidc/token/exchange/package/@acme%2fui")
                .header(AUTHORIZATION, "******")
        };
        let response = app
            .clone()
            .oneshot(request().body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            body_string(response).await,
            r#"{"error":"exchange refused"}"#
        );
        let response = app
            .oneshot(
                request()
                    .header("sec-fetch-site", "cross-site")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn unavailable_credential_check_yields_503_not_401() {
        // A token or session lookup that failed fails closed with 503, even
        // with anonymous access open; no later source (here a session cookie
        // that would authenticate) is consulted and the handler never runs.
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource {
                outcome: SourceOutcome::Unavailable,
                require_header: true,
            }),
            Box::new(AmbientStub),
        ];
        let resp = app(layer(sources, AnonPolicy::All))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(AUTHORIZATION, "Basic x")
                    .header(header::COOKIE, "forge_session=s")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], AUTH_RETRY_AFTER_SECS);
        assert_eq!(
            body_string(resp).await,
            "authentication temporarily unavailable"
        );
    }

    #[tokio::test]
    async fn csrf_check_with_the_database_down_yields_503_not_500() {
        // The session's CSRF secret cannot be read: no verdict on the token,
        // so the mutation answers the same 503 as any other credential check
        // the database could not answer, and the handler never runs.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://forge:forge@127.0.0.1:1/forge")
            .unwrap();
        let sessions =
            SessionService::new(pool, chrono::Duration::hours(1), chrono::Duration::hours(8));
        let sources: Vec<Box<dyn PrincipalSource>> = vec![Box::new(AmbientStub)];
        let mut layer = layer(sources, AnonPolicy::Off);
        layer.sessions = Some(sessions);
        let resp = post_app(layer)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/thing")
                    .header("cookie", "forge_session=s")
                    .header(CSRF_HEADER, "whatever")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], AUTH_RETRY_AFTER_SECS);
        assert_eq!(
            body_string(resp).await,
            "authentication temporarily unavailable"
        );
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
