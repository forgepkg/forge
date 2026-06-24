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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use forge_core::auth::client_ip::{resolve_client_ip, AnonPolicy};
use forge_core::auth::principal::Principal;
use forge_core::auth::token::{resolve_principal, AuthError, PrincipalSource};
use ipnet::IpNet;

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

    let principal =
        match resolve_principal(&layer.sources, req.headers(), client_ip, &layer.anon).await {
            Ok(p) => p,
            Err(AuthError::Unauthorized) => {
                return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
            }
        };

    req.extensions_mut().insert(principal);
    next.run(req).await
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
        }
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
