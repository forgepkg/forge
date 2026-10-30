//! Application assembly: build the axum [`Router`], the principal middleware
//! layer, and the startup routine (connect, migrate, bootstrap admin).

use std::sync::Arc;
use std::time::Duration;

use crate::auth::{TrustedHeaderSource, WorkloadIdentitySource};
use anyhow::Context;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use forge_core::auth::session_source::SessionCookieSource;
use forge_core::auth::token::{BasicAuthSource, PrincipalSource, TokenHeaderSource};
use forge_core::net::deadline::HandlerDeadline;
use forge_db::authz_dao;
use forge_db::model::AppUser;
use forge_db::user_dao::{self, NewUser};
use sqlx::PgPool;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::RequestBodyTimeoutLayer;

use crate::admin::admin_router;
use crate::auth::auth_router;
use crate::browse::browse_router;
use crate::config::Config;
use crate::me::me_router;
use crate::me_tokens::me_tokens_router;
use crate::middleware::{attach_principal, AnonSource, PrincipalLayer};
use crate::state::AppState;
use crate::web_ui::spa_service;

/// Build the principal middleware layer from the assembled [`AppState`].
///
/// Sources are ordered: the `X-NuGet-ApiKey` token header first, then HTTP
/// Basic (token-in-basic, with optional password fallback), then the
/// `forge_session` cookie. The cookie source is **last** so that API
/// credentials (tokens) always win for NuGet clients, and the browser session
/// only resolves a principal when no API credential was presented. A session
/// cookie that no longer names a live session reports `Stale`: it is treated
/// as no credentials and cleared on the response (a 401 there would lock the
/// browser out of the login page itself).
///
/// The Basic source's password path asks [`crate::auth::RealmAuth`] for the
/// chain on every attempt, so admin realm edits apply without a restart
/// (the wire path holds only the realms that accept passwords from clients,
/// `accept_client_passwords`, and stays disabled without one). The
/// anonymous policy comes from the auth settings on every request too
/// ([`AnonSource::Settings`]). The session source is
/// always mounted — local password logins mint sessions too — and every
/// state-changing request it authenticates must carry the session's CSRF
/// token (enforced by [`attach_principal`]). The trusted-header realms come
/// after all of them, in place of the anonymous policy, and only for a
/// request a trusted proxy forwarded ([`TrustedHeaderSource`]).
pub fn principal_layer(state: &AppState) -> anyhow::Result<PrincipalLayer> {
    let pool = &state.pool;
    let sources: Vec<Box<dyn PrincipalSource>> = vec![
        // WIF first: a presented JWT whose `iss` names a configured
        // workload_identity realm is claimed here — including one passed as the
        // `X-NuGet-ApiKey` or the Basic password — so it is never treated as an
        // opaque token or forwarded upstream as a password. A non-WIF secret
        // returns NoCredentials and falls through to the sources below.
        Box::new(WorkloadIdentitySource::new(
            state.realms.clone(),
            pool.clone(),
        )),
        Box::new(TokenHeaderSource::new(pool.clone())),
        Box::new(
            BasicAuthSource::with_source(pool.clone(), state.realms.clone())
                .with_throttle(state.login_throttle.clone())
                .with_authz_cache(state.cache.clone()),
        ),
        Box::new(SessionCookieSource::new(
            state.sessions.clone(),
            pool.clone(),
            state.cookie_secure,
        )),
    ];

    let trusted = state
        .config
        .trusted_proxy_cidrs()
        .context("trusted proxy CIDRs")?;
    Ok(PrincipalLayer {
        sources: Arc::new(sources),
        trusted_header: Some(Arc::new(TrustedHeaderSource::new(
            state.realms.clone(),
            pool.clone(),
        ))),
        trusted_proxies: Arc::new(trusted),
        anon: AnonSource::Settings(state.auth_settings.clone()),
        // Cookie-authenticated mutations must carry the session's CSRF token.
        sessions: Some(state.sessions.clone()),
        cookie_secure: state.cookie_secure,
        public_origin: crate::middleware::principal::origin_of(&state.config.public_base_url()),
        // DNS-rebinding guard for the trusted-header realms.
        allowed_hosts: Arc::new(
            crate::middleware::principal::allowed_hosts(
                &state.config.public_base_url(),
                &state.config.server.allowed_hosts,
            )
            .map_err(anyhow::Error::msg)?,
        ),
    })
}

/// Build the full application router:
/// * `/admin/me` — authenticated principal identity + capabilities (NOT
///   admin-gated; any authenticated user may read it).
/// * `/admin/me/tokens` — self-service token management (any signed-in session
///   user; NOT admin-gated).
/// * `/admin/...` — admin REST API (admin-only).
/// * `/browse/...` — read-side browse / search (signed-in users only; per-repo
///   read authz enforced inside the handlers).
/// * `/repository/{repo}/...` — repositories of every non-Docker format,
///   each served by its format's plugin ([`crate::plugins`]).
/// * everything else — the SPA, whose admin screens live under `/manage/*`
///   (see [`crate::web_ui`]).
///
/// All branches run behind the principal middleware so every handler sees a
/// resolved [`forge_core::auth::principal::Principal`] extension.
///
/// Route precedence note: `/admin/me` is merged as its own route and the
/// admin-only API is `nest`ed at `/admin`. A nested router only matches paths
/// *under* its prefix that the nest itself defines, so the standalone
/// `/admin/me` route is matched directly (and is not subject to the admin
/// router's `require_admin` gate).
pub fn build_router(state: AppState, layer: PrincipalLayer) -> Router {
    let admin = admin_router(state.clone());

    let feeds = std::sync::Arc::new(vec!["/repository".to_string()]);
    let mut app = Router::new()
        // Liveness / readiness probes (unauthenticated, dependency-light).
        .merge(crate::health::health_router())
        .merge(me_router())
        // Self-service tokens: any signed-in (session) user manages their own
        // tokens here; mounted like `/admin/me`, outside the admin gate.
        .merge(me_tokens_router())
        .nest("/admin", admin)
        .merge(browse_router())
        // Login / session surface: always mounted — local-password
        // login and sessions exist independent of OIDC; the `/auth/oidc/*`
        // endpoints answer 404 themselves when no enabled oidc realm exists.
        .merge(auth_router())
        // Trusted publishing: a CI job's OIDC token for a short-lived API key
        // (the native NuGet and npm exchange paths and response shapes).
        .merge(crate::auth::token_exchange_router())
        // Forge's own OIDC issuer (discovery + JWKS), public: what an IdP
        // verifies the client assertions of a `federated_credential` realm
        // against. 404 until forge has signing keys.
        .merge(crate::auth::issuer_router());
    // The registry of the images format (Docker / OCI) under its mount,
    // `/v2`: clients always talk to `/v2/` at the host root; the registry
    // resolves repositories from the name (or the host) itself.
    let images = state.formats.images_plugin();
    if images.is_some() {
        let mount = forge_plugin::api::IMAGES_MOUNT;
        app = app
            .route(mount, any(crate::registry::registry))
            .route(&format!("{mount}/"), any(crate::registry::registry))
            .route(
                &format!("{mount}/{{*rest}}"),
                any(crate::registry::registry),
            );
    }
    // Every non-Docker repository shares this prefix. `any` covers
    // GET/HEAD/PUT/POST/DELETE; the dispatcher authorizes per method.
    app = app
        .route("/repository/{repo}", any(crate::plugins::dispatch))
        // A wildcard matches no empty rest: a files format's root listing
        // needs its own route.
        .route("/repository/{repo}/", any(crate::plugins::dispatch))
        .route("/repository/{repo}/{*rest}", any(crate::plugins::dispatch));

    // Static SPA fallback, installed LAST so the API routers above always win
    // and only genuine UI paths fall through to `index.html`. The admin UI
    // lives under `/manage/*`; `/admin/*` is the admin API's.
    let app = app.fallback_service(spa_service(&state.config.web));

    let hsts = state.cookie_secure;
    let recorder = state.traffic.recorder.clone();
    let public_base_url = state.config.public_base_url();
    let images = images.map(|p| p.implementation().clone());
    let server = state.config.server.clone();
    let app = app
        .layer(axum::middleware::from_fn_with_state(
            layer.clone(),
            attach_principal,
        ))
        // Caching and transport policy for every response, including the
        // ones the principal middleware answers itself.
        .layer(axum::middleware::from_fn(move |req, next| {
            response_policy(
                hsts,
                feeds.clone(),
                public_base_url.clone(),
                images.clone(),
                req,
                next,
            )
        }));
    // A stalled upload or a handler that never answers must not pin a task
    // and a connection forever (header reads are bounded in `serve`).
    let app = if server.body_idle_timeout_seconds > 0 {
        app.layer(RequestBodyTimeoutLayer::new(Duration::from_secs(
            server.body_idle_timeout_seconds,
        )))
    } else {
        app
    };
    // A proxy's first download of a package or layer may take longer
    // (`proxy.download_timeout_seconds`): it extends its request's deadline
    // (`forge_core::net::deadline`).
    let app = if server.request_timeout_seconds > 0 {
        let timeout = Duration::from_secs(server.request_timeout_seconds);
        app.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| async move {
                HandlerDeadline::new(timeout)
                    .run(next.run(req))
                    .await
                    .unwrap_or_else(|| StatusCode::REQUEST_TIMEOUT.into_response())
            },
        ))
    } else {
        app
    };
    app
        // Baseline browser hardening for the SPA and every API response (added only
        // when a handler did not set its own): no MIME sniffing, no framing
        // (clickjacking on the admin UI), no cross-origin referrer leakage.
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors 'none'"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        ))
        // Request spans (method, path, status, latency) for every route; emitted
        // at DEBUG, so `RUST_LOG=tower_http=debug` turns on an access log.
        .layer(tower_http::trace::TraceLayer::new_for_http())
        // The request's OpenTelemetry span and metrics, outermost so they
        // time and count every answer, the ones the layers above give
        // themselves (a timeout) included.
        .layer(axum::middleware::from_fn_with_state(
            recorder,
            crate::telemetry::track,
        ))
        .with_state(state)
}

/// `Vary` of every feed response: what a response may depend on besides the
/// URL, so a shared cache never hands one caller's answer to another.
const FEED_VARY: &str = "Authorization, Cookie, X-NuGet-ApiKey";

/// `Vary` of every registry (`/v2`) response.
const REGISTRY_VARY: &str = "Authorization, Cookie, Accept";

/// Response caching and transport policy:
///
/// * API responses (`/admin`, `/auth`, `/browse`) are `Cache-Control:
///   private, no-store` — they carry user data, tokens and CSRF secrets;
/// * feed responses (under `/repository`)
///   carry [`FEED_VARY`], and are `private,
///   no-store` whenever the request presented credentials, so a package
///   fetched with credentials is never stored by a shared cache or served to
///   someone else (the headers of a trusted-header realm's proxy count as
///   credentials: [`crate::middleware::principal::NamedByTrustedHeaders`]);
///   registry responses (`/v2/...`) likewise, with
///   [`REGISTRY_VARY`], and a 401 the authentication middleware answered
///   there gets the registry's Bearer challenge; Anonymous responses carry no `Cache-Control`;
/// * with an `https` public URL every response carries HSTS.
///
/// The SPA keeps its own cache headers (hashed assets are immutable).
async fn response_policy(
    hsts: bool,
    feeds: std::sync::Arc<Vec<String>>,
    public_base_url: String,
    images: Option<std::sync::Arc<dyn forge_plugin::FormatPlugin>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path();
    let under = |prefix: &str| crate::web_ui::is_under(path, prefix);
    let api = under("/admin") || under("/auth") || under("/browse") || under("/api");
    let feed = feeds.iter().any(|mount| under(mount));
    let registry = images
        .as_ref()
        .filter(|_| under(forge_plugin::api::IMAGES_MOUNT));
    let headers = req.headers();
    let credentials = headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key("x-nuget-apikey")
        || headers.contains_key(header::COOKIE);
    let mut resp = next.run(req).await;
    let credentials = credentials
        || resp
            .extensions()
            .get::<crate::middleware::principal::NamedByTrustedHeaders>()
            .is_some();
    if let Some(images) = registry {
        resp = crate::registry::amend_registry_rejection(&public_base_url, images.as_ref(), resp);
    }
    let registry = registry.is_some();
    let out = resp.headers_mut();
    if api || ((feed || registry) && credentials) {
        out.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }
    if feed {
        out.append(header::VARY, HeaderValue::from_static(FEED_VARY));
    }
    if registry {
        out.append(header::VARY, HeaderValue::from_static(REGISTRY_VARY));
    }
    if hsts && !out.contains_key(header::STRICT_TRANSPORT_SECURITY) {
        out.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    resp
}

/// `forge_setting` key prefix (`<prefix>:<username>`) recording that the
/// bootstrap admin was created, so a later deletion sticks across restarts.
pub const BOOTSTRAP_ADMIN_CREATED_KEY: &str = "bootstrap_admin_created";

/// The placeholder bootstrap-admin password shipped in the example and dev
/// configs. Startup config validation refuses it for new deployments, but an
/// account created with it earlier keeps it — there is no password-change
/// flow — so boot checks the stored hash too.
const PLACEHOLDER_BOOTSTRAP_PASSWORD: &str = "changeme";

/// Create the bootstrap admin user if it does not already exist and was never
/// created before (see [`BOOTSTRAP_ADMIN_CREATED_KEY`]).
///
/// Whenever the bootstrap username **exists**, the "created once" marker is
/// recorded (if missing) as well. That covers installs whose account predates
/// the marker and a boot that crashed between creating the account and
/// recording the marker; without it, deleting the account later would bring it
/// back — with full admin rights and the configured password — on the next
/// restart. A concurrent instance creating the account at the same moment is
/// handled the same way.
///
/// The name is a UPN (config validation): `admin@example.com` by default.
///
/// Logs a warning while the bootstrap password remains in use (the admin should
/// rotate it), and a loud one when the existing account still has the
/// placeholder password [`PLACEHOLDER_BOOTSTRAP_PASSWORD`]. When
/// `auth.bootstrap_admin` is unset (the documented production state once the
/// account exists) nothing is created, but the placeholder check still runs
/// for the default `admin@example.com` account and every account a marker
/// names.
pub async fn ensure_bootstrap_admin(config: &Config, pool: &PgPool) -> anyhow::Result<()> {
    let Some(ba) = &config.auth.bootstrap_admin else {
        warn_on_placeholder_accounts(pool).await;
        return Ok(());
    };
    let marker = format!("{BOOTSTRAP_ADMIN_CREATED_KEY}:{}", ba.username);

    if let Some(existing) = user_dao::find_user_by_username(pool, &ba.username)
        .await
        .context("bootstrap admin lookup")?
    {
        tracing::debug!(username = %ba.username, "bootstrap admin already exists; skipping");
        record_bootstrap_marker(pool, &marker, existing.id).await?;
        warn_if_placeholder_password(&existing).await;
        return Ok(());
    }

    // Create it only once: an operator who deleted the bootstrap account (e.g.
    // after setting up a real admin or an IdP) must not get it back — with
    // full admin rights and the password still in the environment — on the
    // next restart.
    if authz_dao::get_setting(pool, &marker)
        .await
        .context("bootstrap admin marker")?
        .is_some()
    {
        tracing::info!(
            username = %ba.username,
            "bootstrap admin was created before and has since been removed; not re-creating it"
        );
        return Ok(());
    }

    let password = ba.password.clone();
    let password_hash = tokio::task::spawn_blocking(move || {
        use argon2::Argon2;
        use argon2::PasswordHasher;
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
    })
    .await
    .context("hashing task")?
    .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?;

    // The account and its `admin` role in one transaction: an account left
    // without the role would not be an administrator.
    let mut tx = forge_db::begin(pool)
        .await
        .context("begin bootstrap admin")?;
    let user = match user_dao::insert_user(
        &mut *tx,
        NewUser::local(ba.username.clone(), password_hash, true),
    )
    .await
    {
        Ok(user) => user,
        // A peer instance booting concurrently created it first: adopt that
        // account (it does the role grant) and make sure the marker exists.
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            drop(tx);
            let existing = user_dao::find_user_by_username(pool, &ba.username)
                .await
                .context("bootstrap admin lookup")?
                .context("bootstrap admin vanished right after a unique violation")?;
            record_bootstrap_marker(pool, &marker, existing.id).await?;
            return Ok(());
        }
        Err(e) => return Err(anyhow::Error::new(e).context("insert bootstrap admin")),
    };

    let admin_role_id = authz_dao::role_id_by_name(&mut *tx, authz_dao::ADMIN_ROLE)
        .await
        .context("look up admin role")?
        .context("the built-in admin role is missing")?;
    authz_dao::assign_role(&mut *tx, user.id, admin_role_id)
        .await
        .context("grant admin role to bootstrap admin")?;
    tx.commit().await.context("commit bootstrap admin")?;
    // A crash before this line leaves the account without the marker; the
    // next boot records it (see the existing-account branch above).
    record_bootstrap_marker(pool, &marker, user.id).await?;

    tracing::warn!(
        username = %ba.username,
        "created bootstrap admin from config; change its password as soon as possible"
    );
    if ba.password == PLACEHOLDER_BOOTSTRAP_PASSWORD {
        warn_placeholder(&ba.username);
    }
    Ok(())
}

/// Record the bootstrap "created once" marker unless it is already there.
async fn record_bootstrap_marker(pool: &PgPool, marker: &str, user_id: i64) -> anyhow::Result<()> {
    if authz_dao::get_setting(pool, marker)
        .await
        .context("bootstrap admin marker")?
        .is_none()
    {
        authz_dao::set_setting(pool, marker, &user_id.to_string())
            .await
            .context("record bootstrap admin marker")?;
    }
    Ok(())
}

/// Whether `user`'s stored local password is the shipped placeholder
/// ([`PLACEHOLDER_BOOTSTRAP_PASSWORD`]). `false` for accounts without a local
/// password or with an unparseable hash. Runs argon2 on a blocking thread.
pub async fn has_placeholder_password(user: &AppUser) -> bool {
    let Some(stored) = user.password_hash.clone() else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        use argon2::{Argon2, PasswordHash, PasswordVerifier};
        PasswordHash::new(&stored)
            .map(|parsed| {
                Argon2::default()
                    .verify_password(PLACEHOLDER_BOOTSTRAP_PASSWORD.as_bytes(), &parsed)
                    .is_ok()
            })
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Boot-time placeholder check when no bootstrap admin is configured: the
/// default `admin@example.com` account and every account a "created once"
/// marker names.
/// Best effort — a lookup failure is logged, never fatal.
async fn warn_on_placeholder_accounts(pool: &PgPool) {
    let pattern = format!("{BOOTSTRAP_ADMIN_CREATED_KEY}:%");
    let markers: Vec<String> = match sqlx::query_scalar(
        "SELECT key FROM forge_setting WHERE key LIKE $1",
    )
    .bind(&pattern)
    .fetch_all(pool)
    .await
    {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!(error = %e, "bootstrap marker lookup failed; placeholder check limited to `admin`");
            Vec::new()
        }
    };
    let prefix = format!("{BOOTSTRAP_ADMIN_CREATED_KEY}:");
    let mut usernames: Vec<String> = markers
        .iter()
        .filter_map(|key| key.strip_prefix(&prefix).map(str::to_string))
        .collect();
    usernames.push(crate::config::DEFAULT_BOOTSTRAP_USERNAME.to_string());
    usernames.sort();
    usernames.dedup();
    for username in usernames {
        match user_dao::find_user_by_username(pool, &username).await {
            Ok(Some(user)) if user.active => warn_if_placeholder_password(&user).await,
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, %username, "placeholder password check failed"),
        }
    }
}

/// Boot-time check of an existing bootstrap account: warn loudly while it
/// still accepts the placeholder password. Startup is not refused — there is
/// no password-change flow to get out of that state.
async fn warn_if_placeholder_password(user: &AppUser) {
    if has_placeholder_password(user).await {
        warn_placeholder(&user.username);
    }
}

fn warn_placeholder(username: &str) {
    tracing::error!(
        username = %username,
        "SECURITY WARNING: the bootstrap admin account still accepts the placeholder password \"{PLACEHOLDER_BOOTSTRAP_PASSWORD}\" — \
         anyone who can reach this instance can sign in as an administrator. Create a real \
         admin (or configure an identity provider) and deactivate or delete this account."
    );
}

/// Import the legacy `[oidc]` / `[auth.upstream_basic]` config blocks into
/// `auth_realm` rows. Delegates to [`crate::auth::seed_auth_realms`]; call on
/// every boot — the first boot inserts the realms, later boots re-apply a
/// changed block only while its seeded row is untouched by the admin API (see
/// there for the drift detection). Seeded realm secrets are sealed with the
/// (bootstrapped) envelope service.
pub async fn ensure_auth_realms(
    config: &Config,
    pool: &PgPool,
    envelope: &forge_crypto::service::EnvelopeService,
) -> anyhow::Result<()> {
    crate::auth::seed_auth_realms(config, pool, envelope)
        .await
        .context("seed auth realms")
}
