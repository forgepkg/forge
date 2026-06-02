//! Application assembly: build the axum [`Router`], the principal middleware
//! layer, and the startup routine (connect, migrate, bootstrap admin).

use std::sync::Arc;

use anyhow::Context;
use axum::routing::any;
use axum::Router;
use forge_core::auth::session_source::SessionCookieSource;
use forge_core::auth::token::{BasicAuthSource, PrincipalSource, TokenHeaderSource};
use forge_core::session::SessionService;
use forge_db::user_dao::{self, NewUser};
use sqlx::PgPool;

use crate::admin::admin_router;
use crate::auth::auth_router;
use crate::browse::browse_router;
use crate::config::Config;
use crate::dispatch::dispatch;
use crate::me::me_router;
use crate::middleware::{attach_principal, PrincipalLayer};
use crate::state::AppState;
use crate::web_ui::spa_service;

/// Build the principal middleware layer from config + pool.
///
/// Sources are ordered: the `X-NuGet-ApiKey` token header first, then HTTP
/// Basic (token-in-basic, with optional password fallback), then — when OIDC is
/// enabled — the `forge_session` cookie. The cookie source is **last** so that
/// API credentials (tokens) always win for NuGet clients, and the browser
/// session only resolves a principal when no API credential was presented. A
/// session cookie that fails validation reports `Invalid`, which the resolver
/// turns into a 401 (never downgraded to anonymous).
pub fn principal_layer(config: &Config, pool: &PgPool) -> anyhow::Result<PrincipalLayer> {
    let mut sources: Vec<Box<dyn PrincipalSource>> = vec![
        Box::new(TokenHeaderSource::new(pool.clone())),
        Box::new(BasicAuthSource::new(
            pool.clone(),
            config.auth.allow_password_basic,
        )),
    ];

    // Append the session-cookie source only when OIDC login is enabled (it is
    // the only path that mints sessions).
    if let Some(oidc) = config.oidc.as_ref().filter(|o| o.enabled) {
        let sessions = SessionService::new(
            pool.clone(),
            chrono::Duration::seconds(oidc.session_idle_ttl_seconds as i64),
            chrono::Duration::seconds(oidc.session_absolute_ttl_seconds as i64),
        );
        sources.push(Box::new(SessionCookieSource::new(sessions, pool.clone())));
    }

    let anon = config.anon_policy().context("anonymous policy")?;
    let trusted = config
        .trusted_proxy_cidrs()
        .context("trusted proxy CIDRs")?;
    Ok(PrincipalLayer {
        sources: Arc::new(sources),
        trusted_proxies: Arc::new(trusted),
        anon: Arc::new(anon),
    })
}

/// Build the full application router:
/// * `/admin/me` — authenticated principal identity + capabilities (NOT
///   admin-gated; any authenticated user may read it).
/// * `/admin/...` — admin REST API (admin-only).
/// * `/browse/...` — read-side browse / search (per-repo `anonymous_read`
///   authz enforced inside the handlers).
/// * `/v3/{repo}/...` — NuGet V3 repository dispatch.
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
    let admin = admin_router();

    let mut app = Router::new()
        .merge(me_router())
        .nest("/admin", admin)
        .merge(browse_router())
        // Interactive OIDC login surface (slice 12.2). Mounted only when the
        // runtime was built (OIDC enabled + config valid); otherwise the
        // `/auth/oidc/*` paths simply 404 (and fall through to the SPA).
        .merge(if state.oidc.is_some() {
            auth_router()
        } else {
            Router::new()
        })
        // Everything under /v3/{repo} is handled by the dispatcher (which builds
        // the per-repo NuGet router internally). `any` covers GET/HEAD/PUT/POST
        // /DELETE; the dispatcher enforces authz per method.
        .route("/v3/{repo}", any(dispatch))
        .route("/v3/{repo}/{*rest}", any(dispatch));

    // Static SPA fallback, installed LAST so the API routers above always win
    // and only genuine UI paths fall through to `index.html`. Skipped for a
    // headless deployment (`web.enabled = false`).
    if state.config.web.enabled {
        app = app.fallback_service(spa_service(&state.config.web));
    }

    app.layer(axum::middleware::from_fn_with_state(
        layer.clone(),
        attach_principal,
    ))
    .with_state(state)
}

/// Create the bootstrap admin user if it does not already exist.
///
/// Logs a warning while the bootstrap password remains in use (the admin should
/// rotate it). A no-op when `auth.bootstrap_admin` is unset or the username
/// already exists.
pub async fn ensure_bootstrap_admin(config: &Config, pool: &PgPool) -> anyhow::Result<()> {
    let Some(ba) = &config.auth.bootstrap_admin else {
        return Ok(());
    };

    if user_dao::find_user_by_username(pool, &ba.username)
        .await
        .context("bootstrap admin lookup")?
        .is_some()
    {
        tracing::debug!(username = %ba.username, "bootstrap admin already exists; skipping");
        return Ok(());
    }

    let password = ba.password.clone();
    let password_hash = tokio::task::spawn_blocking(move || {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        use argon2::Argon2;
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
    })
    .await
    .context("hashing task")?
    .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?;

    user_dao::insert_user(
        pool,
        NewUser {
            username: ba.username.clone(),
            password_hash,
            is_admin: true,
            active: true,
        },
    )
    .await
    .context("insert bootstrap admin")?;

    tracing::warn!(
        username = %ba.username,
        "created bootstrap admin from config; change its password as soon as possible"
    );
    Ok(())
}
