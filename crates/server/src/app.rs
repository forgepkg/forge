//! Application assembly: build the axum [`Router`], the principal middleware
//! layer, and the startup routine (connect, migrate, bootstrap admin).

use std::sync::Arc;

use crate::auth::WorkloadIdentitySource;
use anyhow::Context;
use axum::routing::any;
use axum::Router;
use forge_core::auth::session_source::SessionCookieSource;
use forge_core::auth::token::{BasicAuthSource, PrincipalSource, TokenHeaderSource};
use forge_db::authz_dao;
use forge_db::user_dao::{self, NewUser};
use sqlx::PgPool;

use crate::admin::admin_router;
use crate::auth::auth_router;
use crate::browse::browse_router;
use crate::config::Config;
use crate::dispatch::dispatch;
use crate::me::me_router;
use crate::me_tokens::me_tokens_router;
use crate::middleware::{attach_principal, PrincipalLayer};
use crate::state::AppState;
use crate::web_ui::spa_service;

/// Build the principal middleware layer from the assembled [`AppState`].
///
/// Sources are ordered: the `X-NuGet-ApiKey` token header first, then HTTP
/// Basic (token-in-basic, with optional password fallback), then the
/// `forge_session` cookie. The cookie source is **last** so that API
/// credentials (tokens) always win for NuGet clients, and the browser session
/// only resolves a principal when no API credential was presented. A session
/// cookie that fails validation reports `Invalid`, which the resolver turns
/// into a 401 (never downgraded to anonymous).
///
/// 12.7: the Basic source's password path asks [`crate::auth::RealmAuth`] for
/// the chain on every attempt, so admin realm edits apply without a restart
/// (and the wire path stays disabled unless `auth.allow_password_basic` or an
/// enabled credential-forwarding realm allows it). The session source is
/// always mounted — local password logins mint sessions too.
pub fn principal_layer(state: &AppState) -> anyhow::Result<PrincipalLayer> {
    let pool = &state.pool;
    let sources: Vec<Box<dyn PrincipalSource>> = vec![
        // WIF first (slice 12.8): a presented JWT whose `iss` names a configured
        // workload_identity realm is claimed here — including one passed as the
        // `X-NuGet-ApiKey` or the Basic password — so it is never treated as an
        // opaque token or forwarded upstream as a password. A non-WIF secret
        // returns NoCredentials and falls through to the sources below.
        Box::new(WorkloadIdentitySource::new(
            state.realms.clone(),
            pool.clone(),
        )),
        Box::new(TokenHeaderSource::new(pool.clone())),
        Box::new(BasicAuthSource::with_source(
            pool.clone(),
            state.realms.clone(),
        )),
        Box::new(SessionCookieSource::new(
            state.sessions.clone(),
            pool.clone(),
        )),
    ];

    let anon = state.config.anon_policy().context("anonymous policy")?;
    let trusted = state
        .config
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
/// * `/admin/me/tokens` — self-service token management (any signed-in session
///   user; NOT admin-gated).
/// * `/admin/...` — admin REST API (admin-only).
/// * `/browse/...` — read-side browse / search (signed-in users only; per-repo
///   read authz enforced inside the handlers).
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
    let admin = admin_router(state.clone());

    let mut app = Router::new()
        // Liveness / readiness probes (unauthenticated, dependency-light).
        .merge(crate::health::health_router())
        .merge(me_router())
        // Self-service tokens: any signed-in (session) user manages their own
        // tokens here; mounted like `/admin/me`, outside the admin gate.
        .merge(me_tokens_router())
        .nest("/admin", admin)
        .merge(browse_router())
        // Login / session surface (12.7): always mounted — local-password
        // login and sessions exist independent of OIDC; the `/auth/oidc/*`
        // endpoints answer 404 themselves when no enabled oidc realm exists.
        .merge(auth_router())
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
    // Request spans (method, path, status, latency) for every route; emitted
    // at DEBUG, so `RUST_LOG=tower_http=debug` turns on an access log.
    .layer(tower_http::trace::TraceLayer::new_for_http())
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

    let user = user_dao::insert_user(
        pool,
        NewUser::local(ba.username.clone(), password_hash, true, true),
    )
    .await
    .context("insert bootstrap admin")?;

    // §12.4 Phase 5: the bootstrap admin is granted the built-in `admin` role,
    // not just the slice-1 `is_admin` flag, so it is an admin under fine-grained
    // RBAC even after the `is_admin` column is eventually dropped. Idempotent.
    if let Some(admin_role_id) = authz_dao::role_id_by_name(pool, authz_dao::ADMIN_ROLE)
        .await
        .context("look up admin role")?
    {
        authz_dao::assign_role(pool, user.id, admin_role_id)
            .await
            .context("grant admin role to bootstrap admin")?;
    }

    tracing::warn!(
        username = %ba.username,
        "created bootstrap admin from config; change its password as soon as possible"
    );
    Ok(())
}

/// One-shot import of the legacy `[oidc]` / `[auth.upstream_basic]` config
/// blocks into `auth_realm` rows (12.7). Delegates to
/// [`crate::auth::seed_auth_realms`]; call on every boot — a `forge_setting`
/// marker makes it a no-op after the first import.
pub async fn ensure_auth_realms(config: &Config, pool: &PgPool) -> anyhow::Result<()> {
    crate::auth::seed_auth_realms(config, pool)
        .await
        .context("seed auth realms")
}

/// Re-apply the idempotent behavior-preserving RBAC legacy mapping on boot
/// (§12.4 Phase 5).
///
/// Migration `0007` already ran this once and recorded the install-wide
/// `legacy_open_access` default (open on upgrade, closed on a fresh install).
/// Calling it again here folds in rows that arrived *after* that migration —
/// e.g. a repository whose `anonymous_read` was flipped on, an `is_admin` user
/// created out-of-band, or (on a legacy-open install) any newly-created user
/// that should inherit the `authenticated` role. Every write is an idempotent
/// upsert, so on a fresh / already-converged install this is a cheap no-op.
///
/// It never *opens* a fresh install: the `authenticated` auto-assignment inside
/// the routine is gated on the `legacy_open_access` setting, which is `false`
/// for fresh installs.
pub async fn ensure_legacy_rbac(pool: &PgPool) -> anyhow::Result<()> {
    authz_dao::apply_legacy_migration(pool)
        .await
        .context("apply legacy RBAC migration")?;
    Ok(())
}
