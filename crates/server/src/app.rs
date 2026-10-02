//! Application assembly: build the axum [`Router`], the principal middleware
//! layer, and the startup routine (connect, migrate, bootstrap admin).

use std::sync::Arc;

use crate::auth::WorkloadIdentitySource;
use anyhow::Context;
use axum::http::{header, HeaderValue};
use axum::routing::any;
use axum::Router;
use forge_core::auth::session_source::SessionCookieSource;
use forge_core::auth::token::{BasicAuthSource, PrincipalSource, TokenHeaderSource};
use forge_db::authz_dao;
use forge_db::model::AppUser;
use forge_db::user_dao::{self, NewUser};
use sqlx::PgPool;
use tower_http::set_header::SetResponseHeaderLayer;

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
/// cookie that no longer names a live session reports `Stale`: it is treated
/// as no credentials and cleared on the response (a 401 there would lock the
/// browser out of the login page itself).
///
/// 12.7: the Basic source's password path asks [`crate::auth::RealmAuth`] for
/// the chain on every attempt, so admin realm edits apply without a restart
/// (and the wire path stays disabled unless `auth.allow_password_basic` or an
/// enabled credential-forwarding realm allows it). The session source is
/// always mounted — local password logins mint sessions too — and every
/// state-changing request it authenticates must carry the session's CSRF
/// token (enforced by [`attach_principal`]).
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
        Box::new(
            BasicAuthSource::with_source(pool.clone(), state.realms.clone())
                .with_throttle(state.login_throttle.clone()),
        ),
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
        // Cookie-authenticated mutations must carry the session's CSRF token.
        sessions: Some(state.sessions.clone()),
        cookie_secure: state.cookie_secure,
        public_origin: crate::middleware::principal::origin_of(&state.config.public_base_url()),
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
    .with_state(state)
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
/// Logs a warning while the bootstrap password remains in use (the admin should
/// rotate it), and a loud one when the existing account still has the
/// placeholder password [`PLACEHOLDER_BOOTSTRAP_PASSWORD`]. A no-op when
/// `auth.bootstrap_admin` is unset.
pub async fn ensure_bootstrap_admin(config: &Config, pool: &PgPool) -> anyhow::Result<()> {
    let Some(ba) = &config.auth.bootstrap_admin else {
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

    let user = match user_dao::insert_user(
        pool,
        NewUser::local(ba.username.clone(), password_hash, true, true),
    )
    .await
    {
        Ok(user) => user,
        // A peer instance booting concurrently created it first: adopt that
        // account (it does the role grant) and make sure the marker exists.
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            let existing = user_dao::find_user_by_username(pool, &ba.username)
                .await
                .context("bootstrap admin lookup")?
                .context("bootstrap admin vanished right after a unique violation")?;
            record_bootstrap_marker(pool, &marker, existing.id).await?;
            return Ok(());
        }
        Err(e) => return Err(anyhow::Error::new(e).context("insert bootstrap admin")),
    };

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

/// One-shot import of the legacy `[oidc]` / `[auth.upstream_basic]` config
/// blocks into `auth_realm` rows (12.7). Delegates to
/// [`crate::auth::seed_auth_realms`]; call on every boot — a `forge_setting`
/// marker makes it a no-op after the first import. Pass the (bootstrapped)
/// envelope service when secret encryption is enabled so seeded realm secrets
/// are encrypted at rest.
pub async fn ensure_auth_realms(
    config: &Config,
    pool: &PgPool,
    envelope: Option<&forge_crypto::service::EnvelopeService>,
) -> anyhow::Result<()> {
    crate::auth::seed_auth_realms(config, pool, envelope)
        .await
        .context("seed auth realms")
}

/// Apply the behavior-preserving RBAC legacy mapping **once** per install
/// (§12.4 Phase 5).
///
/// Migration `0007` ran it and recorded the install-wide `legacy_open_access`
/// default (open on upgrade, closed on a fresh install). This boot hook runs it
/// one more time for installs that upgraded before the one-shot marker existed,
/// then records the `legacy_rbac_synced` marker: re-running it on every boot
/// would re-grant admin roles / anonymous grants an operator has since revoked
/// through RBAC (the routine only ever adds). It never *opens* a fresh install:
/// the `authenticated` auto-assignment is gated on `legacy_open_access`.
pub async fn ensure_legacy_rbac(pool: &PgPool) -> anyhow::Result<()> {
    if authz_dao::apply_legacy_migration_once(pool)
        .await
        .context("apply legacy RBAC migration")?
    {
        tracing::info!("applied the one-shot legacy RBAC mapping");
    }
    Ok(())
}
