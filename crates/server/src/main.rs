//! `forge-server` entrypoint: load config, connect + migrate, ensure the
//! bootstrap admin, build the app, spawn background workers, and serve.

use std::path::PathBuf;

use anyhow::Context;
use forge_cache::Cache;
use forge_server::app::{
    build_router, ensure_auth_realms, ensure_bootstrap_admin, ensure_legacy_rbac, principal_layer,
};
use forge_server::config::Config;
use forge_server::state::AppState;
use forge_server::workers;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Config: optional path from FORGE_CONFIG, else `forge.toml` if present.
    let config_path = std::env::var_os("FORGE_CONFIG")
        .map(PathBuf::from)
        .or_else(|| {
            let default = PathBuf::from("forge.toml");
            default.exists().then_some(default)
        });
    let config = Config::load(config_path.as_deref()).context("load configuration")?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        revision = option_env!("FORGE_GIT_SHA").unwrap_or("unknown"),
        "starting forge-server"
    );
    for warning in config.deployment_warnings() {
        tracing::warn!("{warning}");
    }
    for deprecation in config.deprecations() {
        tracing::warn!("{deprecation}");
    }

    // Database.
    let pool = forge_db::connect_with(
        &config.database.url,
        config.database.max_connections,
        std::time::Duration::from_secs(config.database.acquire_timeout_seconds),
    )
    .await
    .context("connect database")?;
    forge_db::migrate(&pool).await.context("run migrations")?;

    // Staging directory for pushes and proxy downloads: create it and remove
    // what killed processes left there. Each process stages in a locked
    // subdirectory of its own, so a dead one's goes at once and another
    // instance sharing the directory, with locks that reach it, is not
    // affected. Loose files from older versions, and the files in a
    // subdirectory whose lock cannot be tried, go once idle for an hour.
    // `AppState` builds the staging that requests use; this one is dropped
    // after the sweep.
    let staging = forge_storage::Staging::new(config.staging_dir(), config.staging_budget())
        .with_context(|| {
            format!(
                "create staging directory {}",
                config.staging_dir().display()
            )
        })?;
    match staging.sweep_stale(std::time::Duration::from_secs(3600)) {
        Ok(0) => {}
        Ok(removed) => tracing::info!(
            removed,
            dir = %staging.dir().display(),
            "removed staged files left by an earlier process"
        ),
        Err(e) => tracing::warn!(error = %e, "staging directory sweep failed"),
    }
    drop(staging);

    // Object store, with the local blob cache in front when configured, and
    // the bucket check. With the cache, an unreachable S3 does not stop the
    // start: the instance serves its cache and retries in the background.
    let blob_store = forge_server::object_store::open(&config)?;
    forge_server::object_store::ensure_bucket(&blob_store).await?;

    // Cache: L2 Redis when configured, else L1-only. Redis is connected
    // lazily: an unreachable Redis delays startup by a few seconds (the first
    // backplane subscription is awaited briefly) but does not prevent it.
    let cache = match &config.redis.url {
        Some(url) => {
            Cache::with_redis_timeouts(config.cache.l1_max_capacity, url, config.redis.timeouts())
                .await
                .context("configure redis cache")?
        }
        None => Cache::l1_only(config.cache.l1_max_capacity),
    };

    // Bootstrap admin (logs a warning while the seeded password is in use).
    ensure_bootstrap_admin(&config, &pool)
        .await
        .context("ensure bootstrap admin")?;

    // §12.4 Phase 5: apply the behavior-preserving RBAC legacy mapping
    // (is_admin→admin role, anonymous_read→anonymous grants, and — only on
    // legacy-open-access installs — authenticated for every user) ONCE per
    // install (a forge_setting marker), so later RBAC revocations stick. Never
    // opens a fresh install. Runs after bootstrap so a freshly-created
    // legacy-open user inherits the `authenticated` role too.
    ensure_legacy_rbac(&pool)
        .await
        .context("ensure legacy RBAC mapping")?;

    // §12.5: secret encryption at rest. Building the envelope service reads
    // the root key (env/file) and FAILS STARTUP on a bad/missing key — an
    // operator who configured encryption never gets a silently-plaintext
    // instance. Bootstrap then idempotently creates the active KEK/DEK and
    // backfills any pre-12.5 plaintext upstream passwords.
    let envelope = forge_server::crypto::build_envelope(&config, &pool)
        .context("build secret-encryption envelope service")?;
    if let (Some(env), Some(crypto_cfg)) = (&envelope, config.crypto.as_ref()) {
        forge_server::crypto::bootstrap(&pool, env, crypto_cfg)
            .await
            .context("bootstrap secret encryption")?;
    }
    if envelope.is_none() {
        forge_server::crypto::refuse_sealed_secrets_without_envelope(&pool).await?;
    }

    // 12.7: import of the legacy [oidc] / [auth.upstream_basic] blocks into
    // auth_realm rows (drift-detected); the DB is the authority. After the
    // crypto bootstrap so seeded realm secrets are encrypted at rest.
    ensure_auth_realms(&config, &pool, envelope.as_deref())
        .await
        .context("ensure auth realms")?;

    let bind_addr = config.server.bind_addr().context("parse server.bind")?;
    let plugins = forge_server::plugins::load(&config.plugins).context("load format plugins")?;
    // Registry (`/v2`) tokens are signed with one key shared by every
    // instance: docker.token_secret, or the install's generated key.
    let registry_keys =
        forge_server::registry::load_token_keys(&config, &pool, envelope.as_deref())
            .await
            .context("load the registry token key")?;
    let state = AppState::new(pool, blob_store, cache, config)
        .with_envelope(envelope)
        .with_registry_keys(registry_keys)
        .with_plugins(plugins)
        .map_err(anyhow::Error::msg)
        .context("install format plugins")?;
    let layer = principal_layer(&state)?;
    let serve_options = forge_server::serve::ServeOptions::from_config(&state.config);

    // Background workers (outbox / reconciler / proxy refresh / …), each
    // supervised: a panicking loop is logged and restarted.
    let workers = workers::spawn_all(&state);

    let downloads = state.downloads.clone();
    let app = build_router(state, layer);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind {bind_addr}"))?;
    tracing::info!(%bind_addr, "forge-server listening");

    forge_server::serve::serve(listener, app, serve_options, shutdown_signal()).await;

    // In-flight requests have drained; stop the background loops. Every worker
    // step is idempotent / lease-fenced, so an interrupted pass is resumed by
    // the next instance.
    workers.abort();
    // Download counts not written yet would be lost with the process.
    downloads.write_pending().await;
    tracing::info!("forge-server stopped");
    Ok(())
}

/// Resolve on Ctrl-C or SIGTERM for graceful shutdown. In a container the
/// server is PID 1 and `docker stop` / Kubernetes send SIGTERM; without
/// handling it every stop would end in SIGKILL mid-request.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}
