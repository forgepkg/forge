//! `forge-server` entrypoint: load config, connect + migrate, ensure the
//! bootstrap admin, build the app, spawn background workers, and serve.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use forge_cache::Cache;
use forge_nuget::NugetFormat;
use forge_server::app::{
    build_router, ensure_auth_realms, ensure_bootstrap_admin, ensure_legacy_rbac, principal_layer,
};
use forge_server::config::Config;
use forge_server::state::AppState;
use forge_server::workers;
use forge_storage::BlobStore;

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

    // Database.
    let pool = forge_db::connect(&config.database.url)
        .await
        .context("connect database")?;
    forge_db::migrate(&pool).await.context("run migrations")?;

    // Object store (ensure the bucket exists).
    let blob_store = BlobStore::new(config.s3.to_storage());
    blob_store
        .ensure_bucket()
        .await
        .context("ensure S3 bucket")?;

    // Cache: L2 Redis when configured, else L1-only.
    let cache = match &config.redis.url {
        Some(url) => Cache::with_redis(config.cache.l1_max_capacity, url)
            .await
            .context("connect redis cache")?,
        None => Cache::l1_only(config.cache.l1_max_capacity),
    };

    // Bootstrap admin (logs a warning while the seeded password is in use).
    ensure_bootstrap_admin(&config, &pool)
        .await
        .context("ensure bootstrap admin")?;

    // §12.4 Phase 5: re-apply the idempotent behavior-preserving RBAC legacy
    // mapping (is_admin→admin role, anonymous_read→anonymous grants, and — only
    // on legacy-open-access installs — authenticated for every user). A no-op
    // once converged; never opens a fresh install. Runs after bootstrap so a
    // freshly-created legacy-open user inherits the `authenticated` role too.
    ensure_legacy_rbac(&pool)
        .await
        .context("ensure legacy RBAC mapping")?;

    // 12.7: import of the legacy [oidc] / [auth.upstream_basic] blocks into
    // auth_realm rows (drift-detected); the DB is the authority.
    ensure_auth_realms(&config, &pool)
        .await
        .context("ensure auth realms")?;

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

    let bind_addr = config.server.bind_addr().context("parse server.bind")?;
    let nuget: Arc<dyn forge_core::format::Format> = Arc::new(NugetFormat::default());
    let state = AppState::new(pool, blob_store, cache, nuget, config).with_envelope(envelope);
    let layer = principal_layer(&state)?;

    // Background workers (outbox / reconciler / proxy refresh).
    let _workers = workers::spawn_all(&state);

    let app = build_router(state, layer);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind {bind_addr}"))?;
    tracing::info!(%bind_addr, "forge-server listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;

    Ok(())
}

/// Resolve on Ctrl-C for graceful shutdown.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
