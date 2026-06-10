//! Background workers (plan 10.5).
//!
//! Three independent loops, each safe to run on **every** instance of a
//! horizontally-scaled deployment with **no Postgres advisory locks**:
//!
//! 1. **Outbox worker** — drains `blob_outbox` to perform deferred S3 deletes.
//!    Cross-instance exclusivity comes from `claim_due`'s
//!    `FOR UPDATE SKIP LOCKED` lease, so two instances never delete the same
//!    object (see [`forge_storage::outbox_worker`]).
//! 2. **Orphan reconciler** — a periodic safety net reclaiming never-committed
//!    `pending` blobs older than the grace window. Idempotent: it deletes the S3
//!    object first, then drops the row only if it is *still* stale, so two
//!    instances racing are harmless.
//! 3. **Proxy metadata refresh** — periodically re-resolves each proxy
//!    repository's upstream service index. The cross-instance singleflight is a
//!    **row lock**: [`forge_core::repo::proxy::ProxyRepo::resolve_upstream_index`]
//!    serializes recompute via `SELECT … FOR UPDATE` on the
//!    `proxy_upstream_index` row (NO advisory locks); other instances wait and
//!    then read the freshly-populated row/cache.
//!
//! 4. **Auth reaper** (slice 12.2) — periodically deletes expired/used
//!    `oidc_flow` rows and revoked/expired `session` rows. Both are pure
//!    `DELETE`s (no advisory locks, no leases): the auth-code-flow rows are
//!    single-use and short-lived, sessions carry their own validity predicate,
//!    so running the reap on **every** instance is harmless (a row deleted by
//!    one instance simply isn't there for the next). It only bounds table
//!    growth; correctness never depends on it (callback/validate already reject
//!    expired rows in SQL).
//!
//! [`spawn_all`] launches all four and returns their join handles (so a caller
//! can abort them on shutdown). Each loop logs and continues on error rather
//! than terminating the process.

use std::sync::Arc;
use std::time::Duration;

use forge_core::format::Format;
use forge_core::repo::proxy::ProxyRepo;
use forge_core::retention::worker::{RetentionConfig, RetentionWorker};
use forge_db::model::RepoKind;
use forge_db::repository_dao;
use forge_storage::{outbox_worker, reconciler, BlobStore, Cas};
use sqlx::PgPool;
use tokio::task::JoinHandle;

use crate::state::AppState;

/// Handles to the spawned worker loops. Dropping/aborting them stops the loops.
pub struct WorkerHandles {
    /// Outbox-drain loop.
    pub outbox: JoinHandle<()>,
    /// Orphan-reconciler loop.
    pub reconciler: JoinHandle<()>,
    /// Proxy metadata-refresh loop.
    pub proxy_refresh: JoinHandle<()>,
    /// Retention-evaluation loop (slice 12.1).
    pub retention: JoinHandle<()>,
    /// Expired-`oidc_flow` / `session` reaper loop (slice 12.2). Present only
    /// when OIDC login is enabled (the only path that writes those tables).
    pub auth_reaper: Option<JoinHandle<()>>,
    /// Secret-encryption rotation/backfill worker (slice 12.5). Present only
    /// when `[crypto]` is enabled and its rotation worker is not turned off.
    /// Cluster-coordinated via a Postgres advisory lock (see
    /// [`crate::crypto::spawn_worker`]) — the documented exception to the
    /// no-advisory-locks slice-1 style, per the §12.5 plan.
    pub crypto_rotation: Option<JoinHandle<()>>,
}

impl WorkerHandles {
    /// Abort all worker loops (used on graceful shutdown / in tests).
    pub fn abort(&self) {
        self.outbox.abort();
        self.reconciler.abort();
        self.proxy_refresh.abort();
        self.retention.abort();
        if let Some(h) = &self.auth_reaper {
            h.abort();
        }
        if let Some(h) = &self.crypto_rotation {
            h.abort();
        }
    }
}

/// Spawn the outbox worker, the orphan reconciler, and the proxy metadata
/// refresher. Intervals/sizing come from the server config.
pub fn spawn_all(state: &AppState) -> WorkerHandles {
    let poll = state.config.outbox.poll_interval();
    let batch = state.config.outbox.batch_size;
    let grace = state.config.outbox.grace();

    let outbox =
        outbox_worker::spawn_loop(state.pool.clone(), state.blob_store.clone(), batch, poll);

    let reconciler = spawn_reconciler(
        state.pool.clone(),
        state.blob_store.clone(),
        grace,
        // Reconcile less often than the outbox polls; it is only a safety net.
        poll.saturating_mul(6).max(Duration::from_secs(60)),
    );

    let proxy_refresh = spawn_proxy_refresh(
        state.pool.clone(),
        state.cas.clone(),
        state.cache.clone(),
        state.formats.nuget(),
        // Refresh upstream metadata on a modest cadence; the per-proxy TTL +
        // row-lock singleflight bound actual upstream traffic.
        poll.saturating_mul(6).max(Duration::from_secs(60)),
    );

    // Retention worker (slice 12.1): runs on every instance, claims one due
    // repository per tick via FOR UPDATE SKIP LOCKED + a lease, evaluates its
    // policy, and applies decisions through the same blob outbox the outbox
    // worker above drains — no parallel S3-delete path. Cross-instance
    // exclusivity is the lease, not leader election. Disabling it
    // (`FORGE_RETENTION__ENABLED=false`) leaves the admin REST surface intact;
    // due repositories simply wait for an instance that runs the worker.
    let retention = if state.config.retention.enabled {
        RetentionWorker::new(
            state.pool.clone(),
            state.formats.nuget(),
            state.cache_invalidator(),
            RetentionConfig {
                poll_interval: state.config.retention.poll_interval(),
                default_run_interval: state.config.retention.default_run_interval(),
                lease: state.config.retention.lease(),
                // Reuse the outbox grace so a retention-dereferenced blob and a
                // redeploy-dereferenced one share the same S3-delete deferral.
                delete_grace: grace,
            },
        )
        .spawn_loop()
    } else {
        tracing::info!("retention worker disabled (FORGE_RETENTION__ENABLED=false)");
        tokio::spawn(async {})
    };

    // Auth reaper (slice 12.2): only when OIDC login is enabled — it is the only
    // path that writes `oidc_flow` / `session`. Both reaps are pure `DELETE`s
    // safe on every instance (no advisory locks, no leases). Cadence reuses the
    // outbox poll scaled up — flow rows live ~10min and sessions hours/days, so
    // a per-minute sweep is plenty to bound growth.
    let auth_reaper = state.config.oidc.as_ref().filter(|o| o.enabled).map(|_| {
        spawn_auth_reaper(
            state.pool.clone(),
            poll.saturating_mul(6).max(Duration::from_secs(60)),
        )
    });

    // Crypto rotation/backfill worker (slice 12.5): only when secret
    // encryption is enabled. One instance at a time performs a pass (advisory
    // lock); every step is idempotent/resumable so crashes are harmless.
    let crypto_rotation = match (&state.envelope, state.config.crypto.as_ref()) {
        (Some(envelope), Some(crypto_cfg)) => {
            crate::crypto::spawn_worker(state.pool.clone(), envelope.clone(), crypto_cfg)
        }
        _ => None,
    };

    WorkerHandles {
        outbox,
        reconciler,
        proxy_refresh,
        retention,
        auth_reaper,
        crypto_rotation,
    }
}

/// Spawn the auth reaper loop: each tick deletes expired/used `oidc_flow` rows
/// and revoked/expired `session` rows. Pure `DELETE`s — no advisory locks; safe
/// to run concurrently on every instance.
fn spawn_auth_reaper(pool: PgPool, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            match forge_db::oidc_flow_dao::reap_expired(&pool).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(reaped = n, "auth reaper deleted expired oidc_flow rows"),
                Err(e) => tracing::error!(error = %e, "oidc_flow reap failed"),
            }
            match forge_db::session_dao::reap_expired(&pool).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(reaped = n, "auth reaper deleted dead session rows"),
                Err(e) => tracing::error!(error = %e, "session reap failed"),
            }
        }
    })
}

/// Spawn the orphan-reconciler loop.
fn spawn_reconciler(
    pool: PgPool,
    store: BlobStore,
    grace: chrono::Duration,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            match reconciler::reconcile_orphans(&pool, &store, grace).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(reclaimed = n, "reconciler reclaimed orphan blobs"),
                Err(e) => tracing::error!(error = %e, "reconciler pass failed"),
            }
        }
    })
}

/// Spawn the proxy metadata-refresh loop. Each tick lists proxy repositories and
/// refreshes their upstream service index; the proxy layer's row-lock
/// singleflight ensures only one instance refetches per repo per TTL window.
fn spawn_proxy_refresh(
    pool: PgPool,
    cas: Cas,
    cache: forge_cache::Cache,
    format: Arc<dyn Format>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = refresh_proxies_once(&pool, &cas, &cache, &format).await {
                tracing::error!(error = %e, "proxy metadata refresh pass failed");
            }
        }
    })
}

/// One proxy-refresh pass: re-resolve every online proxy repository's upstream
/// index (best-effort; a single proxy's failure does not abort the pass).
async fn refresh_proxies_once(
    pool: &PgPool,
    cas: &Cas,
    cache: &forge_cache::Cache,
    format: &Arc<dyn Format>,
) -> anyhow::Result<()> {
    let repos = repository_dao::list_repositories(pool).await?;
    for repo in repos {
        if repo.kind() != RepoKind::Proxy || !repo.online {
            continue;
        }
        let proxy = ProxyRepo::new(pool.clone(), format.clone(), cas.clone(), cache.clone());
        if let Err(e) = proxy.resolve_upstream_index(&repo).await {
            tracing::warn!(error = %e, repo = %repo.name, "proxy upstream refresh failed");
        }
    }
    Ok(())
}
