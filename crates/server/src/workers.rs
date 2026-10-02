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
//!    instances racing are harmless. Each tick also prunes processed
//!    `blob_outbox` rows past `outbox.processed_retention_seconds` (bounded
//!    batched `DELETE`s, safe on every instance).
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
//! 5. **Credential reaper** (slice 12.3) — periodically deletes expired
//!    `validated_credential` verdicts and then the orphaned
//!    `validated_credential_tag` fence rows left behind (rejected/sprayed
//!    usernames, completed revocations). Pure `DELETE`s safe on every instance;
//!    in-flight fills are skipped via `FOR UPDATE SKIP LOCKED`. Like the auth
//!    reaper it only bounds growth — reads already treat expired rows as
//!    misses.
//!
//! [`spawn_all`] launches all of these and returns their join handles (so a caller
//! can abort them on shutdown). Each loop logs and continues on error rather
//! than terminating the process, and runs under [`supervise`]: a loop that
//! panics (or exits) is logged at `error` and restarted after a short pause
//! instead of silently disappearing while the server keeps serving.

use std::time::Duration;

use forge_core::retention::worker::{RetentionConfig, RetentionWorker};
use forge_db::model::RepoKind;
use forge_db::repository_dao;
use forge_storage::{outbox_worker, reconciler, BlobStore};
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
    /// Expired-`validated_credential` / orphaned-tag reaper loop (slice 12.3).
    /// Always present: any credential-forwarding provider writes those tables.
    pub cred_reaper: JoinHandle<()>,
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
        self.cred_reaper.abort();
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

    let outbox = {
        let (pool, store) = (state.pool.clone(), state.blob_store.clone());
        supervise("outbox", move || {
            outbox_worker::spawn_loop(pool.clone(), store.clone(), batch, poll)
        })
    };

    let reconciler = {
        let (pool, store) = (state.pool.clone(), state.blob_store.clone());
        // Reconcile less often than the outbox polls; it is only a safety net.
        let interval = poll.saturating_mul(6).max(Duration::from_secs(60));
        let outbox_retention = state.config.outbox.processed_retention();
        supervise("reconciler", move || {
            spawn_reconciler(
                pool.clone(),
                store.clone(),
                grace,
                outbox_retention,
                interval,
            )
        })
    };

    let proxy_refresh = {
        let state = state.clone();
        // Refresh upstream metadata on a modest cadence; the per-proxy TTL +
        // the shared cache bound actual upstream traffic.
        let interval = poll.saturating_mul(6).max(Duration::from_secs(60));
        supervise("proxy-refresh", move || {
            spawn_proxy_refresh(state.clone(), interval)
        })
    };

    // Retention worker (slice 12.1): runs on every instance, claims one due
    // repository per tick via FOR UPDATE SKIP LOCKED + a lease, evaluates its
    // policy, and applies decisions through the same blob outbox the outbox
    // worker above drains — no parallel S3-delete path. Cross-instance
    // exclusivity is the lease, not leader election. Disabling it
    // (`FORGE_RETENTION__ENABLED=false`) leaves the admin REST surface intact;
    // due repositories simply wait for an instance that runs the worker.
    let retention = if state.config.retention.enabled {
        let state = state.clone();
        supervise("retention", move || {
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
        })
    } else {
        tracing::info!("retention worker disabled (FORGE_RETENTION__ENABLED=false)");
        tokio::spawn(async {})
    };

    // Auth reaper (slice 12.2): always on — local-password logins create
    // `session` rows and DB-managed OIDC realms create `oidc_flow` rows even
    // without the legacy `[oidc]` block. Both reaps are pure `DELETE`s safe on
    // every instance (no advisory locks, no leases). Cadence reuses the outbox
    // poll scaled up — flow rows live ~10min and sessions hours/days, so a
    // per-minute sweep is plenty to bound growth.
    let auth_reaper = {
        let pool = state.pool.clone();
        let interval = poll.saturating_mul(6).max(Duration::from_secs(60));
        Some(supervise("auth-reaper", move || {
            spawn_auth_reaper(pool.clone(), interval)
        }))
    };

    // Credential reaper (slice 12.3): bounds `validated_credential` (expired
    // verdicts) and `validated_credential_tag` (fence rows whose usernames have
    // no verdicts left — including every rejected/sprayed attempt). Runs
    // unconditionally: any credential-forwarding provider writes these tables.
    let cred_reaper = {
        let pool = state.pool.clone();
        let interval = poll.saturating_mul(6).max(Duration::from_secs(60));
        supervise("cred-reaper", move || {
            spawn_cred_reaper(pool.clone(), interval)
        })
    };

    // Crypto rotation/backfill worker (slice 12.5): only when secret
    // encryption is enabled. One instance at a time performs a pass (advisory
    // lock); every step is idempotent/resumable so crashes are harmless.
    let crypto_rotation = match (&state.envelope, state.config.crypto.as_ref()) {
        (Some(envelope), Some(crypto_cfg)) if crypto_cfg.rotation.enabled => {
            let (pool, envelope, crypto_cfg) =
                (state.pool.clone(), envelope.clone(), crypto_cfg.clone());
            Some(supervise("crypto-rotation", move || {
                crate::crypto::spawn_worker(pool.clone(), envelope.clone(), &crypto_cfg)
                    .unwrap_or_else(|| tokio::spawn(std::future::pending()))
            }))
        }
        (Some(_), Some(_)) => {
            tracing::info!(
                "crypto rotation worker disabled (FORGE_CRYPTO__ROTATION__ENABLED=false)"
            );
            None
        }
        _ => None,
    };

    WorkerHandles {
        outbox,
        reconciler,
        proxy_refresh,
        retention,
        auth_reaper,
        cred_reaper,
        crypto_rotation,
    }
}

/// Run a worker loop under supervision: `spawn` starts one instance; if it
/// panics or returns, the failure is logged and a fresh instance is started
/// after a pause. Aborting the returned handle stops the current instance too.
fn supervise<F>(name: &'static str, spawn: F) -> JoinHandle<()>
where
    F: Fn() -> JoinHandle<()> + Send + 'static,
{
    /// Aborts the wrapped task when dropped (i.e. when the supervisor itself
    /// is aborted mid-`await`).
    struct AbortOnDrop(JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    const RESTART_DELAY: Duration = Duration::from_secs(5);
    tokio::spawn(async move {
        loop {
            let mut worker = AbortOnDrop(spawn());
            match (&mut worker.0).await {
                Ok(()) => tracing::error!(worker = name, "worker loop exited; restarting"),
                Err(e) if e.is_cancelled() => return,
                Err(e) => {
                    tracing::error!(worker = name, error = %e, "worker loop panicked; restarting")
                }
            }
            tokio::time::sleep(RESTART_DELAY).await;
        }
    })
}

/// Spawn the credential reaper loop: each tick deletes expired
/// `validated_credential` verdicts, then the `validated_credential_tag` fence
/// rows orphaned by that (no verdicts left for the username). Pure `DELETE`s —
/// no advisory locks; safe to run concurrently on every instance.
fn spawn_cred_reaper(pool: PgPool, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            match forge_db::validated_credential_dao::sweep_expired(&pool).await {
                Ok(0) => {}
                Ok(n) => {
                    tracing::debug!(
                        reaped = n,
                        "cred reaper deleted expired credential verdicts"
                    )
                }
                Err(e) => tracing::error!(error = %e, "validated_credential sweep failed"),
            }
            match forge_db::validated_credential_dao::sweep_orphaned_tags(&pool).await {
                Ok(0) => {}
                Ok(n) => {
                    tracing::debug!(
                        reaped = n,
                        "cred reaper deleted orphaned user-tag fence rows"
                    )
                }
                Err(e) => tracing::error!(error = %e, "validated_credential_tag sweep failed"),
            }
        }
    })
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

/// Spawn the orphan-reconciler loop. Each tick also prunes processed
/// `blob_outbox` rows older than `outbox_retention` (`None` = keep them).
fn spawn_reconciler(
    pool: PgPool,
    store: BlobStore,
    grace: chrono::Duration,
    outbox_retention: Option<chrono::Duration>,
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
            if let Some(retention) = outbox_retention {
                match outbox_worker::prune_processed(&pool, retention).await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(pruned = n, "pruned processed blob_outbox rows"),
                    Err(e) => tracing::error!(error = %e, "blob_outbox prune failed"),
                }
            }
        }
    })
}

/// Spawn the proxy metadata-refresh loop. Each tick lists proxy repositories and
/// refreshes their upstream service index. Each repository's pass runs under
/// the proxy client's own deadlines, so one unreachable upstream delays the
/// pass by at most one metadata timeout instead of stalling it.
fn spawn_proxy_refresh(state: AppState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = refresh_proxies_once(&state).await {
                tracing::error!(error = %e, "proxy metadata refresh pass failed");
            }
        }
    })
}

/// One proxy-refresh pass: re-resolve every online proxy repository's upstream
/// index (best-effort; a single proxy's failure does not abort the pass).
async fn refresh_proxies_once(state: &AppState) -> anyhow::Result<()> {
    let repos = repository_dao::list_repositories(&state.pool).await?;
    for repo in repos {
        if repo.kind() != RepoKind::Proxy || !repo.online {
            continue;
        }
        // Same wiring as request-time reads: shared upstream client and the
        // envelope service, so credentialed upstreams refresh too.
        let proxy = state.proxy_repo(state.formats.for_repository(&repo));
        if let Err(e) = proxy.resolve_upstream_index(&repo).await {
            tracing::warn!(error = %e, repo = %repo.name, "proxy upstream refresh failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn supervise_restarts_a_panicking_loop_and_abort_stops_it() {
        let starts = Arc::new(AtomicUsize::new(0));
        let counter = starts.clone();
        let handle = supervise("test", move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if n == 0 {
                    panic!("first instance dies");
                }
                std::future::pending::<()>().await;
            })
        });
        // Let the first instance panic and the restart delay elapse.
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert_eq!(
            starts.load(Ordering::SeqCst),
            2,
            "restarted once after the panic"
        );

        handle.abort();
        let _ = handle.await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(starts.load(Ordering::SeqCst), 2, "no restarts after abort");
    }
}
