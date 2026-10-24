//! Background workers.
//!
//! The loops below are independent, each safe to run on **every** instance
//! of a horizontally-scaled deployment with **no Postgres advisory locks**:
//!
//! 1. **Outbox worker** — drains `blob_outbox` to perform deferred S3 deletes.
//!    Cross-instance exclusivity comes from `claim_due`'s
//!    `FOR UPDATE SKIP LOCKED` lease, so two instances never delete the same
//!    object (see [`forge_storage::outbox_worker`]).
//! 2. **Orphan reconciler** — a periodic safety net reclaiming never-committed
//!    `pending` blobs older than the grace window. Idempotent: it deletes the S3
//!    object first, then drops the row only if it is *still* stale, so two
//!    instances racing are harmless. Each tick also prunes processed
//!    `blob_outbox` rows past `outbox.processed_retention_seconds` and
//!    `retention_audit` rows past the stored retention settings' audit
//!    retention, read on each tick (bounded batched `DELETE`s, safe on every
//!    instance).
//! 3. **Proxy metadata refresh** — periodically re-resolves each proxy
//!    repository's upstream service index. The cross-instance singleflight is a
//!    **row lock**: [`forge_core::repo::proxy::ProxyRepo::resolve_upstream_index`]
//!    serializes recompute via `SELECT … FOR UPDATE` on the
//!    `proxy_upstream_index` row (NO advisory locks); other instances wait and
//!    then read the freshly-populated row/cache.
//!
//! 4. **Auth reaper** — periodically deletes expired/used `oidc_flow` and
//!    `email_oauth_flow` rows, revoked/expired `session` rows, expired `cli_login`
//!    rows and `login_known_network` rows past the
//!    login throttle's 30-day memory. All are pure `DELETE`s (no advisory
//!    locks, no leases): the auth-code-flow rows are single-use and
//!    short-lived, sessions carry their own validity predicate, so running the
//!    reap on **every** instance is harmless (a row deleted by one instance
//!    simply isn't there for the next). It only bounds table growth;
//!    correctness never depends on it (callback/validate already reject
//!    expired rows in SQL).
//!
//! 5. **Credential reaper** — periodically deletes expired
//!    `validated_credential` verdicts and then the orphaned
//!    `validated_credential_tag` fence rows left behind (rejected/sprayed
//!    usernames, completed revocations). Pure `DELETE`s safe on every instance;
//!    in-flight fills are skipped via `FOR UPDATE SKIP LOCKED`. Like the auth
//!    reaper it only bounds growth — reads already treat expired rows as
//!    misses.
//!
//! 6. **Blob cache maintenance** — only with `[blob_cache]`: re-reads the
//!    cache's filesystem every minute, evicts down to the limit, and logs the
//!    cache's statistics. Per instance, like the cache itself.
//!
//! 7. **Issuer key refresh** — re-reads forge's OIDC issuer keys (the client
//!    assertions of a `federated_credential` realm), creates them once such a
//!    realm is enabled, and rotates them when due. The rotation is a
//!    compare-and-swap on the shared setting, safe on every instance.
//!
//! 8. **Nexus imports** — claims a queued import (or one whose instance
//!    died) with `FOR UPDATE SKIP LOCKED` and a lease it renews, so an import
//!    runs on one instance at a time; every instance runs the loop
//!    ([`crate::nexus_import`]).
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
    /// Retention-evaluation loop.
    pub retention: JoinHandle<()>,
    /// Expired-`oidc_flow` / `session` reaper loop. Always present: local
    /// password logins write `session` rows too.
    pub auth_reaper: Option<JoinHandle<()>>,
    /// Expired-`validated_credential` / orphaned-tag reaper loop. Always
    /// present: any credential-forwarding provider writes those tables.
    pub cred_reaper: JoinHandle<()>,
    /// Docker registry sweeper: abandoned upload sessions and blob links no
    /// manifest references any more.
    pub registry_sweeper: JoinHandle<()>,
    /// Re-reads the shared registry token key, so a key another instance
    /// had to replace is picked up. Not run with `docker.token_secret`.
    pub registry_key_refresh: JoinHandle<()>,
    /// Re-reads, creates and rotates forge's OIDC issuer keys.
    pub issuer_refresh: JoinHandle<()>,
    /// Secret-encryption rotation/backfill worker. Present only when
    /// `[crypto]` is enabled and its rotation worker is not turned off.
    /// Cluster-coordinated via a Postgres advisory lock (see
    /// [`crate::crypto::spawn_worker`]) — the one exception to the
    /// no-advisory-locks rule of the other loops.
    pub crypto_rotation: Option<JoinHandle<()>>,
    /// Local blob cache maintenance (re-read the disk size, evict down to the
    /// limit). Present only with `[blob_cache]`; per instance, like the cache.
    pub blob_cache: Option<JoinHandle<()>>,
    /// Runs imports from Nexus, one at a time per instance.
    pub nexus_import: JoinHandle<()>,
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
        self.registry_sweeper.abort();
        self.registry_key_refresh.abort();
        self.issuer_refresh.abort();
        if let Some(h) = &self.crypto_rotation {
            h.abort();
        }
        if let Some(h) = &self.blob_cache {
            h.abort();
        }
        self.nexus_import.abort();
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
        let prune_outbox = state.config.outbox.processed_retention();
        supervise("reconciler", move || {
            spawn_reconciler(pool.clone(), store.clone(), grace, prune_outbox, interval)
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

    // Retention worker: runs on every instance, claims one due repository per
    // tick via FOR UPDATE SKIP LOCKED + a lease, evaluates its policy, and
    // applies decisions through the same blob outbox the outbox worker above
    // drains — no parallel S3-delete path. Cross-instance exclusivity is the
    // lease, not leader election. While retention runs are switched off
    // (Admin → Retention) it claims nothing and a running run stops before
    // its next batch; the admin REST surface stays intact.
    let retention = {
        let state = state.clone();
        supervise("retention", move || {
            RetentionWorker::new(
                state.pool.clone(),
                crate::state::RegistryResolver(state.formats.clone()),
                state.cache_invalidator(),
                RetentionConfig {
                    poll_interval: state.config.retention.poll_interval(),
                    // No floor of its own: each policy's interval decides.
                    default_run_interval: chrono::Duration::seconds(
                        forge_core::retention::worker::MIN_RUN_INTERVAL_SECONDS,
                    ),
                    lease: state.config.retention.lease(),
                    // Reuse the outbox grace so a retention-dereferenced blob and a
                    // redeploy-dereferenced one share the same S3-delete deferral.
                    delete_grace: grace,
                },
            )
            .spawn_loop()
        })
    };

    // Auth reaper: always on — local-password logins create `session` rows and
    // DB-managed OIDC realms create `oidc_flow` rows even without the legacy
    // `[oidc]` block. Both reaps are pure `DELETE`s safe on every instance (no
    // advisory locks, no leases). Cadence reuses the outbox poll scaled up —
    // flow rows live ~10min and sessions hours/days, so a per-minute sweep is
    // plenty to bound growth.
    let auth_reaper = {
        let pool = state.pool.clone();
        let interval = poll.saturating_mul(6).max(Duration::from_secs(60));
        Some(supervise("auth-reaper", move || {
            spawn_auth_reaper(pool.clone(), interval)
        }))
    };

    // Credential reaper: bounds `validated_credential` (expired verdicts) and
    // `validated_credential_tag` (fence rows whose usernames have no verdicts
    // left — including every rejected/sprayed attempt). Runs unconditionally:
    // any credential-forwarding provider writes these tables.
    let cred_reaper = {
        let pool = state.pool.clone();
        let interval = poll.saturating_mul(6).max(Duration::from_secs(60));
        supervise("cred-reaper", move || {
            spawn_cred_reaper(pool.clone(), interval)
        })
    };

    // Registry sweeper: idempotent per-row deletes under row locks, safe on
    // every instance.
    let registry_sweeper = {
        let pool = state.pool.clone();
        let docker = state.config.docker.clone();
        supervise("registry-sweeper", move || {
            spawn_registry_sweeper(pool.clone(), docker.clone(), grace)
        })
    };

    // The shared registry token key: only the generated one can change.
    let registry_key_refresh = if state.config.docker.token_secret.is_none() {
        let state = state.clone();
        supervise("registry-key-refresh", move || {
            crate::registry::spawn_token_key_refresh(state.clone())
        })
    } else {
        tokio::spawn(async {})
    };

    // Forge's OIDC issuer keys: shared through the database, so every
    // instance re-reads them; any one of them rotates.
    let issuer_refresh = {
        let state = state.clone();
        supervise("issuer-refresh", move || {
            crate::auth::spawn_issuer_refresh(state.clone())
        })
    };

    // Crypto rotation/backfill worker: only when secret encryption is
    // enabled. One instance at a time performs a pass (advisory lock); every
    // step is idempotent/resumable so crashes are harmless.
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

    // Local blob cache (per instance): pick up a resized volume or a disk
    // something else fills, drop what garbage collection deleted on another
    // instance, and log the cache's statistics now and then.
    let blob_cache = state.blob_store.cache().cloned().map(|cache| {
        let pool = state.pool.clone();
        supervise("blob-cache", move || {
            crate::object_store::spawn_maintenance(
                cache.clone(),
                pool.clone(),
                crate::object_store::MAINTENANCE_INTERVAL,
            )
        })
    });

    // Nexus imports: the lease decides which instance runs an import.
    let nexus_import = {
        let state = state.clone();
        supervise("nexus-import", move || {
            crate::nexus_import::ImportWorker::new(state.clone()).spawn_loop()
        })
    };

    WorkerHandles {
        outbox,
        reconciler,
        proxy_refresh,
        retention,
        auth_reaper,
        cred_reaper,
        registry_sweeper,
        registry_key_refresh,
        issuer_refresh,
        crypto_rotation,
        blob_cache,
        nexus_import,
    }
}

/// Sweep expired registry uploads and unreferenced blob links every
/// `docker.sweep_interval_seconds`.
fn spawn_registry_sweeper(
    pool: sqlx::PgPool,
    docker: crate::config::DockerConfig,
    grace: chrono::Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(Duration::from_secs(docker.sweep_interval_seconds.max(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match crate::images::gc::sweep_once(
                &pool,
                chrono::Duration::seconds(docker.upload_ttl_seconds as i64),
                chrono::Duration::seconds(docker.unreferenced_blob_ttl_seconds as i64),
                grace,
            )
            .await
            {
                Ok(s) if s.uploads == 0 && s.links == 0 => {}
                Ok(s) => tracing::info!(
                    uploads = s.uploads,
                    links = s.links,
                    "registry sweep released expired uploads and unreferenced blobs"
                ),
                Err(e) => tracing::error!(error = %e, "registry sweep failed"),
            }
        }
    })
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

/// Spawn the auth reaper loop: each tick deletes expired/used `oidc_flow` rows,
/// revoked/expired `session` rows and spent `workload_api_key` rows. Pure
/// `DELETE`s — no advisory locks; safe to run concurrently on every instance.
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
            // The email service's OAuth authorizations left unfinished.
            match forge_db::email_oauth_flow_dao::sweep_expired(&pool).await {
                Ok(0) => {}
                Ok(n) => {
                    tracing::debug!(reaped = n, "auth reaper deleted expired email OAuth flows")
                }
                Err(e) => tracing::error!(error = %e, "email OAuth flow reap failed"),
            }
            match forge_db::session_dao::reap_expired(&pool).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(reaped = n, "auth reaper deleted dead session rows"),
                Err(e) => tracing::error!(error = %e, "session reap failed"),
            }
            // Command-line logins (`npm login`) nobody finished in the
            // browser.
            match forge_db::cli_login_dao::delete_expired(&pool).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(reaped = n, "auth reaper deleted expired cli logins"),
                Err(e) => tracing::error!(error = %e, "cli login reap failed"),
            }
            // Exchanged workload keys whose CI token has expired as well,
            // well past any clock skew a realm accepts (until then the row
            // records the token's redemption).
            match forge_db::workload_api_key_dao::reap_expired(&pool).await {
                Ok(0) => {}
                Ok(n) => {
                    tracing::debug!(reaped = n, "auth reaper deleted expired workload API keys")
                }
                Err(e) => tracing::error!(error = %e, "workload API key reap failed"),
            }
            // Networks no sign-in came from for longer than the login
            // throttle remembers them.
            let forgotten = chrono::Utc::now()
                - chrono::Duration::from_std(forge_core::auth::login_throttle::KNOWN_NETWORK_TTL)
                    .expect("a 30-day TTL fits");
            match forge_db::login_network_dao::prune(&pool, forgotten, 1000).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(reaped = n, "auth reaper deleted stale login networks"),
                Err(e) => tracing::error!(error = %e, "login network reap failed"),
            }
        }
    })
}

/// Spawn the orphan-reconciler loop. Each tick also prunes processed
/// `blob_outbox` rows older than `prune_outbox` (`None` keeps them all) and
/// `retention_audit` rows older than the stored retention settings say.
fn spawn_reconciler(
    pool: PgPool,
    store: BlobStore,
    grace: chrono::Duration,
    prune_outbox: Option<chrono::Duration>,
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
            if let Some(retention) = prune_outbox {
                match outbox_worker::prune_processed(&pool, retention).await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(pruned = n, "pruned processed blob_outbox rows"),
                    Err(e) => tracing::error!(error = %e, "blob_outbox prune failed"),
                }
            }
            // Read on every tick, so a change in Admin → Retention applies
            // within one; settings that cannot be read prune nothing.
            match forge_db::retention_dao::read_settings(&pool).await {
                Ok(settings) => {
                    if let Some(keep) = settings.audit_retention() {
                        match forge_core::retention::worker::prune_audit(&pool, keep).await {
                            Ok(0) => {}
                            Ok(n) => tracing::debug!(pruned = n, "pruned retention_audit rows"),
                            Err(e) => tracing::error!(error = %e, "retention_audit prune failed"),
                        }
                    }
                }
                Err(e) => tracing::error!(
                    error = %e,
                    "cannot read the retention settings; retention_audit not pruned"
                ),
            }
            // Proxy versions only ever requested, never listed or served
            // upstream, once their negative-cache window has lapsed.
            match forge_db::proxy_dao::prune_unconfirmed(
                &pool,
                forge_core::repo::proxy::DEFAULT_NOT_FOUND_TTL_SECONDS,
                1000,
            )
            .await
            {
                Ok(0) => {}
                Ok(n) => tracing::debug!(pruned = n, "pruned unconfirmed proxy versions"),
                Err(e) => tracing::error!(error = %e, "proxy version prune failed"),
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
        // Proxies of package formats keep an upstream index; docker
        // proxies revalidate per tag (and have no package format).
        let Ok(format) = state.formats.for_repository(&repo) else {
            continue;
        };
        // Same wiring as request-time reads: shared upstream client and the
        // envelope service, so credentialed upstreams refresh too.
        let proxy = state.proxy_repo(format);
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
