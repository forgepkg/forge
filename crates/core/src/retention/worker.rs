//! The retention background worker.
//!
//! The worker runs on **every** instance of a horizontally-scaled deployment
//! with **no Postgres advisory locks**. Each [`tick`](RetentionWorker::tick)
//! claims one due repository via
//! [`retention_dao::claim_next_due_repo`]'s `FOR UPDATE OF retention_run SKIP
//! LOCKED` + a `locked_until` lease, so a repository is evaluated by **at most
//! one instance at a time** and a crashed holder's lease expires and is
//! reclaimed. It then:
//!
//! 1. parses + validates the claimed repo's `retention_policy`;
//! 2. snapshots its candidate components (and, for proxy repos, cached
//!    versions);
//! 3. runs the **pure** [`evaluate`] / [`evaluate_proxy`];
//! 4. [`apply`]s the decisions — each in its own tx, decref + `blob_outbox`
//!    only (no direct S3 delete);
//! 5. records the run summary + schedules the next run on the ledger;
//! 6. invalidates the read cache for every affected package.
//!
//! All S3 deletion flows through the transactional blob outbox; this worker
//! never touches S3. A `dry_run_only` policy (or a disabled one) audits/no-ops
//! but never mutates.

use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use futures_util::FutureExt;
use sqlx::PgPool;

use forge_db::model::RepoKind;
use forge_db::retention_dao::{self, RunSummary};

use crate::format::Format;
use crate::repo::CacheInvalidator;
use crate::retention::apply::{apply, ApplyContext, RunFence};
use crate::retention::evaluate::{
    plan_package_run, CandidateComponent, PackagePlan, ProxyCandidate,
};
use crate::retention::model::{validate_policy, RetentionPolicy, SizeBudgetSummary};

/// The shortest interval the worker ever schedules between two automatic runs
/// of a repository, whatever the config and the policy say (both accept 0).
pub const MIN_RUN_INTERVAL_SECONDS: i64 = 60;

/// A policy's `min_run_interval_seconds` when it names none (the default of
/// every policy shape).
const DEFAULT_POLICY_INTERVAL_SECONDS: u64 = 3600;

/// Tuning for the retention worker, mirrored from the server config.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// How often each instance polls for a due repository.
    pub poll_interval: StdDuration,
    /// Floor on the next-run interval (a per-repo `min_run_interval_seconds`
    /// larger than this wins). Bounds how often a repo is re-evaluated; values
    /// below [`MIN_RUN_INTERVAL_SECONDS`] are raised to it. The server leaves
    /// it at that minimum, so each policy's own interval decides.
    pub default_run_interval: Duration,
    /// Crash-safe lease held while a repo is being evaluated.
    pub lease: Duration,
    /// Grace passed to the blob outbox before a dereferenced blob is S3-deleted.
    pub delete_grace: Duration,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        RetentionConfig {
            poll_interval: StdDuration::from_secs(30),
            default_run_interval: Duration::seconds(3600),
            lease: Duration::seconds(300),
            delete_grace: Duration::seconds(3600),
        }
    }
}

/// Resolves a repository's [`Format`] from its `repository.format` id.
pub trait FormatResolver: Send + Sync {
    /// The format named `id`, or `None` when it is not installed.
    fn resolve(&self, id: &str) -> Option<Arc<dyn Format>>;
}

/// One format for every repository, whatever its `format` column says.
impl FormatResolver for Arc<dyn Format> {
    fn resolve(&self, _id: &str) -> Option<Arc<dyn Format>> {
        Some(Arc::clone(self))
    }
}

/// The retention worker. Cheap to clone (everything inside is `Arc`/clone-cheap).
#[derive(Clone)]
pub struct RetentionWorker {
    pool: PgPool,
    formats: Arc<dyn FormatResolver>,
    cache: Arc<dyn CacheInvalidator>,
    config: RetentionConfig,
}

impl RetentionWorker {
    /// Build a worker over a pool, the version-ordering [`Format`]s (resolved
    /// per repository), a cache invalidator, and tuning.
    pub fn new(
        pool: PgPool,
        formats: impl FormatResolver + 'static,
        cache: Arc<dyn CacheInvalidator>,
        mut config: RetentionConfig,
    ) -> Self {
        // The config and a policy's `min_run_interval_seconds` both accept 0.
        // With both at 0 a finished run would be due again at once, and the
        // drain loop in `spawn_loop` would re-claim the same repository
        // back-to-back forever. A failing run is retried no sooner either
        // ([`Self::retry_interval`]).
        config.default_run_interval = config
            .default_run_interval
            .max(Duration::seconds(MIN_RUN_INTERVAL_SECONDS));
        RetentionWorker {
            pool,
            formats: Arc::new(formats),
            cache,
            config,
        }
    }

    /// Reclaim any leases held by crashed instances (a startup + periodic
    /// sweep). The claim query already tolerates expired leases; this is a
    /// belt-and-suspenders cleanup. Returns the number reclaimed.
    pub async fn release_stale_leases(&self) -> sqlx::Result<u64> {
        let now = forge_db::db_now(&self.pool).await?;
        retention_dao::release_stale_leases(&self.pool, now).await
    }

    /// Run one tick: claim at most one due repository and evaluate it.
    ///
    /// Returns `Ok(Some(summary))` if a repo was claimed + processed, `Ok(None)`
    /// when nothing is due. On a processing error — including a panic while
    /// processing, which is caught ([`WorkerError::Panicked`]) — the lease is
    /// released with the error recorded and the repo rescheduled, then the
    /// error is returned (the loop logs + continues).
    pub async fn tick(&self) -> Result<Option<RunSummary>, WorkerError> {
        self.tick_inner(None).await
    }

    /// Run one tick restricted to a single repository.
    ///
    /// Identical to [`Self::tick`] but the claim is scoped to `repository_id`
    /// (`claim_next_due_repo`'s `only_repo`), so the caller is guaranteed to act
    /// on *that* repo or `Ok(None)` if it is not due — never on some other due
    /// repo. The admin "run now" path and tests use this to avoid racing the
    /// global scan; production loops still call the unscoped [`Self::tick`].
    pub async fn tick_repo(&self, repository_id: i64) -> Result<Option<RunSummary>, WorkerError> {
        self.tick_inner(Some(repository_id)).await
    }

    /// Shared claim-then-process body for [`Self::tick`] / [`Self::tick_repo`].
    async fn tick_inner(&self, only_repo: Option<i64>) -> Result<Option<RunSummary>, WorkerError> {
        // Claim inside a short tx; the row is leased on commit so the network/CPU
        // work below happens with NO transaction held (the same rule as the
        // proxy fetch).
        let claimed = {
            let mut tx = self.pool.begin().await?;
            // Due-ness and the lease (checked by the run fence against
            // `now()`) run on the database's clock.
            let now = forge_db::db_now(&mut *tx).await?;
            let claimed =
                retention_dao::claim_next_due_repo(&mut tx, now, self.config.lease, only_repo)
                    .await?;
            tx.commit().await?;
            claimed
        };

        let Some((repo, run_id)) = claimed else {
            return Ok(None);
        };

        // Keep the lease alive while this (possibly long) run works, so a
        // large repository is never re-claimed by another instance mid-run.
        // The guard aborts the heartbeat however this scope is left — normal
        // return, a caught panic, or the tick future being dropped — so a run
        // that dies can never keep renewing its lease.
        let heartbeat = AbortOnDrop(spawn_lease_heartbeat(
            self.pool.clone(),
            repo.repository_id,
            run_id,
            self.config.lease,
        ));
        // A panic in `process` (a bug, or a panicking `Format`) is recorded
        // like any other failed run instead of unwinding past `fail_run` and
        // leaving the ledger row `running` until its lease expires. Nothing is
        // shared mutably across the unwind: every applied decision committed
        // in its batch's transaction, and the in-flight one rolled back on drop.
        let result = AssertUnwindSafe(self.process(&repo, run_id))
            .catch_unwind()
            .await
            .unwrap_or_else(|panic| Err(WorkerError::Panicked(panic_message(&*panic))));
        drop(heartbeat);

        match result {
            Ok(summary) => Ok(Some(summary)),
            Err(e) => {
                tracing::error!(error = %e, repo = %repo.name, %run_id, "retention run failed");
                // Release the lease, record the error, reschedule.
                let now = forge_db::db_now(&self.pool)
                    .await
                    .unwrap_or_else(|_| Utc::now());
                let next = now + self.retry_interval(&repo.policy);
                if let Err(e2) = retention_dao::fail_run(
                    &self.pool,
                    repo.repository_id,
                    Some(run_id),
                    &e.to_string(),
                    next,
                )
                .await
                {
                    tracing::error!(error = %e2, repo = %repo.name, "failed to record retention run failure");
                }
                Err(e)
            }
        }
    }

    /// Evaluate + apply one claimed repository, then finish the run + invalidate
    /// cache. Separated from [`Self::tick`] so the lease can be released on
    /// error in one place.
    async fn process(
        &self,
        repo: &retention_dao::ClaimedRepo,
        run_id: uuid::Uuid,
    ) -> Result<RunSummary, WorkerError> {
        let kind = RepoKind::from(repo.kind.as_str());
        // An images format's repositories (Docker) hold images.
        if self
            .formats
            .resolve(&repo.format)
            .is_some_and(|format| format.stores_images())
        {
            return self.process_images(repo, kind, run_id).await;
        }
        // A files format's repositories (raw) hold files under paths.
        if self
            .formats
            .resolve(&repo.format)
            .is_some_and(|format| format.stores_files())
        {
            return self.process_files(repo, kind, run_id).await;
        }

        // Parse + validate the policy. A malformed or repo-kind-incoherent policy
        // is a configuration error: record it and reschedule (do not mutate).
        // This is also what refuses a policy stored before validation rejected
        // hosted-scope rules on proxy repos: such a rule would delete cached
        // components while `proxy_cached_version` still claims them, so the
        // whole run fails until the operator switches it to `proxy_cached`.
        let policy: RetentionPolicy = serde_json::from_value(repo.policy.clone())
            .map_err(|e| WorkerError::Policy(format!("parse retention_policy: {e}")))?;
        validate_policy(&policy, kind)
            .map_err(|e| WorkerError::Policy(format!("invalid retention_policy: {e}")))?;
        // A repository of a format that is not installed (a plugin removed
        // from the configuration) cannot order its versions: fail the run
        // without mutating anything until the format is back.
        let format = self.formats.resolve(&repo.format).ok_or_else(|| {
            WorkerError::Policy(format!("format {:?} is not installed", repo.format))
        })?;

        // The database's clock: `next_run_at` is compared with it, and the
        // ages evaluated below are of timestamps it wrote.
        let now = forge_db::db_now(&self.pool).await?;
        let next_run_at = now + self.next_interval(&policy);

        // Disabled policy ⇒ no-op run (still advance the schedule).
        if !policy.enabled {
            retention_dao::finish_run(
                &self.pool,
                repo.repository_id,
                Some(run_id),
                &RunSummary::default(),
                next_run_at,
            )
            .await?;
            return Ok(RunSummary::default());
        }

        // ── Snapshot candidates (no tx held across apply; apply re-locks rows). ──
        // A proxy's components are cache entries owned by its
        // `proxy_cached_version` rows, never hosted content, so they are only
        // ever evicted through the proxy path below.
        let hosted: Vec<CandidateComponent> = if kind == RepoKind::Proxy {
            Vec::new()
        } else {
            retention_dao::load_candidate_components(
                &self.pool,
                repo.repository_id,
                format.package_asset_path(),
            )
            .await?
            .into_iter()
            .map(|(r, _sha)| CandidateComponent {
                component_id: r.component_id,
                package_name: r.name,
                version: r.version,
                listed: r.listed,
                created_at: r.created_at,
                last_downloaded_at: r.last_downloaded_at,
                size_bytes: u64::try_from(r.size_bytes).unwrap_or_default(),
            })
            .collect()
        };

        let proxy: Vec<ProxyCandidate> = if kind == RepoKind::Proxy {
            retention_dao::load_proxy_candidates(&self.pool, repo.repository_id)
                .await?
                .into_iter()
                .map(|r| ProxyCandidate {
                    cached_version_id: r.cached_version_id,
                    package_name: r.name,
                    version: r.version,
                    listed: r.listed,
                    first_seen_at: r.first_seen_at,
                    last_downloaded_at: r.last_downloaded_at,
                    size_bytes: u64::try_from(r.size_bytes).unwrap_or_default(),
                })
                .collect()
        } else {
            Vec::new()
        };

        // A version a package tag names is never touched: it stays in the
        // snapshot (it counts as a newer version), but neither a rule nor the
        // size budget selects it.
        let tagged_hosted_ids =
            crate::retention::tagged_candidate_ids(&self.pool, repo.repository_id, &hosted).await?;
        let size_before = match policy.size_budget {
            Some(_) => {
                Some(retention_dao::package_repository_size(&self.pool, repo.repository_id).await?)
            }
            None => None,
        };

        // ── Pure evaluation, on the blocking pool: it is CPU-bound and grows
        // with the repository, so it must not stall a runtime worker thread. ──
        let evaluation = {
            let format = Arc::clone(&format);
            let policy = policy.clone();
            tokio::task::spawn_blocking(move || {
                plan_package_run(
                    format.as_ref(),
                    now,
                    &policy,
                    &hosted,
                    &proxy,
                    &tagged_hosted_ids,
                    size_before,
                )
            })
        };
        // A panic there (e.g. a panicking `Format`) fails the run like a panic
        // anywhere else in `process`.
        let PackagePlan {
            hosted: hosted_decisions,
            proxy: proxy_decisions,
            spared,
            budget,
        } = evaluation.await.map_err(|e| {
            WorkerError::Panicked(match e.try_into_panic() {
                Ok(panic) => panic_message(&*panic),
                Err(e) => e.to_string(), // cancelled: the runtime is shutting down
            })
        })?;
        if spared > 0 {
            tracing::info!(repo = %repo.name, spared, "retention spared tagged versions");
        }

        // Affected package names (for cache invalidation after the run).
        let mut affected: BTreeSet<String> = BTreeSet::new();
        for d in &hosted_decisions {
            affected.insert(d.package_name.clone());
        }
        for d in &proxy_decisions {
            affected.insert(d.package_name.clone());
        }

        // ── Apply (skipped for dry-run; apply records dry-run audit rows). ──
        let ctx = ApplyContext {
            pool: &self.pool,
            repository_id: repo.repository_id,
            repository_name: &repo.name,
            run_id,
            delete_grace: self.config.delete_grace,
            dry_run: policy.dry_run_only,
            evaluated_at: Some(now),
            fence: Some(RunFence {
                stored_policy: &repo.policy,
                policy: &policy,
                format: format.as_ref(),
            }),
        };
        let mut summary = apply(&ctx, &hosted_decisions, &proxy_decisions).await?;
        if let Some(budget) = budget {
            let size_after = if policy.dry_run_only {
                budget.size_after
            } else {
                retention_dao::package_repository_size(&self.pool, repo.repository_id).await?
            };
            record_budget(&mut summary, budget, size_after);
        }

        // ── Finish: record summary, advance schedule, clear lease. ──
        if !retention_dao::finish_run(
            &self.pool,
            repo.repository_id,
            Some(run_id),
            &summary,
            next_run_at,
        )
        .await?
        {
            tracing::warn!(repo = %repo.name, %run_id, "retention lease lost before the run finished; another instance owns the schedule");
        }
        // Advisory marker on the repository row (the ledger is authoritative).
        if let Err(e) = retention_dao::mark_repo_last_run(&self.pool, repo.repository_id, now).await
        {
            tracing::warn!(error = %e, repo = %repo.name, "failed to stamp retention_last_run_at");
        }

        // ── Cache invalidation (skip for dry-run — nothing changed). ──
        if !policy.dry_run_only {
            for name in &affected {
                self.cache.invalidate_package(&repo.name, name).await;
            }
        }

        Ok(summary)
    }

    /// [`Self::process`] for a docker repository: image tags and manifests
    /// (see [`crate::retention::images`]).
    async fn process_images(
        &self,
        repo: &retention_dao::ClaimedRepo,
        kind: RepoKind,
        run_id: uuid::Uuid,
    ) -> Result<RunSummary, WorkerError> {
        use crate::retention::images;
        let policy: images::ImageRetentionPolicy = serde_json::from_value(repo.policy.clone())
            .map_err(|e| WorkerError::Policy(format!("parse retention_policy: {e}")))?;
        images::validate_image_policy(&policy, kind)
            .map_err(|e| WorkerError::Policy(format!("invalid retention_policy: {e}")))?;
        let now = forge_db::db_now(&self.pool).await?;
        let secs = policy
            .min_run_interval_seconds
            .min(crate::retention::model::MAX_MIN_RUN_INTERVAL_SECONDS);
        let next_run_at = now
            + Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX))
                .max(self.config.default_run_interval);
        let mut summary = RunSummary::default();
        if policy.enabled {
            let (decisions, evaluated, budget) =
                images::evaluate_repository(&self.pool, repo.repository_id, now, &policy).await?;
            let fence = images::ImageRunFence {
                stored_policy: &repo.policy,
                policy: &policy,
                evaluated_at: now,
            };
            summary = images::apply_images(
                &self.pool,
                repo.repository_id,
                run_id,
                &decisions,
                self.config.delete_grace,
                policy.dry_run_only,
                Some(&fence),
            )
            .await?;
            summary.evaluated = evaluated;
            if let Some(budget) = budget {
                let size_after = if policy.dry_run_only {
                    budget.size_after
                } else {
                    forge_db::oci_dao::repository_size(&self.pool, repo.repository_id).await?
                };
                record_budget(&mut summary, budget, size_after);
            }
        }
        if !retention_dao::finish_run(
            &self.pool,
            repo.repository_id,
            Some(run_id),
            &summary,
            next_run_at,
        )
        .await?
        {
            tracing::warn!(repo = %repo.name, %run_id, "retention lease lost before the run finished; another instance owns the schedule");
        }
        if let Err(e) = retention_dao::mark_repo_last_run(&self.pool, repo.repository_id, now).await
        {
            tracing::warn!(error = %e, repo = %repo.name, "failed to stamp retention_last_run_at");
        }
        Ok(summary)
    }

    async fn process_files(
        &self,
        repo: &retention_dao::ClaimedRepo,
        kind: RepoKind,
        run_id: uuid::Uuid,
    ) -> Result<RunSummary, WorkerError> {
        use crate::retention::files;
        let policy: files::FileRetentionPolicy = serde_json::from_value(repo.policy.clone())
            .map_err(|e| WorkerError::Policy(format!("parse retention_policy: {e}")))?;
        files::validate_file_policy(&policy, kind)
            .map_err(|e| WorkerError::Policy(format!("invalid retention_policy: {e}")))?;
        let now = forge_db::db_now(&self.pool).await?;
        let secs = policy
            .min_run_interval_seconds
            .min(crate::retention::model::MAX_MIN_RUN_INTERVAL_SECONDS);
        let next_run_at = now
            + Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX))
                .max(self.config.default_run_interval);
        let mut summary = RunSummary::default();
        if policy.enabled {
            let (decisions, evaluated, budget) =
                files::evaluate_repository(&self.pool, repo.repository_id, now, &policy).await?;
            let fence = files::FileRunFence {
                stored_policy: &repo.policy,
                policy: &policy,
                evaluated_at: now,
            };
            summary = files::apply_files(
                &self.pool,
                repo.repository_id,
                run_id,
                &decisions,
                self.config.delete_grace,
                policy.dry_run_only,
                Some(&fence),
            )
            .await?;
            summary.evaluated = evaluated;
            if let Some(budget) = budget {
                let size_after = if policy.dry_run_only {
                    budget.size_after
                } else {
                    forge_db::raw_dao::repository_size(&self.pool, repo.repository_id).await?
                };
                record_budget(&mut summary, budget, size_after);
            }
        }
        if !retention_dao::finish_run(
            &self.pool,
            repo.repository_id,
            Some(run_id),
            &summary,
            next_run_at,
        )
        .await?
        {
            tracing::warn!(repo = %repo.name, %run_id, "retention lease lost before the run finished; another instance owns the schedule");
        }
        if let Err(e) = retention_dao::mark_repo_last_run(&self.pool, repo.repository_id, now).await
        {
            tracing::warn!(error = %e, repo = %repo.name, "failed to stamp retention_last_run_at");
        }
        Ok(summary)
    }

    /// The next-run interval for a policy: the larger of the repo's
    /// `min_run_interval_seconds` and the global default (which [`Self::new`]
    /// raised to at least [`MIN_RUN_INTERVAL_SECONDS`]).
    fn next_interval(&self, policy: &RetentionPolicy) -> Duration {
        // Clamped defensively: validation already bounds the policy value, and
        // an out-of-range interval must never panic the worker loop.
        let secs = policy
            .min_run_interval_seconds
            .min(crate::retention::model::MAX_MIN_RUN_INTERVAL_SECONDS);
        let per_repo = Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX));
        per_repo.max(self.config.default_run_interval)
    }

    /// When a failed run is tried again: after its policy's
    /// `min_run_interval_seconds`, read from the raw document (which may be
    /// what failed to parse) or the default when it names none, and no sooner
    /// than the floor, so a broken policy is not retried every minute.
    fn retry_interval(&self, policy: &serde_json::Value) -> Duration {
        let secs = policy
            .get("min_run_interval_seconds")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_POLICY_INTERVAL_SECONDS)
            .min(crate::retention::model::MAX_MIN_RUN_INTERVAL_SECONDS);
        Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX))
            .max(self.config.default_run_interval)
    }

    /// Run the worker loop forever: a startup stale-lease sweep, then a tick on
    /// each poll interval. Errors are logged and the loop continues. Returns the
    /// spawned task handle.
    pub fn spawn_loop(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Startup sweep so a previous instance's crashed leases are freed.
            if let Err(e) = self.release_stale_leases().await {
                tracing::error!(error = %e, "retention startup lease sweep failed");
            }
            let mut ticker = tokio::time::interval(self.config.poll_interval);
            loop {
                ticker.tick().await;
                // Drain all currently-due repos this cycle (bounded by the lease
                // / SKIP LOCKED so other instances share the work).
                loop {
                    match self.tick().await {
                        Ok(Some(summary)) => {
                            tracing::debug!(?summary, "retention run completed");
                        }
                        Ok(None) => break, // nothing due
                        Err(e) => {
                            tracing::error!(error = %e, "retention tick failed");
                            break;
                        }
                    }
                }
            }
        })
    }
}

/// Aborts the wrapped task when dropped (a [`tokio::task::JoinHandle`] only
/// detaches on drop).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Best-effort text of a caught panic payload (`panic!` with a literal yields
/// `&str`, with format arguments `String`).
/// Record a size budget's outcome on a run's summary: `size_after` is the
/// size measured once the run applied, or, for a dry run, the projected one.
fn record_budget(summary: &mut RunSummary, budget: SizeBudgetSummary, size_after: u64) {
    summary.size_before = Some(budget.size_before);
    summary.size_after = Some(size_after);
    summary.target_bytes = Some(budget.target_bytes);
    summary.target_reached = Some(budget.reached(size_after));
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

/// Renew the run's lease every third of its length until aborted; stops on
/// its own once the lease is lost.
fn spawn_lease_heartbeat(
    pool: PgPool,
    repository_id: i64,
    run_id: uuid::Uuid,
    lease: Duration,
) -> tokio::task::JoinHandle<()> {
    let every = (lease / 3)
        .to_std()
        .unwrap_or_default()
        .max(std::time::Duration::from_secs(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        ticker.tick().await; // the first tick completes immediately
        loop {
            ticker.tick().await;
            let renewed = match forge_db::db_now(&pool).await {
                Ok(now) => {
                    retention_dao::renew_run_lease(&pool, repository_id, run_id, now + lease).await
                }
                Err(e) => Err(e),
            };
            match renewed {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(repository_id, %run_id, "retention lease lost; heartbeat stopped");
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, repository_id, "retention lease renewal failed")
                }
            }
        }
    })
}

/// Rows deleted per statement by [`prune_audit`].
const AUDIT_PRUNE_BATCH: i64 = 1_000;

/// Upper bound on statements per [`prune_audit`] call, so one pass stays short
/// on a large backlog; the rest goes on the next call.
const AUDIT_PRUNE_MAX_BATCHES: usize = 50;

/// Delete `retention_audit` rows older than `keep`, in short batches. Returns
/// the number of rows deleted. Safe on every instance at once.
pub async fn prune_audit(pool: &PgPool, keep: Duration) -> sqlx::Result<u64> {
    let cutoff = forge_db::db_now(pool).await? - keep;
    let mut total = 0u64;
    for _ in 0..AUDIT_PRUNE_MAX_BATCHES {
        let deleted = retention_dao::prune_audit(pool, cutoff, AUDIT_PRUNE_BATCH).await?;
        total += deleted;
        if deleted < AUDIT_PRUNE_BATCH as u64 {
            break;
        }
    }
    Ok(total)
}

/// Errors a retention tick can surface (logged; the loop continues).
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// A database / sqlx error during claim, load, apply, or finish.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// The repository's stored policy failed to parse or validate.
    #[error("policy error: {0}")]
    Policy(String),
    /// Processing the claimed repository panicked; the panic was caught and the
    /// run recorded as failed.
    #[error("retention run panicked: {0}")]
    Panicked(String),
}
