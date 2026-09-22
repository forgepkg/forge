//! The retention background worker (design §3.5, §3.6 steps 1–10; plan Phase 5).
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
//! All S3 deletion still flows through the slice-1 outbox; this worker never
//! touches S3. A `dry_run_only` policy (or a disabled one) audits/no-ops but
//! never mutates.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use sqlx::PgPool;

use forge_db::model::RepoKind;
use forge_db::retention_dao::{self, RunSummary};

use crate::format::Format;
use crate::repo::CacheInvalidator;
use crate::retention::apply::{apply, ApplyContext};
use crate::retention::evaluate::{evaluate, evaluate_proxy, CandidateComponent, ProxyCandidate};
use crate::retention::model::{validate_policy, RetentionPolicy};

/// Tuning for the retention worker, mirrored from the server config.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// How often each instance polls for a due repository.
    pub poll_interval: StdDuration,
    /// Floor on the next-run interval (a per-repo `min_run_interval_seconds`
    /// larger than this wins). Bounds how often a repo is re-evaluated.
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

/// The retention worker. Cheap to clone (everything inside is `Arc`/clone-cheap).
#[derive(Clone)]
pub struct RetentionWorker {
    pool: PgPool,
    format: Arc<dyn Format>,
    cache: Arc<dyn CacheInvalidator>,
    config: RetentionConfig,
}

impl RetentionWorker {
    /// Build a worker over a pool, a version-ordering [`Format`], a cache
    /// invalidator, and tuning.
    pub fn new(
        pool: PgPool,
        format: Arc<dyn Format>,
        cache: Arc<dyn CacheInvalidator>,
        config: RetentionConfig,
    ) -> Self {
        RetentionWorker {
            pool,
            format,
            cache,
            config,
        }
    }

    /// Reclaim any leases held by crashed instances (a startup + periodic
    /// sweep). The claim query already tolerates expired leases; this is a
    /// belt-and-suspenders cleanup. Returns the number reclaimed.
    pub async fn release_stale_leases(&self) -> sqlx::Result<u64> {
        retention_dao::release_stale_leases(&self.pool, Utc::now()).await
    }

    /// Run one tick: claim at most one due repository and evaluate it.
    ///
    /// Returns `Ok(Some(summary))` if a repo was claimed + processed, `Ok(None)`
    /// when nothing is due. On a processing error the lease is released with the
    /// error recorded and the repo rescheduled, then the error is returned (the
    /// loop logs + continues).
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
        // work below happens with NO transaction held (mirrors the proxy A7 rule).
        let claimed = {
            let mut tx = self.pool.begin().await?;
            let claimed = retention_dao::claim_next_due_repo(
                &mut tx,
                Utc::now(),
                self.config.lease,
                only_repo,
            )
            .await?;
            tx.commit().await?;
            claimed
        };

        let Some((repo, run_id)) = claimed else {
            return Ok(None);
        };

        // Keep the lease alive while this (possibly long) run works, so a
        // large repository is never re-claimed by another instance mid-run.
        let heartbeat = spawn_lease_heartbeat(
            self.pool.clone(),
            repo.repository_id,
            run_id,
            self.config.lease,
        );
        let result = self.process(&repo, run_id).await;
        heartbeat.abort();

        match result {
            Ok(summary) => Ok(Some(summary)),
            Err(e) => {
                // Release the lease, record the error, reschedule.
                let next = Utc::now() + self.config.default_run_interval;
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

        // Parse + validate the policy. A malformed or repo-kind-incoherent policy
        // is a configuration error: record it and reschedule (do not mutate).
        let policy: RetentionPolicy = serde_json::from_value(repo.policy.clone())
            .map_err(|e| WorkerError::Policy(format!("parse retention_policy: {e}")))?;
        validate_policy(&policy, kind)
            .map_err(|e| WorkerError::Policy(format!("invalid retention_policy: {e}")))?;

        let now = Utc::now();
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
        let hosted_rows =
            retention_dao::load_candidate_components(&self.pool, repo.repository_id).await?;
        let hosted: Vec<CandidateComponent> = hosted_rows
            .into_iter()
            .map(|(r, _sha)| CandidateComponent {
                component_id: r.component_id,
                package_name: r.name,
                version: r.version,
                listed: r.listed,
                created_at: r.created_at,
                last_downloaded_at: r.last_downloaded_at,
            })
            .collect();

        let proxy: Vec<ProxyCandidate> = if kind == RepoKind::Proxy {
            retention_dao::load_proxy_candidates(&self.pool, repo.repository_id)
                .await?
                .into_iter()
                .map(|r| ProxyCandidate {
                    cached_version_id: r.cached_version_id,
                    package_name: r.name,
                    version: r.version,
                    first_seen_at: r.first_seen_at,
                    last_downloaded_at: r.last_downloaded_at,
                })
                .collect()
        } else {
            Vec::new()
        };

        // ── Pure evaluation. ──
        let hosted_decisions = evaluate(self.format.as_ref(), now, &policy, &hosted);
        let proxy_decisions = evaluate_proxy(now, &policy, &proxy);

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
        };
        let summary = apply(&ctx, &hosted_decisions, &proxy_decisions).await?;

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

    /// The next-run interval for a policy: the larger of the repo's
    /// `min_run_interval_seconds` and the global default.
    fn next_interval(&self, policy: &RetentionPolicy) -> Duration {
        // Clamped defensively: validation already bounds the policy value, and
        // an out-of-range interval must never panic the worker loop.
        let secs = policy
            .min_run_interval_seconds
            .min(crate::retention::model::MAX_MIN_RUN_INTERVAL_SECONDS);
        let per_repo = Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX));
        per_repo.max(self.config.default_run_interval)
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
            match retention_dao::renew_run_lease(&pool, repository_id, run_id, Utc::now() + lease)
                .await
            {
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

/// Errors a retention tick can surface (logged; the loop continues).
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// A database / sqlx error during claim, load, apply, or finish.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// The repository's stored policy failed to parse or validate.
    #[error("policy error: {0}")]
    Policy(String),
}
