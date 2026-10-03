//! Data access for the slice-12.1 retention coordination ledger
//! (`retention_run`), the audit log (`retention_audit`), the policy column on
//! `repository`, and the candidate snapshots the evaluator consumes.
//!
//! The worker claims one due repository at a time via
//! `SELECT … FOR UPDATE OF retention_run SKIP LOCKED` plus a `locked_until`
//! lease (mirroring `blob_outbox`), so a repository is evaluated by **at most
//! one instance at a time** and a crashed instance's lease expires and is
//! reclaimed. There are **no Postgres advisory locks** here.

use chrono::{DateTime, Duration, Utc};
use serde_json::Value as JsonValue;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};

/// A repository claimed for a retention pass: its identity (needed to load the
/// `Format` and run the evaluator/apply path) plus the raw policy jsonb.
#[derive(Debug, Clone)]
pub struct ClaimedRepo {
    /// `repository.id`.
    pub repository_id: i64,
    /// `repository.name` (used by the apply path's cache invalidation).
    pub name: String,
    /// `repository.format` (selects the `Format` impl for version ordering).
    pub format: String,
    /// `repository.kind` (`hosted` | `proxy` | `group`).
    pub kind: String,
    /// The raw `retention_policy` jsonb (guaranteed non-null by the claim query).
    pub policy: JsonValue,
}

/// One hosted candidate row loaded for evaluation: the component plus the
/// `blob_sha256` of its primary `.nupkg` asset (used by the apply path to
/// decref the right blob). A component with no `.nupkg` asset is skipped by the
/// loader (it has nothing to GC).
#[derive(Debug, Clone)]
pub struct CandidateRow {
    /// `component.id`.
    pub component_id: i64,
    /// Lowercased package id (`component.name`).
    pub name: String,
    /// Normalized version (`component.version`).
    pub version: String,
    /// Whether the version is currently listed.
    pub listed: bool,
    /// When the component was created.
    pub created_at: DateTime<Utc>,
    /// Denormalized last-download timestamp (`component.last_downloaded_at`).
    pub last_downloaded_at: Option<DateTime<Utc>>,
}

/// One proxy cached-version candidate row loaded for eviction evaluation.
/// Only versions whose bytes are cached locally (`downloaded = true`) are
/// candidates; see [`load_proxy_candidates`].
#[derive(Debug, Clone)]
pub struct ProxyCandidateRow {
    /// `proxy_cached_version.id`.
    pub cached_version_id: i64,
    /// Lowercased package id.
    pub name: String,
    /// Normalized version.
    pub version: String,
    /// When the version was first seen upstream (the package-delay anchor).
    pub first_seen_at: DateTime<Utc>,
    /// Last pull timestamp, or `None` if never pulled.
    pub last_downloaded_at: Option<DateTime<Utc>>,
}

/// An append-only audit row to persist after a decision is applied (or previewed).
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub repository_id: i64,
    pub run_id: uuid::Uuid,
    pub rule_id: String,
    /// `unlist` | `hard_delete` | `skipped`.
    pub action: String,
    /// `component` | `proxy_cached_version`.
    pub target_kind: String,
    pub package_name: String,
    pub version: String,
    /// `component.id`, or `None` once it has been hard-deleted.
    pub component_id: Option<i64>,
    /// The blob touched, if any.
    pub blob_sha256: Option<String>,
    /// The observed `ref_count` after the decrement, if a blob was touched.
    pub ref_count_after: Option<i64>,
    /// Whether a `blob_outbox` delete was enqueued (ref_count hit 0).
    pub blob_delete_enqueued: bool,
    /// Dry-run (preview / `dry_run_only` policy) — effect was **not** applied.
    pub dry_run: bool,
    /// Structured reason (matched criteria), serialized to the `reason` jsonb.
    pub reason: JsonValue,
}

/// A summary of a completed run, persisted on `retention_run.last_run_summary`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RunSummary {
    /// Components/proxy entries inspected.
    pub evaluated: u64,
    /// Versions unlisted.
    pub unlisted: u64,
    /// Versions hard-deleted (components + proxy evictions).
    pub deleted: u64,
    /// Blob deletes enqueued into `blob_outbox` (ref_count hit 0).
    pub blobs_enqueued: u64,
    /// Decisions skipped at apply time (row changed under us).
    pub skipped: u64,
}

/// Ensure a `retention_run` ledger row exists for `repository_id` (idempotent).
///
/// Created lazily the first time a repo with a policy is seen; `next_run_at`
/// defaults to `now()` so a freshly-armed policy is picked up promptly. An
/// existing row is left untouched.
pub async fn upsert_retention_run<'e, E>(executor: E, repository_id: i64) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        INSERT INTO retention_run (repository_id)
        VALUES ($1)
        ON CONFLICT (repository_id) DO NOTHING
        "#,
        repository_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Claim the next due repository for a retention pass, atomically marking it
/// `running` with a fresh lease and a new `current_run_id`.
///
/// "Due" = a `retention_run` row whose `next_run_at <= now` that is either
/// `idle` or whose lease (`locked_until`) has expired, whose repository still
/// has a non-null `retention_policy`. The row is taken with
/// `FOR UPDATE OF retention_run SKIP LOCKED` so concurrent instances never claim
/// the same repository. Returns the claimed repo + the generated `run_id`, or
/// `None` when nothing is due.
///
/// The worker passes `only_repo = None` to scan all due repositories. Passing
/// `Some(id)` restricts the claim to a single repository — used by the admin
/// "run now" path and by tests that need to claim a specific repo without
/// racing the global scan.
///
/// `lease` is truncated to whole seconds (`make_interval`).
pub async fn claim_next_due_repo(
    tx: &mut Transaction<'_, Postgres>,
    now: DateTime<Utc>,
    lease: Duration,
    only_repo: Option<i64>,
) -> sqlx::Result<Option<(ClaimedRepo, uuid::Uuid)>> {
    let run_id = uuid::Uuid::new_v4();
    let lease_secs = lease.num_seconds() as f64;

    let row = sqlx::query!(
        r#"
        WITH due AS (
            SELECT rr.repository_id
            FROM retention_run rr
            JOIN repository r ON r.id = rr.repository_id
            WHERE rr.next_run_at <= $1
              AND (rr.state = 'idle' OR rr.locked_until IS NULL OR rr.locked_until < $1)
              AND r.retention_policy IS NOT NULL
              AND ($4::bigint IS NULL OR rr.repository_id = $4)
            ORDER BY rr.next_run_at
            FOR UPDATE OF rr SKIP LOCKED
            LIMIT 1
        )
        UPDATE retention_run rr
        SET state = 'running',
            started_at = $1,
            finished_at = NULL,
            locked_until = $1 + make_interval(secs => $2),
            current_run_id = $3,
            last_error = NULL
        FROM due
        WHERE rr.repository_id = due.repository_id
        RETURNING rr.repository_id
        "#,
        now,
        lease_secs,
        run_id,
        only_repo,
    )
    .fetch_optional(&mut **tx)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    // Load the repository identity + policy on the same connection.
    let repo = sqlx::query!(
        r#"
        SELECT id, name, format, kind, retention_policy AS "policy!: JsonValue"
        FROM repository
        WHERE id = $1
        "#,
        row.repository_id,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(Some((
        ClaimedRepo {
            repository_id: repo.id,
            name: repo.name,
            format: repo.format,
            kind: repo.kind,
            policy: repo.policy,
        },
        run_id,
    )))
}

/// Reclaim leases held by crashed instances: any `running` row whose
/// `locked_until` is in the past is reset to `idle` so the next `claim` can take
/// it. Returns the number of rows reclaimed. Called as a startup sweep and
/// periodically; the claim query already tolerates expired leases, so this is a
/// belt-and-suspenders cleanup that also clears `started_at`.
pub async fn release_stale_leases<'e, E>(executor: E, now: DateTime<Utc>) -> sqlx::Result<u64>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        UPDATE retention_run
        SET state = 'idle',
            locked_until = NULL,
            current_run_id = NULL,
            last_error = COALESCE(last_error, 'lease expired; reclaimed')
        WHERE state = 'running'
          AND locked_until IS NOT NULL
          AND locked_until < $1
        "#,
        now,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected())
}

/// Finish a run: record its summary, clear the lease, set `state = 'idle'` and
/// the next scheduled run. Accepts any executor.
///
/// With `run_id`, the update is **fenced** to the run that still owns the
/// lease: a worker whose lease expired and was re-claimed by another instance
/// cannot clear the newer owner's lease. Returns whether the row was updated.
pub async fn finish_run<'e, E>(
    executor: E,
    repository_id: i64,
    run_id: Option<uuid::Uuid>,
    summary: &RunSummary,
    next_run_at: DateTime<Utc>,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let summary_json = serde_json::to_value(summary).unwrap_or(JsonValue::Null);
    let res = sqlx::query!(
        r#"
        UPDATE retention_run
        SET state = 'idle',
            finished_at = now(),
            locked_until = NULL,
            current_run_id = NULL,
            next_run_at = $2,
            last_run_summary = $3
        WHERE repository_id = $1
          AND ($4::uuid IS NULL OR current_run_id = $4)
        "#,
        repository_id,
        next_run_at,
        summary_json,
        run_id,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Record a run-level error and release the lease so the repo is retried.
/// Fenced to `run_id` like [`finish_run`].
pub async fn fail_run<'e, E>(
    executor: E,
    repository_id: i64,
    run_id: Option<uuid::Uuid>,
    error: &str,
    next_run_at: DateTime<Utc>,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        UPDATE retention_run
        SET state = 'idle',
            finished_at = now(),
            locked_until = NULL,
            current_run_id = NULL,
            next_run_at = $2,
            last_error = $3
        WHERE repository_id = $1
          AND ($4::uuid IS NULL OR current_run_id = $4)
        "#,
        repository_id,
        next_run_at,
        error,
        run_id,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Extend the lease of the run `run_id` to `locked_until`. Returns `false`
/// when that run no longer owns the lease (expired and re-claimed).
pub async fn renew_run_lease<'e, E>(
    executor: E,
    repository_id: i64,
    run_id: uuid::Uuid,
    locked_until: DateTime<Utc>,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        UPDATE retention_run
        SET locked_until = $3
        WHERE repository_id = $1 AND current_run_id = $2 AND state = 'running'
        "#,
        repository_id,
        run_id,
        locked_until,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Bump `repository.retention_last_run_at` (advisory only). Best-effort.
pub async fn mark_repo_last_run<'e, E>(
    executor: E,
    repository_id: i64,
    at: DateTime<Utc>,
) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"UPDATE repository SET retention_last_run_at = $2 WHERE id = $1"#,
        repository_id,
        at,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Load the hosted retention candidates for a repository: every component whose
/// primary `.nupkg` asset exists, with that asset's `blob_sha256`. Components
/// without a `.nupkg` asset (nothing to GC) are excluded.
///
/// The primary `.nupkg` is the lexicographically-first asset whose `path` ends
/// in `.nupkg` (NuGet stores exactly one per version; the ordering makes the
/// pick deterministic if that ever changes).
pub async fn load_candidate_components<'e, E>(
    executor: E,
    repository_id: i64,
) -> sqlx::Result<Vec<(CandidateRow, String)>>
where
    E: PgExecutor<'e>,
{
    let rows = sqlx::query!(
        r#"
        SELECT
            c.id            AS component_id,
            c.name          AS name,
            c.version       AS version,
            c.listed        AS listed,
            c.created_at    AS created_at,
            c.last_downloaded_at AS last_downloaded_at,
            (
                SELECT a.blob_sha256
                FROM asset a
                WHERE a.component_id = c.id AND a.path LIKE '%.nupkg'
                ORDER BY a.path
                LIMIT 1
            ) AS "blob_sha256?: String"
        FROM component c
        WHERE c.repository_id = $1
        ORDER BY c.name, c.id
        "#,
        repository_id,
    )
    .fetch_all(executor)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|r| {
            r.blob_sha256.map(|sha| {
                (
                    CandidateRow {
                        component_id: r.component_id,
                        name: r.name,
                        version: r.version,
                        listed: r.listed,
                        created_at: r.created_at,
                        last_downloaded_at: r.last_downloaded_at,
                    },
                    sha,
                )
            })
        })
        .collect())
}

/// Load the proxy cached-version candidates for a proxy repository: only rows
/// whose bytes are cached locally (`downloaded = true`, not a `not_found`
/// tombstone).
///
/// Metadata-only rows (`downloaded = false`: versions seen in an upstream
/// listing but never pulled, or already evicted) hold nothing to evict. They
/// are excluded so a run neither "evicts" them again nor writes an audit row
/// per never-pulled version on every pass, and so their `first_seen_at` — the
/// package-delay anchor — is never disturbed.
pub async fn load_proxy_candidates<'e, E>(
    executor: E,
    repository_id: i64,
) -> sqlx::Result<Vec<ProxyCandidateRow>>
where
    E: PgExecutor<'e>,
{
    let rows = sqlx::query!(
        r#"
        SELECT id, name, version, first_seen_at, last_downloaded_at
        FROM proxy_cached_version
        WHERE repository_id = $1 AND downloaded AND not_found = false
        ORDER BY name, version
        "#,
        repository_id,
    )
    .fetch_all(executor)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ProxyCandidateRow {
            cached_version_id: r.id,
            name: r.name,
            version: r.version,
            first_seen_at: r.first_seen_at,
            last_downloaded_at: r.last_downloaded_at,
        })
        .collect())
}

/// Insert one audit row. Accepts any executor so it composes inside the same
/// transaction that applied the decision (effect + audit commit atomically).
pub async fn insert_audit<'e, E>(executor: E, row: &AuditRow) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        INSERT INTO retention_audit (
            repository_id, run_id, rule_id, action, target_kind,
            package_name, version, component_id, blob_sha256,
            ref_count_after, blob_delete_enqueued, dry_run, reason
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
        row.repository_id,
        row.run_id,
        row.rule_id,
        row.action,
        row.target_kind,
        row.package_name,
        row.version,
        row.component_id,
        row.blob_sha256,
        row.ref_count_after,
        row.blob_delete_enqueued,
        row.dry_run,
        row.reason,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Read a repository's `retention_policy` jsonb (`None` ⇒ no retention).
pub async fn read_policy(pool: &PgPool, repository_id: i64) -> sqlx::Result<Option<JsonValue>> {
    let row = sqlx::query!(
        r#"SELECT retention_policy FROM repository WHERE id = $1"#,
        repository_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.retention_policy))
}

/// Write (or clear, with `None`) a repository's `retention_policy`. When a
/// non-null policy is written, the coordination ledger row is upserted so the
/// worker can claim it. Returns whether the repository row exists.
pub async fn write_policy(
    pool: &PgPool,
    repository_id: i64,
    policy: Option<&JsonValue>,
) -> sqlx::Result<bool> {
    let mut tx = pool.begin().await?;
    let res = sqlx::query!(
        r#"
        UPDATE repository
        SET retention_policy = $2, updated_at = now()
        WHERE id = $1
        "#,
        repository_id,
        policy,
    )
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    if policy.is_some() {
        upsert_retention_run(&mut *tx, repository_id).await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Fetch the current `retention_run` state for a repository (for the admin GET
/// surface). Returned as a typed tuple of the columns the API needs.
pub async fn get_run(pool: &PgPool, repository_id: i64) -> sqlx::Result<Option<RunState>> {
    let row = sqlx::query!(
        r#"
        SELECT state, next_run_at, started_at, finished_at, locked_until,
               last_error, last_run_summary
        FROM retention_run
        WHERE repository_id = $1
        "#,
        repository_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| RunState {
        state: r.state,
        next_run_at: r.next_run_at,
        started_at: r.started_at,
        finished_at: r.finished_at,
        locked_until: r.locked_until,
        last_error: r.last_error,
        last_run_summary: r.last_run_summary,
    }))
}

/// The `retention_run` row as surfaced to the admin API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunState {
    pub state: String,
    pub next_run_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub locked_until: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_run_summary: Option<JsonValue>,
}

/// A persisted audit row as surfaced to the admin `GET …/retention/audit` API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRecord {
    pub id: i64,
    pub run_id: uuid::Uuid,
    pub rule_id: String,
    pub action: String,
    pub target_kind: String,
    pub package_name: String,
    pub version: String,
    pub component_id: Option<i64>,
    pub blob_sha256: Option<String>,
    pub ref_count_after: Option<i64>,
    pub blob_delete_enqueued: bool,
    pub dry_run: bool,
    pub reason: JsonValue,
    pub created_at: DateTime<Utc>,
}

/// Delete up to `limit` audit rows created before `created_before`, oldest
/// first. Returns how many were deleted; fewer than `limit` means none older
/// are left. Each call is one short statement, idempotent and safe on every
/// instance at once.
pub async fn prune_audit(
    pool: &PgPool,
    created_before: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        r#"
        DELETE FROM retention_audit
        WHERE id = ANY(ARRAY(
            SELECT id
            FROM retention_audit
            WHERE created_at < $1
            ORDER BY created_at
            LIMIT $2
        ))
        "#,
        created_before,
        limit,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Read recent audit rows for a repository, newest first. Optionally filter by
/// `run_id` (one evaluation pass) and/or page with `before` (only rows with a
/// smaller `id`, i.e. older than the last page). `limit` is clamped by the
/// caller.
pub async fn read_audit(
    pool: &PgPool,
    repository_id: i64,
    run_id: Option<uuid::Uuid>,
    before_id: Option<i64>,
    limit: i64,
) -> sqlx::Result<Vec<AuditRecord>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, run_id, rule_id, action, target_kind, package_name, version,
               component_id, blob_sha256, ref_count_after, blob_delete_enqueued,
               dry_run, reason, created_at
        FROM retention_audit
        WHERE repository_id = $1
          AND ($2::uuid   IS NULL OR run_id = $2)
          AND ($3::bigint IS NULL OR id < $3)
        ORDER BY id DESC
        LIMIT $4
        "#,
        repository_id,
        run_id,
        before_id,
        limit,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| AuditRecord {
            id: r.id,
            run_id: r.run_id,
            rule_id: r.rule_id,
            action: r.action,
            target_kind: r.target_kind,
            package_name: r.package_name,
            version: r.version,
            component_id: r.component_id,
            blob_sha256: r.blob_sha256,
            ref_count_after: r.ref_count_after,
            blob_delete_enqueued: r.blob_delete_enqueued,
            dry_run: r.dry_run,
            reason: r.reason,
            created_at: r.created_at,
        })
        .collect())
}

/// Set `retention_run.next_run_at = now()` so the worker claims the repo on its
/// next poll (the admin "run now" trigger; does **not** run inline). Upserts the
/// ledger row first. Returns the new `next_run_at`'s `run_id` is generated by
/// the worker on claim; this only schedules. Returns whether the repo exists.
pub async fn schedule_now(pool: &PgPool, repository_id: i64) -> sqlx::Result<bool> {
    // Only schedule repos that exist and have a policy.
    let exists = sqlx::query_scalar!(
        r#"SELECT retention_policy IS NOT NULL AS "armed!" FROM repository WHERE id = $1"#,
        repository_id,
    )
    .fetch_optional(pool)
    .await?;

    let Some(armed) = exists else {
        return Ok(false);
    };
    if !armed {
        return Ok(false);
    }

    let mut tx = pool.begin().await?;
    upsert_retention_run(&mut *tx, repository_id).await?;
    sqlx::query!(
        r#"
        UPDATE retention_run
        SET next_run_at = now()
        WHERE repository_id = $1 AND state = 'idle'
        "#,
        repository_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}
