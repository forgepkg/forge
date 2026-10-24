//! The retention **apply** path (blob GC through the transactional outbox).
//!
//! Turns the pure evaluator's [`Decision`] / [`ProxyDecision`] sets into durable
//! mutations in small transactions: one per proxy eviction, and one per batch
//! of up to [`HOSTED_BATCH`] hosted decisions of the same package. Concurrent
//! pushes interleave between them, and a crash mid-run loses at most the
//! in-flight transaction (committed ones are durable + idempotent). Within
//! each transaction we:
//!
//! 1. Fence the step to its run ([`RunFence`]): the run must still own its
//!    lease and the stored policy must still be the one it evaluated, or the
//!    run **stops** (the rest is left to the next run under the current
//!    policy). For hosted decisions, then lock the package's versions and
//!    **re-evaluate** them, once per batch: a decision the current state no
//!    longer produces (say `keep_last_n` now protects the version because a
//!    newer one was unlisted) is skipped. The versions stay locked until the
//!    batch commits, so that one evaluation holds for the whole batch.
//!    `SELECT … FOR UPDATE` the target row (component or proxy cached
//!    version) by **id** and re-verify it still matches the decision. A
//!    concurrent redeploy / re-push / admin delete that changed the row makes
//!    us **skip** (audited as `skipped`) rather than act on stale state.
//! 2. For a hard delete: delete the asset rows, then
//!    [`blob_dao::decref_and_maybe_enqueue_delete`] each referenced blob — this
//!    is the **only** blob-GC path; it decrements `ref_count` and, iff it hits
//!    zero, enqueues a `blob_outbox` `delete_object` in the *same* transaction.
//!    A blob still referenced elsewhere (`ref_count > 0`) gets **no** outbox row
//!    and its S3 object survives. We never delete an S3 object directly.
//! 3. For an unlist: flip `component.listed = false`. For a proxy eviction:
//!    delete the cached component like a hard delete, but **keep** the
//!    `proxy_cached_version` row, flipping it back to `downloaded = false`
//!    (see `apply_proxy`).
//! 4. Insert the `retention_audit` row in the **same** transaction, so the
//!    effect and its audit commit atomically (capturing the observed
//!    `ref_count_after` and whether a delete was enqueued).
//!
//! When `dry_run` is set (preview or a `dry_run_only` policy) no mutation runs;
//! we still record `dry_run = true` audit rows so an operator can inspect what
//! *would* happen.

use std::collections::HashMap;

use chrono::Duration;
use serde_json::Value as JsonValue;
use sqlx::PgPool;

use forge_db::retention_dao::{self, AuditRow, RunSummary};
use forge_db::{asset_dao, blob_dao, component_dao};

use crate::format::Format;
use crate::retention::evaluate::{
    evaluate, size_budget_protected_ids, CandidateComponent, Decision, ProxyDecision,
};
use crate::retention::model::{Action, RetentionPolicy};

/// What a run's decisions were made under, re-checked before each one is
/// applied (see the module docs).
pub struct RunFence<'a> {
    /// The policy as stored in `repository.retention_policy` when the run
    /// claimed the repository.
    pub stored_policy: &'a JsonValue,
    /// The same policy, parsed: re-evaluates a package's versions.
    pub policy: &'a RetentionPolicy,
    /// The repository's format: orders versions for the re-evaluation.
    pub format: &'a dyn Format,
}

/// Whether the run goes on after a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Continue,
    /// The run lost its lease or its policy changed.
    Stop,
}

/// Everything the apply path needs that is not in the decision itself.
pub struct ApplyContext<'a> {
    /// The metadata pool (each batch or eviction opens its own short tx on it).
    pub pool: &'a PgPool,
    /// Repository the decisions belong to (for the unlist/delete DAO calls and
    /// the audit rows).
    pub repository_id: i64,
    /// Lowercased repository name (unused by apply itself; the worker invalidates
    /// cache after the run — kept here so call sites stay uniform).
    pub repository_name: &'a str,
    /// The run id grouping every audit row of this pass.
    pub run_id: uuid::Uuid,
    /// Deferred-delete grace passed straight to
    /// [`blob_dao::decref_and_maybe_enqueue_delete`].
    pub delete_grace: Duration,
    /// When true, evaluate + audit only; never mutate (preview / `dry_run_only`).
    pub dry_run: bool,
    /// When the decisions were evaluated. A decision driven by a
    /// "not downloaded / pulled for N days" trigger is skipped if the target was
    /// downloaded after this instant (it is no longer cold). `None` disables
    /// the re-check.
    pub evaluated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Fence and re-evaluate every mutating step (the worker always sets
    /// it). `None` applies the decisions as given.
    pub fence: Option<RunFence<'a>>,
}

/// Whether a download-driven decision became stale: the target was fetched
/// after the evaluation snapshot.
fn downloaded_since(
    ctx: &ApplyContext<'_>,
    download_trigger: bool,
    last_downloaded_at: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    match (ctx.evaluated_at, last_downloaded_at) {
        (Some(evaluated), Some(downloaded)) => download_trigger && downloaded > evaluated,
        _ => false,
    }
}

/// Serialize a decision's reason to the audit `reason` jsonb. Falls back to an
/// empty object if (impossibly) serialization fails.
fn reason_json<R: serde::Serialize>(reason: &R) -> JsonValue {
    serde_json::to_value(reason).unwrap_or_else(|_| JsonValue::Object(Default::default()))
}

/// The most hosted decisions of one package applied in one transaction: the
/// package's versions are locked and re-evaluated once per batch, not once
/// per decision, so a package with thousands of versions costs one lock of
/// its versions per hundred decisions.
const HOSTED_BATCH: usize = 100;

/// Apply a set of hosted + proxy decisions, returning the run summary.
///
/// Hosted decisions are applied per package in batches of up to
/// [`HOSTED_BATCH`], proxy evictions one by one; each batch or eviction is one
/// transaction. An error aborts that transaction (rolling back its effects
/// *and* audits together) and propagates, leaving earlier committed ones
/// intact.
pub async fn apply(
    ctx: &ApplyContext<'_>,
    hosted: &[Decision],
    proxy: &[ProxyDecision],
) -> Result<RunSummary, sqlx::Error> {
    let total = hosted.len() + proxy.len();
    let mut summary = RunSummary {
        evaluated: total as u64,
        ..Default::default()
    };

    let mut done = 0;
    if ctx.dry_run {
        for d in hosted {
            record_hosted_dry_run(ctx, d, &mut summary).await?;
        }
        done += hosted.len();
    } else {
        for batch in package_batches(hosted) {
            if apply_hosted_batch(ctx, &batch, &mut summary).await? == Step::Stop {
                return Ok(stopped(ctx, summary, total - done));
            }
            done += batch.len();
        }
    }
    for d in proxy {
        if apply_proxy(ctx, d, &mut summary).await? == Step::Stop {
            return Ok(stopped(ctx, summary, total - done));
        }
        done += 1;
    }

    Ok(summary)
}

/// `hosted` grouped by package, in the order the packages first appear, and
/// split into batches of at most [`HOSTED_BATCH`].
fn package_batches(hosted: &[Decision]) -> Vec<Vec<&Decision>> {
    let mut packages: Vec<Vec<&Decision>> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for d in hosted {
        let i = *index.entry(d.package_name.as_str()).or_insert_with(|| {
            packages.push(Vec::new());
            packages.len() - 1
        });
        packages[i].push(d);
    }
    packages
        .iter()
        .flat_map(|decisions| decisions.chunks(HOSTED_BATCH).map(<[_]>::to_vec))
        .collect()
}

/// The summary of a run that stopped with `remaining` decisions unapplied
/// (counted as skipped; the next run re-evaluates them).
fn stopped(ctx: &ApplyContext<'_>, mut summary: RunSummary, remaining: usize) -> RunSummary {
    tracing::info!(
        repository = ctx.repository_name,
        run_id = %ctx.run_id,
        remaining,
        "retention run stopped: it lost its lease or its policy changed; \
         the next run re-evaluates the rest"
    );
    summary.skipped += remaining as u64;
    summary
}

/// What evaluating `package_name`'s current versions (locked by this call)
/// under the run's policy decides now, by component id.
async fn decided_now(
    tx: &mut sqlx::PgConnection,
    ctx: &ApplyContext<'_>,
    fence: &RunFence<'_>,
    package_name: &str,
    size_budget: bool,
) -> Result<HashMap<i64, Action>, sqlx::Error> {
    let candidates: Vec<CandidateComponent> = retention_dao::lock_package_candidates(
        tx,
        ctx.repository_id,
        package_name,
        fence.format.package_asset_path(),
    )
    .await?
    .into_iter()
    .map(|r| CandidateComponent {
        component_id: r.component_id,
        package_name: r.name,
        version: r.version,
        listed: r.listed,
        created_at: r.created_at,
        last_downloaded_at: r.last_downloaded_at,
        size_bytes: u64::try_from(r.size_bytes).unwrap_or_default(),
    })
    .collect();
    let now = ctx.evaluated_at.unwrap_or_else(chrono::Utc::now);
    let mut decisions: HashMap<i64, Action> =
        evaluate(fence.format, now, fence.policy, &candidates)
            .into_iter()
            .map(|again| (again.component_id, again.action))
            .collect();
    if size_budget && fence.policy.size_budget.is_some() {
        let (protected, _) =
            size_budget_protected_ids(fence.format, fence.policy, &candidates, &[]);
        for candidate in &candidates {
            if !protected.contains(&candidate.component_id) {
                decisions.insert(candidate.component_id, Action::HardDelete);
            }
        }
    }
    Ok(decisions)
}

/// Record one hosted decision of a dry run: the audit row only.
async fn record_hosted_dry_run(
    ctx: &ApplyContext<'_>,
    d: &Decision,
    summary: &mut RunSummary,
) -> Result<(), sqlx::Error> {
    let reason = reason_json(&d.reason);

    let mut tx = ctx.pool.begin().await?;
    retention_dao::insert_audit(
        &mut *tx,
        &AuditRow {
            repository_id: ctx.repository_id,
            run_id: ctx.run_id,
            rule_id: d.rule_id.clone(),
            action: action_str(d.action).to_string(),
            target_kind: "component".to_string(),
            package_name: d.package_name.clone(),
            version: d.version.clone(),
            component_id: Some(d.component_id),
            blob_sha256: None,
            ref_count_after: None,
            blob_delete_enqueued: false,
            dry_run: true,
            reason,
        },
    )
    .await?;
    tx.commit().await?;
    match d.action {
        Action::Unlist => summary.unlisted += 1,
        Action::HardDelete => summary.deleted += 1,
    }
    Ok(())
}

/// Apply a batch of one package's hosted decisions in one transaction. With a
/// fence, the run's lease and policy are checked first (or the run stops),
/// then the package's versions are locked and re-evaluated once; a decision
/// they no longer produce is skipped.
async fn apply_hosted_batch(
    ctx: &ApplyContext<'_>,
    batch: &[&Decision],
    summary: &mut RunSummary,
) -> Result<Step, sqlx::Error> {
    let Some(first) = batch.first() else {
        return Ok(Step::Continue);
    };
    let mut tx = ctx.pool.begin().await?;
    let decided = match &ctx.fence {
        Some(fence) => {
            if !retention_dao::lock_run_fence(
                &mut tx,
                ctx.repository_id,
                ctx.run_id,
                fence.stored_policy,
            )
            .await?
            {
                return Ok(Step::Stop);
            }
            Some(
                decided_now(
                    &mut tx,
                    ctx,
                    fence,
                    &first.package_name,
                    batch.iter().any(|d| d.rule_id == "size_budget"),
                )
                .await?,
            )
        }
        None => None,
    };
    for d in batch {
        let still = decided
            .as_ref()
            .is_none_or(|now| now.get(&d.component_id) == Some(&d.action));
        if still {
            apply_hosted(&mut tx, ctx, d, summary).await?;
        } else {
            audit_skipped(&mut tx, ctx, d, "component").await?;
            summary.skipped += 1;
        }
    }
    tx.commit().await?;
    Ok(Step::Continue)
}

/// Apply one hosted decision inside its batch's transaction: lock the
/// component by id and re-verify it before acting.
async fn apply_hosted(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ApplyContext<'_>,
    d: &Decision,
    summary: &mut RunSummary,
) -> Result<(), sqlx::Error> {
    let reason = reason_json(&d.reason);

    // Re-verify: lock the component row by id. A concurrent hard delete may have
    // removed it; a redeploy may have swapped its assets. Lock first so our read
    // of the asset set is consistent with the decref.
    let locked = sqlx::query!(
        r#"
        SELECT id, name, version, last_downloaded_at
        FROM component
        WHERE id = $1 AND repository_id = $2
        FOR UPDATE
        "#,
        d.component_id,
        ctx.repository_id,
    )
    .fetch_optional(&mut **tx)
    .await?;

    let Some(row) = locked else {
        // Gone under us — skip, audit as skipped.
        audit_skipped(tx, ctx, d, "component").await?;
        summary.skipped += 1;
        return Ok(());
    };
    // Downloaded while this run was working: no longer cold — skip.
    if downloaded_since(
        ctx,
        d.reason.not_downloaded_for_days.is_some(),
        row.last_downloaded_at,
    ) {
        audit_skipped(tx, ctx, d, "component").await?;
        summary.skipped += 1;
        return Ok(());
    }
    if d.reason.size_budget.is_some()
        && d.reason.last_used_at.is_some_and(|last_used| {
            row.last_downloaded_at
                .is_some_and(|downloaded| downloaded > last_used)
        })
    {
        audit_skipped(tx, ctx, d, "component").await?;
        summary.skipped += 1;
        return Ok(());
    }
    // A package tag (npm's `latest`, `next`, …) names it now: never touched,
    // whatever the evaluation said.
    if forge_db::tag_dao::is_tagged(&mut **tx, ctx.repository_id, &row.name, &row.version).await? {
        audit_skipped(tx, ctx, d, "component").await?;
        summary.skipped += 1;
        return Ok(());
    }

    match d.action {
        Action::Unlist => {
            sqlx::query!(
                r#"UPDATE component SET listed = false, updated_at = now() WHERE id = $1"#,
                row.id,
            )
            .execute(&mut **tx)
            .await?;
            retention_dao::insert_audit(
                &mut **tx,
                &AuditRow {
                    repository_id: ctx.repository_id,
                    run_id: ctx.run_id,
                    rule_id: d.rule_id.clone(),
                    action: "unlist".to_string(),
                    target_kind: "component".to_string(),
                    package_name: d.package_name.clone(),
                    version: d.version.clone(),
                    component_id: Some(row.id),
                    blob_sha256: None,
                    ref_count_after: None,
                    blob_delete_enqueued: false,
                    dry_run: false,
                    reason,
                },
            )
            .await?;
            summary.unlisted += 1;
        }
        Action::HardDelete => {
            let assets = asset_dao::assets_for_component(&mut **tx, row.id).await?;

            // Track the primary .nupkg blob for the audit row; decref every
            // referenced blob (an asset set may share or differ).
            let mut audit_blob: Option<String> = None;
            let mut audit_ref_after: Option<i64> = None;
            let mut audit_enqueued = false;

            for asset in &assets {
                sqlx::query!(r#"DELETE FROM asset WHERE id = $1"#, asset.id)
                    .execute(&mut **tx)
                    .await?;
                let enqueued = blob_dao::decref_and_maybe_enqueue_delete(
                    tx,
                    &asset.blob_sha256,
                    ctx.delete_grace,
                )
                .await?;

                // Observe the post-decref ref_count for the audit row.
                let ref_after: i64 = sqlx::query_scalar!(
                    r#"SELECT ref_count FROM blob WHERE sha256 = $1"#,
                    asset.blob_sha256,
                )
                .fetch_optional(&mut **tx)
                .await?
                // The row may already be gone if a parallel reconciler removed a
                // zero-ref blob between decref and read; treat as 0.
                .unwrap_or(0);

                if enqueued {
                    summary.blobs_enqueued += 1;
                }
                // Record the .nupkg blob as the representative one.
                if asset.path.ends_with(".nupkg") || audit_blob.is_none() {
                    audit_blob = Some(asset.blob_sha256.clone());
                    audit_ref_after = Some(ref_after);
                    audit_enqueued = enqueued;
                }
            }

            component_dao::delete_component(&mut **tx, ctx.repository_id, &row.name, &row.version)
                .await?;

            retention_dao::insert_audit(
                &mut **tx,
                &AuditRow {
                    repository_id: ctx.repository_id,
                    run_id: ctx.run_id,
                    rule_id: d.rule_id.clone(),
                    action: "hard_delete".to_string(),
                    target_kind: "component".to_string(),
                    package_name: d.package_name.clone(),
                    version: d.version.clone(),
                    // Component row is gone; the FK is ON DELETE SET NULL but we
                    // record it as already-null since the audit commits in the
                    // same tx as the delete.
                    component_id: None,
                    blob_sha256: audit_blob,
                    ref_count_after: audit_ref_after,
                    blob_delete_enqueued: audit_enqueued,
                    dry_run: false,
                    reason,
                },
            )
            .await?;
            summary.deleted += 1;
        }
    }

    Ok(())
}

/// Apply one proxy eviction in its own transaction. Eviction deletes the cached
/// version's `component` (assets + blob decref, driving the outbox) and resets
/// its `proxy_cached_version` row to metadata-only (`downloaded = false`).
///
/// The row itself is **kept**: it is the version's upstream listing entry and
/// its `first_seen_at` anchors `package_delay_seconds`. Deleting it would make
/// the next listing refresh re-insert the version with `first_seen_at = now()`,
/// hiding a long-established version for a whole delay window after every
/// eviction. With `downloaded = false` the proxy treats the version exactly
/// like one it has listed but never pulled: listings keep showing it, and the
/// next pull re-fetches the bytes from upstream and serves them at once.
async fn apply_proxy(
    ctx: &ApplyContext<'_>,
    d: &ProxyDecision,
    summary: &mut RunSummary,
) -> Result<Step, sqlx::Error> {
    let reason = reason_json(&d.reason);

    if ctx.dry_run {
        let mut tx = ctx.pool.begin().await?;
        retention_dao::insert_audit(
            &mut *tx,
            &AuditRow {
                repository_id: ctx.repository_id,
                run_id: ctx.run_id,
                rule_id: d.rule_id.clone(),
                action: "hard_delete".to_string(),
                target_kind: "proxy_cached_version".to_string(),
                package_name: d.package_name.clone(),
                version: d.version.clone(),
                component_id: None,
                blob_sha256: None,
                ref_count_after: None,
                blob_delete_enqueued: false,
                dry_run: true,
                reason,
            },
        )
        .await?;
        tx.commit().await?;
        summary.deleted += 1;
        return Ok(Step::Continue);
    }

    let mut tx = ctx.pool.begin().await?;

    if let Some(fence) = &ctx.fence {
        if !retention_dao::lock_run_fence(
            &mut tx,
            ctx.repository_id,
            ctx.run_id,
            fence.stored_policy,
        )
        .await?
        {
            return Ok(Step::Stop);
        }
    }

    // Lock the cached-version row by id (the proxy's download finalize locks
    // the same row first, so the two serialize). Skip if it is gone, or if it
    // no longer holds cached bytes (a concurrent run already evicted it).
    let cached = sqlx::query!(
        r#"
        SELECT id, name, version, last_downloaded_at, downloaded
        FROM proxy_cached_version
        WHERE id = $1 AND repository_id = $2
        FOR UPDATE
        "#,
        d.cached_version_id,
        ctx.repository_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(cached) = cached.filter(|c| c.downloaded) else {
        audit_skipped_proxy(&mut tx, ctx, d).await?;
        tx.commit().await?;
        summary.skipped += 1;
        return Ok(Step::Continue);
    };
    // Pulled while this run was working: no longer cold — skip.
    if downloaded_since(
        ctx,
        d.reason.not_pulled_for_days.is_some(),
        cached.last_downloaded_at,
    ) {
        audit_skipped_proxy(&mut tx, ctx, d).await?;
        tx.commit().await?;
        summary.skipped += 1;
        return Ok(Step::Continue);
    }
    if d.reason.size_budget.is_some()
        && d.reason.last_used_at.is_some_and(|last_used| {
            cached
                .last_downloaded_at
                .is_some_and(|downloaded| downloaded > last_used)
        })
    {
        audit_skipped_proxy(&mut tx, ctx, d).await?;
        tx.commit().await?;
        summary.skipped += 1;
        return Ok(Step::Continue);
    }

    // Delete the parallel component + its assets (decref their blobs), if any.
    let mut audit_blob: Option<String> = None;
    let mut audit_ref_after: Option<i64> = None;
    let mut audit_enqueued = false;

    if let Some(comp) =
        component_dao::find_component(&mut *tx, ctx.repository_id, &cached.name, &cached.version)
            .await?
    {
        // Lock the component so a concurrent re-cache serializes behind us.
        sqlx::query!(
            r#"SELECT id FROM component WHERE id = $1 FOR UPDATE"#,
            comp.id
        )
        .fetch_one(&mut *tx)
        .await?;

        let assets = asset_dao::assets_for_component(&mut *tx, comp.id).await?;
        for asset in &assets {
            sqlx::query!(r#"DELETE FROM asset WHERE id = $1"#, asset.id)
                .execute(&mut *tx)
                .await?;
            let enqueued = blob_dao::decref_and_maybe_enqueue_delete(
                &mut tx,
                &asset.blob_sha256,
                ctx.delete_grace,
            )
            .await?;
            let ref_after: i64 = sqlx::query_scalar!(
                r#"SELECT ref_count FROM blob WHERE sha256 = $1"#,
                asset.blob_sha256,
            )
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(0);
            if enqueued {
                summary.blobs_enqueued += 1;
            }
            if audit_blob.is_none() {
                audit_blob = Some(asset.blob_sha256.clone());
                audit_ref_after = Some(ref_after);
                audit_enqueued = enqueued;
            }
        }

        component_dao::delete_component(&mut *tx, ctx.repository_id, &cached.name, &cached.version)
            .await?;
    }

    // Keep the row (and its `first_seen_at`) as a metadata-only entry; the
    // next pull re-fetches the bytes from upstream.
    sqlx::query!(
        r#"UPDATE proxy_cached_version SET downloaded = false WHERE id = $1"#,
        cached.id,
    )
    .execute(&mut *tx)
    .await?;

    retention_dao::insert_audit(
        &mut *tx,
        &AuditRow {
            repository_id: ctx.repository_id,
            run_id: ctx.run_id,
            rule_id: d.rule_id.clone(),
            action: "hard_delete".to_string(),
            target_kind: "proxy_cached_version".to_string(),
            package_name: d.package_name.clone(),
            version: d.version.clone(),
            component_id: None,
            blob_sha256: audit_blob,
            ref_count_after: audit_ref_after,
            blob_delete_enqueued: audit_enqueued,
            dry_run: false,
            reason,
        },
    )
    .await?;
    tx.commit().await?;
    summary.deleted += 1;

    Ok(Step::Continue)
}

fn action_str(a: Action) -> &'static str {
    match a {
        Action::Unlist => "unlist",
        Action::HardDelete => "hard_delete",
    }
}

async fn audit_skipped(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ApplyContext<'_>,
    d: &Decision,
    target_kind: &str,
) -> Result<(), sqlx::Error> {
    retention_dao::insert_audit(
        &mut **tx,
        &AuditRow {
            repository_id: ctx.repository_id,
            run_id: ctx.run_id,
            rule_id: d.rule_id.clone(),
            action: "skipped".to_string(),
            target_kind: target_kind.to_string(),
            package_name: d.package_name.clone(),
            version: d.version.clone(),
            component_id: None,
            blob_sha256: None,
            ref_count_after: None,
            blob_delete_enqueued: false,
            dry_run: false,
            reason: reason_json(&d.reason),
        },
    )
    .await
}

async fn audit_skipped_proxy(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ApplyContext<'_>,
    d: &ProxyDecision,
) -> Result<(), sqlx::Error> {
    retention_dao::insert_audit(
        &mut **tx,
        &AuditRow {
            repository_id: ctx.repository_id,
            run_id: ctx.run_id,
            rule_id: d.rule_id.clone(),
            action: "skipped".to_string(),
            target_kind: "proxy_cached_version".to_string(),
            package_name: d.package_name.clone(),
            version: d.version.clone(),
            component_id: None,
            blob_sha256: None,
            ref_count_after: None,
            blob_delete_enqueued: false,
            dry_run: false,
            reason: reason_json(&d.reason),
        },
    )
    .await
}
