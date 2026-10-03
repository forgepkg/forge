//! The retention **apply** path (design §3.6 step 9, §3.4 outbox integration).
//!
//! Turns the pure evaluator's [`Decision`] / [`ProxyDecision`] sets into durable
//! mutations. Each decision runs in its **own** small transaction so concurrent
//! pushes can interleave and a crash mid-run loses at most the in-flight
//! decision (already-committed ones are durable + idempotent). Within that one
//! transaction we:
//!
//! 1. Fence the step to its run ([`RunFence`]): the run must still own its
//!    lease and the stored policy must still be the one it evaluated, or the
//!    run **stops** (the rest is left to the next run under the current
//!    policy). Then lock the package's versions and **re-evaluate** them: a
//!    decision the current state no longer produces (say `keep_last_n` now
//!    protects the version because a newer one was unlisted) is skipped.
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

use chrono::Duration;
use serde_json::Value as JsonValue;
use sqlx::PgPool;

use forge_db::retention_dao::{self, AuditRow, RunSummary};
use forge_db::{asset_dao, blob_dao, component_dao};

use crate::format::Format;
use crate::retention::evaluate::{evaluate, CandidateComponent, Decision, ProxyDecision};
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
    /// The metadata pool (each decision opens its own short tx on it).
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

/// Apply a set of hosted + proxy decisions, returning the run summary.
///
/// Decisions are applied independently; an error on one decision aborts that
/// decision's transaction (rolling back its effect *and* audit together) and
/// propagates, leaving earlier committed decisions intact.
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

    let mut started = 0;
    for d in hosted {
        started += 1;
        if apply_hosted(ctx, d, &mut summary).await? == Step::Stop {
            return Ok(stopped(ctx, summary, total - started + 1));
        }
    }
    for d in proxy {
        started += 1;
        if apply_proxy(ctx, d, &mut summary).await? == Step::Stop {
            return Ok(stopped(ctx, summary, total - started + 1));
        }
    }

    Ok(summary)
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

/// Whether evaluating the package's current versions (locked by this call)
/// under the run's policy still yields `d`.
async fn still_decided(
    tx: &mut sqlx::PgConnection,
    ctx: &ApplyContext<'_>,
    fence: &RunFence<'_>,
    d: &Decision,
) -> Result<bool, sqlx::Error> {
    let candidates: Vec<CandidateComponent> =
        retention_dao::lock_package_candidates(tx, ctx.repository_id, &d.package_name)
            .await?
            .into_iter()
            .map(|r| CandidateComponent {
                component_id: r.component_id,
                package_name: r.name,
                version: r.version,
                listed: r.listed,
                created_at: r.created_at,
                last_downloaded_at: r.last_downloaded_at,
            })
            .collect();
    let now = ctx.evaluated_at.unwrap_or_else(chrono::Utc::now);
    Ok(evaluate(fence.format, now, fence.policy, &candidates)
        .iter()
        .any(|again| again.component_id == d.component_id && again.action == d.action))
}

/// Apply one hosted decision in its own transaction.
async fn apply_hosted(
    ctx: &ApplyContext<'_>,
    d: &Decision,
    summary: &mut RunSummary,
) -> Result<Step, sqlx::Error> {
    let reason = reason_json(&d.reason);

    // Dry run: record intent, mutate nothing.
    if ctx.dry_run {
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
        if !still_decided(&mut tx, ctx, fence, d).await? {
            audit_skipped(&mut tx, ctx, d, "component").await?;
            tx.commit().await?;
            summary.skipped += 1;
            return Ok(Step::Continue);
        }
    }

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
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = locked else {
        // Gone under us — skip, audit as skipped.
        audit_skipped(&mut tx, ctx, d, "component").await?;
        tx.commit().await?;
        summary.skipped += 1;
        return Ok(Step::Continue);
    };
    // Downloaded while this run was working: no longer cold — skip.
    if downloaded_since(
        ctx,
        d.reason.not_downloaded_for_days.is_some(),
        row.last_downloaded_at,
    ) {
        audit_skipped(&mut tx, ctx, d, "component").await?;
        tx.commit().await?;
        summary.skipped += 1;
        return Ok(Step::Continue);
    }

    match d.action {
        Action::Unlist => {
            sqlx::query!(
                r#"UPDATE component SET listed = false, updated_at = now() WHERE id = $1"#,
                row.id,
            )
            .execute(&mut *tx)
            .await?;
            retention_dao::insert_audit(
                &mut *tx,
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
            tx.commit().await?;
            summary.unlisted += 1;
        }
        Action::HardDelete => {
            let assets = asset_dao::assets_for_component(&mut *tx, row.id).await?;

            // Track the primary .nupkg blob for the audit row; decref every
            // referenced blob (an asset set may share or differ).
            let mut audit_blob: Option<String> = None;
            let mut audit_ref_after: Option<i64> = None;
            let mut audit_enqueued = false;

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

                // Observe the post-decref ref_count for the audit row.
                let ref_after: i64 = sqlx::query_scalar!(
                    r#"SELECT ref_count FROM blob WHERE sha256 = $1"#,
                    asset.blob_sha256,
                )
                .fetch_optional(&mut *tx)
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

            component_dao::delete_component(&mut *tx, ctx.repository_id, &row.name, &row.version)
                .await?;

            retention_dao::insert_audit(
                &mut *tx,
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
            tx.commit().await?;
            summary.deleted += 1;
        }
    }

    Ok(Step::Continue)
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
