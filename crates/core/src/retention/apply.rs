//! The retention **apply** path (design §3.6 step 9, §3.4 outbox integration).
//!
//! Turns the pure evaluator's [`Decision`] / [`ProxyDecision`] sets into durable
//! mutations. Each decision runs in its **own** small transaction so concurrent
//! pushes can interleave and a crash mid-run loses at most the in-flight
//! decision (already-committed ones are durable + idempotent). Within that one
//! transaction we:
//!
//! 1. `SELECT … FOR UPDATE` the target row (component or proxy cached version)
//!    by **id** and re-verify it still matches the decision. A concurrent
//!    redeploy / re-push / admin delete that changed the row makes us **skip**
//!    (audited as `skipped`) rather than act on stale state.
//! 2. For a hard delete: delete the asset rows, then
//!    [`blob_dao::decref_and_maybe_enqueue_delete`] each referenced blob — this
//!    is the **only** blob-GC path; it decrements `ref_count` and, iff it hits
//!    zero, enqueues a `blob_outbox` `delete_object` in the *same* transaction.
//!    A blob still referenced elsewhere (`ref_count > 0`) gets **no** outbox row
//!    and its S3 object survives. We never delete an S3 object directly.
//! 3. For an unlist: flip `component.listed = false`.
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

use crate::retention::evaluate::{Decision, ProxyDecision};
use crate::retention::model::Action;

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
    let mut summary = RunSummary {
        evaluated: (hosted.len() + proxy.len()) as u64,
        ..Default::default()
    };

    for d in hosted {
        apply_hosted(ctx, d, &mut summary).await?;
    }
    for d in proxy {
        apply_proxy(ctx, d, &mut summary).await?;
    }

    Ok(summary)
}

/// Apply one hosted decision in its own transaction.
async fn apply_hosted(
    ctx: &ApplyContext<'_>,
    d: &Decision,
    summary: &mut RunSummary,
) -> Result<(), sqlx::Error> {
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
        return Ok(());
    }

    let mut tx = ctx.pool.begin().await?;

    // Re-verify: lock the component row by id. A concurrent hard delete may have
    // removed it; a redeploy may have swapped its assets. Lock first so our read
    // of the asset set is consistent with the decref.
    let locked = sqlx::query!(
        r#"
        SELECT id, name, version
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
        return Ok(());
    };

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

    Ok(())
}

/// Apply one proxy eviction in its own transaction. Eviction deletes the cached
/// version's `component` (assets + blob decref, driving the outbox) and the
/// `proxy_cached_version` row.
async fn apply_proxy(
    ctx: &ApplyContext<'_>,
    d: &ProxyDecision,
    summary: &mut RunSummary,
) -> Result<(), sqlx::Error> {
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
        return Ok(());
    }

    let mut tx = ctx.pool.begin().await?;

    // Lock the cached-version row by id; skip if it's gone.
    let cached = sqlx::query!(
        r#"
        SELECT id, name, version
        FROM proxy_cached_version
        WHERE id = $1 AND repository_id = $2
        FOR UPDATE
        "#,
        d.cached_version_id,
        ctx.repository_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(cached) = cached else {
        audit_skipped_proxy(&mut tx, ctx, d).await?;
        tx.commit().await?;
        summary.skipped += 1;
        return Ok(());
    };

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

    // Delete the cached-version marker itself (re-caches on the next pull).
    sqlx::query!(
        r#"DELETE FROM proxy_cached_version WHERE id = $1"#,
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

    Ok(())
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
