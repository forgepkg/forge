//! Integration tests for the retention **worker**
//! (`forge_core::retention::worker::RetentionWorker`, slice 12.1 Phase 5).
//!
//! A single tick on a seeded, armed repository must prune per policy via the
//! slice-1 outbox (decref + `blob_outbox`, never a direct S3 delete); a second
//! tick is a no-op (idempotent — the deleted components are no longer
//! candidates); the ledger's `next_run_at` advances by the per-repo interval;
//! the lease is cleared and the run summary recorded. A `dry_run_only` policy
//! audits but mutates nothing. A shared blob across two versions is not enqueued
//! until its last reference is removed.
//!
//! Postgres only — the apply path produces outbox rows the slice-1 worker
//! drains; no S3 needed here.

mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use forge_core::repo::NoopCacheInvalidator;
use forge_core::retention::worker::{RetentionConfig, RetentionWorker};
use forge_db::asset_dao::{self, NewAsset};
use forge_db::component_dao::{self, NewComponent};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::{blob_dao, retention_dao};
use forge_nuget::NugetFormat;
use serde_json::{json, Value};
use sqlx::PgPool;

use common::{pool, unique};

fn config() -> RetentionConfig {
    RetentionConfig {
        poll_interval: StdDuration::from_millis(10),
        default_run_interval: Duration::seconds(1),
        lease: Duration::seconds(60),
        delete_grace: Duration::seconds(60),
    }
}

fn worker(pool: &PgPool, config: RetentionConfig) -> RetentionWorker {
    RetentionWorker::new(
        pool.clone(),
        Arc::new(NugetFormat::new()),
        Arc::new(NoopCacheInvalidator),
        config,
    )
}

/// Seed a committed blob (`ref_count = increments`) and return its sha.
async fn seed_blob(pool: &PgPool, tag: u64, increments: u32) -> String {
    let sha = format!("{:064x}", tag);
    blob_dao::upsert_pending(pool, &sha, 100, &format!("k/{sha}"))
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    for _ in 0..increments {
        blob_dao::commit_and_incref(&mut tx, &sha).await.unwrap();
    }
    tx.commit().await.unwrap();
    sha
}

/// Seed a hosted component + its `.nupkg` asset pointing at `sha`, backdating
/// `created_at` by `created_days_ago` so age criteria fire deterministically.
async fn seed_component(
    pool: &PgPool,
    repo_id: i64,
    name: &str,
    version: &str,
    sha: &str,
    created_days_ago: i64,
) -> i64 {
    let comp = component_dao::insert_component(
        pool,
        NewComponent {
            repository_id: repo_id,
            name: name.into(),
            original_id: name.into(),
            version: version.into(),
            version_original: version.into(),
            listed: true,
        },
    )
    .await
    .unwrap();
    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: comp.id,
            path: format!("{name}.{version}.nupkg"),
            content_type: "application/octet-stream".into(),
            blob_sha256: sha.into(),
            size: 100,
            sha512_base64: None,
        },
    )
    .await
    .unwrap();
    // Backdate created_at.
    sqlx::query(
        "UPDATE component SET created_at = now() - make_interval(days => $2) WHERE id = $1",
    )
    .bind(comp.id)
    .bind(created_days_ago as i32)
    .execute(pool)
    .await
    .unwrap();
    comp.id
}

async fn arm(pool: &PgPool, repo_id: i64, policy: &Value) {
    retention_dao::write_policy(pool, repo_id, Some(policy))
        .await
        .unwrap();
}

async fn ref_count(pool: &PgPool, sha: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT ref_count FROM blob WHERE sha256 = $1")
        .bind(sha)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn outbox_count(pool: &PgPool, sha: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM blob_outbox WHERE sha256 = $1 AND op = 'delete_object'",
    )
    .bind(sha)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn component_exists(pool: &PgPool, repo_id: i64, name: &str, version: &str) -> bool {
    component_dao::find_component(pool, repo_id, name, version)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn tick_prunes_per_policy_and_drives_outbox() {
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw-{n}")))
        .await
        .unwrap();

    // 12 versions, each its own blob, all 100 days old; keep_last_n=10 +
    // older_than_days=30 ⇒ delete the 2 oldest (1.0.1, 1.0.2).
    let mut shas = Vec::new();
    for i in 1..=12u64 {
        let sha = seed_blob(&pool, n * 100 + i, 1).await;
        seed_component(&pool, repo.id, "lib", &format!("1.0.{i}"), &sha, 100).await;
        shas.push(sha);
    }

    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{
                "id": "keep-recent",
                "action": "hard_delete",
                "criteria": { "keep_last_n": 10, "older_than_days": 30 }
            }]
        }),
    )
    .await;

    let w = worker(&pool, config());
    let summary = w
        .tick_repo(repo.id)
        .await
        .expect("tick")
        .expect("a repo was due");

    assert_eq!(summary.deleted, 2, "two oldest hard-deleted");
    assert_eq!(summary.blobs_enqueued, 2);

    // 1.0.1 and 1.0.2 gone; 1.0.3..1.0.12 remain.
    assert!(!component_exists(&pool, repo.id, "lib", "1.0.1").await);
    assert!(!component_exists(&pool, repo.id, "lib", "1.0.2").await);
    assert!(component_exists(&pool, repo.id, "lib", "1.0.3").await);
    assert!(component_exists(&pool, repo.id, "lib", "1.0.12").await);

    // Their blobs hit ref_count 0 and were enqueued for S3 deletion.
    assert_eq!(ref_count(&pool, &shas[0]).await, Some(0));
    assert_eq!(outbox_count(&pool, &shas[0]).await, 1);
    assert_eq!(ref_count(&pool, &shas[1]).await, Some(0));
    assert_eq!(outbox_count(&pool, &shas[1]).await, 1);
    // A surviving version's blob is untouched.
    assert_eq!(ref_count(&pool, &shas[11]).await, Some(1));
    assert_eq!(outbox_count(&pool, &shas[11]).await, 0);

    // Ledger: idle, lease cleared, next_run_at advanced, summary recorded.
    let run = retention_dao::get_run(&pool, repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "idle");
    assert!(run.locked_until.is_none());
    assert!(run.next_run_at > Utc::now());
    assert!(run.last_run_summary.is_some());
}

#[tokio::test]
async fn second_tick_is_a_noop_after_pruning() {
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw2-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n * 100, 1).await;
    seed_component(&pool, repo.id, "lib", "1.0.0", &sha, 100).await;
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{ "id": "sweep", "action": "hard_delete", "criteria": { "older_than_days": 30 } }]
        }),
    )
    .await;

    let w = worker(&pool, config());
    let s1 = w.tick_repo(repo.id).await.unwrap().unwrap();
    assert_eq!(s1.deleted, 1);
    assert!(!component_exists(&pool, repo.id, "lib", "1.0.0").await);

    // Force it due again (the schedule pushed it into the future).
    retention_dao::schedule_now(&pool, repo.id).await.unwrap();
    let s2 = w.tick_repo(repo.id).await.unwrap().unwrap();
    assert_eq!(s2.deleted, 0, "nothing left to delete");
    assert_eq!(s2.evaluated, 0);
}

#[tokio::test]
async fn next_run_at_respects_per_repo_min_interval() {
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw3-{n}")))
        .await
        .unwrap();
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "min_run_interval_seconds": 86400,
            "rules": [{ "id": "r", "action": "hard_delete", "criteria": { "older_than_days": 30 } }]
        }),
    )
    .await;

    let before = Utc::now();
    let w = worker(&pool, config()); // default_run_interval = 1s
    w.tick_repo(repo.id).await.unwrap().unwrap();

    let run = retention_dao::get_run(&pool, repo.id)
        .await
        .unwrap()
        .unwrap();
    // The per-repo 1-day floor wins over the 1s default.
    assert!(
        run.next_run_at >= before + Duration::seconds(86_400 - 5),
        "next_run_at should honor the larger per-repo interval"
    );
}

#[tokio::test]
async fn dry_run_only_audits_but_mutates_nothing() {
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw4-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n * 100, 1).await;
    seed_component(&pool, repo.id, "lib", "1.0.0", &sha, 100).await;
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "dry_run_only": true,
            "rules": [{ "id": "r", "action": "hard_delete", "criteria": { "older_than_days": 30 } }]
        }),
    )
    .await;

    let w = worker(&pool, config());
    let summary = w.tick_repo(repo.id).await.unwrap().unwrap();
    assert_eq!(summary.deleted, 1, "summary counts the would-be delete");

    // Nothing mutated: component present, blob untouched, no outbox.
    assert!(component_exists(&pool, repo.id, "lib", "1.0.0").await);
    assert_eq!(ref_count(&pool, &sha).await, Some(1));
    assert_eq!(outbox_count(&pool, &sha).await, 0);

    // A dry-run audit row exists.
    let dry: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM retention_audit WHERE repository_id = $1 AND dry_run",
    )
    .bind(repo.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dry, 1);
}

#[tokio::test]
async fn shared_blob_not_enqueued_until_last_reference_removed() {
    // One blob shared by two versions of the SAME package (ref_count = 2).
    // older_than_days sweeps both; the first delete drops ref to 1 (no outbox),
    // the second to 0 (enqueued once). Proves the worker never deletes a still-
    // referenced blob.
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw5-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n * 100, 2).await; // shared
    seed_component(&pool, repo.id, "lib", "1.0.0", &sha, 100).await;
    seed_component(&pool, repo.id, "lib", "2.0.0", &sha, 100).await;
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{ "id": "sweep", "action": "hard_delete", "criteria": { "older_than_days": 30 } }]
        }),
    )
    .await;

    let w = worker(&pool, config());
    let summary = w.tick_repo(repo.id).await.unwrap().unwrap();

    assert_eq!(summary.deleted, 2);
    // Both versions deleted, but the shared blob was only enqueued once (when
    // its last reference dropped to 0).
    assert_eq!(summary.blobs_enqueued, 1);
    assert_eq!(ref_count(&pool, &sha).await, Some(0));
    assert_eq!(outbox_count(&pool, &sha).await, 1);
}
