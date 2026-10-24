//! Integration tests for the retention **worker**
//! (`forge_core::retention::worker::RetentionWorker`).
//!
//! A single tick on a seeded, armed repository must prune per policy via the
//! blob outbox (decref + `blob_outbox`, never a direct S3 delete); a second
//! tick is a no-op (idempotent — the deleted components are no longer
//! candidates); the ledger's `next_run_at` advances by the per-repo interval;
//! the lease is cleared and the run summary recorded. A `dry_run_only` policy
//! audits but mutates nothing. A shared blob across two versions is not enqueued
//! until its last reference is removed.
//!
//! Postgres only — the apply path produces outbox rows the outbox worker
//! drains; no S3 needed here.

mod common;

use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use forge_core::repo::NoopCacheInvalidator;
use forge_core::retention::worker::{
    RetentionConfig, RetentionWorker, WorkerError, MIN_RUN_INTERVAL_SECONDS,
};
use forge_core::{Format, FormatError, ParsedUpload, ReadSeek};
use forge_db::asset_dao::{self, NewAsset};
use forge_db::component_dao::{self, NewComponent};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::{blob_dao, proxy_dao, retention_dao};
use serde_json::{json, Value};
use sqlx::PgPool;

use common::{pool, unique};

/// NuGet, the built-in format plugin, as the `Format` the repository code
/// works with.
fn nuget() -> forge_plugin::PluginFormat {
    let plugin = forge_plugin::Plugin::builtin(forge_format_nuget::Nuget::default());
    forge_plugin::PluginFormat::new(&plugin)
}

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
        Arc::new(nuget()) as Arc<dyn Format>,
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
async fn zero_run_intervals_do_not_rerun_back_to_back() {
    // Regression (#25): with `default_run_interval = 0` and a policy's
    // `min_run_interval_seconds: 0` (both accepted), a finished run was due
    // again at once, so the drain loop re-claimed the repository forever,
    // a dry-run policy appending audit rows on every pass. Runs are now at
    // least MIN_RUN_INTERVAL_SECONDS apart; a failed run is retried no sooner.
    let pool = pool().await;
    let n = unique();
    let w = worker(
        &pool,
        RetentionConfig {
            default_run_interval: Duration::zero(),
            ..config()
        },
    );
    let floor = Duration::seconds(MIN_RUN_INTERVAL_SECONDS - 5);

    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw0-{n}")))
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
            "min_run_interval_seconds": 0,
            "rules": [{ "id": "r", "action": "hard_delete", "criteria": { "older_than_days": 30 } }]
        }),
    )
    .await;

    let before = Utc::now();
    let summary = w.tick_repo(repo.id).await.unwrap().expect("first run");
    assert_eq!(summary.deleted, 1);
    let run = retention_dao::get_run(&pool, repo.id)
        .await
        .unwrap()
        .unwrap();
    assert!(run.next_run_at >= before + floor, "{:?}", run.next_run_at);
    // The drain loop's next tick finds the repository not due and stops.
    assert!(
        w.tick_repo(repo.id).await.unwrap().is_none(),
        "the repository must not be due again right away"
    );
    assert_eq!(audit_total(&pool, repo.id).await, 1);

    // A run that fails is retried after its policy's interval, here 0, so
    // after the floor.
    let broken =
        repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw0b-{n}")))
            .await
            .unwrap();
    arm(
        &pool,
        broken.id,
        &json!({ "version": 1, "min_run_interval_seconds": 0, "rules": [] }),
    )
    .await;
    let before = Utc::now();
    w.tick_repo(broken.id)
        .await
        .expect_err("an invalid policy fails the run");
    let run = retention_dao::get_run(&pool, broken.id)
        .await
        .unwrap()
        .unwrap();
    assert!(run.next_run_at >= before + floor, "{:?}", run.next_run_at);
    assert!(w.tick_repo(broken.id).await.unwrap().is_none());
}

#[tokio::test]
async fn a_run_survives_an_app_clock_behind_the_database() {
    // #27: with this process's clock an hour behind the database's, the
    // run's lease was computed from the process clock and so had already
    // run out by the database's `now()`: every apply step failed its lease
    // fence, and retention on the instance never removed anything.
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rwc-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n * 100, 1).await;
    seed_component(&pool, repo.id, "lib", "1.0.0", &sha, 100).await;
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{ "id": "r", "action": "hard_delete", "criteria": { "older_than_days": 30 } }]
        }),
    )
    .await;

    let skewed = common::pool_with_clock_ahead().await;
    let w = worker(&skewed, config()); // a 60 s lease, an hour of skew
    let summary = w.tick_repo(repo.id).await.unwrap().unwrap();
    assert_eq!(summary.deleted, 1);
    assert!(!component_exists(&pool, repo.id, "lib", "1.0.0").await);
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

/// The ledger's `locked_until` for a repo.
async fn locked_until(pool: &PgPool, repo_id: i64) -> Option<DateTime<Utc>> {
    retention_dao::get_run(pool, repo_id)
        .await
        .unwrap()
        .unwrap()
        .locked_until
}

/// Insert a proxy cached-version row with backdated timestamps.
async fn seed_cached_version(
    pool: &PgPool,
    repo_id: i64,
    version: &str,
    downloaded: bool,
    last_pulled_days_ago: Option<i32>,
) {
    proxy_dao::upsert_cached_version(
        pool,
        proxy_dao::NewProxyCachedVersion {
            repository_id: repo_id,
            name: "lib".into(),
            version: version.into(),
            listed: true,
            downloaded,
            not_found: false,
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE proxy_cached_version \
         SET first_seen_at = now() - interval '90 days', \
             last_downloaded_at = now() - make_interval(days => $3) \
         WHERE repository_id = $1 AND version = $2",
    )
    .bind(repo_id)
    .bind(version)
    .bind(last_pulled_days_ago)
    .execute(pool)
    .await
    .unwrap();
}

async fn cached_row(
    pool: &PgPool,
    repo_id: i64,
    version: &str,
) -> Option<forge_db::model::ProxyCachedVersion> {
    proxy_dao::get_cached_version(pool, repo_id, "lib", version)
        .await
        .unwrap()
}

async fn audit_total(pool: &PgPool, repo_id: i64) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM retention_audit WHERE repository_id = $1")
        .bind(repo_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn stored_hosted_scope_rule_on_proxy_fails_the_run_without_mutating() {
    // Regression (H2): a policy stored before validation rejected hosted-scope
    // rules on proxies (scope omitted ⇒ hosted) must not run its hosted-style
    // deletes against the proxy's cached components — that left
    // `proxy_cached_version.downloaded = true` with no local copy, so restores
    // 404ed forever. The worker refuses the policy and records a failed run.
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy(format!("rwp-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n * 100, 1).await;
    seed_component(&pool, repo.id, "lib", "1.0.0", &sha, 100).await;
    seed_cached_version(&pool, repo.id, "1.0.0", true, Some(90)).await;

    // Written straight through the DAO, bypassing the admin API's validation,
    // like a policy stored by an older release.
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [
                { "id": "sweep", "action": "hard_delete", "criteria": { "older_than_days": 30 } },
                { "id": "evict", "action": "hard_delete", "scope": "proxy_cached",
                  "criteria": { "not_pulled_for_days": 30 } }
            ]
        }),
    )
    .await;

    let w = worker(&pool, config());
    let err = w
        .tick_repo(repo.id)
        .await
        .expect_err("a hosted-scope rule on a proxy must fail the run");
    assert!(
        matches!(&err, WorkerError::Policy(m) if m.contains("proxy_cached")),
        "error must name the fix: {err}"
    );

    // Nothing was deleted or evicted.
    assert!(component_exists(&pool, repo.id, "lib", "1.0.0").await);
    assert_eq!(ref_count(&pool, &sha).await, Some(1));
    assert!(
        cached_row(&pool, repo.id, "1.0.0")
            .await
            .unwrap()
            .downloaded
    );
    assert_eq!(audit_total(&pool, repo.id).await, 0);

    // The failure is on the ledger and the lease is released.
    let run = retention_dao::get_run(&pool, repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "idle");
    assert!(run.locked_until.is_none());
    let last_error = run.last_error.expect("failed run records last_error");
    assert!(
        last_error.contains("\"sweep\"") && last_error.contains("proxy_cached"),
        "{last_error}"
    );
}

#[tokio::test]
async fn proxy_eviction_keeps_rows_and_ignores_metadata_only_versions() {
    // Regression (M7): eviction used to delete the `proxy_cached_version` row
    // (resetting `first_seen_at`, the package-delay anchor, on the next
    // listing), and metadata-only rows (`downloaded = false`, never pulled)
    // were candidates too, so every run "evicted" them again with an audit row
    // per version. Now only cached bytes are evicted, the row is kept as
    // metadata-only, and a second run finds nothing to do.
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy(format!("rwm-{n}")))
        .await
        .unwrap();
    // 1.0.0: cached bytes, cold. 2.0.0: listed upstream, never pulled.
    let sha = seed_blob(&pool, n * 100, 1).await;
    seed_component(&pool, repo.id, "lib", "1.0.0", &sha, 100).await;
    seed_cached_version(&pool, repo.id, "1.0.0", true, Some(90)).await;
    seed_cached_version(&pool, repo.id, "2.0.0", false, None).await;
    let cold_before = cached_row(&pool, repo.id, "1.0.0").await.unwrap();
    let meta_before = cached_row(&pool, repo.id, "2.0.0").await.unwrap();

    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{ "id": "evict", "action": "hard_delete", "scope": "proxy_cached",
                        "criteria": { "not_pulled_for_days": 30 } }]
        }),
    )
    .await;

    let w = worker(&pool, config());
    let s1 = w.tick_repo(repo.id).await.unwrap().unwrap();
    assert_eq!(
        s1.evaluated, 1,
        "only the downloaded version is a candidate"
    );
    assert_eq!(s1.deleted, 1);
    assert_eq!(audit_total(&pool, repo.id).await, 1);

    // The evicted version: bytes gone, row kept as metadata-only.
    assert!(!component_exists(&pool, repo.id, "lib", "1.0.0").await);
    assert_eq!(ref_count(&pool, &sha).await, Some(0));
    assert_eq!(outbox_count(&pool, &sha).await, 1);
    let cold_after = cached_row(&pool, repo.id, "1.0.0").await.unwrap();
    assert!(!cold_after.downloaded);
    assert_eq!(cold_after.id, cold_before.id);
    assert_eq!(cold_after.first_seen_at, cold_before.first_seen_at);
    // The metadata-only version is untouched.
    let meta_after = cached_row(&pool, repo.id, "2.0.0").await.unwrap();
    assert_eq!(meta_after.id, meta_before.id);
    assert_eq!(meta_after.first_seen_at, meta_before.first_seen_at);

    // A second run has nothing to evict and writes no audit rows.
    retention_dao::schedule_now(&pool, repo.id).await.unwrap();
    let s2 = w.tick_repo(repo.id).await.unwrap().unwrap();
    assert_eq!(s2.evaluated, 0);
    assert_eq!(s2.deleted, 0);
    assert_eq!(audit_total(&pool, repo.id).await, 1);
}

/// A [`Format`] whose version ordering panics, to make `process` panic in the
/// evaluator (which orders each package's versions through the seam).
struct PanickingFormat;

impl Format for PanickingFormat {
    fn id(&self) -> &'static str {
        "nuget"
    }
    fn parse_upload(&self, _file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        unreachable!("retention never parses")
    }
    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        Ok(raw.to_string())
    }
    fn compare_versions(&self, _a: &str, _b: &str) -> Ordering {
        panic!("compare_versions exploded")
    }
    fn lower_id(&self, id: &str) -> String {
        id.to_lowercase()
    }
}

/// Short lease ⇒ the heartbeat renews every second.
fn short_lease_config() -> RetentionConfig {
    RetentionConfig {
        lease: Duration::seconds(3),
        ..config()
    }
}

#[tokio::test]
async fn panicking_run_is_recorded_as_failed_and_its_heartbeat_stops() {
    // Regression (L10): a panic in `process` used to unwind past `fail_run`,
    // leaving the ledger row `running` while the detached heartbeat renewed
    // its lease forever, so the repository was never retried.
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw6-{n}")))
        .await
        .unwrap();
    for i in 0..2u64 {
        let sha = seed_blob(&pool, n * 100 + i, 1).await;
        seed_component(&pool, repo.id, "lib", &format!("1.0.{i}"), &sha, 100).await;
    }
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{ "id": "sweep", "action": "hard_delete", "criteria": { "older_than_days": 30 } }]
        }),
    )
    .await;

    let w = RetentionWorker::new(
        pool.clone(),
        Arc::new(PanickingFormat) as Arc<dyn Format>,
        Arc::new(NoopCacheInvalidator),
        short_lease_config(),
    );
    let err = w
        .tick_repo(repo.id)
        .await
        .expect_err("a panicking run surfaces as an error");
    assert!(
        matches!(&err, WorkerError::Panicked(m) if m.contains("compare_versions exploded")),
        "{err}"
    );

    let run = retention_dao::get_run(&pool, repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "idle", "the failed run must be recorded");
    assert!(run.locked_until.is_none(), "the lease must be released");
    assert!(run.last_error.unwrap().contains("panicked"));

    // Past several heartbeat periods, nothing renews the lease.
    tokio::time::sleep(StdDuration::from_millis(2500)).await;
    let run = retention_dao::get_run(&pool, repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "idle");
    assert!(run.locked_until.is_none());
    assert!(component_exists(&pool, repo.id, "lib", "1.0.0").await);
}

#[tokio::test]
async fn dropped_tick_aborts_its_lease_heartbeat() {
    // Regression (L10): the heartbeat was a detached task, so a run whose
    // future was dropped mid-flight (e.g. a shutdown select or timeout) kept
    // renewing its lease forever. Block the run on a row lock, drop it, and
    // check the lease stops advancing.
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw7-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n * 100, 1).await;
    let comp_id = seed_component(&pool, repo.id, "lib", "1.0.0", &sha, 100).await;
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{ "id": "sweep", "action": "hard_delete", "criteria": { "older_than_days": 30 } }]
        }),
    )
    .await;

    // Hold the component's row lock so the apply step blocks.
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM component WHERE id = $1 FOR UPDATE")
        .bind(comp_id)
        .execute(&mut *blocker)
        .await
        .unwrap();

    let w = worker(&pool, short_lease_config());
    let timed_out = tokio::time::timeout(StdDuration::from_millis(2500), w.tick_repo(repo.id))
        .await
        .is_err();
    assert!(timed_out, "the run must have been blocked on the row lock");

    // The run was claimed and its lease renewed while it ran ...
    let before = locked_until(&pool, repo.id)
        .await
        .expect("the abandoned run still holds its lease");
    // ... but once the tick future is gone, nobody renews it.
    tokio::time::sleep(StdDuration::from_millis(2500)).await;
    assert_eq!(
        locked_until(&pool, repo.id).await,
        Some(before),
        "a dropped run's heartbeat must stop renewing the lease"
    );

    blocker.rollback().await.unwrap();
}

/// Claim `repo_id`'s run and evaluate its hosted versions as the worker does,
/// stopping before the apply step so a test can change state in between.
async fn claim_and_evaluate(
    pool: &PgPool,
    repo_id: i64,
) -> (
    retention_dao::ClaimedRepo,
    uuid::Uuid,
    forge_core::retention::model::RetentionPolicy,
    Vec<forge_core::retention::evaluate::Decision>,
) {
    let mut tx = pool.begin().await.unwrap();
    let (claimed, run_id) = retention_dao::claim_next_due_repo(
        &mut tx,
        Utc::now(),
        Duration::seconds(300),
        Some(repo_id),
    )
    .await
    .unwrap()
    .expect("due");
    tx.commit().await.unwrap();
    let policy: forge_core::retention::model::RetentionPolicy =
        serde_json::from_value(claimed.policy.clone()).unwrap();
    let candidates: Vec<_> =
        retention_dao::load_candidate_components(pool, repo_id, forge_core::repo::NUPKG_ASSET_PATH)
            .await
            .unwrap()
            .into_iter()
            .map(
                |(r, _)| forge_core::retention::evaluate::CandidateComponent {
                    component_id: r.component_id,
                    package_name: r.name,
                    version: r.version,
                    listed: r.listed,
                    created_at: r.created_at,
                    last_downloaded_at: r.last_downloaded_at,
                    size_bytes: u64::try_from(r.size_bytes).unwrap_or_default(),
                },
            )
            .collect();
    let decisions =
        forge_core::retention::evaluate::evaluate(&nuget(), Utc::now(), &policy, &candidates);
    (claimed, run_id, policy, decisions)
}

async fn apply_fenced(
    pool: &PgPool,
    claimed: &retention_dao::ClaimedRepo,
    run_id: uuid::Uuid,
    policy: &forge_core::retention::model::RetentionPolicy,
    decisions: &[forge_core::retention::evaluate::Decision],
) -> retention_dao::RunSummary {
    let format = nuget();
    let ctx = forge_core::retention::apply::ApplyContext {
        pool,
        repository_id: claimed.repository_id,
        repository_name: &claimed.name,
        run_id,
        delete_grace: Duration::seconds(60),
        dry_run: false,
        evaluated_at: Some(Utc::now()),
        fence: Some(forge_core::retention::apply::RunFence {
            stored_policy: &claimed.policy,
            policy,
            format: &format,
        }),
    };
    forge_core::retention::apply::apply(&ctx, decisions, &[])
        .await
        .unwrap()
}

/// Review: `keep_last_n: 1` protects 2.0.0, so 1.0.0 is decided for deletion;
/// the owner unlists 2.0.0 before the decision is applied. Re-evaluated under
/// the lock, 1.0.0 is now the newest listed version and protected: it must
/// not be deleted (that would leave the package without a listed version).
#[tokio::test]
async fn a_protection_gained_mid_run_is_honoured() {
    let pool = pool().await;
    let n = unique();
    let repo =
        repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw-fence-{n}")))
            .await
            .unwrap();
    for (i, version) in ["1.0.0", "2.0.0"].into_iter().enumerate() {
        let sha = seed_blob(&pool, n * 100 + i as u64, 1).await;
        seed_component(&pool, repo.id, "lib", version, &sha, 100).await;
    }
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{
                "id": "latest",
                "action": "hard_delete",
                "criteria": { "keep_last_n": 1, "older_than_days": 30 }
            }]
        }),
    )
    .await;
    let (claimed, run_id, policy, decisions) = claim_and_evaluate(&pool, repo.id).await;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].version, "1.0.0");

    sqlx::query(
        "UPDATE component SET listed = false WHERE repository_id = $1 AND version = '2.0.0'",
    )
    .bind(repo.id)
    .execute(&pool)
    .await
    .unwrap();

    let summary = apply_fenced(&pool, &claimed, run_id, &policy, &decisions).await;
    assert_eq!((summary.deleted, summary.skipped), (0, 1));
    assert!(component_exists(&pool, repo.id, "lib", "1.0.0").await);
}

/// A policy edited (or disabled) while a run is applying stops the run: no
/// further decision made under the old policy is applied. So does a run
/// that lost its lease.
#[tokio::test]
async fn a_policy_change_or_lost_lease_stops_the_run() {
    let pool = pool().await;
    let n = unique();
    let policy_json = json!({
        "version": 1,
        "rules": [{
            "id": "latest",
            "action": "hard_delete",
            "criteria": { "keep_last_n": 1, "older_than_days": 30 }
        }]
    });
    for lose_lease in [false, true] {
        let repo = repository_dao::insert_repository(
            &pool,
            NewRepository::hosted(format!("rw-stop-{n}-{lose_lease}")),
        )
        .await
        .unwrap();
        for (i, version) in ["1.0.0", "2.0.0", "3.0.0"].into_iter().enumerate() {
            let sha = seed_blob(&pool, n * 100 + 10 * lose_lease as u64 + i as u64, 1).await;
            seed_component(&pool, repo.id, "lib", version, &sha, 100).await;
        }
        arm(&pool, repo.id, &policy_json).await;
        let (claimed, run_id, policy, decisions) = claim_and_evaluate(&pool, repo.id).await;
        assert_eq!(decisions.len(), 2);

        if lose_lease {
            sqlx::query("UPDATE retention_run SET current_run_id = gen_random_uuid() WHERE repository_id = $1")
                .bind(repo.id)
                .execute(&pool)
                .await
                .unwrap();
        } else {
            let mut keep_all = policy_json.clone();
            keep_all["rules"][0]["criteria"]["keep_last_n"] = json!(5);
            retention_dao::write_policy(&pool, repo.id, Some(&keep_all))
                .await
                .unwrap();
        }

        let summary = apply_fenced(&pool, &claimed, run_id, &policy, &decisions).await;
        assert_eq!(
            (summary.deleted, summary.skipped),
            (0, 2),
            "lose_lease={lose_lease}"
        );
        for version in ["1.0.0", "2.0.0", "3.0.0"] {
            assert!(component_exists(&pool, repo.id, "lib", version).await);
        }
    }
}

/// Review: re-evaluating a package once per decision was quadratic. Its
/// decisions are now applied in batches that re-evaluate it once each; every
/// batch still honours a protection gained after the evaluation (here: the
/// newest `big` version unlisted, so `keep_last_n: 1` now protects the one
/// before it, whichever batch holds that decision).
#[tokio::test]
async fn a_package_with_many_versions_is_applied_in_batches() {
    let pool = pool().await;
    let n = unique();
    let repo =
        repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rw-batch-{n}")))
            .await
            .unwrap();
    let mut tag = (1u64 << 48) | (n << 16);
    for (package, count) in [("big", 230), ("small", 2)] {
        for i in 0..count {
            tag += 1;
            let sha = seed_blob(&pool, tag, 1).await;
            seed_component(&pool, repo.id, package, &format!("1.0.{i}"), &sha, 100).await;
        }
    }
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{
                "id": "latest",
                "action": "hard_delete",
                "criteria": { "keep_last_n": 1, "older_than_days": 30 }
            }]
        }),
    )
    .await;
    let (claimed, run_id, policy, decisions) = claim_and_evaluate(&pool, repo.id).await;
    assert_eq!(decisions.len(), 229 + 1);

    sqlx::query(
        "UPDATE component SET listed = false \
         WHERE repository_id = $1 AND name = 'big' AND version = '1.0.229'",
    )
    .bind(repo.id)
    .execute(&pool)
    .await
    .unwrap();

    let summary = apply_fenced(&pool, &claimed, run_id, &policy, &decisions).await;
    assert_eq!((summary.deleted, summary.skipped), (228 + 1, 1));
    assert!(component_exists(&pool, repo.id, "big", "1.0.228").await);
    assert!(component_exists(&pool, repo.id, "big", "1.0.229").await);
    assert!(!component_exists(&pool, repo.id, "big", "1.0.0").await);
    assert!(!component_exists(&pool, repo.id, "big", "1.0.227").await);
    assert!(component_exists(&pool, repo.id, "small", "1.0.1").await);
    assert!(!component_exists(&pool, repo.id, "small", "1.0.0").await);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM retention_audit WHERE run_id = $1 AND action = 'hard_delete'",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 229);
}

#[tokio::test]
async fn a_failed_run_is_retried_after_its_policy_interval() {
    // The worker's floor is a minute (the server sets no floor of its own,
    // #429), but a broken policy must not be retried every minute: a failed
    // run waits for its policy's interval, the default hour when it names
    // none.
    let pool = pool().await;
    let n = unique();
    let w = worker(
        &pool,
        RetentionConfig {
            default_run_interval: Duration::seconds(MIN_RUN_INTERVAL_SECONDS),
            ..config()
        },
    );
    let broken =
        repository_dao::insert_repository(&pool, NewRepository::hosted(format!("rwr-{n}")))
            .await
            .unwrap();
    arm(&pool, broken.id, &json!({ "version": 1, "rules": [] })).await;
    let before = Utc::now();
    w.tick_repo(broken.id)
        .await
        .expect_err("an invalid policy fails the run");
    let run = retention_dao::get_run(&pool, broken.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        run.next_run_at >= before + Duration::seconds(3600 - 5),
        "{:?}",
        run.next_run_at
    );
}

#[tokio::test]
async fn proxy_eviction_keeps_the_newest_and_the_recently_pulled_versions() {
    // #59: a proxy rule's protections keep a working set per package, so a
    // quiet month no longer evicts every cached version of it.
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy(format!("rwk-{n}")))
        .await
        .unwrap();
    // Four cold cached versions; 1.0.0 was pulled last, 4.0.0 is the newest.
    for (i, (version, pulled)) in [("1.0.0", 40), ("2.0.0", 60), ("3.0.0", 70), ("4.0.0", 80)]
        .into_iter()
        .enumerate()
    {
        let sha = seed_blob(&pool, n * 100 + i as u64, 1).await;
        seed_component(&pool, repo.id, "lib", version, &sha, 100).await;
        seed_cached_version(&pool, repo.id, version, true, Some(pulled)).await;
    }
    arm(
        &pool,
        repo.id,
        &json!({
            "version": 1,
            "rules": [{ "id": "evict", "action": "hard_delete", "scope": "proxy_cached",
                        "criteria": { "not_pulled_for_days": 30,
                                      "keep_last_n": 1, "keep_n_most_downloaded": 1 } }]
        }),
    )
    .await;

    let w = worker(&pool, config());
    let summary = w.tick_repo(repo.id).await.unwrap().unwrap();
    assert_eq!(summary.deleted, 2);
    // The newest (4.0.0) and the one pulled last (1.0.0) stay cached.
    for (version, kept) in [
        ("1.0.0", true),
        ("2.0.0", false),
        ("3.0.0", false),
        ("4.0.0", true),
    ] {
        assert_eq!(
            component_exists(&pool, repo.id, "lib", version).await,
            kept,
            "{version}"
        );
        assert_eq!(
            cached_row(&pool, repo.id, version)
                .await
                .unwrap()
                .downloaded,
            kept,
            "{version}"
        );
    }
}
