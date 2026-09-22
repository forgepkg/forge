//! Integration tests for the retention **apply** path (`forge_core::retention::apply`).
//!
//! These exercise the slice-1 outbox integration directly: applying a
//! `hard_delete` decision must decrement `blob.ref_count` and enqueue a
//! `blob_outbox` delete **only** when the count hits zero; a blob still
//! referenced by another version/repo must **not** be enqueued and its row must
//! survive; an `unlist` decision flips `listed=false` and enqueues nothing; a
//! `dry_run` records audit rows but mutates nothing. Postgres only — no S3 (the
//! apply path never touches S3, it only produces outbox rows the slice-1 worker
//! drains).

mod common;

use chrono::Duration;
use forge_core::retention::apply::{apply, ApplyContext};
use forge_core::retention::evaluate::{Decision, DecisionReason, ProxyDecision};
use forge_core::retention::model::Action;
use forge_db::asset_dao::{self, NewAsset};
use forge_db::component_dao::{self, NewComponent};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::{blob_dao, proxy_dao};
use sqlx::PgPool;

const GRACE: Duration = Duration::seconds(60);

fn reason() -> DecisionReason {
    DecisionReason {
        older_than_days: Some(30),
        not_downloaded_for_days: None,
        not_pulled_for_days: None,
    }
}

/// Seed a committed blob with `ref_count = 1` and return its sha.
async fn seed_blob(pool: &PgPool, tag: u64, ref_increments: u32) -> String {
    let sha = format!("{:064x}", tag);
    blob_dao::upsert_pending(pool, &sha, 100, &format!("k/{sha}"))
        .await
        .expect("upsert blob");
    let mut tx = pool.begin().await.unwrap();
    for _ in 0..ref_increments {
        blob_dao::commit_and_incref(&mut tx, &sha).await.unwrap();
    }
    tx.commit().await.unwrap();
    sha
}

/// Seed a hosted component + its .nupkg asset pointing at `sha` (does not touch
/// the blob refcount — caller seeds that). Returns component id.
async fn seed_component(pool: &PgPool, repo_id: i64, name: &str, version: &str, sha: &str) -> i64 {
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
    .expect("insert component");
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
    .expect("insert asset");
    comp.id
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

async fn ref_count(pool: &PgPool, sha: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT ref_count FROM blob WHERE sha256 = $1")
        .bind(sha)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn audit_rows(pool: &PgPool, run_id: uuid::Uuid) -> Vec<(String, bool, Option<i64>)> {
    sqlx::query_as::<_, (String, bool, Option<i64>)>(
        "SELECT action, blob_delete_enqueued, ref_count_after \
         FROM retention_audit WHERE run_id = $1 ORDER BY id",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

fn ctx<'a>(pool: &'a PgPool, repo_id: i64, name: &'a str, run_id: uuid::Uuid) -> ApplyContext<'a> {
    ApplyContext {
        pool,
        repository_id: repo_id,
        repository_name: name,
        run_id,
        delete_grace: GRACE,
        dry_run: false,
        evaluated_at: None,
    }
}

#[tokio::test]
async fn hard_delete_drives_refcount_to_zero_and_enqueues_outbox() {
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("r-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n, 1).await; // ref_count = 1
    let comp_id = seed_component(&pool, repo.id, "lib", "1.0.0", &sha).await;

    let run_id = uuid::Uuid::new_v4();
    let decision = Decision {
        component_id: comp_id,
        package_name: "lib".into(),
        version: "1.0.0".into(),
        action: Action::HardDelete,
        rule_id: "r".into(),
        reason: reason(),
    };

    let summary = apply(&ctx(&pool, repo.id, &repo.name, run_id), &[decision], &[])
        .await
        .expect("apply");

    assert_eq!(summary.deleted, 1);
    assert_eq!(summary.blobs_enqueued, 1);

    // ref_count hit 0 → exactly one outbox row enqueued.
    assert_eq!(ref_count(&pool, &sha).await, Some(0));
    assert_eq!(outbox_count(&pool, &sha).await, 1);

    // Component + asset are gone.
    assert!(
        component_dao::find_component(&pool, repo.id, "lib", "1.0.0")
            .await
            .unwrap()
            .is_none()
    );

    // One hard_delete audit row recording the enqueue.
    let rows = audit_rows(&pool, run_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "hard_delete");
    assert!(rows[0].1, "blob_delete_enqueued must be true");
    assert_eq!(rows[0].2, Some(0));
}

#[tokio::test]
async fn shared_blob_is_not_enqueued_while_still_referenced() {
    // One blob referenced by two versions (ref_count = 2). Deleting one version
    // drops it to 1 → NO outbox row, blob survives. Deleting the second drops it
    // to 0 → outbox row enqueued.
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("r-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n, 2).await; // ref_count = 2 (shared)
    let c1 = seed_component(&pool, repo.id, "lib", "1.0.0", &sha).await;
    let c2 = seed_component(&pool, repo.id, "lib", "2.0.0", &sha).await;

    // Delete v1: ref_count 2 → 1, nothing enqueued.
    let run1 = uuid::Uuid::new_v4();
    let s1 = apply(
        &ctx(&pool, repo.id, &repo.name, run1),
        &[Decision {
            component_id: c1,
            package_name: "lib".into(),
            version: "1.0.0".into(),
            action: Action::HardDelete,
            rule_id: "r".into(),
            reason: reason(),
        }],
        &[],
    )
    .await
    .unwrap();
    assert_eq!(s1.blobs_enqueued, 0);
    assert_eq!(ref_count(&pool, &sha).await, Some(1));
    assert_eq!(
        outbox_count(&pool, &sha).await,
        0,
        "shared blob must NOT be enqueued"
    );

    // The audit row reflects the surviving reference.
    let rows1 = audit_rows(&pool, run1).await;
    assert_eq!(rows1[0].0, "hard_delete");
    assert!(
        !rows1[0].1,
        "blob_delete_enqueued must be false while referenced"
    );
    assert_eq!(rows1[0].2, Some(1));

    // Delete v2: ref_count 1 → 0, now enqueued exactly once.
    let run2 = uuid::Uuid::new_v4();
    let s2 = apply(
        &ctx(&pool, repo.id, &repo.name, run2),
        &[Decision {
            component_id: c2,
            package_name: "lib".into(),
            version: "2.0.0".into(),
            action: Action::HardDelete,
            rule_id: "r".into(),
            reason: reason(),
        }],
        &[],
    )
    .await
    .unwrap();
    assert_eq!(s2.blobs_enqueued, 1);
    assert_eq!(ref_count(&pool, &sha).await, Some(0));
    assert_eq!(outbox_count(&pool, &sha).await, 1);
}

#[tokio::test]
async fn shared_blob_across_two_repos_is_not_enqueued() {
    // Same bytes pushed to repo A and repo B (one blob, ref_count = 2). Retention
    // deletes the version in repo A → ref_count 1, no outbox row, S3 object (row)
    // survives.
    let pool = common::pool().await;
    let n = common::unique();
    let repo_a = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("a-{n}")))
        .await
        .unwrap();
    let repo_b = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("b-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n, 2).await;
    let ca = seed_component(&pool, repo_a.id, "lib", "1.0.0", &sha).await;
    seed_component(&pool, repo_b.id, "lib", "1.0.0", &sha).await;

    let run = uuid::Uuid::new_v4();
    apply(
        &ctx(&pool, repo_a.id, &repo_a.name, run),
        &[Decision {
            component_id: ca,
            package_name: "lib".into(),
            version: "1.0.0".into(),
            action: Action::HardDelete,
            rule_id: "r".into(),
            reason: reason(),
        }],
        &[],
    )
    .await
    .unwrap();

    assert_eq!(ref_count(&pool, &sha).await, Some(1));
    assert_eq!(outbox_count(&pool, &sha).await, 0);
    // repo B's version is untouched.
    assert!(
        component_dao::find_component(&pool, repo_b.id, "lib", "1.0.0")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn unlist_flips_listed_and_enqueues_nothing() {
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("r-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n, 1).await;
    let comp_id = seed_component(&pool, repo.id, "lib", "1.0.0", &sha).await;

    let run = uuid::Uuid::new_v4();
    let summary = apply(
        &ctx(&pool, repo.id, &repo.name, run),
        &[Decision {
            component_id: comp_id,
            package_name: "lib".into(),
            version: "1.0.0".into(),
            action: Action::Unlist,
            rule_id: "r".into(),
            reason: reason(),
        }],
        &[],
    )
    .await
    .unwrap();

    assert_eq!(summary.unlisted, 1);
    assert_eq!(summary.blobs_enqueued, 0);

    let comp = component_dao::find_component(&pool, repo.id, "lib", "1.0.0")
        .await
        .unwrap()
        .expect("component still exists");
    assert!(!comp.listed, "version must be unlisted");
    assert_eq!(ref_count(&pool, &sha).await, Some(1), "blob untouched");
    assert_eq!(outbox_count(&pool, &sha).await, 0);

    let rows = audit_rows(&pool, run).await;
    assert_eq!(rows[0].0, "unlist");
    assert!(!rows[0].1);
}

#[tokio::test]
async fn dry_run_mutates_nothing_but_audits() {
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("r-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n, 1).await;
    let comp_id = seed_component(&pool, repo.id, "lib", "1.0.0", &sha).await;

    let run = uuid::Uuid::new_v4();
    let mut c = ctx(&pool, repo.id, &repo.name, run);
    c.dry_run = true;
    apply(
        &c,
        &[Decision {
            component_id: comp_id,
            package_name: "lib".into(),
            version: "1.0.0".into(),
            action: Action::HardDelete,
            rule_id: "r".into(),
            reason: reason(),
        }],
        &[],
    )
    .await
    .unwrap();

    // No mutation: component present, blob untouched, no outbox.
    assert!(
        component_dao::find_component(&pool, repo.id, "lib", "1.0.0")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(ref_count(&pool, &sha).await, Some(1));
    assert_eq!(outbox_count(&pool, &sha).await, 0);

    // But a dry-run audit row exists.
    let dry: i64 =
        sqlx::query_scalar("SELECT count(*) FROM retention_audit WHERE run_id = $1 AND dry_run")
            .bind(run)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dry, 1);
}

#[tokio::test]
async fn decision_for_vanished_component_is_skipped() {
    // A decision targeting a component id that no longer exists (a concurrent
    // delete/redeploy raced us) is audited as skipped, mutating nothing.
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("r-{n}")))
        .await
        .unwrap();

    let run = uuid::Uuid::new_v4();
    let summary = apply(
        &ctx(&pool, repo.id, &repo.name, run),
        &[Decision {
            component_id: 9_999_999, // does not exist
            package_name: "lib".into(),
            version: "1.0.0".into(),
            action: Action::HardDelete,
            rule_id: "r".into(),
            reason: reason(),
        }],
        &[],
    )
    .await
    .unwrap();

    assert_eq!(summary.skipped, 1);
    assert_eq!(summary.deleted, 0);
    let rows = audit_rows(&pool, run).await;
    assert_eq!(rows[0].0, "skipped");
}

#[tokio::test]
async fn proxy_eviction_deletes_component_and_cached_row_driving_outbox() {
    // A downloaded proxy cached version has a parallel component+asset. Evicting
    // it deletes both, decrefs the blob to 0, enqueues the outbox, and removes
    // the proxy_cached_version row.
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy(format!("p-{n}")))
        .await
        .unwrap();
    let sha = seed_blob(&pool, n, 1).await;
    let comp_id = seed_component(&pool, repo.id, "lib", "1.0.0", &sha).await;

    // The proxy cached marker for the same (repo, name, version).
    proxy_dao::upsert_cached_version(
        &pool,
        proxy_dao::NewProxyCachedVersion {
            repository_id: repo.id,
            name: "lib".into(),
            version: "1.0.0".into(),
            listed: true,
            downloaded: true,
            not_found: false,
        },
    )
    .await
    .unwrap();
    let cached = proxy_dao::get_cached_version(&pool, repo.id, "lib", "1.0.0")
        .await
        .unwrap()
        .unwrap();

    let run = uuid::Uuid::new_v4();
    let summary = apply(
        &ctx(&pool, repo.id, &repo.name, run),
        &[],
        &[ProxyDecision {
            cached_version_id: cached.id,
            package_name: "lib".into(),
            version: "1.0.0".into(),
            rule_id: "evict".into(),
            reason: DecisionReason {
                older_than_days: None,
                not_downloaded_for_days: None,
                not_pulled_for_days: Some(30),
            },
        }],
    )
    .await
    .unwrap();

    assert_eq!(summary.deleted, 1);
    assert_eq!(summary.blobs_enqueued, 1);
    assert_eq!(ref_count(&pool, &sha).await, Some(0));
    assert_eq!(outbox_count(&pool, &sha).await, 1);

    // Both the cached marker and the component are gone.
    assert!(
        proxy_dao::get_cached_version(&pool, repo.id, "lib", "1.0.0")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        component_dao::find_component(&pool, repo.id, "lib", "1.0.0")
            .await
            .unwrap()
            .is_none()
    );
    let _ = comp_id;

    let rows = audit_rows(&pool, run).await;
    assert_eq!(rows[0].0, "hard_delete");
    assert!(rows[0].1);
}
