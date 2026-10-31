//! Integration tests for the retention DAO (`retention_dao`) against a real
//! Postgres (testcontainers). Focus: the `FOR UPDATE SKIP LOCKED` claim
//! never lets two instances grab the same repo, stale leases get reclaimed, and
//! the candidate/audit/policy queries round-trip.

mod common;

use chrono::{Duration, Utc};
use forge_db::{
    asset_dao::{self, NewAsset},
    blob_dao,
    component_dao::{self, NewComponent},
    proxy_dao::{self, NewProxyCachedVersion},
    repository_dao::{self, NewRepository},
    retention_dao::{self, AuditRow, RunSummary},
};
use serde_json::json;

/// A minimal valid hosted policy jsonb for arming a repo.
fn hosted_policy_json() -> serde_json::Value {
    json!({
        "version": 1,
        "rules": [
            { "id": "r", "action": "hard_delete", "criteria": { "older_than_days": 30 } }
        ]
    })
}

async fn armed_hosted_repo(pool: &sqlx::PgPool, suffix: u64) -> i64 {
    let repo =
        repository_dao::insert_repository(pool, NewRepository::hosted(format!("ret-{suffix}")))
            .await
            .expect("insert repo");
    retention_dao::write_policy(pool, repo.id, Some(&hosted_policy_json()))
        .await
        .expect("write policy");
    // `write_policy` upserts the ledger row with `next_run_at DEFAULT now()`
    // using the **database** clock. Tests then capture `now = Utc::now()` on the
    // **host** clock and claim with it; under testcontainers the container clock
    // can drift slightly ahead of the host, making `next_run_at > now` so the
    // freshly-armed repo is (wrongly) not yet due and the claim no-ops. Backdate
    // the row a minute into the past so it is unambiguously due for any host
    // clock within a sane skew window. This changes nothing about claim/lease
    // semantics — tests that finish/fail a run rewrite `next_run_at` forward.
    sqlx::query("UPDATE retention_run SET next_run_at = now() - interval '60 seconds' WHERE repository_id = $1")
        .bind(repo.id)
        .execute(pool)
        .await
        .expect("backdate next_run_at");
    repo.id
}

#[tokio::test]
async fn write_policy_round_trips_and_creates_run_row() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;

    let back = retention_dao::read_policy(&pool, repo_id)
        .await
        .expect("read policy");
    assert_eq!(back, Some(hosted_policy_json()));

    // The ledger row exists and is due immediately.
    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .expect("get run")
        .expect("run row exists");
    assert_eq!(run.state, "idle");

    // Clearing the policy nulls the column.
    assert!(retention_dao::write_policy(&pool, repo_id, None)
        .await
        .expect("clear"));
    assert_eq!(
        retention_dao::read_policy(&pool, repo_id).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn write_policy_returns_false_for_missing_repo() {
    let pool = common::pool().await;
    let ok = retention_dao::write_policy(&pool, 9_999_999, Some(&hosted_policy_json()))
        .await
        .expect("write");
    assert!(!ok);
}

#[tokio::test]
async fn claim_marks_running_with_lease_and_run_id() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;
    let now = Utc::now();

    let mut tx = pool.begin().await.unwrap();
    let (claimed, run_id) =
        retention_dao::claim_next_due_repo(&mut tx, now, Duration::seconds(60), Some(repo_id))
            .await
            .expect("claim")
            .expect("a repo was due");
    assert_eq!(claimed.repository_id, repo_id);
    assert_eq!(claimed.kind, "hosted");
    assert_eq!(claimed.format, "nuget");
    assert_eq!(claimed.policy, hosted_policy_json());
    tx.commit().await.unwrap();

    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "running");
    assert!(run.locked_until.is_some());
    assert!(run.started_at.is_some());
    let _ = run_id;
}

#[tokio::test]
async fn second_concurrent_claim_skips_the_locked_repo() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;
    let now = Utc::now();

    // First tx claims and holds its row lock (FOR UPDATE OF retention_run).
    let mut tx1 = pool.begin().await.unwrap();
    let first =
        retention_dao::claim_next_due_repo(&mut tx1, now, Duration::seconds(60), Some(repo_id))
            .await
            .expect("claim 1");
    assert!(first.is_some());
    assert_eq!(first.unwrap().0.repository_id, repo_id);

    // A concurrent tx targeting the SAME repo must SKIP the locked row → None.
    let mut tx2 = pool.begin().await.unwrap();
    let second =
        retention_dao::claim_next_due_repo(&mut tx2, now, Duration::seconds(60), Some(repo_id))
            .await
            .expect("claim 2");
    assert!(
        second.is_none(),
        "concurrent claim must skip the locked repo"
    );
    tx2.commit().await.unwrap();
    tx1.commit().await.unwrap();
}

#[tokio::test]
async fn two_due_repos_claimed_by_disjoint_concurrent_txns() {
    // Each tx scopes to its own repo, so the only way both succeed is if the
    // SKIP-LOCKED claim never double-claims: tx1 takes `a`, tx2 takes `b`, and
    // neither blocks on the other.
    let pool = common::pool().await;
    let a = armed_hosted_repo(&pool, common::unique()).await;
    let b = armed_hosted_repo(&pool, common::unique()).await;
    let now = Utc::now();

    let mut tx1 = pool.begin().await.unwrap();
    let (c1, _) = retention_dao::claim_next_due_repo(&mut tx1, now, Duration::seconds(60), Some(a))
        .await
        .unwrap()
        .expect("claim a");

    let mut tx2 = pool.begin().await.unwrap();
    let (c2, _) = retention_dao::claim_next_due_repo(&mut tx2, now, Duration::seconds(60), Some(b))
        .await
        .unwrap()
        .expect("claim b");

    tx1.commit().await.unwrap();
    tx2.commit().await.unwrap();

    assert_eq!(c1.repository_id, a);
    assert_eq!(c2.repository_id, b);
    assert_ne!(c1.repository_id, c2.repository_id);
}

#[tokio::test]
async fn finished_run_advances_next_run_and_goes_idle() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;
    let now = Utc::now();

    let mut tx = pool.begin().await.unwrap();
    retention_dao::claim_next_due_repo(&mut tx, now, Duration::seconds(60), Some(repo_id))
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();

    let next = now + Duration::seconds(3600);
    let summary = RunSummary {
        evaluated: 5,
        deleted: 2,
        blobs_enqueued: 2,
        ..Default::default()
    };
    retention_dao::finish_run(&pool, repo_id, None, &summary, next, None)
        .await
        .expect("finish");

    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "idle");
    assert!(run.locked_until.is_none());
    assert!(run.next_run_at > now);
    let stored: RunSummary = serde_json::from_value(run.last_run_summary.unwrap()).unwrap();
    assert_eq!(stored.deleted, 2);
}

#[tokio::test]
async fn running_repo_is_not_claimed_until_due_and_idle() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;
    let now = Utc::now();

    // Claim and finish with next_run in the future: not due → not re-claimed.
    let mut tx = pool.begin().await.unwrap();
    retention_dao::claim_next_due_repo(&mut tx, now, Duration::seconds(60), Some(repo_id))
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    retention_dao::finish_run(
        &pool,
        repo_id,
        None,
        &RunSummary::default(),
        now + Duration::seconds(3600),
        None,
    )
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let again =
        retention_dao::claim_next_due_repo(&mut tx, now, Duration::seconds(60), Some(repo_id))
            .await
            .unwrap();
    tx.commit().await.unwrap();
    // Scheduled in the future → not due → nothing claimed for this repo.
    assert!(again.is_none());
}

#[tokio::test]
async fn stale_lease_is_reclaimed() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;
    let now = Utc::now();

    // Claim with a lease that's already expired relative to the sweep below.
    let mut tx = pool.begin().await.unwrap();
    retention_dao::claim_next_due_repo(&mut tx, now, Duration::seconds(1), Some(repo_id))
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();

    // The sweep is not limited to this repository, and the other tests of
    // this binary hold 60 s leases on the same database meanwhile: a cutoff
    // just past this 1 s lease releases none of theirs (#345).
    let reclaimed = retention_dao::release_stale_leases(&pool, now + Duration::seconds(2))
        .await
        .expect("reclaim");
    assert!(reclaimed >= 1);

    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "idle");
    assert!(run.locked_until.is_none());

    // After reclaim, a fresh claim can take it again.
    let later = now + Duration::seconds(120);
    let mut tx = pool.begin().await.unwrap();
    let again =
        retention_dao::claim_next_due_repo(&mut tx, later, Duration::seconds(60), Some(repo_id))
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(again.unwrap().0.repository_id, repo_id);
}

#[tokio::test]
async fn expired_lease_is_directly_reclaimable_by_claim() {
    // The claim query itself tolerates an expired lease even without an explicit
    // release_stale_leases sweep (belt and suspenders).
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;
    let now = Utc::now();

    let mut tx = pool.begin().await.unwrap();
    retention_dao::claim_next_due_repo(&mut tx, now, Duration::seconds(1), Some(repo_id))
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();

    let later = now + Duration::seconds(120);
    let mut tx = pool.begin().await.unwrap();
    let again =
        retention_dao::claim_next_due_repo(&mut tx, later, Duration::seconds(60), Some(repo_id))
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(again.unwrap().0.repository_id, repo_id);
}

#[tokio::test]
async fn load_candidate_components_returns_components_with_nupkg_blob() {
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("cand-{n}")))
        .await
        .unwrap();

    // Component WITH a .nupkg asset → included.
    let with = component_dao::insert_component(
        &pool,
        NewComponent {
            repository_id: repo.id,
            name: "lib".into(),
            original_id: "Lib".into(),
            version: "1.0.0".into(),
            version_original: "1.0.0".into(),
            listed: true,
        },
    )
    .await
    .unwrap();
    let sha = format!("{:064x}", n);
    blob_dao::upsert_pending(&pool, &sha, 10, &format!("k/{sha}"))
        .await
        .unwrap();
    asset_dao::insert_asset(
        &pool,
        NewAsset {
            component_id: with.id,
            path: "lib.1.0.0.nupkg".into(),
            content_type: "application/octet-stream".into(),
            blob_sha256: sha.clone(),
            size: 10,
            sha512_base64: None,
        },
    )
    .await
    .unwrap();

    // Component WITHOUT a .nupkg asset → excluded (nothing to GC).
    component_dao::insert_component(
        &pool,
        NewComponent {
            repository_id: repo.id,
            name: "lib".into(),
            original_id: "Lib".into(),
            version: "2.0.0".into(),
            version_original: "2.0.0".into(),
            listed: true,
        },
    )
    .await
    .unwrap();

    let cands = retention_dao::load_candidate_components(&pool, repo.id, "package.nupkg")
        .await
        .expect("load");
    assert_eq!(cands.len(), 1);
    assert_eq!(cands[0].0.component_id, with.id);
    assert_eq!(cands[0].0.version, "1.0.0");
    assert_eq!(cands[0].1, sha);
}

#[tokio::test]
async fn load_proxy_candidates_returns_only_versions_with_cached_bytes() {
    // Regression (M7): metadata-only rows (`downloaded = false`: listed
    // upstream but never pulled, or already evicted) hold nothing to evict and
    // must not be candidates, or every run "evicts" them again. Negative-cache
    // tombstones are excluded as before.
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy(format!("pc-{n}")))
        .await
        .unwrap();
    for (version, downloaded, not_found) in [
        ("1.0.0", true, false),
        ("2.0.0", false, false),
        ("3.0.0", false, true),
    ] {
        proxy_dao::upsert_cached_version(
            &pool,
            NewProxyCachedVersion {
                repository_id: repo.id,
                name: "lib".into(),
                version: version.into(),
                listed: true,
                downloaded,
                not_found,
            },
        )
        .await
        .unwrap();
    }

    let cands = retention_dao::load_proxy_candidates(&pool, repo.id)
        .await
        .expect("load");
    let versions: Vec<&str> = cands.iter().map(|c| c.version.as_str()).collect();
    assert_eq!(versions, vec!["1.0.0"]);
}

#[tokio::test]
async fn insert_audit_persists_row() {
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("aud-{n}")))
        .await
        .unwrap();
    let run_id = uuid::Uuid::new_v4();

    retention_dao::insert_audit(
        &pool,
        &AuditRow {
            repository_id: repo.id,
            run_id,
            rule_id: "r".into(),
            action: "hard_delete".into(),
            target_kind: "component".into(),
            package_name: "lib".into(),
            version: "1.0.0".into(),
            component_id: None,
            blob_sha256: Some("deadbeef".into()),
            ref_count_after: Some(0),
            blob_delete_enqueued: true,
            dry_run: false,
            reason: json!({ "older_than_days": 30 }),
        },
    )
    .await
    .expect("insert audit");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM retention_audit WHERE repository_id = $1 AND run_id = $2",
    )
    .bind(repo.id)
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

/// Audit rows past the retention window are pruned; newer ones stay.
#[tokio::test]
async fn prune_audit_deletes_only_rows_past_the_cutoff() {
    let pool = common::pool().await;
    let n = common::unique();
    let repo =
        repository_dao::insert_repository(&pool, NewRepository::hosted(format!("aud-prune-{n}")))
            .await
            .unwrap();
    let run_id = uuid::Uuid::new_v4();
    for version in ["1.0.0", "2.0.0"] {
        retention_dao::insert_audit(
            &pool,
            &AuditRow {
                repository_id: repo.id,
                run_id,
                rule_id: "r".into(),
                action: "skipped".into(),
                target_kind: "component".into(),
                package_name: "lib".into(),
                version: version.into(),
                component_id: None,
                blob_sha256: None,
                ref_count_after: None,
                blob_delete_enqueued: false,
                dry_run: true,
                reason: json!({}),
            },
        )
        .await
        .unwrap();
    }
    sqlx::query(
        "UPDATE retention_audit SET created_at = now() - interval '100 days' \
         WHERE repository_id = $1 AND version = '1.0.0'",
    )
    .bind(repo.id)
    .execute(&pool)
    .await
    .unwrap();

    let pruned = retention_dao::prune_audit(&pool, Utc::now() - Duration::days(90), 1000)
        .await
        .unwrap();
    assert!(pruned >= 1);
    let left: Vec<String> =
        sqlx::query_scalar("SELECT version FROM retention_audit WHERE repository_id = $1")
            .bind(repo.id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(left, vec!["2.0.0".to_string()]);
}

#[tokio::test]
async fn schedule_now_makes_repo_immediately_due() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;

    // Push it into the future, then schedule_now and confirm claimable at `now`.
    let now = Utc::now();
    retention_dao::finish_run(
        &pool,
        repo_id,
        None,
        &RunSummary::default(),
        now + Duration::seconds(99999),
        None,
    )
    .await
    .unwrap();

    assert!(retention_dao::schedule_now(&pool, repo_id).await.unwrap());

    let mut tx = pool.begin().await.unwrap();
    let claimed = retention_dao::claim_next_due_repo(
        &mut tx,
        Utc::now(),
        Duration::seconds(60),
        Some(repo_id),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(claimed.unwrap().0.repository_id, repo_id);
}

/// finish/fail are fenced to the run that owns the lease; the heartbeat can
/// only renew its own run.
#[tokio::test]
async fn run_completion_and_renewal_are_fenced_to_the_lease_owner() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;
    let now = Utc::now();

    let mut tx = pool.begin().await.unwrap();
    let (_, run_id) =
        retention_dao::claim_next_due_repo(&mut tx, now, Duration::seconds(60), Some(repo_id))
            .await
            .unwrap()
            .unwrap();
    tx.commit().await.unwrap();

    let stranger = uuid::Uuid::new_v4();
    assert!(!retention_dao::renew_run_lease(
        &pool,
        repo_id,
        stranger,
        now + Duration::seconds(120)
    )
    .await
    .unwrap());
    assert!(
        retention_dao::renew_run_lease(&pool, repo_id, run_id, now + Duration::seconds(120))
            .await
            .unwrap()
    );
    assert!(!retention_dao::finish_run(
        &pool,
        repo_id,
        Some(stranger),
        &RunSummary::default(),
        now + Duration::seconds(3600),
        None,
    )
    .await
    .unwrap());
    assert!(
        !retention_dao::fail_run(&pool, repo_id, Some(stranger), "x", now, None)
            .await
            .unwrap()
    );
    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "running", "a stale owner cannot clear the lease");

    assert!(retention_dao::finish_run(
        &pool,
        repo_id,
        Some(run_id),
        &RunSummary::default(),
        now + Duration::seconds(3600),
        None,
    )
    .await
    .unwrap());
    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "idle");
}

/// `component.unlisted_at` (for `unlisted_for_days`), kept by a trigger on
/// every path: set when a version is unlisted or arrives unlisted, kept while
/// it stays unlisted, cleared when it is listed again.
#[tokio::test]
async fn unlisting_records_when_on_every_path() {
    let pool = common::pool().await;
    let n = common::unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("unl-{n}")))
        .await
        .unwrap();
    let insert = |version: &'static str, listed: bool| {
        let pool = pool.clone();
        async move {
            component_dao::insert_component(
                &pool,
                NewComponent {
                    repository_id: repo.id,
                    name: "lib".into(),
                    original_id: "Lib".into(),
                    version: version.into(),
                    version_original: version.into(),
                    listed,
                },
            )
            .await
            .unwrap()
            .id
        }
    };
    let unlisted_at = |id: i64| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
                "SELECT unlisted_at FROM component WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };

    let listed = insert("1.0.0", true).await;
    assert_eq!(unlisted_at(listed).await, None);
    // A version pushed unlisted.
    let pushed_unlisted = insert("2.0.0", false).await;
    assert!(unlisted_at(pushed_unlisted).await.is_some());

    // A client's unlist (NuGet's DELETE, npm) and its relist.
    assert!(
        component_dao::set_listed(&pool, repo.id, "lib", "1.0.0", false)
            .await
            .unwrap()
    );
    let first = unlisted_at(listed)
        .await
        .expect("unlisting records the time");
    // Backdated, as a test or an operator might; unlisting again keeps it.
    sqlx::query("UPDATE component SET unlisted_at = now() - interval '40 days' WHERE id = $1")
        .bind(listed)
        .execute(&pool)
        .await
        .unwrap();
    let backdated = unlisted_at(listed).await.unwrap();
    assert!(backdated < first - Duration::days(39));
    component_dao::set_listed(&pool, repo.id, "lib", "1.0.0", false)
        .await
        .unwrap();
    assert_eq!(unlisted_at(listed).await, Some(backdated));
    component_dao::set_listed(&pool, repo.id, "lib", "1.0.0", true)
        .await
        .unwrap();
    assert_eq!(unlisted_at(listed).await, None);

    // Retention's own unlist goes through the same column; the candidates
    // carry it.
    sqlx::query("UPDATE component SET listed = false, updated_at = now() WHERE id = $1")
        .bind(listed)
        .execute(&pool)
        .await
        .unwrap();
    let sha = format!("{:064x}", n);
    blob_dao::upsert_pending(&pool, &sha, 10, &format!("k/{sha}"))
        .await
        .unwrap();
    asset_dao::insert_asset(
        &pool,
        NewAsset {
            component_id: listed,
            path: "lib.1.0.0.nupkg".into(),
            content_type: "application/octet-stream".into(),
            blob_sha256: sha,
            size: 10,
            sha512_base64: None,
        },
    )
    .await
    .unwrap();
    let cands = retention_dao::load_candidate_components(&pool, repo.id, "package.nupkg")
        .await
        .unwrap();
    assert_eq!(cands.len(), 1);
    assert!(!cands[0].0.listed);
    assert_eq!(cands[0].0.unlisted_at, unlisted_at(listed).await);
    assert!(cands[0].0.unlisted_at.is_some());
}

/// A policy with a schedule sets the ledger's next run when it is saved;
/// a run that finishes after its policy was changed keeps the next run the
/// change set, instead of the old policy's.
#[tokio::test]
async fn a_saved_schedule_sets_the_next_run_and_a_stale_run_keeps_it() {
    let pool = common::pool().await;
    let repo_id = armed_hosted_repo(&pool, common::unique()).await;
    let old_policy = hosted_policy_json();

    let window = Utc::now() + Duration::days(1);
    let mut scheduled = hosted_policy_json();
    scheduled["schedule"] = json!("0 3 * * *");
    assert!(
        retention_dao::write_policy_at(&pool, repo_id, Some(&scheduled), Some(window))
            .await
            .unwrap()
    );
    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert!((run.next_run_at - window).num_milliseconds().abs() < 1);

    // A run of the old policy ends: its next time is not the one to keep.
    let stale_next = Utc::now() + Duration::hours(1);
    assert!(retention_dao::finish_run(
        &pool,
        repo_id,
        None,
        &RunSummary::default(),
        stale_next,
        Some(&old_policy),
    )
    .await
    .unwrap());
    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert!((run.next_run_at - window).num_milliseconds().abs() < 1);
    assert_eq!(run.state, "idle");
    assert!(
        retention_dao::fail_run(&pool, repo_id, None, "x", stale_next, Some(&old_policy))
            .await
            .unwrap()
    );
    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert!((run.next_run_at - window).num_milliseconds().abs() < 1);

    // A run of the stored policy sets its next run.
    let stored = retention_dao::read_policy(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    retention_dao::finish_run(
        &pool,
        repo_id,
        None,
        &RunSummary::default(),
        stale_next,
        Some(&stored),
    )
    .await
    .unwrap();
    let run = retention_dao::get_run(&pool, repo_id)
        .await
        .unwrap()
        .unwrap();
    assert!((run.next_run_at - stale_next).num_milliseconds().abs() < 1);
}

/// A run that stopped at its time limit records how many decisions it left.
#[tokio::test]
async fn the_summary_records_deferred_decisions_only_when_there_are_some() {
    let summary = RunSummary {
        deleted: 3,
        deferred: 7,
        ..RunSummary::default()
    };
    let json = serde_json::to_value(&summary).unwrap();
    assert_eq!(json["deferred"], 7);
    let none = serde_json::to_value(RunSummary::default()).unwrap();
    assert!(none.get("deferred").is_none());
    // A summary recorded before the field existed reads as none deferred.
    let back: RunSummary = serde_json::from_value(json!({
        "evaluated": 1, "unlisted": 0, "deleted": 0, "blobs_enqueued": 0, "skipped": 0
    }))
    .unwrap();
    assert_eq!(back.deferred, 0);
}

/// The repositories whose retention rules name a content selector.
#[tokio::test]
async fn repositories_using_a_selector_are_found_by_their_rules() {
    let pool = common::pool().await;
    let n = common::unique();
    let selector = format!("sel-{n}");
    let using = armed_hosted_repo(&pool, n).await;
    let mut policy = hosted_policy_json();
    policy["rules"][0]["selector"] = json!(selector);
    retention_dao::write_policy(&pool, using, Some(&policy))
        .await
        .unwrap();
    let other = armed_hosted_repo(&pool, common::unique()).await;
    let mut unrelated = hosted_policy_json();
    unrelated["rules"][0]["selector"] = json!(format!("{selector}-other"));
    retention_dao::write_policy(&pool, other, Some(&unrelated))
        .await
        .unwrap();
    let names = retention_dao::repositories_using_selector(&pool, &selector)
        .await
        .unwrap();
    assert_eq!(names, vec![format!("ret-{n}")]);
    assert!(
        retention_dao::repositories_using_selector(&pool, "nobody-uses-this")
            .await
            .unwrap()
            .is_empty()
    );
}
