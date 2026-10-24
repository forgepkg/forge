//! E2E: retention / cleanup + policy-driven blob GC.
//!
//! Full-stack scenarios on the shared testcontainers harness (Postgres +
//! versitygw, in-process server[s] with workers). Each scenario arms a
//! `retention_policy` via the admin REST surface, lets the background
//! `RetentionWorker` claim + evaluate + apply the repo, and asserts the end
//! state: components unlisted/hard-deleted, blobs dereferenced + S3 objects
//! removed **through the outbox worker**, audit rows written.
//!
//! Hard rules exercised here:
//!   * blob deletion only ever flows through `decref → blob_outbox → outbox
//!     worker` (no parallel S3 delete path); a blob shared across repos is
//!     retained while still referenced and removed only when the last ref goes.
//!   * multi-instance: two server instances sharing the DB evaluate a due repo
//!     exactly once (`FOR UPDATE SKIP LOCKED` + lease).
//!
//! Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::time::Duration;

use forge_e2e::{make_nupkg, MockUpstream, StackBuilder, TestServer, UpstreamPackage};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Boot a single worker-enabled stack (the retention + outbox workers run with a
/// 1s poll, see the harness config).
async fn worker_stack() -> TestServer {
    StackBuilder::default().workers(true).start().await
}

/// Arm a retention policy on a repo via the admin PUT endpoint.
async fn put_policy(srv: &TestServer, repo: &str, policy: Value) -> reqwest::StatusCode {
    let (u, p) = srv.admin_basic();
    srv.client()
        .put(format!(
            "{}/admin/repositories/{repo}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({ "policy": policy }))
        .send()
        .await
        .unwrap()
        .status()
}

/// Trigger a prompt run (`next_run_at = now()`) so the worker claims the repo on
/// its next poll. Returns the HTTP status (202 when armed, 409 when no policy).
async fn trigger_run(srv: &TestServer, repo: &str) -> reqwest::StatusCode {
    let (u, p) = srv.admin_basic();
    srv.client()
        .post(format!(
            "{}/admin/repositories/{repo}/retention/run",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .status()
}

/// The flat-container version list for a package (listed versions only).
async fn listed_versions(srv: &TestServer, repo: &str, lower: &str) -> Vec<String> {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/repository/{repo}/flat/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    if resp.status() == 404 {
        return Vec::new();
    }
    let body: Value = resp.json().await.unwrap();
    body["versions"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Count audit rows for a repo (optionally only hard_delete / unlist).
async fn audit_count(pool: &PgPool, repo_id: i64, action: Option<&str>) -> i64 {
    match action {
        Some(a) => sqlx::query_scalar(
            "SELECT count(*) FROM retention_audit WHERE repository_id = $1 AND action = $2",
        )
        .bind(repo_id)
        .bind(a)
        .fetch_one(pool)
        .await
        .unwrap(),
        None => sqlx::query_scalar("SELECT count(*) FROM retention_audit WHERE repository_id = $1")
            .bind(repo_id)
            .fetch_one(pool)
            .await
            .unwrap(),
    }
}

async fn repo_id(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM repository WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Backdate every component of a repo by `days` so `older_than_days` triggers
/// fire (the validator rejects `older_than_days = 0`, so age tests must age the
/// rows rather than use a zero threshold).
async fn age_all_components(pool: &PgPool, repo_id: i64, days: i64) {
    sqlx::query("UPDATE component SET created_at = now() - make_interval(days => $2) WHERE repository_id = $1")
    .bind(repo_id)
    .bind(days as i32)
    .execute(pool)
    .await
    .unwrap();
}

/// Poll a DB predicate (returns the scalar) until it satisfies `done`, or panic.
async fn wait_until<F>(pool: &PgPool, sql: &str, done: F, what: &str) -> i64
where
    F: Fn(i64) -> bool,
{
    // Test-authored SQL (ids interpolated from fixtures), safe to run dynamically.
    let query = || sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()));
    for _ in 0..80 {
        let v: i64 = query().fetch_one(pool).await.unwrap();
        if done(v) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let v: i64 = query().fetch_one(pool).await.unwrap();
    panic!("timed out waiting for {what}; last value = {v}");
}

// ── 1. keep_last_n: hard-delete older versions + GC their blobs via outbox ─────

/// Push 15 distinct versions, arm `keep_last_n = 10` + `older_than_days = 0`,
/// run the worker, and assert the 5 oldest are hard-deleted: gone from the
/// flat-container list, their blobs dereferenced and removed from S3 by the
/// outbox worker, and 5 audit rows recorded.
#[tokio::test]
async fn keep_last_n_hard_deletes_oldest_and_gcs_blobs() {
    let srv = worker_stack().await;
    let repo = "ret-keepn";
    let id = "Sample.Lib";
    let lower = id.to_lowercase();

    assert_eq!(
        srv.create_repo(json!({"name": repo, "kind": "hosted"}))
            .await
            .status(),
        201
    );

    // 15 versions, each with distinct bytes (version is embedded in the nuspec).
    for minor in 0..15 {
        let bytes = make_nupkg(id, &format!("1.{minor}.0"));
        assert_eq!(srv.push_nupkg(repo, bytes).await.status(), 201);
    }

    let rid = repo_id(&srv.pool, repo).await;
    let committed_before: i64 = sqlx::query_scalar("SELECT count(*) FROM blob WHERE ref_count > 0")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert!(committed_before >= 15, "at least 15 nupkg blobs referenced");

    // Age every version past the 1-day trigger threshold (the validator rejects
    // older_than_days = 0); the keep_last_n protection still shields the newest.
    age_all_components(&srv.pool, rid, 2).await;

    // Arm policy: keep the newest 10, hard-delete the older ones.
    let status = put_policy(
        &srv,
        repo,
        json!({
            "version": 1,
            "enabled": true,
            "dry_run_only": false,
            "min_run_interval_seconds": 0,
            "rules": [{
                "id": "keep-10",
                "action": "hard_delete",
                "release_type": "any",
                "criteria": { "keep_last_n": 10, "older_than_days": 1 }
            }]
        }),
    )
    .await;
    assert_eq!(status, 200, "PUT policy");
    assert_eq!(trigger_run(&srv, repo).await, 202, "run scheduled");

    // The worker hard-deletes 5 components; assert via the audit ledger.
    wait_until(
        &srv.pool,
        &format!(
            "SELECT count(*) FROM retention_audit WHERE repository_id = {rid} AND action = 'hard_delete'"
        ),
        |c| c == 5,
        "5 hard_delete audit rows",
    )
    .await;

    // Exactly 10 versions remain in the flat-container list.
    let remaining = listed_versions(&srv, repo, &lower).await;
    assert_eq!(
        remaining.len(),
        10,
        "10 newest versions kept: {remaining:?}"
    );
    // The 5 oldest (1.0.0 .. 1.4.0) are gone; the newest (1.14.0) is kept.
    assert!(!remaining.contains(&"1.0.0".to_string()));
    assert!(!remaining.contains(&"1.4.0".to_string()));
    assert!(remaining.contains(&"1.14.0".to_string()));

    // The outbox worker drains the 5 dereferenced blobs and removes them from S3.
    wait_until(
        &srv.pool,
        "SELECT count(*) FROM blob WHERE ref_count <= 0",
        |c| c == 0,
        "all dereferenced blobs removed",
    )
    .await;
    wait_until(
        &srv.pool,
        "SELECT count(*) FROM blob_outbox WHERE processed_at IS NULL",
        |c| c == 0,
        "outbox fully drained",
    )
    .await;

    assert_eq!(audit_count(&srv.pool, rid, Some("hard_delete")).await, 5);
}

// ── 2. older_than_days: only sufficiently-old versions are deleted ────────────

/// With `keep_last_n = 0` + `older_than_days = 30`, only versions whose
/// `created_at` is older than 30 days are deleted; fresh ones are retained.
#[tokio::test]
async fn keep_days_only_deletes_old_versions() {
    let srv = worker_stack().await;
    let repo = "ret-keepdays";
    let id = "Aged.Lib";
    let lower = id.to_lowercase();

    assert_eq!(
        srv.create_repo(json!({"name": repo, "kind": "hosted"}))
            .await
            .status(),
        201
    );

    for v in ["1.0.0", "2.0.0", "3.0.0"] {
        assert_eq!(srv.push_nupkg(repo, make_nupkg(id, v)).await.status(), 201);
    }
    let rid = repo_id(&srv.pool, repo).await;

    // Backdate 1.0.0 and 2.0.0 to 60 days ago; leave 3.0.0 fresh.
    sqlx::query(
        "UPDATE component SET created_at = now() - interval '60 days' \
         WHERE repository_id = $1 AND version IN ('1.0.0', '2.0.0')",
    )
    .bind(rid)
    .execute(&srv.pool)
    .await
    .unwrap();

    let status = put_policy(
        &srv,
        repo,
        json!({
            "version": 1,
            "enabled": true,
            "min_run_interval_seconds": 0,
            "rules": [{
                "id": "evict-old",
                "action": "hard_delete",
                "criteria": { "older_than_days": 30 }
            }]
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(trigger_run(&srv, repo).await, 202);

    wait_until(
        &srv.pool,
        &format!(
            "SELECT count(*) FROM retention_audit WHERE repository_id = {rid} AND action = 'hard_delete'"
        ),
        |c| c == 2,
        "2 old versions hard-deleted",
    )
    .await;

    let remaining = listed_versions(&srv, repo, &lower).await;
    assert_eq!(
        remaining,
        vec!["3.0.0".to_string()],
        "only the fresh version survives: {remaining:?}"
    );
}

// ── 3. unlist action: hide from search, keep downloadable, no blob deleted ────

/// An `action = unlist` rule flips `listed=false` (hidden from search /
/// flat-container) but never dereferences a blob — the version stays
/// downloadable by exact version and no outbox row is enqueued.
#[tokio::test]
async fn unlist_action_hides_without_deleting_blob() {
    let srv = worker_stack().await;
    let repo = "ret-unlist";
    let id = "Soft.Lib";
    let lower = id.to_lowercase();

    assert_eq!(
        srv.create_repo(json!({"name": repo, "kind": "hosted"}))
            .await
            .status(),
        201
    );
    for minor in 0..3 {
        assert_eq!(
            srv.push_nupkg(repo, make_nupkg(id, &format!("1.{minor}.0")))
                .await
                .status(),
            201
        );
    }
    let rid = repo_id(&srv.pool, repo).await;
    let blobs_before: i64 = sqlx::query_scalar("SELECT count(*) FROM blob")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    age_all_components(&srv.pool, rid, 2).await;

    let status = put_policy(
        &srv,
        repo,
        json!({
            "version": 1,
            "enabled": true,
            "min_run_interval_seconds": 0,
            "rules": [{
                "id": "unlist-old",
                "action": "unlist",
                "criteria": { "keep_last_n": 1, "older_than_days": 1 }
            }]
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(trigger_run(&srv, repo).await, 202);

    // 2 of 3 versions get unlisted (keep newest 1).
    wait_until(
        &srv.pool,
        &format!(
            "SELECT count(*) FROM retention_audit WHERE repository_id = {rid} AND action = 'unlist'"
        ),
        |c| c == 2,
        "2 unlist audit rows",
    )
    .await;

    // Exactly the 2 oldest are flagged unlisted; the newest stays listed. The
    // flat container intentionally lists unlisted versions (NuGet semantics), so
    // assert the `listed` flag directly + via search visibility below.
    let unlisted_versions: Vec<String> = sqlx::query_scalar(
        "SELECT version FROM component WHERE repository_id = $1 AND NOT listed ORDER BY version",
    )
    .bind(rid)
    .fetch_all(&srv.pool)
    .await
    .unwrap();
    assert_eq!(
        unlisted_versions,
        vec!["1.0.0".to_string(), "1.1.0".to_string()],
        "2 oldest unlisted"
    );
    let still_listed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM component WHERE repository_id = $1 AND listed AND version = '1.2.0'",
    )
    .bind(rid)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(still_listed, 1, "newest stays listed");

    // The flat container still lists all 3 (unlisted versions remain resolvable).
    let all = listed_versions(&srv, repo, &lower).await;
    assert_eq!(
        all.len(),
        3,
        "flat container lists all versions incl. unlisted"
    );

    // Search hides the unlisted versions but the package (newest) remains.
    let (su, sp) = srv.admin_basic();
    let search: Value = srv
        .client()
        .get(format!("{}/repository/{repo}/query?q={id}", srv.base_url))
        .basic_auth(&su, Some(&sp))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        search["totalHits"].as_u64().unwrap() >= 1,
        "newest listed version still searchable: {search}"
    );

    // No blob dereferenced, no outbox row, all blobs still present.
    let blobs_after: i64 = sqlx::query_scalar("SELECT count(*) FROM blob")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(blobs_after, blobs_before, "unlist deletes no blobs");
    let outbox: i64 = sqlx::query_scalar("SELECT count(*) FROM blob_outbox")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(outbox, 0, "unlist enqueues no outbox deletes");
    assert_eq!(audit_count(&srv.pool, rid, Some("hard_delete")).await, 0);

    // An unlisted version is still downloadable by exact version.
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/repository/{repo}/flat/{lower}/1.0.0/{lower}.1.0.0.nupkg",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "unlisted version still downloadable");
}

// ── 4. shared blob: retained while referenced, deleted when last ref goes ─────

/// Identical bytes pushed to two repos share one CAS blob (`ref_count = 2`).
/// Retention deletes the version in repo A → `ref_count` drops to 1, **no**
/// outbox row, S3 object still present. Deleting the version in repo B → the
/// outbox worker removes the S3 object and the `blob` row.
#[tokio::test]
async fn shared_blob_retained_until_last_reference() {
    let srv = worker_stack().await;
    let id = "Shared.Lib";

    for repo in ["ret-shared-a", "ret-shared-b"] {
        assert_eq!(
            srv.create_repo(json!({"name": repo, "kind": "hosted"}))
                .await
                .status(),
            201
        );
    }

    // Identical bytes → identical sha256 → one shared blob with ref_count 2.
    let bytes = make_nupkg(id, "1.0.0");
    assert_eq!(
        srv.push_nupkg("ret-shared-a", bytes.clone()).await.status(),
        201
    );
    assert_eq!(srv.push_nupkg("ret-shared-b", bytes).await.status(), 201);

    // The nupkg blob is shared by both repos' assets (ref_count = 2).
    let shared_sha: String = sqlx::query_scalar(
        "SELECT b.sha256 FROM blob b WHERE b.ref_count = 2 \
         AND EXISTS (SELECT 1 FROM asset a WHERE a.blob_sha256 = b.sha256 \
                     AND a.path LIKE '%.nupkg') LIMIT 1",
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();

    // Age both repos' components so the older_than_days trigger fires.
    age_all_components(&srv.pool, repo_id(&srv.pool, "ret-shared-a").await, 2).await;
    age_all_components(&srv.pool, repo_id(&srv.pool, "ret-shared-b").await, 2).await;

    let policy = json!({
        "version": 1,
        "enabled": true,
        "min_run_interval_seconds": 0,
        "rules": [{
            "id": "purge-all",
            "action": "hard_delete",
            "criteria": { "older_than_days": 1 }
        }]
    });

    // Delete in repo A: ref_count 2 → 1, NO outbox row, blob still present.
    assert_eq!(put_policy(&srv, "ret-shared-a", policy.clone()).await, 200);
    assert_eq!(trigger_run(&srv, "ret-shared-a").await, 202);

    let count_sql =
        format!("SELECT count(*) FROM blob WHERE sha256 = '{shared_sha}' AND ref_count = 1");
    wait_until(
        &srv.pool,
        &count_sql,
        |c| c == 1,
        "shared blob ref_count -> 1",
    )
    .await;

    // Give the outbox worker time; it must NOT have enqueued/processed a delete.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let outbox_for_shared: i64 =
        sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE sha256 = $1")
            .bind(&shared_sha)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert_eq!(
        outbox_for_shared, 0,
        "a still-referenced blob must never be enqueued for deletion"
    );
    let still_present: i64 = sqlx::query_scalar("SELECT count(*) FROM blob WHERE sha256 = $1")
        .bind(&shared_sha)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(still_present, 1, "shared blob row still present");

    // Delete in repo B: last ref goes → outbox enqueues → worker removes blob.
    assert_eq!(put_policy(&srv, "ret-shared-b", policy).await, 200);
    assert_eq!(trigger_run(&srv, "ret-shared-b").await, 202);

    wait_until(
        &srv.pool,
        &format!("SELECT count(*) FROM blob WHERE sha256 = '{shared_sha}'"),
        |c| c == 0,
        "shared blob removed after last reference dropped",
    )
    .await;
    wait_until(
        &srv.pool,
        "SELECT count(*) FROM blob_outbox WHERE processed_at IS NULL",
        |c| c == 0,
        "outbox drained after last-ref delete",
    )
    .await;
}

// ── 5. multi-instance: a due repo is evaluated exactly once (SKIP LOCKED) ─────

/// Two server instances sharing the same Postgres + versitygw both run the
/// retention worker. A single armed repo must be evaluated by **exactly one**
/// instance per cycle: the `FOR UPDATE SKIP LOCKED` lease over `retention_run`
/// means no double-evaluation. We assert all audit rows carry a single `run_id`
/// and the expected number of deletes happened exactly once.
#[tokio::test]
async fn multi_instance_evaluates_due_repo_only_once() {
    let a = worker_stack().await;
    let _b = a.spawn_peer().await; // peer shares DB + S3, workers enabled.

    let repo = "ret-multi";
    let id = "Multi.Lib";

    assert_eq!(
        a.create_repo(json!({"name": repo, "kind": "hosted"}))
            .await
            .status(),
        201
    );
    for minor in 0..12 {
        assert_eq!(
            a.push_nupkg(repo, make_nupkg(id, &format!("1.{minor}.0")))
                .await
                .status(),
            201
        );
    }
    let rid = repo_id(&a.pool, repo).await;
    age_all_components(&a.pool, rid, 2).await;

    assert_eq!(
        put_policy(
            &a,
            repo,
            json!({
                "version": 1,
                "enabled": true,
                "min_run_interval_seconds": 3600,
                "rules": [{
                    "id": "keep-10",
                    "action": "hard_delete",
                    "criteria": { "keep_last_n": 10, "older_than_days": 1 }
                }]
            }),
        )
        .await,
        200
    );
    assert_eq!(trigger_run(&a, repo).await, 202);

    // Exactly 2 hard-deletes (12 - keep 10), evaluated once.
    wait_until(
        &a.pool,
        &format!(
            "SELECT count(*) FROM retention_audit WHERE repository_id = {rid} AND action = 'hard_delete'"
        ),
        |c| c == 2,
        "2 hard_delete audit rows",
    )
    .await;

    // Let both instances poll a few more times; with min_run_interval=3600 the
    // repo is not due again, so no extra evaluation may happen on either node.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM retention_audit WHERE repository_id = $1")
            .bind(rid)
            .fetch_one(&a.pool)
            .await
            .unwrap();
    assert_eq!(
        total, 2,
        "no double-evaluation across instances: exactly 2 audit rows"
    );

    // All audit rows belong to a single evaluation pass (one run_id).
    let distinct_runs: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT run_id) FROM retention_audit WHERE repository_id = $1",
    )
    .bind(rid)
    .fetch_one(&a.pool)
    .await
    .unwrap();
    assert_eq!(
        distinct_runs, 1,
        "audit rows attributable to a single run_id"
    );

    // No blob left dangling; outbox drained cluster-wide.
    wait_until(
        &a.pool,
        "SELECT count(*) FROM blob WHERE ref_count <= 0",
        |c| c == 0,
        "no zero-ref blobs left",
    )
    .await;
}

// ── 6. preview / run / audit admin endpoints ─────────────────────────────────

/// The `preview` endpoint returns the decision set the worker *would* apply with
/// **zero** mutation and **zero** outbox rows; `run` then schedules a real pass
/// whose `audit` listing matches the preview.
#[tokio::test]
async fn preview_then_run_then_audit_endpoints() {
    let srv = worker_stack().await;
    let repo = "ret-preview";
    let id = "Preview.Lib";

    assert_eq!(
        srv.create_repo(json!({"name": repo, "kind": "hosted"}))
            .await
            .status(),
        201
    );
    for minor in 0..5 {
        assert_eq!(
            srv.push_nupkg(repo, make_nupkg(id, &format!("1.{minor}.0")))
                .await
                .status(),
            201
        );
    }
    let rid = repo_id(&srv.pool, repo).await;
    age_all_components(&srv.pool, rid, 2).await;

    // Pin the schedule far in the future BEFORE arming the policy so the
    // autonomous retention worker cannot claim this repo before the manual
    // `preview` below. (Otherwise, on a slow CI runner, the worker's ~1s poll
    // prunes the 3 eligible versions first, and preview then sees only the 2
    // kept ones — flaky.) `set_policy`'s run-row upsert is ON CONFLICT DO
    // NOTHING, so this future `next_run_at` survives arming; `trigger_run` below
    // resets it to now() to drive the real pass deterministically.
    sqlx::query(
        "INSERT INTO retention_run (repository_id, next_run_at) VALUES ($1, now() + interval '1 day') \
         ON CONFLICT (repository_id) DO UPDATE SET next_run_at = now() + interval '1 day'",
    )
    .bind(rid)
    .execute(&srv.pool)
    .await
    .expect("pin retention_run schedule");

    assert_eq!(
        put_policy(
            &srv,
            repo,
            json!({
                "version": 1,
                "enabled": true,
                "min_run_interval_seconds": 0,
                "rules": [{
                    "id": "keep-2",
                    "action": "hard_delete",
                    "criteria": { "keep_last_n": 2, "older_than_days": 1 }
                }]
            }),
        )
        .await,
        200
    );

    let (u, p) = srv.admin_basic();

    // ── preview: 3 hard-deletes predicted, nothing mutated ──
    let preview: Value = srv
        .client()
        .post(format!(
            "{}/admin/repositories/{repo}/retention/preview",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        preview["counts"]["deleted"].as_u64().unwrap(),
        3,
        "preview predicts 3 deletes (5 - keep 2): {preview}"
    );
    assert_eq!(preview["decisions"].as_array().unwrap().len(), 3);

    // Preview mutated nothing: no audit rows, no outbox, all blobs intact.
    assert_eq!(
        audit_count(&srv.pool, rid, None).await,
        0,
        "preview wrote no audit"
    );
    let outbox: i64 = sqlx::query_scalar("SELECT count(*) FROM blob_outbox")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(outbox, 0, "preview enqueued no outbox rows");

    // ── run: real pass ──
    assert_eq!(trigger_run(&srv, repo).await, 202);
    wait_until(
        &srv.pool,
        &format!(
            "SELECT count(*) FROM retention_audit WHERE repository_id = {rid} AND action = 'hard_delete'"
        ),
        |c| c == 3,
        "3 hard_delete audit rows after run",
    )
    .await;

    // ── audit endpoint reflects the applied decisions ──
    let audit: Value = srv
        .client()
        .get(format!(
            "{}/admin/repositories/{repo}/retention/audit",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = audit["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        3,
        "audit endpoint lists the 3 deletes: {audit}"
    );
    assert!(items.iter().all(|i| i["action"] == json!("hard_delete")));
    assert!(items.iter().all(|i| !i["dry_run"].as_bool().unwrap()));
}

// ── 7. proxy evict-not-pulled: cold cached versions evicted, warm retained ────

/// Two long-established versions are cached on a proxy with a package delay by
/// downloading them through the full HTTP stack. The older one is backdated to
/// look "cold" (not pulled in > 30 days); a `scope: proxy_cached` rule with
/// `not_pulled_for_days = 30` evicts only the cold one: its downloaded blob is
/// dereferenced + removed via the outbox worker while the warm one is retained.
///
/// The evicted version's `proxy_cached_version` row is **kept** as
/// metadata-only (`downloaded = false`, `first_seen_at` untouched), so it
/// stays listed and its next pull re-fetches it from upstream and serves it at
/// once. Regression for M7: the row used to be deleted, so the version
/// vanished from `index.json` and, re-discovered with `first_seen_at = now()`,
/// was hidden by the package delay for a whole window after every eviction.
#[tokio::test]
async fn proxy_evicts_cold_cached_versions_only() {
    let srv = worker_stack().await;
    let id = "Cold.Lib";
    let lower = id.to_lowercase();

    // One upstream package with two versions (a per-version `single` would
    // overwrite the corpus entry, leaving only the last version resolvable).
    let mut versions = HashMap::new();
    versions.insert("1.0.0".to_string(), make_nupkg(id, "1.0.0"));
    versions.insert("2.0.0".to_string(), make_nupkg(id, "2.0.0"));
    let mock = MockUpstream::start(vec![UpstreamPackage {
        id: lower.clone(),
        versions,
    }])
    .await;

    let repo = "ret-proxy";
    assert_eq!(
        srv.create_repo(json!({
            "name": repo,
            "kind": "proxy",
            "remote_url": mock.index_url(),
            "metadata_ttl_seconds": 600,
            "not_found_ttl_seconds": 600,
            "package_delay_seconds": 3600,
        }))
        .await
        .status(),
        201
    );
    let rid = repo_id(&srv.pool, repo).await;

    // Discover both versions; the package delay hides them at first ...
    assert!(
        listed_versions(&srv, repo, &lower).await.is_empty(),
        "fresh versions are delay-gated"
    );
    // ... so make them long-established (first seen 90 days ago).
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = now() - interval '90 days' \
         WHERE repository_id = $1",
    )
    .bind(rid)
    .execute(&srv.pool)
    .await
    .unwrap();

    // Cache both versions on demand (creates component + asset + blob each).
    let (u, p) = srv.admin_basic();
    let pull = |v: &'static str| {
        let url = format!(
            "{}/repository/{repo}/flat/{lower}/{v}/{lower}.{v}.nupkg",
            srv.base_url
        );
        let req = srv.client().get(url).basic_auth(&u, Some(&p));
        async move { req.send().await.unwrap().status() }
    };
    for v in ["1.0.0", "2.0.0"] {
        assert_eq!(pull(v).await, 200, "cache {v}");
    }

    // Both cached + downloaded.
    let cached: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM proxy_cached_version WHERE repository_id = $1 AND downloaded",
    )
    .bind(rid)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(cached, 2, "both versions cached + downloaded");
    let first_seen_before: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT first_seen_at FROM proxy_cached_version \
         WHERE repository_id = $1 AND version = '1.0.0'",
    )
    .bind(rid)
    .fetch_one(&srv.pool)
    .await
    .unwrap();

    // Downloads are counted in batches (#119): let both pulls be written
    // first, so a late write cannot warm the version backdated below.
    let mut stamped = 0_i64;
    for _ in 0..200 {
        stamped = sqlx::query_scalar(
            "SELECT count(*) FROM proxy_cached_version \
             WHERE repository_id = $1 AND last_downloaded_at IS NOT NULL",
        )
        .bind(rid)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
        if stamped == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(stamped, 2, "both pulls were counted");

    // Make 1.0.0 cold: not pulled for 90 days.
    sqlx::query(
        "UPDATE proxy_cached_version SET last_downloaded_at = now() - interval '90 days' \
         WHERE repository_id = $1 AND version = '1.0.0'",
    )
    .bind(rid)
    .execute(&srv.pool)
    .await
    .unwrap();
    // Keep 2.0.0 warm (pulled just now).
    sqlx::query(
        "UPDATE proxy_cached_version SET last_downloaded_at = now() \
         WHERE repository_id = $1 AND version = '2.0.0'",
    )
    .bind(rid)
    .execute(&srv.pool)
    .await
    .unwrap();

    assert_eq!(
        put_policy(
            &srv,
            repo,
            json!({
                "version": 1,
                "enabled": true,
                "min_run_interval_seconds": 0,
                "rules": [{
                    "id": "proxy-evict-cold",
                    "action": "hard_delete",
                    "scope": "proxy_cached",
                    "criteria": { "not_pulled_for_days": 30 }
                }]
            }),
        )
        .await,
        200
    );
    assert_eq!(trigger_run(&srv, repo).await, 202);

    // Exactly one cold version evicted.
    wait_until(
        &srv.pool,
        &format!(
            "SELECT count(*) FROM retention_audit WHERE repository_id = {rid} \
             AND action = 'hard_delete' AND target_kind = 'proxy_cached_version'"
        ),
        |c| c == 1,
        "1 proxy eviction audit row",
    )
    .await;

    // Both rows remain; only the warm version still has its bytes, and the
    // evicted one kept its first sighting.
    let rows: Vec<(String, bool, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT version, downloaded, first_seen_at FROM proxy_cached_version \
         WHERE repository_id = $1 ORDER BY version",
    )
    .bind(rid)
    .fetch_all(&srv.pool)
    .await
    .unwrap();
    let state: Vec<(&str, bool)> = rows.iter().map(|(v, d, _)| (v.as_str(), *d)).collect();
    assert_eq!(
        state,
        vec![("1.0.0", false), ("2.0.0", true)],
        "evicted row kept as metadata-only"
    );
    assert_eq!(rows[0].2, first_seen_before, "first_seen_at preserved");
    assert!(
        !component_exists(&srv.pool, rid, &lower, "1.0.0").await,
        "evicted bytes' component removed"
    );

    // The evicted version's blob is dereferenced and removed via the outbox.
    wait_until(
        &srv.pool,
        "SELECT count(*) FROM blob WHERE ref_count <= 0",
        |c| c == 0,
        "evicted blob removed",
    )
    .await;
    wait_until(
        &srv.pool,
        "SELECT count(*) FROM blob_outbox WHERE processed_at IS NULL",
        |c| c == 0,
        "proxy-eviction outbox drained",
    )
    .await;

    // The evicted version is still listed (not delay-gated) ...
    let mut listed = listed_versions(&srv, repo, &lower).await;
    listed.sort();
    assert_eq!(listed, vec!["1.0.0".to_string(), "2.0.0".to_string()]);
    // ... and its next pull re-fetches it from upstream and serves it at once.
    let upstream_pulls = mock.nupkg_hits();
    assert_eq!(pull("1.0.0").await, 200, "evicted version restores");
    assert_eq!(mock.nupkg_hits(), upstream_pulls + 1, "re-fetched upstream");
    let downloaded: bool = sqlx::query_scalar(
        "SELECT downloaded FROM proxy_cached_version \
         WHERE repository_id = $1 AND version = '1.0.0'",
    )
    .bind(rid)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert!(downloaded, "re-cached on the pull");
}

async fn component_exists(pool: &PgPool, repo_id: i64, name: &str, version: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM component WHERE repository_id = $1 AND name = $2 AND version = $3",
    )
    .bind(repo_id)
    .bind(name)
    .bind(version)
    .fetch_one(pool)
    .await
    .unwrap()
        > 0
}

/// A `run` against a repo with no policy is a 409 (nothing to schedule).
#[tokio::test]
async fn run_without_policy_conflicts() {
    let srv = worker_stack().await;
    let repo = "ret-nopolicy";
    assert_eq!(
        srv.create_repo(json!({"name": repo, "kind": "hosted"}))
            .await
            .status(),
        201
    );
    assert_eq!(
        trigger_run(&srv, repo).await,
        reqwest::StatusCode::CONFLICT,
        "run on an unarmed repo is a 409"
    );
}
