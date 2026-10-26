//! E2E: admin retention REST surface. Requires Docker (Postgres + versitygw
//! via the shared harness).
//!
//! Covers the six endpoints under `/admin/repositories/{name}/retention`:
//! admin gating (401/403), PUT validation (400) + GET round-trip, DELETE
//! clearing, dry-run preview (decisions without mutation), run scheduling
//! (`next_run_at = now()` via the ledger), and audit listing.

mod common;

use forge_db::asset_dao::{self, NewAsset};
use forge_db::blob_dao;
use forge_db::component_dao::{self, NewComponent};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::retention_dao;
use serde_json::{json, Value};

/// A minimal valid hosted policy: keep newest 1, hard-delete the rest. The
/// trigger is `not_downloaded_for_days`; seeded components are never
/// downloaded and published two days ago, so it fires.
fn keep_one_policy() -> Value {
    json!({
        "version": 1,
        "enabled": true,
        "dry_run_only": false,
        "min_run_interval_seconds": 3600,
        "rules": [
            {
                "id": "keep-one",
                "action": "hard_delete",
                "release_type": "any",
                "criteria": { "keep_last_n": 1, "not_downloaded_for_days": 1 }
            }
        ]
    })
}

/// Seed a hosted repo with `versions.len()` components, each with a committed
/// blob + `.nupkg` asset, so retention has real candidates to evaluate.
async fn seed_hosted_with_versions(
    srv: &common::TestServer,
    repo_name: &str,
    pkg: &str,
    versions: &[&str],
) -> i64 {
    let repo =
        repository_dao::insert_repository(&srv.pool, NewRepository::hosted(repo_name.to_string()))
            .await
            .unwrap();

    for (i, ver) in versions.iter().enumerate() {
        let sha = format!("{:0>64}", format!("{repo_name}{i}"));
        let s3_key = format!("blobs/{sha}");
        blob_dao::upsert_pending(&srv.pool, &sha, 10, &s3_key)
            .await
            .unwrap();
        let mut tx = srv.pool.begin().await.unwrap();
        blob_dao::commit_and_incref(&mut tx, &sha).await.unwrap();
        let comp = component_dao::insert_component(
            &mut *tx,
            NewComponent {
                repository_id: repo.id,
                name: pkg.to_lowercase(),
                original_id: pkg.to_string(),
                version: ver.to_string(),
                version_original: ver.to_string(),
                listed: true,
            },
        )
        .await
        .unwrap();
        asset_dao::insert_asset(
            &mut *tx,
            NewAsset {
                component_id: comp.id,
                path: format!("{}.{ver}.nupkg", pkg.to_lowercase()),
                content_type: "application/octet-stream".into(),
                blob_sha256: sha.clone(),
                size: 10,
                sha512_base64: Some("c2hh".into()),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // Never downloaded counts from publication: make them two days old.
    sqlx::query(
        "UPDATE component SET created_at = now() - interval '2 days' WHERE repository_id = $1",
    )
    .bind(repo.id)
    .execute(&srv.pool)
    .await
    .unwrap();

    repo.id
}

/// Anonymous → 401; non-admin → 403 on the retention surface.
#[tokio::test]
async fn retention_admin_gated() {
    let srv = common::start().await;
    let client = srv.client();
    let s = common::unique();
    let name = format!("ret{s}");
    seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0"]).await;

    // Anonymous → 401.
    let resp = client
        .get(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anonymous retention GET must be 401");

    // Non-admin user → 403.
    let username = format!("plain{s}@example.com");
    srv.create_user(&username, "pw123456-retention", "reader")
        .await;

    let resp = client
        .get(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&username, Some("pw123456-retention"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin retention GET must be 403");
}

/// PUT an invalid policy → 400; PUT a valid one → 200, then GET round-trips it.
#[tokio::test]
async fn put_validates_then_get_round_trips() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("ret{s}");
    seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0"]).await;

    // Invalid: empty rules list is rejected by validate_policy → 400.
    let bad = json!({
        "version": 1, "enabled": true, "dry_run_only": false,
        "min_run_interval_seconds": 3600, "rules": []
    });
    let resp = client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": bad}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "empty-rules policy must be rejected");

    // A valid size budget can be the policy's only content.
    let budget_only = json!({
        "version": 1,
        "size_budget": { "max_bytes": 100, "target_bytes": 80 },
        "rules": []
    });
    let resp = client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": budget_only}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "budget-only policy must be accepted");
    let stored: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(stored["policy"]["size_budget"]["max_bytes"], 100);
    assert!(stored["current_size_bytes"].is_number());

    let preview = client
        .post(format!(
            "{}/admin/repositories/{name}/retention/preview",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(preview.status(), 200);
    let preview: serde_json::Value = preview.json().await.unwrap();
    assert_eq!(preview["size_before"], 10);
    assert_eq!(preview["size_after"], 10);
    assert_eq!(preview["target_bytes"], 80);
    assert_eq!(preview["target_reached"], true);

    let invalid_budget = json!({
        "version": 1,
        "size_budget": { "max_bytes": 100, "target_bytes": 101 },
        "rules": []
    });
    let resp = client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": invalid_budget}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "target above maximum must be rejected");

    let zero_max = json!({
        "version": 1,
        "size_budget": { "max_bytes": 0 },
        "rules": []
    });
    let resp = client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": zero_max}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "zero maximum must be rejected");

    // Invalid: a proxy-cached rule on a hosted repo is rejected → 400.
    let proxy_on_hosted = json!({
        "version": 1, "enabled": true, "dry_run_only": false,
        "min_run_interval_seconds": 3600,
        "rules": [{ "id": "x", "action": "hard_delete", "scope": "proxy_cached",
                    "criteria": { "not_pulled_for_days": 30 } }]
    });
    let resp = client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": proxy_on_hosted}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "proxy_cached scope on hosted repo must be rejected"
    );

    // Valid PUT → 200.
    let resp = client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": keep_one_policy()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "valid policy PUT must succeed");

    // GET round-trips the policy and exposes a ledger run row (armed).
    let resp = client
        .get(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["policy"]["rules"][0]["id"], json!("keep-one"));
    assert!(
        !body["last_run"].is_null(),
        "arming a policy must create a ledger run row"
    );
    assert_eq!(body["last_run"]["state"], json!("idle"));
}

/// A misspelled field anywhere in a PUT body is refused, not dropped: every
/// default it would fall back to is the unsafe one (`dry_run` for
/// `dry_run_only` stored a live policy, `package_prefix` matched every id,
/// `keep_last` protected nothing). A stored policy still parses: GET's policy
/// PUT back is accepted and preview evaluates it.
#[tokio::test]
async fn put_rejects_unknown_fields() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("retu{s}");
    seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0"]).await;
    let url = format!("{}/admin/repositories/{name}/retention", srv.base_url);
    let put = |body: Value| client.put(&url).basic_auth(&u, Some(&p)).json(&body).send();

    let rule = |extra: Value| {
        let mut rule = json!({
            "id": "old", "action": "hard_delete",
            "criteria": { "older_than_days": 30, "keep_last_n": 5 }
        });
        for (k, v) in extra.as_object().unwrap() {
            rule[k] = v.clone();
        }
        rule
    };
    for (body, field) in [
        // The example from the bug report, as sent.
        (
            json!({"policy": {"version": 1, "dry_run": true, "rules": [{
                "id": "old", "action": "hard_delete", "package_prefix": "Acme.Experimental",
                "criteria": { "older_than_days": 30, "keep_last": 5 }
            }]}}),
            "dry_run",
        ),
        (
            json!({"policy": {"version": 1, "enable": false, "rules": [rule(json!({}))]}}),
            "enable",
        ),
        (
            json!({"policy": {"version": 1, "rules": [rule(json!({"package_prefix": "Acme."}))]}}),
            "package_prefix",
        ),
        (
            json!({"policy": {"version": 1, "rules": [rule(json!({
                "criteria": { "older_than_days": 30, "keep_last": 5 }
            }))]}}),
            "keep_last",
        ),
        (
            json!({"policy": keep_one_policy(), "dry_run_only": true}),
            "dry_run_only",
        ),
    ] {
        let resp = put(body.clone()).await.unwrap();
        assert_eq!(resp.status(), 422, "{body}");
        let msg = resp.text().await.unwrap();
        assert!(
            msg.contains(&format!("unknown field `{field}`")),
            "the error names {field}: {msg}"
        );
    }
    let resp = client
        .get(&url)
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(body["policy"].is_null(), "nothing stored: {body}");

    // The stored (canonical) form round-trips.
    let resp = put(json!({"policy": keep_one_policy()})).await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(&url)
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let stored = resp.json::<Value>().await.unwrap()["policy"].clone();
    // Serialized with every field, including the defaulted ones.
    assert_eq!(stored["rules"][0]["scope"], json!("hosted"), "{stored}");
    assert!(stored["rules"][0]["package_name_prefix"].is_null());
    let resp = put(json!({"policy": stored})).await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{url}/preview"))
        .basic_auth(&u, Some(&p))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
}

/// A hosted-scope rule (scope omitted ⇒ hosted) on a proxy repo is rejected
/// with a 400 naming `scope: "proxy_cached"`, both on PUT and when such a
/// policy is already stored (preview). Regression for H2: it used to validate
/// and then delete the proxy's cached components behind `proxy_cached_version`.
#[tokio::test]
async fn hosted_scope_rule_on_proxy_is_rejected() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("retp{s}");
    let repo = repository_dao::insert_repository(&srv.pool, NewRepository::proxy(name.clone()))
        .await
        .unwrap();
    let url = format!("{}/admin/repositories/{name}/retention", srv.base_url);

    let hosted_on_proxy = json!({
        "version": 1,
        "rules": [{ "id": "sweep", "action": "hard_delete",
                    "criteria": { "older_than_days": 30 } }]
    });
    let resp = client
        .put(&url)
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": hosted_on_proxy}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "hosted-scope rule on a proxy must be rejected"
    );
    let msg = resp.text().await.unwrap();
    assert!(
        msg.contains(r#""scope": "proxy_cached""#),
        "the 400 must tell the operator to use proxy_cached: {msg}"
    );

    // The proxy-scoped equivalent is accepted.
    let proxy_rule = json!({
        "version": 1,
        "rules": [{ "id": "evict", "action": "hard_delete", "scope": "proxy_cached",
                    "criteria": { "not_pulled_for_days": 30 } }]
    });
    let resp = client
        .put(&url)
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": proxy_rule}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A hosted-scope policy stored before this validation existed is refused
    // by preview (the worker refuses it the same way) instead of evaluated.
    retention_dao::write_policy(&srv.pool, repo.id, Some(&hosted_on_proxy))
        .await
        .unwrap();
    let resp = client
        .post(format!("{url}/preview"))
        .basic_auth(&u, Some(&p))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let msg = resp.text().await.unwrap();
    assert!(
        msg.contains("stored policy is invalid") && msg.contains("proxy_cached"),
        "{msg}"
    );
}

/// DELETE clears the policy; a subsequent GET shows a null policy.
#[tokio::test]
async fn delete_clears_policy() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("ret{s}");
    seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0"]).await;

    client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": keep_one_policy()}))
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "DELETE clears the policy");

    let resp = client
        .get(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(body["policy"].is_null(), "policy must be cleared");
}

/// Preview is a true dry run: it returns the decisions the worker would apply
/// but mutates nothing (no listed flip, no deleted component, no outbox row).
#[tokio::test]
async fn preview_returns_decisions_without_mutating() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("ret{s}");
    // 3 versions; keep_last_n=1 → 2 oldest are deletion candidates.
    let repo_id =
        seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0", "1.1.0", "2.0.0"]).await;

    client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": keep_one_policy()}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!(
            "{}/admin/repositories/{name}/retention/preview",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    assert_eq!(
        body["counts"]["evaluated"],
        json!(3),
        "all three versions evaluated"
    );
    assert_eq!(
        body["counts"]["deleted"],
        json!(2),
        "two oldest would be hard-deleted"
    );
    assert_eq!(body["decisions"].as_array().unwrap().len(), 2);

    // No mutation: all three components still present.
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM component WHERE repository_id = $1")
            .bind(repo_id)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert_eq!(remaining, 3, "preview must not delete any component");

    // No outbox rows enqueued by the preview.
    let outbox: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blob_outbox bo \
         JOIN asset a ON a.blob_sha256 = bo.sha256 \
         JOIN component c ON c.id = a.component_id \
         WHERE c.repository_id = $1",
    )
    .bind(repo_id)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(outbox, 0, "preview must not enqueue any outbox delete");

    // No audit rows persisted by the preview.
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM retention_audit WHERE repository_id = $1")
            .bind(repo_id)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert_eq!(audited, 0, "preview must not write audit rows");
}

/// A preview over the size budget lists the budget's deletions next to the
/// rules' decisions, as a run would apply them: a tagged version is left
/// alone, a version the budget deletes is not also unlisted, and the
/// projected size says the target is out of reach.
#[tokio::test]
async fn preview_shows_the_size_budget_as_a_run_applies_it() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("ret{s}");
    // Four versions of 10 bytes each: 40 bytes.
    let repo_id = seed_hosted_with_versions(
        &srv,
        &name,
        "Sample.Lib",
        &["1.0.0", "1.1.0", "1.2.0", "2.0.0"],
    )
    .await;
    forge_db::tag_dao::set_tag(&srv.pool, repo_id, "sample.lib", "legacy", "1.0.0")
        .await
        .unwrap();

    let policy = json!({
        "version": 1,
        "size_budget": { "max_bytes": 25, "target_bytes": 15 },
        "rules": [{
            "id": "unlist-cold",
            "action": "unlist",
            "release_type": "any",
            "criteria": { "keep_last_n": 1, "not_downloaded_for_days": 1 }
        }]
    });
    let resp = client
        .post(format!(
            "{}/admin/repositories/{name}/retention/preview",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({ "policy": policy }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    // 1.0.0 is tagged and 2.0.0 the newest listed version: the budget
    // deletes the other two instead of the rule unlisting them.
    let decisions: Vec<(&str, &str, &str)> = body["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["version"].as_str().unwrap(),
                d["action"].as_str().unwrap(),
                d["rule_id"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        decisions,
        vec![
            ("1.1.0", "hard_delete", "size_budget"),
            ("1.2.0", "hard_delete", "size_budget"),
        ]
    );
    assert_eq!(body["counts"]["deleted"], 2);
    assert_eq!(body["counts"]["unlisted"], 0);
    assert_eq!(body["size_before"], 40);
    assert_eq!(body["size_after"], 20);
    assert_eq!(body["target_bytes"], 15);
    assert_eq!(body["target_reached"], false);
}

/// Preview with no policy returns an empty decision set (not an error).
#[tokio::test]
async fn preview_without_policy_is_empty() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("ret{s}");
    seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0"]).await;

    let resp = client
        .post(format!(
            "{}/admin/repositories/{name}/retention/preview",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decisions"].as_array().unwrap().len(), 0);
    assert_eq!(body["counts"]["evaluated"], json!(0));
}

/// `run` with a policy schedules the repo promptly (`next_run_at` advanced to
/// ~now via the ledger); without a policy it is a 409.
#[tokio::test]
async fn run_schedules_via_ledger() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("ret{s}");
    let repo_id = seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0"]).await;

    // No policy yet → run is a 409.
    let resp = client
        .post(format!(
            "{}/admin/repositories/{name}/retention/run",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "run without a policy must be 409");

    // Arm a policy with a far-future next_run via a large min_run_interval, then
    // push next_run_at into the future by finishing a run? Simpler: arm, then
    // bump next_run_at far out, then `run` should reset it to ~now.
    client
        .put(format!(
            "{}/admin/repositories/{name}/retention",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .json(&json!({"policy": keep_one_policy()}))
        .send()
        .await
        .unwrap();

    // Move next_run_at far into the future to prove `run` pulls it back.
    sqlx::query(
        "UPDATE retention_run SET next_run_at = now() + interval '1 day' WHERE repository_id = $1",
    )
    .bind(repo_id)
    .execute(&srv.pool)
    .await
    .unwrap();

    let resp = client
        .post(format!(
            "{}/admin/repositories/{name}/retention/run",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "run with a policy must be 202");

    // next_run_at was pulled back to ~now (well under the 1-day future stamp).
    let due_soon: bool = sqlx::query_scalar(
        "SELECT next_run_at <= now() + interval '1 minute' FROM retention_run WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert!(due_soon, "run must schedule next_run_at to ~now");
}

/// The audit endpoint returns persisted audit rows (newest first) and respects
/// the `run_id` filter.
#[tokio::test]
async fn audit_lists_persisted_rows() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("ret{s}");
    let repo_id = seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0"]).await;

    // Insert two audit rows directly (one per run) to exercise the reader +
    // filter without driving a full worker run.
    let run_a = uuid::Uuid::new_v4();
    let run_b = uuid::Uuid::new_v4();
    for (run, ver) in [(run_a, "1.0.0"), (run_b, "2.0.0")] {
        sqlx::query(
            "INSERT INTO retention_audit \
             (repository_id, run_id, rule_id, action, target_kind, package_name, version, dry_run, reason) \
             VALUES ($1, $2, 'keep-one', 'hard_delete', 'component', 'sample.lib', $3, false, '{}'::jsonb)",
        )
        .bind(repo_id)
        .bind(run)
        .bind(ver)
        .execute(&srv.pool)
        .await
        .unwrap();
    }

    // All rows for the repo.
    let resp = client
        .get(format!(
            "{}/admin/repositories/{name}/retention/audit",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "both audit rows returned");
    // Newest first: the second-inserted row (larger id) comes first.
    assert_eq!(items[0]["version"], json!("2.0.0"));

    // Filtered by run_id → only that pass's row.
    let resp = client
        .get(format!(
            "{}/admin/repositories/{name}/retention/audit?run_id={run_a}",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "run_id filter narrows to one row");
    assert_eq!(items[0]["version"], json!("1.0.0"));
}

/// A draft `policy` in the preview body is evaluated in place of the stored
/// one: validated like a `PUT` of it (422 for an unknown field, 400 for an
/// invalid rule), evaluated even while disabled, and never stored. A
/// misspelled `policy` is refused instead of previewing the stored policy.
#[tokio::test]
async fn preview_evaluates_a_draft_without_storing_it() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("retd{s}");
    seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0", "1.1.0", "2.0.0"]).await;
    let url = format!("{}/admin/repositories/{name}/retention", srv.base_url);
    let preview = |body: Value| {
        client
            .post(format!("{url}/preview"))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
    };
    let stored = || async {
        let resp = client
            .get(&url)
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap();
        resp.json::<Value>().await.unwrap()
    };

    // A disabled draft, with nothing stored: evaluated all the same.
    let mut draft = keep_one_policy();
    draft["enabled"] = json!(false);
    let resp = preview(json!({ "policy": draft })).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["counts"]["evaluated"], json!(3));
    assert_eq!(body["counts"]["deleted"], json!(2), "{body}");
    let view = stored().await;
    assert!(view["policy"].is_null(), "a draft is not stored: {view}");
    assert!(view["last_run"].is_null(), "a draft arms nothing: {view}");

    // With a policy stored, the draft is evaluated in its place.
    let resp = client
        .put(&url)
        .basic_auth(&u, Some(&p))
        .json(&json!({ "policy": keep_one_policy() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut keep_two = keep_one_policy();
    keep_two["rules"][0]["criteria"]["keep_last_n"] = json!(2);
    let body: Value = preview(json!({ "policy": keep_two }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["counts"]["deleted"], json!(1), "{body}");
    assert_eq!(body["decisions"][0]["version"], json!("1.0.0"));
    let body: Value = preview(json!({})).await.unwrap().json().await.unwrap();
    assert_eq!(
        body["counts"]["deleted"],
        json!(2),
        "the stored policy: {body}"
    );
    let view = stored().await;
    assert_eq!(
        view["policy"]["rules"][0]["criteria"]["keep_last_n"],
        json!(1),
        "the stored policy is unchanged: {view}"
    );

    // Refused like a PUT of it.
    let mut misspelled = keep_one_policy();
    misspelled["dry_run"] = json!(true);
    let resp = preview(json!({ "policy": misspelled })).await.unwrap();
    assert_eq!(resp.status(), 422);
    let msg = resp.text().await.unwrap();
    assert!(msg.contains("unknown field `dry_run`"), "{msg}");
    let mut empty = keep_one_policy();
    empty["rules"] = json!([]);
    let resp = preview(json!({ "policy": empty })).await.unwrap();
    assert_eq!(resp.status(), 400);
    let msg = resp.text().await.unwrap();
    assert!(msg.starts_with("invalid retention policy"), "{msg}");

    // A misspelled `policy` is not silently read as "the stored policy".
    let resp = preview(json!({ "polciy": keep_one_policy() }))
        .await
        .unwrap();
    assert_eq!(resp.status(), 422, "{}", resp.text().await.unwrap());
}

/// Whether retention runs and how long its audit log is kept are settings of
/// every instance (`/admin/settings/retention`, #429), on a database of its
/// own since they are install-wide. Switched off, no run is claimed, a run in
/// progress fails its fence, and Run now answers 409; switched on again, the
/// due run is claimed.
#[tokio::test]
async fn retention_settings_switch_runs_off_and_on() {
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            ..Default::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let settings_url = format!("{}/admin/settings/retention", srv.base_url);
    let put = |body: Value| {
        client
            .put(&settings_url)
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
    };
    let name = format!("rets{}", common::unique());
    let repo_id = seed_hosted_with_versions(&srv, &name, "Sample.Lib", &["1.0.0", "2.0.0"]).await;
    let url = format!("{}/admin/repositories/{name}/retention", srv.base_url);
    let resp = client
        .put(&url)
        .basic_auth(&u, Some(&p))
        .json(&json!({ "policy": keep_one_policy() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The defaults of an install that never saved them.
    let resp = client
        .get(&settings_url)
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        json!({ "runs_enabled": true, "audit_retention_seconds": 7_776_000 })
    );

    // Refused like the other admin bodies: out of range, unknown fields.
    let resp = put(json!({ "audit_retention_seconds": 3_153_600_001_u64 }))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = put(json!({ "enabled": false })).await.unwrap();
    assert_eq!(resp.status(), 422);

    // A run claimed while runs are on.
    let mut tx = srv.pool.begin().await.unwrap();
    let now = forge_db::db_now(&mut *tx).await.unwrap();
    let (claimed, run_id) = retention_dao::claim_next_due_repo(
        &mut tx,
        now,
        chrono::Duration::seconds(60),
        Some(repo_id),
    )
    .await
    .unwrap()
    .expect("a due repository is claimed while runs are on");
    tx.commit().await.unwrap();
    let fence = || async {
        let mut conn = srv.pool.acquire().await.unwrap();
        retention_dao::lock_run_fence(&mut conn, repo_id, run_id, &claimed.policy)
            .await
            .unwrap()
    };
    assert!(fence().await, "the fence holds while runs are on");

    // Switched off: the fence stops the run, Run now is refused, and the
    // repository's view says so. The other field keeps its value.
    let resp = put(json!({ "runs_enabled": false })).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        json!({ "runs_enabled": false, "audit_retention_seconds": 7_776_000 })
    );
    assert!(!fence().await, "a running run stops at its next batch");
    let resp = client
        .post(format!("{url}/run"))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    assert!(resp.text().await.unwrap().contains("switched off"));
    let view: Value = client
        .get(&url)
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(view["runs_enabled"], json!(false), "{view}");

    // Nothing is claimed while off, even a repository that is due.
    retention_dao::fail_run(&srv.pool, repo_id, Some(run_id), "test", now)
        .await
        .unwrap();
    let mut tx = srv.pool.begin().await.unwrap();
    let off = retention_dao::claim_next_due_repo(
        &mut tx,
        now + chrono::Duration::seconds(1),
        chrono::Duration::seconds(60),
        Some(repo_id),
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert!(off.is_none(), "no run is claimed while runs are off");

    // Switched on again with another audit retention: Run now is accepted.
    let resp = put(json!({ "runs_enabled": true, "audit_retention_seconds": 0 }))
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        json!({ "runs_enabled": true, "audit_retention_seconds": 0 })
    );
    let resp = client
        .post(format!("{url}/run"))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let settings = retention_dao::read_settings(&srv.pool).await.unwrap();
    assert!(settings.runs_enabled);
    assert!(settings.audit_retention().is_none(), "0 keeps every row");
}

/// #59: a proxy rule takes `keep_last_n` and `keep_n_most_downloaded`, and the
/// preview evicts none of the cached versions they keep.
#[tokio::test]
async fn proxy_rules_keep_the_newest_and_recently_pulled_cached_versions() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("retk{s}");
    let repo = repository_dao::insert_repository(&srv.pool, NewRepository::proxy(name.clone()))
        .await
        .unwrap();
    // Four cold cached versions: 1.0.0 was pulled last, 4.0.0 is the newest.
    for (version, pulled) in [("1.0.0", 40), ("2.0.0", 60), ("3.0.0", 70), ("4.0.0", 80)] {
        forge_db::proxy_dao::upsert_cached_version(
            &srv.pool,
            forge_db::proxy_dao::NewProxyCachedVersion {
                repository_id: repo.id,
                name: "lib".into(),
                version: version.into(),
                listed: true,
                downloaded: true,
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
        .bind(repo.id)
        .bind(version)
        .bind(pulled)
        .execute(&srv.pool)
        .await
        .unwrap();
    }
    let policy = json!({
        "version": 1,
        "rules": [{ "id": "evict", "action": "hard_delete", "scope": "proxy_cached",
                    "criteria": { "not_pulled_for_days": 30,
                                  "keep_last_n": 1, "keep_n_most_downloaded": 1 } }]
    });
    let url = format!("{}/admin/repositories/{name}/retention", srv.base_url);
    let resp = client
        .put(&url)
        .basic_auth(&u, Some(&p))
        .json(&json!({ "policy": policy }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let body: Value = client
        .post(format!("{url}/preview"))
        .basic_auth(&u, Some(&p))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["counts"]["evaluated"], json!(4), "{body}");
    let mut evicted: Vec<&str> = body["proxy_decisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["version"].as_str().unwrap())
        .collect();
    evicted.sort_unstable();
    assert_eq!(evicted, ["2.0.0", "3.0.0"], "{body}");

    // Zero protects nothing and is refused, as on hosted rules.
    let mut zero = policy.clone();
    zero["rules"][0]["criteria"]["keep_last_n"] = json!(0);
    let resp = client
        .put(&url)
        .basic_auth(&u, Some(&p))
        .json(&json!({ "policy": zero }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
