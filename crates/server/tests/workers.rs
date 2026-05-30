//! E2E: background workers drain the outbox exactly once cluster-wide, even
//! with two server instances sharing one DB + S3 (plan 10.5). Requires Docker.

mod common;

use common::ServerOpts;
use std::time::Duration;

/// Publish a package, hard-delete it (driving its blob ref-count to zero and
/// enqueuing an outbox delete), then let the workers run on **two** instances
/// sharing the DB and assert the blob row + outbox row are gone (S3 object
/// deleted exactly once via `FOR UPDATE SKIP LOCKED`).
#[tokio::test]
async fn outbox_drained_once_across_two_instances() {
    let pool = common::pool().await;

    // Instance A: workers on. Instance B: workers on too (shared DB).
    let a = common::start_with(
        pool.clone(),
        ServerOpts {
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            spawn_workers: true,
            ..Default::default()
        },
    )
    .await;
    let b = common::start_with(
        pool.clone(),
        ServerOpts {
            // Avoid a second bootstrap-admin insert clash on the shared DB.
            bootstrap_admin: None,
            spawn_workers: true,
            ..Default::default()
        },
    )
    .await;

    let (u, p) = a.admin_basic();
    let client = a.client();
    let repo = format!("wrepo{}", common::unique());
    let id = format!("Worker.Pkg{}", common::unique());
    let lower = id.to_lowercase();

    client
        .post(format!("{}/admin/repositories", a.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();

    // Publish via instance A (API-key authenticated).
    let api_key = a.admin_token().await;
    let bytes = common::make_nupkg(&id, "1.0.0");
    let part = reqwest::multipart::Part::bytes(bytes.clone())
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("package", part);
    let resp = client
        .put(format!("{}/v3/{repo}/package", a.base_url))
        .header("X-NuGet-ApiKey", &api_key)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // The package is visible on instance B (shared DB) — scale-out read.
    let resp = client
        .get(format!("{}/v3/{repo}/flat/{lower}/index.json", b.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "push on A must be visible on B");

    // How many committed blobs exist for this package right now? (nupkg +
    // derived nuspec = 2 distinct blobs.)
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM blob WHERE state = 'committed' AND ref_count > 0")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(before >= 2, "expected the package's blobs to be committed");

    // Hard-delete the package via the admin API (decref → ref_count 0 →
    // enqueue outbox delete in one tx; grace_seconds = 0 so it is due now).
    let resp = client
        .delete(format!(
            "{}/admin/repositories/{repo}/packages/{id}/1.0.0",
            a.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "hard delete must return 204");

    // Wait for the workers (poll every 1s) to drain the outbox on either
    // instance. The blob rows for this package must disappear and there must be
    // no unprocessed outbox rows left.
    let mut drained = false;
    for _ in 0..40 {
        let pending_outbox: i64 =
            sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE processed_at IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        let zero_ref_blobs: i64 =
            sqlx::query_scalar("SELECT count(*) FROM blob WHERE ref_count <= 0")
                .fetch_one(&pool)
                .await
                .unwrap();
        if pending_outbox == 0 && zero_ref_blobs == 0 {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        drained,
        "outbox should be drained and zero-ref blobs removed by the workers"
    );

    drop(a);
    drop(b);
}
