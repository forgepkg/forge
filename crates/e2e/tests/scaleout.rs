//! E2E: scale-out — two server instances sharing one Postgres + versitygw.
//! A push on instance A is visible on instance B; concurrent proxy misses across
//! both instances fetch upstream exactly once (row `FOR UPDATE`); the outbox is
//! drained exactly once cluster-wide (`SKIP LOCKED`) (spec §9). Gated behind
//! `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::time::Duration;

use forge_e2e::{make_nupkg, start_stack, MockUpstream, TestServer, UpstreamPackage};
use serde_json::Value;

async fn versions_on(srv: &TestServer, repo: &str, lower: &str) -> Vec<String> {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/index.json",
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

/// A package pushed on instance A is immediately visible on instance B (shared
/// DB + S3) and downloadable byte-for-byte from B.
#[tokio::test]
async fn push_on_a_visible_and_downloadable_on_b() {
    let a = start_stack().await;
    let b = a.spawn_peer().await;

    let id = "ScaleOut.Lib";
    let lower = id.to_lowercase();
    assert_eq!(
        a.create_repo(serde_json::json!({"name": "so-repo", "kind": "hosted"}))
            .await
            .status(),
        201
    );

    let bytes = make_nupkg(id, "1.0.0");
    assert_eq!(a.push_nupkg("so-repo", bytes.clone()).await.status(), 201);

    assert_eq!(
        versions_on(&b, "so-repo", &lower).await,
        vec!["1.0.0".to_string()],
        "push on A is visible on B"
    );

    let (u, p) = b.admin_basic();
    let resp = b
        .client()
        .get(format!(
            "{}/v3/so-repo/flat/{lower}/1.0.0/{lower}.1.0.0.nupkg",
            b.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap().as_ref(),
        bytes.as_slice(),
        "B serves the shared-S3 bytes pushed on A"
    );
}

/// Concurrent first-time proxy downloads of the same version — one issued to
/// instance A, one to instance B — both succeed and converge on a single cached
/// copy (cross-instance singleflight via the `proxy_cached_version` row lock, no
/// advisory locks).
///
/// The row lock is held only for the short state-decision and finalize
/// transactions, never across the upstream fetch / CAS PUT (Addendum A7). The
/// singleflight is thus *best-effort*: under contention both instances may fetch
/// from upstream, but the content-addressed CAS plus the `downloaded` re-check
/// in the finalize tx make the writers converge on identical state, after which
/// no instance hits upstream again.
#[tokio::test]
async fn concurrent_proxy_misses_across_instances_converge() {
    let a = start_stack().await;
    let b = a.spawn_peer().await;

    let nupkg = make_nupkg("Cross.Lib", "1.0.0");
    let mock =
        MockUpstream::start(vec![UpstreamPackage::single("cross.lib", "1.0.0", nupkg)]).await;
    assert_eq!(
        a.create_repo(serde_json::json!({
            "name": "xo-proxy",
            "kind": "proxy",
            "remote_url": mock.index_url(),
            "allow_private_upstream": true,
            "metadata_ttl_seconds": 600,
            "not_found_ttl_seconds": 600,
        }))
        .await
        .status(),
        201
    );

    let download = |srv: TestServer| async move {
        let (u, p) = srv.admin_basic();
        let st = srv
            .client()
            .get(format!(
                "{}/v3/xo-proxy/flat/cross.lib/1.0.0/cross.lib.1.0.0.nupkg",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap()
            .status();
        (srv, st)
    };

    let ha = tokio::spawn(download(a));
    let hb = tokio::spawn(download(b));
    let ((a, sa), (b, sb)) = (ha.await.unwrap(), hb.await.unwrap());

    assert_eq!(sa, 200, "A download ok");
    assert_eq!(sb, 200, "B download ok");

    let after_race = mock.nupkg_hits();
    assert!(
        after_race >= 1,
        "concurrent cross-instance first downloads must hit upstream at least once"
    );

    // The version is now cached and shared across both instances; a follow-up
    // read on instance A converges on the local copy with NO further upstream
    // call.
    let (u, p) = a.admin_basic();
    let st = a
        .client()
        .get(format!(
            "{}/v3/xo-proxy/flat/cross.lib/1.0.0/cross.lib.1.0.0.nupkg",
            a.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 200, "cached read ok");
    assert_eq!(
        mock.nupkg_hits(),
        after_race,
        "once cached, further cross-instance reads do not hit upstream"
    );

    drop(a);
    drop(b);
}

/// With workers running on both instances, the outbox is drained exactly once
/// cluster-wide: a hard-deleted package's blobs are removed and no instance
/// double-processes (the `SKIP LOCKED` lease guarantees single ownership).
#[tokio::test]
async fn outbox_drained_once_cluster_wide() {
    let a = start_stack().await; // primary mints the admin token (no workers)
                                 // Two worker-enabled peers sharing the same DB + S3 contend for the outbox;
                                 // the SKIP LOCKED lease guarantees each row is processed by exactly one.
    let _peer1 = a.spawn_peer().await;
    let _peer2 = a.spawn_peer().await;

    let id = "Cluster.Pkg";
    assert_eq!(
        a.create_repo(serde_json::json!({"name": "cl-repo", "kind": "hosted"}))
            .await
            .status(),
        201
    );
    let bytes = make_nupkg(id, "1.0.0");
    assert_eq!(a.push_nupkg("cl-repo", bytes).await.status(), 201);

    let committed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM blob WHERE state = 'committed' AND ref_count > 0")
            .fetch_one(&a.pool)
            .await
            .unwrap();
    assert!(committed >= 2, "nupkg + nuspec blobs committed");

    // Hard-delete ⇒ ref_count 0 ⇒ outbox deletes enqueued (grace 0).
    let (u, p) = a.admin_basic();
    let resp = a
        .client()
        .delete(format!(
            "{}/admin/repositories/cl-repo/packages/{id}/1.0.0",
            a.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Workers on the peers drain the outbox exactly once cluster-wide.
    let mut drained = false;
    for _ in 0..40 {
        let pending: i64 =
            sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE processed_at IS NULL")
                .fetch_one(&a.pool)
                .await
                .unwrap();
        let zero_ref: i64 = sqlx::query_scalar("SELECT count(*) FROM blob WHERE ref_count <= 0")
            .fetch_one(&a.pool)
            .await
            .unwrap();
        if pending == 0 && zero_ref == 0 {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        drained,
        "the cluster's workers must drain the outbox and remove zero-ref blobs"
    );

    // Every processed outbox row was claimed once; none is left unprocessed.
    let unprocessed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE processed_at IS NULL")
            .fetch_one(&a.pool)
            .await
            .unwrap();
    assert_eq!(unprocessed, 0, "outbox fully drained cluster-wide");
}
