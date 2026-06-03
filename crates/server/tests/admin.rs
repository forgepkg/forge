//! E2E: admin API gating, bootstrap admin, repository/user/token/member CRUD,
//! password redaction, SSRF rejection, nested-group + duplicate-priority
//! rejection (plan 10.4). Requires Docker (Postgres + versitygw).

mod common;

use forge_db::asset_dao::{self, NewAsset};
use forge_db::blob_dao;
use forge_db::component_dao::{self, NewComponent};
use forge_db::repository_dao::{self, NewRepository};
use serde_json::{json, Value};

/// The bootstrap admin can authenticate (basic) and list repositories; the
/// admin API requires admin (anonymous → 401).
#[tokio::test]
async fn bootstrap_admin_and_gating() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // No credentials → 401.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anonymous admin call must be 401");

    // Bootstrap admin via basic auth → 200.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin basic auth must succeed");
    let repos: Value = resp.json().await.unwrap();
    // Shared test DB: just assert a well-formed array (other parallel tests may
    // have created repos).
    assert!(repos.is_array(), "repositories list must be a JSON array");
}

/// A non-admin user is forbidden (403) from the admin API.
#[tokio::test]
async fn non_admin_forbidden() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let suffix = common::unique();
    let username = format!("plain{suffix}");

    // Admin creates a non-admin user.
    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": username, "password": "pw123456", "is_admin": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // That user authenticates (password basic) but is forbidden from admin.
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&username, Some("pw123456"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin must be 403");
}

/// `POST /admin/users/{id}/reauth` (slice 12.3): admin-only, 204 on a known
/// user (idempotent even with no cached verdicts), 404 for an unknown id, 403
/// for a non-admin caller.
#[tokio::test]
async fn reauth_endpoint_admin_only_and_idempotent() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let suffix = common::unique();
    let username = format!("reauth{suffix}");

    // Admin creates a non-admin user and discovers its id.
    let created: Value = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": username, "password": "pw123456", "is_admin": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = created["id"].as_i64().expect("user id");

    // Admin reauth → 204 (no cached verdicts, but still succeeds idempotently).
    let resp = client
        .post(format!("{}/admin/users/{user_id}/reauth", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "admin reauth succeeds");

    // Unknown id → 404.
    let resp = client
        .post(format!("{}/admin/users/9999999/reauth", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "unknown user → 404");

    // Non-admin caller → 403 (gated by require_admin).
    let resp = client
        .post(format!("{}/admin/users/{user_id}/reauth", srv.base_url))
        .basic_auth(&username, Some("pw123456"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin reauth → 403");
}

/// Create a proxy repository; `upstream_password` is accepted but REDACTED in
/// all responses (write-only).
#[tokio::test]
async fn proxy_password_is_write_only_and_redacted() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let name = format!("proxy{}", common::unique());

    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": "https://api.nuget.org/v3/index.json",
            "upstream_username": "svc",
            "upstream_password": "s3cret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "proxy create should succeed");
    let body: Value = resp.json().await.unwrap();
    // No password field anywhere; only a boolean flag.
    assert_eq!(body["has_upstream_password"], json!(true));
    assert!(body.get("upstream_password").is_none());
    assert_eq!(body["upstream_username"], json!("svc"));

    // GET also redacts.
    let resp = client
        .get(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("upstream_password").is_none());
    assert_eq!(body["has_upstream_password"], json!(true));
}

/// Creating a proxy whose `remote_url` resolves to a private address is
/// rejected by the SSRF guard (400) by default.
#[tokio::test]
async fn ssrf_private_remote_url_rejected() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let name = format!("ssrf{}", common::unique());

    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": "http://127.0.0.1:6379/index.json",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "private remote_url must be rejected");
}

/// Token issue returns the plaintext **once**; the issued token then
/// authenticates against the admin API; revoke disables it.
#[tokio::test]
async fn token_issue_use_and_revoke() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // Find the admin user's id.
    let users: Value = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["username"] == json!(u))
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    // Issue a token.
    let resp = client
        .post(format!("{}/admin/users/{admin_id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "ci"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    let token_id = body["id"].as_i64().unwrap();
    assert!(!token.is_empty());

    // The token authenticates via the X-NuGet-ApiKey header on the admin API.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "issued token should authenticate");

    // Revoke it.
    let resp = client
        .delete(format!("{}/admin/tokens/{token_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Now the token is rejected (present-but-invalid → 401).
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "revoked token must be rejected");
}

/// Deleting a **proxy** repository that has cached packages must decrement the
/// referenced blobs' ref-counts (enqueuing outbox deletes at zero) so S3 objects
/// can be reclaimed — a raw FK cascade would orphan the blob references. The
/// repository is then removed (204).
#[tokio::test]
async fn delete_proxy_repo_decrefs_cached_blobs() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("proxydel{s}");
    let sha = format!("{:0>64}", format!("deadbeef{s}"));
    let s3_key = format!("blobs/{sha}");

    // Seed a proxy repo with a cached package: blob (committed, ref_count 1) +
    // component + asset — mirroring what the proxy download path persists.
    let repo = repository_dao::insert_repository(
        &srv.pool,
        NewRepository {
            remote_url: Some("https://api.nuget.org/v3/index.json".into()),
            ..NewRepository::proxy(name.clone())
        },
    )
    .await
    .unwrap();

    assert!(
        blob_dao::upsert_pending(&srv.pool, &sha, 123, &s3_key)
            .await
            .unwrap(),
        "blob should be newly inserted"
    );
    {
        let mut tx = srv.pool.begin().await.unwrap();
        blob_dao::commit_and_incref(&mut tx, &sha).await.unwrap();
        let comp = component_dao::insert_component(
            &mut *tx,
            NewComponent {
                repository_id: repo.id,
                name: "somepkg".into(),
                original_id: "SomePkg".into(),
                version: "1.0.0".into(),
                version_original: "1.0.0".into(),
                listed: true,
            },
        )
        .await
        .unwrap();
        asset_dao::insert_asset(
            &mut *tx,
            NewAsset {
                component_id: comp.id,
                path: "somepkg.1.0.0.nupkg".into(),
                content_type: "application/octet-stream".into(),
                blob_sha256: sha.clone(),
                size: 123,
                sha512_base64: Some("c2hh".into()),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let before = blob_dao::get_blob(&srv.pool, &sha).await.unwrap().unwrap();
    assert_eq!(before.ref_count, 1, "blob seeded with one reference");

    // Delete the proxy repository.
    let resp = client
        .delete(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "proxy repo with cache must delete");

    // The repository is gone.
    assert!(repository_dao::find_repository_by_name(&srv.pool, &name)
        .await
        .unwrap()
        .is_none());

    // The blob ref-count was decremented to zero (not leaked).
    let after = blob_dao::get_blob(&srv.pool, &sha).await.unwrap().unwrap();
    assert_eq!(
        after.ref_count, 0,
        "blob ref-count must be decremented on repo delete"
    );

    // A deferred delete was enqueued so the S3 object is reclaimable (grace=0).
    let enqueued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blob_outbox WHERE sha256 = $1 AND op = 'delete_object'",
    )
    .bind(&sha)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(
        enqueued, 1,
        "an outbox delete must be enqueued at zero refs"
    );
}

/// Deleting a **hosted** repository that still owns packages is refused (409);
/// the admin must hard-delete the packages first.
#[tokio::test]
async fn delete_hosted_repo_with_packages_refused() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("hosteddel{s}");

    let repo = repository_dao::insert_repository(&srv.pool, NewRepository::hosted(name.clone()))
        .await
        .unwrap();
    component_dao::insert_component(
        &srv.pool,
        NewComponent {
            repository_id: repo.id,
            name: "pkg".into(),
            original_id: "Pkg".into(),
            version: "1.0.0".into(),
            version_original: "1.0.0".into(),
            listed: true,
        },
    )
    .await
    .unwrap();

    let resp = client
        .delete(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "hosted repo with packages must be refused"
    );

    // Still present.
    assert!(repository_dao::find_repository_by_name(&srv.pool, &name)
        .await
        .unwrap()
        .is_some());
}

/// Group membership: nested-group members and duplicate priorities are
/// rejected; a hosted member is accepted.
#[tokio::test]
async fn group_member_validation() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let group = format!("grp{s}");
    let group2 = format!("grp2_{s}");
    let hosted = format!("host{s}");

    let create = |name: &str, kind: &str| {
        let url = format!("{}/admin/repositories", srv.base_url);
        let (u, p) = (u.clone(), p.clone());
        let body = json!({"name": name, "kind": kind});
        let client = client.clone();
        async move {
            client
                .post(url)
                .basic_auth(&u, Some(&p))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    assert_eq!(create(&group, "group").await, 201);
    assert_eq!(create(&group2, "group").await, 201);
    assert_eq!(create(&hosted, "hosted").await, 201);

    let add = |member: &str, priority: i32| {
        let url = format!("{}/admin/repositories/{group}/members", srv.base_url);
        let (u, p) = (u.clone(), p.clone());
        let body = json!({"member": member, "priority": priority});
        let client = client.clone();
        async move {
            client
                .post(url)
                .basic_auth(&u, Some(&p))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    // Hosted member at priority 10 → created.
    assert_eq!(add(&hosted, 10).await, 201);
    // Nested group member → 400.
    assert_eq!(add(&group2, 20).await, 400, "nested group must be rejected");
    // Duplicate priority → 409.
    assert_eq!(
        add(&hosted, 10).await,
        409,
        "duplicate priority/member must be rejected"
    );
}
