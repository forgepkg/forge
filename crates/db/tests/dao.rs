//! Integration tests for the DAO layer against a real Postgres testcontainer.
//!
//! Requires Docker on the host. All tests share one container/pool (see
//! `common`) and isolate themselves with unique names.

mod common;

use chrono::{Duration, Utc};
use forge_db::asset_dao::{self, NewAsset};
use forge_db::blob_dao;
use forge_db::component_dao::{self, NewComponent};
use forge_db::model::{BlobState, RepoKind};
use forge_db::outbox_dao;
use forge_db::proxy_dao::{self, NewProxyCachedVersion};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::token_dao::{self, NewToken};
use forge_db::user_dao::{self, NewUser};

use common::{pool, unique};

// ── repository / group_member ───────────────────────────────────────────────

#[tokio::test]
async fn repository_insert_and_fetch_round_trip() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let name = format!("repo-rt-{n}");

    let inserted = repository_dao::insert_repository(pool, NewRepository::hosted(&name))
        .await
        .expect("insert");
    assert_eq!(inserted.name, name);
    assert_eq!(inserted.kind(), RepoKind::Hosted);

    let by_name = repository_dao::find_repository_by_name(pool, &name)
        .await
        .expect("find by name")
        .expect("present");
    assert_eq!(by_name.id, inserted.id);

    let by_id = repository_dao::find_repository_by_id(pool, inserted.id)
        .await
        .expect("find by id")
        .expect("present");
    assert_eq!(by_id.name, name);

    let all = repository_dao::list_repositories(pool).await.expect("list");
    assert!(all.iter().any(|r| r.id == inserted.id));
}

#[tokio::test]
async fn group_members_ordered_by_priority_desc() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();

    let group = repository_dao::insert_repository(pool, NewRepository::group(format!("grp-{n}")))
        .await
        .expect("group");
    let low = repository_dao::insert_repository(pool, NewRepository::hosted(format!("m-low-{n}")))
        .await
        .expect("low");
    let high =
        repository_dao::insert_repository(pool, NewRepository::hosted(format!("m-high-{n}")))
            .await
            .expect("high");
    let mid = repository_dao::insert_repository(pool, NewRepository::hosted(format!("m-mid-{n}")))
        .await
        .expect("mid");

    repository_dao::add_group_member(pool, group.id, low.id, 1)
        .await
        .expect("add low");
    repository_dao::add_group_member(pool, group.id, high.id, 100)
        .await
        .expect("add high");
    repository_dao::add_group_member(pool, group.id, mid.id, 50)
        .await
        .expect("add mid");

    let members = repository_dao::group_members(pool, group.id)
        .await
        .expect("members");

    // Highest priority first (wins ties per spec §7).
    let priorities: Vec<i32> = members.iter().map(|(_, p)| *p).collect();
    assert_eq!(priorities, vec![100, 50, 1], "must be priority DESC");
    assert_eq!(members[0].0.id, high.id);
    assert_eq!(members[2].0.id, low.id);

    assert!(repository_dao::remove_group_member(pool, group.id, mid.id)
        .await
        .expect("remove"));
    let after = repository_dao::group_members(pool, group.id)
        .await
        .expect("members after");
    assert_eq!(after.len(), 2);
}

// ── blob ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn blob_upsert_pending_returns_true_then_false() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-upsert-{}", unique());

    let first = blob_dao::upsert_pending(pool, &sha, 123, "k/1")
        .await
        .expect("first");
    assert!(first, "first insert returns true");

    let second = blob_dao::upsert_pending(pool, &sha, 123, "k/1")
        .await
        .expect("second");
    assert!(!second, "already-existing returns false");

    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(blob.state(), BlobState::Pending);
    assert_eq!(blob.ref_count, 0);
    assert_eq!(blob.size, 123);
}

#[tokio::test]
async fn blob_commit_and_incref_increments_and_commits() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-incref-{}", unique());
    blob_dao::upsert_pending(pool, &sha, 10, "k/2")
        .await
        .expect("upsert");

    let mut tx = pool.begin().await.expect("begin");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref 1");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref 2");
    tx.commit().await.expect("commit");

    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(blob.ref_count, 2);
    assert_eq!(blob.state(), BlobState::Committed);
}

#[tokio::test]
async fn blob_decref_to_zero_enqueues_exactly_one_outbox_row_in_same_tx() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-zero-{}", unique());
    let s3_key = format!("blobs/{sha}");
    blob_dao::upsert_pending(pool, &sha, 10, &s3_key)
        .await
        .expect("upsert");

    // refcount -> 1
    let mut tx = pool.begin().await.expect("begin");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref");
    tx.commit().await.expect("commit");

    // decref -> 0, must enqueue and return true; assert the outbox row exists
    // INSIDE the same transaction (before commit).
    let mut tx = pool.begin().await.expect("begin");
    let hit_zero =
        blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::seconds(3600))
            .await
            .expect("decref");
    assert!(hit_zero, "decref to zero returns true");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blob_outbox WHERE sha256 = $1 AND op = 'delete_object'",
    )
    .bind(&sha)
    .fetch_one(&mut *tx)
    .await
    .expect("count in tx");
    assert_eq!(
        count, 1,
        "exactly one delete_object row enqueued in same tx"
    );

    // The enqueued row carries the blob's s3_key and a future available_at.
    let row = sqlx::query!(
        "SELECT s3_key, available_at FROM blob_outbox WHERE sha256 = $1",
        sha
    )
    .fetch_one(&mut *tx)
    .await
    .expect("row in tx");
    assert_eq!(row.s3_key, s3_key);
    assert!(row.available_at > Utc::now());

    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn blob_decref_above_zero_returns_false_and_enqueues_nothing() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-nonzero-{}", unique());
    blob_dao::upsert_pending(pool, &sha, 10, "k/nz")
        .await
        .expect("upsert");

    // refcount -> 2
    let mut tx = pool.begin().await.expect("begin");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref 1");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref 2");
    tx.commit().await.expect("commit");

    // decref -> 1
    let mut tx = pool.begin().await.expect("begin");
    let hit_zero = blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::seconds(60))
        .await
        .expect("decref");
    assert!(!hit_zero, "decref above zero returns false");
    tx.commit().await.expect("commit");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE sha256 = $1")
        .bind(&sha)
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "nothing enqueued when refcount stays above zero");

    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(blob.ref_count, 1);
}

// ── outbox ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn outbox_claim_due_concurrent_txns_get_disjoint_rows() {
    let pool = pool().await;
    let pool = &pool;
    let tag = format!("claim-{}", unique());

    // Seed several due rows (sha tagged so we can isolate them).
    for i in 0..6 {
        sqlx::query(
            "INSERT INTO blob_outbox (op, sha256, s3_key, available_at) \
             VALUES ('delete_object', $1, $2, now() - interval '1 minute')",
        )
        .bind(format!("{tag}-{i}"))
        .bind(format!("k/{tag}/{i}"))
        .execute(pool)
        .await
        .expect("seed");
    }

    let now = Utc::now();

    // Two concurrent transactions, each claiming a batch with SKIP LOCKED.
    let mut tx_a = pool.begin().await.expect("begin a");
    let mut tx_b = pool.begin().await.expect("begin b");

    let claimed_a = outbox_dao::claim_due(&mut tx_a, 3, now, Duration::seconds(30))
        .await
        .expect("claim a");
    let claimed_b = outbox_dao::claim_due(&mut tx_b, 3, now, Duration::seconds(30))
        .await
        .expect("claim b");

    let ids_a: std::collections::HashSet<i64> = claimed_a.iter().map(|r| r.id).collect();
    let ids_b: std::collections::HashSet<i64> = claimed_b.iter().map(|r| r.id).collect();

    assert!(!ids_a.is_empty(), "tx A claimed some rows");
    assert!(!ids_b.is_empty(), "tx B claimed some rows");
    assert!(
        ids_a.is_disjoint(&ids_b),
        "concurrent claims must be disjoint (SKIP LOCKED): a={ids_a:?} b={ids_b:?}"
    );

    tx_a.commit().await.expect("commit a");
    tx_b.commit().await.expect("commit b");
}

#[tokio::test]
async fn outbox_mark_processed_and_bump_attempt() {
    let pool = pool().await;
    let pool = &pool;
    let tag = format!("mp-{}", unique());

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO blob_outbox (op, sha256, s3_key, available_at) \
         VALUES ('delete_object', $1, $2, now() - interval '1 minute') RETURNING id",
    )
    .bind(&tag)
    .bind(format!("k/{tag}"))
    .fetch_one(pool)
    .await
    .expect("seed");

    let next = Utc::now() + Duration::minutes(5);
    outbox_dao::bump_attempt(pool, id, next)
        .await
        .expect("bump");
    let row = sqlx::query!(
        "SELECT attempts, locked_until, processed_at FROM blob_outbox WHERE id = $1",
        id
    )
    .fetch_one(pool)
    .await
    .expect("row");
    assert_eq!(row.attempts, 1);
    assert!(row.locked_until.is_none());
    assert!(row.processed_at.is_none());

    outbox_dao::mark_processed(pool, id)
        .await
        .expect("processed");
    let processed_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT processed_at FROM blob_outbox WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("processed_at");
    assert!(processed_at.is_some());
}

// ── component / asset ─────────────────────────────────────────────────────────

#[tokio::test]
async fn component_find_and_list_versions() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo = repository_dao::insert_repository(pool, NewRepository::hosted(format!("crepo-{n}")))
        .await
        .expect("repo");

    for v in ["1.0.0", "1.1.0", "2.0.0"] {
        component_dao::insert_component(
            pool,
            NewComponent {
                repository_id: repo.id,
                name: "newtonsoft.json".to_string(),
                original_id: "Newtonsoft.Json".to_string(),
                version: v.to_string(),
                version_original: v.to_string(),
                listed: true,
            },
        )
        .await
        .expect("insert component");
    }

    let found = component_dao::find_component(pool, repo.id, "newtonsoft.json", "1.1.0")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(found.version, "1.1.0");
    assert_eq!(found.original_id, "Newtonsoft.Json");

    let versions = component_dao::list_versions(pool, repo.id, "newtonsoft.json")
        .await
        .expect("list");
    assert_eq!(versions.len(), 3);

    // set_listed flips the flag.
    assert!(
        component_dao::set_listed(pool, repo.id, "newtonsoft.json", "1.0.0", false)
            .await
            .expect("set_listed")
    );
    let unlisted = component_dao::find_component(pool, repo.id, "newtonsoft.json", "1.0.0")
        .await
        .expect("find")
        .expect("present");
    assert!(!unlisted.listed);

    // delete_component removes the version.
    assert!(
        component_dao::delete_component(pool, repo.id, "newtonsoft.json", "2.0.0")
            .await
            .expect("delete")
    );
    let remaining = component_dao::list_versions(pool, repo.id, "newtonsoft.json")
        .await
        .expect("list");
    assert_eq!(remaining.len(), 2);
}

#[tokio::test]
async fn asset_insert_find_and_list() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo = repository_dao::insert_repository(pool, NewRepository::hosted(format!("arepo-{n}")))
        .await
        .expect("repo");
    let component = component_dao::insert_component(
        pool,
        NewComponent {
            repository_id: repo.id,
            name: "pkg".to_string(),
            original_id: "Pkg".to_string(),
            version: "1.0.0".to_string(),
            version_original: "1.0.0".to_string(),
            listed: true,
        },
    )
    .await
    .expect("component");

    let sha = format!("asha-{n}");
    blob_dao::upsert_pending(pool, &sha, 99, &format!("k/{sha}"))
        .await
        .expect("blob");

    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: component.id,
            path: "pkg.1.0.0.nupkg".to_string(),
            content_type: "application/octet-stream".to_string(),
            blob_sha256: sha.clone(),
            size: 99,
            sha512_base64: Some("deadbeef".to_string()),
        },
    )
    .await
    .expect("asset nupkg");
    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: component.id,
            path: "pkg.nuspec".to_string(),
            content_type: "application/xml".to_string(),
            blob_sha256: sha.clone(),
            size: 99,
            sha512_base64: None,
        },
    )
    .await
    .expect("asset nuspec");

    let found = asset_dao::find_asset(pool, component.id, "pkg.1.0.0.nupkg")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(found.blob_sha256, sha);

    let all = asset_dao::assets_for_component(pool, component.id)
        .await
        .expect("list");
    assert_eq!(all.len(), 2);
    // Ordered by path.
    assert_eq!(all[0].path, "pkg.1.0.0.nupkg");
    assert_eq!(all[1].path, "pkg.nuspec");
}

// ── user / token ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_and_token_round_trip() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let username = format!("user-{n}");

    let user = user_dao::insert_user(
        pool,
        NewUser {
            username: username.clone(),
            password_hash: "argon2-hash".to_string(),
            is_admin: true,
            active: true,
        },
    )
    .await
    .expect("user");

    assert_eq!(
        user_dao::find_user_by_username(pool, &username)
            .await
            .expect("by name")
            .expect("present")
            .id,
        user.id
    );
    assert_eq!(
        user_dao::find_user_by_id(pool, user.id)
            .await
            .expect("by id")
            .expect("present")
            .username,
        username
    );

    let hash = format!("token-hash-{n}");
    let token = token_dao::insert_token(
        pool,
        NewToken {
            user_id: user.id,
            name: "ci".to_string(),
            token_hash: hash.clone(),
            expires_at: None,
        },
    )
    .await
    .expect("token");
    assert!(token.last_used_at.is_none());

    let by_hash = token_dao::find_token_by_hash(pool, &hash)
        .await
        .expect("by hash")
        .expect("present");
    assert_eq!(by_hash.id, token.id);
    assert_eq!(by_hash.user_id, user.id);

    token_dao::touch_last_used(pool, token.id)
        .await
        .expect("touch");
    let touched = token_dao::find_token_by_hash(pool, &hash)
        .await
        .expect("by hash")
        .expect("present");
    assert!(touched.last_used_at.is_some());
}

// ── proxy_dao ─────────────────────────────────────────────────────────────────

/// Helper: insert a proxy repository and return its id.
async fn proxy_repo(pool: &sqlx::PgPool, suffix: u64) -> i64 {
    repository_dao::insert_repository(pool, NewRepository::proxy(format!("proxy-repo-{suffix}")))
        .await
        .expect("proxy repo")
        .id
}

#[tokio::test]
async fn proxy_upsert_cached_version_insert_then_conflict_is_noop() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;

    let new = NewProxyCachedVersion {
        repository_id: repo_id,
        name: format!("pkg-{n}"),
        version: "1.0.0".to_string(),
        listed: true,
        downloaded: false,
        not_found: false,
    };

    // First insert: returns true (row created).
    let inserted = proxy_dao::upsert_cached_version(pool, new.clone())
        .await
        .expect("first upsert");
    assert!(inserted, "first upsert must return true");

    // Second insert with same (repo, name, version): ON CONFLICT DO NOTHING.
    let conflict = proxy_dao::upsert_cached_version(pool, new)
        .await
        .expect("second upsert");
    assert!(!conflict, "ON CONFLICT DO NOTHING must return false");
}

#[tokio::test]
async fn proxy_get_cached_version_returns_inserted_row() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;
    let name = format!("pkg-get-{n}");

    proxy_dao::upsert_cached_version(
        pool,
        NewProxyCachedVersion {
            repository_id: repo_id,
            name: name.clone(),
            version: "2.0.0".to_string(),
            listed: false,
            downloaded: true,
            not_found: false,
        },
    )
    .await
    .expect("upsert");

    let row = proxy_dao::get_cached_version(pool, repo_id, &name, "2.0.0")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(row.repository_id, repo_id);
    assert_eq!(row.name, name);
    assert_eq!(row.version, "2.0.0");
    assert!(!row.listed);
    assert!(row.downloaded);
    assert!(!row.not_found);

    // Missing version returns None.
    let missing = proxy_dao::get_cached_version(pool, repo_id, &name, "9.9.9")
        .await
        .expect("get missing");
    assert!(missing.is_none());
}

#[tokio::test]
async fn proxy_set_upstream_index_insert_then_upsert_updates_resources() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;

    let v1 = serde_json::json!([{"@id": "https://example.com/v1/", "@type": "SearchQueryService"}]);
    let first = proxy_dao::set_upstream_index(pool, repo_id, v1.clone(), Some("etag-1"))
        .await
        .expect("insert");
    assert_eq!(first.repository_id, repo_id);
    assert_eq!(first.resources, v1);
    assert_eq!(first.etag.as_deref(), Some("etag-1"));

    // Upsert with updated resources and etag.
    let v2 = serde_json::json!([{"@id": "https://example.com/v2/", "@type": "SearchQueryService"}]);
    let second = proxy_dao::set_upstream_index(pool, repo_id, v2.clone(), Some("etag-2"))
        .await
        .expect("upsert");
    assert_eq!(second.resources, v2);
    assert_eq!(second.etag.as_deref(), Some("etag-2"));
}

#[tokio::test]
async fn proxy_get_upstream_index_returns_latest() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;

    // Not yet set.
    let missing = proxy_dao::get_upstream_index(pool, repo_id)
        .await
        .expect("get missing");
    assert!(missing.is_none());

    let resources =
        serde_json::json!([{"@id": "https://example.com/", "@type": "RegistrationsBaseUrl"}]);
    proxy_dao::set_upstream_index(pool, repo_id, resources.clone(), None)
        .await
        .expect("set");

    let fetched = proxy_dao::get_upstream_index(pool, repo_id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(fetched.repository_id, repo_id);
    assert_eq!(fetched.resources, resources);
    assert!(fetched.etag.is_none());
}

#[tokio::test]
async fn proxy_lock_cached_version_for_update_blocks_concurrent_tx() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;
    let name = format!("pkg-lock-{n}");
    let version = "1.0.0".to_string();

    // Seed the row.
    proxy_dao::upsert_cached_version(
        pool,
        NewProxyCachedVersion {
            repository_id: repo_id,
            name: name.clone(),
            version: version.clone(),
            listed: true,
            downloaded: false,
            not_found: false,
        },
    )
    .await
    .expect("seed");

    // Transaction A locks the row.
    let mut tx_a = pool.begin().await.expect("begin a");
    let locked = proxy_dao::lock_cached_version_for_update(&mut tx_a, repo_id, &name, &version)
        .await
        .expect("lock a")
        .expect("row present");
    assert_eq!(locked.version, version);

    // Transaction B tries to lock the same row with a statement timeout; it
    // must block (and time out) because A still holds the FOR UPDATE lock.
    let mut tx_b = pool.begin().await.expect("begin b");
    sqlx::query("SET LOCAL statement_timeout = '500ms'")
        .execute(&mut *tx_b)
        .await
        .expect("set timeout b");
    let blocked =
        proxy_dao::lock_cached_version_for_update(&mut tx_b, repo_id, &name, &version).await;
    assert!(
        blocked.is_err(),
        "second locker must block (and time out) while A holds FOR UPDATE"
    );
    let _ = tx_b.rollback().await;

    // A releases by committing; row is now free.
    tx_a.commit().await.expect("commit a");

    // Transaction C can now lock the row without timing out.
    let mut tx_c = pool.begin().await.expect("begin c");
    sqlx::query("SET LOCAL statement_timeout = '2s'")
        .execute(&mut *tx_c)
        .await
        .expect("set timeout c");
    let re_locked = proxy_dao::lock_cached_version_for_update(&mut tx_c, repo_id, &name, &version)
        .await
        .expect("lock c")
        .expect("row present c");
    assert_eq!(re_locked.version, version);
    tx_c.commit().await.expect("commit c");
}
