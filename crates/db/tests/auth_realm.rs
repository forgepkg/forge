//! Integration tests for the `auth_realm` DAO against a real Postgres
//! testcontainer.
//!
//! Covers what the realm runtime hinges on:
//!   * the schema seeds the built-in `local` realm;
//!   * try-order is `priority` ascending and `reorder_realms` rewrites the
//!     full order transactionally (the unique constraint is deferrable);
//!   * `name` uniqueness and the slug CHECK surface as DB errors;
//!   * `kind_exists` answers the one-shot seeding guard.
//!
//! Requires Docker on the host. Tests share one container/pool (see `common`)
//! and isolate themselves with unique names where possible — except the seeded
//! `local` row assertions, which are read-only.

mod common;

use forge_db::auth_realm_dao::{self, AuthRealmUpdate, NewAuthRealm};
use serde_json::json;

use common::{pool, unique};

/// `reorder_realms` renumbers every realm in the shared database and bumps its
/// `updated_at`, so it would make a concurrent compare-and-set write see its
/// row as changed. The reorder and compare-and-set tests hold this lock for
/// their whole body.
static REWRITES_ALL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn new_realm(name: &str, kind: &str, priority: i32) -> NewAuthRealm {
    NewAuthRealm {
        kind: kind.to_string(),
        name: name.to_string(),
        enabled: true,
        priority,
        config: json!({"url": "https://example.test/status", "key_pepper": "p"}),
    }
}

#[tokio::test]
async fn migration_seeds_builtin_local_realm() {
    let pool = pool().await;
    let local = auth_realm_dao::find_realm_by_name(&pool, "local")
        .await
        .expect("query")
        .expect("local realm seeded by the schema");
    assert_eq!(local.kind, "local");
    assert!(local.enabled);
    assert!(auth_realm_dao::kind_exists(&pool, "local")
        .await
        .expect("query"));
}

#[tokio::test]
async fn insert_list_update_delete_round_trip() {
    let pool = pool().await;
    let n = unique();
    let name = format!("cf-{n}");

    // A fixed per-test offset avoids racing other tests for the same
    // next_priority slot (tests share one database).
    let prio = 200_000 + n as i32;
    let realm =
        auth_realm_dao::insert_realm(&pool, new_realm(&name, "credential_forwarding", prio))
            .await
            .expect("insert");
    assert_eq!(realm.name, name);
    assert_eq!(realm.priority, prio);

    // Listed in priority order, after the seeded local realm.
    let all = auth_realm_dao::list_realms(&pool).await.expect("list");
    let pos_local = all.iter().position(|r| r.name == "local").unwrap();
    let pos_new = all.iter().position(|r| r.name == name).unwrap();
    assert!(pos_local < pos_new, "local (priority 10) sorts first");

    // Disable → drops out of the enabled list.
    let updated = auth_realm_dao::update_realm(
        &pool,
        realm.id,
        AuthRealmUpdate {
            name: name.clone(),
            enabled: false,
            priority: realm.priority,
            config: realm.config.clone(),
        },
    )
    .await
    .expect("update")
    .expect("row exists");
    assert!(!updated.enabled);
    assert!(updated.updated_at >= realm.updated_at);
    let enabled = auth_realm_dao::list_enabled_realms(&pool)
        .await
        .expect("list");
    assert!(enabled.iter().all(|r| r.name != name));

    assert!(auth_realm_dao::delete_realm(&pool, realm.id)
        .await
        .expect("delete"));
    assert!(!auth_realm_dao::delete_realm(&pool, realm.id)
        .await
        .expect("idempotent"));
}

#[tokio::test]
async fn duplicate_name_and_bad_slug_rejected() {
    let pool = pool().await;
    let n = unique();
    let name = format!("dup-{n}");
    let prio = 300_000 + 2 * n as i32;
    auth_realm_dao::insert_realm(&pool, new_realm(&name, "credential_forwarding", prio))
        .await
        .expect("insert");

    // Same name again → unique violation (23505).
    let err =
        auth_realm_dao::insert_realm(&pool, new_realm(&name, "credential_forwarding", prio + 1))
            .await
            .expect_err("duplicate name");
    assert!(
        matches!(&err, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")),
        "{err}"
    );

    // Uppercase / spaces violate the slug CHECK (23514).
    let err = auth_realm_dao::insert_realm(
        &pool,
        new_realm("Not A Slug", "credential_forwarding", prio + 1_000_000),
    )
    .await
    .expect_err("bad slug");
    assert!(
        matches!(&err, sqlx::Error::Database(db) if db.code().as_deref() == Some("23514")),
        "{err}"
    );
}

#[tokio::test]
async fn reorder_swaps_priorities_transactionally() {
    let _rewrites_all = REWRITES_ALL.lock().await;
    let pool = pool().await;
    let n = unique();
    let a = auth_realm_dao::insert_realm(
        &pool,
        new_realm(
            &format!("ra-{n}"),
            "credential_forwarding",
            100_000 + n as i32,
        ),
    )
    .await
    .expect("insert a");
    let b = auth_realm_dao::insert_realm(
        &pool,
        new_realm(
            &format!("rb-{n}"),
            "credential_forwarding",
            100_001 + n as i32,
        ),
    )
    .await
    .expect("insert b");

    // Full-order rewrite: every realm id, with b promoted above a. A direct
    // swap collides on the unique priority mid-transaction — the deferrable
    // constraint is what makes this work.
    let mut order: Vec<i64> = auth_realm_dao::list_realms(&pool)
        .await
        .expect("list")
        .iter()
        .map(|r| r.id)
        .filter(|id| *id != a.id && *id != b.id)
        .collect();
    order.push(b.id);
    order.push(a.id);
    auth_realm_dao::reorder_realms(&pool, &order)
        .await
        .expect("reorder");

    let all = auth_realm_dao::list_realms(&pool).await.expect("list");
    let pos_a = all.iter().position(|r| r.id == a.id).unwrap();
    let pos_b = all.iter().position(|r| r.id == b.id).unwrap();
    assert!(pos_b < pos_a, "b reordered above a");
    // Priorities were renumbered to the (index+1)*10 scheme.
    assert!(all.windows(2).all(|w| w[0].priority < w[1].priority));
}

/// The compare-and-set writes the legacy config seed re-applies with: a row
/// changed since it was read (an admin edit, or a re-seal sweep, which leaves
/// `updated_at` alone) is not written, and neither is a marker that an admin
/// edit dropped or replaced.
#[tokio::test]
async fn compare_and_set_writes_refuse_a_changed_row_or_marker() {
    let _rewrites_all = REWRITES_ALL.lock().await;
    let pool = pool().await;
    let n = unique();
    let name = format!("cas-{n}");
    // Its own band: `300_000 + n` collides with the `300_000 + 2n` slots
    // `duplicate_name_and_bad_slug_rejected` takes whenever its `n` is half
    // of this one's.
    let realm = auth_realm_dao::insert_realm(
        &pool,
        new_realm(&name, "credential_forwarding", 400_000 + n as i32),
    )
    .await
    .expect("insert");
    let upd = |pepper: &str| AuthRealmUpdate {
        name: name.clone(),
        enabled: true,
        priority: realm.priority,
        config: json!({"url": "https://example.test/status", "key_pepper": pepper}),
    };

    let written =
        auth_realm_dao::update_realm_and_secrets_if_unchanged(&pool, &realm, upd("seed"), None)
            .await
            .expect("update")
            .expect("an unchanged row is written");
    assert!(
        auth_realm_dao::update_realm_and_secrets_if_unchanged(&pool, &realm, upd("stale"), None)
            .await
            .expect("update")
            .is_none(),
        "the row changed since `realm` was read"
    );
    sqlx::query("UPDATE auth_realm SET secrets_enc = '\\x00'::bytea WHERE id = $1")
        .bind(realm.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        auth_realm_dao::update_realm_and_secrets_if_unchanged(&pool, &written, upd("stale"), None)
            .await
            .expect("update")
            .is_none(),
        "a change that keeps updated_at is seen too"
    );
    let row = auth_realm_dao::find_realm_by_id(&pool, realm.id)
        .await
        .expect("find")
        .expect("row");
    assert_eq!(row.config["key_pepper"], "seed");

    let key = format!("test_seed_marker_{n}");
    forge_db::authz_dao::set_setting(&pool, &key, "v2:a")
        .await
        .unwrap();
    assert!(
        forge_db::authz_dao::replace_setting(&pool, &key, "v2:a", "v2:b")
            .await
            .unwrap()
    );
    assert!(
        !forge_db::authz_dao::replace_setting(&pool, &key, "v2:a", "v2:c")
            .await
            .unwrap()
    );
    forge_db::authz_dao::delete_setting(&pool, &key)
        .await
        .unwrap();
    assert!(
        !forge_db::authz_dao::replace_setting(&pool, &key, "v2:b", "v2:c")
            .await
            .unwrap(),
        "a dropped marker is not re-created"
    );
    assert_eq!(
        forge_db::authz_dao::get_setting(&pool, &key).await.unwrap(),
        None
    );
    auth_realm_dao::delete_realm(&pool, realm.id).await.unwrap();
}
