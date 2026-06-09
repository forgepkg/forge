//! Integration tests for the 12.7 `auth_realm` DAO against a real Postgres
//! testcontainer.
//!
//! Covers what the realm runtime hinges on:
//!   * migration 0010 seeds the built-in `local` realm;
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
        .expect("local realm seeded by migration 0010");
    assert_eq!(local.kind, "local");
    assert!(local.enabled);
    assert!(auth_realm_dao::kind_exists(&pool, "local").await.expect("query"));
}

#[tokio::test]
async fn insert_list_update_delete_round_trip() {
    let pool = pool().await;
    let n = unique();
    let name = format!("cf-{n}");

    // A fixed per-test offset avoids racing other tests for the same
    // next_priority slot (tests share one database).
    let prio = 200_000 + n as i32;
    let realm = auth_realm_dao::insert_realm(
        &pool,
        new_realm(&name, "credential_forwarding", prio),
    )
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
    let enabled = auth_realm_dao::list_enabled_realms(&pool).await.expect("list");
    assert!(enabled.iter().all(|r| r.name != name));

    assert!(auth_realm_dao::delete_realm(&pool, realm.id).await.expect("delete"));
    assert!(!auth_realm_dao::delete_realm(&pool, realm.id).await.expect("idempotent"));
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
    let err = auth_realm_dao::insert_realm(
        &pool,
        new_realm(&name, "credential_forwarding", prio + 1),
    )
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
    let pool = pool().await;
    let n = unique();
    let a = auth_realm_dao::insert_realm(
        &pool,
        new_realm(&format!("ra-{n}"), "credential_forwarding", 100_000 + n as i32),
    )
    .await
    .expect("insert a");
    let b = auth_realm_dao::insert_realm(
        &pool,
        new_realm(&format!("rb-{n}"), "credential_forwarding", 100_001 + n as i32),
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
    auth_realm_dao::reorder_realms(&pool, &order).await.expect("reorder");

    let all = auth_realm_dao::list_realms(&pool).await.expect("list");
    let pos_a = all.iter().position(|r| r.id == a.id).unwrap();
    let pos_b = all.iter().position(|r| r.id == b.id).unwrap();
    assert!(pos_b < pos_a, "b reordered above a");
    // Priorities were renumbered to the (index+1)*10 scheme.
    assert!(all.windows(2).all(|w| w[0].priority < w[1].priority));
}
