//! Kept password hashes of credential-forwarding accounts (migration 0035):
//! where they may be stored, how a realm drops them, and how an account is
//! switched to a local one with its kept password.

mod common;

use forge_db::auth_realm_dao::{self, NewAuthRealm};
use forge_db::user_dao::{self, CapturedPasswordCounts};
use serde_json::json;
use sqlx::PgPool;

use common::{pool, unique};

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo";

async fn realm(pool: &PgPool, capture: bool) -> i64 {
    auth_realm_dao::insert_realm(
        pool,
        NewAuthRealm {
            kind: "credential_forwarding".into(),
            name: format!("kept-{}", unique()),
            enabled: false,
            priority: 5_000_000 + (unique() % 1_000_000) as i32,
            config: json!({ "url": "https://nexus.test/status", "capture_password_hash": capture }),
        },
    )
    .await
    .unwrap()
    .id
}

async fn upstream_user(pool: &PgPool, realm_id: i64) -> (i64, String) {
    let name = format!("kept-user-{}@example.com", unique());
    let user = user_dao::insert_forwarded_user(pool, &name, realm_id, true)
        .await
        .unwrap();
    (user.id, user.username)
}

async fn kept(pool: &PgPool, user_id: i64) -> Option<String> {
    sqlx::query_scalar("SELECT captured_password_hash FROM app_user WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_hash_is_stored_only_on_an_opted_in_realms_own_account() {
    let pool = pool().await;
    let on = realm(&pool, true).await;
    let off = realm(&pool, false).await;
    let (user, name) = upstream_user(&pool, on).await;

    assert!(
        !user_dao::store_captured_password_hash(&pool, user, off, HASH)
            .await
            .unwrap()
    );
    assert_eq!(
        kept(&pool, user).await,
        None,
        "another realm cannot store one"
    );

    assert!(
        user_dao::store_captured_password_hash(&pool, user, on, HASH)
            .await
            .unwrap()
    );
    assert_eq!(kept(&pool, user).await.as_deref(), Some(HASH));
    assert_eq!(
        user_dao::find_captured_password_hash(&pool, &name.to_uppercase(), on)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    assert_eq!(
        user_dao::find_captured_password_hash(&pool, &name, off)
            .await
            .unwrap(),
        None
    );
    let at = user_dao::captured_password_at(&pool, user).await.unwrap();
    assert!(at.is_some());
    assert!(user_dao::captured_password_times(&pool)
        .await
        .unwrap()
        .contains(&(user, at.unwrap())));

    // Never on a local account, even one in the realm's name space.
    let local = user_dao::insert_user(
        &pool,
        user_dao::NewUser::local(
            format!("kept-local-{}@example.com", unique()),
            HASH.into(),
            true,
        ),
    )
    .await
    .unwrap();
    assert!(
        !user_dao::store_captured_password_hash(&pool, local.id, on, HASH)
            .await
            .unwrap()
    );

    // The table refuses one on a local account outright.
    let err = sqlx::query(
        "UPDATE app_user SET captured_password_hash = $2, captured_password_at = now() WHERE id = $1",
    )
    .bind(local.id)
    .bind(HASH)
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("app_user_captured_password_hash_check"),
        "{err}"
    );
}

#[tokio::test]
async fn a_realm_drops_its_accounts_hashes() {
    let pool = pool().await;
    let a = realm(&pool, true).await;
    let b = realm(&pool, true).await;
    let (ua, _) = upstream_user(&pool, a).await;
    let (ub, _) = upstream_user(&pool, b).await;
    for (user, realm) in [(ua, a), (ub, b)] {
        assert!(
            user_dao::store_captured_password_hash(&pool, user, realm, HASH)
                .await
                .unwrap()
        );
    }

    assert_eq!(
        user_dao::clear_captured_password_hashes(&pool, a)
            .await
            .unwrap(),
        1
    );
    assert_eq!(kept(&pool, ua).await, None);
    assert_eq!(
        kept(&pool, ub).await.as_deref(),
        Some(HASH),
        "other realms keep theirs"
    );
    assert_eq!(
        user_dao::captured_password_at(&pool, ua).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn an_account_with_a_kept_hash_becomes_a_local_one() {
    let pool = pool().await;
    let realm_id = realm(&pool, true).await;
    let (with, with_name) = upstream_user(&pool, realm_id).await;
    let (without, _) = upstream_user(&pool, realm_id).await;
    assert!(
        user_dao::store_captured_password_hash(&pool, with, realm_id, HASH)
            .await
            .unwrap()
    );

    assert_eq!(
        user_dao::convert_to_local(&pool, without).await.unwrap(),
        None
    );
    let converted = user_dao::convert_to_local(&pool, with)
        .await
        .unwrap()
        .expect("converted");
    assert_eq!(converted.id, with);
    assert_eq!(converted.username, with_name);

    let user = user_dao::find_user_by_id(&pool, with)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.auth_source, "local");
    assert_eq!(user.password_hash.as_deref(), Some(HASH));
    assert!(user.active);
    assert_eq!(kept(&pool, with).await, None);
    assert!(
        user_dao::find_upstream_user(&pool, &with_name, Some(realm_id))
            .await
            .unwrap()
            .is_none(),
        "no longer the realm's account"
    );
    // Not again, and no new hash lands on it.
    assert_eq!(user_dao::convert_to_local(&pool, with).await.unwrap(), None);
    assert!(
        !user_dao::store_captured_password_hash(&pool, with, realm_id, HASH)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_realms_accounts_are_converted_at_once_and_orphans_one_by_one() {
    let pool = pool().await;
    let realm_id = realm(&pool, true).await;
    let (a, _) = upstream_user(&pool, realm_id).await;
    let (b, _) = upstream_user(&pool, realm_id).await;
    // A third account that keeps no hash.
    upstream_user(&pool, realm_id).await;
    for user in [a, b] {
        assert!(
            user_dao::store_captured_password_hash(&pool, user, realm_id, HASH)
                .await
                .unwrap()
        );
    }
    assert_eq!(
        user_dao::captured_password_counts(&pool, realm_id)
            .await
            .unwrap(),
        CapturedPasswordCounts {
            accounts: 3,
            captured: 2
        }
    );

    let mut converted: Vec<i64> = user_dao::convert_realm_users_to_local(&pool, realm_id)
        .await
        .unwrap()
        .into_iter()
        .map(|u| u.id)
        .collect();
    converted.sort();
    assert_eq!(converted, vec![a, b]);
    assert_eq!(
        user_dao::captured_password_counts(&pool, realm_id)
            .await
            .unwrap(),
        CapturedPasswordCounts {
            accounts: 1,
            captured: 0
        }
    );

    // Deleting a realm keeps its accounts' hashes: the orphans can still be
    // switched to local accounts.
    let gone = realm(&pool, true).await;
    let (orphan, _) = upstream_user(&pool, gone).await;
    assert!(
        user_dao::store_captured_password_hash(&pool, orphan, gone, HASH)
            .await
            .unwrap()
    );
    assert!(auth_realm_dao::delete_realm(&pool, gone).await.unwrap());
    assert_eq!(kept(&pool, orphan).await.as_deref(), Some(HASH));
    assert!(user_dao::convert_to_local(&pool, orphan)
        .await
        .unwrap()
        .is_some());
    let orphan = user_dao::find_user_by_id(&pool, orphan)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(orphan.auth_source, "local");
}
