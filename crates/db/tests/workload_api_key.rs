//! Integration tests for the token exchange's redemption records
//! (`workload_api_key_dao`) against a real Postgres testcontainer: a CI token
//! is redeemed once, never once the database's clock has it expired, and its
//! record outlives the latest moment it could still be redeemed.
//!
//! Requires Docker on the host (or `FORGE_TEST_DATABASE_URL`).

mod common;

use chrono::{DateTime, Duration, Utc};
use forge_db::workload_api_key_dao::{
    self, NewWorkloadApiKey, Redemption, MAX_TOKEN_LEEWAY_SECONDS, REAP_MARGIN_SECONDS,
};
use sqlx::PgPool;

use common::{pool, unique};

/// A digest that differs per test and per `salt`.
fn digest(n: u64, salt: u8) -> [u8; 32] {
    let mut bytes = [salt; 32];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    bytes
}

/// Redeem the CI token `(issuer, jti)` of test `n` for a fresh key.
async fn redeem(
    pool: &PgPool,
    n: u64,
    key_salt: u8,
    token_expires_at: DateTime<Utc>,
    token_leeway_seconds: u64,
) -> Redemption {
    let mut conn = pool.acquire().await.unwrap();
    workload_api_key_dao::insert(
        &mut conn,
        NewWorkloadApiKey {
            key_sha256: &digest(n, key_salt),
            realm_id: 1,
            role_id: 1,
            issuer_sha256: &digest(n, 1),
            config_sha256: &digest(n, 2),
            subject_sha256: &digest(n, 3),
            jti_sha256: &digest(n, 4),
            token_issued_at: token_expires_at - Duration::minutes(5),
            token_expires_at,
            token_leeway_seconds,
            ttl_seconds: 3600,
        },
    )
    .await
    .unwrap()
}

/// The database's clock (the instance's may differ).
async fn db_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT now()")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_token_is_redeemed_once() {
    let pool = pool().await;
    let n = unique();
    let exp = db_now(&pool).await + Duration::minutes(5);
    assert!(matches!(
        redeem(&pool, n, 10, exp, 60).await,
        Redemption::Issued(_)
    ));
    assert_eq!(redeem(&pool, n, 11, exp, 60).await, Redemption::Replayed);
}

#[tokio::test]
async fn a_token_past_its_leeway_on_the_database_clock_is_not_redeemed() {
    // An instance whose clock runs behind the database's still verifies the
    // token: the database decides, on the clock its records are reaped on.
    let pool = pool().await;
    let now = db_now(&pool).await;

    let n = unique();
    assert_eq!(
        redeem(&pool, n, 10, now - Duration::seconds(61), 60).await,
        Redemption::TokenExpired
    );
    let n = unique();
    assert!(matches!(
        redeem(&pool, n, 10, now - Duration::seconds(30), 60).await,
        Redemption::Issued(_)
    ));
    // The leeway is capped at the most any realm accepts.
    let n = unique();
    assert_eq!(
        redeem(
            &pool,
            n,
            10,
            now - Duration::seconds(MAX_TOKEN_LEEWAY_SECONDS as i64 + 1),
            u64::MAX,
        )
        .await,
        Redemption::TokenExpired
    );
}

#[tokio::test]
async fn a_record_outlives_its_token_by_the_leeway_and_a_margin() {
    let pool = pool().await;
    let n = unique();
    let exp = db_now(&pool).await + Duration::minutes(5);
    assert!(matches!(
        redeem(&pool, n, 10, exp, 60).await,
        Redemption::Issued(_)
    ));
    let key = digest(n, 10);
    let age = |token_expired_seconds_ago: i64| {
        sqlx::query(
            "UPDATE workload_api_key SET created_at = now() - interval '1 day', \
             expires_at = now() - interval '1 hour', \
             token_expires_at = now() - make_interval(secs => $2) \
             WHERE key_sha256 = $1",
        )
        .bind(key.as_slice())
        .bind(token_expired_seconds_ago as f64)
        .execute(&pool)
    };
    let present = || {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM workload_api_key WHERE key_sha256 = $1)",
        )
        .bind(key.as_slice())
        .fetch_one(&pool)
    };

    // Exactly at the most leeway, and a little past it: the token was
    // redeemable moments ago, so its record stays.
    let kept = (MAX_TOKEN_LEEWAY_SECONDS + REAP_MARGIN_SECONDS) as i64 - 60;
    for ago in [MAX_TOKEN_LEEWAY_SECONDS as i64, kept] {
        age(ago).await.unwrap();
        workload_api_key_dao::reap_expired(&pool).await.unwrap();
        assert!(
            present().await.unwrap(),
            "kept {ago} s after the token's exp"
        );
    }
    age((MAX_TOKEN_LEEWAY_SECONDS + REAP_MARGIN_SECONDS) as i64 + 1)
        .await
        .unwrap();
    workload_api_key_dao::reap_expired(&pool).await.unwrap();
    assert!(!present().await.unwrap(), "reaped past the margin");
}
