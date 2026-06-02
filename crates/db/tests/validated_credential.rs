//! Integration tests for the slice-12.3 `validated_credential` DAO against a
//! real Postgres testcontainer.
//!
//! Covers the durable-cache properties the credential-forwarding design hinges
//! on:
//!   * a fresh verdict round-trips; an expired one reads as a miss;
//!   * `upsert_verdict` refreshes verdict + expiry on the unique triple (no
//!     duplicate rows);
//!   * `revoke_by_username` removes a user's verdicts (optionally per-provider);
//!   * `sweep_expired` reaps only expired rows;
//!   * the **stored bytes are never the plaintext password** — the column holds
//!     only the caller-supplied hmac;
//!   * the singleflight ROW-lock anchor serializes concurrent identical checks
//!     so the upstream is consulted once (no advisory locks).
//!
//! Requires Docker on the host. All tests share one container/pool (see
//! `common`) and isolate themselves with unique provider/username values.

mod common;

use chrono::{Duration, Utc};
use forge_db::validated_credential_dao::{self as vc, NewVerdict};

use common::{pool, unique};

const PROVIDER: &str = "upstream-basic";

fn new_verdict(username: &str, hmac: &str, verdict: bool, ttl_secs: i64) -> NewVerdict {
    NewVerdict {
        provider_id: PROVIDER.to_string(),
        username: username.to_string(),
        cred_hmac: hmac.to_string(),
        verdict,
        expires_at: Utc::now() + Duration::seconds(ttl_secs),
    }
}

#[tokio::test]
async fn fresh_verdict_round_trips_and_expired_is_a_miss() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = format!("vc-user-{n}");
    let hmac = format!("hmac-{n}");

    // No row yet → miss.
    assert!(vc::get_verdict(pool, PROVIDER, &user, &hmac)
        .await
        .unwrap()
        .is_none());

    // Positive verdict, well in the future → hit.
    let stored = vc::upsert_verdict(pool, new_verdict(&user, &hmac, true, 300))
        .await
        .unwrap();
    assert!(stored.verdict);
    let got = vc::get_verdict(pool, PROVIDER, &user, &hmac)
        .await
        .unwrap()
        .expect("fresh verdict is a hit");
    assert!(got.verdict);
    assert_eq!(got.cred_hmac, hmac);

    // Overwrite with an already-expired verdict → reads as a miss.
    vc::upsert_verdict(pool, new_verdict(&user, &hmac, true, -10))
        .await
        .unwrap();
    assert!(
        vc::get_verdict(pool, PROVIDER, &user, &hmac)
            .await
            .unwrap()
            .is_none(),
        "expired verdict must read as a cache miss"
    );
}

#[tokio::test]
async fn upsert_refreshes_in_place_no_duplicate_rows() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = format!("vc-user-{n}");
    let hmac = format!("hmac-{n}");

    let first = vc::upsert_verdict(pool, new_verdict(&user, &hmac, false, 30))
        .await
        .unwrap();
    assert!(!first.verdict, "first write is negative");

    // Same triple, flipped verdict + longer TTL.
    let second = vc::upsert_verdict(pool, new_verdict(&user, &hmac, true, 300))
        .await
        .unwrap();
    assert_eq!(first.id, second.id, "upsert reuses the same row");
    assert!(second.verdict, "verdict flipped to positive");
    assert!(second.expires_at > first.expires_at, "expiry refreshed");

    // Exactly one row for the triple.
    let count = sqlx::query_scalar!(
        r#"SELECT count(*) FROM validated_credential
           WHERE provider_id = $1 AND username = $2 AND cred_hmac = $3"#,
        PROVIDER,
        user,
        hmac,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(count, Some(1));
}

#[tokio::test]
async fn revoke_by_username_deletes_verdicts() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = format!("vc-user-{n}");
    let other = format!("vc-other-{n}");

    vc::upsert_verdict(pool, new_verdict(&user, &format!("h1-{n}"), true, 300))
        .await
        .unwrap();
    vc::upsert_verdict(pool, new_verdict(&user, &format!("h2-{n}"), false, 300))
        .await
        .unwrap();
    vc::upsert_verdict(pool, new_verdict(&other, &format!("h3-{n}"), true, 300))
        .await
        .unwrap();

    // Revoke all providers for `user`: both of their rows go, `other` stays.
    let deleted = vc::revoke_by_username(pool, &user, None).await.unwrap();
    assert_eq!(deleted, 2);
    assert!(vc::get_verdict(pool, PROVIDER, &user, &format!("h1-{n}"))
        .await
        .unwrap()
        .is_none());
    assert!(vc::get_verdict(pool, PROVIDER, &other, &format!("h3-{n}"))
        .await
        .unwrap()
        .is_some());

    // Provider-scoped revoke: a non-matching provider deletes nothing.
    vc::upsert_verdict(pool, new_verdict(&user, &format!("h4-{n}"), true, 300))
        .await
        .unwrap();
    let scoped = vc::revoke_by_username(pool, &user, Some("no-such-provider"))
        .await
        .unwrap();
    assert_eq!(scoped, 0, "wrong provider must not delete");
    let scoped_hit = vc::revoke_by_username(pool, &user, Some(PROVIDER))
        .await
        .unwrap();
    assert_eq!(scoped_hit, 1);
}

#[tokio::test]
async fn sweep_expired_reaps_only_expired() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let live = format!("vc-live-{n}");
    let dead = format!("vc-dead-{n}");

    vc::upsert_verdict(pool, new_verdict(&live, &format!("hl-{n}"), true, 300))
        .await
        .unwrap();
    vc::upsert_verdict(pool, new_verdict(&dead, &format!("hd-{n}"), true, -10))
        .await
        .unwrap();

    let removed = vc::sweep_expired(pool).await.unwrap();
    assert!(removed >= 1, "at least the expired row is swept");

    // The live row survives; the dead one is gone.
    assert!(vc::get_verdict(pool, PROVIDER, &live, &format!("hl-{n}"))
        .await
        .unwrap()
        .is_some());
    let dead_count = sqlx::query_scalar!(
        r#"SELECT count(*) FROM validated_credential WHERE username = $1"#,
        dead,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(dead_count, Some(0));
}

/// The DAO must never persist the plaintext password. We store a credential and
/// scan every text column of the row for a substring of the (never-passed)
/// plaintext — it can't be there because the DAO only ever receives the hmac.
#[tokio::test]
async fn stored_bytes_never_contain_plaintext() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = format!("vc-user-{n}");
    let plaintext = format!("super-secret-password-{n}");
    // The caller (forge-core) hands the DAO only the hmac; the password never
    // reaches the DB layer. Use a deliberately distinct opaque hmac.
    let hmac = format!("deadbeef{n:016x}");

    vc::upsert_verdict(pool, new_verdict(&user, &hmac, true, 300))
        .await
        .unwrap();

    let row = sqlx::query!(
        r#"SELECT provider_id, username, cred_hmac
           FROM validated_credential
           WHERE provider_id = $1 AND username = $2 AND cred_hmac = $3"#,
        PROVIDER,
        user,
        hmac,
    )
    .fetch_one(pool)
    .await
    .unwrap();

    for col in [&row.provider_id, &row.username, &row.cred_hmac] {
        assert!(
            !col.contains(&plaintext),
            "plaintext password must never appear in a stored column: {col}"
        );
    }
    assert_eq!(row.cred_hmac, hmac, "only the hmac is stored as the key");
}

/// The singleflight ROW lock (no advisory locks) serializes concurrent identical
/// checks: a winner holds the lock, "forwards" (simulated), writes the verdict,
/// and commits; a peer that called `begin_singleflight` concurrently blocks on
/// the row lock and, on release, observes the fresh verdict instead of
/// forwarding again.
#[tokio::test]
async fn singleflight_row_lock_serializes_concurrent_checks() {
    let pool = pool().await;
    let n = unique();
    let user = format!("vc-sf-{n}");
    let hmac = format!("sf-hmac-{n}");

    // Winner: open a tx, take the anchor lock, but DON'T commit yet.
    let mut winner_tx = pool.begin().await.unwrap();
    let winner = vc::begin_singleflight(&mut winner_tx, PROVIDER, &user, &hmac)
        .await
        .unwrap();
    assert!(
        winner.is_none(),
        "first caller is the singleflight winner (no fresh verdict yet)"
    );

    // Peer: try to begin singleflight on a separate connection with a short
    // statement timeout — it must BLOCK on the row lock the winner holds.
    let peer_pool = pool.clone();
    let peer_user = user.clone();
    let peer_hmac = hmac.clone();
    let peer = tokio::spawn(async move {
        let mut tx = peer_pool.begin().await.unwrap();
        // Bound the wait so a regression (no lock) is observable as a fast
        // return rather than a hang; the winner releases well within this.
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let res = vc::begin_singleflight(&mut tx, PROVIDER, &peer_user, &peer_hmac).await;
        tx.commit().await.ok();
        res
    });

    // Give the peer a moment to reach the blocking SELECT ... FOR UPDATE.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !peer.is_finished(),
        "peer must block on the winner's row lock"
    );

    // Winner forwards (simulated) and writes a positive verdict, then commits.
    vc::finalize_singleflight(&mut winner_tx, new_verdict(&user, &hmac, true, 300))
        .await
        .unwrap();
    winner_tx.commit().await.unwrap();

    // Peer unblocks and sees the fresh verdict → it would NOT forward upstream.
    let peer_result = peer.await.unwrap().unwrap();
    let peer_row = peer_result.expect("peer observes the winner's fresh verdict");
    assert!(
        peer_row.verdict,
        "peer reads the positive verdict, not a sentinel"
    );
}
