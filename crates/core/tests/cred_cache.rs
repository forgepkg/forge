//! Integration tests for the slice-12.3 validated-credential cache against a
//! real Postgres testcontainer.
//!
//! These exercise the security-critical behaviors from the plan (§2.5, Phase 3):
//!   * a positive verdict is cached so a second identical check does **not**
//!     re-run the upstream forward (the whole point — NuGet's per-request Basic);
//!   * a negative verdict is cached too (bounded brute-force amplification);
//!   * `Unavailable` (fail-closed) is **never** cached — the next check
//!     re-forwards;
//!   * TTL expiry forces a re-forward;
//!   * `revoke_user` deletes the authoritative rows so the next check re-forwards;
//!   * the stored `validated_credential` rows never contain the plaintext
//!     password — only the HMAC.
//!
//! Each test drives the cache with an **L1-only** [`forge_cache::Cache`] (so the
//! Postgres factory is reached deterministically) and a counting `forward`
//! closure that records how many times the upstream would have been hit.
//!
//! Requires Docker on the host.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use forge_cache::Cache;
use forge_core::auth::{
    revoke_credentials_for_user, CredCacheError, CredKeyPepper, UpstreamVerdict,
    ValidatedCredentialCache,
};

use common::{pool, unique};

const PROVIDER: &str = "upstream-basic";

fn pepper() -> CredKeyPepper {
    CredKeyPepper::new(b"integration-test-pepper".to_vec())
}

/// Build a cache with the given TTLs over the shared Postgres pool + a fresh
/// L1-only cache (no cross-test L1 sharing).
async fn make_cache(positive_ttl: Duration, negative_ttl: Duration) -> ValidatedCredentialCache {
    let pool = pool().await;
    ValidatedCredentialCache::new(
        Cache::l1_only(256),
        pool,
        pepper(),
        positive_ttl,
        negative_ttl,
    )
}

/// A counter wrapped so the `FnOnce` factory can bump it and return a verdict.
fn counting_forward(
    counter: Arc<AtomicU32>,
    verdict: UpstreamVerdict,
) -> impl FnOnce() -> std::future::Ready<UpstreamVerdict> {
    move || {
        counter.fetch_add(1, Ordering::SeqCst);
        std::future::ready(verdict)
    }
}

#[tokio::test]
async fn positive_hit_avoids_second_forward() {
    let cache = make_cache(Duration::from_secs(300), Duration::from_secs(30)).await;
    let user = format!("hit-user-{}", unique());
    let pw = "good-password";
    let hits = Arc::new(AtomicU32::new(0));

    // First check: miss → forwards once → valid.
    let r1 = cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert!(r1, "valid credential authenticates");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Second identical check: cache hit → forward NOT invoked.
    let r2 = cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert!(r2);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "second identical check must be served from cache (no re-forward)"
    );
}

#[tokio::test]
async fn negative_verdict_is_cached() {
    let cache = make_cache(Duration::from_secs(300), Duration::from_secs(300)).await;
    let user = format!("neg-user-{}", unique());
    let pw = "wrong-password";
    let hits = Arc::new(AtomicU32::new(0));

    let r1 = cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Rejected),
        )
        .await
        .unwrap();
    assert!(!r1, "rejected credential does not authenticate");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Negative is cached: second check does not re-forward.
    let r2 = cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Rejected),
        )
        .await
        .unwrap();
    assert!(!r2);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "negative verdict must be cached (throttles brute-force amplification)"
    );
}

#[tokio::test]
async fn unavailable_is_fail_closed_and_never_cached() {
    let cache = make_cache(Duration::from_secs(300), Duration::from_secs(30)).await;
    let user = format!("down-user-{}", unique());
    let pw = "any-password";
    let hits = Arc::new(AtomicU32::new(0));

    // Upstream down on a miss → fail-closed error, nothing cached.
    let err = cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Unavailable),
        )
        .await
        .unwrap_err();
    assert_eq!(err, CredCacheError::Unavailable);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Nothing was persisted → the next check re-forwards (does not serve a stale
    // grant or a stale deny).
    let r2 = cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert!(r2);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "an Unavailable must never be cached; the next attempt re-forwards"
    );
}

#[tokio::test]
async fn ttl_expiry_forces_recheck() {
    // Tiny positive TTL so the authoritative row expires almost immediately.
    let cache = make_cache(Duration::from_millis(50), Duration::from_secs(30)).await;
    let user = format!("ttl-user-{}", unique());
    let pw = "good-password";
    let hits = Arc::new(AtomicU32::new(0));

    let r1 = cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert!(r1);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Wait past the TTL: both the L1 entry and the Postgres row expire.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let r2 = cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert!(r2);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "after TTL expiry the credential must be re-validated upstream"
    );
}

#[tokio::test]
async fn revoke_user_forces_recheck() {
    let cache = make_cache(Duration::from_secs(300), Duration::from_secs(30)).await;
    let user = format!("revoke-user-{}", unique());
    let pw = "good-password";
    let hits = Arc::new(AtomicU32::new(0));

    cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Admin "force re-auth": delete the verdict + invalidate the cache layer.
    let deleted = cache.revoke_user(&user, Some(PROVIDER)).await.unwrap();
    assert_eq!(deleted, 1);

    // Next check re-forwards (the cached positive is gone).
    cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "after revocation the credential must be re-validated upstream"
    );
}

#[tokio::test]
async fn revoke_user_all_providers() {
    let cache = make_cache(Duration::from_secs(300), Duration::from_secs(30)).await;
    let user = format!("revoke-all-{}", unique());
    let pw = "good-password";
    let hits = Arc::new(AtomicU32::new(0));

    cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();

    // Revoke across all providers (None) also drops it.
    let deleted = cache.revoke_user(&user, None).await.unwrap();
    assert_eq!(deleted, 1);

    cache
        .check(
            PROVIDER,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn standalone_revoke_invalidates_realm_scoped_provider() {
    let pool = pool().await;
    let hot_cache = Cache::l1_only(256);
    let cache = ValidatedCredentialCache::new(
        hot_cache.clone(),
        pool.clone(),
        pepper(),
        Duration::from_secs(300),
        Duration::from_secs(30),
    );
    let user = format!("realm-revoke-{}", unique());
    let provider = format!("realm:corporate-{}", unique());
    let pw = "good-password";
    let hits = Arc::new(AtomicU32::new(0));

    cache
        .check(
            &provider,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let deleted = revoke_credentials_for_user(&hot_cache, &pool, &user)
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    cache
        .check(
            &provider,
            &user,
            pw,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "standalone reauth must invalidate dynamically named realm providers"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_fences_an_inflight_forward_before_deleting_its_verdict() {
    let cache = make_cache(Duration::from_secs(300), Duration::from_secs(30)).await;
    let user = format!("revoke-race-{}", unique());
    let password = "still-valid-upstream";
    let forward_started = Arc::new(tokio::sync::Notify::new());
    let release_forward = Arc::new(tokio::sync::Notify::new());

    let fill = {
        let cache = cache.clone();
        let user = user.clone();
        let forward_started = forward_started.clone();
        let release_forward = release_forward.clone();
        tokio::spawn(async move {
            cache
                .check(PROVIDER, &user, password, || async move {
                    forward_started.notify_one();
                    release_forward.notified().await;
                    UpstreamVerdict::Valid
                })
                .await
                .unwrap()
        })
    };
    forward_started.notified().await;

    let revoke = {
        let cache = cache.clone();
        let user = user.clone();
        tokio::spawn(async move { cache.revoke_user(&user, Some(PROVIDER)).await.unwrap() })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !revoke.is_finished(),
        "revocation must wait on the durable user-tag lock held by the fill"
    );

    release_forward.notify_one();
    assert!(fill.await.unwrap());
    assert_eq!(
        revoke.await.unwrap(),
        1,
        "revocation deletes the verdict committed by the older fill"
    );

    let forwards_after_revoke = Arc::new(AtomicU32::new(0));
    let valid = cache
        .check(
            PROVIDER,
            &user,
            password,
            counting_forward(forwards_after_revoke.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    assert!(valid);
    assert_eq!(
        forwards_after_revoke.load(Ordering::SeqCst),
        1,
        "the first request after revocation must forward upstream again"
    );
}

/// A definitive ACCEPT records a `(username, auth method)` row in the
/// `auth_success` cutoff log; a REJECT records nothing there, and once its
/// short-lived negative verdict is swept the sprayed username's fence row is
/// reaped too — an unauthenticated attacker leaves no durable rows behind.
#[tokio::test]
async fn only_successful_auth_is_recorded_and_spray_leaves_no_durable_rows() {
    let p = pool().await;
    let cache = ValidatedCredentialCache::new(
        Cache::l1_only(64),
        p.clone(),
        pepper(),
        Duration::from_secs(300),
        // Negative TTL of zero: the sprayed attempt's verdict expires
        // immediately, as after a real negative window lapses.
        Duration::from_secs(0),
    );
    let n = unique();
    let good_user = format!("success-log-{n}");
    let sprayed_user = format!("sprayed-{n}");

    cache
        .check(PROVIDER, &good_user, "good-password", || async {
            UpstreamVerdict::Valid
        })
        .await
        .unwrap();
    let recorded = forge_db::validated_credential_dao::list_auth_successes(&p, &good_user)
        .await
        .unwrap();
    assert_eq!(recorded.len(), 1, "a successful validation is recorded");
    assert_eq!(recorded[0].auth_method, PROVIDER);

    let rejected = cache
        .check(PROVIDER, &sprayed_user, "wrong-password", || async {
            UpstreamVerdict::Rejected
        })
        .await
        .unwrap();
    assert!(!rejected);
    assert!(
        forge_db::validated_credential_dao::list_auth_successes(&p, &sprayed_user)
            .await
            .unwrap()
            .is_empty(),
        "a rejected attempt must never be recorded as an auth success"
    );

    // The reaper pass: expired verdicts first, then orphaned fence rows.
    forge_db::validated_credential_dao::sweep_expired(&p)
        .await
        .unwrap();
    forge_db::validated_credential_dao::sweep_orphaned_tags(&p)
        .await
        .unwrap();

    let sprayed_tag_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM validated_credential_tag WHERE username = $1")
            .bind(&sprayed_user)
            .fetch_one(&p)
            .await
            .unwrap();
    assert_eq!(
        sprayed_tag_rows, 0,
        "after the sweep a sprayed username leaves no fence row behind"
    );

    let good_tag_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM validated_credential_tag WHERE username = $1")
            .bind(&good_user)
            .fetch_one(&p)
            .await
            .unwrap();
    assert_eq!(
        good_tag_rows, 1,
        "a user with a live positive verdict keeps their fence row"
    );
}

/// After caching a credential, dump every text column of `validated_credential`
/// and assert the plaintext password is nowhere to be found — only the HMAC key.
#[tokio::test]
async fn stored_rows_never_contain_plaintext() {
    let p = pool().await;
    let cache = ValidatedCredentialCache::new(
        Cache::l1_only(64),
        p.clone(),
        pepper(),
        Duration::from_secs(300),
        Duration::from_secs(300),
    );
    let n = unique();
    let user = format!("plain-user-{n}");
    let plaintext = format!("plaintext-password-{n}");
    let hits = Arc::new(AtomicU32::new(0));

    // One positive and one negative, both with a distinctive plaintext.
    cache
        .check(
            PROVIDER,
            &user,
            &plaintext,
            counting_forward(hits.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap();
    let bad = format!("{plaintext}-bad");
    cache
        .check(
            PROVIDER,
            &user,
            &bad,
            counting_forward(hits.clone(), UpstreamVerdict::Rejected),
        )
        .await
        .unwrap();

    let rows = sqlx::query!(
        r#"SELECT provider_id, username, cred_hmac FROM validated_credential WHERE username = $1"#,
        user,
    )
    .fetch_all(&p)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2, "one positive + one negative row");

    for row in &rows {
        for col in [&row.provider_id, &row.username, &row.cred_hmac] {
            assert!(
                !col.contains(&plaintext),
                "plaintext password must never appear in a stored column: {col}"
            );
        }
        // The key is the 64-hex HMAC, not anything resembling the password.
        assert_eq!(row.cred_hmac.len(), 64);
        assert!(row.cred_hmac.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
