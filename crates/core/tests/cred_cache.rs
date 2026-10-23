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
//!   * a revocation landing mid-forward fences that forward's verdict;
//!   * the stored `validated_credential` rows never contain the plaintext
//!     password — only the HMAC;
//!   * a slow upstream holds **no** pooled connection (review H1): many slow
//!     forwards on a 2-connection pool leave room for unrelated queries;
//!   * identical misses on two instances forward once (lease singleflight), a
//!     lapsed lease is taken over, and the per-provider forward limit fails
//!     excess misses closed.
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
    cred_key, revoke_credentials_for_user, CredCacheError, CredKeyPepper, UpstreamVerdict,
    ValidatedCredentialCache,
};
use forge_db::validated_credential_dao::{self as vc_dao, Claim};

use common::{pool, small_pool, unique};

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
async fn a_rejection_lives_only_for_the_negative_ttl() {
    // #17: an upstream 401 (say, its own short lockout) must not keep a
    // correct password rejected for the much longer positive TTL.
    let cache = make_cache(Duration::from_secs(300), Duration::from_millis(200)).await;
    let user = format!("neg-ttl-{}", unique());
    let hits = Arc::new(AtomicU32::new(0));
    for expected_forwards in [1, 2] {
        let ok = cache
            .check(
                PROVIDER,
                &user,
                "pw",
                counting_forward(hits.clone(), UpstreamVerdict::Rejected),
            )
            .await
            .unwrap();
        assert!(!ok);
        assert_eq!(hits.load(Ordering::SeqCst), expected_forwards);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

#[tokio::test]
async fn a_peers_verdict_is_cached_only_for_what_its_row_has_left() {
    // #17: instance B reads instance A's verdict while its row is still
    // valid. B must not then keep accepting the credential in memory for a
    // whole positive TTL of its own: past the row's expiry it re-validates.
    let pool = pool().await;
    let instance = |positive_ttl| {
        ValidatedCredentialCache::new(
            Cache::l1_only(256),
            pool.clone(),
            pepper(),
            positive_ttl,
            Duration::from_secs(30),
        )
    };
    // A's row lives 2 s: B reads it 400 ms in, with room to spare on a
    // loaded machine (#347), and again 2.2 s in, past its expiry.
    let a = instance(Duration::from_secs(2));
    let b = instance(Duration::from_secs(300));
    let user = format!("peer-ttl-{}", unique());
    let forwards = Arc::new(AtomicU32::new(0));

    let forward = || counting_forward(forwards.clone(), UpstreamVerdict::Valid);
    assert_eq!(a.check(PROVIDER, &user, "pw", forward()).await, Ok(true));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(b.check(PROVIDER, &user, "pw", forward()).await, Ok(true));
    assert_eq!(forwards.load(Ordering::SeqCst), 1, "B read A's verdict");

    tokio::time::sleep(Duration::from_millis(1800)).await;
    assert_eq!(b.check(PROVIDER, &user, "pw", forward()).await, Ok(true));
    assert_eq!(
        forwards.load(Ordering::SeqCst),
        2,
        "past the row's expiry B forwards again"
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

/// A revocation that lands while a forward is in flight neither waits for it
/// at the database (no lock is held across the forward) nor lets its
/// now-stale answer through: the claim row is deleted with the verdicts, the
/// fill's conditional verdict write finds nothing to update, and that request
/// fails closed. The next request re-forwards.
///
/// (Before the lease redesign the fill held a share lock across the forward
/// and the revocation queued behind it — the very connection-pinning H1 is
/// about.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_during_an_inflight_forward_fences_its_verdict() {
    let pool = pool().await;
    let cache = ValidatedCredentialCache::new(
        Cache::l1_only(256),
        pool.clone(),
        pepper(),
        Duration::from_secs(300),
        Duration::from_secs(30),
    );
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
        })
    };
    forward_started.notified().await;

    // The admin revocation (issued on another instance: its own cache layer)
    // completes promptly — nothing it needs is held by the in-flight fill.
    let deleted = tokio::time::timeout(
        Duration::from_secs(5),
        revoke_credentials_for_user(&Cache::l1_only(16), &pool, &user),
    )
    .await
    .expect("revocation must not wait on the in-flight forward")
    .unwrap();
    assert_eq!(deleted, 1, "the in-flight claim row is revoked");

    release_forward.notify_one();
    assert_eq!(
        fill.await.unwrap(),
        Err(CredCacheError::Unavailable),
        "a verdict obtained across a revocation is discarded (fail closed)"
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM validated_credential WHERE username = $1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 0, "the fenced fill wrote no verdict");

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

/// Review H1: a slow upstream must not pin pooled connections. Five
/// concurrent slow forwards for different users run against a pool of only
/// two connections, and an unrelated query still gets a connection while all
/// five are in flight. (Under the old design each forward held a transaction,
/// so only two could even start and the pool was exhausted.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_forwards_do_not_hold_db_connections() {
    let pool = small_pool(2, Duration::from_secs(3)).await;
    let cache = ValidatedCredentialCache::new(
        Cache::l1_only(256),
        pool.clone(),
        pepper(),
        Duration::from_secs(300),
        Duration::from_secs(30),
    );
    let n = unique();
    let started = Arc::new(AtomicU32::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));

    let mut fills = Vec::new();
    for i in 0..5 {
        let cache = cache.clone();
        let user = format!("slow-upstream-{n}-{i}");
        let started = started.clone();
        let release = release.clone();
        fills.push(tokio::spawn(async move {
            cache
                .check(PROVIDER, &user, "pw", || async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    // A stalled upstream: blocks until the test releases it.
                    release.acquire().await.expect("gate open").forget();
                    UpstreamVerdict::Valid
                })
                .await
        }));
    }

    // Every one of the five forwards gets going at once ...
    let all_started = tokio::time::timeout(Duration::from_secs(10), async {
        while started.load(Ordering::SeqCst) < 5 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        all_started.is_ok(),
        "all five slow forwards must start on a 2-connection pool (started {})",
        started.load(Ordering::SeqCst)
    );

    // ... and while they are all stalled, the pool still serves other work.
    let one: i32 = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query_scalar("SELECT 1").fetch_one(&pool),
    )
    .await
    .expect("an unrelated query must not wait behind stalled forwards")
    .expect("an unrelated query gets a pooled connection");
    assert_eq!(one, 1);

    release.add_permits(5);
    for fill in fills {
        assert_eq!(fill.await.unwrap(), Ok(true));
    }
}

/// Cross-instance singleflight: two instances (separate L1 caches, one
/// Postgres) missing on the same credential at the same time forward once.
/// The loser polls the winner's row instead of forwarding, and gets its
/// verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_misses_on_two_instances_forward_once() {
    let pool = pool().await;
    let instance = || {
        ValidatedCredentialCache::new(
            Cache::l1_only(256),
            pool.clone(),
            pepper(),
            Duration::from_secs(300),
            Duration::from_secs(30),
        )
    };
    let (a, b) = (instance(), instance());
    let user = format!("sf-cross-{}", unique());
    let forwards = Arc::new(AtomicU32::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());

    let winner = {
        let user = user.clone();
        let (forwards, started, release) = (forwards.clone(), started.clone(), release.clone());
        tokio::spawn(async move {
            a.check(PROVIDER, &user, "pw", || async move {
                forwards.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                release.notified().await;
                UpstreamVerdict::Valid
            })
            .await
        })
    };
    started.notified().await;

    let loser = {
        let user = user.clone();
        let forwards = forwards.clone();
        tokio::spawn(async move {
            b.check(
                PROVIDER,
                &user,
                "pw",
                counting_forward(forwards, UpstreamVerdict::Valid),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !loser.is_finished(),
        "the second instance waits for the in-flight forward"
    );

    release.notify_one();
    assert_eq!(winner.await.unwrap(), Ok(true));
    assert_eq!(
        loser.await.unwrap(),
        Ok(true),
        "the loser reads the winner's verdict"
    );
    assert_eq!(
        forwards.load(Ordering::SeqCst),
        1,
        "identical misses across instances forward exactly once"
    );
}

/// A winner that vanished mid-forward (crash, cancelled request) leaves a
/// claim behind; peers wait for its lease to lapse, then take over instead of
/// failing forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lapsed_lease_is_taken_over() {
    let pool = pool().await;
    let cache = ValidatedCredentialCache::new(
        Cache::l1_only(256),
        pool.clone(),
        pepper(),
        Duration::from_secs(300),
        Duration::from_secs(30),
    );
    let user = format!("sf-lapsed-{}", unique());
    let hmac = cred_key(&pepper(), PROVIDER, &user, "pw");

    // A "crashed" peer's claim with a short lease that is never finalized.
    let claim = vc_dao::claim_singleflight(&pool, PROVIDER, &user, &hmac, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(matches!(claim, Claim::Won { .. }));

    let forwards = Arc::new(AtomicU32::new(0));
    let valid = tokio::time::timeout(
        Duration::from_secs(10),
        cache.check(
            PROVIDER,
            &user,
            "pw",
            counting_forward(forwards.clone(), UpstreamVerdict::Valid),
        ),
    )
    .await
    .expect("the lapsed lease is taken over well before the loser's deadline")
    .unwrap();
    assert!(valid);
    assert_eq!(
        forwards.load(Ordering::SeqCst),
        1,
        "the taker-over forwards"
    );
}

/// The per-provider forward limit: with one permit, a second concurrent miss
/// (another user) fails closed at once — it neither forwards nor writes a
/// row — while the first completes normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_limit_fails_excess_misses_closed() {
    let pool = pool().await;
    let cache = ValidatedCredentialCache::new(
        Cache::l1_only(256),
        pool.clone(),
        pepper(),
        Duration::from_secs(300),
        Duration::from_secs(30),
    )
    .with_forward_limit(Arc::new(tokio::sync::Semaphore::new(1)));
    let n = unique();
    let (first, second) = (format!("limit-a-{n}"), format!("limit-b-{n}"));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());

    let busy = {
        let cache = cache.clone();
        let first = first.clone();
        let (started, release) = (started.clone(), release.clone());
        tokio::spawn(async move {
            cache
                .check(PROVIDER, &first, "pw", || async move {
                    started.notify_one();
                    release.notified().await;
                    UpstreamVerdict::Valid
                })
                .await
        })
    };
    started.notified().await;

    let excess_forwards = Arc::new(AtomicU32::new(0));
    let err = cache
        .check(
            PROVIDER,
            &second,
            "pw",
            counting_forward(excess_forwards.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap_err();
    assert_eq!(err, CredCacheError::Unavailable, "excess miss fails closed");
    assert_eq!(
        excess_forwards.load(Ordering::SeqCst),
        0,
        "and never forwards"
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM validated_credential WHERE username = $1")
            .bind(&second)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 0, "a refused miss writes nothing");

    release.notify_one();
    assert_eq!(busy.await.unwrap(), Ok(true));

    // With the permit back, the refused user validates normally.
    assert!(cache
        .check(
            PROVIDER,
            &second,
            "pw",
            counting_forward(excess_forwards.clone(), UpstreamVerdict::Valid),
        )
        .await
        .unwrap());
    assert_eq!(excess_forwards.load(Ordering::SeqCst), 1);
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
