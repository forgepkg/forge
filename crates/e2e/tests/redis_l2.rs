//! E2E (optional): Redis L2 invalidation backplane. Two server instances share
//! a Redis L2; an `invalidate` on instance A drops the corresponding stale L1
//! entry on instance B via the pub/sub backplane (spec §9). Gated behind
//! `forge-e2e`; additionally boots a Redis container.

#![cfg(feature = "forge-e2e")]

use std::time::Duration;

use forge_e2e::StackBuilder;

const NS: &str = "package";

/// Populate an L1 entry on instance B, then invalidate the same key on instance
/// A. The backplane message must cause B to drop its (now stale) L1 entry, so
/// B's next read re-runs the factory.
#[tokio::test]
async fn invalidate_on_a_drops_stale_l1_on_b() {
    // Two instances sharing the same DB + S3 + Redis.
    let a = StackBuilder::default().with_redis().start().await;
    let b = a.spawn_peer().await;

    let cache_a = a.state.cache.clone();
    let cache_b = b.state.cache.clone();

    let key = format!("redis-test/{}", forge_e2e_unique());
    let ttl = Duration::from_secs(60);

    // Seed B's L1 (and the shared L2) with value 1.
    let v: i64 = cache_b
        .get_or_try_insert_with::<i64, _, _, std::convert::Infallible>(NS, &key, ttl, || async {
            Ok(1)
        })
        .await
        .unwrap();
    assert_eq!(v, 1, "B caches value 1");

    // Invalidate the key on A. This deletes L2 and publishes on the backplane;
    // B's subscriber must drop its L1 entry.
    cache_a.invalidate(NS, &key).await;

    // Allow the pub/sub message to propagate to B's subscriber.
    let mut dropped = false;
    for _ in 0..40 {
        // If B's L1 entry is gone, the factory runs again and yields 2.
        let v: i64 = cache_b
            .get_or_try_insert_with::<i64, _, _, std::convert::Infallible>(
                NS,
                &key,
                ttl,
                || async { Ok(2) },
            )
            .await
            .unwrap();
        if v == 2 {
            dropped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        dropped,
        "invalidate on A must drop B's stale L1 entry via the Redis backplane"
    );
}

/// A small process-unique counter so re-runs don't collide on the cache key.
fn forge_e2e_unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    C.fetch_add(1, Ordering::Relaxed)
}

/// Redis is a trust boundary: a value planted in Redis under an authorization
/// cache key (here: an admin effective set for an ordinary user, written via
/// the shared L2 API exactly as a Redis writer could) must never be used by
/// another instance. Authorization sets are cached in process only.
#[tokio::test]
async fn a_planted_redis_authz_entry_is_never_trusted() {
    use forge_core::auth::Principal;
    use forge_core::authz::cache::NS_AUTHZ;
    use forge_core::authz::RawEffectiveSet;
    use forge_db::user_dao::{self, NewUser};

    let a = StackBuilder::default().with_redis().start().await;
    let b = a.spawn_peer().await;
    let user = user_dao::insert_user(
        &a.pool,
        NewUser::local(
            format!("plain{}", forge_e2e_unique()),
            "x".into(),
            false,
            true,
        ),
    )
    .await
    .unwrap();

    // Plant an admin set for the user in the shared L2.
    let forged: RawEffectiveSet = a
        .state
        .cache
        .get_or_try_insert_with::<RawEffectiveSet, _, _, std::convert::Infallible>(
            NS_AUTHZ,
            &format!("user:{}", user.id),
            Duration::from_secs(60),
            || async {
                Ok(RawEffectiveSet {
                    is_admin: true,
                    grants: Vec::new(),
                })
            },
        )
        .await
        .unwrap();
    assert!(forged.is_admin);

    let principal = Principal::User {
        user_id: user.id,
        token_id: None,
        is_admin: false,
    };
    assert!(
        !b.state.authz.is_global_admin(&principal).await,
        "an authz set read from Redis would make an ordinary user admin"
    );
}
