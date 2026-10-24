//! L1-only unit tests — no Redis required.
//!
//! Covers the spec's required behaviours:
//!   * factory invoked exactly once under 50 concurrent callers (coalescing),
//!   * TTL expiry forces a re-run,
//!   * distinct keys run distinct factories,
//!   * a factory `Err` is NOT cached (the next call retries).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use forge_cache::Cache;

// A trivially cloneable error so it satisfies the `E: Clone` bound.
#[derive(Clone, Debug, PartialEq)]
struct TestError(&'static str);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn factory_runs_once_under_concurrency() {
    let cache = Cache::l1_only(1000);
    let calls = Arc::new(AtomicUsize::new(0));

    // Launch 50 concurrent callers for the SAME (ns, key). moka's coalescing
    // must collapse them onto a single factory invocation.
    let mut handles = Vec::new();
    for _ in 0..50 {
        let cache = cache.clone();
        let calls = calls.clone();
        handles.push(tokio::spawn(async move {
            cache
                .get_or_try_insert_with::<u64, _, _, TestError>(
                    "ns",
                    "shared",
                    Duration::from_secs(60),
                    || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // Yield so concurrent callers really overlap on the load.
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(42u64)
                    },
                )
                .await
        }));
    }

    for h in handles {
        let v = h.await.unwrap().unwrap();
        assert_eq!(v, 42);
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "factory must run exactly once for 50 coalesced callers"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ttl_expiry_forces_rerun() {
    let cache = Cache::l1_only(1000);
    let calls = Arc::new(AtomicUsize::new(0));

    let run = || {
        let cache = cache.clone();
        let calls = calls.clone();
        async move {
            cache
                .get_or_try_insert_with::<u64, _, _, TestError>(
                    "ns",
                    "ttl",
                    Duration::from_secs(1),
                    || async move {
                        let n = calls.fetch_add(1, Ordering::SeqCst);
                        Ok(n as u64)
                    },
                )
                .await
                .unwrap()
        }
    };

    let first = run().await;
    assert_eq!(first, 0);
    // Within TTL → cached, no re-run.
    let cached = run().await;
    assert_eq!(cached, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Let the entry expire, then it must re-run the factory.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let after = run().await;
    assert_eq!(after, 1, "expired entry must trigger a fresh factory run");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distinct_keys_run_distinct_factories() {
    let cache = Cache::l1_only(1000);
    let calls = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..10u64 {
        let cache = cache.clone();
        let calls = calls.clone();
        handles.push(tokio::spawn(async move {
            let key = format!("k{i}");
            cache
                .get_or_try_insert_with::<u64, _, _, TestError>(
                    "ns",
                    &key,
                    Duration::from_secs(60),
                    || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(i)
                    },
                )
                .await
                .unwrap()
        }));
    }

    let mut got = Vec::new();
    for h in handles {
        got.push(h.await.unwrap());
    }
    got.sort_unstable();
    assert_eq!(got, (0..10).collect::<Vec<_>>());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        10,
        "each distinct key must run its own factory"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn factory_error_is_not_cached() {
    let cache = Cache::l1_only(1000);
    let calls = Arc::new(AtomicUsize::new(0));

    let run = |should_fail: bool| {
        let cache = cache.clone();
        let calls = calls.clone();
        async move {
            cache
                .get_or_try_insert_with::<u64, _, _, TestError>(
                    "ns",
                    "flaky",
                    Duration::from_secs(60),
                    || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        if should_fail {
                            Err(TestError("boom"))
                        } else {
                            Ok(7u64)
                        }
                    },
                )
                .await
        }
    };

    // First call fails — must NOT be cached.
    assert_eq!(run(true).await, Err(TestError("boom")));
    // Second call (now succeeding) must re-run the factory and cache.
    assert_eq!(run(false).await, Ok(7));
    // Third call is served from cache (no further factory run).
    assert_eq!(run(false).await, Ok(7));

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "factory should run on the failed call and the first successful call only"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidate_drops_entry() {
    let cache = Cache::l1_only(1000);
    let calls = Arc::new(AtomicUsize::new(0));

    let run = || {
        let cache = cache.clone();
        let calls = calls.clone();
        async move {
            cache
                .get_or_try_insert_with::<u64, _, _, TestError>(
                    "ns",
                    "x",
                    Duration::from_secs(60),
                    || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(1u64)
                    },
                )
                .await
                .unwrap()
        }
    };

    run().await;
    run().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    cache.invalidate("ns", "x").await;
    run().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "invalidate must force a re-run"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidate_ns_drops_all_keys_in_namespace() {
    let cache = Cache::l1_only(1000);
    let calls = Arc::new(AtomicUsize::new(0));

    let run = |key: &'static str| {
        let cache = cache.clone();
        let calls = calls.clone();
        async move {
            cache
                .get_or_try_insert_with::<u64, _, _, TestError>(
                    "ns",
                    key,
                    Duration::from_secs(60),
                    || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(1u64)
                    },
                )
                .await
                .unwrap()
        }
    };

    run("a").await;
    run("b").await;
    // Different namespace must survive the ns-invalidation below.
    let other_calls = Arc::new(AtomicUsize::new(0));
    {
        let cache = cache.clone();
        let other_calls = other_calls.clone();
        cache
            .get_or_try_insert_with::<u64, _, _, TestError>(
                "other",
                "a",
                Duration::from_secs(60),
                || async move {
                    other_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(1u64)
                },
            )
            .await
            .unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    cache.invalidate_ns("ns").await;
    run("a").await;
    run("b").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "both keys in the namespace must be re-run after invalidate_ns"
    );

    // The other namespace's entry must still be cached.
    {
        let cache = cache.clone();
        let other_calls = other_calls.clone();
        cache
            .get_or_try_insert_with::<u64, _, _, TestError>(
                "other",
                "a",
                Duration::from_secs(60),
                || async move {
                    other_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(1u64)
                },
            )
            .await
            .unwrap();
    }
    assert_eq!(
        other_calls.load(Ordering::SeqCst),
        1,
        "invalidate_ns must not touch other namespaces"
    );
}

/// A namespace invalidation does not wait for a fill already in flight (no
/// lock is held across a fill, so a slow factory or a stalled Redis cannot
/// freeze invalidations), and that fill's result, computed before the
/// invalidation, is not left in L1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn namespace_invalidation_does_not_wait_for_and_drops_an_inflight_fill() {
    let cache = Cache::l1_only(1000);
    let calls = Arc::new(AtomicUsize::new(0));
    let factory_started = Arc::new(tokio::sync::Notify::new());
    let release_factory = Arc::new(tokio::sync::Notify::new());

    let fill = {
        let cache = cache.clone();
        let calls = calls.clone();
        let factory_started = factory_started.clone();
        let release_factory = release_factory.clone();
        tokio::spawn(async move {
            cache
                .get_or_try_insert_with::<u64, _, _, TestError>(
                    "ns",
                    "racy",
                    Duration::from_secs(60),
                    || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        factory_started.notify_one();
                        release_factory.notified().await;
                        Ok(1)
                    },
                )
                .await
                .unwrap()
        })
    };
    factory_started.notified().await;

    tokio::time::timeout(Duration::from_secs(5), cache.invalidate_ns("ns"))
        .await
        .expect("the invalidation does not wait for the fill");

    release_factory.notify_one();
    // The fill's own caller started before the invalidation: it may use it.
    assert_eq!(fill.await.unwrap(), 1);

    let calls_after_race = calls.clone();
    let value = cache
        .get_or_try_insert_with::<u64, _, _, TestError>(
            "ns",
            "racy",
            Duration::from_secs(60),
            || async move {
                calls_after_race.fetch_add(1, Ordering::SeqCst);
                Ok(2)
            },
        )
        .await
        .unwrap();
    assert_eq!(value, 2);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the fill that raced the invalidation was not kept"
    );
}

/// A caller that arrives after an invalidation is coalesced onto the fill
/// already in flight for its key, which started before the invalidation. It
/// must not get that fill's value: it loads again with its own factory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_after_an_invalidation_never_gets_an_older_fill() {
    let cache = Cache::l1_only(1000);
    let factory_started = Arc::new(tokio::sync::Notify::new());
    let release_factory = Arc::new(tokio::sync::Notify::new());

    let early = {
        let cache = cache.clone();
        let factory_started = factory_started.clone();
        let release_factory = release_factory.clone();
        tokio::spawn(async move {
            cache
                .get_or_try_insert_local::<String, _, _, TestError>(
                    "authz",
                    "user:1",
                    Duration::from_secs(60),
                    || async move {
                        factory_started.notify_one();
                        release_factory.notified().await;
                        Ok("before-revocation".to_string())
                    },
                )
                .await
                .unwrap()
        })
    };
    factory_started.notified().await;
    cache.invalidate("authz", "user:1").await;

    let late_calls = Arc::new(AtomicUsize::new(0));
    let late = {
        let cache = cache.clone();
        let late_calls = late_calls.clone();
        tokio::spawn(async move {
            cache
                .get_or_try_insert_local::<String, _, _, TestError>(
                    "authz",
                    "user:1",
                    Duration::from_secs(60),
                    || async move {
                        late_calls.fetch_add(1, Ordering::SeqCst);
                        Ok("after-revocation".to_string())
                    },
                )
                .await
                .unwrap()
        })
    };
    // Let the late caller join the in-flight fill before it completes.
    tokio::time::sleep(Duration::from_millis(100)).await;
    release_factory.notify_one();

    assert_eq!(late.await.unwrap(), "after-revocation");
    assert_eq!(late_calls.load(Ordering::SeqCst), 1);
    let _ = early.await.unwrap();
    let cached = cache
        .get_or_try_insert_local::<String, _, _, TestError>(
            "authz",
            "user:1",
            Duration::from_secs(60),
            || async { Ok("refilled".to_string()) },
        )
        .await
        .unwrap();
    assert_eq!(cached, "after-revocation");
}

#[tokio::test]
async fn custom_tag_invalidation_expires_only_matching_entries() {
    let cache = Cache::l1_only(64);
    let tagged = vec!["user:alice".to_string()];
    let other = vec!["user:bob".to_string()];

    let _: String = cache
        .get_or_try_insert_with_tags(
            "credential",
            "alice-one",
            &tagged,
            Duration::from_secs(60),
            || async { Ok::<_, TestError>("OLD-ALICE-1".to_string()) },
        )
        .await
        .unwrap();
    let _: String = cache
        .get_or_try_insert_with_tags(
            "credential",
            "alice-two",
            &tagged,
            Duration::from_secs(60),
            || async { Ok::<_, TestError>("OLD-ALICE-2".to_string()) },
        )
        .await
        .unwrap();
    let _: String = cache
        .get_or_try_insert_with_tags(
            "credential",
            "bob",
            &other,
            Duration::from_secs(60),
            || async { Ok::<_, TestError>("OLD-BOB".to_string()) },
        )
        .await
        .unwrap();

    cache.invalidate_tag("credential", "user:alice").await;

    let alice_one: String = cache
        .get_or_try_insert_with_tags(
            "credential",
            "alice-one",
            &tagged,
            Duration::from_secs(60),
            || async { Ok::<_, TestError>("FRESH-ALICE-1".to_string()) },
        )
        .await
        .unwrap();
    let alice_two: String = cache
        .get_or_try_insert_with_tags(
            "credential",
            "alice-two",
            &tagged,
            Duration::from_secs(60),
            || async { Ok::<_, TestError>("FRESH-ALICE-2".to_string()) },
        )
        .await
        .unwrap();
    let bob: String = cache
        .get_or_try_insert_with_tags(
            "credential",
            "bob",
            &other,
            Duration::from_secs(60),
            || async { Ok::<_, TestError>("SHOULD-NOT-RUN".to_string()) },
        )
        .await
        .unwrap();

    assert_eq!(alice_one, "FRESH-ALICE-1");
    assert_eq!(alice_two, "FRESH-ALICE-2");
    assert_eq!(bob, "OLD-BOB");
}

#[tokio::test]
async fn a_factory_chosen_lifetime_shortens_the_ttl() {
    // A value copied from a record that expires in 1 s lives 1 s, not the
    // caller's 3 s; a longer factory lifetime never extends the TTL.
    let cache = Cache::l1_only(100);
    let calls = Arc::new(AtomicUsize::new(0));
    let load = |lifetime: Duration| {
        let (cache, calls) = (cache.clone(), calls.clone());
        async move {
            cache
                .get_or_try_insert_local_with_tags_expiring::<usize, _, _, TestError>(
                    "ns",
                    "expiring",
                    &[],
                    Duration::from_secs(3),
                    || async move { Ok((calls.fetch_add(1, Ordering::SeqCst) + 1, lifetime)) },
                )
                .await
                .unwrap()
        }
    };
    assert_eq!(load(Duration::from_secs(1)).await, 1);
    assert_eq!(load(Duration::from_secs(1)).await, 1, "still live");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(load(Duration::from_secs(60)).await, 2, "expired at 1 s");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(load(Duration::from_secs(60)).await, 2, "capped at the TTL");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(load(Duration::from_secs(60)).await, 3, "expired at 3 s");
}
