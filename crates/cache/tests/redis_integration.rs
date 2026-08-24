//! Redis L2 + backplane integration test (gated on a Docker/Redis container).
//!
//! Shares one `redis:7` testcontainer across the binary (tests use disjoint
//! namespaces) and exercises the spec's cross-instance requirements:
//!   * miss → factory → BOTH layers (L1 + L2) populated,
//!   * a second independent `Cache` sharing the same Redis sees an L2 hit
//!     WITHOUT running its own factory,
//!   * `invalidate` on instance A drives instance B to drop its L1 entry, via
//!     the pub/sub backplane (polled until processed, with a timeout).
//!
//! Docker was available in the authoring environment, so this test is NOT
//! `#[ignore]`d. It does require Docker at run time; if Docker is absent the
//! container start panics with a clear message (the unit tests in `l1_unit.rs`
//! cover all non-Redis behaviour and run without Docker).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use forge_cache::Cache;
use redis::AsyncCommands;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::GenericImage;
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
struct TestError(&'static str);

const REDIS_PORT: u16 = 6379;

// `redis://host:port` of the shared container, computed once per test binary.
static REDIS_URL: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());

/// The shared `redis:7` container's `redis://host:port` URL (mirroring the
/// Postgres harness in `forge-db`): one container per test binary — every test
/// starting its own container meant as many concurrent image pulls as tests,
/// which flaked in CI — started once behind a lock and intentionally leaked so
/// its async `Drop` never runs on a torn-down per-test runtime. Tests isolate
/// themselves with disjoint namespaces. Set `FORGE_TEST_REDIS_URL` to use an
/// external Redis instead (for environments without Docker); it must be a
/// dedicated server that is **empty** at the start of each run, so `FLUSHALL`
/// between runs.
async fn redis_url() -> String {
    if let Ok(url) = std::env::var("FORGE_TEST_REDIS_URL") {
        return url;
    }
    if let Some(url) = REDIS_URL.get() {
        return url.clone();
    }
    // Serialize first-time startup across concurrent tests.
    let _guard = INIT_LOCK.lock().await;
    if let Some(url) = REDIS_URL.get() {
        return url.clone();
    }

    let container = GenericImage::new("redis", "7")
        .with_exposed_port(REDIS_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
        .await
        .expect("failed to start redis testcontainer (is Docker running?)");

    let host = container.get_host().await.expect("host");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("mapped port");

    // Leak so the container outlives this runtime; the testcontainers reaper
    // removes it when the process exits.
    let _: &'static testcontainers::ContainerAsync<GenericImage> = Box::leak(Box::new(container));

    let url = format!("redis://{host}:{port}");
    REDIS_URL.set(url).ok();
    REDIS_URL.get().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l2_sharing_and_backplane_invalidation() {
    let url = redis_url().await;

    let a = Cache::with_redis(1000, &url)
        .await
        .expect("instance A connects to redis");
    let b = Cache::with_redis(1000, &url)
        .await
        .expect("instance B connects to redis");

    let a_calls = Arc::new(AtomicUsize::new(0));
    let b_calls = Arc::new(AtomicUsize::new(0));

    // 1) Miss on A → factory runs once → L1 + L2 populated.
    let v = {
        let a_calls = a_calls.clone();
        a.get_or_try_insert_with::<String, _, _, TestError>(
            "pkg",
            "Newtonsoft.Json",
            Duration::from_secs(300),
            || async move {
                a_calls.fetch_add(1, Ordering::SeqCst);
                Ok("13.0.3".to_string())
            },
        )
        .await
        .unwrap()
    };
    assert_eq!(v, "13.0.3");
    assert_eq!(a_calls.load(Ordering::SeqCst), 1);

    // 2) Instance B (cold L1, shared L2) must hit L2 and NOT run its factory.
    let v_b = {
        let b_calls = b_calls.clone();
        b.get_or_try_insert_with::<String, _, _, TestError>(
            "pkg",
            "Newtonsoft.Json",
            Duration::from_secs(300),
            || async move {
                b_calls.fetch_add(1, Ordering::SeqCst);
                Ok("SHOULD-NOT-RUN".to_string())
            },
        )
        .await
        .unwrap()
    };
    assert_eq!(v_b, "13.0.3", "B must read A's value from the shared L2");
    assert_eq!(
        b_calls.load(Ordering::SeqCst),
        0,
        "B must hit L2, not run its factory"
    );

    // B's value is now in B's L1 too. Confirm a second B read stays at 0 calls.
    {
        let b_calls = b_calls.clone();
        let again = b
            .get_or_try_insert_with::<String, _, _, TestError>(
                "pkg",
                "Newtonsoft.Json",
                Duration::from_secs(300),
                || async move {
                    b_calls.fetch_add(1, Ordering::SeqCst);
                    Ok("SHOULD-NOT-RUN".to_string())
                },
            )
            .await
            .unwrap();
        assert_eq!(again, "13.0.3");
    }
    assert_eq!(b_calls.load(Ordering::SeqCst), 0);

    // 3) invalidate on A → Redis tag bump + backplane → B rejects its older L1
    //    and shared L2 envelopes. Its next read must run the factory.
    a.invalidate("pkg", "Newtonsoft.Json").await;

    // Poll until B has observed the tag barrier and re-runs its factory.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let b_calls_probe = b_calls.clone();
        let probe = b
            .get_or_try_insert_with::<String, _, _, TestError>(
                "pkg",
                "Newtonsoft.Json",
                Duration::from_secs(300),
                || async move {
                    b_calls_probe.fetch_add(1, Ordering::SeqCst);
                    Ok("RECOMPUTED".to_string())
                },
            )
            .await
            .unwrap();

        if probe == "RECOMPUTED" {
            // B's factory ran → both layers were invalidated as required.
            assert_eq!(b_calls.load(Ordering::SeqCst), 1);
            break;
        }

        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for backplane invalidation to drop B's L1 entry \
                 (B still served the stale value)"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_namespace_invalidation_clears_an_inflight_l2_fill() {
    let url = redis_url().await;
    let a = Cache::with_redis(1000, &url).await.unwrap();
    let b = Cache::with_redis(1000, &url).await.unwrap();
    // Let both detached subscribers finish subscribing before publishing.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let factory_started = Arc::new(tokio::sync::Notify::new());
    let release_factory = Arc::new(tokio::sync::Notify::new());
    let fill = {
        let b = b.clone();
        let factory_started = factory_started.clone();
        let release_factory = release_factory.clone();
        tokio::spawn(async move {
            b.get_or_try_insert_with::<String, _, _, TestError>(
                "race",
                "credential",
                Duration::from_secs(300),
                || async move {
                    factory_started.notify_one();
                    release_factory.notified().await;
                    Ok("STALE-FILL".to_string())
                },
            )
            .await
            .unwrap()
        })
    };
    factory_started.notified().await;

    // A advances the namespace tag while B's older fill is blocked. B's
    // conditional Redis write must fail because its captured generation is old.
    a.invalidate_ns("race").await;
    release_factory.notify_one();
    assert_eq!(fill.await.unwrap(), "STALE-FILL");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let probe = b
            .get_or_try_insert_with::<String, _, _, TestError>(
                "race",
                "credential",
                Duration::from_secs(300),
                || async { Ok("FRESH".to_string()) },
            )
            .await
            .unwrap();
        if probe == "FRESH" {
            break;
        }
        if Instant::now() >= deadline {
            panic!("remote invalidation left an in-flight stale L2 fill readable");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tag_generation_prevents_three_node_stale_l2_relay() {
    let url = redis_url().await;
    let a = Cache::with_redis(1000, &url).await.unwrap();
    let b = Cache::with_redis(1000, &url).await.unwrap();
    let c = Cache::with_redis(1000, &url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Keep C's namespace read fence occupied even after the stale relay fill
    // completes. In the former delete/re-delete design this held C's subscriber
    // back long enough for B to promote C's stale L2 write into B's L1.
    let blocker_started = Arc::new(tokio::sync::Notify::new());
    let release_blocker = Arc::new(tokio::sync::Notify::new());
    let blocker = {
        let c = c.clone();
        let blocker_started = blocker_started.clone();
        let release_blocker = release_blocker.clone();
        tokio::spawn(async move {
            c.get_or_try_insert_with::<String, _, _, TestError>(
                "relay-race",
                "blocker",
                Duration::from_secs(300),
                || async move {
                    blocker_started.notify_one();
                    release_blocker.notified().await;
                    Ok("BLOCKER".to_string())
                },
            )
            .await
            .unwrap()
        })
    };

    let stale_started = Arc::new(tokio::sync::Notify::new());
    let release_stale = Arc::new(tokio::sync::Notify::new());
    let stale_fill = {
        let c = c.clone();
        let stale_started = stale_started.clone();
        let release_stale = release_stale.clone();
        tokio::spawn(async move {
            c.get_or_try_insert_with::<String, _, _, TestError>(
                "relay-race",
                "credential",
                Duration::from_secs(300),
                || async move {
                    stale_started.notify_one();
                    release_stale.notified().await;
                    Ok("STALE-C".to_string())
                },
            )
            .await
            .unwrap()
        })
    };

    blocker_started.notified().await;
    stale_started.notified().await;
    a.invalidate_ns("relay-race").await;

    // C captured generation 0 before invalidation. Its Redis CAS must reject the
    // stale write because A already advanced the namespace tag to generation 1.
    release_stale.notify_one();
    assert_eq!(stale_fill.await.unwrap(), "STALE-C");

    let observed_by_b = b
        .get_or_try_insert_with::<String, _, _, TestError>(
            "relay-race",
            "credential",
            Duration::from_secs(300),
            || async { Ok("FRESH-B".to_string()) },
        )
        .await
        .unwrap();
    assert_eq!(
        observed_by_b, "FRESH-B",
        "a stale fill on C must never relay through shared L2 into B"
    );

    release_blocker.notify_one();
    assert_eq!(blocker.await.unwrap(), "BLOCKER");
}

/// Every tag generation key must carry a TTL: an invalidated tag would
/// otherwise live in Redis forever (one key per ever-invalidated tag), and a
/// pre-TTL key from an older deployment gets its clock started by the next
/// conditional value write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tag_generation_keys_carry_a_ttl() {
    let url = redis_url().await;
    let cache = Cache::with_redis(1000, &url).await.unwrap();

    cache
        .get_or_try_insert_with("ttl-ns", "item", Duration::from_secs(300), || async {
            Ok::<_, TestError>("VALUE".to_string())
        })
        .await
        .unwrap();
    cache.invalidate("ttl-ns", "item").await;

    let client = redis::Client::open(url).unwrap();
    let mut conn = redis::aio::ConnectionManager::new(client).await.unwrap();
    for tag_key in [
        "forge:cache:tag:@key:ttl-ns:item",
        "forge:cache:tag:@ns:ttl-ns",
    ] {
        // The bump created @key (and invalidate_ns would create @ns); only the
        // bumped @key tag must exist here — and with an expiry.
        let ttl: i64 = redis::cmd("TTL")
            .arg(tag_key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_ne!(ttl, -1, "tag key {tag_key} must never be persistent");
        if tag_key.contains("@key") {
            assert!(ttl > 0, "bumped tag key {tag_key} must exist with a TTL");
        }
    }

    // A pre-TTL (persistent) tag key from an older deployment gets an expiry
    // from the next conditional value write that touches it.
    let _: () = redis::cmd("SET")
        .arg("forge:cache:tag:@ns:ttl-ns")
        .arg(0u64)
        .query_async(&mut conn)
        .await
        .unwrap();
    cache
        .get_or_try_insert_with("ttl-ns", "item", Duration::from_secs(300), || async {
            Ok::<_, TestError>("REFILLED".to_string())
        })
        .await
        .unwrap();
    let ttl: i64 = redis::cmd("TTL")
        .arg("forge:cache:tag:@ns:ttl-ns")
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(
        ttl > 0,
        "a legacy persistent tag key must be given a TTL by the next value write (got {ttl})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_backplane_message_is_promoted_to_a_tag_generation() {
    let url = redis_url().await;
    let cache = Cache::with_redis(1000, &url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let old: String = cache
        .get_or_try_insert_with("legacy", "item", Duration::from_secs(300), || async {
            Ok::<_, TestError>("OLD".to_string())
        })
        .await
        .unwrap();
    assert_eq!(old, "OLD");

    // Simulate a pre-tag-version node. A new subscriber must turn this legacy
    // namespace event into a durable Redis tag bump and apply it locally.
    let client = redis::Client::open(url).unwrap();
    let mut publisher = redis::aio::ConnectionManager::new(client).await.unwrap();
    let _: () = publisher
        .publish("forge:cache:invalidate", "424242|n|legacy")
        .await
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let value = cache
            .get_or_try_insert_with("legacy", "item", Duration::from_secs(300), || async {
                Ok::<_, TestError>("FRESH".to_string())
            })
            .await
            .unwrap();
        if value == "FRESH" {
            break;
        }
        if Instant::now() >= deadline {
            panic!("legacy invalidation was not promoted to a tag barrier");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
