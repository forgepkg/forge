//! Redis L2 + backplane integration test (gated on a Docker/Redis container).
//!
//! Starts a `redis:7` testcontainer and exercises the spec's cross-instance
//! requirements:
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
use std::sync::Arc;
use std::time::{Duration, Instant};

use forge_cache::Cache;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::GenericImage;

#[derive(Clone, Debug, PartialEq)]
struct TestError(&'static str);

const REDIS_PORT: u16 = 6379;

/// Start a fresh `redis:7` container and return its `redis://host:port` URL,
/// keeping the container alive by leaking it (its async `Drop` would otherwise
/// run on a torn-down runtime).
async fn redis_url() -> String {
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

    format!("redis://{host}:{port}")
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

    // 3) invalidate on A → backplane → B drops its L1 entry (and L2 is gone).
    //    After this, B's next read must MISS both layers and run its factory.
    a.invalidate("pkg", "Newtonsoft.Json").await;

    // Poll until the backplane message has been processed by B (its L1 drop) and
    // the L2 key is deleted, so B re-runs its factory. Timeout to avoid hangs.
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

    // A deletes the shared L2 namespace and publishes while B's older fill is
    // still blocked. B will write after A's first delete, so its subscriber must
    // fence that fill and delete the stale L1/L2 value again.
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
