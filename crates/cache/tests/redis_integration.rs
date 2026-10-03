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
//! No test sleeps "until the subscriber is up": `Cache::with_redis*` returns
//! only once its backplane subscription is live (bounded by the Redis
//! timeouts, which [`connect`] sets generously so a loaded CI box cannot hit
//! the bound), and a subscription that comes up late flushes L1.
//!
//! Docker was available in the authoring environment, so this test is NOT
//! `#[ignore]`d. It does require Docker at run time; if Docker is absent the
//! container start panics with a clear message (the unit tests in `l1_unit.rs`
//! cover all non-Redis behaviour and run without Docker).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use forge_cache::{Cache, RedisTimeouts};
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

/// A Redis-backed cache whose construction waits for its backplane
/// subscription; the timeouts (and so that bounded wait) are generous so the
/// tests do not depend on how loaded the machine is.
async fn connect(url: &str) -> Cache {
    Cache::with_redis_timeouts(
        1000,
        url,
        RedisTimeouts {
            connect: Duration::from_secs(10),
            response: Duration::from_secs(10),
        },
    )
    .await
    .expect("cache connects to redis")
}

/// How long a test waits for a backplane message to be applied.
const DELIVERY_DEADLINE: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l2_sharing_and_backplane_invalidation() {
    let url = redis_url().await;

    // Both instances are subscribed when construction returns (review L1):
    // no sleep, no race with A's invalidation below.
    let a = connect(&url).await;
    let b = connect(&url).await;

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
    let deadline = Instant::now() + DELIVERY_DEADLINE;
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
    let a = connect(&url).await;
    let b = connect(&url).await;

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

    let deadline = Instant::now() + DELIVERY_DEADLINE;
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
    let a = connect(&url).await;
    let b = connect(&url).await;
    let c = connect(&url).await;

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
    let cache = connect(&url).await;

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

    let deadline = Instant::now() + DELIVERY_DEADLINE;
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

/// A Redis entry whose envelope is current but whose payload does not decode as
/// the caller's type (a changed type after an upgrade, two deployments sharing
/// one Redis) is a miss that refills — never a panic in the request path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l2_payload_of_another_type_is_a_miss_not_a_panic() {
    let url = redis_url().await;
    let writer = Cache::with_redis(1000, &url)
        .await
        .expect("writer connects");
    let reader = Cache::with_redis(1000, &url)
        .await
        .expect("reader connects");

    let stored = writer
        .get_or_try_insert_with::<String, _, _, TestError>(
            "typeshift",
            "k",
            Duration::from_secs(300),
            || async { Ok("not a number".to_string()) },
        )
        .await
        .unwrap();
    assert_eq!(stored, "not a number");

    let calls = Arc::new(AtomicUsize::new(0));
    let got = {
        let calls = calls.clone();
        reader
            .get_or_try_insert_with::<u64, _, _, TestError>(
                "typeshift",
                "k",
                Duration::from_secs(300),
                || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(42)
                },
            )
            .await
            .unwrap()
    };
    assert_eq!(
        got, 42,
        "undecodable L2 payload falls through to the factory"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Security-relevant values are cached in process only: a local entry is
/// never written to Redis (a peer with a cold L1 runs its own factory), and a
/// value planted in Redis under the same key is never read back by a local
/// lookup — anyone who can write to Redis must not be able to supply an
/// authorization set or a credential verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_entries_never_touch_redis() {
    let url = redis_url().await;
    let a = connect(&url).await;
    let b = connect(&url).await;
    let key = format!("local-{}", std::process::id());

    // A caches locally; B (cold L1, shared L2) must not find it in Redis.
    let v = a
        .get_or_try_insert_local::<String, _, _, TestError>(
            "sec",
            &key,
            Duration::from_secs(300),
            || async { Ok("genuine-a".to_string()) },
        )
        .await
        .unwrap();
    assert_eq!(v, "genuine-a");
    let seen_by_b = b
        .get_or_try_insert_with::<String, _, _, TestError>(
            "sec",
            &key,
            Duration::from_secs(300),
            || async { Ok("b-factory".to_string()) },
        )
        .await
        .unwrap();
    assert_eq!(
        seen_by_b, "b-factory",
        "a local entry must not be shared through Redis"
    );

    // B's shared write above is now in Redis ("planted"). A fresh instance's
    // local lookup must ignore it and run its own factory.
    let c = connect(&url).await;
    let v = c
        .get_or_try_insert_local::<String, _, _, TestError>(
            "sec",
            &key,
            Duration::from_secs(300),
            || async { Ok("genuine-c".to_string()) },
        )
        .await
        .unwrap();
    assert_eq!(
        v, "genuine-c",
        "a local lookup must never read a Redis entry"
    );
}

/// Local entries still honor cross-instance invalidation over the
/// backplane: an invalidation on one instance evicts every instance's copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_entries_are_invalidated_across_instances() {
    let url = redis_url().await;
    let a = connect(&url).await;
    let b = connect(&url).await;
    let key = format!("local-inv-{}", std::process::id());

    let v = a
        .get_or_try_insert_local::<i64, _, _, TestError>(
            "sec",
            &key,
            Duration::from_secs(300),
            || async { Ok(1) },
        )
        .await
        .unwrap();
    assert_eq!(v, 1);
    b.invalidate("sec", &key).await;

    let deadline = Instant::now() + DELIVERY_DEADLINE;
    loop {
        let v = a
            .get_or_try_insert_local::<i64, _, _, TestError>(
                "sec",
                &key,
                Duration::from_secs(300),
                || async { Ok(2) },
            )
            .await
            .unwrap();
        if v == 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "backplane never evicted the local entry"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `rediss://` (TLS) URLs are supported, and an unreachable Redis does not
/// keep a cache from being built (an instance can start during a Redis
/// outage): connections are lazy, and reads fall back to the factory.
#[tokio::test]
async fn an_unreachable_redis_does_not_block_startup_and_rediss_urls_work() {
    for url in ["rediss://127.0.0.1:9/", "redis://127.0.0.1:9/"] {
        let started = Instant::now();
        let cache = Cache::with_redis_timeouts(
            10,
            url,
            RedisTimeouts {
                connect: Duration::from_millis(200),
                response: Duration::from_millis(200),
            },
        )
        .await
        .unwrap_or_else(|err| panic!("{url}: {err}"));
        let value: u32 = cache
            .get_or_try_insert_with("ns", "k", Duration::from_secs(5), || async {
                Ok::<_, TestError>(7)
            })
            .await
            .unwrap();
        assert_eq!(value, 7);
        cache.invalidate("ns", "k").await;
        assert!(started.elapsed() < Duration::from_secs(10), "{url}");
    }
}

/// A TCP relay to the test Redis that can be told to go silent: from then on
/// every byte in either direction is swallowed while both sockets stay open,
/// like a Redis node lost behind a NAT or a failover without a reset.
struct Relay {
    url: String,
    silent: Arc<std::sync::atomic::AtomicBool>,
}

impl Relay {
    async fn start(redis_url: &str) -> Relay {
        use tokio::net::{TcpListener, TcpStream};
        let upstream = redis_url
            .trim_start_matches("redis://")
            .trim_end_matches('/')
            .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}", listener.local_addr().unwrap());
        let silent = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = silent.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(&upstream).await else {
                    continue;
                };
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                tokio::spawn(Relay::pump(client_read, server_write, flag.clone()));
                tokio::spawn(Relay::pump(server_read, client_write, flag.clone()));
            }
        });
        Relay { url, silent }
    }

    async fn pump(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
        silent: Arc<std::sync::atomic::AtomicBool>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match from.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if silent.load(Ordering::SeqCst) {
                break;
            }
            if to.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
        // Silent: keep both sockets open and never answer.
        let _open = (from, to);
        std::future::pending::<()>().await;
    }

    fn go_silent(&self) {
        self.silent.store(true, Ordering::SeqCst);
    }
}

async fn connect_with(url: &str, timeout: Duration) -> Cache {
    Cache::with_redis_timeouts(
        1000,
        url,
        RedisTimeouts {
            connect: timeout,
            response: timeout,
        },
    )
    .await
    .expect("cache builds")
}

/// Review M1: an invalidation stalled on a Redis that stopped answering must
/// not freeze lookups in its namespace; an L1 hit is answered at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_redis_does_not_block_reads_behind_an_invalidation() {
    let relay = Relay::start(&redis_url().await).await;
    let cache = connect_with(&relay.url, Duration::from_secs(2)).await;
    let cached: u32 = cache
        .get_or_try_insert_local("stall-ns", "hit", Duration::from_secs(60), || async {
            Ok::<_, TestError>(1)
        })
        .await
        .unwrap();
    assert_eq!(cached, 1);

    relay.go_silent();
    let invalidation = {
        let cache = cache.clone();
        tokio::spawn(async move { cache.invalidate("stall-ns", "other").await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !invalidation.is_finished(),
        "the invalidation waits on Redis"
    );

    let started = Instant::now();
    let hit: u32 = cache
        .get_or_try_insert_local("stall-ns", "hit", Duration::from_secs(60), || async {
            Ok::<_, TestError>(2)
        })
        .await
        .unwrap();
    assert_eq!(hit, 1);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "an L1 hit waited {:?} behind a stalled invalidation",
        started.elapsed()
    );
    invalidation.await.unwrap();
}

/// Review M3: a subscription whose connection went silent (no reset) is
/// detected by the backplane's ping; the instance flushes L1 instead of
/// serving entries whose invalidations it can no longer hear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silently_dead_subscription_is_detected_and_l1_flushed() {
    let url = redis_url().await;
    let relay = Relay::start(&url).await;
    let a = connect_with(&relay.url, Duration::from_secs(2)).await;
    let b = connect(&url).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let read = |cache: &Cache| {
        let cache = cache.clone();
        let calls = calls.clone();
        async move {
            cache
                .get_or_try_insert_local::<usize, _, _, TestError>(
                    "dead-sub",
                    "k",
                    Duration::from_secs(600),
                    || async move { Ok(calls.fetch_add(1, Ordering::SeqCst)) },
                )
                .await
                .unwrap()
        }
    };
    assert_eq!(read(&a).await, 0);

    relay.go_silent();
    b.invalidate("dead-sub", "k").await;

    // Ping every 10 s with a 2 s answer deadline: flushed well within 30 s.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if read(&a).await != 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a dead subscription kept serving the invalidated entry"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
