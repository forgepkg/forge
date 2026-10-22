//! The local blob cache (`BlobStore::with_cache`) against a scripted fake S3:
//! hits never reach S3, concurrent misses fill once, damaged files are
//! detected and fetched again, FIFO eviction (also after a restart), the
//! size limit, a full disk and a failing fill falling back to S3, Range reads,
//! write-through, garbage collection, and an S3 outage. No containers.
//!
//! The fake answers one request per connection (`connection: close`), so
//! "S3 down" is simply refusing new connections.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use forge_storage::blob_cache::{FsProbe, FsSpace};
use forge_storage::breaker::CircuitBreaker;
use forge_storage::{
    BlobCache, BlobCacheConfig, BlobRef, BlobStore, CacheLimit, ConditionalWrites, S3Config,
    S3Credentials, S3Error,
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const BUCKET: &str = "forge-test";

/// The fake backend's objects and behavior.
#[derive(Default)]
struct FakeS3 {
    objects: Mutex<HashMap<String, Vec<u8>>>,
    /// `GET`s of objects, per key.
    gets: Mutex<HashMap<String, usize>>,
    /// Refuse connections (S3 down).
    down: AtomicBool,
    /// Send object bodies in small pieces with pauses in between.
    slow: AtomicBool,
    deletes: AtomicUsize,
}

impl FakeS3 {
    fn put(&self, key: &str, bytes: Vec<u8>) {
        self.objects.lock().unwrap().insert(key.into(), bytes);
    }

    fn gets(&self, key: &str) -> usize {
        self.gets.lock().unwrap().get(key).copied().unwrap_or(0)
    }
}

async fn spawn_fake_s3() -> (String, Arc<FakeS3>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let fake = Arc::new(FakeS3::default());
    let state = fake.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            if state.down.load(Ordering::SeqCst) {
                drop(sock);
                continue;
            }
            let state = state.clone();
            tokio::spawn(serve(sock, state));
        }
    });
    (endpoint, fake)
}

async fn serve(mut sock: tokio::net::TcpStream, fake: Arc<FakeS3>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let header = |name: &str| {
        head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    };
    let content_length: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut have = buf.len() - (head_end + 4);
    while have < content_length {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => have += n,
        }
    }
    let mut parts = head.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").split('?').next().unwrap_or("");
    let key = path
        .strip_prefix(&format!("/{BUCKET}"))
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();

    let (status, extra, body): (u16, String, Vec<u8>) = match (method.as_str(), key.is_empty()) {
        ("HEAD", true) | ("PUT", true) => (200, String::new(), Vec::new()),
        ("DELETE", false) => {
            fake.deletes.fetch_add(1, Ordering::SeqCst);
            fake.objects.lock().unwrap().remove(&key);
            (204, String::new(), Vec::new())
        }
        ("GET", false) => {
            *fake.gets.lock().unwrap().entry(key.clone()).or_default() += 1;
            match fake.objects.lock().unwrap().get(&key).cloned() {
                None => (
                    404,
                    "content-type: application/xml\r\n".into(),
                    b"<Error><Code>NoSuchKey</Code></Error>".to_vec(),
                ),
                Some(bytes) => match header("range")
                    .and_then(|r| r.strip_prefix("bytes=").map(str::to_string))
                {
                    Some(spec) => {
                        let (a, b) = spec.split_once('-').unwrap();
                        let a: usize = a.parse().unwrap();
                        let b: usize = b.parse().unwrap();
                        let slice = bytes[a..=b.min(bytes.len() - 1)].to_vec();
                        (
                            206,
                            format!(
                                "content-range: bytes {a}-{}/{}\r\n",
                                a + slice.len() - 1,
                                bytes.len()
                            ),
                            slice,
                        )
                    }
                    None => (200, String::new(), bytes),
                },
            }
        }
        _ => (400, String::new(), Vec::new()),
    };
    let reply = format!(
        "HTTP/1.1 {status} X\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    if sock.write_all(reply.as_bytes()).await.is_err() || method == "HEAD" {
        return;
    }
    if fake.slow.load(Ordering::SeqCst) {
        for piece in body.chunks(4096) {
            if sock.write_all(piece).await.is_err() {
                return;
            }
            let _ = sock.flush().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    } else {
        let _ = sock.write_all(&body).await;
    }
    let _ = sock.shutdown().await;
}

fn store(endpoint: &str) -> BlobStore {
    BlobStore::new(S3Config {
        endpoint: endpoint.to_string(),
        region: "us-east-1".into(),
        bucket: BUCKET.into(),
        credentials: S3Credentials::from_keys("test", "test"),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: ConditionalWrites::Off,
    })
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "forge-blob-cache-test-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A filesystem of `total` bytes with `available` free, whatever the real
/// disk says.
fn fake_fs(total: u64, available: Arc<Mutex<u64>>) -> FsProbe {
    Arc::new(move |_: &Path| {
        Ok(FsSpace {
            total,
            available: *available.lock().unwrap(),
        })
    })
}

/// A roomy fake filesystem.
fn roomy() -> FsProbe {
    fake_fs(1 << 40, Arc::new(Mutex::new(1 << 40)))
}

fn config(dir: &Path, max: CacheLimit) -> BlobCacheConfig {
    BlobCacheConfig {
        path: dir.to_path_buf(),
        max_bytes: max,
        min_free_bytes: Some(0),
        staging: None,
    }
}

fn cached_store(endpoint: &str, cache: BlobCache) -> BlobStore {
    // Short intervals so the outage tests do not wait long.
    store(endpoint).with_cache_and_breaker(
        cache,
        CircuitBreaker::new(1, Duration::from_millis(200), Duration::from_secs(5)),
    )
}

/// A blob: random-ish bytes, their hash and S3 key.
struct Blob {
    bytes: Vec<u8>,
    sha256: String,
    key: String,
}

impl Blob {
    fn new(seed: u8, len: usize) -> Blob {
        let bytes: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect();
        let sha256 = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let key = format!("blobs/sha256/{}/{sha256}/1", &sha256[..2]);
        Blob { bytes, sha256, key }
    }

    fn r(&self) -> BlobRef<'_> {
        BlobRef {
            sha256: &self.sha256,
            s3_key: &self.key,
            size: self.bytes.len() as u64,
        }
    }

    fn file(&self, dir: &Path) -> PathBuf {
        dir.join(&self.sha256[..2]).join(&self.sha256)
    }
}

async fn read(store: &BlobStore, blob: &Blob, range: Option<std::ops::Range<u64>>) -> Vec<u8> {
    let mut stream = store.open(blob.r(), range).await.expect("open");
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk.expect("chunk"));
    }
    out
}

/// Wait for an evicted entry's file to be removed (in the background).
async fn until_gone(path: &Path) {
    for _ in 0..200 {
        if !path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} was never removed", path.display());
}

/// Wait for a background fill or copy to land in the cache.
async fn until_cached(cache: &BlobCache, blob: &Blob) {
    for _ in 0..200 {
        if cache.contains(&blob.sha256) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} was never cached", blob.sha256);
}

#[tokio::test]
async fn a_hit_never_contacts_s3() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("hit");
    let blob = Blob::new(1, 300_000);
    fake.put(&blob.key, blob.bytes.clone());
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());

    assert_eq!(read(&store, &blob, None).await, blob.bytes, "miss: from S3");
    until_cached(&cache, &blob).await;
    assert_eq!(std::fs::read(blob.file(&dir)).unwrap(), blob.bytes);
    assert_eq!(read(&store, &blob, None).await, blob.bytes, "hit");
    assert_eq!(store.read_all(blob.r()).await.unwrap(), blob.bytes);
    assert_eq!(fake.gets(&blob.key), 1, "only the miss read S3");

    let stats = cache.stats();
    assert_eq!((stats.hits, stats.misses, stats.fills), (2, 1, 1));
    assert_eq!(stats.hit_bytes, 2 * blob.bytes.len() as u64);
    assert_eq!(
        (stats.entries, stats.size_bytes),
        (1, blob.bytes.len() as u64)
    );
}

#[tokio::test]
async fn concurrent_misses_share_one_fill() {
    let (endpoint, fake) = spawn_fake_s3().await;
    fake.slow.store(true, Ordering::SeqCst);
    let dir = scratch("single-flight");
    let blob = Arc::new(Blob::new(2, 200_000));
    fake.put(&blob.key, blob.bytes.clone());
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());

    let readers: Vec<_> = (0..8)
        .map(|i| {
            let (store, blob) = (store.clone(), blob.clone());
            tokio::spawn(async move {
                // Some read ranges, while the fill is still running.
                let range = (i % 2 == 1).then_some(1000..150_000);
                (read(&store, &blob, range.clone()).await, range)
            })
        })
        .collect();
    for reader in readers {
        let (bytes, range) = reader.await.unwrap();
        match range {
            Some(r) => assert_eq!(bytes, blob.bytes[r.start as usize..r.end as usize]),
            None => assert_eq!(bytes, blob.bytes),
        }
    }
    assert_eq!(fake.gets(&blob.key), 1, "one S3 GET for all of them");
    until_cached(&cache, &blob).await;
    let stats = cache.stats();
    assert_eq!((stats.fills, stats.misses, stats.fill_failures), (1, 8, 0));
}

#[tokio::test]
async fn a_damaged_file_is_detected_and_fetched_again() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("damaged");
    let blob = Blob::new(3, 50_000);
    fake.put(&blob.key, blob.bytes.clone());
    {
        let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
        let store = cached_store(&endpoint, cache.clone());
        read(&store, &blob, None).await;
        until_cached(&cache, &blob).await;
    }
    // Damage the file while "the process is down": same size, other bytes.
    let mut damaged = blob.bytes.clone();
    damaged[10_000] ^= 0xff;
    std::fs::write(blob.file(&dir), &damaged).unwrap();

    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    assert!(cache.contains(&blob.sha256), "the scan found it");
    let store = cached_store(&endpoint, cache.clone());
    assert_eq!(
        read(&store, &blob, None).await,
        blob.bytes,
        "never the damaged bytes"
    );
    assert_eq!(fake.gets(&blob.key), 2, "fetched again");
    until_cached(&cache, &blob).await;
    assert_eq!(
        std::fs::read(blob.file(&dir)).unwrap(),
        blob.bytes,
        "repaired"
    );
    assert_eq!(cache.stats().corrupt, 1);

    // A file cut short is caught on any hit, even one already verified.
    std::fs::write(blob.file(&dir), &blob.bytes[..100]).unwrap();
    assert_eq!(read(&store, &blob, None).await, blob.bytes);
    assert_eq!(fake.gets(&blob.key), 3);
    assert_eq!(cache.stats().corrupt, 2);
}

#[tokio::test]
async fn concurrent_hits_after_a_restart_check_the_hash_once() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("verify-once");
    let blob = Blob::new(4, 4 << 20);
    fake.put(&blob.key, blob.bytes.clone());
    {
        let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
        let store = cached_store(&endpoint, cache.clone());
        read(&store, &blob, None).await;
        until_cached(&cache, &blob).await;
    }
    // After a restart the entry is unverified: fifty clients at once, half
    // of them asking for a single byte, share one read of the whole file.
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());
    let reads = (0..50u64).map(|i| {
        let (store, blob) = (&store, &blob);
        async move {
            let range = (i % 2 == 0).then_some(i..i + 1);
            let expected = match &range {
                Some(r) => blob.bytes[r.start as usize..r.end as usize].to_vec(),
                None => blob.bytes.clone(),
            };
            assert_eq!(read(store, blob, range).await, expected);
        }
    });
    futures_util::future::join_all(reads).await;
    let stats = cache.stats();
    assert_eq!(stats.verifications, 1, "one hash check for every hit");
    assert_eq!(stats.hits, 50);
    assert_eq!(
        fake.gets(&blob.key),
        1,
        "S3 was read before the restart only"
    );

    // Verified now: later hits read no more than they serve.
    read(&store, &blob, Some(0..1)).await;
    assert_eq!(cache.stats().verifications, 1);
}

#[tokio::test]
async fn s3_bytes_that_do_not_match_the_hash_are_not_cached() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("bad-source");
    let blob = Blob::new(4, 20_000);
    let mut wrong = blob.bytes.clone();
    wrong[0] ^= 1;
    fake.put(&blob.key, wrong.clone());
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());
    // S3 is the source of truth: its bytes are served, but never cached.
    assert_eq!(read(&store, &blob, None).await, wrong);
    assert!(!cache.contains(&blob.sha256));
    let stats = cache.stats();
    assert_eq!((stats.corrupt, stats.fill_failures, stats.fills), (1, 1, 0));
    assert_eq!(stats.reserved_bytes, 0, "the reservation was given back");
}

#[tokio::test]
async fn eviction_is_fifo_and_survives_a_restart() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("fifo");
    let blobs: Vec<Blob> = (10..15).map(|seed| Blob::new(seed, 1000)).collect();
    for blob in &blobs {
        fake.put(&blob.key, blob.bytes.clone());
    }
    let (a, b, c, d, e) = (&blobs[0], &blobs[1], &blobs[2], &blobs[3], &blobs[4]);
    {
        // Room for three.
        let cache = BlobCache::open_with(config(&dir, CacheLimit::Bytes(3000)), roomy()).unwrap();
        let store = cached_store(&endpoint, cache.clone());
        for blob in [a, b, c] {
            read(&store, blob, None).await;
            until_cached(&cache, blob).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Hits change nothing: `a` is still the oldest.
        read(&store, a, None).await;
        read(&store, a, None).await;
        read(&store, d, None).await;
        until_cached(&cache, d).await;
        assert!(!cache.contains(&a.sha256), "the oldest fill went first");
        until_gone(&a.file(&dir)).await;
        assert_eq!(cache.stats().evictions, 1);
    }
    // The order comes back from the files' mtimes.
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Bytes(3000)), roomy()).unwrap();
    assert_eq!(cache.stats().entries, 3);
    let store = cached_store(&endpoint, cache.clone());
    read(&store, e, None).await;
    until_cached(&cache, e).await;
    assert!(
        !cache.contains(&b.sha256),
        "b was the oldest after the restart"
    );
    assert!(cache.contains(&c.sha256) && cache.contains(&d.sha256));

    // A smaller limit after a restart evicts down to it at once.
    drop(store);
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Bytes(1000)), roomy()).unwrap();
    let stats = cache.stats();
    assert_eq!((stats.entries, stats.size_bytes), (1, 1000));
    assert!(cache.contains(&e.sha256), "the newest stays");
}

#[tokio::test]
async fn limits_follow_the_disk_min_free_and_staging() {
    let dir = scratch("limits");
    let available = Arc::new(Mutex::new(800u64));
    let cfg = |max, min_free, staging| BlobCacheConfig {
        path: dir.clone(),
        max_bytes: max,
        min_free_bytes: min_free,
        staging,
    };
    // auto: the filesystem (1000) minus min_free (default 5 %: 50).
    let cache = BlobCache::open_with(
        cfg(CacheLimit::Auto, None, None),
        fake_fs(1000, available.clone()),
    )
    .unwrap();
    let stats = cache.stats();
    assert!(stats.limit_auto);
    // ... capped by what is free beyond min_free: 800 - 50.
    assert_eq!(stats.limit_bytes, 750);
    *available.lock().unwrap() = 1000;
    assert_eq!(cache.maintain().limit_bytes, 950, "re-read on maintenance");

    // Staging on the same filesystem: its budget is kept free too.
    let staging = scratch("limits-staging");
    let cache = BlobCache::open_with(
        cfg(CacheLimit::Auto, Some(100), Some((staging.clone(), 300))),
        fake_fs(1000, available.clone()),
    )
    .unwrap();
    assert_eq!(cache.stats().limit_bytes, 600);
    // Not with a fixed limit.
    let cache = BlobCache::open_with(
        cfg(CacheLimit::Bytes(700), Some(100), Some((staging, 300))),
        fake_fs(1000, available.clone()),
    )
    .unwrap();
    assert!(!cache.stats().limit_auto);
    assert_eq!(cache.stats().limit_bytes, 700);
    // A fixed limit is still capped by min_free.
    *available.lock().unwrap() = 400;
    assert_eq!(cache.maintain().limit_bytes, 300);
}

#[tokio::test]
async fn only_maintenance_reads_the_filesystem_size() {
    // A miss runs on a runtime worker: it goes by the size maintenance last
    // read, and evicts without unlinking files under the cache's lock.
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("probe");
    let probes = Arc::new(AtomicUsize::new(0));
    let counted = probes.clone();
    let available = Arc::new(Mutex::new(10_000u64));
    let disk = fake_fs(1 << 30, available.clone());
    let probe: FsProbe = Arc::new(move |path: &Path| {
        counted.fetch_add(1, Ordering::SeqCst);
        disk(path)
    });
    let cache = BlobCache::open_with(
        BlobCacheConfig {
            min_free_bytes: Some(0),
            ..config(&dir, CacheLimit::Auto)
        },
        probe,
    )
    .unwrap();
    let opened = probes.load(Ordering::SeqCst);
    let store = cached_store(&endpoint, cache.clone());
    let blobs: Vec<Blob> = (60..66).map(|seed| Blob::new(seed, 3_000)).collect();
    for blob in &blobs {
        fake.put(&blob.key, blob.bytes.clone());
        assert_eq!(read(&store, blob, None).await, blob.bytes);
        until_cached(&cache, blob).await;
    }
    assert_eq!(probes.load(Ordering::SeqCst), opened, "no probe on a miss");
    // The cache's own fills count against the space read then: 10 000
    // bytes hold three blobs, and the older ones were evicted.
    let stats = cache.stats();
    assert_eq!((stats.entries, stats.size_bytes), (3, 9_000));
    for old in &blobs[..3] {
        until_gone(&old.file(&dir)).await;
    }
    cache.maintain();
    assert_eq!(probes.load(Ordering::SeqCst), opened + 1);
}

#[tokio::test]
async fn a_full_disk_serves_from_s3_without_caching() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("full");
    let blob = Blob::new(20, 10_000);
    fake.put(&blob.key, blob.bytes.clone());
    // 5 000 bytes free, 1 000 of which must stay free: no room for 10 000.
    let available = Arc::new(Mutex::new(5_000u64));
    let cache = BlobCache::open_with(
        BlobCacheConfig {
            min_free_bytes: Some(1_000),
            ..config(&dir, CacheLimit::Auto)
        },
        fake_fs(1 << 30, available.clone()),
    )
    .unwrap();
    let store = cached_store(&endpoint, cache.clone());
    assert_eq!(read(&store, &blob, None).await, blob.bytes);
    assert!(!cache.contains(&blob.sha256));
    assert_eq!(cache.stats().bypassed, 1);

    // Room again, as the next maintenance finds: cached.
    *available.lock().unwrap() = 1 << 30;
    cache.maintain();
    read(&store, &blob, None).await;
    until_cached(&cache, &blob).await;

    // Something else fills the disk past min_free: maintenance evicts.
    *available.lock().unwrap() = 0;
    assert_eq!(cache.maintain().entries, 0);
    assert!(!blob.file(&dir).exists());
}

#[tokio::test]
async fn a_fill_that_cannot_write_falls_back_to_s3() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("broken");
    let blob = Blob::new(21, 10_000);
    fake.put(&blob.key, blob.bytes.clone());
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());
    // The cache's temp directory is gone: no fill file can be created.
    std::fs::remove_dir_all(dir.join("tmp")).unwrap();
    assert_eq!(
        read(&store, &blob, Some(100..9000)).await,
        blob.bytes[100..9000]
    );
    assert_eq!(read(&store, &blob, None).await, blob.bytes);
    assert!(!cache.contains(&blob.sha256));
    assert_eq!(cache.stats().reserved_bytes, 0);
}

#[tokio::test]
async fn startup_removes_partial_fills_and_ignores_strangers() {
    let dir = scratch("partial");
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    std::fs::write(dir.join("tmp").join("abc.part"), b"half a blob").unwrap();
    std::fs::create_dir_all(dir.join("ab")).unwrap();
    std::fs::write(dir.join("ab").join("not-a-hash"), b"x").unwrap();
    std::fs::write(dir.join("README"), b"x").unwrap();
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    assert_eq!(std::fs::read_dir(dir.join("tmp")).unwrap().count(), 0);
    assert_eq!(cache.stats().entries, 0);
    assert!(dir.join("ab").join("not-a-hash").exists(), "left alone");
}

#[tokio::test]
async fn ranges_are_served_from_the_cached_file() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("range");
    let blob = Blob::new(30, 700_000);
    fake.put(&blob.key, blob.bytes.clone());
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());
    // A range on a miss fills the whole blob.
    assert_eq!(read(&store, &blob, Some(5..10)).await, blob.bytes[5..10]);
    until_cached(&cache, &blob).await;
    for range in [0..1, 300_000..700_000, 699_999..700_000, 1..699_999] {
        let (a, b) = (range.start as usize, range.end as usize);
        assert_eq!(read(&store, &blob, Some(range)).await, blob.bytes[a..b]);
    }
    assert_eq!(fake.gets(&blob.key), 1);

    // Without a cache, a range goes to S3 as a ranged GET.
    let plain = store_without_cache(&endpoint);
    assert_eq!(read(&plain, &blob, Some(10..20)).await, blob.bytes[10..20]);
}

fn store_without_cache(endpoint: &str) -> BlobStore {
    store(endpoint)
}

#[tokio::test]
async fn uploads_are_written_through() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("write-through");
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());

    // Staged on the cache's filesystem: hard-linked.
    let blob = Blob::new(40, 64_000);
    let staged = scratch("write-through-staging").join("staged");
    std::fs::write(&staged, &blob.bytes).unwrap();
    cache
        .insert_staged(&blob.sha256, blob.bytes.len() as u64, &staged)
        .await;
    std::fs::remove_file(&staged).unwrap();
    assert!(cache.contains(&blob.sha256));
    assert_eq!(read(&store, &blob, None).await, blob.bytes);
    assert_eq!(fake.gets(&blob.key), 0, "never read from S3");

    // On another filesystem (when the host has a tmpfs at /dev/shm): copied
    // in the background, even though the staged file goes at once.
    let shm = Path::new("/dev/shm");
    if shm.is_dir() {
        let blob = Blob::new(41, 64_000);
        let staged = shm.join(format!("forge-write-through-{}", std::process::id()));
        std::fs::write(&staged, &blob.bytes).unwrap();
        cache
            .insert_staged(&blob.sha256, blob.bytes.len() as u64, &staged)
            .await;
        std::fs::remove_file(&staged).unwrap();
        until_cached(&cache, &blob).await;
        assert_eq!(read(&store, &blob, None).await, blob.bytes);
        assert_eq!(fake.gets(&blob.key), 0);
    }
    assert_eq!(cache.stats().reserved_bytes, 0);
}

#[cfg(unix)]
#[tokio::test]
async fn the_cache_is_private_to_forges_user() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;

    // A directory others can write is refused, sticky or not.
    for shared in [0o777, 0o1777, 0o775] {
        let dir = scratch("shared");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(shared)).unwrap();
        let err = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{shared:o}"
        );
    }

    // What the cache creates only Forge's user can read: directories 0700,
    // entries 0600, whether filled from S3, hard-linked or copied.
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("private").join("cache");
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    assert_eq!(mode(&dir), 0o700);
    let store = cached_store(&endpoint, cache.clone());
    let filled = Blob::new(50, 4096);
    fake.put(&filled.key, filled.bytes.clone());
    assert_eq!(read(&store, &filled, None).await, filled.bytes);
    until_cached(&cache, &filled).await;
    let mut entries = vec![filled];

    let linked = Blob::new(51, 4096);
    let staged = scratch("private-staging").join("staged");
    std::fs::write(&staged, &linked.bytes).unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
    cache
        .insert_staged(&linked.sha256, linked.bytes.len() as u64, &staged)
        .await;
    until_cached(&cache, &linked).await;
    entries.push(linked);

    let shm = Path::new("/dev/shm");
    if shm.is_dir() {
        let copied = Blob::new(52, 4096);
        let staged = shm.join(format!("forge-private-{}", std::process::id()));
        std::fs::write(&staged, &copied.bytes).unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
        cache
            .insert_staged(&copied.sha256, copied.bytes.len() as u64, &staged)
            .await;
        std::fs::remove_file(&staged).unwrap();
        until_cached(&cache, &copied).await;
        entries.push(copied);
    }
    for blob in &entries {
        let file = blob.file(&dir);
        assert_eq!(mode(&file), 0o600, "{}", file.display());
        assert_eq!(mode(file.parent().unwrap()), 0o700);
    }
}

/// What the kubelet does to a volume at each mount of a pod with `fsGroup`
/// (without `fsGroupChangePolicy: OnRootMismatch`): every directory gets
/// `mode | 02770`, every file `mode | 0660`.
#[cfg(unix)]
fn kubelet_fs_group_pass(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).unwrap();
    let mode = meta.permissions().mode() & 0o7777;
    if meta.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            kubelet_fs_group_pass(&entry.unwrap().path());
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o2770)).unwrap();
    } else if meta.is_file() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o660)).unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_cache_on_a_volume_the_kubelet_regrouped_reopens() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    let (endpoint, fake) = spawn_fake_s3().await;
    let volume = scratch("fs-group");
    let dir = volume.join("blobs");
    let blob = Blob::new(53, 4096);
    fake.put(&blob.key, blob.bytes.clone());
    {
        let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
        let store = cached_store(&endpoint, cache.clone());
        read(&store, &blob, None).await;
        until_cached(&cache, &blob).await;
    }
    // The next pod start: the kubelet walks the volume before Forge starts.
    kubelet_fs_group_pass(&volume);
    assert_eq!(mode(&dir) & 0o2070, 0o2070);
    assert_eq!(mode(&blob.file(&dir)) & 0o060, 0o060);

    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("tmp")), 0o700);
    assert_eq!(mode(blob.file(&dir).parent().unwrap()), 0o700);
    assert_eq!(mode(&blob.file(&dir)), 0o600);
    let store = cached_store(&endpoint, cache.clone());
    assert_eq!(read(&store, &blob, None).await, blob.bytes);
    assert_eq!(fake.gets(&blob.key), 1, "served from the cache it kept");

    // Only that mark is undone: writable by others, it is still refused.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o2777)).unwrap();
    let err = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn garbage_collection_evicts_the_cached_copy() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("gc");
    let blob = Blob::new(50, 5_000);
    fake.put(&blob.key, blob.bytes.clone());
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());
    read(&store, &blob, None).await;
    until_cached(&cache, &blob).await;
    store.delete_blob(&blob.sha256, &blob.key).await.unwrap();
    assert_eq!(fake.deletes.load(Ordering::SeqCst), 1);
    assert!(!cache.contains(&blob.sha256));
    assert!(!blob.file(&dir).exists());
}

#[tokio::test]
async fn a_fill_of_a_blob_deleted_meanwhile_is_not_cached() {
    // The fill read the object before garbage collection deleted it: it
    // still serves its reader, but must not put the bytes back.
    let (endpoint, fake) = spawn_fake_s3().await;
    fake.slow.store(true, Ordering::SeqCst);
    let dir = scratch("gc-during-fill");
    let blob = Arc::new(Blob::new(51, 200_000));
    fake.put(&blob.key, blob.bytes.clone());
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());
    let reader = {
        let (store, blob) = (store.clone(), blob.clone());
        tokio::spawn(async move { read(&store, &blob, None).await })
    };
    for _ in 0..200 {
        if cache.stats().reserved_bytes > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(cache.stats().reserved_bytes > 0, "the fill is running");
    store.delete_blob(&blob.sha256, &blob.key).await.unwrap();
    assert_eq!(reader.await.unwrap(), blob.bytes);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stats = cache.stats();
    assert_eq!((stats.entries, stats.reserved_bytes), (0, 0));
    assert!(!cache.contains(&blob.sha256));
    assert!(!blob.file(&dir).exists());
}

#[tokio::test]
async fn while_s3_is_down_hits_are_served_and_misses_fail_fast() {
    let (endpoint, fake) = spawn_fake_s3().await;
    let dir = scratch("outage");
    let cached = Blob::new(60, 30_000);
    let uncached = Blob::new(61, 30_000);
    fake.put(&cached.key, cached.bytes.clone());
    fake.put(&uncached.key, uncached.bytes.clone());
    let cache = BlobCache::open_with(config(&dir, CacheLimit::Auto), roomy()).unwrap();
    let store = cached_store(&endpoint, cache.clone());
    read(&store, &cached, None).await;
    until_cached(&cache, &cached).await;

    fake.down.store(true, Ordering::SeqCst);
    // The first miss finds S3 down (and opens the breaker) ...
    let err = store
        .open(uncached.r(), None)
        .await
        .err()
        .expect("miss fails");
    assert!(matches!(err, S3Error::Unavailable(_)), "{err:?}");
    assert!(store.is_unavailable());
    // ... the next ones fail at once.
    let started = std::time::Instant::now();
    let err = store
        .open(uncached.r(), None)
        .await
        .err()
        .expect("miss fails");
    assert!(err.is_unavailable());
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "{:?}",
        started.elapsed()
    );
    assert!(store.ping().await.unwrap_err().is_unavailable());

    // Cached blobs are served as usual.
    assert_eq!(read(&store, &cached, Some(0..10)).await, cached.bytes[..10]);
    assert_eq!(read(&store, &cached, None).await, cached.bytes);
    assert!(cache.stats().hits_while_store_down >= 2);
    assert!(!cache.contains(&uncached.sha256));
    assert_eq!(cache.stats().reserved_bytes, 0);

    // S3 is back: after the open interval a probe goes through and misses
    // fill again.
    fake.down.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(read(&store, &uncached, None).await, uncached.bytes);
    assert!(!store.is_unavailable());
    until_cached(&cache, &uncached).await;
}

#[tokio::test]
async fn without_a_cache_errors_stay_plain_s3_errors() {
    // Unchanged behavior when the cache is off: no breaker, no Unavailable.
    let plain = store("http://127.0.0.1:1");
    let blob = Blob::new(70, 10);
    let err = plain.open(blob.r(), None).await.err().expect("fails");
    assert!(matches!(err, S3Error::S3(_)), "{err:?}");
    assert!(!plain.is_unavailable());
}
