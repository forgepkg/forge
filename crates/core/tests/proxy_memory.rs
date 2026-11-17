//! The memory one upstream conversation of a proxy takes (#601), measured.
//!
//! A test binary of its own: its allocator counts the bytes the process
//! holds, so the one test here runs alone. An in-process upstream serves
//! documents just under `proxy.max_metadata_bytes`, more of them than the
//! conversation's budget (4 × that) has room for, and a scripted format asks
//! for all of them in one round, which fetches four at a time.
//!
//! Against the code before the fix the test measures 28 ×
//! `max_metadata_bytes` (19 × with a local cache that keeps no document).

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::routing::get;
use axum::Router;
use forge_cache::Cache;
use forge_core::net::upstream::{UpstreamHttp, UpstreamHttpConfig};
use forge_core::repo::proxy::ProxyRepo;
use forge_core::repo::RepoReadOps;
use forge_core::{Format, FormatError, ParsedUpload, ReadSeek};
use forge_db::repository_dao::{self, NewRepository};
use forge_format_api::{
    Fetch, FetchResult, Fetched, Freshness, Remote, UpstreamAnswer, UpstreamOp, UpstreamStep,
};
use tokio::net::TcpListener;

/// The system allocator, counting the bytes held and their peak.
struct Counting;

static HELD: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn took(bytes: usize) {
    let held = HELD.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(held, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            took(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        HELD.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = System.realloc(ptr, layout, new_size);
        if !new.is_null() {
            // Counted as the copy it may be: the new allocation beside the
            // old one, then the old one freed.
            took(new_size);
            HELD.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const MIB: usize = 1024 * 1024;
/// `proxy.max_metadata_bytes` of the test.
const MAX_DOCUMENT: usize = 4 * MIB;
/// A document of the upstream: just under the limit.
const DOCUMENT: usize = MAX_DOCUMENT - 1024;
/// The documents the format asks for: twice what the conversation keeps.
const DOCUMENTS: usize = 8;

/// NuGet, asking its upstream for [`DOCUMENTS`] documents when it lists a
/// package's versions, and recording how each fetch went.
struct Greedy {
    nuget: forge_core::format::SpecFormat,
    docs: Vec<String>,
    /// The size of each document read, `None` for a fetch that failed.
    seen: Arc<Mutex<Vec<Option<usize>>>>,
}

impl Format for Greedy {
    fn id(&self) -> &'static str {
        "nuget"
    }
    fn parse_upload(&self, file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        self.nuget.parse_upload(file)
    }
    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        self.nuget.normalize_version(raw)
    }
    fn compare_versions(&self, a: &str, b: &str) -> std::cmp::Ordering {
        self.nuget.compare_versions(a, b)
    }
    fn lower_id(&self, id: &str) -> String {
        self.nuget.lower_id(id)
    }
    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        self.nuget.validate_id(id)
    }
    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        match op {
            UpstreamOp::Index => Ok(UpstreamStep::Done(UpstreamAnswer::Index("{}".into()))),
            UpstreamOp::Versions(_) if fetched.is_empty() => Ok(UpstreamStep::Fetch(
                self.docs
                    .iter()
                    .map(|url| Fetch::new(url.clone(), Freshness::Metadata))
                    .collect(),
            )),
            UpstreamOp::Versions(_) => {
                *self.seen.lock().unwrap() = fetched
                    .iter()
                    .map(|fetch| match &fetch.outcome {
                        Fetched::Found(body) => Some(body.len()),
                        _ => None,
                    })
                    .collect();
                Ok(UpstreamStep::Done(UpstreamAnswer::Versions(Some(vec![
                    "1.0.0".into(),
                ]))))
            }
            _ => self.nuget.upstream(remote, op, fetched),
        }
    }
}

/// An upstream answering every `/doc/{n}` with the same [`DOCUMENT`] bytes,
/// which it holds once: what it sends is not copied per request.
async fn upstream() -> String {
    let document = Bytes::from(vec![b'x'; DOCUMENT]);
    let app = Router::new().route(
        "/doc/{n}",
        get(move || {
            let document = document.clone();
            async move { document }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// #601: a conversation holds its documents, those it keeps and those it is
/// reading, within 4 × `max_metadata_bytes`, and beside them the encoding
/// for the local cache (4/3) of at most one `max_metadata_bytes` of
/// documents at a time: 5 1/3 × `max_metadata_bytes` in all. The local cache
/// keeps what was encoded, which is its own memory.
///
/// The bytes were counted once a document had been read, cached and
/// decoded, so the four fetches of a round each held theirs, and the copies
/// made on the way, whatever the conversation kept already: 28 ×
/// `max_metadata_bytes` here, the cache's share included, where 9 1/3 × is
/// the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conversation_reads_its_documents_within_its_budget() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let base = upstream().await;
    let seen: Arc<Mutex<Vec<Option<usize>>>> = Arc::default();
    let format = Greedy {
        nuget: forge_core::format::SpecFormat::new(Arc::new(forge_format_nuget::Nuget::default())),
        docs: (0..DOCUMENTS).map(|n| format!("{base}/doc/{n}")).collect(),
        seen: seen.clone(),
    };
    // A local cache with room for every document read, so that what it
    // holds is known: it never has one it is about to let go.
    let px = ProxyRepo::new(
        pool.clone(),
        Arc::new(format),
        cas,
        Cache::l1_only(4096),
        common::envelope(&pool),
    )
    .with_http(
        UpstreamHttp::new(UpstreamHttpConfig {
            max_metadata_bytes: MAX_DOCUMENT as u64,
            spool_memory_bytes: 64 * 1024,
            ..Default::default()
        })
        .unwrap(),
    );
    let repo = format!("proxy{}", common::unique());
    let mut new = NewRepository::proxy(repo.clone());
    new.remote_url = Some(format!("{base}/index.json"));
    repository_dao::insert_repository(&pool, new)
        .await
        .expect("insert proxy repository");

    let before = HELD.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let versions = px.list_versions(&repo, "Sample.Lib").await.unwrap();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);

    assert_eq!(versions.len(), 1, "the format answers with what it read");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), DOCUMENTS, "every fetch has an outcome");
    assert_eq!(
        seen.iter().flatten().collect::<Vec<_>>(),
        [&DOCUMENT; 4],
        "four documents fit 4 x max_metadata_bytes; the others are not read"
    );
    // The conversation: 4 x for its documents and 4/3 x for the one being
    // encoded. The cache: the encodings of the three read before it. And two
    // megabytes for everything else that is allocated meanwhile.
    let encoded = MAX_DOCUMENT * 4 / 3;
    let bound = 4 * MAX_DOCUMENT + encoded + 3 * encoded + 2 * MIB;
    println!(
        "peak: {peak} bytes, {:.2} x max_metadata_bytes (bound: {:.2} x)",
        peak as f64 / MAX_DOCUMENT as f64,
        bound as f64 / MAX_DOCUMENT as f64
    );
    assert!(
        peak <= bound,
        "the conversation and the cache held {peak} bytes at their peak \
         ({:.2} x max_metadata_bytes), over {bound}",
        peak as f64 / MAX_DOCUMENT as f64
    );
}
