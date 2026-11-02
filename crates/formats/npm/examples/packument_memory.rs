//! The heap a proxy's upstream conversations take for real packuments.
//!
//! Save a package's packuments as `<name>.full.json` (`Accept:
//! application/json`) and `<name>.abbr.json` (`Accept:
//! application/vnd.npm.install-v1+json`), and the object of its latest
//! version (`GET /<name>/latest`) as `<name>.latest.json`, in a directory,
//! then:
//!
//! ```text
//! cargo run --release -p forge-format-npm --example packument_memory -- <dir>
//! ```
//!
//! For each package it prints the peak heap (above what was live before)
//! of every upstream operation a packument read through a proxy runs, and
//! then of all the packages read at once, the way an npm group with a
//! proxy member reads them for concurrent clients: the abbreviated reads an
//! install makes, and the full ones (with their publish times and the
//! latest manifest) that `npm view` and Renovate make.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use forge_format_npm::proxy::FULL_ACCEPT;
use forge_format_npm::{version, Npm};
use forge_plugin_api::testing::converse;
use forge_plugin_api::{
    Fetch, Fetched, PackageRef, PackageVersions, Remote, UpstreamAnswer, UpstreamOp,
};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new_size) };
        if !q.is_null() {
            if new_size > layout.size() {
                let grown = new_size - layout.size();
                let live = LIVE.fetch_add(grown, Ordering::Relaxed) + grown;
                PEAK.fetch_max(live, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const MIB: f64 = 1024.0 * 1024.0;

/// The peak heap `f` takes above what is live when it starts, in MiB.
fn peak<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base);
    (out, peak as f64 / MIB)
}

struct Package {
    name: String,
    full: Vec<u8>,
    abbreviated: Vec<u8>,
    latest_object: Vec<u8>,
    versions: Vec<String>,
    latest: String,
}

fn remote() -> Remote {
    Remote {
        url: "https://registry.npmjs.org".into(),
        index: Some("{}".into()),
        options: Vec::new(),
    }
}

/// `proxy.max_metadata_bytes`' default.
const MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;

/// Run `op` against `package` as npmjs serves it: each fetch gets its own
/// copy of the body, as the host hands one to every conversation, and a
/// body over `proxy.max_metadata_bytes` fails as the host fails it.
fn run(package: &Package, op: &UpstreamOp) -> UpstreamAnswer {
    converse(&Npm::default(), &remote(), op, |fetch: &Fetch| {
        let body = if fetch.url.ends_with(&format!("/{}", package.latest)) {
            &package.latest_object
        } else if fetch.accept.as_deref() == Some(FULL_ACCEPT) {
            &package.full
        } else {
            &package.abbreviated
        };
        if body.len() > MAX_METADATA_BYTES {
            return Fetched::Failed(format!(
                "upstream response from {} exceeds {MAX_METADATA_BYTES} bytes",
                fetch.url
            ));
        }
        Fetched::Found(body.clone())
    })
    .map(|c| c.answer)
    .unwrap_or_else(|e| UpstreamAnswer::Failed(e.to_string()))
}

/// The operations a packument read runs against one proxy member.
fn read_ops(package: &Package, full: bool) -> Vec<UpstreamOp> {
    let set = PackageVersions {
        id: package.name.clone(),
        versions: package.versions.clone(),
    };
    let mut ops = vec![
        UpstreamOp::Versions(package.name.clone()),
        UpstreamOp::Tags(package.name.clone()),
    ];
    if full {
        ops.push(UpstreamOp::Dating(set));
        ops.push(UpstreamOp::Manifest(PackageRef {
            id: package.name.clone(),
            version: package.latest.clone(),
        }));
    } else {
        ops.push(UpstreamOp::Metadata(set));
    }
    ops
}

fn label(op: &UpstreamOp) -> &'static str {
    match op {
        UpstreamOp::Versions(_) => "versions",
        UpstreamOp::Tags(_) => "tags",
        UpstreamOp::Metadata(_) => "metadata",
        UpstreamOp::Dating(_) => "dating",
        UpstreamOp::Manifest(_) => "manifest",
        _ => "other",
    }
}

fn outcome(answer: &UpstreamAnswer) -> String {
    match answer {
        UpstreamAnswer::Versions(v) => format!("{} versions", v.as_ref().map_or(0, Vec::len)),
        UpstreamAnswer::Tags(t) => format!("{} tags", t.as_ref().map_or(0, Vec::len)),
        UpstreamAnswer::Metadata(m) => format!(
            "{} versions, summaries {:.1} MiB",
            m.versions.len(),
            m.versions
                .iter()
                .map(|v| v.summary.as_ref().map_or(0, String::len))
                .sum::<usize>() as f64
                / MIB
        ),
        UpstreamAnswer::Manifest(m) => {
            format!("manifest {} KiB", m.as_ref().map_or(0, Vec::len) / 1024)
        }
        UpstreamAnswer::Failed(reason) => format!("FAILED: {reason}"),
        other => format!("{other:?}"),
    }
}

fn load(dir: &Path) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read the directory")
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let file = entry.file_name().to_string_lossy().to_string();
        let Some(stem) = file.strip_suffix(".full.json") else {
            continue;
        };
        let full = std::fs::read(entry.path()).expect("read the full packument");
        let abbreviated =
            std::fs::read(dir.join(format!("{stem}.abbr.json"))).expect("read the abbreviated one");
        let latest_object =
            std::fs::read(dir.join(format!("{stem}.latest.json"))).expect("read the latest one");
        // What the operations ask for, the way the host asks: every version.
        let doc: serde_json::Value =
            serde_json::from_slice(&abbreviated).expect("an abbreviated packument");
        let versions: Vec<String> = doc["versions"]
            .as_object()
            .expect("versions")
            .keys()
            .filter_map(|v| version::normalize(v).ok())
            .collect();
        let latest = version::normalize(doc["dist-tags"]["latest"].as_str().expect("latest"))
            .expect("a version");
        packages.push(Package {
            name: doc["name"].as_str().expect("a name").to_string(),
            full,
            abbreviated,
            latest_object,
            versions,
            latest,
        });
    }
    packages
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: packument_memory <dir>");
    let packages = load(Path::new(&dir));
    for package in &packages {
        println!(
            "{}: full {:.1} MiB, abbreviated {:.1} MiB, {} versions",
            package.name,
            package.full.len() as f64 / MIB,
            package.abbreviated.len() as f64 / MIB,
            package.versions.len()
        );
        for full in [false, true] {
            for op in read_ops(package, full) {
                if !full && matches!(op, UpstreamOp::Versions(_) | UpstreamOp::Tags(_)) {
                    // The same for both reads.
                } else if full && matches!(op, UpstreamOp::Versions(_) | UpstreamOp::Tags(_)) {
                    continue;
                }
                let started = Instant::now();
                let (answer, mib) = peak(|| run(package, &op));
                println!(
                    "  {:<9} peak {:>7.1} MiB  {:>5} ms  {}",
                    label(&op),
                    mib,
                    started.elapsed().as_millis(),
                    outcome(&answer)
                );
            }
        }
    }
    for full in [false, true] {
        let started = Instant::now();
        let (_, mib) = peak(|| {
            std::thread::scope(|s| {
                for package in &packages {
                    for op in read_ops(package, full) {
                        s.spawn(move || run(package, &op));
                    }
                }
            })
        });
        println!(
            "all {} packages' {} reads at once: peak {:.1} MiB, {} ms",
            packages.len(),
            if full { "full" } else { "abbreviated" },
            mib,
            started.elapsed().as_millis()
        );
    }
}
