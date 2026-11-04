//! What reading an import source's `Packages` index holds (#821), counted
//! by a global allocator: a test binary of its own, with one test, so no
//! other test's allocations count.
//!
//! The crafted index is that of the issue: 10 million `Package:a`
//! paragraphs, 110 MB of text, which inflates from a small `Packages.xz`.
//! Each made an entry of about 160 bytes, all of them kept: about 2.5 GiB
//! with the list's growth. A real index (Debian main for amd64, about
//! 65,000 entries) is still read.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};

use forge_format_apt::import::{read_packages, MAX_ENTRIES_BYTES};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grow(layout.size());
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
            // Counted as held side by side, as a copying realloc holds them.
            grow(new_size);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const MIB: usize = 1024 * 1024;

/// The most `f` held at once above what was held when it started.
fn peak<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    (out, PEAK.load(Ordering::Relaxed).saturating_sub(base))
}

/// An index of `count` paragraphs `paragraph`, made as it is read, so that
/// the index itself holds nothing.
struct Repeated {
    paragraph: Vec<u8>,
    left: usize,
    at: usize,
}

impl Repeated {
    fn new(paragraph: &str, count: usize) -> Self {
        Repeated {
            paragraph: paragraph.as_bytes().to_vec(),
            left: count,
            at: 0,
        }
    }
}

impl Read for Repeated {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut n = 0;
        while n < buf.len() && self.left > 0 {
            let rest = &self.paragraph[self.at..];
            let take = rest.len().min(buf.len() - n);
            buf[n..n + take].copy_from_slice(&rest[..take]);
            n += take;
            self.at += take;
            if self.at == self.paragraph.len() {
                self.at = 0;
                self.left -= 1;
            }
        }
        Ok(n)
    }
}

#[test]
fn reading_an_index_holds_a_bounded_amount() {
    // The crafted index is refused, holding no more than the budget.
    let (read, held) = peak(|| read_packages(Repeated::new("Package:a\n\n", 10_000_000)));
    let refusal = read.unwrap_err();
    assert!(refusal.contains("MiB of memory"), "{refusal}");
    assert!(
        held <= (MAX_ENTRIES_BYTES + MIB).min(300 * MIB),
        "{} MiB held",
        held / MIB
    );

    // An index of Debian's size, its entries as Debian's are, is read.
    let paragraph = format!(
        "Package: libreoffice-help-common\nSource: libreoffice\n\
         Version: 4:7.4.7-1+deb12u5\nInstalled-Size: 123456\n\
         Maintainer: Debian LibreOffice Maintainers <debian-openoffice@lists.debian.org>\n\
         Architecture: amd64\nDepends: libc6 (>= 2.34), libstdc++6 (>= 13)\n\
         Description: office productivity suite -- common files for LibreOffice help\n\
         Multi-Arch: foreign\nHomepage: https://www.libreoffice.org\n\
         Description-md5: 0123456789abcdef0123456789abcdef\nSection: doc\n\
         Priority: optional\n\
         Filename: pool/main/libr/libreoffice/libreoffice-help-common_7.4.7-1+deb12u5_amd64.deb\n\
         Size: 12345678\nMD5sum: 0123456789abcdef0123456789abcdef\n\
         SHA256: {}\nSHA512: {}\n\n",
        "a".repeat(64),
        "b".repeat(128)
    );
    let (read, held) = peak(|| read_packages(Repeated::new(&paragraph, 65_000)));
    assert_eq!(read.unwrap().len(), 65_000);
    assert!(held < MAX_ENTRIES_BYTES / 4, "{} MiB held", held / MIB);
}
