//! What reading a package's control member holds (#815), counted by a
//! global allocator: a test binary of its own, with one test, so no other
//! test's allocations count.
//!
//! The crafted packages are those of the issue: a control member holding a
//! GNU long name of 256 MiB of `a`, in a few KiB (MiB for gzip). `tar`
//! read the long name whole before it refused the package; the xz decoder's
//! window grew with it. The zstd decoder holds a window whole, so what it
//! holds is bounded by the window it may declare.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Cursor, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

use forge_format_apt::deb::{control_file, MAX_CONTROL_TAR_BYTES, MAX_ZSTD_WINDOW_BYTES};

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

/// The size of the crafted long name.
const LONG_NAME: usize = 256 * MIB;

/// A tar header of `kind` and `size` named `path`.
fn header(path: &str, kind: tar::EntryType, size: usize) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).unwrap();
    header.set_entry_type(kind);
    header.set_size(size as u64);
    header.set_mode(0o644);
    header.set_cksum();
    header.as_bytes().to_vec()
}

fn long_name_header() -> Vec<u8> {
    header("././@LongLink", tar::EntryType::GNULongName, LONG_NAME)
}

/// A `.deb` whose control member is `member`, named `name`.
fn deb(name: &str, member: &[u8]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in [("debian-binary", &b"2.0\n"[..]), (name, member)] {
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name,
            0,
            0,
            0,
            100644,
            data.len()
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

/// xz: the header in a stream of its own, then streams of 1 MiB of `a`
/// (the reader reads every stream).
fn xz_long_name() -> Vec<u8> {
    let xz = |data: &[u8]| {
        let options = lzma_rust2::XzOptions::with_preset(0);
        let mut xz = lzma_rust2::XzWriter::new(Vec::new(), options).unwrap();
        xz.write_all(data).unwrap();
        xz.finish().unwrap()
    };
    let mut member = xz(&long_name_header());
    let run = xz(&vec![b'a'; MIB]);
    for _ in 0..LONG_NAME / MIB {
        member.extend_from_slice(&run);
    }
    member
}

/// gzip: the header and an `a` in a stored block, then fixed-Huffman blocks
/// copying the `a` (length 258, distance 1), with no end: it is never read.
fn gzip_long_name() -> Vec<u8> {
    let mut head = long_name_header();
    head.push(b'a');
    // The gzip header, then a stored block that is not the last.
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 0];
    let len = head.len() as u16;
    member.extend_from_slice(&len.to_le_bytes());
    member.extend_from_slice(&(!len).to_le_bytes());
    member.extend_from_slice(&head);
    // A block of 3 + 13 * COPIES + 7 bits, whole bytes, so that copies of
    // it follow on.
    const COPIES: usize = 8 * 1000 + 6;
    let mut block = Vec::new();
    let (mut bits, mut used) = (0u32, 0);
    let mut put = |code: u32, len: u32, block: &mut Vec<u8>| {
        // Huffman codes go most significant bit first.
        for i in (0..len).rev() {
            bits |= ((code >> i) & 1) << used;
            used += 1;
            if used == 8 {
                block.push(bits as u8);
                (bits, used) = (0, 0);
            }
        }
    };
    // BFINAL 0, BTYPE 01 (fixed Huffman): written least significant first.
    put(0b010, 3, &mut block);
    for _ in 0..COPIES {
        put(0b1100_0101, 8, &mut block); // length 258 (code 285)
        put(0, 5, &mut block); // distance 1 (code 0)
    }
    put(0, 7, &mut block); // end of block (code 256)
    assert_eq!(used, 0, "the block ends on a byte");
    for _ in 0..LONG_NAME / (COPIES * 258) + 1 {
        member.extend_from_slice(&block);
    }
    member
}

/// zstd: the header in a raw block, then RLE blocks of `a`, with the
/// largest window read.
fn zstd_long_name() -> Vec<u8> {
    let mut frame = zstd_frame(MAX_ZSTD_WINDOW_BYTES.ilog2() as u8);
    zstd_block(&mut frame, 0, &long_name_header(), 512, false);
    for i in 0..LONG_NAME / (128 * 1024) {
        let last = i + 1 == LONG_NAME / (128 * 1024);
        zstd_block(&mut frame, 1, b"a", 128 * 1024, last);
    }
    frame
}

/// A zstd frame header without content size, checksum or dictionary,
/// declaring a window of `2^log` bytes.
fn zstd_frame(log: u8) -> Vec<u8> {
    vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, (log - 10) << 3]
}

/// A zstd block of `kind` (0 raw, 1 RLE) and `size`.
fn zstd_block(frame: &mut Vec<u8>, kind: u32, data: &[u8], size: usize, last: bool) {
    let header = u32::from(last) | kind << 1 | (size as u32) << 3;
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.extend_from_slice(data);
}

/// What the zstd decoder may hold: the largest window, growing as it fills
/// (and the old and the new buffer while it grows).
const ZSTD_HELD: usize = 3 * MAX_ZSTD_WINDOW_BYTES as usize + MIB;

#[test]
fn reading_a_control_member_holds_little() {
    // The crafted packages are refused at the long name's header.
    for (name, member, most) in [
        ("control.tar.xz", xz_long_name(), 2 * MIB),
        ("control.tar.gz", gzip_long_name(), 2 * MIB),
        ("control.tar.zst", zstd_long_name(), ZSTD_HELD),
    ] {
        let deb = deb(name, &member);
        let (read, held) = peak(|| control_file(&mut Cursor::new(&deb)));
        let refusal = read.unwrap_err().to_string();
        assert!(
            refusal.contains("GNU long name larger than"),
            "{name}: {refusal}"
        );
        assert!(held < most, "{name}: {} KiB held", held / 1024);
    }

    // A control member that inflates up to the bound, md5sums before the
    // control file, in a frame of the largest window.
    let control = b"Package: hello\nVersion: 1.0-1\nArchitecture: amd64\nDescription: hi\n";
    let md5sums = MAX_CONTROL_TAR_BYTES as usize - 3 * 512;
    let mut frame = zstd_frame(MAX_ZSTD_WINDOW_BYTES.ilog2() as u8);
    zstd_block(
        &mut frame,
        0,
        &header("./md5sums", tar::EntryType::Regular, md5sums),
        512,
        false,
    );
    for _ in 0..md5sums / (128 * 1024) {
        zstd_block(&mut frame, 1, b"0", 128 * 1024, false);
    }
    zstd_block(&mut frame, 1, b"0", md5sums % (128 * 1024), false);
    let mut tail = header("./control", tar::EntryType::Regular, control.len());
    tail.extend_from_slice(control);
    tail.resize(2048, 0);
    zstd_block(&mut frame, 0, &tail, tail.len(), true);
    let deb = deb("control.tar.zst", &frame);
    let (read, held) = peak(|| control_file(&mut Cursor::new(&deb)));
    assert_eq!(read.unwrap(), control);
    assert!(held < ZSTD_HELD, "{} KiB held", held / 1024);
}
