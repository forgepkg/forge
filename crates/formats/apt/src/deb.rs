//! Reading a binary package (`.deb`, deb(5)): an `ar` archive holding
//! `debian-binary`, then `control.tar[.gz|.xz|.zst]`, then the data. Only
//! the `control` file of the control member is read; the data is never
//! touched, and every member is read within bounds, in time and in memory:
//! a package that inflates without end fails fast, and what it holds while
//! it does follows [`MAX_CONTROL_TAR_BYTES`], not what it inflates to
//! (#815).

use std::io::{self, Read, Seek, SeekFrom};

use ruzstd::decoding::errors::FrameDecoderError;

use crate::control::MAX_CONTROL_BYTES;

/// The largest control member read (compressed).
pub const MAX_CONTROL_MEMBER_BYTES: u64 = 64 * 1024 * 1024;

/// The most the control member may inflate to. It is read to its end, to
/// make sure it holds one `control` file only (#807); the `control` file is
/// at most [`MAX_CONTROL_BYTES`], and `md5sums` takes the most of the rest:
/// a package stays below the bound up to some 70,000 files.
///
/// It also bounds what the xz decoder holds: its window grows with what it
/// decodes, up to the dictionary the stream declares.
pub const MAX_CONTROL_TAR_BYTES: u64 = 8 * 1024 * 1024;

/// The largest dictionary an xz control member may declare: `xz -9`'s.
/// dpkg-deb compresses the control member like the data, so `-Zxz -z9`
/// declares it. The window is filled only as far as the member inflates
/// ([`MAX_CONTROL_TAR_BYTES`]); the bound refuses a stream that asks for
/// more (up to 4 GiB).
pub const MAX_XZ_DICTIONARY_BYTES: u32 = 64 * 1024 * 1024;

/// The largest window a zstd control member may declare: level 19's, which
/// dpkg-deb `-Zzstd -z19` declares for a control member it streams (levels
/// 20 to 22 declare 32 to 128 MiB). The decoder hands out nothing of a
/// frame until it has decoded a window more, so it holds the whole window:
/// the bound is what the member may inflate to.
pub const MAX_ZSTD_WINDOW_BYTES: u64 = MAX_CONTROL_TAR_BYTES;

/// The largest GNU long name or long link, or PAX extended header, read
/// from the control member. They give a path or a link target, a few
/// hundred bytes; the cap is the npm tarball reader's.
pub const MAX_EXTENSION_BYTES: u64 = 64 * 1024;

/// The most members looked at before the control member.
const MAX_MEMBERS: usize = 16;

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const AR_HEADER: usize = 60;

/// Why a package was refused.
#[derive(Debug)]
pub enum DebError {
    /// Not a binary package, or a damaged one: the text says why.
    Invalid(String),
    /// Reading the staged package failed.
    Io(io::Error),
}

impl std::fmt::Display for DebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebError::Invalid(m) => f.write_str(m),
            DebError::Io(e) => write!(f, "reading the package failed: {e}"),
        }
    }
}

impl From<io::Error> for DebError {
    fn from(e: io::Error) -> Self {
        DebError::Io(e)
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DebError> {
    Err(DebError::Invalid(message.into()))
}

/// One member of the archive: its name and where its data is.
struct Member {
    name: String,
    offset: u64,
    size: u64,
}

/// Read the next member header at the reader's position (even-aligned), or
/// `None` at the end of the archive.
fn next_member<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<Option<Member>, DebError> {
    let mut header = [0u8; AR_HEADER];
    let mut filled = 0;
    while filled < AR_HEADER {
        match reader.read(&mut header[filled..])? {
            0 if filled == 0 => return Ok(None),
            0 => return invalid("not a Debian package: the archive ends inside a member header"),
            n => filled += n,
        }
    }
    if &header[58..60] != b"`\n" {
        return invalid("not a Debian package: a damaged ar member header");
    }
    let field = |range: std::ops::Range<usize>| {
        std::str::from_utf8(&header[range])
            .map(str::trim_end)
            .unwrap_or("")
            .to_string()
    };
    let name = field(0..16);
    // GNU ar ends names with `/`.
    let name = name.strip_suffix('/').unwrap_or(&name).to_string();
    let Ok(size) = field(48..58).parse::<u64>() else {
        return invalid("not a Debian package: an ar member without a size");
    };
    let offset = reader.stream_position()?;
    Ok(Some(Member { name, offset, size }))
}

/// The bytes of the `control` file of the package `reader` holds.
pub fn control_file<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<Vec<u8>, DebError> {
    reader.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 8];
    if reader.read_exact(&mut magic).is_err() || &magic != AR_MAGIC {
        return invalid("not a Debian package (.deb): no ar archive");
    }
    let mut seen_binary = false;
    for _ in 0..MAX_MEMBERS {
        let Some(member) = next_member(reader)? else {
            break;
        };
        let next = member.offset + member.size + (member.size & 1);
        match member.name.as_str() {
            "debian-binary" => {
                if member.size > 64 {
                    return invalid("not a Debian package: debian-binary is too long");
                }
                let mut version = Vec::new();
                Read::take(&mut *reader, member.size).read_to_end(&mut version)?;
                if !version.starts_with(b"2.") {
                    return invalid(format!(
                        "unsupported package format {:?} (debian-binary)",
                        String::from_utf8_lossy(&version).trim()
                    ));
                }
                seen_binary = true;
            }
            // Reserved for internal use: skipped, as dpkg does.
            name if name.starts_with('_') => {}
            name if name == "control.tar" || name.starts_with("control.tar.") => {
                if !seen_binary {
                    return invalid("not a Debian package: debian-binary is not the first member");
                }
                if member.size > MAX_CONTROL_MEMBER_BYTES {
                    return invalid("the package's control member is too large");
                }
                let compressed = Read::take(&mut *reader, member.size);
                let tar: Box<dyn Read + '_> = match &name["control.tar".len()..] {
                    "" => Box::new(compressed),
                    ".gz" => Box::new(flate2::read::GzDecoder::new(compressed)),
                    ".xz" => Box::new(lzma_rust2::XzReader::new_mem_limit(
                        compressed,
                        true,
                        lzma_rust2::lzma2_get_memory_usage(MAX_XZ_DICTIONARY_BYTES),
                    )),
                    ".zst" => Box::new(
                        ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
                            compressed,
                            MAX_ZSTD_WINDOW_BYTES,
                        )
                        .map_err(|e| match e {
                            FrameDecoderError::WindowSizeTooBig { .. } => {
                                window_too_large("zstd window", MAX_ZSTD_WINDOW_BYTES)
                            }
                            e => DebError::Invalid(format!("the control member is not zstd: {e}")),
                        })?,
                    ),
                    other => {
                        return invalid(format!(
                            "the control member is compressed with an unsupported method ({other})"
                        ))
                    }
                };
                let mut tar = tar.take(MAX_CONTROL_TAR_BYTES);
                let too_large = || {
                    DebError::Invalid(format!(
                        "the control member inflates to more than {} MiB",
                        MAX_CONTROL_TAR_BYTES >> 20
                    ))
                };
                // Whatever failed once the bound is reached failed for it.
                let control = control_in_tar(&mut tar).map_err(|e| match tar.limit() {
                    0 => too_large(),
                    _ => e,
                })?;
                // `tar` takes the end of the input for the end of the
                // archive: one that reaches the bound must end there, with
                // a zero block (or nothing) next.
                if tar.limit() == 0 {
                    let mut next = Vec::with_capacity(512);
                    tar.into_inner()
                        .take(512)
                        .read_to_end(&mut next)
                        .map_err(unreadable)?;
                    if next.iter().any(|&b| b != 0) {
                        return Err(too_large());
                    }
                }
                return Ok(control);
            }
            other => {
                return invalid(format!(
                    "not a Debian package: member {other:?} comes before the control member"
                ))
            }
        }
        reader.seek(SeekFrom::Start(next))?;
    }
    invalid("not a Debian package: no control member")
}

fn window_too_large(what: &str, max: u64) -> DebError {
    DebError::Invalid(format!(
        "the control member's {what} is larger than {} MiB",
        max >> 20
    ))
}

/// A read of the inflated control member failed. The xz decoder fails with
/// `OutOfMemory` on a dictionary over [`MAX_XZ_DICTIONARY_BYTES`], before
/// it allocates any of it.
fn unreadable(e: io::Error) -> DebError {
    if e.kind() == io::ErrorKind::OutOfMemory {
        return window_too_large("xz dictionary", MAX_XZ_DICTIONARY_BYTES.into());
    }
    DebError::Invalid(format!("the control member is not a tar archive: {e}"))
}

/// The data of `entry`, a GNU long name or long link or a PAX extended
/// header of `size` bytes: one larger than [`MAX_EXTENSION_BYTES`] is
/// refused before any of it is read.
fn extension(entry: &mut impl Read, size: u64, what: &str) -> Result<Vec<u8>, DebError> {
    if size > MAX_EXTENSION_BYTES {
        return invalid(format!(
            "the control member has a {what} larger than {MAX_EXTENSION_BYTES} bytes"
        ));
    }
    let mut data = Vec::with_capacity(size as usize);
    entry.read_to_end(&mut data).map_err(unreadable)?;
    Ok(data)
}

/// The `control` file inside a control tarball.
///
/// The entries are read raw: `tar` would read a GNU long name or long link,
/// or a PAX extended header, whole before it hands back the entry it
/// describes, however large its header says it is (#815). They are read
/// here instead, bounded ([`extension`]), and applied as `tar` applies
/// them: at most one of each kind before an entry, its path the long name's,
/// else the PAX `path`, else the header's own. A PAX `size` other than the
/// header's (it would lay the archive out otherwise than `tar` reads it
/// raw) and a GNU sparse entry (its map follows the header) are refused; a
/// control member has neither.
///
/// The whole archive is read: dpkg extracts it with GNU tar, where a later
/// entry of a name overwrites an earlier one, so a member holding more than
/// one entry that resolves to `control` ([`is_control`]) is refused (#807).
fn control_in_tar(tar: impl Read) -> Result<Vec<u8>, DebError> {
    let mut archive = tar::Archive::new(tar);
    let entries = archive.entries().map_err(unreadable)?.raw(true);
    // What the extension entries before the next entry say of it.
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link = false;
    let mut pax: Option<Vec<u8>> = None;
    let mut found: Option<Vec<u8>> = None;
    for entry in entries {
        let mut entry = entry.map_err(unreadable)?;
        let kind = entry.header().entry_type();
        let size = entry.size();
        if kind.is_gnu_longname() {
            if long_name.is_some() {
                return invalid("the control member has two GNU long names for one entry");
            }
            long_name = Some(extension(&mut entry, size, "GNU long name")?);
            continue;
        }
        if kind.is_gnu_longlink() {
            if long_link {
                return invalid("the control member has two GNU long links for one entry");
            }
            extension(&mut entry, size, "GNU long link")?;
            long_link = true;
            continue;
        }
        if kind.is_pax_local_extensions() {
            if pax.is_some() {
                return invalid("the control member has two PAX headers for one entry");
            }
            pax = Some(extension(&mut entry, size, "PAX header")?);
            continue;
        }
        if kind.is_gnu_sparse() {
            return invalid("the control member holds a sparse file");
        }
        let mut pax_path = None;
        for record in tar::PaxExtensions::new(pax.as_deref().unwrap_or_default()) {
            let record = record.map_err(|e| {
                DebError::Invalid(format!("the control member has a damaged PAX header: {e}"))
            })?;
            match record.key_bytes() {
                b"path" => pax_path = Some(record.value_bytes().to_vec()),
                b"size" if record.value().ok().and_then(|v| v.parse().ok()) != Some(size) => {
                    return invalid(
                        "the control member's PAX header gives an entry another size than its own",
                    );
                }
                _ => {}
            }
        }
        let path = match long_name.take() {
            // A GNU long name ends with a NUL.
            Some(mut name) => {
                if name.last() == Some(&0) {
                    name.pop();
                }
                name
            }
            None => pax_path.unwrap_or_else(|| entry.path_bytes().into_owned()),
        };
        long_link = false;
        pax = None;
        if !is_control(&path) {
            continue;
        }
        if found.is_some() {
            return invalid("the package's control member holds more than one control file");
        }
        if !entry.header().entry_type().is_file() {
            return invalid("the package's control is not a file");
        }
        if entry.size() > MAX_CONTROL_BYTES as u64 {
            return invalid(format!(
                "the package's control file is larger than {} KiB",
                MAX_CONTROL_BYTES >> 10
            ));
        }
        let mut control = Vec::new();
        entry
            .by_ref()
            .take(MAX_CONTROL_BYTES as u64)
            .read_to_end(&mut control)
            .map_err(|e| DebError::Invalid(format!("the control file could not be read: {e}")))?;
        // `tar` ends an entry quietly where the member ends.
        if control.len() as u64 != entry.size() {
            return invalid("the package's control file is cut short");
        }
        found = Some(control);
    }
    match found {
        Some(control) => Ok(control),
        None => invalid("the package has no control file"),
    }
}

/// Whether GNU tar extracts the entry `path` as `control`: it drops what
/// comes up to the last `..` component and the leading `/`, and the
/// directory it extracts into resolves empty and `.` components.
fn is_control(path: &[u8]) -> bool {
    let components: Vec<&[u8]> = path
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .collect();
    let after = match components.iter().rposition(|c| *c == b"..") {
        Some(i) => &components[i + 1..],
        None => &components[..],
    };
    after == [b"control"]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    /// The compressions a control member comes in.
    const METHODS: [&str; 4] = ["", "gz", "xz", "zst"];

    /// A `.deb` of `control`, its control member compressed by `method`
    /// (one of [`METHODS`]), with a small data member.
    pub(crate) fn deb(control: &str, method: &str) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        append(&mut tar, "./control", control.as_bytes());
        package(&tar.into_inner().unwrap(), method)
    }

    /// Append a file of `data` at `path` to `tar`.
    fn append(tar: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, data).unwrap();
    }

    /// A `.deb` whose control member is `tar`, compressed by `method`.
    fn package(tar: &[u8], method: &str) -> Vec<u8> {
        let name = match method {
            "" => "control.tar".to_string(),
            method => format!("control.tar.{method}"),
        };
        ar(&[
            ("debian-binary", b"2.0\n".to_vec()),
            (&name, compress(tar, method)),
            ("data.tar", vec![0u8; 1024]),
        ])
    }

    fn compress(tar: &[u8], method: &str) -> Vec<u8> {
        match method {
            "" => tar.to_vec(),
            "gz" => {
                let mut gz =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                gz.write_all(tar).unwrap();
                gz.finish().unwrap()
            }
            "xz" => {
                let mut xz =
                    lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))
                        .unwrap();
                xz.write_all(tar).unwrap();
                xz.finish().unwrap()
            }
            "zst" => {
                ruzstd::encoding::compress_to_vec(tar, ruzstd::encoding::CompressionLevel::Fastest)
            }
            other => panic!("{other}"),
        }
    }

    pub(crate) fn ar(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = AR_MAGIC.to_vec();
        for (name, data) in members {
            out.extend_from_slice(
                format!(
                    "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    name,
                    0,
                    0,
                    0,
                    100644,
                    data.len()
                )
                .as_bytes(),
            );
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    const CONTROL: &str = "Package: hello\nVersion: 1.0-1\nArchitecture: amd64\nDescription: hi\n";

    #[test]
    fn reads_the_control_file_of_every_compression() {
        for method in METHODS {
            let deb = deb(CONTROL, method);
            assert_eq!(
                control_file(&mut Cursor::new(deb)).unwrap(),
                CONTROL.as_bytes(),
                "{method}"
            );
        }
    }

    #[test]
    fn refuses_what_is_not_a_package() {
        for bad in [
            b"not an archive".to_vec(),
            ar(&[("debian-binary", b"2.0\n".to_vec())]),
            ar(&[
                ("debian-binary", b"3.0\n".to_vec()),
                ("control.tar", vec![]),
            ]),
            ar(&[("data.tar", vec![0; 10]), ("control.tar", vec![])]),
            ar(&[("control.tar", vec![])]),
            ar(&[
                ("debian-binary", b"2.0\n".to_vec()),
                ("control.tar.bz2", vec![1]),
            ]),
            ar(&[
                ("debian-binary", b"2.0\n".to_vec()),
                ("control.tar.gz", vec![1, 2, 3]),
            ]),
            // A truncated header.
            b"!<arch>\ndebian-binary   ".to_vec(),
        ] {
            assert!(
                matches!(
                    control_file(&mut Cursor::new(&bad)),
                    Err(DebError::Invalid(_))
                ),
                "{:?}",
                String::from_utf8_lossy(&bad)
            );
        }
    }

    #[test]
    fn a_control_tar_without_control_is_refused() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_cksum();
        tar.append_data(&mut header, "./md5sums", &b"abc"[..])
            .unwrap();
        let deb = ar(&[
            ("debian-binary", b"2.0\n".to_vec()),
            ("control.tar", tar.into_inner().unwrap()),
        ]);
        let err = control_file(&mut Cursor::new(deb)).unwrap_err();
        assert!(err.to_string().contains("no control file"), "{err}");
    }

    #[test]
    fn a_control_file_over_the_cap_is_refused() {
        // A control file of exactly the cap is read; one byte more is
        // refused (#797: it was 1 MiB).
        let head = "Package: big\nVersion: 1\nArchitecture: all\nDescription: x\n ";
        let at_cap = format!("{head}{}\n", "y".repeat(MAX_CONTROL_BYTES - head.len() - 1));
        assert_eq!(at_cap.len(), MAX_CONTROL_BYTES);
        let read = control_file(&mut Cursor::new(deb_of(&[("./control", &at_cap)]))).unwrap();
        assert_eq!(read.len(), MAX_CONTROL_BYTES);
        let over = format!("{at_cap}z");
        let err = control_file(&mut Cursor::new(deb_of(&[("./control", &over)]))).unwrap_err();
        assert!(err.to_string().contains("larger than 64 KiB"), "{err}");
    }

    /// A `.deb` whose control member holds a regular file of `data` at each
    /// of `files`' paths, as written: a leading `/` is kept.
    fn deb_of(files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.extend_from_slice(header.as_bytes());
            tar.extend_from_slice(data.as_bytes());
            tar.resize(tar.len().next_multiple_of(512), 0);
        }
        tar.resize(tar.len() + 1024, 0);
        package(&tar, "gz")
    }

    #[test]
    fn a_control_tar_with_one_control_is_read() {
        for path in ["control", "./control", "/control"] {
            let deb = deb_of(&[(path, CONTROL), ("./md5sums", "abc")]);
            assert_eq!(
                control_file(&mut Cursor::new(deb)).unwrap(),
                CONTROL.as_bytes(),
                "{path}"
            );
        }
    }

    #[test]
    fn a_control_tar_with_two_controls_is_refused() {
        let other = "Package: libc6\nVersion: 99\nArchitecture: amd64\nDescription: hi\n";
        for second in [
            "./control",
            "/control",
            "control",
            "//control",
            "././control",
            "./debian/../control",
        ] {
            let deb = deb_of(&[
                ("./control", CONTROL),
                ("./md5sums", "abc"),
                (second, other),
            ]);
            match control_file(&mut Cursor::new(deb)) {
                Err(DebError::Invalid(m)) => {
                    assert!(m.contains("more than one control file"), "{second}: {m}")
                }
                other => panic!("{second}: {other:?}"),
            }
        }
        // Names that GNU tar extracts elsewhere are not the control file.
        for path in ["./control.orig", "./debian/control", "./control/x"] {
            let deb = deb_of(&[("./control", CONTROL), (path, other)]);
            assert_eq!(
                control_file(&mut Cursor::new(deb)).unwrap(),
                CONTROL.as_bytes(),
                "{path}"
            );
        }
    }

    #[test]
    fn a_control_member_reaching_its_bound_must_end_there() {
        let bound = MAX_CONTROL_TAR_BYTES as usize;
        // The control file, then md5sums whose data ends at the bound.
        let mut tar = tar::Builder::new(Vec::new());
        append(&mut tar, "./control", CONTROL.as_bytes());
        append(&mut tar, "./md5sums", &vec![b'0'; bound - 3 * 512]);
        let mut tar = entries(tar);
        assert_eq!(tar.len(), bound);
        let mut ended = tar.clone();
        ended.resize(bound + 1024, 0);
        assert_eq!(
            control_file(&mut Cursor::new(package(&ended, "gz"))).unwrap(),
            CONTROL.as_bytes()
        );
        // An entry past the bound is not looked at: the member is refused.
        tar.extend(raw_entry("./control", tar::EntryType::Regular, b"x"));
        let refusal = refusal(&tar, "gz");
        assert!(refusal.contains("inflates to more than 8 MiB"), "{refusal}");
    }

    /// A raw tar header of `kind` and `size` named `path`.
    fn raw_header(path: &str, kind: tar::EntryType, size: u64) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_entry_type(kind);
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        header.as_bytes().to_vec()
    }

    /// A raw tar entry of `kind` holding `data`.
    fn raw_entry(path: &str, kind: tar::EntryType, data: &[u8]) -> Vec<u8> {
        let mut entry = raw_header(path, kind, data.len() as u64);
        entry.extend_from_slice(data);
        entry.resize(entry.len().next_multiple_of(512), 0);
        entry
    }

    /// The entries `tar` holds, without the end of the archive.
    fn entries(tar: tar::Builder<Vec<u8>>) -> Vec<u8> {
        tar.get_ref().clone()
    }

    /// `prefix` (entries), then a `./control` file of [`CONTROL`].
    fn with_control(prefix: Vec<u8>) -> Vec<u8> {
        let mut tar = tar::Builder::new(prefix);
        append(&mut tar, "./control", CONTROL.as_bytes());
        tar.into_inner().unwrap()
    }

    fn refusal(tar: &[u8], method: &str) -> String {
        match control_file(&mut Cursor::new(package(tar, method))) {
            Err(DebError::Invalid(m)) => m,
            other => panic!("{method:?}: {other:?}"),
        }
    }

    #[test]
    fn long_names_long_links_and_pax_headers_are_refused_before_they_are_read() {
        // The header says 256 MiB; the member does not hold them, and the
        // header alone is refused (#815).
        for (kind, what) in [
            (tar::EntryType::GNULongName, "GNU long name"),
            (tar::EntryType::GNULongLink, "GNU long link"),
            (tar::EntryType::XHeader, "PAX header"),
        ] {
            let mut tar = raw_header("././@LongLink", kind, 256 << 20);
            tar.extend_from_slice(&[b'a'; 4096]);
            for method in METHODS {
                let refusal = refusal(&tar, method);
                assert!(
                    refusal.contains(&format!("{what} larger than {MAX_EXTENSION_BYTES} bytes")),
                    "{method:?}: {refusal}"
                );
            }
        }
        // Up to the bound they are read.
        let name = format!("./{}\0", "d/".repeat(MAX_EXTENSION_BYTES as usize / 2 - 2));
        assert_eq!(name.len() as u64, MAX_EXTENSION_BYTES - 1);
        let mut tar = raw_entry(
            "././@LongLink",
            tar::EntryType::GNULongName,
            name.as_bytes(),
        );
        tar.extend(raw_entry("./d", tar::EntryType::Directory, b""));
        let deb = package(&with_control(tar), "gz");
        assert_eq!(
            control_file(&mut Cursor::new(deb)).unwrap(),
            CONTROL.as_bytes()
        );
    }

    #[test]
    fn long_names_and_pax_paths_name_the_next_entry() {
        let pax = |records: &[(&str, &str)]| {
            let mut tar = tar::Builder::new(Vec::new());
            tar.append_pax_extensions(records.iter().map(|(k, v)| (*k, v.as_bytes())))
                .unwrap();
            entries(tar)
        };
        let named = |prefix: Vec<u8>, path: &str| {
            let mut tar = tar::Builder::new(prefix);
            append(&mut tar, path, CONTROL.as_bytes());
            tar.into_inner().unwrap()
        };
        let long_name = |name: &str| {
            raw_entry(
                "././@LongLink",
                tar::EntryType::GNULongName,
                name.as_bytes(),
            )
        };
        let size = CONTROL.len().to_string();
        // What `tar` writes for a path over 100 bytes, before the control file.
        let mut tar = tar::Builder::new(Vec::new());
        append(&mut tar, &format!("./{}/md5sums", "d".repeat(150)), b"abc");
        let read = [
            with_control(entries(tar)),
            named(long_name("./control\0"), "./other"),
            named(pax(&[("path", "./control")]), "./other"),
            named(pax(&[("path", "./control"), ("size", &size)]), "./other"),
            // The long name comes first, as `tar` reads them.
            named(
                [long_name("control"), pax(&[("path", "other")])].concat(),
                "x",
            ),
        ];
        for tar in read {
            for method in METHODS {
                let deb = package(&tar, method);
                assert_eq!(
                    control_file(&mut Cursor::new(deb)).unwrap(),
                    CONTROL.as_bytes()
                );
            }
        }
        let refused = [
            (
                named(long_name("./other\0"), "./control"),
                "no control file",
            ),
            (
                named(pax(&[("path", "./other")]), "./control"),
                "no control file",
            ),
            (named(pax(&[("size", "1")]), "./control"), "another size"),
            (named(pax(&[("size", "lots")]), "./control"), "another size"),
            (
                named([long_name("a"), long_name("control")].concat(), "x"),
                "two GNU long names",
            ),
            (
                named(
                    [pax(&[("mtime", "1")]), pax(&[("path", "control")])].concat(),
                    "x",
                ),
                "two PAX headers",
            ),
            (
                with_control(raw_entry("./sparse", tar::EntryType::GNUSparse, b"")),
                "sparse",
            ),
        ];
        for (tar, why) in refused {
            let refusal = refusal(&tar, "");
            assert!(refusal.contains(why), "{why}: {refusal}");
        }
    }

    #[test]
    fn a_control_member_is_read_up_to_its_bound() {
        let bound = MAX_CONTROL_TAR_BYTES as usize;
        // What comes before the control file, and the control file itself.
        let before = |size: usize| {
            let mut tar = tar::Builder::new(Vec::new());
            append(&mut tar, "./md5sums", &vec![b'0'; size]);
            with_control(entries(tar))
        };
        // The md5sums header and data, the control file's header, then its
        // data in the last block below the bound.
        let fits = before(bound - 3 * 512);
        assert_eq!(
            fits.len(),
            bound + 2 * 512,
            "the end of the archive follows"
        );
        for method in ["", "zst"] {
            let deb = package(&fits, method);
            assert_eq!(
                control_file(&mut Cursor::new(deb)).unwrap(),
                CONTROL.as_bytes()
            );
            // The control file's data starts at the bound, which cuts it
            // short; the md5sums run past it.
            for size in [bound - 2 * 512, bound] {
                let refusal = refusal(&before(size), method);
                assert!(refusal.contains("inflates to more than 8 MiB"), "{refusal}");
            }
        }
    }

    /// `xz` (one block) with its LZMA2 dictionary property set to `prop`.
    fn declare_xz_dictionary(xz: &mut [u8], prop: u8) {
        // The block header follows the 12-byte stream header: its size,
        // flags without sizes, one filter (LZMA2, one property byte), its
        // padding and CRC32.
        let size = (xz[12] as usize + 1) * 4;
        assert_eq!(&xz[13..16], [0x00, 0x21, 0x01]);
        xz[16] = prop;
        let mut crc = flate2::Crc::new();
        crc.update(&xz[12..12 + size - 4]);
        xz[12 + size - 4..12 + size].copy_from_slice(&crc.sum().to_le_bytes());
    }

    /// A zstd frame of `data` in raw blocks, declaring a window of
    /// `2^log` bytes.
    fn zstd_with_window(data: &[u8], log: u8) -> Vec<u8> {
        // Magic, no content size, checksum or dictionary, the window.
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, (log - 10) << 3];
        let mut blocks = data.chunks(64 * 1024).peekable();
        while let Some(block) = blocks.next() {
            // Last_Block, Block_Type 0 (raw), Block_Size.
            let header = u32::from(blocks.peek().is_none()) | (block.len() as u32) << 3;
            frame.extend_from_slice(&header.to_le_bytes()[..3]);
            frame.extend_from_slice(block);
        }
        frame
    }

    #[test]
    fn a_compression_window_over_the_bound_is_refused() {
        let tar = with_control(Vec::new());
        let deb = |name: &str, member: Vec<u8>| {
            ar(&[("debian-binary", b"2.0\n".to_vec()), (name, member)])
        };
        // xz: `-6`'s 8 MiB, `-9`'s 64 MiB; 96 MiB, 4 GiB.
        for (prop, fits) in [(22, true), (28, true), (29, false), (40, false)] {
            let mut xz = compress(&tar, "xz");
            declare_xz_dictionary(&mut xz, prop);
            let read = control_file(&mut Cursor::new(deb("control.tar.xz", xz)));
            match read {
                Ok(control) if fits => assert_eq!(control, CONTROL.as_bytes()),
                Err(DebError::Invalid(m)) if !fits => {
                    assert!(m.contains("xz dictionary is larger than 64 MiB"), "{m}")
                }
                other => panic!("{prop}: {other:?}"),
            }
        }
        // zstd: level 19's 8 MiB; level 20's 32 MiB, level 22's 128 MiB.
        for (log, fits) in [(23, true), (24, false), (25, false), (27, false)] {
            let zst = zstd_with_window(&tar, log);
            let read = control_file(&mut Cursor::new(deb("control.tar.zst", zst)));
            match read {
                Ok(control) if fits => assert_eq!(control, CONTROL.as_bytes()),
                Err(DebError::Invalid(m)) if !fits => {
                    assert!(m.contains("zstd window is larger than 8 MiB"), "{m}")
                }
                other => panic!("{log}: {other:?}"),
            }
        }
    }
}
