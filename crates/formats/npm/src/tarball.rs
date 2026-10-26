//! Reading a package tarball the way npm installs it.
//!
//! npm (pacote) unpacks a tarball with `strip: 1`: the first component of
//! every path is dropped, whatever it is called (`package/` by convention),
//! so the package's `package.json` is any entry at depth one. When several
//! entries map to it, the last one wins on disk, so the last one is read.
//! A file is any entry node-tar unpacks as one: a regular file (`0`, or NUL
//! in the old form) or a contiguous file (`7`). The whole archive is read,
//! bounded in what it unpacks to.

use std::io::Read;

use serde_json::{Map, Value};

/// The most a tarball may unpack to by default: 1 GiB.
pub const DEFAULT_MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;

/// The largest `package.json` read.
pub const MAX_PACKAGE_JSON_BYTES: u64 = 8 * 1024 * 1024;

/// The largest GNU long name or PAX extended header read. They name a path
/// of a few hundred bytes; the cap is the chart reader's.
const MAX_HEADER_ENTRY_BYTES: u64 = 64 * 1024;

/// What a tarball holds, as far as the registry cares.
#[derive(Debug, Clone, PartialEq)]
pub struct Tarball {
    /// The `package.json` npm installs, as an object.
    pub package_json: Map<String, Value>,
    /// Its `name`.
    pub name: String,
    /// Its `version`, as written.
    pub version: String,
    /// Files in the archive (`dist.fileCount`).
    pub file_count: u64,
    /// Their unpacked size (`dist.unpackedSize`).
    pub unpacked_size: u64,
}

/// The path an entry named `raw` unpacks to with `strip: 1`, as components.
fn stripped(raw: &[u8]) -> Vec<&[u8]> {
    let mut parts = raw
        .split(|b| *b == b'/' || *b == b'\\')
        .filter(|part| !part.is_empty() && *part != b".");
    parts.next();
    parts.collect()
}

/// Read the data of `entry`, a GNU long name or a PAX extended header of
/// `size` bytes, refusing one larger than [`MAX_HEADER_ENTRY_BYTES`].
fn header_entry(entry: &mut impl Read, size: u64, what: &str) -> Result<Vec<u8>, String> {
    if size > MAX_HEADER_ENTRY_BYTES {
        return Err(format!(
            "the tarball's {what} is larger than {MAX_HEADER_ENTRY_BYTES} bytes"
        ));
    }
    let mut data = Vec::with_capacity(size as usize);
    entry
        .read_to_end(&mut data)
        .map_err(|e| format!("unreadable {what}: {e}"))?;
    Ok(data)
}

/// The `path` and `size` records of the PAX header `data` (the last of each,
/// as node-tar reads them).
fn pax(data: &[u8]) -> Result<(Option<Vec<u8>>, Option<u64>), String> {
    let (mut path, mut size) = (None, None);
    for record in tar::PaxExtensions::new(data).flatten() {
        match record.key_bytes() {
            b"path" => path = Some(record.value_bytes().to_vec()),
            b"size" => {
                let value = std::str::from_utf8(record.value_bytes()).ok();
                size = Some(
                    value
                        .and_then(|v| v.parse().ok())
                        .ok_or("the tarball's PAX header has an unreadable size")?,
                );
            }
            _ => {}
        }
    }
    Ok((path, size))
}

/// Read the gzip-compressed tarball in `tgz`, refusing one that unpacks to
/// more than `max_unpacked` bytes or holds no `package.json` npm would read.
///
/// The entries are read raw: `tar` would read a GNU long name or a PAX
/// extended header whole, unbounded, before it hands back the entry it
/// names. They are read here instead, bounded ([`header_entry`]) and counted
/// against `max_unpacked` like any entry, and the path they give the next
/// entry is applied as npm (node-tar) applies it: the later one wins, old
/// forms included. A PAX `size` that is not the next entry's own is
/// refused (an npm tarball is far below the 8 GiB a header holds, so the
/// record only ever disagrees), as are a global one and a GNU sparse entry:
/// each would lay the archive out otherwise than its headers do.
pub fn read(tgz: impl Read, max_unpacked: u64) -> Result<Tarball, String> {
    let gz = flate2::read::GzDecoder::new(tgz);
    let mut archive = tar::Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|e| format!("not a gzip-compressed tar archive: {e}"))?
        .raw(true);
    let mut package_json: Option<Vec<u8>> = None;
    let mut file_count = 0u64;
    let mut unpacked = 0u64;
    // What a GNU long name or a PAX header says of the next entry.
    let mut next_path: Option<Vec<u8>> = None;
    let mut next_size: Option<u64> = None;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("unreadable tar entry: {e}"))?;
        let size = entry.header().entry_size().unwrap_or(0);
        unpacked = unpacked.saturating_add(size);
        if unpacked > max_unpacked {
            return Err(format!(
                "the tarball unpacks to more than {max_unpacked} bytes"
            ));
        }
        let kind = entry.header().entry_type();
        // The entries node-tar reads as describing the next one.
        match kind.as_byte() {
            // A GNU long name (`N` in its old form) names the next entry.
            b'L' | b'N' => {
                let mut name = header_entry(&mut entry, size, "GNU long name")?;
                name.truncate(name.iter().position(|b| *b == 0).unwrap_or(name.len()));
                next_path = Some(name);
                continue;
            }
            // A PAX extended header (`X` in its old form) names the next
            // entry and may give its size.
            b'x' | b'X' => {
                let (path, size) = pax(&header_entry(&mut entry, size, "PAX header")?)?;
                next_path = path.or(next_path);
                next_size = size.or(next_size);
                continue;
            }
            // A PAX global header: node-tar takes no path from it, but a
            // size for every later entry.
            b'g' => {
                if pax(&header_entry(&mut entry, size, "PAX global header")?)?
                    .1
                    .is_some()
                {
                    return Err("the tarball's PAX global header gives entries a size".into());
                }
                continue;
            }
            // A long link name names no path npm reads.
            b'K' => continue,
            b'S' => return Err("the tarball holds a GNU sparse entry".into()),
            _ => {}
        }
        if next_size.take().is_some_and(|pax| pax != size) {
            return Err("the tarball's PAX header gives an entry another size than its own".into());
        }
        let path = next_path
            .take()
            .unwrap_or_else(|| entry.path_bytes().into_owned());
        if !(kind.is_file() || kind.is_contiguous()) {
            continue;
        }
        file_count += 1;
        if stripped(&path) == [b"package.json".as_slice()] {
            if size > MAX_PACKAGE_JSON_BYTES {
                return Err(format!(
                    "package.json is larger than {MAX_PACKAGE_JSON_BYTES} bytes"
                ));
            }
            let mut data = Vec::with_capacity(size as usize);
            (&mut entry)
                .take(MAX_PACKAGE_JSON_BYTES + 1)
                .read_to_end(&mut data)
                .map_err(|e| format!("unreadable package.json: {e}"))?;
            package_json = Some(data);
        }
        // The rest of the entry's data is skipped by the archive reader,
        // which still inflates it: what the size bound above is for.
    }
    let data = package_json.ok_or("the tarball holds no package/package.json")?;
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&data);
    let package_json: Map<String, Value> = match serde_json::from_slice(data) {
        Ok(Value::Object(map)) => map,
        Ok(_) => return Err("package.json is not a JSON object".into()),
        Err(e) => return Err(format!("package.json is not valid JSON: {e}")),
    };
    let field = |key: &str| {
        package_json
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("package.json has no {key:?}"))
    };
    let name = field("name")?;
    let version = field("version")?;
    Ok(Tarball {
        package_json,
        name,
        version,
        file_count,
        unpacked_size: unpacked,
    })
}

/// Build a gzip-compressed tarball of `entries` (path, contents), for tests.
#[doc(hidden)]
pub fn build(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, path, *data)
            .expect("append tar entry");
    }
    let tar = builder.into_inner().expect("finish tar");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar).expect("gzip");
    gz.finish().expect("finish gzip")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_package_json_npm_installs() {
        let tgz = build(&[
            ("package/package.json", br#"{"name":"a","version":"1.0.0"}"#),
            ("package/index.js", b"module.exports = 1"),
            ("package/lib/package.json", br#"{"name":"nested"}"#),
        ]);
        let t = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.version.as_str()), ("a", "1.0.0"));
        assert_eq!(t.file_count, 3);

        // Any top-level directory; the last entry wins.
        let tgz = build(&[
            (
                "node-uuid/package.json",
                br#"{"name":"first","version":"1.0.0"}"#,
            ),
            (
                "./package/package.json",
                "\u{feff}{\"name\":\"last\",\"version\":\"2.0.0\"}".as_bytes(),
            ),
        ]);
        let t = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.version.as_str()), ("last", "2.0.0"));
    }

    #[test]
    fn refuses_what_npm_would_not_install() {
        let none = build(&[("package.json", br#"{"name":"a","version":"1.0.0"}"#)]);
        assert!(read(&none[..], DEFAULT_MAX_UNPACKED_BYTES).is_err());
        let not_json = build(&[("package/package.json", b"name: a")]);
        assert!(read(&not_json[..], DEFAULT_MAX_UNPACKED_BYTES).is_err());
        let no_version = build(&[("package/package.json", br#"{"name":"a"}"#)]);
        assert!(read(&no_version[..], DEFAULT_MAX_UNPACKED_BYTES).is_err());
        assert!(read(&b"not gzip"[..], DEFAULT_MAX_UNPACKED_BYTES).is_err());
        let big = build(&[
            ("package/package.json", br#"{"name":"a","version":"1.0.0"}"#),
            ("package/blob", &[0u8; 4096]),
        ]);
        let err = read(&big[..], 1024).unwrap_err();
        assert!(err.contains("unpacks to more than"), "{err}");
    }

    /// Append an entry of `kind` named `name` to the uncompressed `tar`: a
    /// header that says `size`, then `data` (which may be shorter).
    fn raw_entry(tar: &mut Vec<u8>, name: &str, kind: u8, size: u64, data: &[u8]) {
        let mut header = tar::Header::new_ustar();
        header.set_path(name).expect("short name");
        header.set_size(size);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::new(kind));
        header.set_cksum();
        tar.extend_from_slice(header.as_bytes());
        tar.extend_from_slice(data);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }

    /// `tar` ended and gzip-compressed.
    fn finish(mut tar: Vec<u8>) -> Vec<u8> {
        tar.extend_from_slice(&[0; 1024]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).expect("gzip");
        gz.finish().expect("finish gzip")
    }

    /// A PAX record, `<length> <key>=<value>\n`, its length counting itself.
    fn pax_record(key: &str, value: &str) -> String {
        let rest = format!(" {key}={value}\n");
        let mut len = rest.len();
        while rest.len() + len.to_string().len() != len {
            len = rest.len() + len.to_string().len();
        }
        format!("{len}{rest}")
    }

    const PACKAGE_JSON: &[u8] = br#"{"name":"a","version":"1.0.0"}"#;

    #[test]
    fn reads_every_entry_npm_unpacks_as_a_file() {
        // A regular file, in its current and its old form, and a contiguous
        // file: the later one is the package.json npm installs.
        let later = br#"{"name":"b","version":"2.0.0"}"#;
        for kind in *b"0\x007" {
            let mut tar = Vec::new();
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            raw_entry(&mut tar, "package/package.json", kind, 30, later);
            let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
            assert_eq!((t.name.as_str(), t.file_count), ("b", 2), "{kind}");
        }

        // What npm does not unpack as a file is neither read nor counted.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        raw_entry(&mut tar, "package/package.json", b'6', 30, later);
        let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.file_count), ("a", 1));
    }

    #[test]
    fn long_names_and_pax_headers_are_read_bounded() {
        let huge = 8 * 1024 * 1024 * 1024;
        for kind in *b"LNxXg" {
            // An 8 GiB header entry (cut short: it is never read): past the
            // unpack bound, and past the header cap under a bigger one.
            let mut tar = Vec::new();
            raw_entry(&mut tar, "././@LongLink", kind, huge, &[0; 512]);
            let tgz = finish(tar);
            let err = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains("unpacks to more than"), "{err}");
            let err = read(&tgz[..], 2 * huge).unwrap_err();
            assert!(err.contains("larger than 65536 bytes"), "{err}");

            // One byte over the cap, all there.
            let mut tar = Vec::new();
            let over = vec![b'a'; MAX_HEADER_ENTRY_BYTES as usize + 1];
            raw_entry(&mut tar, "././@LongLink", kind, over.len() as u64, &over);
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains("larger than 65536 bytes"), "{err}");
        }
    }

    #[test]
    fn long_names_and_pax_paths_name_the_next_entry_as_npm_reads_it() {
        // What `tar` writes for a path over 100 bytes: a GNU long name.
        let long = format!("package/{}/index.js", "d".repeat(150));
        let tgz = build(&[
            (long.as_str(), b"module.exports = 1"),
            ("package/package.json", PACKAGE_JSON),
        ]);
        let t = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.file_count), ("a", 2));

        let pax_path = pax_record("path", "package/package.json");
        let other = pax_record("path", "package/other.json");
        let named: [&[(&str, u8, &[u8])]; 5] = [
            // A GNU long name, in its current and its old form.
            &[("././@LongLink", b'L', b"package/package.json\0")],
            &[("././@LongLink", b'N', b"package/package.json")],
            // A PAX path, in its current and its old form.
            &[("PaxHeaders/x", b'x', pax_path.as_bytes())],
            &[("PaxHeaders/x", b'X', pax_path.as_bytes())],
            // The later of the two wins, and a long link names nothing.
            &[
                ("PaxHeaders/x", b'x', other.as_bytes()),
                ("././@LongLink", b'L', b"package/package.json"),
                ("././@LongLink", b'K', b"target"),
            ],
        ];
        for headers in named {
            let mut tar = Vec::new();
            for (name, kind, data) in headers {
                raw_entry(&mut tar, name, *kind, data.len() as u64, data);
            }
            raw_entry(&mut tar, "package/x", b'0', 30, PACKAGE_JSON);
            let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES)
                .unwrap_or_else(|e| panic!("{headers:?}: {e}"));
            assert_eq!((t.name.as_str(), t.file_count), ("a", 1), "{headers:?}");
        }

        // A name applies to the next entry only.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "././@LongLink", b'L', 20, b"package/package.json");
        raw_entry(&mut tar, "package/dir", b'5', 0, &[]);
        raw_entry(&mut tar, "package/x", b'0', 30, PACKAGE_JSON);
        let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
        assert!(err.contains("no package/package.json"), "{err}");
    }

    #[test]
    fn refuses_an_archive_laid_out_otherwise_than_its_headers() {
        let size_of = |n: usize| pax_record("size", &n.to_string());
        let same = size_of(PACKAGE_JSON.len());
        let mut tar = Vec::new();
        raw_entry(
            &mut tar,
            "PaxHeaders/x",
            b'x',
            same.len() as u64,
            same.as_bytes(),
        );
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        assert!(read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).is_ok());

        let refused: [(&str, u8, String, &str); 4] = [
            ("PaxHeaders/x", b'x', size_of(8 * 1024), "another size"),
            (
                "PaxHeaders/x",
                b'x',
                pax_record("size", "lots"),
                "unreadable size",
            ),
            ("PaxHeaders/g", b'g', same.clone(), "global header"),
            ("package/sparse", b'S', String::new(), "sparse"),
        ];
        for (name, kind, data, why) in refused {
            let mut tar = Vec::new();
            raw_entry(&mut tar, name, kind, data.len() as u64, data.as_bytes());
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains(why), "{name}: {err}");
        }
    }
}
