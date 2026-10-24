//! Reading a package tarball the way npm installs it.
//!
//! npm (pacote) unpacks a tarball with `strip: 1`: the first component of
//! every path is dropped, whatever it is called (`package/` by convention),
//! so the package's `package.json` is any entry at depth one. When several
//! entries map to it, the last one wins on disk, so the last one is read.
//! The whole archive is read, bounded in what it unpacks to.

use std::io::Read;

use serde_json::{Map, Value};

/// The most a tarball may unpack to by default: 1 GiB.
pub const DEFAULT_MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;

/// The largest `package.json` read.
pub const MAX_PACKAGE_JSON_BYTES: u64 = 8 * 1024 * 1024;

/// What a tarball holds, as far as the registry cares.
#[derive(Debug, Clone, PartialEq)]
pub struct Tarball {
    /// The `package.json` npm installs, as an object.
    pub package_json: Map<String, Value>,
    /// Its `name`.
    pub name: String,
    /// Its `version`, as written.
    pub version: String,
    /// Regular files in the archive (`dist.fileCount`).
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

/// Read the gzip-compressed tarball in `tgz`, refusing one that unpacks to
/// more than `max_unpacked` bytes or holds no `package.json` npm would read.
pub fn read(tgz: impl Read, max_unpacked: u64) -> Result<Tarball, String> {
    let gz = flate2::read::GzDecoder::new(tgz);
    let mut archive = tar::Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|e| format!("not a gzip-compressed tar archive: {e}"))?;
    let mut package_json: Option<Vec<u8>> = None;
    let mut file_count = 0u64;
    let mut unpacked = 0u64;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("unreadable tar entry: {e}"))?;
        let size = entry.header().entry_size().unwrap_or(0);
        unpacked = unpacked.saturating_add(size);
        if unpacked > max_unpacked {
            return Err(format!(
                "the tarball unpacks to more than {max_unpacked} bytes"
            ));
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }
        file_count += 1;
        let path = entry.path_bytes().into_owned();
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
}
