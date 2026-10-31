//! Proxies of an apt repository (a Debian or Ubuntu mirror): every file is
//! the upstream's, at `<remote_url>/<path>`, served as it is, so clients
//! verify the upstream's signatures with the upstream's keys.
//!
//! * `dists/<distribution>/…` (the distribution the proxy is for): the
//!   indexes, re-validated once the repository's metadata TTL has passed;
//!   their `by-hash` copies never change.
//! * `pool/…`: packages, which never change at their path. Before a
//!   package is cached the host checks it against the size and SHA-256 the
//!   upstream's `Packages` index of its component and architecture gives it
//!   (`Packages.gz`, else `.xz`, else the plain one), when there is such an
//!   index and it lists the file.

use std::io::{BufRead, BufReader, Read};

use forge_plugin_api::{
    Fetch, FetchResult, Fetched, FileLocation, Freshness, Remote, UpstreamAnswer, UpstreamStep,
};

use crate::layout::{self, Target};

/// The most an index may inflate to while it is searched.
const MAX_INDEX_BYTES: u64 = 1024 * 1024 * 1024;

/// The upstream URL of `path`: `remote_url` (as a directory) with the path's
/// segments appended, each percent-encoded.
pub fn upstream_url(remote_url: &str, path: &str) -> Option<String> {
    let mut url = url::Url::parse(remote_url).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    {
        let mut segments = url.path_segments_mut().ok()?;
        segments.pop_if_empty();
        for segment in path.split('/') {
            segments.push(segment);
        }
    }
    Some(url.into())
}

/// The answer to the upstream operation `file(path)`, round by round.
pub fn file(remote: &Remote, path: &str, fetched: &[FetchResult]) -> UpstreamStep {
    let Some(url) = upstream_url(&remote.url, path) else {
        return UpstreamStep::Done(UpstreamAnswer::File(None));
    };
    let mut location = FileLocation::at(url);
    match layout::parse(path) {
        Ok(Target::Dists { rest, .. }) => {
            location.immutable = layout::is_by_hash(&rest);
            location.sha256 = layout::by_hash_sha256(&rest);
        }
        Ok(Target::Pool(pool)) => {
            location.immutable = true;
            if let (Some(deb), Some(distribution)) =
                (layout::deb_name(&pool.file), remote.option("distribution"))
            {
                let dir = format!(
                    "dists/{distribution}/{}/binary-{}",
                    pool.component, deb.architecture
                );
                match listed(remote, &dir, path, fetched) {
                    Lookup::Fetch(fetch) => return UpstreamStep::Fetch(vec![fetch]),
                    Lookup::Found { size, sha256 } => {
                        location.size = size;
                        location.sha256 = sha256;
                    }
                    Lookup::Unknown => {}
                }
            }
        }
        // The plugin asks for nothing else.
        _ => return UpstreamStep::Done(UpstreamAnswer::File(None)),
    }
    UpstreamStep::Done(UpstreamAnswer::FileAt(location))
}

enum Lookup {
    Fetch(Fetch),
    Found {
        size: Option<u64>,
        sha256: Option<String>,
    },
    Unknown,
}

/// What the `Packages` index in `dir` says of the file at `path`: the next
/// index to fetch, the file's size and digest, or nothing (no index, or the
/// index does not list the file).
fn listed(remote: &Remote, dir: &str, path: &str, fetched: &[FetchResult]) -> Lookup {
    for name in ["Packages.gz", "Packages.xz", "Packages"] {
        let Some(url) = upstream_url(&remote.url, &format!("{dir}/{name}")) else {
            return Lookup::Unknown;
        };
        match fetched.iter().find(|f| f.fetch.url == url) {
            None => return Lookup::Fetch(Fetch::new(url, Freshness::Metadata)),
            Some(FetchResult {
                outcome: Fetched::Found(body),
                ..
            }) => {
                return match find(body, path) {
                    Some((size, sha256)) => Lookup::Found { size, sha256 },
                    None => Lookup::Unknown,
                }
            }
            // Not there: the next compression.
            Some(FetchResult {
                outcome: Fetched::NotFound,
                ..
            }) => {}
            // Unavailable or too large: unverified, as apt verifies.
            Some(_) => return Lookup::Unknown,
        }
    }
    Lookup::Unknown
}

/// The size and SHA-256 an index (gzip, xz or plain, as its first bytes
/// say) gives the file at `path`, read as a stream.
pub fn find(index: &[u8], path: &str) -> Option<(Option<u64>, Option<String>)> {
    let reader: Box<dyn Read + '_> = if index.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::MultiGzDecoder::new(index))
    } else if index.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Box::new(lzma_rust2::XzReader::new(index, true))
    } else {
        Box::new(index)
    };
    let reader = BufReader::new(reader.take(MAX_INDEX_BYTES));
    let (mut filename, mut size, mut sha256) = (None::<String>, None, None);
    for line in reader.split(b'\n') {
        let line = line.ok()?;
        let line = line.strip_suffix(b"\r").unwrap_or(&line);
        if line.iter().all(u8::is_ascii_whitespace) {
            if filename.as_deref() == Some(path) {
                return Some((size, sha256));
            }
            (filename, size, sha256) = (None, None, None);
            continue;
        }
        let Some((name, value)) = std::str::from_utf8(line)
            .ok()
            .and_then(|line| line.split_once(':'))
        else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Filename") {
            filename = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("Size") {
            size = value.parse().ok();
        } else if name.eq_ignore_ascii_case("SHA256") {
            sha256 = (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| value.to_ascii_lowercase());
        }
    }
    (filename.as_deref() == Some(path)).then_some((size, sha256))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const INDEX: &str =
        "Package: a\nFilename: pool/main/a/a/a_1_amd64.deb\nSize: 10\nSHA256: AAAA\n\n\
        Package: hello\nVersion: 1.0\nFilename: pool/main/h/hello/hello_1.0_amd64.deb\nSize: 42\n\
        SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ABCDEF\n";

    #[test]
    fn indexes_are_searched_in_every_compression() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(INDEX.as_bytes()).unwrap();
        let gz = gz.finish().unwrap();
        let mut xz =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
        xz.write_all(INDEX.as_bytes()).unwrap();
        let xz = xz.finish().unwrap();
        for index in [INDEX.as_bytes().to_vec(), gz, xz] {
            assert_eq!(
                find(&index, "pool/main/h/hello/hello_1.0_amd64.deb"),
                Some((
                    Some(42),
                    Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into())
                ))
            );
            // A malformed digest is no digest.
            assert_eq!(
                find(&index, "pool/main/a/a/a_1_amd64.deb"),
                Some((Some(10), None))
            );
            assert_eq!(find(&index, "pool/main/x/x/x_1_amd64.deb"), None);
        }
    }

    fn remote() -> Remote {
        let mut remote = Remote::new("http://deb.example.test/debian");
        remote
            .options
            .push(("distribution".into(), "bookworm".into()));
        remote
    }

    #[test]
    fn index_files_are_the_upstreams() {
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) =
            file(&remote(), "dists/bookworm/InRelease", &[])
        else {
            panic!()
        };
        assert_eq!(
            at.url,
            "http://deb.example.test/debian/dists/bookworm/InRelease"
        );
        assert!(!at.immutable);
        let hash = "c".repeat(64);
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) = file(
            &remote(),
            &format!("dists/bookworm/main/binary-amd64/by-hash/SHA256/{hash}"),
            &[],
        ) else {
            panic!()
        };
        assert!(at.immutable);
        assert_eq!(at.sha256, Some(hash));
    }

    #[test]
    fn packages_are_checked_against_the_index() {
        let path = "pool/main/h/hello/hello_1.0_amd64.deb";
        let UpstreamStep::Fetch(fetches) = file(&remote(), path, &[]) else {
            panic!()
        };
        assert_eq!(
            fetches[0].url,
            "http://deb.example.test/debian/dists/bookworm/main/binary-amd64/Packages.gz"
        );
        let result = |url: &str, outcome| FetchResult {
            fetch: Fetch::new(url, Freshness::Metadata),
            outcome,
            status: None,
            headers: Vec::new(),
        };
        // No .gz: the .xz is next, then the plain index.
        let gz = result(&fetches[0].url, Fetched::NotFound);
        let UpstreamStep::Fetch(next) = file(&remote(), path, std::slice::from_ref(&gz)) else {
            panic!()
        };
        assert!(next[0].url.ends_with("/Packages.xz"));
        let xz = result(&next[0].url, Fetched::NotFound);
        let UpstreamStep::Fetch(next) = file(&remote(), path, &[gz.clone(), xz.clone()]) else {
            panic!()
        };
        assert!(next[0].url.ends_with("/Packages"));
        let plain = result(&next[0].url, Fetched::Found(INDEX.as_bytes().to_vec()));
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) =
            file(&remote(), path, &[gz, xz, plain])
        else {
            panic!()
        };
        assert!(at.immutable);
        assert_eq!(at.size, Some(42));
        assert!(at.sha256.is_some());
        // An index that is down leaves the package to apt's own check.
        let down = result(&fetches[0].url, Fetched::Failed("503".into()));
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) = file(&remote(), path, &[down]) else {
            panic!()
        };
        assert_eq!((at.size, at.sha256), (None, None));
    }

    #[test]
    fn urls_append_encoded_segments() {
        assert_eq!(
            upstream_url(
                "http://up.test/debian/",
                "pool/main/h/hello/hello_1:2.0_amd64.deb"
            )
            .unwrap(),
            "http://up.test/debian/pool/main/h/hello/hello_1:2.0_amd64.deb"
        );
        assert_eq!(upstream_url("ftp://up.test/", "x"), None);
    }
}
