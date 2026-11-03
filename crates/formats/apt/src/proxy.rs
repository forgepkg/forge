//! Proxies of an apt repository (a Debian or Ubuntu mirror): every file is
//! the upstream's, at `<remote_url>/<path>`, served as it is, so clients
//! verify the upstream's signatures with the upstream's keys.
//!
//! * `dists/<distribution>/…` (the distribution the proxy is for): the
//!   indexes, re-validated once the repository's metadata TTL has passed.
//!   A `by-hash/<type>/<digest>` copy (`MD5Sum`, `SHA1`, `SHA256` or
//!   `SHA512`) is checked against the digest its path names, and never
//!   changes once it matched.
//!   The indexes but those copies are kept consistent with the
//!   distribution's `InRelease` and `Release` ([`releases`],
//!   [`listed_in`]): an upstream without `Acquire-By-Hash` has apt fetch
//!   them at their own path, and checks each against the `InRelease` it
//!   was served.
//! * `pool/…`: packages, which never change at their path. Before a
//!   package is cached the host checks it against the size and SHA-256 the
//!   upstream's `Packages` index of its component and architecture gives it
//!   (`Packages.gz`, else `.xz`, else the plain one), when there is such an
//!   index and it lists the file. The component is the pool directory's
//!   last before the name's prefix: `main` for the Debian security
//!   archive's `pool/updates/main/o/openssl/…`, which
//!   `dists/<distribution>/main/binary-<arch>/Packages` lists.
//!
//! Only a file so checked is kept as immutable. One the host could not
//! check (no index lists it, the index could not be fetched, Ubuntu's
//! `_all` packages without a `binary-all` index) is cached as an index is,
//! and re-validated once the metadata TTL has passed: a wrong copy is not
//! kept for good.

use std::io::{BufRead, BufReader, Read};

use forge_format_api::{
    Fetch, FetchResult, Fetched, FileLocation, Freshness, Remote, UpstreamAnswer, UpstreamStep,
};

use forge_format_api::ListedFile;

use crate::import::{cleartext, Release};
use crate::layout::{self, HashType, Target};

/// The most an index may inflate to while it is searched.
const MAX_INDEX_BYTES: u64 = 1024 * 1024 * 1024;

/// The longest line of an index that is searched, its line break aside: far
/// above any real `Packages` line (a long `Description` or `Depends` runs to
/// a few KiB). An index with a longer line is not searched.
const MAX_LINE_BYTES: usize = 256 * 1024;

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
            if let Some((kind, digest)) = layout::by_hash_digest(&rest) {
                let field = match kind {
                    HashType::Md5 => &mut location.md5,
                    HashType::Sha1 => &mut location.sha1,
                    HashType::Sha256 => &mut location.sha256,
                    HashType::Sha512 => &mut location.sha512,
                };
                *field = Some(digest);
                location.immutable = true;
            }
        }
        Ok(Target::Pool(pool)) => {
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
                        // Kept for good only once both are checked.
                        location.immutable = size.is_some() && sha256.is_some();
                        location.size = size;
                        location.sha256 = sha256;
                    }
                    Lookup::Unknown => {}
                }
            }
        }
        // The format asks for nothing else.
        _ => return UpstreamStep::Done(UpstreamAnswer::File(None)),
    }
    UpstreamStep::Done(UpstreamAnswer::FileAt(location))
}

/// The files a cached file of the distribution is kept consistent with:
/// for every file under `dists/<distribution>/` but its `by-hash` copies,
/// the distribution's `InRelease` (what apt reads first) and `Release`,
/// the file itself aside.
pub fn releases(path: &str) -> Vec<String> {
    let Ok(Target::Dists {
        distribution, rest, ..
    }) = layout::parse(path)
    else {
        return Vec::new();
    };
    if layout::is_by_hash(&rest) {
        return Vec::new();
    }
    ["InRelease", "Release"]
        .into_iter()
        .filter(|name| rest != *name)
        .map(|name| format!("dists/{distribution}/{name}"))
        .collect()
}

/// The size and SHA-256 that `release` (the content of `release_path`, an
/// `InRelease` or a `Release` of [`releases`]`(path)`) lists for `path`.
pub fn listed_in(release_path: &str, release: &[u8], path: &str) -> Option<ListedFile> {
    let (dir, name) = release_path.rsplit_once('/')?;
    let rest = path.strip_prefix(dir)?.strip_prefix('/')?;
    let text = std::str::from_utf8(release).ok()?;
    let text = match name {
        "InRelease" => cleartext(text).ok()?,
        "Release" => text.to_string(),
        _ => return None,
    };
    let listed = Release::parse(&text).ok()?.files.remove(rest)?;
    Some(ListedFile {
        size: listed.size,
        sha256: listed.sha256,
    })
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
    search(reader, path, &mut Vec::with_capacity(MAX_LINE_BYTES + 1))
}

/// What reading one line of an index gave.
enum Line {
    /// A line, in the buffer without its line break.
    Read,
    /// The index has ended.
    End,
    /// The line is longer than [`MAX_LINE_BYTES`] (or the index cannot be
    /// read); what is in the buffer is no line.
    Unusable,
}

/// Reads the next line of `reader` into `line`, holding at most
/// [`MAX_LINE_BYTES`] and a byte more of it whatever its length.
fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> Line {
    line.clear();
    let limit = MAX_LINE_BYTES as u64 + 1;
    match reader.by_ref().take(limit).read_until(b'\n', line) {
        Ok(0) => Line::End,
        Ok(_) if line.last() == Some(&b'\n') => {
            line.pop();
            Line::Read
        }
        // No line break within the bound: the index's last line, or one
        // that is too long.
        Ok(n) if n <= MAX_LINE_BYTES => Line::Read,
        Ok(_) | Err(_) => Line::Unusable,
    }
}

/// [`find`] in an inflated index, read a line at a time into `line`.
fn search(
    mut reader: impl BufRead,
    path: &str,
    line: &mut Vec<u8>,
) -> Option<(Option<u64>, Option<String>)> {
    let (mut filename, mut size, mut sha256) = (None::<String>, None, None);
    loop {
        match read_line(&mut reader, line) {
            Line::Read => {}
            Line::End => break,
            Line::Unusable => return None,
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
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

    /// `len` bytes of `a`, without a line break, made as they are read.
    struct Endless {
        left: u64,
        read: u64,
    }

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.left as usize);
            buf[..n].fill(b'a');
            self.left -= n as u64;
            self.read += n as u64;
            Ok(n)
        }
    }

    #[test]
    fn an_index_with_a_line_past_the_bound_is_given_up_on() {
        let mut index = Endless {
            left: 64 * 1024 * 1024,
            read: 0,
        };
        // As `find` gives it.
        let mut line = Vec::with_capacity(MAX_LINE_BYTES + 1);
        let reader = BufReader::new(&mut index);
        let capacity = reader.capacity() as u64;
        assert_eq!(
            search(reader, "pool/main/h/hello/hello_1.0_amd64.deb", &mut line),
            None
        );
        // No more than the bound was held, or read.
        assert!(line.capacity() <= MAX_LINE_BYTES + 1, "{}", line.capacity());
        assert!(
            index.read <= MAX_LINE_BYTES as u64 + 1 + capacity,
            "{}",
            index.read
        );

        // A stanza after the long line is not searched either.
        let long = format!("X-Long: {}\n\n{INDEX}", "a".repeat(MAX_LINE_BYTES));
        assert_eq!(
            find(long.as_bytes(), "pool/main/h/hello/hello_1.0_amd64.deb"),
            None
        );
    }

    #[test]
    fn a_stanza_after_a_long_line_within_the_bound_is_found() {
        // The line, its line break (`\r\n`) aside, is as long as may be.
        let field = "X-Long: ";
        let long = format!(
            "Package: z\n{field}{}\r\n\n{INDEX}",
            "a".repeat(MAX_LINE_BYTES - field.len() - 1)
        );
        assert_eq!(
            find(long.as_bytes(), "pool/main/h/hello/hello_1.0_amd64.deb"),
            Some((
                Some(42),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into())
            ))
        );
        // A last line without a line break, as long as may be, is a line.
        let last = format!(
            "{}{field}{}",
            INDEX.replace("Size: 42\n", ""),
            "a".repeat(MAX_LINE_BYTES - field.len())
        );
        assert_eq!(
            find(last.as_bytes(), "pool/main/h/hello/hello_1.0_amd64.deb"),
            Some((
                None,
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into())
            ))
        );
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
        // Every hash type apt asks for is checked against its digest (#760).
        for (name, len) in [("MD5Sum", 32), ("SHA1", 40), ("SHA512", 128)] {
            let hash = "e".repeat(len);
            let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) = file(
                &remote(),
                &format!("dists/bookworm/main/binary-amd64/by-hash/{name}/{hash}"),
                &[],
            ) else {
                panic!()
            };
            assert!(at.immutable, "{name}");
            let given = match name {
                "MD5Sum" => &at.md5,
                "SHA1" => &at.sha1,
                _ => &at.sha512,
            };
            assert_eq!(given.as_deref(), Some(hash.as_str()), "{name}");
            assert_eq!(at.sha256, None);
        }
        // A copy whose name is no digest of its type is not kept for good.
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) = file(
            &remote(),
            &format!(
                "dists/bookworm/main/binary-amd64/by-hash/SHA512/{}",
                "e".repeat(64)
            ),
            &[],
        ) else {
            panic!()
        };
        assert!(!at.immutable);
        assert!(!at.has_digest());
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
        // An index that is down leaves the package to apt's own check, and
        // the copy is re-validated, not kept for good (#760).
        let down = result(&fetches[0].url, Fetched::Failed("503".into()));
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) = file(&remote(), path, &[down]) else {
            panic!()
        };
        assert_eq!((at.size, at.sha256), (None, None));
        assert!(!at.immutable);
        // So does an index that does not list the package, or lists it
        // without a usable digest.
        let index = result(&fetches[0].url, Fetched::Found(INDEX.as_bytes().to_vec()));
        for path in ["pool/main/x/x/x_1_amd64.deb", "pool/main/a/a/a_1_amd64.deb"] {
            let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) =
                file(&remote(), path, std::slice::from_ref(&index))
            else {
                panic!()
            };
            assert!(!at.immutable, "{path}");
        }
        // No index anywhere (Ubuntu's `binary-all`).
        let gone: Vec<_> = ["Packages.gz", "Packages.xz", "Packages"]
            .iter()
            .map(|name| {
                result(
                    &format!(
                        "http://deb.example.test/debian/dists/bookworm/main/binary-amd64/{name}"
                    ),
                    Fetched::NotFound,
                )
            })
            .collect();
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) = file(&remote(), path, &gone) else {
            panic!()
        };
        assert!(!at.immutable);
        // A package the format cannot place in an index.
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) =
            file(&remote(), "pool/main/h/hello/README", &[])
        else {
            panic!()
        };
        assert!(!at.immutable);
    }

    #[test]
    fn security_archive_packages_are_checked_against_their_components_index() {
        // security.debian.org: `Filename: pool/updates/main/…`, listed in
        // `dists/bookworm-security/main/binary-amd64/Packages`.
        let mut remote = Remote::new("http://security.example.test/debian-security");
        remote
            .options
            .push(("distribution".into(), "bookworm-security".into()));
        let path = "pool/updates/main/o/openssl/libssl3_3.0.17-1~deb12u3_amd64.deb";
        let UpstreamStep::Fetch(fetches) = file(&remote, path, &[]) else {
            panic!()
        };
        assert_eq!(
            fetches[0].url,
            "http://security.example.test/debian-security/dists/bookworm-security/main/binary-amd64/Packages.gz"
        );
        let index = format!(
            "Package: libssl3\nFilename: {path}\nSize: 7\nSHA256: {}\n",
            "d".repeat(64)
        );
        let found = FetchResult {
            fetch: Fetch::new(&fetches[0].url, Freshness::Metadata),
            outcome: Fetched::Found(index.into_bytes()),
            status: None,
            headers: Vec::new(),
        };
        let UpstreamStep::Done(UpstreamAnswer::FileAt(at)) = file(&remote, path, &[found]) else {
            panic!()
        };
        assert_eq!(
            at.url,
            format!("http://security.example.test/debian-security/{path}")
        );
        assert!(at.immutable);
        assert_eq!((at.size, at.sha256), (Some(7), Some("d".repeat(64))));
    }

    #[test]
    fn index_files_are_kept_consistent_with_the_release() {
        assert_eq!(
            releases("dists/bookworm/main/binary-amd64/Packages.gz"),
            ["dists/bookworm/InRelease", "dists/bookworm/Release"]
        );
        assert_eq!(
            releases("dists/bookworm/Release.gpg"),
            ["dists/bookworm/InRelease", "dists/bookworm/Release"]
        );
        // Each of the two with the other.
        assert_eq!(
            releases("dists/bookworm/InRelease"),
            ["dists/bookworm/Release"]
        );
        assert_eq!(
            releases("dists/bookworm/Release"),
            ["dists/bookworm/InRelease"]
        );
        // Content-addressed copies and packages never change.
        let hash = "c".repeat(64);
        assert!(releases(&format!(
            "dists/bookworm/main/binary-amd64/by-hash/SHA256/{hash}"
        ))
        .is_empty());
        assert!(releases("pool/main/h/hello/hello_1.0_amd64.deb").is_empty());

        let release = format!(
            "Origin: Acme\nSuite: bookworm\nSHA256:\n {} 42 main/binary-amd64/Packages.gz\n",
            "A".repeat(64)
        );
        let path = "dists/bookworm/main/binary-amd64/Packages.gz";
        let listed = ListedFile {
            size: 42,
            sha256: "a".repeat(64),
        };
        assert_eq!(
            listed_in("dists/bookworm/Release", release.as_bytes(), path),
            Some(listed.clone())
        );
        let in_release = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n{release}\
             -----BEGIN PGP SIGNATURE-----\n\nxyz\n-----END PGP SIGNATURE-----\n"
        );
        assert_eq!(
            listed_in("dists/bookworm/InRelease", in_release.as_bytes(), path),
            Some(listed)
        );
        // Not listed, another distribution's, or no InRelease.
        let unlisted = "dists/bookworm/main/binary-arm64/Packages.gz";
        assert_eq!(
            listed_in("dists/bookworm/Release", release.as_bytes(), unlisted),
            None
        );
        assert_eq!(
            listed_in(
                "dists/trixie/Release",
                release.as_bytes(),
                "dists/bookworm/main/binary-amd64/Packages.gz"
            ),
            None
        );
        assert_eq!(
            listed_in("dists/bookworm/InRelease", release.as_bytes(), path),
            None
        );
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
