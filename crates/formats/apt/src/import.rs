//! What an import reads of another apt repository (Nexus' apt hosted
//! repository, a static repository made with `dpkg-scanpackages` or
//! `apt-ftparchive`, another Forge), as `apt-get` reads it:
//!
//! * `dists/<distribution>/InRelease` (else `Release`): the components, the
//!   architectures, and each index file with its size and SHA-256
//!   ([`Release`]). An `InRelease`'s text is read out of its cleartext
//!   signature ([`cleartext`]); checking the signature is the host's.
//! * `dists/<distribution>/<component>/binary-<arch>/Packages` (`.xz`,
//!   `.gz`, or as it is): every binary package with its `Filename`, `Size`
//!   and `SHA256` ([`read_packages`]). Each is checked against what
//!   `Release` lists for it ([`IndexFile::check`]) before it is read.
//!
//! Source packages (`Sources`) and `debian-installer` udebs are not read.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};

use forge_plugin_api::files;
use sha2::{Digest, Sha256};

use crate::control::{valid_architecture, valid_component, valid_package_name, Paragraph};
use crate::version;

/// The most a `Packages` index may inflate to.
pub const MAX_INDEX_BYTES: u64 = 1024 * 1024 * 1024;

/// The most memory the entries of a `Packages` index may take
/// ([`read_packages`]): the list's allocation and every entry's strings.
/// An entry takes far more than its text (`Package:a` and a blank line, 11
/// bytes, take about 160), so [`MAX_INDEX_BYTES`] alone does not bound it.
/// Debian's largest index (main, amd64: about 65,000 entries) takes about
/// 40 MiB.
pub const MAX_ENTRIES_BYTES: usize = 256 * 1024 * 1024;

/// What a `Release` says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Release {
    /// `Components`, as listed (may be empty).
    pub components: Vec<String>,
    /// `Architectures`, as listed (may be empty).
    pub architectures: Vec<String>,
    /// `Acquire-By-Hash: yes`: every index is also served under
    /// `by-hash/SHA256/<sha256>` next to it.
    pub acquire_by_hash: bool,
    /// Every file the `SHA256` field lists, by its path below
    /// `dists/<distribution>/`.
    pub files: BTreeMap<String, Listed>,
}

/// A file's size and SHA-256, as `Release` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub size: u64,
    /// Lowercase hex.
    pub sha256: String,
}

/// The `Packages` index of one component and architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub component: String,
    pub architecture: String,
    /// The files `Release` lists for it, the one to read first first:
    /// `Packages.xz`, `Packages.gz`, `Packages`. (Debian lists the
    /// uncompressed `Packages` but does not serve it.)
    pub files: Vec<IndexFile>,
}

/// One file of an [`Index`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexFile {
    /// Below `dists/<distribution>/`.
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

impl Index {
    /// Where the index's cursor is: `<component>/<architecture>`.
    pub fn key(&self) -> String {
        format!("{}/{}", self.component, self.architecture)
    }
}

impl IndexFile {
    /// Its content-addressed copy below `dists/<distribution>/`
    /// (`main/binary-amd64/by-hash/SHA256/<sha256>`), for a `Release` that
    /// says `Acquire-By-Hash: yes`.
    pub fn by_hash(&self) -> String {
        let dir = self.path.rsplit_once('/').map_or("", |(dir, _)| dir);
        format!("{dir}/by-hash/SHA256/{}", self.sha256)
    }

    /// Check a download of the file against the size and SHA-256 `Release`
    /// lists for it.
    pub fn check(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() as u64 != self.size {
            return Err(format!(
                "{} is {} bytes; Release lists {}",
                self.path,
                bytes.len(),
                self.size
            ));
        }
        let sha256 = hex::encode(Sha256::digest(bytes));
        if sha256 != self.sha256 {
            return Err(format!(
                "{} does not match the SHA-256 Release lists for it",
                self.path
            ));
        }
        Ok(())
    }
}

/// The text of a cleartext-signed `InRelease`, dash-escapes removed, its
/// signature left unchecked. Nothing but blank lines may come before the
/// signed message or after its signature: apt refuses such a file too, since
/// what lies outside the signature is not signed.
pub fn cleartext(in_release: &str) -> Result<String, String> {
    const BEGIN: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
    const SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----";
    const END: &str = "-----END PGP SIGNATURE-----";
    let mut lines = in_release
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    loop {
        match lines.next() {
            Some(line) if line.trim().is_empty() => {}
            Some(line) if line.trim_end() == BEGIN => break,
            _ => return Err("InRelease is not a cleartext-signed message".into()),
        }
    }
    // The armor headers (`Hash: SHA512`), up to a blank line.
    loop {
        match lines.next() {
            Some(line) if line.trim().is_empty() => break,
            Some(line) if line.contains(": ") => {}
            _ => return Err("InRelease's signed message has no text".into()),
        }
    }
    let mut text = String::new();
    loop {
        match lines.next() {
            Some(line) if line.trim_end() == SIGNATURE => break,
            Some(line) => {
                let line = match line.strip_prefix("- ") {
                    Some(escaped) => escaped,
                    None if line.starts_with('-') => {
                        return Err("InRelease holds a line that is not dash-escaped".into())
                    }
                    None => line,
                };
                text.push_str(line);
                text.push('\n');
            }
            None => return Err("InRelease's signed message has no signature".into()),
        }
    }
    loop {
        match lines.next() {
            Some(line) if line.trim_end() == END => break,
            Some(_) => {}
            None => return Err("InRelease's signature does not end".into()),
        }
    }
    if lines.any(|line| !line.trim().is_empty()) {
        return Err("InRelease holds text after its signature".into());
    }
    Ok(text)
}

/// The words of a field's value.
fn words(paragraph: &Paragraph, name: &str) -> Vec<String> {
    paragraph
        .get(name)
        .map(|value| value.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

impl Release {
    /// Read a `Release` (or the text of an `InRelease`).
    pub fn parse(text: &str) -> Result<Release, String> {
        let paragraph = Paragraph::parse_one(text).map_err(|e| format!("Release: {e}"))?;
        let Some(sha256) = paragraph.get("SHA256") else {
            return Err("Release lists no SHA-256 checksums (its SHA256 field)".into());
        };
        let mut files = BTreeMap::new();
        for line in sha256.split('\n') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let [hash, size, path] = parts.as_slice() else {
                if parts.is_empty() {
                    continue;
                }
                return Err(format!(
                    "Release's SHA256 field holds {line:?}, not `<sha256> <size> <path>`"
                ));
            };
            let valid = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
            let size = size.parse::<u64>().ok().filter(|_| valid).ok_or_else(|| {
                format!("Release's SHA256 field holds {line:?}, not `<sha256> <size> <path>`")
            })?;
            files.insert(
                (*path).to_string(),
                Listed {
                    size,
                    sha256: hash.to_ascii_lowercase(),
                },
            );
        }
        Ok(Release {
            components: words(&paragraph, "Components"),
            architectures: words(&paragraph, "Architectures"),
            acquire_by_hash: paragraph
                .first_line("Acquire-By-Hash")
                .is_some_and(|v| v.eq_ignore_ascii_case("yes")),
            files,
        })
    }

    /// The `Packages` index of every component and architecture `Release`
    /// lists one for, by component and architecture. A component is one the
    /// `Components` field names (when it names any; `debian-installer` and
    /// other directories below a component are none), the architecture any
    /// but `source`.
    pub fn indexes(&self) -> Vec<Index> {
        let mut found: BTreeMap<(String, String), Vec<(u8, IndexFile)>> = BTreeMap::new();
        for (path, listed) in &self.files {
            let Some((dir, file)) = path.rsplit_once('/') else {
                continue;
            };
            let rank = match file {
                "Packages.xz" => 0,
                "Packages.gz" => 1,
                "Packages" => 2,
                _ => continue,
            };
            let Some((component, arch)) = dir.rsplit_once("/binary-") else {
                continue;
            };
            let listed_component = if self.components.is_empty() {
                !component.contains('/')
            } else {
                self.components.iter().any(|c| c == component)
            };
            if !listed_component || arch.is_empty() || arch.contains('/') {
                continue;
            }
            found
                .entry((component.to_string(), arch.to_string()))
                .or_default()
                .push((
                    rank,
                    IndexFile {
                        path: path.clone(),
                        size: listed.size,
                        sha256: listed.sha256.clone(),
                    },
                ));
        }
        found
            .into_iter()
            .map(|((component, architecture), mut files)| {
                files.sort_by_key(|(rank, _)| *rank);
                Index {
                    component,
                    architecture,
                    files: files.into_iter().map(|(_, file)| file).collect(),
                }
            })
            .collect()
    }
}

/// Why a component cannot be imported, if it cannot: Forge publishes a
/// component under its name (`main`, `non-free-firmware`), which a `/`
/// (`updates/main`) cannot be part of.
pub fn component_problem(component: &str) -> Option<String> {
    (!valid_component(component)).then(|| {
        format!(
            "Forge publishes no component named {component:?} (lowercase letters, digits, '-', \
             '+' and '.'): nothing of it is copied"
        )
    })
}

/// A binary package as a `Packages` index lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    pub package: String,
    pub version: String,
    pub architecture: String,
    /// Where the package is, below the repository's base URL, its `.`
    /// segments dropped ([`resolve_filename`]).
    pub filename: String,
    pub size: Option<u64>,
    /// Lowercase hex digests.
    pub sha256: Option<String>,
    pub sha512: Option<String>,
}

impl Entry {
    /// What its strings take on the heap, besides the entry itself.
    pub fn heap_bytes(&self) -> usize {
        self.package.capacity()
            + self.version.capacity()
            + self.architecture.capacity()
            + self.filename.capacity()
            + self.sha256.as_ref().map_or(0, String::capacity)
            + self.sha512.as_ref().map_or(0, String::capacity)
    }

    /// The package id Forge stores it under (`hello:amd64`).
    pub fn id(&self) -> String {
        crate::layout::package_id(&self.package, &self.architecture)
    }

    /// Its version as Forge stores it (an epoch of 0 dropped); as listed
    /// when it does not parse.
    pub fn normalized_version(&self) -> String {
        version::normalize(&self.version).unwrap_or_else(|_| self.version.clone())
    }

    /// Why the entry cannot be copied, if it cannot: what Forge refuses of
    /// its name, version or architecture, a `Filename` that is no path
    /// below the repository or no `.deb`, and a missing `Size` or
    /// `SHA256`.
    pub fn problem(&self) -> Option<String> {
        if !valid_package_name(&self.package) {
            return Some(format!("{:?} is not a package name", self.package));
        }
        if let Err(e) = version::Version::parse(&self.version) {
            return Some(format!("{:?} is not a Debian version: {e}", self.version));
        }
        if !valid_architecture(&self.architecture) {
            return Some(format!("{:?} is not an architecture", self.architecture));
        }
        if self.filename.is_empty() {
            return Some("the index names no Filename for it".into());
        }
        if let Err(e) = files::validate_path(&self.filename) {
            return Some(format!(
                "its Filename {:?} is no path below the repository: {e}",
                self.filename
            ));
        }
        if !self.filename.ends_with(".deb") {
            return Some(format!("its Filename {:?} is no .deb", self.filename));
        }
        if self.size.is_none() {
            return Some("the index lists no Size for it".into());
        }
        if self.sha256.is_none() {
            return Some("the index lists no SHA256 for it".into());
        }
        None
    }
}

/// A `Filename` as apt resolves it against the base URL: its `.` segments
/// (the leading `./` of `dpkg-scanpackages ./pool`) dropped. Everything else
/// stays, a `..`, an empty segment or a leading `/` among it, for
/// [`Entry::problem`] to refuse.
pub fn resolve_filename(filename: &str) -> String {
    filename
        .split('/')
        .filter(|segment| *segment != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// A lowercase hex digest of `len` digits, if `value` is one.
fn hex_digest(value: &str, len: usize) -> Option<String> {
    (value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// The index `bytes` (gzip, xz or plain, as its first bytes say) inflated,
/// up to [`MAX_INDEX_BYTES`].
pub fn inflate<'a>(bytes: &'a [u8]) -> Box<dyn Read + 'a> {
    let reader: Box<dyn Read + 'a> = if bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::MultiGzDecoder::new(bytes))
    } else if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Box::new(lzma_rust2::XzReader::new(bytes, true))
    } else {
        Box::new(bytes)
    };
    Box::new(reader.take(MAX_INDEX_BYTES + 1))
}

/// Every entry of a `Packages` index (inflated), in its order. Only the
/// fields an import reads are kept; a paragraph without a `Package` field
/// is none. An index with control characters, a line that is no field,
/// more than [`MAX_INDEX_BYTES`], or entries that take more than
/// [`MAX_ENTRIES_BYTES`] is refused.
pub fn read_packages(index: impl Read) -> Result<Vec<Entry>, String> {
    read_packages_within(index, MAX_ENTRIES_BYTES)
}

/// [`read_packages`], its entries taking at most `budget` bytes.
fn read_packages_within(index: impl Read, budget: usize) -> Result<Vec<Entry>, String> {
    let mut reader = BufReader::new(index);
    let mut entries: Vec<Entry> = Vec::new();
    // What the entries' strings take.
    let mut heap: usize = 0;
    let mut current: Option<Entry> = None;
    let mut seen = false;
    let mut read: u64 = 0;
    let mut number = 0usize;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("the index cannot be read: {e}"))?;
        read += n as u64;
        if read > MAX_INDEX_BYTES {
            return Err(format!(
                "the index inflates to more than {MAX_INDEX_BYTES} bytes"
            ));
        }
        let end = n == 0;
        number += 1;
        let text = std::str::from_utf8(&line)
            .map_err(|_| format!("line {number} of the index is not UTF-8"))?;
        let text = text.trim_end_matches(['\n', '\r']);
        if text.chars().any(|c| c.is_control() && c != '\t') {
            return Err(format!(
                "line {number} of the index holds control characters"
            ));
        }
        if end || text.trim().is_empty() {
            if let Some(entry) = current.take() {
                if seen {
                    // The list grows as `Vec` grows it (doubling), the old
                    // allocation held beside the new while it is copied.
                    let slot = std::mem::size_of::<Entry>();
                    let list = if entries.len() == entries.capacity() {
                        let grown = (entries.capacity() * 2).max(4);
                        entries.capacity() * slot + grown * slot
                    } else {
                        entries.capacity() * slot
                    };
                    heap += entry.heap_bytes();
                    if list.saturating_add(heap) > budget {
                        return Err(format!(
                            "its entries take more than {} MiB of memory (after {} of them): \
                             Forge reads no index that large",
                            budget / (1024 * 1024),
                            entries.len()
                        ));
                    }
                    if entries.len() == entries.capacity() {
                        entries.reserve_exact(entries.capacity().max(4));
                    }
                    entries.push(entry);
                }
            }
            seen = false;
            if end {
                return Ok(entries);
            }
            continue;
        }
        if text.starts_with([' ', '\t']) {
            // A continuation line of a field the import does not read.
            if current.is_none() {
                return Err(format!("line {number} of the index continues no field"));
            }
            continue;
        }
        let Some((name, value)) = text.split_once(':') else {
            return Err(format!("line {number} of the index is not a field"));
        };
        let value = value.trim();
        let entry = current.get_or_insert_with(Entry::default);
        match name.to_ascii_lowercase().as_str() {
            "package" => {
                entry.package = value.to_string();
                seen = true;
            }
            "version" => entry.version = value.to_string(),
            "architecture" => entry.architecture = value.to_string(),
            "filename" => entry.filename = resolve_filename(value),
            "size" => entry.size = value.parse().ok(),
            "sha256" => entry.sha256 = hex_digest(value, 64),
            "sha512" => entry.sha512 = hex_digest(value, 128),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const RELEASE: &str = "Origin: Acme\nLabel: Acme\nSuite: stable\nCodename: bookworm\n\
        Date: Sat, 01 Nov 2026 10:00:00 UTC\nArchitectures: amd64 arm64\n\
        Components: main contrib\nAcquire-By-Hash: yes\n\
        MD5Sum:\n 00000000000000000000000000000000 10 main/binary-amd64/Packages\n\
        SHA256:\n \
        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 100 main/binary-amd64/Packages\n \
        BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB 40 main/binary-amd64/Packages.gz\n \
        cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 30 main/binary-amd64/Packages.xz\n \
        dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 50 main/binary-arm64/Packages.gz\n \
        eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 60 contrib/binary-all/Packages\n \
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 70 main/debian-installer/binary-amd64/Packages\n \
        1111111111111111111111111111111111111111111111111111111111111111 80 main/source/Sources.xz\n \
        2222222222222222222222222222222222222222222222222222222222222222 90 main/binary-amd64/Release\n \
        3333333333333333333333333333333333333333333333333333333333333333 95 non-free/binary-amd64/Packages\n";

    #[test]
    fn release_lists_the_indexes_of_its_components_and_architectures() {
        let release = Release::parse(RELEASE).unwrap();
        assert_eq!(release.components, ["main", "contrib"]);
        assert_eq!(release.architectures, ["amd64", "arm64"]);
        assert!(release.acquire_by_hash);
        assert_eq!(
            release.files["main/binary-amd64/Packages.gz"],
            Listed {
                size: 40,
                sha256: "b".repeat(64)
            }
        );
        let indexes = release.indexes();
        let keys: Vec<String> = indexes.iter().map(Index::key).collect();
        // Not debian-installer, Sources, a component Components does not
        // name, nor the Release of an architecture.
        assert_eq!(keys, ["contrib/all", "main/amd64", "main/arm64"]);
        let amd64 = &indexes[1];
        let paths: Vec<&str> = amd64.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "main/binary-amd64/Packages.xz",
                "main/binary-amd64/Packages.gz",
                "main/binary-amd64/Packages"
            ]
        );
        assert_eq!(
            amd64.files[0].by_hash(),
            format!("main/binary-amd64/by-hash/SHA256/{}", "c".repeat(64))
        );

        // Without Components, every component but a directory below one.
        let mut release = release;
        release.components.clear();
        let keys: Vec<String> = release.indexes().iter().map(Index::key).collect();
        assert_eq!(
            keys,
            ["contrib/all", "main/amd64", "main/arm64", "non-free/amd64"]
        );
    }

    #[test]
    fn a_release_needs_sha256_checksums() {
        let err =
            Release::parse("Origin: x\nMD5Sum:\n 00 1 main/binary-amd64/Packages\n").unwrap_err();
        assert!(err.contains("SHA-256"), "{err}");
        for bad in [
            "SHA256:\n xyz 1 main/binary-amd64/Packages\n",
            "SHA256:\n aaaa 1 main/binary-amd64/Packages\n",
            &format!(
                "SHA256:\n {} big main/binary-amd64/Packages\n",
                "a".repeat(64)
            ),
            &format!("SHA256:\n {} 1\n", "a".repeat(64)),
        ] {
            assert!(Release::parse(bad).is_err(), "{bad}");
        }
        assert!(Release::parse("not a release").is_err());
    }

    #[test]
    fn an_index_file_is_checked_against_release() {
        let bytes = b"Package: hello\n";
        let file = IndexFile {
            path: "main/binary-amd64/Packages".into(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        file.check(bytes).unwrap();
        let err = file.check(b"Package: hellO\n").unwrap_err();
        assert!(err.contains("SHA-256"), "{err}");
        let err = file.check(b"Package: hello!\n").unwrap_err();
        assert!(err.contains("bytes; Release lists"), "{err}");
    }

    #[test]
    fn the_text_of_an_in_release_is_its_signed_message() {
        let signed = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n\
            Origin: Acme\n- -dashed: x\nSHA256:\n abc\n\
            -----BEGIN PGP SIGNATURE-----\n\nwsBcBAEBCgAG\n=abcd\n-----END PGP SIGNATURE-----\n";
        assert_eq!(
            cleartext(signed).unwrap(),
            "Origin: Acme\n-dashed: x\nSHA256:\n abc\n"
        );
        assert_eq!(
            cleartext(&signed.replace('\n', "\r\n")).unwrap(),
            "Origin: Acme\n-dashed: x\nSHA256:\n abc\n"
        );
        assert_eq!(
            cleartext(&format!("\n\n{signed}\n")).unwrap(),
            "Origin: Acme\n-dashed: x\nSHA256:\n abc\n"
        );
        for bad in [
            "Origin: Acme\n".to_string(),
            format!("Origin: unsigned\n{signed}"),
            format!("{signed}Origin: unsigned\n"),
            signed.replace("- -dashed", "-dashed"),
            signed.replace("-----END PGP SIGNATURE-----\n", ""),
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Acme\n".into(),
        ] {
            assert!(cleartext(&bad).is_err(), "{bad}");
        }
    }

    fn packages() -> String {
        format!(
            "Package: hello\nVersion: 1:2.10-3\nArchitecture: amd64\n\
             Maintainer: Someone <someone@example.com>\n\
             Description: greet\n Prints a greeting.\n .\n More.\n\
             Filename: pool/main/h/hello/hello_2.10-3_amd64.deb\nSize: 42\n\
             SHA256: 0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef\n\
             MD5sum: 00000000000000000000000000000000\n\
             \n\
             Package: libfoo1\nVersion: 1.0\nArchitecture: all\n\
             Filename: pool/main/libf/libfoo1/libfoo1_1.0_all.deb\nSize: x\nSHA256: short\n\
             SHA512: {}\n\n\n",
            "a".repeat(128)
        )
    }

    #[test]
    fn packages_list_every_binary_package_in_every_compression() {
        let text = packages();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(text.as_bytes()).unwrap();
        let gz = gz.finish().unwrap();
        let mut xz =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
        xz.write_all(text.as_bytes()).unwrap();
        let xz = xz.finish().unwrap();
        for index in [text.as_bytes().to_vec(), gz, xz] {
            let entries = read_packages(inflate(&index)).unwrap();
            assert_eq!(entries.len(), 2);
            let hello = &entries[0];
            assert_eq!(hello.id(), "hello:amd64");
            assert_eq!(hello.version, "1:2.10-3");
            assert_eq!(hello.filename, "pool/main/h/hello/hello_2.10-3_amd64.deb");
            assert_eq!(hello.size, Some(42));
            assert_eq!(
                hello.sha256.as_deref(),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            );
            assert_eq!(hello.problem(), None);
            let foo = &entries[1];
            assert_eq!(foo.id(), "libfoo1:all");
            // A malformed size or digest is none.
            assert_eq!(foo.size, None);
            assert_eq!(foo.sha256, None);
            assert_eq!(foo.sha512, Some("a".repeat(128)));
            assert!(foo.problem().unwrap().contains("Size"));
        }
    }

    #[test]
    fn an_entry_that_cannot_be_copied_says_why() {
        let good = Entry {
            package: "hello".into(),
            version: "0:1.0-1".into(),
            architecture: "amd64".into(),
            filename: "pool/main/h/hello/hello_1.0-1_amd64.deb".into(),
            size: Some(1),
            sha256: Some("a".repeat(64)),
            sha512: None,
        };
        assert_eq!(good.problem(), None);
        assert_eq!(good.normalized_version(), "1.0-1");
        for (entry, why) in [
            (
                Entry {
                    package: "Hello".into(),
                    ..good.clone()
                },
                "package name",
            ),
            (
                Entry {
                    version: "x".into(),
                    ..good.clone()
                },
                "Debian version",
            ),
            (
                Entry {
                    architecture: "source".into(),
                    ..good.clone()
                },
                "architecture",
            ),
            (
                Entry {
                    filename: "../etc/passwd.deb".into(),
                    ..good.clone()
                },
                "no path below",
            ),
            (
                Entry {
                    filename: "/pool/x.deb".into(),
                    ..good.clone()
                },
                "no path below",
            ),
            (
                Entry {
                    filename: "pool/main/h/hello/hello_1.0_amd64.udeb".into(),
                    ..good.clone()
                },
                "no .deb",
            ),
            (
                Entry {
                    filename: String::new(),
                    ..good.clone()
                },
                "Filename",
            ),
            (
                Entry {
                    sha256: None,
                    ..good.clone()
                },
                "SHA256",
            ),
        ] {
            let problem = entry.problem().unwrap_or_default();
            assert!(problem.contains(why), "{problem} should say {why}");
        }
        assert!(component_problem("main").is_none());
        assert!(component_problem("updates/main").is_some());
    }

    #[test]
    fn a_filename_is_resolved_as_apt_resolves_it() {
        // `dpkg-scanpackages ./pool` and `apt-ftparchive packages ./pool`
        // write a leading `./`.
        let index = b"Package: hello\nVersion: 1.0\nArchitecture: amd64\n\
            Filename: ./pool/main/h/hello/./hello_1.0_amd64.deb\nSize: 42\n\
            SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        let entries = read_packages(&index[..]).unwrap();
        assert_eq!(entries[0].filename, "pool/main/h/hello/hello_1.0_amd64.deb");
        assert_eq!(entries[0].problem(), None);
        for (listed, resolved) in [
            ("pool/x.deb", "pool/x.deb"),
            ("./pool/x.deb", "pool/x.deb"),
            ("././pool/./x.deb", "pool/x.deb"),
            // A `..`, an empty segment and a leading `/` stay, refused.
            ("./../x.deb", "../x.deb"),
            ("pool/../../x.deb", "pool/../../x.deb"),
            ("pool//x.deb", "pool//x.deb"),
            ("/./pool/x.deb", "/pool/x.deb"),
        ] {
            assert_eq!(resolve_filename(listed), resolved, "{listed}");
        }
        for refused in ["./../x.deb", "pool/./../x.deb", "/./pool/x.deb", "./"] {
            let entry = read_packages(
                format!(
                    "Package: a\nVersion: 1\nArchitecture: all\nFilename: {refused}\n\
                     Size: 1\nSHA256: {}\n",
                    "0".repeat(64)
                )
                .as_bytes(),
            )
            .unwrap()
            .remove(0);
            assert!(entry.problem().is_some(), "{refused}");
        }
    }

    #[test]
    fn a_malformed_index_is_refused() {
        for bad in [
            &b" continues nothing\n"[..],
            b"Package: a\nnot a field\n",
            b"Package: a\x07\n",
            b"Package: \xff\n",
        ] {
            assert!(read_packages(bad).is_err(), "{bad:?}");
        }
        assert_eq!(read_packages(&b""[..]).unwrap(), Vec::new());
        // A paragraph without Package is none.
        assert_eq!(read_packages(&b"Version: 1\n\n"[..]).unwrap(), Vec::new());
    }

    #[test]
    fn entries_past_the_budget_are_refused() {
        const MIB: usize = 1024 * 1024;
        let index = "Package:a\n\n".repeat(100_000);
        // About 160 bytes each, the list's growth among them.
        let err = read_packages_within(index.as_bytes(), MIB).unwrap_err();
        assert!(err.contains("more than 1 MiB of memory"), "{err}");
        assert_eq!(
            read_packages_within(index.as_bytes(), 64 * MIB)
                .unwrap()
                .len(),
            100_000
        );
    }
}
