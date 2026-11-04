//! A hosted repository's indexes: what `apt-get update` reads.
//!
//! For each component and architecture, `Packages` lists every version
//! with its control data, where it is in the pool, its size and SHA-256
//! (also as `Packages.gz` and `Packages.xz`). Architecture `all` packages
//! are listed under every architecture of their component, and under
//! `binary-all`. `Release` names every index file with its size and
//! SHA-256, and says `Acquire-By-Hash: yes`: every index file is also
//! published under `by-hash/SHA256/<sha256>`, so a client that read one
//! `Release` finds the `Packages` it names even once a newer index
//! replaced it. The host signs `Release` as `InRelease` (cleartext) and
//! `Release.gpg` (detached), and publishes the keys as `key.asc` and
//! `key.gpg`.
//!
//! Everything but `Release`'s `Date` is a function of the packages: the
//! same packages give the same `Packages`, byte for byte.
//!
//! The lists are made one at a time and handed to the host as they are
//! made, after their size was checked (#797). A package whose stored
//! control data is longer than any upload may give
//! ([`MAX_LISTED_CONTROL_BYTES`]) is not listed.

use std::collections::BTreeSet;
use std::io::Write;

use forge_plugin_api::{
    FormatError, IndexFile, IndexInput, IndexedPackage, SignatureKind, SignedCopy,
};
use sha2::{Digest, Sha256};

use crate::control::{Paragraph, MAX_CONTROL_BYTES};
use crate::layout::{self, KEY_ASC, KEY_GPG};
use crate::manifest::Summary;

/// Fields of a package's control data that an index sets itself.
const INDEX_FIELDS: &[&str] = &[
    "Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Status",
];

/// What a repository's `Release` says about it.
#[derive(Debug, Clone)]
pub struct ReleaseInfo<'a> {
    pub distribution: &'a str,
    /// The repository's name (`Label`).
    pub label: &'a str,
}

/// The longest stored control data a package may have to be listed. Every
/// package uploaded or imported has a control file of at most
/// [`MAX_CONTROL_BYTES`], which its stored control data spells canonically
/// (a space after each `:`, ` .` for a blank line), a few bytes more at most;
/// twice the cap leaves room for that. A package stored while the cap was
/// 1 MiB (before #797) may have more: it is left out of the indexes, so that
/// it neither costs every index generation its size per list nor fails
/// them. It stays in the pool until it is deleted.
pub const MAX_LISTED_CONTROL_BYTES: usize = 2 * MAX_CONTROL_BYTES;

/// One package's entry, ready to be listed.
struct Entry {
    component: String,
    architecture: String,
    stanza: String,
}

/// The entry of `package`; `None` when its control data is too long to be
/// listed ([`MAX_LISTED_CONTROL_BYTES`]).
fn entry(package: &IndexedPackage) -> Result<Option<Entry>, FormatError> {
    let summary = package
        .summary
        .as_deref()
        .and_then(Summary::parse)
        .ok_or_else(|| {
            FormatError::Internal(format!(
                "{} {} has no control data stored",
                package.id, package.version
            ))
        })?;
    if summary.control.len() > MAX_LISTED_CONTROL_BYTES {
        return Ok(None);
    }
    let mut paragraph = Paragraph::parse_one(&summary.control)
        .map_err(|e| FormatError::Internal(format!("{} {}: {e}", package.id, package.version)))?;
    for field in INDEX_FIELDS {
        paragraph.remove(field);
    }
    let filename = layout::pool_path(
        &summary.component,
        &summary.package,
        &package.version,
        &summary.architecture,
    );
    paragraph.set("Filename", &filename);
    paragraph.set("Size", &package.size.to_string());
    paragraph.set("SHA256", &package.sha256);
    Ok(Some(Entry {
        component: summary.component,
        architecture: summary.architecture,
        stanza: paragraph.to_text(),
    }))
}

/// Whether `entry` is listed in the `Packages` of `component` and `arch`:
/// its own, and every architecture's for an `all` package.
fn listed_in(entry: &Entry, component: &str, arch: &str) -> bool {
    entry.component == component && (entry.architecture == arch || entry.architecture == "all")
}

/// The index files of `input` (see the module's documentation), each handed
/// to `sink` as it is made. The `Packages` lists are made one at a time:
/// what is held at once is the packages' stanzas, once each, and one list
/// with its compressed copies (#797). Before any is made, their size is
/// checked against [`IndexInput::max_bytes`]: each list is stored twice
/// uncompressed (by name and by hash), and an index whose lists alone hold
/// more is refused.
pub fn render(
    info: &ReleaseInfo<'_>,
    input: &IndexInput,
    sink: &mut dyn FnMut(IndexFile) -> Result<(), FormatError>,
) -> Result<(), FormatError> {
    let mut entries = Vec::with_capacity(input.packages.len());
    for package in &input.packages {
        entries.extend(entry(package)?);
    }

    // Components and architectures: those of the packages; `main` and
    // `all` when there are none.
    let mut components: BTreeSet<String> = entries.iter().map(|e| e.component.clone()).collect();
    if components.is_empty() {
        components.insert("main".into());
    }
    let concrete: BTreeSet<String> = entries
        .iter()
        .filter(|e| e.architecture != "all")
        .map(|e| e.architecture.clone())
        .collect();
    let mut architectures = concrete.clone();
    let has_all = entries.iter().any(|e| e.architecture == "all");
    if has_all || architectures.is_empty() {
        architectures.insert("all".into());
    }

    // What the lists will hold, before any is made: a stanza's bytes for
    // each list it is in, and a blank line between two stanzas.
    let mut plain_bytes: u64 = 0;
    for component in &components {
        for arch in &architectures {
            let (count, bytes) = entries
                .iter()
                .filter(|e| listed_in(e, component, arch))
                .fold((0u64, 0u64), |(n, b), e| (n + 1, b + e.stanza.len() as u64));
            plain_bytes += bytes + count.saturating_sub(1);
        }
    }
    let stored = plain_bytes.saturating_mul(2);
    if stored > input.max_bytes {
        return Err(FormatError::Internal(format!(
            "the index's Packages lists would hold {stored} bytes, more than the {} an index may hold",
            input.max_bytes
        )));
    }

    let base = format!("dists/{}", info.distribution);
    // (path below dists/<distribution>/, size, sha256), for Release.
    let mut listed: Vec<(String, usize, String)> = Vec::new();
    // Packages of each component and architecture, in input order (by id,
    // then version), made, handed over and dropped one at a time.
    for component in &components {
        for arch in &architectures {
            let mut packages = String::new();
            for e in entries.iter().filter(|e| listed_in(e, component, arch)) {
                if !packages.is_empty() {
                    packages.push('\n');
                }
                packages.push_str(&e.stanza);
            }
            let dir = format!("{component}/binary-{arch}");
            let plain = packages.into_bytes();
            let gz = gzip(&plain)?;
            let xz = xz(&plain)?;
            for (name, content, content_type) in [
                ("Packages", plain, "text/plain; charset=utf-8"),
                ("Packages.gz", gz, "application/gzip"),
                ("Packages.xz", xz, "application/x-xz"),
            ] {
                let sha256 = hex::encode(Sha256::digest(&content));
                listed.push((format!("{dir}/{name}"), content.len(), sha256.clone()));
                sink(IndexFile {
                    path: format!("{base}/{dir}/by-hash/SHA256/{sha256}"),
                    content: content.clone(),
                    content_type: content_type.into(),
                    immutable: true,
                    signed: Vec::new(),
                })?;
                sink(IndexFile {
                    path: format!("{base}/{dir}/{name}"),
                    content,
                    content_type: content_type.into(),
                    immutable: false,
                    signed: Vec::new(),
                })?;
            }
        }
    }

    let release = release(
        info,
        input,
        &components,
        &architectures,
        &concrete,
        has_all,
        &listed,
    )?;
    sink(IndexFile {
        path: format!("{base}/Release"),
        content: release.into_bytes(),
        content_type: "text/plain; charset=utf-8".into(),
        immutable: false,
        signed: vec![
            SignedCopy {
                path: format!("{base}/InRelease"),
                signature: SignatureKind::Cleartext,
            },
            SignedCopy {
                path: format!("{base}/Release.gpg"),
                signature: SignatureKind::Detached,
            },
        ],
    })?;
    sink(IndexFile {
        path: KEY_ASC.into(),
        content: input.keyring_armored.clone().into_bytes(),
        content_type: "application/pgp-keys".into(),
        immutable: false,
        signed: Vec::new(),
    })?;
    sink(IndexFile {
        path: KEY_GPG.into(),
        content: input.keyring.clone(),
        content_type: "application/pgp-keys".into(),
        immutable: false,
        signed: Vec::new(),
    })
}

/// The `Release` file.
fn release(
    info: &ReleaseInfo<'_>,
    input: &IndexInput,
    components: &BTreeSet<String>,
    architectures: &BTreeSet<String>,
    concrete: &BTreeSet<String>,
    has_all: bool,
    listed: &[(String, usize, String)],
) -> Result<String, FormatError> {
    let date = chrono::DateTime::parse_from_rfc3339(&input.generated)
        .map_err(|e| FormatError::Internal(format!("generated {:?}: {e}", input.generated)))?
        .with_timezone(&chrono::Utc);
    let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(" ");
    let mut out = String::new();
    let label = one_line(info.label);
    out.push_str("Origin: Forge\n");
    out.push_str(&format!("Label: {label}\n"));
    out.push_str(&format!("Suite: {}\n", info.distribution));
    out.push_str(&format!("Codename: {}\n", info.distribution));
    out.push_str(&format!(
        "Date: {}\n",
        date.format("%a, %d %b %Y %H:%M:%S UTC")
    ));
    out.push_str(&format!("Architectures: {}\n", join(architectures)));
    out.push_str(&format!("Components: {}\n", join(components)));
    out.push_str(&format!("Description: {label}\n"));
    if has_all && !concrete.is_empty() {
        // `all` packages are in every architecture's Packages too.
        out.push_str("No-Support-for-Architecture-all: Packages\n");
    }
    out.push_str("Acquire-By-Hash: yes\n");
    out.push_str("SHA256:\n");
    let width = listed
        .iter()
        .map(|(_, size, _)| size.to_string().len())
        .max()
        .unwrap_or(1);
    for (path, size, sha256) in listed {
        out.push_str(&format!(" {sha256} {size:>width$} {path}\n"));
    }
    Ok(out)
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn gzip(data: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::best());
    gz.write_all(data)
        .and_then(|()| gz.finish())
        .map_err(|e| FormatError::Internal(format!("gzip: {e}")))
}

fn xz(data: &[u8]) -> Result<Vec<u8>, FormatError> {
    let fail = |e: std::io::Error| FormatError::Internal(format!("xz: {e}"));
    let mut xz = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))
        .map_err(fail)?;
    xz.write_all(data).map_err(fail)?;
    xz.finish().map_err(fail)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::manifest;

    fn package(control: &str, size: u64) -> IndexedPackage {
        let summary = manifest::summarize(control.as_bytes()).unwrap();
        let paragraph = Paragraph::parse_one(control).unwrap();
        let name = paragraph.get("Package").unwrap();
        let arch = paragraph.get("Architecture").unwrap();
        IndexedPackage {
            id: format!("{name}:{arch}"),
            version: paragraph.get("Version").unwrap().to_string(),
            version_original: paragraph.get("Version").unwrap().to_string(),
            summary: Some(summary),
            size,
            sha256: "ab".repeat(32),
            sha512: None,
            published: None,
        }
    }

    fn input(packages: Vec<IndexedPackage>) -> IndexInput {
        IndexInput {
            packages,
            generated: "2026-10-31T12:00:00Z".into(),
            keyring: vec![1, 2, 3],
            keyring_armored: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n".into(),
            max_bytes: 1 << 30,
        }
    }

    /// Every file [`render`] hands over, in order.
    fn collect(info: &ReleaseInfo<'_>, input: &IndexInput) -> Result<Vec<IndexFile>, FormatError> {
        let mut files = Vec::new();
        render(info, input, &mut |file| {
            files.push(file);
            Ok(())
        })?;
        Ok(files)
    }

    fn file<'a>(files: &'a [IndexFile], path: &str) -> &'a IndexFile {
        files
            .iter()
            .find(|f| f.path == path)
            .unwrap_or_else(|| panic!("no {path}"))
    }

    const INFO: ReleaseInfo<'static> = ReleaseInfo {
        distribution: "bookworm",
        label: "apt-internal",
    };

    #[test]
    fn packages_list_every_version_under_its_component_and_architecture() {
        let files = collect(
            &INFO,
            &input(vec![
                package(
                    "Package: hello\nVersion: 1.0-1\nArchitecture: amd64\nSection: utils\nSize: 1\nDescription: hi\n there\n",
                    100,
                ),
                package(
                    "Package: hello\nVersion: 1.1-1\nArchitecture: arm64\nDescription: hi\n",
                    200,
                ),
                package(
                    "Package: tool\nVersion: 2:3.0\nArchitecture: all\nSection: contrib/net\nDescription: t\n",
                    300,
                ),
            ]),
        )
        .unwrap();
        let amd64 = String::from_utf8(
            file(&files, "dists/bookworm/main/binary-amd64/Packages")
                .content
                .clone(),
        )
        .unwrap();
        assert_eq!(
            amd64,
            format!(
                "Package: hello\nVersion: 1.0-1\nArchitecture: amd64\nSection: utils\nDescription: hi\n there\n\
                 Filename: pool/main/h/hello/hello_1.0-1_amd64.deb\nSize: 100\nSHA256: {}\n",
                "ab".repeat(32)
            )
        );
        let contrib = String::from_utf8(
            file(&files, "dists/bookworm/contrib/binary-arm64/Packages")
                .content
                .clone(),
        )
        .unwrap();
        assert!(contrib.contains("Filename: pool/contrib/t/tool/tool_2:3.0_all.deb\n"));
        assert!(!file(&files, "dists/bookworm/contrib/binary-all/Packages")
            .content
            .is_empty());
        let release =
            String::from_utf8(file(&files, "dists/bookworm/Release").content.clone()).unwrap();
        assert!(
            release.contains("Suite: bookworm\nCodename: bookworm\n"),
            "{release}"
        );
        assert!(
            release.contains("Date: Sat, 31 Oct 2026 12:00:00 UTC\n"),
            "{release}"
        );
        assert!(
            release.contains("Architectures: all amd64 arm64\n"),
            "{release}"
        );
        assert!(release.contains("Components: contrib main\n"), "{release}");
        assert!(release.contains("Acquire-By-Hash: yes\n"), "{release}");
        assert!(release.contains("No-Support-for-Architecture-all: Packages\n"));
        // Every listed file is there under its name and by its hash, with
        // the hash and size Release gives it.
        let entries: Vec<&str> = release.split("SHA256:\n").nth(1).unwrap().lines().collect();
        assert_eq!(entries.len(), 2 * 3 * 3);
        for line in entries {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let (sha, size, path) = (parts[0], parts[1], parts[2]);
            let named = file(&files, &format!("dists/bookworm/{path}"));
            assert_eq!(named.content.len().to_string(), size);
            assert_eq!(hex::encode(Sha256::digest(&named.content)), sha);
            let dir = path.rsplit_once('/').unwrap().0;
            let by_hash = file(
                &files,
                &format!("dists/bookworm/{dir}/by-hash/SHA256/{sha}"),
            );
            assert!(by_hash.immutable);
            assert_eq!(by_hash.content, named.content);
        }
        let signed = &file(&files, "dists/bookworm/Release").signed;
        assert_eq!(signed.len(), 2);
        assert_eq!(file(&files, "key.gpg").content, vec![1, 2, 3]);
    }

    #[test]
    fn compressed_copies_hold_the_same_list() {
        let files = collect(
            &INFO,
            &input(vec![package(
                "Package: hello\nVersion: 1.0\nArchitecture: amd64\nDescription: hi\n",
                1,
            )]),
        )
        .unwrap();
        let plain = &file(&files, "dists/bookworm/main/binary-amd64/Packages").content;
        let mut gz = Vec::new();
        flate2::read::GzDecoder::new(
            &file(&files, "dists/bookworm/main/binary-amd64/Packages.gz").content[..],
        )
        .read_to_end(&mut gz)
        .unwrap();
        assert_eq!(&gz, plain);
        let mut xz = Vec::new();
        lzma_rust2::XzReader::new(
            &file(&files, "dists/bookworm/main/binary-amd64/Packages.xz").content[..],
            true,
        )
        .read_to_end(&mut xz)
        .unwrap();
        assert_eq!(&xz, plain);
    }

    #[test]
    fn an_empty_repository_has_an_empty_index() {
        let files = collect(&INFO, &input(Vec::new())).unwrap();
        assert!(file(&files, "dists/bookworm/main/binary-all/Packages")
            .content
            .is_empty());
        let release =
            String::from_utf8(file(&files, "dists/bookworm/Release").content.clone()).unwrap();
        assert!(
            release.contains("Architectures: all\nComponents: main\n"),
            "{release}"
        );
    }

    #[test]
    fn the_same_packages_give_the_same_files() {
        let one = collect(
            &INFO,
            &input(vec![package(
                "Package: a1\nVersion: 1\nArchitecture: amd64\n",
                1,
            )]),
        )
        .unwrap();
        let mut later = input(vec![package(
            "Package: a1\nVersion: 1\nArchitecture: amd64\n",
            1,
        )]);
        later.generated = "2027-01-01T00:00:00Z".into();
        let two = collect(&INFO, &later).unwrap();
        for (a, b) in one.iter().zip(&two) {
            assert_eq!(a.path, b.path);
            if !a.path.ends_with("/Release") {
                assert_eq!(a.content, b.content, "{}", a.path);
            }
        }
    }

    /// A package of `arch` whose `Description` makes its control data
    /// `bytes` long, about.
    fn large(name: &str, arch: &str, bytes: usize) -> IndexedPackage {
        package(
            &format!(
                "Package: {name}\nVersion: 1\nArchitecture: {arch}\nDescription: big\n {}\n",
                "x".repeat(bytes)
            ),
            1,
        )
    }

    #[test]
    fn an_index_over_the_byte_cap_fails_before_anything_is_compressed() {
        // 20 `all` packages of 60 KiB and one amd64 package: the `all`
        // packages are listed under binary-all and binary-amd64, so the
        // lists hold 2 × 20 × 60 KiB, stored twice: some 4.7 MiB.
        let mut packages: Vec<_> = (0..20)
            .map(|i| large(&format!("p{i:02}"), "all", 60 * 1024))
            .collect();
        packages.push(package("Package: zz\nVersion: 1\nArchitecture: amd64\n", 1));
        let mut capped = input(packages);
        capped.max_bytes = 4 * 1024 * 1024;
        let mut handed = 0;
        let err = render(&INFO, &capped, &mut |_| {
            handed += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(err.to_string().contains("more than the 4194304"), "{err}");
        // Refused before the first list was made, compressed and handed
        // over.
        assert_eq!(handed, 0);
        // Within the cap it is made.
        capped.max_bytes = 5 * 1024 * 1024;
        assert!(collect(&INFO, &capped).is_ok());
    }

    #[test]
    fn lists_are_handed_over_one_at_a_time() {
        // The sink sees each list's files before the next list is made,
        // and its error stops the rendering.
        let packages = vec![
            package("Package: aa\nVersion: 1\nArchitecture: amd64\n", 1),
            package("Package: bb\nVersion: 1\nArchitecture: arm64\n", 1),
        ];
        let mut paths = Vec::new();
        let err = render(&INFO, &input(packages), &mut |file| {
            paths.push(file.path);
            if paths.len() == 6 {
                return Err(FormatError::Internal("full".into()));
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            FormatError::Internal("full".into()).to_string()
        );
        assert_eq!(paths.len(), 6);
        assert!(
            paths.iter().all(|p| p.contains("/main/binary-amd64/")),
            "{paths:?}"
        );
    }

    #[test]
    fn a_package_stored_over_the_cap_is_left_out() {
        // Stored when a control file could be 1 MiB (before #797): not
        // listed, and the index is made of the others.
        let files = collect(
            &INFO,
            &input(vec![
                large("huge", "all", MAX_LISTED_CONTROL_BYTES),
                package("Package: small\nVersion: 1\nArchitecture: amd64\n", 1),
            ]),
        )
        .unwrap();
        let amd64 = &file(&files, "dists/bookworm/main/binary-amd64/Packages").content;
        let amd64 = String::from_utf8(amd64.clone()).unwrap();
        assert!(amd64.starts_with("Package: small\n"), "{amd64}");
        assert!(!amd64.contains("huge"));
        let release =
            String::from_utf8(file(&files, "dists/bookworm/Release").content.clone()).unwrap();
        assert!(release.contains("Architectures: amd64\n"), "{release}");
        // One at the upload cap is listed.
        let files = collect(
            &INFO,
            &input(vec![large("fits", "all", MAX_CONTROL_BYTES - 100)]),
        )
        .unwrap();
        let all = &file(&files, "dists/bookworm/main/binary-all/Packages").content;
        assert!(all.starts_with(b"Package: fits\n"));
    }
}
