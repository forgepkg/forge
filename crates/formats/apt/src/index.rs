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

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use forge_plugin_api::{
    FormatError, IndexFile, IndexInput, IndexedPackage, SignatureKind, SignedCopy,
};
use sha2::{Digest, Sha256};

use crate::control::Paragraph;
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

/// One package's entry, ready to be listed.
struct Entry {
    component: String,
    architecture: String,
    stanza: String,
}

fn entry(package: &IndexedPackage) -> Result<Entry, FormatError> {
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
    Ok(Entry {
        component: summary.component,
        architecture: summary.architecture,
        stanza: paragraph.to_text(),
    })
}

/// The index files of `input` (see the module's documentation).
pub fn render(info: &ReleaseInfo<'_>, input: &IndexInput) -> Result<Vec<IndexFile>, FormatError> {
    let entries = input
        .packages
        .iter()
        .map(entry)
        .collect::<Result<Vec<_>, _>>()?;

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

    // Packages of each component and architecture, in input order (by id,
    // then version).
    let mut lists: BTreeMap<(String, String), String> = BTreeMap::new();
    for component in &components {
        for arch in &architectures {
            lists.insert((component.clone(), arch.clone()), String::new());
        }
    }
    for e in &entries {
        let targets: Vec<&String> = if e.architecture == "all" {
            architectures.iter().collect()
        } else {
            vec![&e.architecture]
        };
        for arch in targets {
            let list = lists
                .get_mut(&(e.component.clone(), arch.clone()))
                .expect("every component and architecture has a list");
            if !list.is_empty() {
                list.push('\n');
            }
            list.push_str(&e.stanza);
        }
    }

    let base = format!("dists/{}", info.distribution);
    let mut files = Vec::new();
    // (path below dists/<distribution>/, size, sha256), for Release.
    let mut listed: Vec<(String, usize, String)> = Vec::new();
    for ((component, arch), packages) in &lists {
        let dir = format!("{component}/binary-{arch}");
        let plain = packages.as_bytes().to_vec();
        let gz = gzip(&plain)?;
        let xz = xz(&plain)?;
        for (name, content, content_type) in [
            ("Packages", plain, "text/plain; charset=utf-8"),
            ("Packages.gz", gz, "application/gzip"),
            ("Packages.xz", xz, "application/x-xz"),
        ] {
            let sha256 = hex::encode(Sha256::digest(&content));
            listed.push((format!("{dir}/{name}"), content.len(), sha256.clone()));
            files.push(IndexFile {
                path: format!("{base}/{dir}/by-hash/SHA256/{sha256}"),
                content: content.clone(),
                content_type: content_type.into(),
                immutable: true,
                signed: Vec::new(),
            });
            files.push(IndexFile {
                path: format!("{base}/{dir}/{name}"),
                content,
                content_type: content_type.into(),
                immutable: false,
                signed: Vec::new(),
            });
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
    files.push(IndexFile {
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
    });
    files.push(IndexFile {
        path: KEY_ASC.into(),
        content: input.keyring_armored.clone().into_bytes(),
        content_type: "application/pgp-keys".into(),
        immutable: false,
        signed: Vec::new(),
    });
    files.push(IndexFile {
        path: KEY_GPG.into(),
        content: input.keyring.clone(),
        content_type: "application/pgp-keys".into(),
        immutable: false,
        signed: Vec::new(),
    });
    Ok(files)
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
        }
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
        let files = render(
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
        let files = render(
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
        let files = render(&INFO, &input(Vec::new())).unwrap();
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
        let one = render(
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
        let two = render(&INFO, &later).unwrap();
        for (a, b) in one.iter().zip(&two) {
            assert_eq!(a.path, b.path);
            if !a.path.ends_with("/Release") {
                assert_eq!(a.content, b.content, "{}", a.path);
            }
        }
    }
}
