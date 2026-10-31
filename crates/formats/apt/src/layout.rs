//! Where things are in a repository, as apt asks for them:
//!
//! * `dists/<distribution>/InRelease`, `Release`, `Release.gpg`;
//! * `dists/<distribution>/<component>/binary-<arch>/Packages` (`.gz`,
//!   `.xz`), and their `by-hash/SHA256/<sha256>` copies;
//! * `pool/<component>/<prefix>/<name>/<name>_<version>_<arch>.deb`, the
//!   prefix being the name's first letter (`lib` and the next letter for a
//!   `lib` name), the version the normalized one (an epoch keeps its `:`);
//! * `key.asc` and `key.gpg`, the repository's signing keys (hosted).
//!
//! Request paths are parsed with [`forge_plugin_api::files`]: a path that
//! needs normalizing (`..`, `//`, an encoded `/`, a backslash) is refused,
//! never resolved.

use forge_plugin_api::files::{self, PathError};

use crate::control::{valid_architecture, valid_component, valid_package_name};
use crate::version;

/// The armored public keys of a hosted repository.
pub const KEY_ASC: &str = "key.asc";
/// The same keys, as a binary keyring (`signed-by=` takes either).
pub const KEY_GPG: &str = "key.gpg";

/// What a request path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The repository's URL itself (`/` or nothing).
    Root,
    /// A file directly below the root (an upload's name, `key.asc`).
    TopFile(String),
    /// A file under `dists/<distribution>/`: `path` is the whole path,
    /// `rest` what follows the distribution.
    Dists {
        path: String,
        distribution: String,
        rest: String,
    },
    /// A file under `pool/`.
    Pool(PoolPath),
    /// Anything else (a directory, another top-level directory).
    Other(String),
}

/// A file under `pool/`: `pool/<component>/<prefix>/<directory>/<file>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolPath {
    pub path: String,
    pub component: String,
    pub prefix: String,
    pub directory: String,
    pub file: String,
}

/// A binary package's file name, `<name>_<version>_<arch>.deb`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebName {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

/// Parse a request path (still percent-encoded, with or without its leading
/// `/`).
pub fn parse(encoded: &str) -> Result<Target, PathError> {
    let encoded = encoded.strip_prefix('/').unwrap_or(encoded);
    match files::parse_request(encoded)? {
        files::Target::Directory(dir) if dir.is_empty() => Ok(Target::Root),
        files::Target::Directory(dir) => Ok(Target::Other(dir)),
        files::Target::File(path) => Ok(classify(path)),
    }
}

fn classify(path: String) -> Target {
    let segments: Vec<&str> = path.split('/').collect();
    match segments.as_slice() {
        [file] => Target::TopFile((*file).to_string()),
        ["dists", distribution, rest @ ..] if !rest.is_empty() => Target::Dists {
            distribution: (*distribution).to_string(),
            rest: rest.join("/"),
            path: path.clone(),
        },
        ["pool", component, prefix, directory, file] => Target::Pool(PoolPath {
            component: (*component).to_string(),
            prefix: (*prefix).to_string(),
            directory: (*directory).to_string(),
            file: (*file).to_string(),
            path: path.clone(),
        }),
        _ => Target::Other(path),
    }
}

/// The pool directory prefix of a package name: `libf` for `libfoo`, `h`
/// for `hello`.
pub fn prefix(name: &str) -> &str {
    if name.len() > 3 && name.starts_with("lib") {
        &name[..4]
    } else {
        &name[..name.len().min(1)]
    }
}

/// The path of a hosted package's file.
pub fn pool_path(component: &str, name: &str, version: &str, architecture: &str) -> String {
    format!(
        "pool/{component}/{}/{name}/{name}_{version}_{architecture}.deb",
        prefix(name)
    )
}

/// The package id of a binary package: `<name>:<architecture>`, Debian's
/// spelling of a package of one architecture (`hello:amd64`).
pub fn package_id(name: &str, architecture: &str) -> String {
    format!("{name}:{architecture}")
}

/// Split a package id into its name and architecture.
pub fn split_id(id: &str) -> Option<(&str, &str)> {
    let (name, arch) = id.split_once(':')?;
    (valid_package_name(name) && valid_architecture(arch)).then_some((name, arch))
}

/// Parse `<name>_<version>_<arch>.deb` (`.udeb` and `.ddeb` too).
pub fn deb_name(file: &str) -> Option<DebName> {
    let stem = file
        .strip_suffix(".deb")
        .or_else(|| file.strip_suffix(".udeb"))
        .or_else(|| file.strip_suffix(".ddeb"))?;
    let mut parts = stem.split('_');
    let (name, version, architecture) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || !valid_package_name(name)
        || !valid_architecture(architecture)
        || version::Version::parse(version).is_err()
    {
        return None;
    }
    Some(DebName {
        name: name.to_string(),
        version: version.to_string(),
        architecture: architecture.to_string(),
    })
}

/// The package a pool path's file belongs to, for package selectors: a
/// binary package's id (`hello:amd64`), else the source package the
/// directory is named after (`hello:source`).
pub fn pool_package(pool: &PoolPath) -> Option<String> {
    if let Some(deb) = deb_name(&pool.file) {
        return Some(package_id(&deb.name, &deb.architecture));
    }
    valid_package_name(&pool.directory).then(|| format!("{}:source", pool.directory))
}

/// Whether `distribution` may name a distribution: letters, digits and
/// `.`, `_`, `-`, `+`, `~`.
pub fn valid_distribution(distribution: &str) -> bool {
    !distribution.is_empty()
        && distribution.len() <= 64
        && distribution != "."
        && distribution != ".."
        && distribution
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'~'))
}

/// Whether `rest` (below `dists/<distribution>/`) is a content-addressed
/// copy, `…/by-hash/<algorithm>/<hex>`: it never changes.
pub fn is_by_hash(rest: &str) -> bool {
    let mut segments = rest.rsplit('/');
    let (Some(hash), Some(algorithm), Some(by_hash)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    by_hash == "by-hash"
        && matches!(algorithm, "MD5Sum" | "SHA1" | "SHA256" | "SHA512")
        && !hash.is_empty()
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The SHA-256 a `by-hash/SHA256/<hex>` path names.
pub fn by_hash_sha256(rest: &str) -> Option<String> {
    let hash = rest
        .strip_prefix("by-hash/SHA256/")
        .or_else(|| rest.rsplit_once("/by-hash/SHA256/").map(|(_, hash)| hash))?;
    (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hash.to_ascii_lowercase())
}

/// Whether a pool path is where a hosted package of `component` and `name`
/// lives (its prefix and directory).
pub fn pool_matches(pool: &PoolPath, component: &str, name: &str) -> bool {
    valid_component(&pool.component)
        && pool.component == component
        && pool.prefix == prefix(name)
        && pool.directory == name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_name_their_parts() {
        assert_eq!(parse("").unwrap(), Target::Root);
        assert_eq!(parse("/").unwrap(), Target::Root);
        assert_eq!(
            parse("/key.asc").unwrap(),
            Target::TopFile("key.asc".into())
        );
        assert_eq!(
            parse("/dists/bookworm/InRelease").unwrap(),
            Target::Dists {
                path: "dists/bookworm/InRelease".into(),
                distribution: "bookworm".into(),
                rest: "InRelease".into(),
            }
        );
        assert_eq!(
            parse("/pool/main/h/hello/hello_1%3a2.0-1_amd64.deb").unwrap(),
            Target::Pool(PoolPath {
                path: "pool/main/h/hello/hello_1:2.0-1_amd64.deb".into(),
                component: "main".into(),
                prefix: "h".into(),
                directory: "hello".into(),
                file: "hello_1:2.0-1_amd64.deb".into(),
            })
        );
        assert_eq!(parse("/dists/").unwrap(), Target::Other("dists/".into()));
        assert_eq!(parse("/dists/x").unwrap(), Target::Other("dists/x".into()));
    }

    #[test]
    fn traversal_is_refused() {
        for bad in [
            "/../etc/passwd",
            "/dists/../../x",
            "/pool/main/h/hello/..",
            "/pool/main/%2e%2e/x/y",
            "/pool/main/h/hello%2Fx/y.deb",
            "/dists//InRelease",
            "/pool\\main",
            "/dists/a/%00",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pool_paths_follow_debian() {
        assert_eq!(
            pool_path("main", "hello", "2.10-3", "amd64"),
            "pool/main/h/hello/hello_2.10-3_amd64.deb"
        );
        assert_eq!(
            pool_path("contrib", "libfoo1", "1:1.0", "arm64"),
            "pool/contrib/libf/libfoo1/libfoo1_1:1.0_arm64.deb"
        );
        assert_eq!(prefix("lib"), "l");
        assert_eq!(prefix("libc6"), "libc");
    }

    #[test]
    fn deb_names_are_parsed_strictly() {
        assert_eq!(
            deb_name("hello_2.10-3_amd64.deb"),
            Some(DebName {
                name: "hello".into(),
                version: "2.10-3".into(),
                architecture: "amd64".into()
            })
        );
        assert_eq!(deb_name("hello_1:2.0_all.deb").unwrap().version, "1:2.0");
        for bad in [
            "hello_2.10-3.deb",
            "hello_2.10-3_amd64_x.deb",
            "Hello_1.0_amd64.deb",
            "hello_x_amd64.deb",
            "hello_1.0_amd64.rpm",
            "hello_1.0_any.deb",
        ] {
            assert_eq!(deb_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn pool_files_belong_to_packages() {
        let Target::Pool(pool) = parse("/pool/main/h/hello/hello_1.0_amd64.deb").unwrap() else {
            panic!()
        };
        assert_eq!(pool_package(&pool).as_deref(), Some("hello:amd64"));
        assert!(pool_matches(&pool, "main", "hello"));
        assert!(!pool_matches(&pool, "contrib", "hello"));
        let Target::Pool(pool) = parse("/pool/main/h/hello/hello_1.0.orig.tar.gz").unwrap() else {
            panic!()
        };
        assert_eq!(pool_package(&pool).as_deref(), Some("hello:source"));
        assert_eq!(split_id("hello:amd64"), Some(("hello", "amd64")));
        assert_eq!(split_id("hello"), None);
    }

    #[test]
    fn by_hash_paths_are_recognized() {
        let hash = "a".repeat(64);
        assert!(is_by_hash(&format!(
            "main/binary-amd64/by-hash/SHA256/{hash}"
        )));
        assert_eq!(
            by_hash_sha256(&format!("main/binary-amd64/by-hash/SHA256/{hash}")),
            Some(hash.clone())
        );
        assert!(!is_by_hash("main/binary-amd64/Packages"));
        assert!(!is_by_hash("by-hash/SHA256/xyz"));
        assert_eq!(by_hash_sha256("main/by-hash/SHA256/abc"), None);
    }

    #[test]
    fn distributions_are_names() {
        for good in [
            "bookworm",
            "bookworm-security",
            "stable",
            "jammy-updates",
            "v1.2",
        ] {
            assert!(valid_distribution(good), "{good}");
        }
        for bad in ["", "..", "a/b", "a b", "x%y"] {
            assert!(!valid_distribution(bad), "{bad}");
        }
    }
}
