//! npm registries for Forge, as a built-in format plugin: what npm, pnpm,
//! Yarn and Bun read and write under `/repository/<repository>/`.
//!
//! [`Npm`] implements [`FormatPlugin`]: the rules of package names and
//! versions, reading a tarball, and the registry protocol
//! ([`protocol`]): packuments (full and abbreviated), versions, tarballs,
//! search, publishing (the tarball comes inside a JSON document,
//! [`publish`]), dist-tags, deprecations, unpublishing, the logins, and
//! audits passed to an upstream. Proxies read another registry through
//! [`proxy`]. Forge keeps the rest: storage, authentication, the tags and
//! deprecations themselves, hosted/proxy/group semantics and retention.
//!
//! The pure parts: [`name`] and [`version`] rules, [`tarball`] reading,
//! [`integrity`] checks, the [`document`]s clients `PUT`, version
//! [`manifest`] summaries, [`packument`] rendering and the parsing of
//! [`upstream`] packuments.

pub mod document;
pub mod integrity;
pub mod manifest;
pub mod name;
pub mod packument;
pub mod protocol;
pub mod proxy;
pub mod publish;
pub mod tarball;
pub mod upstream;
pub mod version;

use std::cmp::Ordering;
use std::io::{Read, SeekFrom, Write};

use forge_plugin_api::{
    Action, Assets, AuthOutcome, Change, Dependency, DependencyGroup, Descriptor, FetchResult,
    FormatError, FormatPlugin, Forward, Loaded, PackageRef, PackageSource, ParsedPackage, Remote,
    Repository, RepositoryKind, Request, Response, Storage, Unpacked, Uploaded, UpstreamOp,
    UpstreamStep, UpstreamToken,
};
use serde_json::Value;

pub use name::PackageName;

/// What npm says about itself: its format id, name and version.
pub const DESCRIPTOR: Descriptor = Descriptor {
    id: "npm",
    name: "npm",
    version: env!("CARGO_PKG_VERSION"),
    description: "npm registries: publish, install and log in with npm, pnpm, Yarn and Bun; \
                  dist-tags, deprecations and audits; proxies of registry.npmjs.org and other \
                  registries.",
    // Proxies mirror another registry through the plugin's upstream side.
    kinds: &[
        RepositoryKind::Hosted,
        RepositoryKind::Proxy,
        RepositoryKind::Group,
    ],
    storage: Storage::Packages,
    assets: Assets {
        package: "package.tgz",
        package_type: "application/octet-stream",
        manifest: "package.json",
        manifest_type: "application/json",
    },
    // A proxy given only a password (a registry token) sends it as a Bearer
    // token, as npm clients do with `_authToken`.
    upstream_token: UpstreamToken::Bearer,
    options: &[],
    prereleases: forge_plugin_api::Prereleases::Dash,
    indexes: false,
};

/// What the plugin reads of a request, beyond the package the repository's
/// upload limit bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NpmLimits {
    /// The largest publish document, its tarball's data aside, and the
    /// largest other document a client sends (an unpublish, an audit).
    pub max_document_bytes: u64,
    /// The most a tarball may unpack to.
    pub max_unpacked_bytes: u64,
}

impl Default for NpmLimits {
    fn default() -> Self {
        NpmLimits {
            max_document_bytes: 32 * 1024 * 1024,
            max_unpacked_bytes: tarball::DEFAULT_MAX_UNPACKED_BYTES,
        }
    }
}

/// The npm format plugin.
///
/// Package ids are names as npm writes them (`left-pad`, `@acme/ui`), case
/// and all: the registry keeps names that differ only in case apart
/// (`JSONStream` is not `jsonstream`).
#[derive(Debug, Clone, Default)]
pub struct Npm {
    limits: NpmLimits,
}

impl Npm {
    pub fn with_limits(limits: NpmLimits) -> Self {
        Npm { limits }
    }

    pub fn limits(&self) -> NpmLimits {
        self.limits
    }
}

fn invalid(e: impl std::fmt::Display) -> FormatError {
    FormatError::InvalidPackage(e.to_string())
}

fn io(e: std::io::Error) -> FormatError {
    FormatError::InvalidPackage(format!("read the package: {e}"))
}

/// A manifest's dependencies as the host records them: a group per kind.
fn dependency_groups(manifest: &serde_json::Map<String, Value>) -> Vec<DependencyGroup> {
    manifest::dependencies(manifest)
        .into_iter()
        .map(|(kind, deps)| DependencyGroup {
            target: Some(kind),
            dependencies: deps
                .into_iter()
                .map(|(id, range)| Dependency {
                    id,
                    range: Some(range),
                })
                .collect(),
        })
        .collect()
}

impl FormatPlugin for Npm {
    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }

    fn canonical_id(&self, id: &str) -> String {
        id.to_string()
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        PackageName::parse(id)
            .map(|_| ())
            .map_err(|e| FormatError::InvalidId(e.to_string()))
    }

    fn normalize_version(&self, version: &str) -> Result<String, FormatError> {
        version::normalize(version).map_err(FormatError::InvalidVersion)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        version::compare(a, b)
    }

    /// A tarball on its own (what a proxy downloads): its `package.json` is
    /// its manifest, with the `dist` the registry computes.
    fn parse_package(&self, package: &mut dyn PackageSource) -> Result<ParsedPackage, FormatError> {
        let digests = integrity::Digests::of(&mut *package).map_err(io)?;
        package.seek(SeekFrom::Start(0)).map_err(io)?;
        let tarball =
            tarball::read(&mut *package, self.limits.max_unpacked_bytes).map_err(invalid)?;
        let name = PackageName::parse(&tarball.name).map_err(invalid)?;
        let version = version::normalize(&tarball.version).map_err(FormatError::InvalidVersion)?;
        let mut manifest = tarball.package_json.clone();
        manifest.insert("version".into(), Value::String(version.clone()));
        manifest.insert("_id".into(), Value::String(format!("{name}@{version}")));
        manifest.insert(
            "dist".into(),
            serde_json::json!({
                "integrity": digests.integrity(),
                "shasum": digests.sha1_hex,
                "fileCount": tarball.file_count,
                "unpackedSize": tarball.unpacked_size,
            }),
        );
        Ok(ParsedPackage {
            id: name.to_string(),
            original_id: name.to_string(),
            version,
            version_original: tarball.version,
            listed: true,
            dependencies: dependency_groups(&manifest),
            manifest: serde_json::to_vec(&manifest).map_err(invalid)?,
        })
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<String> {
        match serde_json::from_slice(manifest).ok()? {
            Value::Object(m) => serde_json::to_string(&manifest::summary(&m)).ok(),
            _ => None,
        }
    }

    fn readme(&self, manifest: &[u8]) -> Option<String> {
        let manifest: serde_json::Map<String, Value> = serde_json::from_slice(manifest).ok()?;
        manifest
            .get("readme")
            .and_then(Value::as_str)
            .filter(|readme| !readme.trim().is_empty())
            .map(str::to_string)
    }

    /// A scope (`@acme`, stored as `@acme/` so that it reserves the scope's
    /// packages, not every scope starting like it) or a name prefix.
    fn reserved_prefix(&self, prefix: &str) -> Result<String, FormatError> {
        let word = |s: &str| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        };
        // `@scope`, `@scope/` or `@scope/name-start`; or `name-start`.
        let valid = match prefix.strip_prefix('@') {
            Some(scoped) => {
                let (scope, rest) = scoped.split_once('/').unwrap_or((scoped, ""));
                !scope.is_empty() && word(scope) && word(rest)
            }
            None => !prefix.is_empty() && word(prefix),
        };
        if !valid {
            return Err(FormatError::InvalidId(format!(
                "{prefix:?} is not a package name prefix (a scope such as @acme, or letters, \
                 digits, '.', '_', '-')"
            )));
        }
        let mut prefix = prefix.to_ascii_lowercase();
        if prefix.starts_with('@') && !prefix.contains('/') {
            prefix.push('/');
        }
        Ok(prefix)
    }

    fn handle(&self, _repo: &Repository, req: &Request) -> Action {
        protocol::handle(self, req)
    }

    fn render(&self, repo: &Repository, req: &Request, data: &[Loaded]) -> Action {
        protocol::render(self, repo, req, data)
    }

    fn forward_body(&self, forward: &Forward, hidden: &dyn Fn(&str) -> bool) -> Option<Vec<u8>> {
        protocol::forward_body(forward, hidden)
    }

    fn auth_response(&self, repo: &Repository, req: &Request, outcome: &AuthOutcome) -> Response {
        protocol::auth_response(repo, req, outcome)
    }

    fn error_response(&self, status: u16, message: &str) -> Option<Response> {
        Some(protocol::error(status, message))
    }

    /// The publish document's tarball, decoded from its base64 as the body
    /// streams by ([`publish::Extractor`]); the document is what remains.
    fn unpack_upload(
        &self,
        body: &mut dyn Read,
        package: &mut dyn Write,
    ) -> Result<Unpacked, FormatError> {
        let max_document = usize::try_from(self.limits.max_document_bytes).unwrap_or(usize::MAX);
        let mut extractor = publish::Extractor::new(max_document);
        let mut buf = vec![0u8; 64 * 1024];
        let mut out = Vec::new();
        loop {
            let n = body.read(&mut buf).map_err(io)?;
            if n == 0 {
                break;
            }
            out.clear();
            extractor.feed(&buf[..n], &mut out).map_err(invalid)?;
            package.write_all(&out).map_err(io)?;
        }
        let extracted = extractor.finish().map_err(invalid)?;
        Ok(match extracted.attachment {
            Some(_) => Unpacked::Package {
                document: extracted.document,
            },
            None => Unpacked::Document(extracted.document),
        })
    }

    /// The version a publish stores: the version object its document
    /// describes, checked against the tarball ([`document::release`]).
    fn parse_upload(
        &self,
        upload: &Uploaded<'_>,
        package: &mut dyn PackageSource,
    ) -> Result<ParsedPackage, FormatError> {
        let doc = publish_document(upload.document)?;
        let release = document::release(
            &doc,
            package,
            upload.publisher,
            self.limits.max_unpacked_bytes,
        )
        .map_err(invalid)?;
        Ok(ParsedPackage {
            id: doc.name.to_string(),
            original_id: doc.name.to_string(),
            version: doc.version.clone(),
            version_original: doc.version_original.clone(),
            listed: true,
            dependencies: dependency_groups(&release.manifest),
            manifest: serde_json::to_vec(&release.manifest).map_err(invalid)?,
        })
    }

    /// The dist-tags the publish document points at the new version.
    fn published(&self, document: &[u8], package: &PackageRef) -> Vec<Change> {
        let Ok(doc) = publish_document(document) else {
            return Vec::new();
        };
        doc.dist_tags
            .into_iter()
            .map(|tag| Change::Tag {
                id: package.id.clone(),
                tag,
                version: package.version.clone(),
            })
            .collect()
    }

    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        Ok(proxy::upstream(remote, op, fetched))
    }
}

/// The publish document of an upload: its name must be one a new package
/// may take.
fn publish_document(document: &[u8]) -> Result<document::PublishDocument, FormatError> {
    let doc: Value = serde_json::from_slice(document)
        .map_err(|e| invalid(format!("the document is not valid JSON: {e}")))?;
    let raw = doc
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("the document has no name"))?;
    let name = PackageName::parse_new(raw).map_err(invalid)?;
    document::read_publish(&doc, &name).map_err(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_a_tarball_on_its_own() {
        let tgz = tarball::build(&[(
            "package/package.json",
            br##"{"name":"@acme/a","version":"v1.2.3","readme":"# A","dependencies":{"b":"^1"}}"##,
        )]);
        let npm = Npm::default();
        let parsed = npm.parse_package(&mut Cursor::new(tgz)).unwrap();
        assert_eq!(parsed.id, "@acme/a");
        assert_eq!(parsed.version, "1.2.3");
        assert_eq!(parsed.version_original, "v1.2.3");
        assert_eq!(
            parsed.dependencies[0].target.as_deref(),
            Some("dependencies")
        );
        let summary: Value =
            serde_json::from_str(&npm.manifest_summary(&parsed.manifest).unwrap()).unwrap();
        assert!(summary.get("readme").is_none());
        assert_eq!(
            summary["dependency_groups"][0]["dependencies"][0]["id"],
            "b"
        );
        assert!(summary["dist"]["integrity"]
            .as_str()
            .unwrap()
            .starts_with("sha512-"));
        assert_eq!(npm.readme(&parsed.manifest).as_deref(), Some("# A"));
    }

    #[test]
    fn ids_keep_their_case() {
        let npm = Npm::default();
        assert_eq!(npm.canonical_id("JSONStream"), "JSONStream");
        assert!(npm.validate_id("@acme/a").is_ok());
        assert!(npm.validate_id("../etc").is_err());
        assert_eq!(npm.compare_versions("1.10.0", "1.9.0"), Ordering::Greater);
    }

    #[test]
    fn reserved_prefixes_are_scopes_or_name_prefixes() {
        let npm = Npm::default();
        assert_eq!(npm.reserved_prefix("@Acme").unwrap(), "@acme/");
        assert_eq!(npm.reserved_prefix("@acme/ui-").unwrap(), "@acme/ui-");
        assert_eq!(npm.reserved_prefix("acme-").unwrap(), "acme-");
        assert!(npm.reserved_prefix("a@b").is_err());
        assert!(npm.reserved_prefix("").is_err());
        // Nothing is named so: these would reserve nothing.
        assert!(npm.reserved_prefix("@").is_err());
        assert!(npm.reserved_prefix("@/").is_err());
        assert!(npm.reserved_prefix("acme/ui").is_err());
        assert!(npm.reserved_prefix("@acme/ui/").is_err());
    }
}
