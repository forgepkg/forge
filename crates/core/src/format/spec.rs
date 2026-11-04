//! [`Format`] for a [`FormatSpec`].

use std::cmp::Ordering;
use std::path::Path;
use std::sync::Arc;

use crate::domain::{Dependency, DependencyGroup, FormatError, ParsedUpload};
use std::sync::OnceLock;

use crate::format::{Format, ReadSeek};
use forge_format_api::{self as api, Assets, FormatSpec, Storage, UpstreamToken};

/// The longest version the host takes from a format, in bytes: a version to
/// normalize as given, its normalized form, and a parsed package's version
/// as written and normalized. Versions are stored in the
/// `UNIQUE (repository_id, name, version)` indexes of `component` and
/// `proxy_cached_version`, and PostgreSQL refuses a B-tree index entry
/// larger than about 2,700 bytes: a format without a limit of its own let a
/// multi-kilobyte version through to that insert, so a push answered 500
/// instead of 400, and so did a proxy asked for such a version. 256 is above
/// NuGet's own limit (64 characters) and, with [`MAX_ID_LENGTH`], keeps an
/// entry far below PostgreSQL's.
const MAX_VERSION_LENGTH: usize = 256;

/// The longest package id the host takes from a format, in bytes: an id to
/// validate, and a parsed package's id as written and canonical. Ids share
/// the indexes of [`MAX_VERSION_LENGTH`]. 512 is above NuGet's own limit
/// (100 characters, at most 400 bytes in UTF-8).
const MAX_ID_LENGTH: usize = 512;

/// A [`FormatSpec`] as a [`Format`]: what the hosted write path, the read
/// ops, the proxy read path and retention work with.
#[derive(Clone)]
pub struct SpecFormat {
    id: &'static str,
    spec: Arc<dyn FormatSpec>,
    assets: Assets,
    storage: Storage,
    upstream_token: UpstreamToken,
}

impl SpecFormat {
    /// Adapt `spec`.
    pub fn new(spec: Arc<dyn FormatSpec>) -> Self {
        let descriptor = spec.descriptor();
        SpecFormat {
            id: descriptor.id,
            assets: descriptor.assets,
            storage: descriptor.storage,
            upstream_token: descriptor.upstream_token,
            spec,
        }
    }

    /// The format of one publish through the format's protocol: the package
    /// is parsed with the document it came in, when there is one
    /// ([`FormatSpec::parse_upload`]; the host sets
    /// [`UploadFormat::document`] once the body is read, before the staged
    /// package is parsed), must have the canonical id `expected_id`, when
    /// one is given, and its identity is recorded in
    /// [`UploadFormat::parsed`].
    pub fn upload(
        &self,
        document: bool,
        publisher: Option<String>,
        expected_id: Option<String>,
    ) -> UploadFormat {
        UploadFormat {
            format: self.clone(),
            document: document.then(|| Arc::new(OnceLock::new())),
            publisher,
            expected_id,
            parsed: Arc::new(OnceLock::new()),
        }
    }
}

/// See [`SpecFormat::upload`].
pub struct UploadFormat {
    format: SpecFormat,
    /// The rest of the document the package came in, for an
    /// [`api::Upload::Document`].
    pub document: Option<Arc<OnceLock<Vec<u8>>>>,
    /// The username of the account publishing.
    publisher: Option<String>,
    expected_id: Option<String>,
    /// `(canonical id, normalized version)` of the package, once parsed.
    pub parsed: Arc<OnceLock<(String, String)>>,
}

impl Format for UploadFormat {
    fn id(&self) -> &'static str {
        self.format.id()
    }

    fn package_asset_path(&self) -> &str {
        self.format.package_asset_path()
    }

    fn package_content_type(&self) -> &str {
        self.format.package_content_type()
    }

    fn manifest_asset_path(&self) -> &str {
        self.format.manifest_asset_path()
    }

    fn manifest_content_type(&self) -> &str {
        self.format.manifest_content_type()
    }

    fn parse_upload(&self, mut file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        file.rewind()?;
        let parsed = match &self.document {
            Some(document) => {
                let document = document.get().ok_or_else(|| {
                    FormatError::InvalidPackage("the upload's document is incomplete".into())
                })?;
                let upload = api::Uploaded {
                    document,
                    publisher: self.publisher.as_deref(),
                };
                self.format.spec.parse_upload(&upload, &mut file)
            }
            None => self.format.spec.parse_package(&mut file),
        }
        .map_err(format_error)
        .and_then(parsed_upload)?;
        if let Some(expected) = &self.expected_id {
            if &parsed.id != expected {
                return Err(FormatError::InvalidPackage(format!(
                    "the package is {}, not {expected}",
                    parsed.id
                )));
            }
        }
        let _ = self.parsed.set((parsed.id.clone(), parsed.version.clone()));
        Ok(parsed)
    }

    fn parse_upload_file(&self, path: &Path) -> Result<ParsedUpload, FormatError> {
        let mut file = std::fs::File::open(path)?;
        self.parse_upload(&mut file)
    }

    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        self.format.normalize_version(raw)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        self.format.compare_versions(a, b)
    }

    fn lower_id(&self, id: &str) -> String {
        self.format.lower_id(id)
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        self.format.validate_id(id)
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<serde_json::Value> {
        self.format.manifest_summary(manifest)
    }

    fn summary_caps(&self) -> &'static [api::SummaryCap] {
        self.format.summary_caps()
    }
}

fn format_error(e: api::FormatError) -> FormatError {
    use api::FormatError as E;
    match e {
        E::InvalidPackage(m) | E::InvalidId(m) => FormatError::InvalidPackage(m),
        E::MissingManifest(m) => FormatError::MissingManifest(m),
        E::MalformedManifest(m) => FormatError::MalformedManifest(m),
        E::InvalidVersion(m) => FormatError::InvalidVersion {
            value: String::new(),
            reason: m,
        },
        E::Internal(m) => FormatError::Io(std::io::Error::other(m)),
    }
}

/// The start of `value`, to name an oversized one in an error.
fn start(value: &str) -> String {
    let start: String = value.chars().take(64).collect();
    format!("{start}…")
}

/// Refuses an id longer than [`MAX_ID_LENGTH`].
fn check_id(id: &str) -> Result<(), FormatError> {
    if id.len() > MAX_ID_LENGTH {
        return Err(FormatError::InvalidPackage(format!(
            "invalid package id {:?}: longer than {MAX_ID_LENGTH} bytes",
            start(id)
        )));
    }
    Ok(())
}

/// Refuses a version longer than [`MAX_VERSION_LENGTH`].
fn check_version(version: &str) -> Result<(), FormatError> {
    if version.len() > MAX_VERSION_LENGTH {
        return Err(FormatError::InvalidVersion {
            value: start(version),
            reason: format!("longer than {MAX_VERSION_LENGTH} bytes"),
        });
    }
    Ok(())
}

/// A package the format parsed, as the host stores it, unless its id or
/// version is longer than the host takes ([`MAX_ID_LENGTH`],
/// [`MAX_VERSION_LENGTH`]): a push of it is refused (400).
fn parsed_upload(parsed: api::ParsedPackage) -> Result<ParsedUpload, FormatError> {
    check_id(&parsed.id)?;
    check_id(&parsed.original_id)?;
    check_version(&parsed.version)?;
    check_version(&parsed.version_original)?;
    Ok(ParsedUpload {
        id: parsed.id,
        original_id: parsed.original_id,
        version: parsed.version,
        version_original: parsed.version_original,
        listed: parsed.listed,
        nuspec_bytes: parsed.manifest,
        deps: parsed
            .dependencies
            .into_iter()
            .map(|g| DependencyGroup {
                target_framework: g.target,
                dependencies: g
                    .dependencies
                    .into_iter()
                    .map(|d| Dependency {
                        id: d.id,
                        range: d.range,
                    })
                    .collect(),
            })
            .collect(),
    })
}

impl Format for SpecFormat {
    fn id(&self) -> &'static str {
        self.id
    }

    fn stores_files(&self) -> bool {
        self.storage == Storage::Files
    }

    fn stores_images(&self) -> bool {
        self.storage == Storage::Images
    }

    fn package_asset_path(&self) -> &str {
        self.assets.package
    }

    fn package_content_type(&self) -> &str {
        self.assets.package_type
    }

    fn manifest_asset_path(&self) -> &str {
        self.assets.manifest
    }

    fn manifest_content_type(&self) -> &str {
        self.assets.manifest_type
    }

    fn parse_upload(&self, mut file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        file.rewind()?;
        self.spec
            .parse_package(&mut file)
            .map_err(format_error)
            .and_then(parsed_upload)
    }

    fn parse_upload_file(&self, path: &Path) -> Result<ParsedUpload, FormatError> {
        self.spec
            .parse_package_file(path)
            .map_err(format_error)
            .and_then(parsed_upload)
    }

    /// The format's normalized form of `raw`, refused when either is longer
    /// than [`MAX_VERSION_LENGTH`] (a read naming it answers 404).
    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        // Before the format, so an oversized version never reaches it.
        check_version(raw)?;
        let normalized = self.spec.normalize_version(raw).map_err(format_error)?;
        check_version(&normalized)?;
        Ok(normalized)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        self.spec.compare_versions(a, b)
    }

    fn has_prereleases(&self) -> bool {
        self.spec.descriptor().prereleases != api::Prereleases::None
    }

    fn lower_id(&self, id: &str) -> String {
        self.spec.canonical_id(id)
    }

    fn version_class(&self, version: &str) -> crate::format::VersionClass {
        self.spec.version_class(version)
    }

    fn retention_partition(&self, id: &str, version: &str) -> Option<String> {
        self.spec.retention_partition(id, version)
    }

    /// Whether the format takes `id`, which is never longer than
    /// [`MAX_ID_LENGTH`].
    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        // Before the format, so an oversized id never reaches it.
        check_id(id)?;
        self.spec.validate_id(id).map_err(format_error)
    }

    fn upstream(
        &self,
        remote: &api::Remote,
        op: &api::UpstreamOp,
        fetched: &[api::FetchResult],
    ) -> Result<api::UpstreamStep, FormatError> {
        self.spec
            .upstream(remote, op, fetched)
            .map_err(format_error)
    }

    fn upstream_bearer_token(&self) -> bool {
        self.upstream_token == UpstreamToken::Bearer
    }

    fn readme(&self, manifest: &[u8]) -> Option<String> {
        self.spec.readme(manifest)
    }

    fn reserved_prefix(&self, prefix: &str) -> Result<String, FormatError> {
        self.spec.reserved_prefix(prefix).map_err(format_error)
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<serde_json::Value> {
        let text = self.spec.manifest_summary(manifest)?;
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(summary @ serde_json::Value::Object(_)) => Some(summary),
            _ => {
                tracing::warn!(
                    format = self.id,
                    "manifest-summary returned something other than a JSON object; not stored"
                );
                None
            }
        }
    }

    fn summary_caps(&self) -> &'static [api::SummaryCap] {
        self.spec.summary_caps()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A format without limits of its own: every id is valid, every version
    /// normalizes to `normalized` (or to itself), and every package parses
    /// as `parsed`.
    struct Unlimited {
        normalized: Option<String>,
        parsed: api::ParsedPackage,
    }

    const UNLIMITED: api::Descriptor = api::Descriptor {
        id: "unlimited",
        name: "Unlimited",
        description: "Every id, every version.",
        kinds: &[api::RepositoryKind::Hosted, api::RepositoryKind::Group],
        storage: Storage::Packages,
        assets: Assets::DEFAULT,
        upstream_token: UpstreamToken::None,
        options: &[],
        prereleases: forge_format_api::Prereleases::Dash,
        indexes: false,
    };

    impl FormatSpec for Unlimited {
        fn descriptor(&self) -> &'static api::Descriptor {
            &UNLIMITED
        }

        fn canonical_id(&self, id: &str) -> String {
            id.to_ascii_lowercase()
        }

        fn validate_id(&self, _id: &str) -> Result<(), api::FormatError> {
            Ok(())
        }

        fn normalize_version(&self, version: &str) -> Result<String, api::FormatError> {
            Ok(self
                .normalized
                .clone()
                .unwrap_or_else(|| version.to_string()))
        }

        fn compare_versions(&self, a: &str, b: &str) -> Ordering {
            a.cmp(b)
        }

        fn parse_package(
            &self,
            _package: &mut dyn api::PackageSource,
        ) -> Result<api::ParsedPackage, api::FormatError> {
            Ok(self.parsed.clone())
        }

        fn manifest_summary(&self, _manifest: &[u8]) -> Option<String> {
            None
        }

        fn handle(&self, _repo: &api::Repository, _req: &api::Request) -> api::Action {
            api::Action::Respond(api::Response::text(404, "not found"))
        }

        fn render(
            &self,
            _repo: &api::Repository,
            _req: &api::Request,
            _data: &[api::Loaded],
        ) -> api::Action {
            api::Action::Respond(api::Response::text(404, "not found"))
        }
    }

    /// A package `id` at `version`, as written and normalized.
    fn package(id: &str, version: &str) -> api::ParsedPackage {
        api::ParsedPackage {
            id: id.to_ascii_lowercase(),
            original_id: id.to_string(),
            version: version.to_string(),
            version_original: version.to_string(),
            listed: true,
            manifest: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    /// [`Unlimited`] as the host sees it.
    fn unlimited(normalized: Option<&str>, parsed: api::ParsedPackage) -> SpecFormat {
        SpecFormat::new(Arc::new(Unlimited {
            normalized: normalized.map(str::to_string),
            parsed,
        }))
    }

    #[test]
    fn versions_longer_than_the_host_takes_do_not_normalize() {
        let longest = "1".repeat(MAX_VERSION_LENGTH);
        let longer = "1".repeat(MAX_VERSION_LENGTH + 1);
        let format = unlimited(None, package("demo", "1.0.0"));
        assert_eq!(format.normalize_version(&longest).unwrap(), longest);
        for version in [longer.clone(), "1".repeat(4096)] {
            let err = format.normalize_version(&version).unwrap_err();
            assert!(matches!(err, FormatError::InvalidVersion { .. }), "{err}");
            assert!(err.to_string().len() < 200, "{err}");
        }
        // The normalized form too.
        let lengthened = unlimited(Some(&longer), package("demo", "1.0.0"));
        assert!(matches!(
            lengthened.normalize_version("1"),
            Err(FormatError::InvalidVersion { .. })
        ));
        let normalized = unlimited(Some(&longest), package("demo", "1.0.0"));
        assert_eq!(normalized.normalize_version("1").unwrap(), longest);
    }

    #[test]
    fn ids_longer_than_the_host_takes_are_invalid() {
        let format = unlimited(None, package("demo", "1.0.0"));
        assert!(format.validate_id(&"a".repeat(MAX_ID_LENGTH)).is_ok());
        // Bytes: 129 four-byte characters are longer.
        for id in ["a".repeat(MAX_ID_LENGTH + 1), "\u{1F600}".repeat(129)] {
            assert!(matches!(
                format.validate_id(&id),
                Err(FormatError::InvalidPackage(_))
            ));
        }
    }

    #[test]
    fn a_package_with_a_longer_id_or_version_is_refused() {
        let parse = |parsed: api::ParsedPackage| {
            unlimited(None, parsed).parse_upload(&mut std::io::Cursor::new(Vec::new()))
        };
        let longest_version = "1".repeat(MAX_VERSION_LENGTH);
        let longest_id = "A".repeat(MAX_ID_LENGTH);
        let parsed = parse(package(&longest_id, &longest_version)).unwrap();
        assert_eq!(parsed.id, longest_id.to_ascii_lowercase());
        assert_eq!(parsed.version, longest_version);

        let longer_version = format!("{longest_version}1");
        let longer_id = format!("{longest_id}A");
        let version_original = api::ParsedPackage {
            version_original: longer_version.clone(),
            ..package("demo", "1.0.0")
        };
        let original_id = api::ParsedPackage {
            original_id: longer_id.clone(),
            ..package("demo", "1.0.0")
        };
        for parsed in [package("demo", &longer_version), version_original] {
            assert!(matches!(
                parse(parsed),
                Err(FormatError::InvalidVersion { .. })
            ));
        }
        for parsed in [package(&longer_id, "1.0.0"), original_id] {
            assert!(matches!(parse(parsed), Err(FormatError::InvalidPackage(_))));
        }
    }

    /// A format with retention hooks of its own: Maven-like snapshots,
    /// counted per base version.
    struct Snapshots;

    impl FormatSpec for Snapshots {
        fn descriptor(&self) -> &'static api::Descriptor {
            &UNLIMITED
        }

        fn version_class(&self, version: &str) -> api::VersionClass {
            if version.ends_with("-SNAPSHOT") {
                api::VersionClass::Snapshot
            } else {
                api::VersionClass::Release
            }
        }

        fn retention_partition(&self, _id: &str, version: &str) -> Option<String> {
            version.strip_suffix("-SNAPSHOT").map(str::to_string)
        }

        fn handle(&self, _repo: &api::Repository, _req: &api::Request) -> api::Action {
            api::Action::Respond(api::Response::text(404, "not found"))
        }

        fn render(
            &self,
            _repo: &api::Repository,
            _req: &api::Request,
            _data: &[api::Loaded],
        ) -> api::Action {
            api::Action::Respond(api::Response::text(404, "not found"))
        }
    }

    #[test]
    fn retention_hooks_reach_the_host() {
        use crate::format::VersionClass;
        // The defaults: SemVer's prereleases, one partition per package.
        let plain = unlimited(None, package("demo", "1.0.0"));
        assert_eq!(plain.version_class("1.0.0"), VersionClass::Release);
        assert_eq!(plain.version_class("1.0.0-ci.1"), VersionClass::Prerelease);
        assert_eq!(plain.retention_partition("demo", "1.0.0-ci.1"), None);
        // A format's own.
        let snapshots = SpecFormat::new(Arc::new(Snapshots));
        assert_eq!(snapshots.version_class("33.0.0-jre"), VersionClass::Release);
        assert_eq!(
            snapshots.version_class("1.0-SNAPSHOT"),
            VersionClass::Snapshot
        );
        assert_eq!(
            snapshots
                .retention_partition("g:a", "1.0-SNAPSHOT")
                .as_deref(),
            Some("1.0")
        );
    }
}
