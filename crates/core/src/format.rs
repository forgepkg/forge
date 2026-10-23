//! The format seam: an object-safe trait every package format implements.
//!
//! A `Format` is stored behind `Arc<dyn Format>`, so the trait must stay
//! **object-safe**: no generic methods, no `Self`-typed returns. Parsing reads
//! from a `&mut dyn ReadSeek` (formats such as ZIP-based NuGet packages need to
//! seek), keeping the trait usable both with files and in-memory cursors.

use std::cmp::Ordering;

use forge_plugin_api::{FetchResult, Remote, UpstreamOp, UpstreamStep};

use crate::domain::{FormatError, ParsedUpload};

/// A reader that supports seeking and is movable across threads.
///
/// The blanket impl makes any `Read + Seek + Send` type usable as a
/// `&mut dyn ReadSeek` without callers naming the concrete type.
pub trait ReadSeek: std::io::Read + std::io::Seek + Send {}
impl<T: std::io::Read + std::io::Seek + Send> ReadSeek for T {}

/// Lowercase a package id (or a search term) the way .NET's
/// `ToLowerInvariant()` does, so stored names match what NuGet clients
/// request: character by character with the simple (1:1) Unicode mapping —
/// no context rules (a final `Σ` lowers to `σ`, not `ς`) and no expansions.
/// `char::to_lowercase` is already context-free; its only multi-character
/// result is `İ` (U+0130), whose simple mapping is a plain `i`.
pub fn lower_invariant(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\u{130}' {
                return 'i';
            }
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(l), None) => l,
                _ => c,
            }
        })
        .collect()
}

/// A package format (e.g. NuGet). Object-safe so it can be registered as
/// `Arc<dyn Format>` in a format registry.
pub trait Format: Send + Sync {
    /// Stable identifier for this format (e.g. `"nuget"`). Used for routing and
    /// the `repository.format` column.
    fn id(&self) -> &'static str;

    /// Parse an uploaded package into format-neutral [`ParsedUpload`] data.
    fn parse_upload(&self, file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError>;

    /// [`Self::parse_upload`] for a package staged on disk at `path` (what
    /// the hosted publish path parses). The default opens the file and reads
    /// it through `parse_upload`; a format that needs the file itself (a
    /// format plugin lends it to its sandbox) overrides it.
    fn parse_upload_file(&self, path: &std::path::Path) -> Result<ParsedUpload, FormatError> {
        let mut file = std::fs::File::open(path)?;
        self.parse_upload(&mut file)
    }

    /// Normalize a raw version string into the canonical form used for storage
    /// and lookups (e.g. SemVer normalization for NuGet).
    fn normalize_version(&self, raw: &str) -> Result<String, FormatError>;

    /// Order two **normalized** version strings.
    fn compare_versions(&self, a: &str, b: &str) -> Ordering;

    /// Lowercase / canonicalize a package id for case-insensitive lookups.
    fn lower_id(&self, id: &str) -> String;

    /// The asset path a version's package archive is stored under (the
    /// `asset.path` of its component). Internal to the repository: clients
    /// never see it. NuGet keeps `package.nupkg`.
    fn package_asset_path(&self) -> &str {
        "package"
    }

    /// The content type stored and served for the package archive.
    fn package_content_type(&self) -> &str {
        "application/octet-stream"
    }

    /// The asset path of the manifest the parser extracted
    /// ([`ParsedUpload::nuspec_bytes`]). NuGet keeps `package.nuspec`.
    fn manifest_asset_path(&self) -> &str {
        "manifest"
    }

    /// The content type stored for the manifest asset.
    fn manifest_content_type(&self) -> &str {
        "application/octet-stream"
    }

    /// A summary of `manifest` to store with the version at publish, so that
    /// metadata endpoints render it without fetching and re-parsing the
    /// manifest on every request. `None` when the format keeps none (the
    /// default) or the manifest cannot be summarized.
    fn manifest_summary(&self, manifest: &[u8]) -> Option<serde_json::Value> {
        let _ = manifest;
        None
    }

    /// Whether `id` is a well-formed package id of this format. Read routes
    /// answer 404 for anything else, and a proxy never puts such an id into
    /// an upstream URL: an id is pasted into URL paths, so `/`, `..`, `?`,
    /// `#` or `%` in it would let a reader steer a credentialed upstream
    /// request to another path or query.
    ///
    /// The default accepts only letters, digits, `_`, `.` and `-` (no empty
    /// id, no `..`); formats with a stricter grammar override it.
    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        let ok = !id.is_empty()
            && !id.contains("..")
            && id
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if ok {
            Ok(())
        } else {
            Err(FormatError::InvalidPackage(format!(
                "invalid package id {id:?}"
            )))
        }
    }

    /// One step of the upstream side of a proxy repository
    /// ([`forge_plugin_api::FormatPlugin::upstream`]): what to fetch from
    /// `remote` for `op`, or what came of it. The proxy read path
    /// ([`crate::repo::proxy::ProxyRepo`]) performs the fetches and calls
    /// again with everything fetched so far. The default has no upstream: a
    /// format without proxy repositories never gets here.
    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        let _ = (remote, op, fetched);
        Err(FormatError::InvalidPackage(format!(
            "{} has no proxy repositories",
            self.id()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ParsedUpload;
    use std::io::Cursor;
    use std::sync::Arc;

    /// A trivial format used only to prove object-safety and exercise the seam.
    struct DummyFormat;

    impl Format for DummyFormat {
        fn id(&self) -> &'static str {
            "dummy"
        }

        fn parse_upload(&self, file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            Ok(ParsedUpload {
                id: "dummy".into(),
                original_id: "Dummy".into(),
                version: "1.0.0".into(),
                version_original: "1.0.0".into(),
                listed: true,
                nuspec_bytes: buf,
                deps: Vec::new(),
            })
        }

        fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
            Ok(raw.trim().to_string())
        }

        fn compare_versions(&self, a: &str, b: &str) -> Ordering {
            a.cmp(b)
        }

        fn lower_id(&self, id: &str) -> String {
            super::lower_invariant(id)
        }
    }

    #[test]
    fn lower_invariant_matches_dotnet_simple_mapping() {
        use super::lower_invariant;
        assert_eq!(lower_invariant("Newtonsoft.JSON"), "newtonsoft.json");
        assert_eq!(lower_invariant("Ünicode.Lib"), "ünicode.lib");
        // No final-sigma context rule: `ToLowerInvariant` gives `οδοσ`.
        assert_eq!(lower_invariant("ΟΔΟΣ"), "οδοσ");
        // No expansion: U+0130 lowers to a single `i`.
        assert_eq!(lower_invariant("İstanbul"), "istanbul");
        assert_eq!(lower_invariant("İstanbul").chars().count(), 8);
    }

    #[test]
    fn trait_is_object_safe() {
        // If `Format` were not object-safe, this line would fail to compile.
        let f: Arc<dyn Format> = Arc::new(DummyFormat);
        assert_eq!(f.id(), "dummy");
        assert_eq!(f.lower_id("Foo.Bar"), "foo.bar");
        assert_eq!(f.compare_versions("1.0.0", "2.0.0"), Ordering::Less);
        assert_eq!(f.normalize_version(" 1.2.3 ").unwrap(), "1.2.3");
    }

    #[test]
    fn parse_upload_reads_through_dyn_readseek() {
        let f: Arc<dyn Format> = Arc::new(DummyFormat);
        let mut cur = Cursor::new(b"hello".to_vec());
        let parsed = f.parse_upload(&mut cur).unwrap();
        assert_eq!(parsed.nuspec_bytes, b"hello");
        assert_eq!(parsed.id, "dummy");
    }
}
