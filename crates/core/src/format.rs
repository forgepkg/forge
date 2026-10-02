//! The format seam: an object-safe trait every package format implements.
//!
//! A `Format` is stored behind `Arc<dyn Format>`, so the trait must stay
//! **object-safe**: no generic methods, no `Self`-typed returns. Parsing reads
//! from a `&mut dyn ReadSeek` (formats such as ZIP-based NuGet packages need to
//! seek), keeping the trait usable both with files and in-memory cursors.

use std::cmp::Ordering;

use crate::domain::{DependencyGroup, FormatError, ParsedUpload};

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

    /// Normalize a raw version string into the canonical form used for storage
    /// and lookups (e.g. SemVer normalization for NuGet).
    fn normalize_version(&self, raw: &str) -> Result<String, FormatError>;

    /// Order two **normalized** version strings.
    fn compare_versions(&self, a: &str, b: &str) -> Ordering;

    /// Lowercase / canonicalize a package id for case-insensitive lookups.
    fn lower_id(&self, id: &str) -> String;

    /// The identity a standalone manifest (e.g. a `.nuspec`) declares, as
    /// `(lower_id, normalized version)`. A proxy verifies a manifest fetched
    /// from its upstream with this before serving or caching it. The default
    /// rejects every manifest, so a format without manifest support never has
    /// an unverified upstream manifest served.
    fn manifest_identity(&self, manifest: &[u8]) -> Result<(String, String), FormatError> {
        let _ = manifest;
        Err(FormatError::MalformedManifest(format!(
            "{} manifests cannot be verified",
            self.id()
        )))
    }

    /// Render a minimal manifest declaring `id`, `version` and `deps`, for a
    /// version whose metadata is known only from an upstream index (a proxied
    /// version that is not downloaded yet), so it is read back through the
    /// same manifest parsing as a stored one. `None` (the default) when the
    /// format cannot express one.
    fn synthesize_manifest(
        &self,
        id: &str,
        version: &str,
        deps: &[DependencyGroup],
    ) -> Option<Vec<u8>> {
        let _ = (id, version, deps);
        None
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
