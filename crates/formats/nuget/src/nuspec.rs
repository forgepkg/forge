//! `.nupkg` (zip) and `.nuspec` (XML) parsing into a [`ParsedNupkg`].
//!
//! A `.nupkg` is an OPC zip. We locate the single top-level `*.nuspec`
//! manifest, read it under strict zip-bomb limits, and parse it
//! **namespace-insensitively** (matching XML *local* names) because the nuspec
//! schema uses versioned `xmlns` URIs that differ across packages.
//!
//! Only the manifest is decompressed; the `<id>`, `<version>`, and
//! `<dependencies>` groups are extracted. The raw manifest bytes are carried in
//! [`ParsedNupkg::nuspec_bytes`] so the server can store and re-serve them.

use std::io::{BufReader, Read, SeekFrom};

use forge_plugin_api::PackageSource as ReadSeek;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::model::{
    Dependency, DependencyGroup, FormatError, NupkgError, NupkgLimits, ParsedNupkg as ParsedUpload,
};
use crate::version;

/// Parse a `.nupkg` from a seekable reader into a [`ParsedNupkg`].
pub fn parse_nupkg(
    file: &mut dyn ReadSeek,
    limits: &NupkgLimits,
) -> Result<ParsedUpload, FormatError> {
    let nuspec_bytes = extract_nuspec(file, limits)?;
    let raw = parse_nuspec(&nuspec_bytes)?;

    validate_package_id(&raw.id)?;
    // NuGet clients reject a `v` prefix; accepting it would store a package
    // whose own manifest the client later refuses to read.
    if raw.version.starts_with(['v', 'V']) {
        return Err(FormatError::InvalidVersion {
            value: raw.version.clone(),
            reason: "a leading 'v' is not a valid NuGet version".into(),
        });
    }
    // A `.snupkg` is a symbols package: pushing it to the package endpoint
    // must not replace (or pose as) the real package of the same identity.
    if raw
        .metadata
        .package_types
        .iter()
        .any(|t| t.eq_ignore_ascii_case("SymbolsPackage"))
    {
        return Err(FormatError::InvalidPackage(
            "symbol packages (.snupkg) are not accepted by the package publish endpoint".into(),
        ));
    }

    version::NugetVersion::validate_publishable(&raw.version)?;
    let version_normalized = version::normalize(&raw.version)?;
    let id_lower = lower_id(&raw.id);

    Ok(ParsedUpload {
        id: id_lower,
        original_id: raw.id,
        version: version_normalized,
        version_original: raw.version,
        listed: true,
        nuspec_bytes,
        deps: raw.deps,
    })
}

/// Maximum package id length accepted by NuGet.
pub const MAX_PACKAGE_ID_LENGTH: usize = 100;

/// Validate a package id against NuGet's rules: at most 100 characters,
/// matching `^\w+([.-]\w+)*$` (word characters separated by single dots or
/// dashes). Ids outside this grammar are rejected by NuGet clients, so a
/// package carrying one could never be restored.
pub fn validate_package_id(id: &str) -> Result<(), FormatError> {
    let invalid = |reason: &str| {
        Err(FormatError::InvalidPackage(format!(
            "invalid package id {id:?}: {reason}"
        )))
    };
    if id.chars().count() > MAX_PACKAGE_ID_LENGTH {
        return invalid("longer than 100 characters");
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut prev_sep = true; // disallow a leading separator
    for c in id.chars() {
        if c == '.' || c == '-' {
            if prev_sep {
                return invalid("separators must sit between word characters");
            }
            prev_sep = true;
        } else if is_word(c) {
            prev_sep = false;
        } else {
            return invalid("only letters, digits, '_', '.' and '-' are allowed");
        }
    }
    if prev_sep {
        return invalid("must not be empty or end with a separator");
    }
    Ok(())
}

/// Lowercase a package id for case-insensitive lookups, matching NuGet's
/// `ToLowerInvariant()`: ids may contain non-ASCII letters (see
/// [`validate_package_id`]), so this lowers every letter (`Ünicode.Lib` →
/// `ünicode.lib`), character by character with the simple (1:1) Unicode
/// mapping, like .NET: no context rules (a final `Σ` lowers to `σ`, not
/// `ς`) and no expansions. `char::to_lowercase` is already context-free; its
/// only multi-character result is `İ` (U+0130), whose simple mapping is a
/// plain `i`.
pub fn lower_id(id: &str) -> String {
    id.trim()
        .chars()
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

/// Display metadata of a `.nuspec`, for registration catalog entries and
/// search results. Absent elements are `None` / empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NuspecMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub summary: Option<String>,
    pub authors: Option<String>,
    pub owners: Option<String>,
    pub tags: Vec<String>,
    pub project_url: Option<String>,
    pub license_url: Option<String>,
    /// SPDX expression from `<license type="expression">`.
    pub license_expression: Option<String>,
    pub icon_url: Option<String>,
    pub release_notes: Option<String>,
    pub copyright: Option<String>,
    pub language: Option<String>,
    pub require_license_acceptance: bool,
    /// `<packageTypes><packageType name=…/>` names (empty ⇒ `Dependency`).
    pub package_types: Vec<String>,
    /// `<minClientVersion>` from the `metadata` element attribute.
    pub min_client_version: Option<String>,
    #[serde(skip)]
    raw_tags: Option<String>,
    #[serde(skip)]
    raw_require_license_acceptance: Option<String>,
}

impl NuspecMetadata {
    /// Trim collected text, split tags, and drop empty values.
    fn trim(&mut self) {
        for slot in [
            &mut self.title,
            &mut self.description,
            &mut self.summary,
            &mut self.authors,
            &mut self.owners,
            &mut self.project_url,
            &mut self.license_url,
            &mut self.license_expression,
            &mut self.icon_url,
            &mut self.release_notes,
            &mut self.copyright,
            &mut self.language,
        ] {
            *slot = slot
                .take()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
        }
        if let Some(tags) = self.raw_tags.take() {
            self.tags = tags
                .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Some(flag) = self.raw_require_license_acceptance.take() {
            self.require_license_acceptance = flag.trim().eq_ignore_ascii_case("true");
        }
    }
}

/// Extract the display metadata from raw `.nuspec` bytes.
pub fn metadata_from_nuspec(bytes: &[u8]) -> Result<NuspecMetadata, FormatError> {
    Ok(parse_nuspec(bytes).map_err(FormatError::from)?.metadata)
}

/// What the feed renders from a `.nuspec`: its display metadata and
/// dependency groups. Computed once at publish and stored with the version
/// (`component.manifest_summary`), so registration pages and search results
/// do not fetch and re-parse every manifest on every request.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ManifestSummary {
    pub metadata: NuspecMetadata,
    pub dependency_groups: Vec<DependencyGroup>,
}

/// Parse raw `.nuspec` bytes into a [`ManifestSummary`].
pub fn manifest_summary(bytes: &[u8]) -> Result<ManifestSummary, FormatError> {
    let parsed = parse_nuspec(bytes).map_err(FormatError::from)?;
    Ok(ManifestSummary {
        metadata: parsed.metadata,
        dependency_groups: parsed.deps,
    })
}

/// The display metadata of one V3 search result entry
/// (`SearchQueryService`), as a [`ManifestSummary`] without dependency
/// groups. `authors`, `owners` and `tags` may be arrays or strings; text is
/// trimmed and empty values are dropped, as for a `.nuspec`.
pub fn summary_from_search_hit(hit: &serde_json::Value) -> ManifestSummary {
    use serde_json::Value;

    let text = |key: &str| {
        hit.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let list = |key: &str, split: fn(char) -> bool| -> Vec<String> {
        let items: Vec<&str> = match hit.get(key) {
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
            Some(Value::String(joined)) => joined.split(split).collect(),
            _ => Vec::new(),
        };
        items
            .into_iter()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .collect()
    };
    let names =
        |key: &str| Some(list(key, |c| c == ',').join(", ")).filter(|joined| !joined.is_empty());
    let package_types = hit
        .get("packageTypes")
        .and_then(Value::as_array)
        .map(|types| {
            types
                .iter()
                .filter_map(|t| t.get("name")?.as_str())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    ManifestSummary {
        metadata: NuspecMetadata {
            title: text("title"),
            description: text("description"),
            summary: text("summary"),
            authors: names("authors"),
            owners: names("owners"),
            tags: list("tags", |c| c.is_whitespace() || c == ',' || c == ';'),
            project_url: text("projectUrl"),
            license_url: text("licenseUrl"),
            icon_url: text("iconUrl"),
            package_types,
            ..NuspecMetadata::default()
        },
        dependency_groups: Vec::new(),
    }
}

/// The [`ManifestSummary`] of a version: the stored one when present (and
/// readable), else parsed from the manifest bytes; empty when neither works.
pub fn summary_of(stored: Option<&serde_json::Value>, manifest: Option<&[u8]>) -> ManifestSummary {
    if let Some(summary) =
        stored.and_then(|v| serde_json::from_value::<ManifestSummary>(v.clone()).ok())
    {
        return summary;
    }
    manifest
        .and_then(|b| manifest_summary(b).ok())
        .unwrap_or_default()
}

/// Extract just the dependency groups from raw `.nuspec` bytes.
///
/// Used by the registration route to render `dependencyGroups` without
/// re-reading the package zip (the manifest is already stored as an asset).
pub fn dependency_groups_from_nuspec(bytes: &[u8]) -> Result<Vec<DependencyGroup>, FormatError> {
    Ok(parse_nuspec(bytes).map_err(FormatError::from)?.deps)
}

/// The identity a standalone `.nuspec` declares, as `(lower_id, normalized
/// version)`. Used to verify a manifest fetched from an upstream before it is
/// served or cached; a manifest over `limits.max_nuspec_bytes` is rejected.
pub fn manifest_identity(
    bytes: &[u8],
    limits: &NupkgLimits,
) -> Result<(String, String), FormatError> {
    if bytes.len() as u64 > limits.max_nuspec_bytes {
        return Err(NupkgError::LimitExceeded(format!(
            ".nuspec of {} bytes exceeds max {}",
            bytes.len(),
            limits.max_nuspec_bytes
        ))
        .into());
    }
    let raw = parse_nuspec(bytes)?;
    Ok((lower_id(&raw.id), version::normalize(&raw.version)?))
}

/// Render a minimal `.nuspec` declaring `id`, `version` and `deps`.
///
/// A proxy knows the dependency groups of a version it has not downloaded yet
/// only from the upstream registration; rendering them as a manifest lets the
/// registration and package-detail views parse them through
/// [`dependency_groups_from_nuspec`] exactly like a stored manifest.
pub fn synthesize_nuspec(id: &str, version: &str, deps: &[DependencyGroup]) -> Vec<u8> {
    use quick_xml::escape::escape;
    use std::fmt::Write as _;

    let mut xml = String::from(concat!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
        "<package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">\n",
        "  <metadata>\n",
    ));
    let _ = writeln!(xml, "    <id>{}</id>", escape(id));
    let _ = writeln!(xml, "    <version>{}</version>", escape(version));
    if !deps.is_empty() {
        xml.push_str("    <dependencies>\n");
        for group in deps {
            match &group.target_framework {
                Some(tfm) => {
                    let _ = writeln!(xml, "      <group targetFramework=\"{}\">", escape(tfm));
                }
                None => xml.push_str("      <group>\n"),
            }
            for dep in &group.dependencies {
                let _ = write!(xml, "        <dependency id=\"{}\"", escape(&dep.id));
                if let Some(range) = &dep.range {
                    let _ = write!(xml, " version=\"{}\"", escape(range));
                }
                xml.push_str(" />\n");
            }
            xml.push_str("      </group>\n");
        }
        xml.push_str("    </dependencies>\n");
    }
    xml.push_str("  </metadata>\n</package>\n");
    xml.into_bytes()
}

/// Locate and read the `*.nuspec` entry out of the zip, enforcing limits.
///
/// Only the manifest is decompressed, so the size and compression-ratio caps
/// apply to it alone; other entries are bounded only by the archive-shape
/// limits (entry count, central-directory size, total declared size). The
/// central directory is read one header at a time and nothing is kept of an
/// entry but the manifest's, so a package of many entries costs the time to
/// read its directory once, not memory.
fn extract_nuspec(file: &mut dyn ReadSeek, limits: &NupkgLimits) -> Result<Vec<u8>, NupkgError> {
    // Vet the end-of-central-directory records before the central directory
    // they describe is read.
    let directory = check_archive_directory(file, limits)?;
    // Check every entry and choose the manifest as NuGet would.
    let manifest = find_manifest(file, &directory, limits)?;
    read_manifest(file, &manifest, limits)
}

/// Local file header signature (`PK\x03\x04`) and the size of its fixed part.
const LOCAL_HEADER_SIG: [u8; 4] = *b"PK\x03\x04";
const LOCAL_HEADER_LEN: usize = 30;
/// The compression methods a manifest is read in: stored, and deflated (what
/// NuGet writes).
const STORED: u16 = 0;
const DEFLATED: u16 = 8;

/// Decompress the manifest [`find_manifest`] chose, under the manifest caps.
///
/// Its sizes, compression method and CRC-32 are its central header's. Of its
/// local header only the signature and the lengths of the name and the extra
/// field are read, to find where its data starts, as .NET (and so NuGet) does.
fn read_manifest(
    file: &mut dyn ReadSeek,
    manifest: &ManifestEntry,
    limits: &NupkgLimits,
) -> Result<Vec<u8>, NupkgError> {
    let declared = manifest.uncompressed_size;
    if declared > limits.max_nuspec_bytes {
        return Err(NupkgError::LimitExceeded(format!(
            ".nuspec declared size {declared} exceeds max {}",
            limits.max_nuspec_bytes
        )));
    }
    if let Some(ratio) = declared.checked_div(manifest.compressed_size) {
        if ratio > limits.max_nuspec_compression_ratio {
            return Err(NupkgError::LimitExceeded(format!(
                ".nuspec compression ratio {ratio} exceeds max {}",
                limits.max_nuspec_compression_ratio
            )));
        }
    }

    let len = file.seek(SeekFrom::End(0))?;
    let header = match manifest.local_header.checked_add(LOCAL_HEADER_LEN as u64) {
        Some(end) if end <= len => read_at(file, manifest.local_header, LOCAL_HEADER_LEN)?,
        _ => {
            return Err(NupkgError::InvalidZip(
                "the manifest's local header lies outside the archive".into(),
            ))
        }
    };
    if header[..4] != LOCAL_HEADER_SIG {
        return Err(NupkgError::InvalidZip(
            "the manifest's local header is corrupt".into(),
        ));
    }
    let data = manifest.local_header
        + LOCAL_HEADER_LEN as u64
        + u64::from(le_u16(&header, 26))
        + u64::from(le_u16(&header, 28));
    if data
        .checked_add(manifest.compressed_size)
        .is_none_or(|end| end > len)
    {
        return Err(NupkgError::InvalidZip(
            "the manifest's data runs past the end of the archive".into(),
        ));
    }

    file.seek(SeekFrom::Start(data))?;
    let compressed = (&mut *file).take(manifest.compressed_size);
    // Read with a hard cap: the declared size is within the manifest cap, and
    // one byte past it tells a manifest that is longer than it says.
    let cap = declared + 1;
    let mut buf = Vec::new();
    let read = match manifest.method {
        STORED => compressed.take(cap).read_to_end(&mut buf),
        DEFLATED => flate2::read::DeflateDecoder::new(compressed)
            .take(cap)
            .read_to_end(&mut buf),
        method => {
            return Err(NupkgError::UnsupportedEntry(format!(
                "the manifest uses compression method {method}; only stored and deflated are read"
            )))
        }
    };
    read.map_err(|e| match e.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
            NupkgError::InvalidZip(format!("the manifest does not decompress: {e}"))
        }
        _ => NupkgError::Io(e),
    })?;
    if buf.len() as u64 != declared {
        return Err(NupkgError::InvalidZip(format!(
            "the manifest decompresses to {} bytes, not the {declared} its header declares",
            buf.len()
        )));
    }
    if crc32fast::hash(&buf) != manifest.crc32 {
        return Err(NupkgError::InvalidZip(
            "the manifest does not match its CRC-32".into(),
        ));
    }
    Ok(buf)
}

/// End-of-central-directory record signature (`PK\x05\x06`) and fixed size.
const EOCD_SIG: [u8; 4] = *b"PK\x05\x06";
const EOCD_LEN: u64 = 22;
/// ZIP64 end-of-central-directory locator signature (`PK\x06\x07`) and size.
const ZIP64_LOCATOR_SIG: [u8; 4] = *b"PK\x06\x07";
const ZIP64_LOCATOR_LEN: u64 = 20;
/// ZIP64 end-of-central-directory record signature (`PK\x06\x06`) and the
/// size of its fixed part.
const ZIP64_EOCD_SIG: [u8; 4] = *b"PK\x06\x06";
const ZIP64_EOCD_LEN: u64 = 56;
/// Where a well-formed archive's trailing records can start, counted from the
/// end of the file: the EOCD with a maximal comment, preceded by the ZIP64
/// locator and record.
const ZIP_TRAILER_WINDOW: u64 = EOCD_LEN + u16::MAX as u64 + ZIP64_LOCATOR_LEN + ZIP64_EOCD_LEN;

/// A central directory, as an end-of-central-directory record declares it.
#[derive(Debug, Default)]
struct Directory {
    /// Where it starts in the archive.
    start: u64,
    /// Its size in bytes.
    size: u64,
    /// How many entries [`find_manifest`] walks.
    entries: u64,
}

/// Vet the archive's end-of-central-directory records against the entry-count
/// and central-directory limits **before** the central directory they describe
/// is read.
///
/// Takes the record NuGet reads: the last EOCD signature with a whole record
/// after it (plus, for ZIP64, the record its locator names), refusing one
/// whose comment runs past the end of the file, which other zip readers pass
/// over, and one whose ZIP64 marker they read differently from NuGet. Earlier
/// signature matches — which ordinary compressed data or a package signature
/// contains by chance — are never read.
fn check_archive_directory(
    file: &mut dyn ReadSeek,
    limits: &NupkgLimits,
) -> Result<Directory, NupkgError> {
    let len = file.seek(SeekFrom::End(0))?;
    let trailer = ZIP_TRAILER_WINDOW.min(len);
    // NuGet (.NET's `ZipArchive`) reads the last signature with a whole
    // record after it, whatever its comment says: .NET 8 and .NET Framework
    // read what comment there is, .NET 9 and later refuse the archive. Other
    // zip readers (the `zip` crate, for one) pass over a record whose comment
    // runs past the end of the file for an earlier one, so such an archive is
    // refused.
    let Some(pos) = find_signatures(file, len - trailer, len, &EOCD_SIG)?
        .into_iter()
        .rev()
        .find(|pos| pos + EOCD_LEN <= len)
    else {
        return Err(NupkgError::InvalidZip(
            "no end-of-central-directory record near the end of the archive".into(),
        ));
    };
    let rec = read_at(file, pos, EOCD_LEN as usize)?;
    if pos + EOCD_LEN + u64::from(le_u16(&rec, 20)) > len {
        return Err(NupkgError::InvalidZip(
            "the end-of-central-directory record's comment runs past the end of the archive".into(),
        ));
    }
    check_eocd_candidate(file, pos, len, limits)
}

/// Check one EOCD candidate at `pos`. Returns the central directory it
/// declares, with the number of entries [`find_manifest`] walks.
///
/// When a field holds the ZIP64 marker (`0xFFFF…`) and a ZIP64 locator
/// precedes the record, only the ZIP64 record's counts are used (the one at
/// the locator's offset), otherwise the 32-bit counts are; of those, the
/// entries on this disk are walked.
fn check_eocd_candidate(
    file: &mut dyn ReadSeek,
    pos: u64,
    len: u64,
    limits: &NupkgLimits,
) -> Result<Directory, NupkgError> {
    if pos + EOCD_LEN > len {
        return Ok(Directory::default());
    }
    let rec = read_at(file, pos, EOCD_LEN as usize)?;
    let disk = le_u16(&rec, 4);
    let (on_disk, total) = (le_u16(&rec, 8), le_u16(&rec, 10));
    let (directory, offset) = (le_u32(&rec, 12), le_u32(&rec, 16));
    let zip64_marker = total == u16::MAX || directory == u32::MAX || offset == u32::MAX;
    // NuGet (.NET's `ZipArchive`) looks for the ZIP64 records when the disk
    // number, the offset or the entry count holds the marker, other zip
    // readers (the `zip` crate, for one) when the entry count, the size or the
    // offset does: with the marker in the size or the disk number alone, they
    // read different central directories.
    if zip64_marker != (disk == u16::MAX || offset == u32::MAX || total == u16::MAX) {
        return Err(NupkgError::InvalidZip(
            "the end-of-central-directory record marks ZIP64 in a field NuGet reads otherwise"
                .into(),
        ));
    }

    // A ZIP64 locator sits immediately before the EOCD. The record it names
    // must be exactly there: a reader that went looking for it elsewhere (as
    // the `zip` crate does in an archive with data prepended) would read a
    // record that was never vetted, so the archive is refused.
    if zip64_marker && pos >= ZIP64_LOCATOR_LEN {
        let loc = read_at(file, pos - ZIP64_LOCATOR_LEN, ZIP64_LOCATOR_LEN as usize)?;
        if loc[..4] == ZIP64_LOCATOR_SIG {
            let record = le_u64(&loc, 8);
            if record < pos && read_at(file, record, 4)? == ZIP64_EOCD_SIG {
                return check_zip64_record(file, record, len, limits);
            }
            return Err(NupkgError::InvalidZip(
                "the ZIP64 locator does not point at a ZIP64 end-of-central-directory record"
                    .into(),
            ));
        }
    }
    check_directory_limits(u64::from(on_disk.max(total)), u64::from(directory), limits)?;
    Ok(Directory {
        start: u64::from(offset),
        size: u64::from(directory),
        entries: u64::from(on_disk),
    })
}

/// Check one ZIP64 end-of-central-directory record at `pos`. Returns the
/// central directory it declares, with the number of entries [`find_manifest`]
/// walks (the total).
fn check_zip64_record(
    file: &mut dyn ReadSeek,
    pos: u64,
    len: u64,
    limits: &NupkgLimits,
) -> Result<Directory, NupkgError> {
    if pos + ZIP64_EOCD_LEN > len {
        return Ok(Directory::default());
    }
    let rec = read_at(file, pos, ZIP64_EOCD_LEN as usize)?;
    let (on_disk, total) = (le_u64(&rec, 24), le_u64(&rec, 32));
    let (size, start) = (le_u64(&rec, 40), le_u64(&rec, 48));
    check_directory_limits(on_disk.max(total), size, limits)?;
    Ok(Directory {
        start,
        size,
        entries: total,
    })
}

fn check_directory_limits(
    entries: u64,
    directory: u64,
    limits: &NupkgLimits,
) -> Result<(), NupkgError> {
    if entries > limits.max_entries as u64 {
        return Err(NupkgError::LimitExceeded(format!(
            "{entries} entries exceeds max {}",
            limits.max_entries
        )));
    }
    if directory > limits.max_central_directory_bytes {
        return Err(NupkgError::LimitExceeded(format!(
            "zip central directory of {directory} bytes exceeds max {}",
            limits.max_central_directory_bytes
        )));
    }
    Ok(())
}

/// Central-directory file header signature (`PK\x01\x02`) and the size of
/// its fixed part.
const CENTRAL_HEADER_SIG: [u8; 4] = *b"PK\x01\x02";
const CENTRAL_HEADER_LEN: usize = 46;
/// Extra-field ids: ZIP64 extended information, and the Info-ZIP Unicode Path.
const ZIP64_EXTRA_ID: u16 = 0x0001;
const UNICODE_PATH_EXTRA_ID: u16 = 0x7075;
/// The ZIP64 field's length from which .NET reads each of its values at its
/// fixed place (the two sizes and the local header offset, 8 bytes each, and
/// the disk, 4), skipping those the header does not mark.
const ZIP64_FIXED_PLACES_LEN: usize = 28;

/// The manifest's entry, as its central header (and ZIP64 field) declares it.
#[derive(Debug)]
struct ManifestEntry {
    /// Its compression method.
    method: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    /// Where its local header starts.
    local_header: u64,
}

/// What [`find_manifest`] reads the central directory through.
const DIRECTORY_BUFFER: usize = 64 * 1024;

/// Check every entry of the central directory [`check_archive_directory`]
/// vetted, as .NET's zip reader (and so NuGet) lists them, and return the
/// package's one manifest.
///
/// The directory is read one header at a time, and nothing is kept of an
/// entry but the manifest's: a package of a million entries costs the time to
/// read its directory, not memory. Each entry is checked as the directory
/// holds it, so a repeated name hides none of them (a reader that indexes the
/// entries by name, as the `zip` crate does, sees only the last). A repeated
/// name is no reason to refuse a package: packages on nuget.org hold
/// `packageIcon.png` twice (`Microsoft.Extensions.Logging.Abstractions`
/// 3.1.0, for one), and NuGet restores them. A repeated manifest is: NuGet
/// then sees several manifests, and refuses the package.
fn find_manifest(
    file: &mut dyn ReadSeek,
    directory: &Directory,
    limits: &NupkgLimits,
) -> Result<ManifestEntry, NupkgError> {
    let Directory {
        start,
        size,
        entries,
    } = *directory;
    let len = file.seek(SeekFrom::End(0))?;
    if start.checked_add(size).is_none_or(|end| end > len) {
        return Err(NupkgError::InvalidZip(
            "the central directory lies outside the archive".into(),
        ));
    }
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::with_capacity(DIRECTORY_BUFFER, (&mut *file).take(size));
    let truncated = || {
        NupkgError::InvalidZip(
            "the central directory holds fewer entries than its end record declares".into(),
        )
    };
    // Fill `buf` from the directory; running out of it means it holds fewer
    // headers than its end record declares.
    let mut read = |buf: &mut [u8]| {
        reader.read_exact(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => truncated(),
            _ => NupkgError::Io(e),
        })
    };

    // NuGet reads the one `*.nuspec` at the package root (and refuses a
    // package with several), ignoring nested ones; anything else would let
    // Forge and the client disagree about which manifest — and so which
    // identity — the package has. Every entry that some reading of its name
    // puts at the root counts ([`could_be_root_manifest`]), and the one
    // manifest must be named literally, so no reader can resolve it to a
    // different entry.
    let mut manifest: Option<ManifestEntry> = None;
    let mut total_uncompressed: u64 = 0;
    let mut header = [0u8; CENTRAL_HEADER_LEN];
    // The name, the extra fields and the comment of the header at hand.
    let mut variable = Vec::new();
    // The bytes of the headers read so far.
    let mut consumed: u64 = 0;
    for _ in 0..entries {
        read(&mut header)?;
        if header[..4] != CENTRAL_HEADER_SIG {
            return Err(truncated());
        }
        let flags = le_u16(&header, 8);
        let name_end = usize::from(le_u16(&header, 28));
        let extra_end = name_end + usize::from(le_u16(&header, 30));
        variable.resize(extra_end + usize::from(le_u16(&header, 32)), 0);
        read(&mut variable)?;
        consumed += (CENTRAL_HEADER_LEN + variable.len()) as u64;
        let raw = &variable[..name_end];
        let name = String::from_utf8_lossy(raw);

        if flags & 1 != 0 {
            return Err(NupkgError::UnsupportedEntry(format!(
                "entry {name:?} is encrypted"
            )));
        }
        // The uncompressed size, the compressed size and the local header's
        // offset, in the order a ZIP64 field holds those the header marks
        // (`0xFFFFFFFF`).
        let declared = [
            le_u32(&header, 24),
            le_u32(&header, 20),
            le_u32(&header, 42),
        ];
        let marked = declared.map(|v| v == u32::MAX);
        let mut values = declared.map(u64::from);
        let mut zip64 = false;
        let mut fields = &variable[name_end..extra_end];
        while let [a, b, c, d, rest @ ..] = fields {
            let id = u16::from_le_bytes([*a, *b]);
            let Some(data) = rest.get(..usize::from(u16::from_le_bytes([*c, *d]))) else {
                break;
            };
            // Zip readers that apply an Info-ZIP Unicode Path field (the
            // `zip` crate, for one) rename the entry after it, .NET ignores
            // it, so they would not agree on the name (nor on which entries
            // share one). Neither NuGet nor .NET writes the field.
            if id == UNICODE_PATH_EXTRA_ID {
                return Err(NupkgError::UnsupportedEntry(format!(
                    "entry {name:?} carries an Info-ZIP Unicode Path field"
                )));
            }
            if id == ZIP64_EXTRA_ID {
                // .NET reads the first ZIP64 field of a header, other zip
                // readers (the `zip` crate, for one) apply each in turn, so
                // the last wins: with two, they would find the entry's data
                // (its local header, its sizes) in different places, and
                // could read different manifests. Neither NuGet nor .NET
                // writes a second one.
                if std::mem::replace(&mut zip64, true) {
                    return Err(NupkgError::UnsupportedEntry(format!(
                        "entry {name:?} carries more than one ZIP64 extra field"
                    )));
                }
                // Forge, like most zip readers, takes the values the header
                // marks one after the other from the field's start, .NET
                // (from 28 bytes on) each at its fixed place: a marked value
                // after one that is not then sits at two places, so the two
                // would find the entry's local header (or its compressed
                // size) apart, and could read different manifests. Neither
                // NuGet nor .NET writes such a field.
                if data.len() >= ZIP64_FIXED_PLACES_LEN
                    && marked.windows(2).any(|pair| !pair[0] && pair[1])
                {
                    return Err(NupkgError::UnsupportedEntry(format!(
                        "entry {name:?} carries a ZIP64 extra field whose values NuGet reads from other places"
                    )));
                }
                // A marked value the field is too short to hold keeps the
                // header's `0xFFFFFFFF`, as with .NET.
                let mut next = data;
                for (value, _) in values.iter_mut().zip(marked).filter(|(_, m)| *m) {
                    if let Some((at, rest)) = next.split_first_chunk::<8>() {
                        *value = u64::from_le_bytes(*at);
                        next = rest;
                    }
                }
            }
            fields = &rest[data.len()..];
        }
        let [uncompressed_size, compressed_size, local_header] = values;

        // Entries other than the manifest are never decompressed, so neither
        // their individual size nor their compression ratio matters here; the
        // total declared size only rejects absurd archives.
        total_uncompressed = total_uncompressed.saturating_add(uncompressed_size);
        if total_uncompressed > limits.max_total_uncompressed {
            return Err(NupkgError::LimitExceeded(format!(
                "total uncompressed size exceeds max {}",
                limits.max_total_uncompressed
            )));
        }

        if could_be_root_manifest(raw) {
            if manifest.is_some() {
                return Err(NupkgError::MalformedNuspec(
                    "the package root holds more than one .nuspec".into(),
                ));
            }
            if raw.contains(&b'%') || raw.contains(&b'\\') {
                return Err(NupkgError::MalformedNuspec(format!(
                    "the manifest name {name:?} must not contain '%' or '\\'"
                )));
            }
            manifest = Some(ManifestEntry {
                method: le_u16(&header, 10),
                crc32: le_u32(&header, 16),
                compressed_size,
                uncompressed_size,
                local_header,
            });
        }
    }
    // .NET reads central headers on until one does not match, whatever size
    // the end record declares, and refuses an archive with more of them than
    // the record's count: a header right after the declared ones makes a
    // package no NuGet client installs, though Forge would list it.
    let next = start + consumed;
    if next + CENTRAL_HEADER_SIG.len() as u64 <= len
        && read_at(file, next, CENTRAL_HEADER_SIG.len())? == CENTRAL_HEADER_SIG
    {
        return Err(NupkgError::InvalidZip(
            "the central directory holds more entries than its end record declares".into(),
        ));
    }
    manifest.ok_or(NupkgError::MissingNuspec)
}

/// Offsets of every occurrence of `sig` starting in `[start, end)`, read in
/// bounded chunks.
fn find_signatures(
    file: &mut dyn ReadSeek,
    start: u64,
    end: u64,
    sig: &[u8; 4],
) -> Result<Vec<u64>, NupkgError> {
    const CHUNK: u64 = 64 * 1024;
    let mut out = Vec::new();
    let mut chunk_start = start;
    let mut buf = Vec::new();
    while chunk_start < end {
        // Overlap by the signature length so a match across chunks is seen.
        let chunk_end = (chunk_start + CHUNK + 3).min(end + 3);
        buf.clear();
        file.seek(SeekFrom::Start(chunk_start))?;
        (&mut *file)
            .take(chunk_end - chunk_start)
            .read_to_end(&mut buf)?;
        for (i, window) in buf.windows(4).enumerate() {
            let at = chunk_start + i as u64;
            if at < end.min(chunk_start + CHUNK) && window == sig {
                out.push(at);
            }
        }
        chunk_start += CHUNK;
    }
    Ok(out)
}

fn read_at(file: &mut dyn ReadSeek, pos: u64, len: usize) -> Result<Vec<u8>, NupkgError> {
    let mut buf = vec![0u8; len];
    file.seek(SeekFrom::Start(pos))?;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn le_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(raw)
}

/// Whether some reader could take the entry named `name` (the bytes the
/// central directory holds) for the manifest at the package root.
///
/// NuGet percent-decodes a name that holds `%` (`UnescapePath`), then treats
/// one ending in `.nuspec` (any case) with neither `/` nor `\` in it as a root
/// manifest (`PackageHelper.IsManifest` and `IsRoot`). Both the raw and the
/// decoded name are checked, so an entry counts if either reading puts it at
/// the root.
fn could_be_root_manifest(name: &[u8]) -> bool {
    is_root_nuspec(name) || (name.contains(&b'%') && is_root_nuspec(&percent_decode(name)))
}

fn is_root_nuspec(name: &[u8]) -> bool {
    const SUFFIX: &[u8] = b".nuspec";
    // `/` nests the entry under every reading of the name. `\` does for NuGet
    // too, but .NET Framework decodes a name without the UTF-8 flag in the
    // system code page, where a `\` byte can be the second half of a
    // double-byte character: in a name that is not pure ASCII it may not be a
    // separator at all.
    let nested = name.contains(&b'/') || (name.is_ascii() && name.contains(&b'\\'));
    !nested
        && name.len() >= SUFFIX.len()
        && name[name.len() - SUFFIX.len()..].eq_ignore_ascii_case(SUFFIX)
}

/// `name` with every `%XX` escape decoded to its byte, as
/// `Uri.UnescapeDataString` does for the ASCII ones (it keeps escapes that do
/// not form UTF-8, which only ever differ from these bytes outside ASCII).
fn percent_decode(name: &[u8]) -> Vec<u8> {
    let hex = |b: Option<&u8>| b.and_then(|b| (*b as char).to_digit(16));
    let mut out = Vec::with_capacity(name.len());
    let mut i = 0;
    while i < name.len() {
        if name[i] == b'%' {
            if let (Some(hi), Some(lo)) = (hex(name.get(i + 1)), hex(name.get(i + 2))) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(name[i]);
        i += 1;
    }
    out
}

/// The fields we pull out of a `.nuspec` manifest before normalization.
#[derive(Debug)]
struct RawNuspec {
    id: String,
    version: String,
    deps: Vec<DependencyGroup>,
    metadata: NuspecMetadata,
}

/// Deepest element nesting a `.nuspec` may use. Real manifests nest about
/// five levels (`package/metadata/dependencies/group/dependency`); the cap
/// bounds the parser's path bookkeeping on hostile input.
pub const MAX_NUSPEC_DEPTH: usize = 32;

/// Parse the `.nuspec` XML namespace-insensitively (by local name).
fn parse_nuspec(bytes: &[u8]) -> Result<RawNuspec, NupkgError> {
    let mut reader = Reader::from_reader(bytes);
    // Text is kept verbatim (entity references split it into several
    // events, so trimming per event would eat inner spaces); values are
    // trimmed once parsing is complete.
    reader.config_mut().trim_text(false);

    // Path of local element names, so we know our context (e.g. metadata/id).
    let mut path: Vec<Vec<u8>> = Vec::new();
    // Singular manifest elements seen so far ([`check_element`]).
    let mut seen = Seen::default();
    let mut id: Option<String> = None;
    let mut ver: Option<String> = None;
    let mut groups: Vec<DependencyGroup> = Vec::new();
    // The currently open <group> (a direct child of <dependencies>).
    let mut current_group: Option<DependencyGroup> = None;
    // Whether the manifest's <dependencies> holds a <group>: NuGet then
    // ignores the flat <dependency> elements beside them.
    let mut saw_group = false;
    // Flat (groupless) dependencies collected directly under <dependencies>.
    let mut flat_group: Option<DependencyGroup> = None;
    let mut metadata = NuspecMetadata::default();
    // `type` attribute of the currently open <license>, if any.
    let mut license_type: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| NupkgError::MalformedNuspec(e.to_string()))?
        {
            Event::Start(e) => {
                if path.len() >= MAX_NUSPEC_DEPTH {
                    return Err(NupkgError::MalformedNuspec(format!(
                        "elements nested deeper than {MAX_NUSPEC_DEPTH} levels"
                    )));
                }
                let local = e.local_name().as_ref().as_bytes().to_vec();
                check_element(&path, &local, &mut seen)?;
                match local.as_slice() {
                    b"metadata" if path.len() == 1 => {
                        metadata.min_client_version = attr_local(&e, b"minClientVersion")?;
                    }
                    b"license" if path.last().map(Vec::as_slice) == Some(b"metadata") => {
                        license_type = attr_local(&e, b"type")?;
                    }
                    // `<dependency ...></dependency>` (explicit end tag) is as
                    // valid as the self-closing form.
                    b"dependency" => {
                        collect_dependency(&path, &e, &mut current_group, &mut flat_group)?;
                    }
                    b"packageType" if path.last().map(Vec::as_slice) == Some(b"packageTypes") => {
                        if let Some(name) = attr_local(&e, b"name")? {
                            metadata.package_types.push(name);
                        }
                    }
                    b"dependencies" if in_metadata(&path) => {
                        flat_group = None;
                    }
                    b"group" if in_dependencies_element(&path) => {
                        saw_group = true;
                        let tfm = attr_local(&e, b"targetFramework")?;
                        current_group = Some(DependencyGroup {
                            target_framework: tfm,
                            dependencies: Vec::new(),
                        });
                    }
                    _ => {}
                }
                path.push(local);
            }
            Event::Empty(e) => {
                let local = e.local_name().as_ref().as_bytes().to_vec();
                check_element(&path, &local, &mut seen)?;
                match local.as_slice() {
                    b"dependency" => {
                        collect_dependency(&path, &e, &mut current_group, &mut flat_group)?;
                    }
                    b"packageType" if path.last().map(Vec::as_slice) == Some(b"packageTypes") => {
                        if let Some(name) = attr_local(&e, b"name")? {
                            metadata.package_types.push(name);
                        }
                    }
                    // A self-closing <group/> with no dependencies still
                    // represents a target framework group.
                    b"group" if in_dependencies_element(&path) => {
                        saw_group = true;
                        let tfm = attr_local(&e, b"targetFramework")?;
                        groups.push(DependencyGroup {
                            target_framework: tfm,
                            dependencies: Vec::new(),
                        });
                    }
                    _ => {}
                }
                // Empty elements do not change nesting depth.
            }
            Event::Text(t) => {
                let text = t.xml10_content().into_owned();
                append_text(
                    &path,
                    &text,
                    &mut id,
                    &mut ver,
                    &mut metadata,
                    &license_type,
                );
            }
            Event::CData(t) => {
                let text = t.xml10_content().into_owned();
                append_text(
                    &path,
                    &text,
                    &mut id,
                    &mut ver,
                    &mut metadata,
                    &license_type,
                );
            }
            Event::GeneralRef(r) => {
                let resolved = if r.is_char_ref() {
                    r.resolve_char_ref()
                        .map_err(|e| NupkgError::MalformedNuspec(e.to_string()))?
                        .map(String::from)
                } else {
                    let name: &str = &r;
                    quick_xml::escape::resolve_predefined_entity(name).map(str::to_string)
                };
                if let Some(text) = resolved {
                    append_text(
                        &path,
                        &text,
                        &mut id,
                        &mut ver,
                        &mut metadata,
                        &license_type,
                    );
                }
            }
            Event::End(e) => {
                let local = e.local_name().as_ref().as_bytes().to_vec();
                // `path` still ends with the element being closed.
                let parent = &path[..path.len().saturating_sub(1)];
                if local.as_slice() == b"group" && in_dependencies_element(parent) {
                    if let Some(g) = current_group.take() {
                        groups.push(g);
                    }
                } else if local.as_slice() == b"dependencies" && in_metadata(parent) {
                    // Like NuGet: flat dependencies only count when no
                    // <group> exists.
                    if let Some(g) = flat_group.take().filter(|_| !saw_group) {
                        groups.push(g);
                    }
                }
                path.pop();
            }
            // NuGet reads manifests with `DtdProcessing.Prohibit`, so it
            // refuses a package whose manifest declares a document type.
            Event::DocType(_) => {
                return Err(NupkgError::MalformedNuspec(
                    "a <!DOCTYPE> declaration is not allowed".into(),
                ));
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    metadata.trim();
    let id = id.ok_or_else(|| NupkgError::MalformedNuspec("missing <id>".into()))?;
    let version = ver.ok_or_else(|| NupkgError::MalformedNuspec("missing <version>".into()))?;
    if id.trim().is_empty() {
        return Err(NupkgError::MalformedNuspec("empty <id>".into()));
    }
    if version.trim().is_empty() {
        return Err(NupkgError::MalformedNuspec("empty <version>".into()));
    }

    Ok(RawNuspec {
        id: id.trim().to_string(),
        version: version.trim().to_string(),
        deps: groups,
        metadata,
    })
}

/// Route a piece of element text to its field. Text of one element may
/// arrive in several pieces (entity references, CDATA), so values append.
fn append_text(
    path: &[Vec<u8>],
    text: &str,
    id: &mut Option<String>,
    ver: &mut Option<String>,
    metadata: &mut NuspecMetadata,
    license_type: &Option<String>,
) {
    if !under_metadata_parent(path) {
        return;
    }
    let slot = match path.last().map(Vec::as_slice) {
        Some(b"id") => id,
        Some(b"version") => ver,
        Some(b"title") => &mut metadata.title,
        Some(b"description") => &mut metadata.description,
        Some(b"summary") => &mut metadata.summary,
        Some(b"authors") => &mut metadata.authors,
        Some(b"owners") => &mut metadata.owners,
        Some(b"projectUrl") => &mut metadata.project_url,
        Some(b"licenseUrl") => &mut metadata.license_url,
        Some(b"iconUrl") => &mut metadata.icon_url,
        Some(b"releaseNotes") => &mut metadata.release_notes,
        Some(b"copyright") => &mut metadata.copyright,
        Some(b"language") => &mut metadata.language,
        Some(b"tags") => &mut metadata.raw_tags,
        Some(b"requireLicenseAcceptance") => &mut metadata.raw_require_license_acceptance,
        Some(b"license")
            if license_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("expression")) =>
        {
            &mut metadata.license_expression
        }
        _ => return,
    };
    slot.get_or_insert_with(String::new).push_str(text);
}

/// Build a [`Dependency`] from a `<dependency>` element's attributes.
fn parse_dependency(e: &quick_xml::events::BytesStart) -> Result<Dependency, NupkgError> {
    let dep_id = attr_local(e, b"id")?
        .ok_or_else(|| NupkgError::MalformedNuspec("<dependency> missing id".into()))?;
    let range = attr_local(e, b"version")?;
    Ok(Dependency { id: dep_id, range })
}

/// Record a `<dependency>` (whose parents are `path`) the way NuGet reads
/// it: a direct child of `<dependencies>` is a flat (groupless) dependency,
/// a direct child of a `<group>` there belongs to that group, and one nested
/// anywhere else is not a dependency at all.
fn collect_dependency(
    path: &[Vec<u8>],
    e: &quick_xml::events::BytesStart<'_>,
    current_group: &mut Option<DependencyGroup>,
    flat_group: &mut Option<DependencyGroup>,
) -> Result<(), NupkgError> {
    if in_dependencies_element(path) {
        flat_group
            .get_or_insert_with(|| DependencyGroup {
                target_framework: None,
                dependencies: Vec::new(),
            })
            .dependencies
            .push(parse_dependency(e)?);
    } else if let (Some((last, parent)), Some(group)) = (path.split_last(), current_group.as_mut())
    {
        if last.as_slice() == b"group" && in_dependencies_element(parent) {
            group.dependencies.push(parse_dependency(e)?);
        }
    }
    Ok(())
}

/// True if the next element is a direct child of the manifest's
/// `<dependencies>` — the path is `[package, metadata, dependencies]`.
fn in_dependencies_element(path: &[Vec<u8>]) -> bool {
    path.len() == 3 && path[1].as_slice() == b"metadata" && path[2].as_slice() == b"dependencies"
}

/// True if the *parent* of the current text node is the manifest's
/// `<metadata>` — i.e. the path is `[package, metadata, id|version|…]`.
/// Guards against e.g. an `<id>` nested in a dependency or a decoy
/// `<metadata>` deeper in the document.
fn under_metadata_parent(path: &[Vec<u8>]) -> bool {
    path.len() == 3 && path[1].as_slice() == b"metadata"
}

/// Whether `path` is exactly the manifest's `<metadata>` (`[package,
/// metadata]`), i.e. a child started now is a direct child of it.
fn in_metadata(path: &[Vec<u8>]) -> bool {
    path.len() == 2 && path[1].as_slice() == b"metadata"
}

/// Singular manifest elements already seen.
#[derive(Default)]
struct Seen {
    metadata: bool,
    id: bool,
    version: bool,
    dependencies: bool,
}

/// Hold the manifest to the one shape NuGet reads: a root `<package>` whose
/// single `<metadata>` child has one text-only `<id>` and `<version>` and at
/// most one `<dependencies>`. NuGet takes the *first* `<id>` (and ignores a
/// `<metadata>` or `<dependencies>` anywhere else), while a lenient reading
/// would join repeated ones or pick up a nested decoy — a package whose
/// identity Forge and the client disagree on, published past an id-scoped
/// grant. Such manifests are refused.
fn check_element(path: &[Vec<u8>], local: &[u8], seen: &mut Seen) -> Result<(), NupkgError> {
    let malformed = |what: &str| Err(NupkgError::MalformedNuspec(what.to_string()));
    match path.len() {
        0 if local != b"package" => malformed("the root element must be <package>"),
        1 if local == b"metadata" => {
            if std::mem::replace(&mut seen.metadata, true) {
                return malformed("more than one <metadata>");
            }
            Ok(())
        }
        2 if in_metadata(path) => {
            let slot = match local {
                b"id" => &mut seen.id,
                b"version" => &mut seen.version,
                b"dependencies" => &mut seen.dependencies,
                _ => return Ok(()),
            };
            if std::mem::replace(slot, true) {
                return malformed(&format!(
                    "more than one <{}>",
                    String::from_utf8_lossy(local)
                ));
            }
            Ok(())
        }
        3 if path[1].as_slice() == b"metadata"
            && matches!(path[2].as_slice(), b"id" | b"version") =>
        {
            malformed("<id> and <version> hold text only")
        }
        _ => Ok(()),
    }
}

/// Read an attribute by its *local* name (namespace-insensitive).
fn attr_local(
    e: &quick_xml::events::BytesStart,
    local: &[u8],
) -> Result<Option<String>, NupkgError> {
    for attr in e.attributes().with_checks(false) {
        let attr = attr.map_err(|err| NupkgError::MalformedNuspec(err.to_string()))?;
        let key = attr.key;
        let key_local = key.local_name();
        if key_local.as_ref().as_bytes() == local {
            // Equivalent to the (deprecated) `unescape_value`: decode UTF-8 and
            // resolve the predefined XML entities (`&amp;`, `&lt;`, …).
            let val = attr
                .normalized_value_with(
                    quick_xml::XmlVersion::Implicit1_0,
                    1,
                    quick_xml::escape::resolve_predefined_entity,
                )
                .map_err(|err| NupkgError::MalformedNuspec(err.to_string()))?
                .into_owned();
            return Ok(Some(val));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deeply_nested_manifests_are_rejected_quickly() {
        let depth = 200_000;
        let xml = format!(
            "<package><metadata><id>a</id><version>1.0.0</version>{}{}</metadata></package>",
            "<x>".repeat(depth),
            "</x>".repeat(depth)
        );
        let started = std::time::Instant::now();
        let err = parse_nuspec(xml.as_bytes()).expect_err("too deep");
        assert!(err.to_string().contains("nested deeper"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        // Realistic nesting still parses.
        let ok = "<package><metadata><id>a</id><version>1.0.0</version><dependencies>\
                  <group targetFramework=\"net8.0\"><dependency id=\"b\" version=\"1.0\"/>\
                  </group></dependencies></metadata></package>";
        let parsed = parse_nuspec(ok.as_bytes()).unwrap();
        assert_eq!(parsed.deps[0].dependencies[0].id, "b");
    }

    #[test]
    fn search_hits_map_to_manifest_summaries() {
        let hit = serde_json::json!({
            "id": "Serilog",
            "version": "4.0.0",
            "title": " Serilog ",
            "description": "Simple .NET logging",
            "summary": "",
            "authors": ["Serilog Contributors", " "],
            "owners": "serilog, nblumhardt",
            "tags": ["logging", "semantic"],
            "projectUrl": "https://serilog.net/",
            "licenseUrl": "https://licenses.nuget.org/Apache-2.0",
            "iconUrl": "https://api.nuget.org/v3-flatcontainer/serilog/4.0.0/icon",
            "packageTypes": [{ "name": "Dependency" }],
            "totalDownloads": 1
        });
        let summary = summary_from_search_hit(&hit);
        let meta = &summary.metadata;
        assert_eq!(meta.title.as_deref(), Some("Serilog"));
        assert_eq!(meta.description.as_deref(), Some("Simple .NET logging"));
        assert_eq!(meta.summary, None);
        assert_eq!(meta.authors.as_deref(), Some("Serilog Contributors"));
        assert_eq!(meta.owners.as_deref(), Some("serilog, nblumhardt"));
        assert_eq!(meta.tags, ["logging", "semantic"]);
        assert_eq!(meta.project_url.as_deref(), Some("https://serilog.net/"));
        assert_eq!(meta.package_types, ["Dependency"]);
        assert!(summary.dependency_groups.is_empty());

        // Tags as one string, and a hit without metadata.
        let meta = summary_from_search_hit(&serde_json::json!({ "tags": "a b,c" })).metadata;
        assert_eq!(meta.tags, ["a", "b", "c"]);
        assert_eq!(
            summary_from_search_hit(&serde_json::json!({})),
            ManifestSummary::default()
        );
    }

    #[test]
    fn manifest_summary_round_trips_through_json() {
        let xml = "<package><metadata><id>A</id><version>1.0.0</version><description>d</description>\
                   <tags>x y</tags><dependencies><dependency id=\"b\" version=\"1.0\"/></dependencies>\
                   </metadata></package>";
        let summary = manifest_summary(xml.as_bytes()).unwrap();
        let stored = serde_json::to_value(&summary).unwrap();
        assert_eq!(summary_of(Some(&stored), None), summary);
        assert_eq!(summary_of(None, Some(xml.as_bytes())), summary);
        assert_eq!(
            summary.metadata.tags,
            vec!["x".to_string(), "y".to_string()]
        );
        assert_eq!(summary_of(None, None), ManifestSummary::default());
    }

    #[test]
    fn parses_id_version_and_grouped_deps_namespace_insensitive() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Sample.Lib</id>
    <version>1.02.3-Beta</version>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="[13.0.1, )" />
      </group>
      <group targetFramework="netstandard2.0" />
    </dependencies>
  </metadata>
</package>"#;
        let raw = parse_nuspec(xml).unwrap();
        assert_eq!(raw.id, "Sample.Lib");
        assert_eq!(raw.version, "1.02.3-Beta");
        assert_eq!(raw.deps.len(), 2);
        assert_eq!(raw.deps[0].target_framework.as_deref(), Some("net8.0"));
        assert_eq!(raw.deps[0].dependencies[0].id, "Newtonsoft.Json");
        assert_eq!(
            raw.deps[0].dependencies[0].range.as_deref(),
            Some("[13.0.1, )")
        );
        assert_eq!(
            raw.deps[1].target_framework.as_deref(),
            Some("netstandard2.0")
        );
        assert!(raw.deps[1].dependencies.is_empty());
    }

    #[test]
    fn parses_flat_dependencies_without_groups() {
        let xml = br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>Flat.Pkg</id>
    <version>2.0.0</version>
    <dependencies>
      <dependency id="A" version="1.0.0" />
      <dependency id="B" />
    </dependencies>
  </metadata>
</package>"#;
        let raw = parse_nuspec(xml).unwrap();
        assert_eq!(raw.deps.len(), 1);
        assert_eq!(raw.deps[0].target_framework, None);
        assert_eq!(raw.deps[0].dependencies.len(), 2);
        assert_eq!(raw.deps[0].dependencies[1].id, "B");
        assert_eq!(raw.deps[0].dependencies[1].range, None);
    }

    #[test]
    fn dependency_groups_are_read_the_way_nuget_reads_them() {
        // #75: NuGet reads only direct children of <dependencies>, and once a
        // <group> exists it ignores the flat <dependency> elements.
        let xml = br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>Mixed.Pkg</id>
    <version>1.0.0</version>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="A" version="1.0.0" />
        <x><dependency id="Nested.In.Group" /></x>
      </group>
      <dependency id="B" version="1.0.0" />
      <wrapper>
        <group targetFramework="net48"><dependency id="C" /></group>
        <dependency id="D" />
      </wrapper>
    </dependencies>
  </metadata>
</package>"#;
        let raw = parse_nuspec(xml).unwrap();
        assert_eq!(raw.deps.len(), 1, "{:?}", raw.deps);
        assert_eq!(raw.deps[0].target_framework.as_deref(), Some("net8.0"));
        let ids: Vec<&str> = raw.deps[0]
            .dependencies
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        assert_eq!(ids, ["A"]);

        // Without a group, only the direct flat dependencies count.
        let xml = br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>Flat.Pkg</id>
    <version>1.0.0</version>
    <dependencies>
      <dependency id="B" />
      <wrapper><dependency id="D" /></wrapper>
    </dependencies>
  </metadata>
</package>"#;
        let raw = parse_nuspec(xml).unwrap();
        assert_eq!(raw.deps.len(), 1);
        let ids: Vec<&str> = raw.deps[0]
            .dependencies
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        assert_eq!(ids, ["B"]);
    }

    #[test]
    fn ignores_unprefixed_namespace_and_prefixed_elements() {
        // Using an explicit prefix on every element; local-name matching must
        // still find id/version/dependencies.
        let xml = br#"<?xml version="1.0"?>
<n:package xmlns:n="http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd">
  <n:metadata>
    <n:id>Prefixed.Pkg</n:id>
    <n:version>3.0.0</n:version>
  </n:metadata>
</n:package>"#;
        let raw = parse_nuspec(xml).unwrap();
        assert_eq!(raw.id, "Prefixed.Pkg");
        assert_eq!(raw.version, "3.0.0");
        assert!(raw.deps.is_empty());
    }

    #[test]
    fn manifests_with_an_ambiguous_identity_are_refused() {
        let wrap = |metadata: &str| format!("<package><metadata>{metadata}</metadata></package>");
        for (xml, why) in [
            (
                wrap("<id>Foo</id><id>Bar</id><version>1.0.0</version>"),
                "repeated <id>",
            ),
            (
                wrap("<id>Foo</id><version>1.0.0</version><version>2.0.0</version>"),
                "repeated <version>",
            ),
            (
                wrap("<id>Foo<x/>Bar</id><version>1.0.0</version>"),
                "element inside <id>",
            ),
            (
                wrap("<id/><id>Foo</id><version>1.0.0</version>"),
                "empty then real <id>",
            ),
            (
                wrap(
                    "<id>Foo</id><version>1.0.0</version><dependencies/><dependencies>\
                      <dependency id=\"X\"/></dependencies>",
                ),
                "repeated <dependencies>",
            ),
            (
                "<package><metadata><id>Foo</id><version>1.0.0</version></metadata>\
                 <metadata><id>Bar</id></metadata></package>"
                    .to_string(),
                "repeated <metadata>",
            ),
            (
                "<other><metadata><id>Foo</id><version>1.0.0</version></metadata></other>"
                    .to_string(),
                "root is not <package>",
            ),
        ] {
            assert!(parse_nuspec(xml.as_bytes()).is_err(), "{why}: {xml}");
        }
        // A `<metadata>` nested elsewhere is not the manifest's (NuGet ignores
        // it), and neither are dependencies outside the real one.
        let xml = "<package><files><metadata><id>Decoy</id></metadata></files>\
                   <metadata><id>Real</id><version>1.0.0</version></metadata>\
                   <x><dependencies><dependency id=\"Y\"/></dependencies></x></package>";
        let raw = parse_nuspec(xml.as_bytes()).unwrap();
        assert_eq!(raw.id, "Real");
        assert!(raw.deps.is_empty());
    }

    #[test]
    fn only_a_single_root_level_nuspec_is_the_manifest() {
        let nuspec = |id: &str| {
            format!("<package><metadata><id>{id}</id><version>1.0.0</version></metadata></package>")
        };
        let limits = NupkgLimits::default();
        let extract = |zip: Vec<u8>| extract_nuspec(&mut std::io::Cursor::new(zip), &limits);
        // Two at the root: NuGet refuses the package, so must Forge.
        let zip = zip_of(&[
            ("A.nuspec", nuspec("A").as_bytes()),
            ("B.nuspec", nuspec("B").as_bytes()),
        ]);
        assert!(extract(zip).is_err());
        // Only a nested one: NuGet finds no manifest.
        let zip = zip_of(&[("lib/Decoy.nuspec", nuspec("Decoy").as_bytes())]);
        assert!(matches!(extract(zip), Err(NupkgError::MissingNuspec)));
        // A nested decoy beside the root manifest is ignored.
        let zip = zip_of(&[
            ("content/Decoy.nuspec", nuspec("Decoy").as_bytes()),
            ("Real.nuspec", nuspec("Real").as_bytes()),
        ]);
        let bytes = extract(zip).unwrap();
        assert_eq!(parse_nuspec(&bytes).unwrap().id, "Real");
    }

    fn nuspec_of(id: &str) -> Vec<u8> {
        format!("<package><metadata><id>{id}</id><version>1.0.0</version></metadata></package>")
            .into_bytes()
    }

    fn manifest_id(zip: Vec<u8>) -> Result<String, NupkgError> {
        let bytes = extract_nuspec(&mut std::io::Cursor::new(zip), &NupkgLimits::default())?;
        Ok(parse_nuspec(&bytes)?.id)
    }

    #[test]
    fn the_manifest_is_chosen_by_nuget_s_reading_of_entry_names() {
        // The review's case: NuGet takes `x\allowed.nuspec` as nested and
        // decodes `victim%2Enuspec` to the root manifest `victim.nuspec`; a
        // reader splitting on `/` alone and not decoding takes the other.
        let zip = zip_of(&[
            ("x\\allowed.nuspec", &nuspec_of("Allowed.Lib")),
            ("victim%2Enuspec", &nuspec_of("Victim.Lib")),
        ]);
        assert!(matches!(
            manifest_id(zip),
            Err(NupkgError::MalformedNuspec(_))
        ));
        // A manifest NuGet finds only by decoding its name is refused too.
        let zip = zip_of(&[("victim%2Enuspec", &nuspec_of("Victim.Lib"))]);
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("must not contain '%'"), "{err}");
        // So is one whose decoded name is nested but raw name is not.
        let zip = zip_of(&[("x%2Fvictim.nuspec", &nuspec_of("Victim.Lib"))]);
        assert!(manifest_id(zip).is_err());
        // Escapes that decode to a second root manifest count as one.
        let zip = zip_of(&[
            ("Real.nuspec", &nuspec_of("Real")),
            ("Other%2Enuspec", &nuspec_of("Other")),
        ]);
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("more than one"), "{err}");
        // Root manifests that differ only in case are two manifests.
        let zip = zip_of(&[
            ("Real.nuspec", &nuspec_of("Real")),
            ("real.NUSPEC", &nuspec_of("Other")),
        ]);
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("more than one"), "{err}");

        // `\` nests a manifest as `/` does: it is ignored beside the root one,
        // and on its own leaves the package without a manifest.
        let zip = zip_of(&[
            ("content\\Decoy.nuspec", &nuspec_of("Decoy")),
            ("Real.NuSpec", &nuspec_of("Real")),
        ]);
        assert_eq!(manifest_id(zip).unwrap(), "Real");
        let zip = zip_of(&[("lib\\Decoy.nuspec", &nuspec_of("Decoy"))]);
        assert!(matches!(manifest_id(zip), Err(NupkgError::MissingNuspec)));
        // In a non-ASCII name a `\` byte may belong to a double-byte
        // character, so it does not count as nesting the entry.
        let zip = zip_of(&[
            ("Ü\\Decoy.nuspec", &nuspec_of("Decoy")),
            ("Real.nuspec", &nuspec_of("Real")),
        ]);
        assert!(manifest_id(zip).is_err());

        // Escaped names elsewhere in the package are fine: `nuget pack`
        // writes them for file names with spaces and the like.
        let zip = zip_of(&[
            ("lib/net8.0/My%20Lib.dll", b"MZ"),
            ("content/a%5Cb.nuspec", &nuspec_of("Decoy")),
            ("Real.nuspec", &nuspec_of("Real")),
        ]);
        assert_eq!(manifest_id(zip).unwrap(), "Real");
    }

    /// Rename the entry `from` to `to` (of the same length) in its local and
    /// central headers, so an archive can repeat a name the zip writer
    /// refuses to write twice.
    fn rename_entry(zip: &mut [u8], from: &str, to: &str) {
        assert_eq!(from.len(), to.len());
        let mut renamed = 0;
        for at in 0..=zip.len() - from.len() {
            if &zip[at..at + from.len()] == from.as_bytes() {
                zip[at..at + to.len()].copy_from_slice(to.as_bytes());
                renamed += 1;
            }
        }
        assert_eq!(renamed, 2, "local header and central directory");
    }

    /// Where the central headers of the entries named `name` start.
    fn central_headers_of(zip: &[u8], name: &str) -> Vec<usize> {
        let directory = zip.len() - EOCD_LEN as usize;
        let directory = le_u32(zip, directory + 16) as usize;
        (directory..zip.len() - name.len())
            .filter(|&at| &zip[at..at + name.len()] == name.as_bytes())
            .map(|at| at - CENTRAL_HEADER_LEN)
            .collect()
    }

    #[test]
    fn repeated_entry_names_are_read_as_nuget_reads_them() {
        // `Microsoft.Extensions.Logging.Abstractions` 3.1.0 on nuget.org
        // holds `packageIcon.png` twice, and NuGet restores it.
        let mut zip = zip_of(&[
            ("Real.nuspec", &nuspec_of("Real")),
            ("packageIcon.png", b"one"),
            ("packageIcoN.png", b"two"),
        ]);
        rename_entry(&mut zip, "packageIcoN.png", "packageIcon.png");
        // The `zip` crate keys its index by name: it sees one icon.
        let archive = zip::ZipArchive::new(std::io::Cursor::new(zip.clone())).unwrap();
        assert_eq!(archive.len(), 2);
        assert_eq!(manifest_id(zip).unwrap(), "Real");

        // Two entries named `a.nuspec`: NuGet sees two manifests, the `zip`
        // crate only the last one.
        let mut zip = zip_of(&[
            ("a.nuspec", &nuspec_of("First")),
            ("b.nuspec", &nuspec_of("Second")),
        ]);
        rename_entry(&mut zip, "b.nuspec", "a.nuspec");
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("more than one"), "{err}");

        // An entry the `zip` crate hides is checked like any other: an
        // encrypted one is refused...
        let mut zip = zip_of(&[
            ("Real.nuspec", &nuspec_of("Real")),
            ("lib/a.dll", b"MZ"),
            ("lib/b.dll", b"MZ"),
        ]);
        rename_entry(&mut zip, "lib/b.dll", "lib/a.dll");
        let hidden = central_headers_of(&zip, "lib/a.dll")[0];
        zip[hidden + 8] |= 1;
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("encrypted"), "{err}");
        // ...so is one the `zip` crate renames into another entry's name...
        let zip = {
            use std::io::Write;
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            zw.start_file("Real.nuspec", zip::write::FullFileOptions::default())
                .unwrap();
            zw.write_all(&nuspec_of("Real")).unwrap();
            zw.start_file("lib/a.dat", unicode_path("lib/a.dat", "lib/b.dat"))
                .unwrap();
            zw.start_file("lib/b.dat", zip::write::FullFileOptions::default())
                .unwrap();
            zw.finish().unwrap().into_inner()
        };
        let archive = zip::ZipArchive::new(std::io::Cursor::new(zip.clone())).unwrap();
        assert_eq!(archive.len(), 2);
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("Unicode Path"), "{err}");
        // ...and its size counts against the total.
        let payload = vec![0u8; 600 * 1024];
        let mut zip = zip_of(&[
            ("p.nuspec", OK_NUSPEC.as_bytes()),
            ("big.bin", &payload),
            ("bIg.bin", &payload),
        ]);
        rename_entry(&mut zip, "bIg.bin", "big.bin");
        let limits = NupkgLimits {
            max_total_uncompressed: 1024 * 1024,
            ..NupkgLimits::default()
        };
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &limits).unwrap_err();
        assert!(err.to_string().contains("total uncompressed"), "{err}");
    }

    #[test]
    fn the_central_directory_must_hold_the_entries_its_end_record_declares() {
        let mut zip = zip_of(&[("p.nuspec", OK_NUSPEC.as_bytes())]);
        let eocd = eocd_offset(&zip);
        zip[eocd + 8..eocd + 12].copy_from_slice(&[2, 0, 2, 0]);
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap_err();
        assert!(err.to_string().contains("fewer entries"), "{err}");
    }

    #[test]
    fn the_central_directory_must_hold_no_more_entries_than_its_end_record_declares() {
        let zip = zip_of(&[
            ("p.nuspec", OK_NUSPEC.as_bytes()),
            ("lib/a.dll", b"a"),
            ("lib/b.dll", b"b"),
        ]);
        let eocd = eocd_offset(&zip);
        let directory = le_u32(&zip, eocd + 16) as usize;
        let third = central_headers_of(&zip, "lib/b.dll")[0];
        // The end record counts two entries, and its size covers all three
        // headers, as .NET reads them; or only the two, while .NET reads on.
        for size in [eocd - directory, third - directory] {
            let mut zip = zip.clone();
            zip[eocd + 8..eocd + 12].copy_from_slice(&[2, 0, 2, 0]);
            zip[eocd + 12..eocd + 16].copy_from_slice(&(size as u32).to_le_bytes());
            let err =
                parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap_err();
            assert!(err.to_string().contains("more entries"), "{size}: {err}");
        }
        // Whatever follows the declared headers otherwise is no entry.
        let mut zip = zip_of(&[("p.nuspec", OK_NUSPEC.as_bytes())]);
        let eocd = eocd_offset(&zip);
        let directory = le_u32(&zip, eocd + 16) as usize;
        zip.splice(eocd..eocd, *b"PK\x05\x05\0\0");
        let size = le_u32(&zip, eocd + 6 + 12) + 6;
        zip[eocd + 6 + 12..eocd + 6 + 16].copy_from_slice(&size.to_le_bytes());
        assert_eq!(le_u32(&zip, eocd + 6 + 16) as usize, directory);
        let parsed = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap();
        assert_eq!(parsed.id, "a.b");
    }

    #[test]
    fn packages_of_tens_of_thousands_of_entries_are_read() {
        // A package that bundles web assets: more entries than the 10 000
        // Forge took at most before.
        let zip = {
            use std::io::Write;
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let stored = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for i in 0..30_000 {
                zw.start_file(format!("content/wwwroot/js/{i}.js"), stored)
                    .unwrap();
            }
            zw.start_file("p.nuspec", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(OK_NUSPEC.as_bytes()).unwrap();
            zw.finish().unwrap().into_inner()
        };
        let parsed = parse_nupkg(
            &mut std::io::Cursor::new(zip.clone()),
            &NupkgLimits::default(),
        )
        .unwrap();
        assert_eq!(parsed.id, "a.b");
        assert_eq!(parsed.nuspec_bytes, OK_NUSPEC.as_bytes());

        let limits = NupkgLimits {
            max_entries: 10_000,
            ..NupkgLimits::default()
        };
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &limits).unwrap_err();
        assert!(
            err.to_string().contains("30001 entries exceeds max 10000"),
            "{err}"
        );
    }

    #[test]
    fn the_manifest_is_read_as_its_central_header_declares_it() {
        let stored = || {
            use std::io::Write;
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let stored = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zw.start_file("p.nuspec", stored).unwrap();
            zw.write_all(OK_NUSPEC.as_bytes()).unwrap();
            zw.finish().unwrap().into_inner()
        };
        let refused = |zip: Vec<u8>, why: &str| {
            let err = manifest_id(zip).unwrap_err();
            assert!(err.to_string().contains(why), "{why}: {err}");
        };
        // Stored and deflated manifests are read.
        assert_eq!(manifest_id(stored()).unwrap(), "A.B");
        let deflated = zip_of(&[("p.nuspec", OK_NUSPEC.as_bytes())]);
        let central = central_headers_of(&deflated, "p.nuspec")[0];
        assert_eq!(le_u16(&deflated, central + 10), DEFLATED);
        assert_eq!(manifest_id(deflated.clone()).unwrap(), "A.B");

        // A CRC-32 that does not match.
        let mut zip = stored();
        let central = central_headers_of(&zip, "p.nuspec")[0];
        zip[central + 16] ^= 1;
        refused(zip, "CRC-32");
        // A deflate stream that does not decompress to the manifest.
        let mut zip = deflated.clone();
        zip[LOCAL_HEADER_LEN + "p.nuspec".len()] ^= 0xFF;
        let err = manifest_id(zip).unwrap_err();
        assert!(matches!(err, NupkgError::InvalidZip(_)), "{err}");
        // A compression method other than stored or deflated (bzip2).
        let mut zip = stored();
        let central = central_headers_of(&zip, "p.nuspec")[0];
        zip[central + 10..central + 12].copy_from_slice(&12u16.to_le_bytes());
        refused(zip, "compression method 12");
        // A declared size the manifest does not have.
        let mut zip = stored();
        let central = central_headers_of(&zip, "p.nuspec")[0];
        let size = le_u32(&zip, central + 24) - 1;
        zip[central + 24..central + 28].copy_from_slice(&size.to_le_bytes());
        refused(zip, "not the");
        // A local header that is not one, or lies outside the archive.
        let mut zip = stored();
        zip[0] = b'X';
        refused(zip, "local header is corrupt");
        let mut zip = stored();
        let central = central_headers_of(&zip, "p.nuspec")[0];
        zip[central + 42..central + 46].copy_from_slice(&u32::MAX.to_le_bytes());
        refused(zip, "outside the archive");
        // Data that runs past the end of the archive.
        let mut zip = stored();
        let central = central_headers_of(&zip, "p.nuspec")[0];
        zip[central + 20..central + 24].copy_from_slice(&(1u32 << 20).to_le_bytes());
        refused(zip, "past the end");
    }

    #[test]
    fn zip64_entry_sizes_count_against_the_total() {
        // The header holds 0xFFFFFFFF and the ZIP64 field the size.
        let zip = {
            use std::io::Write;
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            zw.start_file("p.nuspec", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(OK_NUSPEC.as_bytes()).unwrap();
            let large = zip::write::SimpleFileOptions::default().large_file(true);
            zw.start_file("big.bin", large).unwrap();
            zw.write_all(&vec![0u8; 2 * 1024 * 1024]).unwrap();
            zw.finish().unwrap().into_inner()
        };
        let header = central_headers_of(&zip, "big.bin")[0];
        assert_eq!(le_u32(&zip, header + 24), u32::MAX);
        let limits = NupkgLimits {
            max_total_uncompressed: 1024 * 1024,
            ..NupkgLimits::default()
        };
        let err = parse_nupkg(&mut std::io::Cursor::new(zip.clone()), &limits).unwrap_err();
        assert!(err.to_string().contains("total uncompressed"), "{err}");
        let parsed = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap();
        assert_eq!(parsed.id, "a.b");
    }

    #[test]
    fn two_zip64_fields_in_a_header_are_refused() {
        // One central header whose local header offset is in its ZIP64
        // field, twice: .NET (and so NuGet) reads the first field and the
        // manifest of `Good.Package`, the `zip` crate the last and that of
        // `Evil.Package`.
        let (good, evil) = (nuspec_of("Good.Package"), nuspec_of("Evil.Package"));
        let zip = zip64_manifest(&[&good, &evil], crc32(&evil), false, |locals| {
            locals
                .iter()
                .flat_map(|local| zip64_field(&local.to_le_bytes()))
                .collect()
        });

        // The `zip` crate really does read the last field's manifest.
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip.clone())).unwrap();
        let mut read = Vec::new();
        archive.by_index(0).unwrap().read_to_end(&mut read).unwrap();
        assert_eq!(read, evil);
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("more than one ZIP64"), "{err}");
    }

    #[test]
    fn a_zip64_field_read_at_other_places_by_net_is_refused() {
        // One ZIP64 field of 28 bytes, the header marking only the local
        // header offset: the `zip` crate takes the offset from the field's
        // first 8 bytes and the manifest of `Good.Package`, .NET 8 and later
        // (and so NuGet in `dotnet restore`) from its third 8 and that of
        // `Evil.Package`.
        let (good, evil) = (nuspec_of("Good.Package"), nuspec_of("Evil.Package"));
        let zip = zip64_manifest(&[&good, &evil], crc32(&good), false, |locals| {
            let mut values = Vec::new();
            for value in [locals[0], 0, locals[1]] {
                values.extend_from_slice(&value.to_le_bytes());
            }
            values.extend_from_slice(&0u32.to_le_bytes());
            zip64_field(&values)
        });
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip.clone())).unwrap();
        let mut read = Vec::new();
        archive.by_index(0).unwrap().read_to_end(&mut read).unwrap();
        assert_eq!(read, good);
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("other places"), "{err}");

        // Every value marked: both read each one at its fixed place.
        let len = good.len() as u64;
        let zip = zip64_manifest(&[&good], crc32(&good), true, |locals| {
            let mut values = Vec::new();
            for value in [len, len, locals[0]] {
                values.extend_from_slice(&value.to_le_bytes());
            }
            values.extend_from_slice(&0u32.to_le_bytes());
            zip64_field(&values)
        });
        assert_eq!(manifest_id(zip).unwrap(), "Good.Package");
    }

    /// A ZIP64 extended information field holding `values`.
    fn zip64_field(values: &[u8]) -> Vec<u8> {
        let mut field = 0x0001u16.to_le_bytes().to_vec();
        field.extend_from_slice(&u16::try_from(values.len()).unwrap().to_le_bytes());
        field.extend_from_slice(values);
        field
    }

    /// A package of stored local headers, one for each of `manifests` (all of
    /// one length), and one central header of `Pkg.nuspec` with `crc`, whose
    /// local header offset (and with `sizes_marked` its sizes) is
    /// `0xFFFFFFFF`, and whose extra fields `extra` writes from the local
    /// headers' offsets.
    fn zip64_manifest(
        manifests: &[&[u8]],
        crc: u32,
        sizes_marked: bool,
        extra: impl FnOnce(&[u64]) -> Vec<u8>,
    ) -> Vec<u8> {
        fn put16(zip: &mut Vec<u8>, v: u16) {
            zip.extend_from_slice(&v.to_le_bytes());
        }
        fn put32(zip: &mut Vec<u8>, v: u32) {
            zip.extend_from_slice(&v.to_le_bytes());
        }
        let name = b"Pkg.nuspec";
        let len = u32::try_from(manifests[0].len()).unwrap();
        assert!(manifests
            .iter()
            .all(|data| data.len() == manifests[0].len()));
        let mut zip = Vec::new();
        let mut locals = Vec::new();
        for data in manifests {
            locals.push(zip.len() as u64);
            put32(&mut zip, 0x0403_4b50);
            // Version, flags, stored, time, date.
            for v in [20, 0, 0, 0, 0x21] {
                put16(&mut zip, v);
            }
            put32(&mut zip, crc32(data));
            put32(&mut zip, len);
            put32(&mut zip, len);
            put16(&mut zip, name.len() as u16);
            put16(&mut zip, 0);
            zip.extend_from_slice(name);
            zip.extend_from_slice(data);
        }
        let directory = zip.len();
        put32(&mut zip, 0x0201_4b50);
        // Made by, needed, flags, stored, time, date.
        for v in [45, 45, 0, 0, 0, 0x21] {
            put16(&mut zip, v);
        }
        put32(&mut zip, crc);
        let size = if sizes_marked { u32::MAX } else { len };
        put32(&mut zip, size);
        put32(&mut zip, size);
        let extra = extra(&locals);
        // Name, extra fields, comment, disk, internal attributes.
        for v in [name.len() as u16, extra.len() as u16, 0, 0, 0] {
            put16(&mut zip, v);
        }
        put32(&mut zip, 0);
        // The local header's offset is in the ZIP64 field.
        put32(&mut zip, u32::MAX);
        zip.extend_from_slice(name);
        zip.extend_from_slice(&extra);
        let directory_size = zip.len() - directory;
        put32(&mut zip, 0x0605_4b50);
        for v in [0, 0, 1, 1] {
            put16(&mut zip, v);
        }
        put32(&mut zip, directory_size as u32);
        put32(&mut zip, directory as u32);
        put16(&mut zip, 0);
        zip
    }

    /// CRC-32 (IEEE), as the Info-ZIP Unicode Path field stores it.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in bytes {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }

    /// Options writing an Info-ZIP Unicode Path field (0x7075) that names the
    /// entry `header` as `unicode`.
    fn unicode_path(header: &str, unicode: &str) -> zip::write::FullFileOptions<'static, 'static> {
        let mut data = vec![1u8];
        data.extend_from_slice(&crc32(header.as_bytes()).to_le_bytes());
        data.extend_from_slice(unicode.as_bytes());
        let mut opts = zip::write::FullFileOptions::default();
        opts.add_extra_field(0x7075, data, false).unwrap();
        opts
    }

    #[test]
    fn unicode_path_extra_fields_are_refused() {
        // Each entry's Info-ZIP Unicode Path field (0x7075) swaps its name
        // for the other's role: the `zip` crate applies the field, .NET (and
        // so NuGet) ignores it and reads `Victim.nuspec` as the manifest.
        let zip = {
            use std::io::Write;
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            zw.start_file("lib/a.dat", unicode_path("lib/a.dat", "Allowed.nuspec"))
                .unwrap();
            zw.write_all(&nuspec_of("Allowed.Lib")).unwrap();
            zw.start_file("Victim.nuspec", unicode_path("Victim.nuspec", "lib/v.dat"))
                .unwrap();
            zw.write_all(&nuspec_of("Victim.Lib")).unwrap();
            zw.finish().unwrap().into_inner()
        };
        // The `zip` crate really does see the swapped names.
        let archive = zip::ZipArchive::new(std::io::Cursor::new(zip.clone())).unwrap();
        let names: Vec<_> = archive.file_names().map(|n| n.unwrap()).collect();
        assert_eq!(names, ["Allowed.nuspec", "lib/v.dat"]);
        let err = manifest_id(zip).unwrap_err();
        assert!(err.to_string().contains("Unicode Path"), "{err}");
    }

    #[test]
    fn a_doctype_is_refused_as_nuget_does() {
        let xml = br#"<?xml version="1.0"?><!DOCTYPE package [<!ENTITY x "Victim">]>
            <package><metadata><id>A.B</id><version>1.0.0</version></metadata></package>"#;
        let err = parse_nuspec(xml).unwrap_err();
        assert!(err.to_string().contains("DOCTYPE"), "{err}");
    }

    #[test]
    fn missing_id_or_version_is_error() {
        let xml = br#"<package><metadata><version>1.0.0</version></metadata></package>"#;
        assert!(parse_nuspec(xml).is_err());
        let xml2 = br#"<package><metadata><id>X</id></metadata></package>"#;
        assert!(parse_nuspec(xml2).is_err());
    }

    #[test]
    fn lower_id_is_unicode_invariant() {
        assert_eq!(lower_id("Newtonsoft.JSON"), "newtonsoft.json");
        assert_eq!(lower_id("  Foo.Bar  "), "foo.bar");
        // Non-ASCII letters are valid in ids, so they must lower too: NuGet
        // clients request `ünicode.lib` (`ToLowerInvariant()`).
        assert_eq!(lower_id("Ünicode.Lib"), "ünicode.lib");
        assert_eq!(lower_id("ÆØÅ.Pakke"), lower_id("æøå.pakke"));
    }

    #[test]
    fn extracts_display_metadata_with_entities_and_cdata() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/10/nuspec.xsd">
  <metadata minClientVersion="4.1">
    <id>Contoso.Tools</id>
    <version>2.1.0</version>
    <title>Contoso Tools</title>
    <authors>Alice &amp; Bob</authors>
    <description><![CDATA[Fast <b>and</b> safe]]> tooling</description>
    <tags>cli  tools,build</tags>
    <license type="expression">MIT OR Apache-2.0</license>
    <projectUrl>https://example.com/tools</projectUrl>
    <requireLicenseAcceptance>true</requireLicenseAcceptance>
    <packageTypes><packageType name="DotnetTool" /></packageTypes>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Explicit.End" version="1.0.0"></dependency>
        <dependency id="Self.Closing" version="2.0.0" />
      </group>
    </dependencies>
  </metadata>
</package>"#;
        let raw = parse_nuspec(xml).unwrap();
        let m = &raw.metadata;
        assert_eq!(m.authors.as_deref(), Some("Alice & Bob"));
        assert_eq!(
            m.description.as_deref(),
            Some("Fast <b>and</b> safe tooling")
        );
        assert_eq!(m.tags, ["cli", "tools", "build"]);
        assert_eq!(m.license_expression.as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(m.project_url.as_deref(), Some("https://example.com/tools"));
        assert!(m.require_license_acceptance);
        assert_eq!(m.package_types, ["DotnetTool"]);
        assert_eq!(m.min_client_version.as_deref(), Some("4.1"));
        let ids: Vec<&str> = raw.deps[0]
            .dependencies
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        assert_eq!(ids, ["Explicit.End", "Self.Closing"]);
    }

    #[test]
    fn package_id_grammar() {
        for ok in ["A", "Newtonsoft.Json", "my_pkg-2.x", "Ünicode.Lib"] {
            assert!(validate_package_id(ok).is_ok(), "{ok}");
        }
        // An accepted non-ASCII id is stored under the id clients look up.
        let unicode = r#"<package><metadata><id>Ünicode.Lib</id><version>1.0.0</version></metadata></package>"#;
        let parsed = parse_nupkg(&mut nupkg_with(unicode), &NupkgLimits::default()).unwrap();
        assert_eq!(parsed.id, "ünicode.lib");
        assert_eq!(parsed.original_id, "Ünicode.Lib");
        let long = "a".repeat(101);
        for bad in [
            "",
            ".lead",
            "trail.",
            "two..dots",
            "sp ace",
            "slash/x",
            long.as_str(),
        ] {
            assert!(validate_package_id(bad).is_err(), "{bad}");
        }
    }

    fn nupkg_with(nuspec: &str) -> std::io::Cursor<Vec<u8>> {
        use std::io::Write;
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zw.start_file("p.nuspec", zip::write::SimpleFileOptions::default())
            .unwrap();
        zw.write_all(nuspec.as_bytes()).unwrap();
        std::io::Cursor::new(zw.finish().unwrap().into_inner())
    }

    /// A zip holding `entries` (name, bytes), deflated.
    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in entries {
            zw.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(body).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    const OK_NUSPEC: &str =
        r#"<package><metadata><id>A.B</id><version>1.0.0</version></metadata></package>"#;

    /// Offset of the (last) EOCD record of a comment-less archive.
    fn eocd_offset(zip: &[u8]) -> usize {
        zip.len() - EOCD_LEN as usize
    }

    #[test]
    fn large_and_compressible_payload_entries_are_not_capped() {
        // A payload entry compressed far beyond the old per-entry ratio cap
        // (200) is never decompressed, so it must not fail the package (the
        // `zip-bomb.nupkg` fixture covers the old 64 MiB per-entry size cap).
        let payload = vec![0u8; 4 * 1024 * 1024];
        let zip = zip_of(&[
            ("p.nuspec", OK_NUSPEC.as_bytes()),
            ("runtimes/x/native.so", &payload),
        ]);
        let parsed = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap();
        assert_eq!(parsed.id, "a.b");
    }

    #[test]
    fn total_declared_size_is_still_bounded() {
        let payload = vec![0u8; 2 * 1024 * 1024];
        let zip = zip_of(&[("p.nuspec", OK_NUSPEC.as_bytes()), ("big.bin", &payload)]);
        let limits = NupkgLimits {
            max_total_uncompressed: 1024 * 1024,
            ..NupkgLimits::default()
        };
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &limits).unwrap_err();
        assert!(err.to_string().contains("total uncompressed"), "{err}");
    }

    #[test]
    fn nuspec_size_and_ratio_caps_apply_to_the_manifest() {
        // Oversized manifest (declared size over the cap).
        let padding = " ".repeat(2 * 1024 * 1024);
        let big = format!("<package><metadata><id>A.B</id><version>1.0.0</version><description>{padding}</description></metadata></package>");
        let zip = zip_of(&[("p.nuspec", big.as_bytes())]);
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap_err();
        assert!(err.to_string().contains(".nuspec declared size"), "{err}");

        // A manifest under the size cap but compressed far beyond the ratio cap.
        let padding = " ".repeat(512 * 1024);
        let bomb = format!("<package><metadata><id>A.B</id><version>1.0.0</version><description>{padding}</description></metadata></package>");
        let zip = zip_of(&[("p.nuspec", bomb.as_bytes())]);
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap_err();
        assert!(err.to_string().contains("compression ratio"), "{err}");
    }

    #[test]
    fn eocd_entry_count_is_checked_before_the_directory_is_parsed() {
        let mut zip = zip_of(&[("p.nuspec", OK_NUSPEC.as_bytes())]);
        let eocd = eocd_offset(&zip);
        assert_eq!(zip[eocd..eocd + 4], EOCD_SIG);
        // Claim 60 000 entries; walking the directory would only notice the
        // lie at its end — the pre-check refuses up front.
        zip[eocd + 8..eocd + 10].copy_from_slice(&60_000u16.to_le_bytes());
        zip[eocd + 10..eocd + 12].copy_from_slice(&60_000u16.to_le_bytes());
        let limits = NupkgLimits {
            max_entries: 50_000,
            ..NupkgLimits::default()
        };
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &limits).unwrap_err();
        assert!(
            err.to_string().contains("60000 entries exceeds max"),
            "{err}"
        );
    }

    #[test]
    fn eocd_directory_size_is_checked_before_the_directory_is_parsed() {
        let mut zip = zip_of(&[("p.nuspec", OK_NUSPEC.as_bytes())]);
        let eocd = eocd_offset(&zip);
        zip[eocd + 12..eocd + 16].copy_from_slice(&(512u32 * 1024 * 1024).to_le_bytes());
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("central directory of 536870912 bytes exceeds max"),
            "{err}"
        );
    }

    #[test]
    fn zip64_entry_count_is_checked_before_the_directory_is_parsed() {
        // An empty archive with a ZIP64 trailer claiming two million entries:
        // [ZIP64 EOCD record][ZIP64 locator][EOCD with 0xFFFF markers].
        let mut zip = Vec::new();
        zip.extend_from_slice(&ZIP64_EOCD_SIG);
        zip.extend_from_slice(&44u64.to_le_bytes()); // size of the remaining record
        zip.extend_from_slice(&45u16.to_le_bytes()); // version made by
        zip.extend_from_slice(&45u16.to_le_bytes()); // version needed
        zip.extend_from_slice(&0u32.to_le_bytes()); // this disk
        zip.extend_from_slice(&0u32.to_le_bytes()); // disk with the directory
        zip.extend_from_slice(&2_000_000u64.to_le_bytes()); // entries on this disk
        zip.extend_from_slice(&2_000_000u64.to_le_bytes()); // total entries
        zip.extend_from_slice(&0u64.to_le_bytes()); // directory size
        zip.extend_from_slice(&0u64.to_le_bytes()); // directory offset
        zip.extend_from_slice(&ZIP64_LOCATOR_SIG);
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u64.to_le_bytes()); // ZIP64 record offset
        zip.extend_from_slice(&1u32.to_le_bytes());
        zip.extend_from_slice(&EOCD_SIG);
        zip.extend_from_slice(&[0, 0, 0, 0]);
        zip.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        zip.extend_from_slice(&[0xFF; 8]);
        zip.extend_from_slice(&0u16.to_le_bytes());
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("2000000 entries exceeds max 1000000"),
            "{err}"
        );
    }

    #[test]
    fn a_zip64_locator_must_name_its_record() {
        // The ZIP64 trailer of the test above, shifted by 16 bytes of junk
        // while the locator still says offset 0: a reader that looked for the
        // record elsewhere would trust a million unvetted entries.
        let mut zip = vec![0u8; 16];
        zip.extend_from_slice(&ZIP64_EOCD_SIG);
        zip.extend_from_slice(&44u64.to_le_bytes());
        zip.extend_from_slice(&45u16.to_le_bytes());
        zip.extend_from_slice(&45u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&1_000_000u64.to_le_bytes());
        zip.extend_from_slice(&1_000_000u64.to_le_bytes());
        zip.extend_from_slice(&0u64.to_le_bytes());
        zip.extend_from_slice(&0u64.to_le_bytes());
        zip.extend_from_slice(&ZIP64_LOCATOR_SIG);
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u64.to_le_bytes()); // names offset 0: junk
        zip.extend_from_slice(&1u32.to_le_bytes());
        zip.extend_from_slice(&EOCD_SIG);
        zip.extend_from_slice(&[0, 0, 0, 0]);
        zip.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        zip.extend_from_slice(&[0xFF; 8]);
        zip.extend_from_slice(&0u16.to_le_bytes());
        let err = check_archive_directory(&mut std::io::Cursor::new(zip), &NupkgLimits::default())
            .unwrap_err();
        assert!(err.to_string().contains("ZIP64 locator"), "{err}");
    }

    #[test]
    fn signature_lookalikes_in_entry_data_are_not_vetted() {
        // Stored (uncompressed) payload bytes that happen to contain EOCD and
        // ZIP64-record signatures with absurd counts, inside the trailing
        // window. NuGet reads the real EOCD at the end, so must we.
        let mut payload = Vec::new();
        payload.extend_from_slice(&EOCD_SIG);
        payload.extend_from_slice(&[0xFF; 18]);
        payload.extend_from_slice(&ZIP64_EOCD_SIG);
        payload.extend_from_slice(&[0xFF; 52]);
        payload.extend(std::iter::repeat_n(7u8, 1024));
        let zip = {
            use std::io::Write;
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            zw.start_file("p.nuspec", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(OK_NUSPEC.as_bytes()).unwrap();
            let stored = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zw.start_file("lib/payload.bin", stored).unwrap();
            zw.write_all(&payload).unwrap();
            zw.finish().unwrap().into_inner()
        };
        assert!(zip.windows(4).filter(|w| *w == EOCD_SIG).count() >= 2);
        let parsed = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap();
        assert_eq!(parsed.id, "a.b");
    }

    /// An archive of a `Good.Package` and an `Evil.Package` manifest of the
    /// same name, stored, with a central directory of its own each (the evil
    /// one first, ended by four zero bytes, where .NET stops reading headers),
    /// and no end record yet. Returns it with the good and the evil
    /// directory's offset and size.
    fn two_directories() -> (Vec<u8>, (u32, u32), (u32, u32)) {
        const NAME: &[u8] = b"Pkg.nuspec";
        fn put16(zip: &mut Vec<u8>, v: u16) {
            zip.extend_from_slice(&v.to_le_bytes());
        }
        fn put32(zip: &mut Vec<u8>, v: u32) {
            zip.extend_from_slice(&v.to_le_bytes());
        }
        let local = |zip: &mut Vec<u8>, data: &[u8]| {
            let at = zip.len() as u32;
            put32(zip, 0x0403_4b50);
            for v in [20, 0, 0, 0, 0x21] {
                put16(zip, v);
            }
            put32(zip, crc32(data));
            put32(zip, data.len() as u32);
            put32(zip, data.len() as u32);
            put16(zip, NAME.len() as u16);
            put16(zip, 0);
            zip.extend_from_slice(NAME);
            zip.extend_from_slice(data);
            at
        };
        let central = |zip: &mut Vec<u8>, data: &[u8], local_at: u32| {
            let at = zip.len() as u32;
            put32(zip, 0x0201_4b50);
            for v in [20, 20, 0, 0, 0, 0x21] {
                put16(zip, v);
            }
            put32(zip, crc32(data));
            put32(zip, data.len() as u32);
            put32(zip, data.len() as u32);
            for v in [NAME.len() as u16, 0, 0, 0, 0] {
                put16(zip, v);
            }
            put32(zip, 0);
            put32(zip, local_at);
            zip.extend_from_slice(NAME);
            (at, zip.len() as u32 - at)
        };
        let (good, evil) = (nuspec_of("Good.Package"), nuspec_of("Evil.Package"));
        let mut zip = Vec::new();
        let good_at = local(&mut zip, &good);
        let evil_at = local(&mut zip, &evil);
        let evil_directory = central(&mut zip, &evil, evil_at);
        put32(&mut zip, 0);
        let good_directory = central(&mut zip, &good, good_at);
        (zip, good_directory, evil_directory)
    }

    /// An end-of-central-directory record of one entry.
    fn end_record(zip: &mut Vec<u8>, disk: u16, (offset, size): (u32, u32), comment: u16) {
        zip.extend_from_slice(&EOCD_SIG);
        for v in [disk, disk, 1, 1] {
            zip.extend_from_slice(&v.to_le_bytes());
        }
        zip.extend_from_slice(&size.to_le_bytes());
        zip.extend_from_slice(&offset.to_le_bytes());
        zip.extend_from_slice(&comment.to_le_bytes());
    }

    /// A ZIP64 end record of one entry naming `(offset, size)`, and its
    /// locator.
    fn zip64_trailer(zip: &mut Vec<u8>, (offset, size): (u32, u32)) {
        let record = zip.len() as u64;
        zip.extend_from_slice(&ZIP64_EOCD_SIG);
        zip.extend_from_slice(&44u64.to_le_bytes());
        zip.extend_from_slice(&45u16.to_le_bytes());
        zip.extend_from_slice(&45u16.to_le_bytes());
        zip.extend_from_slice(&[0; 8]);
        zip.extend_from_slice(&1u64.to_le_bytes());
        zip.extend_from_slice(&1u64.to_le_bytes());
        zip.extend_from_slice(&u64::from(size).to_le_bytes());
        zip.extend_from_slice(&u64::from(offset).to_le_bytes());
        zip.extend_from_slice(&ZIP64_LOCATOR_SIG);
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&record.to_le_bytes());
        zip.extend_from_slice(&1u32.to_le_bytes());
    }

    #[test]
    fn the_end_record_is_the_one_nuget_reads() {
        // The baseline: one end record, a comment that fits.
        let (mut zip, good, _) = two_directories();
        end_record(&mut zip, 0, good, 3);
        zip.extend_from_slice(b"abc");
        assert_eq!(manifest_id(zip).unwrap(), "Good.Package");

        let refused = |zip: Vec<u8>, why: &str| {
            let err = manifest_id(zip).unwrap_err();
            assert!(err.to_string().contains(why), "{why}: {err}");
        };
        // The ZIP64 marker in the directory size alone: the `zip` crate reads
        // the ZIP64 record's directory, NuGet the 32-bit offset's.
        let (mut zip, good, evil) = two_directories();
        zip64_trailer(&mut zip, good);
        end_record(&mut zip, 0, (evil.0, u32::MAX), 0);
        refused(zip, "marks ZIP64");
        // The marker in the disk numbers alone (both equal, as NuGet asks):
        // NuGet reads the ZIP64 record's directory, the `zip` crate the
        // 32-bit one.
        let (mut zip, good, evil) = two_directories();
        zip64_trailer(&mut zip, evil);
        end_record(&mut zip, u16::MAX, good, 0);
        refused(zip, "marks ZIP64");
        // A last record whose comment overruns the file: the `zip` crate
        // takes the one before, .NET 8 and .NET Framework this one.
        let (mut zip, good, evil) = two_directories();
        end_record(&mut zip, 0, good, 0);
        end_record(&mut zip, 0, evil, 100);
        refused(zip, "comment runs past the end");
    }

    #[test]
    fn archive_without_a_trailing_eocd_is_rejected() {
        let mut zip = zip_of(&[("p.nuspec", OK_NUSPEC.as_bytes())]);
        // Push the real EOCD out of the trailer window with junk.
        zip.extend(std::iter::repeat_n(0u8, 128 * 1024));
        let err = parse_nupkg(&mut std::io::Cursor::new(zip), &NupkgLimits::default()).unwrap_err();
        assert!(
            err.to_string().contains("end-of-central-directory"),
            "{err}"
        );
    }

    #[test]
    fn synthesized_nuspec_escapes_and_round_trips() {
        let deps = vec![
            DependencyGroup {
                target_framework: Some("net8.0".into()),
                dependencies: vec![
                    Dependency {
                        id: "A&B".into(),
                        range: Some("[1.0.0, 2.0.0)".into()),
                    },
                    Dependency {
                        id: "C".into(),
                        range: None,
                    },
                ],
            },
            DependencyGroup {
                target_framework: None,
                dependencies: Vec::new(),
            },
        ];
        let xml = synthesize_nuspec("Weird<Id>", "1.0.0", &deps);
        let raw = parse_nuspec(&xml).unwrap();
        assert_eq!(raw.id, "Weird<Id>");
        assert_eq!(raw.version, "1.0.0");
        assert_eq!(raw.deps, deps);
        assert!(parse_nuspec(&synthesize_nuspec("X", "2.0.0", &[]))
            .unwrap()
            .deps
            .is_empty());
    }

    #[test]
    fn rejects_symbols_packages_v_versions_and_bad_ids() {
        let limits = NupkgLimits::default();
        let symbols = r#"<package><metadata><id>A.B</id><version>1.0.0</version>
            <packageTypes><packageType name="SymbolsPackage"/></packageTypes></metadata></package>"#;
        let err = parse_nupkg(&mut nupkg_with(symbols), &limits).unwrap_err();
        assert!(err.to_string().contains("symbol packages"), "{err}");

        let v = r#"<package><metadata><id>A.B</id><version>v1.0.0</version></metadata></package>"#;
        assert!(parse_nupkg(&mut nupkg_with(v), &limits).is_err());

        let id = r#"<package><metadata><id>a/b</id><version>1.0.0</version></metadata></package>"#;
        assert!(parse_nupkg(&mut nupkg_with(id), &limits).is_err());

        let ok = r#"<package><metadata><id>A.B</id><version>1.0.0</version></metadata></package>"#;
        assert_eq!(parse_nupkg(&mut nupkg_with(ok), &limits).unwrap().id, "a.b");

        // Versions NuGet clients cannot read as the package's own.
        for version in ["2147483648.0.0", "1.0.0-rc.01", "1.0.0+bad_meta", "1.0.0+"] {
            let xml = format!(
                "<package><metadata><id>A.B</id><version>{version}</version></metadata></package>"
            );
            assert!(
                parse_nupkg(&mut nupkg_with(&xml), &limits).is_err(),
                "{version}"
            );
        }
        let edge = r#"<package><metadata><id>A.B</id><version>2147483647.0.0-rc.0.10+build.5-x</version></metadata></package>"#;
        assert!(parse_nupkg(&mut nupkg_with(edge), &limits).is_ok());
    }
}
