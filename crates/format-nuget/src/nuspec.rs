//! `.nupkg` (zip) and `.nuspec` (XML) parsing into a [`ParsedUpload`].
//!
//! A `.nupkg` is an OPC zip. We locate the single top-level `*.nuspec`
//! manifest, read it under strict zip-bomb limits, and parse it
//! **namespace-insensitively** (matching XML *local* names) because the nuspec
//! schema uses versioned `xmlns` URIs that differ across packages.
//!
//! Only the manifest is decompressed; the `<id>`, `<version>`, and
//! `<dependencies>` groups are extracted. The raw manifest bytes are carried in
//! [`ParsedUpload::nuspec_bytes`] so the server can store and re-serve them.

use std::io::Read;

use forge_core::domain::{Dependency, DependencyGroup, FormatError, ParsedUpload};
use forge_core::format::ReadSeek;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::model::{NupkgError, NupkgLimits};
use crate::version;

/// Parse a `.nupkg` from a seekable reader into a [`ParsedUpload`].
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

/// Lowercase a package id using ASCII (invariant) lowering, matching
/// `ToLowerInvariant()`.
pub fn lower_id(id: &str) -> String {
    id.trim().to_ascii_lowercase()
}

/// Display metadata of a `.nuspec`, for registration catalog entries and
/// search results. Absent elements are `None` / empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    raw_tags: Option<String>,
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

/// Extract just the dependency groups from raw `.nuspec` bytes.
///
/// Used by the registration route to render `dependencyGroups` without
/// re-reading the package zip (the manifest is already stored as an asset).
pub fn dependency_groups_from_nuspec(bytes: &[u8]) -> Result<Vec<DependencyGroup>, FormatError> {
    Ok(parse_nuspec(bytes).map_err(FormatError::from)?.deps)
}

/// Locate and read the `*.nuspec` entry out of the zip, enforcing limits.
fn extract_nuspec(file: &mut dyn ReadSeek, limits: &NupkgLimits) -> Result<Vec<u8>, NupkgError> {
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| NupkgError::InvalidZip(e.to_string()))?;

    if archive.len() > limits.max_entries {
        return Err(NupkgError::LimitExceeded(format!(
            "{} entries exceeds max {}",
            archive.len(),
            limits.max_entries
        )));
    }

    // First pass: find the index of the top-level .nuspec without decompressing.
    // NuGet places exactly one .nuspec at the package root; pick the shallowest
    // *.nuspec to avoid being fooled by a nested decoy.
    let mut nuspec_index: Option<usize> = None;
    let mut best_depth = usize::MAX;
    let mut total_uncompressed: u64 = 0;

    for i in 0..archive.len() {
        let entry = archive
            .by_index_raw(i)
            .map_err(|e| NupkgError::InvalidZip(e.to_string()))?;

        if entry.encrypted() {
            return Err(NupkgError::UnsupportedEntry(format!(
                "entry {:?} is encrypted",
                entry.name()
            )));
        }

        let size = entry.size();
        let name = entry.name().to_string();

        // Per-entry uncompressed cap: reject any single oversized member,
        // since a real package never needs an entry this large and an attacker
        // could otherwise smuggle a bomb past the total budget.
        if size > limits.max_entry_uncompressed {
            return Err(NupkgError::LimitExceeded(format!(
                "entry {name:?} uncompressed size {size} exceeds per-entry max {}",
                limits.max_entry_uncompressed
            )));
        }

        // Per-entry compression-ratio cap: catches highly compressible bombs
        // even when each individual entry is under the size cap.
        let compressed = entry.compressed_size();
        if let Some(ratio) = size.checked_div(compressed) {
            if ratio > limits.max_compression_ratio {
                return Err(NupkgError::LimitExceeded(format!(
                    "entry {name:?} compression ratio {ratio} exceeds max {}",
                    limits.max_compression_ratio
                )));
            }
        }

        total_uncompressed = total_uncompressed.saturating_add(size);
        if total_uncompressed > limits.max_total_uncompressed {
            return Err(NupkgError::LimitExceeded(format!(
                "total uncompressed size exceeds max {}",
                limits.max_total_uncompressed
            )));
        }

        if is_nuspec_name(&name) {
            let depth = name.bytes().filter(|&b| b == b'/').count();
            if depth < best_depth {
                best_depth = depth;
                nuspec_index = Some(i);
            }
        }
    }

    let index = nuspec_index.ok_or(NupkgError::MissingNuspec)?;

    // Second pass: decompress just the chosen .nuspec under per-entry caps.
    let mut entry = archive
        .by_index(index)
        .map_err(|e| NupkgError::InvalidZip(e.to_string()))?;

    let declared = entry.size();
    if declared > limits.max_nuspec_bytes {
        return Err(NupkgError::LimitExceeded(format!(
            ".nuspec declared size {declared} exceeds max {}",
            limits.max_nuspec_bytes
        )));
    }

    let compressed = entry.compressed_size();
    if let Some(ratio) = declared.checked_div(compressed) {
        if ratio > limits.max_compression_ratio {
            return Err(NupkgError::LimitExceeded(format!(
                ".nuspec compression ratio {ratio} exceeds max {}",
                limits.max_compression_ratio
            )));
        }
    }

    // Read with a hard cap (declared size may lie; the +1 detects overruns).
    let cap = limits
        .max_nuspec_bytes
        .min(limits.max_entry_uncompressed)
        .saturating_add(1);
    let mut buf = Vec::new();
    let read = entry
        .by_ref()
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(NupkgError::Io)?;
    if read as u64 >= cap {
        return Err(NupkgError::LimitExceeded(
            ".nuspec exceeds maximum size during decompression".into(),
        ));
    }

    Ok(buf)
}

fn is_nuspec_name(name: &str) -> bool {
    // Case-insensitive `.nuspec` suffix; ignore directory entries.
    !name.ends_with('/')
        && name
            .rsplit('/')
            .next()
            .map(|f| f.to_ascii_lowercase().ends_with(".nuspec"))
            .unwrap_or(false)
}

/// The fields we pull out of a `.nuspec` manifest before normalization.
#[derive(Debug)]
struct RawNuspec {
    id: String,
    version: String,
    deps: Vec<DependencyGroup>,
    metadata: NuspecMetadata,
}

/// Parse the `.nuspec` XML namespace-insensitively (by local name).
fn parse_nuspec(bytes: &[u8]) -> Result<RawNuspec, NupkgError> {
    let mut reader = Reader::from_reader(bytes);
    // Text is kept verbatim (entity references split it into several
    // events, so trimming per event would eat inner spaces); values are
    // trimmed once parsing is complete.
    reader.config_mut().trim_text(false);

    // Path of local element names, so we know our context (e.g. metadata/id).
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut id: Option<String> = None;
    let mut ver: Option<String> = None;
    let mut groups: Vec<DependencyGroup> = Vec::new();
    // The currently open <group> (or the implicit flat group keyed by None).
    let mut current_group: Option<DependencyGroup> = None;
    // Whether we are inside a <dependencies> element.
    let mut in_dependencies = false;
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
                let local = e.local_name().as_ref().to_vec();
                match local.as_slice() {
                    b"metadata" => {
                        metadata.min_client_version = attr_local(&e, b"minClientVersion")?;
                    }
                    b"license" if path.last().map(Vec::as_slice) == Some(b"metadata") => {
                        license_type = attr_local(&e, b"type")?;
                    }
                    // `<dependency ...></dependency>` (explicit end tag) is as
                    // valid as the self-closing form.
                    b"dependency" if in_dependencies => {
                        let dep = parse_dependency(&e)?;
                        push_dependency(&mut current_group, &mut flat_group, dep);
                    }
                    b"packageType" if path.last().map(Vec::as_slice) == Some(b"packageTypes") => {
                        if let Some(name) = attr_local(&e, b"name")? {
                            metadata.package_types.push(name);
                        }
                    }
                    b"dependencies" if under_metadata(&path) => {
                        in_dependencies = true;
                        flat_group = None;
                    }
                    b"group" if in_dependencies => {
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
                let local = e.local_name().as_ref().to_vec();
                match local.as_slice() {
                    b"dependency" if in_dependencies => {
                        let dep = parse_dependency(&e)?;
                        push_dependency(&mut current_group, &mut flat_group, dep);
                    }
                    b"packageType" if path.last().map(Vec::as_slice) == Some(b"packageTypes") => {
                        if let Some(name) = attr_local(&e, b"name")? {
                            metadata.package_types.push(name);
                        }
                    }
                    // A self-closing <group/> with no dependencies still
                    // represents a target framework group.
                    b"group" if in_dependencies => {
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
                let text = t
                    .decode()
                    .map_err(|e| NupkgError::MalformedNuspec(e.to_string()))?
                    .into_owned();
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
                let text = t
                    .decode()
                    .map_err(|e| NupkgError::MalformedNuspec(e.to_string()))?
                    .into_owned();
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
                    let name = r
                        .decode()
                        .map_err(|e| NupkgError::MalformedNuspec(e.to_string()))?;
                    quick_xml::escape::resolve_predefined_entity(&name).map(str::to_string)
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
                let local = e.local_name().as_ref().to_vec();
                if local.as_slice() == b"group" && in_dependencies {
                    if let Some(g) = current_group.take() {
                        groups.push(g);
                    }
                } else if local.as_slice() == b"dependencies" {
                    in_dependencies = false;
                    if let Some(g) = flat_group.take() {
                        groups.push(g);
                    }
                }
                path.pop();
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

/// Add `dep` to the open `<group>`, or to the flat (groupless) group.
fn push_dependency(
    current_group: &mut Option<DependencyGroup>,
    flat_group: &mut Option<DependencyGroup>,
    dep: Dependency,
) {
    if let Some(g) = current_group.as_mut() {
        g.dependencies.push(dep);
    } else {
        flat_group
            .get_or_insert_with(|| DependencyGroup {
                target_framework: None,
                dependencies: Vec::new(),
            })
            .dependencies
            .push(dep);
    }
}

/// True if the element path is currently inside `<metadata>` (any ancestor).
fn under_metadata(path: &[Vec<u8>]) -> bool {
    path.iter().any(|p| p.as_slice() == b"metadata")
}

/// True if the *parent* of the current text node is `<metadata>` — i.e. the
/// path is `[.., metadata, id|version]`. Guards against e.g. a `<id>` nested in
/// a dependency.
fn under_metadata_parent(path: &[Vec<u8>]) -> bool {
    path.len() >= 2 && path[path.len() - 2].as_slice() == b"metadata"
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
        if key_local.as_ref() == local {
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
    fn missing_id_or_version_is_error() {
        let xml = br#"<package><metadata><version>1.0.0</version></metadata></package>"#;
        assert!(parse_nuspec(xml).is_err());
        let xml2 = br#"<package><metadata><id>X</id></metadata></package>"#;
        assert!(parse_nuspec(xml2).is_err());
    }

    #[test]
    fn lower_id_is_ascii_invariant() {
        assert_eq!(lower_id("Newtonsoft.JSON"), "newtonsoft.json");
        assert_eq!(lower_id("  Foo.Bar  "), "foo.bar");
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
    }
}
