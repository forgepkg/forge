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

/// Lowercase a package id using ASCII (invariant) lowering, matching
/// `ToLowerInvariant()`.
pub fn lower_id(id: &str) -> String {
    id.trim().to_ascii_lowercase()
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
}

/// Parse the `.nuspec` XML namespace-insensitively (by local name).
fn parse_nuspec(bytes: &[u8]) -> Result<RawNuspec, NupkgError> {
    let mut reader = Reader::from_reader(bytes);
    let config = reader.config_mut();
    config.trim_text(true);

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

    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| NupkgError::MalformedNuspec(e.to_string()))?
        {
            Event::Start(e) => {
                let local = e.local_name().as_ref().to_vec();
                match local.as_slice() {
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
                        let dep_id = attr_local(&e, b"id")?.ok_or_else(|| {
                            NupkgError::MalformedNuspec("<dependency> missing id".into())
                        })?;
                        let range = attr_local(&e, b"version")?;
                        let dep = Dependency { id: dep_id, range };
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
                match path.last().map(Vec::as_slice) {
                    Some(b"id") if under_metadata_parent(&path) => {
                        id.get_or_insert(text);
                    }
                    Some(b"version") if under_metadata_parent(&path) => {
                        ver.get_or_insert(text);
                    }
                    _ => {}
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
    })
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
}
