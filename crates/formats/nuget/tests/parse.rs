//! Integration tests parsing the real `.nupkg` fixtures under `fixtures/nuget/`.
//!
//! Regenerate fixtures with `python3 fixtures/nuget/make_fixtures.py`.

use std::fs::File;
use std::path::PathBuf;

use forge_format_nuget::{Nuget, NupkgLimits};
use forge_plugin_api::{FormatError, FormatPlugin};

fn fixture(name: &str) -> File {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../../fixtures/nuget");
    p.push(name);
    File::open(&p).unwrap_or_else(|e| panic!("open fixture {}: {e}", p.display()))
}

#[test]
fn parses_grouped_dependency_package() {
    let fmt = Nuget::default();
    let mut f = fixture("sample.lib.1.0.0.nupkg");
    let parsed = fmt.parse_package(&mut f).expect("parse sample.lib");

    assert_eq!(parsed.original_id, "Sample.Lib");
    assert_eq!(parsed.id, "sample.lib");
    // 1.02.3 normalizes to 1.2.3.
    assert_eq!(parsed.version_original, "1.02.3");
    assert_eq!(parsed.version, "1.2.3");
    assert!(parsed.listed);
    assert!(!parsed.manifest.is_empty());
    // nuspec_bytes round-trip the actual manifest (A4).
    let text = String::from_utf8(parsed.manifest.clone()).unwrap();
    assert!(text.contains("<id>Sample.Lib</id>"));

    assert_eq!(parsed.dependencies.len(), 2);
    let net8 = parsed
        .dependencies
        .iter()
        .find(|g| g.target.as_deref() == Some("net8.0"))
        .expect("net8.0 group");
    assert_eq!(net8.dependencies.len(), 2);
    assert_eq!(net8.dependencies[0].id, "Newtonsoft.Json");
    assert_eq!(net8.dependencies[0].range.as_deref(), Some("[13.0.1, )"));
    assert_eq!(net8.dependencies[1].id, "Serilog");

    let netstd = parsed
        .dependencies
        .iter()
        .find(|g| g.target.as_deref() == Some("netstandard2.0"))
        .expect("netstandard2.0 group");
    assert_eq!(netstd.dependencies.len(), 1);
}

#[test]
fn parses_second_namespace_with_flat_deps_and_prerelease() {
    // Different xmlns (A3) + flat dependencies + prerelease normalization.
    let fmt = Nuget::default();
    let mut f = fixture("other.package.2.0.0-beta.1.nupkg");
    let parsed = fmt.parse_package(&mut f).expect("parse other.package");

    assert_eq!(parsed.original_id, "Other.Package");
    assert_eq!(parsed.id, "other.package");
    assert_eq!(parsed.version_original, "2.0.0-Beta.1");
    assert_eq!(parsed.version, "2.0.0-beta.1");

    assert_eq!(parsed.dependencies.len(), 1);
    assert_eq!(parsed.dependencies[0].target, None);
    assert_eq!(parsed.dependencies[0].dependencies.len(), 1);
    assert_eq!(
        parsed.dependencies[0].dependencies[0].id,
        "Microsoft.Extensions.Logging"
    );
}

/// The `zip-bomb.nupkg` fixture holds a 64 MiB + 1 entry of zeros (ratio ~1000)
/// next to a valid manifest. Only the `.nuspec` is ever decompressed, so that
/// payload is harmless and must not fail the package — large native packages
/// (CUDA, libtorch, …) look exactly like this. (It used to be rejected by
/// per-entry size/ratio caps applied to every entry.)
#[test]
fn large_compressible_payload_entry_is_accepted() {
    let fmt = Nuget::default();
    let mut f = fixture("zip-bomb.nupkg");
    let parsed = fmt
        .parse_package(&mut f)
        .expect("a large payload entry is not a bomb for the manifest reader");
    assert_eq!(parsed.id, "sample.lib");
}

/// A manifest that would decompress to far more than the `.nuspec` cap is a
/// bomb: rejected before it is read into memory.
#[test]
fn rejects_nuspec_bomb() {
    use std::io::Write;
    let padding = " ".repeat(4 * 1024 * 1024);
    let nuspec = format!(
        "<package><metadata><id>Bomb</id><version>1.0.0</version>\
         <description>{padding}</description></metadata></package>"
    );
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zw.start_file("Bomb.nuspec", zip::write::SimpleFileOptions::default())
        .unwrap();
    zw.write_all(nuspec.as_bytes()).unwrap();
    let mut cur = std::io::Cursor::new(zw.finish().unwrap().into_inner());

    let err = Nuget::default()
        .parse_package(&mut cur)
        .expect_err("nuspec bomb must be rejected");
    match err {
        FormatError::InvalidPackage(msg) => {
            assert!(msg.contains("limit"), "unexpected message: {msg}");
        }
        other => panic!("expected InvalidPackage limit error, got {other:?}"),
    }
}

#[test]
fn small_total_budget_also_rejects_bomb() {
    // The total declared uncompressed size stays bounded: a tight budget
    // rejects the fixture's oversized payload without decompressing it.
    let limits = NupkgLimits {
        max_total_uncompressed: 4 * 1024 * 1024,
        ..NupkgLimits::default()
    };
    let fmt = Nuget::with_limits(limits);
    let mut f = fixture("zip-bomb.nupkg");
    assert!(fmt.parse_package(&mut f).is_err());
}
