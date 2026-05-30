//! Integration tests parsing the real `.nupkg` fixtures under `fixtures/nuget/`.
//!
//! Regenerate fixtures with `python3 fixtures/nuget/make_fixtures.py`.

use std::fs::File;
use std::path::PathBuf;

use forge_core::domain::FormatError;
use forge_core::format::Format;
use forge_nuget::model::NupkgLimits;
use forge_nuget::NugetFormat;

fn fixture(name: &str) -> File {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../fixtures/nuget");
    p.push(name);
    File::open(&p).unwrap_or_else(|e| panic!("open fixture {}: {e}", p.display()))
}

#[test]
fn parses_grouped_dependency_package() {
    let fmt = NugetFormat::new();
    let mut f = fixture("sample.lib.1.0.0.nupkg");
    let parsed = fmt.parse_upload(&mut f).expect("parse sample.lib");

    assert_eq!(parsed.original_id, "Sample.Lib");
    assert_eq!(parsed.id, "sample.lib");
    // 1.02.3 normalizes to 1.2.3.
    assert_eq!(parsed.version_original, "1.02.3");
    assert_eq!(parsed.version, "1.2.3");
    assert!(parsed.listed);
    assert!(!parsed.nuspec_bytes.is_empty());
    // nuspec_bytes round-trip the actual manifest (A4).
    let text = String::from_utf8(parsed.nuspec_bytes.clone()).unwrap();
    assert!(text.contains("<id>Sample.Lib</id>"));

    assert_eq!(parsed.deps.len(), 2);
    let net8 = parsed
        .deps
        .iter()
        .find(|g| g.target_framework.as_deref() == Some("net8.0"))
        .expect("net8.0 group");
    assert_eq!(net8.dependencies.len(), 2);
    assert_eq!(net8.dependencies[0].id, "Newtonsoft.Json");
    assert_eq!(net8.dependencies[0].range.as_deref(), Some("[13.0.1, )"));
    assert_eq!(net8.dependencies[1].id, "Serilog");

    let netstd = parsed
        .deps
        .iter()
        .find(|g| g.target_framework.as_deref() == Some("netstandard2.0"))
        .expect("netstandard2.0 group");
    assert_eq!(netstd.dependencies.len(), 1);
}

#[test]
fn parses_second_namespace_with_flat_deps_and_prerelease() {
    // Different xmlns (A3) + flat dependencies + prerelease normalization.
    let fmt = NugetFormat::new();
    let mut f = fixture("other.package.2.0.0-beta.1.nupkg");
    let parsed = fmt.parse_upload(&mut f).expect("parse other.package");

    assert_eq!(parsed.original_id, "Other.Package");
    assert_eq!(parsed.id, "other.package");
    assert_eq!(parsed.version_original, "2.0.0-Beta.1");
    assert_eq!(parsed.version, "2.0.0-beta.1");

    assert_eq!(parsed.deps.len(), 1);
    assert_eq!(parsed.deps[0].target_framework, None);
    assert_eq!(parsed.deps[0].dependencies.len(), 1);
    assert_eq!(
        parsed.deps[0].dependencies[0].id,
        "Microsoft.Extensions.Logging"
    );
}

#[test]
fn rejects_zip_bomb() {
    let fmt = NugetFormat::new();
    let mut f = fixture("zip-bomb.nupkg");
    let err = fmt
        .parse_upload(&mut f)
        .expect_err("zip bomb must be rejected");
    // The huge entry trips the per-entry size / compression-ratio guard.
    match err {
        FormatError::InvalidPackage(msg) => {
            assert!(msg.contains("limit"), "unexpected message: {msg}");
        }
        other => panic!("expected InvalidPackage limit error, got {other:?}"),
    }
}

#[test]
fn small_per_entry_limit_also_rejects_bomb() {
    // Even if the total budget were generous, a tight per-archive entry cap
    // catches the oversized payload.
    let limits = NupkgLimits {
        max_total_uncompressed: 4 * 1024 * 1024,
        ..NupkgLimits::default()
    };
    let fmt = NugetFormat::with_limits(limits);
    let mut f = fixture("zip-bomb.nupkg");
    assert!(fmt.parse_upload(&mut f).is_err());
}
