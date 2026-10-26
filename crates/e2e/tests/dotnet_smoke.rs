//! E2E (optional): real `dotnet` NuGet client smoke test — `dotnet nuget push`
//! a package built with `dotnet pack`, then `dotnet restore` it back from a
//! consuming project. Skipped (passes trivially) when the dotnet SDK is not on
//! PATH. Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::path::Path;
use std::process::Command;

use forge_e2e::{AnonMode, StackBuilder};

/// True if a usable `dotnet` SDK is on PATH.
fn dotnet_available() -> bool {
    Command::new("dotnet")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a `dotnet` command on a blocking thread so it never starves the runtime
/// that is concurrently serving the in-process axum server (a blocking
/// `Command::output()` on the runtime thread would deadlock the HTTP requests
/// the CLI makes back to us).
async fn run(mut cmd: Command, what: &'static str) {
    let out = tokio::task::spawn_blocking(move || cmd.output())
        .await
        .expect("join blocking")
        .unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    assert!(
        out.status.success(),
        "{what} failed (status {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Build → push → restore a package using the real dotnet CLI against a hosted
/// repo. Exercises NuGet V3 service index, PackagePublish, the flat container,
/// and registration as a real client consumes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dotnet_push_and_restore_smoke() {
    if !dotnet_available() {
        eprintln!("dotnet SDK not present; skipping dotnet smoke test");
        return;
    }

    // anonymous_mode = all + an anonymous_read repo so the NuGet client can load
    // the service index / flat container without per-request auth (it does not
    // send the api-key when GETting the service index). The push itself still
    // authenticates via X-NuGet-ApiKey.
    let srv = StackBuilder::default().anon(AnonMode::All).start().await;
    assert_eq!(
        srv.create_repo(
            serde_json::json!({"name": "dn-repo", "kind": "hosted", "anonymous_read": true})
        )
        .await
        .status(),
        201
    );
    // RBAC: anonymous read flows through an anonymous-role grant (what the RBAC
    // data migration converted the anonymous_read flag into).
    srv.grant_anonymous_read("dn-repo").await;
    let source = format!("{}/repository/dn-repo/index.json", srv.base_url);
    let api_key = srv.admin_token.clone();

    let tmp = tempdir();
    let lib_dir = tmp.join("Forge.Smoke.Lib");
    let app_dir = tmp.join("Consumer");
    std::fs::create_dir_all(&lib_dir).unwrap();
    std::fs::create_dir_all(&app_dir).unwrap();

    // A shared nuget.config at the tmp root: a named `forge` source over HTTP
    // with `allowInsecureConnections=true` (modern NuGet refuses plain HTTP
    // otherwise). Both push (by source name) and restore inherit it.
    write_file(
        &tmp.join("nuget.config"),
        &format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="forge" value="{source}" allowInsecureConnections="true" />
  </packageSources>
</configuration>
"#,
        ),
    );

    // ── Build a packable class library and pack it ──
    write_file(
        &lib_dir.join("Forge.Smoke.Lib.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>Forge.Smoke.Lib</PackageId>
    <Version>1.0.0</Version>
    <Authors>e2e</Authors>
    <Description>forge e2e smoke package</Description>
    <IncludeBuildOutput>true</IncludeBuildOutput>
  </PropertyGroup>
</Project>
"#,
    );
    write_file(
        &lib_dir.join("Class1.cs"),
        "namespace Forge.Smoke.Lib; public static class Greeter { public static string Hi() => \"hi\"; }\n",
    );

    let mut pack = Command::new("dotnet");
    pack.args(["pack", "-c", "Release", "-o", out_str(&tmp)])
        .current_dir(&lib_dir);
    run(pack, "dotnet pack").await;

    let nupkg = tmp.join("Forge.Smoke.Lib.1.0.0.nupkg");
    assert!(nupkg.exists(), "pack produced the nupkg");

    // ── Push the package to the hosted repo (by the named source, so the
    // shared nuget.config's allowInsecureConnections applies) ──
    let mut push = Command::new("dotnet");
    push.args([
        "nuget",
        "push",
        out_str(&nupkg),
        "--source",
        "forge",
        "--api-key",
        &api_key,
    ])
    .current_dir(&tmp);
    run(push, "dotnet nuget push").await;

    // ── Consume it from a fresh project, restoring ONLY from our feed ──
    write_file(
        &app_dir.join("nuget.config"),
        &format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="forge" value="{source}" allowInsecureConnections="true" />
  </packageSources>
</configuration>
"#,
        ),
    );
    write_file(
        &app_dir.join("Consumer.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Forge.Smoke.Lib" Version="1.0.0" />
  </ItemGroup>
</Project>
"#,
    );
    write_file(
        &app_dir.join("Program.cs"),
        "System.Console.WriteLine(Forge.Smoke.Lib.Greeter.Hi());\n",
    );

    let mut restore = Command::new("dotnet");
    restore
        .args(["restore", "--no-cache"])
        .current_dir(&app_dir);
    run(restore, "dotnet restore").await;
}

// ── tiny fs helpers (avoid a tempfile dep just for a dir) ────────────────────

fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("forge-dotnet-{n}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn write_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn out_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}
