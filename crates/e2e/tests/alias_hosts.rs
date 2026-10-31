//! E2E (optional clients): real clients reach a server under an alias host
//! name (`server.alias_base_urls`, #312).
//!
//! The servers' public base URL is `http://forge.invalid:<port>`, a name that
//! never resolves (RFC 6761), and their alias `http://localhost:<port>`. The
//! clients are configured with the alias alone, so a client that followed a
//! URL on the public host (a NuGet resource, a token realm) would fail: a
//! passing client made every request on the alias.
//!
//! * `dotnet nuget push` and `dotnet restore` of a private feed;
//! * `docker login`, `push` and `pull`, the challenge naming
//!   `http://localhost:<port>/v2/token`;
//! * `helm registry login`, `push` and `pull` of a private chart. Helm keeps
//!   its charts in docker repositories (OCI): Forge serves no `index.yaml`
//!   chart repositories, so `helm repo add` has nothing to add, and helm
//!   fetches the registry token from the realm the challenge names.
//!
//! Each test is skipped (passes trivially) when its client is not on PATH,
//! like `dotnet_smoke`. Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::path::Path;
use std::process::{Command, Stdio};

use forge_e2e::{StackBuilder, TestServer};

/// The public host of the servers: never resolves.
const PUBLIC_HOST: &str = "forge.invalid";

/// The alias the clients use.
const ALIAS_HOST: &str = "localhost";

/// A server on `http://forge.invalid:<port>` with the alias
/// `http://localhost:<port>`.
async fn aliased_server() -> TestServer {
    StackBuilder::default()
        .public_host(PUBLIC_HOST)
        .alias_host(ALIAS_HOST)
        .start()
        .await
}

/// `localhost:<port>` of `srv`.
fn alias_authority(srv: &TestServer) -> String {
    let port = srv.base_url.rsplit(':').next().expect("a port");
    format!("{ALIAS_HOST}:{port}")
}

/// Whether `program` runs (`<program> <args>` succeeds).
fn available(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run `cmd` on a blocking thread (the CLI calls back into the in-process
/// server, which must keep running), feeding `stdin`; panics with its output
/// unless it succeeds. Returns its stdout.
async fn run(mut cmd: Command, what: &str, stdin: Option<String>) -> String {
    let what = what.to_string();
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(input.as_bytes())
                .expect("write stdin");
        }
        let out = child.wait_with_output().expect("wait");
        assert!(
            out.status.success(),
            "{what} failed (status {:?})\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    })
    .await
    .expect("join blocking")
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

fn write_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// `dotnet --version`'s major version as a target framework (`net8.0`).
fn dotnet_tfm() -> Option<String> {
    let out = Command::new("dotnet").arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let version = String::from_utf8(out.stdout).ok()?;
    let major = version.trim().split('.').next()?.parse::<u32>().ok()?;
    Some(format!("net{major}.0"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dotnet_pushes_and_restores_through_an_alias_alone() {
    let Some(tfm) = dotnet_tfm() else {
        eprintln!("dotnet SDK not present; skipping the alias dotnet test");
        return;
    };
    let srv = aliased_server().await;
    let repo = "alias-nuget";
    assert_eq!(
        srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted"}))
            .await
            .status(),
        201
    );
    let alias = alias_authority(&srv);
    let source = format!("http://{alias}/repository/{repo}/index.json");
    // The service index fetched on the alias names only the alias.
    let index: serde_json::Value = srv
        .client()
        .get(format!("{}/repository/{repo}/index.json", srv.base_url))
        .header("host", &alias)
        .basic_auth(srv.admin_user.as_ref().unwrap(), Some(&srv.admin_token))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for resource in index["resources"].as_array().unwrap() {
        let id = resource["@id"].as_str().unwrap();
        assert!(
            id.starts_with(&format!("http://{alias}/repository/{repo}/")),
            "{id}"
        );
    }

    // A private feed: the client sends its source credentials (an API token
    // as the password) to the host of the source, the alias.
    let tmp = tempfile::tempdir().unwrap();
    let (lib, app) = (tmp.path().join("Alias.Lib"), tmp.path().join("Consumer"));
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::create_dir_all(&app).unwrap();
    write_file(
        &tmp.path().join("nuget.config"),
        &format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="forge" value="{source}" allowInsecureConnections="true" />
  </packageSources>
  <packageSourceCredentials>
    <forge>
      <add key="Username" value="{user}" />
      <add key="ClearTextPassword" value="{token}" />
    </forge>
  </packageSourceCredentials>
</configuration>
"#,
            user = srv.admin_user.as_ref().unwrap(),
            token = srv.admin_token,
        ),
    );
    write_file(
        &lib.join("Alias.Lib.csproj"),
        &format!(
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>{tfm}</TargetFramework>
    <PackageId>Alias.Lib</PackageId>
    <Version>1.0.0</Version>
    <Authors>e2e</Authors>
    <Description>forge e2e alias package</Description>
  </PropertyGroup>
</Project>
"#
        ),
    );
    write_file(
        &lib.join("Class1.cs"),
        "namespace Alias.Lib; public static class Greeter { public static string Hi() => \"hi\"; }\n",
    );
    let mut pack = Command::new("dotnet");
    pack.args(["pack", "-c", "Release", "-o", path_str(tmp.path())])
        .current_dir(&lib);
    run(pack, "dotnet pack", None).await;
    let nupkg = tmp.path().join("Alias.Lib.1.0.0.nupkg");
    let mut push = Command::new("dotnet");
    push.args([
        "nuget",
        "push",
        path_str(&nupkg),
        "--source",
        "forge",
        "--api-key",
        &srv.admin_token,
    ])
    .current_dir(tmp.path());
    run(push, "dotnet nuget push", None).await;

    write_file(
        &app.join("Consumer.csproj"),
        &format!(
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>{tfm}</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Alias.Lib" Version="1.0.0" />
  </ItemGroup>
</Project>
"#
        ),
    );
    write_file(
        &app.join("Program.cs"),
        "System.Console.WriteLine(Alias.Lib.Greeter.Hi());\n",
    );
    let mut restore = Command::new("dotnet");
    restore
        .args(["restore", "--no-cache", "--force-evaluate"])
        .current_dir(&app);
    run(restore, "dotnet restore", None).await;
    assert!(
        app.join("obj").join("project.assets.json").exists(),
        "restore wrote its assets file"
    );
}

/// A tar archive of one small file, for `docker import`.
fn rootfs_tar(dir: &Path) -> std::path::PathBuf {
    let root = dir.join("rootfs");
    std::fs::create_dir_all(&root).unwrap();
    write_file(&root.join("hello.txt"), "served through an alias\n");
    let tar = dir.join("rootfs.tar");
    let status = Command::new("tar")
        .args(["-cf", path_str(&tar), "-C", path_str(&root), "hello.txt"])
        .status()
        .expect("run tar");
    assert!(status.success(), "tar");
    tar
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn docker_logs_in_pushes_and_pulls_through_an_alias_alone() {
    if !available("docker", &["version"]) {
        eprintln!("docker (client and daemon) not present; skipping the alias docker test");
        return;
    }
    let srv = aliased_server().await;
    // Each stack has a database of its own.
    let repo = "alias-docker";
    assert_eq!(
        srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted", "format": "docker"}))
            .await
            .status(),
        201
    );
    let alias = alias_authority(&srv);

    // The challenge on the alias names the alias's token service.
    let resp = srv
        .client()
        .get(format!("{}/v2/", srv.base_url))
        .header("host", &alias)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.headers()["www-authenticate"],
        format!("Bearer realm=\"http://{alias}/v2/token\",service=\"{alias}\"").as_str()
    );

    // docker keeps its login here, not in ~/.docker.
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("docker-config");
    std::fs::create_dir_all(&config).unwrap();
    let docker = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.env("DOCKER_CONFIG", &config).args(args);
        cmd
    };
    let image = format!("{alias}/{repo}/alias/app:1");
    run(
        docker(&[
            "login",
            &alias,
            "--username",
            srv.admin_user.as_ref().unwrap(),
            "--password-stdin",
        ]),
        "docker login",
        Some(srv.admin_token.clone()),
    )
    .await;
    run(
        docker(&["import", path_str(&rootfs_tar(tmp.path())), &image]),
        "docker import",
        None,
    )
    .await;
    let id = run(
        docker(&["image", "inspect", "--format", "{{.Id}}", &image]),
        "docker image inspect",
        None,
    )
    .await;
    run(docker(&["push", &image]), "docker push", None).await;
    run(docker(&["image", "rm", &image]), "docker image rm", None).await;
    run(docker(&["pull", &image]), "docker pull", None).await;
    let pulled = run(
        docker(&["image", "inspect", "--format", "{{.Id}}", &image]),
        "docker image inspect",
        None,
    )
    .await;
    assert_eq!(pulled.trim(), id.trim(), "pulled the pushed image");
    run(docker(&["image", "rm", &image]), "docker image rm", None).await;
    run(docker(&["logout", &alias]), "docker logout", None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn helm_pushes_and_pulls_a_private_chart_through_an_alias_alone() {
    if !available("helm", &["version"]) {
        eprintln!("helm not present; skipping the alias helm test");
        return;
    }
    // The test server speaks plain HTTP: a helm that cannot log in over it
    // cannot run this test.
    let login_help = Command::new("helm")
        .args(["registry", "login", "--help"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if !login_help.contains("--plain-http") {
        eprintln!("helm has no `registry login --plain-http`; skipping the alias helm test");
        return;
    }
    let srv = aliased_server().await;
    let repo = "alias-charts";
    assert_eq!(
        srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted", "format": "docker"}))
            .await
            .status(),
        201
    );
    let alias = alias_authority(&srv);

    // Helm keeps its registry login and cache here.
    let tmp = tempfile::tempdir().unwrap();
    let helm = |args: &[&str]| {
        let mut cmd = Command::new("helm");
        for (var, dir) in [
            ("HELM_CONFIG_HOME", "config"),
            ("HELM_CACHE_HOME", "cache"),
            ("HELM_DATA_HOME", "data"),
        ] {
            cmd.env(var, tmp.path().join("helm").join(dir));
        }
        cmd.args(args);
        cmd
    };
    run(
        helm(&[
            "registry",
            "login",
            &alias,
            "--username",
            srv.admin_user.as_ref().unwrap(),
            "--password-stdin",
            "--plain-http",
        ]),
        "helm registry login",
        Some(srv.admin_token.clone()),
    )
    .await;
    let charts = tmp.path().join("charts");
    std::fs::create_dir_all(&charts).unwrap();
    let chart_dir = charts.join("alias-chart");
    run(helm(&["create", path_str(&chart_dir)]), "helm create", None).await;
    run(
        helm(&["package", path_str(&chart_dir), "-d", path_str(&charts)]),
        "helm package",
        None,
    )
    .await;
    let packaged = charts.join("alias-chart-0.1.0.tgz");
    run(
        helm(&[
            "push",
            path_str(&packaged),
            &format!("oci://{alias}/{repo}/charts"),
            "--plain-http",
        ]),
        "helm push",
        None,
    )
    .await;
    let pulled = tmp.path().join("pulled");
    std::fs::create_dir_all(&pulled).unwrap();
    run(
        helm(&[
            "pull",
            &format!("oci://{alias}/{repo}/charts/alias-chart"),
            "--version",
            "0.1.0",
            "--plain-http",
            "-d",
            path_str(&pulled),
        ]),
        "helm pull",
        None,
    )
    .await;
    assert_eq!(
        std::fs::read(pulled.join("alias-chart-0.1.0.tgz")).unwrap(),
        std::fs::read(&packaged).unwrap(),
        "pulled the pushed chart"
    );
}
