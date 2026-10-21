//! The example Helm plugin (`plugins/helm`) loaded into the host: its format
//! rules, its package parser, its protocol, and the sandbox around it.

use std::cmp::Ordering;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use forge_core::Format;
use forge_plugin::protocol::{
    Action, Answer, Loaded, PackageInfo, Query, Rendered, Repository, RepositoryKind, Request,
    SearchHit, SearchResult, Upload, VersionInfo,
};
use forge_plugin::testing::{component_sha256, example_plugin};
use forge_plugin::{HostLimits, Manifest, Plugin, PluginError, PluginFormat};

fn helm() -> (PathBuf, Arc<Plugin>) {
    let dir = example_plugin("helm");
    let plugin = Plugin::load(&dir, &component_sha256(&dir), &HostLimits::default())
        .expect("load the helm plugin");
    (dir, plugin)
}

/// A gzipped ustar archive of `(path, contents)` entries.
fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (path, data) in entries {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        tar.extend_from_slice(&header);
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.extend_from_slice(&[0u8; 1024]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

fn chart(name: &str, version: &str) -> Vec<u8> {
    let yaml = format!(
        "apiVersion: v2\nname: {name}\nversion: {version}\nappVersion: \"1.27\"\n\
         description: The {name} chart\ndependencies:\n  - name: redis\n    version: \">=17\"\n"
    );
    tgz(&[
        (&format!("{name}/values.yaml"), b"replicas: 1\n"),
        (&format!("{name}/Chart.yaml"), yaml.as_bytes()),
    ])
}

fn repo() -> Repository {
    Repository {
        name: "charts".into(),
        kind: RepositoryKind::Hosted,
        base_url: "https://forge.example.com/repository/charts".into(),
    }
}

fn request(method: &str, path: &str) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        query: String::new(),
        headers: Vec::new(),
    }
}

#[test]
fn loads_only_the_pinned_component() {
    let (dir, plugin) = helm();
    assert_eq!(plugin.id(), "helm");
    assert_eq!(plugin.sha256(), component_sha256(&dir));
    let err = Plugin::load(&dir, &"0".repeat(64), &HostLimits::default()).unwrap_err();
    assert!(matches!(err, PluginError::Digest { .. }), "{err}");
    // The pin may carry its algorithm.
    let pinned = format!("sha256:{}", component_sha256(&dir).to_uppercase());
    assert!(Plugin::load(&dir, &pinned, &HostLimits::default()).is_ok());
}

#[test]
fn the_format_rules_come_from_the_plugin() {
    let (_, plugin) = helm();
    let format = PluginFormat::new(plugin);
    assert_eq!(format.id(), "helm");
    assert_eq!(format.lower_id("Ingress-NGINX"), "ingress-nginx");
    assert!(format.validate_id("ingress-nginx").is_ok());
    assert!(format.validate_id("../etc").is_err());
    assert_eq!(format.normalize_version("v1.2").unwrap(), "1.2.0");
    assert!(format.normalize_version("one").is_err());
    assert_eq!(
        format.compare_versions("1.10.0", "1.9.0"),
        Ordering::Greater
    );
    assert_eq!(
        format.compare_versions("1.0.0-rc.1", "1.0.0"),
        Ordering::Less
    );
    // Remembered comparisons answer the same.
    assert_eq!(
        format.compare_versions("1.10.0", "1.9.0"),
        Ordering::Greater
    );
    assert_eq!(format.package_asset_path(), "package");
}

#[test]
fn parses_a_chart_through_the_lent_reader() {
    let (_, plugin) = helm();
    let format = PluginFormat::new(plugin);
    let mut staged = tempfile::NamedTempFile::new().unwrap();
    staged.write_all(&chart("NGINX", "v2.1")).unwrap();

    let parsed = format.parse_upload_file(staged.path()).unwrap();
    assert_eq!(parsed.id, "nginx");
    assert_eq!(parsed.original_id, "NGINX");
    assert_eq!(parsed.version, "2.1.0");
    assert_eq!(parsed.version_original, "v2.1");
    assert!(parsed.listed);
    assert!(String::from_utf8_lossy(&parsed.nuspec_bytes).contains("name: NGINX"));
    assert_eq!(parsed.deps.len(), 1);
    assert_eq!(parsed.deps[0].dependencies[0].id, "redis");

    // The reader-based entry point spools into a file first.
    let mut cursor = std::io::Cursor::new(chart("demo", "1.0.0"));
    assert_eq!(format.parse_upload(&mut cursor).unwrap().id, "demo");

    let summary = format.manifest_summary(&parsed.nuspec_bytes).unwrap();
    assert_eq!(summary["chart"]["appVersion"], "1.27");
    assert_eq!(summary["description"], "The NGINX chart");
    assert_eq!(
        summary["dependency_groups"][0]["dependencies"][0]["id"],
        "redis"
    );

    let mut not_a_chart = tempfile::NamedTempFile::new().unwrap();
    not_a_chart.write_all(b"definitely not gzip").unwrap();
    let err = format.parse_upload_file(not_a_chart.path()).unwrap_err();
    assert!(err.to_string().contains("not a chart archive"), "{err}");
}

#[tokio::test]
async fn routes_requests_to_host_actions() {
    let (_, plugin) = helm();

    let action = plugin
        .handle(repo(), request("GET", "/charts/nginx/v2.1/nginx-2.1.0.tgz"))
        .await
        .unwrap();
    let Action::Download(target) = action else {
        panic!("expected a download, got {action:?}");
    };
    assert_eq!(
        (target.id.as_str(), target.version.as_str()),
        ("nginx", "2.1.0")
    );

    let action = plugin
        .handle(repo(), request("POST", "/api/charts"))
        .await
        .unwrap();
    assert!(
        matches!(&action, Action::Publish(p) if matches!(p.upload, Upload::Body)),
        "{action:?}"
    );
    let mut multipart = request("POST", "/api/charts");
    multipart.headers = vec![(
        "content-type".into(),
        "multipart/form-data; boundary=x".into(),
    )];
    let action = plugin.handle(repo(), multipart).await.unwrap();
    assert!(
        matches!(&action, Action::Publish(p) if matches!(&p.upload, Upload::MultipartField(f) if f == "chart")),
        "{action:?}"
    );

    let action = plugin
        .handle(repo(), request("DELETE", "/api/charts/NGINX/2.1.0"))
        .await
        .unwrap();
    assert!(
        matches!(&action, Action::Delete(c) if c.target.id == "nginx"),
        "{action:?}"
    );

    for (method, path) in [
        ("GET", "/nope"),
        ("PUT", "/index.yaml"),
        ("GET", "/charts/..%2Fx/1.0.0/x.tgz"),
    ] {
        let action = plugin.handle(repo(), request(method, path)).await.unwrap();
        assert!(
            matches!(&action, Action::Respond(r) if r.status == 404),
            "{method} {path}: {action:?}"
        );
    }
}

#[tokio::test]
async fn renders_the_index_from_what_it_loads() {
    let (_, plugin) = helm();
    let req = request("GET", "/index.yaml");
    let Action::Load(first) = plugin.handle(repo(), req.clone()).await.unwrap() else {
        panic!("the index loads data");
    };
    assert!(matches!(&first[..], [Query::Search(s)] if s.skip == 0 && s.prerelease));

    let version = |v: &str| VersionInfo {
        original_id: "NGINX".into(),
        version: v.into(),
        version_original: v.into(),
        listed: true,
    };
    let mut data = vec![Loaded {
        query: first[0].clone(),
        answer: Answer::Search(SearchResult {
            total: 1,
            hits: vec![SearchHit {
                original_id: "NGINX".into(),
                latest_version: "2.1.0".into(),
                versions: vec![version("1.0.0"), version("2.1.0")],
                summary: None,
            }],
        }),
    }];
    let Rendered::Load(second) = plugin
        .render(repo(), req.clone(), data.clone())
        .await
        .unwrap()
    else {
        panic!("the index loads each chart's versions");
    };
    assert!(
        matches!(&second[..], [Query::Packages(id)] if id == "nginx"),
        "{second:?}"
    );

    let package = |v: &str, listed: bool| PackageInfo {
        original_id: "NGINX".into(),
        version: v.into(),
        version_original: v.into(),
        listed,
        published: Some("2026-10-01T12:00:00+00:00".into()),
        sha256: Some("ab".repeat(32)),
        sha512: None,
        size: Some(1234),
        summary: Some(r#"{"chart":{"apiVersion":"v2","appVersion":"1.27"}}"#.into()),
    };
    data.push(Loaded {
        query: second[0].clone(),
        answer: Answer::Packages(vec![
            package("1.0.0", true),
            package("1.5.0", false),
            package("2.1.0", true),
        ]),
    });
    let Rendered::Respond(response) = plugin.render(repo(), req, data).await.unwrap() else {
        panic!("the index renders once everything is loaded");
    };
    assert_eq!(response.status, 200);
    let index: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let entries = index["entries"]["NGINX"].as_array().unwrap();
    // Newest first; unlisted versions are not offered.
    let versions: Vec<&str> = entries
        .iter()
        .map(|e| e["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["2.1.0", "1.0.0"]);
    assert_eq!(
        entries[0]["urls"][0],
        "https://forge.example.com/repository/charts/charts/nginx/2.1.0/NGINX-2.1.0.tgz"
    );
    assert_eq!(entries[0]["digest"], "ab".repeat(32));
    assert_eq!(entries[0]["appVersion"], "1.27");
    assert_eq!(index["apiVersion"], "v1");
}

#[test]
fn runs_inside_its_limits() {
    let dir = example_plugin("helm");
    let sha = component_sha256(&dir);
    let manifest = |limits: &str| {
        let text = std::fs::read_to_string(dir.join("plugin.toml")).unwrap();
        let text = text.split("[limits]").next().unwrap().to_string() + "[limits]\n" + limits;
        Manifest::parse(&text).unwrap()
    };
    let component = std::fs::read(dir.join("forge_format_helm.wasm")).unwrap();

    // Not enough fuel to even start.
    let err = Plugin::from_parts(
        manifest("fuel = 1\n"),
        &component,
        &sha,
        &HostLimits::default(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("ran out of fuel"), "{err}");

    // Not enough memory for the guest's initial heap.
    let err = Plugin::from_parts(
        manifest("memory_mib = 1\n"),
        &component,
        &sha,
        &HostLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, PluginError::Trap(_)), "{err}");

    // More than the host allows.
    let err = Plugin::from_parts(
        manifest("memory_mib = 4096\n"),
        &component,
        &sha,
        &HostLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, PluginError::Manifest(_)), "{err}");

    // A decompression bomb runs out of time or fuel instead of hanging the
    // host, and the plugin keeps serving afterwards.
    let plugin = Plugin::from_parts(
        manifest("fuel = 20000000\ntimeout_ms = 2000\n"),
        &component,
        &sha,
        &HostLimits::default(),
    )
    .unwrap();
    let format = PluginFormat::new(plugin);
    let bomb = {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        // A tar entry claiming 32 MiB of zeros before any Chart.yaml.
        let mut header = [0u8; 512];
        header[..10].copy_from_slice(b"bomb/zeros");
        header[124..136].copy_from_slice(format!("{:011o}\0", 32u64 << 20).as_bytes());
        header[156] = b'0';
        gz.write_all(&header).unwrap();
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..32 {
            gz.write_all(&zeros).unwrap();
        }
        gz.finish().unwrap()
    };
    let mut staged = tempfile::NamedTempFile::new().unwrap();
    staged.write_all(&bomb).unwrap();
    let err = format.parse_upload_file(staged.path()).unwrap_err();
    assert!(
        err.to_string().contains("fuel") || err.to_string().contains("time limit"),
        "{err}"
    );
    assert_eq!(format.normalize_version("1.0").unwrap(), "1.0.0");
}
