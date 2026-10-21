//! Helm proxies without a server: the upstream side run through
//! `forge_plugin_api::testing::converse` against a canned `index.yaml`, and a
//! proxy's index rendered through `testing::serve` from the search the host
//! answers with the upstream's charts.

use std::collections::BTreeMap;

use forge_format_helm::Helm;
use forge_plugin_api::testing::{converse, repository, serve, Conversed};
use forge_plugin_api::{
    Answer, Fetch, Fetched, Freshness, PackageRef, PackageVersions, Query, Remote, RepositoryKind,
    Request, SearchHit, SearchQuery, SearchResult, UpstreamAnswer, UpstreamOp, VersionInfo,
};
use serde_json::{json, Value};

const BASE: &str = "https://charts.example/stable";

const INDEX: &str = r#"apiVersion: v1
entries:
  Nginx:
    - apiVersion: v2
      name: Nginx
      version: 2.1.0
      appVersion: "1.25"
      description: A web server
      created: "2026-05-01T10:00:00.123456789Z"
      digest: abc
      urls:
        - charts/Nginx-2.1.0.tgz
    - apiVersion: v2
      name: Nginx
      version: v1.0
      description: An old web server
      created: "2024-01-01T00:00:00Z"
      urls:
        - https://cdn.example/Nginx-1.0.0.tgz
  redis:
    - apiVersion: v2
      name: redis
      version: 7.0.0
      urls: [redis-7.0.0.tgz]
generated: "2026-05-01T10:00:00Z"
"#;

fn resolved() -> Remote {
    Remote {
        url: format!("{BASE}/"),
        index: Some(json!({ "base": BASE }).to_string()),
    }
}

fn run(remote: &Remote, op: UpstreamOp, docs: &BTreeMap<String, Fetched>) -> Conversed {
    converse(&Helm, remote, &op, |fetch: &Fetch| {
        docs.get(&fetch.url).cloned().unwrap_or(Fetched::NotFound)
    })
    .expect("the conversation ends")
}

fn upstream() -> BTreeMap<String, Fetched> {
    BTreeMap::from([(
        format!("{BASE}/index.yaml"),
        Fetched::Found(INDEX.as_bytes().to_vec()),
    )])
}

fn package(id: &str, version: &str) -> PackageRef {
    PackageRef {
        id: id.into(),
        version: version.into(),
    }
}

#[test]
fn the_index_is_the_repository_base() {
    let unresolved = Remote {
        url: format!("{BASE}/"),
        index: None,
    };
    let done = run(&unresolved, UpstreamOp::Index, &upstream());
    assert_eq!(
        done.fetches,
        [Fetch {
            url: format!("{BASE}/index.yaml"),
            freshness: Freshness::Metadata,
        }]
    );
    let UpstreamAnswer::Index(index) = done.answer else {
        panic!("{:?}", done.answer)
    };
    assert_eq!(
        serde_json::from_str::<Value>(&index).unwrap(),
        json!({ "base": BASE })
    );

    // Not a chart repository: a failure, never an empty one.
    let portal = BTreeMap::from([(
        format!("{BASE}/index.yaml"),
        Fetched::Found(b"<html>sign in</html>".to_vec()),
    )]);
    assert!(matches!(
        run(&unresolved, UpstreamOp::Index, &portal).answer,
        UpstreamAnswer::Failed(_)
    ));
    assert!(matches!(
        run(&unresolved, UpstreamOp::Index, &BTreeMap::new()).answer,
        UpstreamAnswer::Failed(m) if m.contains("404")
    ));
}

#[test]
fn versions_and_packages_come_from_the_index() {
    let remote = resolved();
    assert_eq!(
        run(&remote, UpstreamOp::Versions("nginx".into()), &upstream()).answer,
        UpstreamAnswer::Versions(Some(vec!["1.0.0".into(), "2.1.0".into()]))
    );
    assert_eq!(
        run(&remote, UpstreamOp::Versions("mysql".into()), &upstream()).answer,
        UpstreamAnswer::Versions(None)
    );
    // Relative and absolute URLs; a version the index does not list gets
    // the conventional location.
    for (target, url) in [
        (
            package("nginx", "2.1.0"),
            format!("{BASE}/charts/Nginx-2.1.0.tgz"),
        ),
        (
            package("nginx", "1.0.0"),
            "https://cdn.example/Nginx-1.0.0.tgz".to_string(),
        ),
        (package("redis", "7.0.0"), format!("{BASE}/redis-7.0.0.tgz")),
        (package("redis", "6.0.0"), format!("{BASE}/redis-6.0.0.tgz")),
    ] {
        assert_eq!(
            run(&remote, UpstreamOp::Package(target), &upstream()).answer,
            UpstreamAnswer::Package(url)
        );
    }
    // A chart repository has no manifest without its chart.
    let manifest = run(
        &remote,
        UpstreamOp::Manifest(package("nginx", "2.1.0")),
        &upstream(),
    );
    assert!(manifest.fetches.is_empty());
    assert_eq!(manifest.answer, UpstreamAnswer::Manifest(None));
}

#[test]
fn metadata_and_dating_read_the_entries() {
    let wanted = PackageVersions {
        id: "nginx".into(),
        versions: vec!["1.0.0".into(), "2.1.0".into(), "9.9.9".into()],
    };
    let UpstreamAnswer::Metadata(metadata) =
        run(&resolved(), UpstreamOp::Dating(wanted.clone()), &upstream()).answer
    else {
        panic!("metadata")
    };
    assert_eq!(metadata.original_id.as_deref(), Some("Nginx"));
    assert_eq!(metadata.versions.len(), 2);
    let newest = &metadata.versions[1];
    assert_eq!(newest.version, "2.1.0");
    assert!(newest.listed);
    assert_eq!(
        newest.created.as_deref(),
        Some("2026-05-01T10:00:00.123456789Z")
    );
    let summary: Value = serde_json::from_str(newest.summary.as_deref().unwrap()).unwrap();
    assert_eq!(summary["description"], "A web server");
    assert_eq!(summary["chart"]["appVersion"], "1.25");

    let UpstreamAnswer::Metadata(plain) =
        run(&resolved(), UpstreamOp::Metadata(wanted), &upstream()).answer
    else {
        panic!("metadata")
    };
    assert!(plain.versions.iter().all(|v| v.created.is_none()));
}

#[test]
fn search_matches_chart_names() {
    let query = |text: &str, skip: u32, take: u32| SearchQuery {
        text: text.into(),
        skip,
        take,
        prerelease: true,
        semver2: true,
        upstream: true,
    };
    let search = |q: SearchQuery| match run(&resolved(), UpstreamOp::Search(q), &upstream()).answer
    {
        UpstreamAnswer::Search(Some(page)) => page,
        other => panic!("{other:?}"),
    };
    let all = search(query("", 0, 0));
    assert_eq!(all.total, 2);
    assert_eq!(all.hits[0].id, "Nginx");
    assert_eq!(all.hits[0].versions, ["1.0.0", "2.1.0"]);
    assert_eq!(all.hits[1].id, "redis");
    assert_eq!(search(query("ngi", 0, 0)).total, 1);
    assert_eq!(search(query("id:ngi", 0, 0)).total, 0);
    assert_eq!(search(query("packageid:NGINX", 0, 0)).hits[0].id, "Nginx");
    let second = search(query("", 1, 1));
    assert_eq!((second.total, second.hits.len()), (2, 1));
    assert_eq!(second.hits[0].id, "redis");
}

#[test]
fn a_proxys_index_lists_what_its_upstream_search_found() {
    let repo = repository(RepositoryKind::Proxy, "/repository");
    let summary = json!({ "chart": {
        "apiVersion": "v2", "name": "Nginx", "version": "2.1.0", "appVersion": "1.25"
    }, "description": "A web server", "dependency_groups": [] })
    .to_string();
    let version = |v: &str| VersionInfo {
        original_id: "Nginx".into(),
        version: v.into(),
        version_original: v.into(),
        listed: true,
    };
    let served = serve(&Helm, &repo, &Request::new("GET", "/index.yaml"), |query| {
        match query {
            // The upstream's charts too, not only the cached ones.
            Query::Search(q) if q.upstream => Answer::Search(SearchResult {
                total: 1,
                hits: vec![SearchHit {
                    original_id: "Nginx".into(),
                    latest_version: "2.1.0".into(),
                    versions: vec![version("1.0.0"), version("2.1.0")],
                    summary: Some(summary.clone()),
                    total_downloads: None,
                }],
            }),
            other => panic!("unexpected {other:?}"),
        }
    });
    // One search, no per-chart reads of the upstream.
    assert_eq!(served.queries.len(), 1);
    let index: Value = serde_json::from_str(&served.text()).unwrap();
    let entries = index["entries"]["Nginx"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["version"], "2.1.0");
    assert_eq!(entries[0]["appVersion"], "1.25");
    assert_eq!(
        entries[0]["urls"][0],
        "https://forge.example.com/repository/repo/charts/nginx/2.1.0/Nginx-2.1.0.tgz"
    );
    // An older version: name, version and URL (the search describes the
    // newest only).
    assert_eq!(entries[1]["version"], "1.0.0");
    assert_eq!(entries[1]["apiVersion"], "v2");
    assert!(entries[1].get("appVersion").is_none());
}
