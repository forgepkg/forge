//! The upstream side of NuGet proxies, without a server: each operation run
//! through `forge_plugin_api::testing::converse` against canned upstream
//! documents. The host's proxy read path (`forge-core`'s `proxy_read` tests)
//! covers what it does with the answers.

use std::collections::BTreeMap;

use forge_format_nuget::upstream::Resources;
use forge_format_nuget::Nuget;
use forge_plugin_api::testing::{converse, Conversed};
use forge_plugin_api::{
    Fetch, Fetched, Freshness, PackageRef, PackageVersions, Remote, SearchQuery, UpstreamAnswer,
    UpstreamOp,
};
use serde_json::{json, Value};

const FEED: &str = "https://up.example/v3/index.json";

fn resources() -> Resources {
    Resources {
        package_base_address: Some("https://up.example/flat/".into()),
        registrations_base_url: Some("https://up.example/reg/".into()),
        search_query_service: Some("https://search.example/query".into()),
    }
}

fn remote(resources: &Resources) -> Remote {
    Remote {
        url: FEED.into(),
        index: Some(serde_json::to_string(resources).unwrap()),
    }
}

/// Run `op` against `docs` (by URL; anything else is a 404).
fn run(remote: &Remote, op: UpstreamOp, docs: &BTreeMap<String, Fetched>) -> Conversed {
    converse(&Nuget::default(), remote, &op, |fetch: &Fetch| {
        docs.get(&fetch.url).cloned().unwrap_or(Fetched::NotFound)
    })
    .expect("the conversation ends")
}

fn found(doc: Value) -> Fetched {
    Fetched::Found(doc.to_string().into_bytes())
}

fn docs(entries: impl IntoIterator<Item = (String, Fetched)>) -> BTreeMap<String, Fetched> {
    entries.into_iter().collect()
}

fn package(id: &str, version: &str) -> PackageRef {
    PackageRef {
        id: id.into(),
        version: version.into(),
    }
}

fn nuspec(id: &str, version: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?><package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">\
         <metadata><id>{id}</id><version>{version}</version><authors>a</authors>\
         <description>d</description></metadata></package>"
    )
    .into_bytes()
}

#[test]
fn the_index_is_the_service_indexs_resources() {
    let index = found(json!({ "version": "3.0.0", "resources": [
        { "@id": "https://up.example/flat", "@type": "PackageBaseAddress/3.0.0" },
        { "@id": "https://up.example/reg", "@type": "RegistrationsBaseUrl/3.6.0" },
        { "@id": "https://search.example/query", "@type": ["SearchQueryService/3.5.0"] },
    ]}));
    let unresolved = Remote {
        url: FEED.into(),
        index: None,
    };
    let done = run(
        &unresolved,
        UpstreamOp::Index,
        &docs([(FEED.into(), index)]),
    );
    assert_eq!(
        done.fetches,
        [Fetch {
            url: FEED.into(),
            freshness: Freshness::Metadata
        }]
    );
    let UpstreamAnswer::Index(index) = done.answer else {
        panic!("{:?}", done.answer)
    };
    assert_eq!(serde_json::from_str::<Resources>(&index).unwrap(), resources());

    // Not a service index (a captive portal, an error page): a failure,
    // never an empty feed.
    let portal = run(
        &unresolved,
        UpstreamOp::Index,
        &docs([(FEED.into(), found(json!({ "hello": "portal" })))]),
    );
    assert!(
        matches!(&portal.answer, UpstreamAnswer::Failed(m) if m.contains("PackageBaseAddress")),
        "{:?}",
        portal.answer
    );
    let missing = run(&unresolved, UpstreamOp::Index, &docs([]));
    assert!(
        matches!(&missing.answer, UpstreamAnswer::Failed(m) if m.contains("404")),
        "{:?}",
        missing.answer
    );
}

#[test]
fn versions_are_the_flat_containers_normalized() {
    let remote = remote(&resources());
    let url = "https://up.example/flat/contoso.lib/index.json".to_string();
    let listed = run(
        &remote,
        UpstreamOp::Versions("contoso.lib".into()),
        &docs([(url.clone(), found(json!({ "versions": ["1.0", "2.0.0-Beta", "x"] })))]),
    );
    assert_eq!(
        listed.answer,
        UpstreamAnswer::Versions(Some(vec!["1.0.0".into(), "2.0.0-beta".into()]))
    );
    assert_eq!(listed.fetches[0].url, url);

    let unknown = run(&remote, UpstreamOp::Versions("nope".into()), &docs([]));
    assert_eq!(unknown.answer, UpstreamAnswer::Versions(None));

    // A document without a versions array is no listing.
    let broken = run(
        &remote,
        UpstreamOp::Versions("contoso.lib".into()),
        &docs([(url, found(json!({ "oops": [] })))]),
    );
    assert!(matches!(broken.answer, UpstreamAnswer::Failed(_)));
}

#[test]
fn a_package_is_in_the_flat_container() {
    let done = run(
        &remote(&resources()),
        UpstreamOp::Package(package("contoso.lib", "1.0.0")),
        &docs([]),
    );
    assert!(done.fetches.is_empty());
    assert_eq!(
        done.answer,
        UpstreamAnswer::Package(
            "https://up.example/flat/contoso.lib/1.0.0/contoso.lib.1.0.0.nupkg".into()
        )
    );
}

#[test]
fn a_manifest_is_served_only_for_its_own_version() {
    let remote = remote(&resources());
    let url = "https://up.example/flat/contoso.lib/1.0.0/contoso.lib.nuspec".to_string();
    let own = run(
        &remote,
        UpstreamOp::Manifest(package("contoso.lib", "1.0.0")),
        &docs([(url.clone(), Fetched::Found(nuspec("Contoso.Lib", "1.0")))]),
    );
    assert_eq!(own.fetches[0].freshness, Freshness::Immutable);
    assert_eq!(
        own.answer,
        UpstreamAnswer::Manifest(Some(nuspec("Contoso.Lib", "1.0")))
    );
    let other = run(
        &remote,
        UpstreamOp::Manifest(package("contoso.lib", "1.0.0")),
        &docs([(url, Fetched::Found(nuspec("Evil.Lib", "1.0.0")))]),
    );
    assert_eq!(other.answer, UpstreamAnswer::Manifest(None));
}

fn leaf(id: &str, version: &str, listed: bool) -> Value {
    json!({ "catalogEntry": {
        "@id": format!("https://up.example/catalog/{version}.json"),
        "id": id,
        "version": version,
        "listed": listed,
        "published": "2021-05-01T10:00:00+00:00",
        "dependencyGroups": [ {
            "targetFramework": "net8.0",
            "dependencies": [ { "id": format!("Dep.{version}"), "range": "[1.0.0, )" } ]
        } ]
    } })
}

#[test]
fn metadata_reads_the_newest_registration_pages_only() {
    let versions: Vec<String> = (1..=12).map(|n| format!("{n}.0.0")).collect();
    let mut entries = vec![(
        "https://up.example/reg/contoso.lib/index.json".to_string(),
        found(json!({ "items": versions.iter().map(|v| json!({
            "@id": format!("https://up.example/reg/contoso.lib/page/{v}.json"),
            "lower": v,
            "upper": v,
        })).collect::<Vec<_>>() })),
    )];
    for v in &versions {
        entries.push((
            format!("https://up.example/reg/contoso.lib/page/{v}.json"),
            found(json!({ "items": [leaf("Contoso.Lib", v, true)] })),
        ));
    }
    let done = run(
        &remote(&resources()),
        UpstreamOp::Metadata(PackageVersions {
            id: "contoso.lib".into(),
            versions: versions.clone(),
        }),
        &docs(entries),
    );
    // The index, then the ten newest pages.
    assert_eq!(done.fetches.len(), 11);
    assert!(done.fetches[1..]
        .iter()
        .all(|f| !f.url.ends_with("/1.0.0.json") && !f.url.ends_with("/2.0.0.json")));
    let UpstreamAnswer::Metadata(metadata) = done.answer else {
        panic!("{:?}", done.answer)
    };
    assert_eq!(metadata.original_id.as_deref(), Some("Contoso.Lib"));
    assert_eq!(metadata.versions.len(), 10);
    let newest = metadata
        .versions
        .iter()
        .find(|v| v.version == "12.0.0")
        .unwrap();
    assert!(newest.listed);
    assert_eq!(
        newest.published.as_deref(),
        Some("2021-05-01T10:00:00+00:00")
    );
    assert_eq!(newest.created, None, "only dating dates");
    let summary: Value = serde_json::from_str(newest.summary.as_deref().unwrap()).unwrap();
    assert_eq!(
        summary["dependency_groups"][0]["dependencies"][0]["id"],
        "Dep.12.0.0"
    );
}

#[test]
fn dating_reads_the_catalog_of_unlisted_versions() {
    let entries = vec![
        (
            "https://up.example/reg/contoso.lib/index.json".to_string(),
            found(json!({ "items": [ {
                "@id": "https://up.example/reg/contoso.lib/page/1.json",
                "lower": "1.0.0",
                "upper": "2.0.0",
                "items": [
                    leaf("Contoso.Lib", "1.0.0", false),
                    leaf("Contoso.Lib", "2.0.0", true),
                    // Not this package's metadata.
                    leaf("Evil.Lib", "3.0.0", true),
                ],
            } ] })),
        ),
        (
            "https://up.example/catalog/1.0.0.json".to_string(),
            found(json!({ "created": "2019-01-01T00:00:00Z" })),
        ),
    ];
    let done = run(
        &remote(&resources()),
        UpstreamOp::Dating(PackageVersions {
            id: "contoso.lib".into(),
            versions: vec!["1.0.0".into(), "2.0.0".into(), "3.0.0".into()],
        }),
        &docs(entries),
    );
    assert_eq!(
        done.fetches.last().unwrap(),
        &Fetch {
            url: "https://up.example/catalog/1.0.0.json".into(),
            freshness: Freshness::Immutable,
        }
    );
    let UpstreamAnswer::Metadata(metadata) = done.answer else {
        panic!("{:?}", done.answer)
    };
    let by_version: BTreeMap<&str, _> = metadata
        .versions
        .iter()
        .map(|v| (v.version.as_str(), v))
        .collect();
    assert_eq!(
        by_version.keys().copied().collect::<Vec<_>>(),
        ["1.0.0", "2.0.0"]
    );
    assert!(!by_version["1.0.0"].listed);
    assert_eq!(
        by_version["1.0.0"].created.as_deref(),
        Some("2019-01-01T00:00:00Z")
    );
    assert_eq!(
        by_version["2.0.0"].created.as_deref(),
        Some("2021-05-01T10:00:00+00:00")
    );
}

#[test]
fn search_forwards_the_query_and_reads_the_hits() {
    let url = "https://search.example/query?q=contoso&skip=0&take=2&prerelease=false&semVerLevel=2.0.0";
    let page = found(json!({ "totalHits": 7, "data": [
        { "id": "Contoso.Lib", "version": "2.0.0",
          "versions": [ { "version": "2.0" }, { "version": "1.0.0" } ],
          "description": " A lib ", "totalDownloads": 42 },
        { "id": "../admin", "version": "1.0.0" },
        { "id": "Beyond.Take", "version": "1.0.0" },
    ]}));
    let query = SearchQuery {
        text: "contoso".into(),
        skip: 0,
        take: 2,
        prerelease: false,
        semver2: true,
        upstream: true,
    };
    let done = run(
        &remote(&resources()),
        UpstreamOp::Search(query.clone()),
        &docs([(url.to_string(), page)]),
    );
    assert_eq!(done.fetches[0].url, url);
    let UpstreamAnswer::Search(Some(search)) = done.answer else {
        panic!("{:?}", done.answer)
    };
    // Two entries read (`take`); the malformed id dropped and the total
    // reduced by it.
    assert_eq!(search.total, 6);
    assert_eq!(search.hits.len(), 1);
    let hit = &search.hits[0];
    assert_eq!(hit.id, "Contoso.Lib");
    assert_eq!(hit.versions, ["1.0.0", "2.0.0"]);
    assert_eq!(hit.total_downloads, Some(42));
    let summary: Value = serde_json::from_str(hit.summary.as_deref().unwrap()).unwrap();
    assert_eq!(summary["metadata"]["description"], "A lib");

    let without = Resources {
        search_query_service: None,
        ..resources()
    };
    assert_eq!(
        run(&remote(&without), UpstreamOp::Search(query), &docs([])).answer,
        UpstreamAnswer::Search(None)
    );
}
