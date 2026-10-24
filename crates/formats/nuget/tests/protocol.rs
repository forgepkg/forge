//! The NuGet V3 protocol as the plugin speaks it,
//! driven through `forge_plugin_api::testing::serve` against an in-memory
//! repository: the exact JSON shapes, absolute `@id`s, hosted-only
//! `PackagePublish`, `GET` + `HEAD`, content types, lowercasing, 404s before
//! any data is loaded, and the host actions it asks for. What the host does
//! with those actions (streaming, ranges, publishing, authorization) is
//! tested with the server.

use std::collections::HashMap;

use forge_format_nuget::Nuget;
use forge_plugin_api::testing::{serve, Served};
use forge_plugin_api::{
    Action, Answer, FormatPlugin, PackageInfo, PackageRef, Query, Repository, RepositoryKind,
    Request, SearchHit, SearchResult, Upload, VersionInfo,
};
use serde_json::{json, Value};

const BASE: &str = "https://forge.example.com";

fn repo(kind: RepositoryKind) -> Repository {
    Repository {
        name: "main".into(),
        kind,
        base_url: format!("{BASE}/repository/main"),
        inline: false,
        reserved_prefixes: Vec::new(),
    }
}

/// An in-memory repository answering the plugin's queries as the host does.
#[derive(Default, Clone)]
struct MockRepo {
    /// lower id → versions (ascending).
    versions: HashMap<String, Vec<VersionInfo>>,
    /// lower id → versions with metadata (ascending).
    packages: HashMap<String, Vec<PackageInfo>>,
    /// (lower id, version) → stored `.nuspec`.
    manifests: HashMap<(String, String), Vec<u8>>,
    /// Search hits, in order.
    hits: Vec<SearchHit>,
}

impl MockRepo {
    fn answer(&self, query: &Query) -> Answer {
        match query {
            Query::Versions(id) => {
                Answer::Versions(self.versions.get(id).cloned().unwrap_or_default())
            }
            Query::Packages(id) | Query::DatedPackages(id) => {
                Answer::Packages(self.packages.get(id).cloned().unwrap_or_default())
            }
            Query::PackagesOf(set) => Answer::Packages(
                self.packages
                    .get(&set.id)
                    .into_iter()
                    .flatten()
                    .filter(|p| set.versions.contains(&p.version))
                    .cloned()
                    .collect(),
            ),
            Query::Package(target) => Answer::Package(
                self.packages
                    .get(&target.id)
                    .into_iter()
                    .flatten()
                    .find(|p| p.version == target.version)
                    .cloned(),
            ),
            Query::Tags(_) => Answer::Tags(Vec::new()),
            Query::Manifest(target) => Answer::Manifest(
                self.manifests
                    .get(&(target.id.clone(), target.version.clone()))
                    .cloned(),
            ),
            Query::Search(search) => {
                // As the host: SemVer 2.0.0 versions dropped unless asked
                // for, before paging; take 0 is 20, more than 1000 is 1000.
                let semver2 = |v: &str| {
                    v.contains('+') || v.split_once('-').is_some_and(|(_, p)| p.contains('.'))
                };
                let matching: Vec<SearchHit> = self
                    .hits
                    .iter()
                    .filter_map(|hit| {
                        let mut hit = hit.clone();
                        hit.versions
                            .retain(|v| search.semver2 || !semver2(&v.version_original));
                        hit.latest_version = hit.versions.last()?.version.clone();
                        Some(hit)
                    })
                    .collect();
                let take = match search.take {
                    0 => 20,
                    n => n.min(1000),
                } as usize;
                Answer::Search(SearchResult {
                    total: matching.len() as u32,
                    hits: matching
                        .into_iter()
                        .skip(search.skip as usize)
                        .take(take)
                        .collect(),
                })
            }
            other => panic!("NuGet asked for files: {other:?}"),
        }
    }

    fn serve(&self, kind: RepositoryKind, req: &Request) -> Served {
        serve(&Nuget::default(), &repo(kind), req, |q| self.answer(q))
    }

    fn get(&self, target: &str) -> Served {
        self.serve(RepositoryKind::Hosted, &Request::new("GET", target))
    }
}

fn json_of(served: &Served) -> Value {
    let response = served.response();
    assert_eq!(response.status, 200, "{}", served.text());
    assert_eq!(served.header("content-type"), Some("application/json"));
    serde_json::from_slice(&response.body).expect("valid json")
}

fn version(id: &str, v: &str, listed: bool) -> VersionInfo {
    VersionInfo {
        original_id: id.into(),
        version: v.into(),
        version_original: v.into(),
        listed,
    }
}

/// A version's metadata as the host hands it over: the summary is what the
/// plugin's `manifest_summary` made of its manifest.
fn package(id: &str, v: &str, nuspec: Option<&[u8]>) -> PackageInfo {
    PackageInfo {
        original_id: id.into(),
        version: v.into(),
        version_original: v.into(),
        listed: true,
        published: None,
        sha256: None,
        sha512: None,
        size: None,
        summary: nuspec.and_then(|n| Nuget::default().manifest_summary(n)),
        deprecated: None,
    }
}

// ── Service index ────────────────────────────────────────────────────────────

#[test]
fn service_index_hosted_advertises_publish_with_absolute_ids() {
    let v = json_of(&MockRepo::default().get("/index.json"));
    assert_eq!(v["version"], "3.0.0");
    let resources = v["resources"].as_array().unwrap();
    let by_type = |t: &str| {
        resources
            .iter()
            .find(|r| r["@type"] == t)
            .map(|r| r["@id"].as_str().unwrap().to_string())
    };
    assert_eq!(
        by_type("SearchQueryService/3.5.0").as_deref(),
        Some("https://forge.example.com/repository/main/query")
    );
    assert_eq!(
        by_type("RegistrationsBaseUrl/3.6.0").as_deref(),
        Some("https://forge.example.com/repository/main/registration/")
    );
    assert_eq!(
        by_type("PackageBaseAddress/3.0.0").as_deref(),
        Some("https://forge.example.com/repository/main/flat/")
    );
    assert_eq!(
        by_type("PackagePublish/2.0.0").as_deref(),
        Some("https://forge.example.com/repository/main/package")
    );
}

#[test]
fn service_index_of_proxies_and_groups_omits_publish() {
    for kind in [RepositoryKind::Proxy, RepositoryKind::Group] {
        let served = MockRepo::default().serve(kind, &Request::new("GET", "/index.json"));
        let v = json_of(&served);
        let has_publish = v["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["@type"] == "PackagePublish/2.0.0");
        assert!(!has_publish, "{kind:?} must not advertise PackagePublish");
    }
}

#[test]
fn service_index_advertises_every_registration_variant() {
    let served =
        MockRepo::default().serve(RepositoryKind::Proxy, &Request::new("GET", "/index.json"));
    let types: Vec<String> = json_of(&served)["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["@type"].as_str().unwrap().to_string())
        .collect();
    for ty in [
        "RegistrationsBaseUrl",
        "RegistrationsBaseUrl/3.0.0-rc",
        "RegistrationsBaseUrl/3.4.0",
        "RegistrationsBaseUrl/3.6.0",
    ] {
        assert!(types.iter().any(|t| t == ty), "missing {ty}");
    }
}

#[test]
fn read_routes_take_get_and_head_only() {
    let mock = MockRepo::default();
    for method in ["GET", "HEAD"] {
        let served = mock.serve(RepositoryKind::Hosted, &Request::new(method, "/index.json"));
        assert_eq!(served.response().status, 200, "{method}");
    }
    let served = mock.serve(
        RepositoryKind::Hosted,
        &Request::new("DELETE", "/index.json"),
    );
    assert_eq!(served.response().status, 405);
    assert_eq!(served.header("allow"), Some("GET,HEAD"));
    // Unknown paths answer an empty 404, as a router does.
    for target in ["/", "/no/such/route", "/index.json/", "/flat//index.json"] {
        let served = mock.get(target);
        assert_eq!(served.response().status, 404, "{target}");
        assert!(served.response().body.is_empty(), "{target}");
    }
}

// ── Flat container ───────────────────────────────────────────────────────────

fn with_versions() -> MockRepo {
    let mut mock = MockRepo::default();
    mock.versions.insert(
        "sample.lib".into(),
        vec![
            version("Sample.Lib", "1.0.0", true),
            version("Sample.Lib", "2.0.0-beta1", false),
        ],
    );
    mock
}

#[test]
fn flat_versions_lists_all_including_unlisted() {
    // A mixed-case id is lowercased before the lookup.
    let served = with_versions().get("/flat/Sample.LIB/index.json");
    assert_eq!(served.queries, [Query::Versions("sample.lib".into())]);
    assert_eq!(
        json_of(&served)["versions"],
        json!(["1.0.0", "2.0.0-beta1"])
    );
}

#[test]
fn flat_versions_unknown_id_404() {
    let served = MockRepo::default().get("/flat/nope/index.json");
    assert_eq!(served.response().status, 404);
    assert_eq!(served.text(), "package not found");
}

#[test]
fn flat_nupkg_is_a_download_of_the_normalized_version() {
    for (target, version) in [
        ("/flat/Sample.Lib/1.0.0/sample.lib.1.0.0.nupkg", "1.0.0"),
        ("/flat/sample.lib/1.0/sample.lib.1.0.nupkg", "1.0.0"),
        ("/flat/sample.lib/9.9.9/sample.lib.9.9.9.NUPKG", "9.9.9"),
    ] {
        for method in ["GET", "HEAD"] {
            let served =
                MockRepo::default().serve(RepositoryKind::Hosted, &Request::new(method, target));
            assert_eq!(
                served.outcome,
                Action::Download(PackageRef {
                    id: "sample.lib".into(),
                    version: version.into(),
                }),
                "{method} {target}"
            );
            assert!(served.queries.is_empty());
        }
    }
}

#[test]
fn flat_nuspec_serves_xml() {
    let mut mock = MockRepo::default();
    mock.manifests.insert(
        ("sample.lib".into(), "1.0.0".into()),
        b"<?xml version=\"1.0\"?><package/>".to_vec(),
    );
    let served = mock.get("/flat/sample.lib/1.0.0/sample.lib.nuspec");
    assert_eq!(served.response().status, 200);
    assert_eq!(served.header("content-type"), Some("application/xml"));
    assert!(served.text().contains("<package/>"));

    let served = mock.get("/flat/sample.lib/9.9.9/sample.lib.nuspec");
    assert_eq!(served.response().status, 404);
    assert_eq!(served.text(), "nuspec not found");
    let served = mock.get("/flat/sample.lib/1.0.0/sample.lib.zip");
    assert_eq!(served.text(), "unknown content");
    let served = mock.get("/flat/sample.lib/not-a-version/x.nupkg");
    assert_eq!(served.text(), "invalid version");
}

/// Ids that are not well-formed never reach the host's queries (a proxy
/// would paste them into credentialed upstream URLs): every id-addressed
/// route answers 404 first, however the id is percent-encoded.
#[test]
fn malformed_ids_are_404_before_any_query() {
    for target in [
        "/flat/x%2F..%2Fsample.lib/index.json",
        "/flat/X%2F..%2Fsample.lib/1.0.0/x.nuspec",
        "/flat/X%2F..%2Fsample.lib/1.0.0/x.nupkg",
        "/flat/sample.lib%3Fq%3D1/index.json",
        "/flat/sample.lib%23frag/index.json",
        "/registration/x%2F..%2Fsample.lib/index.json",
        "/registration/x%2F..%2Fsample.lib/1.0.0.json",
        "/registration/x%2F..%2Fsample.lib/page/1.0.0/2.0.0.json",
        "/catalog/x%2F..%2Fsample.lib/1.0.0.json",
    ] {
        let served = MockRepo::default().serve(RepositoryKind::Proxy, &Request::new("GET", target));
        assert_eq!(served.response().status, 404, "{target}");
        assert!(served.queries.is_empty(), "{target}");
    }
}

/// A version longer than any publishable one answers 404 before any query.
#[test]
fn overlong_versions_are_404_before_any_query() {
    let long = format!("1.0.0-{}", "a".repeat(59));
    for target in [
        format!("/flat/sample.lib/{long}/sample.lib.nuspec"),
        format!("/flat/sample.lib/{long}/sample.lib.nupkg"),
        format!("/registration/sample.lib/{long}.json"),
        format!("/catalog/sample.lib/{long}.json"),
    ] {
        let served =
            MockRepo::default().serve(RepositoryKind::Proxy, &Request::new("GET", &target));
        assert_eq!(served.response().status, 404, "{target}");
        assert!(served.queries.is_empty(), "{target}");
    }
}

// ── Registration ─────────────────────────────────────────────────────────────

fn nuspec_with_dep() -> Vec<u8> {
    br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Sample.Lib</id>
    <version>1.0.0</version>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="[13.0.1, )" />
      </group>
    </dependencies>
  </metadata>
</package>"#
        .to_vec()
}

fn nuspec_with_metadata() -> Vec<u8> {
    br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Sample.Lib</id>
    <version>1.0.0</version>
    <authors>Alice, Bob</authors>
    <description>A sample &amp; more</description>
    <tags>json serializer</tags>
    <license type="expression">MIT</license>
    <projectUrl>https://example.com/p</projectUrl>
  </metadata>
</package>"#
        .to_vec()
}

/// `mock` with `packages` registered under `id`, and their versions listed.
fn register(mock: &mut MockRepo, id: &str, packages: Vec<PackageInfo>) {
    mock.versions.insert(
        id.into(),
        packages
            .iter()
            .map(|p| version(&p.original_id, &p.version, p.listed))
            .collect(),
    );
    mock.packages.insert(id.into(), packages);
}

#[test]
fn registration_inlined_page_shape() {
    let mut mock = MockRepo::default();
    let mut first = package("Sample.Lib", "1.0.0", Some(&nuspec_with_dep()));
    first.sha512 = Some("HASH512".into());
    let mut second = package("Sample.Lib", "2.0.0", None);
    second.sha512 = Some("HASH2".into());
    register(&mut mock, "sample.lib", vec![first, second]);

    let served = mock.get("/registration/Sample.Lib/index.json");
    assert_eq!(
        served.queries,
        [
            Query::Versions("sample.lib".into()),
            Query::Packages("sample.lib".into())
        ]
    );
    let v = json_of(&served);
    assert_eq!(v["count"], 1);
    let page = &v["items"][0];
    assert_eq!(page["count"], 2);
    assert_eq!(page["lower"], "1.0.0");
    assert_eq!(page["upper"], "2.0.0");

    let leaf0 = &page["items"][0];
    let ce = &leaf0["catalogEntry"];
    assert_eq!(ce["id"], "Sample.Lib");
    assert_eq!(ce["version"], "1.0.0");
    assert_eq!(ce["listed"], true);
    assert_eq!(ce["packageHash"], "HASH512");
    assert_eq!(ce["packageHashAlgorithm"], "SHA512");
    assert_eq!(
        ce["packageContent"],
        "https://forge.example.com/repository/main/flat/sample.lib/1.0.0/sample.lib.1.0.0.nupkg"
    );
    assert_eq!(leaf0["packageContent"], ce["packageContent"]);

    let groups = ce["dependencyGroups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["targetFramework"], "net8.0");
    assert_eq!(groups[0]["dependencies"][0]["id"], "Newtonsoft.Json");
    assert_eq!(groups[0]["dependencies"][0]["range"], "[13.0.1, )");

    // A version without a manifest summary: no dependency groups, still valid.
    let leaf1 = &page["items"][1];
    assert_eq!(
        leaf1["catalogEntry"]["dependencyGroups"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

/// Up to 128 versions the index inlines every page (of 64); beyond that the
/// index only lists the pages and each page is served on its own URL.
#[test]
fn registration_pages_large_packages() {
    let packages = |id: &str, n: usize| {
        (0..n)
            .map(|i| package(id, &format!("1.0.{i}"), None))
            .collect()
    };
    let mut mock = MockRepo::default();
    register(&mut mock, "big.lib", packages("Big.Lib", 200));
    register(&mut mock, "small.lib", packages("Small.Lib", 100));
    register(&mut mock, "huge.lib", packages("Huge.Lib", 300));

    let doc = json_of(&mock.get("/registration/small.lib/index.json"));
    assert_eq!(doc["count"], 2);
    assert_eq!(doc["items"][0]["count"], 64);
    assert_eq!(doc["items"][0]["items"].as_array().unwrap().len(), 64);
    assert_eq!(doc["items"][1]["items"].as_array().unwrap().len(), 36);

    let served = mock.get("/registration/big.lib/index.json");
    // The versions alone: no metadata is loaded for a paged index.
    assert_eq!(served.queries, [Query::Versions("big.lib".into())]);
    let doc = json_of(&served);
    assert_eq!(doc["count"], 4);
    let pages = doc["items"].as_array().unwrap();
    assert!(
        pages.iter().all(|p| p.get("items").is_none()),
        "pages are not inlined"
    );
    assert_eq!(pages[3]["count"], 8);
    let page_url = pages[1]["@id"].as_str().unwrap();
    assert_eq!(
        page_url,
        format!("{BASE}/repository/main/registration/big.lib/page/1.0.64/1.0.127.json")
    );
    let served = mock.get(&page_url[format!("{BASE}/repository/main").len()..]);
    let Some(Query::PackagesOf(set)) = served.queries.last() else {
        panic!("a page loads its versions: {:?}", served.queries);
    };
    assert_eq!(set.versions.len(), 64);
    let page = json_of(&served);
    assert_eq!(page["items"].as_array().unwrap().len(), 64);
    assert_eq!(page["lower"], "1.0.64");
    for bad in [
        "/registration/big.lib/page/not-a-version/1.0.2.json",
        "/registration/nope.lib/page/1.0.0/1.0.63.json",
        "/registration/big.lib/page/1.0.0/1.0.63",
        // More versions than any page holds: not rendered in one response.
        "/registration/huge.lib/page/0.0.0/9.0.0.json",
    ] {
        let served = mock.get(bad);
        assert_eq!(served.response().status, 404, "{bad}");
        assert_eq!(served.text(), "registration page not found", "{bad}");
    }
}

/// A page URL from an index a client cached keeps resolving after pushes and
/// deletes re-chunk the index: the page serves the versions in its range.
#[test]
fn registration_page_urls_survive_a_rechunk() {
    // As cached: 1.0.0 .. 1.0.199; the second page is 1.0.64 .. 1.0.127.
    // Now 1.0.0 is deleted and a servicing release 1.0.100-fix lands inside
    // that page's range, so every chunk boundary has moved.
    let mut packages: Vec<PackageInfo> = (1..200)
        .map(|i| package("Big.Lib", &format!("1.0.{i}"), None))
        .collect();
    packages.insert(99, package("Big.Lib", "1.0.100-fix", None));
    let mut mock = MockRepo::default();
    register(&mut mock, "big.lib", packages);

    let page = json_of(&mock.get("/registration/big.lib/page/1.0.64/1.0.127.json"));
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 65, "1.0.64 ..= 1.0.127 plus 1.0.100-fix");
    assert_eq!(items[0]["catalogEntry"]["version"], "1.0.64");
    assert_eq!(items[64]["catalogEntry"]["version"], "1.0.127");
    assert_eq!(page["lower"], "1.0.64");
    assert_eq!(page["upper"], "1.0.127");
    assert_eq!(
        page["@id"],
        format!("{BASE}/repository/main/registration/big.lib/page/1.0.64/1.0.127.json")
    );
}

#[test]
fn registration_unknown_id_404() {
    let served = MockRepo::default().get("/registration/nope/index.json");
    assert_eq!(served.response().status, 404);
    assert_eq!(served.text(), "registration not found");
}

#[test]
fn registration_leaf_and_catalog_documents_resolve() {
    let mut mock = MockRepo::default();
    let mut listed = package("Sample.Lib", "1.0.0", Some(&nuspec_with_metadata()));
    listed.sha512 = Some("HASH".into());
    listed.published = Some("2026-01-02T03:04:05.000+00:00".into());
    let mut unlisted = package("Sample.Lib", "0.9.0", None);
    unlisted.listed = false;
    unlisted.published = Some("2026-01-02T03:04:05.000+00:00".into());
    register(&mut mock, "sample.lib", vec![unlisted, listed]);

    let index = json_of(&mock.get("/registration/sample.lib/index.json"));
    let leaf = &index["items"][0]["items"][1];
    let ce = &leaf["catalogEntry"];
    assert_eq!(ce["published"], "2026-01-02T03:04:05.000+00:00");
    assert_eq!(ce["description"], "A sample & more");
    assert_eq!(ce["licenseExpression"], "MIT");
    assert_eq!(ce["licenseUrl"], "https://licenses.nuget.org/MIT");
    assert_eq!(
        index["items"][0]["items"][0]["catalogEntry"]["published"], "1900-01-01T00:00:00+00:00",
        "unlisted versions use nuget.org's 1900 marker"
    );

    // The leaf @id resolves to the leaf document …
    let path = leaf["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("https://forge.example.com/repository/main")
        .unwrap()
        .to_string();
    let doc = json_of(&mock.get(&path));
    assert_eq!(doc["listed"], true);
    assert_eq!(doc["catalogEntry"], ce["@id"]);
    assert_eq!(doc["published"], "2026-01-02T03:04:05.000+00:00");

    // … and its catalogEntry URL to the catalog entry.
    let path = doc["catalogEntry"]
        .as_str()
        .unwrap()
        .strip_prefix("https://forge.example.com/repository/main")
        .unwrap()
        .to_string();
    assert_eq!(json_of(&mock.get(&path))["authors"], "Alice, Bob");

    for target in [
        "/registration/sample.lib/9.9.9.json",
        "/registration/sample.lib/1.0.0",
        "/catalog/sample.lib/9.9.9.json",
    ] {
        let served = mock.get(target);
        assert_eq!(served.response().status, 404, "{target}");
        assert_eq!(served.text(), "registration leaf not found", "{target}");
    }
}

// ── Search ───────────────────────────────────────────────────────────────────

fn hit(id: &str, versions: &[(&str, &str)]) -> SearchHit {
    SearchHit {
        original_id: id.into(),
        latest_version: versions.last().unwrap().0.into(),
        versions: versions
            .iter()
            .map(|(version, original)| VersionInfo {
                original_id: id.into(),
                version: (*version).into(),
                version_original: (*original).into(),
                listed: true,
            })
            .collect(),
        summary: None,
        total_downloads: None,
    }
}

fn with_search() -> MockRepo {
    MockRepo {
        hits: vec![hit("Sample.Lib", &[("1.0.0", "1.0.0"), ("2.0.0", "2.0.0")])],
        ..MockRepo::default()
    }
}

fn with_hits(n: usize) -> MockRepo {
    MockRepo {
        hits: (0..n)
            .map(|i| hit(&format!("Pkg.{i:04}"), &[("1.0.0", "1.0.0")]))
            .collect(),
        ..MockRepo::default()
    }
}

#[test]
fn search_asks_what_the_client_asked_for() {
    let served = MockRepo::default()
        .get("/query?q=json+lib&skip=5&take=10&prerelease=TRUE&semVerLevel=2.0.0");
    let [Query::Search(search)] = served.queries.as_slice() else {
        panic!("{:?}", served.queries);
    };
    assert_eq!(search.text, "json lib");
    assert_eq!((search.skip, search.take), (5, 10));
    assert!(search.prerelease && search.semver2 && search.upstream);

    let served = MockRepo::default().get("/query");
    let [Query::Search(search)] = served.queries.as_slice() else {
        panic!("{:?}", served.queries);
    };
    assert_eq!((search.skip, search.take), (0, 20));
    assert!(!search.prerelease && !search.semver2);
}

#[test]
fn search_shape_with_total_hits_and_versions() {
    let v = json_of(&with_search().get("/query?q=sample&prerelease=false"));
    assert_eq!(v["totalHits"], 1);
    let hit = &v["data"][0];
    assert_eq!(hit["id"], "Sample.Lib");
    assert_eq!(hit["version"], "2.0.0");
    let versions = hit["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["version"], "1.0.0");
    assert_eq!(versions[0]["downloads"], 0);
    assert_eq!(
        versions[0]["@id"],
        "https://forge.example.com/repository/main/registration/sample.lib/1.0.0.json"
    );
}

#[test]
fn search_empty_query_returns_empty_data() {
    let v = json_of(&MockRepo::default().get("/query"));
    assert_eq!(v["totalHits"], 0);
    assert_eq!(v["data"].as_array().unwrap().len(), 0);
}

#[test]
fn search_skip_past_hits_yields_empty_page_with_accurate_total() {
    let v = json_of(&with_search().get("/query?skip=5&take=10"));
    assert_eq!(v["totalHits"], 1);
    assert_eq!(v["data"].as_array().unwrap().len(), 0);
}

#[test]
fn search_take_is_clamped_like_the_host_does() {
    // take=0 and no take are the default page (20); more than 1000 is 1000.
    for (target, n, expected) in [
        ("/query?take=0", 25, 20),
        ("/query?q=pkg", 25, 20),
        ("/query?take=1100", 1050, 1000),
        ("/query?take=abc", 25, 20),
    ] {
        let v = json_of(&with_hits(n).get(target));
        assert_eq!(v["totalHits"], n, "{target}");
        assert_eq!(v["data"].as_array().unwrap().len(), expected, "{target}");
    }
}

#[test]
fn search_skip_take_page_window() {
    let v = json_of(&with_hits(10).get("/query?skip=3&take=4"));
    assert_eq!(v["totalHits"], 10);
    let data = v["data"].as_array().unwrap();
    assert_eq!(data.len(), 4);
    assert_eq!(data[0]["id"], "Pkg.0003");
    assert_eq!(data[3]["id"], "Pkg.0006");
}

#[test]
fn search_hides_semver2_versions_unless_semver_level_2() {
    let mock = MockRepo {
        hits: vec![
            hit("Only.Dotted", &[("1.0.0-beta.1", "1.0.0-beta.1")]),
            hit("Plain.One", &[("1.0.0", "1.0.0")]),
            hit("Only.Metadata", &[("2.0.0", "2.0.0+build.5")]),
            hit(
                "Sample.Lib",
                &[("1.0.0", "1.0.0"), ("2.0.0-beta.1", "2.0.0-beta.1")],
            ),
            hit("Plain.Two", &[("1.0.0", "1.0.0")]),
        ],
        ..MockRepo::default()
    };
    let ids = |v: &Value| -> Vec<String> {
        v["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap().to_string())
            .collect()
    };

    let legacy = json_of(&mock.get("/query?prerelease=true&take=2"));
    assert_eq!(legacy["totalHits"], 3);
    assert_eq!(ids(&legacy), ["Plain.One", "Sample.Lib"], "a full page");
    assert_eq!(legacy["data"][1]["version"], "1.0.0");
    assert_eq!(legacy["data"][1]["versions"].as_array().unwrap().len(), 1);

    let legacy = json_of(&mock.get("/query?prerelease=true&skip=2&take=2"));
    assert_eq!(legacy["totalHits"], 3);
    assert_eq!(ids(&legacy), ["Plain.Two"]);

    let modern = json_of(&mock.get("/query?prerelease=true&skip=2&take=2&semVerLevel=2.0.0"));
    assert_eq!(modern["totalHits"], 5);
    assert_eq!(ids(&modern), ["Only.Metadata", "Sample.Lib"]);
    assert_eq!(modern["data"][1]["version"], "2.0.0-beta.1");
    assert_eq!(modern["data"][1]["versions"].as_array().unwrap().len(), 2);
}

#[test]
fn search_hits_carry_manifest_metadata_and_downloads() {
    let mut sample = hit("Sample.Lib", &[("1.0.0", "1.0.0")]);
    sample.summary = Nuget::default().manifest_summary(&nuspec_with_metadata());
    sample.total_downloads = Some(42);
    let mock = MockRepo {
        hits: vec![sample],
        ..MockRepo::default()
    };
    let hit = json_of(&mock.get("/query?q=sample"))["data"][0].clone();
    assert_eq!(hit["description"], "A sample & more");
    assert_eq!(hit["authors"], json!(["Alice", "Bob"]));
    assert_eq!(hit["tags"], json!(["json", "serializer"]));
    assert_eq!(hit["licenseUrl"], "https://licenses.nuget.org/MIT");
    assert_eq!(hit["projectUrl"], "https://example.com/p");
    assert_eq!(hit["totalDownloads"], 42);
    assert_eq!(
        hit["registration"],
        "https://forge.example.com/repository/main/registration/sample.lib/index.json"
    );
}

#[test]
fn search_supports_head() {
    let served = with_search().serve(
        RepositoryKind::Hosted,
        &Request::new("HEAD", "/query?q=sample"),
    );
    assert_eq!(served.response().status, 200);
}

// ── PackagePublish ───────────────────────────────────────────────────────────

#[test]
fn push_publishes_the_first_multipart_part() {
    for target in ["/package", "/package/"] {
        let served =
            MockRepo::default().serve(RepositoryKind::Hosted, &Request::new("PUT", target));
        let Action::Publish(publish) = &served.outcome else {
            panic!("{target}: {:?}", served.outcome);
        };
        assert_eq!(publish.upload, Upload::FirstPart);
        // Create and redeploy both answer 201, without a body.
        assert_eq!(publish.done.status, 201);
        assert!(publish.done.body.is_empty());
    }
    let served =
        MockRepo::default().serve(RepositoryKind::Hosted, &Request::new("POST", "/package"));
    assert_eq!(served.response().status, 405);
    assert_eq!(served.header("allow"), Some("PUT"));
}

#[test]
fn unlist_and_relist_are_changes_of_the_version() {
    let served = MockRepo::default().serve(
        RepositoryKind::Hosted,
        &Request::new("DELETE", "/package/Sample.Lib/1.0.0"),
    );
    let Action::Unlist(change) = &served.outcome else {
        panic!("{:?}", served.outcome);
    };
    assert_eq!(
        (change.target.id.as_str(), change.target.version.as_str()),
        ("Sample.Lib", "1.0.0")
    );
    assert_eq!(change.done.status, 204);

    let served = MockRepo::default().serve(
        RepositoryKind::Hosted,
        &Request::new("POST", "/package/Sample.Lib/1.0.0"),
    );
    let Action::Relist(change) = &served.outcome else {
        panic!("{:?}", served.outcome);
    };
    assert_eq!(change.done.status, 200);

    let served = MockRepo::default().serve(
        RepositoryKind::Hosted,
        &Request::new("GET", "/package/Sample.Lib/1.0.0"),
    );
    assert_eq!(served.response().status, 405);
    assert_eq!(served.header("allow"), Some("DELETE,POST"));
}

#[test]
fn publish_routes_are_for_hosted_repositories_only() {
    for kind in [RepositoryKind::Proxy, RepositoryKind::Group] {
        for (method, target) in [
            ("PUT", "/package"),
            ("DELETE", "/package/Sample.Lib/1.0.0"),
            ("POST", "/package/Sample.Lib/1.0.0"),
        ] {
            let served = MockRepo::default().serve(kind, &Request::new(method, target));
            assert_eq!(served.response().status, 404, "{kind:?} {method} {target}");
        }
    }
}
