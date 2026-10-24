//! The npm registry protocol as the plugin speaks it, driven through
//! `forge_plugin_api::testing::serve` against an in-memory repository: the
//! packuments (abbreviated for installs, full with publish times and the
//! README), the host actions it asks for (downloads, publishes, changes,
//! logins, forwards), the bodies it reads first, and its errors. What the
//! host does with those actions is tested with the server
//! (`crates/server/tests/npm.rs`).

use std::collections::HashMap;

use forge_format_npm::Npm;
use forge_plugin_api::testing::{serve, serve_with_body, Served};
use forge_plugin_api::{
    Action, Answer, AuthOutcome, AuthRequest, BodyUse, Change, FormatPlugin, PackageInfo,
    PackageRef, Query, Repository, RepositoryKind, Request, SearchHit, SearchResult, Tag, Upload,
    VersionInfo,
};
use serde_json::{json, Value};

const BASE: &str = "https://forge.example.com/repository/main";
const ABBREVIATED: &str =
    "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

fn repo(kind: RepositoryKind) -> Repository {
    Repository {
        name: "main".into(),
        kind,
        base_url: BASE.into(),
        inline: false,
        reserved_prefixes: Vec::new(),
    }
}

fn hosted() -> Repository {
    repo(RepositoryKind::Hosted)
}

/// An in-memory repository answering the plugin's queries as the host does.
#[derive(Default, Clone)]
struct MockRepo {
    packages: HashMap<String, Vec<PackageInfo>>,
    tags: HashMap<String, Vec<Tag>>,
    manifests: HashMap<(String, String), Vec<u8>>,
    hits: Vec<SearchHit>,
}

impl MockRepo {
    /// `name` with `versions` (ascending, with their publish times) and
    /// `tags`; every version's manifest has a README.
    fn with(mut self, name: &str, versions: &[(&str, &str)], tags: &[(&str, &str)]) -> Self {
        let infos = versions
            .iter()
            .map(|(version, published)| {
                let manifest = json!({
                    "name": name,
                    "version": version,
                    "description": format!("{name} {version}"),
                    "readme": format!("# {name} {version}"),
                    "dependencies": {"left-pad": "^1.0.0"},
                    "devDependencies": {"jest": "^29.0.0"},
                    "scripts": {"test": "jest"},
                    "dist": {"integrity": format!("sha512-{version}"), "shasum": "ab12"},
                });
                let bytes = serde_json::to_vec(&manifest).unwrap();
                self.manifests
                    .insert((name.to_string(), version.to_string()), bytes.clone());
                PackageInfo {
                    original_id: name.into(),
                    version: (*version).into(),
                    version_original: (*version).into(),
                    listed: true,
                    published: Some((*published).into()),
                    sha256: None,
                    sha512: None,
                    size: Some(1234),
                    summary: Npm::default().manifest_summary(&bytes),
                    deprecated: None,
                }
            })
            .collect();
        self.packages.insert(name.into(), infos);
        self.tags.insert(
            name.into(),
            tags.iter()
                .map(|(tag, version)| Tag {
                    name: (*tag).into(),
                    version: (*version).into(),
                })
                .collect(),
        );
        self
    }

    fn answer(&self, query: &Query) -> Answer {
        match query {
            Query::Packages(id) | Query::DatedPackages(id) => {
                Answer::Packages(self.packages.get(id).cloned().unwrap_or_default())
            }
            Query::Versions(id) => Answer::Versions(
                self.packages
                    .get(id)
                    .into_iter()
                    .flatten()
                    .map(|p| VersionInfo {
                        original_id: p.original_id.clone(),
                        version: p.version.clone(),
                        version_original: p.version_original.clone(),
                        listed: p.listed,
                    })
                    .collect(),
            ),
            Query::Tags(id) => Answer::Tags(self.tags.get(id).cloned().unwrap_or_default()),
            Query::Manifest(target) => Answer::Manifest(
                self.manifests
                    .get(&(target.id.clone(), target.version.clone()))
                    .cloned(),
            ),
            Query::Search(_) => Answer::Search(SearchResult {
                total: self.hits.len() as u32,
                hits: self.hits.clone(),
            }),
            other => panic!("unexpected query {other:?}"),
        }
    }

    fn serve(&self, req: &Request) -> Served {
        serve(&Npm::default(), &hosted(), req, |q| self.answer(q))
    }

    fn serve_with_body(&self, req: &Request, body: &[u8]) -> Served {
        serve_with_body(&Npm::default(), &hosted(), req, body, |q| self.answer(q))
    }
}

fn get(path: &str) -> Request {
    Request::new("GET", path)
}

fn json_of(served: &Served) -> Value {
    serde_json::from_slice(&served.response().body).expect("a JSON body")
}

fn sample() -> MockRepo {
    MockRepo::default().with(
        "@acme/ui",
        &[
            ("1.0.0", "2026-01-01T00:00:00.000+00:00"),
            ("1.1.0-beta.1", "2026-02-01T00:00:00.000+00:00"),
            ("2.0.0", "2026-03-01T00:00:00.000+00:00"),
        ],
        &[("latest", "2.0.0"), ("next", "1.1.0-beta.1")],
    )
}

#[test]
fn ping_answers_without_loading_anything() {
    let served = MockRepo::default().serve(&get("/-/ping"));
    assert_eq!(served.response().status, 200);
    assert_eq!(json_of(&served), json!({}));
    assert!(served.queries.is_empty());
}

#[test]
fn installs_read_the_abbreviated_packument() {
    let served = sample().serve(&get("/@acme%2fui").with_header("accept", ABBREVIATED));
    // No publish times, no manifest: what an install needs only.
    assert_eq!(
        served.queries,
        [
            Query::Packages("@acme/ui".into()),
            Query::Tags("@acme/ui".into())
        ]
    );
    assert_eq!(
        served.header("content-type"),
        Some("application/vnd.npm.install-v1+json")
    );
    assert_eq!(served.header("vary"), Some("Accept"));
    let doc = json_of(&served);
    assert_eq!(doc["name"], "@acme/ui");
    assert_eq!(doc["modified"], "2026-03-01T00:00:00.000Z");
    assert_eq!(
        doc["dist-tags"],
        json!({"latest": "2.0.0", "next": "1.1.0-beta.1"})
    );
    let v = &doc["versions"]["2.0.0"];
    assert_eq!(
        v["dist"]["tarball"],
        format!("{BASE}/@acme/ui/-/ui-2.0.0.tgz")
    );
    assert_eq!(v["dist"]["integrity"], "sha512-2.0.0");
    assert_eq!(v["dependencies"], json!({"left-pad": "^1.0.0"}));
    assert_eq!(v["devDependencies"], json!({"jest": "^29.0.0"}));
    // Fields installs do not read are left out.
    assert!(
        v.get("description").is_none() && v.get("scripts").is_none(),
        "{v}"
    );
    assert!(doc.get("time").is_none() && doc.get("readme").is_none());
}

#[test]
fn the_full_packument_has_publish_times_and_the_readme_of_latest() {
    let served = sample().serve(&get("/@acme%2Fui").with_header("accept", "application/json"));
    assert_eq!(
        served.queries,
        [
            Query::DatedPackages("@acme/ui".into()),
            Query::Tags("@acme/ui".into()),
            Query::Manifest(PackageRef {
                id: "@acme/ui".into(),
                version: "2.0.0".into(),
            }),
        ]
    );
    assert_eq!(served.header("content-type"), Some("application/json"));
    let doc = json_of(&served);
    assert_eq!(doc["readme"], "# @acme/ui 2.0.0");
    assert_eq!(doc["time"]["created"], "2026-01-01T00:00:00.000Z");
    assert_eq!(doc["time"]["2.0.0"], "2026-03-01T00:00:00.000Z");
    let v = &doc["versions"]["1.0.0"];
    assert_eq!(v["description"], "@acme/ui 1.0.0");
    assert!(
        v.get("readme").is_none(),
        "only the package has a README: {v}"
    );
    // An Accept that refuses the abbreviated document gets the full one.
    let refused = sample().serve(&get("/@acme%2fui").with_header(
        "accept",
        "application/vnd.npm.install-v1+json; q=0, application/json",
    ));
    assert!(json_of(&refused).get("time").is_some());
}

#[test]
fn tags_point_at_the_latest_version_when_none_is_set() {
    let repo = MockRepo::default().with(
        "plain",
        &[
            ("0.9.0", "2026-01-01T00:00:00.000Z"),
            ("1.0.0", "2026-01-02T00:00:00.000Z"),
        ],
        &[],
    );
    let served = repo.serve(&get("/-/package/plain/dist-tags"));
    assert_eq!(json_of(&served), json!({"latest": "1.0.0"}));
}

#[test]
fn versions_resolve_by_tag_or_by_version() {
    let repo = sample();
    let by_tag = repo.serve(&get("/@acme%2fui/next"));
    assert_eq!(json_of(&by_tag)["version"], "1.1.0-beta.1");
    let by_version = repo.serve(&get("/@acme%2fui/1.0.0"));
    assert_eq!(json_of(&by_version)["version"], "1.0.0");
    let missing = repo.serve(&get("/@acme%2fui/9.9.9"));
    assert_eq!(missing.response().status, 404);
}

#[test]
fn an_unknown_package_is_a_404_npm_reads() {
    let served = MockRepo::default().serve(&get("/nope"));
    assert_eq!(served.response().status, 404);
    assert!(json_of(&served)["error"].as_str().unwrap().contains("nope"));
    // So is a path that names no package, before anything is loaded.
    let served = MockRepo::default().serve(&get("/a/b/c/d"));
    assert_eq!(served.response().status, 404);
    assert!(served.queries.is_empty());
}

#[test]
fn host_errors_are_rendered_as_npm_reads_them() {
    let response = Npm::default()
        .error_response(409, "package left-pad 1.0.0 already exists")
        .unwrap();
    assert_eq!(response.status, 409);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        body,
        json!({"error": "package left-pad 1.0.0 already exists"})
    );
}

#[test]
fn tarballs_are_downloads() {
    let served = MockRepo::default().serve(&get("/@acme%2fui/-/ui-2.0.0.tgz"));
    assert_eq!(
        served.outcome,
        Action::Download(PackageRef {
            id: "@acme/ui".into(),
            version: "2.0.0".into(),
        })
    );
    // A file of another package is not one.
    let served = MockRepo::default().serve(&get("/@acme%2fui/-/other-2.0.0.tgz"));
    assert_eq!(served.response().status, 404);
}

#[test]
fn a_publish_streams_its_document_to_the_host() {
    let served = MockRepo::default().serve(&Request::new("PUT", "/@acme%2fui"));
    let Action::Publish(publish) = served.outcome else {
        panic!("expected a publish, got {:?}", served.outcome);
    };
    assert_eq!(publish.upload, Upload::Document);
    assert_eq!(publish.id.as_deref(), Some("@acme/ui"));
    assert_eq!(publish.done.status, 201);
}

#[test]
fn dist_tags_are_set_with_a_body_and_removed_without() {
    let repo = sample();
    let put = Request::new("PUT", "/-/package/@acme%2fui/dist-tags/stable");
    let Action::ReadBody(wanted) = repo.serve(&put).outcome else {
        panic!("a dist-tag's version comes in the body");
    };
    assert_eq!(wanted.used_for, BodyUse::Change);
    let served = repo.serve_with_body(&put, b"\"1.0.0\"");
    let Action::Change(set) = served.outcome else {
        panic!("expected a change, got {:?}", served.outcome);
    };
    assert_eq!(
        set.changes,
        [Change::Tag {
            id: "@acme/ui".into(),
            tag: "stable".into(),
            version: "1.0.0".into(),
        }]
    );
    assert_eq!(set.done.status, 201);

    let served = repo.serve(&Request::new(
        "DELETE",
        "/-/package/@acme%2fui/dist-tags/next",
    ));
    let Action::Change(set) = served.outcome else {
        panic!("expected a change");
    };
    assert_eq!(
        set.changes,
        [Change::Untag {
            id: "@acme/ui".into(),
            tag: "next".into(),
        }]
    );
    // `latest` always names a version.
    let served = repo.serve(&Request::new(
        "DELETE",
        "/-/package/@acme%2fui/dist-tags/latest",
    ));
    assert_eq!(served.response().status, 400);
    // A tag that looks like a version would shadow it.
    let served = repo.serve(&Request::new("PUT", "/-/package/@acme%2fui/dist-tags/1.0"));
    assert_eq!(served.response().status, 400);
}

/// The packument `npm deprecate` and `npm unpublish <version>` send back.
fn updated(versions: &[(&str, Option<&str>)], tags: Value) -> Vec<u8> {
    let versions: serde_json::Map<String, Value> = versions
        .iter()
        .map(|(v, deprecated)| {
            let mut doc = json!({"name": "@acme/ui", "version": v});
            if let Some(message) = deprecated {
                doc["deprecated"] = json!(message);
            }
            (v.to_string(), doc)
        })
        .collect();
    serde_json::to_vec(&json!({
        "_id": "@acme/ui",
        "_rev": "3-abc",
        "name": "@acme/ui",
        "dist-tags": tags,
        "versions": versions,
    }))
    .unwrap()
}

#[test]
fn a_packument_update_deprecates_unpublishes_and_retags() {
    let repo = sample();
    let put = Request::new("PUT", "/@acme%2fui/-rev/3-abc");
    let Action::ReadBody(wanted) = repo.serve(&put).outcome else {
        panic!("an update comes in the body");
    };
    assert_eq!(wanted.used_for, BodyUse::Change);

    // 1.1.0-beta.1 is left out (unpublished; its `next` tag goes with it),
    // 1.0.0 deprecated, and `stable` added.
    let body = updated(
        &[("1.0.0", Some("use 2")), ("2.0.0", None)],
        json!({"latest": "2.0.0", "stable": "1.0.0"}),
    );
    let served = repo.serve_with_body(&put, &body);
    let Action::Change(set) = served.outcome else {
        panic!("expected changes, got {:?}", served.outcome);
    };
    let target = |v: &str| PackageRef {
        id: "@acme/ui".into(),
        version: v.into(),
    };
    assert_eq!(
        set.changes,
        [
            Change::Delete(target("1.1.0-beta.1")),
            Change::Deprecate {
                target: target("1.0.0"),
                message: Some("use 2".into()),
            },
            Change::Tag {
                id: "@acme/ui".into(),
                tag: "stable".into(),
                version: "1.0.0".into(),
            },
        ]
    );

    // A document that leaves no version is refused: that is an unpublish
    // of the package.
    let body = updated(&[], json!({}));
    assert_eq!(repo.serve_with_body(&put, &body).response().status, 400);
    // Nothing changed: nothing to do.
    let body = updated(
        &[("1.0.0", None), ("1.1.0-beta.1", None), ("2.0.0", None)],
        json!({"latest": "2.0.0", "next": "1.1.0-beta.1"}),
    );
    assert_eq!(repo.serve_with_body(&put, &body).response().status, 200);
}

#[test]
fn unpublishing_a_package_deletes_every_version() {
    let served = sample().serve(&Request::new("DELETE", "/@acme%2fui/-rev/3-abc"));
    let Action::Change(set) = served.outcome else {
        panic!("expected changes, got {:?}", served.outcome);
    };
    assert_eq!(set.changes.len(), 3);
    assert!(set.changes.iter().all(|c| matches!(c, Change::Delete(_))));
}

#[test]
fn logins_are_the_hosts() {
    let npm = Npm::default();
    let repo = MockRepo::default();
    // Legacy: `npm login --auth-type=legacy`, `yarn npm login`.
    let put = Request::new("PUT", "/-/user/org.couchdb.user:jane@example.com");
    let Action::ReadBody(wanted) = repo.serve(&put).outcome else {
        panic!("a login comes in the body");
    };
    assert_eq!(wanted.used_for, BodyUse::Login);
    let served = repo.serve_with_body(
        &put,
        br#"{"name": "jane@example.com", "password": "secret", "type": "user"}"#,
    );
    assert_eq!(
        served.outcome,
        Action::Auth(AuthRequest::Password {
            username: "jane@example.com".into(),
            password: "secret".into(),
        })
    );
    let minted = npm.auth_response(
        &hosted(),
        &put,
        &AuthOutcome::Token {
            token: "t0k3n".into(),
            username: "jane@example.com".into(),
        },
    );
    assert_eq!(minted.status, 201);
    let body: Value = serde_json::from_slice(&minted.body).unwrap();
    assert_eq!(body["token"], "t0k3n");
    assert_eq!(body["ok"], true);

    // Web: `npm login` opens the login URL and polls the done URL.
    let start = Request::new("POST", "/-/v1/login");
    let served = repo.serve_with_body(&start, br#"{"hostname": "laptop"}"#);
    assert_eq!(
        served.outcome,
        Action::Auth(AuthRequest::StartWebLogin {
            hostname: Some("laptop".into()),
        })
    );
    let started = npm.auth_response(
        &hosted(),
        &start,
        &AuthOutcome::WebLoginStarted {
            login_url: "https://forge.example.com/cli-login/abc".into(),
            secret: "def".into(),
        },
    );
    let body: Value = serde_json::from_slice(&started.body).unwrap();
    assert_eq!(body["loginUrl"], "https://forge.example.com/cli-login/abc");
    assert_eq!(body["doneUrl"], format!("{BASE}/-/v1/login/done/def"));
    let done = get("/-/v1/login/done/def");
    assert_eq!(
        repo.serve(&done).outcome,
        Action::Auth(AuthRequest::PollWebLogin {
            secret: "def".into(),
        })
    );
    let pending = npm.auth_response(&hosted(), &done, &AuthOutcome::WebLoginPending);
    assert_eq!(pending.status, 202);
    assert!(pending
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("retry-after")));

    assert_eq!(
        repo.serve(&get("/-/whoami")).outcome,
        Action::Auth(AuthRequest::Whoami)
    );
    assert_eq!(
        repo.serve(&Request::new("DELETE", "/-/user/token/t0k3n"))
            .outcome,
        Action::Auth(AuthRequest::Logout {
            token: "t0k3n".into(),
        })
    );
}

#[test]
fn search_renders_what_npm_search_prints() {
    let mut repo = MockRepo::default();
    let summary = Npm::default().manifest_summary(
        br#"{"name": "left-pad", "version": "1.3.0", "description": "String left pad", "keywords": ["pad"]}"#,
    );
    repo.hits.push(SearchHit {
        original_id: "left-pad".into(),
        latest_version: "1.3.0".into(),
        versions: Vec::new(),
        summary,
        total_downloads: None,
    });
    let served = repo.serve(&get("/-/v1/search?text=pad&size=5&from=10"));
    let [Query::Search(search)] = served.queries.as_slice() else {
        panic!("expected one search, got {:?}", served.queries);
    };
    assert_eq!(
        (search.text.as_str(), search.take, search.skip),
        ("pad", 5, 10)
    );
    let doc = json_of(&served);
    assert_eq!(doc["total"], 1);
    let package = &doc["objects"][0]["package"];
    assert_eq!(package["name"], "left-pad");
    assert_eq!(package["version"], "1.3.0");
    assert_eq!(package["description"], "String left pad");
}

#[test]
fn audits_go_upstream_without_internal_names() {
    let mut group = repo(RepositoryKind::Group);
    group.reserved_prefixes = vec!["@acme/".into()];
    let req = Request::new("POST", "/-/npm/v1/security/advisories/bulk");
    let body = br#"{"@acme/ui": ["1.0.0"], "left-pad": ["1.3.0"]}"#;
    let served = serve_with_body(&Npm::default(), &group, &req, body, |q| {
        panic!("unexpected query {q:?}")
    });
    let Action::Forward(forward) = served.outcome else {
        panic!("expected a forward, got {:?}", served.outcome);
    };
    assert_eq!(forward.path, "/-/npm/v1/security/advisories/bulk");
    let sent: Value = serde_json::from_slice(&forward.body).unwrap();
    assert_eq!(sent, json!({"left-pad": ["1.3.0"]}));
    // Other audit endpoints are not forwarded.
    let served = MockRepo::default().serve(&Request::new("POST", "/-/npm/v1/security/anything"));
    assert_eq!(served.response().status, 404);
}
