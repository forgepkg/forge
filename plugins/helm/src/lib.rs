//! Helm chart repositories for Forge.
//!
//! Served under a Forge repository's base URL:
//!
//! * `GET /index.yaml` — the repository index (`helm repo add`, `helm repo
//!   update`); every chart and version the caller may read;
//! * `GET /charts/{name}/{version}/{name}-{version}.tgz` — a chart (the URL
//!   the index points at);
//! * `POST /api/charts` — upload a chart, as the request body
//!   (`curl --data-binary @chart.tgz`) or as the multipart field `chart`
//!   (`helm cm-push`);
//! * `DELETE /api/charts/{name}/{version}` — delete a version;
//! * `GET /api/charts`, `/api/charts/{name}`, `/api/charts/{name}/{version}`
//!   — the ChartMuseum JSON listing.
//!
//! Chart names are matched case-insensitively (the canonical id is the
//! lowercased name); versions are SemVer, normalized (`v1.2` → `1.2.0`).

mod chart;
mod semver;
mod tar;

use std::collections::BTreeMap;
use std::io::{self, Read};

use serde_json::{json, Map, Value};

wit_bindgen::generate!({
    world: "format-plugin",
    path: "../../crates/plugin/wit",
});

use exports::forge::format::format::{Guest as FormatGuest, ParsedPackage};
use exports::forge::format::protocol::{
    Action, Answer, ChangeRequest, Guest as ProtocolGuest, Loaded, PackageInfo, PackageRef,
    PublishRequest, Query, Rendered, Repository, Request, Response, SearchQuery, Upload,
};
use forge::format::package_source::PackageReader;
use forge::format::types::{Dependency, DependencyGroup, FormatError};
use semver::Version;

/// Searches page through the repository this many charts at a time.
const PAGE: u32 = 1000;

/// The Chart.yaml keys an index entry carries (Helm's chart metadata).
const METADATA_KEYS: &[&str] = &[
    "apiVersion",
    "name",
    "version",
    "kubeVersion",
    "description",
    "type",
    "keywords",
    "home",
    "sources",
    "dependencies",
    "maintainers",
    "icon",
    "appVersion",
    "deprecated",
    "annotations",
    "condition",
    "tags",
];

struct Helm;

export!(Helm);

/// A package reader as [`Read`].
struct Source<'a> {
    reader: &'a PackageReader,
    offset: u64,
}

impl Read for Source<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let chunk = self
            .reader
            .read_at(self.offset, len)
            .map_err(io::Error::other)?;
        buf[..chunk.len()].copy_from_slice(&chunk);
        self.offset += chunk.len() as u64;
        Ok(chunk.len())
    }
}

impl FormatGuest for Helm {
    fn canonical_id(id: String) -> String {
        id.to_ascii_lowercase()
    }

    fn validate_id(id: String) -> Result<(), FormatError> {
        if chart::valid_name(&id) {
            Ok(())
        } else {
            Err(FormatError::InvalidId(format!("invalid chart name {id:?}")))
        }
    }

    fn normalize_version(version: String) -> Result<String, FormatError> {
        Version::parse(&version)
            .map(|v| v.to_string())
            .map_err(FormatError::InvalidVersion)
    }

    fn compare_versions(a: String, b: String) -> i8 {
        let order = match (Version::parse(&a), Version::parse(&b)) {
            (Ok(a), Ok(b)) => a.cmp(&b),
            _ => a.cmp(&b),
        };
        order as i8
    }

    fn parse_package(source: &PackageReader) -> Result<ParsedPackage, FormatError> {
        let chart = chart::read(Source {
            reader: source,
            offset: 0,
        })
        .map_err(FormatError::InvalidPackage)?;
        let dependencies = dependencies(&chart.metadata);
        Ok(ParsedPackage {
            id: chart.name.to_ascii_lowercase(),
            original_id: chart.name,
            version: chart.normalized.to_string(),
            version_original: chart.version,
            listed: true,
            manifest: chart.chart_yaml,
            dependencies: if dependencies.is_empty() {
                Vec::new()
            } else {
                vec![DependencyGroup {
                    target: None,
                    dependencies,
                }]
            },
        })
    }

    fn manifest_summary(manifest: Vec<u8>) -> Option<String> {
        let chart = chart::parse_chart_yaml(manifest).ok()?;
        let metadata: Map<String, Value> = chart
            .metadata
            .iter()
            .filter(|(k, _)| METADATA_KEYS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let deps: Vec<Value> = dependencies(&chart.metadata)
            .into_iter()
            .map(|d| json!({ "id": d.id, "range": d.range }))
            .collect();
        // `description` and `dependency_groups` are what Forge's web UI shows.
        let summary = json!({
            "chart": metadata,
            "description": chart.metadata.get("description").cloned().unwrap_or(Value::Null),
            "dependency_groups": if deps.is_empty() {
                json!([])
            } else {
                json!([{ "target_framework": null, "dependencies": deps }])
            },
        });
        Some(summary.to_string())
    }
}

/// Chart.yaml `dependencies` as Forge dependencies.
fn dependencies(metadata: &Map<String, Value>) -> Vec<Dependency> {
    let Some(Value::Array(deps)) = metadata.get("dependencies") else {
        return Vec::new();
    };
    deps.iter()
        .filter_map(|d| {
            let name = d.get("name")?.as_str()?;
            Some(Dependency {
                id: name.to_string(),
                range: d.get("version").and_then(Value::as_str).map(str::to_string),
            })
        })
        .collect()
}

fn respond(status: u16, content_type: &str, body: Vec<u8>) -> Response {
    Response {
        status,
        headers: vec![("content-type".into(), content_type.into())],
        body,
    }
}

fn json_response(status: u16, value: &Value) -> Response {
    respond(status, "application/json", value.to_string().into_bytes())
}

fn not_found() -> Response {
    json_response(404, &json!({ "error": "not found" }))
}

/// Percent-decode one path segment.
fn decode(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = segment.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `(canonical id, normalized version)` of a name and version from a URL.
fn package_ref(name: &str, version: &str) -> Option<PackageRef> {
    let name = decode(name)?;
    let version = Version::parse(&decode(version)?).ok()?;
    chart::valid_name(&name).then(|| PackageRef {
        id: name.to_ascii_lowercase(),
        version: version.to_string(),
    })
}

fn search_page(skip: u32) -> Query {
    Query::Search(SearchQuery {
        text: String::new(),
        skip,
        take: PAGE,
        prerelease: true,
    })
}

impl ProtocolGuest for Helm {
    fn handle(_repo: Repository, req: Request) -> Action {
        let read = matches!(req.method.as_str(), "GET" | "HEAD");
        let segments: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
        match (req.method.as_str(), segments.as_slice()) {
            (_, ["index.yaml"]) if read => Action::Load(vec![search_page(0)]),
            (_, ["charts", name, version, file]) if read => match package_ref(name, version) {
                Some(target) if file.ends_with(".tgz") => Action::Download(target),
                _ => Action::Respond(not_found()),
            },
            (_, ["api", "charts"]) if read => Action::Load(vec![search_page(0)]),
            (_, ["api", "charts", name]) if read => match decode(name) {
                Some(name) if chart::valid_name(&name) => {
                    Action::Load(vec![Query::Packages(name.to_ascii_lowercase())])
                }
                _ => Action::Respond(not_found()),
            },
            (_, ["api", "charts", name, version]) if read => match package_ref(name, version) {
                Some(target) => Action::Load(vec![Query::Package(target)]),
                None => Action::Respond(not_found()),
            },
            ("POST", ["api", "charts"]) => {
                let multipart = req.headers.iter().any(|(k, v)| {
                    k == "content-type" && v.to_ascii_lowercase().starts_with("multipart/form-data")
                });
                Action::Publish(PublishRequest {
                    upload: if multipart {
                        Upload::MultipartField("chart".into())
                    } else {
                        Upload::Body
                    },
                    done: json_response(201, &json!({ "saved": true })),
                })
            }
            ("DELETE", ["api", "charts", name, version]) => match package_ref(name, version) {
                Some(target) => Action::Delete(ChangeRequest {
                    target,
                    done: json_response(200, &json!({ "deleted": true })),
                }),
                None => Action::Respond(not_found()),
            },
            _ => Action::Respond(not_found()),
        }
    }

    fn render(repo: Repository, req: Request, data: Vec<Loaded>) -> Rendered {
        let segments: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
        match segments.as_slice() {
            ["index.yaml"] | ["api", "charts"] => render_listing(&repo, &segments, &data),
            ["api", "charts", _] => match data.first().map(|l| &l.answer) {
                Some(Answer::Packages(versions)) if !versions.is_empty() => {
                    let mut versions: Vec<&PackageInfo> = versions.iter().collect();
                    newest_first(&mut versions);
                    let entries: Vec<Value> =
                        versions.into_iter().map(|p| entry(&repo, p)).collect();
                    Rendered::Respond(json_response(200, &Value::Array(entries)))
                }
                _ => Rendered::Respond(not_found()),
            },
            ["api", "charts", _, _] => match data.first().map(|l| &l.answer) {
                Some(Answer::Package(Some(p))) => {
                    Rendered::Respond(json_response(200, &entry(&repo, p)))
                }
                _ => Rendered::Respond(not_found()),
            },
            _ => Rendered::Respond(not_found()),
        }
    }
}

/// The index (`/index.yaml`) or the ChartMuseum listing (`/api/charts`):
/// page through the search, then load every chart's versions, then render.
fn render_listing(repo: &Repository, segments: &[&str], data: &[Loaded]) -> Rendered {
    let mut total = 0u32;
    let mut pages = 0u32;
    let mut ids: Vec<String> = Vec::new();
    let mut charts: Vec<Vec<&PackageInfo>> = Vec::new();
    for loaded in data {
        match (&loaded.query, &loaded.answer) {
            (Query::Search(_), Answer::Search(result)) => {
                total = total.max(result.total);
                pages += 1;
                ids.extend(
                    result
                        .hits
                        .iter()
                        .map(|h| h.original_id.to_ascii_lowercase()),
                );
            }
            // Unlisted versions stay downloadable but are not offered.
            (Query::Packages(_), Answer::Packages(versions)) => {
                let mut listed: Vec<&PackageInfo> = versions.iter().filter(|p| p.listed).collect();
                if !listed.is_empty() {
                    newest_first(&mut listed);
                    charts.push(listed);
                }
            }
            _ => {}
        }
    }
    // Search pages are all loaded in the second round, charts in the next.
    let loaded_charts = data.iter().any(|l| matches!(l.query, Query::Packages(_)));
    if !loaded_charts {
        if pages * PAGE < total && pages == 1 {
            let more = (1..total.div_ceil(PAGE))
                .map(|p| search_page(p * PAGE))
                .collect();
            return Rendered::Load(more);
        }
        if !ids.is_empty() {
            ids.sort();
            ids.dedup();
            return Rendered::Load(ids.into_iter().map(Query::Packages).collect());
        }
    }

    // A chart is listed under the name its newest version is published as
    // (names match case-insensitively).
    let mut by_name: BTreeMap<String, Vec<&PackageInfo>> = BTreeMap::new();
    for versions in charts {
        by_name
            .entry(versions[0].original_id.clone())
            .or_default()
            .extend(versions);
    }
    let mut entries = Map::new();
    let mut latest: Option<&str> = None;
    for (name, versions) in by_name {
        for p in &versions {
            if let Some(published) = p.published.as_deref() {
                if latest.is_none_or(|l| published > l) {
                    latest = Some(published);
                }
            }
        }
        let list: Vec<Value> = versions.into_iter().map(|p| entry(repo, p)).collect();
        entries.insert(name, Value::Array(list));
    }
    if segments == ["api", "charts"] {
        return Rendered::Respond(json_response(200, &Value::Object(entries)));
    }
    let mut index = Map::new();
    index.insert("apiVersion".into(), json!("v1"));
    index.insert("entries".into(), Value::Object(entries));
    if let Some(latest) = latest {
        index.insert("generated".into(), json!(latest));
    }
    // JSON is YAML; Helm reads either.
    Rendered::Respond(Response {
        status: 200,
        headers: vec![
            ("content-type".into(), "application/x-yaml".into()),
            ("cache-control".into(), "no-cache".into()),
        ],
        body: Value::Object(index).to_string().into_bytes(),
    })
}

fn newest_first(versions: &mut [&PackageInfo]) {
    versions.sort_by(
        |a, b| match (Version::parse(&a.version), Version::parse(&b.version)) {
            (Ok(a), Ok(b)) => b.cmp(&a),
            _ => b.version.cmp(&a.version),
        },
    );
}

/// One chart version as the index and the ChartMuseum API list it.
fn entry(repo: &Repository, p: &PackageInfo) -> Value {
    let mut chart = p
        .summary
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|s| s.get("chart").cloned())
        .and_then(|c| match c {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    chart.insert("name".into(), json!(p.original_id));
    chart.insert("version".into(), json!(p.version_original));
    let file = format!("{}-{}.tgz", p.original_id, p.version);
    chart.insert(
        "urls".into(),
        json!([format!(
            "{}/charts/{}/{}/{}",
            repo.base_url,
            p.original_id.to_ascii_lowercase(),
            p.version,
            file
        )]),
    );
    if let Some(published) = &p.published {
        chart.insert("created".into(), json!(published));
    }
    if let Some(sha256) = &p.sha256 {
        chart.insert("digest".into(), json!(sha256));
    }
    Value::Object(chart)
}
