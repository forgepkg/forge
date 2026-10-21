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
//!
//! A proxy repository mirrors another chart repository ([`upstream`]): its
//! index lists the upstream's charts, each downloaded and cached on first
//! use.
//!
//! Forge links this plugin in ([`Helm`], [`PLUGIN_TOML`]). With the
//! `component` feature the same crate builds as a WebAssembly component of
//! the `forge:format` world instead (`cargo xtask plugins`).

mod chart;
mod semver;
mod tar;
mod upstream;

use std::cmp::Ordering;
use std::collections::BTreeMap;

use forge_plugin_api::{
    Action, Answer, ChangeRequest, Dependency, DependencyGroup, FetchResult, FormatError,
    FormatPlugin, Loaded, PackageInfo, PackageRef, PackageSource, ParsedPackage, PublishRequest,
    Query, Remote, Rendered, Repository, RepositoryKind, Request, Response, SearchHit, SearchQuery,
    Upload, UpstreamOp, UpstreamStep,
};
use serde_json::{json, Map, Value};

use semver::Version;

/// This plugin's `plugin.toml`: its format id, name and version.
pub const PLUGIN_TOML: &str = forge_plugin_api::plugin_toml!();

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

/// The Helm chart format.
#[derive(Debug, Default, Clone, Copy)]
pub struct Helm;

#[cfg(feature = "component")]
forge_plugin_api::export_component!(Helm);

impl FormatPlugin for Helm {
    fn canonical_id(&self, id: &str) -> String {
        id.to_ascii_lowercase()
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        if chart::valid_name(id) {
            Ok(())
        } else {
            Err(FormatError::InvalidId(format!("invalid chart name {id:?}")))
        }
    }

    fn normalize_version(&self, version: &str) -> Result<String, FormatError> {
        Version::parse(version)
            .map(|v| v.to_string())
            .map_err(FormatError::InvalidVersion)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        match (Version::parse(a), Version::parse(b)) {
            (Ok(a), Ok(b)) => a.cmp(&b),
            _ => a.cmp(b),
        }
    }

    fn parse_package(&self, package: &mut dyn PackageSource) -> Result<ParsedPackage, FormatError> {
        let chart = chart::read(package).map_err(FormatError::InvalidPackage)?;
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

    fn manifest_summary(&self, manifest: &[u8]) -> Option<String> {
        let chart = chart::parse_chart_yaml(manifest.to_vec()).ok()?;
        Some(summary(&chart.metadata))
    }

    fn handle(&self, repo: &Repository, req: &Request) -> Action {
        let read = matches!(req.method.as_str(), "GET" | "HEAD");
        let segments: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
        match (req.method.as_str(), segments.as_slice()) {
            (_, ["index.yaml"]) if read => Action::Load(vec![search_page(repo, 0)]),
            (_, ["charts", name, version, file]) if read => match package_ref(name, version) {
                Some(target) if file.ends_with(".tgz") => Action::Download(target),
                _ => Action::Respond(not_found()),
            },
            (_, ["api", "charts"]) if read => Action::Load(vec![search_page(repo, 0)]),
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
                let multipart = req
                    .header("content-type")
                    .is_some_and(|v| v.to_ascii_lowercase().starts_with("multipart/form-data"));
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

    fn render(&self, repo: &Repository, req: &Request, data: &[Loaded]) -> Rendered {
        let segments: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
        match segments.as_slice() {
            ["index.yaml"] | ["api", "charts"] => render_listing(repo, &segments, data),
            ["api", "charts", _] => match data.first().map(|l| &l.answer) {
                Some(Answer::Packages(versions)) if !versions.is_empty() => {
                    let mut versions: Vec<&PackageInfo> = versions.iter().collect();
                    newest_first(&mut versions);
                    let entries: Vec<Value> =
                        versions.into_iter().map(|p| entry(repo, p)).collect();
                    Rendered::Respond(json_response(200, &Value::Array(entries)))
                }
                _ => Rendered::Respond(not_found()),
            },
            ["api", "charts", _, _] => match data.first().map(|l| &l.answer) {
                Some(Answer::Package(Some(p))) => {
                    Rendered::Respond(json_response(200, &entry(repo, p)))
                }
                _ => Rendered::Respond(not_found()),
            },
            _ => Rendered::Respond(not_found()),
        }
    }

    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        upstream::step(remote, op, fetched)
    }
}

/// The manifest summary of a chart's metadata (its Chart.yaml, or an index
/// entry): the chart metadata an index entry carries, and the description
/// and dependency groups Forge's web UI shows.
fn summary(metadata: &Map<String, Value>) -> String {
    let chart: Map<String, Value> = metadata
        .iter()
        .filter(|(k, _)| METADATA_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let deps: Vec<Value> = dependencies(metadata)
        .into_iter()
        .map(|d| json!({ "id": d.id, "range": d.range }))
        .collect();
    json!({
        "chart": chart,
        "description": metadata.get("description").cloned().unwrap_or(Value::Null),
        "dependency_groups": if deps.is_empty() {
            json!([])
        } else {
            json!([{ "target_framework": null, "dependencies": deps }])
        },
    })
    .to_string()
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

fn json_response(status: u16, value: &Value) -> Response {
    Response::new(status, "application/json", value.to_string())
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

/// A page of every chart of `repo`: a proxy's (and a group's proxies')
/// upstream charts included, not only the ones it has cached.
fn search_page(repo: &Repository, skip: u32) -> Query {
    Query::Search(SearchQuery {
        text: String::new(),
        skip,
        take: PAGE,
        prerelease: true,
        semver2: true,
        upstream: repo.kind != RepositoryKind::Hosted,
    })
}

/// The index (`/index.yaml`) or the ChartMuseum listing (`/api/charts`):
/// page through the search, then load every chart's versions, then render.
fn render_listing(repo: &Repository, segments: &[&str], data: &[Loaded]) -> Rendered {
    let mut total = 0u32;
    let mut pages = 0u32;
    let mut ids: Vec<String> = Vec::new();
    let mut hits: Vec<&SearchHit> = Vec::new();
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
                hits.extend(result.hits.iter());
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
                .map(|p| search_page(repo, p * PAGE))
                .collect();
            return Rendered::Load(more);
        }
        // A proxy's charts are its upstream's: the search lists each with
        // its versions and the newest one's metadata, so the index comes
        // from it rather than from reading the upstream once per chart.
        if repo.kind == RepositoryKind::Proxy {
            let mut entries = Map::new();
            for hit in hits {
                entries.insert(
                    hit.original_id.clone(),
                    Value::Array(hit_entries(repo, hit)),
                );
            }
            return render_index(segments, entries, None);
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
    render_index(segments, entries, latest)
}

/// The index (`/index.yaml`) or the ChartMuseum listing (`/api/charts`) of
/// `entries`, generated as of `latest`.
fn render_index(segments: &[&str], entries: Map<String, Value>, latest: Option<&str>) -> Rendered {
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
    Rendered::Respond(
        Response::new(200, "application/x-yaml", Value::Object(index).to_string())
            .with_header("cache-control", "no-cache"),
    )
}

/// The index entries of a chart a proxy's search found, newest first. The
/// newest version carries the chart's metadata; the others, which the
/// search does not describe, their name, version and URL.
fn hit_entries(repo: &Repository, hit: &SearchHit) -> Vec<Value> {
    let chart: Map<String, Value> = hit
        .summary
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|s| match s.get("chart") {
            Some(Value::Object(map)) => Some(map.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let mut versions: Vec<_> = hit.versions.iter().collect();
    versions.sort_by(
        |a, b| match (Version::parse(&a.version), Version::parse(&b.version)) {
            (Ok(a), Ok(b)) => b.cmp(&a),
            _ => b.version.cmp(&a.version),
        },
    );
    versions
        .into_iter()
        .map(|v| {
            let mut entry = if v.version == hit.latest_version {
                chart.clone()
            } else {
                chart
                    .get("apiVersion")
                    .map(|api| Map::from_iter([("apiVersion".to_string(), api.clone())]))
                    .unwrap_or_default()
            };
            entry.insert("name".into(), json!(hit.original_id));
            entry.insert("version".into(), json!(v.version_original));
            entry.insert(
                "urls".into(),
                json!([chart_url(repo, &hit.original_id, &v.version)]),
            );
            Value::Object(entry)
        })
        .collect()
}

/// Where a chart version is downloaded from this repository.
fn chart_url(repo: &Repository, name: &str, version: &str) -> String {
    format!(
        "{}/charts/{}/{version}/{name}-{version}.tgz",
        repo.base_url,
        name.to_ascii_lowercase(),
    )
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
    chart.insert(
        "urls".into(),
        json!([chart_url(repo, &p.original_id, &p.version)]),
    );
    if let Some(published) = &p.published {
        chart.insert("created".into(), json!(published));
    }
    if let Some(sha256) = &p.sha256 {
        chart.insert("digest".into(), json!(sha256));
    }
    Value::Object(chart)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_toml_names_this_crate() {
        let value = |key: &str| {
            PLUGIN_TOML
                .lines()
                .filter_map(|line| line.split_once('='))
                .find(|(k, _)| k.trim() == key)
                .map(|(_, v)| v.trim().trim_matches('"').to_string())
        };
        assert_eq!(value("id").as_deref(), Some("helm"));
        assert_eq!(value("version").as_deref(), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(value("api").as_deref(), Some(forge_plugin_api::API));
        assert_eq!(
            value("component"),
            Some(format!("{}.wasm", env!("CARGO_CRATE_NAME")))
        );
    }
}
