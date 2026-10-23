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
//! lowercased name); versions are SemVer, normalized (`v1.2` → `1.2.0`), and
//! at most 128 characters ([`semver::MAX_VERSION_LENGTH`]).
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
mod yaml;

use std::cmp::{Ordering, Reverse};
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

/// The Chart.yaml keys an index entry carries: the JSON names of the fields
/// of Helm's chart metadata (`chart.Metadata`), every one of them.
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

/// The most a chart version's manifest summary takes, as JSON. Every
/// `index.yaml` request renders every version from its summary, so this
/// bounds what a version adds to the index: 300 versions make under 5 MB,
/// where a Chart.yaml of 1 MiB each made 300 MB. A typical chart's summary
/// takes a few hundred bytes to a few KiB.
const MAX_SUMMARY: usize = 16 * 1024;

/// The longest description, in bytes, that a summary over [`MAX_SUMMARY`]
/// keeps. Helm asks for a single sentence, and `helm search` shows its first
/// 50 characters.
const MAX_DESCRIPTION: usize = 1024;

/// The Chart.yaml keys a summary over [`MAX_SUMMARY`] gives up last: what
/// Helm needs to list, choose and install a version, each a short string or
/// a boolean.
const ESSENTIAL_KEYS: &[&str] = &[
    "apiVersion",
    "name",
    "version",
    "appVersion",
    "kubeVersion",
    "type",
    "deprecated",
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
/// and dependency groups Forge's web UI shows, within [`MAX_SUMMARY`].
fn summary(metadata: &Map<String, Value>) -> String {
    let deps: Vec<Value> = dependencies(metadata)
        .into_iter()
        .map(|d| json!({ "id": d.id, "range": d.range }))
        .collect();
    let mut summary = Map::new();
    summary.insert("chart".into(), Value::Object(helm_metadata(metadata)));
    summary.insert(
        "description".into(),
        metadata.get("description").cloned().unwrap_or(Value::Null),
    );
    summary.insert(
        "dependency_groups".into(),
        if deps.is_empty() {
            json!([])
        } else {
            json!([{ "target_framework": null, "dependencies": deps }])
        },
    );
    bounded(&mut summary)
}

/// `summary` (a manifest summary's `chart`, with its `description` and
/// `dependency_groups` when it has them) cut down to [`MAX_SUMMARY`], and
/// its JSON.
///
/// A summary within the budget stays as it is. One over it has its
/// description cut to [`MAX_DESCRIPTION`] bytes and an ellipsis, then loses
/// whole fields, the largest first and the [`ESSENTIAL_KEYS`] last, until it
/// fits. So what is left of a field is all of it, never part of a list or a
/// map, and the same summary always comes out the same.
fn bounded(summary: &mut Map<String, Value>) -> String {
    let text = serde_json::to_string(summary).unwrap_or_default();
    if text.len() <= MAX_SUMMARY {
        return text;
    }
    // The description, in both of its places.
    let mut description = None;
    if let Some(Value::Object(chart)) = summary.get_mut("chart") {
        if let Some(Value::String(long)) = chart.get_mut("description") {
            let end = long.floor_char_boundary(MAX_DESCRIPTION);
            if end < long.len() {
                long.truncate(end);
                long.push('…');
            }
        }
        description = chart.get("description").cloned();
    }
    if summary.contains_key("description") {
        summary.insert("description".into(), description.unwrap_or(Value::Null));
    }
    // Then whole fields, the chart's and the summary's own, ordered by
    // (essential, largest first, the summary's before the chart's, key).
    let mut fields: Vec<(bool, Reverse<usize>, bool, String)> = Vec::new();
    for (key, value) in summary.iter() {
        match value {
            Value::Object(chart) if key == "chart" => {
                fields.extend(chart.iter().map(|(key, value)| {
                    let essential = ESSENTIAL_KEYS.contains(&key.as_str());
                    (essential, Reverse(field_len(key, value)), true, key.clone())
                }));
            }
            _ => fields.push((false, Reverse(field_len(key, value)), false, key.clone())),
        }
    }
    fields.sort();
    let mut size = serde_json::to_string(summary).map_or(0, |text| text.len());
    for (_, Reverse(len), in_chart, key) in fields {
        if size <= MAX_SUMMARY {
            break;
        }
        let object = if in_chart {
            match summary.get_mut("chart") {
                Some(Value::Object(chart)) => chart,
                _ => continue,
            }
        } else {
            &mut *summary
        };
        // The field, and the comma between it and its neighbour.
        size = size.saturating_sub(len + usize::from(object.len() > 1));
        object.remove(&key);
    }
    serde_json::to_string(summary).unwrap_or_default()
}

/// The length of `"key":value` in JSON.
fn field_len(key: &str, value: &Value) -> usize {
    Value::from(key).to_string().len() + 1 + value.to_string().len()
}

/// The [`METADATA_KEYS`] of `metadata`, each as the type Helm's
/// `chart.Metadata` declares for it.
///
/// Helm reads an index that is valid JSON with Go's `encoding/json`, straight
/// into those types, and refuses the whole index when one value has another
/// type. A Chart.yaml (or a YAML index of an upstream) may hold
/// `appVersion: 2` or an annotation `false`: Helm's YAML reader turns such a
/// scalar into the string its field wants, so the chart is valid, but its
/// JSON number or boolean would break every chart of the index. So scalars
/// become strings where Helm wants strings, and a value that has no such
/// form (a mapping where a string belongs) is left out.
fn helm_metadata(metadata: &Map<String, Value>) -> Map<String, Value> {
    metadata
        .iter()
        .filter_map(|(key, value)| {
            let value = match key.as_str() {
                "keywords" | "sources" => string_list(value),
                "deprecated" => value.is_boolean().then(|| value.clone()),
                "annotations" => string_map(value),
                "maintainers" => objects(value, |maintainer| {
                    pick(maintainer, &["name", "email", "url"], &[], &[])
                }),
                "dependencies" => objects(value, |dependency| {
                    let mut picked = pick(
                        dependency,
                        &["name", "version", "repository", "condition", "alias"],
                        &["tags"],
                        &["enabled"],
                    );
                    // `[]interface{}`: any list.
                    if let Some(values @ Value::Array(_)) = dependency.get("import-values") {
                        picked.insert("import-values".into(), values.clone());
                    }
                    picked
                }),
                key if METADATA_KEYS.contains(&key) => scalar_string(value),
                _ => None,
            }?;
            Some((key.clone(), value))
        })
        .collect()
}

/// A scalar as the string Helm's YAML reader makes of it.
fn scalar_string(value: &Value) -> Option<Value> {
    match value {
        Value::String(_) => Some(value.clone()),
        Value::Number(n) => Some(Value::String(n.to_string())),
        Value::Bool(b) => Some(Value::String(b.to_string())),
        _ => None,
    }
}

/// A list of strings (`[]string`): its scalars as strings.
fn string_list(value: &Value) -> Option<Value> {
    let items = value.as_array()?;
    Some(Value::Array(
        items.iter().filter_map(scalar_string).collect(),
    ))
}

/// A string map (`map[string]string`): its scalar values as strings.
fn string_map(value: &Value) -> Option<Value> {
    let map = value.as_object()?;
    Some(Value::Object(
        map.iter()
            .filter_map(|(k, v)| Some((k.clone(), scalar_string(v)?)))
            .collect(),
    ))
}

/// A list of objects (`[]*Maintainer`, `[]*Dependency`), each made by `one`.
fn objects(
    value: &Value,
    one: impl Fn(&Map<String, Value>) -> Map<String, Value>,
) -> Option<Value> {
    let items = value.as_array()?;
    Some(Value::Array(
        items
            .iter()
            .filter_map(|item| Some(Value::Object(one(item.as_object()?))))
            .collect(),
    ))
}

/// The `strings`, `lists` (of strings) and `bools` of `object`, as such.
fn pick(
    object: &Map<String, Value>,
    strings: &[&str],
    lists: &[&str],
    bools: &[&str],
) -> Map<String, Value> {
    let mut picked = Map::new();
    for (key, value) in object {
        let value = if strings.contains(&key.as_str()) {
            scalar_string(value)
        } else if lists.contains(&key.as_str()) {
            string_list(value)
        } else if bools.contains(&key.as_str()) {
            value.is_boolean().then(|| value.clone())
        } else {
            None
        };
        if let Some(value) = value {
            picked.insert(key.clone(), value);
        }
    }
    picked
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
    let chart = stored_chart(hit.summary.as_deref());
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

/// The chart metadata of a stored manifest summary, typed for Helm again (a
/// summary stored before may not be). A summary this plugin makes fits in
/// [`MAX_SUMMARY`]; one over it, stored before summaries were bounded, has
/// its chart cut down the same way ([`bounded`]).
fn stored_chart(summary: Option<&str>) -> Map<String, Value> {
    let Some(text) = summary else {
        return Map::new();
    };
    let chart = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|s| match s.get("chart") {
            Some(Value::Object(map)) => Some(helm_metadata(map)),
            _ => None,
        })
        .unwrap_or_default();
    if text.len() <= MAX_SUMMARY {
        return chart;
    }
    let mut summary = Map::from_iter([("chart".to_string(), Value::Object(chart))]);
    bounded(&mut summary);
    match summary.remove("chart") {
        Some(Value::Object(chart)) => chart,
        _ => Map::new(),
    }
}

/// One chart version as the index and the ChartMuseum API list it.
fn entry(repo: &Repository, p: &PackageInfo) -> Value {
    let mut chart = stored_chart(p.summary.as_deref());
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
    fn index_metadata_has_the_types_helm_reads() {
        let chart = chart::parse_chart_yaml(
            b"apiVersion: v2\nname: demo\nversion: 1.0.0\nappVersion: 2\ndeprecated: true\n\
              annotations: {a: false, b: 1.5, c: [x]}\nkeywords: [k, 3]\nhome: [x]\nextra: 1\n"
                .to_vec(),
        )
        .unwrap();
        let metadata = helm_metadata(&chart.metadata);
        assert_eq!(
            Value::Object(metadata),
            json!({
                "apiVersion": "v2",
                "name": "demo",
                "version": "1.0.0",
                "appVersion": "2",
                "deprecated": true,
                "annotations": {"a": "false", "b": "1.5"},
                "keywords": ["k", "3"],
            })
        );
    }

    fn summary_of(chart_yaml: &str) -> Value {
        let chart = chart::parse_chart_yaml(chart_yaml.as_bytes().to_vec()).unwrap();
        let text = summary(&chart.metadata);
        assert!(text.len() <= MAX_SUMMARY, "{} bytes", text.len());
        serde_json::from_str(&text).unwrap()
    }

    fn package_info(summary: &str) -> PackageInfo {
        PackageInfo {
            original_id: "demo".into(),
            version: "1.0.0".into(),
            version_original: "1.0.0".into(),
            listed: true,
            published: None,
            sha256: None,
            sha512: None,
            size: None,
            summary: Some(summary.into()),
        }
    }

    fn hosted() -> Repository {
        forge_plugin_api::testing::repository(RepositoryKind::Hosted, "/repository")
    }

    #[test]
    fn a_typical_charts_summary_is_all_of_its_metadata() {
        let summary = summary_of(
            "apiVersion: v2\nname: web\nversion: 1.2.0\nappVersion: \"1.27\"\n\
             kubeVersion: \">=1.25.0-0\"\ndescription: A web server\ntype: application\n\
             keywords: [web, http]\nhome: https://example.com/web\n\
             sources: [https://github.com/example/web]\nicon: https://example.com/web.png\n\
             maintainers:\n  - name: Ada\n    email: ada@example.com\n\
             dependencies:\n  - name: redis\n    version: \">=17\"\n    \
             repository: https://charts.example.com\n    condition: redis.enabled\n\
             annotations:\n  artifacthub.io/license: Apache-2.0\n",
        );
        let chart = json!({
            "apiVersion": "v2",
            "name": "web",
            "version": "1.2.0",
            "appVersion": "1.27",
            "kubeVersion": ">=1.25.0-0",
            "description": "A web server",
            "type": "application",
            "keywords": ["web", "http"],
            "home": "https://example.com/web",
            "sources": ["https://github.com/example/web"],
            "icon": "https://example.com/web.png",
            "maintainers": [{"name": "Ada", "email": "ada@example.com"}],
            "dependencies": [{
                "name": "redis",
                "version": ">=17",
                "repository": "https://charts.example.com",
                "condition": "redis.enabled",
            }],
            "annotations": {"artifacthub.io/license": "Apache-2.0"},
        });
        assert_eq!(
            summary,
            json!({
                "chart": chart,
                "description": "A web server",
                "dependency_groups": [{
                    "target_framework": null,
                    "dependencies": [{"id": "redis", "range": ">=17"}],
                }],
            })
        );
        // The index entry carries all of it (and the stored version's name
        // and version).
        let entry = entry(&hosted(), &package_info(&summary.to_string()));
        for (key, value) in chart.as_object().unwrap() {
            if key != "name" && key != "version" {
                assert_eq!(&entry[key], value, "{key}");
            }
        }
    }

    #[test]
    fn a_huge_description_is_cut_short() {
        // 990 kB of a three-byte character: the cut falls inside one.
        let description = "€".repeat(330_000);
        let summary = summary_of(&format!(
            "apiVersion: v2\nname: demo\nversion: 1.0.0\nappVersion: \"2.0\"\n\
             keywords: [a, b]\ndescription: {description}\n"
        ));
        let cut = format!("{}…", "€".repeat(MAX_DESCRIPTION / 3));
        assert_eq!(
            summary,
            json!({
                "chart": {
                    "apiVersion": "v2",
                    "name": "demo",
                    "version": "1.0.0",
                    "appVersion": "2.0",
                    "keywords": ["a", "b"],
                    "description": cut,
                },
                "description": cut,
                "dependency_groups": [],
            })
        );
        let entry = entry(&hosted(), &package_info(&summary.to_string()));
        assert!(entry.to_string().len() <= MAX_SUMMARY);
        assert_eq!(entry["description"], json!(cut));
    }

    #[test]
    fn the_largest_fields_go_first_and_the_essential_ones_last() {
        let big = "x".repeat(20_000);
        // Long annotations go, and nothing else.
        let summary = summary_of(&format!(
            "apiVersion: v2\nname: demo\nversion: 1.0.0\ndescription: A demo\n\
             keywords: [a]\nannotations:\n  changes: {big}\n  license: MIT\n"
        ));
        assert_eq!(
            summary,
            json!({
                "chart": {
                    "apiVersion": "v2",
                    "name": "demo",
                    "version": "1.0.0",
                    "description": "A demo",
                    "keywords": ["a"],
                },
                "description": "A demo",
                "dependency_groups": [],
            })
        );
        // A long essential field goes only after every other one.
        let summary = summary_of(&format!(
            "apiVersion: v2\nname: demo\nversion: 1.0.0\nappVersion: {big}\n\
             description: A demo\nkeywords: [a]\ntype: application\n"
        ));
        assert_eq!(
            summary,
            json!({
                "chart": {
                    "apiVersion": "v2",
                    "name": "demo",
                    "version": "1.0.0",
                    "type": "application",
                },
            })
        );
    }

    #[test]
    fn an_oversized_stored_summary_renders_a_bounded_entry() {
        // As stored before summaries were bounded, and not typed for Helm.
        let big = "x".repeat(1 << 20);
        let stored = json!({
            "chart": {
                "apiVersion": "v2",
                "name": "demo",
                "version": "1.0.0",
                "appVersion": 2,
                "description": big,
                "keywords": ["a"],
                "annotations": {"changes": big},
            },
            "description": big,
            "dependency_groups": [],
        })
        .to_string();
        let expected = json!({
            "apiVersion": "v2",
            "name": "demo",
            "version": "1.0.0",
            "appVersion": "2",
            "description": format!("{}…", &big[..MAX_DESCRIPTION]),
            "keywords": ["a"],
        });
        let check = |mut entry: Value| {
            assert!(entry.to_string().len() <= MAX_SUMMARY);
            let entry = entry.as_object_mut().unwrap();
            for key in ["urls", "created", "digest"] {
                entry.remove(key);
            }
            assert_eq!(Value::Object(entry.clone()), expected);
        };
        check(entry(&hosted(), &package_info(&stored)));
        let hit = SearchHit {
            original_id: "demo".into(),
            latest_version: "1.0.0".into(),
            versions: vec![forge_plugin_api::VersionInfo {
                original_id: "demo".into(),
                version: "1.0.0".into(),
                version_original: "1.0.0".into(),
                listed: true,
            }],
            summary: Some(stored),
            total_downloads: None,
        };
        let proxy = forge_plugin_api::testing::repository(RepositoryKind::Proxy, "/repository");
        let entries = hit_entries(&proxy, &hit);
        check(entries.into_iter().next().unwrap());
    }

    #[test]
    fn versions_longer_than_an_oci_tag_are_refused() {
        let longest = format!("1.0.0-{}", "a".repeat(semver::MAX_VERSION_LENGTH - 6));
        let longer = format!("{longest}a");
        assert_eq!(Helm.normalize_version(&longest).unwrap(), longest);
        assert!(matches!(
            Helm.normalize_version(&longer),
            Err(FormatError::InvalidVersion(_))
        ));
        assert_eq!(
            package_ref("Demo", &longest),
            Some(PackageRef {
                id: "demo".into(),
                version: longest.clone(),
            })
        );
        assert_eq!(package_ref("demo", &longer), None);

        // A URL naming a longer version is not found: nothing is loaded,
        // downloaded or deleted.
        let repo = Repository {
            name: "charts".into(),
            kind: RepositoryKind::Proxy,
            base_url: "https://forge.example.com/repository/charts".into(),
        };
        let download = Helm.handle(
            &repo,
            &Request::new("GET", &format!("/charts/demo/{longest}/demo.tgz")),
        );
        assert!(matches!(download, Action::Download(_)), "{download:?}");
        let huge = format!("1.0.0-{}", "x".repeat(4096));
        for (method, path) in [
            ("GET", format!("/charts/demo/{longer}/demo.tgz")),
            ("GET", format!("/charts/demo/{huge}/demo.tgz")),
            ("GET", format!("/api/charts/demo/{huge}")),
            ("DELETE", format!("/api/charts/demo/{huge}")),
        ] {
            let action = Helm.handle(&repo, &Request::new(method, &path));
            assert!(
                matches!(&action, Action::Respond(r) if r.status == 404),
                "{method} {path}: {action:?}"
            );
        }
    }

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
