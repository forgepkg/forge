//! The registry protocol: what npm clients request under a repository,
//! `/repository/<repo>/…`, and what they get.
//!
//! A package is named in one path segment, `left-pad` or `@scope%2fname`
//! (npm's `escapedName`, `%2f` or `%2F`), or in two, `@scope/name` (how
//! tarball URLs and some clients write it). Segments are percent-decoded
//! one by one after the path is split, so an encoded `/` never adds a
//! segment, and a name is only ever what [`PackageName::parse`] accepts.
//!
//! Reads load the package's versions and tags and render the packument,
//! full or abbreviated (`Accept: application/vnd.npm.install-v1+json`, what
//! installs ask for). Writes are a publish (the tarball inside the JSON
//! document, [`Upload::Document`]), and documents that change versions:
//! deprecations, unpublishing the versions a document leaves out, dist-tags.
//! Logins and `whoami` are the host's ([`Action::Auth`]); audits go to the
//! upstream ([`Action::Forward`]).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use forge_plugin_api::{
    Action, Answer, AuthOutcome, AuthRequest, BodyRequest, BodyUse, Change, ChangeSet, Forward,
    Loaded, PackageInfo, PackageRef, PublishRequest, Query, Repository, Request, Response,
    SearchQuery, Upload,
};
use serde_json::{json, Map, Value};

use crate::document;
use crate::manifest;
use crate::packument::{Packument, PackumentVersion, ABBREVIATED_MEDIA_TYPE, LATEST};
use crate::{version, Npm, PackageName};

/// The endpoints of `npm audit` passed on to the upstream, under
/// [`SECURITY`].
pub const AUDITS: &[&str] = &["advisories/bulk", "audits/quick", "audits"];

/// Where the endpoints of `npm audit` are.
const SECURITY: &str = "/-/npm/v1/security/";

/// The largest body of a login, a web login's start or `npm dist-tag add`.
const SMALL_BODY: u64 = 64 * 1024;

/// How long a client waits before it polls a web login again, in seconds.
const POLL_SECONDS: &str = "2";

/// What a request is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `GET /-/ping`.
    Ping,
    /// `GET /-/whoami`.
    Whoami,
    /// `GET /-/v1/search`.
    Search,
    /// `POST /-/v1/login`: start a web login.
    WebLogin,
    /// `GET /-/v1/login/done/<secret>`: poll a web login.
    WebLoginDone(String),
    /// `PUT /-/user/org.couchdb.user:<name>[/-rev/<rev>]`: a legacy login
    /// (`npm login --auth-type=legacy`, `yarn npm login`).
    UserLogin(String),
    /// `DELETE /-/user/token/<token>`: `npm logout`.
    Logout(String),
    /// `POST /-/npm/v1/security/…`: `npm audit`.
    Audit(String),
    /// `GET /-/package/<package>/dist-tags`.
    DistTags(PackageName),
    /// `PUT`/`DELETE /-/package/<package>/dist-tags/<tag>`.
    DistTag(PackageName, String),
    /// `GET`/`PUT /<package>`: the packument, a publish or an update.
    Package(PackageName),
    /// `PUT`/`DELETE /<package>/-rev/<rev>`: an update, or unpublishing
    /// the whole package.
    PackageRev(PackageName),
    /// `GET /<package>/<version or dist-tag>`.
    Version(PackageName, String),
    /// `GET /<package>/-/<file>.tgz`.
    Tarball(PackageName, String),
    /// `DELETE /<package>/-/<file>.tgz/-rev/<rev>`.
    TarballRev(PackageName, String),
}

/// Why a path is no route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    NotFound,
    BadRequest(String),
}

/// Percent-decode one path segment. A malformed escape, or one decoding to
/// a control character or invalid UTF-8, is refused.
pub fn decode(segment: &str) -> Result<String, RouteError> {
    let bad = || RouteError::BadRequest(format!("bad percent-encoding in {segment:?}"));
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or_else(bad)?;
            let hex = std::str::from_utf8(hex).map_err(|_| bad())?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| bad())?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let decoded = String::from_utf8(out).map_err(|_| bad())?;
    if decoded.chars().any(char::is_control) {
        return Err(bad());
    }
    Ok(decoded)
}

/// The package named at the start of `segments`, and the segments after it.
fn package<'a>(segments: &'a [&'a str]) -> Result<(PackageName, &'a [&'a str]), RouteError> {
    let first = segments.first().ok_or(RouteError::NotFound)?;
    let first = decode(first)?;
    let (raw, rest) = if first.starts_with('@') && !first.contains('/') {
        let second = segments.get(1).ok_or(RouteError::NotFound)?;
        (format!("{first}/{}", decode(second)?), &segments[2..])
    } else {
        (first, &segments[1..])
    };
    let name = PackageName::parse(&raw).map_err(|_| RouteError::NotFound)?;
    Ok((name, rest))
}

/// The route of a request path below the repository (`/left-pad`, raw,
/// not decoded).
pub fn parse(path: &str) -> Result<Route, RouteError> {
    let rest = path.strip_prefix('/').unwrap_or(path);
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(RouteError::NotFound);
    }
    match segments.as_slice() {
        ["-", "ping"] => Ok(Route::Ping),
        ["-", "whoami"] => Ok(Route::Whoami),
        ["-", "v1", "search"] => Ok(Route::Search),
        ["-", "v1", "login"] => Ok(Route::WebLogin),
        ["-", "v1", "login", "done", secret] => Ok(Route::WebLoginDone(decode(secret)?)),
        ["-", "user", "token", token] => Ok(Route::Logout(decode(token)?)),
        ["-", "user", user] | ["-", "user", user, "-rev", _] => {
            let user = decode(user)?;
            let name = user
                .strip_prefix("org.couchdb.user:")
                .ok_or(RouteError::NotFound)?;
            Ok(Route::UserLogin(name.to_string()))
        }
        ["-", "npm", "v1", "security", rest @ ..] if !rest.is_empty() => {
            Ok(Route::Audit(rest.join("/")))
        }
        ["-", "package", rest @ ..] => {
            let (name, rest) = package(rest)?;
            match rest {
                ["dist-tags"] => Ok(Route::DistTags(name)),
                ["dist-tags", tag] => Ok(Route::DistTag(name, decode(tag)?)),
                _ => Err(RouteError::NotFound),
            }
        }
        ["-", ..] => Err(RouteError::NotFound),
        _ => {
            let (name, rest) = package(&segments)?;
            match rest {
                [] => Ok(Route::Package(name)),
                ["-rev", _] => Ok(Route::PackageRev(name)),
                ["-", file] => Ok(Route::Tarball(name, decode(file)?)),
                ["-", file, "-rev", _] => Ok(Route::TarballRev(name, decode(file)?)),
                [version] => Ok(Route::Version(name, decode(version)?)),
                _ => Err(RouteError::NotFound),
            }
        }
    }
}

fn json_response(status: u16, body: &Value) -> Response {
    Response::new(
        status,
        "application/json",
        serde_json::to_vec(body).unwrap_or_default(),
    )
}

/// An error as npm clients read it: `{"error": "…"}`.
pub fn error(status: u16, message: impl Into<String>) -> Response {
    json_response(status, &json!({ "error": message.into() }))
}

fn ok(status: u16) -> Response {
    json_response(status, &json!({ "ok": true, "success": true }))
}

fn respond(response: Response) -> Action {
    Action::Respond(response)
}

/// Whether the request asks for abbreviated metadata (and does not refuse
/// it with `q=0`).
pub fn wants_abbreviated(req: &Request) -> bool {
    req.header("accept").is_some_and(|accept| {
        accept.split(',').any(|part| {
            let mut params = part.split(';');
            let media = params.next().unwrap_or("").trim();
            let refused = params.any(|p| {
                p.trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q == 0.0)
            });
            media.eq_ignore_ascii_case(ABBREVIATED_MEDIA_TYPE) && !refused
        })
    })
}

fn reads(name: &PackageName) -> Action {
    let id = name.to_string();
    Action::Load(vec![Query::Packages(id.clone()), Query::Tags(id)])
}

/// The full packument's: with the publish times (`time`) it shows, which
/// cost a proxy the upstream's full packument too.
fn dated_reads(name: &PackageName) -> Action {
    let id = name.to_string();
    Action::Load(vec![Query::DatedPackages(id.clone()), Query::Tags(id)])
}

/// The search of `GET /-/v1/search?text=&size=&from=`.
fn search_query(req: &Request) -> SearchQuery {
    let number = |key: &str, default: u32| {
        req.query_param(key)
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(default)
    };
    SearchQuery {
        text: req.query_param("text").unwrap_or_default(),
        skip: number("from", 0),
        take: number("size", 20).clamp(1, 250),
        prerelease: true,
        semver2: true,
        upstream: true,
    }
}

/// What a request is: see the module documentation.
pub fn handle(npm: &Npm, req: &Request) -> Action {
    let route = match parse(&req.path) {
        Ok(route) => route,
        Err(RouteError::NotFound) => return respond(error(404, "not found")),
        Err(RouteError::BadRequest(m)) => return respond(error(400, m)),
    };
    let document_limit = npm.limits().max_document_bytes;
    let body = req.body.as_deref();
    match (req.method.as_str(), route) {
        ("GET" | "HEAD", Route::Ping) => respond(json_response(200, &json!({}))),
        ("GET", Route::Whoami) => Action::Auth(AuthRequest::Whoami),
        ("GET", Route::Search) => Action::Load(vec![Query::Search(search_query(req))]),
        ("POST", Route::WebLogin) => match body {
            None => Action::ReadBody(BodyRequest {
                limit: SMALL_BODY,
                used_for: BodyUse::Login,
            }),
            Some(body) => {
                let hostname = serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|v| v.get("hostname")?.as_str().map(str::to_string))
                    .filter(|h| !h.is_empty() && h.len() <= 255);
                Action::Auth(AuthRequest::StartWebLogin { hostname })
            }
        },
        ("GET", Route::WebLoginDone(secret)) => Action::Auth(AuthRequest::PollWebLogin { secret }),
        ("PUT", Route::UserLogin(user)) => match body {
            None => Action::ReadBody(BodyRequest {
                limit: SMALL_BODY,
                used_for: BodyUse::Login,
            }),
            Some(body) => {
                let doc: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
                let username = doc
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or(user);
                match doc.get("password").and_then(Value::as_str) {
                    Some(password) if !password.is_empty() => Action::Auth(AuthRequest::Password {
                        username,
                        password: password.to_string(),
                    }),
                    _ => respond(error(400, "the login has no password")),
                }
            }
        },
        ("DELETE", Route::Logout(token)) => Action::Auth(AuthRequest::Logout { token }),
        ("POST", Route::Audit(kind)) => {
            if !AUDITS.contains(&kind.as_str()) {
                return respond(error(404, "not found"));
            }
            match body {
                None => Action::ReadBody(BodyRequest {
                    limit: document_limit,
                    used_for: BodyUse::Read,
                }),
                Some(body) => audit(req, &kind, body),
            }
        }
        ("GET", Route::DistTags(name)) => reads(&name),
        ("PUT", Route::DistTag(name, tag)) => {
            if !document::valid_tag(&tag) {
                return respond(error(
                    400,
                    format!("{tag:?} is not a dist-tag: use letters, digits, '.', '_' and '-', not starting with a digit"),
                ));
            }
            let Some(body) = body else {
                return Action::ReadBody(BodyRequest {
                    limit: SMALL_BODY,
                    used_for: BodyUse::Change,
                });
            };
            let raw = match serde_json::from_slice::<Value>(body) {
                Ok(Value::String(v)) => v,
                _ => String::from_utf8_lossy(body).trim().to_string(),
            };
            match version::normalize(&raw) {
                Ok(version) => Action::Change(ChangeSet {
                    changes: vec![Change::Tag {
                        id: name.to_string(),
                        tag,
                        version,
                    }],
                    done: ok(201),
                }),
                Err(_) => respond(error(400, format!("{raw:?} is not a version"))),
            }
        }
        ("DELETE", Route::DistTag(name, tag)) => {
            if tag == LATEST {
                return respond(error(
                    400,
                    "the latest tag cannot be removed; point it at another version",
                ));
            }
            Action::Change(ChangeSet {
                changes: vec![Change::Untag {
                    id: name.to_string(),
                    tag,
                }],
                done: ok(200),
            })
        }
        ("GET" | "HEAD", Route::Package(name)) if wants_abbreviated(req) => reads(&name),
        ("GET" | "HEAD", Route::Package(name)) => dated_reads(&name),
        ("PUT", Route::Package(name)) => match body {
            // A publish, unless the document carries no tarball: then it is
            // an update, and the host asks again with it.
            None => Action::Publish(PublishRequest {
                upload: Upload::Document,
                id: Some(name.to_string()),
                done: ok(201),
            }),
            Some(_) => reads(&name),
        },
        ("PUT", Route::PackageRev(name)) => match body {
            None => Action::ReadBody(BodyRequest {
                limit: document_limit,
                used_for: BodyUse::Change,
            }),
            Some(_) => reads(&name),
        },
        ("DELETE", Route::PackageRev(name)) => reads(&name),
        ("GET" | "HEAD", Route::Version(name, _)) => reads(&name),
        ("GET" | "HEAD", Route::Tarball(name, file)) => match tarball_version(&name, &file) {
            Some(version) => Action::Download(PackageRef {
                id: name.to_string(),
                version,
            }),
            None => respond(error(404, format!("tarball {file} of {name} not found"))),
        },
        ("DELETE", Route::TarballRev(name, file)) => match tarball_version(&name, &file) {
            // npm unpublishes a version with a packument update first, and
            // takes the 404 of this second request for done.
            Some(version) => Action::Change(ChangeSet {
                changes: vec![Change::Delete(PackageRef {
                    id: name.to_string(),
                    version,
                })],
                done: ok(200),
            }),
            None => respond(error(404, format!("tarball {file} of {name} not found"))),
        },
        _ => respond(error(405, "method not allowed")),
    }
}

/// The version a tarball's file name (`name-1.0.0.tgz`) names.
fn tarball_version(name: &PackageName, file: &str) -> Option<String> {
    name.version_of_tarball(file)
        .and_then(|v| version::normalize(v).ok())
}

/// An audit, to the upstream. Through a group, the host sends the body
/// [`forward_body`] leaves of it.
fn audit(req: &Request, kind: &str, body: &[u8]) -> Action {
    let query = if req.query.is_empty() {
        String::new()
    } else {
        format!("?{}", req.query)
    };
    Action::Forward(Forward {
        path: format!("{SECURITY}{kind}{query}"),
        content_type: "application/json".into(),
        body: body.to_vec(),
    })
}

/// An audit's body without the packages `hidden` names, for a group's
/// upstream: a bulk request (`{name: [versions]}`, npm 7 and later), or the
/// dependency tree of a legacy one (`audits/quick` and `audits`: npm 6,
/// pnpm, and npm's fallback when a bulk request fails). `None` when it
/// cannot be filtered: a body that is no JSON object, or a tree that names
/// its packages by their paths (`packages`, npm 7's lockfile).
pub fn forward_body(forward: &Forward, hidden: &dyn Fn(&str) -> bool) -> Option<Vec<u8>> {
    let path = forward.path.split('?').next().unwrap_or_default();
    let kind = path.strip_prefix(SECURITY)?;
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&forward.body) else {
        return None;
    };
    let filtered = match kind {
        "advisories/bulk" => body.into_iter().filter(|(name, _)| !hidden(name)).collect(),
        "audits/quick" | "audits" => tree_without(body, hidden)?,
        _ => return None,
    };
    serde_json::to_vec(&Value::Object(filtered)).ok()
}

/// The root of a legacy audit's dependency tree without the packages
/// `hidden` names. Only what the upstream audits with is kept: the
/// project's name when it is not hidden, the scalars that describe the
/// client, the client's `metadata`, the packages installed or removed and
/// the tree ([`node_without`]).
fn tree_without(
    mut root: Map<String, Value>,
    hidden: &dyn Fn(&str) -> bool,
) -> Option<Map<String, Value>> {
    if root.contains_key("packages") {
        return None;
    }
    let mut kept = node_without(&mut root, hidden);
    if let Some(Value::String(name)) = root.remove("name") {
        if !hidden(&name) {
            kept.insert("name".into(), Value::String(name));
        }
    }
    for key in ["install", "remove"] {
        if let Some(Value::Array(specs)) = root.remove(key) {
            let specs = specs
                .into_iter()
                .filter(|spec| {
                    spec.as_str()
                        .is_some_and(|spec| !names_hidden(spec, hidden))
                })
                .collect();
            kept.insert(key.into(), Value::Array(specs));
        }
    }
    if let Some(Value::Object(metadata)) = root.remove("metadata") {
        let metadata = metadata
            .into_iter()
            .filter(|(_, value)| !(value.is_object() || value.is_array()))
            .collect();
        kept.insert("metadata".into(), Value::Object(metadata));
    }
    for key in [
        "lockfileVersion",
        "npm_version",
        "node_version",
        "platform",
        "arch",
        "node_env",
    ] {
        if let Some(value) = root
            .remove(key)
            .filter(|v| !(v.is_object() || v.is_array()))
        {
            kept.insert(key.into(), value);
        }
    }
    Some(kept)
}

/// A node of a legacy audit's dependency tree without the packages
/// `hidden` names: they are the keys of `requires` (to a version or a
/// range) and of `dependencies` (to the nodes below), at every depth, and
/// the targets of aliases (`npm:@acme/ui@1.0.0`). Of a node only its
/// version, integrity and kind of dependency are kept: its `resolved` URL
/// and the `from` it was installed as may name a package too.
fn node_without(
    node: &mut Map<String, Value>,
    hidden: &dyn Fn(&str) -> bool,
) -> Map<String, Value> {
    let mut kept = Map::new();
    match node.remove("requires") {
        Some(Value::Object(requires)) => {
            let requires = requires
                .into_iter()
                .filter(|(name, spec)| {
                    !hidden(name)
                        && spec
                            .as_str()
                            .is_some_and(|spec| !aliases_hidden(spec, hidden))
                })
                .collect();
            kept.insert("requires".into(), Value::Object(requires));
        }
        // A lockfile's `"requires": true`.
        Some(Value::Bool(requires)) => {
            kept.insert("requires".into(), Value::Bool(requires));
        }
        _ => {}
    }
    if let Some(Value::Object(dependencies)) = node.remove("dependencies") {
        let dependencies = dependencies
            .into_iter()
            .filter(|(name, _)| !hidden(name))
            .filter_map(|(name, dependency)| {
                let Value::Object(mut dependency) = dependency else {
                    return None;
                };
                let version = dependency.get("version").and_then(Value::as_str);
                if version.is_some_and(|version| aliases_hidden(version, hidden)) {
                    return None;
                }
                Some((name, Value::Object(node_without(&mut dependency, hidden))))
            })
            .collect();
        kept.insert("dependencies".into(), Value::Object(dependencies));
    }
    for key in [
        "version",
        "integrity",
        "dev",
        "optional",
        "devOptional",
        "peer",
        "bundled",
    ] {
        if let Some(value) = node
            .remove(key)
            .filter(|v| !(v.is_object() || v.is_array()))
        {
            kept.insert(key.into(), value);
        }
    }
    kept
}

/// Whether `spec` is an alias (`npm:@acme/ui@^1.0.0`) of a package `hidden`
/// names.
fn aliases_hidden(spec: &str, hidden: &dyn Fn(&str) -> bool) -> bool {
    spec.strip_prefix("npm:")
        .is_some_and(|target| names_hidden(target, hidden))
}

/// Whether `spec` (`@acme/ui@1.0.0`, `left-pad`, `ui@npm:@acme/ui@1.0.0`)
/// names a package `hidden` names, or is an alias of one.
fn names_hidden(spec: &str, hidden: &dyn Fn(&str) -> bool) -> bool {
    if aliases_hidden(spec, hidden) {
        return true;
    }
    // The version starts at the first `@` after the scope's.
    let (name, version) = match spec.char_indices().skip(1).find(|&(_, c)| c == '@') {
        Some((at, _)) => (&spec[..at], &spec[at + 1..]),
        None => (spec, ""),
    };
    hidden(name) || aliases_hidden(version, hidden)
}

/// The versions of `id` loaded, if they were.
fn packages<'a>(data: &'a [Loaded], id: &str) -> Option<&'a [PackageInfo]> {
    data.iter()
        .find_map(|loaded| match (&loaded.query, &loaded.answer) {
            (Query::Packages(q) | Query::DatedPackages(q), Answer::Packages(infos)) if q == id => {
                Some(infos.as_slice())
            }
            _ => None,
        })
}

/// The tags of `id` loaded (none when they were not).
fn tags(data: &[Loaded], id: &str) -> BTreeMap<String, String> {
    data.iter()
        .find_map(|loaded| match (&loaded.query, &loaded.answer) {
            (Query::Tags(q), Answer::Tags(tags)) if q == id => Some(
                tags.iter()
                    .map(|t| (t.name.clone(), t.version.clone()))
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

/// The manifest of `target` loaded: `None` when it was not asked for yet.
fn loaded_manifest<'a>(data: &'a [Loaded], target: &PackageRef) -> Option<Option<&'a [u8]>> {
    data.iter()
        .find_map(|loaded| match (&loaded.query, &loaded.answer) {
            (Query::Manifest(q), Answer::Manifest(m)) if q == target => Some(m.as_deref()),
            _ => None,
        })
}

/// A version's summary as the packument lists it: its deprecation is the
/// one Forge stores, when there is one.
fn summary_of(info: &PackageInfo) -> Map<String, Value> {
    let mut summary = info
        .summary
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    if let Some(message) = &info.deprecated {
        summary.insert("deprecated".into(), Value::String(message.clone()));
    }
    summary
}

fn published(info: &PackageInfo) -> Option<DateTime<Utc>> {
    info.published
        .as_deref()
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc))
}

/// What the repository serves of `name`: its loaded versions and tags.
fn packument_of(
    name: &PackageName,
    infos: &[PackageInfo],
    tags: BTreeMap<String, String>,
) -> Packument {
    Packument {
        name: name.clone(),
        versions: infos
            .iter()
            .map(|info| PackumentVersion {
                version: info.version.clone(),
                summary: summary_of(info),
                published: published(info),
            })
            .collect(),
        dist_tags: tags,
        readme: None,
    }
}

/// The response to a request [`handle`] asked data for.
pub fn render(npm: &Npm, repo: &Repository, req: &Request, data: &[Loaded]) -> Action {
    let Ok(route) = parse(&req.path) else {
        return Action::Respond(error(404, "not found"));
    };
    let name = match &route {
        Route::Search => return Action::Respond(search(data)),
        Route::DistTags(name)
        | Route::Package(name)
        | Route::PackageRev(name)
        | Route::Version(name, _) => name,
        _ => return Action::Respond(error(500, "nothing to render")),
    };
    let id = name.to_string();
    let infos = packages(data, &id).unwrap_or_default();
    let not_found = || Action::Respond(error(404, format!("package {name} not found")));
    if infos.is_empty() {
        return not_found();
    }
    let mut packument = packument_of(name, infos, tags(data, &id));
    match (req.method.as_str(), &route) {
        (_, Route::DistTags(_)) => {
            Action::Respond(json_response(200, &json!(packument.served_dist_tags())))
        }
        ("GET" | "HEAD", Route::Package(_)) => {
            let abbreviated = wants_abbreviated(req);
            // The full document carries the latest version's README.
            if !abbreviated {
                if let Some(latest) = packument.served_dist_tags().get(LATEST) {
                    let target = PackageRef {
                        id: id.clone(),
                        version: latest.clone(),
                    };
                    match loaded_manifest(data, &target) {
                        None => return Action::Load(vec![Query::Manifest(target)]),
                        Some(manifest) => {
                            packument.readme = manifest
                                .and_then(|m| forge_plugin_api::FormatPlugin::readme(npm, m))
                        }
                    }
                }
            }
            let doc = packument.render(&repo.base_url, abbreviated);
            let content_type = if abbreviated {
                ABBREVIATED_MEDIA_TYPE
            } else {
                "application/json"
            };
            Action::Respond(
                Response::new(
                    200,
                    content_type,
                    serde_json::to_vec(&doc).unwrap_or_default(),
                )
                .with_header("vary", "Accept"),
            )
        }
        ("GET" | "HEAD", Route::Version(_, spec)) => {
            let version = match packument.served_dist_tags().get(spec.as_str()) {
                Some(v) => v.clone(),
                None => match version::normalize(spec) {
                    Ok(v) => v,
                    Err(_) => {
                        return Action::Respond(error(
                            404,
                            format!("version {spec:?} of {name} not found"),
                        ))
                    }
                },
            };
            match packument.render_version(&repo.base_url, &version) {
                Some(doc) => Action::Respond(json_response(200, &doc)),
                None => {
                    Action::Respond(error(404, format!("version {version} of {name} not found")))
                }
            }
        }
        ("PUT", Route::Package(_) | Route::PackageRev(_)) => update(req, name, infos, data),
        ("DELETE", Route::PackageRev(_)) => Action::Change(ChangeSet {
            changes: infos
                .iter()
                .map(|info| {
                    Change::Delete(PackageRef {
                        id: id.clone(),
                        version: info.version.clone(),
                    })
                })
                .collect(),
            done: ok(200),
        }),
        _ => Action::Respond(error(405, "method not allowed")),
    }
}

/// A packument update (a `PUT` without a tarball): `npm deprecate`
/// (versions' `deprecated`), `npm unpublish <version>` (versions left out)
/// and dist-tag changes, as changes to make.
fn update(req: &Request, name: &PackageName, infos: &[PackageInfo], data: &[Loaded]) -> Action {
    let bad = |m: String| Action::Respond(error(400, m));
    let Some(body) = req.body.as_deref() else {
        return bad("the document is missing".into());
    };
    let doc: Value = match serde_json::from_slice(body) {
        Ok(doc) => doc,
        Err(e) => return bad(format!("the document is not valid JSON: {e}")),
    };
    let update = match document::read_update(&doc, name) {
        Ok(update) => update,
        Err(e) => return bad(e),
    };
    let id = name.to_string();
    let target = |version: &str| PackageRef {
        id: id.clone(),
        version: version.to_string(),
    };
    let removed: Vec<&PackageInfo> = infos
        .iter()
        .filter(|info| !update.versions.contains_key(&info.version))
        .collect();
    if removed.len() == infos.len() {
        // npm unpublishes a package's last version with `DELETE /-rev`.
        return bad(
            "the document leaves the package no version: unpublish the package instead".into(),
        );
    }
    // Leaving versions out removes them: the delete permission's.
    let mut changes: Vec<Change> = removed
        .iter()
        .map(|info| Change::Delete(target(&info.version)))
        .collect();
    for info in infos {
        let Some(wanted) = update.versions.get(&info.version) else {
            continue;
        };
        let summary = summary_of(info);
        if manifest::deprecation(&summary) != wanted.as_deref() {
            changes.push(Change::Deprecate {
                target: target(&info.version),
                message: wanted.clone(),
            });
        }
    }
    if update.dist_tags_given {
        let current = tags(data, &id);
        for (tag, version) in &update.dist_tags {
            let kept = infos
                .iter()
                .any(|info| &info.version == version && update.versions.contains_key(version));
            if kept && current.get(tag) != Some(version) {
                changes.push(Change::Tag {
                    id: id.clone(),
                    tag: tag.clone(),
                    version: version.clone(),
                });
            }
        }
        for (tag, version) in &current {
            // Deleting a version drops its tags already.
            let deleted = removed.iter().any(|info| &info.version == version);
            if !deleted && !update.dist_tags.contains_key(tag) {
                changes.push(Change::Untag {
                    id: id.clone(),
                    tag: tag.clone(),
                });
            }
        }
    }
    if changes.is_empty() {
        return Action::Respond(ok(200));
    }
    Action::Change(ChangeSet {
        changes,
        done: ok(200),
    })
}

/// `GET /-/v1/search`: the results as npm prints them.
fn search(data: &[Loaded]) -> Response {
    let Some(result) = data.iter().find_map(|loaded| match &loaded.answer {
        Answer::Search(result) => Some(result),
        _ => None,
    }) else {
        return error(500, "no search results");
    };
    let objects: Vec<Value> = result
        .hits
        .iter()
        .map(|hit| {
            let summary: Map<String, Value> = hit
                .summary
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let scope = PackageName::parse(&hit.original_id)
                .ok()
                .and_then(|n| n.scope().map(str::to_string))
                .unwrap_or_else(|| "unscoped".into());
            let mut package = Map::new();
            package.insert("name".into(), json!(hit.original_id));
            package.insert("scope".into(), json!(scope));
            package.insert("version".into(), json!(hit.latest_version));
            for key in ["description", "keywords", "date", "links", "author"] {
                if let Some(value) = summary.get(key) {
                    package.insert(key.into(), value.clone());
                }
            }
            // Search results name people by `username` (a packument by
            // `name`), and clients expect the list.
            let person = |p: &Value| {
                let username = p
                    .get("username")
                    .or_else(|| p.get("name"))
                    .and_then(Value::as_str)?;
                let mut out = json!({ "username": username });
                if let Some(email) = p.get("email").and_then(Value::as_str) {
                    out["email"] = json!(email);
                }
                Some(out)
            };
            let maintainers: Vec<Value> = summary
                .get("maintainers")
                .and_then(Value::as_array)
                .map(|m| m.iter().filter_map(person).collect())
                .unwrap_or_default();
            package.insert("maintainers".into(), Value::Array(maintainers));
            if let Some(publisher) = summary
                .get("publisher")
                .or_else(|| summary.get("_npmUser"))
                .and_then(person)
            {
                package.insert("publisher".into(), publisher);
            }
            json!({
                "package": package,
                "score": {"final": 1.0, "detail": {"quality": 1.0, "popularity": 1.0, "maintenance": 1.0}},
                "searchScore": 1.0,
            })
        })
        .collect();
    json_response(
        200,
        &json!({
            "objects": objects,
            "total": result.total,
            "time": Utc::now().to_rfc2822(),
        }),
    )
}

/// The response to a login, a logout or `whoami` the host performed.
pub fn auth_response(repo: &Repository, req: &Request, outcome: &AuthOutcome) -> Response {
    match outcome {
        AuthOutcome::Token { token, username } => match parse(&req.path) {
            Ok(Route::UserLogin(_)) => json_response(
                201,
                &json!({
                    "ok": true,
                    "id": format!("org.couchdb.user:{username}"),
                    "rev": "_we_dont_use_revs_any_more",
                    "username": username,
                    "token": token,
                }),
            ),
            _ => json_response(200, &json!({ "token": token })),
        },
        AuthOutcome::WebLoginStarted { login_url, secret } => json_response(
            200,
            &json!({
                "loginUrl": login_url,
                "doneUrl": format!("{}/-/v1/login/done/{secret}", repo.base_url),
            }),
        ),
        AuthOutcome::WebLoginPending => {
            json_response(202, &json!({})).with_header("retry-after", POLL_SECONDS)
        }
        AuthOutcome::WebLoginUnknown => error(404, "no such login, or it expired"),
        AuthOutcome::LoggedOut => json_response(200, &json!({ "ok": true })),
        AuthOutcome::Identity { username } => json_response(200, &json!({ "username": username })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(raw: &str) -> PackageName {
        PackageName::parse(raw).unwrap()
    }

    #[test]
    fn parses_routes() {
        assert_eq!(parse("/-/ping"), Ok(Route::Ping));
        assert_eq!(parse("/left-pad"), Ok(Route::Package(name("left-pad"))));
        assert_eq!(parse("/@acme%2fui"), Ok(Route::Package(name("@acme/ui"))));
        assert_eq!(parse("/@acme%2Fui"), Ok(Route::Package(name("@acme/ui"))));
        assert_eq!(parse("/@acme/ui"), Ok(Route::Package(name("@acme/ui"))));
        assert_eq!(
            parse("/@acme/ui/-/ui-1.0.0.tgz"),
            Ok(Route::Tarball(name("@acme/ui"), "ui-1.0.0.tgz".into()))
        );
        assert_eq!(
            parse("/left-pad/-/left-pad-1.0.0.tgz/-rev/3-x"),
            Ok(Route::TarballRev(
                name("left-pad"),
                "left-pad-1.0.0.tgz".into()
            ))
        );
        assert_eq!(
            parse("/left-pad/-rev/3-x"),
            Ok(Route::PackageRev(name("left-pad")))
        );
        assert_eq!(
            parse("/left-pad/latest"),
            Ok(Route::Version(name("left-pad"), "latest".into()))
        );
        assert_eq!(
            parse("/-/package/@acme%2fui/dist-tags/next"),
            Ok(Route::DistTag(name("@acme/ui"), "next".into()))
        );
        assert_eq!(
            parse("/-/user/org.couchdb.user:alice@example.com"),
            Ok(Route::UserLogin("alice@example.com".into()))
        );
        assert_eq!(parse("/-/user/token/abc"), Ok(Route::Logout("abc".into())));
        assert_eq!(
            parse("/-/npm/v1/security/advisories/bulk"),
            Ok(Route::Audit("advisories/bulk".into()))
        );
        assert_eq!(
            parse("/-/v1/login/done/s3cret"),
            Ok(Route::WebLoginDone("s3cret".into()))
        );
    }

    #[test]
    fn refuses_paths_that_are_no_package() {
        for bad in [
            "/",
            "/..%2f..%2fadmin",
            "/%2e%2e",
            "/a%2fb",
            "/-/nope",
            "/a//b",
            "/@acme",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(matches!(parse("/%zz"), Err(RouteError::BadRequest(_))));
    }

    #[test]
    fn abbreviated_metadata_is_asked_for() {
        let req = |accept: &str| Request::new("GET", "/x").with_header("accept", accept);
        assert!(wants_abbreviated(&req(
            "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"
        )));
        assert!(!wants_abbreviated(&req("application/json")));
        assert!(!wants_abbreviated(&req(
            "application/vnd.npm.install-v1+json;q=0"
        )));
        assert!(!wants_abbreviated(&Request::new("GET", "/x")));
    }

    /// An audit to `kind` with `body`, as the plugin forwards it.
    fn forwarded(kind: &str, body: &Value) -> Forward {
        Forward {
            path: format!("{SECURITY}{kind}"),
            content_type: "application/json".into(),
            body: serde_json::to_vec(body).unwrap(),
        }
    }

    /// What of `body` goes to the upstream with `@acme/` hidden.
    fn filtered(kind: &str, body: &Value) -> Option<Value> {
        let hidden = |name: &str| name.to_ascii_lowercase().starts_with("@acme/");
        forward_body(&forwarded(kind, body), &hidden)
            .map(|body| serde_json::from_slice(&body).unwrap())
    }

    #[test]
    fn bulk_audits_keep_internal_names_inside() {
        let body = json!({"@acme/ui": ["1.0.0"], "left-pad": ["1.3.0"], "@ACME/core": ["2.0.0"]});
        assert_eq!(
            filtered("advisories/bulk", &body),
            Some(json!({"left-pad": ["1.3.0"]}))
        );
        let mut with_query = forwarded("advisories/bulk", &body);
        with_query.path.push_str("?x=1");
        assert!(forward_body(&with_query, &|_: &str| false).is_some());
    }

    #[test]
    fn legacy_audits_keep_internal_names_inside_at_every_depth() {
        // npm 6: the lockfile's tree, the project's name and what an
        // install adds; an alias of an internal package.
        let npm6 = json!({
            "name": "@acme/app",
            "version": "1.0.0",
            "requires": {"@acme/ui": "^1.0.0", "left-pad": "^1.3.0", "pad": "npm:@acme/pad@^2.0.0"},
            "dependencies": {
                "@acme/ui": {"version": "1.0.0", "integrity": "sha512-a", "requires": {"left-pad": "1.3.0"}},
                "pad": {"version": "npm:@acme/pad@2.0.0", "integrity": "sha512-b"},
                "left-pad": {
                    "version": "1.3.0",
                    "integrity": "sha512-c",
                    "resolved": "https://forge.example.com/repository/npm/left-pad/-/left-pad-1.3.0.tgz",
                    "from": "left-pad@^1.3.0",
                    "dev": true,
                    "requires": {"@acme/core": "2.0.0", "right-pad": "1.0.0"},
                    "dependencies": {
                        "@acme/core": {"version": "2.0.0"},
                        "right-pad": {"version": "1.0.0", "bundled": true, "license": "MIT"}
                    }
                }
            },
            "install": ["@acme/ui@1.0.0", "left-pad@1.3.0", "pad@npm:@acme/pad@2.0.0", 7],
            "remove": ["@ACME/old"],
            "metadata": {"npm_version": "6.14.18", "node_version": "v14.21.3", "platform": "linux", "x": {"@acme/ui": 1}}
        });
        let expected = json!({
            "version": "1.0.0",
            "requires": {"left-pad": "^1.3.0"},
            "dependencies": {
                "left-pad": {
                    "version": "1.3.0",
                    "integrity": "sha512-c",
                    "dev": true,
                    "requires": {"right-pad": "1.0.0"},
                    "dependencies": {"right-pad": {"version": "1.0.0", "bundled": true}}
                }
            },
            "install": ["left-pad@1.3.0"],
            "remove": [],
            "metadata": {"npm_version": "6.14.18", "node_version": "v14.21.3", "platform": "linux"}
        });
        assert_eq!(filtered("audits/quick", &npm6), Some(expected.clone()));
        assert_eq!(filtered("audits", &npm6), Some(expected));

        // pnpm: a node per workspace project, the packages below it.
        let pnpm = json!({
            "dependencies": {".": {
                "dependencies": {"@acme/ui": {"version": "1.0.0", "dev": false}, "left-pad": {"version": "1.3.0", "dev": false}},
                "dev": false,
                "requires": {"@acme/ui": "1.0.0", "left-pad": "1.3.0"},
                "version": "0.0.0"
            }},
            "dev": false,
            "install": [],
            "metadata": {},
            "remove": [],
            "requires": {".": "0.0.0"}
        });
        assert_eq!(
            filtered("audits", &pnpm),
            Some(json!({
                "dependencies": {".": {
                    "dependencies": {"left-pad": {"version": "1.3.0", "dev": false}},
                    "dev": false,
                    "requires": {"left-pad": "1.3.0"},
                    "version": "0.0.0"
                }},
                "dev": false,
                "install": [],
                "metadata": {},
                "remove": [],
                "requires": {".": "0.0.0"}
            }))
        );
    }

    #[test]
    fn a_body_that_cannot_be_filtered_is_not_forwarded() {
        for kind in ["advisories/bulk", "audits/quick", "audits"] {
            assert_eq!(
                filtered(kind, &json!([{"@acme/ui": ["1.0.0"]}])),
                None,
                "{kind}"
            );
            let bad = Forward {
                body: b"{\"@acme/ui\": [".to_vec(),
                ..forwarded(kind, &json!({}))
            };
            assert_eq!(forward_body(&bad, &|_: &str| false), None, "{kind}");
        }
        // npm 7's lockfile names its packages by their paths.
        let lockfile = json!({
            "name": "app",
            "lockfileVersion": 3,
            "packages": {"node_modules/@acme/ui": {"version": "1.0.0"}}
        });
        assert_eq!(filtered("audits/quick", &lockfile), None);
        assert_eq!(filtered("anything", &json!({})), None);
    }
}
