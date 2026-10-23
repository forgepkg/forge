//! Directory listings: `GET /raw/<repo>/<dir>/`, as HTML for browsers or as
//! JSON (`Accept: application/json`), a page at a time.
//!
//! A page holds at most `limit` entries (default 100, at most 1000) after
//! the entry named by `after`, in byte order of their names, a
//! subdirectory's name ending in `/`; `next` (and a `Link: rel="next"`
//! header) names where the following page starts. A listing walks the
//! index ([`raw_dao::walk_directory`]): a page costs `limit` index probes,
//! however many files are below the directory.
//!
//! Package selectors apply: a file outside the caller's selector is not
//! listed, and a subdirectory is listed only when it holds a file the
//! caller may see (looked for among its first files; a subdirectory none of
//! whose first [`SUBDIRECTORY_SCAN`] files is visible is left out). A
//! group lists the merged entries of the members the caller may read, the
//! highest-priority member's file first; a proxy lists what it has cached.

use std::collections::BTreeMap;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use forge_core::authz::PackageFilter;
use forge_db::model::{RepoKind, Repository};
use forge_db::raw_dao::{self, RawFile};
use serde::Serialize;

use super::{path, Raw, RawError};

/// Default page size.
pub const DEFAULT_LIMIT: usize = 100;

/// Largest page size.
pub const MAX_LIMIT: usize = 1000;

/// How many of a subdirectory's files a listing reads, at most, to find one
/// a selector-restricted caller may see.
pub const SUBDIRECTORY_SCAN: usize = 1000;

/// One entry of a listing.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Entry {
    /// The entry's name in its directory; a subdirectory's ends in `/`.
    pub name: String,
    /// The full path (a subdirectory's ends in `/`).
    pub path: String,
    /// `file` | `directory`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_downloaded: Option<DateTime<Utc>>,
}

impl Entry {
    fn file(file: &RawFile, name: &str) -> Self {
        Entry {
            name: name.to_string(),
            path: file.path.clone(),
            kind: "file",
            size: Some(file.size),
            content_type: Some(file.content_type.clone()),
            sha256: Some(file.blob_sha256.clone()),
            last_modified: Some(file.updated_at),
            last_downloaded: file.last_downloaded_at,
        }
    }

    fn directory(prefix: &str, name: &str) -> Self {
        Entry {
            name: format!("{name}/"),
            path: format!("{prefix}{name}/"),
            kind: "directory",
            size: None,
            content_type: None,
            sha256: None,
            last_modified: None,
            last_downloaded: None,
        }
    }
}

/// A page of a listing.
#[derive(Debug, Clone, Serialize)]
pub struct Page {
    pub repository: String,
    /// The directory (`""` for the root).
    pub path: String,
    pub entries: Vec<Entry>,
    /// The `after` of the next page, if there is one.
    pub next: Option<String>,
}

/// The query of a listing.
#[derive(Debug, Default, serde::Deserialize)]
pub struct ListQuery {
    pub after: Option<String>,
    pub limit: Option<usize>,
    /// `json` | `html`: overrides `Accept`.
    pub format: Option<String>,
}

impl ListQuery {
    /// Parse a request's query string; other parameters are ignored.
    pub fn parse(query: Option<&str>) -> Result<Self, RawError> {
        let mut out = ListQuery::default();
        for (key, value) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
            match key.as_ref() {
                "after" => out.after = Some(value.into_owned()),
                "limit" => {
                    out.limit = Some(value.parse().map_err(|_| {
                        RawError::BadRequest("limit must be a positive number".into())
                    })?)
                }
                "format" => match value.as_ref() {
                    "json" | "html" => out.format = Some(value.into_owned()),
                    _ => return Err(RawError::BadRequest("format is json or html".into())),
                },
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Where a page starting after the entry `after` (a name in directory
/// `prefix`, a subdirectory's ending in `/`) resumes: the least path past
/// that entry (past all of a subdirectory's files: `'0'` follows `'/'`; past
/// a file: no path holds a control character).
fn resume_at(prefix: &str, after: Option<&str>) -> Result<String, RawError> {
    let Some(after) = after.filter(|a| !a.is_empty()) else {
        return Ok(prefix.to_string());
    };
    let (name, directory) = match after.strip_suffix('/') {
        Some(name) => (name, true),
        None => (after, false),
    };
    path::validate_segment(name).map_err(|e| RawError::BadRequest(format!("after: {e}")))?;
    Ok(if directory {
        format!("{prefix}{name}0")
    } else {
        format!("{prefix}{name}\u{1}")
    })
}

/// One repository's entries of a page: what it has after `from`, as far as
/// it read (`more`: it has entries past the last one returned, up to and
/// including the entry named `more`, which it has read).
struct Partial {
    entries: Vec<Entry>,
    more: Option<String>,
}

impl Raw<'_> {
    /// The entries of `prefix` in hosted or proxy `repo` from `from` on,
    /// visible through every one of `filters`.
    async fn list_local(
        &self,
        repo: &Repository,
        prefix: &str,
        from: &str,
        limit: usize,
        filters: &[PackageFilter],
    ) -> Result<Partial, RawError> {
        let walked = raw_dao::walk_directory(
            &self.state.pool,
            repo.id,
            prefix,
            from,
            i64::try_from(limit + 1).unwrap_or(i64::MAX),
        )
        .await?;
        let more = walked.len() > limit;
        let mut entries = Vec::new();
        let mut last = None;
        for walked in walked.into_iter().take(limit) {
            let rest = &walked.path[prefix.len()..];
            let (entry, key) = match (rest.find('/'), &walked.file) {
                (None, Some(file)) => {
                    let visible = filters.iter().all(|f| f.allows(&file.path));
                    (visible.then(|| Entry::file(file, rest)), rest.to_string())
                }
                (Some(i), _) => {
                    let name = &rest[..i];
                    let dir = format!("{prefix}{name}/");
                    let visible = self.directory_visible(repo, &dir, filters).await?;
                    (
                        visible.then(|| Entry::directory(prefix, name)),
                        format!("{name}/"),
                    )
                }
                // A file row vanished between the walk and the join.
                (None, None) => (None, rest.to_string()),
            };
            entries.extend(entry);
            last = Some(key);
        }
        Ok(Partial {
            entries,
            more: if more { last } else { None },
        })
    }

    /// Whether directory `dir` of `repo` holds a file visible through every
    /// one of `filters`.
    async fn directory_visible(
        &self,
        repo: &Repository,
        dir: &str,
        filters: &[PackageFilter],
    ) -> Result<bool, RawError> {
        if filters.iter().all(|f| matches!(f, PackageFilter::AllowAll)) {
            return Ok(true);
        }
        const BATCH: usize = 200;
        let mut after = String::new();
        let mut read = 0;
        while read < SUBDIRECTORY_SCAN {
            let paths =
                raw_dao::paths_under(&self.state.pool, repo.id, dir, &after, BATCH as i64).await?;
            if paths.iter().any(|p| filters.iter().all(|f| f.allows(p))) {
                return Ok(true);
            }
            if paths.len() < BATCH {
                return Ok(false);
            }
            read += paths.len();
            after = paths.last().cloned().unwrap_or_default();
        }
        Ok(false)
    }

    /// The entries of `prefix` in `repo` (any kind) from `from` on.
    fn list_in<'a>(
        &'a self,
        repo: &'a Repository,
        prefix: &'a str,
        from: &'a str,
        limit: usize,
        filters: Vec<PackageFilter>,
        depth: u32,
    ) -> futures_util::future::BoxFuture<'a, Result<Partial, RawError>> {
        Box::pin(async move {
            let mut filters = filters;
            filters.push(self.state.authz.package_filter(&self.principal, repo).await);
            if repo.kind() != RepoKind::Group {
                return self.list_local(repo, prefix, from, limit, &filters).await;
            }
            // A merge of the members' pages, complete up to the first point
            // a member stopped reading at.
            let mut merged: BTreeMap<String, Entry> = BTreeMap::new();
            let mut cutoff: Option<String> = None;
            for member in self.serving_members(repo, depth).await? {
                let part = self
                    .list_in(&member, prefix, from, limit, filters.clone(), depth + 1)
                    .await?;
                for entry in part.entries {
                    merged.entry(entry.name.clone()).or_insert(entry);
                }
                if let Some(more) = part.more {
                    if cutoff.as_ref().is_none_or(|c| more < *c) {
                        cutoff = Some(more);
                    }
                }
            }
            let mut entries: Vec<Entry> = merged
                .into_values()
                .filter(|e| cutoff.as_ref().is_none_or(|c| e.name <= *c))
                .collect();
            let more = if entries.len() > limit {
                entries.truncate(limit);
                entries.last().map(|e| e.name.clone())
            } else {
                cutoff
            };
            Ok(Partial { entries, more })
        })
    }

    /// A page of directory `prefix` of `repo`, `None` when it does not
    /// exist (a directory other than the root without visible entries).
    pub async fn list(
        &self,
        repo: &Repository,
        prefix: &str,
        query: &ListQuery,
    ) -> Result<Option<Page>, RawError> {
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let from = resume_at(prefix, query.after.as_deref())?;
        let partial = self
            .list_in(repo, prefix, &from, limit, Vec::new(), 0)
            .await?;
        if partial.entries.is_empty() && partial.more.is_none() && !prefix.is_empty() {
            // Past the end of an existing directory is an empty page, not a
            // missing directory.
            if query.after.is_none() {
                return Ok(None);
            }
        }
        Ok(Some(Page {
            repository: repo.name.clone(),
            path: prefix.to_string(),
            entries: partial.entries,
            next: partial.more,
        }))
    }
}

/// Whether the client wants JSON: `format=json`, or an `Accept` preferring
/// `application/json` to HTML.
pub fn wants_json(headers: &HeaderMap, query: &ListQuery) -> bool {
    match query.format.as_deref() {
        Some("json") => return true,
        Some("html") => return false,
        _ => {}
    }
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let quality = |wanted: &str| {
        accept
            .split(',')
            .filter_map(|item| {
                let mut parts = item.split(';');
                let media = parts.next()?.trim().to_ascii_lowercase();
                (media == wanted).then(|| {
                    parts
                        .filter_map(|p| p.trim().strip_prefix("q="))
                        .find_map(|q| q.parse::<f32>().ok())
                        .unwrap_or(1.0)
                })
            })
            .fold(0.0f32, f32::max)
    };
    quality("application/json") > 0.0 && quality("application/json") >= quality("text/html")
}

/// The URL of the page after `page`.
fn next_link(page: &Page, query: &ListQuery) -> Option<String> {
    let next = page.next.as_deref()?;
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("after", next);
    if let Some(limit) = query.limit {
        params.append_pair("limit", &limit.to_string());
    }
    if let Some(format) = &query.format {
        params.append_pair("format", format);
    }
    Some(format!(
        "/raw/{}/{}?{}",
        page.repository,
        path::encode(&page.path),
        params.finish()
    ))
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The page as an HTML document: a table of the entries, linked.
pub fn html(page: &Page, query: &ListQuery) -> String {
    let title = format!("Index of /raw/{}/{}", page.repository, page.path);
    let mut out = format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{t}</title></head>\n<body>\n<h1>{t}</h1>\n<table>\n<tr><th>Name</th><th>Size</th><th>Last modified</th><th>SHA-256</th></tr>\n",
        t = escape(&title)
    );
    if !page.path.is_empty() {
        out.push_str("<tr><td><a href=\"../\">../</a></td><td></td><td></td><td></td></tr>\n");
    }
    for entry in &page.entries {
        let href = path::encode(&entry.name);
        out.push_str(&format!(
            "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape(&href),
            escape(&entry.name),
            entry.size.map(|s| s.to_string()).unwrap_or_default(),
            entry
                .last_modified
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_default(),
            escape(entry.sha256.as_deref().unwrap_or("")),
        ));
    }
    out.push_str("</table>\n");
    if let Some(next) = next_link(page, query) {
        out.push_str(&format!(
            "<p><a href=\"{}\">Next page</a></p>\n",
            escape(&next)
        ));
    }
    out.push_str("</body></html>\n");
    out
}

/// Answer a listing request.
pub fn respond(page: &Page, query: &ListQuery, json: bool, head: bool) -> Response {
    let (content_type, body) = if json {
        (
            "application/json",
            serde_json::to_string(page).unwrap_or_default(),
        )
    } else {
        ("text/html; charset=utf-8", html(page, query))
    };
    let length = body.len();
    let mut response = if head {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::OK, body).into_response()
    };
    let out = response.headers_mut();
    out.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    out.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    // Forge's own document, shown in the browser (and sandboxed).
    out.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    out.insert(header::VARY, HeaderValue::from_static("Accept"));
    if let Some(next) = next_link(page, query) {
        if let Ok(value) = HeaderValue::from_str(&format!("<{next}>; rel=\"next\"")) {
            out.insert(header::LINK, value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_resume_past_the_named_entry() {
        assert_eq!(resume_at("a/", None).unwrap(), "a/");
        assert_eq!(resume_at("a/", Some("")).unwrap(), "a/");
        assert_eq!(resume_at("a/", Some("x.bin")).unwrap(), "a/x.bin\u{1}");
        assert_eq!(resume_at("", Some("dir/")).unwrap(), "dir0");
        assert!(resume_at("a/", Some("../x")).is_err());
        assert!(resume_at("a/", Some("b/c")).is_err());
    }

    #[test]
    fn json_is_asked_for() {
        let query = ListQuery::default();
        let mut h = HeaderMap::new();
        assert!(!wants_json(&h, &query));
        h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(wants_json(&h, &query));
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            ),
        );
        assert!(!wants_json(&h, &query));
        let query = ListQuery {
            format: Some("json".into()),
            ..Default::default()
        };
        assert!(wants_json(&h, &query));
    }

    #[test]
    fn html_escapes_names_and_links_them_encoded() {
        let page = Page {
            repository: "bin".into(),
            path: "a/".into(),
            entries: vec![Entry {
                name: "<x> y.txt".into(),
                path: "a/<x> y.txt".into(),
                kind: "file",
                size: Some(3),
                content_type: Some("text/plain".into()),
                sha256: Some("ab".into()),
                last_modified: None,
                last_downloaded: None,
            }],
            next: Some("<x> y.txt".into()),
        };
        let html = html(&page, &ListQuery::default());
        assert!(
            html.contains("href=\"%3Cx%3E%20y.txt\">&lt;x&gt; y.txt</a>"),
            "{html}"
        );
        assert!(html.contains("href=\"../\""));
        assert!(html.contains("/raw/bin/a/?after=%3Cx%3E+y.txt"), "{html}");
        assert!(!html.contains("<x>"));
    }
}
