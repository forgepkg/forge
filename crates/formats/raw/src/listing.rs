//! Directory listings: `GET /repository/<repo>/<dir>/`, as HTML for browsers or as
//! JSON (`Accept: application/json`, or `?format=json`), a page at a time.
//!
//! A page holds at most `limit` entries (default 100, at most 1000) after
//! the entry named by `after`, in byte order of their names, a
//! subdirectory's name ending in `/`; `next` (and a `Link: rel="next"`
//! header) names where the following page starts. The host walks its file
//! store for the page ([`forge_plugin_api::Query::Directory`]): package
//! selectors, group members and a proxy's cache are its business.

use forge_plugin_api::files;
use forge_plugin_api::{Action, Answer, DirectoryEntry, Loaded, Repository, Request, Response};
use serde::Serialize;

/// Largest page size.
pub const MAX_LIMIT: usize = 1000;

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
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_downloaded: Option<String>,
}

impl Entry {
    fn of(directory: &str, entry: &DirectoryEntry) -> Self {
        match entry {
            DirectoryEntry::File(file) => Entry {
                name: file
                    .path
                    .strip_prefix(directory)
                    .unwrap_or(&file.path)
                    .to_string(),
                path: file.path.clone(),
                kind: "file",
                size: Some(file.size),
                content_type: Some(file.content_type.clone()),
                sha256: Some(file.sha256.clone()),
                last_modified: Some(file.modified.clone()),
                last_downloaded: file.last_downloaded.clone(),
            },
            DirectoryEntry::Directory(path) => Entry {
                name: path.strip_prefix(directory).unwrap_or(path).to_string(),
                path: path.clone(),
                kind: "directory",
                size: None,
                content_type: None,
                sha256: None,
                last_modified: None,
                last_downloaded: None,
            },
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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ListQuery {
    pub after: Option<String>,
    pub limit: Option<usize>,
    /// `json` | `html`: overrides `Accept`.
    pub format: Option<String>,
}

impl ListQuery {
    /// Parse a request's query string; other parameters are ignored.
    pub fn parse(query: &str) -> Result<Self, String> {
        let mut out = ListQuery::default();
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "after" => out.after = Some(value.into_owned()),
                "limit" => {
                    out.limit = Some(
                        value
                            .parse()
                            .map_err(|_| "limit must be a positive number".to_string())?,
                    )
                }
                "format" => match value.as_ref() {
                    "json" | "html" => out.format = Some(value.into_owned()),
                    _ => return Err("format is json or html".into()),
                },
                _ => {}
            }
        }
        if let Some(after) = out.after.as_deref().filter(|a| !a.is_empty()) {
            let name = after.strip_suffix('/').unwrap_or(after);
            files::validate_segment(name).map_err(|e| format!("after: {e}"))?;
        }
        Ok(out)
    }

    /// The page size to ask the host for: 0 (its default) unless the client
    /// named one.
    pub fn limit_for_host(&self) -> u32 {
        self.limit
            .map_or(0, |limit| limit.clamp(1, MAX_LIMIT) as u32)
    }
}

/// Answer a listing request from the page the host loaded.
pub fn render(repo: &Repository, req: &Request, directory: &str, data: &[Loaded]) -> Action {
    let page = data.iter().rev().find_map(|loaded| match &loaded.answer {
        Answer::Directory(page) => Some(page),
        _ => None,
    });
    let Some(page) = page else {
        return Action::Respond(Response::text(500, "raw: no listing was loaded"));
    };
    let Some(page) = page else {
        return Action::Respond(Response::text(404, "not found"));
    };
    let query = ListQuery::parse(&req.query).unwrap_or_default();
    let page = Page {
        repository: repo.name.clone(),
        path: directory.to_string(),
        entries: page
            .entries
            .iter()
            .map(|entry| Entry::of(directory, entry))
            .collect(),
        next: page.next.clone(),
    };
    Action::Respond(respond(repo, &page, &query, wants_json(req, &query)))
}

/// Whether the client wants JSON: `format=json`, or an `Accept` preferring
/// `application/json` to HTML.
pub fn wants_json(req: &Request, query: &ListQuery) -> bool {
    match query.format.as_deref() {
        Some("json") => return true,
        Some("html") => return false,
        _ => {}
    }
    let accept = req.header("accept").unwrap_or("");
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
fn next_link(repo: &Repository, page: &Page, query: &ListQuery) -> Option<String> {
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
        "{}/{}?{}",
        base_path(&repo.base_url),
        files::encode(&page.path),
        params.finish()
    ))
}

/// The path of the repository's URL (`/repository/<repository>`), for links and
/// redirects that keep the client on the host it asked.
pub fn base_path(base_url: &str) -> &str {
    base_url
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or("")
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

/// An RFC 3339 time as `YYYY-MM-DD HH:MM:SS UTC` (the host's times are in
/// UTC).
fn display_time(rfc3339: &str) -> String {
    match (rfc3339.get(..10), rfc3339.get(11..19)) {
        (Some(date), Some(time)) => format!("{date} {time} UTC"),
        _ => rfc3339.to_string(),
    }
}

/// The page as an HTML document: a table of the entries, linked.
pub fn html(repo: &Repository, page: &Page, query: &ListQuery) -> String {
    let title = format!("Index of {}/{}", base_path(&repo.base_url), page.path);
    let mut out = format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{t}</title></head>\n<body>\n<h1>{t}</h1>\n<table>\n<tr><th>Name</th><th>Size</th><th>Last modified</th><th>SHA-256</th></tr>\n",
        t = escape(&title)
    );
    if !page.path.is_empty() {
        out.push_str("<tr><td><a href=\"../\">../</a></td><td></td><td></td><td></td></tr>\n");
    }
    for entry in &page.entries {
        let href = files::encode(&entry.name);
        out.push_str(&format!(
            "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape(&href),
            escape(&entry.name),
            entry.size.map(|s| s.to_string()).unwrap_or_default(),
            entry
                .last_modified
                .as_deref()
                .map(display_time)
                .unwrap_or_default(),
            escape(entry.sha256.as_deref().unwrap_or("")),
        ));
    }
    out.push_str("</table>\n");
    if let Some(next) = next_link(repo, page, query) {
        out.push_str(&format!(
            "<p><a href=\"{}\">Next page</a></p>\n",
            escape(&next)
        ));
    }
    out.push_str("</body></html>\n");
    out
}

/// The listing response: the page, its `Link` to the next page.
pub fn respond(repo: &Repository, page: &Page, query: &ListQuery, json: bool) -> Response {
    let mut response = if json {
        Response::new(
            200,
            "application/json",
            serde_json::to_string(page).unwrap_or_default(),
        )
    } else {
        Response::new(200, "text/html; charset=utf-8", html(repo, page, query))
    };
    // Forge's own document, shown in the browser (and sandboxed).
    response = response
        .with_header("content-disposition", "inline")
        .with_header("vary", "Accept");
    if let Some(next) = next_link(repo, page, query) {
        response = response.with_header("link", &format!("<{next}>; rel=\"next\""));
    }
    response
}

/// Seconds since the epoch of an RFC 3339 time (`2026-10-01T12:00:00.250Z`,
/// or with a `+hh:mm` / `-hh:mm` offset), whole seconds.
pub fn epoch_seconds(rfc3339: &str) -> Option<u64> {
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let text = rfc3339.get(range)?;
        text.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| text.parse().ok())?
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Skip a fraction, then read the offset.
    let rest = rfc3339.get(19..)?;
    let rest = rest
        .strip_prefix('.')
        .map_or(rest, |r| r.trim_start_matches(|c: char| c.is_ascii_digit()));
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.get(..1)? {
                "+" => 1,
                "-" => -1,
                _ => return None,
            };
            let hours: i64 = rest.get(1..3)?.parse().ok()?;
            let minutes: i64 = rest.get(4..6)?.parse().ok()?;
            sign * (hours * 3600 + minutes * 60)
        }
    };
    // Days since 1970-01-01 of a proleptic Gregorian date.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let day_of_year = (153 * m + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(seconds).ok()
}

/// Seconds since the epoch as an HTTP date (IMF-fixdate).
pub fn http_date(seconds: u64) -> String {
    httpdate::fmt_http_date(std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_plugin_api::RepositoryKind;

    fn repo() -> Repository {
        Repository {
            name: "bin".into(),
            kind: RepositoryKind::Hosted,
            base_url: "https://forge.example.com/repository/bin".into(),
            inline: false,
        }
    }

    #[test]
    fn queries_are_checked() {
        assert_eq!(ListQuery::parse("").unwrap(), ListQuery::default());
        let q = ListQuery::parse("after=x.bin&limit=5&format=json&other=1").unwrap();
        assert_eq!(q.after.as_deref(), Some("x.bin"));
        assert_eq!(q.limit_for_host(), 5);
        assert_eq!(ListQuery::parse("limit=0").unwrap().limit_for_host(), 1);
        assert_eq!(
            ListQuery::parse("limit=5000").unwrap().limit_for_host(),
            1000
        );
        assert_eq!(ListQuery::default().limit_for_host(), 0);
        assert!(ListQuery::parse("limit=x").is_err());
        assert!(ListQuery::parse("format=xml").is_err());
        assert!(ListQuery::parse("after=..%2Fx").is_err());
        assert!(ListQuery::parse("after=b%2Fc").is_err());
        assert!(ListQuery::parse("after=dir%2F").is_ok());
    }

    #[test]
    fn json_is_asked_for() {
        let query = ListQuery::default();
        let req = Request::new("GET", "/");
        assert!(!wants_json(&req, &query));
        let req = Request::new("GET", "/").with_header("accept", "application/json");
        assert!(wants_json(&req, &query));
        let req = Request::new("GET", "/").with_header(
            "accept",
            "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        );
        assert!(!wants_json(&req, &query));
        let query = ListQuery {
            format: Some("json".into()),
            ..Default::default()
        };
        assert!(wants_json(&req, &query));
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
                last_modified: Some("2026-10-21T10:58:44.123456Z".into()),
                last_downloaded: None,
            }],
            next: Some("<x> y.txt".into()),
        };
        let html = html(&repo(), &page, &ListQuery::default());
        assert!(
            html.contains("href=\"%3Cx%3E%20y.txt\">&lt;x&gt; y.txt</a>"),
            "{html}"
        );
        assert!(
            html.contains("<title>Index of /repository/bin/a/</title>"),
            "{html}"
        );
        assert!(html.contains("href=\"../\""));
        assert!(html.contains("2026-10-21 10:58:44 UTC"), "{html}");
        assert!(
            html.contains("/repository/bin/a/?after=%3Cx%3E+y.txt"),
            "{html}"
        );
        assert!(!html.contains("<x>"));
    }

    #[test]
    fn json_keeps_the_listing_shape() {
        let page = Page {
            repository: "bin".into(),
            path: String::new(),
            entries: vec![
                Entry::of("", &DirectoryEntry::Directory("d/".into())),
                Entry::of(
                    "",
                    &DirectoryEntry::File(forge_plugin_api::FileInfo {
                        path: "f.txt".into(),
                        size: 3,
                        content_type: "text/plain".into(),
                        sha256: "ab".into(),
                        sha512: String::new(),
                        sha1: String::new(),
                        md5: String::new(),
                        modified: "2026-10-21T10:58:44Z".into(),
                        last_downloaded: None,
                    }),
                ),
            ],
            next: None,
        };
        let response = respond(&repo(), &page, &ListQuery::default(), true);
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            r#"{"repository":"bin","path":"","entries":[{"name":"d/","path":"d/","type":"directory"},{"name":"f.txt","path":"f.txt","type":"file","size":3,"content_type":"text/plain","sha256":"ab","last_modified":"2026-10-21T10:58:44Z"}],"next":null}"#
        );
    }

    #[test]
    fn times_convert() {
        assert_eq!(epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            epoch_seconds("2026-10-01T12:00:00.250Z"),
            Some(1_790_856_000)
        );
        assert_eq!(
            epoch_seconds("2026-10-01T14:00:00+02:00"),
            Some(1_790_856_000)
        );
        assert_eq!(epoch_seconds("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(epoch_seconds("not a time"), None);
        assert_eq!(http_date(1_790_856_000), "Thu, 01 Oct 2026 12:00:00 GMT");
    }
}
