//! A raw repository as an import's source. Raw has no protocol beyond a
//! `GET` of a path and no standard listing, so the import reads one of
//! these:
//!
//! * **Nexus' asset listing**, `GET <nexus>/service/rest/v1/assets?repository=<name>`,
//!   paged with `continuationToken` ([`RawSource::assets`]): each file's
//!   path, size, content type, SHA-1, SHA-256 and SHA-512, when its blob was
//!   created, when it was last downloaded, and who uploaded it. It is the
//!   only listing of a Nexus raw repository with checksums (its HTML browse
//!   pages carry none), so for raw the import reads Nexus' REST API. The
//!   source is the repository, `<nexus>/repository/<name>`.
//! * **Another Forge's listing**, `GET <directory>/` as JSON, paged with
//!   `after` ([`RawSource::directory`]): each file's size, content type,
//!   SHA-256, upload time and last download, one directory at a time
//!   ([`Walk`]).
//! * **The paths the import names**, for a server with no listing (a plain
//!   web server): a `HEAD` says the file's size, type and `Last-Modified`
//!   ([`RawSource::head`]), and its `.sha256` sidecar, where the server
//!   serves one, its SHA-256 ([`RawSource::sidecar`]).
//!
//! A file is downloaded from the import's URL and its path
//! ([`RawSource::file_url`]), never from Nexus' `downloadUrl`, which carries
//! the base URL Nexus is configured with. Requests go through the shared
//! [`UpstreamHttp`] client (timeouts, size caps, no cloud-metadata targets),
//! with the credentials sent to the source's origin only.

use chrono::{DateTime, Utc};
use forge_core::net::upstream::{Origin, RequestClass, SpooledBody, UpstreamAuth, UpstreamHttp};
use forge_crypto::{ExposeSecret, PlaintextSecret};
use forge_plugin::api::files;
use reqwest::StatusCode;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};

use super::{Listing, SourceError};

/// Entries a page of another Forge's listing is asked for (its default).
pub const DIRECTORY_PAGE: u32 = 100;

/// A file as the source lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listed {
    /// Its path below the source's URL, as the source names it.
    pub path: String,
    pub size: Option<u64>,
    pub content_type: Option<String>,
    /// Lowercase hex digests.
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    /// The SHA-256 is the one its `.sha256` sidecar holds.
    pub sidecar: bool,
    /// When the source stored the content: Nexus' `blobCreated` (else its
    /// `lastModified`), another Forge's `last_modified`, a web server's
    /// `Last-Modified`.
    pub created: Option<DateTime<Utc>>,
    /// When the source last served it: Nexus' `lastDownloaded`, another
    /// Forge's `last_downloaded`.
    pub downloaded: Option<DateTime<Utc>>,
    /// Who uploaded it (Nexus).
    pub uploader: Option<String>,
}

/// One page of Nexus' asset listing.
#[derive(Debug, Default)]
pub struct AssetPage {
    pub files: Vec<Listed>,
    /// The `continuationToken` of the next page; `None` on the last.
    pub next: Option<String>,
}

/// One entry of another Forge's listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A file, its `path` the directory's and its name.
    File(Listed),
    /// A subdirectory: its name, without the trailing `/`.
    Directory(String),
}

/// One page of a directory of another Forge's listing.
#[derive(Debug, Default)]
pub struct DirectoryPage {
    pub entries: Vec<Entry>,
    /// The `after` of the next page; `None` on the last.
    pub next: Option<String>,
}

/// Where a walk of another Forge's listing is: in directory `dir` (`""` for
/// the root, else ending in `/`), after the entry `after` (a subdirectory's
/// name ending in `/`). It is the scan's cursor, so a walk resumes where it
/// stopped without a stack: once a directory is listed to its end, the walk
/// goes on in its parent after it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Walk {
    pub dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// What one step of a [`Walk`] found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// The files, up to the page's first subdirectory.
    pub files: Vec<Listed>,
    /// Subdirectories whose names Forge refuses (`a\b/`): not walked, and
    /// reported as failed items.
    pub refused: Vec<(String, String)>,
    /// Where the walk goes on; `None` once it is done.
    pub next: Option<Walk>,
}

impl Walk {
    /// The walk's cursor, as the import stores it.
    pub fn cursor(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The walk a stored cursor names; the root's start without one.
    pub fn parse(cursor: Option<&str>) -> Result<Walk, SourceError> {
        match cursor {
            None => Ok(Walk::default()),
            Some(cursor) => serde_json::from_str(cursor).map_err(|e| {
                SourceError::Invalid(format!("the import's cursor {cursor:?} is unreadable: {e}"))
            }),
        }
    }

    /// The next step after `page`, the page of `self.dir` after
    /// `self.after`. The files up to the page's first subdirectory are
    /// taken, and the walk goes down into it; the rest of the page is read
    /// again once that subdirectory is walked. A page without a
    /// subdirectory goes on to the next page, or, at the directory's end,
    /// back up to the parent after it.
    pub fn step(&self, page: DirectoryPage) -> Step {
        let mut step = Step::default();
        for entry in page.entries {
            match entry {
                Entry::File(file) => step.files.push(file),
                Entry::Directory(name) => {
                    let dir = format!("{}{name}/", self.dir);
                    match files::validate_segment(&name)
                        .and_then(|()| files::validate_directory(&dir))
                    {
                        Ok(()) => {
                            step.next = Some(Walk { dir, after: None });
                            return step;
                        }
                        // Not walked: Forge could store nothing below it.
                        Err(e) => step.refused.push((dir, e.to_string())),
                    }
                }
            }
        }
        step.next = match page.next {
            Some(after) => Some(Walk {
                dir: self.dir.clone(),
                after: Some(after),
            }),
            None => self.up(),
        };
        step
    }

    /// The walk in the parent directory, after this one; `None` at the root.
    fn up(&self) -> Option<Walk> {
        let dir = self.dir.strip_suffix('/')?;
        let (parent, name) = match dir.rsplit_once('/') {
            Some((parent, name)) => (format!("{parent}/"), name),
            None => (String::new(), dir),
        };
        Some(Walk {
            dir: parent,
            after: Some(format!("{name}/")),
        })
    }
}

/// What a `HEAD` of a named file says.
#[derive(Debug, Default)]
pub struct Head {
    pub size: Option<u64>,
    pub content_type: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
}

/// A raw repository at `url` (no trailing `/`).
pub struct RawSource {
    http: UpstreamHttp,
    url: String,
    username: Option<String>,
    password: Option<PlaintextSecret>,
    /// The `Server` header the source answered the preflight with.
    server: Option<String>,
}

impl RawSource {
    pub fn new(
        http: UpstreamHttp,
        url: &str,
        username: Option<String>,
        password: Option<PlaintextSecret>,
    ) -> Self {
        RawSource {
            http,
            url: url.trim_end_matches('/').to_string(),
            username,
            password,
            server: None,
        }
    }

    /// The `Server` header the source answered [`Self::probe`] with.
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// The Basic credentials, for the source's origin only.
    fn auth(&self) -> Option<UpstreamAuth<'_>> {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => Some(UpstreamAuth {
                origin: Origin::of(&self.url),
                username,
                password: password.expose_secret(),
                bearer: false,
            }),
            _ => None,
        }
    }

    /// Where the source serves the file at `path`, each segment
    /// percent-encoded.
    pub fn file_url(&self, path: &str) -> String {
        format!("{}/{}", self.url, files::encode(path))
    }

    /// The Nexus server and repository the URL names, when it has the shape
    /// of a Nexus repository's: `<nexus>/repository/<name>`.
    pub fn nexus(&self) -> Option<(&str, &str)> {
        let (base, name) = self.url.rsplit_once("/repository/")?;
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        (valid && base.contains("://")).then_some((base, name))
    }

    fn assets_url(&self, cursor: Option<&str>) -> Option<String> {
        let (base, repository) = self.nexus()?;
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("repository", repository);
        if let Some(cursor) = cursor {
            query.append_pair("continuationToken", cursor);
        }
        Some(format!("{base}/service/rest/v1/assets?{}", query.finish()))
    }

    fn directory_url(&self, dir: &str, after: Option<&str>, limit: u32) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("format", "json");
        query.append_pair("limit", &limit.to_string());
        if let Some(after) = after {
            query.append_pair("after", after);
        }
        format!("{}/{}?{}", self.url, files::encode(dir), query.finish())
    }

    /// GET `url`: the answer, or `None` for a status that says the resource
    /// is not there (or is no document of this kind). A refusal of the
    /// credentials, a server error and a failed transfer are errors.
    async fn get_document(
        &self,
        url: &str,
        accept: &str,
    ) -> Result<Option<(Option<String>, Vec<u8>)>, SourceError> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(accept) = reqwest::header::HeaderValue::from_str(accept) {
            headers.insert(reqwest::header::ACCEPT, accept);
        }
        let response = self
            .http
            .send(
                reqwest::Method::GET,
                url,
                RequestClass::Metadata,
                headers,
                self.auth().as_ref(),
            )
            .await
            .map_err(|e| SourceError::of(e, url))?;
        let status = response.status();
        let server = header(&response, reqwest::header::SERVER);
        if !status.is_success() {
            return match status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    Err(SourceError::status(status, url))
                }
                s if s.is_server_error() || s == StatusCode::TOO_MANY_REQUESTS => {
                    Err(SourceError::status(status, url))
                }
                _ => Ok(None),
            };
        }
        let config = self.http.config();
        let body = SpooledBody::read(
            response,
            url,
            config.max_metadata_bytes,
            config.spool_memory_bytes,
        )
        .await
        .map_err(|e| SourceError::of(e, url))?;
        let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut body.into_reader()?, &mut out)?;
            Ok(out)
        })
        .await
        .map_err(|e| SourceError::Invalid(e.to_string()))?
        .map_err(|e| SourceError::Unreachable(format!("reading {url}: {e}")))?;
        Ok(Some((server, bytes)))
    }

    /// The preflight: which listing names the source's files. Another
    /// Forge's (its root as JSON) is tried first, then, for a URL of a
    /// Nexus repository's shape, Nexus' asset listing. `None` when the
    /// source serves neither: the import names its paths.
    pub async fn probe(&mut self) -> Result<Option<Listing>, SourceError> {
        let url = self.directory_url("", None, 1);
        if let Some((server, body)) = self.get_document(&url, "application/json").await? {
            self.server = server;
            if parse_directory(&body).is_ok() {
                return Ok(Some(Listing::Directories));
            }
        }
        let Some(url) = self.assets_url(None) else {
            return Ok(None);
        };
        if let Some((server, body)) = self.get_document(&url, "application/json").await? {
            if parse_assets(&body).is_ok() {
                self.server = server;
                return Ok(Some(Listing::Assets));
            }
        }
        Ok(None)
    }

    /// The preflight of an import that names its paths: the first named
    /// file is asked for, so wrong credentials or an unreachable server are
    /// reported before the import is stored. A file it does not have is no
    /// error (it fails as its item).
    pub async fn probe_named(&mut self, path: &str) -> Result<(), SourceError> {
        let url = self.file_url(path);
        let response = self
            .http
            .send(
                reqwest::Method::HEAD,
                &url,
                RequestClass::Metadata,
                reqwest::header::HeaderMap::new(),
                self.auth().as_ref(),
            )
            .await
            .map_err(|e| SourceError::of(e, &url))?;
        self.server = header(&response, reqwest::header::SERVER);
        let status = response.status();
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
            || status.is_server_error()
        {
            return Err(SourceError::status(status, &url));
        }
        Ok(())
    }

    /// The page of Nexus' asset listing after `cursor`.
    pub async fn assets(&self, cursor: Option<&str>) -> Result<AssetPage, SourceError> {
        let url = self.assets_url(cursor).ok_or_else(|| {
            SourceError::Invalid(format!(
                "{} is no Nexus repository's URL (<nexus>/repository/<name>)",
                self.url
            ))
        })?;
        let (_, body) = self
            .get_document(&url, "application/json")
            .await?
            .ok_or_else(|| {
                SourceError::Invalid(format!("Nexus serves no asset listing at {url}"))
            })?;
        parse_assets(&body).map_err(|e| SourceError::Invalid(format!("{url}: {e}")))
    }

    /// The page of the directory `dir` (`""` or ending in `/`) of another
    /// Forge's listing after the entry `after`.
    pub async fn directory(
        &self,
        dir: &str,
        after: Option<&str>,
    ) -> Result<DirectoryPage, SourceError> {
        let url = self.directory_url(dir, after, DIRECTORY_PAGE);
        let Some((_, body)) = self.get_document(&url, "application/json").await? else {
            // Emptied since it was listed in its parent.
            return Ok(DirectoryPage::default());
        };
        let mut page =
            parse_directory(&body).map_err(|e| SourceError::Invalid(format!("{url}: {e}")))?;
        for entry in &mut page.entries {
            if let Entry::File(file) = entry {
                file.path = format!("{dir}{}", file.path);
            }
        }
        Ok(page)
    }

    /// What a `HEAD` of the file at `path` says; `None` when the source has
    /// no file there. A server that does not answer `HEAD` says nothing: the
    /// download tells.
    pub async fn head(&self, path: &str) -> Result<Option<Head>, SourceError> {
        let url = self.file_url(path);
        let response = self
            .http
            .send(
                reqwest::Method::HEAD,
                &url,
                RequestClass::Metadata,
                reqwest::header::HeaderMap::new(),
                self.auth().as_ref(),
            )
            .await
            .map_err(|e| SourceError::of(e, &url))?;
        let status = response.status();
        match status {
            StatusCode::NOT_FOUND | StatusCode::GONE => return Ok(None),
            StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_IMPLEMENTED => {
                return Ok(Some(Head::default()))
            }
            s if !s.is_success() => return Err(SourceError::status(s, &url)),
            _ => {}
        }
        Ok(Some(Head {
            size: header(&response, reqwest::header::CONTENT_LENGTH).and_then(|v| v.parse().ok()),
            content_type: header(&response, reqwest::header::CONTENT_TYPE),
            last_modified: header(&response, reqwest::header::LAST_MODIFIED)
                .and_then(|v| DateTime::parse_from_rfc2822(&v).ok())
                .map(|t| t.with_timezone(&Utc)),
        }))
    }

    /// The SHA-256 the `.sha256` sidecar of the file at `path` holds, where
    /// the source serves one (`<hex>`, or `<hex>  <name>` as `sha256sum`
    /// prints it). A sidecar that holds no SHA-256 is none.
    pub async fn sidecar(&self, path: &str) -> Result<Option<String>, SourceError> {
        let url = self.file_url(&format!("{path}.sha256"));
        let document = match self.get_document(&url, "text/plain, */*").await {
            Ok(document) => document,
            // A server that keeps its sidecars from these credentials has
            // none for the import.
            Err(SourceError::Refused(_)) => None,
            Err(e) => return Err(e),
        };
        Ok(document.and_then(|(_, body)| parse_sidecar(&body)))
    }

    /// GET the file at `path` (streamed by the caller); `None` when the
    /// source has no file there.
    pub async fn download(&self, path: &str) -> Result<Option<reqwest::Response>, SourceError> {
        let url = self.file_url(path);
        let response = self
            .http
            .get(&url, RequestClass::Download, self.auth().as_ref())
            .await
            .map_err(|e| SourceError::of(e, &url))?;
        match response.status() {
            s if s.is_success() => Ok(Some(response)),
            StatusCode::NOT_FOUND | StatusCode::GONE => Ok(None),
            s => Err(SourceError::status(s, &url)),
        }
    }
}

fn header(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// A lowercase hex digest of `len` digits, if `s` is one.
fn hex_digest(s: &str, len: usize) -> Option<String> {
    (s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_ascii_lowercase())
}

/// The SHA-256 of a `.sha256` sidecar: its first word, 64 hex digits.
pub fn parse_sidecar(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body.get(..body.len().min(4096))?).ok()?;
    hex_digest(text.split_whitespace().next()?, 64)
}

fn rfc3339(value: Option<&JsonValue>) -> Option<DateTime<Utc>> {
    value
        .and_then(JsonValue::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

fn text(value: Option<&JsonValue>) -> Option<String> {
    value
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// A page of Nexus' asset listing (`{"items": [...], "continuationToken"}`).
pub fn parse_assets(body: &[u8]) -> Result<AssetPage, String> {
    #[derive(Deserialize)]
    struct Raw {
        items: Vec<Lenient>,
        #[serde(rename = "continuationToken", default)]
        continuation_token: Option<String>,
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let files = raw
        .items
        .into_iter()
        .filter_map(|Lenient(asset)| {
            // Nexus names a raw asset's path without a leading `/` (older
            // releases with one).
            let path = asset.get("path").and_then(JsonValue::as_str)?;
            let path = path.strip_prefix('/').unwrap_or(path).to_string();
            let checksum = |key: &str| {
                asset
                    .get("checksum")
                    .and_then(|c| c.get(key))
                    .and_then(JsonValue::as_str)
                    .and_then(|s| hex_digest(s, s.len()))
                    .filter(|s| !s.is_empty())
            };
            Some(Listed {
                path,
                size: asset.get("fileSize").and_then(JsonValue::as_u64),
                content_type: text(asset.get("contentType")),
                sha1: checksum("sha1").filter(|s| s.len() == 40),
                sha256: checksum("sha256").filter(|s| s.len() == 64),
                sha512: checksum("sha512").filter(|s| s.len() == 128),
                sidecar: false,
                created: rfc3339(asset.get("blobCreated")).or(rfc3339(asset.get("lastModified"))),
                downloaded: rfc3339(asset.get("lastDownloaded")),
                uploader: text(asset.get("uploader")),
            })
        })
        .collect();
    Ok(AssetPage {
        files,
        next: raw.continuation_token.filter(|t| !t.is_empty()),
    })
}

/// A page of another Forge's listing (`{"entries": [...], "next"}`); a
/// file's `path` is its name, the caller prefixes its directory.
pub fn parse_directory(body: &[u8]) -> Result<DirectoryPage, String> {
    #[derive(Deserialize)]
    struct Raw {
        entries: Vec<Map<String, JsonValue>>,
        #[serde(default)]
        next: Option<String>,
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let mut entries = Vec::with_capacity(raw.entries.len());
    for entry in raw.entries {
        let Some(name) = entry.get("name").and_then(JsonValue::as_str) else {
            continue;
        };
        let directory = entry.get("type").and_then(JsonValue::as_str) == Some("directory");
        if directory {
            entries.push(Entry::Directory(
                name.strip_suffix('/').unwrap_or(name).to_string(),
            ));
            continue;
        }
        entries.push(Entry::File(Listed {
            path: name.to_string(),
            size: entry.get("size").and_then(JsonValue::as_u64),
            content_type: text(entry.get("content_type")),
            sha256: entry
                .get("sha256")
                .and_then(JsonValue::as_str)
                .and_then(|s| hex_digest(s, 64)),
            created: rfc3339(entry.get("last_modified")),
            downloaded: rfc3339(entry.get("last_downloaded")),
            ..Listed::default()
        }));
    }
    Ok(DirectoryPage {
        entries,
        next: raw.next.filter(|n| !n.is_empty()),
    })
}

/// A JSON object whose repeated keys keep their first non-null value. Nexus
/// 3.70 writes `"blobCreated": null` and then `"blobCreated": "<time>"`
/// into one asset object; a derived struct refuses the duplicate, and a
/// plain map keeps whichever comes last.
struct Lenient(Map<String, JsonValue>);

impl<'de> Deserialize<'de> for Lenient {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LenientVisitor;
        impl<'de> Visitor<'de> for LenientVisitor {
            type Value = Lenient;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Lenient, A::Error> {
                let mut out = Map::new();
                while let Some((key, value)) = map.next_entry::<String, JsonValue>()? {
                    let keep = out.get(&key).is_some_and(|v| !v.is_null()) && value.is_null();
                    if !keep {
                        out.insert(key, value);
                    }
                }
                Ok(Lenient(out))
            }
        }
        deserializer.deserialize_map(LenientVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An excerpt of what Nexus 3.70.1 answers for a raw repository, its
    /// repeated `blobCreated` included.
    const ASSETS: &str = r#"{
      "items" : [ {
        "downloadUrl" : "http://nexus.internal:8081/repository/raw-hosted/docs/a%20b%C3%BC.txt",
        "path" : "docs/a bü.txt",
        "id" : "cmF3LWhvc3RlZA",
        "repository" : "raw-hosted",
        "format" : "raw",
        "checksum" : {
          "sha1" : "90D195B301F7DB729F1B773536F21B6DA08ECE13",
          "sha512" : "ae206702ea661de518d6451ee5b76fe0120429239b73838301991a294bc2628c0b9bbe79d06b1ab0610a66e9ce7d7e16cdcbdc244058befefc03c5d9cce54357",
          "sha256" : "5D215626A671A8D27335E711C4FAD329D8674D5BC6DE7194E8A0B6E77AD0E560",
          "md5" : "8d777f385d3dfec8815d20f7496026dc"
        },
        "contentType" : "text/plain",
        "lastModified" : "2026-10-22T17:10:05.232+00:00",
        "lastDownloaded" : "2026-10-23T08:00:00.000+00:00",
        "uploader" : "admin",
        "uploaderIp" : "172.17.0.1",
        "fileSize" : 853,
        "blobCreated" : null,
        "blobCreated" : "2026-10-22T17:10:04.232+00:00"
      }, {
        "path" : "/old/style.bin",
        "checksum" : { "sha1" : "not a digest" },
        "contentType" : "application/octet-stream",
        "lastModified" : "2026-10-22T17:10:04.232+00:00",
        "lastDownloaded" : null,
        "fileSize" : 3
      } ],
      "continuationToken" : "770b204746f24a91"
    }"#;

    #[test]
    fn nexus_assets_are_read_with_their_repeated_keys() {
        let page = parse_assets(ASSETS.as_bytes()).unwrap();
        assert_eq!(page.next.as_deref(), Some("770b204746f24a91"));
        let file = &page.files[0];
        assert_eq!(file.path, "docs/a bü.txt");
        assert_eq!(file.size, Some(853));
        assert_eq!(file.content_type.as_deref(), Some("text/plain"));
        assert_eq!(
            file.sha256.as_deref(),
            Some("5d215626a671a8d27335e711c4fad329d8674d5bc6de7194e8a0b6e77ad0e560")
        );
        assert_eq!(
            file.sha1.as_deref(),
            Some("90d195b301f7db729f1b773536f21b6da08ece13")
        );
        assert_eq!(file.sha512.as_ref().map(String::len), Some(128));
        assert_eq!(
            file.created.unwrap().to_rfc3339(),
            "2026-10-22T17:10:04.232+00:00"
        );
        assert_eq!(
            file.downloaded.unwrap().to_rfc3339(),
            "2026-10-23T08:00:00+00:00"
        );
        assert_eq!(file.uploader.as_deref(), Some("admin"));

        // A leading `/` goes; a checksum that is none is left out; without
        // `blobCreated`, `lastModified` says when it was stored.
        let file = &page.files[1];
        assert_eq!(file.path, "old/style.bin");
        assert_eq!(file.sha1, None);
        assert_eq!(file.downloaded, None);
        assert_eq!(
            file.created.unwrap().to_rfc3339(),
            "2026-10-22T17:10:04.232+00:00"
        );

        let last = parse_assets(br#"{"items": [], "continuationToken": null}"#).unwrap();
        assert!(last.files.is_empty());
        assert_eq!(last.next, None);
        assert!(parse_assets(b"<html>").is_err());
        assert!(parse_assets(br#"{"entries": []}"#).is_err());
    }

    #[test]
    fn a_forge_listing_is_read_with_its_directories() {
        let body = br#"{
          "repository": "binaries", "path": "pdfium/",
          "entries": [
            {"name": "7350/", "path": "pdfium/7350/", "type": "directory"},
            {"name": "README.txt", "path": "pdfium/README.txt", "type": "file", "size": 1204,
             "content_type": "text/plain", "sha256": "5D215626A671A8D27335E711C4FAD329D8674D5BC6DE7194E8A0B6E77AD0E560",
             "last_modified": "2026-10-21T10:58:44.123456Z", "last_downloaded": "2026-10-22T10:00:00Z"}
          ],
          "next": "README.txt"
        }"#;
        let page = parse_directory(body).unwrap();
        assert_eq!(page.next.as_deref(), Some("README.txt"));
        assert_eq!(page.entries[0], Entry::Directory("7350".into()));
        let Entry::File(file) = &page.entries[1] else {
            panic!("{:?}", page.entries[1]);
        };
        assert_eq!(file.path, "README.txt");
        assert_eq!(file.size, Some(1204));
        assert_eq!(
            file.sha256.as_deref(),
            Some("5d215626a671a8d27335e711c4fad329d8674d5bc6de7194e8a0b6e77ad0e560")
        );
        assert_eq!(
            file.created
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            "2026-10-21T10:58:44.123456Z"
        );
        assert!(file.downloaded.is_some());
        assert!(parse_directory(b"<html><body>Index of /</body></html>").is_err());
        assert!(parse_directory(br#"{"items": []}"#).is_err());
    }

    #[test]
    fn sidecars_hold_the_digest_first() {
        let sha = "5d215626a671a8d27335e711c4fad329d8674d5bc6de7194e8a0b6e77ad0e560";
        assert_eq!(parse_sidecar(sha.as_bytes()).as_deref(), Some(sha));
        assert_eq!(
            parse_sidecar(format!("{}  tool.tgz\n", sha.to_uppercase()).as_bytes()).as_deref(),
            Some(sha)
        );
        assert_eq!(parse_sidecar(b"not a digest"), None);
        assert_eq!(parse_sidecar(b""), None);
        assert_eq!(parse_sidecar(&sha.as_bytes()[..63]), None);
    }

    fn file(path: &str) -> Entry {
        Entry::File(Listed {
            path: path.into(),
            ..Listed::default()
        })
    }

    #[test]
    fn a_walk_goes_down_into_each_directory_and_back_up_after_it() {
        let root = Walk::default();
        // Files up to the first subdirectory, then into it.
        let step = root.step(DirectoryPage {
            entries: vec![file("a.txt"), Entry::Directory("b".into()), file("c.txt")],
            next: None,
        });
        assert_eq!(step.files.len(), 1);
        let into_b = step.next.unwrap();
        assert_eq!(
            into_b,
            Walk {
                dir: "b/".into(),
                after: None
            }
        );
        // A page of b/ with more after it.
        let step = into_b.step(DirectoryPage {
            entries: vec![file("b/x")],
            next: Some("x".into()),
        });
        let more = step.next.unwrap();
        assert_eq!(more.dir, "b/");
        assert_eq!(more.after.as_deref(), Some("x"));
        // b/c/ goes down further; its end goes back up to b/ after c/.
        let into_c = more
            .step(DirectoryPage {
                entries: vec![Entry::Directory("c d".into())],
                next: None,
            })
            .next
            .unwrap();
        assert_eq!(into_c.dir, "b/c d/");
        let back = into_c.step(DirectoryPage::default()).next.unwrap();
        assert_eq!(
            back,
            Walk {
                dir: "b/".into(),
                after: Some("c d/".into())
            }
        );
        // The end of b/ goes back to the root after b/, where c.txt is read
        // again; the root's end is the walk's.
        let back = back.step(DirectoryPage::default()).next.unwrap();
        assert_eq!(
            back,
            Walk {
                dir: String::new(),
                after: Some("b/".into())
            }
        );
        let end = back.step(DirectoryPage {
            entries: vec![file("c.txt")],
            next: None,
        });
        assert_eq!(end.files.len(), 1);
        assert_eq!(end.next, None);

        // A cursor reads back as the walk it was.
        assert_eq!(Walk::parse(Some(&back.cursor())).unwrap(), back);
        assert_eq!(Walk::parse(None).unwrap(), root);
        assert!(Walk::parse(Some("garbage")).is_err());
    }

    #[test]
    fn a_directory_forge_refuses_is_not_walked() {
        let step = Walk::default().step(DirectoryPage {
            entries: vec![
                Entry::Directory("a\\b".into()),
                Entry::Directory("..".into()),
                file("ok.txt"),
            ],
            next: None,
        });
        assert_eq!(step.files.len(), 1);
        assert_eq!(step.next, None);
        let refused: Vec<&str> = step.refused.iter().map(|(dir, _)| dir.as_str()).collect();
        assert_eq!(refused, ["a\\b/", "../"]);
    }

    #[test]
    fn urls_are_built_from_the_import_url() {
        let source = RawSource::new(
            UpstreamHttp::shared_default(),
            "https://nexus.example.com/nexus/repository/raw-hosted/",
            None,
            None,
        );
        assert_eq!(
            source.file_url("docs/a bü+1.txt"),
            "https://nexus.example.com/nexus/repository/raw-hosted/docs/a%20b%C3%BC+1.txt"
        );
        assert_eq!(
            source.nexus(),
            Some(("https://nexus.example.com/nexus", "raw-hosted"))
        );
        assert_eq!(
            source.assets_url(Some("a b")).unwrap(),
            "https://nexus.example.com/nexus/service/rest/v1/assets?repository=raw-hosted&continuationToken=a+b"
        );
        assert_eq!(
            source.directory_url("a b/", Some("c/"), 100),
            "https://nexus.example.com/nexus/repository/raw-hosted/a%20b/?format=json&limit=100&after=c%2F"
        );
        for not_nexus in [
            "https://files.example.com/releases",
            "https://forge.example.com/repository/binaries/pdfium",
        ] {
            let source = RawSource::new(UpstreamHttp::shared_default(), not_nexus, None, None);
            assert_eq!(source.nexus(), None, "{not_nexus}");
        }
    }
}
