//! The parts of the Nexus Repository 3 REST API an import reads:
//!
//! * `GET /service/rest/v1/status`: the server is up; its `Server` header
//!   names the version (`Nexus/3.70.1-02 (OSS)`);
//! * `GET /service/rest/v1/repositories`: name, format and type of each
//!   repository the credentials may see;
//! * `GET /service/rest/v1/components?repository=<name>` and
//!   `…/assets?repository=<name>`, paged with `continuationToken`;
//! * `<base>/repository/<name>/<asset path>`: an asset's content.
//!
//! Requests go through the shared [`UpstreamHttp`] client (timeouts, size
//! caps, no cloud-metadata targets); the credentials are sent to the Nexus
//! origin only. Download URLs are built from the import's base URL and the
//! asset's path rather than taken from Nexus' `downloadUrl`, which carries
//! Nexus' configured base URL and may name a host Forge does not reach the
//! server on.

use chrono::{DateTime, Utc};
use forge_core::net::upstream::{Origin, RequestClass, UpstreamAuth, UpstreamError, UpstreamHttp};
use forge_crypto::{ExposeSecret, PlaintextSecret};
use reqwest::StatusCode;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};

/// What went wrong talking to Nexus.
#[derive(Debug, thiserror::Error)]
pub enum NexusError {
    /// The server could not be reached, or the transfer failed.
    #[error("Nexus is unreachable: {0}")]
    Unreachable(String),
    /// The credentials were refused (or may not see the resource).
    #[error("Nexus refused the credentials ({status}) for {url}")]
    Refused { status: StatusCode, url: String },
    /// Any other answer than the one asked for.
    #[error("Nexus answered {status} for {url}")]
    Status { status: StatusCode, url: String },
    /// The answer was not the document the API describes.
    #[error("Nexus answered an unexpected document for {url}: {error}")]
    Invalid { url: String, error: String },
}

impl NexusError {
    /// Whether trying again later may succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            NexusError::Unreachable(_) => true,
            NexusError::Status { status, .. } => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
            NexusError::Refused { .. } | NexusError::Invalid { .. } => false,
        }
    }

    fn from_upstream(e: UpstreamError, url: &str) -> Self {
        match e {
            UpstreamError::Status { status, url } => status_error(status, url),
            UpstreamError::Json { source, .. } => NexusError::Invalid {
                url: url.to_string(),
                error: source.to_string(),
            },
            other => NexusError::Unreachable(other.to_string()),
        }
    }
}

fn status_error(status: StatusCode, url: String) -> NexusError {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        NexusError::Refused { status, url }
    } else {
        NexusError::Status { status, url }
    }
}

/// A repository as `GET /service/rest/v1/repositories` lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct NexusRepository {
    pub name: String,
    /// `nuget`, `docker`, `helm`, `apt`, `maven2`, …
    pub format: String,
    /// `hosted`, `proxy` or `group`.
    #[serde(rename = "type")]
    pub kind: String,
}

/// The two listings an import walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    Components,
    Assets,
}

impl Listing {
    pub fn as_str(self) -> &'static str {
        match self {
            Listing::Components => "components",
            Listing::Assets => "assets",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "assets" => Listing::Assets,
            _ => Listing::Components,
        }
    }
}

/// An asset as an import keeps it (the item's `source`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAsset {
    /// The path within the repository (`Sample.Lib/1.0.0`,
    /// `v2/team/app/manifests/1.0`).
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
    /// `blobCreated`: when these bytes were stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    /// `lastModified`: when the path last changed (a tag last moved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<DateTime<Utc>>,
    /// `lastDownloaded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downloaded: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploader: Option<String>,
}

impl SourceAsset {
    /// Read an asset object of either listing. `None` without a path.
    fn from_object(object: &Map<String, JsonValue>) -> Option<Self> {
        let text = |key: &str| {
            object
                .get(key)
                .and_then(JsonValue::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let time = |key: &str| {
            object
                .get(key)
                .and_then(JsonValue::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&Utc))
        };
        let checksum = |key: &str| {
            object
                .get("checksum")
                .and_then(|c| c.get(key))
                .and_then(JsonValue::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_lowercase)
        };
        Some(SourceAsset {
            path: text("path")?,
            content_type: text("contentType"),
            size: object.get("fileSize").and_then(JsonValue::as_i64),
            sha1: checksum("sha1"),
            sha256: checksum("sha256"),
            sha512: checksum("sha512"),
            created: time("blobCreated"),
            modified: time("lastModified"),
            downloaded: time("lastDownloaded"),
            uploader: text("uploader"),
        })
    }
}

/// A component (or, for Docker, a manifest held by digest) as an import
/// keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceItem {
    /// The package id or image name.
    pub name: String,
    /// The version, tag, or manifest digest.
    pub version: String,
    pub assets: Vec<SourceAsset>,
}

/// One page of a listing.
#[derive(Debug, Default)]
pub struct Page {
    /// Components (a components listing), or every asset (an assets
    /// listing) as one-asset items without a name or version.
    pub items: Vec<SourceItem>,
    /// The token of the next page; `None` on the last.
    pub next: Option<String>,
}

/// A client of one Nexus server.
pub struct Nexus {
    http: UpstreamHttp,
    base: String,
    origin: Option<Origin>,
    username: Option<String>,
    password: Option<PlaintextSecret>,
}

impl Nexus {
    /// A client of the Nexus at `base_url` (a context path included, no
    /// trailing `/`), with Basic credentials when both are given.
    pub fn new(
        http: UpstreamHttp,
        base_url: &str,
        username: Option<String>,
        password: Option<PlaintextSecret>,
    ) -> Self {
        let base = base_url.trim_end_matches('/').to_string();
        Nexus {
            origin: Origin::of(&base),
            http,
            base,
            username,
            password,
        }
    }

    fn auth(&self) -> Option<UpstreamAuth<'_>> {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => Some(UpstreamAuth {
                origin: self.origin.clone(),
                username,
                password: password.expose_secret(),
                bearer: false,
            }),
            _ => None,
        }
    }

    fn api(&self, path: &str, query: &[(&str, &str)]) -> String {
        let mut url = format!("{}/service/rest/v1/{path}", self.base);
        if !query.is_empty() {
            url.push('?');
            url.push_str(
                &url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(query)
                    .finish(),
            );
        }
        url
    }

    /// GET a JSON document of the API and parse it as `T`.
    async fn get<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, NexusError> {
        let bytes = self
            .http
            .get_bytes(url, self.auth().as_ref())
            .await
            .map_err(|e| NexusError::from_upstream(e, url))?
            .ok_or_else(|| NexusError::Status {
                status: StatusCode::NOT_FOUND,
                url: url.to_string(),
            })?;
        serde_json::from_slice(&bytes).map_err(|e| NexusError::Invalid {
            url: url.to_string(),
            error: e.to_string(),
        })
    }

    /// The server's version (its `Server` header), checking that it is up
    /// and is Nexus Repository 3.
    pub async fn status(&self) -> Result<String, NexusError> {
        let url = self.api("status", &[]);
        let response = self
            .http
            .get(&url, RequestClass::Metadata, self.auth().as_ref())
            .await
            .map_err(|e| NexusError::from_upstream(e, &url))?;
        if !response.status().is_success() {
            return Err(status_error(response.status(), url));
        }
        let server = response
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if !server.starts_with("Nexus/") {
            return Err(NexusError::Invalid {
                url,
                error: format!("not a Nexus Repository 3 server (Server: {server:?})"),
            });
        }
        Ok(server)
    }

    /// The repository `name`, if the credentials may see it.
    pub async fn repository(&self, name: &str) -> Result<Option<NexusRepository>, NexusError> {
        let url = self.api("repositories", &[]);
        let repositories: Vec<NexusRepository> = self.get(&url).await?;
        Ok(repositories.into_iter().find(|r| r.name == name))
    }

    /// One page of `listing` of `repository`, after `cursor`.
    pub async fn page(
        &self,
        listing: Listing,
        repository: &str,
        cursor: Option<&str>,
    ) -> Result<Page, NexusError> {
        let mut query = vec![("repository", repository)];
        if let Some(cursor) = cursor {
            query.push(("continuationToken", cursor));
        }
        let url = self.api(listing.as_str(), &query);
        let raw: RawPage = self.get(&url).await?;
        let items = match listing {
            Listing::Components => raw
                .items
                .iter()
                .filter_map(|item| {
                    let component: RawComponent =
                        serde_json::from_value(JsonValue::Object(item.0.clone())).ok()?;
                    Some(SourceItem {
                        name: component.name?,
                        version: component.version?,
                        assets: component
                            .assets
                            .iter()
                            .filter_map(|asset| SourceAsset::from_object(&asset.0))
                            .collect(),
                    })
                })
                .collect(),
            Listing::Assets => raw
                .items
                .iter()
                .filter_map(|item| SourceAsset::from_object(&item.0))
                .map(|asset| SourceItem {
                    name: String::new(),
                    version: String::new(),
                    assets: vec![asset],
                })
                .collect(),
        };
        Ok(Page {
            items,
            next: raw.continuation_token.filter(|t| !t.is_empty()),
        })
    }

    /// The URL of the asset at `path` in `repository`.
    pub fn content_url(&self, repository: &str, path: &str) -> String {
        let mut url = format!("{}/repository/", self.base);
        let segments = std::iter::once(repository).chain(path.split('/'));
        let encoded: Vec<String> = segments.map(percent_encode_segment).collect();
        url.push_str(&encoded.join("/"));
        url
    }

    /// GET the content of an asset (streamed by the caller).
    pub async fn download(&self, url: &str) -> Result<reqwest::Response, NexusError> {
        let response = self
            .http
            .get(url, RequestClass::Download, self.auth().as_ref())
            .await
            .map_err(|e| NexusError::from_upstream(e, url))?;
        if !response.status().is_success() {
            return Err(status_error(response.status(), url.to_string()));
        }
        Ok(response)
    }

    /// Whether `url` answers the registry API (`/v2/`): 200, or a 401
    /// challenge.
    pub async fn probe_registry(&self, url: &str) -> Result<(), NexusError> {
        let response = self
            .http
            .get(url, RequestClass::Metadata, self.auth().as_ref())
            .await
            .map_err(|e| NexusError::from_upstream(e, url))?;
        let status = response.status();
        let answers = status.is_success()
            || (status == StatusCode::UNAUTHORIZED
                && response
                    .headers()
                    .contains_key(reqwest::header::WWW_AUTHENTICATE));
        if answers {
            Ok(())
        } else {
            Err(status_error(status, url.to_string()))
        }
    }
}

/// Percent-encode one path segment (RFC 3986 `pchar`, minus the
/// sub-delimiters a server might treat specially).
fn percent_encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'@' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[derive(Deserialize)]
struct RawPage {
    #[serde(default)]
    items: Vec<Lenient>,
    #[serde(rename = "continuationToken", default)]
    continuation_token: Option<String>,
}

#[derive(Deserialize)]
struct RawComponent {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    assets: Vec<Lenient>,
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

    /// An excerpt of what Nexus 3.70.1 answers, its repeated `blobCreated`
    /// included.
    const COMPONENTS: &str = r#"{
      "items" : [ {
        "id" : "bnVnZXQtaG9zdGVk",
        "repository" : "nuget-hosted",
        "format" : "nuget",
        "group" : null,
        "name" : "Sample.Lib",
        "version" : "1.02.3",
        "assets" : [ {
          "downloadUrl" : "http://nexus.internal:8081/repository/nuget-hosted/Sample.Lib/1.02.3",
          "path" : "Sample.Lib/1.02.3",
          "checksum" : {
            "sha1" : "90d195b301f7db729f1b773536f21b6da08ece13",
            "sha256" : "5D215626A671A8D27335E711C4FAD329D8674D5BC6DE7194E8A0B6E77AD0E560"
          },
          "contentType" : "application/zip",
          "lastModified" : "2026-10-22T17:10:04.232+00:00",
          "lastDownloaded" : null,
          "uploader" : "admin",
          "fileSize" : 853,
          "blobCreated" : null,
          "blobCreated" : "2026-10-22T17:10:04.232+00:00"
        } ]
      } ],
      "continuationToken" : "770b204746f24a91"
    }"#;

    #[test]
    fn components_are_read_with_their_repeated_keys() {
        let raw: RawPage = serde_json::from_str(COMPONENTS).unwrap();
        assert_eq!(raw.continuation_token.as_deref(), Some("770b204746f24a91"));
        let component: RawComponent =
            serde_json::from_value(JsonValue::Object(raw.items[0].0.clone())).unwrap();
        let asset = SourceAsset::from_object(&component.assets[0].0).unwrap();
        assert_eq!(asset.path, "Sample.Lib/1.02.3");
        assert_eq!(asset.size, Some(853));
        assert_eq!(
            asset.sha256.as_deref(),
            Some("5d215626a671a8d27335e711c4fad329d8674d5bc6de7194e8a0b6e77ad0e560")
        );
        assert_eq!(asset.uploader.as_deref(), Some("admin"));
        assert_eq!(asset.downloaded, None);
        assert_eq!(
            asset.created.unwrap().to_rfc3339(),
            "2026-10-22T17:10:04.232+00:00"
        );
    }

    #[test]
    fn a_later_null_does_not_hide_a_value() {
        let raw: Lenient = serde_json::from_str(r#"{"a": "x", "a": null, "b": null}"#).unwrap();
        assert_eq!(raw.0["a"], "x");
        assert!(raw.0["b"].is_null());
    }

    #[test]
    fn content_urls_encode_each_segment() {
        let nexus = Nexus::new(
            UpstreamHttp::shared_default(),
            "https://nexus.example.com/nexus/",
            None,
            None,
        );
        assert_eq!(
            nexus.content_url("nuget-hosted", "Sample.Lib/1.0.0+build 1"),
            "https://nexus.example.com/nexus/repository/nuget-hosted/Sample.Lib/1.0.0%2Bbuild%201"
        );
    }
}
