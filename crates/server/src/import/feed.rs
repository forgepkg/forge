//! A NuGet v3 feed as an import's source, read through the NuGet format's
//! own upstream protocol ([`Format::upstream`], the conversations a proxy
//! repository holds with its upstream):
//!
//! * the service index (`…/index.json`) resolves the feed's resources
//!   ([`UpstreamOp::Index`]);
//! * its search (`SearchQueryService`) names the package ids, a page at a
//!   time ([`Feed::search`]);
//! * its package base address lists each package's versions, unlisted ones
//!   included ([`Feed::versions`]), and serves the `.nupkg`
//!   ([`Feed::package_url`]);
//! * its registration says when each version was published, and its SHA-512
//!   where the feed lists one inline ([`Feed::metadata`]).
//!
//! Requests go only where the feed points: the origin of its service index,
//! and those its documents name ([`UpstreamOrigins`]). The credentials go to
//! the service index's origin alone, through the shared [`UpstreamHttp`]
//! client (timeouts, size caps, no cloud-metadata targets).

use std::sync::{Arc, Mutex};

use forge_core::format::Format;
use forge_core::net::origins::{named_origins, UpstreamOrigins};
use forge_core::net::upstream::{Origin, RequestClass, UpstreamAuth, UpstreamError, UpstreamHttp};
use forge_crypto::{ExposeSecret, PlaintextSecret};
use forge_format_api::{
    FetchResult, Fetched, PackageRef, PackageVersions, Remote, UpstreamAnswer, UpstreamOp,
    UpstreamStep, VersionMetadata,
};
use reqwest::StatusCode;

use super::SourceError;

/// Rounds of one conversation, and fetches in all: a version list or a
/// registration takes a few.
const MAX_ROUNDS: usize = 8;
const MAX_FETCHES: usize = 256;

/// A NuGet v3 feed.
pub struct Feed {
    http: UpstreamHttp,
    format: Arc<dyn Format>,
    /// The service index, and the resources it lists (once resolved).
    remote: Remote,
    origins: Mutex<UpstreamOrigins>,
    username: Option<String>,
    password: Option<PlaintextSecret>,
    /// The `Server` header the service index was served with.
    server: Option<String>,
}

impl Feed {
    /// The feed at `url` (its service index), resolved: its resources are
    /// known once this returns.
    pub async fn open(
        http: UpstreamHttp,
        format: Arc<dyn Format>,
        url: &str,
        username: Option<String>,
        password: Option<PlaintextSecret>,
    ) -> Result<Feed, SourceError> {
        let mut feed = Feed {
            http,
            format,
            remote: Remote {
                url: url.to_string(),
                index: None,
                options: Vec::new(),
            },
            origins: Mutex::new(UpstreamOrigins::new(url, [])),
            username,
            password,
            server: None,
        };
        // The service index once directly, for its `Server` header and a
        // plain answer to an unreachable or refusing feed.
        let response = feed
            .http
            .get(url, RequestClass::Metadata, feed.auth().as_ref())
            .await
            .map_err(SourceError::of)?;
        if !response.status().is_success() {
            return Err(SourceError::status(response.status(), url));
        }
        feed.server = response
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        match feed.converse(UpstreamOp::Index).await? {
            UpstreamAnswer::Index(index) => feed.remote.index = Some(index),
            other => {
                return Err(SourceError::Invalid(format!(
                    "{url} is no NuGet v3 service index: {}",
                    answer_text(&other)
                )))
            }
        }
        Ok(feed)
    }

    /// The `Server` header the service index was served with.
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// The Basic credentials, for the service index's origin only.
    fn auth(&self) -> Option<UpstreamAuth<'_>> {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => Some(UpstreamAuth {
                origin: Origin::of(&self.remote.url),
                username,
                password: password.expose_secret(),
                bearer: false,
            }),
            _ => None,
        }
    }

    /// A page of the feed's search for every package (prerelease and SemVer
    /// 2.0.0 versions included): its total and the ids, after `skip`.
    /// `None` when the feed offers no search.
    pub async fn search(
        &self,
        skip: u32,
        take: u32,
    ) -> Result<Option<(u64, Vec<String>)>, SourceError> {
        match self.converse(UpstreamOp::Packages { skip, take }).await? {
            UpstreamAnswer::Search(None) => Ok(None),
            UpstreamAnswer::Search(Some(page)) => Ok(Some((
                page.total,
                page.hits.into_iter().map(|hit| hit.id).collect(),
            ))),
            other => Err(unexpected("search", &other)),
        }
    }

    /// Every version of the package `id` the feed lists (normalized),
    /// unlisted ones included; `None` when it does not know the package.
    pub async fn versions(&self, id: &str) -> Result<Option<Vec<String>>, SourceError> {
        let id = self.format.lower_id(id);
        match self.converse(UpstreamOp::Versions(id)).await? {
            UpstreamAnswer::Versions(versions) => Ok(versions),
            other => Err(unexpected("versions", &other)),
        }
    }

    /// What the feed's registration says of `versions` of `id`: when each
    /// was published, whether it is listed, its SHA-512 where listed. Best
    /// effort: a version the registration does not have is left out.
    pub async fn metadata(
        &self,
        id: &str,
        versions: &[String],
    ) -> Result<Vec<VersionMetadata>, SourceError> {
        let wanted = PackageVersions {
            id: self.format.lower_id(id),
            versions: versions.to_vec(),
        };
        match self.converse(UpstreamOp::Metadata(wanted)).await? {
            UpstreamAnswer::Metadata(metadata) => Ok(metadata.versions),
            other => Err(unexpected("registration", &other)),
        }
    }

    /// Where the feed serves the package of `id` `version`: on an origin the
    /// feed names, or an error.
    pub async fn package_url(&self, id: &str, version: &str) -> Result<String, SourceError> {
        let target = PackageRef {
            id: self.format.lower_id(id),
            version: version.to_string(),
        };
        let url = match self.converse(UpstreamOp::Package(target)).await? {
            UpstreamAnswer::Package(url) => url,
            UpstreamAnswer::Located(location) => location.url,
            other => return Err(unexpected("package", &other)),
        };
        if !self.permits(&url) {
            return Err(SourceError::Invalid(format!(
                "the feed names the package at {url}, an origin it does not otherwise name"
            )));
        }
        Ok(url)
    }

    /// GET a package (streamed by the caller).
    pub async fn download(&self, url: &str) -> Result<reqwest::Response, SourceError> {
        let response = self
            .http
            .get(url, RequestClass::Download, self.auth().as_ref())
            .await
            .map_err(SourceError::of)?;
        if !response.status().is_success() {
            return Err(SourceError::status(response.status(), url));
        }
        Ok(response)
    }

    fn permits(&self, url: &str) -> bool {
        self.origins
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .permits(url)
    }

    /// One conversation of the format with the feed about `op`: the format
    /// names what to fetch, the feed's answers go back to it, until it
    /// answers. A failed answer after a fetch that failed is that fetch's
    /// failure (an unreachable or refusing feed).
    async fn converse(&self, op: UpstreamOp) -> Result<UpstreamAnswer, SourceError> {
        let mut fetched: Vec<FetchResult> = Vec::new();
        let mut trouble: Option<SourceError> = None;
        for _ in 0..MAX_ROUNDS {
            let (format, remote, round) = (self.format.clone(), self.remote.clone(), op.clone());
            let (step, back) = tokio::task::spawn_blocking(move || {
                let step = format.upstream(&remote, &round, &fetched);
                (step, fetched)
            })
            .await
            .map_err(|e| SourceError::Invalid(format!("the NuGet protocol: {e}")))?;
            fetched = back;
            let wanted =
                match step.map_err(|e| SourceError::Invalid(format!("the NuGet protocol: {e}")))? {
                    UpstreamStep::Done(UpstreamAnswer::Failed(reason)) => {
                        return Err(match trouble {
                            Some(trouble) => trouble,
                            None => SourceError::Invalid(reason),
                        })
                    }
                    UpstreamStep::Done(answer) => return Ok(answer),
                    UpstreamStep::Fetch(wanted) => wanted,
                };
            if wanted.is_empty() || fetched.len() + wanted.len() > MAX_FETCHES {
                return Err(SourceError::Invalid(format!(
                    "the NuGet protocol asked for {} fetches after {}",
                    wanted.len(),
                    fetched.len()
                )));
            }
            for fetch in wanted {
                let (outcome, status) = if !self.permits(&fetch.url) {
                    (
                        Fetched::Failed(format!(
                            "{}: not sent, its origin is neither the service index's nor one \
                             the feed names",
                            fetch.url
                        )),
                        None,
                    )
                } else {
                    let got = self
                        .http
                        .get_bytes_accepting(
                            &fetch.url,
                            self.auth().as_ref(),
                            fetch.accept.as_deref(),
                        )
                        .await;
                    match got {
                        Ok(Some(body)) => {
                            self.origins
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .extend(named_origins(&body));
                            (Fetched::Found(body), Some(200))
                        }
                        Ok(None) => (Fetched::NotFound, Some(404)),
                        Err(e) => {
                            let error = SourceError::of(e);
                            let status = error.status_code();
                            let reason = error.to_string();
                            trouble.get_or_insert(error);
                            (Fetched::Failed(reason), status)
                        }
                    }
                };
                fetched.push(FetchResult {
                    fetch,
                    outcome,
                    status,
                    headers: Vec::new(),
                });
            }
        }
        Err(SourceError::Invalid(format!(
            "the NuGet protocol needed more than {MAX_ROUNDS} rounds"
        )))
    }
}

/// What an answer was, for an error message.
fn answer_text(answer: &UpstreamAnswer) -> String {
    match answer {
        UpstreamAnswer::Failed(reason) => reason.clone(),
        other => format!("{other:?}"),
    }
}

fn unexpected(what: &str, answer: &UpstreamAnswer) -> SourceError {
    SourceError::Invalid(format!("the feed's {what}: {}", answer_text(answer)))
}

/// What tells the administrator that the document at `url` is larger than
/// the `limit` bytes Forge reads, and which setting holds the limit.
fn too_large(url: &str, limit: u64) -> String {
    format!(
        "{url} is larger than the {limit} bytes Forge reads of a metadata document; raise \
         `proxy.max_metadata_bytes` to read it"
    )
}

impl SourceError {
    /// A transport or status error of the upstream client. A document
    /// larger than Forge reads, a target Forge does not request and a
    /// redirect that does not end are the same on every try: they are
    /// [`SourceError::Invalid`], never retried, and say what to change.
    pub fn of(e: UpstreamError) -> Self {
        match e {
            UpstreamError::Status { status, url } => SourceError::status(status, &url),
            UpstreamError::TooLarge { url, limit } => SourceError::Invalid(too_large(&url, limit)),
            UpstreamError::MetadataTarget { url } => SourceError::Invalid(format!(
                "{url} is a link-local or cloud-metadata address, which Forge does not request"
            )),
            UpstreamError::TooManyRedirects { url, max } => SourceError::Invalid(format!(
                "{url} redirects more than {max} times; give the URL the source answers at"
            )),
            other @ (UpstreamError::Transport { .. } | UpstreamError::Io(_)) => {
                SourceError::Unreachable(other.to_string())
            }
        }
    }

    /// [`SourceError::of`] for a listing of every package: one larger than
    /// Forge reads also says that naming what to import reads no listing.
    pub fn of_listing(e: UpstreamError) -> Self {
        match e {
            UpstreamError::TooLarge { url, limit } => SourceError::Invalid(format!(
                "{}, or name the packages or scopes to import instead",
                too_large(&url, limit)
            )),
            other => SourceError::of(other),
        }
    }

    /// An answer of `status` for `url` that is not the one asked for.
    pub fn status(status: StatusCode, url: &str) -> Self {
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            SourceError::Refused(format!(
                "the source refused the credentials ({status}) for {url}"
            ))
        } else {
            SourceError::Status {
                status,
                url: url.to_string(),
            }
        }
    }

    fn status_code(&self) -> Option<u16> {
        match self {
            SourceError::Status { status, .. } => Some(status.as_u16()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://npm.example.com/-/all";

    /// The error is permanent: not retried by the worker, and a 400 of the
    /// preflight rather than its 502.
    fn permanent(e: UpstreamError) -> String {
        let error = SourceError::of(e);
        assert!(matches!(error, SourceError::Invalid(_)), "{error:?}");
        assert!(!error.is_transient(), "{error:?}");
        let text = error.to_string();
        assert!(!text.contains("unreachable"), "{text}");
        text
    }

    #[test]
    fn a_document_larger_than_forge_reads_is_permanent_and_names_the_limit_and_its_setting() {
        let too_large = || UpstreamError::TooLarge {
            url: URL.into(),
            limit: 33_554_432,
        };
        let text = permanent(too_large());
        assert!(text.contains(URL), "{text}");
        assert!(text.contains("33554432 bytes"), "{text}");
        assert!(text.contains("`proxy.max_metadata_bytes`"), "{text}");
        assert!(!text.contains("name the packages"), "{text}");

        // A listing of every package: naming what to import is the other way.
        let listing = SourceError::of_listing(too_large());
        assert!(!listing.is_transient(), "{listing:?}");
        let text = listing.to_string();
        assert!(text.contains("33554432 bytes"), "{text}");
        assert!(text.contains("`proxy.max_metadata_bytes`"), "{text}");
        assert!(
            text.contains("name the packages or scopes to import instead"),
            "{text}"
        );
    }

    #[test]
    fn a_refused_target_is_permanent_and_names_the_url() {
        let url = "http://169.254.169.254/latest/meta-data/";
        let text = permanent(UpstreamError::MetadataTarget { url: url.into() });
        assert!(text.contains(url), "{text}");
        assert!(text.contains("link-local or cloud-metadata"), "{text}");
    }

    #[test]
    fn too_many_redirects_are_permanent_and_name_the_url() {
        let text = permanent(UpstreamError::TooManyRedirects {
            url: URL.into(),
            max: 5,
        });
        assert!(text.contains(URL), "{text}");
        assert!(text.contains("more than 5 times"), "{text}");
    }

    #[test]
    fn a_listing_keeps_the_other_errors_as_they_are() {
        let error = SourceError::of_listing(UpstreamError::TooManyRedirects {
            url: URL.into(),
            max: 5,
        });
        assert!(matches!(error, SourceError::Invalid(_)), "{error:?}");
        let error = SourceError::of_listing(UpstreamError::Status {
            url: URL.into(),
            status: StatusCode::BAD_GATEWAY,
        });
        assert!(error.is_transient(), "{error:?}");
    }

    #[test]
    fn a_failed_transfer_is_still_retried() {
        let error = SourceError::of(UpstreamError::Io(std::io::Error::other("disk")));
        assert!(matches!(error, SourceError::Unreachable(_)), "{error:?}");
        assert!(error.is_transient());
    }
}
