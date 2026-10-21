//! Shared HTTP plumbing for proxy-repository upstream traffic.
//!
//! One [`UpstreamHttp`] is built per server from the `[proxy]` config section
//! and shared by every proxy repository (and every proxy group member), so
//! upstream connections are pooled instead of re-established per request.
//!
//! It owns three concerns the proxy read path must never get wrong:
//!
//! * **Timeouts** — a connect timeout, an idle-read timeout (no bytes for
//!   `read_timeout` aborts the transfer, however large the package), and a
//!   total deadline per request class: metadata documents are small and get a
//!   short deadline, `.nupkg` downloads a long one so multi-hundred-MiB
//!   packages over slow links still complete.
//! * **Bounded bodies** — the size cap is enforced *while streaming*, never
//!   after buffering a whole response. Metadata bodies are spooled: up to
//!   `spool_memory_bytes` stay in memory, larger bodies roll over to an
//!   anonymous temp file that the OS reclaims as soon as it is dropped (also on
//!   every error path).
//! * **Credential scoping** — upstream Basic credentials are attached to every
//!   request whose host matches the configured `remote_url` host (service
//!   index, flat container, `.nuspec`, `.nupkg`), and to nothing else. A
//!   service index that points a resource at a foreign host therefore never
//!   receives the proxy's credentials; redirects to a different host are
//!   stripped of `Authorization` by reqwest itself.
//! * **No cloud-metadata targets** — a request, a redirect hop, or a host name
//!   resolving to a link-local / cloud-metadata address (`169.254.0.0/16`,
//!   `fe80::/10`, `fd00:ec2::254`, `metadata.google.internal`, …) is refused
//!   ([`is_metadata_target`]). Resource `@id`s and redirects are chosen by the
//!   upstream, not the admin, and such a target is never a package feed, but
//!   it is where a malicious upstream would bounce Forge to read instance
//!   credentials. Private and loopback upstreams stay allowed (12.7 §3.6).
//!   Behind an outbound proxy (`HTTP(S)_PROXY`) the proxy resolves host
//!   names, so only literal addresses and the well-known metadata names are
//!   refused there.
//! * **Encoded metadata** — a metadata body sent with `Content-Encoding: gzip`
//!   (nuget.org's `registration5-gz-*` documents always are) is inflated with
//!   the same size cap applied to the decoded bytes.

use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use serde_json::Value as JsonValue;
use url::Url;

/// Tuning for outbound proxy traffic. Built from the server's `[proxy]` config
/// section; [`Default`] carries the documented defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHttpConfig {
    /// TCP + TLS connect deadline.
    pub connect_timeout: Duration,
    /// Maximum idle time between two reads of a response body. Protects every
    /// transfer against a stalled peer independently of its total size.
    pub read_timeout: Duration,
    /// Total deadline for a metadata request (service index, version listing,
    /// `.nuspec`), including reading the body.
    pub metadata_timeout: Duration,
    /// Total deadline for a `.nupkg` download, including reading the body.
    /// Deliberately generous: large packages over slow links must complete.
    pub download_timeout: Duration,
    /// Upper bound on a metadata document.
    pub max_metadata_bytes: u64,
    /// Upper bound on a proxied `.nupkg`.
    pub max_package_bytes: u64,
    /// Bodies up to this size are kept in memory; larger ones spill to a
    /// self-deleting temp file.
    pub spool_memory_bytes: usize,
    /// Maximum redirect hops followed per request.
    pub max_redirects: usize,
}

impl Default for UpstreamHttpConfig {
    fn default() -> Self {
        UpstreamHttpConfig {
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(60),
            metadata_timeout: Duration::from_secs(60),
            download_timeout: Duration::from_secs(30 * 60),
            max_metadata_bytes: 32 * 1024 * 1024,
            max_package_bytes: 1024 * 1024 * 1024,
            spool_memory_bytes: 2 * 1024 * 1024,
            max_redirects: 5,
        }
    }
}

/// Errors raised by upstream requests.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// Transport failure, including connect/read/total timeouts.
    #[error("upstream GET {url}: {source}")]
    Transport {
        /// Requested URL (never carries credentials).
        url: String,
        /// Underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },
    /// The body exceeded its configured bound.
    #[error("upstream response from {url} exceeds {limit} bytes")]
    TooLarge {
        /// Requested URL.
        url: String,
        /// The bound that was exceeded.
        limit: u64,
    },
    /// The upstream answered with an unexpected status.
    #[error("upstream GET {url} returned {status}")]
    Status {
        /// Requested URL.
        url: String,
        /// Response status.
        status: reqwest::StatusCode,
    },
    /// Local spool / temp-file I/O failure.
    #[error("spool upstream body: {0}")]
    Io(#[from] std::io::Error),
    /// The body was not valid JSON.
    #[error("parse upstream JSON from {url}: {source}")]
    Json {
        /// Requested URL.
        url: String,
        /// Parser error.
        #[source]
        source: serde_json::Error,
    },
    /// The request targets a link-local / cloud-metadata endpoint
    /// ([`is_metadata_target`]).
    #[error("upstream GET {url}: refusing link-local / cloud-metadata target")]
    MetadataTarget {
        /// Requested URL.
        url: String,
    },
}

/// Host names of cloud instance-metadata services.
const METADATA_HOSTS: &[&str] = &[
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "metadata.tencentyun.com",
];

/// Whether `ip` is link-local or a well-known cloud-metadata address:
/// `169.254.0.0/16` (AWS, Azure, GCP, OCI, … IMDS), `100.100.100.200`
/// (Alibaba Cloud), `fe80::/10`, and `fd00:ec2::254` (AWS IMDS over IPv6).
/// IPv4-mapped IPv6 addresses are judged by their IPv4 form.
pub fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_link_local() || v4 == Ipv4Addr::new(100, 100, 100, 200),
        IpAddr::V6(v6) => {
            v6.is_unicast_link_local() || v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
        }
    }
}

/// Whether `host` (a DNS name) names a cloud instance-metadata service.
fn is_metadata_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    METADATA_HOSTS.contains(&host.as_str())
}

/// Whether `url` targets a link-local or cloud-metadata endpoint, by literal
/// address or well-known host name. Names that merely *resolve* to such an
/// address are refused by the client's resolver instead.
pub fn is_metadata_target(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => is_metadata_ip(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => is_metadata_ip(IpAddr::V6(ip)),
        Some(url::Host::Domain(name)) => is_metadata_host(name),
        None => false,
    }
}

/// A redirect hop refused because it targets a metadata endpoint.
#[derive(Debug, thiserror::Error)]
#[error("refusing redirect to link-local / cloud-metadata target {0}")]
struct MetadataRedirect(String);

/// System DNS resolution (`getaddrinfo` on the blocking pool, like reqwest's
/// default resolver) minus link-local / cloud-metadata addresses, so a host
/// name pointing at one is refused like the literal address.
struct MetadataGuardResolver;

impl reqwest::dns::Resolve for MetadataGuardResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let refused = || -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(std::io::Error::other(format!(
                    "{host} resolves only to link-local / cloud-metadata addresses"
                )))
            };
            if is_metadata_host(&host) {
                return Err(refused());
            }
            let lookup = host.clone();
            let addrs: Vec<SocketAddr> =
                tokio::task::spawn_blocking(move || (lookup.as_str(), 0).to_socket_addrs())
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)??
                    .filter(|addr| !is_metadata_ip(addr.ip()))
                    .collect();
            if addrs.is_empty() {
                return Err(refused());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Request class, selecting the total deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClass {
    /// Service index, version listing, `.nuspec`.
    Metadata,
    /// `.nupkg` download.
    Download,
}

/// Credentials for an upstream, scoped to the `remote_url` host.
pub struct UpstreamAuth<'a> {
    /// Host (and port) of the configured `remote_url`.
    pub origin: Option<Origin>,
    /// Basic-auth username.
    pub username: &'a str,
    /// Basic-auth password.
    pub password: &'a str,
}

/// Scheme + host + port triple used to scope credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Origin {
    /// The origin of `url`, or `None` if it does not parse or has no host.
    pub fn of(url: &str) -> Option<Origin> {
        let parsed = Url::parse(url).ok()?;
        Some(Origin {
            scheme: parsed.scheme().to_string(),
            host: parsed.host_str()?.to_ascii_lowercase(),
            port: parsed.port_or_known_default(),
        })
    }
}

/// Shared, pooled client for proxy upstream traffic.
#[derive(Clone)]
pub struct UpstreamHttp {
    client: reqwest::Client,
    config: Arc<UpstreamHttpConfig>,
}

impl std::fmt::Debug for UpstreamHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamHttp")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Process-wide default client, used when no explicit [`UpstreamHttp`] is
/// injected (tests, tooling). Built lazily so connection pooling still applies.
static DEFAULT_UPSTREAM: LazyLock<UpstreamHttp> = LazyLock::new(|| {
    UpstreamHttp::new(UpstreamHttpConfig::default()).expect("default upstream client builds")
});

impl UpstreamHttp {
    /// Build a client from `config`.
    pub fn new(config: UpstreamHttpConfig) -> Result<Self, reqwest::Error> {
        // Hop-capped like `Policy::limited`, and never towards a metadata
        // endpoint (the upstream picks redirect targets, not the admin).
        let limited = reqwest::redirect::Policy::limited(config.max_redirects);
        let redirect = reqwest::redirect::Policy::custom(move |attempt| {
            if is_metadata_target(attempt.url()) {
                let target = attempt.url().to_string();
                return attempt.error(MetadataRedirect(target));
            }
            limited.redirect(attempt)
        });
        let client = reqwest::Client::builder()
            .redirect(redirect)
            .dns_resolver(MetadataGuardResolver)
            .connect_timeout(config.connect_timeout)
            .read_timeout(config.read_timeout)
            .user_agent(concat!("envisia-forge/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(UpstreamHttp {
            client,
            config: Arc::new(config),
        })
    }

    /// The shared default client (see [`UpstreamHttpConfig::default`]).
    pub fn shared_default() -> Self {
        DEFAULT_UPSTREAM.clone()
    }

    /// The active tuning.
    pub fn config(&self) -> &UpstreamHttpConfig {
        &self.config
    }

    /// Issue a GET for `url`, attaching `auth` only when `url` shares the
    /// credential origin. Non-success statuses are returned to the caller
    /// (a 404 is meaningful to the proxy); only transport errors fail here.
    pub async fn get(
        &self,
        url: &str,
        class: RequestClass,
        auth: Option<&UpstreamAuth<'_>>,
    ) -> Result<reqwest::Response, UpstreamError> {
        let timeout = match class {
            RequestClass::Metadata => self.config.metadata_timeout,
            RequestClass::Download => self.config.download_timeout,
        };
        if Url::parse(url).is_ok_and(|u| is_metadata_target(&u)) {
            return Err(UpstreamError::MetadataTarget {
                url: url.to_string(),
            });
        }
        let mut req = self.client.get(url).timeout(timeout);
        if let Some(auth) = auth {
            if auth.origin.is_some() && auth.origin == Origin::of(url) {
                req = req.basic_auth(auth.username, Some(auth.password));
            } else {
                tracing::debug!(%url, "upstream resource is off-origin; not sending proxy credentials");
            }
        }
        req.send().await.map_err(|source| UpstreamError::Transport {
            url: url.to_string(),
            source,
        })
    }

    /// GET a JSON document. `Ok(None)` on a 404; any other non-2xx is an error.
    /// The body is size-bounded while streaming and spooled to disk past the
    /// in-memory threshold; parsing runs on the blocking pool.
    pub async fn get_json(
        &self,
        url: &str,
        auth: Option<&UpstreamAuth<'_>>,
    ) -> Result<Option<JsonValue>, UpstreamError> {
        let Some(spool) = self.get_metadata_body(url, auth).await? else {
            return Ok(None);
        };
        let url_owned = url.to_string();
        let parsed = tokio::task::spawn_blocking(move || {
            serde_json::from_reader::<_, JsonValue>(std::io::BufReader::new(spool.into_reader()?))
                .map_err(|source| UpstreamError::Json {
                    url: url_owned,
                    source,
                })
        })
        .await
        .map_err(|e| UpstreamError::Io(std::io::Error::other(e)))??;
        Ok(Some(parsed))
    }

    /// GET a small metadata body as bytes (e.g. a `.nuspec`). `Ok(None)` on 404.
    pub async fn get_bytes(
        &self,
        url: &str,
        auth: Option<&UpstreamAuth<'_>>,
    ) -> Result<Option<Vec<u8>>, UpstreamError> {
        let Some(spool) = self.get_metadata_body(url, auth).await? else {
            return Ok(None);
        };
        let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut out = Vec::new();
            spool.into_reader()?.read_to_end(&mut out)?;
            Ok(out)
        })
        .await
        .map_err(|e| UpstreamError::Io(std::io::Error::other(e)))??;
        Ok(Some(bytes))
    }

    /// GET a metadata body, size-capped and spooled; a gzip-encoded body is
    /// inflated (on the blocking pool) under the same cap.
    async fn get_metadata_body(
        &self,
        url: &str,
        auth: Option<&UpstreamAuth<'_>>,
    ) -> Result<Option<SpooledBody>, UpstreamError> {
        let resp = self.get(url, RequestClass::Metadata, auth).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(UpstreamError::Status {
                url: url.to_string(),
                status: resp.status(),
            });
        }
        let gzip = resp
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
        let limit = self.config.max_metadata_bytes;
        let threshold = self.config.spool_memory_bytes;
        let body = SpooledBody::read(resp, url, limit, threshold).await?;
        if !gzip {
            return Ok(Some(body));
        }
        let url_owned = url.to_string();
        let inflated =
            tokio::task::spawn_blocking(move || body.gunzip(&url_owned, limit, threshold))
                .await
                .map_err(|e| UpstreamError::Io(std::io::Error::other(e)))??;
        Ok(Some(inflated))
    }
}

/// A response body held in memory up to a threshold, then in an anonymous temp
/// file (unlinked on creation, reclaimed when dropped).
pub struct SpooledBody {
    inner: tempfile::SpooledTempFile,
    len: u64,
}

impl SpooledBody {
    /// Stream `resp` into a spool, failing as soon as more than `limit` bytes
    /// arrive (or the advertised `Content-Length` already exceeds it).
    pub async fn read(
        mut resp: reqwest::Response,
        url: &str,
        limit: u64,
        memory_threshold: usize,
    ) -> Result<SpooledBody, UpstreamError> {
        let too_large = || UpstreamError::TooLarge {
            url: url.to_string(),
            limit,
        };
        if resp.content_length().is_some_and(|len| len > limit) {
            return Err(too_large());
        }
        let mut inner = tempfile::SpooledTempFile::new(memory_threshold);
        let mut len: u64 = 0;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|source| UpstreamError::Transport {
                url: url.to_string(),
                source,
            })?
        {
            len += chunk.len() as u64;
            if len > limit {
                return Err(too_large());
            }
            if !inner.is_rolled() && len > memory_threshold as u64 {
                // Rolling over creates the temp file and copies the in-memory
                // prefix; do that (and all later file writes) off the reactor.
                inner = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
                    let mut inner = inner;
                    inner.roll()?;
                    inner.write_all(&chunk)?;
                    Ok(inner)
                })
                .await
                .map_err(std::io::Error::other)??;
            } else if inner.is_rolled() {
                inner = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
                    let mut inner = inner;
                    inner.write_all(&chunk)?;
                    Ok(inner)
                })
                .await
                .map_err(std::io::Error::other)??;
            } else {
                inner.write_all(&chunk)?;
            }
        }
        Ok(SpooledBody { inner, len })
    }

    /// Number of bytes spooled.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the body spilled to disk.
    pub fn is_on_disk(&self) -> bool {
        self.inner.is_rolled()
    }

    /// Rewind and hand out a blocking reader over the body.
    pub fn into_reader(mut self) -> std::io::Result<impl Read + Seek> {
        self.inner.seek(SeekFrom::Start(0))?;
        Ok(self.inner)
    }

    /// Inflate a gzip-encoded body into a new spool, failing as soon as the
    /// decoded size exceeds `limit`. Blocking: call from the blocking pool.
    fn gunzip(
        self,
        url: &str,
        limit: u64,
        memory_threshold: usize,
    ) -> Result<SpooledBody, UpstreamError> {
        let mut decoder = flate2::read::GzDecoder::new(self.into_reader()?);
        let mut inner = tempfile::SpooledTempFile::new(memory_threshold);
        let len = std::io::copy(
            &mut (&mut decoder).take(limit.saturating_add(1)),
            &mut inner,
        )?;
        if len > limit {
            return Err(UpstreamError::TooLarge {
                url: url.to_string(),
                limit,
            });
        }
        Ok(SpooledBody { inner, len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_matches_scheme_host_and_default_port() {
        let a = Origin::of("https://Feed.Example.com/v3/index.json").unwrap();
        let b = Origin::of("https://feed.example.com:443/flat/x/index.json").unwrap();
        assert_eq!(a, b);
        assert_ne!(
            a,
            Origin::of("http://feed.example.com/v3/index.json").unwrap()
        );
        assert_ne!(
            a,
            Origin::of("https://evil.example.com/v3/index.json").unwrap()
        );
        assert_ne!(a, Origin::of("https://feed.example.com:8443/").unwrap());
    }

    #[test]
    fn default_client_builds_with_generous_download_deadline() {
        let http = UpstreamHttp::shared_default();
        assert!(http.config().download_timeout >= Duration::from_secs(600));
        assert_eq!(http.config().spool_memory_bytes, 2 * 1024 * 1024);
    }

    #[tokio::test]
    async fn spool_keeps_small_bodies_in_memory_and_spills_large_ones() {
        use axum_like_server::serve_bytes;

        let small = serve_bytes(vec![b'a'; 1024]).await;
        let resp = reqwest::get(&small).await.unwrap();
        let body = SpooledBody::read(resp, &small, 1 << 20, 4096)
            .await
            .unwrap();
        assert_eq!(body.len(), 1024);
        assert!(!body.is_on_disk());

        let big = serve_bytes(vec![b'b'; 64 * 1024]).await;
        let resp = reqwest::get(&big).await.unwrap();
        let body = SpooledBody::read(resp, &big, 1 << 20, 4096).await.unwrap();
        assert_eq!(body.len(), 64 * 1024);
        assert!(body.is_on_disk());
        let mut out = Vec::new();
        body.into_reader().unwrap().read_to_end(&mut out).unwrap();
        assert!(out.iter().all(|b| *b == b'b'));

        let resp = reqwest::get(&big).await.unwrap();
        let err = SpooledBody::read(resp, &big, 1000, 4096)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, UpstreamError::TooLarge { limit: 1000, .. }));
    }

    #[test]
    fn metadata_targets_are_link_local_and_cloud_metadata_only() {
        let target = |u: &str| is_metadata_target(&Url::parse(u).unwrap());
        for bad in [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.0.1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[fe80::1]/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://METADATA.GOOGLE.INTERNAL./computeMetadata/v1/",
            "http://metadata/computeMetadata/v1/",
            "http://instance-data/latest/",
        ] {
            assert!(target(bad), "{bad} must be refused");
        }
        // Private and loopback upstreams are legitimate (12.7 §3.6).
        for ok in [
            "https://api.nuget.org/v3/index.json",
            "http://127.0.0.1:8081/repository/nuget/index.json",
            "http://10.0.0.5/v3/index.json",
            "http://192.168.1.10/v3/index.json",
            "http://[fd00::5]/v3/index.json",
            "http://nexus.internal/v3/index.json",
        ] {
            assert!(!target(ok), "{ok} must stay allowed");
        }
    }

    #[tokio::test]
    async fn redirect_to_a_metadata_endpoint_is_refused() {
        use axum_like_server::serve_raw;

        let http = UpstreamHttp::new(UpstreamHttpConfig::default()).unwrap();
        let redirect = serve_raw(
            b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/iam/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
        .await;
        let err = http.get_bytes(&redirect, None).await.unwrap_err();
        match &err {
            UpstreamError::Transport { source, .. } => {
                assert!(source.is_redirect(), "{err}");
                let chain = format!("{source:?}");
                assert!(chain.contains("MetadataRedirect"), "{chain}");
            }
            other => panic!("expected a refused redirect, got {other}"),
        }

        // A redirect to another (loopback) host is still followed.
        let target = serve_raw(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        )
        .await;
        let hop = serve_raw(
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            )
            .into_bytes(),
        )
        .await;
        assert_eq!(http.get_bytes(&hop, None).await.unwrap().unwrap(), b"ok");

        // A literal metadata URL is refused before any connection is made.
        assert!(matches!(
            http.get_bytes("http://169.254.169.254/latest/meta-data/", None)
                .await
                .unwrap_err(),
            UpstreamError::MetadataTarget { .. }
        ));
    }

    #[tokio::test]
    async fn resolver_drops_metadata_addresses() {
        use reqwest::dns::Resolve;

        let resolve = |host: &str| MetadataGuardResolver.resolve(host.parse().unwrap());
        let addrs: Vec<SocketAddr> = resolve("localhost").await.unwrap().collect();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
        assert!(resolve("metadata.google.internal").await.is_err());
        assert!(!is_metadata_ip("127.0.0.1".parse().unwrap()));
        assert!(is_metadata_ip("169.254.169.254".parse().unwrap()));
    }

    #[tokio::test]
    async fn gzip_encoded_metadata_is_inflated_under_the_cap() {
        use axum_like_server::serve_raw;
        use std::io::Write as _;

        let doc = serde_json::json!({ "items": [ { "lower": "1.0.0" } ] });
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(doc.to_string().as_bytes()).unwrap();
        let body = gz.finish().unwrap();
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(&body);
        let url = serve_raw(resp.clone()).await;

        let http = UpstreamHttp::new(UpstreamHttpConfig::default()).unwrap();
        assert_eq!(http.get_json(&url, None).await.unwrap().unwrap(), doc);

        // The cap applies to the decoded bytes, not just the compressed ones.
        let tight = UpstreamHttp::new(UpstreamHttpConfig {
            max_metadata_bytes: 8,
            ..UpstreamHttpConfig::default()
        })
        .unwrap();
        let url = serve_raw(resp).await;
        assert!(matches!(
            tight.get_json(&url, None).await.unwrap_err(),
            UpstreamError::TooLarge { limit: 8, .. }
        ));
    }

    /// Minimal one-route HTTP server for the spool tests (no extra deps).
    mod axum_like_server {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// Answer every request with the fixed raw `response` bytes and return
        /// the server's URL.
        pub async fn serve_raw(response: Vec<u8>) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let response = response.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let _ = sock.read(&mut buf).await;
                        let _ = sock.write_all(&response).await;
                    });
                }
            });
            format!("http://{addr}/")
        }

        /// Serve `body` (chunked, no Content-Length) on an ephemeral port and
        /// return its URL. The server answers any number of requests.
        pub async fn serve_bytes(body: Vec<u8>) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let body = body.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let _ = sock.read(&mut buf).await;
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                        for part in body.chunks(1000) {
                            let _ = sock
                                .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                                .await;
                            let _ = sock.write_all(part).await;
                            let _ = sock.write_all(b"\r\n").await;
                        }
                        let _ = sock.write_all(b"0\r\n\r\n").await;
                    });
                }
            });
            format!("http://{addr}/")
        }
    }
}
