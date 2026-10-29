//! The image store: the repositories of a format whose descriptor says
//! `Storage::Images` (Docker / OCI, `crates/formats/docker`) hold images,
//! with hosted, proxy and group repositories over Forge's CAS. The format
//! owns the client protocol under `/v2`; this module is everything else:
//!
//! * [`dispatch`]: the `/v2` request, routed and authorized here, then a
//!   conversation with the format ([`forge_plugin::api::images`]): the
//!   site (by path, or a repository's own host, `config.host`), the caller
//!   (registry Bearer tokens), RBAC, package selectors and token scopes on
//!   the image, where a change lands (a group's writable member), the
//!   offline mode, the queries and actions the format asks for, and the
//!   response hardening;
//! * [`token`], [`auth`]: the registry's Bearer tokens and the token service
//!   (`/v2/token`);
//! * [`push`], [`pull`], [`group`], [`proxy`]: upload sessions, chunks and
//!   cross-repository mounts, manifest commits and their references,
//!   immutable tags, the trusted-publishing ledger; manifests, blobs, tags
//!   and referrers of hosted, proxy and group repositories; an upstream
//!   registry's token exchange and caching;
//! * [`download`]: a proxy's first download of a layer, served while it
//!   arrives;
//! * [`gc`]: abandoned upload sessions and unreferenced blob links;
//! * [`import`]: copying images from another registry (a Nexus hosted
//!   repository) into a hosted repository, through the same store.

pub mod auth;
pub mod digest;
pub mod dispatch;
mod download;
pub mod gc;
mod group;
pub mod import;
mod proxy;
mod pull;
mod push;
pub mod token;

use std::sync::Arc;

use axum::http::{HeaderName, HeaderValue};
use forge_cache::Cache;
use forge_core::auth::authz::Authz;
use forge_core::auth::Principal;
use forge_core::authz::PackageFilter;
use forge_core::net::upstream::UpstreamHttp;
use forge_core::repo::PublishPolicy;
use forge_db::model::Repository;
use forge_plugin::api::images::ImageError;
use forge_plugin::FormatPlugin;
use forge_storage::{BlobStore, Cas};
use sqlx::PgPool;

pub use dispatch::registry_origin;
use token::TokenKeys;

/// Tunables of the registry (the server's `[docker]` section and friends).
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// `server.public_base_url`, without a trailing `/`.
    pub public_base_url: String,
    /// Largest blob (layer) a proxy downloads from its upstream.
    pub max_blob_bytes: u64,
    /// Largest blob a push to a hosted repository may carry when the
    /// repository has no upload limit of its own
    /// ([`Repository::max_upload_bytes`]).
    pub default_max_upload_bytes: u64,
    /// Lifetime of a registry Bearer token.
    pub token_ttl_seconds: u64,
    /// Outbox grace of released blob references.
    pub delete_grace: chrono::Duration,
    /// `groups.max_nesting_depth`.
    pub max_group_depth: u32,
    /// `docker.unreferenced_blob_ttl_seconds`: a blob link no manifest names
    /// is released after this long unused.
    pub unreferenced_blob_ttl: chrono::Duration,
}

impl RegistryConfig {
    /// How often a pull (or `HEAD`) of a blob records a use of its link: a
    /// tenth of the unreferenced-blob TTL, at most hourly. A link a client
    /// confirmed then stays at least nine tenths of the TTL, whereas an
    /// hourly record with the smallest TTL (an hour) could leave it none.
    pub fn link_touch_interval(&self) -> chrono::Duration {
        (self.unreferenced_blob_ttl / 10).min(chrono::Duration::hours(1))
    }
}

/// Builds the request-scoped policy that records a workload's publishes
/// (the trusted-publishing ledger) in the manifest transaction.
pub trait PublishRecorder: Send + Sync {
    fn for_repository(
        &self,
        repository: &Repository,
        role_filter: PackageFilter,
        role_replace_filter: PackageFilter,
    ) -> Arc<dyn PublishPolicy>;
}

/// Whether the workload principal of a registry token still stands. The
/// server answers it from its realms: like a workload key, a token stands
/// only while its realm is enabled with the configuration it was verified
/// under, and, when it was minted with a workload key, while that key has
/// not ended.
#[async_trait::async_trait]
pub trait WorkloadCheck: Send + Sync {
    async fn still_valid(&self, principal: &Principal) -> Result<bool, String>;
}

/// The registry: everything under the images format's mount (`/v2`).
#[derive(Clone)]
pub struct Registry {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub pool: PgPool,
    pub cas: Cas,
    pub store: BlobStore,
    pub cache: Cache,
    pub authz: Authz,
    pub http: UpstreamHttp,
    pub envelope: Arc<forge_crypto::service::EnvelopeService>,
    pub config: RegistryConfig,
    pub keys: TokenKeys,
    pub recorder: Option<Arc<dyn PublishRecorder>>,
    pub workloads: Option<Arc<dyn WorkloadCheck>>,
    /// The images format: the protocol.
    pub plugin: Arc<dyn FormatPlugin>,
}

/// Parts the registry is built from.
pub struct RegistryParts {
    pub pool: PgPool,
    pub cas: Cas,
    pub store: BlobStore,
    pub cache: Cache,
    pub authz: Authz,
    pub http: UpstreamHttp,
    pub envelope: Arc<forge_crypto::service::EnvelopeService>,
    pub config: RegistryConfig,
    pub keys: TokenKeys,
    pub recorder: Option<Arc<dyn PublishRecorder>>,
    pub workloads: Option<Arc<dyn WorkloadCheck>>,
    pub plugin: Arc<dyn FormatPlugin>,
}

impl Registry {
    pub fn new(parts: RegistryParts) -> Self {
        Registry {
            inner: Arc::new(Inner {
                pool: parts.pool,
                cas: parts.cas,
                store: parts.store,
                cache: parts.cache,
                authz: parts.authz,
                http: parts.http,
                envelope: parts.envelope,
                config: parts.config,
                keys: parts.keys,
                recorder: parts.recorder,
                workloads: parts.workloads,
                plugin: parts.plugin,
            }),
        }
    }

    pub fn config(&self) -> &RegistryConfig {
        &self.inner.config
    }

    /// The images format.
    pub(crate) fn plugin(&self) -> &dyn FormatPlugin {
        self.inner.plugin.as_ref()
    }

    /// The images format's id: `repository.format` of its repositories.
    pub(crate) fn format(&self) -> &'static str {
        self.inner.plugin.descriptor().id
    }

    /// Whether `repo` is a repository of the images format.
    pub(crate) fn serves(&self, repo: &Repository) -> bool {
        repo.format == self.format()
    }
}

/// What went wrong serving an image request: what the format answers
/// ([`ImageError`], [`FormatPlugin::image_error`]), the headers the host
/// adds to it (a Bearer challenge), and what to tell an administrator (an
/// import's report, the log).
#[derive(Debug, Clone)]
pub struct Failure {
    pub error: ImageError,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Said instead of the error's own description.
    text: Option<String>,
}

/// Result alias of the image store.
pub type ImgResult<T> = Result<T, Failure>;

impl Failure {
    pub fn new(error: ImageError) -> Self {
        Failure {
            error,
            headers: Vec::new(),
            text: None,
        }
    }

    /// Say `text` of it instead of the error's own description.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// The service cannot answer now (staging full, upstream down, offline
    /// repository): the client may retry.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Failure::new(ImageError::Unavailable(message.into()))
    }

    /// What the host does not do (405, or `status`).
    pub fn unsupported(status: u16, message: impl Into<String>) -> Self {
        Failure::new(ImageError::Unsupported {
            status,
            message: message.into(),
        })
    }

    /// An internal failure; the details go to the log, not the client.
    pub fn internal(context: &str, error: impl std::fmt::Display) -> Self {
        tracing::error!(error = %error, "registry: {context}");
        Failure::new(ImageError::Internal)
    }

    /// A failed read from the object store (through the local blob cache):
    /// unavailable while S3 cannot be reached, a server error otherwise.
    pub(crate) fn storage_read(context: &str, error: forge_storage::S3Error) -> Self {
        if error.is_unavailable() {
            tracing::warn!(%error, "registry: {context}: the object store is unavailable");
            Failure::object_store_unavailable()
        } else {
            Failure::internal(context, error)
        }
    }

    fn object_store_unavailable() -> Self {
        Failure::unavailable("the object store is unavailable; retry later")
    }

    /// What went wrong, for an administrator.
    pub fn message(&self) -> String {
        if let Some(text) = &self.text {
            return text.clone();
        }
        match &self.error {
            ImageError::NotAnEndpoint => "not a registry endpoint".into(),
            ImageError::NameInvalid { name, .. } => format!("invalid image name {name:?}"),
            ImageError::NameUnknown { name } => format!("no repository named by {name:?}"),
            ImageError::AuthenticationRequired { .. } => "authentication required".into(),
            ImageError::InvalidToken => "invalid or expired registry token".into(),
            ImageError::InvalidCredentials => "invalid credentials".into(),
            ImageError::Denied { name, .. } => format!("access to {name:?} denied"),
            ImageError::Unsupported { message, .. }
            | ImageError::ManifestInvalid(message)
            | ImageError::Unavailable(message) => message.clone(),
            ImageError::Offline => "the repository is offline".into(),
            ImageError::BlobUnknown { digest } => format!("blob {digest} unknown"),
            ImageError::ManifestUnknown { reference } => format!("manifest {reference} unknown"),
            ImageError::UploadUnknown => "upload unknown".into(),
            ImageError::DigestMismatch => "the content does not match its digest".into(),
            ImageError::ChunkOutOfOrder { .. } => "the chunk does not continue the upload".into(),
            ImageError::ChunkLength { .. } => {
                "the chunk length does not match its Content-Range".into()
            }
            ImageError::TooLarge { limit } => {
                format!("content exceeds the limit of {limit} bytes")
            }
            ImageError::BodyUnreadable => "the request body could not be read".into(),
            ImageError::ManifestBlobUnknown { digest, manifest } => format!(
                "the manifest references a {} the repository does not hold: {digest}",
                if *manifest { "manifest" } else { "blob" }
            ),
            ImageError::TagImmutable { tag } => {
                format!("tag {tag:?} already exists and tags are immutable in this repository")
            }
            ImageError::BlobReferenced { digest } => {
                format!("the blob {digest} is referenced by a manifest")
            }
            ImageError::NoLongerAllowed => {
                "the workload identity may no longer change this repository".into()
            }
            ImageError::RateLimited => "the upstream registry rate-limits; retry later".into(),
            ImageError::Internal => "internal error".into(),
        }
    }
}

impl From<ImageError> for Failure {
    fn from(error: ImageError) -> Self {
        Failure::new(error)
    }
}

impl From<sqlx::Error> for Failure {
    fn from(e: sqlx::Error) -> Self {
        forge_db::observe_error(&e);
        Failure::internal("database error", e)
    }
}

/// A request body that could not be read: the client aborted it, or it
/// stalled past the idle timeout. Travels inside the I/O error staging the
/// body fails with.
#[derive(Debug)]
pub(crate) struct RequestBodyError(pub axum::Error);

impl std::fmt::Display for RequestBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reading the request body: {}", self.0)
    }
}

impl std::error::Error for RequestBodyError {}

impl From<forge_storage::CasError> for Failure {
    fn from(e: forge_storage::CasError) -> Self {
        match e {
            forge_storage::CasError::TooLarge { limit } => {
                Failure::new(ImageError::TooLarge { limit })
            }
            forge_storage::CasError::StagingFull { .. } => {
                Failure::unavailable("temporary storage is full; retry later")
            }
            e if e.is_unavailable() => {
                tracing::warn!(error = %e, "registry: the object store is unavailable");
                Failure::object_store_unavailable()
            }
            forge_storage::CasError::Io(e)
                if e.get_ref()
                    .is_some_and(|inner| inner.is::<RequestBodyError>()) =>
            {
                tracing::debug!(error = %e, "registry: the upload body could not be read");
                Failure::new(ImageError::BodyUnreadable)
            }
            other => Failure::internal("storage error", other),
        }
    }
}

/// A header value from text Forge produced or validated.
pub(crate) fn header_value(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
}

#[cfg(test)]
mod tests {
    use forge_storage::{CasError, S3Error};

    use super::*;

    fn down() -> S3Error {
        S3Error::Unavailable("connection refused".into())
    }

    #[test]
    fn an_unavailable_object_store_is_worth_a_retry() {
        // Also when a stream read from S3 failed while it was staged (the
        // finish of a chunked upload).
        for e in [
            CasError::S3(down()),
            CasError::Io(std::io::Error::other(down())),
        ] {
            assert!(matches!(Failure::from(e).error, ImageError::Unavailable(_)));
        }
        let e = Failure::storage_read("blob read", down());
        assert!(matches!(e.error, ImageError::Unavailable(_)));
        let e = Failure::storage_read("blob read", S3Error::S3("access denied".into()));
        assert_eq!(e.error, ImageError::Internal);
    }

    #[test]
    fn an_unreadable_request_body_is_the_clients_error() {
        let aborted = std::io::Error::other(RequestBodyError(axum::Error::new(
            "connection reset by peer",
        )));
        let e = Failure::from(CasError::Io(aborted));
        assert_eq!(e.error, ImageError::BodyUnreadable);
        // Staging's own I/O errors stay server errors.
        let e = Failure::from(CasError::Io(std::io::Error::other("disk full")));
        assert_eq!(e.error, ImageError::Internal);
    }
}
