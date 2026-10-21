//! Where the S3 client's credentials come from (`s3.credentials`).
//!
//! * [`S3Credentials::Static`] — a long-lived access key / secret key pair.
//! * [`S3Credentials::DefaultChain`] — the AWS SDK default credentials chain:
//!   environment variables (with `AWS_SESSION_TOKEN`), the shared profile,
//!   web identity (IRSA's `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`), the
//!   container credentials endpoint (ECS task roles, EKS Pod Identity) and EC2
//!   instance metadata.
//! * [`S3Credentials::WebIdentity`] — a token file (a Kubernetes projected
//!   service-account token, or any OIDC token) exchanged for temporary keys
//!   with STS `AssumeRoleWithWebIdentity`, against AWS STS or the STS endpoint
//!   of an S3-compatible store (MinIO, Ceph RGW).
//!
//! The S3 client caches temporary credentials and fetches new ones shortly
//! before they expire ([`REFRESH_BEFORE_EXPIRY`]), so no request is signed
//! with expired keys. Each request is signed with the credentials current when it
//! is sent, so a multipart upload that outlives one set of credentials still
//! completes. Every web-identity fetch reads the token file again, which picks
//! up a token the kubelet rotated.
//!
//! A failed fetch fails the S3 call that needed the credentials with a message
//! that names the credential source ([`failure`]). The token and the derived
//! keys never appear in errors, logs or `Debug`.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::{future, ProvideCredentials, SharedCredentialsProvider};
use aws_credential_types::Credentials;
use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::error::SdkError;
use aws_sdk_sts::config::{BehaviorVersion, Region};
use aws_sdk_sts::error::{DisplayErrorContext, ProvideErrorMetadata};
use tokio::sync::OnceCell;

/// The S3 client's identity-cache buffer: it fetches new credentials this
/// long before the current ones expire, less a random jitter of up to half
/// of it (so 30 to 60 s before). Above the SDK's default of 10 s, so that a
/// clock running a little behind the STS issuer's, or a request slow to
/// reach S3, never presents expired credentials.
pub(crate) const REFRESH_BEFORE_EXPIRY: Duration = Duration::from_secs(60);

/// STS connect deadline.
const STS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for one STS attempt.
const STS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the S3 client's credentials come from. `Debug` shows the source and
/// its settings, never a secret.
#[derive(Clone, PartialEq, Eq)]
pub enum S3Credentials {
    /// A long-lived access key / secret key pair.
    Static {
        access_key: String,
        secret_key: String,
    },
    /// The AWS SDK default credentials chain, in the S3 region.
    DefaultChain,
    /// A token file exchanged for temporary keys via STS
    /// `AssumeRoleWithWebIdentity`.
    WebIdentity(WebIdentity),
}

impl S3Credentials {
    /// Static credentials from an access key and a secret key.
    pub fn from_keys(access_key: impl Into<String>, secret_key: impl Into<String>) -> Self {
        Self::Static {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
        }
    }

    /// The source's name as `s3.credentials` spells it.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Static { .. } => "static",
            Self::DefaultChain => "default_chain",
            Self::WebIdentity(_) => "web_identity",
        }
    }

    /// The SDK credentials provider for this source. `region` is the region
    /// STS and the default chain are asked in.
    pub(crate) fn provider(&self, region: &str) -> SharedCredentialsProvider {
        match self {
            Self::Static {
                access_key,
                secret_key,
            } => SharedCredentialsProvider::new(Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "forge-static",
            )),
            Self::DefaultChain => SharedCredentialsProvider::new(DefaultChain {
                region: region.to_string(),
                chain: OnceCell::new(),
            }),
            Self::WebIdentity(config) => {
                SharedCredentialsProvider::new(WebIdentityProvider::new(config.clone(), region))
            }
        }
    }
}

impl fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static { access_key, .. } => f
                .debug_struct("Static")
                .field("access_key", access_key)
                .field("secret_key", &"<redacted>")
                .finish(),
            Self::DefaultChain => f.write_str("DefaultChain"),
            Self::WebIdentity(config) => f.debug_tuple("WebIdentity").field(config).finish(),
        }
    }
}

/// The settings of [`S3Credentials::WebIdentity`]. Holds the token's path,
/// never the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebIdentity {
    /// The role to assume. `None` sends no `RoleArn`, which MinIO accepts
    /// for its claim-based policies; AWS requires one.
    pub role_arn: Option<String>,
    /// The file holding the token, read again for every fetch.
    pub token_file: PathBuf,
    /// The STS endpoint URL; `None` is AWS STS in the S3 region.
    pub sts_endpoint: Option<String>,
    /// `RoleSessionName`, which AWS CloudTrail records.
    pub session_name: String,
    /// The credentials' lifetime asked of STS; `None` leaves it to STS (one
    /// hour on AWS).
    pub duration_seconds: Option<u32>,
}

impl WebIdentity {
    /// The source as errors name it: the role and the STS endpoint.
    fn describe(&self) -> String {
        format!(
            "web_identity, role {}, token_file {}, STS {}",
            self.role_arn.as_deref().unwrap_or("<none>"),
            self.token_file.display(),
            self.sts_endpoint
                .as_deref()
                .unwrap_or("<AWS STS in the S3 region>"),
        )
    }
}

/// A failure to obtain S3 credentials. It travels inside the SDK's
/// [`CredentialsError`] to the S3 call that needed the credentials, where
/// [`failure`] finds it.
#[derive(Debug)]
pub(crate) struct CredentialsFailure {
    /// What failed, naming the source; never the token or a key.
    message: String,
    /// The credential endpoint could not be reached (as opposed to refusing).
    unreachable: bool,
}

impl CredentialsFailure {
    fn new(source: &str, unreachable: bool, reason: impl fmt::Display) -> Self {
        Self {
            message: format!("could not obtain S3 credentials ({source}): {reason}"),
            unreachable,
        }
    }

    /// Whether the credential endpoint (STS, the container endpoint, instance
    /// metadata) could not be reached, like an S3 that cannot be reached.
    pub(crate) fn is_unreachable(&self) -> bool {
        self.unreachable
    }

    fn into_error(self) -> CredentialsError {
        tracing::warn!(error = %self.message, "S3 credentials fetch failed");
        CredentialsError::provider_error(self)
    }
}

impl fmt::Display for CredentialsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CredentialsFailure {}

/// The credentials failure an S3 call failed with, if that is why it failed.
pub(crate) fn failure<E>(e: &SdkError<E, HttpResponse>) -> Option<&CredentialsFailure> {
    // The SDK resolves credentials before it sends a request and reports a
    // failure there as a dispatch failure.
    let SdkError::DispatchFailure(dispatch) = e else {
        return None;
    };
    let mut next: Option<&(dyn Error + 'static)> = dispatch
        .as_connector_error()
        .map(|c| c as &(dyn Error + 'static));
    while let Some(err) = next {
        if let Some(found) = err.downcast_ref::<CredentialsFailure>() {
            return Some(found);
        }
        next = err.source();
    }
    None
}

/// The default chain, built on first use: building it is async, and
/// [`crate::BlobStore::new`] is not.
#[derive(Debug)]
struct DefaultChain {
    region: String,
    chain: OnceCell<DefaultCredentialsChain>,
}

impl DefaultChain {
    async fn fetch(&self) -> aws_credential_types::provider::Result {
        let chain = self
            .chain
            .get_or_init(|| {
                DefaultCredentialsChain::builder()
                    .region(Region::new(self.region.clone()))
                    .build()
            })
            .await;
        chain.provide_credentials().await.map_err(|e| {
            let unreachable = matches!(e, CredentialsError::ProviderTimedOut(_));
            CredentialsFailure::new("default_chain", unreachable, DisplayErrorContext(&e))
                .into_error()
        })
    }
}

impl ProvideCredentials for DefaultChain {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(self.fetch())
    }
}

/// STS `AssumeRoleWithWebIdentity` with the token read from a file.
#[derive(Debug)]
struct WebIdentityProvider {
    config: WebIdentity,
    sts: aws_sdk_sts::Client,
}

impl WebIdentityProvider {
    fn new(config: WebIdentity, region: &str) -> Self {
        let mut sts = aws_sdk_sts::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.to_string()))
            .timeout_config(
                aws_sdk_sts::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(STS_CONNECT_TIMEOUT)
                    .operation_attempt_timeout(STS_ATTEMPT_TIMEOUT)
                    .build(),
            );
        if let Some(endpoint) = &config.sts_endpoint {
            sts = sts.endpoint_url(endpoint);
        }
        Self {
            config,
            sts: aws_sdk_sts::Client::from_conf(sts.build()),
        }
    }

    fn fail(&self, unreachable: bool, reason: impl fmt::Display) -> CredentialsError {
        CredentialsFailure::new(&self.config.describe(), unreachable, reason).into_error()
    }

    async fn fetch(&self) -> aws_credential_types::provider::Result {
        let path = &self.config.token_file;
        let token = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| self.fail(false, format_args!("read token_file: {e}")))?;
        // A token written with a trailing newline (`echo`, a Secret's file).
        let token = token.trim();
        if token.is_empty() {
            return Err(self.fail(false, "token_file is empty"));
        }
        let output = self
            .sts
            .assume_role_with_web_identity()
            .set_role_arn(self.config.role_arn.clone())
            .role_session_name(&self.config.session_name)
            .web_identity_token(token)
            .set_duration_seconds(
                self.config
                    .duration_seconds
                    .map(|s| i32::try_from(s).unwrap_or(i32::MAX)),
            )
            .send()
            .await
            .map_err(|e| {
                let unreachable = match &e {
                    SdkError::DispatchFailure(_) | SdkError::TimeoutError(_) => true,
                    SdkError::ServiceError(se) => se.raw().status().is_server_error(),
                    _ => false,
                };
                // The error code and message STS answered with; neither
                // repeats the token.
                let reason = match e.code() {
                    Some(code) => format!(
                        "STS AssumeRoleWithWebIdentity failed: {code}: {}",
                        e.message().unwrap_or("(no message)")
                    ),
                    None => format!(
                        "STS AssumeRoleWithWebIdentity failed: {}",
                        DisplayErrorContext(&e)
                    ),
                };
                self.fail(unreachable, reason)
            })?;
        let Some(credentials) = output.credentials else {
            return Err(self.fail(false, "STS answered without credentials"));
        };
        let expiry = SystemTime::try_from(credentials.expiration)
            .map_err(|e| self.fail(false, format_args!("STS expiration: {e}")))?;
        tracing::debug!(
            credentials = "web_identity",
            role_arn = self.config.role_arn.as_deref(),
            expires_in_seconds = expiry
                .duration_since(SystemTime::now())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "fetched temporary S3 credentials"
        );
        Ok(Credentials::new(
            credentials.access_key_id,
            credentials.secret_access_key,
            Some(credentials.session_token),
            Some(expiry),
            "forge-web-identity",
        ))
    }
}

impl ProvideCredentials for WebIdentityProvider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(self.fetch())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web_identity() -> WebIdentity {
        WebIdentity {
            role_arn: Some("arn:aws:iam::123456789012:role/forge".into()),
            token_file: "/var/run/secrets/forge/s3/token".into(),
            sts_endpoint: Some("https://minio.example.com:9000".into()),
            session_name: "forge".into(),
            duration_seconds: Some(900),
        }
    }

    #[test]
    fn names_follow_the_config_values() {
        assert_eq!(S3Credentials::from_keys("a", "b").name(), "static");
        assert_eq!(S3Credentials::DefaultChain.name(), "default_chain");
        assert_eq!(
            S3Credentials::WebIdentity(web_identity()).name(),
            "web_identity"
        );
    }

    #[test]
    fn debug_never_shows_the_secret_key() {
        let shown = format!("{:?}", S3Credentials::from_keys("ak", "sk"));
        assert!(shown.contains("\"ak\""), "{shown}");
        assert!(!shown.contains("\"sk\""), "{shown}");
    }

    #[test]
    fn debug_shows_the_web_identity_settings() {
        let shown = format!("{:?}", S3Credentials::WebIdentity(web_identity()));
        for part in [
            "arn:aws:iam::123456789012:role/forge",
            "/var/run/secrets/forge/s3/token",
            "https://minio.example.com:9000",
        ] {
            assert!(shown.contains(part), "{shown}");
        }
    }

    #[tokio::test]
    async fn a_missing_token_file_names_the_source() {
        let mut config = web_identity();
        config.token_file = "/nonexistent/forge/token".into();
        let provider = WebIdentityProvider::new(config, "us-east-1");
        let err = provider.fetch().await.expect_err("no token file");
        let shown = DisplayErrorContext(&err).to_string();
        assert!(shown.contains("web_identity"), "{shown}");
        assert!(shown.contains("/nonexistent/forge/token"), "{shown}");
        assert!(
            shown.contains("arn:aws:iam::123456789012:role/forge"),
            "{shown}"
        );
    }

    #[tokio::test]
    async fn an_empty_token_file_is_refused_without_calling_sts() {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "\n").unwrap();
        let mut config = web_identity();
        config.token_file = token_file;
        // Nothing listens there: an STS call would fail differently.
        config.sts_endpoint = Some("http://127.0.0.1:1".into());
        let err = WebIdentityProvider::new(config, "us-east-1")
            .fetch()
            .await
            .expect_err("empty token");
        let shown = DisplayErrorContext(&err).to_string();
        assert!(shown.contains("token_file is empty"), "{shown}");
    }
}
