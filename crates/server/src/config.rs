//! Server configuration (spec §8).
//!
//! Configuration is layered: a TOML file (optional) is the base, and `FORGE_*`
//! environment variables override individual keys. Nested keys use `__` as the
//! separator, e.g. `FORGE_SERVER__BIND`, `FORGE_S3__ACCESS_KEY`,
//! `FORGE_AUTH__ANONYMOUS_MODE`.
//!
//! Secret string keys ([`SECRET_KEYS`]: database/Redis URLs, S3 keys, the
//! bootstrap-admin password, the OIDC client secret, the credential-forwarding
//! pepper) are read from the environment **verbatim** — never type-sniffed, so
//! a numeric or bracketed password stays a string — and configuration errors
//! never echo their values.
//!
//! The raw deserialized shape ([`Config`]) is validated into typed runtime
//! values where useful (e.g. the anonymous policy + trusted-proxy CIDRs are
//! parsed once via [`Config::anon_policy`] / [`Config::trusted_proxy_cidrs`]).

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use forge_core::auth::client_ip::AnonPolicy;
use ipnet::IpNet;
use serde::Deserialize;

/// Top-level server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// HTTP listener + public URL.
    pub server: ServerConfig,
    /// PostgreSQL connection.
    pub database: DatabaseConfig,
    /// S3 / versitygw object store.
    pub s3: S3Config,
    /// Authentication / anonymous-access policy. Every key has a default, so
    /// the section may be left out (e.g. an install configured through
    /// `FORGE_*` variables without any `FORGE_AUTH__*`).
    #[serde(default)]
    pub auth: AuthConfig,
    /// Optional Redis L2 cache.
    #[serde(default)]
    pub redis: RedisConfig,
    /// In-process cache sizing / TTL.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Background outbox worker tuning.
    #[serde(default)]
    pub outbox: OutboxConfig,
    /// Background retention worker tuning.
    #[serde(default)]
    pub retention: RetentionConfig,
    /// Group-repository nesting limits (slice 12.4).
    #[serde(default)]
    pub groups: GroupsConfig,
    /// Proxy-repository upstream HTTP tuning (timeouts, size caps, spooling).
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// `.nupkg` archive safety limits (zip-bomb defenses) for published and
    /// proxied packages.
    #[serde(default)]
    pub nuget: NugetConfig,
    /// WebAssembly format plugins: further package formats loaded at startup
    /// (see `docs/format-plugins.md`). None are loaded by default; the
    /// built-in plugins (Helm) need no configuration.
    #[serde(default)]
    pub plugins: PluginsConfig,
    /// Docker / OCI registry (`/v2`): size limits, registry tokens, upload
    /// and blob-link expiry.
    #[serde(default)]
    pub docker: DockerConfig,
    /// Static web UI (SPA) serving.
    #[serde(default)]
    pub web: WebConfig,
    /// Optional OpenID Connect / Microsoft Entra interactive login (slice 12.2).
    /// Absent ⇒ OIDC disabled, no `/auth/oidc/*` routes.
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    /// Optional secret encryption at rest (slice 12.5). Absent/disabled ⇒
    /// slice-1 behavior (secrets stay in the legacy plaintext columns; no key
    /// bootstrap, rotation worker, or backfill). Present + enabled ⇒ proxy
    /// `upstream_password` writes are envelope-encrypted under the root → KEK
    /// → DEK hierarchy, existing plaintext is backfilled at startup, and the
    /// `/admin/crypto/*` endpoints are live.
    #[serde(default)]
    pub crypto: Option<CryptoConfig>,
    /// Optional local disk cache for blobs. Absent (no `path`) ⇒ every
    /// download reads S3.
    #[serde(default)]
    pub blob_cache: BlobCacheConfig,
}

/// `server.*`
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Socket address to bind, e.g. `0.0.0.0:8080`.
    pub bind: String,
    /// Public base URL used to build absolute NuGet `@id`s (no trailing slash
    /// required; it is trimmed). e.g. `https://forge.example.com`.
    pub public_base_url: String,
    /// Largest accepted package upload (`dotnet nuget push`, a Helm chart
    /// push, …) in bytes, unless `plugins.max_upload_bytes` names another for
    /// the repository's format. Uploads are streamed to a temp file, never
    /// buffered in memory; exceeding the limit yields HTTP 413. Default 512
    /// MiB.
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: u64,
    /// Directory pushes and first-time proxy downloads are staged in. Files a
    /// killed process left there are removed at startup. Default:
    /// `forge-staging` under the system temp directory.
    #[serde(default)]
    pub staging_dir: Option<std::path::PathBuf>,
    /// Temp space all staged pushes and proxy downloads of this instance may
    /// use at once, in bytes; a stage that would exceed it is answered `503`
    /// with `Retry-After`. Default: four times the largest item staged:
    /// `max_upload_bytes`, `plugins.max_upload_bytes`,
    /// `proxy.max_package_bytes` or `docker.max_blob_bytes` (4 GiB with the
    /// defaults). `0` removes the limit. Size the staging volume above it.
    #[serde(default)]
    pub max_staging_bytes: Option<u64>,
    /// Permit starting with **known-insecure placeholder credentials** (the
    /// `changeme` bootstrap-admin password, `minioadmin` S3 keys, an unedited
    /// `<…>` value of an example env file).
    /// Default `false`: such a config refuses to start, so a copied dev config
    /// or the image's baked defaults never reach production unnoticed. Set
    /// `true` only for local development / compose stacks.
    #[serde(default)]
    pub allow_insecure_defaults: bool,
    /// Extra `Host` names (an optional `:port` is ignored) under which the
    /// server is legitimately reached, besides the host of
    /// [`Self::public_base_url`]. Only consulted for the
    /// `auth.anonymous_mode = "allowlist"` grant: an unauthenticated request
    /// whose `Host` matches neither is not served anonymously by IP (a
    /// DNS-rebinding page in an internal user's browser presents its own host
    /// name). Add the names a reverse proxy rewrites `Host` to, or that
    /// internal clients use. Default empty.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Seconds a client may take to send a request's headers before the
    /// connection is closed (slow-header "slowloris" defence). The same timer
    /// closes a keep-alive connection that stays idle this long, so keep it
    /// above the upstream keep-alive idle timeout of the reverse proxy in
    /// front (AWS ALB and ingress-nginx 60 s, Traefik 90 s, Caddy 120 s);
    /// otherwise the proxy can reuse a connection Forge is closing and answer
    /// 502. `0` disables. Default 150.
    #[serde(default = "default_header_read_timeout_seconds")]
    pub header_read_timeout_seconds: u64,
    /// Seconds a request body may stall (no data arriving) before the request
    /// is aborted. `0` disables. Default 60.
    #[serde(default = "default_body_idle_timeout_seconds")]
    pub body_idle_timeout_seconds: u64,
    /// Seconds a handler has to produce its response (`408` after that); a
    /// response body already streaming, such as a package download, is not cut
    /// off. Covers reading an upload, so keep it above the slowest expected
    /// push of `max_upload_bytes`. `0` disables. Default 900.
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
}

fn default_max_upload_bytes() -> u64 {
    512 * 1024 * 1024
}

fn default_header_read_timeout_seconds() -> u64 {
    150
}

fn default_body_idle_timeout_seconds() -> u64 {
    60
}

fn default_request_timeout_seconds() -> u64 {
    900
}

impl ServerConfig {
    /// Parse [`Self::bind`] into a [`SocketAddr`].
    pub fn bind_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.bind
            .parse()
            .map_err(|_| ConfigError::Invalid(format!("invalid server.bind {:?}", self.bind)))
    }
}

/// `database.*`
#[derive(Clone, Deserialize)]
pub struct DatabaseConfig {
    /// `postgres://…` connection URL.
    pub url: String,
    /// Connection-pool size. Default 20.
    #[serde(default = "default_db_max_connections")]
    pub max_connections: u32,
    /// How long a request waits for a free pooled connection before failing
    /// (seconds). Default 10.
    #[serde(default = "default_db_acquire_timeout")]
    pub acquire_timeout_seconds: u64,
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &redacted_url(&self.url))
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout_seconds", &self.acquire_timeout_seconds)
            .finish()
    }
}

/// A connection URL fit for logs: any password is replaced and a query
/// string (which may carry `password=` or a TLS key path) is dropped. An
/// unparsable URL is not shown at all.
pub fn redacted_url(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return "<unparsable url>".into();
    };
    if url.password().is_some() {
        let _ = url.set_password(Some("redacted"));
    }
    if url.query().is_some() {
        url.set_query(Some("redacted"));
    }
    url.to_string()
}

fn default_db_max_connections() -> u32 {
    20
}

fn default_db_acquire_timeout() -> u64 {
    10
}

/// `s3.*`
#[derive(Clone, Deserialize)]
pub struct S3Config {
    /// S3 endpoint URL (e.g. `http://localhost:8422` for versitygw).
    pub endpoint: String,
    /// AWS region (any value for versitygw; `us-east-1` is fine). Also the
    /// region STS and the AWS default credentials chain are asked in.
    #[serde(default = "default_region")]
    pub region: String,
    /// Bucket name holding all blobs.
    pub bucket: String,
    /// Where the credentials come from: `static` (default) uses
    /// [`Self::access_key`] / [`Self::secret_key`]; `default_chain` the AWS
    /// SDK default credentials chain (env vars with `AWS_SESSION_TOKEN`,
    /// profile, IRSA web identity, EKS Pod Identity, ECS task role, EC2
    /// instance metadata); `web_identity` exchanges a token file for
    /// temporary keys via STS `AssumeRoleWithWebIdentity` ([`Self::web_identity`]).
    #[serde(default)]
    pub credentials: S3CredentialsMode,
    /// Access key id. Required with `credentials = "static"`, refused with
    /// the other modes.
    #[serde(default)]
    pub access_key: Option<String>,
    /// Secret access key. Required with `credentials = "static"`, refused
    /// with the other modes.
    #[serde(default)]
    pub secret_key: Option<String>,
    /// `s3.web_identity.*`: required with `credentials = "web_identity"`,
    /// refused with the other modes.
    #[serde(default)]
    pub web_identity: Option<S3WebIdentityConfig>,
    /// Use path-style addressing (required for versitygw/MinIO).
    #[serde(default = "default_true")]
    pub force_path_style: bool,
    /// Switch to multipart upload above this many bytes.
    #[serde(default = "default_multipart_threshold")]
    pub multipart_threshold: u64,
    /// Conditional-write dedup PUTs (`If-None-Match: *`): `auto` | `on` | `off`.
    /// `auto` (default) tries the conditional PUT and permanently falls back to
    /// HEAD-then-PUT if the backend rejects it with `NotImplemented` (versitygw
    /// does); `on` forces conditional (real AWS S3/MinIO); `off` keeps
    /// HEAD-then-PUT. Pure optimization — behavior is identical either way.
    #[serde(default)]
    pub conditional_writes: ConditionalWritesMode,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &redacted_url(&self.endpoint))
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("credentials", &self.credentials)
            .field("access_key", &self.access_key)
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "<redacted>"),
            )
            .field("web_identity", &self.web_identity)
            .field("force_path_style", &self.force_path_style)
            .field("multipart_threshold", &self.multipart_threshold)
            .field("conditional_writes", &self.conditional_writes)
            .finish()
    }
}

/// `s3.credentials` values (snake_case in TOML/env).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S3CredentialsMode {
    /// `s3.access_key` / `s3.secret_key`.
    #[default]
    Static,
    /// The AWS SDK default credentials chain.
    DefaultChain,
    /// STS `AssumeRoleWithWebIdentity` with `[s3.web_identity]`.
    WebIdentity,
}

impl S3CredentialsMode {
    /// The value as `s3.credentials` spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::DefaultChain => "default_chain",
            Self::WebIdentity => "web_identity",
        }
    }
}

/// `s3.web_identity.*`: a token file exchanged for temporary S3 keys via
/// STS `AssumeRoleWithWebIdentity`. `Debug` shows the token's path, never a
/// token (none is held here).
#[derive(Clone, Deserialize)]
pub struct S3WebIdentityConfig {
    /// The role to assume. AWS requires it; MinIO takes none for its
    /// claim-based policies (its `RoleArn` for a role policy otherwise).
    #[serde(default)]
    pub role_arn: Option<String>,
    /// The file holding the web identity token (e.g. a projected
    /// service-account token). Read again on every refresh, so a token the
    /// kubelet rotated is picked up.
    pub token_file: std::path::PathBuf,
    /// STS endpoint URL. Unset: AWS STS in `s3.region`. Set it for MinIO or
    /// Ceph RGW (usually the S3 endpoint).
    #[serde(default)]
    pub sts_endpoint: Option<String>,
    /// `RoleSessionName` (AWS CloudTrail records it). Default `forge`.
    #[serde(default = "default_s3_session_name")]
    pub session_name: String,
    /// Lifetime of the temporary credentials asked of STS, 900..=43200
    /// seconds. Unset: the STS default (one hour on AWS).
    #[serde(default)]
    pub duration_seconds: Option<u32>,
}

fn default_s3_session_name() -> String {
    "forge".into()
}

impl std::fmt::Debug for S3WebIdentityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3WebIdentityConfig")
            .field("role_arn", &self.role_arn)
            .field("token_file", &self.token_file)
            .field(
                "sts_endpoint",
                &self.sts_endpoint.as_deref().map(redacted_url),
            )
            .field("session_name", &self.session_name)
            .field("duration_seconds", &self.duration_seconds)
            .finish()
    }
}

/// `s3.conditional_writes` values (lowercase in TOML/env).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionalWritesMode {
    /// Try `If-None-Match: *`; fall back for the process lifetime on a
    /// `NotImplemented`-style rejection.
    #[default]
    Auto,
    /// Always send `If-None-Match: *` (unsupported backends surface errors).
    On,
    /// Always HEAD-then-PUT.
    Off,
}

impl S3Config {
    /// Convert into the storage crate's S3 config. Call on a validated
    /// config: `static` then has both keys.
    pub fn to_storage(&self) -> forge_storage::S3Config {
        forge_storage::S3Config {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            bucket: self.bucket.clone(),
            credentials: self.storage_credentials(),
            force_path_style: self.force_path_style,
            multipart_threshold: self.multipart_threshold,
            conditional_writes: match self.conditional_writes {
                ConditionalWritesMode::Auto => forge_storage::ConditionalWrites::Auto,
                ConditionalWritesMode::On => forge_storage::ConditionalWrites::On,
                ConditionalWritesMode::Off => forge_storage::ConditionalWrites::Off,
            },
        }
    }

    fn storage_credentials(&self) -> forge_storage::S3Credentials {
        match (self.credentials, &self.web_identity) {
            (S3CredentialsMode::DefaultChain, _) => forge_storage::S3Credentials::DefaultChain,
            (S3CredentialsMode::WebIdentity, Some(wi)) => {
                forge_storage::S3Credentials::WebIdentity(forge_storage::WebIdentity {
                    role_arn: wi.role_arn.clone(),
                    token_file: wi.token_file.clone(),
                    sts_endpoint: wi.sts_endpoint.clone(),
                    session_name: wi.session_name.clone(),
                    duration_seconds: wi.duration_seconds,
                })
            }
            // `static`, or an unvalidated `web_identity` without its block
            // (whose keys are then empty and S3 refuses them).
            _ => forge_storage::S3Credentials::from_keys(
                self.access_key.clone().unwrap_or_default(),
                self.secret_key.clone().unwrap_or_default(),
            ),
        }
    }

    /// Blank optional values mean unset (`FORGE_S3__ACCESS_KEY=` in an env
    /// file or a chart that renders every variable).
    fn normalize(&mut self) {
        fn blank_is_none(value: &mut Option<String>) {
            if value.as_deref().is_some_and(|v| v.trim().is_empty()) {
                *value = None;
            }
        }
        blank_is_none(&mut self.access_key);
        blank_is_none(&mut self.secret_key);
        if let Some(wi) = self.web_identity.as_mut() {
            blank_is_none(&mut wi.role_arn);
            blank_is_none(&mut wi.sts_endpoint);
        }
    }

    /// The credential source has exactly the settings it uses: both keys for
    /// `static`, `[s3.web_identity]` for `web_identity`, neither for
    /// `default_chain`. A setting the chosen source would ignore is refused
    /// rather than silently left unused (a long-lived key kept in a Secret
    /// after the switch to short-lived credentials, or the wrong mode).
    fn validate(&self) -> Result<(), ConfigError> {
        let mode = self.credentials.as_str();
        let keys_set = self.access_key.is_some() || self.secret_key.is_some();
        match self.credentials {
            S3CredentialsMode::Static => {
                if self.access_key.is_none() || self.secret_key.is_none() {
                    return Err(ConfigError::Invalid(
                        "s3.access_key and s3.secret_key are required with s3.credentials = \
                         \"static\" (the default): set FORGE_S3__ACCESS_KEY and \
                         FORGE_S3__SECRET_KEY, or set s3.credentials to \"default_chain\" or \
                         \"web_identity\" for short-lived credentials"
                            .into(),
                    ));
                }
            }
            S3CredentialsMode::DefaultChain | S3CredentialsMode::WebIdentity => {
                if keys_set {
                    return Err(ConfigError::Invalid(format!(
                        "s3.access_key / s3.secret_key are set, but s3.credentials = \
                         \"{mode}\" does not use them: remove them (FORGE_S3__ACCESS_KEY / \
                         FORGE_S3__SECRET_KEY) or set s3.credentials = \"static\""
                    )));
                }
            }
        }
        match (self.credentials, &self.web_identity) {
            (S3CredentialsMode::WebIdentity, None) => Err(ConfigError::Invalid(
                "s3.credentials = \"web_identity\" needs [s3.web_identity] with at least \
                 token_file (FORGE_S3__WEB_IDENTITY__TOKEN_FILE)"
                    .into(),
            )),
            (S3CredentialsMode::WebIdentity, Some(wi)) => wi.validate(),
            (_, Some(_)) => Err(ConfigError::Invalid(format!(
                "[s3.web_identity] is set, but s3.credentials = \"{mode}\" does not use it: \
                 set s3.credentials = \"web_identity\" (FORGE_S3__CREDENTIALS) or remove it"
            ))),
            (_, None) => Ok(()),
        }
    }
}

impl S3WebIdentityConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(format!("s3.web_identity.{msg}")));
        if self.token_file.as_os_str().is_empty() {
            return invalid("token_file must not be empty".into());
        }
        if let Some(endpoint) = &self.sts_endpoint {
            let ok = url::Url::parse(endpoint)
                .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some());
            if !ok {
                return invalid(format!(
                    "sts_endpoint must be an http(s) URL, got {:?}",
                    redacted_url(endpoint)
                ));
            }
        }
        // AWS's limits; MinIO and Ceph RGW apply the same ones.
        let name = &self.session_name;
        let name_ok = (2..=64).contains(&name.len())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c));
        if !name_ok {
            return invalid(format!(
                "session_name must be 2 to 64 characters of letters, digits and _+=,.@- \
                 (got {name:?})"
            ));
        }
        if let Some(seconds) = self.duration_seconds {
            if !(900..=43_200).contains(&seconds) {
                return invalid(format!(
                    "duration_seconds must be between 900 and 43200, got {seconds}"
                ));
            }
        }
        Ok(())
    }
}

/// `auth.*`
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Global anonymous mode: `off` | `allowlist` | `all`.
    #[serde(default = "default_anonymous_mode")]
    pub anonymous_mode: String,
    /// Allowlist tokens for `anonymous_mode = allowlist`
    /// (`loopback` / `private` / `local` / explicit CIDRs / hosts).
    #[serde(default)]
    pub anonymous_ip_allowlist: Vec<String>,
    /// CIDRs of proxies whose `X-Forwarded-For` we trust.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
    /// Allow HTTP Basic password auth (token-in-basic always allowed). Defaults
    /// off; intended for the admin API.
    #[serde(default)]
    pub allow_password_basic: bool,
    /// First-run bootstrap admin credentials.
    #[serde(default)]
    pub bootstrap_admin: Option<BootstrapAdmin>,
    /// Ordered password-style auth provider chain (slice 12.3). Each entry is a
    /// provider id; the chain is walked in order and the first to authenticate
    /// wins. Known ids: `local-password`, `upstream-basic`. The default keeps the
    /// local provider first so a locally-created admin survives an upstream
    /// outage. An entry of `upstream-basic` requires `[auth.upstream_basic]` to be
    /// present and enabled (validated at startup).
    #[serde(default = "default_providers")]
    pub providers: Vec<String>,
    /// Optional credential-forwarding upstream-basic provider (slice 12.3).
    /// Present + enabled ⇒ the `upstream-basic` provider can appear in
    /// [`Self::providers`].
    ///
    /// Since 12.7 this block (like `[oidc]`) is a **seed**: on first boot it is
    /// imported into an `auth_realm` row and the database becomes the
    /// authority (edit realms in the admin UI; the block is ignored afterwards).
    #[serde(default)]
    pub upstream_basic: Option<UpstreamBasicAuthConfig>,
    /// Login-screen behavior (12.7 §3.4): `identifier_first` (default — ask for
    /// the username, then route to a password prompt or an OIDC redirect) or
    /// `combined` (always show username+password plus a button per enabled
    /// OIDC realm).
    #[serde(default = "default_login_mode")]
    pub login_mode: String,
    /// Idle timeout (seconds) for browser sessions: a session expires this long
    /// after its last use. Applies to ALL sessions (local-password logins and
    /// OIDC). When unset, falls back to the legacy `oidc.session_idle_ttl_seconds`
    /// if an `[oidc]` block is present, else 8h.
    #[serde(default)]
    pub session_idle_ttl_seconds: Option<u64>,
    /// Absolute lifetime (seconds) for browser sessions, regardless of
    /// activity. Fallback mirrors [`Self::session_idle_ttl_seconds`]; default 7d.
    #[serde(default)]
    pub session_absolute_ttl_seconds: Option<u64>,
    /// How long (seconds) an instance trusts its in-process snapshot of the
    /// `auth_realm` table before re-reading it. Admin realm edits invalidate
    /// the local snapshot immediately; OTHER instances converge within this
    /// window. Keep small — the rebuild is two cheap queries.
    #[serde(default = "default_realm_cache_ttl")]
    pub realm_cache_ttl_seconds: u64,
    /// Failed password attempts allowed per `(client IP, username)` within
    /// [`Self::login_failure_window_seconds`] before further attempts are
    /// refused until the window lapses (browser login and Basic password auth;
    /// per instance, in memory). `0` disables the lockout.
    #[serde(default = "default_login_max_failures")]
    pub login_max_failures: u32,
    /// Length (seconds) of the password-failure window / lockout.
    #[serde(default = "default_login_failure_window")]
    pub login_failure_window_seconds: u64,
    /// OIDC login starts (`GET /auth/oidc/login`) allowed per client network
    /// (IPv6: per /64) and minute, per instance. Each start stores a flow
    /// row. `0` disables the limit.
    #[serde(default = "default_oidc_login_starts_per_minute")]
    pub oidc_login_starts_per_minute: u32,
    /// Maximum concurrent upstream credential forwards **per
    /// credential-forwarding realm, per instance** (verdict-cache misses
    /// only; cache hits never forward). A miss beyond the bound fails closed
    /// (401) instead of queueing, so an upstream stall or a password spray
    /// cannot pile up unbounded outbound work. Forwards never hold a database
    /// connection, whatever this is set to. Values below 1 are treated as 1.
    #[serde(default = "default_credential_forward_max_concurrent")]
    pub credential_forward_max_concurrent: usize,
    /// Most argon2 password verifications (local-password logins and Basic
    /// password auth) running at once on this instance; each holds ~19 MiB
    /// and a CPU core. Further attempts queue up to a few seconds, then fail
    /// as "unavailable" (denied, not counted as a failed password). `0`
    /// (default) means the number of available CPUs.
    #[serde(default)]
    pub password_verify_concurrency: usize,
}

impl Default for AuthConfig {
    /// Every key at its serde default, as for an empty `[auth]` table.
    fn default() -> Self {
        serde_json::from_value(serde_json::json!({})).expect("every auth key has a default")
    }
}

/// Longest accepted session lifetime (10 years): longer ones overflow the
/// duration arithmetic and are a configuration mistake anyway.
const MAX_SESSION_TTL_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;

/// Longest accepted worker and key-cache duration (100 years). Larger values
/// panic in the duration arithmetic (chrono above about 9.2e15 seconds, moka
/// TTLs above 1000 years, timestamps past year 262143) instead of failing
/// validation, and are a configuration mistake anyway.
const MAX_DURATION_SECONDS: i64 = 100 * 365 * 24 * 60 * 60;

fn default_credential_forward_max_concurrent() -> usize {
    forge_core::auth::DEFAULT_MAX_CONCURRENT_FORWARDS
}

fn default_login_max_failures() -> u32 {
    10
}

fn default_login_failure_window() -> u64 {
    300
}

fn default_oidc_login_starts_per_minute() -> u32 {
    30
}

fn default_login_mode() -> String {
    "identifier_first".into()
}

fn default_realm_cache_ttl() -> u64 {
    10
}

fn default_providers() -> Vec<String> {
    vec!["local-password".to_string()]
}

/// `auth.upstream_basic.*` — credential-forwarding authentication (slice 12.3).
///
/// Forwards a user's `username:password` to a configured upstream over HTTP
/// Basic (the verdaccio-nexus-auth-proxy pattern; for a Nexus this is the
/// status/whoami endpoint). The `key_pepper` is a **secret**: it keys the
/// validated-credential cache HMAC and is **redacted** from `Debug` (and any
/// config dump), mirroring the slice-1 `upstream_password` / OIDC `client_secret`
/// treatment, and is forward-compatible with §12.5 encryption at rest.
///
/// Unknown keys are refused, like in a realm config set through the admin
/// API: a misspelled `identity_path` or `required_groups` would otherwise
/// seed the realm with that gate turned off.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamBasicAuthConfig {
    /// Master switch. When `false`, the provider is not built even if it appears
    /// in `auth.providers` (that combination is a startup error — see validate).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Upstream endpoint hit with the user's Basic credentials. Must be http/https
    /// and pass the SSRF scheme check; for a Nexus, e.g.
    /// `https://nexus.internal/service/rest/v1/status`.
    pub url: String,
    /// HTTP method (Nexus status is `GET`).
    #[serde(default = "default_upstream_method")]
    pub method: String,
    /// Status codes meaning "credentials valid".
    #[serde(default = "default_success_status")]
    pub success_status: Vec<u16>,
    /// Status codes meaning "definitively rejected".
    #[serde(default = "default_reject_status")]
    pub reject_status: Vec<u16>,
    /// Connect timeout (ms).
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Total request timeout (ms).
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Optional coarse allow-gate: only accept a success when the user holds one
    /// of these groups. Empty ⇒ any success accepted. Requires `groups_path`.
    #[serde(default)]
    pub required_groups: Vec<String>,
    /// `.`-separated path into the JSON body locating the user's groups
    /// (e.g. `user.roles`). Empty ⇒ no group parsing.
    #[serde(default)]
    pub groups_path: String,
    /// `.`-separated path into the JSON success body naming the account the
    /// upstream authenticated (e.g. `login`); when set it must equal the
    /// canonical username. Required for upstreams that accept a secret with
    /// any username (personal access tokens). Empty ⇒ no identity check.
    #[serde(default)]
    pub identity_path: String,
    /// Accept a plain-`http` `url` that is not loopback (passwords then travel
    /// in the clear). Default `false`.
    #[serde(default)]
    pub allow_http: bool,
    /// Optional upstream group that maps to forge admin. Every login that
    /// fetches the groups re-applies it (grants and demotes), with or without
    /// `auto_provision`.
    #[serde(default)]
    pub admin_group: String,
    /// Auto-provision an `app_user` on first successful upstream login.
    #[serde(default = "default_true")]
    pub auto_provision: bool,
    /// Validated-credential cache TTLs + the secret pepper.
    #[serde(default)]
    pub cache: CredCacheConfig,
}

/// Manual `Debug` that **redacts** the cache pepper (which lives under
/// [`Self::cache`]) so it can never land in a log line or error body.
impl std::fmt::Debug for UpstreamBasicAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamBasicAuthConfig")
            .field("enabled", &self.enabled)
            .field("url", &self.url)
            .field("method", &self.method)
            .field("success_status", &self.success_status)
            .field("reject_status", &self.reject_status)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("required_groups", &self.required_groups)
            .field("groups_path", &self.groups_path)
            .field("identity_path", &self.identity_path)
            .field("admin_group", &self.admin_group)
            .field("auto_provision", &self.auto_provision)
            .field("cache", &self.cache) // cache's own Debug redacts the pepper
            .finish()
    }
}

impl UpstreamBasicAuthConfig {
    /// Build the `forge-core` provider config from this block.
    pub fn to_core(&self) -> forge_core::auth::UpstreamBasicConfig {
        forge_core::auth::UpstreamBasicConfig {
            url: self.url.clone(),
            method: self.method.to_ascii_uppercase(),
            success_status: self.success_status.clone(),
            reject_status: self.reject_status.clone(),
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            request_timeout: Duration::from_millis(self.request_timeout_ms),
            required_groups: self.required_groups.clone(),
            groups_path: self.groups_path.clone(),
            identity_path: self.identity_path.clone(),
            admin_group: self.admin_group.clone(),
            provider_id: forge_core::auth::UPSTREAM_BASIC_ID.to_string(),
            auto_provision: self.auto_provision,
            realm_id: None,
        }
    }
}

/// `auth.upstream_basic.cache.*` — the validated-credential cache tuning.
/// Unknown keys are refused (see [`UpstreamBasicAuthConfig`]).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredCacheConfig {
    /// How long a *good* credential is trusted without re-forwarding (seconds).
    #[serde(default = "default_positive_ttl")]
    pub positive_ttl_secs: u64,
    /// How long a *bad* credential is remembered (seconds). Kept short so a user
    /// who fixes their password is not locked out for long.
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl_secs: u64,
    /// Server-held secret keying the cache HMAC. **Redacted** from `Debug`.
    /// High-entropy; rotating it invalidates the whole cache (causes re-forwards).
    /// Required (non-empty) when the provider is enabled — validated at startup.
    #[serde(default)]
    pub key_pepper: String,
}

impl Default for CredCacheConfig {
    fn default() -> Self {
        CredCacheConfig {
            positive_ttl_secs: default_positive_ttl(),
            negative_ttl_secs: default_negative_ttl(),
            key_pepper: String::new(),
        }
    }
}

/// Manual `Debug` that **redacts** the `key_pepper`.
impl std::fmt::Debug for CredCacheConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredCacheConfig")
            .field("positive_ttl_secs", &self.positive_ttl_secs)
            .field("negative_ttl_secs", &self.negative_ttl_secs)
            .field("key_pepper", &"<redacted>")
            .finish()
    }
}

fn default_upstream_method() -> String {
    "GET".into()
}
fn default_success_status() -> Vec<u16> {
    vec![200]
}
fn default_reject_status() -> Vec<u16> {
    vec![401, 403]
}
fn default_connect_timeout_ms() -> u64 {
    2000
}
fn default_request_timeout_ms() -> u64 {
    5000
}
fn default_positive_ttl() -> u64 {
    300
}
fn default_negative_ttl() -> u64 {
    30
}

/// `auth.bootstrap_admin.*`
///
/// Configured entirely through the environment in the container image
/// (`FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD`, optionally `…__USERNAME`). A block
/// **without a (non-blank) password means "no bootstrap admin"**: the loader
/// drops it ([`Config::load`]), so removing the password once real admins
/// exist is a normal configuration, not a startup error.
#[derive(Clone, Deserialize)]
pub struct BootstrapAdmin {
    /// Admin username to create on first run if absent. Default `admin`.
    #[serde(default = "default_bootstrap_username")]
    pub username: String,
    /// Plaintext password (hashed with argon2id on creation). Required for the
    /// bootstrap admin to exist; **redacted** from `Debug`.
    #[serde(default)]
    pub password: String,
}

fn default_bootstrap_username() -> String {
    "admin".into()
}

/// Manual `Debug` that **redacts the password**.
impl std::fmt::Debug for BootstrapAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapAdmin")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// `redis.*` (optional).
#[derive(Clone, Default, Deserialize)]
pub struct RedisConfig {
    /// `redis://…` URL. Absent or blank ⇒ L1-only caching (a blank
    /// `FORGE_REDIS__URL=` disables Redis, see [`Config::load`]).
    #[serde(default)]
    pub url: Option<String>,
    /// Connect / reconnect deadline in milliseconds. Default 2000.
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
    /// Per-command response deadline in milliseconds. A slower Redis is
    /// treated as unavailable (reads fall through to the source). Default 2000.
    #[serde(default)]
    pub response_timeout_ms: Option<u64>,
}

impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfig")
            .field("url", &self.url.as_deref().map(redacted_url))
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("response_timeout_ms", &self.response_timeout_ms)
            .finish()
    }
}

impl RedisConfig {
    /// The runtime timeouts handed to the cache.
    pub fn timeouts(&self) -> forge_cache::RedisTimeouts {
        let defaults = forge_cache::RedisTimeouts::default();
        forge_cache::RedisTimeouts {
            connect: self
                .connect_timeout_ms
                .map(Duration::from_millis)
                .unwrap_or(defaults.connect),
            response: self
                .response_timeout_ms
                .map(Duration::from_millis)
                .unwrap_or(defaults.response),
        }
    }
}

/// `blob_cache.*` (optional): a copy of downloaded blobs on a local disk, so
/// hot downloads skip S3 and cached packages keep resolving while S3 is down.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BlobCacheConfig {
    /// The cache directory (created if missing). Unset or blank ⇒ no cache.
    /// Each instance needs a directory of its own.
    #[serde(default)]
    pub path: Option<std::path::PathBuf>,
    /// `"auto"` (default): the size of the filesystem holding `path`, minus
    /// `min_free_bytes` (and `server.max_staging_bytes` when staging is on
    /// the same filesystem), re-read periodically; or a fixed byte count.
    /// Either way capped so the filesystem keeps `min_free_bytes` free.
    #[serde(default)]
    pub max_bytes: BlobCacheMaxBytes,
    /// Free space the cache leaves on its filesystem, evicting instead of
    /// filling it. Default: 5 % of the filesystem.
    #[serde(default)]
    pub min_free_bytes: Option<u64>,
}

/// `blob_cache.max_bytes`: `"auto"` or a byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlobCacheMaxBytes {
    /// Sized from the disk.
    #[default]
    Auto,
    /// A fixed limit in bytes.
    Bytes(u64),
}

impl<'de> Deserialize<'de> for BlobCacheMaxBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = BlobCacheMaxBytes;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("\"auto\" or a number of bytes")
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(BlobCacheMaxBytes::Bytes(v))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                u64::try_from(v)
                    .map(BlobCacheMaxBytes::Bytes)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Signed(v), &self))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let v = v.trim();
                if v.eq_ignore_ascii_case("auto") {
                    Ok(BlobCacheMaxBytes::Auto)
                } else {
                    v.parse()
                        .map(BlobCacheMaxBytes::Bytes)
                        .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))
                }
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// `cache.*`
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Max number of L1 entries.
    #[serde(default = "default_l1_capacity")]
    pub l1_max_capacity: u64,
    /// Default TTL (seconds) for cached read responses.
    #[serde(default = "default_cache_ttl_seconds")]
    pub default_ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            l1_max_capacity: default_l1_capacity(),
            default_ttl_seconds: default_cache_ttl_seconds(),
        }
    }
}

impl CacheConfig {
    /// Default read-response TTL as a [`Duration`].
    pub fn default_ttl(&self) -> Duration {
        Duration::from_secs(self.default_ttl_seconds)
    }
}

/// `outbox.*`
#[derive(Debug, Clone, Deserialize)]
pub struct OutboxConfig {
    /// Rows claimed per worker tick.
    #[serde(default = "default_outbox_batch")]
    pub batch_size: i64,
    /// Grace period (seconds) before a dereferenced blob is S3-deleted.
    #[serde(default = "default_outbox_grace")]
    pub grace_seconds: i64,
    /// Worker poll interval (seconds).
    #[serde(default = "default_outbox_poll")]
    pub poll_interval_seconds: u64,
    /// How long (seconds) a *processed* `blob_outbox` row is kept before the
    /// reconciler loop prunes it (default 7 days). Processed rows are only a
    /// history of completed deletes — GC never reads them — so this bounds
    /// table growth. `0` disables pruning (keep every row).
    #[serde(default = "default_outbox_processed_retention")]
    pub processed_retention_seconds: u64,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        OutboxConfig {
            batch_size: default_outbox_batch(),
            grace_seconds: default_outbox_grace(),
            poll_interval_seconds: default_outbox_poll(),
            processed_retention_seconds: default_outbox_processed_retention(),
        }
    }
}

impl OutboxConfig {
    /// Poll interval as a [`Duration`].
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_seconds)
    }
    /// Grace period as a chrono [`chrono::Duration`].
    pub fn grace(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.grace_seconds)
    }
    /// Retention for processed outbox rows, or `None` when pruning is
    /// disabled (`processed_retention_seconds = 0`). Clamped to 100 years so
    /// the cutoff arithmetic can never overflow.
    pub fn processed_retention(&self) -> Option<chrono::Duration> {
        const MAX_SECS: u64 = 100 * 365 * 24 * 3600;
        match self.processed_retention_seconds {
            0 => None,
            secs => Some(chrono::Duration::seconds(secs.min(MAX_SECS) as i64)),
        }
    }
}

/// `retention.*` — background retention worker tuning (slice 12.1).
///
/// The worker runs on every instance, claims one due repository per tick via
/// `FOR UPDATE SKIP LOCKED` + a lease, evaluates its policy, and applies
/// decisions through the slice-1 blob outbox. `default_run_interval` is the
/// floor between automatic runs (a larger per-repo `min_run_interval_seconds`
/// in the policy wins); `lease_seconds` is the crash-safe lease; `delete_grace`
/// defaults to the outbox grace when unset and is the deferral before a
/// dereferenced blob is S3-deleted.
#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    /// Run the background retention worker on this instance. When `false`, the
    /// worker loop is not spawned (the admin REST surface — including manual
    /// "run now" scheduling and dry-run preview — still works; scheduled rows
    /// simply accumulate until an instance with the worker enabled drains them).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How often each instance polls for a due repository (seconds).
    #[serde(default = "default_retention_poll")]
    pub poll_interval_seconds: u64,
    /// Default floor between automatic runs per repo (seconds). The worker
    /// never schedules runs less than 60 s apart, so `0` leaves the interval
    /// to each policy's `min_run_interval_seconds`.
    #[serde(default = "default_retention_run_interval")]
    pub default_run_interval_seconds: i64,
    /// Crash-safe lease held while a repo is evaluated (seconds).
    #[serde(default = "default_retention_lease")]
    pub lease_seconds: i64,
    /// How long `retention_audit` rows are kept before the reconciler loop
    /// deletes them (default 90 days). Dry-run policies add a row per
    /// matched version on every run, so the table grows without this. `0`
    /// keeps every row. Pruning runs on every instance, also where the
    /// worker is disabled.
    #[serde(default = "default_retention_audit_retention")]
    pub audit_retention_seconds: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        RetentionConfig {
            enabled: default_true(),
            poll_interval_seconds: default_retention_poll(),
            default_run_interval_seconds: default_retention_run_interval(),
            lease_seconds: default_retention_lease(),
            audit_retention_seconds: default_retention_audit_retention(),
        }
    }
}

impl RetentionConfig {
    /// Poll interval as a [`Duration`].
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_seconds)
    }
    /// Default run interval as a chrono [`chrono::Duration`].
    pub fn default_run_interval(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.default_run_interval_seconds)
    }
    /// Lease as a chrono [`chrono::Duration`].
    pub fn lease(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.lease_seconds)
    }
    /// How long audit rows are kept, or `None` when pruning is disabled
    /// (`audit_retention_seconds = 0`). Clamped to 100 years so the cutoff
    /// arithmetic can never overflow.
    pub fn audit_retention(&self) -> Option<chrono::Duration> {
        const MAX_SECS: u64 = 100 * 365 * 24 * 3600;
        match self.audit_retention_seconds {
            0 => None,
            secs => Some(chrono::Duration::seconds(secs.min(MAX_SECS) as i64)),
        }
    }
}

/// `groups.*` — nested group-repository limits (slice 12.4 Phase 4).
///
/// Nested group repositories (a group whose member is itself a group) are
/// allowed, but the graph must stay an acyclic DAG of bounded depth. The
/// config-time admin guard rejects an edge that would create a cycle or exceed
/// `max_nesting_depth`; the resolve-time walk independently enforces the same
/// depth bound and a visited-set so a cycle injected by a raw DB write still
/// terminates (fail-closed).
#[derive(Debug, Clone, Deserialize)]
pub struct GroupsConfig {
    /// Maximum nesting depth of the group graph: the longest member-path from a
    /// group to a leaf (a direct hosted/proxy member is depth 1). Both the
    /// config-time insert guard and the resolve-time walk enforce this bound.
    #[serde(default = "default_max_nesting_depth")]
    pub max_nesting_depth: i32,
}

impl Default for GroupsConfig {
    fn default() -> Self {
        GroupsConfig {
            max_nesting_depth: default_max_nesting_depth(),
        }
    }
}

fn default_max_nesting_depth() -> i32 {
    20
}

/// `proxy.*` — outbound HTTP tuning shared by every proxy repository.
///
/// Timeouts are split by what they protect against: `connect_timeout_seconds`
/// and `read_timeout_seconds` (no bytes received for that long) bound a dead
/// or stalled peer for every request, while the total deadlines differ by
/// request class — metadata documents are small, but `.nupkg` downloads may be
/// hundreds of MiB over a slow link, so `download_timeout_seconds` is
/// deliberately generous. Response bodies are size-capped while streaming;
/// metadata up to `spool_memory_bytes` stays in memory and larger bodies spill
/// to a self-deleting temp file, and packages always stream to a temp file.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// TCP + TLS connect deadline. Default 15 s.
    #[serde(default = "default_proxy_connect_timeout")]
    pub connect_timeout_seconds: u64,
    /// Maximum idle time between two reads of a response. Default 60 s.
    #[serde(default = "default_proxy_read_timeout")]
    pub read_timeout_seconds: u64,
    /// Total deadline for metadata requests (service index, version listing,
    /// `.nuspec`). Default 60 s.
    #[serde(default = "default_proxy_metadata_timeout")]
    pub metadata_timeout_seconds: u64,
    /// Total deadline for a `.nupkg` download. Default 30 min.
    #[serde(default = "default_proxy_download_timeout")]
    pub download_timeout_seconds: u64,
    /// Largest accepted upstream metadata document. Default 32 MiB.
    #[serde(default = "default_proxy_max_metadata_bytes")]
    pub max_metadata_bytes: u64,
    /// Largest accepted upstream `.nupkg`. Default 1 GiB.
    #[serde(default = "default_proxy_max_package_bytes")]
    pub max_package_bytes: u64,
    /// Bodies up to this size are kept in memory; larger ones spill to a temp
    /// file that is removed when the request finishes. Default 2 MiB.
    #[serde(default = "default_proxy_spool_memory_bytes")]
    pub spool_memory_bytes: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            connect_timeout_seconds: default_proxy_connect_timeout(),
            read_timeout_seconds: default_proxy_read_timeout(),
            metadata_timeout_seconds: default_proxy_metadata_timeout(),
            download_timeout_seconds: default_proxy_download_timeout(),
            max_metadata_bytes: default_proxy_max_metadata_bytes(),
            max_package_bytes: default_proxy_max_package_bytes(),
            spool_memory_bytes: default_proxy_spool_memory_bytes(),
        }
    }
}

impl ProxyConfig {
    /// The runtime tuning handed to [`forge_core::net::upstream::UpstreamHttp`].
    pub fn upstream_http(&self) -> forge_core::net::upstream::UpstreamHttpConfig {
        forge_core::net::upstream::UpstreamHttpConfig {
            connect_timeout: Duration::from_secs(self.connect_timeout_seconds),
            read_timeout: Duration::from_secs(self.read_timeout_seconds),
            metadata_timeout: Duration::from_secs(self.metadata_timeout_seconds),
            download_timeout: Duration::from_secs(self.download_timeout_seconds),
            max_metadata_bytes: self.max_metadata_bytes,
            max_package_bytes: self.max_package_bytes,
            spool_memory_bytes: usize::try_from(self.spool_memory_bytes).unwrap_or(usize::MAX),
            ..Default::default()
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (key, value) in [
            (
                "proxy.connect_timeout_seconds",
                self.connect_timeout_seconds,
            ),
            ("proxy.read_timeout_seconds", self.read_timeout_seconds),
            (
                "proxy.metadata_timeout_seconds",
                self.metadata_timeout_seconds,
            ),
            (
                "proxy.download_timeout_seconds",
                self.download_timeout_seconds,
            ),
            ("proxy.max_metadata_bytes", self.max_metadata_bytes),
            ("proxy.max_package_bytes", self.max_package_bytes),
        ] {
            if value == 0 {
                return Err(ConfigError::Invalid(format!(
                    "{key} must be greater than 0"
                )));
            }
        }
        Ok(())
    }
}

fn default_proxy_connect_timeout() -> u64 {
    15
}
fn default_proxy_read_timeout() -> u64 {
    60
}
fn default_proxy_metadata_timeout() -> u64 {
    60
}
fn default_proxy_download_timeout() -> u64 {
    30 * 60
}
fn default_proxy_max_metadata_bytes() -> u64 {
    32 * 1024 * 1024
}
fn default_proxy_max_package_bytes() -> u64 {
    1024 * 1024 * 1024
}
fn default_proxy_spool_memory_bytes() -> u64 {
    2 * 1024 * 1024
}

/// `nuget.*` — `.nupkg` archive safety limits, applied when a package is
/// published and when a proxy caches an upstream package (and, for
/// `max_nuspec_bytes`, to an upstream `.nuspec` a proxy verifies).
///
/// Only the `.nuspec` manifest is ever decompressed, so it alone is capped by
/// size and compression ratio; every other entry (native binaries of hundreds
/// of MiB included) is only bounded by the archive-shape limits, which reject
/// pathological archives before the zip central directory is loaded.
#[derive(Debug, Clone, Deserialize)]
pub struct NugetConfig {
    /// Maximum number of entries in a package archive. Default 10 000.
    #[serde(default = "default_nuget_max_entries")]
    pub max_entries: usize,
    /// Maximum size of the zip central directory (per-entry metadata loaded
    /// into memory to open the archive). Default 16 MiB.
    #[serde(default = "default_nuget_max_central_directory_bytes")]
    pub max_central_directory_bytes: u64,
    /// Maximum total declared uncompressed size of all entries. Nothing but
    /// the manifest is decompressed, so this only rejects absurd archives.
    /// Default 16 GiB.
    #[serde(default = "default_nuget_max_total_uncompressed_bytes")]
    pub max_total_uncompressed_bytes: u64,
    /// Maximum size of the `.nuspec` manifest (read into memory, stored, and
    /// re-parsed for registration/search). Default 1 MiB.
    #[serde(default = "default_nuget_max_nuspec_bytes")]
    pub max_nuspec_bytes: u64,
    /// Maximum compression ratio of the `.nuspec` entry. Default 200.
    #[serde(default = "default_nuget_max_nuspec_compression_ratio")]
    pub max_nuspec_compression_ratio: u64,
}

impl Default for NugetConfig {
    fn default() -> Self {
        NugetConfig {
            max_entries: default_nuget_max_entries(),
            max_central_directory_bytes: default_nuget_max_central_directory_bytes(),
            max_total_uncompressed_bytes: default_nuget_max_total_uncompressed_bytes(),
            max_nuspec_bytes: default_nuget_max_nuspec_bytes(),
            max_nuspec_compression_ratio: default_nuget_max_nuspec_compression_ratio(),
        }
    }
}

impl NugetConfig {
    /// The limits handed to [`forge_format_nuget::Nuget::with_limits`].
    pub fn limits(&self) -> forge_format_nuget::NupkgLimits {
        forge_format_nuget::NupkgLimits {
            max_entries: self.max_entries,
            max_central_directory_bytes: self.max_central_directory_bytes,
            max_total_uncompressed: self.max_total_uncompressed_bytes,
            max_nuspec_bytes: self.max_nuspec_bytes,
            max_nuspec_compression_ratio: self.max_nuspec_compression_ratio,
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (key, value) in [
            ("nuget.max_entries", self.max_entries as u64),
            (
                "nuget.max_central_directory_bytes",
                self.max_central_directory_bytes,
            ),
            (
                "nuget.max_total_uncompressed_bytes",
                self.max_total_uncompressed_bytes,
            ),
            ("nuget.max_nuspec_bytes", self.max_nuspec_bytes),
            (
                "nuget.max_nuspec_compression_ratio",
                self.max_nuspec_compression_ratio,
            ),
        ] {
            if value == 0 {
                return Err(ConfigError::Invalid(format!(
                    "{key} must be greater than 0"
                )));
            }
        }
        Ok(())
    }
}

/// `[docker]`: the Docker / OCI registry served under `/v2`.
#[derive(Debug, Clone, Deserialize)]
pub struct DockerConfig {
    /// Largest blob (image layer) a push or a proxy download may carry.
    /// Staged on disk while it arrives, so it counts towards
    /// `server.max_staging_bytes` like `server.max_upload_bytes` does.
    /// Default 1 GiB.
    #[serde(default = "default_docker_max_blob_bytes")]
    pub max_blob_bytes: u64,
    /// Lifetime of a registry Bearer token from `/v2/token` (60–3600 s).
    /// Default 300.
    #[serde(default = "default_docker_token_ttl_seconds")]
    pub token_ttl_seconds: u64,
    /// Secret the registry tokens are signed with (at least 32 characters).
    /// Unset: a random key is generated once and kept in the database (sealed
    /// with `[crypto]` when that is enabled), shared by every instance.
    #[serde(default)]
    pub token_secret: Option<String>,
    /// An upload session idle this long is abandoned and removed. Default
    /// 24 h.
    #[serde(default = "default_docker_upload_ttl_seconds")]
    pub upload_ttl_seconds: u64,
    /// A blob pushed into an image that no manifest of the image references
    /// is released after this long unused (the time a client has between
    /// pushing layers and pushing their manifest). Default 24 h, at least 1 h.
    #[serde(default = "default_docker_unreferenced_blob_ttl_seconds")]
    pub unreferenced_blob_ttl_seconds: u64,
    /// How often expired uploads and unreferenced blob links are swept.
    /// Default 300.
    #[serde(default = "default_docker_sweep_interval_seconds")]
    pub sweep_interval_seconds: u64,
}

impl Default for DockerConfig {
    fn default() -> Self {
        DockerConfig {
            max_blob_bytes: default_docker_max_blob_bytes(),
            token_ttl_seconds: default_docker_token_ttl_seconds(),
            token_secret: None,
            upload_ttl_seconds: default_docker_upload_ttl_seconds(),
            unreferenced_blob_ttl_seconds: default_docker_unreferenced_blob_ttl_seconds(),
            sweep_interval_seconds: default_docker_sweep_interval_seconds(),
        }
    }
}

impl DockerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_blob_bytes == 0 {
            return Err(ConfigError::Invalid(
                "docker.max_blob_bytes must be greater than 0".into(),
            ));
        }
        if !(60..=3600).contains(&self.token_ttl_seconds) {
            return Err(ConfigError::Invalid(
                "docker.token_ttl_seconds must be between 60 and 3600".into(),
            ));
        }
        if self
            .token_secret
            .as_deref()
            .is_some_and(|s| s.chars().count() < 32)
        {
            return Err(ConfigError::Invalid(
                "docker.token_secret must be at least 32 characters (or unset to generate a key)"
                    .into(),
            ));
        }
        if self.upload_ttl_seconds == 0 || self.sweep_interval_seconds == 0 {
            return Err(ConfigError::Invalid(
                "docker.upload_ttl_seconds and docker.sweep_interval_seconds must be greater than 0"
                    .into(),
            ));
        }
        if self.unreferenced_blob_ttl_seconds < 3600 {
            return Err(ConfigError::Invalid(
                "docker.unreferenced_blob_ttl_seconds must be at least 3600: a client needs time \
                 between pushing an image's layers and its manifest"
                    .into(),
            ));
        }
        Ok(())
    }
}

fn default_docker_max_blob_bytes() -> u64 {
    1024 * 1024 * 1024
}
fn default_docker_token_ttl_seconds() -> u64 {
    300
}
fn default_docker_upload_ttl_seconds() -> u64 {
    24 * 3600
}
fn default_docker_unreferenced_blob_ttl_seconds() -> u64 {
    24 * 3600
}
fn default_docker_sweep_interval_seconds() -> u64 {
    300
}

fn default_nuget_max_entries() -> usize {
    forge_format_nuget::NupkgLimits::default().max_entries
}
fn default_nuget_max_central_directory_bytes() -> u64 {
    forge_format_nuget::NupkgLimits::default().max_central_directory_bytes
}
fn default_nuget_max_total_uncompressed_bytes() -> u64 {
    forge_format_nuget::NupkgLimits::default().max_total_uncompressed
}
fn default_nuget_max_nuspec_bytes() -> u64 {
    forge_format_nuget::NupkgLimits::default().max_nuspec_bytes
}
fn default_nuget_max_nuspec_compression_ratio() -> u64 {
    forge_format_nuget::NupkgLimits::default().max_nuspec_compression_ratio
}

/// `plugins.*` — WebAssembly format plugins.
///
/// The format plugins built into the server (Helm) are always installed.
/// Further ones are WebAssembly components, each listed explicitly with the
/// SHA-256 of its component: a directory under `dir` that is not listed is
/// never loaded, and a listed one whose component does not match its pin, or
/// whose id is taken by a built-in format, fails startup. Every instance must
/// therefore load the same plugins (the same configuration and files), since
/// a repository of a format an instance lacks is unavailable there.
///
/// ```toml
/// [plugins]
/// dir = "/etc/forge/plugins"     # holds <id>/plugin.toml + its component
///
/// [plugins.formats]
/// example = "sha256:3f1c…"       # format id → pinned component digest
/// ```
///
/// As environment variables: `FORGE_PLUGINS__DIR`,
/// `FORGE_PLUGINS__FORMATS__EXAMPLE`.
///
/// `max_upload_bytes` overrides `server.max_upload_bytes` for the
/// repositories of one format, built-in plugins included (Docker has
/// `docker.max_blob_bytes`):
///
/// ```toml
/// [plugins.max_upload_bytes]
/// helm = 104857600               # format id → largest accepted push
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginsConfig {
    /// Directory with one subdirectory per plugin, named by its format id.
    #[serde(default)]
    pub dir: Option<std::path::PathBuf>,
    /// The plugins to load: format id → SHA-256 of its component (lowercase
    /// hex, optionally prefixed `sha256:`).
    #[serde(default)]
    pub formats: std::collections::BTreeMap<String, String>,
    /// Largest accepted push per format: format id → bytes, in place of
    /// `server.max_upload_bytes` for that format's repositories. Staged on
    /// disk like every push, so it counts towards `server.max_staging_bytes`.
    /// An id no installed format has fails startup.
    #[serde(default)]
    pub max_upload_bytes: std::collections::BTreeMap<String, u64>,
}

impl PluginsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for (id, bytes) in &self.max_upload_bytes {
            if id == forge_db::model::DOCKER_FORMAT {
                return Err(ConfigError::Invalid(
                    "plugins.max_upload_bytes.docker: docker is not a plugin format; \
                     set docker.max_blob_bytes"
                        .into(),
                ));
            }
            forge_plugin::manifest::validate_id(id)
                .map_err(|e| ConfigError::Invalid(format!("plugins.max_upload_bytes.{id}: {e}")))?;
            if *bytes == 0 {
                return Err(ConfigError::Invalid(format!(
                    "plugins.max_upload_bytes.{id} must be greater than 0"
                )));
            }
        }
        if self.formats.is_empty() {
            return Ok(());
        }
        if self.dir.is_none() {
            return Err(ConfigError::Invalid(
                "plugins.formats lists plugins but plugins.dir is not set".into(),
            ));
        }
        for (id, sha256) in &self.formats {
            forge_plugin::manifest::validate_id(id)
                .map_err(|e| ConfigError::Invalid(format!("plugins.formats.{id}: {e}")))?;
            let hex = sha256.trim();
            let hex = hex.strip_prefix("sha256:").unwrap_or(hex);
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ConfigError::Invalid(format!(
                    "plugins.formats.{id} must be the component's SHA-256 (64 hex digits)"
                )));
            }
        }
        Ok(())
    }
}

/// `web.*` — static SPA serving.
///
/// When `enabled`, the server serves the built TanStack Start SPA from
/// `assets_dir` (a directory containing `index.html` + `assets/*`), mounted as
/// the router's fallback **after** the `/admin`, `/v3`, and `/browse` API
/// routers so API paths always win. Unknown paths fall back to `index.html` so
/// client-side (TanStack Router) deep links resolve.
///
/// `assets_dir` defaults to the relative path `web/dist`, matching the
/// repository layout (`web/` is built by Vite into `web/dist/`). Container
/// images set `FORGE_WEB__ASSETS_DIR` to the in-image asset path. A headless
/// deployment sets `FORGE_WEB__ENABLED=false`.
#[derive(Debug, Clone, Deserialize)]
pub struct WebConfig {
    /// Serve the SPA. When false, only the API routers are mounted.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Directory holding the built SPA (`index.html` + `assets/`).
    #[serde(default = "default_web_assets_dir")]
    pub assets_dir: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            enabled: default_true(),
            assets_dir: default_web_assets_dir(),
        }
    }
}

fn default_web_assets_dir() -> String {
    "web/dist".into()
}

/// `oidc.*` — OpenID Connect / Microsoft Entra interactive login (slice 12.2).
///
/// The whole `[oidc]` section is **optional**: when it is absent the feature is
/// off and the server mounts no `/auth/oidc/*` routes. When present, it
/// configures the authorization-code + PKCE flow against a single OIDC provider
/// (Entra-first, but generic OIDC). All ephemeral flow state and sessions live
/// in Postgres (`oidc_flow` / `session`), never in process memory, so any
/// instance can complete a callback another instance started.
///
/// `client_secret` is read from env/file and **redacted** from the `Debug`
/// impl (and must be redacted from any admin API that echoes config), mirroring
/// the slice-1 proxy `upstream_password` treatment. Encrypting it at rest is
/// slice 12.5.
///
/// Unknown keys are refused, like in a realm config set through the admin
/// API: a misspelled `required_claims` or `auto_provision` would otherwise
/// seed the realm with that gate turned off.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Master switch. When `false`, the section parses but the feature stays off
    /// (lets an operator keep the block while disabling login).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// OIDC issuer URL (must be `https`). For Entra v2 this includes the tenant,
    /// e.g. `https://login.microsoftonline.com/<tenant-id>/v2.0`. Discovery is
    /// fetched from `{issuer}/.well-known/openid-configuration`.
    pub issuer: String,
    /// OAuth client (application) id.
    pub client_id: String,
    /// OAuth client secret. **Redacted** from `Debug`/API output.
    pub client_secret: String,
    /// Absolute redirect URL registered with the IdP; must equal
    /// `{public_base_url}/auth/oidc/callback` (host is validated against
    /// `server.public_base_url`).
    pub redirect_url: String,
    /// Requested scopes. `openid` is always required and is added implicitly if
    /// missing.
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// Allowed leeway (seconds) on `exp`/`nbf`/`iat` ID-token validation.
    #[serde(default = "default_oidc_clock_skew")]
    pub clock_skew_seconds: u64,
    /// Permit a plain-`http` issuer URL. Off by default — a production issuer
    /// must be `https`. Set `true` only for a self-hosted/dev IdP without TLS
    /// (this is what the integration tests' in-process mock IdP uses). Since
    /// 12.7 §3.6 dropped the private-range SSRF restriction, this flag no
    /// longer affects which *addresses* are reachable — only the scheme rule.
    #[serde(default)]
    pub allow_private_issuer: bool,

    // ---- claim → user mapping ----
    /// Claim used as the `app_user.username` (fallback chain handled in code:
    /// this claim → `email` → `sub`).
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
    /// Claim carrying the user's email.
    #[serde(default = "default_email_claim")]
    pub email_claim: String,
    /// Claim carrying the user's display name.
    #[serde(default = "default_display_name_claim")]
    pub display_name_claim: String,

    // ---- provisioning ----
    /// Create an `app_user` on first successful login when no link exists.
    #[serde(default = "default_true")]
    pub auto_provision: bool,
    /// Link a new OIDC identity to an existing `app_user` whose `username`
    /// matches the resolved username claim. Off by default (the claim is
    /// IdP-controlled); even when on, accounts with a local password or admin
    /// rights are never linked by name.
    #[serde(default)]
    pub link_existing_by_username: bool,

    // ---- admin assignment ----
    /// Values (group object-ids/names or app-role names) that grant
    /// `is_admin`. Empty ⇒ OIDC never grants admin (admins stay locally
    /// managed) — the safe default.
    #[serde(default)]
    pub admin_groups: Vec<String>,
    /// Claim whose values are matched against [`Self::admin_groups`] (Entra: app
    /// roles arrive in `roles`, security groups in `groups`; `roles` is
    /// recommended to avoid the Graph "groups overage" callout).
    #[serde(default = "default_admin_claim")]
    pub admin_claim: String,
    /// Allow-gate: claim name → allowed values. Every listed claim must carry
    /// one of its values or the login is refused (e.g. `tid` for one Entra
    /// tenant, `hd` for a Google Workspace domain, `groups`). Empty ⇒ off.
    #[serde(default)]
    pub required_claims: std::collections::BTreeMap<String, Vec<String>>,
    /// Hosts besides the issuer's that the discovery document's token, JWKS
    /// and authorization endpoints may use, for IdPs that serve them elsewhere
    /// (Google: `oauth2.googleapis.com`, `www.googleapis.com`). Empty ⇒ the
    /// issuer's host only.
    #[serde(default)]
    pub endpoint_hosts: Vec<String>,

    // ---- session lifecycle ----
    /// Idle timeout (seconds): a session expires this long after its last use.
    #[serde(default = "default_session_idle_ttl")]
    pub session_idle_ttl_seconds: u64,
    /// Absolute lifetime (seconds): a session expires this long after creation
    /// regardless of activity.
    #[serde(default = "default_session_absolute_ttl")]
    pub session_absolute_ttl_seconds: u64,
}

/// Manual `Debug` that **redacts `client_secret`** so it never lands in logs.
impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("enabled", &self.enabled)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .field("allow_private_issuer", &self.allow_private_issuer)
            .field("username_claim", &self.username_claim)
            .field("email_claim", &self.email_claim)
            .field("display_name_claim", &self.display_name_claim)
            .field("auto_provision", &self.auto_provision)
            .field("link_existing_by_username", &self.link_existing_by_username)
            .field("admin_groups", &self.admin_groups)
            .field("admin_claim", &self.admin_claim)
            .field("endpoint_hosts", &self.endpoint_hosts)
            .field("session_idle_ttl_seconds", &self.session_idle_ttl_seconds)
            .field(
                "session_absolute_ttl_seconds",
                &self.session_absolute_ttl_seconds,
            )
            .finish()
    }
}

impl OidcConfig {
    /// Idle timeout as a [`Duration`].
    pub fn session_idle_ttl(&self) -> Duration {
        Duration::from_secs(self.session_idle_ttl_seconds)
    }
    /// Absolute lifetime as a [`Duration`].
    pub fn session_absolute_ttl(&self) -> Duration {
        Duration::from_secs(self.session_absolute_ttl_seconds)
    }
    /// Clock-skew leeway as a [`Duration`].
    pub fn clock_skew(&self) -> Duration {
        Duration::from_secs(self.clock_skew_seconds)
    }
    /// Scopes with `openid` guaranteed present (added first if missing).
    pub fn effective_scopes(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.scopes.len() + 1);
        if !self.scopes.iter().any(|s| s == "openid") {
            out.push("openid".to_string());
        }
        out.extend(self.scopes.iter().cloned());
        out
    }
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}
fn default_oidc_clock_skew() -> u64 {
    60
}
fn default_username_claim() -> String {
    "preferred_username".into()
}
fn default_email_claim() -> String {
    "email".into()
}
fn default_display_name_claim() -> String {
    "name".into()
}
fn default_admin_claim() -> String {
    "roles".into()
}
fn default_session_idle_ttl() -> u64 {
    8 * 60 * 60 // 8h
}
fn default_session_absolute_ttl() -> u64 {
    7 * 24 * 60 * 60 // 7d
}

/// `crypto.*` — secret encryption at rest (slice 12.5).
///
/// No field here is itself a secret: the **env provider** stores the *name* of
/// the environment variable holding the base64 root key and the **file
/// provider** stores a *path* — the key bytes are only ever read by the root
/// provider at startup (and never logged; `forge-crypto` wraps them in
/// zeroizing, Debug-redacted newtypes). The derived `Debug` is therefore safe.
#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    /// Master switch. `false` parses but keeps encryption off (lets an
    /// operator stage the block before flipping it on).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// AEAD for new keys and new secret envelopes:
    /// `aes-256-gcm` (default) or `xchacha20-poly1305`. Existing material
    /// keeps the algorithm recorded on its key row / blob header.
    #[serde(default = "default_crypto_algorithm")]
    pub algorithm: String,
    /// Where the root key lives.
    pub root: CryptoRootConfig,
    /// Unwrapped-key cache tuning.
    #[serde(default)]
    pub cache: CryptoCacheConfig,
    /// Rotation worker tuning.
    #[serde(default)]
    pub rotation: CryptoRotationConfig,
    /// Also open secrets sealed by pre-release builds, which were bound to
    /// their row but not to where they are sent, and re-seal them for their
    /// destination at startup. Turn it on for one start after upgrading such
    /// an installation, then off again: while on, someone who can write to
    /// the database can replay such a blob into a repointed row.
    #[serde(default)]
    pub accept_row_bound_secrets: bool,
}

/// `crypto.root.*` — the root-key provider.
#[derive(Debug, Clone, Deserialize)]
pub struct CryptoRootConfig {
    /// `"env"` | `"file"`. (`"aws-kms"` is reserved for the later KMS provider
    /// and is rejected at startup until it ships.)
    pub provider: String,
    /// env provider: name of the env var holding the base64 32-byte root key.
    #[serde(default = "default_root_key_env")]
    pub root_key_env: String,
    /// env provider: optional env var holding the **previous** root key,
    /// reachable during a root-rotation window (until the KEK re-wrap sweep
    /// completes; see the rotation runbook in the plan).
    #[serde(default)]
    pub root_key_env_previous: Option<String>,
    /// file provider: path of the file holding the base64 32-byte root key
    /// (e.g. a mounted Kubernetes secret).
    #[serde(default)]
    pub root_key_path: Option<String>,
    /// file provider: optional path of the **previous** root key.
    #[serde(default)]
    pub root_key_path_previous: Option<String>,
}

/// `crypto.cache.*` — the bounded, zeroizing L1 of unwrapped keys (§2.6).
#[derive(Debug, Clone, Deserialize)]
pub struct CryptoCacheConfig {
    /// TTL (seconds) of unwrapped key bytes in RAM. Bounds both root-provider
    /// traffic and the window revoked keys may linger on other instances.
    #[serde(default = "default_unwrapped_key_ttl")]
    pub unwrapped_key_ttl_secs: u64,
    /// Max cached unwrapped keys.
    #[serde(default = "default_unwrapped_key_max")]
    pub unwrapped_key_max: u64,
}

impl Default for CryptoCacheConfig {
    fn default() -> Self {
        CryptoCacheConfig {
            unwrapped_key_ttl_secs: default_unwrapped_key_ttl(),
            unwrapped_key_max: default_unwrapped_key_max(),
        }
    }
}

/// `crypto.rotation.*` — the cluster-coordinated rotation/backfill worker.
#[derive(Debug, Clone, Deserialize)]
pub struct CryptoRotationConfig {
    /// Run the background worker (backfill, sweeps, age-based rotation) on
    /// this instance. Admin-triggered rotation works regardless.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Worker poll interval (seconds).
    #[serde(default = "default_crypto_poll")]
    pub poll_interval_seconds: u64,
    /// Auto-rotate the active DEK once it is older than this many days.
    /// `0` disables age-based DEK rotation.
    #[serde(default = "default_dek_max_age_days")]
    pub dek_max_age_days: i64,
    /// Auto-rotate the active KEK once it is older than this many days.
    /// `0` disables age-based KEK rotation.
    #[serde(default = "default_kek_max_age_days")]
    pub kek_max_age_days: i64,
    /// Rows per backfill / re-encrypt sweep batch (each batch is its own
    /// transaction-free unit; the sweep is keyset-paginated and resumable).
    #[serde(default = "default_sweep_batch_size")]
    pub sweep_batch_size: i64,
}

impl Default for CryptoRotationConfig {
    fn default() -> Self {
        CryptoRotationConfig {
            enabled: default_true(),
            poll_interval_seconds: default_crypto_poll(),
            dek_max_age_days: default_dek_max_age_days(),
            kek_max_age_days: default_kek_max_age_days(),
            sweep_batch_size: default_sweep_batch_size(),
        }
    }
}

impl CryptoConfig {
    /// Poll interval as a [`Duration`].
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.rotation.poll_interval_seconds)
    }
}

/// Refuse a duration setting above [`MAX_DURATION_SECONDS`], naming the key.
fn at_most_100_years(key: &str, seconds: i128) -> Result<(), ConfigError> {
    if seconds > i128::from(MAX_DURATION_SECONDS) {
        return Err(ConfigError::Invalid(format!(
            "{key} must be at most {MAX_DURATION_SECONDS} (100 years), got {seconds}"
        )));
    }
    Ok(())
}

fn default_crypto_algorithm() -> String {
    "aes-256-gcm".into()
}
fn default_root_key_env() -> String {
    "FORGE_ROOT_KEY".into()
}
fn default_unwrapped_key_ttl() -> u64 {
    300
}
fn default_unwrapped_key_max() -> u64 {
    64
}
fn default_crypto_poll() -> u64 {
    300
}
fn default_dek_max_age_days() -> i64 {
    30
}
fn default_kek_max_age_days() -> i64 {
    365
}
fn default_sweep_batch_size() -> i64 {
    500
}

fn default_region() -> String {
    "us-east-1".into()
}
fn default_true() -> bool {
    true
}
fn default_multipart_threshold() -> u64 {
    8 * 1024 * 1024
}
fn default_anonymous_mode() -> String {
    "off".into()
}
fn default_l1_capacity() -> u64 {
    10_000
}
fn default_cache_ttl_seconds() -> u64 {
    30
}
fn default_outbox_batch() -> i64 {
    100
}
fn default_outbox_grace() -> i64 {
    3600
}
fn default_outbox_poll() -> u64 {
    10
}
fn default_outbox_processed_retention() -> u64 {
    7 * 24 * 3600
}
fn default_retention_poll() -> u64 {
    30
}
fn default_retention_run_interval() -> i64 {
    3600
}
fn default_retention_lease() -> i64 {
    300
}
fn default_retention_audit_retention() -> u64 {
    90 * 24 * 3600
}

/// Dotted config keys holding **secret strings**. Their `FORGE_*` environment
/// values are taken verbatim (figment's `Env` provider would otherwise parse
/// `12345` as an integer, `true` as a bool or `[a]` as an array, and the type
/// error would print the value), and errors at these keys never echo the
/// value ([`ConfigError::Load`]).
pub const SECRET_KEYS: &[&str] = &[
    "database.url",
    "redis.url",
    "s3.access_key",
    "s3.secret_key",
    "auth.bootstrap_admin.password",
    "auth.upstream_basic.cache.key_pepper",
    "oidc.client_secret",
    "docker.token_secret",
];

/// Whether an error at config key `path` must not echo its value: one of
/// [`SECRET_KEYS`], or any key whose name marks it as a credential.
fn is_secret_path(path: &[String]) -> bool {
    let joined = path.join(".");
    SECRET_KEYS.iter().any(|k| k.eq_ignore_ascii_case(&joined))
        || path.last().is_some_and(|leaf| {
            let leaf = leaf.to_ascii_lowercase();
            ["password", "secret", "pepper", "token"]
                .iter()
                .any(|marker| leaf.contains(marker))
        })
}

/// The type of a figment value without the value itself.
fn actual_kind(actual: &figment::error::Actual) -> figment::error::Actual {
    use figment::error::Actual;
    let name = match actual {
        Actual::Bool(_) => "bool",
        Actual::Unsigned(_) => "unsigned int",
        Actual::Signed(_) => "signed int",
        Actual::Float(_) => "float",
        Actual::Char(_) => "char",
        Actual::Str(_) => "string",
        Actual::Bytes(_) => "bytes",
        Actual::Other(_) => "value",
        other => return other.clone(),
    };
    Actual::Other(format!("{name} (value redacted)"))
}

/// Render a figment error chain with the values of secret keys redacted (the
/// key name, the expected type and the source are kept, so the message still
/// says what to fix).
fn redacted_load_error(err: &figment::Error) -> String {
    use figment::error::Kind;
    err.clone()
        .into_iter()
        .map(|mut e| {
            if is_secret_path(&e.path) {
                e.kind = match e.kind {
                    Kind::InvalidType(actual, expected) => {
                        Kind::InvalidType(actual_kind(&actual), expected)
                    }
                    Kind::InvalidValue(actual, expected) => {
                        Kind::InvalidValue(actual_kind(&actual), expected)
                    }
                    Kind::UnknownVariant(_, expected) => Kind::Message(format!(
                        "unknown variant (value redacted), expected one of {expected:?}"
                    )),
                    Kind::Unsupported(actual) => Kind::Unsupported(actual_kind(&actual)),
                    other => other,
                };
            }
            e.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Layer the `FORGE_*` environment over `fig`: every key through figment's
/// typed `Env` provider except [`SECRET_KEYS`], which are merged verbatim as
/// strings (same `FORGE_` prefix and `__` nesting).
fn merge_env(fig: Figment) -> Figment {
    let env = || Env::prefixed("FORGE_").split("__");
    let mut fig = fig.merge(env().ignore(SECRET_KEYS));
    for (key, value) in env().only(SECRET_KEYS).iter() {
        fig = fig.merge(Serialized::default(
            key.as_str(),
            normalize_secret_env(&value),
        ));
    }
    fig
}

/// Normalize a secret's environment value the way figment's typed parsing
/// (which every other `FORGE_*` value still gets) and earlier releases did:
/// surrounding whitespace — a trailing newline from a secret file or
/// `kubectl create secret --from-file` — is trimmed, and one pair of
/// surrounding double quotes (an `--env-file` written as `KEY="value"`) is
/// removed. The value is never type-converted.
fn normalize_secret_env(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(trimmed)
        .to_string()
}

/// Whether a secret is still a `<…>` placeholder of an example env file
/// (`<initial admin password>`, `<secret key>`), copied without filling it in.
fn is_placeholder(value: &str) -> bool {
    let value = value.trim();
    value.len() > 2 && value.starts_with('<') && value.ends_with('>')
}

/// [`is_placeholder`] for the password of a connection URL, as the example
/// env files write it (`postgres://forge:<password>@host/forge`).
fn url_password_is_placeholder(url: &str) -> bool {
    url.split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .and_then(|authority| authority.rsplit_once('@'))
        .and_then(|(userinfo, _)| userinfo.split_once(':'))
        .is_some_and(|(_, password)| is_placeholder(password))
}

/// Configuration load / validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required key was missing or the file/env was malformed. The message
    /// never echoes the value of a secret key (see [`SECRET_KEYS`]).
    ///
    /// Holds the already-redacted message rather than the figment error, so
    /// no `source()` chain (an `anyhow` report prints one) can show the raw
    /// value either.
    #[error("configuration error: {0}")]
    Load(String),
    /// A value was present but invalid (bad CIDR, bad bind addr, unknown mode).
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl From<Box<figment::Error>> for ConfigError {
    fn from(err: Box<figment::Error>) -> Self {
        ConfigError::Load(redacted_load_error(&err))
    }
}

impl Config {
    /// Load configuration from an optional TOML file plus `FORGE_*` env
    /// overrides. Nested keys use `__` (e.g. `FORGE_SERVER__BIND`).
    ///
    /// `toml_path` is loaded from **exactly** that path (no parent-directory
    /// search) and must exist: an explicitly configured `FORGE_CONFIG` that
    /// points nowhere fails startup instead of silently running on env and
    /// built-in defaults. Secret keys ([`SECRET_KEYS`]) are read from the
    /// environment verbatim as strings.
    pub fn load(toml_path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut fig = Figment::new();
        if let Some(path) = toml_path {
            if !path.is_file() {
                return Err(ConfigError::Invalid(format!(
                    "configuration file {} does not exist (FORGE_CONFIG must name an \
                     existing TOML file; unset it to configure through FORGE_* \
                     environment variables only)",
                    path.display()
                )));
            }
            fig = fig.merge(Toml::file_exact(path));
        }
        Self::from_figment(merge_env(fig))
    }

    /// Parse the configuration from an explicit [`Figment`] (used by tests to
    /// inject providers without touching the real environment).
    pub fn from_figment(fig: Figment) -> Result<Self, ConfigError> {
        let mut cfg: Config = fig.extract().map_err(Box::new)?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Apply the "blank means unset" rules that serde cannot express:
    /// * an `auth.bootstrap_admin` block without a non-blank password is
    ///   dropped — no password configured means no bootstrap admin (the image
    ///   is configured purely through env, and removing the password after
    ///   the first start is the documented flow);
    /// * a blank `redis.url` (e.g. `FORGE_REDIS__URL=`) means no Redis.
    ///
    /// It also trims `server.public_base_url` and lowercases its scheme:
    /// session cookies are `Secure` and HSTS is sent when it starts with
    /// `https://`, and `HTTPS://host` or ` https://host` (which validation
    /// accepts) must not turn them off.
    fn normalize(&mut self) {
        self.s3.normalize();
        let base = self.server.public_base_url.trim();
        self.server.public_base_url = match base.split_once("://") {
            Some((scheme, rest)) => format!("{}://{rest}", scheme.to_ascii_lowercase()),
            None => base.to_string(),
        };
        if self
            .auth
            .bootstrap_admin
            .as_ref()
            .is_some_and(|ba| ba.password.trim().is_empty())
        {
            tracing::info!(
                "auth.bootstrap_admin has no password configured; no bootstrap admin \
                 will be created"
            );
            self.auth.bootstrap_admin = None;
        }
        // The account is stored and looked up by its canonical username;
        // `validate` reports a name that has none.
        if let Some(ba) = self.auth.bootstrap_admin.as_mut() {
            if let Ok(canonical) = forge_core::auth::canonical_username(&ba.username) {
                ba.username = canonical;
            }
        }
        if self
            .redis
            .url
            .as_deref()
            .is_some_and(|u| u.trim().is_empty())
        {
            self.redis.url = None;
        }
        // `FORGE_BLOB_CACHE__PATH=` turns the blob cache off.
        if self
            .blob_cache
            .path
            .as_deref()
            .is_some_and(|p| p.as_os_str().to_string_lossy().trim().is_empty())
        {
            self.blob_cache.path = None;
        }
    }

    /// Validate cross-cutting invariants that serde cannot express.
    fn validate(&self) -> Result<(), ConfigError> {
        self.server.bind_addr()?;
        self.validate_public_base_url()?;
        // The DNS-rebinding guard's host list, checked before migrations run
        // rather than when the router is built.
        crate::middleware::principal::allowed_hosts(
            &self.public_base_url(),
            &self.server.allowed_hosts,
        )
        .map_err(|e| ConfigError::Invalid(format!("server.allowed_hosts: {e}")))?;
        let (idle, absolute) = self.session_ttls();
        for (name, ttl) in [
            ("session_idle_ttl_seconds", idle),
            ("session_absolute_ttl_seconds", absolute),
        ] {
            if !(1..=MAX_SESSION_TTL_SECONDS).contains(&ttl) {
                return Err(ConfigError::Invalid(format!(
                    "auth.{name} must be between 1 and {MAX_SESSION_TTL_SECONDS} (10 years), got {ttl}"
                )));
            }
        }
        // Eagerly validate the anon policy + trusted CIDRs so a bad value fails
        // at startup rather than mid-request.
        self.anon_policy()?;
        self.trusted_proxy_cidrs()?;
        self.validate_oidc()?;
        self.validate_auth_providers()?;
        if let Some(ba) = &self.auth.bootstrap_admin {
            // A local password account: its name must be one a password
            // login accepts (no `:`).
            forge_core::auth::canonical_password_username(&ba.username)
                .map_err(|e| ConfigError::Invalid(format!("auth.bootstrap_admin.username: {e}")))?;
        }
        match self.auth.login_mode.as_str() {
            "identifier_first" | "combined" => {}
            other => {
                return Err(ConfigError::Invalid(format!(
                    "unknown auth.login_mode {other:?} (expected identifier_first|combined)"
                )))
            }
        }
        self.s3.validate()?;
        self.validate_crypto()?;
        self.proxy.validate()?;
        self.nuget.validate()?;
        self.plugins.validate()?;
        self.docker.validate()?;
        self.validate_workers()?;
        self.validate_insecure_defaults()?;
        if self.server.max_upload_bytes == 0 {
            return Err(ConfigError::Invalid(
                "server.max_upload_bytes must be greater than 0".into(),
            ));
        }
        if self.blob_cache.path.is_some()
            && self.blob_cache.max_bytes == BlobCacheMaxBytes::Bytes(0)
        {
            return Err(ConfigError::Invalid(
                "blob_cache.max_bytes must be greater than 0 (or \"auto\"); unset \
                 blob_cache.path to turn the cache off"
                    .into(),
            ));
        }
        if let Some(budget) = self.staging_budget() {
            let needed = self.largest_staged_set();
            if budget < needed {
                return Err(ConfigError::Invalid(format!(
                    "server.max_staging_bytes ({budget}) must be at least the largest of \
                     server.max_upload_bytes, plugins.max_upload_bytes, \
                     proxy.max_package_bytes and docker.max_blob_bytes plus \
                     nuget.max_nuspec_bytes ({needed}), or 0 for no limit"
                )));
            }
        }
        Ok(())
    }

    /// The largest single item staged in the temp directory: a package push
    /// (of any format) or download, or an image blob.
    fn largest_staged_item(&self) -> u64 {
        self.plugins
            .max_upload_bytes
            .values()
            .fold(self.server.max_upload_bytes, |largest, &bytes| {
                largest.max(bytes)
            })
            .max(self.proxy.max_package_bytes)
            .max(self.docker.max_blob_bytes)
    }

    /// The largest accepted push to a repository of format `format`:
    /// `plugins.max_upload_bytes.<format>`, else `server.max_upload_bytes`.
    pub fn max_upload_bytes(&self, format: &str) -> u64 {
        self.plugins
            .max_upload_bytes
            .get(format)
            .copied()
            .unwrap_or(self.server.max_upload_bytes)
    }

    /// What one push or download stages at once at most: the package, and
    /// its manifest while the package is still held.
    fn largest_staged_set(&self) -> u64 {
        self.largest_staged_item()
            .saturating_add(self.nuget.max_nuspec_bytes)
    }

    /// The directory pushes and proxy downloads are staged in
    /// (`server.staging_dir`).
    pub fn staging_dir(&self) -> std::path::PathBuf {
        self.server
            .staging_dir
            .clone()
            .unwrap_or_else(forge_storage::Staging::default_dir)
    }

    /// The local blob cache's configuration, `None` when it is off
    /// (`blob_cache.path` unset).
    pub fn blob_cache(&self) -> Option<forge_storage::BlobCacheConfig> {
        let path = self.blob_cache.path.clone()?;
        Some(forge_storage::BlobCacheConfig {
            path,
            max_bytes: match self.blob_cache.max_bytes {
                BlobCacheMaxBytes::Auto => forge_storage::CacheLimit::Auto,
                BlobCacheMaxBytes::Bytes(bytes) => forge_storage::CacheLimit::Bytes(bytes),
            },
            min_free_bytes: self.blob_cache.min_free_bytes,
            staging: self
                .staging_budget()
                .map(|budget| (self.staging_dir(), budget)),
        })
    }

    /// The temp-space budget for staging, or `None` for no limit
    /// (`server.max_staging_bytes`, see there for the default).
    pub fn staging_budget(&self) -> Option<u64> {
        match self.server.max_staging_bytes {
            Some(0) => None,
            Some(bytes) => Some(bytes),
            None => Some(
                self.largest_staged_item()
                    .saturating_mul(4)
                    .max(self.largest_staged_set()),
            ),
        }
    }

    /// Background-worker tuning must be usable: a zero interval makes
    /// `tokio::time::interval` panic inside the spawned loop, and a negative
    /// grace would make blob deletes immediate.
    fn validate_workers(&self) -> Result<(), ConfigError> {
        let positive = |key: &str, ok: bool| {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::Invalid(format!(
                    "{key} must be greater than 0"
                )))
            }
        };
        positive(
            "outbox.poll_interval_seconds",
            self.outbox.poll_interval_seconds > 0,
        )?;
        positive("outbox.batch_size", self.outbox.batch_size > 0)?;
        if self.outbox.grace_seconds < 0 {
            return Err(ConfigError::Invalid(
                "outbox.grace_seconds must not be negative".into(),
            ));
        }
        positive(
            "retention.poll_interval_seconds",
            self.retention.poll_interval_seconds > 0,
        )?;
        positive("retention.lease_seconds", self.retention.lease_seconds > 0)?;
        if self.retention.default_run_interval_seconds < 0 {
            return Err(ConfigError::Invalid(
                "retention.default_run_interval_seconds must not be negative".into(),
            ));
        }
        for (key, seconds) in [
            ("outbox.grace_seconds", self.outbox.grace_seconds),
            (
                "retention.default_run_interval_seconds",
                self.retention.default_run_interval_seconds,
            ),
            ("retention.lease_seconds", self.retention.lease_seconds),
        ] {
            at_most_100_years(key, i128::from(seconds))?;
        }
        positive(
            "groups.max_nesting_depth",
            self.groups.max_nesting_depth > 0,
        )?;
        positive(
            "database.max_connections",
            self.database.max_connections > 0,
        )?;
        positive(
            "database.acquire_timeout_seconds",
            self.database.acquire_timeout_seconds > 0,
        )?;
        if let Some(crypto) = self.crypto.as_ref().filter(|c| c.enabled) {
            positive(
                "crypto.rotation.poll_interval_seconds",
                !crypto.rotation.enabled || crypto.rotation.poll_interval_seconds > 0,
            )?;
        }
        Ok(())
    }

    /// Settings that are legal but unsafe or wrong for a production
    /// deployment, reported as startup warnings (not refusals: a lab or an
    /// internal-only plain-HTTP install may choose them deliberately). Empty
    /// while `server.allow_insecure_defaults` is on (local development).
    pub fn deployment_warnings(&self) -> Vec<String> {
        if self.server.allow_insecure_defaults {
            return Vec::new();
        }
        let mut warnings = Vec::new();
        let base = self.public_base_url();
        let host = url::Url::parse(&base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
        let loopback = matches!(
            host.as_deref(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if loopback {
            warnings.push(format!(
                "server.public_base_url is {base}: NuGet clients are handed URLs on this \
                 host, so set it to the address clients use (FORGE_SERVER__PUBLIC_BASE_URL)"
            ));
        }
        if !base.starts_with("https://") {
            warnings.push(format!(
                "server.public_base_url ({base}) is not https: session cookies are issued \
                 without Secure; terminate TLS in front of Forge and use an https:// URL"
            ));
        }
        if !self.crypto.as_ref().is_some_and(|c| c.enabled) {
            warnings.push(
                "secret encryption at rest is disabled (no [crypto] section): upstream \
                 passwords and auth-realm secrets are stored in plaintext in PostgreSQL"
                    .to_string(),
            );
        }
        warnings
    }

    /// Refuse known-insecure placeholder credentials unless
    /// `server.allow_insecure_defaults` opts in (dev/compose only): a
    /// `changeme` bootstrap-admin password, `minioadmin` S3 keys, or a secret
    /// still holding a `<…>` placeholder of the example env files
    /// (`<initial admin password>`, `postgres://forge:<password>@…`). (A blank
    /// bootstrap password is not a placeholder: it means "no bootstrap admin",
    /// see [`Self::normalize`].)
    fn validate_insecure_defaults(&self) -> Result<(), ConfigError> {
        let mut found: Vec<String> = Vec::new();
        if let Some(ba) = &self.auth.bootstrap_admin {
            if ba.password.trim().eq_ignore_ascii_case("changeme") {
                found.push("auth.bootstrap_admin.password is the \"changeme\" placeholder".into());
            }
        }
        // Only static keys can be placeholders (the other modes have none).
        let static_keys = self.s3.credentials == S3CredentialsMode::Static;
        let s3_key = |key: &Option<String>, check: fn(&str) -> bool| {
            static_keys && key.as_deref().is_some_and(check)
        };
        if s3_key(&self.s3.access_key, |k| k == "minioadmin")
            || s3_key(&self.s3.secret_key, |k| k == "minioadmin")
        {
            found.push("s3.access_key/secret_key are the \"minioadmin\" defaults".into());
        }
        let unedited: Vec<&str> = [
            (
                "auth.bootstrap_admin.password",
                self.auth
                    .bootstrap_admin
                    .as_ref()
                    .is_some_and(|ba| is_placeholder(&ba.password)),
            ),
            ("s3.access_key", s3_key(&self.s3.access_key, is_placeholder)),
            ("s3.secret_key", s3_key(&self.s3.secret_key, is_placeholder)),
            (
                "the database.url password",
                url_password_is_placeholder(&self.database.url),
            ),
            (
                "the redis.url password",
                self.redis
                    .url
                    .as_deref()
                    .is_some_and(url_password_is_placeholder),
            ),
            (
                "auth.upstream_basic.cache.key_pepper",
                self.auth
                    .upstream_basic
                    .as_ref()
                    .is_some_and(|ub| is_placeholder(&ub.cache.key_pepper)),
            ),
            (
                "oidc.client_secret",
                self.oidc
                    .as_ref()
                    .is_some_and(|o| is_placeholder(&o.client_secret)),
            ),
        ]
        .into_iter()
        .filter_map(|(key, hit)| hit.then_some(key))
        .collect();
        if !unedited.is_empty() {
            found.push(format!(
                "{} still hold a \"<…>\" placeholder of an example file",
                unedited.join(", ")
            ));
        }
        if found.is_empty() {
            return Ok(());
        }
        if self.server.allow_insecure_defaults {
            for issue in &found {
                tracing::warn!(%issue, "starting with insecure default credentials (server.allow_insecure_defaults = true)");
            }
            return Ok(());
        }
        Err(ConfigError::Invalid(format!(
            "refusing to start with insecure default credentials: {}; set real secrets \
             (e.g. FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD, FORGE_S3__ACCESS_KEY / \
             FORGE_S3__SECRET_KEY) or, for local development only, \
             server.allow_insecure_defaults = true (FORGE_SERVER__ALLOW_INSECURE_DEFAULTS=true)",
            found.join("; ")
        )))
    }

    /// Validate the optional `[crypto]` section when present and enabled
    /// (slice 12.5): the algorithm name must parse and the root provider must
    /// be a supported kind with the fields it needs. The root key **bytes**
    /// are deliberately not read here — that happens once at startup when the
    /// provider is built, so a missing/short key still refuses to boot, just
    /// with the more precise root-provider error.
    fn validate_crypto(&self) -> Result<(), ConfigError> {
        let Some(crypto) = &self.crypto else {
            return Ok(());
        };
        if !crypto.enabled {
            return Ok(());
        }

        at_most_100_years(
            "crypto.cache.unwrapped_key_ttl_secs",
            i128::from(crypto.cache.unwrapped_key_ttl_secs),
        )?;
        for (key, days) in [
            (
                "crypto.rotation.dek_max_age_days",
                crypto.rotation.dek_max_age_days,
            ),
            (
                "crypto.rotation.kek_max_age_days",
                crypto.rotation.kek_max_age_days,
            ),
        ] {
            if i128::from(days) * 86_400 > i128::from(MAX_DURATION_SECONDS) {
                return Err(ConfigError::Invalid(format!(
                    "{key} must be at most {} (100 years), got {days}",
                    MAX_DURATION_SECONDS / 86_400
                )));
            }
        }

        forge_crypto::Algorithm::parse(&crypto.algorithm).map_err(|_| {
            ConfigError::Invalid(format!(
                "unknown crypto.algorithm {:?} (expected aes-256-gcm|xchacha20-poly1305)",
                crypto.algorithm
            ))
        })?;

        match crypto.root.provider.as_str() {
            "env" => {
                if crypto.root.root_key_env.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "crypto.root.root_key_env must not be empty for the env provider".into(),
                    ));
                }
            }
            "file" => {
                if crypto
                    .root
                    .root_key_path
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    return Err(ConfigError::Invalid(
                        "crypto.root.root_key_path is required for the file provider".into(),
                    ));
                }
            }
            "aws-kms" => {
                return Err(ConfigError::Invalid(
                    "crypto.root.provider \"aws-kms\" is not supported yet (the KmsProvider \
                     trait is the seam; use \"env\" or \"file\")"
                        .into(),
                ));
            }
            other => {
                return Err(ConfigError::Invalid(format!(
                    "unknown crypto.root.provider {other:?} (expected env|file)"
                )));
            }
        }
        Ok(())
    }

    /// Validate the slice-12.3 provider chain + `[auth.upstream_basic]` block.
    ///
    /// Checks (plan §2.3 startup validation):
    /// * every `auth.providers` id is known (`local-password` / `upstream-basic`)
    ///   and not duplicated;
    /// * if `upstream-basic` is in the chain, `[auth.upstream_basic]` is present
    ///   and `enabled`, its `url` parses as an http/https URL (the SSRF scheme
    ///   check), its `key_pepper` is non-empty, and `required_groups` is empty
    ///   unless `groups_path` is set;
    /// * conversely, an enabled `[auth.upstream_basic]` block that is NOT in the
    ///   chain is rejected (a likely misconfiguration that would silently never
    ///   forward).
    fn validate_auth_providers(&self) -> Result<(), ConfigError> {
        let mut seen = std::collections::HashSet::new();
        for id in &self.auth.providers {
            if !matches!(id.as_str(), "local-password" | "upstream-basic") {
                return Err(ConfigError::Invalid(format!(
                    "unknown auth.providers id {id:?} (expected local-password|upstream-basic)"
                )));
            }
            if !seen.insert(id.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate auth.providers id {id:?}"
                )));
            }
        }

        let chain_has_upstream = self.auth.providers.iter().any(|p| p == "upstream-basic");
        let block_enabled = self
            .auth
            .upstream_basic
            .as_ref()
            .map(|u| u.enabled)
            .unwrap_or(false);

        if chain_has_upstream && !block_enabled {
            return Err(ConfigError::Invalid(
                "auth.providers includes 'upstream-basic' but [auth.upstream_basic] is absent or disabled".into(),
            ));
        }
        if block_enabled && !chain_has_upstream {
            return Err(ConfigError::Invalid(
                "[auth.upstream_basic] is enabled but 'upstream-basic' is not in auth.providers"
                    .into(),
            ));
        }

        if let Some(u) = self.auth.upstream_basic.as_ref().filter(|u| u.enabled) {
            let url = url::Url::parse(u.url.trim()).map_err(|e| {
                ConfigError::Invalid(format!("invalid auth.upstream_basic.url {:?}: {e}", u.url))
            })?;
            match url.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(ConfigError::Invalid(format!(
                        "auth.upstream_basic.url scheme {other:?} is not http/https"
                    )))
                }
            }
            // Every login forwards the user's password there: plain http only
            // for a loopback sidecar or when explicitly allowed.
            forge_core::net::ssrf::validate_credential_forward_url(u.url.trim(), u.allow_http)
                .map_err(|e| ConfigError::Invalid(format!("auth.upstream_basic.url: {e}")))?;
            if url.scheme() == "http" {
                tracing::warn!(
                    "auth.upstream_basic.url is http://; the user's password is forwarded in cleartext — use https in production"
                );
            }
            if u.cache.key_pepper.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "auth.upstream_basic.cache.key_pepper must not be empty (it keys the validated-credential cache HMAC)".into(),
                ));
            }
            if !u.required_groups.is_empty() && u.groups_path.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "auth.upstream_basic.required_groups is set but groups_path is empty".into(),
                ));
            }
        }

        Ok(())
    }

    /// Validate the optional `[oidc]` section when present and enabled.
    ///
    /// Checks (per plan §3.5/§4 Phase 0): issuer is a non-empty `https` URL,
    /// `client_id`/`client_secret`/`redirect_url` are non-empty, and the
    /// `redirect_url` shares scheme+host (+port) with `server.public_base_url`
    /// and ends in the canonical `/auth/oidc/callback` path. A disabled section
    /// is not validated (an operator may keep an incomplete block while off).
    fn validate_oidc(&self) -> Result<(), ConfigError> {
        let Some(oidc) = &self.oidc else {
            return Ok(());
        };
        if !oidc.enabled {
            return Ok(());
        }

        let issuer = url::Url::parse(oidc.issuer.trim()).map_err(|e| {
            ConfigError::Invalid(format!("invalid oidc.issuer {:?}: {e}", oidc.issuer))
        })?;
        // The issuer must be https — except when `allow_private_issuer` is set,
        // which signals a trusted IdP on a private/dev network (e.g. a
        // self-hosted Keycloak or the in-process test IdP) where plain http is
        // acceptable. This mirrors the relaxed SSRF posture that flag also
        // enables, so the two knobs move together.
        if issuer.scheme() != "https" && !(oidc.allow_private_issuer && issuer.scheme() == "http") {
            return Err(ConfigError::Invalid(format!(
                "oidc.issuer must be https, got {:?}",
                oidc.issuer
            )));
        }
        if oidc.client_id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "oidc.client_id must not be empty".into(),
            ));
        }
        if oidc.client_secret.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "oidc.client_secret must not be empty".into(),
            ));
        }

        let redirect = url::Url::parse(oidc.redirect_url.trim()).map_err(|e| {
            ConfigError::Invalid(format!(
                "invalid oidc.redirect_url {:?}: {e}",
                oidc.redirect_url
            ))
        })?;
        let base = url::Url::parse(&self.public_base_url()).map_err(|e| {
            ConfigError::Invalid(format!(
                "invalid server.public_base_url {:?}: {e}",
                self.server.public_base_url
            ))
        })?;
        if redirect.scheme() != base.scheme()
            || redirect.host_str() != base.host_str()
            || redirect.port_or_known_default() != base.port_or_known_default()
        {
            return Err(ConfigError::Invalid(format!(
                "oidc.redirect_url host {:?} must match server.public_base_url host {:?}",
                oidc.redirect_url, self.server.public_base_url
            )));
        }
        if redirect.path() != "/auth/oidc/callback" {
            return Err(ConfigError::Invalid(format!(
                "oidc.redirect_url path must be /auth/oidc/callback, got {:?}",
                redirect.path()
            )));
        }
        crate::auth::normalize_endpoint_hosts(&oidc.endpoint_hosts)
            .map_err(|e| ConfigError::Invalid(format!("oidc.{e}")))?;
        Ok(())
    }

    /// Build the [`AnonPolicy`] from `auth.anonymous_mode` + allowlist tokens.
    pub fn anon_policy(&self) -> Result<AnonPolicy, ConfigError> {
        match self.auth.anonymous_mode.to_ascii_lowercase().as_str() {
            "off" => Ok(AnonPolicy::Off),
            "all" => Ok(AnonPolicy::All),
            "allowlist" => AnonPolicy::allowlist_from_tokens(&self.auth.anonymous_ip_allowlist)
                .map_err(|e| ConfigError::Invalid(e.to_string())),
            other => Err(ConfigError::Invalid(format!(
                "unknown auth.anonymous_mode {other:?} (expected off|allowlist|all)"
            ))),
        }
    }

    /// Parse `auth.trusted_proxy_cidrs` into [`IpNet`]s. A bare IP is accepted
    /// as a single-host CIDR.
    pub fn trusted_proxy_cidrs(&self) -> Result<Vec<IpNet>, ConfigError> {
        let mut out = Vec::with_capacity(self.auth.trusted_proxy_cidrs.len());
        for raw in &self.auth.trusted_proxy_cidrs {
            let tok = raw.trim();
            if tok.is_empty() {
                continue;
            }
            // Mapped-IPv4 entries (`::ffff:10.0.0.1`) become plain IPv4: peers
            // are canonicalized before matching.
            use forge_core::auth::client_ip::canonical_net;
            if let Ok(net) = tok.parse::<IpNet>() {
                out.push(canonical_net(net));
            } else if let Ok(ip) = tok.parse::<std::net::IpAddr>() {
                let prefix = match ip {
                    std::net::IpAddr::V4(_) => 32,
                    std::net::IpAddr::V6(_) => 128,
                };
                out.push(canonical_net(
                    IpNet::new(ip, prefix).expect("full-length prefix is valid"),
                ));
            } else {
                return Err(ConfigError::Invalid(format!(
                    "invalid trusted_proxy_cidr {tok:?}"
                )));
            }
        }
        Ok(out)
    }

    /// Resolve the browser-session TTLs `(idle, absolute)` in seconds.
    ///
    /// Precedence: explicit `auth.session_*` → legacy `oidc.session_*` (when an
    /// `[oidc]` block is present — preserves pre-12.7 deployments that tuned
    /// them there) → defaults (8h idle / 7d absolute).
    pub fn session_ttls(&self) -> (u64, u64) {
        let idle = self
            .auth
            .session_idle_ttl_seconds
            .or_else(|| self.oidc.as_ref().map(|o| o.session_idle_ttl_seconds))
            .unwrap_or_else(default_session_idle_ttl);
        let absolute = self
            .auth
            .session_absolute_ttl_seconds
            .or_else(|| self.oidc.as_ref().map(|o| o.session_absolute_ttl_seconds))
            .unwrap_or_else(default_session_absolute_ttl);
        (idle, absolute)
    }

    /// `server.public_base_url` must be an absolute http(s) URL with a host
    /// and without query or fragment: it builds every absolute `@id` in NuGet
    /// responses, the same-origin and allowlist host checks, and the cookie
    /// security decision.
    fn validate_public_base_url(&self) -> Result<(), ConfigError> {
        let raw = &self.server.public_base_url;
        let invalid =
            |why: &str| ConfigError::Invalid(format!("server.public_base_url {raw:?} {why}"));
        let url = url::Url::parse(raw.trim()).map_err(|e| {
            invalid(&format!(
                "is not an absolute URL ({e}), e.g. https://nuget.example.com"
            ))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(invalid("must use http or https"));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(invalid("must name a host"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(invalid("must not have a query or fragment"));
        }
        Ok(())
    }

    /// Public base URL with any trailing slash removed.
    pub fn public_base_url(&self) -> String {
        self.server
            .public_base_url
            .trim_end_matches('/')
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid TOML covering only required keys.
    const MINIMAL: &str = r#"
        [server]
        bind = "0.0.0.0:8080"
        public_base_url = "https://forge.example.com/"

        [database]
        url = "postgres://forge:forge@localhost/forge"

        [s3]
        endpoint = "http://localhost:7070"
        bucket = "forge"
        access_key = "test"
        secret_key = "test"

        [auth]
    "#;

    fn fig_from_toml(toml: &str) -> Figment {
        Figment::new().merge(Toml::string(toml))
    }

    #[test]
    fn deployment_warnings_flag_http_loopback_and_plaintext_secrets() {
        let https = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        let w = https.deployment_warnings();
        assert_eq!(w.len(), 1, "only the missing [crypto] section: {w:?}");
        assert!(w[0].contains("plaintext"));

        let local = MINIMAL.replace("https://forge.example.com/", "http://localhost:8421");
        let cfg = Config::from_figment(fig_from_toml(&local)).expect("valid");
        let w = cfg.deployment_warnings();
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w.iter().any(|m| m.contains("not https")));
        assert!(w.iter().any(|m| m.contains("NuGet clients")));

        let dev = local.replacen(
            "public_base_url = \"http://localhost:8421\"",
            "public_base_url = \"http://localhost:8421\"\n        allow_insecure_defaults = true",
            1,
        );
        let cfg = Config::from_figment(fig_from_toml(&dev)).expect("valid");
        assert!(cfg.deployment_warnings().is_empty(), "dev mode stays quiet");
    }

    #[test]
    fn debug_output_redacts_connection_secrets() {
        let toml = MINIMAL
            .replace(
                "postgres://forge:forge@localhost/forge",
                "postgres://forge:db-secret-pw@localhost/forge?sslpassword=tls-secret",
            )
            .replace("secret_key = \"test\"", "secret_key = \"s3-secret-key\"")
            + "\n[redis]\nurl = \"rediss://:redis-secret-pw@cache:6380/0\"\n";
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        let shown = format!("{cfg:?}");
        for secret in [
            "db-secret-pw",
            "tls-secret",
            "s3-secret-key",
            "redis-secret-pw",
        ] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert!(shown.contains("postgres://forge:redacted@localhost/forge"));
        assert!(shown.contains("rediss://:redacted@cache:6380/0"));
        assert_eq!(redacted_url("not a url"), "<unparsable url>");
    }

    #[test]
    fn nuget_archive_limits_default_and_override() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert_eq!(
            cfg.nuget.limits(),
            forge_format_nuget::NupkgLimits::default()
        );
        assert_eq!(cfg.nuget.max_nuspec_bytes, 1024 * 1024);

        let tuned = format!(
            "{MINIMAL}\n[nuget]\nmax_entries = 50000\nmax_total_uncompressed_bytes = 68719476736\n"
        );
        let cfg = Config::from_figment(fig_from_toml(&tuned)).expect("valid");
        assert_eq!(cfg.nuget.limits().max_entries, 50_000);
        assert_eq!(cfg.nuget.limits().max_total_uncompressed, 64 << 30);
        assert_eq!(cfg.nuget.max_nuspec_compression_ratio, 200);

        let zero = format!("{MINIMAL}\n[nuget]\nmax_nuspec_bytes = 0\n");
        let err = Config::from_figment(fig_from_toml(&zero)).unwrap_err();
        assert!(err.to_string().contains("nuget.max_nuspec_bytes"), "{err}");
    }

    #[test]
    fn loads_minimal_with_defaults() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert_eq!(cfg.server.bind, "0.0.0.0:8080");
        // public_base_url trims the trailing slash.
        assert_eq!(cfg.public_base_url(), "https://forge.example.com");
        // Defaults applied.
        assert_eq!(cfg.s3.region, "us-east-1");
        assert!(cfg.s3.force_path_style);
        assert_eq!(cfg.auth.anonymous_mode, "off");
        assert!(!cfg.auth.allow_password_basic);
        assert!(cfg.redis.url.is_none());
        assert_eq!(cfg.cache.l1_max_capacity, 10_000);
        assert_eq!(cfg.outbox.batch_size, 100);
        assert_eq!(cfg.outbox.processed_retention_seconds, 7 * 24 * 3600);
        assert!(cfg.retention.enabled);
        assert_eq!(cfg.retention.poll_interval_seconds, 30);
        assert_eq!(cfg.retention.default_run_interval_seconds, 3600);
        assert_eq!(cfg.retention.lease_seconds, 300);
        assert!(matches!(cfg.anon_policy().unwrap(), AnonPolicy::Off));
        // Web UI: enabled by default, served from `web/dist`.
        assert!(cfg.web.enabled);
        assert_eq!(cfg.web.assets_dir, "web/dist");
    }

    #[test]
    fn web_block_overrides_defaults() {
        let toml = MINIMAL.replace(
            "[auth]",
            "[auth]\n[web]\nenabled = false\nassets_dir = \"/srv/ui\"",
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        assert!(!cfg.web.enabled);
        assert_eq!(cfg.web.assets_dir, "/srv/ui");
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn env_overrides_nested_keys() {
        // figment's `Jail` provides a sandboxed env so we can assert that
        // `FORGE_*` env vars override TOML values via the `__` nested separator.
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", MINIMAL)?;
            jail.set_env("FORGE_SERVER__BIND", "127.0.0.1:9999");
            jail.set_env("FORGE_AUTH__ALLOW_PASSWORD_BASIC", "true");
            jail.set_env("FORGE_REDIS__URL", "redis://localhost:6379");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            assert_eq!(cfg.server.bind, "127.0.0.1:9999");
            assert!(cfg.auth.allow_password_basic);
            assert_eq!(cfg.redis.url.as_deref(), Some("redis://localhost:6379"));
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn env_example_var_names_map_to_nested_fields() {
        // Guards `.env.example`: every FORGE_* name documented there must use the
        // `__` nested separator and match a real Config field. This exercises one
        // representative key per section (incl. the doubly-nested bootstrap admin,
        // a numeric, a bool, and a Vec) so a stale example name fails CI.
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", MINIMAL)?;
            jail.set_env("FORGE_SERVER__BIND", "127.0.0.1:9999");
            jail.set_env("FORGE_SERVER__PUBLIC_BASE_URL", "https://forge.test");
            jail.set_env("FORGE_DATABASE__URL", "postgres://u:p@db/forge");
            jail.set_env("FORGE_S3__ENDPOINT", "http://s3.test:7070");
            jail.set_env("FORGE_S3__ACCESS_KEY", "ak");
            jail.set_env("FORGE_S3__SECRET_KEY", "sk");
            jail.set_env("FORGE_S3__FORCE_PATH_STYLE", "false");
            jail.set_env("FORGE_S3__MULTIPART_THRESHOLD", "1048576");
            jail.set_env("FORGE_AUTH__ANONYMOUS_MODE", "allowlist");
            jail.set_env("FORGE_AUTH__ANONYMOUS_IP_ALLOWLIST", "[loopback,private]");
            jail.set_env("FORGE_AUTH__ALLOW_PASSWORD_BASIC", "true");
            jail.set_env("FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME", "root");
            jail.set_env("FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD", "s3cret");
            jail.set_env("FORGE_REDIS__URL", "redis://localhost:6379");
            jail.set_env("FORGE_CACHE__L1_MAX_CAPACITY", "42");
            jail.set_env("FORGE_CACHE__DEFAULT_TTL_SECONDS", "120");
            jail.set_env("FORGE_OUTBOX__BATCH_SIZE", "7");
            jail.set_env("FORGE_OUTBOX__GRACE_SECONDS", "60");
            jail.set_env("FORGE_OUTBOX__POLL_INTERVAL_SECONDS", "3");
            jail.set_env("FORGE_RETENTION__ENABLED", "false");
            jail.set_env("FORGE_RETENTION__POLL_INTERVAL_SECONDS", "11");
            jail.set_env("FORGE_RETENTION__DEFAULT_RUN_INTERVAL_SECONDS", "7200");
            jail.set_env("FORGE_RETENTION__LEASE_SECONDS", "120");
            jail.set_env("FORGE_WEB__ENABLED", "false");
            jail.set_env("FORGE_WEB__ASSETS_DIR", "/srv/ui");
            // OIDC section (redirect host must match public_base_url = https://forge.test).
            jail.set_env("FORGE_OIDC__ISSUER", "https://idp.test/v2.0");
            jail.set_env("FORGE_OIDC__CLIENT_ID", "cid");
            jail.set_env("FORGE_OIDC__CLIENT_SECRET", "csecret");
            jail.set_env(
                "FORGE_OIDC__REDIRECT_URL",
                "https://forge.test/auth/oidc/callback",
            );
            jail.set_env("FORGE_OIDC__SCOPES", "[openid,profile,email]");
            jail.set_env("FORGE_OIDC__CLOCK_SKEW_SECONDS", "30");
            jail.set_env("FORGE_OIDC__USERNAME_CLAIM", "preferred_username");
            jail.set_env("FORGE_OIDC__EMAIL_CLAIM", "email");
            jail.set_env("FORGE_OIDC__DISPLAY_NAME_CLAIM", "name");
            jail.set_env("FORGE_OIDC__AUTO_PROVISION", "false");
            jail.set_env("FORGE_OIDC__LINK_EXISTING_BY_USERNAME", "false");
            jail.set_env("FORGE_OIDC__ADMIN_GROUPS", "[forge-admins]");
            jail.set_env("FORGE_OIDC__ADMIN_CLAIM", "groups");
            jail.set_env("FORGE_OIDC__SESSION_IDLE_TTL_SECONDS", "3600");
            jail.set_env("FORGE_OIDC__SESSION_ABSOLUTE_TTL_SECONDS", "86400");

            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");

            assert_eq!(cfg.server.bind, "127.0.0.1:9999");
            assert_eq!(cfg.public_base_url(), "https://forge.test");
            assert_eq!(cfg.database.url, "postgres://u:p@db/forge");
            assert_eq!(cfg.s3.endpoint, "http://s3.test:7070");
            assert_eq!(cfg.s3.access_key.as_deref(), Some("ak"));
            assert_eq!(cfg.s3.secret_key.as_deref(), Some("sk"));
            assert!(!cfg.s3.force_path_style);
            assert_eq!(cfg.s3.multipart_threshold, 1_048_576);
            assert_eq!(cfg.auth.anonymous_mode, "allowlist");
            assert_eq!(
                cfg.auth.anonymous_ip_allowlist,
                vec!["loopback".to_string(), "private".to_string()]
            );
            assert!(cfg.auth.allow_password_basic);
            let ba = cfg
                .auth
                .bootstrap_admin
                .as_ref()
                .expect("bootstrap admin set via env");
            assert_eq!(ba.username, "root");
            assert_eq!(ba.password, "s3cret");
            assert_eq!(cfg.redis.url.as_deref(), Some("redis://localhost:6379"));
            assert_eq!(cfg.cache.l1_max_capacity, 42);
            assert_eq!(cfg.cache.default_ttl_seconds, 120);
            assert_eq!(cfg.outbox.batch_size, 7);
            assert_eq!(cfg.outbox.grace_seconds, 60);
            assert_eq!(cfg.outbox.poll_interval_seconds, 3);
            assert!(!cfg.retention.enabled);
            assert_eq!(cfg.retention.poll_interval_seconds, 11);
            assert_eq!(cfg.retention.default_run_interval_seconds, 7200);
            assert_eq!(cfg.retention.lease_seconds, 120);
            assert!(!cfg.web.enabled);
            assert_eq!(cfg.web.assets_dir, "/srv/ui");
            let oidc = cfg.oidc.as_ref().expect("oidc set via env");
            assert_eq!(oidc.issuer, "https://idp.test/v2.0");
            assert_eq!(oidc.client_id, "cid");
            assert_eq!(oidc.client_secret, "csecret");
            assert_eq!(oidc.redirect_url, "https://forge.test/auth/oidc/callback");
            assert_eq!(oidc.scopes, vec!["openid", "profile", "email"]);
            assert_eq!(oidc.clock_skew_seconds, 30);
            assert_eq!(oidc.username_claim, "preferred_username");
            assert_eq!(oidc.email_claim, "email");
            assert_eq!(oidc.display_name_claim, "name");
            assert!(!oidc.auto_provision);
            assert!(!oidc.link_existing_by_username);
            assert_eq!(oidc.admin_groups, vec!["forge-admins".to_string()]);
            assert_eq!(oidc.admin_claim, "groups");
            assert_eq!(oidc.session_idle_ttl_seconds, 3600);
            assert_eq!(oidc.session_absolute_ttl_seconds, 86400);
            Ok(())
        });
    }

    #[test]
    fn missing_required_key_errors() {
        // Drop the [database] section.
        let toml = r#"
            [server]
            bind = "0.0.0.0:8080"
            public_base_url = "https://x"
            [s3]
            endpoint = "http://localhost:7070"
            bucket = "forge"
            access_key = "a"
            secret_key = "b"
            [auth]
        "#;
        let err = Config::from_figment(fig_from_toml(toml)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("database") || msg.contains("missing"), "{msg}");
    }

    #[test]
    fn bad_bind_addr_rejected() {
        let toml = MINIMAL.replace("0.0.0.0:8080", "not-an-addr");
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("server.bind"), "{err}");
    }

    #[test]
    fn anonymous_mode_allowlist_parses_tokens() {
        let toml = r#"
            [server]
            bind = "0.0.0.0:8080"
            public_base_url = "https://x"
            [database]
            url = "postgres://x"
            [s3]
            endpoint = "http://localhost:7070"
            bucket = "forge"
            access_key = "a"
            secret_key = "b"
            [auth]
            anonymous_mode = "allowlist"
            anonymous_ip_allowlist = ["loopback", "10.0.0.0/8"]
        "#;
        let cfg = Config::from_figment(fig_from_toml(toml)).expect("valid");
        let policy = cfg.anon_policy().unwrap();
        assert!(policy.allows("127.0.0.1".parse().unwrap()));
        assert!(policy.allows("10.1.2.3".parse().unwrap()));
        assert!(!policy.allows("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn unknown_anonymous_mode_rejected() {
        let toml = MINIMAL.replace("[auth]", "[auth]\nanonymous_mode = \"sometimes\"");
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("anonymous_mode"), "{err}");
    }

    #[test]
    fn s3_conditional_writes_defaults_to_auto_and_maps() {
        // Absent ⇒ `auto`, and `to_storage()` carries the mode across.
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert_eq!(cfg.s3.conditional_writes, ConditionalWritesMode::Auto);
        assert_eq!(
            cfg.s3.to_storage().conditional_writes,
            forge_storage::ConditionalWrites::Auto
        );

        for (value, mode, storage) in [
            (
                "on",
                ConditionalWritesMode::On,
                forge_storage::ConditionalWrites::On,
            ),
            (
                "off",
                ConditionalWritesMode::Off,
                forge_storage::ConditionalWrites::Off,
            ),
            (
                "auto",
                ConditionalWritesMode::Auto,
                forge_storage::ConditionalWrites::Auto,
            ),
        ] {
            let toml = MINIMAL.replace(
                "secret_key = \"test\"",
                &format!("secret_key = \"test\"\nconditional_writes = \"{value}\""),
            );
            let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
            assert_eq!(cfg.s3.conditional_writes, mode, "{value}");
            assert_eq!(cfg.s3.to_storage().conditional_writes, storage, "{value}");
        }
    }

    /// `MINIMAL` with its static keys replaced by `credentials` settings.
    fn without_s3_keys(credentials: &str) -> String {
        MINIMAL.replace(
            "access_key = \"test\"\n        secret_key = \"test\"",
            credentials,
        )
    }

    #[test]
    fn s3_credentials_default_to_static_keys() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert_eq!(cfg.s3.credentials, S3CredentialsMode::Static);
        assert_eq!(
            cfg.s3.to_storage().credentials,
            forge_storage::S3Credentials::from_keys("test", "test")
        );
        // Spelled out, the same.
        let toml = MINIMAL.replace(
            "secret_key = \"test\"",
            "secret_key = \"test\"\ncredentials = \"static\"",
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        assert_eq!(cfg.s3.credentials, S3CredentialsMode::Static);
    }

    #[test]
    fn s3_static_credentials_need_both_keys() {
        for keys in ["", "access_key = \"ak\"", "secret_key = \"sk\""] {
            let err = Config::from_figment(fig_from_toml(&without_s3_keys(keys))).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("s3.access_key and s3.secret_key"), "{msg}");
            assert!(msg.contains("FORGE_S3__ACCESS_KEY"), "{msg}");
        }
    }

    #[test]
    fn s3_default_chain_needs_no_keys() {
        let cfg = Config::from_figment(fig_from_toml(&without_s3_keys(
            "credentials = \"default_chain\"",
        )))
        .expect("valid");
        assert_eq!(cfg.s3.credentials, S3CredentialsMode::DefaultChain);
        assert_eq!(cfg.s3.access_key, None);
        assert_eq!(
            cfg.s3.to_storage().credentials,
            forge_storage::S3Credentials::DefaultChain
        );
    }

    #[test]
    fn s3_web_identity_from_toml() {
        let toml = without_s3_keys(
            r#"credentials = "web_identity"
        [s3.web_identity]
        role_arn = "arn:aws:iam::123456789012:role/forge"
        token_file = "/var/run/secrets/forge/s3/token"
        sts_endpoint = "https://minio.example.com:9000"
        session_name = "forge-eu"
        duration_seconds = 3600"#,
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        assert_eq!(cfg.s3.credentials, S3CredentialsMode::WebIdentity);
        assert_eq!(
            cfg.s3.to_storage().credentials,
            forge_storage::S3Credentials::WebIdentity(forge_storage::WebIdentity {
                role_arn: Some("arn:aws:iam::123456789012:role/forge".into()),
                token_file: "/var/run/secrets/forge/s3/token".into(),
                sts_endpoint: Some("https://minio.example.com:9000".into()),
                session_name: "forge-eu".into(),
                duration_seconds: Some(3600),
            })
        );

        // Only the token file is required: no role (MinIO claim-based
        // policies), AWS STS, the default session name and lifetime.
        let toml = without_s3_keys(
            "credentials = \"web_identity\"\n[s3.web_identity]\ntoken_file = \"/token\"",
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        let wi = cfg.s3.web_identity.as_ref().expect("web_identity");
        assert_eq!(wi.role_arn, None);
        assert_eq!(wi.sts_endpoint, None);
        assert_eq!(wi.session_name, "forge");
        assert_eq!(wi.duration_seconds, None);
    }

    #[test]
    fn s3_web_identity_from_env() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", &without_s3_keys(""))?;
            jail.set_env("FORGE_S3__CREDENTIALS", "web_identity");
            jail.set_env(
                "FORGE_S3__WEB_IDENTITY__ROLE_ARN",
                "arn:aws:iam::123456789012:role/forge",
            );
            jail.set_env(
                "FORGE_S3__WEB_IDENTITY__TOKEN_FILE",
                "/var/run/secrets/forge/s3/token",
            );
            jail.set_env(
                "FORGE_S3__WEB_IDENTITY__STS_ENDPOINT",
                "http://minio.forge.svc:9000",
            );
            jail.set_env("FORGE_S3__WEB_IDENTITY__SESSION_NAME", "forge-1");
            jail.set_env("FORGE_S3__WEB_IDENTITY__DURATION_SECONDS", "900");
            // A chart that renders every variable leaves the keys blank.
            jail.set_env("FORGE_S3__ACCESS_KEY", "");
            jail.set_env("FORGE_S3__SECRET_KEY", " ");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            assert_eq!(cfg.s3.credentials, S3CredentialsMode::WebIdentity);
            assert_eq!(cfg.s3.access_key, None);
            assert_eq!(cfg.s3.secret_key, None);
            let wi = cfg.s3.web_identity.as_ref().expect("web_identity");
            assert_eq!(
                wi.role_arn.as_deref(),
                Some("arn:aws:iam::123456789012:role/forge")
            );
            assert_eq!(
                wi.token_file,
                std::path::Path::new("/var/run/secrets/forge/s3/token")
            );
            assert_eq!(
                wi.sts_endpoint.as_deref(),
                Some("http://minio.forge.svc:9000")
            );
            assert_eq!(wi.session_name, "forge-1");
            assert_eq!(wi.duration_seconds, Some(900));
            Ok(())
        });
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", &without_s3_keys(""))?;
            jail.set_env("FORGE_S3__CREDENTIALS", "default_chain");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            assert_eq!(cfg.s3.credentials, S3CredentialsMode::DefaultChain);
            Ok(())
        });
    }

    #[test]
    fn s3_credential_modes_refuse_settings_they_do_not_use() {
        let web_identity = "[s3.web_identity]\ntoken_file = \"/token\"";
        for (toml, expected) in [
            // Long-lived keys left over next to short-lived credentials.
            (
                MINIMAL.replace(
                    "secret_key = \"test\"",
                    "secret_key = \"test\"\ncredentials = \"default_chain\"",
                ),
                "does not use them",
            ),
            (
                format!(
                    "{}\n{web_identity}",
                    MINIMAL.replace(
                        "secret_key = \"test\"",
                        "secret_key = \"test\"\ncredentials = \"web_identity\"",
                    )
                ),
                "does not use them",
            ),
            // A web identity block the mode ignores.
            (format!("{MINIMAL}\n{web_identity}"), "does not use it"),
            (
                format!(
                    "{}\n{web_identity}",
                    without_s3_keys("credentials = \"default_chain\"")
                ),
                "does not use it",
            ),
            // web_identity without its block.
            (
                without_s3_keys("credentials = \"web_identity\""),
                "FORGE_S3__WEB_IDENTITY__TOKEN_FILE",
            ),
        ] {
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            assert!(err.to_string().contains(expected), "{expected}: {err}");
        }
    }

    #[test]
    fn s3_web_identity_settings_are_validated() {
        let web_identity = |extra: &str| {
            without_s3_keys(&format!(
                "credentials = \"web_identity\"\n[s3.web_identity]\ntoken_file = \"/token\"\n{extra}"
            ))
        };
        for (extra, expected) in [
            ("sts_endpoint = \"minio:9000\"", "sts_endpoint"),
            ("sts_endpoint = \"ftp://minio:9000\"", "sts_endpoint"),
            ("session_name = \"x\"", "session_name"),
            ("session_name = \"forge server\"", "session_name"),
            ("duration_seconds = 899", "duration_seconds"),
            ("duration_seconds = 43201", "duration_seconds"),
        ] {
            let err = Config::from_figment(fig_from_toml(&web_identity(extra))).unwrap_err();
            assert!(err.to_string().contains(expected), "{extra}: {err}");
        }
        let err = Config::from_figment(fig_from_toml(&without_s3_keys(
            "credentials = \"web_identity\"\n[s3.web_identity]\ntoken_file = \"\"",
        )))
        .unwrap_err();
        assert!(err.to_string().contains("token_file"), "{err}");
        let err = Config::from_figment(fig_from_toml(&without_s3_keys(
            "credentials = \"web_identity\"\n[s3.web_identity]\nrole_arn = \"arn:x\"",
        )))
        .unwrap_err();
        assert!(err.to_string().contains("token_file"), "{err}");
        let err = Config::from_figment(fig_from_toml(&without_s3_keys(
            "credentials = \"instance_profile\"",
        )))
        .unwrap_err();
        assert!(err.to_string().contains("instance_profile"), "{err}");
    }

    #[test]
    fn s3_debug_shows_the_credential_source_but_no_secret() {
        let toml = without_s3_keys(
            r#"credentials = "web_identity"
        [s3.web_identity]
        role_arn = "arn:aws:iam::123456789012:role/forge"
        token_file = "/var/run/secrets/forge/s3/token"
        sts_endpoint = "https://sts-user:sts-pw@minio.example.com:9000/""#,
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        let shown = format!("{:?}", cfg.s3);
        for part in [
            "WebIdentity",
            "arn:aws:iam::123456789012:role/forge",
            "/var/run/secrets/forge/s3/token",
            "minio.example.com:9000",
        ] {
            assert!(shown.contains(part), "{part} missing: {shown}");
        }
        assert!(!shown.contains("sts-pw"), "{shown}");
        let storage = format!("{:?}", cfg.s3.to_storage());
        assert!(
            storage.contains("/var/run/secrets/forge/s3/token"),
            "{storage}"
        );
    }

    #[test]
    fn insecure_s3_key_checks_apply_only_to_static_keys() {
        // The same check that refuses `minioadmin` static keys has nothing to
        // look at with short-lived credentials.
        let cfg = Config::from_figment(fig_from_toml(&without_s3_keys(
            "credentials = \"default_chain\"",
        )))
        .expect("valid");
        assert!(cfg.validate_insecure_defaults().is_ok());
        let err = Config::from_figment(fig_from_toml(
            &MINIMAL.replace("access_key = \"test\"", "access_key = \"minioadmin\""),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("minioadmin"), "{err}");
    }

    #[test]
    fn unknown_s3_conditional_writes_rejected() {
        let toml = MINIMAL.replace(
            "secret_key = \"test\"",
            "secret_key = \"test\"\nconditional_writes = \"sometimes\"",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        // serde rejects the unknown variant at extract time.
        assert!(err.to_string().contains("sometimes"), "{err}");
    }

    #[test]
    fn trusted_proxy_cidrs_parse_cidr_and_host() {
        let toml = MINIMAL.replace(
            "[auth]",
            "[auth]\ntrusted_proxy_cidrs = [\"10.0.0.0/8\", \"192.168.1.1\"]",
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        let nets = cfg.trusted_proxy_cidrs().unwrap();
        assert_eq!(nets.len(), 2);
        let a: std::net::IpAddr = "10.2.3.4".parse().unwrap();
        let b: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        assert!(nets[0].contains(&a));
        assert!(nets[1].contains(&b));
    }

    #[test]
    fn bad_trusted_proxy_cidr_rejected() {
        let toml = MINIMAL.replace("[auth]", "[auth]\ntrusted_proxy_cidrs = [\"nope\"]");
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("trusted_proxy_cidr"), "{err}");
    }

    /// A valid `[oidc]` block (Entra-shaped) appended to the minimal config.
    /// `public_base_url` is overridden to a plain-host https URL so the redirect
    /// host check passes.
    const OIDC_BLOCK: &str = r#"
        [oidc]
        issuer = "https://login.microsoftonline.com/tenant-id/v2.0"
        client_id = "abc-123"
        client_secret = "shhh-secret"
        redirect_url = "https://forge.example.com/auth/oidc/callback"
    "#;

    fn minimal_with_oidc(extra: &str) -> String {
        // Use an https base URL whose host matches the redirect_url.
        let base = MINIMAL.replace(
            "public_base_url = \"https://forge.example.com/\"",
            "public_base_url = \"https://forge.example.com\"",
        );
        format!("{base}{OIDC_BLOCK}{extra}")
    }

    #[test]
    fn oidc_absent_means_disabled() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert!(cfg.oidc.is_none());
    }

    #[test]
    fn oidc_valid_block_parses_with_defaults() {
        let cfg = Config::from_figment(fig_from_toml(&minimal_with_oidc(""))).expect("valid");
        let oidc = cfg.oidc.expect("present");
        assert!(oidc.enabled);
        assert_eq!(oidc.client_id, "abc-123");
        assert_eq!(oidc.client_secret, "shhh-secret");
        // Defaults.
        assert_eq!(oidc.scopes, vec!["openid", "profile", "email"]);
        assert_eq!(oidc.clock_skew_seconds, 60);
        assert_eq!(oidc.username_claim, "preferred_username");
        assert_eq!(oidc.email_claim, "email");
        assert_eq!(oidc.display_name_claim, "name");
        assert!(oidc.auto_provision);
        assert!(
            !oidc.link_existing_by_username,
            "linking by username is opt-in"
        );
        assert!(oidc.admin_groups.is_empty());
        assert_eq!(oidc.admin_claim, "roles");
        assert_eq!(oidc.session_idle_ttl_seconds, 8 * 60 * 60);
        assert_eq!(oidc.session_absolute_ttl_seconds, 7 * 24 * 60 * 60);
        // effective_scopes keeps openid; idempotent when already present.
        assert_eq!(oidc.effective_scopes(), vec!["openid", "profile", "email"]);
    }

    #[test]
    fn oidc_effective_scopes_inserts_openid_when_missing() {
        let cfg = Config::from_figment(fig_from_toml(&minimal_with_oidc(
            "\nscopes = [\"profile\", \"email\"]",
        )))
        .expect("valid");
        let oidc = cfg.oidc.expect("present");
        assert_eq!(oidc.effective_scopes(), vec!["openid", "profile", "email"]);
    }

    #[test]
    fn oidc_debug_redacts_client_secret() {
        let cfg = Config::from_figment(fig_from_toml(&minimal_with_oidc(""))).expect("valid");
        let dbg = format!("{:?}", cfg.oidc.as_ref().unwrap());
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(!dbg.contains("shhh-secret"), "{dbg}");
        // And the top-level Config Debug must not leak it either.
        let full = format!("{cfg:?}");
        assert!(!full.contains("shhh-secret"), "{full}");
    }

    #[test]
    fn oidc_missing_client_id_rejected() {
        let toml = minimal_with_oidc("").replace("client_id = \"abc-123\"", "client_id = \"\"");
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("oidc.client_id"), "{err}");
    }

    #[test]
    fn public_base_url_must_be_an_absolute_http_url() {
        for bad in [
            "nuget.example.com",
            "ftp://nuget.example.com",
            "https://nuget.example.com/?x=1",
            "https://nuget.example.com/#top",
            "",
        ] {
            let toml = MINIMAL.replace("https://forge.example.com/", bad);
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            assert!(
                err.to_string().contains("server.public_base_url"),
                "{bad:?}: {err}"
            );
        }
        for good in ["http://localhost:8421", "https://nuget.example.com/feeds/"] {
            let toml = MINIMAL.replace("https://forge.example.com/", good);
            Config::from_figment(fig_from_toml(&toml)).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
    }

    #[test]
    fn session_ttls_must_be_positive_and_bounded() {
        for (key, value) in [
            ("session_idle_ttl_seconds", "0"),
            ("session_absolute_ttl_seconds", "0"),
            ("session_idle_ttl_seconds", "18446744073709551615"),
        ] {
            let toml = MINIMAL.replace("[auth]", &format!("[auth]\n{key} = {value}"));
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            assert!(err.to_string().contains(key), "{key} = {value}: {err}");
        }
    }

    #[test]
    fn auth_section_may_be_left_out_and_allowed_hosts_are_checked_early() {
        let toml = MINIMAL.replace("[auth]", "");
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("no [auth] table");
        assert_eq!(cfg.auth.anonymous_mode, "off");
        let toml = MINIMAL.replace(
            "public_base_url = \"https://forge.example.com/\"",
            "public_base_url = \"https://forge.example.com/\"\nallowed_hosts = [\"https://bad/\"]",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("server.allowed_hosts"), "{err}");
    }

    #[test]
    fn oidc_non_https_issuer_rejected() {
        let toml = minimal_with_oidc("").replace(
            "https://login.microsoftonline.com",
            "http://login.microsoftonline.com",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("oidc.issuer"), "{err}");
    }

    #[test]
    fn oidc_mismatched_redirect_host_rejected() {
        let toml = minimal_with_oidc("").replace(
            "https://forge.example.com/auth/oidc/callback",
            "https://evil.example.org/auth/oidc/callback",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("oidc.redirect_url"), "{err}");
    }

    #[test]
    fn oidc_wrong_redirect_path_rejected() {
        let toml = minimal_with_oidc("").replace(
            "https://forge.example.com/auth/oidc/callback",
            "https://forge.example.com/callback",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("oidc.redirect_url"), "{err}");
    }

    #[test]
    fn oidc_http_issuer_allowed_only_with_allow_private_issuer() {
        // Plain-http issuer is rejected by default …
        let toml = minimal_with_oidc("").replace(
            "https://login.microsoftonline.com",
            "http://login.microsoftonline.com",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("oidc.issuer"), "{err}");

        // … but accepted when allow_private_issuer is set (trusted private IdP).
        let toml = toml.replace("[oidc]", "[oidc]\nallow_private_issuer = true");
        let cfg = Config::from_figment(fig_from_toml(&toml))
            .expect("http issuer allowed with allow_private_issuer");
        let oidc = cfg.oidc.expect("present");
        assert!(oidc.allow_private_issuer);
        assert!(oidc.issuer.starts_with("http://"));
    }

    #[test]
    fn oidc_disabled_block_skips_validation() {
        // A disabled section with an otherwise-invalid (http) issuer must parse.
        let toml = minimal_with_oidc("")
            .replace("[oidc]", "[oidc]\nenabled = false")
            .replace(
                "https://login.microsoftonline.com",
                "http://login.microsoftonline.com",
            );
        let cfg =
            Config::from_figment(fig_from_toml(&toml)).expect("disabled section is not validated");
        assert!(!cfg.oidc.unwrap().enabled);
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn oidc_env_overrides_nested_keys() {
        figment::Jail::expect_with(|jail| {
            let base = MINIMAL.replace(
                "public_base_url = \"https://forge.example.com/\"",
                "public_base_url = \"https://forge.test\"",
            );
            jail.create_file("forge.toml", &base)?;
            jail.set_env(
                "FORGE_OIDC__ISSUER",
                "https://login.microsoftonline.com/t/v2.0",
            );
            jail.set_env("FORGE_OIDC__CLIENT_ID", "cid");
            jail.set_env("FORGE_OIDC__CLIENT_SECRET", "csecret");
            jail.set_env(
                "FORGE_OIDC__REDIRECT_URL",
                "https://forge.test/auth/oidc/callback",
            );
            jail.set_env("FORGE_OIDC__ADMIN_GROUPS", "[forge-admins]");
            jail.set_env("FORGE_OIDC__AUTO_PROVISION", "false");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            let oidc = cfg.oidc.expect("present via env");
            assert_eq!(oidc.client_id, "cid");
            assert_eq!(oidc.client_secret, "csecret");
            assert_eq!(oidc.admin_groups, vec!["forge-admins".to_string()]);
            assert!(!oidc.auto_provision);
            Ok(())
        });
    }

    // ── slice 12.3: auth.providers + [auth.upstream_basic] ──────────────────

    /// A minimal valid upstream-basic block + matching provider chain appended.
    fn minimal_with_upstream(extra: &str) -> String {
        let providers = "providers = [\"local-password\", \"upstream-basic\"]\n";
        let block = r#"
            [auth.upstream_basic]
            url = "https://nexus.internal/service/rest/v1/status"
            [auth.upstream_basic.cache]
            key_pepper = "a-high-entropy-pepper"
        "#;
        MINIMAL.replace("[auth]", &format!("[auth]\n{providers}{block}{extra}"))
    }

    #[test]
    fn default_providers_is_local_only() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert_eq!(cfg.auth.providers, vec!["local-password".to_string()]);
        assert!(cfg.auth.upstream_basic.is_none());
    }

    /// The `[auth.upstream_basic]` and `[oidc]` seeds refuse a misspelled key
    /// instead of seeding the realm with that gate turned off, as a realm
    /// config set through the admin API does.
    #[test]
    fn legacy_realm_seeds_refuse_misspelled_keys() {
        let upstream = minimal_with_upstream("").replace(
            "[auth.upstream_basic.cache]",
            "identity_pth = \"login\"\n[auth.upstream_basic.cache]",
        );
        let err = Config::from_figment(fig_from_toml(&upstream)).unwrap_err();
        assert!(err.to_string().contains("identity_pth"), "{err}");

        let cache = minimal_with_upstream("negative_ttl = 5\n");
        let err = Config::from_figment(fig_from_toml(&cache)).unwrap_err();
        assert!(err.to_string().contains("negative_ttl"), "{err}");

        let oidc = minimal_with_oidc("\nrequired_claim = { tid = [\"tenant\"] }");
        let err = Config::from_figment(fig_from_toml(&oidc)).unwrap_err();
        assert!(err.to_string().contains("required_claim"), "{err}");

        // The correctly spelled keys still load.
        let oidc = minimal_with_oidc("\nrequired_claims = { tid = [\"tenant\"] }");
        let cfg = Config::from_figment(fig_from_toml(&oidc)).expect("valid");
        assert_eq!(cfg.oidc.unwrap().required_claims["tid"], vec!["tenant"]);
    }

    /// `HTTPS://` and surrounding whitespace pass validation, so they must
    /// count as https for the cookie and HSTS decision (`starts_with`).
    #[test]
    fn public_base_url_scheme_case_and_whitespace_still_count_as_https() {
        for base in [
            "HTTPS://forge.example.com/",
            "  https://forge.example.com/ ",
        ] {
            let toml = MINIMAL.replace("https://forge.example.com/", base);
            let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
            assert_eq!(
                cfg.public_base_url(),
                "https://forge.example.com",
                "{base:?}"
            );
            assert!(
                !cfg.deployment_warnings()
                    .iter()
                    .any(|w| w.contains("not https")),
                "{base:?}"
            );
        }
    }

    #[test]
    fn the_blob_cache_is_off_unless_a_path_is_set() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert!(cfg.blob_cache().is_none());

        let blank = format!("{MINIMAL}\n[blob_cache]\npath = \" \"\nmax_bytes = 0\n");
        let cfg = Config::from_figment(fig_from_toml(&blank)).expect("blank path: off");
        assert!(cfg.blob_cache().is_none());
    }

    #[test]
    fn blob_cache_max_bytes_is_auto_or_a_byte_count() {
        let auto = format!("{MINIMAL}\n[blob_cache]\npath = \"/var/cache/forge\"\n");
        let cache = Config::from_figment(fig_from_toml(&auto))
            .expect("valid")
            .blob_cache()
            .expect("on");
        assert_eq!(cache.path, std::path::PathBuf::from("/var/cache/forge"));
        assert_eq!(cache.max_bytes, forge_storage::CacheLimit::Auto);
        assert_eq!(cache.min_free_bytes, None);
        let (staging_dir, budget) = cache.staging.expect("staging budget");
        assert_eq!(staging_dir, forge_storage::Staging::default_dir());
        assert_eq!(budget, 4 * 1024 * 1024 * 1024);

        for (value, expected) in [
            ("\"AUTO\"", forge_storage::CacheLimit::Auto),
            ("10737418240", forge_storage::CacheLimit::Bytes(10 << 30)),
            ("\"1048576\"", forge_storage::CacheLimit::Bytes(1 << 20)),
        ] {
            let toml = format!(
                "{MINIMAL}\n[blob_cache]\npath = \"/c\"\nmax_bytes = {value}\nmin_free_bytes = 1024\n"
            );
            let cache = Config::from_figment(fig_from_toml(&toml))
                .expect(value)
                .blob_cache()
                .expect("on");
            assert_eq!(cache.max_bytes, expected, "{value}");
            assert_eq!(cache.min_free_bytes, Some(1024));
        }

        for (value, message) in [
            ("0", "blob_cache.max_bytes"),
            ("\"lots\"", "auto"),
            ("-1", "auto"),
        ] {
            let toml = format!("{MINIMAL}\n[blob_cache]\npath = \"/c\"\nmax_bytes = {value}\n");
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            assert!(err.to_string().contains(message), "{value}: {err}");
        }
    }

    #[test]
    fn staging_budget_defaults_to_four_of_the_largest_item_and_is_validated() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        let largest = cfg.server.max_upload_bytes.max(cfg.proxy.max_package_bytes);
        assert_eq!(cfg.staging_budget(), Some(4 * largest));
        assert_eq!(cfg.staging_dir(), forge_storage::Staging::default_dir());

        let unlimited = MINIMAL.replace(
            "[server]",
            "[server]\nmax_staging_bytes = 0\nstaging_dir = \"/var/tmp/forge\"",
        );
        let cfg = Config::from_figment(fig_from_toml(&unlimited)).expect("valid");
        assert_eq!(cfg.staging_budget(), None);
        assert_eq!(
            cfg.staging_dir(),
            std::path::PathBuf::from("/var/tmp/forge")
        );

        // Smaller than one maximum-size push: every such push would fail.
        let too_small = MINIMAL.replace("[server]", "[server]\nmax_staging_bytes = 1048576");
        let err = Config::from_figment(fig_from_toml(&too_small)).unwrap_err();
        assert!(err.to_string().contains("max_staging_bytes"), "{err}");
        // Exactly one maximum-size package leaves no room for its manifest,
        // which is staged while the package is still held.
        let exact = MINIMAL.replace(
            "[server]",
            &format!("[server]\nmax_staging_bytes = {largest}"),
        );
        assert!(Config::from_figment(fig_from_toml(&exact)).is_err());
    }

    #[test]
    fn upload_limits_per_format_override_the_server_limit_and_size_staging() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        let default = cfg.server.max_upload_bytes;
        assert_eq!(cfg.max_upload_bytes("helm"), default);

        let big = 8 * 1024 * 1024 * 1024u64;
        let toml = format!("{MINIMAL}\n[plugins.max_upload_bytes]\nhelm = {big}\nnuget = 4096\n");
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        assert_eq!(cfg.max_upload_bytes("helm"), big);
        assert_eq!(cfg.max_upload_bytes("nuget"), 4096);
        assert_eq!(cfg.max_upload_bytes("other"), default);
        // A push of the largest format limit fits the default budget.
        assert_eq!(cfg.staging_budget(), Some(4 * big));
        let too_small = toml.replace(
            "[server]",
            &format!("[server]\nmax_staging_bytes = {}", 2 * default),
        );
        let err = Config::from_figment(fig_from_toml(&too_small)).unwrap_err();
        assert!(
            err.to_string().contains("plugins.max_upload_bytes"),
            "{err}"
        );

        for (entry, message) in [
            ("helm = 0", "greater than 0"),
            ("docker = 4096", "docker.max_blob_bytes"),
            ("\"Not An Id\" = 4096", "plugins.max_upload_bytes.Not An Id"),
        ] {
            let toml = format!("{MINIMAL}\n[plugins.max_upload_bytes]\n{entry}\n");
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            assert!(err.to_string().contains(message), "{entry}: {err}");
        }
    }

    #[test]
    fn upstream_basic_block_parses_with_defaults() {
        let cfg = Config::from_figment(fig_from_toml(&minimal_with_upstream(""))).expect("valid");
        let ub = cfg.auth.upstream_basic.as_ref().expect("present");
        assert!(ub.enabled);
        assert_eq!(ub.url, "https://nexus.internal/service/rest/v1/status");
        assert_eq!(ub.method, "GET");
        assert_eq!(ub.success_status, vec![200]);
        assert_eq!(ub.reject_status, vec![401, 403]);
        assert_eq!(ub.connect_timeout_ms, 2000);
        assert_eq!(ub.request_timeout_ms, 5000);
        assert!(ub.auto_provision);
        assert_eq!(ub.cache.positive_ttl_secs, 300);
        assert_eq!(ub.cache.negative_ttl_secs, 30);
        // to_core mirrors the block.
        let core = ub.to_core();
        assert_eq!(core.url, ub.url);
        assert_eq!(core.method, "GET");
        assert_eq!(core.connect_timeout, Duration::from_millis(2000));
    }

    #[test]
    fn upstream_basic_pepper_redacted_in_debug() {
        let cfg = Config::from_figment(fig_from_toml(&minimal_with_upstream(""))).expect("valid");
        let dbg = format!("{:?}", cfg.auth.upstream_basic.as_ref().unwrap());
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(!dbg.contains("a-high-entropy-pepper"), "{dbg}");
        // And the full Config Debug must not leak it either.
        let full = format!("{cfg:?}");
        assert!(!full.contains("a-high-entropy-pepper"), "{full}");
    }

    #[test]
    fn unknown_provider_id_rejected() {
        let toml = MINIMAL.replace("[auth]", "[auth]\nproviders = [\"ldap\"]");
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("auth.providers"), "{err}");
    }

    #[test]
    fn duplicate_provider_id_rejected() {
        let toml = MINIMAL.replace(
            "[auth]",
            "[auth]\nproviders = [\"local-password\", \"local-password\"]",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn upstream_in_chain_without_block_rejected() {
        let toml = MINIMAL.replace(
            "[auth]",
            "[auth]\nproviders = [\"local-password\", \"upstream-basic\"]",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("upstream-basic"), "{err}");
    }

    #[test]
    fn enabled_block_not_in_chain_rejected() {
        // Block present + enabled, but providers stays the default local-only.
        let block = r#"
            [auth.upstream_basic]
            url = "https://nexus.internal/status"
            [auth.upstream_basic.cache]
            key_pepper = "p"
        "#;
        let toml = MINIMAL.replace("[auth]", &format!("[auth]\n{block}"));
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("not in auth.providers"), "{err}");
    }

    #[test]
    fn empty_pepper_rejected() {
        let toml = minimal_with_upstream("").replace(
            "key_pepper = \"a-high-entropy-pepper\"",
            "key_pepper = \"\"",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("key_pepper"), "{err}");
    }

    #[test]
    fn required_groups_without_groups_path_rejected() {
        // required_groups set but groups_path empty → config error.
        let block = r#"
            [auth.upstream_basic]
            url = "https://nexus.internal/status"
            required_groups = ["nuget-users"]
            [auth.upstream_basic.cache]
            key_pepper = "p"
        "#;
        let toml = MINIMAL.replace(
            "[auth]",
            &format!("[auth]\nproviders = [\"local-password\", \"upstream-basic\"]\n{block}"),
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("groups_path"), "{err}");
    }

    #[test]
    fn non_http_upstream_url_rejected() {
        let toml = minimal_with_upstream("").replace(
            "https://nexus.internal/service/rest/v1/status",
            "ftp://nexus.internal/status",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("upstream_basic.url"), "{err}");
    }

    #[test]
    fn disabled_upstream_block_not_in_chain_ok() {
        // A disabled block with the default (local-only) chain is fine.
        let block = r#"
            [auth.upstream_basic]
            enabled = false
            url = "ftp://whatever"
            [auth.upstream_basic.cache]
        "#;
        let toml = MINIMAL.replace("[auth]", &format!("[auth]\n{block}"));
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("disabled block is inert");
        assert!(!cfg.auth.upstream_basic.unwrap().enabled);
    }

    #[test]
    fn bootstrap_admin_parsed() {
        let toml = MINIMAL.replace(
            "[auth]",
            "[auth]\n[auth.bootstrap_admin]\nusername = \"admin\"\npassword = \"s3cret-Pw!\"",
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        let ba = cfg.auth.bootstrap_admin.expect("present");
        assert_eq!(ba.username, "admin");
        assert_eq!(ba.password, "s3cret-Pw!");
        assert!(!cfg.server.allow_insecure_defaults, "off by default");
    }

    /// Review 2026-10-20 M2: the bootstrap admin signs in with a password, so
    /// its name must not contain `:`.
    #[test]
    fn bootstrap_admin_username_with_a_colon_refused() {
        let toml = MINIMAL.replace(
            "[auth]",
            "[auth]\n[auth.bootstrap_admin]\nusername = \"ad:min\"\npassword = \"s3cret-Pw!\"",
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(
            err.to_string()
                .contains("auth.bootstrap_admin.username: username must not contain ':'"),
            "{err}"
        );
    }

    #[test]
    fn insecure_default_credentials_refused_unless_allowed() {
        for (from, to) in [
            (
                "[auth]",
                "[auth]\n[auth.bootstrap_admin]\nusername = \"admin\"\npassword = \"changeme\"",
            ),
            ("access_key = \"test\"", "access_key = \"minioadmin\""),
            ("secret_key = \"test\"", "secret_key = \"minioadmin\""),
            // The `<…>` placeholders of the example env files, left unedited.
            (
                "[auth]",
                "[auth]\n[auth.bootstrap_admin]\nusername = \"admin\"\n\
                 password = \"<initial admin password>\"",
            ),
            ("secret_key = \"test\"", "secret_key = \"<secret key>\""),
            ("forge:forge@localhost", "forge:<password>@localhost"),
            (
                "[auth]",
                "[redis]\nurl = \"redis://:<redis password>@forge-redis:6379\"\n\n[auth]",
            ),
        ] {
            let toml = MINIMAL.replace(from, to);
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            assert!(err.to_string().contains("insecure default"), "{err}");

            // The explicit dev opt-in lets it start.
            let allowed = toml.replace(
                "public_base_url = \"https://forge.example.com/\"",
                "public_base_url = \"https://forge.example.com/\"\nallow_insecure_defaults = true",
            );
            let cfg = Config::from_figment(fig_from_toml(&allowed)).expect("dev opt-in");
            assert!(cfg.server.allow_insecure_defaults);
        }
    }

    /// Review M15: the image configures the bootstrap admin through env only,
    /// and "no password configured" means "no bootstrap admin" — never a
    /// startup refusal (a blank password used to be refused as a placeholder).
    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn missing_or_blank_bootstrap_password_means_no_bootstrap_admin() {
        for block in [
            "[auth]\n[auth.bootstrap_admin]\nusername = \"admin\"\npassword = \"\"",
            "[auth]\n[auth.bootstrap_admin]\nusername = \"admin\"\npassword = \"   \"",
            "[auth]\n[auth.bootstrap_admin]\nusername = \"admin\"",
        ] {
            let toml = MINIMAL.replace("[auth]", block);
            let cfg = Config::from_figment(fig_from_toml(&toml)).expect("starts");
            assert!(cfg.auth.bootstrap_admin.is_none(), "{block}");
        }
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", MINIMAL)?;
            // Username without a password (the password was removed after the
            // first start, as docs/deployment.md tells operators to do).
            jail.set_env("FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME", "admin");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("starts");
            assert!(cfg.auth.bootstrap_admin.is_none());
            // Password only: the username defaults to `admin`.
            jail.clear_env();
            jail.set_env("FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD", "Real-Pw-1");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("starts");
            let ba = cfg.auth.bootstrap_admin.expect("bootstrap admin from env");
            assert_eq!(ba.username, "admin");
            assert_eq!(ba.password, "Real-Pw-1");
            assert!(!format!("{ba:?}").contains("Real-Pw-1"), "Debug redacts");
            Ok(())
        });
    }

    /// The image's baked config carries no bootstrap admin and no
    /// `allow_password_basic`, and loads with only the required env set.
    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn docker_image_config_starts_without_a_bootstrap_password() {
        let baked = include_str!("../../../docker/forge.docker.toml");
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", baked)?;
            jail.set_env("FORGE_DATABASE__URL", "postgres://forge:pw@db/forge");
            jail.set_env("FORGE_S3__ACCESS_KEY", "real-access");
            jail.set_env("FORGE_S3__SECRET_KEY", "real-secret");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml")))
                .expect("the image starts without any bootstrap password");
            assert!(cfg.auth.bootstrap_admin.is_none());
            assert!(!cfg.auth.allow_password_basic);
            assert!(!cfg.server.allow_insecure_defaults);

            jail.set_env("FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD", "First-Run-Pw");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            let ba = cfg
                .auth
                .bootstrap_admin
                .expect("env-driven bootstrap admin");
            assert_eq!(
                (ba.username.as_str(), ba.password.as_str()),
                ("admin", "First-Run-Pw")
            );
            Ok(())
        });
    }

    /// The image's baked config names no S3 keys: they come from the
    /// environment, or short-lived credentials replace them, configured
    /// through the environment alone.
    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn docker_image_config_takes_s3_keys_or_short_lived_credentials_from_env() {
        let baked = include_str!("../../../docker/forge.docker.toml");
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", baked)?;
            jail.set_env("FORGE_DATABASE__URL", "postgres://forge:pw@db/forge");
            let err = Config::load(Some(std::path::Path::new("forge.toml"))).unwrap_err();
            assert!(err.to_string().contains("FORGE_S3__ACCESS_KEY"), "{err}");

            jail.set_env("FORGE_S3__CREDENTIALS", "web_identity");
            jail.set_env(
                "FORGE_S3__WEB_IDENTITY__TOKEN_FILE",
                "/var/run/secrets/forge/s3/token",
            );
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            assert_eq!(cfg.s3.credentials, S3CredentialsMode::WebIdentity);
            assert_eq!(cfg.s3.access_key, None);
            Ok(())
        });
    }

    /// Review L9: secret env values are taken verbatim as strings — figment
    /// would otherwise type-sniff them (`12345` → integer, `true` → bool,
    /// `[x]` → array) and refuse them as "invalid type", echoing the value.
    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn secret_env_values_are_read_verbatim_as_strings() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", MINIMAL)?;
            jail.set_env("FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD", "1234567890");
            jail.set_env("FORGE_S3__ACCESS_KEY", "true");
            jail.set_env("FORGE_S3__SECRET_KEY", "[not-a-list]");
            jail.set_env("FORGE_DATABASE__URL", "postgres://u:{p}@db/forge");
            jail.set_env("FORGE_OIDC__ISSUER", "https://idp.test/v2.0");
            jail.set_env("FORGE_OIDC__CLIENT_ID", "cid");
            jail.set_env("FORGE_OIDC__CLIENT_SECRET", "0x1F");
            jail.set_env(
                "FORGE_OIDC__REDIRECT_URL",
                "https://forge.example.com/auth/oidc/callback",
            );
            // A non-secret key keeps figment's typed parsing.
            jail.set_env("FORGE_CACHE__L1_MAX_CAPACITY", "42");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            let ba = cfg.auth.bootstrap_admin.as_ref().expect("bootstrap admin");
            assert_eq!(ba.password, "1234567890");
            assert_eq!(cfg.s3.access_key.as_deref(), Some("true"));
            assert_eq!(cfg.s3.secret_key.as_deref(), Some("[not-a-list]"));
            assert_eq!(cfg.database.url, "postgres://u:{p}@db/forge");
            assert_eq!(cfg.oidc.as_ref().expect("oidc").client_secret, "0x1F");
            assert_eq!(cfg.cache.l1_max_capacity, 42);
            Ok(())
        });
    }

    /// Secret env values keep their pre-release normalization: surrounding
    /// whitespace (a trailing newline from a secret file) is trimmed and one
    /// pair of surrounding double quotes is removed.
    #[test]
    fn trusted_proxy_cidrs_accept_ipv4_mapped_entries() {
        let mut cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        cfg.auth.trusted_proxy_cidrs =
            vec!["::ffff:172.17.0.1".into(), "::ffff:10.0.0.0/104".into()];
        let nets = cfg.trusted_proxy_cidrs().expect("parse");
        assert_eq!(
            nets,
            vec![
                "172.17.0.1/32".parse::<IpNet>().unwrap(),
                "10.0.0.0/8".parse::<IpNet>().unwrap()
            ]
        );
    }

    #[test]
    fn secret_env_values_are_trimmed_and_unquoted() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", MINIMAL)?;
            jail.set_env("FORGE_S3__SECRET_KEY", "s3-secret\n");
            jail.set_env(
                "FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD",
                "\"pw with \"inner\" quotes\"",
            );
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            assert_eq!(cfg.s3.secret_key.as_deref(), Some("s3-secret"));
            let ba = cfg.auth.bootstrap_admin.as_ref().expect("bootstrap admin");
            assert_eq!(ba.password, "pw with \"inner\" quotes");
            Ok(())
        });
    }

    /// Review L9: a config error at a secret key names the key and the
    /// expected type but never echoes the value.
    #[test]
    fn config_errors_never_echo_secret_values() {
        for (from, to, key) in [
            (
                "secret_key = \"test\"",
                "secret_key = 98765432101",
                "secret_key",
            ),
            (
                "[auth]",
                "[auth]\n[auth.bootstrap_admin]\npassword = 55555555555",
                "password",
            ),
            (
                "url = \"postgres://forge:forge@localhost/forge\"",
                "url = 77777777777",
                "url",
            ),
        ] {
            let toml = MINIMAL.replace(from, to);
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            // No source chain: `main` reports errors through anyhow, whose
            // Debug output prints every `source()`.
            assert!(std::error::Error::source(&err).is_none());
            let debug = format!("{err:?}");
            let msg = err.to_string();
            let value = to.rsplit(' ').next().unwrap();
            assert!(!msg.contains(value), "value echoed: {msg}");
            assert!(!debug.contains(value), "value echoed in Debug: {debug}");
            assert!(msg.contains(key), "{msg}");
            assert!(msg.contains("redacted"), "{msg}");
        }
        // Non-secret keys keep the full message (useful for typos).
        let toml = MINIMAL.replace(
            "secret_key = \"test\"",
            "secret_key = \"test\"\nconditional_writes = \"sometimes\"",
        );
        let msg = Config::from_figment(fig_from_toml(&toml))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("sometimes"), "{msg}");
    }

    /// Review L9: an explicitly configured config file that does not exist
    /// fails startup (it used to be silently ignored), and the path is used
    /// exactly — never searched for in parent directories.
    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn explicit_config_path_must_exist_exactly() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", MINIMAL)?;
            let err = Config::load(Some(std::path::Path::new("missing.toml"))).unwrap_err();
            assert!(err.to_string().contains("does not exist"), "{err}");
            assert!(err.to_string().contains("missing.toml"), "{err}");

            // figment's `Toml::file` would find ../forge.toml; the exact loader
            // does not.
            jail.change_dir(jail.create_dir("sub")?)?;
            let err = Config::load(Some(std::path::Path::new("forge.toml"))).unwrap_err();
            assert!(err.to_string().contains("does not exist"), "{err}");
            Ok(())
        });
    }

    /// `.env.example`: a blank `FORGE_REDIS__URL` disables Redis instead of
    /// handing the cache an empty URL (which failed startup).
    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn blank_redis_url_means_no_redis() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", MINIMAL)?;
            jail.set_env("FORGE_REDIS__URL", "");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            assert!(cfg.redis.url.is_none());
            jail.set_env("FORGE_REDIS__URL", "redis://cache:6379");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            assert_eq!(cfg.redis.url.as_deref(), Some("redis://cache:6379"));
            Ok(())
        });
    }

    // ── slice 12.5: [crypto] secret encryption at rest ───────────────────────

    #[test]
    fn crypto_absent_means_disabled() {
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert!(cfg.crypto.is_none());
    }

    #[test]
    fn crypto_env_provider_parses_with_defaults() {
        let toml = format!("{MINIMAL}\n[crypto]\n[crypto.root]\nprovider = \"env\"\n");
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        let crypto = cfg.crypto.expect("present");
        assert!(crypto.enabled);
        assert_eq!(crypto.algorithm, "aes-256-gcm");
        assert_eq!(crypto.root.provider, "env");
        assert_eq!(crypto.root.root_key_env, "FORGE_ROOT_KEY");
        assert!(crypto.root.root_key_env_previous.is_none());
        assert_eq!(crypto.cache.unwrapped_key_ttl_secs, 300);
        assert_eq!(crypto.cache.unwrapped_key_max, 64);
        assert!(crypto.rotation.enabled);
        assert_eq!(crypto.rotation.poll_interval_seconds, 300);
        assert_eq!(crypto.rotation.dek_max_age_days, 30);
        assert_eq!(crypto.rotation.kek_max_age_days, 365);
        assert_eq!(crypto.rotation.sweep_batch_size, 500);
    }

    #[test]
    fn crypto_file_provider_requires_path() {
        let toml = format!("{MINIMAL}\n[crypto]\n[crypto.root]\nprovider = \"file\"\n");
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("root_key_path"), "{err}");

        let toml = format!(
            "{MINIMAL}\n[crypto]\n[crypto.root]\nprovider = \"file\"\nroot_key_path = \"/run/secrets/forge_root_key\"\n"
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        assert_eq!(
            cfg.crypto.unwrap().root.root_key_path.as_deref(),
            Some("/run/secrets/forge_root_key")
        );
    }

    #[test]
    fn crypto_unknown_provider_and_algorithm_rejected() {
        let toml = format!("{MINIMAL}\n[crypto]\n[crypto.root]\nprovider = \"vault\"\n");
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("crypto.root.provider"), "{err}");

        let toml = format!(
            "{MINIMAL}\n[crypto]\nalgorithm = \"rot13\"\n[crypto.root]\nprovider = \"env\"\n"
        );
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("crypto.algorithm"), "{err}");
    }

    /// Durations past the arithmetic's limits used to panic at startup or in
    /// a worker loop; they fail validation instead, naming the key.
    #[test]
    fn oversized_durations_fail_validation_naming_the_key() {
        let max = i64::MAX;
        for (section, key) in [
            ("outbox", "grace_seconds"),
            ("retention", "default_run_interval_seconds"),
            ("retention", "lease_seconds"),
        ] {
            let toml = format!("{MINIMAL}\n[{section}]\n{key} = {max}\n");
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            assert!(
                err.to_string().contains(&format!("{section}.{key}")),
                "{err}"
            );
            let toml = format!("{MINIMAL}\n[{section}]\n{key} = 3153600000\n");
            Config::from_figment(fig_from_toml(&toml)).expect("100 years is accepted");
        }
        for (section, key) in [
            ("cache", "unwrapped_key_ttl_secs"),
            ("rotation", "dek_max_age_days"),
            ("rotation", "kek_max_age_days"),
        ] {
            let toml = format!(
                "{MINIMAL}\n[crypto]\n[crypto.root]\nprovider = \"env\"\n[crypto.{section}]\n{key} = {max}\n"
            );
            let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
            assert!(
                err.to_string().contains(&format!("crypto.{section}.{key}")),
                "{err}"
            );
        }
    }

    #[test]
    fn crypto_aws_kms_rejected_until_it_ships() {
        let toml = format!("{MINIMAL}\n[crypto]\n[crypto.root]\nprovider = \"aws-kms\"\n");
        let err = Config::from_figment(fig_from_toml(&toml)).unwrap_err();
        assert!(err.to_string().contains("not supported yet"), "{err}");
    }

    #[test]
    fn crypto_disabled_block_skips_validation() {
        // A staged-but-disabled block with an invalid provider must parse.
        let toml =
            format!("{MINIMAL}\n[crypto]\nenabled = false\n[crypto.root]\nprovider = \"vault\"\n");
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("disabled block is inert");
        assert!(!cfg.crypto.unwrap().enabled);
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail's closure returns figment::Error.
    fn crypto_env_overrides_nested_keys() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("forge.toml", MINIMAL)?;
            jail.set_env("FORGE_CRYPTO__ALGORITHM", "xchacha20-poly1305");
            jail.set_env("FORGE_CRYPTO__ROOT__PROVIDER", "env");
            jail.set_env("FORGE_CRYPTO__ROOT__ROOT_KEY_ENV", "MY_ROOT_KEY");
            jail.set_env(
                "FORGE_CRYPTO__ROOT__ROOT_KEY_ENV_PREVIOUS",
                "MY_OLD_ROOT_KEY",
            );
            jail.set_env("FORGE_CRYPTO__CACHE__UNWRAPPED_KEY_TTL_SECS", "60");
            jail.set_env("FORGE_CRYPTO__ROTATION__DEK_MAX_AGE_DAYS", "7");
            jail.set_env("FORGE_CRYPTO__ROTATION__ENABLED", "false");
            let cfg = Config::load(Some(std::path::Path::new("forge.toml"))).expect("valid");
            let crypto = cfg.crypto.expect("present via env");
            assert_eq!(crypto.algorithm, "xchacha20-poly1305");
            assert_eq!(crypto.root.root_key_env, "MY_ROOT_KEY");
            assert_eq!(
                crypto.root.root_key_env_previous.as_deref(),
                Some("MY_OLD_ROOT_KEY")
            );
            assert_eq!(crypto.cache.unwrapped_key_ttl_secs, 60);
            assert_eq!(crypto.rotation.dek_max_age_days, 7);
            assert!(!crypto.rotation.enabled);
            Ok(())
        });
    }

    #[test]
    fn groups_max_nesting_depth_defaults_and_overrides() {
        // Absent [groups] section ⇒ the secure-enough default depth bound.
        let cfg = Config::from_figment(fig_from_toml(MINIMAL)).expect("valid");
        assert_eq!(cfg.groups.max_nesting_depth, 20);

        // Explicit override is honored.
        let toml = format!("{MINIMAL}\n[groups]\nmax_nesting_depth = 3\n");
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        assert_eq!(cfg.groups.max_nesting_depth, 3);
    }
}
