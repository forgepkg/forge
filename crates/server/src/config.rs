//! Server configuration (spec §8).
//!
//! Configuration is layered: a TOML file (optional) is the base, and `FORGE_*`
//! environment variables override individual keys. Nested keys use `__` as the
//! separator, e.g. `FORGE_SERVER__BIND`, `FORGE_S3__ACCESS_KEY`,
//! `FORGE_AUTH__ANONYMOUS_MODE`.
//!
//! The raw deserialized shape ([`Config`]) is validated into typed runtime
//! values where useful (e.g. the anonymous policy + trusted-proxy CIDRs are
//! parsed once via [`Config::anon_policy`] / [`Config::trusted_proxy_cidrs`]).

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use figment::providers::{Env, Format, Toml};
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
    /// Authentication / anonymous-access policy.
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
}

/// `server.*`
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Socket address to bind, e.g. `0.0.0.0:8080`.
    pub bind: String,
    /// Public base URL used to build absolute NuGet `@id`s (no trailing slash
    /// required; it is trimmed). e.g. `https://forge.example.com`.
    pub public_base_url: String,
    /// Largest accepted package upload (`dotnet nuget push`) in bytes. Uploads
    /// are streamed to a temp file, never buffered in memory; exceeding the
    /// limit yields HTTP 413. Default 512 MiB.
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: u64,
}

fn default_max_upload_bytes() -> u64 {
    512 * 1024 * 1024
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
#[derive(Debug, Clone, Deserialize)]
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

fn default_db_max_connections() -> u32 {
    20
}

fn default_db_acquire_timeout() -> u64 {
    10
}

/// `s3.*`
#[derive(Debug, Clone, Deserialize)]
pub struct S3Config {
    /// S3 endpoint URL (e.g. `http://localhost:8422` for versitygw).
    pub endpoint: String,
    /// AWS region (any value for versitygw; `us-east-1` is fine).
    #[serde(default = "default_region")]
    pub region: String,
    /// Bucket name holding all blobs.
    pub bucket: String,
    /// Access key id.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
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
    /// Convert into the storage crate's S3 config.
    pub fn to_storage(&self) -> forge_storage::S3Config {
        forge_storage::S3Config {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            bucket: self.bucket.clone(),
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            force_path_style: self.force_path_style,
            multipart_threshold: self.multipart_threshold,
            conditional_writes: match self.conditional_writes {
                ConditionalWritesMode::Auto => forge_storage::ConditionalWrites::Auto,
                ConditionalWritesMode::On => forge_storage::ConditionalWrites::On,
                ConditionalWritesMode::Off => forge_storage::ConditionalWrites::Off,
            },
        }
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
#[derive(Clone, Deserialize)]
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
    /// Optional upstream group that maps to forge admin on provision (grant only).
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
            admin_group: self.admin_group.clone(),
            provider_id: forge_core::auth::UPSTREAM_BASIC_ID.to_string(),
            auto_provision: self.auto_provision,
            realm_id: None,
        }
    }
}

/// `auth.upstream_basic.cache.*` — the validated-credential cache tuning.
#[derive(Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapAdmin {
    /// Admin username to create on first run if absent.
    pub username: String,
    /// Plaintext password (hashed with argon2id on creation).
    pub password: String,
}

/// `redis.*` (optional).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RedisConfig {
    /// `redis://…` URL. Absent ⇒ L1-only caching.
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
}

impl Default for OutboxConfig {
    fn default() -> Self {
        OutboxConfig {
            batch_size: default_outbox_batch(),
            grace_seconds: default_outbox_grace(),
            poll_interval_seconds: default_outbox_poll(),
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
    /// Default floor between automatic runs per repo (seconds).
    #[serde(default = "default_retention_run_interval")]
    pub default_run_interval_seconds: i64,
    /// Crash-safe lease held while a repo is evaluated (seconds).
    #[serde(default = "default_retention_lease")]
    pub lease_seconds: i64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        RetentionConfig {
            enabled: default_true(),
            poll_interval_seconds: default_retention_poll(),
            default_run_interval_seconds: default_retention_run_interval(),
            lease_seconds: default_retention_lease(),
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
#[derive(Clone, Deserialize)]
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
    /// Link an OIDC identity to an existing local `app_user` whose `username`
    /// matches the resolved username claim (bootstrap-admin interplay). Risky if
    /// the username claim is attacker-influenced — set `false` in hardened
    /// deployments.
    #[serde(default = "default_true")]
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
fn default_retention_poll() -> u64 {
    30
}
fn default_retention_run_interval() -> i64 {
    3600
}
fn default_retention_lease() -> i64 {
    300
}

/// Configuration load / validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required key was missing or the file/env was malformed.
    #[error("configuration error: {0}")]
    Load(#[from] Box<figment::Error>),
    /// A value was present but invalid (bad CIDR, bad bind addr, unknown mode).
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    /// Load configuration from an optional TOML file plus `FORGE_*` env
    /// overrides. Nested keys use `__` (e.g. `FORGE_SERVER__BIND`).
    pub fn load(toml_path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut fig = Figment::new();
        if let Some(path) = toml_path {
            fig = fig.merge(Toml::file(path));
        }
        // `FORGE_` prefix, `__` separates nested keys, lowercase the rest.
        fig = fig.merge(Env::prefixed("FORGE_").split("__"));
        let cfg: Config = fig.extract().map_err(Box::new)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse the configuration from an explicit [`Figment`] (used by tests to
    /// inject providers without touching the real environment).
    pub fn from_figment(fig: Figment) -> Result<Self, ConfigError> {
        let cfg: Config = fig.extract().map_err(Box::new)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate cross-cutting invariants that serde cannot express.
    fn validate(&self) -> Result<(), ConfigError> {
        self.server.bind_addr()?;
        // Eagerly validate the anon policy + trusted CIDRs so a bad value fails
        // at startup rather than mid-request.
        self.anon_policy()?;
        self.trusted_proxy_cidrs()?;
        self.validate_oidc()?;
        self.validate_auth_providers()?;
        match self.auth.login_mode.as_str() {
            "identifier_first" | "combined" => {}
            other => {
                return Err(ConfigError::Invalid(format!(
                    "unknown auth.login_mode {other:?} (expected identifier_first|combined)"
                )))
            }
        }
        self.validate_crypto()?;
        self.proxy.validate()?;
        self.validate_workers()?;
        if self.server.max_upload_bytes == 0 {
            return Err(ConfigError::Invalid(
                "server.max_upload_bytes must be greater than 0".into(),
            ));
        }
        Ok(())
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
            // Warn loudly about plaintext credential forwarding over http (plan
            // §5): the user's password rides the outbound Basic header.
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
            if let Ok(net) = tok.parse::<IpNet>() {
                out.push(net);
            } else if let Ok(ip) = tok.parse::<std::net::IpAddr>() {
                let prefix = match ip {
                    std::net::IpAddr::V4(_) => 32,
                    std::net::IpAddr::V6(_) => 128,
                };
                out.push(IpNet::new(ip, prefix).expect("full-length prefix is valid"));
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
            assert_eq!(cfg.s3.access_key, "ak");
            assert_eq!(cfg.s3.secret_key, "sk");
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
        assert!(oidc.link_existing_by_username);
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
            "[auth]\n[auth.bootstrap_admin]\nusername = \"admin\"\npassword = \"changeme\"",
        );
        let cfg = Config::from_figment(fig_from_toml(&toml)).expect("valid");
        let ba = cfg.auth.bootstrap_admin.expect("present");
        assert_eq!(ba.username, "admin");
        assert_eq!(ba.password, "changeme");
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
