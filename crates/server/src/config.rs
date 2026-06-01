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
}

/// `server.*`
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Socket address to bind, e.g. `0.0.0.0:8080`.
    pub bind: String,
    /// Public base URL used to build absolute NuGet `@id`s (no trailing slash
    /// required; it is trimmed). e.g. `https://forge.example.com`.
    pub public_base_url: String,
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
}

/// `s3.*`
#[derive(Debug, Clone, Deserialize)]
pub struct S3Config {
    /// S3 endpoint URL (e.g. `http://localhost:7070` for versitygw).
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
        assert!(matches!(cfg.anon_policy().unwrap(), AnonPolicy::Off));
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
            let ba = cfg.auth.bootstrap_admin.as_ref().expect("bootstrap admin set via env");
            assert_eq!(ba.username, "root");
            assert_eq!(ba.password, "s3cret");
            assert_eq!(cfg.redis.url.as_deref(), Some("redis://localhost:6379"));
            assert_eq!(cfg.cache.l1_max_capacity, 42);
            assert_eq!(cfg.cache.default_ttl_seconds, 120);
            assert_eq!(cfg.outbox.batch_size, 7);
            assert_eq!(cfg.outbox.grace_seconds, 60);
            assert_eq!(cfg.outbox.poll_interval_seconds, 3);
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
}
