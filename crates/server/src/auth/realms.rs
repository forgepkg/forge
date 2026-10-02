//! DB-backed auth realms (slice 12.7, design doc 2026-06-03 §3).
//!
//! The `auth_realm` table is the **authority** for how password logins and the
//! interactive OIDC login are wired. This module owns:
//!
//! * the typed, serde-checked shapes of each realm `config` jsonb
//!   ([`CredForwardRealmConfig`], [`OidcRealmConfig`]) plus their validation,
//!   secret **redaction** (for API responses) and secret **merge** (write-only
//!   updates keep the stored secret when the caller omits it);
//! * [`RealmAuth`] — the per-instance snapshot cache that rebuilds the
//!   password [`Chain`] and the [`OidcRuntime`] from the realm rows. Admin
//!   writes invalidate the local snapshot immediately; other instances
//!   converge within `auth.realm_cache_ttl_seconds` (the table is the shared
//!   authority — no in-memory-only state, no advisory locks);
//! * **secrets at rest** (review P1.5): with `[crypto]` enabled the secret
//!   keys of a realm config are stripped from the stored jsonb and sealed into
//!   `auth_realm.secrets_enc` via [`forge_db::secret_dao`]; every reader goes
//!   through the *logical* config ([`forge_db::secret_dao::realm_config`]),
//!   legacy plaintext rows keep working and are re-encrypted on write / by the
//!   crypto backfill;
//! * the **legacy-config import** ([`seed_auth_realms`]): the 12.2 `[oidc]`
//!   and 12.3 `[auth.upstream_basic]` TOML blocks become realm rows, with
//!   drift detection — a changed block keeps re-applying only while the row is
//!   untouched since the last seed; the moment an admin edits the row through
//!   the API, the database is the authority and the TOML stops clobbering it.
//!
//! ## Fail-closed posture
//! A snapshot rebuild error (DB down, malformed realm config) never *grants*:
//! the wire password path reports "no chain" (deny), the login endpoint 503s,
//! and OIDC routes report login unavailable. A malformed single realm is
//! skipped with an error log so one bad row cannot take down the others.

use std::sync::Arc;
use std::time::{Duration, Instant};

use forge_cache::Cache;
use forge_core::auth::{
    AuthProvider, Chain, ChainSource, CredKeyPepper, ForwardLimits, LocalPasswordProvider,
    UpstreamBasicProvider, ValidatedCredentialCache,
};
use forge_core::net::ssrf;
use forge_crypto::service::EnvelopeService;
use forge_db::model::AuthRealm;
use forge_db::{auth_realm_dao, authz_dao, secret_dao};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;

use super::OidcRuntime;
use crate::config::{Config, OidcConfig};

/// `forge_setting` key marking the first realm import as done. Gates only the
/// initial `local`-realm priority adjustment; per-kind seed fingerprints (see
/// [`seed_auth_realms`]) govern config re-application.
pub const REALMS_SEEDED_KEY: &str = "auth_realms_seeded";

/// Realm kinds (string forms match the `auth_realm.kind` CHECK).
pub const KIND_LOCAL: &str = "local";
pub const KIND_OIDC: &str = "oidc";
pub const KIND_CRED_FORWARD: &str = "credential_forwarding";
pub const KIND_WORKLOAD_IDENTITY: &str = "workload_identity";

// ─── typed realm configs ─────────────────────────────────────────────────────

/// `config` shape for a `credential_forwarding` realm. Mirrors the 12.3
/// `[auth.upstream_basic]` block (flattened — the cache TTLs and pepper live at
/// the top level of the json document).
///
/// `key_pepper` is a **secret**: write-only at the API layer ([`redact_config`]
/// strips it / [`merge_secrets`] keeps the stored value when omitted) and
/// redacted from `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct CredForwardRealmConfig {
    /// Upstream endpoint hit with the user's Basic credentials (http/https).
    pub url: String,
    /// HTTP method (Nexus status is `GET`).
    #[serde(default = "default_method")]
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
    /// Optional coarse allow-gate: only accept a success when the user holds
    /// one of these groups. Empty ⇒ any success accepted. Requires `groups_path`.
    #[serde(default)]
    pub required_groups: Vec<String>,
    /// `.`-separated path into the JSON body locating the user's groups.
    #[serde(default)]
    pub groups_path: String,
    /// Optional upstream group that maps to forge admin on provision.
    #[serde(default)]
    pub admin_group: String,
    /// Auto-provision an `app_user` on first successful upstream login.
    #[serde(default = "default_true")]
    pub auto_provision: bool,
    /// How long a *good* credential is trusted without re-forwarding (seconds).
    #[serde(default = "default_positive_ttl")]
    pub positive_ttl_secs: u64,
    /// How long a *bad* credential is remembered (seconds).
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl_secs: u64,
    /// Server-held secret keying the validated-credential cache HMAC.
    /// **Write-only / redacted.**
    #[serde(default)]
    pub key_pepper: String,
}

impl std::fmt::Debug for CredForwardRealmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredForwardRealmConfig")
            .field("url", &self.url)
            .field("method", &self.method)
            .field("key_pepper", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// `config` shape for an `oidc` realm. Mirrors the 12.2 `[oidc]` block, minus
/// what is now derived: the redirect URL is always
/// `{public_base_url}/auth/oidc/callback`, and session TTLs are global
/// (`auth.session_*`).
///
/// `client_secret` is a **secret** (write-only / redacted), like `key_pepper`
/// above.
#[derive(Clone, Serialize, Deserialize)]
pub struct OidcRealmConfig {
    /// OIDC issuer URL (`https`, unless `allow_http_issuer` for dev IdPs).
    pub issuer: String,
    /// OAuth client (application) id.
    pub client_id: String,
    /// OAuth client secret. **Write-only / redacted.**
    #[serde(default)]
    pub client_secret: String,
    /// Requested scopes (`openid` added implicitly when missing).
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// Leeway (seconds) on `exp`/`nbf`/`iat` ID-token validation.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
    /// Permit a plain-`http` issuer (dev/test IdPs only).
    #[serde(default)]
    pub allow_http_issuer: bool,
    /// Claim used as the username (12.7 decision: `preferred_username`).
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
    /// Claim carrying the user's email.
    #[serde(default = "default_email_claim")]
    pub email_claim: String,
    /// Claim carrying the display name.
    #[serde(default = "default_display_name_claim")]
    pub display_name_claim: String,
    /// Create an `app_user` on first successful login when no link exists.
    #[serde(default = "default_true")]
    pub auto_provision: bool,
    /// Link a new OIDC identity to an existing user by username. Off by
    /// default; password accounts and admins are never linked by name.
    #[serde(default)]
    pub link_existing_by_username: bool,
    /// Group/role values that grant `is_admin` (empty ⇒ never).
    #[serde(default)]
    pub admin_groups: Vec<String>,
    /// Claim matched against `admin_groups`.
    #[serde(default = "default_admin_claim")]
    pub admin_claim: String,
    /// Identifier-first routing rule (§3.4): a login identifier whose email
    /// domain (the part after `@`, case-insensitive) is in this list is routed
    /// to this realm (`oidc_redirect`). Empty ⇒ never matched by identifier;
    /// the realm is still offered as a button in `combined` mode.
    #[serde(default)]
    pub login_domains: Vec<String>,
    /// Display label for the login button (`Login with <label>`); defaults to
    /// the realm name.
    #[serde(default)]
    pub button_label: Option<String>,
}

impl std::fmt::Debug for OidcRealmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcRealmConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn default_method() -> String {
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
fn default_true() -> bool {
    true
}
fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}
fn default_clock_skew() -> u64 {
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

// ─── validation / redaction / secret merge ──────────────────────────────────

/// Which json keys of a realm `config` are secrets (write-only, redacted,
/// encrypted at rest when `[crypto]` is enabled).
pub fn secret_keys(kind: &str) -> &'static [&'static str] {
    match kind {
        KIND_OIDC => &["client_secret"],
        KIND_CRED_FORWARD => &["key_pepper"],
        _ => &[],
    }
}

/// Parse + validate a realm `config` document for `kind`. Returns a normalized
/// document (kind-specific defaults filled) or a human-readable error. `local`
/// accepts only an empty/no-op config; workload-identity documents are
/// validated by the stricter WIF parser, which rejects unknown policy fields.
pub fn validate_config(kind: &str, config: &JsonValue) -> Result<JsonValue, String> {
    match kind {
        KIND_LOCAL => Ok(JsonValue::Object(Default::default())),
        KIND_CRED_FORWARD => {
            let cfg: CredForwardRealmConfig = serde_json::from_value(config.clone())
                .map_err(|e| format!("invalid config: {e}"))?;
            ssrf::validate_url(&cfg.url).map_err(|e| format!("invalid url: {e}"))?;
            if cfg.key_pepper.trim().is_empty() {
                return Err(
                    "key_pepper must not be empty (it keys the validated-credential cache HMAC)"
                        .into(),
                );
            }
            if !cfg.required_groups.is_empty() && cfg.groups_path.trim().is_empty() {
                return Err("required_groups is set but groups_path is empty".into());
            }
            if !matches!(
                cfg.method.to_ascii_uppercase().as_str(),
                "GET" | "POST" | "HEAD" | "PUT"
            ) {
                return Err(format!("unsupported method {:?}", cfg.method));
            }
            Ok(serde_json::to_value(&cfg).expect("serializable"))
        }
        KIND_OIDC => {
            let cfg: OidcRealmConfig = serde_json::from_value(config.clone())
                .map_err(|e| format!("invalid config: {e}"))?;
            let issuer = url::Url::parse(cfg.issuer.trim())
                .map_err(|e| format!("invalid issuer {:?}: {e}", cfg.issuer))?;
            match issuer.scheme() {
                "https" => {}
                "http" if cfg.allow_http_issuer => {}
                other => {
                    return Err(format!(
                        "issuer must be https (got {other:?}); set allow_http_issuer for a dev IdP"
                    ))
                }
            }
            if cfg.client_id.trim().is_empty() {
                return Err("client_id must not be empty".into());
            }
            if cfg.client_secret.trim().is_empty() {
                return Err("client_secret must not be empty".into());
            }
            Ok(serde_json::to_value(&cfg).expect("serializable"))
        }
        KIND_WORKLOAD_IDENTITY => super::wif::validate_workload_identity_config(config),
        other => Err(format!("unknown realm kind {other:?}")),
    }
}

/// Strip secrets from a realm `config` for an API response: each secret key is
/// removed and replaced by a `<key>_set: bool` marker so the UI can show
/// "a secret is stored" without ever echoing it.
pub fn redact_config(kind: &str, config: &JsonValue) -> JsonValue {
    let mut doc = config.clone();
    if let JsonValue::Object(map) = &mut doc {
        for key in secret_keys(kind) {
            let set = map
                .remove(*key)
                .map(|v| matches!(&v, JsonValue::String(s) if !s.is_empty()))
                .unwrap_or(false);
            map.insert(format!("{key}_set"), JsonValue::Bool(set));
        }
    }
    doc
}

/// Merge a config **update** with the stored document's secrets: when the
/// incoming document omits a secret key (or sends `null` / `""`), the stored
/// value is kept — secrets are write-only, so the admin UI round-trips the
/// redacted view without clobbering them.
pub fn merge_secrets(kind: &str, stored: &JsonValue, incoming: &JsonValue) -> JsonValue {
    let mut doc = incoming.clone();
    if let JsonValue::Object(map) = &mut doc {
        for key in secret_keys(kind) {
            // Drop the redaction marker if the UI echoed it back.
            map.remove(&format!("{key}_set"));
            let incoming_blank = match map.get(*key) {
                None | Some(JsonValue::Null) => true,
                Some(JsonValue::String(s)) => s.is_empty(),
                _ => false,
            };
            if incoming_blank {
                if let Some(stored_secret) = stored.get(*key) {
                    map.insert((*key).to_string(), stored_secret.clone());
                } else {
                    map.remove(*key);
                }
            }
        }
    }
    doc
}

// ─── snapshot runtime ────────────────────────────────────────────────────────

/// The OIDC half of a snapshot: the realm row's identity plus the built
/// login runtime.
#[derive(Clone)]
pub struct OidcRealmRuntime {
    /// `auth_realm.name` of the backing row.
    pub realm_name: String,
    /// Display label for login buttons.
    pub label: String,
    /// Identifier-first routing domains (lowercased).
    pub login_domains: Vec<String>,
    /// The flow runtime (discovery/JWKS client, claim mapping, sessions).
    pub runtime: OidcRuntime,
}

/// One coherent view of the realm table, plus everything built from it.
pub struct RealmSnapshot {
    built_at: Instant,
    /// All realm rows, in try-order (priority ascending).
    pub realms: Vec<AuthRealm>,
    /// The password chain over the enabled password-capable realms (`local`,
    /// `credential_forwarding`), or `None` when none are enabled.
    pub chain: Option<Arc<Chain>>,
    /// Whether the **wire** Basic password path is enabled: the config flag
    /// `auth.allow_password_basic`, or any enabled credential-forwarding realm
    /// (mirrors the 12.3 rule where configuring an upstream enabled the path).
    pub wire_password_enabled: bool,
    /// The (at most one — admin API invariant) enabled OIDC realm's runtime.
    pub oidc: Option<OidcRealmRuntime>,
    /// Enabled `workload_identity` (WIF) realms (slice 12.8), each with its
    /// issuer-scoped JWKS verifier. Multiple issuers are supported (GitLab,
    /// GitHub Actions, …) — unlike OIDC there is no single-realm invariant.
    pub workload: Vec<super::wif::WorkloadIdentityRealm>,
    /// Normalized issuer strings from every enabled WIF row, including rows
    /// whose remaining config is malformed. Token routing consults this before
    /// falling through so a matching JWT is rejected terminally rather than
    /// reinterpreted as a Basic credential by a later realm.
    pub workload_configured_issuers: Vec<String>,
    /// Issuers named by more than one enabled WIF row. Raw DB writes or legacy
    /// data can bypass the admin/DB uniqueness checks; routing such an issuer is
    /// ambiguous and must reject rather than depend on realm priority.
    pub workload_ambiguous_issuers: Vec<String>,
}

impl RealmSnapshot {
    /// The enabled OIDC realm, if any.
    pub fn oidc(&self) -> Option<&OidcRealmRuntime> {
        self.oidc.as_ref()
    }
}

/// Per-instance snapshot cache over the `auth_realm` table.
///
/// `snapshot()` serves a cached [`RealmSnapshot`] until the TTL lapses, then
/// rebuilds it from the database (two cheap queries + pure construction).
/// `invalidate()` drops the cached snapshot (call after every admin write so
/// the local instance converges immediately; peers converge within TTL).
pub struct RealmAuth {
    pool: PgPool,
    cache: Cache,
    config: Arc<Config>,
    ttl: Duration,
    snapshot: tokio::sync::RwLock<Option<Arc<RealmSnapshot>>>,
    /// Decrypts `auth_realm.secrets_enc` when secret encryption is enabled.
    envelope: Option<Arc<EnvelopeService>>,
    /// Per-provider bounds on concurrent upstream credential forwards
    /// (`auth.credential_forward_max_concurrent`). Lives here, not in the
    /// snapshot, so a snapshot rebuild never resets a bound while forwards
    /// started by the previous build are still in flight.
    forward_limits: Arc<ForwardLimits>,
}

impl RealmAuth {
    /// Build the (empty) cache; the first `snapshot()` call populates it.
    pub fn new(pool: PgPool, cache: Cache, config: Arc<Config>) -> Self {
        let ttl = Duration::from_secs(config.auth.realm_cache_ttl_seconds.max(1));
        let forward_limits = Arc::new(ForwardLimits::new(
            config.auth.credential_forward_max_concurrent,
        ));
        Self {
            pool,
            cache,
            config,
            ttl,
            snapshot: tokio::sync::RwLock::new(None),
            envelope: None,
            forward_limits,
        }
    }

    /// Attach the secret-encryption service so encrypted realm secrets can be
    /// read (`None` ⇒ only plaintext realm configs are usable).
    pub fn with_envelope(mut self, envelope: Option<Arc<EnvelopeService>>) -> Self {
        self.envelope = envelope;
        self
    }

    /// The current snapshot (cached within TTL; rebuilt from the DB after).
    pub async fn snapshot(&self) -> anyhow::Result<Arc<RealmSnapshot>> {
        if let Some(s) = self.snapshot.read().await.as_ref() {
            if s.built_at.elapsed() < self.ttl {
                return Ok(s.clone());
            }
        }
        let mut slot = self.snapshot.write().await;
        // Double-check: another task may have rebuilt while we waited.
        if let Some(s) = slot.as_ref() {
            if s.built_at.elapsed() < self.ttl {
                return Ok(s.clone());
            }
        }
        let snap = Arc::new(self.build().await?);
        *slot = Some(snap.clone());
        Ok(snap)
    }

    /// Drop the cached snapshot (after an admin realm write).
    pub async fn invalidate(&self) {
        *self.snapshot.write().await = None;
    }

    /// Rebuild the snapshot from the realm table.
    async fn build(&self) -> anyhow::Result<RealmSnapshot> {
        let realms = auth_realm_dao::list_realms(&self.pool).await?;

        let mut providers: Vec<Box<dyn AuthProvider>> = Vec::new();
        let mut has_cred_forward = false;
        let mut oidc: Option<OidcRealmRuntime> = None;
        let mut workload: Vec<super::wif::WorkloadIdentityRealm> = Vec::new();
        let mut workload_configured_issuers: Vec<String> = Vec::new();

        for realm in realms.iter().filter(|r| r.enabled) {
            // The logical config (encrypted secrets merged in). A realm whose
            // secrets cannot be decrypted is skipped: fail closed.
            let config = match secret_dao::realm_config(self.envelope.as_deref(), realm).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(realm = %realm.name, error = %e, "realm secrets unreadable; realm skipped");
                    continue;
                }
            };
            match realm.kind.as_str() {
                KIND_LOCAL => {
                    providers.push(Box::new(LocalPasswordProvider::new(self.pool.clone())));
                }
                KIND_CRED_FORWARD => match self.build_cred_forward(realm, &config) {
                    Ok(p) => {
                        has_cred_forward = true;
                        providers.push(p);
                    }
                    // One malformed row must not take down the other realms;
                    // its own logins fail (closed) until an admin fixes it.
                    Err(e) => {
                        tracing::error!(realm = %realm.name, error = %e, "credential-forwarding realm skipped");
                    }
                },
                KIND_OIDC => {
                    if oidc.is_some() {
                        // The admin API refuses a second enabled OIDC realm;
                        // a raw DB write could still create one — first wins.
                        tracing::error!(realm = %realm.name, "second enabled oidc realm ignored (multi-IdP is a later slice)");
                        continue;
                    }
                    match self.build_oidc(realm, &config) {
                        Ok(rt) => oidc = Some(rt),
                        Err(e) => {
                            tracing::error!(realm = %realm.name, error = %e, "oidc realm skipped");
                        }
                    }
                }
                KIND_WORKLOAD_IDENTITY => {
                    if let Some(issuer) = realm
                        .config
                        .get("issuer")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .map(|issuer| issuer.trim_end_matches('/'))
                        .filter(|issuer| !issuer.is_empty())
                    {
                        workload_configured_issuers.push(issuer.to_string());
                    }
                    match super::wif::WorkloadIdentityRealm::build(realm, &self.cache) {
                        Ok(w) => workload.push(w),
                        // One malformed WIF realm must not take down the others; its
                        // own tokens fail (closed) until an admin fixes it.
                        Err(e) => {
                            tracing::error!(realm = %realm.name, error = %e, "workload_identity realm skipped");
                        }
                    }
                }
                other => {
                    tracing::error!(realm = %realm.name, kind = %other, "unknown realm kind skipped");
                }
            }
        }

        let chain = if providers.is_empty() {
            None
        } else {
            Some(Arc::new(Chain::new(providers)))
        };
        let wire_password_enabled = self.config.auth.allow_password_basic || has_cred_forward;
        workload_configured_issuers.sort();
        let workload_ambiguous_issuers = workload_configured_issuers
            .windows(2)
            .filter(|pair| pair[0] == pair[1])
            .map(|pair| pair[0].clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        workload_configured_issuers.dedup();

        Ok(RealmSnapshot {
            built_at: Instant::now(),
            realms,
            chain,
            wire_password_enabled,
            oidc,
            workload,
            workload_configured_issuers,
            workload_ambiguous_issuers,
        })
    }

    /// Build the per-realm credential-forwarding provider.
    fn build_cred_forward(
        &self,
        realm: &AuthRealm,
        config: &JsonValue,
    ) -> anyhow::Result<Box<dyn AuthProvider>> {
        let cfg: CredForwardRealmConfig =
            serde_json::from_value(config.clone()).map_err(|e| anyhow::anyhow!("config: {e}"))?;
        let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms);
        let request_timeout = Duration::from_millis(cfg.request_timeout_ms);
        // Never follows redirects: a 3xx is judged (as unavailable) by the
        // provider instead of the page it points at.
        let client = ssrf::credential_forward_client(connect_timeout)
            .map_err(|e| anyhow::anyhow!("build credential-forwarding client: {e}"))?;
        // Realm-scoped: keys the validated-credential cache per realm.
        let provider_id = format!("realm:{}", realm.name);
        let cred_cache = ValidatedCredentialCache::new(
            self.cache.clone(),
            self.pool.clone(),
            CredKeyPepper::new(cfg.key_pepper.clone().into_bytes()),
            Duration::from_secs(cfg.positive_ttl_secs),
            Duration::from_secs(cfg.negative_ttl_secs),
        )
        .with_forward_limit(self.forward_limits.for_provider(&provider_id))
        // The request's own timeout normally fires first (and is logged as
        // such); the cache's deadline is the backstop its lease is sized by.
        .with_forward_timeout(request_timeout + Duration::from_secs(1));
        let core = forge_core::auth::UpstreamBasicConfig {
            url: cfg.url,
            method: cfg.method.to_ascii_uppercase(),
            success_status: cfg.success_status,
            reject_status: cfg.reject_status,
            connect_timeout,
            request_timeout,
            required_groups: cfg.required_groups,
            groups_path: cfg.groups_path,
            admin_group: cfg.admin_group,
            provider_id,
            auto_provision: cfg.auto_provision,
            realm_id: Some(realm.id),
        };
        Ok(Box::new(UpstreamBasicProvider::new(
            core, client, cred_cache,
        )))
    }

    /// Build the OIDC login runtime from a realm row.
    fn build_oidc(
        &self,
        realm: &AuthRealm,
        config: &JsonValue,
    ) -> anyhow::Result<OidcRealmRuntime> {
        let cfg: OidcRealmConfig =
            serde_json::from_value(config.clone()).map_err(|e| anyhow::anyhow!("config: {e}"))?;
        let base = self.config.public_base_url();
        let (idle, absolute) = self.config.session_ttls();
        // Synthesize the legacy-shaped OidcConfig the runtime builder takes;
        // the redirect URL is always derived from the public base URL.
        let oidc_config = OidcConfig {
            enabled: true,
            issuer: cfg.issuer.clone(),
            client_id: cfg.client_id.clone(),
            client_secret: cfg.client_secret.clone(),
            redirect_url: format!("{base}/auth/oidc/callback"),
            scopes: cfg.scopes.clone(),
            clock_skew_seconds: cfg.clock_skew_seconds,
            allow_private_issuer: cfg.allow_http_issuer,
            username_claim: cfg.username_claim.clone(),
            email_claim: cfg.email_claim.clone(),
            display_name_claim: cfg.display_name_claim.clone(),
            auto_provision: cfg.auto_provision,
            link_existing_by_username: cfg.link_existing_by_username,
            admin_groups: cfg.admin_groups.clone(),
            admin_claim: cfg.admin_claim.clone(),
            session_idle_ttl_seconds: idle,
            session_absolute_ttl_seconds: absolute,
        };
        let runtime =
            OidcRuntime::build(&oidc_config, self.pool.clone(), &base, self.cache.clone())?;
        Ok(OidcRealmRuntime {
            realm_name: realm.name.clone(),
            label: cfg
                .button_label
                .clone()
                .filter(|l| !l.trim().is_empty())
                .unwrap_or_else(|| realm.name.clone()),
            login_domains: cfg
                .login_domains
                .iter()
                .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            runtime,
        })
    }
}

/// The wire Basic source asks here for the current password chain (12.7: the
/// chain follows runtime realm edits). Fail-closed: a snapshot error reports
/// "no chain", which denies the password path without touching token/anon
/// handling.
#[async_trait::async_trait]
impl ChainSource for RealmAuth {
    async fn password_chain(&self) -> Option<Arc<Chain>> {
        match self.snapshot().await {
            Ok(s) if s.wire_password_enabled => s.chain.clone(),
            Ok(_) => None,
            Err(e) => {
                tracing::error!(error = %e, "realm snapshot failed; password path denied");
                None
            }
        }
    }
}

// ─── legacy-config import (seed with drift detection) ───────────────────────

/// Fingerprint a realm config document (canonical serde_json string → sha256
/// hex, via the token hasher). Used to detect whether a seeded realm row has
/// been modified through the admin API since the last import.
fn config_fingerprint(config: &JsonValue) -> String {
    forge_core::auth::token::hash_token(&config.to_string())
}

/// The `forge_setting` key holding the seed fingerprint for a realm kind.
fn seed_fingerprint_key(kind: &str) -> String {
    format!("auth_realm_seed_{kind}")
}

/// Import the legacy `[oidc]` / `[auth.upstream_basic]` TOML blocks into
/// `auth_realm` rows.
///
/// Semantics ("config-as-seed with drift detection"):
/// * **First boot** (no realm of the kind): insert a realm row from the block
///   and record a fingerprint of the seeded config in `forge_setting`.
/// * **Later boots with the block still present**: if the seeded row's config
///   still matches the recorded fingerprint (i.e. nobody edited it through the
///   admin API), a *changed* block re-applies — operators who manage forge
///   purely through TOML keep working the way they always did. The moment the
///   row is edited via the API the fingerprint no longer matches and the TOML
///   block stops clobbering it (the database is the authority).
/// * A renamed/deleted seeded row is left alone (the operator took over).
///
/// The one-shot `forge_setting` marker [`REALMS_SEEDED_KEY`] gates only the
/// initial `local`-realm priority adjustment (which must not fight later
/// manual reorders).
///
/// Seeded secrets go through the envelope (`envelope = Some`) like admin
/// writes, and the drift fingerprint is taken over the *logical* config.
pub async fn seed_auth_realms(
    config: &Config,
    pool: &PgPool,
    envelope: Option<&EnvelopeService>,
) -> anyhow::Result<()> {
    let first_import =
        authz_dao::get_setting(pool, REALMS_SEEDED_KEY).await? != Some("true".to_string());

    // Priority slots follow the configured provider order: (index + 1) * 10.
    let slot = |idx: usize| ((idx + 1) * 10) as i32;
    let provider_idx = |id: &str| config.auth.providers.iter().position(|p| p == id);

    if first_import {
        // The built-in local row was created by migration 0010 at priority 10;
        // move it to its configured slot when the order says otherwise.
        if let Some(local) = auth_realm_dao::find_realm_by_name(pool, "local").await? {
            let desired = provider_idx("local-password").map(slot).unwrap_or(10);
            if local.priority != desired {
                auth_realm_dao::update_realm(
                    pool,
                    local.id,
                    forge_db::auth_realm_dao::AuthRealmUpdate {
                        name: local.name.clone(),
                        enabled: local.enabled,
                        priority: desired,
                        config: local.config.clone(),
                    },
                )
                .await?;
            }
        }
    }

    if let Some(ub) = config.auth.upstream_basic.as_ref().filter(|u| u.enabled) {
        let cfg = CredForwardRealmConfig {
            url: ub.url.clone(),
            method: ub.method.to_ascii_uppercase(),
            success_status: ub.success_status.clone(),
            reject_status: ub.reject_status.clone(),
            connect_timeout_ms: ub.connect_timeout_ms,
            request_timeout_ms: ub.request_timeout_ms,
            required_groups: ub.required_groups.clone(),
            groups_path: ub.groups_path.clone(),
            admin_group: ub.admin_group.clone(),
            auto_provision: ub.auto_provision,
            positive_ttl_secs: ub.cache.positive_ttl_secs,
            negative_ttl_secs: ub.cache.negative_ttl_secs,
            key_pepper: ub.cache.key_pepper.clone(),
        };
        let priority = provider_idx("upstream-basic").map(slot).unwrap_or(20);
        apply_seed(
            pool,
            envelope,
            KIND_CRED_FORWARD,
            "upstream-basic",
            priority,
            serde_json::to_value(&cfg).expect("serializable"),
        )
        .await?;
    }

    if let Some(o) = config.oidc.as_ref().filter(|o| o.enabled) {
        let cfg = OidcRealmConfig {
            issuer: o.issuer.clone(),
            client_id: o.client_id.clone(),
            client_secret: o.client_secret.clone(),
            scopes: o.scopes.clone(),
            clock_skew_seconds: o.clock_skew_seconds,
            allow_http_issuer: o.allow_private_issuer,
            username_claim: o.username_claim.clone(),
            email_claim: o.email_claim.clone(),
            display_name_claim: o.display_name_claim.clone(),
            auto_provision: o.auto_provision,
            link_existing_by_username: o.link_existing_by_username,
            admin_groups: o.admin_groups.clone(),
            admin_claim: o.admin_claim.clone(),
            login_domains: Vec::new(),
            button_label: None,
        };
        let priority = auth_realm_dao::next_priority(pool).await?;
        apply_seed(
            pool,
            envelope,
            KIND_OIDC,
            "oidc",
            priority,
            serde_json::to_value(&cfg).expect("serializable"),
        )
        .await?;
    }

    if first_import {
        authz_dao::set_setting(pool, REALMS_SEEDED_KEY, "true").await?;
    }
    Ok(())
}

/// Insert or fingerprint-refresh one seeded realm row (see
/// [`seed_auth_realms`] for the drift-detection contract).
async fn apply_seed(
    pool: &PgPool,
    envelope: Option<&EnvelopeService>,
    kind: &str,
    name: &str,
    priority: i32,
    config: JsonValue,
) -> anyhow::Result<()> {
    let fingerprint = config_fingerprint(&config);
    let key = seed_fingerprint_key(kind);

    match auth_realm_dao::find_realm_by_name(pool, name).await? {
        None => {
            // No seeded row (first boot, or the operator deleted/renamed it).
            // Only insert when the kind is absent entirely — an operator who
            // renamed the row or created their own realm of this kind has
            // taken over and the TOML block is ignored.
            if !auth_realm_dao::kind_exists(pool, kind).await? {
                secret_dao::insert_realm_with_secrets(
                    pool,
                    envelope,
                    forge_db::auth_realm_dao::NewAuthRealm {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        enabled: true,
                        priority,
                        config,
                    },
                    secret_keys(kind),
                )
                .await?;
                authz_dao::set_setting(pool, &key, &fingerprint).await?;
                tracing::info!(realm = %name, %kind, "imported legacy config into auth_realm");
            }
        }
        Some(existing) if existing.kind == kind => {
            // Compare the logical config (encrypted secrets merged in). If the
            // secrets cannot be read here, leave the row alone.
            let Ok(existing_config) = secret_dao::realm_config(envelope, &existing).await else {
                tracing::warn!(realm = %name, "seeded realm secrets unreadable; skipping re-apply");
                return Ok(());
            };
            let last_seed = authz_dao::get_setting(pool, &key).await?;
            let unmodified =
                last_seed.as_deref() == Some(&config_fingerprint(&existing_config) as &str);
            if unmodified && existing_config != config {
                secret_dao::update_realm_with_secrets(
                    pool,
                    envelope,
                    existing.id,
                    forge_db::auth_realm_dao::AuthRealmUpdate {
                        name: existing.name.clone(),
                        enabled: existing.enabled,
                        priority: existing.priority,
                        config,
                    },
                    secret_keys(kind),
                )
                .await?;
                authz_dao::set_setting(pool, &key, &fingerprint).await?;
                tracing::info!(realm = %name, %kind, "re-applied changed legacy config (row unmodified since seed)");
            }
        }
        Some(_) => {
            // A realm with the seed name but a different kind: operator-made;
            // never touch it.
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cred_forward_config_validates_and_normalizes() {
        let ok = validate_config(
            KIND_CRED_FORWARD,
            &json!({"url": "https://nexus.internal/status", "key_pepper": "p3pper"}),
        )
        .expect("valid");
        // Defaults filled in by normalization.
        assert_eq!(ok["method"], "GET");
        assert_eq!(ok["success_status"], json!([200]));
        assert_eq!(ok["positive_ttl_secs"], 300);

        // Loopback/private upstream URLs are fine (12.7 §3.6); bad scheme is not.
        assert!(validate_config(
            KIND_CRED_FORWARD,
            &json!({"url": "http://127.0.0.1:8081/s", "key_pepper": "p"}),
        )
        .is_ok());
        assert!(validate_config(
            KIND_CRED_FORWARD,
            &json!({"url": "ftp://x/s", "key_pepper": "p"}),
        )
        .is_err());
        // Missing pepper / groups_path inconsistency rejected.
        assert!(validate_config(KIND_CRED_FORWARD, &json!({"url": "https://x/s"})).is_err());
        assert!(validate_config(
            KIND_CRED_FORWARD,
            &json!({"url": "https://x/s", "key_pepper": "p", "required_groups": ["g"]}),
        )
        .is_err());
    }

    #[test]
    fn oidc_config_validates_issuer_and_secrets() {
        let base = json!({
            "issuer": "https://login.microsoftonline.com/tid/v2.0",
            "client_id": "cid",
            "client_secret": "shh",
        });
        let ok = validate_config(KIND_OIDC, &base).expect("valid");
        assert_eq!(ok["username_claim"], "preferred_username");

        // http issuer requires the dev opt-in.
        let mut http = base.clone();
        http["issuer"] = json!("http://idp.test/v2.0");
        assert!(validate_config(KIND_OIDC, &http).is_err());
        http["allow_http_issuer"] = json!(true);
        assert!(validate_config(KIND_OIDC, &http).is_ok());

        // Missing secret rejected.
        let mut nosecret = base.clone();
        nosecret["client_secret"] = json!("");
        assert!(validate_config(KIND_OIDC, &nosecret).is_err());
    }

    #[test]
    fn local_config_is_empty_and_workload_identity_validates() {
        assert_eq!(
            validate_config(KIND_LOCAL, &json!({"anything": 1})).unwrap(),
            json!({})
        );
        // workload_identity now validates through the WIF module (slice 12.8):
        // an empty config is rejected (no issuer/audiences/rules)…
        assert!(validate_config(KIND_WORKLOAD_IDENTITY, &json!({})).is_err());
        // …and a complete one is accepted.
        assert!(validate_config(
            KIND_WORKLOAD_IDENTITY,
            &json!({
                "issuer": "https://gitlab.example",
                "allowed_audiences": ["forge"],
                "rules": [{"role": "ci", "conditions": [{"claim": "sub", "any_of": ["s"]}]}],
            }),
        )
        .is_ok());
        assert!(validate_config("nope", &json!({})).is_err());
    }

    #[test]
    fn redaction_strips_secrets_and_marks_presence() {
        let cfg = json!({"url": "https://x/s", "key_pepper": "p3pper"});
        let red = redact_config(KIND_CRED_FORWARD, &cfg);
        assert!(red.get("key_pepper").is_none());
        assert_eq!(red["key_pepper_set"], json!(true));

        let cfg = json!({"issuer": "https://x", "client_id": "c", "client_secret": ""});
        let red = redact_config(KIND_OIDC, &cfg);
        assert!(red.get("client_secret").is_none());
        assert_eq!(red["client_secret_set"], json!(false));
    }

    #[test]
    fn merge_keeps_stored_secret_when_omitted_or_blank() {
        let stored = json!({"url": "https://x/s", "key_pepper": "old-secret"});
        // Omitted → kept.
        let merged = merge_secrets(KIND_CRED_FORWARD, &stored, &json!({"url": "https://y/s"}));
        assert_eq!(merged["key_pepper"], "old-secret");
        assert_eq!(merged["url"], "https://y/s");
        // Blank → kept; echoed redaction marker dropped.
        let merged = merge_secrets(
            KIND_CRED_FORWARD,
            &stored,
            &json!({"url": "https://y/s", "key_pepper": "", "key_pepper_set": true}),
        );
        assert_eq!(merged["key_pepper"], "old-secret");
        assert!(merged.get("key_pepper_set").is_none());
        // Provided → replaced.
        let merged = merge_secrets(
            KIND_CRED_FORWARD,
            &stored,
            &json!({"url": "https://y/s", "key_pepper": "new-secret"}),
        );
        assert_eq!(merged["key_pepper"], "new-secret");
    }
}
