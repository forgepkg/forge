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
use forge_core::auth::local_password::DEFAULT_QUEUE_TIMEOUT;
use forge_core::auth::{
    AuthProvider, Chain, ChainSource, ChainUnavailable, CredKeyPepper, ForwardLimits,
    LocalPasswordProvider, PasswordHashLimiter, UpstreamBasicProvider, ValidatedCredentialCache,
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
///
/// Unknown keys are refused, so a misspelled gate (`identity_pth`,
/// `required_group`) never silently takes its permissive default. Stored rows
/// are parsed with this type too: a field removed later must stay accepted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Optional upstream group that maps to forge admin. Every login that
    /// fetches the groups re-applies it (grants and demotes), with or without
    /// `auto_provision`.
    #[serde(default)]
    pub admin_group: String,
    /// `.`-separated path into the JSON success body naming the account the
    /// upstream authenticated (e.g. `login`). When set it must equal the
    /// canonical username, or the credential is rejected — required for an
    /// upstream that accepts a secret with any username (personal access
    /// tokens). Empty ⇒ the upstream must itself bind username to secret.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity_path: String,
    /// Accept a plain-`http` `url` that is not loopback. Off: every login
    /// sends a password there, so it must be https.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_http: bool,
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
/// above. Unknown keys are refused, as there (a misspelled `required_claims`
/// would let every account of a multi-tenant issuer sign in).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Allow-gate: claim name → allowed values; every listed claim must carry
    /// one of them, or the login is refused (e.g. `{"tid": ["<tenant id>"]}`
    /// for a multi-tenant Entra app, `{"hd": ["corp.example"]}` for Google).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub required_claims: std::collections::BTreeMap<String, Vec<String>>,
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
    /// Hosts besides the issuer's that the IdP's token, JWKS and
    /// authorization endpoints may use (Google: `oauth2.googleapis.com`,
    /// `www.googleapis.com`). Empty ⇒ the issuer's host only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_hosts: Vec<String>,
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
/// accepts only an empty/no-op config; every other kind refuses unknown keys
/// (the `<key>_set` markers of [`redact_config`], which a client may echo
/// back, are dropped first).
pub fn validate_config(kind: &str, config: &JsonValue) -> Result<JsonValue, String> {
    let config = &without_secret_markers(kind, config);
    match kind {
        KIND_LOCAL => Ok(JsonValue::Object(Default::default())),
        KIND_CRED_FORWARD => {
            let cfg: CredForwardRealmConfig = serde_json::from_value(config.clone())
                .map_err(|e| format!("invalid config: {e}"))?;
            ssrf::validate_credential_forward_url(&cfg.url, cfg.allow_http)
                .map_err(|e| format!("invalid url: {e}"))?;
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
            let mut cfg: OidcRealmConfig = serde_json::from_value(config.clone())
                .map_err(|e| format!("invalid config: {e}"))?;
            cfg.endpoint_hosts = normalize_endpoint_hosts(&cfg.endpoint_hosts)?;
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

/// `endpoint_hosts` lowercased and checked: each one a bare host name (no
/// scheme, port, path or wildcard).
pub(crate) fn normalize_endpoint_hosts(hosts: &[String]) -> Result<Vec<String>, String> {
    hosts
        .iter()
        .map(|raw| {
            let host = raw.trim().to_ascii_lowercase();
            let is_name = !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            let parses = url::Url::parse(&format!("https://{host}/"))
                .is_ok_and(|url| url.host_str() == Some(host.as_str()));
            if is_name && parses {
                Ok(host)
            } else {
                Err(format!("endpoint_hosts: {raw:?} is not a host name"))
            }
        })
        .collect()
}

/// `config` without the `<key>_set` markers [`redact_config`] puts in place of
/// the secrets.
fn without_secret_markers(kind: &str, config: &JsonValue) -> JsonValue {
    let mut doc = config.clone();
    if let JsonValue::Object(map) = &mut doc {
        for key in secret_keys(kind) {
            map.remove(&format!("{key}_set"));
        }
    }
    doc
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

/// Config keys a realm's stored secrets are bound to: the secret belongs to
/// that party, so changing any of them requires entering the secret again
/// (the ciphertext is bound to them as well).
fn secret_binding_keys(kind: &str) -> &'static [&'static str] {
    secret_dao::realm_secret_binding_keys(kind)
}

/// Whether `key` differs between two config documents (strings compared
/// trimmed and without a trailing `/`).
fn binding_changed(stored: &JsonValue, incoming: &JsonValue, key: &str) -> bool {
    let norm = |doc: &JsonValue| {
        doc.get(key)
            .and_then(JsonValue::as_str)
            .map(|v| v.trim().trim_end_matches('/').to_string())
    };
    norm(stored) != norm(incoming)
}

/// Merge a config **update** with the stored document's secrets: when the
/// incoming document omits a secret key (or sends `null` / `""`), the stored
/// value is kept — secrets are write-only, so the admin UI round-trips the
/// redacted view without clobbering them. A stored secret is **not** carried
/// over when the party it belongs to changes (an OIDC realm's `issuer` or
/// `client_id`): sending the old IdP's client secret to a new issuer would
/// hand it to whoever runs that issuer, so the update must supply a new one.
pub fn merge_secrets(kind: &str, stored: &JsonValue, incoming: &JsonValue) -> JsonValue {
    let mut doc = incoming.clone();
    let rebound = secret_binding_keys(kind)
        .iter()
        .any(|key| binding_changed(stored, incoming, key));
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
                match stored.get(*key).filter(|_| !rebound) {
                    Some(stored_secret) => {
                        map.insert((*key).to_string(), stored_secret.clone());
                    }
                    None => {
                        map.remove(*key);
                    }
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
    /// Bounds concurrent argon2 verifications across every snapshot's local
    /// provider (`auth.password_verify_concurrency`); outlives rebuilds.
    password_limiter: Arc<PasswordHashLimiter>,
}

impl RealmAuth {
    /// Build the (empty) cache; the first `snapshot()` call populates it.
    pub fn new(pool: PgPool, cache: Cache, config: Arc<Config>) -> Self {
        let ttl = Duration::from_secs(config.auth.realm_cache_ttl_seconds.max(1));
        let forward_limits = Arc::new(ForwardLimits::new(
            config.auth.credential_forward_max_concurrent,
        ));
        let password_limiter = Arc::new(PasswordHashLimiter::new(
            config.auth.password_verify_concurrency,
            DEFAULT_QUEUE_TIMEOUT,
        ));
        Self {
            pool,
            cache,
            config,
            ttl,
            snapshot: tokio::sync::RwLock::new(None),
            envelope: None,
            forward_limits,
            password_limiter,
        }
    }

    /// Use `limiter` for the local provider's argon2 verifications instead of
    /// one sized by `auth.password_verify_concurrency` (a test holds its
    /// permits to observe whether a verification runs).
    pub fn with_password_limiter(mut self, limiter: Arc<PasswordHashLimiter>) -> Self {
        self.password_limiter = limiter;
        self
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

        // Where the local provider goes, and whether a credential-forwarding
        // provider was built after it. Then names the local store does not own
        // go upstream next, and the local provider need not equalize their
        // timing with a dummy hash. Decided from the providers actually built:
        // a forwarding realm that is skipped (fail closed) makes no upstream
        // call, so the local provider must pay the dummy hash itself.
        let mut local_at: Option<usize> = None;
        let mut forwarding_follows_local = false;

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
                // Inserted once the loop knows what follows it.
                KIND_LOCAL => local_at = local_at.or(Some(providers.len())),
                KIND_CRED_FORWARD => match self.build_cred_forward(realm, &config) {
                    Ok(p) => {
                        has_cred_forward = true;
                        forwarding_follows_local |= local_at.is_some();
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

        if let Some(at) = local_at {
            providers.insert(
                at,
                Box::new(
                    LocalPasswordProvider::with_limiter(
                        self.pool.clone(),
                        self.password_limiter.clone(),
                    )
                    .forwarding_follows(forwarding_follows_local),
                ),
            );
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
        // Also for rows stored before the https rule: never forward passwords
        // in the clear to a non-loopback host unless the realm says so.
        ssrf::validate_credential_forward_url(&cfg.url, cfg.allow_http)
            .map_err(|e| anyhow::anyhow!("url: {e}"))?;
        if cfg.auto_provision && cfg.identity_path.trim().is_empty() {
            tracing::warn!(
                realm = %realm.name,
                "credential-forwarding realm provisions accounts without identity_path: \
                 an upstream that also accepts another spelling of a username \
                 (DOMAIN\\user, user@domain) signs that spelling in as a new account, \
                 which a deactivation of the usual name does not stop"
            );
        }
        let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms);
        let request_timeout = Duration::from_millis(cfg.request_timeout_ms);
        // Never follows redirects: a 3xx is judged (as unavailable) by the
        // provider instead of the page it points at.
        let client = ssrf::credential_forward_client(connect_timeout)
            .map_err(|e| anyhow::anyhow!("build credential-forwarding client: {e}"))?;
        // Realm-scoped: keys the validated-credential cache per realm.
        let provider_id = format!("realm:{}", realm.name);
        // Bind cached verdicts to this exact realm config: after an edit (a
        // new required group or identity_path, another URL, …) every verdict
        // cached under the old config is unreachable, so none outlives the
        // policy that produced it.
        let mut pepper = cfg.key_pepper.clone().into_bytes();
        pepper.push(0);
        pepper.extend_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(
            config.to_string().as_bytes(),
        ));
        let cred_cache = ValidatedCredentialCache::new(
            self.cache.clone(),
            self.pool.clone(),
            CredKeyPepper::new(pepper),
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
            identity_path: cfg.identity_path,
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
            required_claims: cfg.required_claims.clone(),
            endpoint_hosts: cfg.endpoint_hosts.clone(),
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
    async fn password_chain(&self) -> Result<Option<Arc<Chain>>, ChainUnavailable> {
        match self.snapshot().await {
            Ok(s) if s.wire_password_enabled => Ok(s.chain.clone()),
            Ok(_) => Ok(None),
            Err(e) => {
                tracing::error!(error = %e, "realm snapshot failed; password path denied");
                Err(ChainUnavailable)
            }
        }
    }
}

// ─── legacy-config import (seed with drift detection) ───────────────────────

/// Prefix of the current seed-marker format (see [`seed_fingerprint`]).
const SEED_FINGERPRINT_V2: &str = "v2:";

/// Fingerprint a seeded realm config: sha256 hex (via the token hasher) of
/// its canonical serde_json form **without its secret keys**. Used to detect
/// whether a seeded realm row has been modified since the last import.
///
/// The secrets are left out because the marker is stored in plaintext in
/// `forge_setting` next to the plaintext `auth_realm.config`: a hash over the
/// whole document let anyone with a database dump test guesses for an
/// encrypted `client_secret` / `key_pepper` offline. A secret changed
/// through the admin API is caught by [`forget_seed`] instead, which drops
/// the marker.
fn seed_fingerprint(kind: &str, config: &JsonValue) -> String {
    let mut doc = config.clone();
    if let JsonValue::Object(map) = &mut doc {
        for key in secret_keys(kind) {
            map.remove(*key);
        }
    }
    format!(
        "{SEED_FINGERPRINT_V2}{}",
        forge_core::auth::token::hash_token(&doc.to_string())
    )
}

/// The marker pre-release builds stored: sha256 hex over the whole config,
/// secrets included. Only ever compared once, then replaced or dropped.
fn legacy_seed_fingerprint(config: &JsonValue) -> String {
    forge_core::auth::token::hash_token(&config.to_string())
}

/// The `forge_setting` key holding the seed fingerprint for a realm kind.
fn seed_fingerprint_key(kind: &str) -> String {
    format!("auth_realm_seed_{kind}")
}

/// The realm row a legacy config block of `kind` is imported into.
fn seed_name(kind: &str) -> Option<&'static str> {
    match kind {
        KIND_CRED_FORWARD => Some("upstream-basic"),
        KIND_OIDC => Some("oidc"),
        _ => None,
    }
}

/// Record that `realm` is about to be changed through the admin API: when it
/// is the row a legacy config block was imported into, drop the seed marker,
/// so the block no longer re-applies over the change (the database is the
/// authority from now on). Call it before the write: if the write then
/// fails, the block merely stops re-applying.
pub async fn forget_seed(pool: &PgPool, realm: &forge_db::model::AuthRealm) -> sqlx::Result<()> {
    if seed_name(&realm.kind) == Some(realm.name.as_str()) {
        authz_dao::delete_setting(pool, &seed_fingerprint_key(&realm.kind)).await?;
    }
    Ok(())
}

/// Import the legacy `[oidc]` / `[auth.upstream_basic]` TOML blocks into
/// `auth_realm` rows.
///
/// Semantics ("config-as-seed with drift detection"):
/// * **First boot** (no realm of the kind): insert a realm row from the block
///   and record a fingerprint of the seeded config in `forge_setting`.
/// * **Later boots with the block still present**: if the seeded row's config
///   still matches the recorded fingerprint and nobody edited it through the
///   admin API, a *changed* block re-applies — operators who manage forge
///   purely through TOML keep working the way they always did. The moment the
///   row's config is edited via the API the marker is dropped
///   ([`forget_seed`]) and the TOML block stops clobbering it (the database
///   is the authority). The fingerprint covers the non-secret fields only
///   ([`seed_fingerprint`]).
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
            identity_path: ub.identity_path.clone(),
            allow_http: ub.allow_http,
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
            required_claims: o.required_claims.clone(),
            login_domains: Vec::new(),
            button_label: None,
            endpoint_hosts: normalize_endpoint_hosts(&o.endpoint_hosts)
                .map_err(anyhow::Error::msg)?,
        };
        let priority = auth_realm_dao::next_priority(pool).await?;
        apply_seed(
            pool,
            envelope,
            KIND_OIDC,
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
    priority: i32,
    config: JsonValue,
) -> anyhow::Result<()> {
    let name = seed_name(kind).expect("a seeded realm kind");
    let fingerprint = seed_fingerprint(kind, &config);
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
            let Some(last_seed) = authz_dao::get_setting(pool, &key).await? else {
                return Ok(());
            };
            // The marker this boot may still re-apply under. An admin edit
            // drops the marker before it writes ([`forget_seed`]), so every
            // write below is a compare-and-set against it: a seed racing an
            // edit backs off instead of re-creating the marker over it.
            let marker = if last_seed.starts_with(SEED_FINGERPRINT_V2) {
                if last_seed != seed_fingerprint(kind, &existing_config) {
                    return Ok(());
                }
                last_seed
            } else if last_seed == legacy_seed_fingerprint(&existing_config) {
                // A pre-release marker hashes the secret as well: replace it
                // whatever happens below.
                let current = seed_fingerprint(kind, &existing_config);
                if !authz_dao::replace_setting(pool, &key, &last_seed, &current).await? {
                    return Ok(());
                }
                current
            } else {
                // A pre-release marker of an edited row.
                authz_dao::delete_setting(pool, &key).await?;
                return Ok(());
            };
            if existing_config == config {
                return Ok(());
            }
            // The row is written only while it is still the one compared
            // above, and the marker only while it is still `marker`.
            let mut tx = pool.begin().await?;
            let applied = secret_dao::update_realm_with_secrets_if_unchanged(
                &mut tx,
                envelope,
                &existing,
                forge_db::auth_realm_dao::AuthRealmUpdate {
                    name: existing.name.clone(),
                    enabled: existing.enabled,
                    priority: existing.priority,
                    config,
                },
                secret_keys(kind),
            )
            .await?
            .is_some()
                && authz_dao::replace_setting(&mut *tx, &key, &marker, &fingerprint).await?;
            if applied {
                if kind == KIND_WORKLOAD_IDENTITY {
                    forge_db::workload_api_key_dao::revoke_realm(&mut tx, existing.id).await?;
                }
                tx.commit().await?;
                tracing::info!(realm = %name, %kind, "re-applied changed legacy config (row unmodified since seed)");
            } else {
                tx.rollback().await?;
                tracing::info!(realm = %name, %kind, "seeded realm changed while its legacy config was re-applied; left as is");
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
        // Passwords go there: plain http to another host needs allow_http.
        assert!(validate_config(
            KIND_CRED_FORWARD,
            &json!({"url": "http://nexus.internal/s", "key_pepper": "p"}),
        )
        .is_err());
        let allowed = validate_config(
            KIND_CRED_FORWARD,
            &json!({"url": "http://nexus.internal/s", "key_pepper": "p", "allow_http": true}),
        )
        .expect("explicitly allowed");
        assert_eq!(allowed["allow_http"], true);
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
    fn realm_configs_refuse_unknown_keys_but_not_secret_markers() {
        let cred = json!({"url": "https://nexus.internal/status", "key_pepper": "p"});
        let oidc = json!({
            "issuer": "https://login.microsoftonline.com/tid/v2.0",
            "client_id": "cid",
            "client_secret": "shh",
        });
        for (kind, base, typo) in [
            (KIND_CRED_FORWARD, &cred, "identity_pth"),
            (KIND_CRED_FORWARD, &cred, "required_group"),
            (KIND_CRED_FORWARD, &cred, "autoprovision"),
            (KIND_OIDC, &oidc, "required_claim"),
            (KIND_OIDC, &oidc, "auto_provison"),
        ] {
            let mut config = base.clone();
            config[typo] = json!("x");
            let err = validate_config(kind, &config).expect_err(typo);
            assert!(err.contains(&format!("unknown field `{typo}`")), "{err}");
        }
        // The redaction markers are dropped, not refused, and never stored.
        let mut echoed = cred.clone();
        echoed["key_pepper_set"] = json!(true);
        let ok = validate_config(KIND_CRED_FORWARD, &echoed).expect("marker dropped");
        assert!(ok.get("key_pepper_set").is_none());
        let mut echoed = oidc.clone();
        echoed["client_secret_set"] = json!(true);
        assert!(validate_config(KIND_OIDC, &echoed).is_ok());
    }

    #[test]
    fn oidc_endpoint_hosts_are_host_names_and_normalized() {
        let mut config = json!({
            "issuer": "https://accounts.google.com",
            "client_id": "cid",
            "client_secret": "shh",
            "endpoint_hosts": [" OAuth2.googleapis.com ", "www.googleapis.com"],
        });
        let ok = validate_config(KIND_OIDC, &config).expect("valid");
        assert_eq!(
            ok["endpoint_hosts"],
            json!(["oauth2.googleapis.com", "www.googleapis.com"])
        );
        for bad in [
            "https://oauth2.googleapis.com",
            "host:443",
            "host/path",
            "",
            "*.googleapis.com",
        ] {
            config["endpoint_hosts"] = json!([bad]);
            assert!(validate_config(KIND_OIDC, &config).is_err(), "{bad:?}");
        }
        // Absent stays absent in the stored document.
        config.as_object_mut().unwrap().remove("endpoint_hosts");
        let ok = validate_config(KIND_OIDC, &config).expect("valid");
        assert!(ok.get("endpoint_hosts").is_none());
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
    fn oidc_client_secret_is_dropped_when_the_issuer_or_client_changes() {
        let stored = json!({"issuer": "https://idp.example/", "client_id": "forge", "client_secret": "s3cret"});
        // Same issuer (trailing slash aside) and client: the secret is kept.
        let kept = merge_secrets(
            KIND_OIDC,
            &stored,
            &json!({"issuer": "https://idp.example", "client_id": "forge", "client_secret_set": true}),
        );
        assert_eq!(kept["client_secret"], json!("s3cret"));
        // A new issuer or client id must come with a new secret.
        for incoming in [
            json!({"issuer": "https://evil.example", "client_id": "forge"}),
            json!({"issuer": "https://idp.example", "client_id": "other"}),
        ] {
            let merged = merge_secrets(KIND_OIDC, &stored, &incoming);
            assert!(merged.get("client_secret").is_none(), "{incoming}");
            assert!(validate_config(KIND_OIDC, &merged).is_err());
        }
        let supplied = merge_secrets(
            KIND_OIDC,
            &stored,
            &json!({"issuer": "https://evil.example", "client_id": "forge", "client_secret": "new"}),
        );
        assert_eq!(supplied["client_secret"], json!("new"));
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
