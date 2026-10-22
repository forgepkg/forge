//! Workload-identity-federation (WIF) auth realm (slice 12.8, design doc
//! 2026-06-03 §4).
//!
//! A **non-interactive** realm for CI/automation: a workload (a GitLab CI job, a
//! GitHub Actions run, …) presents its OIDC `id_token` (a JWT) and forge
//! authenticates it by validating the JWT against a configured **trusted
//! issuer** (`.well-known/openid-configuration` → JWKS, reusing the 12.2
//! verifier), then maps its claims to a forge **role** via ordered claim-match
//! rules. No password ever exists; no interactive session is created — the
//! result is a stateless per-request [`Principal::Workload`] carrying the
//! resolved `role_id` (the §12.4 authz seam loads that role's effective set).
//!
//! ## Token routing (design §8 — no misrouting, no fall-through)
//!
//! NuGet's wire auth is Basic, so the workload can pass its `id_token` as the
//! Basic **password**, `X-NuGet-ApiKey`, or `Authorization: Bearer`. The
//! [`WorkloadIdentitySource`] engages **only** when a presented secret
//! structurally parses as a JWT (three segments; header decodes with a real,
//! non-`none` `alg`) **and** its `iss` matches a configured `workload_identity`
//! realm. When it engages, the outcome is terminal — a JWT that matches a WIF
//! issuer but fails validation (bad signature / `aud` / `exp` / no matching
//! rule) returns `Invalid` (→ 401) and does **not** fall through to the password
//! realms, so a JWT is never forwarded upstream as a "password". A secret that
//! is not a WIF-issuer JWT yields `NoCredentials`, letting the token/Basic
//! sources handle it.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use forge_cache::Cache;
use forge_core::auth::token::{PrincipalSource, SourceOutcome};
use forge_core::auth::Principal;
use forge_core::auth::{is_workload_key, WORKLOAD_USERNAME};
use forge_core::net::ssrf;
use forge_core::oidc::{IdTokenClaims, OidcError, OidcMetadataClient, Verified};
use forge_db::authz_dao;
use forge_db::model::AuthRealm;
use forge_db::workload_api_key_dao;
use http::header::AUTHORIZATION;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use super::realms::{RealmAuth, RealmSnapshot};

/// Default leeway (seconds) on `exp`/`nbf`/`iat` for a WIF token.
fn default_clock_skew() -> u64 {
    60
}

/// Workload tokens are expected to be short lived, but GitLab sets an ID
/// token's lifetime to the job timeout. Eleven hours accommodates long-running
/// jobs while staying below a reusable day-long credential; operators can
/// lower it per realm, or raise it up to one day.
fn default_max_token_age() -> u64 {
    11 * 60 * 60
}

/// Cache only the expensive, positive cryptographic verdict. Claim rules and
/// role resolution still run on every request, so authorization changes are not
/// hidden behind this TTL.
fn default_positive_cache() -> u64 {
    60
}

/// The most leeway a realm may give a token's `exp`, `nbf` and `iat`. The
/// token exchange's redemption records are kept well past it.
const MAX_CLOCK_SKEW_SECONDS: u64 = workload_api_key_dao::MAX_TOKEN_LEEWAY_SECONDS;
const MAX_TOKEN_AGE_SECONDS: u64 = 24 * 60 * 60;
const MAX_POSITIVE_CACHE_SECONDS: u64 = 5 * 60;
/// Lifetime of an exchanged workload API key when the realm sets none: an
/// hour, like nuget.org's trusted-publishing keys.
pub const DEFAULT_API_KEY_TTL_SECONDS: u64 = 60 * 60;
const MIN_API_KEY_TTL_SECONDS: u64 = 60;
const MAX_API_KEY_TTL_SECONDS: u64 = 24 * 60 * 60;
/// Cache namespace for positive workload-token verdicts. In-process only
/// ([`forge_cache::Cache::get_or_try_insert_local`]): a verdict stored in Redis
/// could be planted by anyone with access to it.
const NS_WIF_VERIFIED: &str = "wif_verified";
const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITLAB_COM_ISSUER: &str = "https://gitlab.com";

/// `config` shape for a `workload_identity` realm. Holds **no secret** (the
/// issuer JWKS is public), so it has no write-only fields — the whole document
/// round-trips through the admin API unredacted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentityRealmConfig {
    /// OIDC issuer (discovery base; JWKS via `.well-known/openid-configuration`).
    pub issuer: String,
    /// Accepted token audiences. The token's `aud` must intersect this set; a
    /// wildcard is never allowed (the list must be non-empty).
    pub allowed_audiences: Vec<String>,
    /// Permit a plain-`http` issuer (dev/test IdPs only; CI issuers are https).
    #[serde(default)]
    pub allow_http_issuer: bool,
    /// Leeway (seconds) on `exp`/`nbf`/`iat` validation.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
    /// Maximum accepted age and declared lifetime (`exp - iat`) of a token.
    /// Prevents an issuer or configuration mistake from turning WIF into a
    /// long-lived bearer credential.
    #[serde(default = "default_max_token_age")]
    pub max_token_age_seconds: u64,
    /// Optional exact `azp` allowlist. Providers such as GitHub/GitLab normally
    /// omit `azp`; generic issuers that emit it can bind the authorized party.
    #[serde(default)]
    pub allowed_authorized_parties: Vec<String>,
    /// Maximum positive signature-verification cache TTL. A cache entry is also
    /// bounded by the token's `exp` and keyed by `jti` plus the token digest.
    /// Tokens without `jti` are verified on every request.
    #[serde(default = "default_positive_cache")]
    pub positive_cache_seconds: u64,
    /// Ordered claim-match rules; the **first** fully-matching rule's `role` is
    /// granted. No rule matches ⇒ **default deny** (the token is rejected).
    #[serde(default)]
    pub rules: Vec<ClaimRule>,
    /// Extra claims this issuer uses as a **stable workload identity**, on top
    /// of the built-in [`STABLE_IDENTITY_CLAIMS`]. For issuers other than
    /// GitHub Actions and GitLab.com every rule must pin at least one identity
    /// claim; a custom CI system declares its own (e.g. `pipeline_id`) here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_claims: Vec<String>,
    /// Lifetime of the API key the token exchange (`POST /api/v2/token`)
    /// issues for a token of this realm, independent of the token's own
    /// lifetime. Unset means [`DEFAULT_API_KEY_TTL_SECONDS`]. Left out of the
    /// normalized config while unset, so realms that predate it keep their
    /// policy digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_ttl_seconds: Option<u64>,
}

impl WorkloadIdentityRealmConfig {
    /// The exchanged-key lifetime this realm grants.
    pub fn api_key_ttl_seconds(&self) -> u64 {
        self.api_key_ttl_seconds
            .unwrap_or(DEFAULT_API_KEY_TTL_SECONDS)
    }
}

/// Claims that identify a workload (a repository/project, its owner, or a
/// specific workflow) across the CI systems Forge knows. For issuers other
/// than GitHub Actions and GitLab.com, every rule must pin at least one of
/// these or of the realm's own `identity_claims`; anything else (`actor`,
/// `event_name`, `workflow`, …) can be shared by unrelated workloads.
pub const STABLE_IDENTITY_CLAIMS: &[&str] = &[
    "sub",
    "repository_id",
    "repository_owner_id",
    "repository",
    "repository_owner",
    "job_workflow_ref",
    "workflow_ref",
    "project_id",
    "job_project_id",
    "namespace_id",
    "job_namespace_id",
    "project_path",
    "namespace_path",
];

/// One authorization rule: when **all** `conditions` match the token's claims,
/// grant the forge `role`. At least one condition is mandatory: accepting every
/// token minted by a public CI issuer is never a safe trust policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRule {
    /// The forge `role.name` to grant on a match. Resolved to a `role.id` at
    /// validation time; a non-existent role denies (fail-closed).
    pub role: String,
    /// Claim conditions, AND-combined. Empty is rejected by config validation
    /// and fails closed at runtime for defense in depth.
    #[serde(default)]
    pub conditions: Vec<ClaimCondition>,
}

/// A single claim condition: the named claim's value (stringified; arrays are
/// expanded element-wise) must equal one of `any_of` (OR within a claim).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimCondition {
    /// Claim name — a registered claim (`sub`, `aud`, …) or an IdP-specific one
    /// (`project_path`, `namespace_path`, `ref`, `ref_protected`, …).
    pub claim: String,
    /// Accepted values; the claim matches when any equals one of these.
    #[serde(default)]
    pub any_of: Vec<String>,
}

/// Validate + normalize a `workload_identity` realm `config` document.
pub fn validate_workload_identity_config(config: &JsonValue) -> Result<JsonValue, String> {
    let mut cfg: WorkloadIdentityRealmConfig =
        serde_json::from_value(config.clone()).map_err(|e| format!("invalid config: {e}"))?;

    cfg.issuer = cfg.issuer.trim().trim_end_matches('/').to_string();
    let issuer = url::Url::parse(&cfg.issuer)
        .map_err(|e| format!("invalid issuer {:?}: {e}", cfg.issuer))?;
    if issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(
            "issuer must be an absolute host URL without credentials, query, or fragment".into(),
        );
    }
    match issuer.scheme() {
        "https" => {}
        "http" if cfg.allow_http_issuer => {}
        other => {
            return Err(format!(
                "issuer must be https (got {other:?}); set allow_http_issuer for a dev IdP"
            ))
        }
    }

    cfg.allowed_audiences = normalize_nonempty_values(cfg.allowed_audiences, "allowed_audiences")?;
    if cfg.allowed_audiences.is_empty() {
        return Err("allowed_audiences must list at least one audience (no wildcard)".into());
    }
    if cfg.allowed_audiences.iter().any(|a| a == "*") {
        return Err("allowed_audiences must not contain a wildcard".into());
    }
    cfg.allowed_authorized_parties =
        normalize_nonempty_values(cfg.allowed_authorized_parties, "allowed_authorized_parties")?;
    if cfg.clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS {
        return Err(format!(
            "clock_skew_seconds must not exceed {MAX_CLOCK_SKEW_SECONDS}"
        ));
    }
    if cfg.max_token_age_seconds == 0 || cfg.max_token_age_seconds > MAX_TOKEN_AGE_SECONDS {
        return Err(format!(
            "max_token_age_seconds must be between 1 and {MAX_TOKEN_AGE_SECONDS}"
        ));
    }
    if cfg.positive_cache_seconds > MAX_POSITIVE_CACHE_SECONDS {
        return Err(format!(
            "positive_cache_seconds must not exceed {MAX_POSITIVE_CACHE_SECONDS}"
        ));
    }
    if let Some(ttl) = cfg.api_key_ttl_seconds {
        if !(MIN_API_KEY_TTL_SECONDS..=MAX_API_KEY_TTL_SECONDS).contains(&ttl) {
            return Err(format!(
                "api_key_ttl_seconds must be between {MIN_API_KEY_TTL_SECONDS} and {MAX_API_KEY_TTL_SECONDS}"
            ));
        }
    }
    if cfg.rules.is_empty() {
        return Err(
            "at least one claim-match rule is required (an empty rule set denies every \
                    token)"
                .into(),
        );
    }
    cfg.identity_claims =
        normalize_nonempty_values(std::mem::take(&mut cfg.identity_claims), "identity_claims")?;
    if let Some(claim) = cfg
        .identity_claims
        .iter()
        .find(|claim| is_context_only_claim(claim))
    {
        return Err(format!(
            "identity_claims: {claim:?} is execution context, not a workload identity"
        ));
    }
    let issuer = cfg.issuer.clone();
    let identity_claims = cfg.identity_claims.clone();
    for (i, rule) in cfg.rules.iter_mut().enumerate() {
        rule.role = rule.role.trim().to_string();
        if rule.role.is_empty() {
            return Err(format!("rule {i}: role must not be empty"));
        }
        if rule.role == authz_dao::ADMIN_ROLE {
            return Err(format!(
                "rule {i}: workload identity cannot grant the built-in global admin role"
            ));
        }
        if rule.conditions.is_empty() {
            return Err(format!(
                "rule {i}: at least one claim condition is required (catch-all trust is unsafe)"
            ));
        }
        for (j, cond) in rule.conditions.iter_mut().enumerate() {
            cond.claim = cond.claim.trim().to_string();
            if cond.claim.is_empty() {
                return Err(format!("rule {i} condition {j}: claim must not be empty"));
            }
            cond.any_of = normalize_nonempty_values(
                std::mem::take(&mut cond.any_of),
                &format!("rule {i} condition {j} any_of"),
            )?;
            if cond.any_of.is_empty() {
                return Err(format!(
                    "rule {i} condition {j}: any_of must list at least one accepted value"
                ));
            }
        }
        if !rule_has_identity_scope(&issuer, &identity_claims, rule) {
            if normalize_issuer(&issuer) == GITHUB_ACTIONS_ISSUER {
                return Err(format!(
                    "rule {i}: GitHub Actions trust must include both repository_id and repository_owner_id; mutable names/sub/ref/environment are optional extra boundaries, not identity anchors"
                ));
            }
            if normalize_issuer(&issuer) == GITLAB_COM_ISSUER {
                return Err(format!(
                    "rule {i}: GitLab.com trust must include a numeric project ID (job_project_id or project_id) and namespace ID (job_namespace_id or namespace_id); paths/sub/ref/environment are optional extra boundaries"
                ));
            }
            return Err(format!(
                "rule {i}: at least one stable workload identity claim is required ({}; or a claim listed in identity_claims for a custom issuer); rules on context such as ref, environment, actor or event_name alone are unsafe",
                STABLE_IDENTITY_CLAIMS.join(", ")
            ));
        }
    }

    Ok(serde_json::to_value(&cfg).expect("serializable"))
}

/// Validate, normalize, and hash the complete trust policy. The digest is
/// carried by a workload principal and re-computed from the locked realm row at
/// publish time, fencing stale snapshots after any policy edit.
pub(crate) fn workload_identity_config_sha256(config: &JsonValue) -> Result<[u8; 32], String> {
    let normalized = validate_workload_identity_config(config)?;
    Ok(
        Sha256::digest(serde_json::to_vec(&normalized).expect("normalized WIF config serializes"))
            .into(),
    )
}

fn normalize_nonempty_values(mut values: Vec<String>, field: &str) -> Result<Vec<String>, String> {
    for value in &mut values {
        *value = value.trim().to_string();
        if value.is_empty() {
            return Err(format!("{field} must not contain an empty value"));
        }
    }
    values.sort();
    values.dedup();
    Ok(values)
}

/// Whether `snap` has realm `realm_id` enabled with the configuration
/// `config_sha256` names: what a workload key, and a registry token minted
/// for a workload, rest on. Any edit, disable or delete of the realm ends it.
fn realm_current(snap: &RealmSnapshot, realm_id: i64, config_sha256: &[u8; 32]) -> bool {
    snap.workload
        .iter()
        .any(|realm| realm.realm_id == realm_id && realm.config_sha256 == *config_sha256)
}

/// [`realm_current`] in `snap`, or else in a snapshot rebuilt since
/// ([`RealmAuth::refreshed`]): the realm may have been edited on another
/// instance, which issues credentials under the new configuration before this
/// instance's snapshot expires. Revocation does not rest on this check alone:
/// a realm change ends the realm's keys in the database.
pub(crate) async fn realm_current_now(
    realms: &RealmAuth,
    snap: &Arc<RealmSnapshot>,
    realm_id: i64,
    config_sha256: &[u8; 32],
) -> anyhow::Result<bool> {
    if realm_current(snap, realm_id, config_sha256) {
        return Ok(true);
    }
    let fresh = realms.refreshed(snap).await?;
    Ok(realm_current(&fresh, realm_id, config_sha256))
}

/// A built WIF realm in a [`super::RealmSnapshot`]: the realm identity, the
/// parsed config, and the (issuer-scoped, cache-backed) JWKS verifier.
pub struct WorkloadIdentityRealm {
    /// `auth_realm.id` (audit context on the resulting principal).
    pub realm_id: i64,
    /// `auth_realm.name` (diagnostics).
    pub realm_name: String,
    /// Parsed, validated config.
    pub config: WorkloadIdentityRealmConfig,
    /// Discovery/JWKS fetcher + JWT verifier for this realm's issuer (shares the
    /// process cache; the JWKS is keyed by issuer).
    pub meta: OidcMetadataClient,
    cache: Cache,
    /// Complete normalized realm-policy digest used to fence stale snapshots
    /// inside the package transaction.
    config_sha256: [u8; 32],
    /// Changes whenever any cryptographic-validation policy changes, so a
    /// cached verdict from an old audience/age/azp policy can never be reused.
    verification_policy_hash: String,
}

impl WorkloadIdentityRealm {
    /// Build the runtime from a realm row, reusing the shared cache for
    /// discovery/JWKS and the no-redirect, https-only metadata client.
    pub fn build(realm: &AuthRealm, cache: &Cache) -> anyhow::Result<Self> {
        let normalized = validate_workload_identity_config(&realm.config)
            .map_err(|e| anyhow::anyhow!("config: {e}"))?;
        let config_sha256: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&normalized).expect("normalized WIF config serializes"),
        )
        .into();
        let config: WorkloadIdentityRealmConfig =
            serde_json::from_value(normalized).map_err(|e| anyhow::anyhow!("config: {e}"))?;
        let http = ssrf::outbound_metadata_client(config.allow_http_issuer)
            .map_err(|e| anyhow::anyhow!("build outbound metadata client: {e}"))?;
        let meta = OidcMetadataClient::new(config.issuer.clone(), http, cache.clone());
        let verification_policy_hash = verification_policy_hash(&config);
        Ok(WorkloadIdentityRealm {
            realm_id: realm.id,
            realm_name: realm.name.clone(),
            config,
            meta,
            cache: cache.clone(),
            config_sha256,
            verification_policy_hash,
        })
    }

    /// Whether this realm's configured issuer equals `issuer` (trailing-slash
    /// insensitive — the [`OidcMetadataClient`] stores a normalized issuer).
    fn issuer_matches(&self, issuer: &str) -> bool {
        self.meta.issuer() == normalize_issuer(issuer)
    }

    async fn verify_token(&self, token: &str) -> Result<Verified, OidcError> {
        let audiences = self.config.allowed_audiences.clone();
        let authorized_parties = self.config.allowed_authorized_parties.clone();
        let meta = self.meta.clone();
        let leeway = self.config.clock_skew_seconds;
        let max_age = self.config.max_token_age_seconds;

        let verify = move || async move {
            let audiences: Vec<&str> = audiences.iter().map(String::as_str).collect();
            let authorized_parties: Vec<&str> =
                authorized_parties.iter().map(String::as_str).collect();
            meta.verify_workload_jwt(token, &audiences, &authorized_parties, leeway, max_age)
                .await
        };

        let Some((key, ttl)) = positive_cache_key(
            token,
            self.realm_id,
            &self.verification_policy_hash,
            self.config.positive_cache_seconds,
        ) else {
            return verify().await;
        };

        self.cache
            .get_or_try_insert_local(NS_WIF_VERIFIED, &key, ttl, verify)
            .await
    }
}

fn verification_policy_hash(config: &WorkloadIdentityRealmConfig) -> String {
    let policy = serde_json::json!({
        "issuer": config.issuer.trim_end_matches('/'),
        "allowed_audiences": config.allowed_audiences,
        "allowed_authorized_parties": config.allowed_authorized_parties,
        "clock_skew_seconds": config.clock_skew_seconds,
        "max_token_age_seconds": config.max_token_age_seconds,
        "positive_cache_seconds": config.positive_cache_seconds,
    });
    hex::encode(Sha256::digest(
        serde_json::to_vec(&policy).expect("verification policy serializes"),
    ))
}

/// Return an opaque cache key plus a TTL bounded by both configured policy and
/// token expiry. `jti`/`exp` are only hints until the cache factory verifies the
/// signature; hashing the complete token into the key prevents an untrusted
/// token from aliasing a previously verified one with the same claims.
fn positive_cache_key(
    token: &str,
    realm_id: i64,
    policy_hash: &str,
    configured_ttl_seconds: u64,
) -> Option<(String, Duration)> {
    if configured_ttl_seconds == 0 {
        return None;
    }
    let payload = token.split('.').nth(1).and_then(decode_b64url_json)?;
    let jti = payload.get("jti")?.as_str()?.trim();
    if jti.is_empty() {
        return None;
    }
    let exp = payload.get("exp")?.as_i64()?;
    let remaining = exp.checked_sub(chrono::Utc::now().timestamp())?;
    if remaining <= 0 {
        return None;
    }
    let ttl = configured_ttl_seconds.min(u64::try_from(remaining).ok()?);
    if ttl == 0 {
        return None;
    }

    let mut digest = Sha256::new();
    digest.update(realm_id.to_be_bytes());
    digest.update([0]);
    digest.update(policy_hash.as_bytes());
    digest.update([0]);
    digest.update(jti.as_bytes());
    digest.update([0]);
    digest.update(exp.to_be_bytes());
    digest.update([0]);
    digest.update(token.as_bytes());
    Some((hex::encode(digest.finalize()), Duration::from_secs(ttl)))
}

/// The [`PrincipalSource`] that authenticates WIF workloads. Reads the enabled
/// `workload_identity` realms from the (snapshot-cached) realm table, routes a
/// presented JWT to the realm whose issuer it names, and validates it. It also
/// owns the two other workload credentials: an exchanged workload API key
/// ([`forge_core::auth::workload_key`]) in any transport, and the reserved
/// Basic username `oidc` ([`WORKLOAD_USERNAME`]), whose secret must be one of
/// the two.
pub struct WorkloadIdentitySource {
    realms: Arc<RealmAuth>,
    pool: PgPool,
}

/// A workload proven by a verified OIDC token: the principal it authorizes as,
/// plus what the token exchange records about the token.
pub(crate) struct VerifiedWorkload {
    /// Always a [`Principal::Workload`], whose `expires_at` is the token's
    /// `exp`.
    pub principal: Principal,
    /// The token's `jti`, when it has one.
    pub jti: Option<String>,
    /// The exchanged-key lifetime the token's realm grants.
    pub api_key_ttl_seconds: u64,
    /// The clock skew the token's realm accepts its `exp` with.
    pub clock_skew_seconds: u64,
}

/// Why the token exchange refused a presented token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeRefusal {
    /// Not a JWT for an enabled workload-identity realm.
    NotWorkloadToken,
    /// A workload token that failed verification or matched no rule.
    Rejected,
    /// The realm table or the role lookup failed: retry later.
    Unavailable,
}

/// Where a presented secret routes among the enabled WIF realms.
enum JwtRoute<'a> {
    /// Not a JWT.
    NotJwt,
    /// A JWT, but no enabled realm names its issuer.
    Unclaimed,
    /// A JWT for this realm.
    Realm(&'a WorkloadIdentityRealm),
    /// A JWT whose issuer an invalid or several enabled realms name: refused
    /// terminally, never handed to another source.
    Refused,
}

/// Route `secret` by its (unverified) `iss` claim.
fn route_jwt<'a>(snap: &'a RealmSnapshot, secret: &str) -> JwtRoute<'a> {
    let Some(issuer) = jwt_issuer(secret) else {
        return JwtRoute::NotJwt;
    };
    let issuer = normalize_issuer(&issuer);
    if snap
        .workload_ambiguous_issuers
        .iter()
        .any(|configured| configured == issuer)
    {
        tracing::error!(issuer = %issuer, "JWT issuer is configured by multiple enabled WIF realms; rejecting ambiguous route");
        return JwtRoute::Refused;
    }
    if let Some(realm) = snap.workload.iter().find(|r| r.issuer_matches(issuer)) {
        return JwtRoute::Realm(realm);
    }
    if snap
        .workload_configured_issuers
        .iter()
        .any(|configured| configured == issuer)
    {
        // The enabled row names this issuer but failed runtime config
        // construction. It still owns the JWT routing decision: never let a
        // matching token fall through and become a forwarded Basic password
        // merely because the realm is malformed.
        tracing::error!(issuer = %issuer, "JWT matched an invalid WIF realm; rejecting terminally");
        return JwtRoute::Refused;
    }
    JwtRoute::Unclaimed
}

impl WorkloadIdentitySource {
    /// Build the source over the shared realm snapshot + DB pool (for role
    /// resolution).
    pub fn new(realms: Arc<RealmAuth>, pool: PgPool) -> Self {
        Self { realms, pool }
    }

    /// Verify `token` against `realm` and map it to a [`Principal::Workload`].
    ///
    /// **Terminal**: this is only called once a presented secret has been
    /// positively identified as a JWT for `realm` (its `iss` matched), so every
    /// failure is [`SourceOutcome::Reject`] (or [`SourceOutcome::Unavailable`])
    /// — the chain stops and the token is *never* handed to a downstream
    /// source (so it cannot be reinterpreted as an opaque API token or
    /// forwarded upstream as a password — design §8).
    async fn verify(
        &self,
        realm: &WorkloadIdentityRealm,
        token: &str,
    ) -> Result<VerifiedWorkload, SourceOutcome> {
        let verified = match realm.verify_token(token).await {
            Ok(v) => v,
            // The issuer's discovery document or keys could not be fetched:
            // no verdict on the token, so 503 and the CI job retries.
            Err(e) if e.is_unavailable() => {
                tracing::warn!(realm = %realm.realm_name, error = %e, "WIF issuer unreachable; token not checked");
                return Err(SourceOutcome::Unavailable);
            }
            Err(e) => {
                tracing::warn!(realm = %realm.realm_name, error = %e, "WIF token validation failed");
                return Err(SourceOutcome::Reject);
            }
        };

        let Some(role_name) = matched_role(
            &verified.claims,
            &realm.config.rules,
            &realm.config.identity_claims,
        ) else {
            tracing::warn!(
                realm = %realm.realm_name,
                subject = %verified.subject,
                "WIF token matched no claim rule (default deny)"
            );
            return Err(SourceOutcome::Reject);
        };

        // Defense in depth for malformed/legacy rows that bypassed config
        // validation: a public CI identity can never mint global Forge admin.
        if role_name == authz_dao::ADMIN_ROLE {
            tracing::error!(
                realm = %realm.realm_name,
                "WIF rule attempted to grant the global admin role; denying"
            );
            return Err(SourceOutcome::Reject);
        }

        match authz_dao::role_id_by_name(&self.pool, role_name).await {
            Ok(Some(role_id)) => {
                tracing::info!(
                    realm = %realm.realm_name,
                    subject = %verified.subject,
                    role = %role_name,
                    "WIF workload authenticated"
                );
                Ok(VerifiedWorkload {
                    principal: Principal::Workload {
                        realm_id: realm.realm_id,
                        role_id,
                        issuer_sha256: sha256_bytes(verified.issuer.trim_end_matches('/')),
                        config_sha256: realm.config_sha256,
                        subject_sha256: workload_subject_hash(&verified.issuer, &verified.subject),
                        jti_sha256: verified.claims.jti.as_deref().map(sha256_bytes),
                        issued_at: verified.claims.iat.expect("workload verifier requires iat"),
                        key_id: None,
                        expires_at: verified.claims.exp.expect("workload verifier requires exp"),
                    },
                    jti: verified.claims.jti.clone(),
                    api_key_ttl_seconds: realm.config.api_key_ttl_seconds(),
                    clock_skew_seconds: realm.config.clock_skew_seconds,
                })
            }
            Ok(None) => {
                tracing::error!(
                    realm = %realm.realm_name,
                    role = %role_name,
                    "WIF rule maps to a non-existent role (deny)"
                );
                Err(SourceOutcome::Reject)
            }
            // Not a verdict on the token: 503, so the CI job retries.
            Err(e) => {
                tracing::error!(error = %e, "WIF role lookup failed");
                Err(SourceOutcome::Unavailable)
            }
        }
    }

    async fn authenticate(&self, realm: &WorkloadIdentityRealm, token: &str) -> SourceOutcome {
        match self.verify(realm, token).await {
            Ok(workload) => SourceOutcome::Authenticated(workload.principal),
            Err(outcome) => outcome,
        }
    }

    /// Resolve a workload API key to the principal captured when it was
    /// issued. **Terminal** like a WIF token: a key that is unknown, expired,
    /// or whose realm is no longer enabled with the very configuration it was
    /// issued under (any realm edit revokes its keys) is rejected and never
    /// handed to another source.
    async fn authenticate_key(&self, snap: &Arc<RealmSnapshot>, key: &str) -> SourceOutcome {
        let digest = forge_core::auth::workload_key_sha256(key);
        let row = match workload_api_key_dao::find_live(&self.pool, &digest).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                tracing::warn!("unknown or expired workload API key");
                return SourceOutcome::Reject;
            }
            Err(e) => {
                tracing::error!(error = %e, "workload API key lookup failed");
                return SourceOutcome::Unavailable;
            }
        };
        // Defense in depth against a non-constant-time index comparison.
        if row.key_sha256.ct_eq(&digest).unwrap_u8() != 1 {
            return SourceOutcome::Reject;
        }
        let current =
            match realm_current_now(&self.realms, snap, row.realm_id, &row.config_sha256).await {
                Ok(current) => current,
                Err(e) => {
                    tracing::error!(error = %e, "WIF realm snapshot refresh failed");
                    return SourceOutcome::Unavailable;
                }
            };
        if !current {
            tracing::warn!(
                realm_id = row.realm_id,
                key_id = row.id,
                "workload API key revoked: its realm was disabled, deleted or reconfigured"
            );
            return SourceOutcome::Reject;
        }
        tracing::debug!(
            realm_id = row.realm_id,
            key_id = row.id,
            "workload API key authenticated"
        );
        SourceOutcome::Authenticated(Principal::Workload {
            realm_id: row.realm_id,
            role_id: row.role_id,
            issuer_sha256: row.issuer_sha256,
            config_sha256: row.config_sha256,
            subject_sha256: row.subject_sha256,
            jti_sha256: Some(row.jti_sha256),
            issued_at: row.token_issued_at.timestamp(),
            key_id: Some(row.id),
            expires_at: row.expires_at.timestamp(),
        })
    }

    /// Verify `token`, a CI job's OIDC token, for the token exchange. Routes
    /// and verifies exactly like [`PrincipalSource::resolve`] does; with
    /// `refresh`, against a snapshot rebuilt since the current one (after the
    /// database refused a key issued under the current one's configuration).
    pub(crate) async fn verify_for_exchange(
        &self,
        token: &str,
        refresh: bool,
    ) -> Result<VerifiedWorkload, ExchangeRefusal> {
        let mut snap = self.realms.snapshot().await.map_err(|e| {
            tracing::error!(error = %e, "WIF realm snapshot failed");
            ExchangeRefusal::Unavailable
        })?;
        if refresh {
            snap = self.realms.refreshed(&snap).await.map_err(|e| {
                tracing::error!(error = %e, "WIF realm snapshot refresh failed");
                ExchangeRefusal::Unavailable
            })?;
        }
        let realm = match route_jwt(&snap, token) {
            JwtRoute::Realm(realm) => realm,
            JwtRoute::NotJwt | JwtRoute::Unclaimed => {
                return Err(ExchangeRefusal::NotWorkloadToken)
            }
            JwtRoute::Refused => return Err(ExchangeRefusal::Rejected),
        };
        self.verify(realm, token)
            .await
            .map_err(|outcome| match outcome {
                SourceOutcome::Unavailable => ExchangeRefusal::Unavailable,
                _ => ExchangeRefusal::Rejected,
            })
    }
}

fn workload_subject_hash(issuer: &str, subject: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(issuer.as_bytes());
    digest.update([0]);
    digest.update(subject.as_bytes());
    digest.finalize().into()
}

fn sha256_bytes(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

#[async_trait]
impl PrincipalSource for WorkloadIdentitySource {
    async fn resolve(&self, headers: &HeaderMap, _peer_ip: std::net::IpAddr) -> SourceOutcome {
        // Basic `oidc:<secret>` names a workload whatever the secret is: it is
        // decided here and never reaches the token or password sources.
        let workload_basic = basic_username(headers).is_some_and(|username| {
            forge_db::username::canonical_username(&username)
                .is_ok_and(|name| name == WORKLOAD_USERNAME)
        });
        let candidates = candidate_secrets(headers);
        let claims_any = workload_basic
            || candidates
                .iter()
                .any(|s| is_workload_key(s) || jwt_issuer(s).is_some());
        if !claims_any {
            // Nothing workload-shaped: the token/Basic sources handle it.
            return SourceOutcome::NoCredentials;
        }

        // Resolve the realm snapshot. On a snapshot error we cannot route, and
        // a workload-shaped credential (a JWT, a workload key, the `oidc`
        // username) must never be reinterpreted as a password, even while the
        // realm table is unreadable: temporarily unavailable (terminal, 503).
        let snap = match self.realms.snapshot().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "WIF realm snapshot failed");
                return SourceOutcome::Unavailable;
            }
        };

        for secret in &candidates {
            if is_workload_key(secret) {
                // A workload key, live or not: terminal from here.
                return self.authenticate_key(&snap, secret).await;
            }
            match route_jwt(&snap, secret) {
                // This secret IS a WIF token for `realm`: terminal from here.
                JwtRoute::Realm(realm) => return self.authenticate(realm, secret).await,
                JwtRoute::Refused => return SourceOutcome::Reject,
                // Not a WIF token: let other sources handle this secret.
                JwtRoute::NotJwt | JwtRoute::Unclaimed => {}
            }
        }
        if workload_basic {
            tracing::warn!(
                "Basic username {WORKLOAD_USERNAME:?} without a workload token or key; rejected"
            );
            return SourceOutcome::Reject;
        }
        SourceOutcome::NoCredentials
    }
}

/// Collect candidate secrets a workload could present its `id_token` (or an
/// exchanged workload key) in, in priority order: `Authorization: Bearer`,
/// then the Basic password, then `X-NuGet-ApiKey`.
fn candidate_secrets(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(bearer) = strip_prefix_ci(auth, "Bearer ") {
            let t = bearer.trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
        } else if let Some(basic) = strip_prefix_ci(auth, "Basic ") {
            if let Some((_, pw)) = basic_credentials(basic.trim()) {
                if !pw.is_empty() {
                    out.push(pw);
                }
            }
        }
    }
    if let Some(apikey) = headers.get("x-nuget-apikey").and_then(|v| v.to_str().ok()) {
        let t = apikey.trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
    }
    out
}

/// The username of an HTTP Basic `Authorization` header, if one is present.
fn basic_username(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let basic = strip_prefix_ci(auth, "Basic ")?;
    basic_credentials(basic.trim()).map(|(username, _)| username)
}

/// Case-insensitive prefix strip (HTTP auth schemes are case-insensitive).
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Decode a Base64 `user:password` HTTP Basic credential into its halves.
fn basic_credentials(b64: &str) -> Option<(String, String)> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    s.split_once(':')
        .map(|(user, pw)| (user.to_string(), pw.to_string()))
}

/// If `secret` structurally parses as a JWT (three segments; header decodes with
/// a real, non-`none` `alg`), return its **unverified** `iss` claim — used only
/// to route to a realm; the cryptographic verification happens in
/// [`OidcMetadataClient::verify_jwt`]. Returns `None` for anything that is not a
/// well-formed JWT carrying a string `iss`.
fn jwt_issuer(secret: &str) -> Option<String> {
    let mut parts = secret.split('.');
    let header_b64 = parts.next()?;
    let payload_b64 = parts.next()?;
    let _sig = parts.next()?;
    if parts.next().is_some() {
        return None; // more than three segments — not a JWS compact token
    }

    let header = decode_b64url_json(header_b64)?;
    // Require a syntactically present algorithm for JWT routing, but do not
    // trust its value here. A matching issuer with `alg:none`, HMAC, or a
    // missing `kid` must route to the WIF verifier and fail terminally rather
    // than fall through to password forwarding.
    header.get("alg")?.as_str()?;

    let payload = decode_b64url_json(payload_b64)?;
    payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Base64url-decode (no padding) a JWT segment into JSON.
fn decode_b64url_json(segment: &str) -> Option<JsonValue> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Trim a single trailing slash for issuer comparison (mirrors the core's
/// issuer normalization).
fn normalize_issuer(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

/// The forge role granted by the **first** rule whose every condition matches
/// `claims`, or `None` (default deny).
pub fn matched_role<'a>(
    claims: &IdTokenClaims,
    rules: &'a [ClaimRule],
    identity_claims: &[String],
) -> Option<&'a str> {
    let matched = rules
        .iter()
        .find(|rule| rule_matches(claims, rule, identity_claims))
        .map(|r| r.role.as_str())?;
    (matched != authz_dao::ADMIN_ROLE).then_some(matched)
}

/// Whether every condition of `rule` matches `claims`. Empty and semantically
/// context-only rule sets fail closed even if a malformed row bypassed config
/// validation.
fn rule_matches(claims: &IdTokenClaims, rule: &ClaimRule, identity_claims: &[String]) -> bool {
    !rule.conditions.is_empty()
        && rule_has_identity_scope(&claims.iss, identity_claims, rule)
        && rule.conditions.iter().all(|cond| {
            let values = claim_values(claims, &cond.claim);
            values.iter().any(|v| cond.any_of.iter().any(|a| a == v))
        })
}

/// Whether a rule binds trust to a workload identity rather than only to
/// verifier-global or execution-context claims.
///
/// For GitHub/GitLab's public multi-tenant issuers, require immutable numeric
/// repository/project plus owner/namespace identity explicitly. For other/custom
/// issuers, stay extensible by accepting provider-specific claims while rejecting
/// protocol, temporal, ref, and environment fields shared by many workloads.
fn rule_has_identity_scope(issuer: &str, identity_claims: &[String], rule: &ClaimRule) -> bool {
    if normalize_issuer(issuer) == GITHUB_ACTIONS_ISSUER {
        let has_repository_id = rule
            .conditions
            .iter()
            .any(|condition| condition.claim == "repository_id");
        let has_owner_id = rule
            .conditions
            .iter()
            .any(|condition| condition.claim == "repository_owner_id");
        return has_repository_id && has_owner_id;
    }
    if normalize_issuer(issuer) == GITLAB_COM_ISSUER {
        let has_project_id = rule
            .conditions
            .iter()
            .any(|condition| matches!(condition.claim.as_str(), "project_id" | "job_project_id"));
        let has_namespace_id = rule.conditions.iter().any(|condition| {
            matches!(
                condition.claim.as_str(),
                "namespace_id" | "job_namespace_id"
            )
        });
        return has_project_id && has_namespace_id;
    }

    rule.conditions.iter().any(|condition| {
        STABLE_IDENTITY_CLAIMS.contains(&condition.claim.as_str())
            || identity_claims.contains(&condition.claim)
    })
}

/// Claims that cannot identify which workload is trusted; never accepted as
/// a realm's `identity_claims`.
fn is_context_only_claim(claim: &str) -> bool {
    matches!(
        claim,
        // JWT/OIDC protocol and temporal metadata.
        "iss"
            | "aud"
            | "azp"
            | "exp"
            | "nbf"
            | "iat"
            | "jti"
            | "nonce"
            // Execution context that can be shared across unrelated projects.
            | "ref"
            | "ref_path"
            | "ref_type"
            | "ref_protected"
            | "environment"
            | "environment_protected"
    )
}

/// All string representations of a claim's value(s): registered claims first,
/// then the flattened `additional` map. Arrays expand element-wise; scalars
/// (bool/number) stringify so rules can match `ref_protected: true` etc.
fn claim_values(claims: &IdTokenClaims, name: &str) -> Vec<String> {
    let direct: Option<JsonValue> = match name {
        "sub" => Some(JsonValue::String(claims.sub.clone())),
        "iss" => Some(JsonValue::String(claims.iss.clone())),
        "aud" => claims.aud.clone(),
        "exp" => claims.exp.map(JsonValue::from),
        "nbf" => claims.nbf.map(JsonValue::from),
        "iat" => claims.iat.map(JsonValue::from),
        "jti" => claims.jti.clone().map(JsonValue::String),
        "azp" => claims.azp.clone().map(JsonValue::String),
        "nonce" => claims.nonce.clone().map(JsonValue::String),
        _ => None,
    };
    match direct.or_else(|| claims.additional.get(name).cloned()) {
        Some(v) => json_to_strings(&v),
        None => Vec::new(),
    }
}

/// Flatten a JSON value into its string forms (recursing into arrays).
fn json_to_strings(v: &JsonValue) -> Vec<String> {
    match v {
        JsonValue::String(s) => vec![s.clone()],
        JsonValue::Bool(b) => vec![b.to_string()],
        JsonValue::Number(n) => vec![n.to_string()],
        JsonValue::Array(arr) => arr.iter().flat_map(json_to_strings).collect(),
        JsonValue::Null | JsonValue::Object(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map};

    fn claims_with(additional: Map<String, JsonValue>) -> IdTokenClaims {
        IdTokenClaims {
            sub: "subject-1".into(),
            iss: "https://gitlab.example/".into(),
            aud: Some(json!("forge")),
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            nonce: None,
            azp: None,
            additional,
        }
    }

    #[test]
    fn config_validation_requires_https_audiences_and_rules() {
        let ok = validate_workload_identity_config(&json!({
            "issuer": "https://gitlab.example",
            "allowed_audiences": ["forge"],
            "rules": [{"role": "ci", "conditions": [{"claim": "project_path", "any_of": ["g/p"]}]}],
        }))
        .expect("valid");
        assert_eq!(ok["clock_skew_seconds"], 60);
        assert_eq!(ok["max_token_age_seconds"], 39600);
        assert_eq!(ok["positive_cache_seconds"], 60);

        // http issuer needs the dev opt-in.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "http://idp.test",
            "allowed_audiences": ["forge"],
            "rules": [{"role": "ci"}],
        }))
        .is_err());

        // empty audiences / empty rules rejected.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://x", "allowed_audiences": [], "rules": [{"role": "ci"}],
        }))
        .is_err());
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://x", "allowed_audiences": ["a"], "rules": [],
        }))
        .is_err());

        // a condition with no accepted values is rejected.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://x",
            "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "conditions": [{"claim": "sub", "any_of": []}]}],
        }))
        .is_err());

        // Public CI issuers mint tokens for many repositories. A catch-all
        // mapping, wildcard audience, excessive skew, or long-lived token
        // policy is therefore never accepted.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://x", "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "conditions": []}],
        }))
        .is_err());
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://x", "allowed_audiences": ["*"],
            "rules": [{"role": "ci", "conditions": [{"claim": "sub", "any_of": ["s"]}]}],
        }))
        .is_err());
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://x", "allowed_audiences": ["a"], "clock_skew_seconds": 301,
            "rules": [{"role": "ci", "conditions": [{"claim": "sub", "any_of": ["s"]}]}],
        }))
        .is_err());
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://x", "allowed_audiences": ["a"], "max_token_age_seconds": 86401,
            "rules": [{"role": "ci", "conditions": [{"claim": "sub", "any_of": ["s"]}]}],
        }))
        .is_err());

        // Syntactically non-empty rules that only repeat issuer-global or
        // execution-context claims are semantic catch-alls and are rejected.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://gitlab.example", "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "conditions": [
                {"claim": "iss", "any_of": ["https://gitlab.example"]},
                {"claim": "aud", "any_of": ["a"]},
                {"claim": "ref_protected", "any_of": ["true"]}
            ]}],
        }))
        .is_err());

        // A custom issuer's own identity claim counts only once the realm
        // declares it; an arbitrary claim (here: one any workload can carry)
        // is not an identity anchor.
        let custom = |identity_claims: serde_json::Value, claim: &str| {
            json!({
                "issuer": "https://custom.example", "allowed_audiences": ["a"],
                "identity_claims": identity_claims,
                "rules": [{"role": "ci", "conditions": [
                    {"claim": claim, "any_of": ["build-system-42"]},
                    {"claim": "environment", "any_of": ["production"]}
                ]}],
            })
        };
        assert!(
            validate_workload_identity_config(&custom(json!([]), "custom_workload_id")).is_err()
        );
        assert!(validate_workload_identity_config(&custom(json!([]), "event_name")).is_err());
        assert!(validate_workload_identity_config(&custom(json!([]), "actor")).is_err());
        assert!(validate_workload_identity_config(&custom(
            json!(["custom_workload_id"]),
            "custom_workload_id"
        ))
        .is_ok());
        assert!(
            validate_workload_identity_config(&custom(json!(["ref"]), "ref")).is_err(),
            "context claims cannot be declared identities"
        );
        // Built-in stable claims work for any issuer (self-managed GitLab, GHES).
        assert!(validate_workload_identity_config(&custom(json!([]), "job_project_id")).is_ok());

        // GitHub's public issuer requires repository/workload identity. Owner,
        // branch, and environment context alone can cover unrelated repos.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://token.actions.githubusercontent.com",
            "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "conditions": [
                {"claim": "repository_owner_id", "any_of": ["123"]},
                {"claim": "ref", "any_of": ["refs/heads/main"]}
            ]}],
        }))
        .is_err());
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://token.actions.githubusercontent.com",
            "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "conditions": [
                {"claim": "repository_id", "any_of": ["987654321"]},
                {"claim": "repository_owner_id", "any_of": ["1234567"]},
                {"claim": "ref", "any_of": ["refs/heads/main"]}
            ]}],
        }))
        .is_ok());

        // GitLab.com's public issuer likewise needs project/workload identity;
        // namespace, ref, or environment context alone is too broad.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://gitlab.com", "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "conditions": [
                {"claim": "job_namespace_id", "any_of": ["2001"]},
                {"claim": "ref_protected", "any_of": ["true"]}
            ]}],
        }))
        .is_err());
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://gitlab.com", "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "conditions": [
                {"claim": "job_project_id", "any_of": ["1001"]},
                {"claim": "job_namespace_id", "any_of": ["2001"]},
                {"claim": "ref_protected", "any_of": ["true"]}
            ]}],
        }))
        .is_ok());

        // A workload realm can grant scoped repository roles, never the
        // built-in global administrator role.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://custom.example", "allowed_audiences": ["a"],
            "rules": [{"role": "admin", "conditions": [
                {"claim": "sub", "any_of": ["workload-1"]}
            ]}],
        }))
        .is_err());

        // Security-sensitive typos must not silently fall back to defaults or
        // drop an intended rule condition.
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://custom.example", "allowed_audiences": ["a"],
            "max_token_ages_seconds": 10,
            "rules": [{"role": "ci", "conditions": [
                {"claim": "sub", "any_of": ["workload-1"]}
            ]}],
        }))
        .is_err());
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://custom.example", "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "condition": [
                {"claim": "sub", "any_of": ["workload-1"]}
            ]}],
        }))
        .is_err());
        assert!(validate_workload_identity_config(&json!({
            "issuer": "https://custom.example", "allowed_audiences": ["a"],
            "rules": [{"role": "ci", "conditions": [
                {"claim": "sub", "anyOf": ["workload-1"]}
            ]}],
        }))
        .is_err());
    }

    #[test]
    fn normalized_config_digest_changes_with_trust_policy_not_json_order() {
        let first = json!({
            "issuer": "https://gitlab.example/",
            "allowed_audiences": ["forge", "secondary"],
            "rules": [{"role": "ci", "conditions": [
                {"claim": "job_project_id", "any_of": ["1001"]}
            ]}]
        });
        let reordered = json!({
            "rules": [{"conditions": [
                {"any_of": ["1001"], "claim": "job_project_id"}
            ], "role": "ci"}],
            "allowed_audiences": ["secondary", "forge"],
            "issuer": "https://gitlab.example"
        });
        assert_eq!(
            workload_identity_config_sha256(&first).unwrap(),
            workload_identity_config_sha256(&reordered).unwrap(),
            "equivalent normalized policies must have the same fence"
        );

        let changed = json!({
            "issuer": "https://gitlab.example",
            "allowed_audiences": ["forge", "secondary"],
            "rules": [{"role": "ci", "conditions": [
                {"claim": "job_project_id", "any_of": ["9999"]}
            ]}]
        });
        assert_ne!(
            workload_identity_config_sha256(&first).unwrap(),
            workload_identity_config_sha256(&changed).unwrap(),
            "claim-rule edits must invalidate a stale principal"
        );

        let mut cached_policy: WorkloadIdentityRealmConfig =
            serde_json::from_value(validate_workload_identity_config(&first).unwrap()).unwrap();
        let original_cache_key = verification_policy_hash(&cached_policy);
        cached_policy.positive_cache_seconds = 300;
        assert_ne!(
            original_cache_key,
            verification_policy_hash(&cached_policy),
            "lowering a positive-cache TTL must not hit an older longer-lived verdict"
        );
    }

    #[test]
    fn rule_matching_is_first_match_and_ands_conditions() {
        let mut add = Map::new();
        add.insert("project_path".into(), json!("group/app"));
        add.insert("ref_protected".into(), json!(true));
        let claims = claims_with(add);

        let rules = vec![
            // first rule needs a protected ref on a different project — no match
            ClaimRule {
                role: "deployer".into(),
                conditions: vec![ClaimCondition {
                    claim: "project_path".into(),
                    any_of: vec!["group/other".into()],
                }],
            },
            // second rule: project + protected ref both match
            ClaimRule {
                role: "publisher".into(),
                conditions: vec![
                    ClaimCondition {
                        claim: "project_path".into(),
                        any_of: vec!["group/app".into()],
                    },
                    ClaimCondition {
                        claim: "ref_protected".into(),
                        any_of: vec!["true".into()],
                    },
                ],
            },
        ];
        assert_eq!(matched_role(&claims, &rules, &[]), Some("publisher"));
    }

    #[test]
    fn unprotected_ref_does_not_match_protected_rule() {
        let mut add = Map::new();
        add.insert("project_path".into(), json!("group/app"));
        add.insert("ref_protected".into(), json!(false));
        let claims = claims_with(add);
        let rules = vec![ClaimRule {
            role: "publisher".into(),
            conditions: vec![
                ClaimCondition {
                    claim: "project_path".into(),
                    any_of: vec!["group/app".into()],
                },
                ClaimCondition {
                    claim: "ref_protected".into(),
                    any_of: vec!["true".into()],
                },
            ],
        }];
        assert_eq!(matched_role(&claims, &rules, &[]), None);
    }

    #[test]
    fn empty_conditions_fail_closed_even_if_a_bad_row_bypasses_validation() {
        let claims = claims_with(Map::new());
        let rules = vec![ClaimRule {
            role: "reader".into(),
            conditions: vec![],
        }];
        assert_eq!(matched_role(&claims, &rules, &[]), None);
    }

    #[test]
    fn context_only_conditions_fail_closed_even_if_a_bad_row_bypasses_validation() {
        let mut add = Map::new();
        add.insert("ref_protected".into(), json!(true));
        let claims = claims_with(add);
        let rules = vec![ClaimRule {
            role: "publisher".into(),
            conditions: vec![
                ClaimCondition {
                    claim: "aud".into(),
                    any_of: vec!["forge".into()],
                },
                ClaimCondition {
                    claim: "ref_protected".into(),
                    any_of: vec!["true".into()],
                },
            ],
        }];
        assert_eq!(matched_role(&claims, &rules, &[]), None);
    }

    #[test]
    fn global_admin_mapping_fails_closed_even_if_a_bad_row_bypasses_validation() {
        let claims = claims_with(Map::new());
        let rules = vec![ClaimRule {
            role: authz_dao::ADMIN_ROLE.into(),
            conditions: vec![ClaimCondition {
                claim: "sub".into(),
                any_of: vec!["subject-1".into()],
            }],
        }];
        assert_eq!(matched_role(&claims, &rules, &[]), None);
    }

    #[test]
    fn claim_values_expand_arrays_and_stringify_scalars() {
        let mut add = Map::new();
        add.insert("groups".into(), json!(["a", "b"]));
        add.insert("ref_protected".into(), json!(true));
        let claims = claims_with(add);
        assert_eq!(claim_values(&claims, "groups"), vec!["a", "b"]);
        assert_eq!(claim_values(&claims, "ref_protected"), vec!["true"]);
        assert_eq!(claim_values(&claims, "sub"), vec!["subject-1"]);
        assert!(claim_values(&claims, "absent").is_empty());

        let mut registered = claims;
        registered.exp = Some(123);
        registered.nbf = Some(100);
        registered.iat = Some(101);
        registered.jti = Some("token-1".into());
        assert_eq!(claim_values(&registered, "exp"), vec!["123"]);
        assert_eq!(claim_values(&registered, "nbf"), vec!["100"]);
        assert_eq!(claim_values(&registered, "iat"), vec!["101"]);
        assert_eq!(claim_values(&registered, "jti"), vec!["token-1"]);
    }

    #[test]
    fn jwt_issuer_routes_matching_jwt_shapes_including_unsafe_algorithms() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"alg": "RS256", "kid": "k1"}).to_string());
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"iss": "https://gitlab.example", "sub": "s"}).to_string());
        let token = format!("{header}.{payload}.sig");
        assert_eq!(
            jwt_issuer(&token).as_deref(),
            Some("https://gitlab.example")
        );

        // alg:none is routed by issuer so the verifier rejects it terminally;
        // it must never fall through to a password-forwarding realm.
        let none_h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"alg": "none"}).to_string());
        let none_t = format!("{none_h}.{payload}.");
        assert_eq!(
            jwt_issuer(&none_t).as_deref(),
            Some("https://gitlab.example")
        );

        // opaque (non-JWT) secrets are declined.
        assert_eq!(jwt_issuer("not-a-jwt"), None);
        assert_eq!(jwt_issuer("only.two"), None);
    }

    #[test]
    fn basic_credentials_split_at_the_first_colon() {
        let cred = base64::engine::general_purpose::STANDARD.encode("user:s3:cr3t");
        assert_eq!(
            basic_credentials(&cred),
            Some(("user".to_string(), "s3:cr3t".to_string()))
        );
        // token-as-password with no colon-prefixed user still needs a colon.
        assert_eq!(basic_credentials("@@@notbase64"), None);
    }

    fn basic_header(credential: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode(credential);
        headers.insert(AUTHORIZATION, format!("Basic {encoded}").parse().unwrap());
        headers
    }

    #[test]
    fn basic_username_is_read_from_the_basic_header_only() {
        assert_eq!(
            basic_username(&basic_header("OIDC:secret")).as_deref(),
            Some("OIDC")
        );
        let mut bearer = HeaderMap::new();
        bearer.insert(AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(basic_username(&bearer), None);
        assert_eq!(basic_username(&HeaderMap::new()), None);
    }

    #[test]
    fn api_key_ttl_defaults_to_an_hour_and_is_bounded() {
        let base = json!({
            "issuer": "https://gitlab.example",
            "allowed_audiences": ["https://forge.example"],
            "rules": [{"role": "ci", "conditions": [{"claim": "project_id", "any_of": ["1"]}]}],
        });
        let normalized = validate_workload_identity_config(&base).unwrap();
        // Unset stays out of the normalized document (stable policy digest).
        assert!(normalized.get("api_key_ttl_seconds").is_none());
        let cfg: WorkloadIdentityRealmConfig = serde_json::from_value(normalized).unwrap();
        assert_eq!(cfg.api_key_ttl_seconds(), DEFAULT_API_KEY_TTL_SECONDS);

        let mut with_ttl = base.clone();
        with_ttl["api_key_ttl_seconds"] = json!(900);
        let cfg: WorkloadIdentityRealmConfig =
            serde_json::from_value(validate_workload_identity_config(&with_ttl).unwrap()).unwrap();
        assert_eq!(cfg.api_key_ttl_seconds(), 900);
        for bad in [0, 59, 24 * 60 * 60 + 1] {
            let mut cfg = base.clone();
            cfg["api_key_ttl_seconds"] = json!(bad);
            assert!(validate_workload_identity_config(&cfg).is_err(), "{bad}");
        }
    }

    #[test]
    fn positive_cache_requires_jti_and_is_bounded_by_expiry() {
        let now = chrono::Utc::now().timestamp();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"alg": "RS256", "kid": "k1"}).to_string());
        let payload = |claims: JsonValue| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
        };

        let without_jti = format!("{header}.{}.sig", payload(json!({"exp": now + 120})));
        assert!(positive_cache_key(&without_jti, 1, "policy", 60).is_none());

        let expired = format!(
            "{header}.{}.sig",
            payload(json!({"jti": "one", "exp": now - 1}))
        );
        assert!(positive_cache_key(&expired, 1, "policy", 60).is_none());

        let live = format!(
            "{header}.{}.sig",
            payload(json!({"jti": "one", "exp": now + 2}))
        );
        let (key, ttl) = positive_cache_key(&live, 1, "policy", 60).expect("cacheable");
        assert_eq!(key.len(), 64, "opaque SHA-256 cache key");
        assert!(ttl <= Duration::from_secs(2), "TTL is exp-bounded");

        let different_token = format!(
            "{header}.{}.other-signature",
            payload(json!({"jti": "one", "exp": now + 2}))
        );
        let (other_key, _) =
            positive_cache_key(&different_token, 1, "policy", 60).expect("cacheable");
        assert_ne!(key, other_key, "same jti cannot alias a different token");
    }
}
