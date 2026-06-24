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

use async_trait::async_trait;
use base64::Engine;
use forge_cache::Cache;
use forge_core::auth::token::{PrincipalSource, SourceOutcome};
use forge_core::auth::Principal;
use forge_core::net::ssrf;
use forge_core::oidc::{IdTokenClaims, OidcMetadataClient};
use forge_db::authz_dao;
use forge_db::model::AuthRealm;
use http::header::AUTHORIZATION;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;

use super::realms::RealmAuth;

/// Default leeway (seconds) on `exp`/`nbf`/`iat` for a WIF token.
fn default_clock_skew() -> u64 {
    60
}

/// `config` shape for a `workload_identity` realm. Holds **no secret** (the
/// issuer JWKS is public), so it has no write-only fields — the whole document
/// round-trips through the admin API unredacted.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// Ordered claim-match rules; the **first** fully-matching rule's `role` is
    /// granted. No rule matches ⇒ **default deny** (the token is rejected).
    #[serde(default)]
    pub rules: Vec<ClaimRule>,
}

/// One authorization rule: when **all** `conditions` match the token's claims,
/// grant the forge `role`. An empty `conditions` list is a deliberate catch-all
/// (any validly-signed token from the issuer ⇒ this role).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRule {
    /// The forge `role.name` to grant on a match. Resolved to a `role.id` at
    /// validation time; a non-existent role denies (fail-closed).
    pub role: String,
    /// Claim conditions, AND-combined. Empty ⇒ matches any token (catch-all).
    #[serde(default)]
    pub conditions: Vec<ClaimCondition>,
}

/// A single claim condition: the named claim's value (stringified; arrays are
/// expanded element-wise) must equal one of `any_of` (OR within a claim).
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    let cfg: WorkloadIdentityRealmConfig =
        serde_json::from_value(config.clone()).map_err(|e| format!("invalid config: {e}"))?;

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

    if cfg.allowed_audiences.is_empty() {
        return Err("allowed_audiences must list at least one audience (no wildcard)".into());
    }
    if cfg.allowed_audiences.iter().any(|a| a.trim().is_empty()) {
        return Err("allowed_audiences must not contain an empty value".into());
    }
    if cfg.rules.is_empty() {
        return Err(
            "at least one claim-match rule is required (an empty rule set denies every \
                    token)"
                .into(),
        );
    }
    for (i, rule) in cfg.rules.iter().enumerate() {
        if rule.role.trim().is_empty() {
            return Err(format!("rule {i}: role must not be empty"));
        }
        for (j, cond) in rule.conditions.iter().enumerate() {
            if cond.claim.trim().is_empty() {
                return Err(format!("rule {i} condition {j}: claim must not be empty"));
            }
            if cond.any_of.is_empty() {
                return Err(format!(
                    "rule {i} condition {j}: any_of must list at least one accepted value"
                ));
            }
        }
    }

    Ok(serde_json::to_value(&cfg).expect("serializable"))
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
}

impl WorkloadIdentityRealm {
    /// Build the runtime from a realm row, reusing the shared cache for
    /// discovery/JWKS and the SSRF-guarded outbound client (12.7 §3.6).
    pub fn build(realm: &AuthRealm, cache: &Cache) -> anyhow::Result<Self> {
        let config: WorkloadIdentityRealmConfig = serde_json::from_value(realm.config.clone())
            .map_err(|e| anyhow::anyhow!("config: {e}"))?;
        let http =
            ssrf::outbound_client().map_err(|e| anyhow::anyhow!("build outbound client: {e}"))?;
        let meta = OidcMetadataClient::new(config.issuer.clone(), http, cache.clone());
        Ok(WorkloadIdentityRealm {
            realm_id: realm.id,
            realm_name: realm.name.clone(),
            config,
            meta,
        })
    }

    /// Whether this realm's configured issuer equals `issuer` (trailing-slash
    /// insensitive — the [`OidcMetadataClient`] stores a normalized issuer).
    fn issuer_matches(&self, issuer: &str) -> bool {
        self.meta.issuer() == normalize_issuer(issuer)
    }
}

/// The [`PrincipalSource`] that authenticates WIF workloads. Reads the enabled
/// `workload_identity` realms from the (snapshot-cached) realm table, routes a
/// presented JWT to the realm whose issuer it names, and validates it.
pub struct WorkloadIdentitySource {
    realms: Arc<RealmAuth>,
    pool: PgPool,
}

impl WorkloadIdentitySource {
    /// Build the source over the shared realm snapshot + DB pool (for role
    /// resolution).
    pub fn new(realms: Arc<RealmAuth>, pool: PgPool) -> Self {
        Self { realms, pool }
    }

    /// Verify `token` against `realm` and map it to a [`Principal::Workload`].
    /// Terminal: any failure is [`SourceOutcome::Invalid`] (no fall-through).
    async fn authenticate(&self, realm: &WorkloadIdentityRealm, token: &str) -> SourceOutcome {
        let auds: Vec<&str> = realm
            .config
            .allowed_audiences
            .iter()
            .map(String::as_str)
            .collect();
        let verified = match realm
            .meta
            .verify_jwt(token, &auds, None, realm.config.clock_skew_seconds)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(realm = %realm.realm_name, error = %e, "WIF token validation failed");
                return SourceOutcome::Invalid;
            }
        };

        let Some(role_name) = matched_role(&verified.claims, &realm.config.rules) else {
            tracing::warn!(
                realm = %realm.realm_name,
                subject = %verified.subject,
                "WIF token matched no claim rule (default deny)"
            );
            return SourceOutcome::Invalid;
        };

        match authz_dao::role_id_by_name(&self.pool, role_name).await {
            Ok(Some(role_id)) => {
                tracing::info!(
                    realm = %realm.realm_name,
                    subject = %verified.subject,
                    role = %role_name,
                    "WIF workload authenticated"
                );
                SourceOutcome::Authenticated(Principal::Workload {
                    realm_id: realm.realm_id,
                    role_id,
                })
            }
            Ok(None) => {
                tracing::error!(
                    realm = %realm.realm_name,
                    role = %role_name,
                    "WIF rule maps to a non-existent role (deny)"
                );
                SourceOutcome::Invalid
            }
            Err(e) => {
                tracing::error!(error = %e, "WIF role lookup failed");
                SourceOutcome::Invalid
            }
        }
    }
}

#[async_trait]
impl PrincipalSource for WorkloadIdentitySource {
    async fn resolve(&self, headers: &HeaderMap, _peer_ip: std::net::IpAddr) -> SourceOutcome {
        let candidates = candidate_secrets(headers);
        if candidates.is_empty() {
            return SourceOutcome::NoCredentials;
        }

        // Resolve the realm snapshot. On a snapshot error we cannot route, so we
        // decline (the request falls through to the token/Basic sources and is
        // denied there if it carried no other valid credential) — we never grant.
        let snap = match self.realms.snapshot().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "WIF realm snapshot failed");
                return SourceOutcome::NoCredentials;
            }
        };
        if snap.workload.is_empty() {
            return SourceOutcome::NoCredentials;
        }

        for secret in &candidates {
            let Some(issuer) = jwt_issuer(secret) else {
                continue; // not a JWT — let other sources handle this secret
            };
            let Some(realm) = snap.workload.iter().find(|r| r.issuer_matches(&issuer)) else {
                continue; // a JWT, but not for any configured WIF issuer
            };
            // This secret IS a WIF token for `realm`: terminal from here.
            return self.authenticate(realm, secret).await;
        }
        SourceOutcome::NoCredentials
    }
}

/// Collect candidate secrets a workload could present its `id_token` in, in
/// priority order: `Authorization: Bearer`, then the Basic password, then
/// `X-NuGet-ApiKey`.
fn candidate_secrets(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(bearer) = strip_prefix_ci(auth, "Bearer ") {
            let t = bearer.trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
        } else if let Some(basic) = strip_prefix_ci(auth, "Basic ") {
            if let Some(pw) = basic_password(basic.trim()) {
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

/// Case-insensitive prefix strip (HTTP auth schemes are case-insensitive).
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Decode the password half of a Base64 `user:password` HTTP Basic credential.
fn basic_password(b64: &str) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    s.split_once(':').map(|(_, pw)| pw.to_string())
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
    let alg = header.get("alg")?.as_str()?;
    if alg.eq_ignore_ascii_case("none") {
        return None; // unsigned token — never routed to WIF
    }

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
pub fn matched_role<'a>(claims: &IdTokenClaims, rules: &'a [ClaimRule]) -> Option<&'a str> {
    rules
        .iter()
        .find(|rule| rule_matches(claims, rule))
        .map(|r| r.role.as_str())
}

/// Whether every condition of `rule` matches `claims` (an empty condition list
/// is a catch-all and always matches).
fn rule_matches(claims: &IdTokenClaims, rule: &ClaimRule) -> bool {
    rule.conditions.iter().all(|cond| {
        let values = claim_values(claims, &cond.claim);
        values.iter().any(|v| cond.any_of.iter().any(|a| a == v))
    })
}

/// All string representations of a claim's value(s): registered claims first,
/// then the flattened `additional` map. Arrays expand element-wise; scalars
/// (bool/number) stringify so rules can match `ref_protected: true` etc.
fn claim_values(claims: &IdTokenClaims, name: &str) -> Vec<String> {
    let direct: Option<JsonValue> = match name {
        "sub" => Some(JsonValue::String(claims.sub.clone())),
        "iss" => Some(JsonValue::String(claims.iss.clone())),
        "aud" => claims.aud.clone(),
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
        assert_eq!(matched_role(&claims, &rules), Some("publisher"));
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
        assert_eq!(matched_role(&claims, &rules), None);
    }

    #[test]
    fn empty_conditions_is_a_catch_all() {
        let claims = claims_with(Map::new());
        let rules = vec![ClaimRule {
            role: "reader".into(),
            conditions: vec![],
        }];
        assert_eq!(matched_role(&claims, &rules), Some("reader"));
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
    }

    #[test]
    fn jwt_issuer_extracts_iss_and_rejects_non_jwt_and_alg_none() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"alg": "RS256", "kid": "k1"}).to_string());
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"iss": "https://gitlab.example", "sub": "s"}).to_string());
        let token = format!("{header}.{payload}.sig");
        assert_eq!(
            jwt_issuer(&token).as_deref(),
            Some("https://gitlab.example")
        );

        // alg:none is never routed.
        let none_h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"alg": "none"}).to_string());
        let none_t = format!("{none_h}.{payload}.");
        assert_eq!(jwt_issuer(&none_t), None);

        // opaque (non-JWT) secrets are declined.
        assert_eq!(jwt_issuer("not-a-jwt"), None);
        assert_eq!(jwt_issuer("only.two"), None);
    }

    #[test]
    fn basic_password_decodes_the_password_half() {
        let cred = base64::engine::general_purpose::STANDARD.encode("user:s3cr3t");
        assert_eq!(basic_password(&cred).as_deref(), Some("s3cr3t"));
        // token-as-password with no colon-prefixed user still needs a colon.
        assert_eq!(basic_password("@@@notbase64"), None);
    }
}
