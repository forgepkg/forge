//! OIDC discovery + JWKS fetch (cached) + ID-token verification.
//!
//! See the module docs ([`super`]) for the multi-instance / no-advisory-lock
//! rationale. Everything here is parameterised over an injected
//! [`reqwest::Client`] (so callers pass the no-redirect, https-only client from
//! [`crate::net::ssrf::outbound_metadata_client`]) and a [`forge_cache::Cache`], which is
//! what makes the whole module unit-testable with a [`wiremock`] HTTP server and
//! a self-signed token — no real IdP, no real network.
//!
//! Discovery documents and key sets decide which tokens verify, so they are
//! cached **in-process only** ([`Cache::get_or_try_insert_local`]): never read
//! from Redis, where anyone with access to it could plant their own signing
//! key. Each instance fetches them itself; Redis only relays invalidations.

use std::convert::Infallible;
use std::time::Duration;

use forge_cache::Cache;
use futures_util::StreamExt;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

/// Cache namespace for the parsed OIDC discovery document, keyed by issuer.
const NS_DISCOVERY: &str = "oidc_discovery";
/// Separate namespace for workload-only discovery documents. Keeping it
/// distinct prevents a minimal GitHub Actions document from being cached under
/// the interactive OIDC shape (which requires browser-flow endpoints).
const NS_WORKLOAD_DISCOVERY: &str = "oidc_workload_discovery";
/// Cache namespace for the issuer's JWKS, keyed by issuer.
const NS_JWKS: &str = "oidc_jwks";
/// Issuer-scoped cooldown after a `kid` miss claims the one allowed refresh.
/// Keying only by issuer (not attacker-controlled `kid`) bounds random-kid
/// traffic to one JWKS eviction/refetch per cooldown window.
const NS_JWKS_KID_REFRESH: &str = "oidc_jwks_kid_refresh";

/// Default TTL for the discovery document (stable; refetch daily).
const DEFAULT_DISCOVERY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Default TTL for the JWKS (moderate; kid-miss handles early rotation).
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_UNKNOWN_KID_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

/// Upper bound on a fetched discovery / JWKS document. Generous, but bounds
/// memory against a hostile or misconfigured IdP. (Mirrors the proxy's
/// `MAX_METADATA_BYTES`.)
const MAX_DOC_BYTES: usize = 1024 * 1024;

/// Errors raised while fetching/parsing OIDC metadata or verifying an ID token.
///
/// `Clone` so it can flow back through [`forge_cache::Cache::get_or_try_insert_with`],
/// whose coalescing hands every waiter a shared error on a failing factory.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OidcError {
    /// An HTTP fetch (discovery or JWKS) failed or returned a non-success status.
    #[error("oidc http fetch {url}: {reason}")]
    Http {
        /// The URL we tried to fetch.
        url: String,
        /// Human-readable cause (status line or transport error).
        reason: String,
    },
    /// A fetched document could not be parsed as the expected JSON shape.
    #[error("oidc parse {what}: {reason}")]
    Parse {
        /// What we were parsing (`discovery` / `jwks`).
        what: String,
        /// Human-readable cause.
        reason: String,
    },
    /// The discovery document's `issuer` did not equal the configured issuer, or
    /// an advertised endpoint host did not match the issuer host (SSRF sanity).
    #[error("oidc discovery mismatch: {0}")]
    DiscoveryMismatch(String),
    /// The ID token's header lacked a `kid`, or no JWKS key matched it even after
    /// a forced refetch.
    #[error("oidc signing key not found for kid {0:?}")]
    UnknownKid(Option<String>),
    /// The signing key uses an algorithm family we refuse (e.g. `none`, HMAC, or
    /// an unsupported curve) — defense against key/alg-confusion.
    #[error("oidc unsupported signing algorithm: {0}")]
    UnsupportedAlg(String),
    /// The token signature or a registered claim (`iss`/`aud`/`exp`/`nbf`) failed
    /// validation.
    #[error("oidc id-token invalid: {0}")]
    InvalidToken(String),
    /// The token's `nonce` claim did not match the value bound to this login flow.
    #[error("oidc nonce mismatch")]
    NonceMismatch,
}

impl OidcError {
    /// Whether the issuer could not be asked rather than refusing the token:
    /// its discovery document or JWKS could not be fetched (a transport error,
    /// a timeout, a non-success status) or read (too large, not the expected
    /// JSON). Such an error is no verdict on the token, so a caller answers
    /// "try again later" instead of "invalid credentials".
    pub fn is_unavailable(&self) -> bool {
        matches!(self, OidcError::Http { .. } | OidcError::Parse { .. })
    }
}

/// The subset of the OIDC discovery document we use.
///
/// Cached as JSON via [`forge_cache::Cache`], so it is `Serialize`/`Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// The issuer identifier. Must equal the configured issuer (and the ID
    /// token's `iss`).
    pub issuer: String,
    /// Authorization endpoint (where `/auth/oidc/login` redirects the browser).
    pub authorization_endpoint: String,
    /// Token endpoint (where the callback exchanges the code).
    pub token_endpoint: String,
    /// JWKS URI (where signing keys are published).
    pub jwks_uri: String,
    /// RP-initiated logout endpoint, when the IdP advertises one.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// The metadata a non-interactive workload verifier actually needs.
///
/// GitHub Actions deliberately publishes issuer/JWKS metadata without OAuth
/// authorization or token endpoints. WIF validates a token already obtained by
/// the CI runtime, so requiring browser-flow endpoints here is both unnecessary
/// and incompatible with that provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadDiscoveryDocument {
    /// The issuer identifier. Must equal the configured issuer.
    pub issuer: String,
    /// URI publishing the issuer's signing keys.
    pub jwks_uri: String,
}

/// The ID-token claims we extract after a successful verification. The claim →
/// user mapping happens afterwards ([`super::claims`]); here we keep the raw
/// values plus the full claim set for that step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified {
    /// `sub` — the stable, issuer-scoped subject identifier.
    pub subject: String,
    /// `iss` — the issuer, exactly as the token (and the discovery document)
    /// spell it; equal to the configured issuer up to a trailing slash.
    pub issuer: String,
    /// All decoded claims, for downstream claim → user / admin mapping.
    pub claims: IdTokenClaims,
}

/// Decoded ID-token claims. Registered claims are typed; everything else (the
/// IdP-specific claims used for username/email/groups/roles mapping) is kept in
/// `additional` for the claim mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Subject.
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience (string or array; Entra emits a single string).
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    /// Expiry (seconds since epoch).
    #[serde(default)]
    pub exp: Option<i64>,
    /// Not-before (seconds since epoch).
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Issued-at (seconds since epoch).
    #[serde(default)]
    pub iat: Option<i64>,
    /// Unique token identifier. WIF uses it only for an expiry-bounded positive
    /// signature-verification cache and audit correlation; it is never an
    /// authorization input.
    #[serde(default)]
    pub jti: Option<String>,
    /// Nonce binding the token to a single login flow.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Authorized party (Entra sets `azp` to the client id).
    #[serde(default)]
    pub azp: Option<String>,
    /// All other claims (preferred_username, email, name, groups, roles, …).
    #[serde(flatten)]
    pub additional: serde_json::Map<String, serde_json::Value>,
}

/// Parameters for verifying an ID token, derived from config + the live flow.
#[derive(Debug, Clone)]
pub struct VerifyParams {
    /// Expected audience — the configured `client_id`.
    pub audience: String,
    /// Expected `nonce` (the value persisted in the `oidc_flow` row). When
    /// `None`, the nonce check is skipped (only flows without a nonce — we
    /// always set one, so this is mainly for tests).
    pub nonce: Option<String>,
    /// Clock-skew leeway (seconds) for `exp`/`nbf`/`iat`.
    pub leeway_seconds: u64,
}

/// Fetches + caches an issuer's discovery document and JWKS and verifies ID
/// tokens against them.
///
/// Cheaply [`Clone`]able — shares the [`forge_cache::Cache`] and the
/// [`reqwest::Client`] (the caller builds the latter via the SSRF guard).
#[derive(Clone)]
pub struct OidcMetadataClient {
    /// The configured, trusted issuer (https). Discovery is fetched from
    /// `{issuer}/.well-known/openid-configuration` and the document's own
    /// `issuer` must match this exactly.
    issuer: String,
    /// Outbound HTTP client (no redirects, https only; built by the caller via
    /// [`crate::net::ssrf::outbound_metadata_client`]).
    http: reqwest::Client,
    /// Hybrid cache for discovery + JWKS.
    cache: Cache,
    /// Discovery TTL.
    discovery_ttl: Duration,
    /// JWKS TTL.
    jwks_ttl: Duration,
    /// Hosts besides the issuer's that the advertised endpoints may use
    /// (lowercase), for IdPs that serve tokens and keys elsewhere (Google,
    /// AWS Cognito).
    endpoint_hosts: Vec<String>,
}

impl OidcMetadataClient {
    /// Build a client for `issuer`, fetching through `http` and caching in
    /// `cache`. Uses the default discovery/JWKS TTLs.
    pub fn new(issuer: impl Into<String>, http: reqwest::Client, cache: Cache) -> Self {
        Self {
            issuer: normalize_issuer(issuer.into()),
            http,
            cache,
            discovery_ttl: DEFAULT_DISCOVERY_TTL,
            jwks_ttl: DEFAULT_JWKS_TTL,
            endpoint_hosts: Vec::new(),
        }
    }

    /// Also accept advertised endpoints on these hosts (compared
    /// case-insensitively). The issuer's own host is always accepted.
    pub fn with_endpoint_hosts(mut self, hosts: Vec<String>) -> Self {
        self.endpoint_hosts = hosts.into_iter().map(|h| h.to_ascii_lowercase()).collect();
        self
    }

    /// Override the discovery/JWKS TTLs (mainly for tests).
    pub fn with_ttls(mut self, discovery_ttl: Duration, jwks_ttl: Duration) -> Self {
        self.discovery_ttl = discovery_ttl;
        self.jwks_ttl = jwks_ttl;
        self
    }

    /// The configured issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The outbound HTTP client, for the flow's token-endpoint exchange
    /// (`flow.rs`). Sharing the same client keeps the SSRF/timeout posture
    /// consistent across discovery, JWKS, and token calls.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http
    }

    /// Fetch (or read from cache) the issuer's discovery document.
    ///
    /// The well-known URL is derived from the **configured** issuer (trusted),
    /// never from any IdP-supplied value, and the returned document's own
    /// `issuer` must equal the configured issuer. The advertised endpoints are
    /// sanity-checked to use the issuer's scheme and to live on the issuer's
    /// host or one of the configured endpoint hosts (SSRF defense-in-depth on
    /// top of the guarded client).
    pub async fn discovery(&self) -> Result<DiscoveryDocument, OidcError> {
        let url = discovery_url(&self.issuer);
        let http = self.http.clone();
        let expected_issuer = self.issuer.clone();
        let endpoint_hosts = self.endpoint_hosts.clone();

        let doc: DiscoveryDocument = self
            .cache
            .get_or_try_insert_local(
                NS_DISCOVERY,
                &self.issuer,
                self.discovery_ttl,
                || async move {
                    let doc: DiscoveryDocument = fetch_json(&http, &url, "discovery").await?;
                    validate_discovery(&doc, &expected_issuer, &endpoint_hosts)?;
                    Ok(doc)
                },
            )
            .await?;
        // The cache is per issuer: a document another client (with other
        // endpoint hosts) stored must pass this client's check too.
        validate_discovery(&doc, &self.issuer, &self.endpoint_hosts)?;
        Ok(doc)
    }

    /// Fetch (or read from cache) the minimal discovery document used for
    /// workload-token verification. Unlike [`Self::discovery`], this accepts a
    /// standards-compatible issuer/JWKS-only document and does not require
    /// interactive OAuth endpoints.
    pub async fn workload_discovery(&self) -> Result<WorkloadDiscoveryDocument, OidcError> {
        let url = discovery_url(&self.issuer);
        let http = self.http.clone();
        let expected_issuer = self.issuer.clone();

        let doc: WorkloadDiscoveryDocument = self
            .cache
            .get_or_try_insert_local(
                NS_WORKLOAD_DISCOVERY,
                &self.issuer,
                self.discovery_ttl,
                || async move {
                    let doc: WorkloadDiscoveryDocument =
                        fetch_json(&http, &url, "workload discovery").await?;
                    validate_workload_discovery(&doc, &expected_issuer)?;
                    Ok(doc)
                },
            )
            .await?;
        Ok(doc)
    }

    /// Fetch (or read from cache) the issuer's JWKS.
    pub async fn jwks(&self) -> Result<JwkSet, OidcError> {
        let jwks_uri = self.discovery().await?.jwks_uri;
        self.fetch_jwks_cached(&jwks_uri).await
    }

    /// Read the JWKS from cache (factory on miss).
    async fn fetch_jwks_cached(&self, jwks_uri: &str) -> Result<JwkSet, OidcError> {
        let http = self.http.clone();
        let url = jwks_uri.to_string();
        self.cache
            .get_or_try_insert_local(NS_JWKS, &self.issuer, self.jwks_ttl, || async move {
                let fetched = fetch_json::<JwkSet>(&http, &url, "jwks").await;
                if fetched.is_err() {
                    forge_metrics::auth::jwks_refresh_failed();
                }
                fetched
            })
            .await
    }

    /// Refetch the JWKS after a `kid` miss (an early IdP key rotation),
    /// bypassing the cache; `cached` is the set that missed.
    ///
    /// The fetch comes first. When it fails, `cached` stays in place and keeps
    /// verifying tokens signed with its keys: the token that triggered the
    /// refresh needs no valid signature, so dropping the keys first would let
    /// anyone empty every instance's cache during an IdP outage. Only a set
    /// that differs from `cached` replaces it, through an invalidation that
    /// also reaches the peer instances (via the cache backplane, when Redis is
    /// configured) so they pick up the rotated keys; a refresh that finds the
    /// same keys changes nothing anywhere.
    ///
    /// We deliberately use **no** advisory lock: an occasional duplicate JWKS
    /// fetch is harmless.
    async fn refetch_jwks(&self, jwks_uri: &str, cached: JwkSet) -> JwkSet {
        let fresh = match fetch_json::<JwkSet>(&self.http, jwks_uri, "jwks").await {
            Ok(fresh) => fresh,
            Err(e) => {
                forge_metrics::auth::jwks_refresh_failed();
                tracing::warn!(
                    issuer = %self.issuer,
                    error = %e,
                    "jwks refresh after an unknown kid failed; keeping the cached keys"
                );
                return cached;
            }
        };
        if fresh == cached {
            return cached;
        }
        self.cache.invalidate(NS_JWKS, &self.issuer).await;
        let stored = fresh.clone();
        self.cache
            .get_or_try_insert_local(NS_JWKS, &self.issuer, self.jwks_ttl, || async move {
                Ok::<JwkSet, Infallible>(stored)
            })
            .await
            .unwrap_or_else(|never| match never {})
    }

    /// Claim the issuer's single unknown-`kid` refresh slot for the cooldown
    /// window. The cache's per-key coalescing means concurrent misses share one
    /// winner per instance.
    async fn acquire_unknown_kid_refresh(&self) -> bool {
        let candidate = uuid::Uuid::new_v4().to_string();
        let produced = candidate.clone();
        let cached = self
            .cache
            .get_or_try_insert_local(
                NS_JWKS_KID_REFRESH,
                &self.issuer,
                DEFAULT_UNKNOWN_KID_REFRESH_COOLDOWN,
                || async move { Ok::<String, Infallible>(produced) },
            )
            .await
            .expect("infallible refresh-slot cache factory");
        cached == candidate
    }

    /// Verify an ID token: signature (against the cached JWKS, with a single
    /// kid-miss refetch), then `iss`/`aud`/`exp`/`nbf` (with leeway) and `nonce`.
    ///
    /// Returns the validated subject + full claim set for the claim mapping.
    /// Rejects `alg: none`, HMAC, and any non-RSA key family.
    pub async fn verify_id_token(
        &self,
        token: &str,
        params: &VerifyParams,
    ) -> Result<Verified, OidcError> {
        self.verify_jwt_inner(
            token,
            &[params.audience.as_str()],
            params.nonce.as_deref(),
            params.leeway_seconds,
            DiscoveryKind::Interactive,
            false,
        )
        .await
    }

    /// Verify a JWT against this issuer, accepting **any** of `audiences`
    /// (WIF: a workload realm trusts a set of allowed audiences and
    /// presents no nonce). This is the shared core of [`verify_id_token`]:
    /// signature against the cached JWKS (one kid-miss refetch), the RSA-only
    /// algorithm allowlist, `iss` = configured issuer, `aud` ∈ `audiences`,
    /// `exp`/`nbf` with leeway, and an optional `nonce` equality check.
    ///
    /// `audiences` must be non-empty; an empty slice would make `jsonwebtoken`
    /// skip the audience check, so callers must pass at least one.
    pub async fn verify_jwt(
        &self,
        token: &str,
        audiences: &[&str],
        nonce: Option<&str>,
        leeway_seconds: u64,
    ) -> Result<Verified, OidcError> {
        self.verify_jwt_inner(
            token,
            audiences,
            nonce,
            leeway_seconds,
            DiscoveryKind::Interactive,
            false,
        )
        .await
    }

    /// Verify a non-interactive workload JWT.
    ///
    /// This differs deliberately from browser-login ID-token verification:
    /// workload-only discovery needs only `issuer` + `jwks_uri`; a non-empty
    /// `kid` is mandatory; and `iat` plus the total token lifetime are bounded.
    /// `allowed_authorized_parties` is optional for providers that do not emit
    /// `azp`; when configured, the token must carry one of those exact values.
    pub async fn verify_workload_jwt(
        &self,
        token: &str,
        audiences: &[&str],
        allowed_authorized_parties: &[&str],
        leeway_seconds: u64,
        max_token_age_seconds: u64,
    ) -> Result<Verified, OidcError> {
        let verified = self
            .verify_jwt_inner(
                token,
                audiences,
                None,
                leeway_seconds,
                DiscoveryKind::Workload,
                true,
            )
            .await?;
        validate_workload_claims(
            &verified.claims,
            allowed_authorized_parties,
            leeway_seconds,
            max_token_age_seconds,
        )?;
        Ok(verified)
    }

    async fn verify_jwt_inner(
        &self,
        token: &str,
        audiences: &[&str],
        nonce: Option<&str>,
        leeway_seconds: u64,
        discovery_kind: DiscoveryKind,
        require_kid: bool,
    ) -> Result<Verified, OidcError> {
        if audiences.is_empty() {
            return Err(OidcError::InvalidToken(
                "no allowed audiences configured".into(),
            ));
        }
        // 1. Read the header to find the signing-key id + declared algorithm.
        let header = decode_header(token).map_err(|e| OidcError::InvalidToken(e.to_string()))?;
        let kid = header.kid.clone();
        if require_kid && kid.as_deref().is_none_or(str::is_empty) {
            return Err(OidcError::UnknownKid(None));
        }
        if !is_allowed_rsa_algorithm(header.alg) {
            return Err(OidcError::UnsupportedAlg(format!("{:?}", header.alg)));
        }

        // 2. Locate the key in the cached JWKS; on a kid miss force exactly one
        //    refetch (early IdP rotation) and look again. The discovery
        //    document also supplies the issuer string tokens must carry.
        let (jwks_uri, discovered_issuer) = match discovery_kind {
            DiscoveryKind::Interactive => {
                let doc = self.discovery().await?;
                (doc.jwks_uri, doc.issuer)
            }
            DiscoveryKind::Workload => {
                let doc = self.workload_discovery().await?;
                (doc.jwks_uri, doc.issuer)
            }
        };
        let mut jwks = self.fetch_jwks_cached(&jwks_uri).await?;
        let mut jwk = find_key(&jwks, kid.as_deref());
        if jwk.is_none() && self.acquire_unknown_kid_refresh().await {
            jwks = self.refetch_jwks(&jwks_uri, jwks.clone()).await;
            jwk = find_key(&jwks, kid.as_deref());
        }
        let jwk = jwk.ok_or_else(|| OidcError::UnknownKid(kid.clone()))?;

        // 3. Refuse anything that isn't an RSA key (no `oct`/HMAC, no `alg:none`,
        //    no key/alg confusion).
        if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_)) {
            return Err(OidcError::UnsupportedAlg(format!(
                "{:?}",
                jwk.common.key_algorithm
            )));
        }
        if let Some(key_use) = &jwk.common.public_key_use {
            if key_use != &PublicKeyUse::Signature {
                return Err(OidcError::UnsupportedAlg(format!(
                    "JWK use is {key_use:?}, not sig"
                )));
            }
        }
        if let Some(ops) = &jwk.common.key_operations {
            if !ops.contains(&KeyOperations::Verify) {
                return Err(OidcError::UnsupportedAlg(
                    "JWK key_ops does not include verify".into(),
                ));
            }
        }
        if let Some(key_alg) = jwk.common.key_algorithm {
            if key_alg.to_string() != format!("{:?}", header.alg) {
                return Err(OidcError::UnsupportedAlg(format!(
                    "token alg {:?} does not match JWK alg {key_alg}",
                    header.alg
                )));
            }
        }
        let decoding_key =
            DecodingKey::from_jwk(jwk).map_err(|e| OidcError::InvalidToken(e.to_string()))?;

        // 4. Build a strict validation: RSA family only, issuer = the issuer
        //    string *exactly as the discovery document states it*, audience =
        //    client_id, exp/nbf with leeway. Not the normalized configured
        //    issuer: OIDC requires `iss` to be byte-identical to the discovered
        //    issuer, and issuers such as Auth0's end in `/`, which the
        //    normalized (cache-key / routing) form has stripped — validating
        //    against that would reject every token. The discovery document's
        //    issuer was already checked to equal the configured one up to that
        //    trailing slash.
        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.set_issuer(&[discovered_issuer.as_str()]);
        validation.set_audience(audiences);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.leeway = leeway_seconds;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let data = decode::<IdTokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| OidcError::InvalidToken(e.to_string()))?;
        let claims = data.claims;

        // 5. Manual nonce check (not a registered claim, so jsonwebtoken does not
        //    validate it). Both single-use; the binding is what makes the
        //    cookieless callback safe. WIF passes `None` (non-interactive).
        if let Some(expected) = nonce {
            match &claims.nonce {
                Some(actual) if actual == expected => {}
                _ => return Err(OidcError::NonceMismatch),
            }
        }

        Ok(Verified {
            subject: claims.sub.clone(),
            issuer: claims.iss.clone(),
            claims,
        })
    }
}

#[derive(Clone, Copy)]
enum DiscoveryKind {
    Interactive,
    Workload,
}

fn is_allowed_rsa_algorithm(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
    )
}

/// Workload tokens must be fresh even when an issuer gives them an overly-long
/// `exp`. This closes the gap left by generic JWT libraries, which validate
/// `exp`/`nbf` but intentionally assign no semantics to `iat`.
fn validate_workload_claims(
    claims: &IdTokenClaims,
    allowed_authorized_parties: &[&str],
    leeway_seconds: u64,
    max_token_age_seconds: u64,
) -> Result<(), OidcError> {
    if claims.sub.trim().is_empty() {
        return Err(OidcError::InvalidToken("sub must not be empty".into()));
    }
    let iat = claims
        .iat
        .ok_or_else(|| OidcError::InvalidToken("iat is required for workload tokens".into()))?;
    let exp = claims
        .exp
        .ok_or_else(|| OidcError::InvalidToken("exp is required for workload tokens".into()))?;
    let now = chrono::Utc::now().timestamp();
    let leeway = i64::try_from(leeway_seconds).unwrap_or(i64::MAX);
    let max_age = i64::try_from(max_token_age_seconds).unwrap_or(i64::MAX);
    if max_age <= 0 {
        return Err(OidcError::InvalidToken(
            "max workload token age must be positive".into(),
        ));
    }
    if iat > now.saturating_add(leeway) {
        return Err(OidcError::InvalidToken(
            "workload token iat is in the future".into(),
        ));
    }
    if iat < now.saturating_sub(max_age.saturating_add(leeway)) {
        return Err(OidcError::InvalidToken(
            "workload token exceeds maximum age".into(),
        ));
    }
    if exp <= iat {
        return Err(OidcError::InvalidToken(
            "workload token exp must be after iat".into(),
        ));
    }
    if exp.saturating_sub(iat) > max_age {
        return Err(OidcError::InvalidToken(
            "workload token lifetime exceeds configured maximum".into(),
        ));
    }
    if !allowed_authorized_parties.is_empty() {
        match claims.azp.as_deref() {
            Some(azp) if allowed_authorized_parties.contains(&azp) => {}
            _ => {
                return Err(OidcError::InvalidToken(
                    "workload token azp is missing or not allowed".into(),
                ))
            }
        }
    }
    Ok(())
}

/// Find a JWK by `kid`. When the token header carries no `kid` and the set holds
/// exactly one key, fall back to that key (some minimal IdPs publish a single,
/// unlabeled key).
fn find_key<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Option<&'a jsonwebtoken::jwk::Jwk> {
    match kid {
        Some(kid) => jwks.find(kid),
        None if jwks.keys.len() == 1 => jwks.keys.first(),
        None => None,
    }
}

/// Normalize an issuer for use as a cache key + well-known base (and for
/// comparing a discovery document's issuer with the configured one): trim
/// trailing slashes, so `https://idp/` and `https://idp` share one cache entry
/// and one discovery URL. **Never** used for `iss` validation — tokens must
/// carry the discovered issuer verbatim (Auth0-style issuers end in `/`).
fn normalize_issuer(issuer: String) -> String {
    issuer.trim_end_matches('/').to_string()
}

/// Build the discovery URL from the configured issuer.
fn discovery_url(issuer: &str) -> String {
    format!("{issuer}/.well-known/openid-configuration")
}

/// Validate the discovery document: its `issuer` must equal the configured
/// issuer, and the advertised token/jwks endpoints must use the issuer's
/// scheme and live on the issuer's host or one of `endpoint_hosts` (SSRF
/// sanity on top of the guarded client).
fn validate_discovery(
    doc: &DiscoveryDocument,
    expected_issuer: &str,
    endpoint_hosts: &[String],
) -> Result<(), OidcError> {
    validate_discovery_identity_and_endpoints(
        &doc.issuer,
        expected_issuer,
        endpoint_hosts,
        &[
            ("jwks_uri", doc.jwks_uri.as_str()),
            ("token_endpoint", doc.token_endpoint.as_str()),
            (
                "authorization_endpoint",
                doc.authorization_endpoint.as_str(),
            ),
        ],
    )
}

fn validate_workload_discovery(
    doc: &WorkloadDiscoveryDocument,
    expected_issuer: &str,
) -> Result<(), OidcError> {
    validate_discovery_identity_and_endpoints(
        &doc.issuer,
        expected_issuer,
        &[],
        &[("jwks_uri", doc.jwks_uri.as_str())],
    )
}

fn validate_discovery_identity_and_endpoints(
    document_issuer: &str,
    expected_issuer: &str,
    endpoint_hosts: &[String],
    endpoints: &[(&'static str, &str)],
) -> Result<(), OidcError> {
    if normalize_issuer(document_issuer.to_string()) != expected_issuer {
        return Err(OidcError::DiscoveryMismatch(format!(
            "document issuer {:?} != configured issuer {:?}",
            document_issuer, expected_issuer
        )));
    }
    let issuer_url = Url::parse(expected_issuer).map_err(|e| {
        OidcError::DiscoveryMismatch(format!("configured issuer is not a url: {e}"))
    })?;
    let issuer_host = issuer_url
        .host_str()
        .ok_or_else(|| OidcError::DiscoveryMismatch("configured issuer has no host".into()))?
        .to_string();
    // Endpoints must use the **same scheme as the trusted issuer** (https in
    // production — the config loader requires an https issuer; http only for the
    // loopback mock in tests) and share the issuer's host, or use one the realm
    // names in `endpoint_hosts` (SSRF sanity on top of the guarded client).
    let issuer_scheme = issuer_url.scheme();

    for (label, endpoint) in endpoints {
        let url = Url::parse(endpoint).map_err(|e| {
            OidcError::DiscoveryMismatch(format!("{label} {endpoint:?} is not a valid url: {e}"))
        })?;
        if url.scheme() != issuer_scheme {
            return Err(OidcError::DiscoveryMismatch(format!(
                "{label} {endpoint:?} scheme must match issuer scheme {issuer_scheme:?}"
            )));
        }
        match url.host_str() {
            Some(host)
                if host == issuer_host
                    || endpoint_hosts
                        .iter()
                        .any(|allowed| host.eq_ignore_ascii_case(allowed)) => {}
            other => {
                return Err(OidcError::DiscoveryMismatch(format!(
                    "{label} host {other:?} does not match issuer host {issuer_host:?}"
                )))
            }
        }
    }
    Ok(())
}

/// GET `url` and parse the (bounded) body as JSON into `T`.
/// Why [`read_capped`] gave up.
#[derive(Debug)]
pub(crate) enum ReadCappedError {
    /// The body exceeds the cap.
    TooLarge,
    /// The body could not be read.
    Read(reqwest::Error),
}

/// Read a response body into memory, refusing more than `max` bytes (checked
/// against `Content-Length` up front and while streaming).
pub(crate) async fn read_capped(
    resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, ReadCappedError> {
    if resp
        .content_length()
        .is_some_and(|length| length > max as u64)
    {
        return Err(ReadCappedError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(resp.content_length().unwrap_or(0).min(max as u64) as usize);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(ReadCappedError::Read)?;
        if chunk.len() > max.saturating_sub(bytes.len()) {
            return Err(ReadCappedError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn fetch_json<T: DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    what: &str,
) -> Result<T, OidcError> {
    let resp = http.get(url).send().await.map_err(|e| OidcError::Http {
        url: url.to_string(),
        reason: e.to_string(),
    })?;
    if !resp.status().is_success() {
        return Err(OidcError::Http {
            url: url.to_string(),
            reason: format!("status {}", resp.status()),
        });
    }
    if resp
        .content_length()
        .is_some_and(|length| length > MAX_DOC_BYTES as u64)
    {
        return Err(OidcError::Parse {
            what: what.to_string(),
            reason: "document too large".into(),
        });
    }
    let bytes = match read_capped(resp, MAX_DOC_BYTES).await {
        Ok(bytes) => bytes,
        Err(ReadCappedError::TooLarge) => {
            return Err(OidcError::Parse {
                what: what.to_string(),
                reason: "document too large".into(),
            })
        }
        Err(ReadCappedError::Read(e)) => {
            return Err(OidcError::Http {
                url: url.to_string(),
                reason: format!("read body: {e}"),
            })
        }
    };
    serde_json::from_slice(&bytes).map_err(|e| OidcError::Parse {
        what: what.to_string(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

    /// Bodies over the cap are refused whether or not the server announces a
    /// `Content-Length` (a token or discovery response is never buffered
    /// whole when oversized).
    #[tokio::test]
    async fn read_capped_refuses_oversized_bodies() {
        let server = MockServer::start().await;
        Mock::given(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 4096]))
            .mount(&server)
            .await;
        Mock::given(path("/small"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 16]))
            .mount(&server)
            .await;
        let http = reqwest::Client::new();
        let big = http
            .get(format!("{}/big", server.uri()))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            read_capped(big, 1024).await,
            Err(ReadCappedError::TooLarge)
        ));
        let small = http
            .get(format!("{}/small", server.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(read_capped(small, 1024).await.unwrap().len(), 16);
    }

    /// A throwaway RSA signer: holds the private key (to sign tokens) and can
    /// emit its public half as a JWK (to publish in the mock JWKS).
    struct TestSigner {
        private_pem: String,
        kid: String,
        jwk: serde_json::Value,
    }

    impl TestSigner {
        fn new(kid: &str) -> Self {
            // 2048-bit is the smallest size Entra/AAD uses; fine for a unit test.
            let mut rng = rsa::rand_core::OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
            let public_key = RsaPublicKey::from(&private_key);
            let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(public_key.n().to_bytes_be());
            let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(public_key.e().to_bytes_be());
            let private_pem = private_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .expect("pkcs1 pem")
                .to_string();
            let jwk = json!({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": e,
            });
            Self {
                private_pem,
                kid: kid.to_string(),
                jwk,
            }
        }

        /// Sign `claims` into a compact JWS with this key (header `kid`/`RS256`).
        fn sign(&self, claims: &serde_json::Value) -> String {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(self.kid.clone());
            let key = EncodingKey::from_rsa_pem(self.private_pem.as_bytes()).expect("enc key");
            encode(&header, claims, &key).expect("sign jwt")
        }

        /// Sign with a valid RSA algorithm but deliberately omit `kid`.
        fn sign_without_kid(&self, claims: &serde_json::Value) -> String {
            let header = Header::new(Algorithm::RS256);
            let key = EncodingKey::from_rsa_pem(self.private_pem.as_bytes()).expect("enc key");
            encode(&header, claims, &key).expect("sign jwt")
        }
    }

    /// A wiremock responder that counts how many times it was hit.
    #[derive(Clone)]
    struct CountingJson {
        body: serde_json::Value,
        hits: Arc<AtomicUsize>,
    }
    impl Respond for CountingJson {
        fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
            self.hits.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(self.body.clone())
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// Standard valid claim set for the happy-path tests.
    fn good_claims(issuer: &str, aud: &str, nonce: &str) -> serde_json::Value {
        json!({
            "sub": "subject-123",
            "iss": issuer,
            "aud": aud,
            "exp": now() + 3600,
            "nbf": now() - 10,
            "iat": now() - 10,
            "nonce": nonce,
            "azp": aud,
            "preferred_username": "alice@example.com",
            "email": "alice@example.com",
            "name": "Alice Example",
            "roles": ["forge-admins"],
        })
    }

    /// GitHub/GitLab-shaped workload claims: no nonce or interactive-client
    /// claims, but a unique token id and a short, bounded lifetime.
    fn workload_claims(issuer: &str, aud: &str) -> serde_json::Value {
        json!({
            "sub": "repo:acme/widgets:ref:refs/heads/main",
            "iss": issuer,
            "aud": aud,
            "exp": now() + 600,
            "nbf": now() - 10,
            "iat": now() - 10,
            "jti": "8c11c3fb-0f5d-4b4c-bdf1-4c8dcad3b091",
            "repository": "acme/widgets",
            "ref": "refs/heads/main",
        })
    }

    /// Build a discovery document JSON pointing JWKS/token/authorize at `base`.
    /// `iss` is what the document advertises (host must match for SSRF sanity).
    fn discovery_json(issuer: &str, base: &str) -> serde_json::Value {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
            "end_session_endpoint": format!("{base}/logout"),
        })
    }

    /// L1-only cache + a plain (non-SSRF) reqwest client. The mock runs on
    /// loopback, which the SSRF guard would (correctly) refuse — but SSRF is
    /// covered by `net::ssrf` tests; here we exercise the verifier/cache logic.
    fn client_for(issuer: &str, server: &MockServer) -> OidcMetadataClient {
        let _ = server;
        OidcMetadataClient::new(
            issuer.to_string(),
            reqwest::Client::new(),
            Cache::l1_only(64),
        )
    }

    #[tokio::test]
    async fn discovery_and_jwks_are_cached() {
        let server = MockServer::start().await;
        let issuer = server.uri(); // host == loopback; the doc echoes it.
        let signer = TestSigner::new("k1");

        let disco_hits = Arc::new(AtomicUsize::new(0));
        let jwks_hits = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(CountingJson {
                body: discovery_json(&issuer, &issuer),
                hits: disco_hits.clone(),
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(CountingJson {
                body: json!({ "keys": [signer.jwk] }),
                hits: jwks_hits.clone(),
            })
            .mount(&server)
            .await;

        let client = client_for(&issuer, &server);

        // First call fetches both; second call serves from L1.
        let d1 = client.discovery().await.expect("discovery 1");
        assert_eq!(d1.issuer, issuer);
        let _ = client.jwks().await.expect("jwks 1");
        let _ = client.discovery().await.expect("discovery 2");
        let _ = client.jwks().await.expect("jwks 2");

        assert_eq!(disco_hits.load(Ordering::SeqCst), 1, "discovery cached");
        assert_eq!(jwks_hits.load(Ordering::SeqCst), 1, "jwks cached");
    }

    #[tokio::test]
    async fn workload_verification_accepts_github_style_minimal_discovery() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("github-actions-key");
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "jwks_uri": format!("{issuer}/jwks"),
                "subject_types_supported": ["public", "pairwise"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [signer.jwk] })))
            .mount(&server)
            .await;

        let token = signer.sign(&workload_claims(&issuer, "forge-ci"));
        let verified = client_for(&issuer, &server)
            .verify_workload_jwt(&token, &["forge-ci"], &[], 60, 3600)
            .await
            .expect("GitHub-style workload discovery must be sufficient");
        assert_eq!(verified.subject, "repo:acme/widgets:ref:refs/heads/main");
        assert_eq!(
            verified.claims.additional.get("repository"),
            Some(&json!("acme/widgets"))
        );
    }

    #[tokio::test]
    async fn interactive_discovery_still_requires_browser_flow_endpoints() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "jwks_uri": format!("{issuer}/jwks"),
            })))
            .mount(&server)
            .await;

        let err = client_for(&issuer, &server)
            .discovery()
            .await
            .expect_err("interactive OIDC must still require authorize/token endpoints");
        assert!(matches!(err, OidcError::Parse { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn workload_discovery_rejects_oversized_document() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_DOC_BYTES + 1]))
            .mount(&server)
            .await;

        let err = client_for(&issuer, &server)
            .workload_discovery()
            .await
            .expect_err("metadata over one MiB must be rejected before full buffering");
        assert!(matches!(err, OidcError::Parse { .. }), "got {err:?}");
        assert!(err.is_unavailable(), "no verdict on any token: {err:?}");
    }

    #[tokio::test]
    async fn workload_discovery_obeys_request_timeout() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(250))
                    .set_body_json(json!({
                        "issuer": issuer,
                        "jwks_uri": format!("{issuer}/jwks"),
                    })),
            )
            .mount(&server)
            .await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let client = OidcMetadataClient::new(issuer, http, Cache::l1_only(8));

        let err = client
            .workload_discovery()
            .await
            .expect_err("slow metadata response must honor the client deadline");
        assert!(matches!(err, OidcError::Http { .. }), "got {err:?}");
        assert!(err.is_unavailable(), "no verdict on any token: {err:?}");
    }

    #[tokio::test]
    async fn an_unreachable_jwks_is_unavailable_not_a_verdict_on_the_token() {
        // Discovery answers, the JWKS endpoint fails with a 5xx, and nothing
        // is cached: the token could not be checked, which callers must tell
        // apart from a token that failed its check.
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(discovery_json(&issuer, &issuer)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let token = signer.sign(&workload_claims(&issuer, "forge-ci"));
        let err = client_for(&issuer, &server)
            .verify_workload_jwt(&token, &["forge-ci"], &[], 60, 3600)
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::Http { .. }), "got {err:?}");
        assert!(err.is_unavailable());
    }

    #[tokio::test]
    async fn workload_verification_requires_kid() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("only-key");
        mount_discovery_and_jwks(&server, &issuer, &[&signer]).await;

        let token = signer.sign_without_kid(&workload_claims(&issuer, "forge-ci"));
        let err = client_for(&issuer, &server)
            .verify_workload_jwt(&token, &["forge-ci"], &[], 60, 3600)
            .await
            .expect_err("workload tokens without kid must be rejected");
        assert_eq!(err, OidcError::UnknownKid(None));
    }

    #[tokio::test]
    async fn workload_verification_bounds_issued_at_and_lifetime() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");
        mount_discovery_and_jwks(&server, &issuer, &[&signer]).await;
        let client = client_for(&issuer, &server);

        let mut future = workload_claims(&issuer, "forge-ci");
        future["iat"] = json!(now() + 600);
        future["nbf"] = json!(now() - 10);
        let err = client
            .verify_workload_jwt(&signer.sign(&future), &["forge-ci"], &[], 60, 3600)
            .await
            .expect_err("far-future iat must be rejected");
        assert!(matches!(err, OidcError::InvalidToken(_)), "got {err:?}");

        let mut stale = workload_claims(&issuer, "forge-ci");
        stale["iat"] = json!(now() - 7200);
        stale["nbf"] = json!(now() - 7200);
        stale["exp"] = json!(now() + 300);
        let err = client
            .verify_workload_jwt(&signer.sign(&stale), &["forge-ci"], &[], 60, 3600)
            .await
            .expect_err("over-age token must be rejected even when exp is future");
        assert!(matches!(err, OidcError::InvalidToken(_)), "got {err:?}");

        let mut overlong = workload_claims(&issuer, "forge-ci");
        overlong["exp"] = json!(now() + 7200);
        let err = client
            .verify_workload_jwt(&signer.sign(&overlong), &["forge-ci"], &[], 60, 3600)
            .await
            .expect_err("token lifetime must not exceed the configured maximum");
        assert!(matches!(err, OidcError::InvalidToken(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn verifies_a_valid_self_signed_token() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");
        mount_discovery_and_jwks(&server, &issuer, &[&signer]).await;

        let client = client_for(&issuer, &server);
        let token = signer.sign(&good_claims(&issuer, "client-abc", "nonce-xyz"));
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("nonce-xyz".into()),
            leeway_seconds: 60,
        };
        let verified = client
            .verify_id_token(&token, &params)
            .await
            .expect("verify");
        assert_eq!(verified.subject, "subject-123");
        assert_eq!(verified.issuer, issuer);
        assert_eq!(
            verified
                .claims
                .additional
                .get("preferred_username")
                .unwrap(),
            "alice@example.com"
        );
        // `roles` flows through for the admin mapping (`claims.rs`).
        assert!(verified.claims.additional.contains_key("roles"));
    }

    #[tokio::test]
    async fn rejects_nonce_mismatch() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");
        mount_discovery_and_jwks(&server, &issuer, &[&signer]).await;

        let client = client_for(&issuer, &server);
        let token = signer.sign(&good_claims(&issuer, "client-abc", "the-real-nonce"));
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("a-different-nonce".into()),
            leeway_seconds: 60,
        };
        let err = client.verify_id_token(&token, &params).await.unwrap_err();
        assert_eq!(err, OidcError::NonceMismatch);
    }

    #[tokio::test]
    async fn rejects_audience_mismatch() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");
        mount_discovery_and_jwks(&server, &issuer, &[&signer]).await;

        let client = client_for(&issuer, &server);
        let token = signer.sign(&good_claims(&issuer, "some-other-client", "nonce-xyz"));
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("nonce-xyz".into()),
            leeway_seconds: 60,
        };
        let err = client.verify_id_token(&token, &params).await.unwrap_err();
        assert!(matches!(err, OidcError::InvalidToken(_)), "got {err:?}");
        assert!(!err.is_unavailable(), "a verdict on the token: {err:?}");
    }

    #[tokio::test]
    async fn rejects_issuer_mismatch() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");
        mount_discovery_and_jwks(&server, &issuer, &[&signer]).await;

        let client = client_for(&issuer, &server);
        // Token claims a different issuer than the configured/expected one.
        let token = signer.sign(&good_claims("https://evil.example/v2.0", "client-abc", "n"));
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("n".into()),
            leeway_seconds: 60,
        };
        let err = client.verify_id_token(&token, &params).await.unwrap_err();
        assert!(matches!(err, OidcError::InvalidToken(_)), "got {err:?}");
    }

    /// Review L7(b): issuers that end in `/` (Auth0: `https://tenant.auth0.com/`)
    /// put that exact string in discovery and in every token's `iss`. They must
    /// validate whether the operator configured the issuer with or without the
    /// slash; the normalized form is only a cache key.
    #[tokio::test]
    async fn trailing_slash_issuer_validates_id_tokens() {
        let server = MockServer::start().await;
        let base = server.uri();
        let idp_issuer = format!("{base}/");
        let signer = TestSigner::new("k1");
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(discovery_json(&idp_issuer, &base)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [signer.jwk] })))
            .mount(&server)
            .await;

        let token = signer.sign(&good_claims(&idp_issuer, "client-abc", "n"));
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("n".into()),
            leeway_seconds: 60,
        };
        for configured in [idp_issuer.clone(), base.clone()] {
            let verified = client_for(&configured, &server)
                .verify_id_token(&token, &params)
                .await
                .unwrap_or_else(|e| panic!("configured {configured:?}: {e}"));
            assert_eq!(
                verified.issuer, idp_issuer,
                "the token's exact issuer is reported"
            );
        }

        // `iss` must still match the discovered issuer exactly: the slash-less
        // spelling is a different string.
        let wrong = signer.sign(&good_claims(&base, "client-abc", "n"));
        let err = client_for(&idp_issuer, &server)
            .verify_id_token(&wrong, &params)
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidToken(_)), "got {err:?}");
    }

    /// Review L7(b), WIF side: the workload verifier shares the same `iss`
    /// check, so a trailing-slash workload issuer validates too.
    #[tokio::test]
    async fn trailing_slash_issuer_validates_workload_tokens() {
        let server = MockServer::start().await;
        let base = server.uri();
        let idp_issuer = format!("{base}/");
        let signer = TestSigner::new("wif-key");
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": idp_issuer,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [signer.jwk] })))
            .mount(&server)
            .await;

        let token = signer.sign(&workload_claims(&idp_issuer, "forge-ci"));
        // WIF realms store the issuer normalized (slash trimmed).
        let verified = client_for(&base, &server)
            .verify_workload_jwt(&token, &["forge-ci"], &[], 60, 3600)
            .await
            .expect("trailing-slash workload issuer validates");
        assert_eq!(verified.issuer, idp_issuer);
    }

    #[tokio::test]
    async fn rejects_expired_token_beyond_skew() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");
        mount_discovery_and_jwks(&server, &issuer, &[&signer]).await;

        let client = client_for(&issuer, &server);
        let mut claims = good_claims(&issuer, "client-abc", "n");
        claims["exp"] = json!(now() - 3600); // expired an hour ago
        let token = signer.sign(&claims);
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("n".into()),
            leeway_seconds: 60,
        };
        let err = client.verify_id_token(&token, &params).await.unwrap_err();
        assert!(matches!(err, OidcError::InvalidToken(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn accepts_token_expired_within_skew() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let signer = TestSigner::new("k1");
        mount_discovery_and_jwks(&server, &issuer, &[&signer]).await;

        let client = client_for(&issuer, &server);
        let mut claims = good_claims(&issuer, "client-abc", "n");
        claims["exp"] = json!(now() - 30); // expired 30s ago, within 120s leeway
        let token = signer.sign(&claims);
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("n".into()),
            leeway_seconds: 120,
        };
        client
            .verify_id_token(&token, &params)
            .await
            .expect("within-skew token accepted");
    }

    #[tokio::test]
    async fn kid_miss_triggers_exactly_one_refetch_then_validates() {
        // The JWKS first serves an OLD key; the token is signed with a NEW key
        // whose kid is absent from the cached set. Verification must force one
        // refetch (the endpoint now serves the new key) and then succeed.
        let server = MockServer::start().await;
        let issuer = server.uri();
        let old = TestSigner::new("old-kid");
        let new = TestSigner::new("new-kid");

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(discovery_json(&issuer, &issuer)),
            )
            .mount(&server)
            .await;

        // JWKS responder: serve [old] until `rotated` flips, then [old,new].
        let jwks_hits = Arc::new(AtomicUsize::new(0));
        let responder = RotatingJwks {
            hits: jwks_hits.clone(),
            old: old.jwk.clone(),
            new: new.jwk.clone(),
        };
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(responder)
            .mount(&server)
            .await;

        let client = client_for(&issuer, &server);
        let token = new.sign(&good_claims(&issuer, "client-abc", "n"));
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("n".into()),
            leeway_seconds: 60,
        };
        let verified = client
            .verify_id_token(&token, &params)
            .await
            .expect("verify after rotation");
        assert_eq!(verified.subject, "subject-123");
        // Exactly two JWKS fetches: the initial (cold) load + one kid-miss
        // refetch. Never more (no retry storm, no advisory lock).
        assert_eq!(
            jwks_hits.load(Ordering::SeqCst),
            2,
            "one cold + one refetch"
        );
    }

    #[tokio::test]
    async fn unknown_kid_without_rotation_fails_after_single_refetch() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let present = TestSigner::new("present-kid");
        let absent = TestSigner::new("absent-kid");

        let jwks_hits = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(discovery_json(&issuer, &issuer)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(CountingJson {
                body: json!({ "keys": [present.jwk] }),
                hits: jwks_hits.clone(),
            })
            .mount(&server)
            .await;

        let client = client_for(&issuer, &server);
        // Signed with a key the JWKS never publishes.
        let token = absent.sign(&good_claims(&issuer, "client-abc", "n"));
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("n".into()),
            leeway_seconds: 60,
        };
        let err = client.verify_id_token(&token, &params).await.unwrap_err();
        assert_eq!(err, OidcError::UnknownKid(Some("absent-kid".into())));
        assert!(!err.is_unavailable(), "a verdict on the token: {err:?}");
        // Cold load + one refetch, then give up — no infinite refetch loop.
        assert_eq!(jwks_hits.load(Ordering::SeqCst), 2);

        // A different attacker-controlled kid during the issuer cooldown must
        // reuse the now-fresh JWKS and fail without another eviction/refetch.
        let another_absent = TestSigner::new("another-random-kid");
        let token = another_absent.sign(&good_claims(&issuer, "client-abc", "n"));
        let err = client.verify_id_token(&token, &params).await.unwrap_err();
        assert_eq!(
            err,
            OidcError::UnknownKid(Some("another-random-kid".into()))
        );
        assert_eq!(
            jwks_hits.load(Ordering::SeqCst),
            2,
            "random kid spray must not refetch once per request"
        );
    }

    #[tokio::test]
    async fn a_failed_kid_miss_refresh_keeps_the_cached_keys() {
        // A token with a made-up kid (no valid signature needed) while the
        // IdP's JWKS endpoint is down must not cost the cached keys: tokens
        // signed with them keep verifying until the endpoint recovers.
        let server = MockServer::start().await;
        let issuer = server.uri();
        let present = TestSigner::new("present-kid");
        let made_up = TestSigner::new("made-up-kid");
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(discovery_json(&issuer, &issuer)),
            )
            .mount(&server)
            .await;
        let jwks_hits = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(FirstThenDown {
                body: json!({ "keys": [present.jwk] }),
                hits: jwks_hits.clone(),
            })
            .mount(&server)
            .await;

        let client = client_for(&issuer, &server);
        let params = VerifyParams {
            audience: "client-abc".into(),
            nonce: Some("n".into()),
            leeway_seconds: 60,
        };
        let good = present.sign(&good_claims(&issuer, "client-abc", "n"));
        client
            .verify_id_token(&good, &params)
            .await
            .expect("cold load");

        let bogus = made_up.sign(&good_claims(&issuer, "client-abc", "n"));
        let err = client.verify_id_token(&bogus, &params).await.unwrap_err();
        assert_eq!(err, OidcError::UnknownKid(Some("made-up-kid".into())));
        // The refresh was tried, and failed.
        assert_eq!(jwks_hits.load(Ordering::SeqCst), 2);

        // The cached keys survived: no fetch needed (the endpoint is down).
        client
            .verify_id_token(&good, &params)
            .await
            .expect("cached key still verifies");
        assert_eq!(jwks_hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn discovery_rejects_issuer_host_mismatch_in_endpoints() {
        // SSRF sanity: an advertised jwks_uri on a different host than the issuer
        // must be rejected even if the doc's `issuer` field matches.
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": "https://attacker.example/jwks",
            })))
            .mount(&server)
            .await;

        let client = client_for(&issuer, &server);
        let err = client.discovery().await.unwrap_err();
        assert!(
            matches!(err, OidcError::DiscoveryMismatch(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn discovery_accepts_endpoints_on_configured_hosts_only() {
        // Google serves its token endpoint and keys on other hosts than the
        // issuer's. The realm names them; nothing else is accepted.
        let issuer = "https://accounts.google.com";
        let doc = DiscoveryDocument {
            issuer: issuer.into(),
            authorization_endpoint: format!("{issuer}/o/oauth2/v2/auth"),
            token_endpoint: "https://oauth2.googleapis.com/token".into(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".into(),
            end_session_endpoint: None,
        };
        assert!(matches!(
            validate_discovery(&doc, issuer, &[]),
            Err(OidcError::DiscoveryMismatch(_))
        ));
        let hosts = vec![
            "oauth2.googleapis.com".to_string(),
            "WWW.googleapis.com".to_string(),
        ];
        assert_eq!(validate_discovery(&doc, issuer, &hosts), Ok(()));
        let mut attacker = doc.clone();
        attacker.jwks_uri = "https://attacker.example/certs".into();
        assert!(validate_discovery(&attacker, issuer, &hosts).is_err());
        let mut http = doc.clone();
        http.token_endpoint = "http://oauth2.googleapis.com/token".into();
        assert!(
            validate_discovery(&http, issuer, &hosts).is_err(),
            "scheme still checked"
        );
    }

    #[tokio::test]
    async fn discovery_rejects_issuer_field_mismatch() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": "https://someone-else.example/v2.0",
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            })))
            .mount(&server)
            .await;

        let client = client_for(&issuer, &server);
        let err = client.discovery().await.unwrap_err();
        assert!(
            matches!(err, OidcError::DiscoveryMismatch(_)),
            "got {err:?}"
        );
    }

    // ── helpers ──────────────────────────────────────────────────────────

    /// Mount a fixed discovery doc + a JWKS containing all `signers`' public keys.
    async fn mount_discovery_and_jwks(server: &MockServer, issuer: &str, signers: &[&TestSigner]) {
        let keys: Vec<serde_json::Value> = signers.iter().map(|s| s.jwk.clone()).collect();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery_json(issuer, issuer)))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": keys })))
            .mount(server)
            .await;
    }

    /// JWKS responder that serves `[old]` on the first hit and `[old, new]`
    /// afterwards — simulating an IdP that rolled in a new signing key.
    #[derive(Clone)]
    /// Serves `body` once, then answers 503 (an IdP outage).
    struct FirstThenDown {
        body: serde_json::Value,
        hits: Arc<AtomicUsize>,
    }
    impl Respond for FirstThenDown {
        fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
            if self.hits.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(self.body.clone())
            } else {
                ResponseTemplate::new(503)
            }
        }
    }

    struct RotatingJwks {
        hits: Arc<AtomicUsize>,
        old: serde_json::Value,
        new: serde_json::Value,
    }
    impl Respond for RotatingJwks {
        fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
            let n = self.hits.fetch_add(1, Ordering::SeqCst);
            let keys = if n == 0 {
                vec![self.old.clone()]
            } else {
                vec![self.old.clone(), self.new.clone()]
            };
            ResponseTemplate::new(200).set_body_json(json!({ "keys": keys }))
        }
    }
}
