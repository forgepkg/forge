//! The `upstream-basic` [`AuthProvider`] (slice 12.3, phase 4).
//!
//! Forwards a presented `username:password` to a configured upstream over HTTP
//! Basic — the `github.com/schmitch/verdaccio-nexus-auth-proxy` pattern (for a
//! Nexus, the upstream is typically the status / whoami endpoint). The upstream
//! response decides the verdict:
//!
//! * status ∈ `success_status` (default `[200]`) ⇒ **valid** — optionally gated
//!   by a `required_groups` check parsed from the JSON body;
//! * status ∈ `reject_status` (default `[401, 403]`) ⇒ **rejected**;
//! * any **3xx** ⇒ **unavailable**, whatever the status lists say: redirects
//!   are never followed (an SSO front that 302s bad credentials to a login page
//!   answering 200 would otherwise make every password valid), and a redirect
//!   proves nothing about the credential;
//! * any other status / a network error / a timeout ⇒ **unavailable**
//!   ([`AuthOutcome::Unavailable`]) — **fail-closed**, never granting and never
//!   cached.
//!
//! ## Identity binding
//!
//! Forge maps the login to the account named by the **canonical** username
//! (trimmed, NFC, lowercased — the chain canonicalizes it before this provider
//! runs) and forwards exactly that name, so the upstream verifies the very
//! name Forge will act on. That is only sound when the upstream **binds the
//! username to the secret**. Many do not: a GitHub, Azure DevOps or GitLab
//! personal access token is accepted with *any* username. For such an
//! upstream, set `identity_path`: the name the upstream reports in its JSON
//! response (e.g. `login`) must equal the canonical username, or the
//! credential is rejected. A success without that field is treated as an
//! outage (fail closed).
//!
//! A username containing `:` is rejected without forwarding: HTTP Basic
//! splits at the first colon, so the upstream would verify a different name
//! ([`forge_db::username::canonical_password_username`]).
//!
//! ## Why this is safe on the hot path
//!
//! NuGet clients send Basic credentials on *every* request. This provider never
//! forwards unconditionally: it goes through the [`ValidatedCredentialCache`]
//! ([`super::cred_cache`]), so the steady state of a repeated credential is a
//! cache hit (L1 → L2 → Postgres) and the upstream is hit at most once per
//! credential per TTL window per cluster (the cache's lease singleflight —
//! **no `pg_advisory_*`**, and no database connection held while the upstream
//! answers). The plaintext password leaves the process only here, over the
//! outbound `Authorization: Basic` header; it is never persisted.
//!
//! ## Outbound guard
//!
//! The outbound request uses [`crate::net::ssrf::credential_forward_client`]:
//! the scheme is restricted to http/https (pre-validated at config time via
//! [`crate::net::ssrf::validate_url`]), redirects are **not followed**, and
//! every forward carries the configured total `request_timeout`. Private /
//! loopback upstreams are permitted — the upstream URL is admin-only config
//! (12.7 §3.6), and an internal Nexus on RFC1918 is the common case.
//!
//! ## Auto-provision
//!
//! This provider only *vouches for* a [`ProvenIdentity`] (the username + coarse
//! groups + an admin suggestion). Mapping that to an `app_user` — creating one on
//! first success with `auth_source = 'upstream-basic'` and **no** local password
//! — is the chain caller's job ([`super::chain::provision_and_map`], phase 5), so
//! this file stays free of the DB-provision policy.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use reqwest::Client;

use super::cred_cache::{CredCacheError, UpstreamVerdict, ValidatedCredentialCache};
use super::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential, ProvenIdentity};

/// The stable provider id (matches the config chain spelling + the
/// `app_user.auth_source` value).
pub const UPSTREAM_BASIC_ID: &str = "upstream-basic";

/// Largest success body read for `groups_path` / `identity_path` (1 MiB): a
/// whoami answer is small, and the upstream must not make each login buffer
/// an arbitrary amount.
pub const MAX_SUCCESS_BODY_BYTES: usize = 1024 * 1024;

/// How to read the user's groups/roles from the upstream JSON body.
///
/// Kept deliberately small (plan §6 risk #4: avoid a JSONPath dependency for a
/// status-code-first scheme). A path is a `.`-separated sequence of object keys;
/// the value it points at is interpreted as a list of group strings:
///
/// * a JSON array of strings → those strings;
/// * a single JSON string → a one-element list;
/// * anything else / a missing key → no groups.
///
/// Example: for a body `{"user":{"roles":["nx-admin","dev"]}}`, the path
/// `user.roles` yields `["nx-admin", "dev"]`.
fn extract_groups(body: &serde_json::Value, path: &str) -> Vec<String> {
    let Some(cur) = lookup(body, path) else {
        return Vec::new();
    };
    match cur {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Follow a `.`-separated path of object keys into `body`.
fn lookup<'a>(body: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = body;
    for segment in path.split('.').filter(|s| !s.is_empty()) {
        cur = cur.get(segment)?;
    }
    Some(cur)
}

/// The account name the upstream reports at `path`, canonicalized; `None`
/// when it is absent, not a string, or has no canonical form.
fn extract_identity(body: &serde_json::Value, path: &str) -> Option<String> {
    let name = lookup(body, path)?.as_str()?;
    forge_db::username::canonical_username(name).ok()
}

/// Static configuration for the upstream-basic provider, assembled by the server
/// from the `[auth.upstream_basic]` config block (phase 5). Built once at
/// startup; cheaply cloned into the provider.
#[derive(Debug, Clone)]
pub struct UpstreamBasicConfig {
    /// Upstream endpoint hit with the user's Basic credentials (validated through
    /// the SSRF guard at config time). For a Nexus this is the status/whoami URL.
    pub url: String,
    /// HTTP method (Nexus status is `GET`). Uppercased ASCII verb.
    pub method: String,
    /// Status codes meaning "credentials valid".
    pub success_status: Vec<u16>,
    /// Status codes meaning "definitively rejected" (→ `Rejected`, cached
    /// negative — *not* `Unavailable`).
    pub reject_status: Vec<u16>,
    /// Connect timeout (applied by the caller when it builds the client via
    /// [`crate::net::ssrf::credential_forward_client`]).
    pub connect_timeout: Duration,
    /// Total request timeout (connect + response + body), applied to every
    /// forward.
    pub request_timeout: Duration,
    /// Optional coarse allow-gate: a 200 is only accepted when the user has at
    /// least one of these groups. Empty ⇒ any success is accepted. Requires
    /// `groups_path` to be set (validated at config time).
    pub required_groups: Vec<String>,
    /// `.`-separated path into the JSON body locating the user's groups (see
    /// [`extract_groups`]). Empty ⇒ no group data parsed.
    pub groups_path: String,
    /// `.`-separated path into the JSON success body naming the account the
    /// upstream authenticated (e.g. `login`). When set, that name
    /// (canonicalized) must equal the canonical username presented, or the
    /// credential is rejected. Empty ⇒ the upstream is trusted to bind the
    /// username to the secret (see the [module docs](self)).
    pub identity_path: String,
    /// Optional upstream group that maps to forge admin. When set (with a
    /// `groups_path`), every login that freshly fetched the groups is
    /// authoritative: membership grants admin and its absence revokes it for
    /// `upstream-basic` users (see chain provisioning). Empty ⇒ never suggests
    /// admin and never touches an existing user's admin state.
    pub admin_group: String,
    /// Stable provider id keying the validated-credential cache and logged as
    /// the chain winner. The static-config wiring uses [`UPSTREAM_BASIC_ID`];
    /// realm-driven wiring (12.7) uses a realm-scoped id (`"realm:<name>"`).
    pub provider_id: String,
    /// Auto-provision an `app_user` on first successful upstream login.
    /// Stamped onto every [`ProvenIdentity`] this provider vouches for (the
    /// chain caller acts on it — per-realm since 12.7).
    pub auto_provision: bool,
    /// The `auth_realm.id` this provider was built from, recorded as
    /// provenance on provisioned users. `None` for static-config wiring.
    pub realm_id: Option<i64>,
}

/// Credential-forwarding authentication as an [`AuthProvider`].
///
/// Holds a non-redirecting [`reqwest::Client`] (built once) and the
/// [`ValidatedCredentialCache`] so the hot path is a cache hit.
pub struct UpstreamBasicProvider {
    config: UpstreamBasicConfig,
    client: Client,
    cache: ValidatedCredentialCache,
}

impl UpstreamBasicProvider {
    /// Build the provider from its config, a pre-built outbound client
    /// ([`crate::net::ssrf::credential_forward_client`] — it must not follow
    /// redirects), and the validated-credential cache. Keeping client
    /// construction out of here lets tests inject a client pointed at an
    /// in-process mock upstream.
    pub fn new(
        config: UpstreamBasicConfig,
        client: Client,
        cache: ValidatedCredentialCache,
    ) -> Self {
        Self {
            config,
            client,
            cache,
        }
    }

    /// Forward one credential to the upstream and interpret the response into a
    /// raw [`ForwardResult`]. This is the cache *factory* body — invoked at most
    /// once per credential per TTL window per cluster.
    ///
    /// Returns the verdict plus, on success, the coarse groups parsed from the
    /// body (so the cache can stash them for the provisioning step). A network
    /// error / timeout / unexpected status is `Unavailable` (fail-closed).
    async fn forward(&self, username: &str, password: &str) -> ForwardResult {
        let method = match reqwest::Method::from_bytes(self.config.method.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                tracing::error!(method = %self.config.method, "upstream-basic: invalid HTTP method");
                return ForwardResult {
                    verdict: UpstreamVerdict::Unavailable,
                    groups: Vec::new(),
                };
            }
        };

        // Build the Basic header ourselves so the plaintext is confined to this
        // scope and never logged. `reqwest`'s `basic_auth` would also work but we
        // keep the encoding explicit and auditable.
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));

        let resp = self
            .client
            .request(method, &self.config.url)
            .header(reqwest::header::AUTHORIZATION, format!("Basic {basic}"))
            .header(reqwest::header::ACCEPT, "application/json")
            .timeout(self.config.request_timeout)
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                // Network error / timeout / SSRF-guard refusal / redirect-cap.
                // Never echo credentials; reqwest errors do not carry the header.
                tracing::warn!(error = %e, "upstream-basic: forward request failed (fail-closed)");
                return ForwardResult {
                    verdict: UpstreamVerdict::Unavailable,
                    groups: Vec::new(),
                };
            }
        };

        let status = resp.status().as_u16();

        // A redirect is never a verdict, even if an operator listed a 3xx as a
        // success/reject status: the client does not follow it, and the page
        // it points at (typically an SSO login form answering 200) says
        // nothing about the credential. Fail closed.
        if resp.status().is_redirection() {
            tracing::warn!(
                status,
                location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(""),
                "upstream-basic: upstream answered with a redirect (not followed; treated as unavailable)"
            );
            return ForwardResult {
                verdict: UpstreamVerdict::Unavailable,
                groups: Vec::new(),
            };
        }

        if self.config.success_status.contains(&status) {
            let needs_identity = !self.config.identity_path.is_empty();
            // Parse the body only if a path is configured (cheap no-op otherwise).
            let body = if self.config.groups_path.is_empty() && !needs_identity {
                None
            } else {
                let body = match crate::oidc::jwks::read_capped(resp, MAX_SUCCESS_BODY_BYTES).await
                {
                    Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(format!("{e:?}")),
                };
                match body {
                    Ok(body) => Some(body),
                    Err(e) => {
                        // A success status but an unparseable body: if a group
                        // gate or an identity check is required we cannot
                        // evaluate it, so fail closed rather than silently
                        // granting. With neither, the empty list is harmless.
                        tracing::warn!(error = %e, "upstream-basic: success body parse failed");
                        if needs_identity || !self.config.required_groups.is_empty() {
                            return ForwardResult {
                                verdict: UpstreamVerdict::Unavailable,
                                groups: Vec::new(),
                            };
                        }
                        None
                    }
                }
            };

            if needs_identity {
                let reported = body
                    .as_ref()
                    .and_then(|b| extract_identity(b, &self.config.identity_path));
                match reported {
                    // The secret belongs to the very account Forge maps to.
                    Some(name) if name == username => {}
                    // A valid secret of *another* account (e.g. a personal
                    // access token sent with someone else's username).
                    Some(_) => {
                        tracing::warn!(
                            username = %super::login_throttle::username_for_log(username),
                            "upstream-basic: upstream authenticated a different account; rejected"
                        );
                        return ForwardResult {
                            verdict: UpstreamVerdict::Rejected,
                            groups: Vec::new(),
                        };
                    }
                    None => {
                        tracing::warn!(
                            identity_path = %self.config.identity_path,
                            "upstream-basic: success response names no account at identity_path (fail-closed)"
                        );
                        return ForwardResult {
                            verdict: UpstreamVerdict::Unavailable,
                            groups: Vec::new(),
                        };
                    }
                }
            }

            let groups = match (&body, self.config.groups_path.is_empty()) {
                (Some(body), false) => extract_groups(body, &self.config.groups_path),
                _ => Vec::new(),
            };

            // Coarse allow-gate: when required_groups is set, the user must hold
            // at least one. Failing the gate is a definitive *rejection* (cached
            // negative), not an outage.
            if !self.config.required_groups.is_empty()
                && !self
                    .config
                    .required_groups
                    .iter()
                    .any(|g| groups.iter().any(|u| u == g))
            {
                return ForwardResult {
                    verdict: UpstreamVerdict::Rejected,
                    groups: Vec::new(),
                };
            }

            return ForwardResult {
                verdict: UpstreamVerdict::Valid,
                groups,
            };
        }

        if self.config.reject_status.contains(&status) {
            return ForwardResult {
                verdict: UpstreamVerdict::Rejected,
                groups: Vec::new(),
            };
        }

        // Any other status (5xx, unexpected 2xx, etc.) is an outage from our
        // point of view: fail closed, cache nothing.
        tracing::warn!(
            status,
            "upstream-basic: unexpected status (treated as unavailable)"
        );
        ForwardResult {
            verdict: UpstreamVerdict::Unavailable,
            groups: Vec::new(),
        }
    }
}

/// The raw result of one upstream forward (before it is folded into an
/// [`AuthOutcome`]). `groups` is populated only for a [`UpstreamVerdict::Valid`].
struct ForwardResult {
    verdict: UpstreamVerdict,
    groups: Vec<String>,
}

#[async_trait]
impl AuthProvider for UpstreamBasicProvider {
    fn id(&self) -> &str {
        &self.config.provider_id
    }

    fn source(&self) -> AuthSource {
        AuthSource::UpstreamBasic
    }

    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome {
        // The upstream splits `user:password` at the first colon (RFC 7617),
        // so for `mallory:abc` / `def` it would check `mallory` / `abc:def`
        // while Forge signs in the account `mallory:abc`. Such a name is never
        // forwarded nor answered from the cache. A rejection, not a skip: the
        // chain still lets a later local realm decide, but never falls back to
        // anonymous access.
        if cred.username.contains(':') {
            return AuthOutcome::Rejected;
        }

        // The cache stashes only a boolean verdict (never the groups — they are
        // not security-critical and re-deriving them on a cold cache is cheap and
        // correct). On a cache miss the factory runs `forward`, whose `groups`
        // we capture here for the provisioning identity. Because the factory may
        // be coalesced away (a peer wins the singleflight), `captured_groups`
        // stays empty for the loser; that only means a refreshed login provisions
        // groups, which matches the "coarse, best-effort" contract.
        let username = cred.username.to_string();
        let password = cred.password.to_string();
        // The factory future must be `Send` (moka coalesces it across tasks), so
        // we hand the captured groups out through an `Arc<Mutex<_>>` rather than a
        // `RefCell`. It stays empty when a peer wins the singleflight (the factory
        // never runs locally) — see the note above.
        // `None` until the factory runs locally: distinguishes "fetched, no
        // groups" from "cache hit, groups unknown" for the admin mapping.
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<String>>));
        let captured_factory = captured.clone();

        let result = self
            .cache
            .check(self.id(), cred.username, cred.password, || async move {
                let r = self.forward(&username, &password).await;
                *captured_factory.lock().expect("groups mutex not poisoned") = Some(r.groups);
                r.verdict
            })
            .await;

        match result {
            Ok(true) => {
                let fetched = captured.lock().expect("groups mutex not poisoned").take();
                // An admin group without a groups path can never match; treat
                // it as "no admin mapping" rather than as a standing demotion.
                let admin_mapped =
                    !self.config.admin_group.is_empty() && !self.config.groups_path.is_empty();
                // Admin state is authoritative only when the realm maps an admin
                // group AND this login actually saw the upstream's groups; a
                // cache hit must never demote an upstream admin.
                let admin_authoritative = admin_mapped && fetched.is_some();
                let groups = fetched.unwrap_or_default();
                let suggested_is_admin =
                    admin_mapped && groups.iter().any(|g| g == &self.config.admin_group);
                AuthOutcome::Authenticated(ProvenIdentity {
                    username: cred.username.to_string(),
                    source: AuthSource::UpstreamBasic,
                    external_subject: Some(cred.username.to_string()),
                    groups,
                    suggested_is_admin,
                    admin_authoritative,
                    auto_provision: self.config.auto_provision,
                    realm_id: self.config.realm_id,
                })
            }
            Ok(false) => AuthOutcome::Rejected,
            Err(CredCacheError::Unavailable) => AuthOutcome::Unavailable,
            Err(CredCacheError::Db(e)) => {
                // A store error talking to Postgres is infrastructure: fail
                // closed (deny), never grant.
                tracing::warn!(error = %e, "upstream-basic: credential cache store error (fail-closed)");
                AuthOutcome::Unavailable
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_groups_reads_array() {
        let body = serde_json::json!({ "user": { "roles": ["nx-admin", "dev"] } });
        assert_eq!(
            extract_groups(&body, "user.roles"),
            vec!["nx-admin".to_string(), "dev".to_string()]
        );
    }

    #[test]
    fn extract_groups_reads_single_string() {
        let body = serde_json::json!({ "role": "nx-admin" });
        assert_eq!(extract_groups(&body, "role"), vec!["nx-admin".to_string()]);
    }

    #[test]
    fn extract_groups_missing_path_is_empty() {
        let body = serde_json::json!({ "user": { "name": "alice" } });
        assert!(extract_groups(&body, "user.roles").is_empty());
        assert!(extract_groups(&body, "nope.deep.path").is_empty());
    }

    #[test]
    fn extract_groups_non_string_array_filtered() {
        let body = serde_json::json!({ "roles": ["a", 1, true, "b"] });
        assert_eq!(
            extract_groups(&body, "roles"),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn extract_identity_is_canonical_and_string_only() {
        let body = serde_json::json!({ "user": { "login": " Alice " }, "id": 7 });
        assert_eq!(
            extract_identity(&body, "user.login").as_deref(),
            Some("alice")
        );
        assert_eq!(extract_identity(&body, "id"), None);
        assert_eq!(extract_identity(&body, "user.name"), None);
        assert_eq!(
            extract_identity(&serde_json::json!({ "login": "" }), "login"),
            None
        );
    }

    #[test]
    fn extract_groups_top_level_array() {
        let body = serde_json::json!(["x", "y"]);
        // An empty path segment list points at the root.
        assert_eq!(
            extract_groups(&body, ""),
            vec!["x".to_string(), "y".to_string()]
        );
    }
}
