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
//! * any other status / a network error / a timeout ⇒ **unavailable**
//!   ([`AuthOutcome::Unavailable`]) — **fail-closed**, never granting and never
//!   cached.
//!
//! ## Why this is safe on the hot path
//!
//! NuGet clients send Basic credentials on *every* request. This provider never
//! forwards unconditionally: it goes through the [`ValidatedCredentialCache`]
//! ([`super::cred_cache`]), so the steady state of a repeated credential is a
//! cache hit (L1 → L2 → Postgres) and the upstream is hit at most once per
//! credential per TTL window per cluster (the cache's ROW-lock singleflight —
//! **no `pg_advisory_*`**). The plaintext password leaves the process only here,
//! over the outbound `Authorization: Basic` header; it is never persisted.
//!
//! ## Outbound guard
//!
//! The outbound request uses [`crate::net::ssrf::outbound_client`]: the scheme
//! is restricted to http/https (pre-validated at config time via
//! [`crate::net::ssrf::validate_url`]) and redirects are capped. Private /
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
    let mut cur = body;
    for segment in path.split('.').filter(|s| !s.is_empty()) {
        match cur.get(segment) {
            Some(next) => cur = next,
            None => return Vec::new(),
        }
    }
    match cur {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
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
    /// Connect timeout.
    pub connect_timeout: Duration,
    /// Total request timeout.
    pub request_timeout: Duration,
    /// Optional coarse allow-gate: a 200 is only accepted when the user has at
    /// least one of these groups. Empty ⇒ any success is accepted. Requires
    /// `groups_path` to be set (validated at config time).
    pub required_groups: Vec<String>,
    /// `.`-separated path into the JSON body locating the user's groups (see
    /// [`extract_groups`]). Empty ⇒ no group data parsed.
    pub groups_path: String,
    /// Optional upstream group that maps to forge admin on provision (grant
    /// only, never revoke — see chain provisioning). Empty ⇒ never suggests
    /// admin.
    pub admin_group: String,
}

/// Credential-forwarding authentication as an [`AuthProvider`].
///
/// Holds a redirect-capped [`reqwest::Client`] (built once) and the
/// [`ValidatedCredentialCache`] so the hot path is a cache hit.
pub struct UpstreamBasicProvider {
    config: UpstreamBasicConfig,
    client: Client,
    cache: ValidatedCredentialCache,
}

impl UpstreamBasicProvider {
    /// Build the provider from its config, a pre-built outbound client
    /// ([`crate::net::ssrf::outbound_client`]), and the validated-credential
    /// cache. Keeping client construction out of here lets tests inject a
    /// client pointed at an in-process mock upstream.
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

        if self.config.success_status.contains(&status) {
            // Parse groups only if a path is configured (cheap no-op otherwise).
            let groups = if self.config.groups_path.is_empty() {
                Vec::new()
            } else {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => extract_groups(&body, &self.config.groups_path),
                    Err(e) => {
                        // A success status but an unparseable body: if a group
                        // gate is required we cannot evaluate it, so fail closed
                        // rather than silently granting. With no required groups
                        // the empty list is harmless.
                        tracing::warn!(error = %e, "upstream-basic: success body parse failed");
                        if !self.config.required_groups.is_empty() {
                            return ForwardResult {
                                verdict: UpstreamVerdict::Unavailable,
                                groups: Vec::new(),
                            };
                        }
                        Vec::new()
                    }
                }
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

        // Any other status (5xx, unexpected 2xx/3xx, etc.) is an outage from our
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
    fn id(&self) -> &'static str {
        UPSTREAM_BASIC_ID
    }

    fn source(&self) -> AuthSource {
        AuthSource::UpstreamBasic
    }

    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome {
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
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let captured_factory = captured.clone();

        let result = self
            .cache
            .check(self.id(), cred.username, cred.password, || async move {
                let r = self.forward(&username, &password).await;
                *captured_factory.lock().expect("groups mutex not poisoned") = r.groups;
                r.verdict
            })
            .await;

        match result {
            Ok(true) => {
                let groups =
                    std::mem::take(&mut *captured.lock().expect("groups mutex not poisoned"));
                let suggested_is_admin = !self.config.admin_group.is_empty()
                    && groups.iter().any(|g| g == &self.config.admin_group);
                AuthOutcome::Authenticated(ProvenIdentity {
                    username: cred.username.to_string(),
                    source: AuthSource::UpstreamBasic,
                    external_subject: Some(cred.username.to_string()),
                    groups,
                    suggested_is_admin,
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
    fn extract_groups_top_level_array() {
        let body = serde_json::json!(["x", "y"]);
        // An empty path segment list points at the root.
        assert_eq!(
            extract_groups(&body, ""),
            vec!["x".to_string(), "y".to_string()]
        );
    }
}
