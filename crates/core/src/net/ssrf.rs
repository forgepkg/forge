//! Outbound-URL scheme guard (12.7 design §3.6 — SSRF restriction dropped).
//!
//! Slice 1 shipped a full SSRF guard here: a custom DNS resolver that blocked
//! private/loopback/link-local ranges on every redirect hop, plus a per-proxy
//! `allow_private_upstream` opt-out. The 12.7 auth-realms design **removes that
//! restriction deliberately**: upstream URLs (proxy `remote_url`, the
//! credential-forwarding IdP, OIDC issuers) are configurable only by admins
//! (RBAC `can_admin`), so the threat model is a trusted/compromised admin — and
//! for that actor the IP-range block was a speed bump, not a boundary, while it
//! made every legitimate internal deployment (Nexus on RFC1918, self-hosted
//! IdPs) need a confusing opt-out flag.
//!
//! What remains, and MUST stay:
//! * [`validate_url`] — the **scheme check**: outbound URLs are `http`/`https`
//!   only (never `file:`, `ftp:`, `gopher:`, …) and must have a host.
//! * [`outbound_client`] — the shared client builder, which caps redirects so a
//!   malicious upstream cannot bounce us through an unbounded redirect chain.
//!
//! Operators should know: an admin-configured upstream URL can point anywhere,
//! including cloud-metadata or other internal addresses, and the
//! credential-forwarding realm sends a user's password to its configured
//! upstream. The admin surface logs the configured host on save for that
//! reason.

use std::time::Duration;

use url::Url;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);
const METADATA_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const METADATA_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Reasons a URL is rejected by the outbound guard.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SsrfError {
    /// Scheme was not `http` or `https`.
    #[error("disallowed url scheme {0:?} (only http/https permitted)")]
    BadScheme(String),
    /// The URL did not parse or had no host component.
    #[error("url has no host")]
    NoHost,
}

/// Validate an outbound URL: it must parse, carry a host, and use `http` or
/// `https`. This is the **only** restriction on admin-configured upstream URLs
/// (12.7 §3.6); private/loopback addresses are permitted.
///
/// Synchronous — no DNS is consulted anymore. Used by the admin API to reject a
/// bad `remote_url` / upstream URL at config time, and by config validation at
/// startup.
pub fn validate_url(url: &str) -> Result<(), SsrfError> {
    let parsed = Url::parse(url).map_err(|_| SsrfError::NoHost)?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(SsrfError::BadScheme(other.to_string())),
    }
    if parsed.host_str().is_none() {
        return Err(SsrfError::NoHost);
    }
    Ok(())
}

/// Build the reqwest client used for outbound upstream traffic (proxy fetch,
/// credential forwarding, OIDC discovery/JWKS/token).
///
/// The redirect policy caps the hop count so a redirect loop cannot run
/// forever; scheme validation happens up front via [`validate_url`] (reqwest
/// itself only follows http/https redirects).
pub fn outbound_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        // Never let a blackholed peer pin a request forever. Callers add a
        // per-request total deadline where they know one (the credential
        // forwarder does); these bounds only cap connect + idle time.
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .read_timeout(DEFAULT_READ_TIMEOUT)
        .build()
}

/// Build the stricter client used for OIDC discovery, JWKS, and token-endpoint
/// metadata traffic. A matching-issuer JWT can trigger these calls on a cold
/// cache, so both connection establishment and the full response need hard
/// deadlines rather than occupying an auth request indefinitely.
pub fn outbound_metadata_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(METADATA_CONNECT_TIMEOUT)
        .timeout(METADATA_REQUEST_TIMEOUT)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_scheme() {
        assert!(matches!(
            validate_url("file:///etc/passwd").unwrap_err(),
            SsrfError::BadScheme(_)
        ));
        assert!(matches!(
            validate_url("ftp://example.com/x").unwrap_err(),
            SsrfError::BadScheme(_)
        ));
        assert!(matches!(
            validate_url("gopher://example.com/").unwrap_err(),
            SsrfError::BadScheme(_)
        ));
    }

    #[test]
    fn rejects_unparseable_and_hostless() {
        assert_eq!(validate_url("not a url").unwrap_err(), SsrfError::NoHost);
        // `unix:` parses as a scheme-only URL with no host — caught by the
        // scheme check first.
        assert!(validate_url("unix:/var/run/x.sock").is_err());
    }

    #[test]
    fn accepts_public_and_private_http_urls() {
        // Public hosts are obviously fine…
        assert!(validate_url("https://api.nuget.org/v3/index.json").is_ok());
        // …and per the 12.7 decision, private/loopback hosts are now equally
        // fine: the IP-range restriction is gone, only the scheme is checked.
        assert!(validate_url("http://127.0.0.1:8081/status").is_ok());
        assert!(validate_url("https://nexus.internal/service/rest/v1/status").is_ok());
        assert!(validate_url("http://169.254.169.254/latest/meta-data").is_ok());
    }

    #[test]
    fn outbound_client_builds() {
        assert!(outbound_client().is_ok());
        assert!(outbound_metadata_client().is_ok());
    }
}
