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
//! * [`outbound_metadata_client`] — the OIDC discovery/JWKS/token client: no
//!   redirects, https only (unless a realm allows a development http issuer),
//!   hard deadlines. It is **not** an IP-range guard.
//! * [`credential_forward_client`] — the credential-forwarding client, which
//!   follows **no** redirects at all: a forwarded password must be judged by
//!   the configured endpoint's own answer, never by wherever it bounces to.
//!
//! Operators should know: an admin-configured upstream URL can point anywhere,
//! including cloud-metadata or other internal addresses, and the
//! credential-forwarding realm sends a user's password to its configured
//! upstream. The admin surface logs the configured host on save for that
//! reason.

use std::time::Duration;

use url::Url;

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

/// Build the client used for **credential forwarding** (the
/// `credential_forwarding` realm / `upstream-basic` provider).
///
/// It never follows a redirect
/// (`redirect::Policy::none()`): an upstream behind SSO commonly answers bad
/// credentials with a 302 to a login page that itself returns 200, and judging
/// the *final* status would turn every password into a valid one. The caller
/// sees the 3xx itself and must treat it as unavailable (fail closed). Not
/// following redirects also keeps the user's `Authorization` header from being
/// replayed to a second URL. `connect_timeout` bounds connection setup; the
/// caller adds a per-request total deadline.
pub fn credential_forward_client(
    connect_timeout: Duration,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout)
        .read_timeout(DEFAULT_READ_TIMEOUT)
        .build()
}

/// Build the stricter client used for OIDC discovery, JWKS, and token-endpoint
/// traffic. A matching-issuer JWT can trigger these calls on a cold cache, so
/// both connection establishment and the full response need hard deadlines
/// rather than occupying an auth request indefinitely.
///
/// It never follows a redirect: the token request carries the client secret,
/// the authorization code and the PKCE verifier in its body, which a 307/308
/// would replay to wherever the redirect points, and key material must come
/// from the issuer's own endpoints. Unless `allow_http` (a realm explicitly
/// configured for a plain-http development IdP), every request — including
/// the endpoints a discovery document names — must use https.
pub fn outbound_metadata_client(allow_http: bool) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!allow_http)
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

    #[tokio::test]
    async fn metadata_client_follows_no_redirect_and_is_https_only() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/elsewhere", server.uri())),
            )
            .mount(&server)
            .await;
        Mock::given(path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        // A development realm may use http, but a redirect is never followed
        // (a token request's body carries the client secret).
        let dev = outbound_metadata_client(true).unwrap();
        let resp = dev
            .post(format!("{}/token", server.uri()))
            .form(&[("client_secret", "s3cret")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 307);
        // Any other realm refuses plain http outright.
        let strict = outbound_metadata_client(false).unwrap();
        assert!(strict
            .get(format!("{}/token", server.uri()))
            .send()
            .await
            .is_err());
    }

    #[test]
    fn outbound_client_builds() {
        assert!(outbound_metadata_client(false).is_ok());
        assert!(outbound_metadata_client(true).is_ok());
        assert!(credential_forward_client(Duration::from_secs(2)).is_ok());
    }
}
