//! SSRF guard for outbound requests (spec §A9).
//!
//! The proxy repository fetches arbitrary upstream URLs configured by an admin.
//! Without protection, an attacker who can set `remote_url` (or influence a
//! redirect) could make the server connect to internal services
//! (`169.254.169.254`, `localhost:6379`, RFC1918 hosts, …). This module guards
//! against that.
//!
//! ## Design (defense against DNS rebinding / TOCTOU)
//! We never let reqwest do its own DNS. Instead we install a custom
//! [`reqwest::dns::Resolve`] ([`GuardedResolver`]) that:
//!   1. resolves the host **once** via an injectable [`IpResolver`],
//!   2. validates **every** resolved IP against the private-range policy, and
//!   3. hands reqwest only the validated [`SocketAddr`]s — so the connection is
//!      pinned to exactly the IPs we checked.
//!
//! Because reqwest resolves through this same resolver on **every** redirect
//! hop, each hop is re-validated automatically; an upstream cannot redirect us
//! to an internal address. We additionally cap the redirect count.
//!
//! [`validate_url`] is the synchronous pre-flight (scheme + host resolution +
//! IP policy) used by the admin API to reject a bad `remote_url` at config
//! time, before any request is ever made.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use url::Url;

/// Reasons a URL is rejected by the SSRF guard.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SsrfError {
    /// Scheme was not `http` or `https`.
    #[error("disallowed url scheme {0:?} (only http/https permitted)")]
    BadScheme(String),
    /// The URL had no host component.
    #[error("url has no host")]
    NoHost,
    /// DNS resolution produced no addresses.
    #[error("host {0:?} did not resolve to any address")]
    NoAddresses(String),
    /// A resolved (or literal) address is in a blocked range.
    #[error("address {0} is in a blocked (private/loopback/link-local) range")]
    BlockedAddress(IpAddr),
    /// DNS resolution failed.
    #[error("dns resolution failed for {host:?}: {reason}")]
    ResolutionFailed {
        /// The host we tried to resolve.
        host: String,
        /// Human-readable cause.
        reason: String,
    },
}

/// Whether an IP is in a range we must never connect to (unless explicitly
/// allowed via `allow_private`).
///
/// Covers loopback, link-local, private/ULA, unspecified, broadcast,
/// documentation, the v4 cloud-metadata pin, and IPv4-mapped IPv6.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped / -compatible addresses and re-check as v4.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(mapped);
            }
            if let Some(compat) = v6.to_ipv4() {
                return is_blocked_v4(compat);
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // Carrier-grade NAT (RFC 6598) — not flagged by std helpers.
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64)
        // 0.0.0.0/8 "this host on this network".
        || ip.octets()[0] == 0
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // Unique-local fc00::/7.
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        // Link-local fe80::/10.
        || (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Asynchronous host → IPs resolver, injectable so tests don't hit real DNS.
#[async_trait::async_trait]
pub trait IpResolver: Send + Sync {
    /// Resolve `host` to zero or more IP addresses.
    async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

/// Default resolver backed by the OS resolver (`tokio::net::lookup_host`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

#[async_trait::async_trait]
impl IpResolver for SystemResolver {
    async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        // A literal IP short-circuits DNS.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        // `lookup_host` needs a port; use a placeholder and discard it.
        let addrs = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|e| e.to_string())?;
        Ok(addrs.map(|sa| sa.ip()).collect())
    }
}

/// Validate a URL's scheme and resolve+check its host IPs.
///
/// On success returns the validated IPs (useful for pinning). When
/// `allow_private` is `true`, the IP-range check is skipped (but the scheme and
/// resolvability checks still apply).
pub async fn validate_url<R: IpResolver + ?Sized>(
    url: &str,
    allow_private: bool,
    resolver: &R,
) -> Result<Vec<IpAddr>, SsrfError> {
    let parsed = Url::parse(url).map_err(|_| SsrfError::NoHost)?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(SsrfError::BadScheme(other.to_string())),
    }

    let host = parsed.host_str().ok_or(SsrfError::NoHost)?;
    // url percent-encodes some hosts; for IP-literal and DNS hosts this is the
    // bare host. IPv6 literals arrive bracket-free from `host_str`.
    let ips = resolver
        .resolve_host(host)
        .await
        .map_err(|reason| SsrfError::ResolutionFailed {
            host: host.to_string(),
            reason,
        })?;

    if ips.is_empty() {
        return Err(SsrfError::NoAddresses(host.to_string()));
    }

    if !allow_private {
        for ip in &ips {
            if is_blocked_ip(*ip) {
                return Err(SsrfError::BlockedAddress(*ip));
            }
        }
    }

    Ok(ips)
}

/// A [`reqwest::dns::Resolve`] that validates every resolved address against
/// the SSRF policy and pins reqwest to those exact IPs.
///
/// Installed on the client returned by [`guarded_client`]. Because reqwest
/// resolves through this on each redirect hop, every hop is re-validated.
pub struct GuardedResolver {
    inner: Arc<dyn IpResolver>,
    allow_private: bool,
}

impl GuardedResolver {
    /// Build a resolver wrapping `inner`, blocking private ranges unless
    /// `allow_private`.
    pub fn new(inner: Arc<dyn IpResolver>, allow_private: bool) -> Self {
        Self {
            inner,
            allow_private,
        }
    }
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let inner = self.inner.clone();
        let allow_private = self.allow_private;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let ips = inner.resolve_host(&host).await.map_err(|e| {
                Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "ssrf resolver: dns failed for {host:?}: {e}"
                ))
            })?;
            if ips.is_empty() {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "ssrf resolver: no addresses for {host:?}"
                )));
            }
            if !allow_private {
                for ip in &ips {
                    if is_blocked_ip(*ip) {
                        return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                            "ssrf resolver: blocked address {ip} for {host:?}"
                        )));
                    }
                }
            }
            // Port 0 — reqwest overrides it with the URL/scheme port.
            let addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect();
            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Build a reqwest client that re-validates every hop against the SSRF policy.
///
/// The custom resolver pins each connection (and each redirect hop) to
/// validated IPs; the redirect policy additionally caps the hop count so a
/// redirect loop cannot run forever.
pub fn guarded_client(
    resolver: Arc<dyn IpResolver>,
    allow_private: bool,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(GuardedResolver::new(resolver, allow_private)))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::dns::Resolve;
    use std::collections::HashMap;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A fake resolver mapping hostnames to fixed IPs (and literals to self).
    struct FakeResolver(HashMap<String, Vec<IpAddr>>);

    #[async_trait::async_trait]
    impl IpResolver for FakeResolver {
        async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            if let Ok(literal) = host.parse::<IpAddr>() {
                return Ok(vec![literal]);
            }
            self.0
                .get(host)
                .cloned()
                .ok_or_else(|| format!("no mapping for {host}"))
        }
    }

    fn fake(pairs: &[(&str, &[&str])]) -> FakeResolver {
        let mut m = HashMap::new();
        for (h, ips) in pairs {
            m.insert(h.to_string(), ips.iter().map(|s| ip(s)).collect::<Vec<_>>());
        }
        FakeResolver(m)
    }

    // ── is_blocked_ip classification ─────────────────────────────────────

    #[test]
    fn blocks_private_and_loopback_and_metadata() {
        assert!(is_blocked_ip(ip("127.0.0.1")));
        assert!(is_blocked_ip(ip("10.1.2.3")));
        assert!(is_blocked_ip(ip("172.16.5.5")));
        assert!(is_blocked_ip(ip("192.168.0.1")));
        assert!(is_blocked_ip(ip("169.254.169.254"))); // cloud metadata
        assert!(is_blocked_ip(ip("100.64.0.1"))); // CGNAT
        assert!(is_blocked_ip(ip("0.0.0.0")));
        assert!(is_blocked_ip(ip("::1")));
        assert!(is_blocked_ip(ip("fc00::1")));
        assert!(is_blocked_ip(ip("fe80::1")));
        assert!(is_blocked_ip(ip("::ffff:10.0.0.1"))); // v4-mapped private
    }

    #[test]
    fn allows_public_addresses() {
        assert!(!is_blocked_ip(ip("8.8.8.8")));
        assert!(!is_blocked_ip(ip("1.1.1.1")));
        assert!(!is_blocked_ip(ip("93.184.216.34")));
        assert!(!is_blocked_ip(ip("2606:4700:4700::1111")));
    }

    // ── validate_url ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let r = fake(&[]);
        let err = validate_url("file:///etc/passwd", false, &r)
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::BadScheme(_)));
        let err = validate_url("ftp://example.com/x", false, &r)
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::BadScheme(_)));
    }

    #[tokio::test]
    async fn rejects_private_resolved_ip() {
        let r = fake(&[("evil.example", &["10.0.0.5"])]);
        let err = validate_url("https://evil.example/feed", false, &r)
            .await
            .unwrap_err();
        assert_eq!(err, SsrfError::BlockedAddress(ip("10.0.0.5")));
    }

    #[tokio::test]
    async fn rejects_loopback_literal() {
        let r = fake(&[]);
        let err = validate_url("http://127.0.0.1:6379/", false, &r)
            .await
            .unwrap_err();
        assert_eq!(err, SsrfError::BlockedAddress(ip("127.0.0.1")));
    }

    #[tokio::test]
    async fn accepts_public_resolved_ip() {
        let r = fake(&[("nuget.example", &["93.184.216.34"])]);
        let ips = validate_url("https://nuget.example/v3/index.json", false, &r)
            .await
            .unwrap();
        assert_eq!(ips, vec![ip("93.184.216.34")]);
    }

    #[tokio::test]
    async fn allow_private_bypasses_ip_check() {
        let r = fake(&[("internal.example", &["10.0.0.5"])]);
        let ips = validate_url("https://internal.example/feed", true, &r)
            .await
            .unwrap();
        assert_eq!(ips, vec![ip("10.0.0.5")]);
    }

    #[tokio::test]
    async fn one_blocked_among_many_rejects() {
        // A host resolving to a public AND a private IP must be rejected:
        // an attacker could otherwise force the private one.
        let r = fake(&[("rebind.example", &["93.184.216.34", "169.254.169.254"])]);
        let err = validate_url("https://rebind.example/", false, &r)
            .await
            .unwrap_err();
        assert_eq!(err, SsrfError::BlockedAddress(ip("169.254.169.254")));
    }

    // ── GuardedResolver (what reqwest sees on each hop) ───────────────────

    #[tokio::test]
    async fn guarded_resolver_rejects_blocked_hop() {
        // Simulates a redirect hop resolving to an internal address: reqwest
        // calls `resolve` for the new host, and we refuse it.
        let r: Arc<dyn IpResolver> = Arc::new(fake(&[("redirect-target.internal", &["10.0.0.9"])]));
        let guard = GuardedResolver::new(r, false);
        let name: reqwest::dns::Name = "redirect-target.internal".parse().unwrap();
        let res = guard.resolve(name).await;
        assert!(res.is_err(), "blocked hop must fail resolution");
    }

    #[tokio::test]
    async fn guarded_resolver_passes_public_hop() {
        let r: Arc<dyn IpResolver> = Arc::new(fake(&[("cdn.example", &["93.184.216.34"])]));
        let guard = GuardedResolver::new(r, false);
        let name: reqwest::dns::Name = "cdn.example".parse().unwrap();
        let addrs = guard.resolve(name).await.expect("public hop ok");
        let collected: Vec<_> = addrs.collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].ip(), ip("93.184.216.34"));
    }

    #[test]
    fn guarded_client_builds() {
        let r: Arc<dyn IpResolver> = Arc::new(fake(&[]));
        assert!(guarded_client(r, false).is_ok());
    }
}
