//! Client-IP resolution and the anonymous-access policy.
//!
//! Two concerns live here:
//!
//! 1. [`resolve_client_ip`] — derive the *real* client IP from the socket peer
//!    and a possibly-spoofed `X-Forwarded-For` header, honoring a configured
//!    list of trusted proxy CIDRs.
//! 2. [`AnonPolicy`] — decide whether an unauthenticated request from a given
//!    client IP may be served anonymously (`off` / `allowlist` / `all`).
//!
//! ## XFF trust model (spec §5)
//! The client IP is the **socket peer** unless the peer is itself a trusted
//! proxy. When the peer is trusted, we walk `X-Forwarded-For` **right-to-left**,
//! dropping trusted hops, and take the first untrusted address. A malformed XFF
//! (any unparsable entry we reach) collapses to the peer. We never trust XFF
//! from an untrusted peer.
//!
//! A request may carry several `X-Forwarded-For` header lines (a proxy may add
//! its hop as a new line rather than extending the one the client sent);
//! [`forwarded_for`] joins them in order so the walk sees every hop. Reading
//! only the first line would hand the client-written line to the walk and let
//! it pick its own address.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, as a dual-stack listener
//! reports IPv4 peers) are canonicalized to plain IPv4 before every CIDR check
//! — the peer, each parsed hop, and the anonymous allowlist — so they match
//! IPv4 CIDRs.

use std::net::IpAddr;

use http::HeaderMap;
use ipnet::IpNet;

/// Every `X-Forwarded-For` header line of `headers`, in order, joined with
/// `,` — the input [`resolve_client_ip`] expects. `None` when there is none.
///
/// A line that is not visible ASCII is kept as an unparsable hop, so the walk
/// treats the header as malformed if it gets that far (and ignores it if an
/// untrusted hop to its right already decided).
pub fn forwarded_for(headers: &HeaderMap) -> Option<String> {
    let mut lines = headers.get_all("x-forwarded-for").iter().peekable();
    lines.peek()?;
    Some(
        lines
            .map(|v| v.to_str().unwrap_or("_"))
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// Resolve the effective client IP.
///
/// * `peer` — the socket peer address (always trustworthy as *a* hop).
/// * `xff` — the combined `X-Forwarded-For` value ([`forwarded_for`]), if
///   present.
/// * `trusted` — CIDRs of proxies we operate / trust to prepend XFF.
///
/// Rules (spec §5):
/// * If `peer` is **not** in `trusted`, return `peer` (ignore XFF entirely —
///   an untrusted peer's XFF is attacker-controlled).
/// * If `peer` **is** trusted, split XFF on commas and walk **right-to-left**,
///   skipping addresses that are themselves trusted; the first untrusted,
///   parseable address wins.
/// * If we exhaust XFF (all hops trusted, or it is empty/absent) → `peer`.
/// * If we encounter a non-empty but **unparseable** hop before finding an
///   untrusted address → treat as malformed → `peer`.
///
/// The peer and every hop are canonicalized (IPv4-mapped IPv6 → IPv4) before
/// the CIDR checks, and the returned address is canonical too.
pub fn resolve_client_ip(peer: IpAddr, xff: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    if !ip_in_any(peer, trusted) {
        return peer;
    }

    let Some(xff) = xff else {
        return peer;
    };

    // Walk right-to-left. The right-most entry is the hop closest to us.
    for raw in xff.split(',').rev() {
        let entry = raw.trim();
        if entry.is_empty() {
            // An empty segment is malformed; stop and fall back to peer.
            return peer;
        }
        match entry.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
            Ok(ip) => {
                if ip_in_any(ip, trusted) {
                    // Another trusted hop; keep walking left.
                    continue;
                }
                // First untrusted, parseable address: this is the client.
                return ip;
            }
            Err(_) => {
                // Malformed hop → treat the whole XFF as untrustworthy.
                return peer;
            }
        }
    }

    // All hops were trusted (or XFF empty) → the peer is the client.
    peer
}

fn ip_in_any(ip: IpAddr, nets: &[IpNet]) -> bool {
    let ip = ip.to_canonical();
    nets.iter().any(|n| n.contains(&ip))
}

/// The configured anonymous-access policy (`auth.anonymous_mode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnonPolicy {
    /// No anonymous access at all.
    Off,
    /// Anonymous access only for client IPs inside the allowlist.
    Allowlist(Vec<IpNet>),
    /// Anonymous access for every client IP.
    All,
}

impl AnonPolicy {
    /// Whether an unauthenticated request from `ip` may be served anonymously.
    pub fn allows(&self, ip: IpAddr) -> bool {
        match self {
            AnonPolicy::Off => false,
            AnonPolicy::All => true,
            AnonPolicy::Allowlist(nets) => ip_in_any(ip, nets),
        }
    }

    /// Build an [`AnonPolicy::Allowlist`] from configuration tokens.
    ///
    /// Recognised tokens (case-insensitive):
    /// * `loopback` → `127.0.0.0/8`, `::1/128`
    /// * `private`  → RFC1918 + link-local v4 + ULA + link-local v6
    ///   (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`,
    ///   `fc00::/7`, `fe80::/10`)
    /// * `local`    → loopback **+** private
    ///
    /// Any other token is parsed as a CIDR; a bare IP is accepted as a
    /// single-host CIDR (`/32` or `/128`).
    pub fn allowlist_from_tokens<I, S>(tokens: I) -> Result<Self, AllowlistParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut nets: Vec<IpNet> = Vec::new();
        for tok in tokens {
            let tok = tok.as_ref().trim();
            if tok.is_empty() {
                continue;
            }
            match tok.to_ascii_lowercase().as_str() {
                "loopback" => nets.extend(loopback_nets()),
                "private" => nets.extend(private_nets()),
                "local" => {
                    nets.extend(loopback_nets());
                    nets.extend(private_nets());
                }
                _ => nets.push(parse_cidr_or_host(tok)?),
            }
        }
        Ok(AnonPolicy::Allowlist(nets))
    }
}

/// Failure to parse an allowlist token as a CIDR / host.
#[derive(Debug, thiserror::Error)]
#[error("invalid allowlist entry {entry:?}")]
pub struct AllowlistParseError {
    /// The offending token.
    pub entry: String,
}

fn parse_cidr_or_host(tok: &str) -> Result<IpNet, AllowlistParseError> {
    if let Ok(net) = tok.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(ip) = tok.parse::<IpAddr>() {
        // Single host: full-length prefix.
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        // `new` only fails on an out-of-range prefix, which 32/128 never are.
        return IpNet::new(ip, prefix).map_err(|_| AllowlistParseError {
            entry: tok.to_string(),
        });
    }
    Err(AllowlistParseError {
        entry: tok.to_string(),
    })
}

fn loopback_nets() -> Vec<IpNet> {
    ["127.0.0.0/8", "::1/128"]
        .into_iter()
        .map(|s| s.parse().expect("static CIDR"))
        .collect()
}

fn private_nets() -> Vec<IpNet> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    ]
    .into_iter()
    .map(|s| s.parse().expect("static CIDR"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    // ── resolve_client_ip ────────────────────────────────────────────────

    #[test]
    fn untrusted_peer_ignores_xff() {
        let trusted = nets(&["10.0.0.0/8"]);
        // Peer is public, not trusted → XFF is attacker-controlled, ignore it.
        let got = resolve_client_ip(ip("203.0.113.9"), Some("1.2.3.4, 5.6.7.8"), &trusted);
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn trusted_peer_walks_right_to_left_first_untrusted() {
        // Two trusted proxies (10.x) prepended by an untrusted client (198.51.100.5).
        let trusted = nets(&["10.0.0.0/8"]);
        let got = resolve_client_ip(
            ip("10.0.0.1"),
            Some("198.51.100.5, 10.0.0.9, 10.0.0.1"),
            &trusted,
        );
        assert_eq!(got, ip("198.51.100.5"));
    }

    #[test]
    fn trusted_peer_all_hops_trusted_falls_back_to_peer() {
        let trusted = nets(&["10.0.0.0/8"]);
        let got = resolve_client_ip(ip("10.0.0.1"), Some("10.0.0.2, 10.0.0.3"), &trusted);
        assert_eq!(got, ip("10.0.0.1"));
    }

    #[test]
    fn malformed_xff_falls_back_to_peer() {
        let trusted = nets(&["10.0.0.0/8"]);
        let got = resolve_client_ip(ip("10.0.0.1"), Some("not-an-ip"), &trusted);
        assert_eq!(got, ip("10.0.0.1"));
    }

    #[test]
    fn absent_xff_returns_trusted_peer() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), None, &trusted),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ipv6_trusted_peer_walks_xff() {
        let trusted = nets(&["fd00::/8"]);
        let got = resolve_client_ip(ip("fd00::1"), Some("2001:db8::1, fd00::2"), &trusted);
        assert_eq!(got, ip("2001:db8::1"));
    }

    #[test]
    fn every_xff_line_is_walked_in_order() {
        // M12: the client sends its own (spoofed) line; the trusted proxy adds
        // the real client as a second line. Reading only the first line would
        // let the client pick its address.
        let trusted = nets(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "203.0.113.50".parse().unwrap());
        headers.append("x-forwarded-for", "198.51.100.5, 10.0.0.9".parse().unwrap());
        let xff = forwarded_for(&headers);
        assert_eq!(xff.as_deref(), Some("203.0.113.50,198.51.100.5, 10.0.0.9"));
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), xff.as_deref(), &trusted),
            ip("198.51.100.5")
        );
        assert_eq!(forwarded_for(&HeaderMap::new()), None);
    }

    #[test]
    fn unreadable_xff_line_is_malformed_only_when_reached() {
        let trusted = nets(&["10.0.0.0/8"]);
        let opaque = http::HeaderValue::from_bytes(b"\xff\xfe").unwrap();
        // The unreadable line sits left of the decisive untrusted hop: ignored.
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", opaque.clone());
        headers.append("x-forwarded-for", "198.51.100.5".parse().unwrap());
        let xff = forwarded_for(&headers);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), xff.as_deref(), &trusted),
            ip("198.51.100.5")
        );
        // Reached by the walk: malformed → the peer.
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "198.51.100.5".parse().unwrap());
        headers.append("x-forwarded-for", opaque);
        let xff = forwarded_for(&headers);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), xff.as_deref(), &trusted),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ipv4_mapped_addresses_match_ipv4_cidrs() {
        // M12: a dual-stack listener reports IPv4 peers as ::ffff:a.b.c.d.
        let trusted = nets(&["10.0.0.0/8"]);
        // A mapped trusted peer still walks XFF; a mapped hop is canonical.
        assert_eq!(
            resolve_client_ip(
                ip("::ffff:10.0.0.1"),
                Some("::ffff:198.51.100.5, ::ffff:10.0.0.9"),
                &trusted
            ),
            ip("198.51.100.5")
        );
        // A mapped untrusted peer is returned canonical.
        assert_eq!(
            resolve_client_ip(ip("::ffff:203.0.113.9"), Some("1.2.3.4"), &trusted),
            ip("203.0.113.9")
        );
        // The anonymous allowlist matches mapped addresses too.
        let p = AnonPolicy::allowlist_from_tokens(["loopback", "192.168.0.0/16"]).unwrap();
        assert!(p.allows(ip("::ffff:127.0.0.1")));
        assert!(p.allows(ip("::ffff:192.168.1.1")));
        assert!(!p.allows(ip("::ffff:8.8.8.8")));
    }

    // ── AnonPolicy ───────────────────────────────────────────────────────

    #[test]
    fn off_allows_nothing() {
        assert!(!AnonPolicy::Off.allows(ip("127.0.0.1")));
    }

    #[test]
    fn all_allows_everything() {
        assert!(AnonPolicy::All.allows(ip("203.0.113.1")));
        assert!(AnonPolicy::All.allows(ip("::1")));
    }

    #[test]
    fn loopback_token_expands_v4_and_v6() {
        let p = AnonPolicy::allowlist_from_tokens(["loopback"]).unwrap();
        assert!(p.allows(ip("127.0.0.1")));
        assert!(p.allows(ip("127.5.5.5")));
        assert!(p.allows(ip("::1")));
        assert!(!p.allows(ip("10.0.0.1")));
        assert!(!p.allows(ip("203.0.113.1")));
    }

    #[test]
    fn private_token_expands_rfc1918_and_v6_ula_linklocal() {
        let p = AnonPolicy::allowlist_from_tokens(["private"]).unwrap();
        assert!(p.allows(ip("10.1.2.3")));
        assert!(p.allows(ip("172.16.0.1")));
        assert!(p.allows(ip("192.168.1.1")));
        assert!(p.allows(ip("169.254.1.1")));
        assert!(p.allows(ip("fc00::1")));
        assert!(p.allows(ip("fe80::1")));
        // loopback is NOT private
        assert!(!p.allows(ip("127.0.0.1")));
        assert!(!p.allows(ip("::1")));
        assert!(!p.allows(ip("8.8.8.8")));
    }

    #[test]
    fn local_token_is_loopback_plus_private() {
        let p = AnonPolicy::allowlist_from_tokens(["local"]).unwrap();
        assert!(p.allows(ip("127.0.0.1")));
        assert!(p.allows(ip("::1")));
        assert!(p.allows(ip("10.0.0.1")));
        assert!(!p.allows(ip("8.8.8.8")));
    }

    #[test]
    fn explicit_cidr_and_host_tokens() {
        let p = AnonPolicy::allowlist_from_tokens(["203.0.113.0/24", "2001:db8::1"]).unwrap();
        assert!(p.allows(ip("203.0.113.50")));
        assert!(p.allows(ip("2001:db8::1")));
        assert!(!p.allows(ip("203.0.114.1")));
        assert!(!p.allows(ip("2001:db8::2")));
    }

    #[test]
    fn mixed_tokens_combine() {
        let p = AnonPolicy::allowlist_from_tokens(["loopback", "203.0.113.0/24"]).unwrap();
        assert!(p.allows(ip("127.0.0.1")));
        assert!(p.allows(ip("203.0.113.7")));
        assert!(!p.allows(ip("10.0.0.1")));
    }

    #[test]
    fn invalid_token_errors() {
        let err = AnonPolicy::allowlist_from_tokens(["nope"]).unwrap_err();
        assert_eq!(err.entry, "nope");
    }
}
