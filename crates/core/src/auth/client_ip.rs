//! Client-IP resolution: [`resolve_client_ip`] derives the *real* client IP
//! from the socket peer and a possibly-spoofed `X-Forwarded-For` header,
//! honoring a configured list of trusted proxy CIDRs.
//!
//! ## XFF trust model
//! The client IP is the **socket peer** unless the peer is itself a trusted
//! proxy. When the peer is trusted, we walk `X-Forwarded-For` **right-to-left**,
//! dropping trusted hops, and take the first untrusted address. A malformed XFF
//! (an empty or unparsable entry we reach) falls back to the peer's address.
//! We never trust XFF from an untrusted peer.
//!
//! A request may carry several `X-Forwarded-For` header lines (a proxy may add
//! its hop as a new line rather than extending the one the client sent);
//! [`forwarded_for`] joins them in order so the walk sees every hop. Reading
//! only the first line would hand the client-written line to the walk and let
//! it pick its own address. Each hop is decoded on its own: a proxy such as
//! nginx (`$proxy_add_x_forwarded_for`) appends the real client to the line
//! the client sent, so a byte the client wrote must spoil only its own hop,
//! never the one appended to its right.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, as a dual-stack listener
//! reports IPv4 peers) are canonicalized to plain IPv4 before every CIDR check
//! — the peer and each parsed hop — so they match IPv4 CIDRs.

use std::net::IpAddr;

use http::HeaderMap;
use ipnet::IpNet;

/// Every hop of every `X-Forwarded-For` header line of `headers`, in order,
/// joined with `,` — the input [`resolve_client_ip`] expects. `None` when
/// there is none.
///
/// The raw bytes are split at `,` before they are decoded: a hop that is not
/// visible ASCII is kept as an unparsable hop, so the walk treats the header
/// as malformed if it gets that far (and ignores it if an untrusted hop to its
/// right already decided). Decoding a whole line instead would let one byte
/// the client wrote hide the address a proxy appended to the same line.
pub fn forwarded_for(headers: &HeaderMap) -> Option<String> {
    let mut lines = headers.get_all("x-forwarded-for").iter().peekable();
    lines.peek()?;
    Some(
        lines
            .flat_map(|v| v.as_bytes().split(|b| *b == b','))
            .map(|hop| {
                std::str::from_utf8(hop)
                    .ok()
                    .filter(|s| s.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b)))
                    .unwrap_or("_")
            })
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
/// Rules:
/// * If `peer` is **not** in `trusted`, return `peer` (ignore XFF entirely —
///   an untrusted peer's XFF is attacker-controlled).
/// * If `peer` **is** trusted, split XFF on commas and walk **right-to-left**,
///   skipping addresses that are themselves trusted; the first untrusted,
///   parseable address wins.
/// * If we exhaust XFF (all hops trusted, or it is absent) → `peer`.
/// * If we encounter an empty or **unparseable** hop before finding an
///   untrusted address → treat as malformed → `peer`.
///
/// A hop may carry a port (`198.51.100.5:4711`, `[2001:db8::1]:4711`), as
/// some proxies (Azure Application Gateway) write it.
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
        match parse_hop(raw.trim()) {
            Some(ip) => {
                if ip_in_any(ip, trusted) {
                    // Another trusted hop; keep walking left.
                    continue;
                }
                // First untrusted, parseable address: this is the client.
                return ip;
            }
            // Empty or malformed hop → the whole XFF is untrustworthy.
            None => return peer,
        }
    }

    // All hops were trusted → the peer is the client.
    peer
}

/// Whether the socket `peer` is one of the `trusted` proxies (canonicalized
/// like every other check here). What such a proxy says about the client,
/// its `X-Forwarded-For` or the headers a trusted-header realm reads, counts;
/// from any other peer it is the client's own word and is ignored.
pub fn is_trusted_peer(peer: IpAddr, trusted: &[IpNet]) -> bool {
    ip_in_any(peer, trusted)
}

/// One `X-Forwarded-For` hop as a canonical address: a bare address, or one
/// with a port (`a.b.c.d:port`, `[v6]:port`). `None` when it is neither.
fn parse_hop(entry: &str) -> Option<IpAddr> {
    entry
        .parse::<IpAddr>()
        .or_else(|_| entry.parse::<std::net::SocketAddr>().map(|sa| sa.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}

fn ip_in_any(ip: IpAddr, nets: &[IpNet]) -> bool {
    let ip = ip.to_canonical();
    nets.iter().any(|n| n.contains(&ip))
}

/// An IPv4-mapped IPv6 network (`::ffff:a.b.c.d/(96+n)`) as the IPv4 network
/// `a.b.c.d/n`; any other network unchanged. Peer and forwarded addresses are
/// canonicalized (`to_canonical`) before they are matched, so a configured
/// entry in the mapped form — as older logs printed peers on a `[::]` bind —
/// would otherwise never match anything.
pub fn canonical_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net {
        if let (Some(v4), true) = (v6.addr().to_ipv4_mapped(), v6.prefix_len() >= 96) {
            if let Ok(mapped) = ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96) {
                return IpNet::V4(mapped.trunc());
            }
        }
    }
    net
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

    #[test]
    fn trusted_peers_are_the_listed_proxies_mapped_ones_included() {
        let trusted = nets(&["10.0.0.0/8", "2001:db8::/32"]);
        assert!(is_trusted_peer(ip("10.1.2.3"), &trusted));
        assert!(is_trusted_peer(ip("::ffff:10.1.2.3"), &trusted));
        assert!(is_trusted_peer(ip("2001:db8::7"), &trusted));
        assert!(!is_trusted_peer(ip("203.0.113.9"), &trusted));
        assert!(!is_trusted_peer(ip("10.1.2.3"), &[]));
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
    fn malformed_or_empty_hop_falls_back_to_peer() {
        let trusted = nets(&["10.0.0.0/8"]);
        for xff in ["not-an-ip", "198.51.100.5, ", ",10.0.0.9", ""] {
            let got = resolve_client_ip(ip("10.0.0.1"), Some(xff), &trusted);
            assert_eq!(got, ip("10.0.0.1"), "{xff:?}");
        }
        // An untrusted peer's XFF is never read, malformed or not.
        assert_eq!(
            resolve_client_ip(ip("203.0.113.9"), Some("junk"), &trusted),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn hops_with_a_port_parse() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), Some("198.51.100.5:4711"), &trusted),
            ip("198.51.100.5")
        );
        assert_eq!(
            resolve_client_ip(
                ip("10.0.0.1"),
                Some("[2001:db8::1]:4711, 10.0.0.9:80"),
                &trusted
            ),
            ip("2001:db8::1")
        );
    }

    #[test]
    fn a_non_ascii_hop_does_not_hide_the_hop_a_proxy_appended_to_its_line() {
        // nginx `$proxy_add_x_forwarded_for`: "<client's value>, <real client>"
        // on ONE line. A byte the client wrote spoils only its own hop.
        let trusted = nets(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            http::HeaderValue::from_bytes(b"\xff, 198.51.100.5").unwrap(),
        );
        let xff = forwarded_for(&headers);
        assert_eq!(xff.as_deref(), Some("_, 198.51.100.5"));
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), xff.as_deref(), &trusted),
            ip("198.51.100.5")
        );

        // The proxy's own hop unreadable: malformed → the peer.
        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            http::HeaderValue::from_bytes(b"198.51.100.5, \xfe").unwrap(),
        );
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), forwarded_for(&headers).as_deref(), &trusted),
            ip("10.0.0.1")
        );
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
    }

    #[test]
    fn ipv4_mapped_entries_are_configured_as_ipv4() {
        // An entry written in the mapped form still matches once peers are
        // canonicalized.
        assert_eq!(
            canonical_net("::ffff:172.17.0.0/112".parse().unwrap()),
            "172.17.0.0/16".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            canonical_net("2001:db8::/32".parse().unwrap()),
            "2001:db8::/32".parse::<IpNet>().unwrap()
        );
        let trusted = vec![canonical_net("::ffff:172.17.0.1/128".parse().unwrap())];
        assert!(is_trusted_peer(ip("172.17.0.1"), &trusted));
        assert!(is_trusted_peer(ip("::ffff:172.17.0.1"), &trusted));
        assert!(!is_trusted_peer(ip("172.17.0.2"), &trusted));
    }
}
