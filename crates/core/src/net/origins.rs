//! Where a format's upstream conversation may send requests (#233).
//!
//! A proxy repository's format says which documents to fetch from its
//! upstream, and where a version's package is
//! ([`crate::repo::proxy::ProxyRepo`]). The host sends these requests from
//! Forge's network position, and the format reads the answers back into what
//! the proxy serves, so a document an upstream serves must not be able to
//! steer them at an internal service. They go only where the upstream itself
//! points ([`UpstreamOrigins`]):
//!
//! * the origin (scheme, host, port) of the repository's `remote_url`;
//! * an origin that an absolute `http`/`https` URL names in a document the
//!   host fetched from the upstream for the same conversation, or while
//!   resolving the upstream's index ([`named_origins`]). A NuGet service
//!   index lists resources on other hosts (nuget.org's search service is
//!   `azuresearch-*.nuget.org`), and a Helm index may list charts on another
//!   host (a project's GitHub releases).
//!
//! What the format answers never names an origin: its upstream index is of
//! its own making, and only the documents the host fetched count, from an
//! origin it could already reach. The rule bounds a format to what its
//! upstream points at, and no further: a URL the upstream's documents name
//! makes its origin reachable, an internal address in a public feed's package
//! metadata as well. Confining Forge itself is network policy's job.
//!
//! Redirects are the upstream's choice, not the format's, and are followed
//! under [`super::upstream::UpstreamHttp`]'s own guards.

use std::collections::{BTreeSet, HashSet};

use super::upstream::Origin;

/// Distinct origins one conversation may reach besides the `remote_url`'s,
/// and that one document is read for. A feed names a handful (a NuGet
/// service index three or four; a large Helm index, with its charts' home
/// pages and sources, a few hundred), so the bound only keeps a crafted
/// document from growing the set, and the index record that keeps it,
/// without limit. Origins past it are not added: a request to one is not
/// sent.
pub const MAX_NAMED_ORIGINS: usize = 4096;

/// The longest authority (`user@host:port`) read from a document. A DNS name
/// is at most 253 bytes; anything longer is not a URL a feed names.
const MAX_AUTHORITY_BYTES: usize = 320;

/// Distinct URL prefixes (`scheme://authority`) one document is read for
/// before its repeats are no longer skipped cheaply: the same few hosts
/// are named over and over (every chart of a Helm index), so each is parsed
/// once, while the set itself stays bounded.
const MAX_SEEN_PREFIXES: usize = 4 * MAX_NAMED_ORIGINS;

/// The origins one upstream conversation of a proxy may send requests to:
/// the `remote_url`'s, and those the upstream's documents named.
#[derive(Debug, Clone)]
pub struct UpstreamOrigins {
    /// The origin of the repository's `remote_url`.
    remote: Option<Origin>,
    /// The origins named by documents the host fetched, at most
    /// [`MAX_NAMED_ORIGINS`].
    named: BTreeSet<Origin>,
}

impl UpstreamOrigins {
    /// The origins a conversation with the upstream at `remote_url` starts
    /// with: the `remote_url`'s, and `named` (those the documents fetched
    /// while resolving its index named).
    pub fn new(remote_url: &str, named: impl IntoIterator<Item = Origin>) -> Self {
        let mut origins = UpstreamOrigins {
            remote: Origin::of(remote_url),
            named: BTreeSet::new(),
        };
        origins.extend(named);
        origins
    }

    /// Whether a request to `url` may be sent: its origin is the
    /// `remote_url`'s or one a fetched document named.
    pub fn permits(&self, url: &str) -> bool {
        Origin::of(url).is_some_and(|origin| {
            self.remote.as_ref() == Some(&origin) || self.named.contains(&origin)
        })
    }

    /// Add the origins a fetched document named, up to
    /// [`MAX_NAMED_ORIGINS`] in all.
    pub fn extend(&mut self, named: impl IntoIterator<Item = Origin>) {
        for origin in named {
            if self.named.len() >= MAX_NAMED_ORIGINS {
                break;
            }
            if self.remote.as_ref() != Some(&origin) {
                self.named.insert(origin);
            }
        }
    }

    /// The origins fetched documents named (the `remote_url`'s aside).
    pub fn named(&self) -> &BTreeSet<Origin> {
        &self.named
    }
}

/// The origins of the absolute `http`/`https` URLs in `doc`, at most
/// [`MAX_NAMED_ORIGINS`] of them, whatever the document's format: a URL is
/// `http:` or `https:` (any case), then `//` or JSON's escaped `\/\/`, then
/// an authority, read up to the first byte that cannot be part of one (a
/// `/`, a quote, a space, a `\` escape). One pass over the bytes, so a
/// document of the upstream's size limit is read in linear time.
pub fn named_origins(doc: &[u8]) -> BTreeSet<Origin> {
    let mut out = BTreeSet::new();
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut at = 0;
    while let Some(found) = doc[at..].iter().position(|&b| b == b':') {
        let colon = at + found;
        at = colon + 1;
        let Some((scheme, scheme_start)) = scheme_before(doc, colon) else {
            continue;
        };
        let rest = &doc[colon + 1..];
        let slashes = if rest.starts_with(b"//") {
            2
        } else if rest.starts_with(b"\\/\\/") {
            4
        } else {
            continue;
        };
        let start = colon + 1 + slashes;
        let Some(len) = authority_len(&doc[start..]) else {
            continue;
        };
        // An authority holds no `/`, so the next URL starts after it.
        at = start + len;
        let prefix = &doc[scheme_start..start + len];
        if seen.contains(prefix) {
            continue;
        }
        if seen.len() < MAX_SEEN_PREFIXES {
            seen.insert(prefix);
        }
        // Parsed as a request's URL is ([`Origin::of`]), so a document
        // names exactly the origin a request to the same URL has.
        let Ok(authority) = std::str::from_utf8(&doc[start..start + len]) else {
            continue;
        };
        if let Some(origin) = Origin::of(&format!("{scheme}://{authority}/")) {
            out.insert(origin);
            if out.len() >= MAX_NAMED_ORIGINS {
                break;
            }
        }
    }
    out
}

/// The scheme (`http` or `https`, any case) that ends at `colon`, and where
/// it starts.
fn scheme_before(doc: &[u8], colon: usize) -> Option<(&'static str, usize)> {
    let ends_with = |scheme: &[u8]| {
        colon >= scheme.len() && doc[colon - scheme.len()..colon].eq_ignore_ascii_case(scheme)
    };
    if ends_with(b"https") {
        Some(("https", colon - 5))
    } else if ends_with(b"http") {
        Some(("http", colon - 4))
    } else {
        None
    }
}

/// The length of the authority `rest` starts with: an optional bracketed
/// IPv6 literal, then letters, digits and `-._~%:@` (user info, host, port).
/// `None` when it is empty or longer than [`MAX_AUTHORITY_BYTES`].
fn authority_len(rest: &[u8]) -> Option<usize> {
    let rest = &rest[..rest.len().min(MAX_AUTHORITY_BYTES + 1)];
    let literal = match rest.first() {
        Some(b'[') => rest.iter().position(|&b| b == b']')? + 1,
        _ => 0,
    };
    let len = literal
        + rest[literal..]
            .iter()
            .take_while(|&&b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%' | b':' | b'@')
            })
            .count();
    (len > 0 && len <= MAX_AUTHORITY_BYTES).then_some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origins(doc: &str) -> Vec<String> {
        named_origins(doc.as_bytes())
            .into_iter()
            .map(|o| o.to_string())
            .collect()
    }

    #[test]
    fn a_nuget_service_index_names_its_resources_hosts() {
        let doc = r#"{"version": "3.0.0", "resources": [
            {"@id": "https://api.nuget.org/v3-flatcontainer/", "@type": "PackageBaseAddress/3.0.0"},
            {"@id": "https://azuresearch-usnc.nuget.org/query", "@type": "SearchQueryService"},
            {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/", "@type": "RegistrationsBaseUrl/3.6.0"},
            {"@id": "http://127.0.0.1:8421/v3/feed/flat/", "@type": "PackageBaseAddress/3.0.0"}
        ]}"#;
        assert_eq!(
            origins(doc),
            [
                "http://127.0.0.1:8421",
                "https://api.nuget.org:443",
                "https://azuresearch-usnc.nuget.org:443",
            ]
        );
    }

    #[test]
    fn urls_are_found_in_any_document_and_any_quoting() {
        // JSON-escaped slashes, YAML flow and block sequences, single
        // quotes, an upper-case scheme, user info, an IPv6 literal, markup.
        let doc = concat!(
            r#"{"a": "https:\/\/escaped.example\/x", "b": "HTTPS://Upper.Example/y"}"#,
            "\nurls: [https://flow.example/c.tgz, 'https://single.example/c.tgz']\n",
            "home: https://user:pw@block.example:8443/path?q=1#f\n",
            "- http://[::1]:9200/_search\n",
            "<a href=\"http://markup.example\">x</a> (http://paren.example)\n",
        );
        assert_eq!(
            origins(doc),
            [
                "http://[::1]:9200",
                "http://markup.example:80",
                "http://paren.example:80",
                "https://block.example:8443",
                "https://escaped.example:443",
                "https://flow.example:443",
                "https://single.example:443",
                "https://upper.example:443",
            ]
        );
    }

    #[test]
    fn what_is_not_an_absolute_http_url_names_nothing() {
        for doc in [
            "urls: [charts/demo-1.0.0.tgz, /charts/x.tgz, //cdn.example/x.tgz]",
            "ftp://files.example/x oci://registry.example/chart file:///etc/passwd",
            "http:/one-slash.example http:// https:\\/ key: value",
            "",
            "https://",
        ] {
            assert!(origins(doc).is_empty(), "{doc:?}: {:?}", origins(doc));
        }
        let long = format!("https://{}.example/", "a".repeat(400));
        assert!(origins(&long).is_empty(), "an authority past the bound");
    }

    #[test]
    fn a_document_names_at_most_the_bound() {
        let doc: String = (0..MAX_NAMED_ORIGINS + 10)
            .map(|n| format!("https://h{n}.example/ https://h{n}.example/again\n"))
            .collect();
        assert_eq!(named_origins(doc.as_bytes()).len(), MAX_NAMED_ORIGINS);
    }

    #[test]
    fn a_conversation_reaches_the_remote_url_and_the_named_origins_only() {
        let mut origins = UpstreamOrigins::new("https://feed.example/v3/index.json", []);
        assert!(origins.permits("https://feed.example/v3/flat/x/index.json"));
        assert!(origins.permits("https://FEED.example:443/other"));
        for refused in [
            "http://feed.example/v3/index.json",
            "https://feed.example:8443/",
            "http://localhost:8421/admin/users",
            "http://10.0.0.5:9200/_search",
            "https://cdn.example/x.nupkg",
            "not a url",
            "",
        ] {
            assert!(!origins.permits(refused), "{refused}");
        }

        origins.extend(named_origins(
            br#"{"@id": "https://cdn.example/flat/", "next": "https://feed.example/page2"}"#,
        ));
        assert!(origins.permits("https://cdn.example/x.nupkg"));
        assert!(!origins.permits("http://cdn.example/x.nupkg"));
        assert!(!origins.permits("http://10.0.0.5:9200/_search"));
        assert_eq!(
            origins
                .named()
                .iter()
                .map(Origin::to_string)
                .collect::<Vec<_>>(),
            ["https://cdn.example:443"],
            "the remote_url's origin is not recorded as named"
        );

        // A later conversation starts from the recorded origins.
        let later = UpstreamOrigins::new(
            "https://feed.example/v3/index.json",
            origins.named().iter().cloned(),
        );
        assert!(later.permits("https://cdn.example/y.nupkg"));
    }

    #[test]
    fn a_conversation_holds_at_most_the_bound() {
        let mut origins = UpstreamOrigins::new("https://feed.example/", []);
        origins.extend(
            (0..MAX_NAMED_ORIGINS + 10)
                .filter_map(|n| Origin::of(&format!("https://h{n}.example/"))),
        );
        assert_eq!(origins.named().len(), MAX_NAMED_ORIGINS);
        assert!(origins.permits("https://feed.example/x"));
    }
}
