//! The base URLs the absolute URLs of the client protocols are rendered on
//! (#312): `server.public_base_url`, and for a request that addressed one of
//! `server.alias_base_urls`, that alias.
//!
//! An alias keeps a client on the host name it came in on, such as the old
//! Nexus host pointed at Forge: a NuGet service index fetched there names its
//! resources there, an npm packument its tarballs, and the registry its token
//! realm and service.
//!
//! * Only listed aliases are honoured. A request for any other host is
//!   answered with URLs on the public base URL, so a forged `Host` cannot
//!   make Forge render links to a host of its choosing (cache poisoning).
//! * Hosts are matched the way `server.allowed_hosts` matches them: by name,
//!   case-insensitive, without a trailing dot, the port ignored. The name is
//!   the `Host` header (or an HTTP/2 request's authority), never
//!   `X-Forwarded-Host`: the reverse proxy must pass `Host` through.
//! * Browser surfaces stay on the public base URL: the web UI (a page
//!   requested on an alias is redirected there, [`crate::web_ui`]), sign-in
//!   and OIDC redirects, session cookies, the CSRF origin check, links in
//!   emails, and the connect snippets the web UI shows.

use axum::http::{header, Request};

/// One of `server.alias_base_urls`, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasBaseUrl {
    /// `scheme://host[:port]`, lowercase, without a trailing `/` (and
    /// without the scheme's default port).
    pub url: String,
    /// The host name requests address it by: lowercase, without port or
    /// trailing dot ([`normalize_host`]).
    pub host: String,
}

/// The public base URL and the aliases, as requests are served on them.
#[derive(Debug, Clone)]
pub struct BaseUrls {
    /// `server.public_base_url` without a trailing `/`.
    public: String,
    aliases: Vec<AliasBaseUrl>,
}

impl BaseUrls {
    /// Parse `aliases` (`server.alias_base_urls`) next to `public_base_url`:
    /// each an absolute `http`/`https` URL of a host and an optional port,
    /// without path, query, fragment or credentials, of a host no other entry
    /// and not the public base URL has.
    pub fn new(public_base_url: &str, aliases: &[String]) -> Result<Self, String> {
        let public = public_base_url.trim().trim_end_matches('/').to_string();
        let public_host = url::Url::parse(&public)
            .ok()
            .and_then(|url| authority_of(&url))
            .and_then(|authority| normalize_host(&authority));
        let mut parsed: Vec<AliasBaseUrl> = Vec::with_capacity(aliases.len());
        for raw in aliases {
            let alias = parse_alias(raw)?;
            if public_host.as_deref() == Some(alias.host.as_str()) {
                return Err(format!(
                    "{raw:?} names the host of server.public_base_url; an alias is another \
                     host name"
                ));
            }
            if parsed.iter().any(|other| other.host == alias.host) {
                return Err(format!(
                    "{raw:?} names the host {} twice (hosts are matched without their port)",
                    alias.host
                ));
            }
            parsed.push(alias);
        }
        Ok(BaseUrls {
            public,
            aliases: parsed,
        })
    }

    /// `server.public_base_url`, without a trailing `/`.
    pub fn public(&self) -> &str {
        &self.public
    }

    /// The aliases, in their configured order.
    pub fn aliases(&self) -> &[AliasBaseUrl] {
        &self.aliases
    }

    /// The alias whose host `authority` (a `Host` value, `host[:port]`)
    /// names, if any.
    pub fn alias(&self, authority: Option<&str>) -> Option<&AliasBaseUrl> {
        if self.aliases.is_empty() {
            return None;
        }
        let host = normalize_host(authority?)?;
        self.aliases.iter().find(|alias| alias.host == host)
    }

    /// The alias `req` addressed ([`request_authority`]), if any.
    pub fn alias_of<B>(&self, req: &Request<B>) -> Option<&AliasBaseUrl> {
        self.alias(request_authority(req))
    }

    /// The base URL of a request that addressed `authority`: its alias, or
    /// the public base URL.
    pub fn for_authority(&self, authority: Option<&str>) -> &str {
        self.alias(authority)
            .map_or(self.public.as_str(), |alias| alias.url.as_str())
    }
}

/// Parse one alias base URL ([`BaseUrls::new`]).
fn parse_alias(raw: &str) -> Result<AliasBaseUrl, String> {
    let invalid = |why: &str| format!("{raw:?} {why}, e.g. https://nexus.example.com");
    let trimmed = raw.trim();
    let url =
        url::Url::parse(trimmed).map_err(|e| invalid(&format!("is not an absolute URL ({e})")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid("must use http or https"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid("must name a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("must not carry credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("must not have a query or fragment"));
    }
    // `Url` gives `https://host` the path `/`; `https://host/` is the same
    // URL, anything longer is a path.
    if url.path() != "/" {
        return Err(invalid(
            "must not have a path: an alias serves the server's paths at its root",
        ));
    }
    let authority = authority_of(&url).ok_or_else(|| invalid("must name a host"))?;
    let host = normalize_host(&authority).ok_or_else(|| invalid("must name a valid host"))?;
    Ok(AliasBaseUrl {
        url: format!("{}://{}", url.scheme(), authority.to_ascii_lowercase()),
        host,
    })
}

/// `host[:port]` of `url` (the port only when it is not the scheme's
/// default).
fn authority_of(url: &url::Url) -> Option<String> {
    let host = url.host_str().filter(|h| !h.is_empty())?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// The lowercase host of an authority (`host[:port]`, IPv6 in brackets),
/// without port or trailing dot; `None` if it does not parse.
pub fn normalize_host(authority: &str) -> Option<String> {
    let authority: http::uri::Authority = authority.trim().parse().ok()?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// The authority a request addressed: its `Host` header, or the URI
/// authority of an HTTP/2 request. Never `X-Forwarded-Host`.
pub fn request_authority<B>(req: &Request<B>) -> Option<&str> {
    match req.headers().get(header::HOST) {
        Some(value) => value.to_str().ok(),
        None => req.uri().authority().map(|a| a.as_str()),
    }
    .filter(|authority| !authority.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls(aliases: &[&str]) -> Result<BaseUrls, String> {
        BaseUrls::new(
            "https://forge.example.com/",
            &aliases.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn aliases_are_normalized() {
        let urls = urls(&[
            " HTTPS://Nexus.Example.com/ ",
            "http://old.example.com:8081",
            "https://other.example.com:443",
        ])
        .unwrap();
        assert_eq!(urls.public(), "https://forge.example.com");
        assert_eq!(
            urls.aliases(),
            [
                AliasBaseUrl {
                    url: "https://nexus.example.com".into(),
                    host: "nexus.example.com".into()
                },
                AliasBaseUrl {
                    url: "http://old.example.com:8081".into(),
                    host: "old.example.com".into()
                },
                AliasBaseUrl {
                    url: "https://other.example.com".into(),
                    host: "other.example.com".into()
                },
            ]
        );
    }

    #[test]
    fn malformed_aliases_are_refused() {
        for (bad, why) in [
            ("nexus.example.com", "absolute URL"),
            ("ftp://nexus.example.com", "http or https"),
            ("https://nexus.example.com/repository", "path"),
            ("https://nexus.example.com/repository/", "path"),
            ("https://nexus.example.com/?x=1", "query"),
            ("https://nexus.example.com/#top", "fragment"),
            ("https://user:pw@nexus.example.com", "credentials"),
            ("", "absolute URL"),
        ] {
            let err = urls(&[bad]).unwrap_err();
            assert!(err.contains(why), "{bad:?}: {err}");
        }
    }

    #[test]
    fn duplicates_and_the_public_host_are_refused() {
        let err = urls(&[
            "https://nexus.example.com",
            "http://NEXUS.example.com.:8081",
        ])
        .unwrap_err();
        assert!(err.contains("twice"), "{err}");
        for public in [
            "https://forge.example.com",
            "http://forge.example.com:8421",
            "https://FORGE.example.com./",
        ] {
            let err = urls(&[public]).unwrap_err();
            assert!(err.contains("server.public_base_url"), "{public}: {err}");
        }
    }

    #[test]
    fn hosts_match_like_allowed_hosts() {
        let urls = urls(&["https://nexus.example.com", "http://old.example.com:8081"]).unwrap();
        for host in [
            "nexus.example.com",
            "NEXUS.example.com",
            "nexus.example.com.",
            "nexus.example.com:443",
            "nexus.example.com:8443",
        ] {
            assert_eq!(
                urls.for_authority(Some(host)),
                "https://nexus.example.com",
                "{host}"
            );
        }
        // The port is the alias's own, whatever the request names.
        assert_eq!(
            urls.for_authority(Some("old.example.com")),
            "http://old.example.com:8081"
        );
        // Any other host, or none, is served on the public base URL.
        for host in [
            Some("forge.example.com"),
            Some("evil.example.com"),
            Some("nexus.example.com.evil.example"),
            Some("not a host"),
            None,
        ] {
            assert_eq!(
                urls.for_authority(host),
                "https://forge.example.com",
                "{host:?}"
            );
        }
    }

    #[test]
    fn the_request_host_is_the_host_header_or_the_authority() {
        let req = Request::builder()
            .uri("/repository/x")
            .header(header::HOST, "nexus.example.com")
            .header("x-forwarded-host", "forge.example.com")
            .body(())
            .unwrap();
        assert_eq!(request_authority(&req), Some("nexus.example.com"));
        let req = Request::builder()
            .uri("https://nexus.example.com/repository/x")
            .body(())
            .unwrap();
        assert_eq!(request_authority(&req), Some("nexus.example.com"));
        let req = Request::builder()
            .uri("/repository/x")
            .header("x-forwarded-host", "nexus.example.com")
            .body(())
            .unwrap();
        assert_eq!(request_authority(&req), None);
    }
}
