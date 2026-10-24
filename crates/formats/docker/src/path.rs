//! Parsing `/v2/…` request paths into distribution-spec endpoints.
//!
//! A repository name may itself contain `/` (and words like `blobs` or
//! `manifests` as components), but no reference, digest or upload id does,
//! so endpoints are recognized from the **end** of the path.
//!
//! The host routes `/v2` and answers `/v2/`, `/v2/token` and `/v2/_catalog`
//! itself; it hands the format the path below `/v2`, which [`split`] splits
//! into the name and the rest, and then the rest, which [`of_name`] parses
//! again with the name the host resolved.

/// A `/v2/` endpoint, with the raw (not yet validated) name and argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// `/v2/`: the API version check.
    Base,
    /// `/v2/token`: the Bearer token service.
    Token,
    /// `/v2/_catalog`.
    Catalog,
    /// `/v2/<name>/manifests/<reference>`.
    Manifest { name: String, reference: String },
    /// `/v2/<name>/blobs/<digest>`.
    Blob { name: String, digest: String },
    /// `/v2/<name>/blobs/uploads/` (start an upload).
    UploadStart { name: String },
    /// `/v2/<name>/blobs/uploads/<id>`.
    Upload { name: String, id: String },
    /// `/v2/<name>/tags/list`.
    TagsList { name: String },
    /// `/v2/<name>/referrers/<digest>`.
    Referrers { name: String, digest: String },
}

impl Endpoint {
    /// The `<name>` of a repository endpoint.
    pub fn name(&self) -> Option<&str> {
        match self {
            Endpoint::Base | Endpoint::Token | Endpoint::Catalog => None,
            Endpoint::Manifest { name, .. }
            | Endpoint::Blob { name, .. }
            | Endpoint::UploadStart { name }
            | Endpoint::Upload { name, .. }
            | Endpoint::TagsList { name }
            | Endpoint::Referrers { name, .. } => Some(name),
        }
    }
}

/// A path below `/v2` (`/team/app/manifests/1`) as the endpoint of a name,
/// with the part after the name (`/manifests/1`). `None` for anything that
/// is not the endpoint of a name.
pub fn split(path: &str) -> Option<(Endpoint, String)> {
    let endpoint = parse(&format!("/v2{path}"))?;
    let rest = path.strip_prefix('/')?.strip_prefix(endpoint.name()?)?;
    let rest = rest.to_string();
    Some((endpoint, rest))
}

/// The endpoint `rest` (what [`split`] left after the name) of `name`.
pub fn of_name(name: &str, rest: &str) -> Option<Endpoint> {
    parse(&format!("/v2/{name}{rest}")).filter(|endpoint| endpoint.name() == Some(name))
}

/// Parse a request path. `None` for anything that is not a `/v2` endpoint.
pub fn parse(path: &str) -> Option<Endpoint> {
    let rest = path.strip_prefix("/v2")?;
    if rest.is_empty() || rest == "/" {
        return Some(Endpoint::Base);
    }
    let rest = rest.strip_prefix('/')?;
    match rest {
        "token" => return Some(Endpoint::Token),
        "_catalog" => return Some(Endpoint::Catalog),
        _ => {}
    }
    let segments: Vec<&str> = rest.split('/').collect();
    let n = segments.len();
    let name = |upto: usize| -> Option<String> { (upto > 0).then(|| segments[..upto].join("/")) };
    let last = segments[n - 1];
    let at = |i: usize| if i < n { segments[n - 1 - i] } else { "" };

    if n >= 3 && at(1) == "manifests" {
        return Some(Endpoint::Manifest {
            name: name(n - 2)?,
            reference: last.to_string(),
        });
    }
    if n >= 3 && at(1) == "tags" && last == "list" {
        return Some(Endpoint::TagsList { name: name(n - 2)? });
    }
    if n >= 3 && at(1) == "referrers" {
        return Some(Endpoint::Referrers {
            name: name(n - 2)?,
            digest: last.to_string(),
        });
    }
    // `…/blobs/uploads/` (trailing slash) and `…/blobs/uploads`.
    if n >= 4 && last.is_empty() && at(1) == "uploads" && at(2) == "blobs" {
        return Some(Endpoint::UploadStart { name: name(n - 3)? });
    }
    if n >= 3 && last == "uploads" && at(1) == "blobs" {
        return Some(Endpoint::UploadStart { name: name(n - 2)? });
    }
    if n >= 4 && at(1) == "uploads" && at(2) == "blobs" {
        return Some(Endpoint::Upload {
            name: name(n - 3)?,
            id: last.to_string(),
        });
    }
    if n >= 3 && at(1) == "blobs" {
        return Some(Endpoint::Blob {
            name: name(n - 2)?,
            digest: last.to_string(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_token_catalog() {
        assert_eq!(parse("/v2"), Some(Endpoint::Base));
        assert_eq!(parse("/v2/"), Some(Endpoint::Base));
        assert_eq!(parse("/v2/token"), Some(Endpoint::Token));
        assert_eq!(parse("/v2/_catalog"), Some(Endpoint::Catalog));
        assert_eq!(parse("/v3/x"), None);
        assert_eq!(parse("/v2x"), None);
    }

    #[test]
    fn repository_endpoints() {
        assert_eq!(
            parse("/v2/docker/team/app/manifests/1.0"),
            Some(Endpoint::Manifest {
                name: "docker/team/app".into(),
                reference: "1.0".into()
            })
        );
        assert_eq!(
            parse("/v2/a/b/blobs/sha256:00"),
            Some(Endpoint::Blob {
                name: "a/b".into(),
                digest: "sha256:00".into()
            })
        );
        assert_eq!(
            parse("/v2/a/b/blobs/uploads/"),
            Some(Endpoint::UploadStart { name: "a/b".into() })
        );
        assert_eq!(
            parse("/v2/a/b/blobs/uploads"),
            Some(Endpoint::UploadStart { name: "a/b".into() })
        );
        assert_eq!(
            parse("/v2/a/blobs/uploads/0f7e"),
            Some(Endpoint::Upload {
                name: "a".into(),
                id: "0f7e".into()
            })
        );
        assert_eq!(
            parse("/v2/a/tags/list"),
            Some(Endpoint::TagsList { name: "a".into() })
        );
        assert_eq!(
            parse("/v2/a/referrers/sha256:00"),
            Some(Endpoint::Referrers {
                name: "a".into(),
                digest: "sha256:00".into()
            })
        );
    }

    #[test]
    fn names_may_contain_endpoint_words() {
        assert_eq!(
            parse("/v2/r/manifests/blobs/manifests/latest"),
            Some(Endpoint::Manifest {
                name: "r/manifests/blobs".into(),
                reference: "latest".into()
            })
        );
        assert_eq!(
            parse("/v2/r/blobs/uploads/blobs/uploads/"),
            Some(Endpoint::UploadStart {
                name: "r/blobs/uploads".into()
            })
        );
    }

    #[test]
    fn nameless_paths_are_not_endpoints() {
        assert_eq!(parse("/v2/manifests/latest"), None);
        assert_eq!(parse("/v2/blobs/uploads/"), None);
        assert_eq!(parse("/v2/tags/list"), None);
        assert_eq!(parse("/v2/x"), None);
        assert_eq!(parse("/v2/x/y"), None);
    }

    #[test]
    fn splits_the_name_off_and_back_on() {
        let (endpoint, rest) = split("/docker/team/app/manifests/1.0").unwrap();
        assert_eq!(
            endpoint,
            Endpoint::Manifest {
                name: "docker/team/app".into(),
                reference: "1.0".into()
            }
        );
        assert_eq!(rest, "/manifests/1.0");
        assert_eq!(of_name("docker/team/app", &rest), Some(endpoint));
        let (_, rest) = split("/a/blobs/uploads/").unwrap();
        assert_eq!(rest, "/blobs/uploads/");
        assert_eq!(
            of_name("other", "/blobs/uploads/"),
            Some(Endpoint::UploadStart {
                name: "other".into()
            })
        );
        assert_eq!(split("/token"), None);
        assert_eq!(split("/x"), None);
        assert_eq!(split(""), None);
    }
}
