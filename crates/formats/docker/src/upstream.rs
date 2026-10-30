//! The upstream side of proxy repositories: what to ask an upstream
//! registry (Docker Hub, GHCR, Quay, MCR or any distribution-spec
//! registry) for, and what its answers say.
//!
//! * Docker Hub's implicit `library/` namespace applies to one-component
//!   names (`nginx` is `library/nginx`), so both spellings share one cache
//!   ([`UpstreamOp::ImageName`]).
//! * A manifest's and a blob's URLs ([`UpstreamOp::ImageManifest`],
//!   [`UpstreamOp::ImageBlob`]): the host sends them, answers the
//!   upstream's token challenge, verifies and caches what comes back.
//! * A tag list follows the upstream's own pages (`Link: rel="next"`, back
//!   to the upstream only) to fill one page of Forge's; an upstream that
//!   refuses a large `n` (400) is asked again without one.
//! * Referrers come from the upstream's referrers API, where it has one.
//! * The catalog (`/v2/_catalog`, which an import walks) is paged like a
//!   tag list; an upstream that does not serve it, or refuses it, has none.

use std::collections::BTreeSet;

use forge_plugin_api::images::{CatalogPage, ImageUrl, ManifestInfo, Reference, TagPage};
use forge_plugin_api::{
    Fetch, FetchResult, Fetched, FormatError, Freshness, Remote, UpstreamAnswer, UpstreamOp,
    UpstreamStep,
};
use serde_json::json;

use crate::digest::Digest;
use crate::manifest::media;
use crate::reference;

/// Hosts of Docker Hub's registry, whose one-component names live in
/// `library/`.
const DOCKER_HUB_HOSTS: &[&str] = &[
    "registry-1.docker.io",
    "index.docker.io",
    "docker.io",
    "registry.hub.docker.com",
];

/// Pages of an upstream's tag list followed to fill one page of Forge's: an
/// upstream that pages in small steps is listed further on the client's
/// next request.
pub const MAX_UPSTREAM_TAG_PAGES: usize = 10;

/// The upstream side of a proxy: one step of `op`.
pub fn step(
    remote: &Remote,
    op: &UpstreamOp,
    fetched: &[FetchResult],
) -> Result<UpstreamStep, FormatError> {
    let base = upstream_base(&remote.url);
    let done = |answer| Ok(UpstreamStep::Done(answer));
    match op {
        UpstreamOp::ImageName(image) => {
            done(UpstreamAnswer::ImageName(proxied_image(&remote.url, image)))
        }
        UpstreamOp::ImageManifest { image, reference } => {
            let reference = match reference {
                Reference::Tag(tag) if !crate::reference::valid_tag(tag) => {
                    return Err(FormatError::InvalidVersion(format!("invalid tag {tag:?}")))
                }
                Reference::Tag(tag) => tag,
                Reference::Digest(digest) => digest,
            };
            done(UpstreamAnswer::ImageUrl(ImageUrl {
                url: format!("{base}/v2/{image}/manifests/{reference}"),
                accept: Some(media::ACCEPT_ALL.join(", ")),
                scope: Some(scope(image)),
            }))
        }
        UpstreamOp::ImageBlob { image, digest } => done(UpstreamAnswer::ImageUrl(ImageUrl {
            url: format!("{base}/v2/{image}/blobs/{digest}"),
            accept: None,
            scope: Some(scope(image)),
        })),
        UpstreamOp::ImageTags { image, last, n } => {
            tags(&base, image, last.as_deref(), *n as usize, fetched)
        }
        UpstreamOp::ImageReferrers { image, digest } => referrers(&base, image, digest, fetched),
        UpstreamOp::ImageCatalog { last, n } => {
            catalog(&base, last.as_deref(), *n as usize, fetched)
        }
        _ => Err(FormatError::Internal(
            "Docker proxies have only image operations".into(),
        )),
    }
}

/// The upstream base URL of a proxy: `remote_url` without a trailing `/`
/// (and without a `/v2` suffix an admin may have pasted).
pub fn upstream_base(remote_url: &str) -> String {
    let base = remote_url.trim_end_matches('/');
    base.strip_suffix("/v2").unwrap_or(base).to_string()
}

fn is_docker_hub(remote_url: &str) -> bool {
    url::Url::parse(remote_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|h| DOCKER_HUB_HOSTS.contains(&h.as_str()))
}

/// The image name a proxy of `remote_url` stores and asks its upstream for.
pub fn proxied_image(remote_url: &str, image: &str) -> String {
    if is_docker_hub(remote_url) && !image.contains('/') {
        format!("library/{image}")
    } else {
        image.to_string()
    }
}

/// The token scope reading `image` needs.
fn scope(image: &str) -> String {
    format!("repository:{image}:pull")
}

fn get(url: String, image: &str, accept: Option<&str>) -> Fetch {
    Fetch {
        accept: accept.map(str::to_string),
        scope: Some(scope(image)),
        ..Fetch::new(url, Freshness::Metadata)
    }
}

/// Up to `limit` of the upstream's tags of `image` after `last`
/// ([`list`]).
fn tags(
    base: &str,
    image: &str,
    last: Option<&str>,
    limit: usize,
    fetched: &[FetchResult],
) -> Result<UpstreamStep, FormatError> {
    Ok(
        match list(base, &Listing::Tags(image), last, limit, fetched) {
            Listed::Fetch(fetch) => UpstreamStep::Fetch(vec![fetch]),
            Listed::Unknown => UpstreamStep::Done(UpstreamAnswer::ImageTags(None)),
            Listed::Failed(reason) => UpstreamStep::Done(UpstreamAnswer::Failed(reason)),
            Listed::Page(tags, more) => {
                UpstreamStep::Done(UpstreamAnswer::ImageTags(Some(TagPage { tags, more })))
            }
        },
    )
}

/// Up to `limit` of the names of the upstream's images after `last`, from
/// its catalog (`/v2/_catalog`, [`list`]). The catalog is no part of the
/// distribution spec: an upstream that does not serve it (404), or refuses
/// it (401, 403: Docker Hub), has none.
fn catalog(
    base: &str,
    last: Option<&str>,
    limit: usize,
    fetched: &[FetchResult],
) -> Result<UpstreamStep, FormatError> {
    if fetched
        .first()
        .is_some_and(|first| matches!(first.status, Some(401 | 403)))
    {
        return Ok(UpstreamStep::Done(UpstreamAnswer::ImageCatalog(None)));
    }
    Ok(match list(base, &Listing::Catalog, last, limit, fetched) {
        Listed::Fetch(fetch) => UpstreamStep::Fetch(vec![fetch]),
        Listed::Unknown => UpstreamStep::Done(UpstreamAnswer::ImageCatalog(None)),
        Listed::Failed(reason) => UpstreamStep::Done(UpstreamAnswer::Failed(reason)),
        Listed::Page(images, more) => {
            UpstreamStep::Done(UpstreamAnswer::ImageCatalog(Some(CatalogPage {
                images,
                more,
            })))
        }
    })
}

/// A paged list of names the registry API serves.
enum Listing<'a> {
    /// The tags of an image (`/v2/<image>/tags/list`).
    Tags(&'a str),
    /// The registry's images (`/v2/_catalog`).
    Catalog,
}

impl Listing<'_> {
    fn url(&self, base: &str) -> String {
        match self {
            Listing::Tags(image) => format!("{base}/v2/{image}/tags/list"),
            Listing::Catalog => format!("{base}/v2/_catalog"),
        }
    }

    /// The key of the document's name array.
    fn key(&self) -> &'static str {
        match self {
            Listing::Tags(_) => "tags",
            Listing::Catalog => "repositories",
        }
    }

    fn scope(&self) -> String {
        match self {
            Listing::Tags(image) => scope(image),
            Listing::Catalog => "registry:catalog:*".to_string(),
        }
    }

    fn valid(&self, name: &str) -> bool {
        match self {
            Listing::Tags(_) => reference::valid_tag(name),
            Listing::Catalog => reference::valid_name(name),
        }
    }

    fn what(&self) -> &'static str {
        match self {
            Listing::Tags(_) => "tag list",
            Listing::Catalog => "catalog",
        }
    }

    fn get(&self, url: String) -> Fetch {
        Fetch {
            scope: Some(self.scope()),
            ..Fetch::new(url, Freshness::Metadata)
        }
    }
}

/// Where [`list`] stands.
enum Listed {
    /// Fetch this page next.
    Fetch(Fetch),
    /// The upstream does not have the list (404).
    Unknown,
    Failed(String),
    /// The names, and whether there are more after them.
    Page(Vec<String>, bool),
}

/// Up to `limit` of the names of `listing` after `last`: one more is asked
/// for, to know whether there are more, and the upstream's own pages are
/// followed for up to [`MAX_UPSTREAM_TAG_PAGES`] requests. An upstream that
/// refuses so large an `n` (400, as registries that cap it answer) is asked
/// again without one: its own page size and links take over. The steps so
/// far are in `fetched`.
fn list(
    base: &str,
    listing: &Listing<'_>,
    last: Option<&str>,
    limit: usize,
    fetched: &[FetchResult],
) -> Listed {
    let first = |n: Option<usize>| {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(n) = n {
            query.append_pair("n", &n.to_string());
        }
        if let Some(last) = last {
            query.append_pair("last", last);
        }
        let query = query.finish();
        let url = listing.url(base);
        let url = if query.is_empty() {
            url
        } else {
            format!("{url}?{query}")
        };
        listing.get(url)
    };
    if fetched.is_empty() {
        return Listed::Fetch(first(Some(limit.saturating_add(1))));
    }
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut pages = 0;
    let mut left_out = false;
    for (i, result) in fetched.iter().enumerate() {
        let latest = i + 1 == fetched.len();
        if pages == 0 {
            if result.outcome == Fetched::NotFound {
                return Listed::Unknown;
            }
            if i == 0 && result.status == Some(400) {
                if latest {
                    return Listed::Fetch(first(None));
                }
                continue;
            }
        }
        let body = match &result.outcome {
            Fetched::Found(body) => body,
            Fetched::NotFound => {
                return Listed::Failed(format!(
                    "the upstream lost a page of the {}",
                    listing.what()
                ))
            }
            Fetched::Failed(reason) => return Listed::Failed(reason.clone()),
        };
        pages += 1;
        let Ok(document) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Listed::Failed(format!("the upstream served an invalid {}", listing.what()));
        };
        let listed = match document.get(listing.key()) {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(listed)) => listed.clone(),
            Some(_) => {
                return Listed::Failed(format!("the upstream served an invalid {}", listing.what()))
            }
        };
        names.extend(
            listed
                .into_iter()
                .filter_map(|name| name.as_str().map(str::to_string))
                .filter(|name| listing.valid(name))
                .filter(|name| last.is_none_or(|l| name.as_bytes() > l.as_bytes())),
        );
        if names.len() > limit {
            break;
        }
        if latest {
            match next_link(result, base) {
                Some(next) if pages < MAX_UPSTREAM_TAG_PAGES => {
                    return Listed::Fetch(listing.get(next))
                }
                Some(_) => left_out = true,
                None => {}
            }
        }
    }
    let more = left_out || names.len() > limit;
    Listed::Page(names.into_iter().take(limit).collect(), more)
}

/// The `next` page a tag list's `Link` header names (RFC 8288), resolved
/// against the page's URL: only a link back to the upstream itself is
/// followed, never one to another host.
fn next_link(result: &FetchResult, base: &str) -> Option<String> {
    let page = url::Url::parse(&result.fetch.url).ok()?;
    let base = url::Url::parse(base).ok()?;
    result
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("link"))
        .flat_map(|(_, value)| value.split(','))
        .find_map(|link| {
            let mut parts = link.split(';');
            let target = parts.next()?.trim().strip_prefix('<')?.strip_suffix('>')?;
            let next = parts.any(|param| {
                let param = param.trim().replace(' ', "");
                param.eq_ignore_ascii_case("rel=\"next\"") || param.eq_ignore_ascii_case("rel=next")
            });
            if !next {
                return None;
            }
            // Both as the URL parser writes them (lowercase host, no
            // default port).
            let url = page.join(target).ok()?;
            url.as_str()
                .strip_prefix(base.as_str().trim_end_matches('/'))
                .filter(|path| path.starts_with("/v2/"))
                .map(|_| url.to_string())
        })
}

/// The upstream's referrers of `digest`; `None` when it has no referrers
/// API (clients fall back to the tag scheme, which a proxy serves like any
/// tag) or it failed.
fn referrers(
    base: &str,
    image: &str,
    digest: &str,
    fetched: &[FetchResult],
) -> Result<UpstreamStep, FormatError> {
    let Some(result) = fetched.first() else {
        return Ok(UpstreamStep::Fetch(vec![get(
            format!("{base}/v2/{image}/referrers/{digest}"),
            image,
            Some(media::OCI_INDEX),
        )]));
    };
    let none = || Ok(UpstreamStep::Done(UpstreamAnswer::ImageReferrers(None)));
    let Fetched::Found(body) = &result.outcome else {
        return none();
    };
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Desc {
        media_type: Option<String>,
        digest: String,
        size: i64,
        artifact_type: Option<String>,
        annotations: Option<serde_json::Value>,
    }
    #[derive(serde::Deserialize)]
    struct Index {
        #[serde(default)]
        manifests: Vec<Desc>,
    }
    let Ok(index) = serde_json::from_slice::<Index>(body) else {
        return Ok(UpstreamStep::Done(UpstreamAnswer::Failed(
            "the upstream served an invalid referrers list".into(),
        )));
    };
    let found = index
        .manifests
        .into_iter()
        .filter(|d| Digest::parse(&d.digest).is_ok() && d.size >= 0)
        .map(|d| ManifestInfo {
            digest: d.digest,
            media_type: d.media_type.unwrap_or_else(|| media::OCI_MANIFEST.into()),
            size: d.size as u64,
            artifact_type: d.artifact_type,
            subject: Some(digest.to_string()),
            summary: d
                .annotations
                .map(|annotations| json!({ "annotations": annotations }).to_string()),
        })
        .collect();
    Ok(UpstreamStep::Done(UpstreamAnswer::ImageReferrers(Some(
        found,
    ))))
}

#[cfg(test)]
mod tests {
    use forge_plugin_api::testing::converse_answered;

    use super::*;
    use crate::Docker;

    fn remote(url: &str) -> Remote {
        Remote {
            url: url.into(),
            index: None,
        }
    }

    #[test]
    fn docker_hub_library_names() {
        let hub = "https://registry-1.docker.io";
        assert_eq!(proxied_image(hub, "nginx"), "library/nginx");
        assert_eq!(proxied_image(hub, "bitnami/nginx"), "bitnami/nginx");
        assert_eq!(proxied_image("https://ghcr.io", "nginx"), "nginx");
        assert_eq!(upstream_base("https://ghcr.io/v2/"), "https://ghcr.io");
        assert_eq!(
            upstream_base("https://r.example/prefix/"),
            "https://r.example/prefix"
        );
    }

    #[test]
    fn manifest_and_blob_urls() {
        let op = UpstreamOp::ImageManifest {
            image: "library/nginx".into(),
            reference: Reference::Tag("1.27".into()),
        };
        let UpstreamStep::Done(UpstreamAnswer::ImageUrl(url)) =
            step(&remote("https://registry-1.docker.io/v2/"), &op, &[]).unwrap()
        else {
            panic!("expected a URL");
        };
        assert_eq!(
            url.url,
            "https://registry-1.docker.io/v2/library/nginx/manifests/1.27"
        );
        assert!(url.accept.unwrap().contains(media::OCI_INDEX));
        assert_eq!(url.scope.as_deref(), Some("repository:library/nginx:pull"));
    }

    #[test]
    fn tag_lists_follow_the_upstreams_pages() {
        let base = "http://up.test";
        let mut pages = vec![
            (
                vec!["a", "b"],
                Some("</v2/team/app/tags/list?n=2&last=b>; rel=\"next\""),
            ),
            (
                vec!["c", "d"],
                Some("<http://elsewhere.test/v2/team/app/tags/list?last=d>; rel=\"next\""),
            ),
        ]
        .into_iter();
        let op = UpstreamOp::ImageTags {
            image: "team/app".into(),
            last: None,
            n: 10,
        };
        let conversed = converse_answered(&Docker, &remote(base), &op, |fetch| {
            let (tags, link) = pages.next().expect("no more pages");
            FetchResult {
                fetch: fetch.clone(),
                outcome: Fetched::Found(serde_json::to_vec(&json!({ "tags": tags })).unwrap()),
                status: Some(200),
                headers: link
                    .map(|l| vec![("link".to_string(), l.to_string())])
                    .unwrap_or_default(),
            }
        })
        .unwrap();
        assert_eq!(
            conversed.answer,
            UpstreamAnswer::ImageTags(Some(TagPage {
                tags: vec!["a".into(), "b".into(), "c".into(), "d".into()],
                more: false,
            }))
        );
        assert_eq!(
            conversed.fetches[0].url,
            "http://up.test/v2/team/app/tags/list?n=11"
        );
        assert_eq!(
            conversed.fetches[1].url,
            "http://up.test/v2/team/app/tags/list?n=2&last=b"
        );
        assert_eq!(conversed.fetches.len(), 2, "no link off the upstream");
    }

    #[test]
    fn the_catalog_is_paged_like_a_tag_list() {
        let mut pages = vec![
            (
                vec!["team/app", "team/db"],
                Some("</v2/_catalog?n=2&last=team%2Fdb>; rel=\"next\""),
            ),
            (vec!["Not A Name", "tools/cli"], None),
        ]
        .into_iter();
        let op = UpstreamOp::ImageCatalog {
            last: Some("base".into()),
            n: 10,
        };
        let conversed = converse_answered(&Docker, &remote("http://up.test"), &op, |fetch| {
            let (images, link) = pages.next().expect("no more pages");
            FetchResult {
                fetch: fetch.clone(),
                outcome: Fetched::Found(
                    serde_json::to_vec(&json!({ "repositories": images })).unwrap(),
                ),
                status: Some(200),
                headers: link
                    .map(|l| vec![("link".to_string(), l.to_string())])
                    .unwrap_or_default(),
            }
        })
        .unwrap();
        assert_eq!(
            conversed.answer,
            UpstreamAnswer::ImageCatalog(Some(CatalogPage {
                images: vec!["team/app".into(), "team/db".into(), "tools/cli".into()],
                more: false,
            })),
            "an invalid name is left out"
        );
        assert_eq!(
            conversed.fetches[0].url,
            "http://up.test/v2/_catalog?n=11&last=base"
        );
        assert_eq!(
            conversed.fetches[0].scope.as_deref(),
            Some("registry:catalog:*")
        );
        assert_eq!(
            conversed.fetches[1].url,
            "http://up.test/v2/_catalog?n=2&last=team%2Fdb"
        );
    }

    #[test]
    fn a_registry_without_a_catalog_has_none() {
        for (status, outcome) in [
            (404, Fetched::NotFound),
            (401, Fetched::Failed("401".into())),
            (403, Fetched::Failed("403".into())),
        ] {
            let op = UpstreamOp::ImageCatalog { last: None, n: 5 };
            let conversed = converse_answered(&Docker, &remote("http://up.test"), &op, |fetch| {
                FetchResult {
                    fetch: fetch.clone(),
                    outcome: outcome.clone(),
                    status: Some(status),
                    headers: Vec::new(),
                }
            })
            .unwrap();
            assert_eq!(
                conversed.answer,
                UpstreamAnswer::ImageCatalog(None),
                "{status}"
            );
        }
    }

    #[test]
    fn an_upstream_refusing_a_large_n_is_asked_without_one() {
        let op = UpstreamOp::ImageTags {
            image: "team/app".into(),
            last: Some("a".into()),
            n: 1,
        };
        let conversed = converse_answered(&Docker, &remote("http://up.test"), &op, |fetch| {
            let sized = fetch.url.contains("n=");
            FetchResult {
                fetch: fetch.clone(),
                outcome: if sized {
                    Fetched::Failed("400".into())
                } else {
                    Fetched::Found(br#"{"tags":["a","b","c"]}"#.to_vec())
                },
                status: Some(if sized { 400 } else { 200 }),
                headers: Vec::new(),
            }
        })
        .unwrap();
        assert_eq!(
            conversed.answer,
            UpstreamAnswer::ImageTags(Some(TagPage {
                tags: vec!["b".into()],
                more: true,
            }))
        );
        assert_eq!(
            conversed.fetches[1].url,
            "http://up.test/v2/team/app/tags/list?last=a"
        );
    }

    #[test]
    fn an_unknown_image_has_no_tags_and_referrers_need_an_api() {
        let op = UpstreamOp::ImageTags {
            image: "team/app".into(),
            last: None,
            n: 5,
        };
        let conversed = converse_answered(&Docker, &remote("http://up.test"), &op, |fetch| {
            FetchResult {
                fetch: fetch.clone(),
                outcome: Fetched::NotFound,
                status: Some(404),
                headers: Vec::new(),
            }
        })
        .unwrap();
        assert_eq!(conversed.answer, UpstreamAnswer::ImageTags(None));

        let digest = format!("sha256:{}", "ab".repeat(32));
        let op = UpstreamOp::ImageReferrers {
            image: "team/app".into(),
            digest: digest.clone(),
        };
        let conversed = converse_answered(&Docker, &remote("http://up.test"), &op, |fetch| {
            FetchResult {
                fetch: fetch.clone(),
                outcome: Fetched::NotFound,
                status: Some(404),
                headers: Vec::new(),
            }
        })
        .unwrap();
        assert_eq!(conversed.answer, UpstreamAnswer::ImageReferrers(None));
        assert_eq!(
            conversed.fetches[0].accept.as_deref(),
            Some(media::OCI_INDEX)
        );
    }
}
