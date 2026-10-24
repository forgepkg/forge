//! The distribution-spec v1.1 API of an image: what each request is
//! ([`handle`]), and the answer once the image store answered
//! ([`render`]).
//!
//! The host has resolved the name, authorized the request and picked where
//! a change lands; the request's path is the endpoint after the name.

use forge_plugin_api::images::{
    ChunkRange, ImageAnswer, ImageError, ImageName, ImageQuery, ManifestInfo, Mount, Reference,
    Started, UploadState,
};
use forge_plugin_api::{Action, Answer, Loaded, Query, Request, Response};
use serde_json::{json, Value};

use crate::digest::{Digest, DigestError};
use crate::error::{self, Code, OciError};
use crate::manifest::media;
use crate::path::{self, Endpoint};
use crate::reference::{self, ReferenceError};

/// Tags returned by one `tags/list` page when the client sets no `n`, and
/// the most one page returns.
const DEFAULT_TAG_PAGE: u32 = 10_000;

/// What a request is.
pub fn handle(req: &Request) -> Action {
    let Some((image, endpoint)) = endpoint(req) else {
        return respond(error::of(&ImageError::NotAnEndpoint));
    };
    match request(image, &endpoint, req) {
        Ok(action) => action,
        Err(e) => respond(e),
    }
}

/// The answer once the store answered the request's query.
pub fn render(req: &Request, data: &[Loaded]) -> Action {
    let (Some((image, _)), Some(last)) = (endpoint(req), data.last()) else {
        return respond(error::of(&ImageError::Internal));
    };
    let (Query::Image(query), Answer::Image(answer)) = (&last.query, &last.answer) else {
        return respond(error::of(&ImageError::Internal));
    };
    match answered(image, req, query, answer) {
        Ok(action) => action,
        Err(e) => respond(e),
    }
}

/// The image of the request and its endpoint.
fn endpoint(req: &Request) -> Option<(&ImageName, Endpoint)> {
    let image = req.image.as_ref()?;
    let endpoint = path::of_name(&image.name, &req.path)?;
    Some((image, endpoint))
}

fn respond(error: OciError) -> Action {
    Action::Respond(error.into_response())
}

fn load(query: ImageQuery) -> Result<Action, OciError> {
    Ok(Action::Load(vec![Query::Image(query)]))
}

fn request(image: &ImageName, endpoint: &Endpoint, req: &Request) -> Result<Action, OciError> {
    let name = image.image.clone();
    match (endpoint, req.method.as_str()) {
        (Endpoint::Manifest { reference, .. }, "GET" | "HEAD") => {
            let parsed = parse_reference(reference).map_err(|e| {
                // A malformed reference names nothing that can exist.
                if e.code == Code::ManifestInvalid {
                    OciError::manifest_unknown(reference)
                } else {
                    e
                }
            })?;
            load(ImageQuery::Manifest {
                image: name,
                reference: parsed,
            })
        }
        (Endpoint::Manifest { reference, .. }, "PUT") => {
            let reference = parse_reference(reference)?;
            let mut tags: Vec<String> = Vec::new();
            if let Reference::Tag(tag) = &reference {
                tags.push(tag.clone());
            }
            for (key, value) in req.query_pairs() {
                if key == "tag" {
                    if !reference::valid_tag(&value) {
                        return Err(OciError::manifest_invalid(format!("invalid tag {value:?}")));
                    }
                    if !tags.contains(&value) {
                        tags.push(value);
                    }
                }
            }
            load(ImageQuery::PutManifest {
                image: name,
                reference,
                tags,
            })
        }
        (Endpoint::Manifest { reference, .. }, "DELETE") => load(ImageQuery::DeleteManifest {
            image: name,
            reference: parse_reference(reference)?,
        }),
        (Endpoint::Blob { digest, .. }, "GET" | "HEAD") => load(ImageQuery::Blob {
            image: name,
            digest: parse_digest(digest)?.into_string(),
        }),
        (Endpoint::Blob { digest, .. }, "DELETE") => load(ImageQuery::DeleteBlob {
            image: name,
            digest: parse_digest(digest)?.into_string(),
        }),
        (Endpoint::UploadStart { .. }, "POST") => {
            let mount = match req.query_param("mount") {
                Some(digest) => Some(Mount {
                    digest: parse_digest(&digest)?.into_string(),
                    from: req
                        .query_param("from")
                        .filter(|from| reference::valid_name(from)),
                }),
                None => None,
            };
            // A monolithic upload: checked now, finished once the session
            // stands.
            if let Some(digest) = req.query_param("digest") {
                parse_digest(&digest)?;
            }
            load(ImageQuery::StartUpload { image: name, mount })
        }
        (Endpoint::Upload { id, .. }, "GET") => load(ImageQuery::UploadStatus(id.clone())),
        (Endpoint::Upload { id, .. }, "PATCH") => load(ImageQuery::AppendUpload {
            id: id.clone(),
            range: content_range(req)?,
        }),
        (Endpoint::Upload { id, .. }, "PUT") => {
            let digest = req.query_param("digest").ok_or_else(|| {
                OciError::digest_invalid("the digest query parameter is required")
            })?;
            load(ImageQuery::FinishUpload {
                id: id.clone(),
                digest: parse_digest(&digest)?.into_string(),
                range: content_range(req)?,
            })
        }
        (Endpoint::Upload { id, .. }, "DELETE") => load(ImageQuery::CancelUpload(id.clone())),
        (Endpoint::TagsList { .. }, "GET") => {
            let mut n: Option<u32> = None;
            for (key, value) in req.query_pairs() {
                if key == "n" {
                    // A page larger than the most one returns is that many.
                    let parsed: u64 = value.parse().map_err(|_| {
                        OciError::new(400, Code::Unsupported, format!("invalid n {value:?}"))
                    })?;
                    n = Some(parsed.min(u64::from(DEFAULT_TAG_PAGE)) as u32);
                }
            }
            let page = n.unwrap_or(DEFAULT_TAG_PAGE);
            if page == 0 {
                return Ok(Action::Respond(tag_list(&image.name, &[], None)));
            }
            load(ImageQuery::Tags {
                image: name,
                last: req.query_param("last"),
                n: page,
            })
        }
        (Endpoint::Referrers { digest, .. }, "GET") => load(ImageQuery::Referrers {
            image: name,
            digest: parse_digest(digest)?.into_string(),
            artifact_type: req.query_param("artifactType"),
        }),
        _ => Err(OciError::unsupported("method not allowed on this endpoint")),
    }
}

fn answered(
    image: &ImageName,
    req: &Request,
    query: &ImageQuery,
    answer: &ImageAnswer,
) -> Result<Action, OciError> {
    let name = &image.name;
    let respond = |response: Response| Ok(Action::Respond(response));
    match (query, answer) {
        (ImageQuery::Manifest { reference, .. }, ImageAnswer::Manifest(found)) => {
            match failed(found)? {
                Some(_) => Ok(Action::ServeManifest {
                    image: image.image.clone(),
                    reference: reference.clone(),
                }),
                None => Err(OciError::manifest_unknown(reference.as_str())),
            }
        }
        (ImageQuery::Blob { digest, .. }, ImageAnswer::Blob(found)) => match failed(found)? {
            Some(_) => Ok(Action::ServeBlob {
                image: image.image.clone(),
                digest: digest.clone(),
            }),
            None => Err(OciError::blob_unknown(digest)),
        },
        (ImageQuery::Tags { n, .. }, ImageAnswer::Tags(found)) => match failed(found)? {
            Some(page) => {
                let next = page.more.then_some(*n);
                respond(tag_list(name, &page.tags, next))
            }
            None => Err(OciError::name_unknown(name)),
        },
        (ImageQuery::Referrers { artifact_type, .. }, ImageAnswer::Referrers(found)) => {
            respond(referrers(failed(found)?, artifact_type.is_some()))
        }
        (ImageQuery::StartUpload { .. }, ImageAnswer::Started(started)) => {
            match failed(started)? {
                Started::Mounted(blob) => respond(blob_created(name, &blob.digest)),
                Started::Session(state) => match req.query_param("digest") {
                    // A monolithic upload: the body is the whole blob.
                    Some(digest) => load(ImageQuery::FinishUpload {
                        id: state.id.clone(),
                        digest: parse_digest(&digest)?.into_string(),
                        range: None,
                    }),
                    None => respond(upload_accepted(202, name, state)),
                },
            }
        }
        (ImageQuery::UploadStatus(_), ImageAnswer::Upload(state)) => {
            respond(upload_accepted(204, name, failed(state)?))
        }
        (ImageQuery::AppendUpload { .. }, ImageAnswer::Upload(state)) => {
            respond(upload_accepted(202, name, failed(state)?))
        }
        (ImageQuery::FinishUpload { digest, .. }, ImageAnswer::Blob(stored)) => {
            failed(stored)?;
            respond(blob_created(name, digest))
        }
        (ImageQuery::CancelUpload(_), ImageAnswer::Done(done)) => {
            failed(done)?;
            respond(Response::empty(204))
        }
        (
            ImageQuery::PutManifest {
                reference, tags, ..
            },
            ImageAnswer::Stored(stored),
        ) => {
            let stored = match stored {
                Ok(stored) => stored,
                Err(ImageError::DigestMismatch) => {
                    return Err(OciError::digest_invalid(
                        "the manifest does not match the digest it was pushed as",
                    ))
                }
                Err(ImageError::BodyUnreadable) => {
                    return Err(OciError::manifest_invalid(
                        "the request body could not be read",
                    ))
                }
                Err(e) => return Err(error::of(e)),
            };
            let mut response = Response::empty(201)
                .with_header(
                    "location",
                    &format!("/v2/{name}/manifests/{}", stored.digest),
                )
                .with_header("docker-content-digest", &stored.digest);
            if let Some(subject) = &stored.subject {
                response = response.with_header("oci-subject", subject);
            }
            // A push by digest with `?tag=` parameters names every tag it set.
            if matches!(reference, Reference::Digest(_)) {
                for tag in tags {
                    response = response.with_header("oci-tag", tag);
                }
            }
            respond(response)
        }
        (
            ImageQuery::DeleteManifest { .. } | ImageQuery::DeleteBlob { .. },
            ImageAnswer::Done(done),
        ) => {
            failed(done)?;
            respond(Response::empty(202))
        }
        _ => Err(error::of(&ImageError::Internal)),
    }
}

/// An answer's value, or its error as the client sees it.
fn failed<T>(answer: &Result<T, ImageError>) -> Result<&T, OciError> {
    answer.as_ref().map_err(error::of)
}

pub(crate) fn parse_digest(raw: &str) -> Result<Digest, OciError> {
    Digest::parse(raw).map_err(|e| match e {
        DigestError::Invalid(_) => OciError::digest_invalid(format!("invalid digest {raw:?}")),
        DigestError::Unsupported(_) => OciError::digest_invalid(format!(
            "unsupported digest algorithm in {raw:?}: use sha256 or sha512"
        )),
    })
}

fn parse_reference(raw: &str) -> Result<Reference, OciError> {
    match reference::Reference::parse(raw) {
        Ok(reference::Reference::Tag(tag)) => Ok(Reference::Tag(tag)),
        Ok(reference::Reference::Digest(digest)) => Ok(Reference::Digest(digest.into_string())),
        Err(ReferenceError::InvalidTag) => {
            Err(OciError::manifest_invalid(format!("invalid tag {raw:?}"))
                .with_detail(json!({ "reference": raw })))
        }
        Err(ReferenceError::Digest(_)) => Err(parse_digest(raw)
            .err()
            .unwrap_or_else(|| OciError::digest_invalid(format!("invalid digest {raw:?}")))),
    }
}

/// `Content-Range: <start>-<end>` of a chunk (also accepting a `bytes`
/// prefix some clients add).
fn content_range(req: &Request) -> Result<Option<ChunkRange>, OciError> {
    let Some(value) = req.header("content-range") else {
        return Ok(None);
    };
    let invalid = || OciError::new(416, Code::BlobUploadInvalid, "invalid Content-Range");
    let text = value.trim();
    let text = text
        .strip_prefix("bytes=")
        .or_else(|| text.strip_prefix("bytes "))
        .unwrap_or(text);
    let text = text.split('/').next().unwrap_or(text);
    let (start, end) = text.split_once('-').ok_or_else(invalid)?;
    let start: u64 = start.trim().parse().map_err(|_| invalid())?;
    let end: u64 = end.trim().parse().map_err(|_| invalid())?;
    if end < start {
        return Err(invalid());
    }
    Ok(Some(ChunkRange { start, end }))
}

/// The answer of an upload session in progress.
fn upload_accepted(status: u16, name: &str, upload: &UploadState) -> Response {
    Response::empty(status)
        .with_header(
            "location",
            &format!("/v2/{name}/blobs/uploads/{}", upload.id),
        )
        .with_header("range", &error::upload_range(upload.size))
        .with_header("docker-upload-uuid", &upload.id)
}

/// The 201 answer of a stored blob.
fn blob_created(name: &str, digest: &str) -> Response {
    Response::empty(201)
        .with_header("location", &format!("/v2/{name}/blobs/{digest}"))
        .with_header("docker-content-digest", digest)
}

/// A `tags/list` page, linking to the next one when there is one (`n`: the
/// page size).
fn tag_list(name: &str, tags: &[String], next: Option<u32>) -> Response {
    let body = json!({ "name": name, "tags": tags }).to_string();
    let response = Response::new(200, "application/json", body);
    match (next, tags.last()) {
        (Some(n), Some(last)) => {
            let query: String = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("n", &n.to_string())
                .append_pair("last", last)
                .finish();
            response.with_header(
                "link",
                &format!("</v2/{name}/tags/list?{query}>; rel=\"next\""),
            )
        }
        _ => response,
    }
}

/// The referrers of a manifest, as an OCI index.
fn referrers(found: &[ManifestInfo], filtered: bool) -> Response {
    let manifests: Vec<Value> = found.iter().map(descriptor).collect();
    let body = json!({
        "schemaVersion": 2,
        "mediaType": media::OCI_INDEX,
        "manifests": manifests,
    });
    let response = Response::new(200, media::OCI_INDEX, body.to_string());
    if filtered {
        response.with_header("oci-filters-applied", "artifactType")
    } else {
        response
    }
}

/// A referrer's descriptor: its annotations are kept in its summary.
fn descriptor(manifest: &ManifestInfo) -> Value {
    let mut descriptor = json!({
        "mediaType": manifest.media_type,
        "digest": manifest.digest,
        "size": manifest.size,
    });
    if let Some(artifact_type) = &manifest.artifact_type {
        descriptor["artifactType"] = json!(artifact_type);
    }
    let annotations = manifest
        .summary
        .as_deref()
        .and_then(|summary| serde_json::from_str::<Value>(summary).ok())
        .and_then(|summary| summary.get("annotations").cloned())
        .filter(|a| a.as_object().is_some_and(|o| !o.is_empty()));
    if let Some(annotations) = annotations {
        descriptor["annotations"] = annotations;
    }
    descriptor
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, target: &str) -> Request {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let mut req = Request::new(method, path).with_image("team/app", "docker/team/app");
        req.query = query.to_string();
        req
    }

    fn sha(n: u8) -> String {
        format!("sha256:{}", format!("{n:02x}").repeat(32))
    }

    #[test]
    fn content_ranges() {
        let with = |value: &str| {
            content_range(&req("PATCH", "/blobs/uploads/x").with_header("content-range", value))
        };
        assert_eq!(
            content_range(&req("PATCH", "/blobs/uploads/x")).unwrap(),
            None
        );
        assert_eq!(
            with("0-99").unwrap(),
            Some(ChunkRange { start: 0, end: 99 })
        );
        assert_eq!(
            with("bytes 100-199/*").unwrap(),
            Some(ChunkRange {
                start: 100,
                end: 199
            })
        );
        assert_eq!(with("9-1").unwrap_err().status, 416);
    }

    #[test]
    fn a_get_of_a_malformed_reference_names_an_unknown_manifest() {
        let Action::Respond(response) = handle(&req("GET", "/manifests/-bad")) else {
            panic!("expected a response");
        };
        assert_eq!(response.status, 404);
        let Action::Load(queries) = handle(&req("GET", &format!("/manifests/{}", sha(1)))) else {
            panic!("expected a load");
        };
        assert_eq!(
            queries,
            [Query::Image(ImageQuery::Manifest {
                image: "team/app".into(),
                reference: Reference::Digest(sha(1)),
            })]
        );
    }

    #[test]
    fn tag_pages_link_to_the_next() {
        let response = tag_list("docker/team/app", &["a".into(), "b c".into()], Some(2));
        let link = response
            .headers
            .iter()
            .find(|(k, _)| k == "link")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            link,
            Some("</v2/docker/team/app/tags/list?n=2&last=b+c>; rel=\"next\"")
        );
        assert!(!tag_list("x", &[], Some(2))
            .headers
            .iter()
            .any(|(k, _)| k == "link"));
    }
}
