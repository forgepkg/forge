//! Docker / OCI registries for Forge, as a format plugin: the
//! distribution-spec v1.1 API under `/v2`, over the host's image store.
//!
//! * [`path`], [`digest`], [`reference`]: the protocol's paths and the
//!   grammar of its names, references and digests;
//! * [`manifest`]: Docker v2 schema 2 manifests and manifest lists, OCI
//!   image manifests and indexes, artifacts with `artifactType` and
//!   `subject`, and what Forge shows of them (their summaries);
//! * [`chart`]: Helm charts stored as artifacts: their metadata, README and
//!   values, for the web UI;
//! * [`error`]: the distribution-spec error answers;
//! * [`upstream`]: the URLs of an upstream registry, and its tag lists and
//!   referrers.
//!
//! Forge links this plugin in ([`Docker`], [`DESCRIPTOR`]). The host keeps
//! everything else: the image store (blobs and manifests by digest, tags,
//! upload sessions, groups, proxies' caching, garbage collection), the
//! token service at `/v2/token`, resolving a `<name>` (by path,
//! `<repository>/<image>`, or by a repository's own host) and authorizing
//! a request.

pub mod chart;
pub mod digest;
pub mod error;
pub mod manifest;
pub mod path;
mod protocol;
pub mod reference;
pub mod upstream;

use forge_plugin_api::images::{
    ArtifactFiles, BlobInfo, ConfigBlob, ImageError, ImagePath, ManifestBlob, ParsedManifest,
    Permission, TextFile,
};
use forge_plugin_api::{
    Action, Assets, Descriptor, FetchResult, FormatError, FormatPlugin, Loaded, PackageSource,
    Remote, Repository, RepositoryKind, Request, Response, Storage, UpstreamOp, UpstreamStep,
    UpstreamToken,
};

use crate::manifest::{media, ManifestError, EMPTY_JSON, EMPTY_JSON_DIGEST};
use crate::path::Endpoint;

/// What Docker / OCI says about itself: its format id, name and version.
pub const DESCRIPTOR: Descriptor = Descriptor {
    id: "docker",
    name: "Docker / OCI",
    version: env!("CARGO_PKG_VERSION"),
    description: "Docker / OCI registries: push and pull images, indexes and artifacts (Helm \
                  charts, signatures, SBOMs) with docker, podman, containerd, crane, helm and \
                  cosign; proxies of Docker Hub and other registries.",
    kinds: &[
        RepositoryKind::Hosted,
        RepositoryKind::Proxy,
        RepositoryKind::Group,
    ],
    // Blobs and manifests by digest, tags and upload sessions, in the
    // host's image store.
    storage: Storage::Images,
    assets: Assets::DEFAULT,
    // The host's image store answers an upstream's Bearer challenge itself.
    upstream_token: UpstreamToken::None,
    options: &[],
    prereleases: forge_plugin_api::Prereleases::Dash,
    indexes: false,
};

/// The Docker / OCI format.
#[derive(Debug, Clone, Copy, Default)]
pub struct Docker;

impl FormatPlugin for Docker {
    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }

    /// An image name: the spec's repository-name grammar
    /// ([`reference::valid_name`]).
    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        if reference::valid_name(id) {
            Ok(())
        } else {
            Err(FormatError::InvalidId(format!(
                "{id:?} is not an image name"
            )))
        }
    }

    /// An image-name prefix a group reserves: letters, digits, `.`, `_`,
    /// `-` and `/` (a namespace such as `acme/`), lowercased.
    fn reserved_prefix(&self, prefix: &str) -> Result<String, FormatError> {
        let valid = !prefix.is_empty()
            && prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
        if valid {
            Ok(prefix.to_ascii_lowercase())
        } else {
            Err(FormatError::InvalidId(format!(
                "{prefix:?} is not an image name prefix (letters, digits, '.', '_', '-', '/')"
            )))
        }
    }

    fn handle(&self, _repo: &Repository, req: &Request) -> Action {
        protocol::handle(req)
    }

    fn render(&self, _repo: &Repository, req: &Request, data: &[Loaded]) -> Action {
        protocol::render(req, data)
    }

    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        upstream::step(remote, op, fetched)
    }

    fn image_path(&self, method: &str, path: &str) -> Result<ImagePath, ImageError> {
        let (endpoint, rest) = path::split(path).ok_or(ImageError::NotAnEndpoint)?;
        let name = endpoint.name().unwrap_or_default().to_string();
        if !reference::valid_name(&name) {
            return Err(ImageError::NameInvalid { name, hint: None });
        }
        Ok(ImagePath {
            name,
            endpoint: rest,
            permission: permission(&endpoint, method),
        })
    }

    fn image_error(&self, error: &ImageError) -> Response {
        error::of(error).into_response()
    }

    fn parse_manifest(
        &self,
        manifest: &[u8],
        content_type: Option<&str>,
    ) -> Result<ParsedManifest, FormatError> {
        let parsed = manifest::parse(manifest, content_type).map_err(|e| {
            FormatError::MalformedManifest(match e {
                ManifestError::UnsupportedMediaType(m) => {
                    format!("unsupported manifest media type {m:?}")
                }
                other => other.to_string(),
            })
        })?;
        Ok(contract(&parsed))
    }

    fn config_summary(&self, media_type: &str, config: &[u8]) -> Option<String> {
        manifest::config_summary(media_type, config).map(|part| part.to_string())
    }

    fn artifact_files(&self, blob: &mut dyn PackageSource) -> ArtifactFiles {
        let files = chart::read_files(blob);
        let text = |file: chart::ChartFile| TextFile {
            name: file.name,
            text: file.text,
            truncated: file.truncated,
        };
        ArtifactFiles {
            readme: files.readme.map(text),
            values: files.values.map(text),
        }
    }
}

/// What a request of `method` to `endpoint` needs.
fn permission(endpoint: &Endpoint, method: &str) -> Permission {
    match (endpoint, method) {
        (Endpoint::UploadStart { .. } | Endpoint::Upload { .. }, _) => Permission::Write,
        (_, "PUT" | "POST" | "PATCH") => Permission::Write,
        (_, "DELETE") => Permission::Delete,
        _ => Permission::Read,
    }
}

/// A parsed manifest as the plugin contract carries it.
fn contract(parsed: &manifest::ParsedManifest) -> ParsedManifest {
    ParsedManifest {
        media_type: parsed.media_type.clone(),
        blobs: parsed
            .blob_references()
            .into_iter()
            .map(|d| ManifestBlob {
                digest: d.digest.to_string(),
                size: d.size.max(0) as u64,
                // Layers that live elsewhere by definition.
                required: !media::is_non_distributable(&d.media_type),
                // Clients commonly reference the empty JSON as an
                // artifact's config without uploading it.
                known: (d.digest.as_str() == EMPTY_JSON_DIGEST).then(|| EMPTY_JSON.to_vec()),
            })
            .collect(),
        manifests: parsed
            .manifest_references()
            .into_iter()
            .map(|d| d.digest.to_string())
            .collect(),
        subject: parsed.subject.as_ref().map(|s| s.digest.to_string()),
        artifact_type: parsed.artifact_type.clone(),
        config: parsed.summary_config().map(|c| ConfigBlob {
            digest: c.digest.to_string(),
            media_type: c.media_type.clone(),
            size: c.size.max(0) as u64,
        }),
        files: parsed.chart_archive().map(|a| BlobInfo {
            digest: a.digest.to_string(),
            size: a.size.max(0) as u64,
        }),
        summary: parsed.summary().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_split_into_names_endpoints_and_permissions() {
        let split = |method: &str, path: &str| Docker.image_path(method, path);
        let manifest = split("PUT", "/docker/team/app/manifests/1").unwrap();
        assert_eq!(manifest.name, "docker/team/app");
        assert_eq!(manifest.endpoint, "/manifests/1");
        assert_eq!(manifest.permission, Permission::Write);
        assert_eq!(
            split("GET", "/a/b/manifests/x").unwrap().permission,
            Permission::Read
        );
        assert_eq!(
            split("HEAD", "/a/b/blobs/sha256:00").unwrap().permission,
            Permission::Read
        );
        assert_eq!(
            split("DELETE", "/a/b/manifests/x").unwrap().permission,
            Permission::Delete
        );
        // Every request of an upload session writes.
        for method in ["GET", "DELETE"] {
            assert_eq!(
                split(method, "/a/b/blobs/uploads/x").unwrap().permission,
                Permission::Write
            );
        }
        assert_eq!(split("GET", "/x"), Err(ImageError::NotAnEndpoint));
        assert!(matches!(
            split("GET", "/A/b/manifests/x"),
            Err(ImageError::NameInvalid { .. })
        ));
    }

    #[test]
    fn manifests_name_what_a_push_needs() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media::OCI_MANIFEST,
            "config": {"mediaType": media::OCI_EMPTY, "digest": EMPTY_JSON_DIGEST, "size": 2},
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                 "digest": format!("sha256:{}", "11".repeat(32)), "size": 5,
                 "urls": ["https://example.com/layer"]}
            ],
            "subject": {"mediaType": media::OCI_MANIFEST,
                        "digest": format!("sha256:{}", "22".repeat(32)), "size": 9}
        });
        let parsed = Docker
            .parse_manifest(body.to_string().as_bytes(), None)
            .unwrap();
        assert_eq!(parsed.media_type, media::OCI_MANIFEST);
        assert_eq!(parsed.blobs.len(), 2);
        assert_eq!(parsed.blobs[0].known.as_deref(), Some(EMPTY_JSON));
        assert!(!parsed.blobs[1].required);
        assert_eq!(parsed.subject, Some(format!("sha256:{}", "22".repeat(32))));
        assert!(parsed.config.is_none(), "the empty JSON says nothing");
        let refused = Docker.parse_manifest(b"{}", Some("application/vnd.example"));
        assert!(
            matches!(refused, Err(FormatError::MalformedManifest(m)) if m.contains("unsupported"))
        );
    }
}
