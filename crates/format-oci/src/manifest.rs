//! Manifest parsing: Docker v2 schema 2 manifests and manifest lists, OCI
//! image manifests and indexes (including artifacts with an `artifactType`
//! and a `subject`), and the pre-1.1 OCI artifact manifest.
//!
//! Parsing is deliberately lenient about fields Forge does not use (unknown
//! fields are kept in the stored bytes, which are served unchanged) and
//! strict about the ones it does: every descriptor must carry a supported,
//! well-formed digest and a non-negative size, because those digests decide
//! what a manifest keeps alive in the CAS and what a proxy fetches.

use serde::{Deserialize, Serialize};

use crate::digest::Digest;

/// The media types Forge stores as manifests.
pub mod media {
    pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
    pub const OCI_ARTIFACT_MANIFEST: &str = "application/vnd.oci.artifact.manifest.v1+json";
    pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
    pub const DOCKER_MANIFEST_LIST: &str =
        "application/vnd.docker.distribution.manifest.list.v2+json";
    /// Docker schema 1, refused: deprecated, unsigned-insecure, and no longer
    /// served by Docker Hub.
    pub const DOCKER_SCHEMA1: &str = "application/vnd.docker.distribution.manifest.v1+json";
    pub const DOCKER_SCHEMA1_SIGNED: &str =
        "application/vnd.docker.distribution.manifest.v1+prettyjws";

    pub const OCI_IMAGE_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    pub const DOCKER_IMAGE_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
    /// The OCI empty descriptor's media type (`{}`, two bytes).
    pub const OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";

    /// Every manifest media type a pull may be answered with, for `Accept`
    /// headers sent upstream.
    pub const ACCEPT_ALL: &[&str] = &[
        OCI_INDEX,
        OCI_MANIFEST,
        DOCKER_MANIFEST_LIST,
        DOCKER_MANIFEST,
        OCI_ARTIFACT_MANIFEST,
    ];

    /// Whether `media_type` is one Forge stores as a manifest.
    pub fn is_manifest(media_type: &str) -> bool {
        ACCEPT_ALL.contains(&media_type)
    }

    /// Layers that are, by definition, not pushed to the registry (their
    /// descriptors point at `urls` elsewhere), so a manifest may reference
    /// them without the blob existing.
    pub fn is_non_distributable(media_type: &str) -> bool {
        media_type.starts_with("application/vnd.oci.image.layer.nondistributable.")
            || media_type.starts_with("application/vnd.docker.image.rootfs.foreign.")
    }
}

/// Digest and bytes of the OCI empty JSON blob (`{}`), the config of most
/// artifacts. Clients may reference it without uploading it first.
pub const EMPTY_JSON: &[u8] = b"{}";
pub const EMPTY_JSON_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// Largest manifest Forge accepts or proxies. The spec asks registries to
/// accept at least 4 MiB.
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Whether the manifest is a single image/artifact or a list of manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    /// Docker v2 / OCI image manifest or artifact manifest: config + layers.
    Image,
    /// Docker manifest list / OCI index: child manifests.
    Index,
}

/// A content descriptor (`mediaType`, `digest`, `size`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: i64,
    pub platform: Option<Platform>,
    pub artifact_type: Option<String>,
    pub annotations: Option<serde_json::Map<String, serde_json::Value>>,
    /// External locations (non-distributable layers).
    pub has_urls: bool,
}

/// A descriptor's `platform` (index children only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Platform {
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(
        rename = "os.version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
}

impl Platform {
    /// `os/architecture[/variant]`, e.g. `linux/arm64/v8`.
    pub fn label(&self) -> String {
        match &self.variant {
            Some(v) if !v.is_empty() => format!("{}/{}/{}", self.os, self.architecture, v),
            _ => format!("{}/{}", self.os, self.architecture),
        }
    }
}

/// What Forge needs from a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedManifest {
    /// The effective media type (the `mediaType` field, else the declared
    /// Content-Type, else inferred for OCI content without either).
    pub media_type: String,
    pub kind: ManifestKind,
    /// `artifactType`, or for an image manifest without one, its config's
    /// media type (what the referrers API reports).
    pub artifact_type: Option<String>,
    pub config: Option<Descriptor>,
    /// Layers of an image manifest (`blobs` of an artifact manifest).
    pub layers: Vec<Descriptor>,
    /// Children of an index.
    pub manifests: Vec<Descriptor>,
    pub subject: Option<Descriptor>,
    pub annotations: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ParsedManifest {
    /// Blobs this manifest references (config first, then layers), each once.
    pub fn blob_references(&self) -> Vec<&Descriptor> {
        let mut out: Vec<&Descriptor> = Vec::new();
        for d in self.config.iter().chain(self.layers.iter()) {
            if !out.iter().any(|seen| seen.digest == d.digest) {
                out.push(d);
            }
        }
        out
    }

    /// The child manifests of an index, each once.
    pub fn manifest_references(&self) -> Vec<&Descriptor> {
        let mut out: Vec<&Descriptor> = Vec::new();
        for d in &self.manifests {
            if !out.iter().any(|seen| seen.digest == d.digest) {
                out.push(d);
            }
        }
        out
    }

    /// Total size of the layers (the compressed image size).
    pub fn layers_size(&self) -> i64 {
        self.layers.iter().map(|l| l.size).sum()
    }
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest is not valid JSON: {0}")]
    Json(String),
    #[error("{0}")]
    Invalid(String),
    #[error("unsupported manifest media type {0:?}")]
    UnsupportedMediaType(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawManifest {
    schema_version: Option<i64>,
    media_type: Option<String>,
    artifact_type: Option<String>,
    config: Option<RawDescriptor>,
    layers: Option<Vec<RawDescriptor>>,
    /// Artifact manifest (pre-1.1) only.
    blobs: Option<Vec<RawDescriptor>>,
    manifests: Option<Vec<RawDescriptor>>,
    subject: Option<RawDescriptor>,
    annotations: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDescriptor {
    media_type: Option<String>,
    digest: Option<String>,
    size: Option<i64>,
    platform: Option<Platform>,
    artifact_type: Option<String>,
    annotations: Option<serde_json::Map<String, serde_json::Value>>,
    urls: Option<Vec<String>>,
}

fn descriptor(raw: RawDescriptor, what: &str) -> Result<Descriptor, ManifestError> {
    let digest = raw
        .digest
        .as_deref()
        .ok_or_else(|| ManifestError::Invalid(format!("{what} has no digest")))?;
    let digest =
        Digest::parse(digest).map_err(|e| ManifestError::Invalid(format!("{what}: {e}")))?;
    let size = raw
        .size
        .ok_or_else(|| ManifestError::Invalid(format!("{what} has no size")))?;
    if size < 0 {
        return Err(ManifestError::Invalid(format!(
            "{what} has a negative size"
        )));
    }
    Ok(Descriptor {
        media_type: raw.media_type.unwrap_or_default(),
        digest,
        size,
        platform: raw.platform,
        artifact_type: raw.artifact_type,
        annotations: raw.annotations,
        has_urls: raw.urls.is_some_and(|u| !u.is_empty()),
    })
}

/// The media type of a `Content-Type` header value, without parameters.
pub fn base_media_type(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or_default().trim()
}

/// Parse `bytes` as a manifest. `content_type` is the request's
/// Content-Type (a push) or the upstream response's (a proxy fetch), if any.
///
/// A `mediaType` field must agree with a manifest Content-Type; content
/// without either is accepted only when its shape is unambiguously OCI
/// (`manifests` → index, `config` → image manifest), as OCI made the field
/// optional.
pub fn parse(bytes: &[u8], content_type: Option<&str>) -> Result<ParsedManifest, ManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::Invalid(format!(
            "manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let raw: RawManifest =
        serde_json::from_slice(bytes).map_err(|e| ManifestError::Json(e.to_string()))?;
    let declared = content_type.map(base_media_type).filter(|ct| {
        !ct.is_empty() && *ct != "application/json" && *ct != "application/octet-stream"
    });

    let field = raw.media_type.as_deref().filter(|m| !m.is_empty());
    if let (Some(field), Some(declared)) = (field, declared) {
        if field != declared {
            return Err(ManifestError::Invalid(format!(
                "Content-Type {declared:?} does not match the manifest's mediaType {field:?}"
            )));
        }
    }
    let media_type = match field.or(declared) {
        Some(m) => m.to_string(),
        None if raw.manifests.is_some() => media::OCI_INDEX.to_string(),
        None if raw.config.is_some() => media::OCI_MANIFEST.to_string(),
        None => {
            return Err(ManifestError::Invalid(
                "manifest declares no media type".into(),
            ))
        }
    };
    if media_type == media::DOCKER_SCHEMA1 || media_type == media::DOCKER_SCHEMA1_SIGNED {
        return Err(ManifestError::UnsupportedMediaType(media_type));
    }
    if !media::is_manifest(&media_type) {
        return Err(ManifestError::UnsupportedMediaType(media_type));
    }
    if raw.schema_version != Some(2) && media_type != media::OCI_ARTIFACT_MANIFEST {
        return Err(ManifestError::Invalid("schemaVersion must be 2".into()));
    }

    let kind = match media_type.as_str() {
        media::OCI_INDEX | media::DOCKER_MANIFEST_LIST => ManifestKind::Index,
        _ => ManifestKind::Image,
    };
    let subject = raw.subject.map(|s| descriptor(s, "subject")).transpose()?;

    let (config, layers, manifests) = match kind {
        ManifestKind::Index => {
            if raw.config.is_some() || raw.layers.is_some() {
                return Err(ManifestError::Invalid(
                    "an index carries no config or layers".into(),
                ));
            }
            let manifests = raw
                .manifests
                .ok_or_else(|| ManifestError::Invalid("an index needs `manifests`".into()))?
                .into_iter()
                .enumerate()
                .map(|(i, d)| descriptor(d, &format!("manifests[{i}]")))
                .collect::<Result<Vec<_>, _>>()?;
            (None, Vec::new(), manifests)
        }
        ManifestKind::Image if media_type == media::OCI_ARTIFACT_MANIFEST => {
            let blobs = raw
                .blobs
                .unwrap_or_default()
                .into_iter()
                .enumerate()
                .map(|(i, d)| descriptor(d, &format!("blobs[{i}]")))
                .collect::<Result<Vec<_>, _>>()?;
            (None, blobs, Vec::new())
        }
        ManifestKind::Image => {
            if raw.manifests.is_some() {
                return Err(ManifestError::Invalid(
                    "an image manifest carries no `manifests`".into(),
                ));
            }
            let config = raw
                .config
                .ok_or_else(|| ManifestError::Invalid("an image manifest needs `config`".into()))
                .and_then(|c| descriptor(c, "config"))?;
            let layers = raw
                .layers
                .unwrap_or_default()
                .into_iter()
                .enumerate()
                .map(|(i, d)| descriptor(d, &format!("layers[{i}]")))
                .collect::<Result<Vec<_>, _>>()?;
            if layers.is_empty() && media_type == media::DOCKER_MANIFEST {
                return Err(ManifestError::Invalid(
                    "a Docker image manifest needs at least one layer".into(),
                ));
            }
            (Some(config), layers, Vec::new())
        }
    };

    let artifact_type = raw
        .artifact_type
        .filter(|a| !a.is_empty())
        .or_else(|| config.as_ref().map(|c| c.media_type.clone()));
    Ok(ParsedManifest {
        media_type,
        kind,
        artifact_type,
        config,
        layers,
        manifests,
        subject,
        annotations: raw.annotations,
    })
}

/// The `architecture`/`os`/`variant` of an image config blob, for display.
pub fn config_platform(config: &[u8]) -> Option<Platform> {
    #[derive(Deserialize)]
    struct Cfg {
        architecture: Option<String>,
        os: Option<String>,
        variant: Option<String>,
        #[serde(rename = "os.version")]
        os_version: Option<String>,
    }
    let cfg: Cfg = serde_json::from_slice(config).ok()?;
    let architecture = cfg.architecture.filter(|a| !a.is_empty())?;
    Some(Platform {
        architecture,
        os: cfg.os.unwrap_or_default(),
        variant: cfg.variant.filter(|v| !v.is_empty()),
        os_version: cfg.os_version.filter(|v| !v.is_empty()),
    })
}

/// Whether a config media type describes a runnable image (whose config
/// blob carries the platform), not an artifact.
pub fn is_image_config(media_type: &str) -> bool {
    media_type == media::OCI_IMAGE_CONFIG || media_type == media::DOCKER_IMAGE_CONFIG
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> String {
        format!("sha256:{}", format!("{n:02x}").repeat(32))
    }

    #[test]
    fn docker_image_manifest() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media::DOCKER_MANIFEST,
            "config": {"mediaType": media::DOCKER_IMAGE_CONFIG, "digest": d(1), "size": 10},
            "layers": [
                {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": d(2), "size": 100},
                {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": d(2), "size": 100},
                {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": d(3), "size": 50}
            ]
        });
        let m = parse(body.to_string().as_bytes(), Some(media::DOCKER_MANIFEST)).unwrap();
        assert_eq!(m.kind, ManifestKind::Image);
        assert_eq!(m.blob_references().len(), 3);
        assert_eq!(m.layers_size(), 250);
        assert_eq!(m.artifact_type.as_deref(), Some(media::DOCKER_IMAGE_CONFIG));
    }

    #[test]
    fn oci_index_with_platforms_and_subject() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media::OCI_INDEX,
            "artifactType": "application/example",
            "subject": {"mediaType": media::OCI_MANIFEST, "digest": d(9), "size": 1},
            "manifests": [
                {"mediaType": media::OCI_MANIFEST, "digest": d(4), "size": 7,
                 "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}},
                {"mediaType": media::OCI_MANIFEST, "digest": d(5), "size": 7,
                 "platform": {"architecture": "amd64", "os": "linux"}}
            ]
        });
        let m = parse(body.to_string().as_bytes(), None).unwrap();
        assert_eq!(m.kind, ManifestKind::Index);
        assert_eq!(m.manifest_references().len(), 2);
        assert_eq!(
            m.manifests[0].platform.as_ref().unwrap().label(),
            "linux/arm64/v8"
        );
        assert_eq!(m.subject.unwrap().digest.as_str(), d(9));
        assert_eq!(m.artifact_type.as_deref(), Some("application/example"));
    }

    #[test]
    fn oci_manifest_without_media_type_field_is_inferred() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": media::OCI_EMPTY, "digest": EMPTY_JSON_DIGEST, "size": 2},
            "layers": []
        });
        let m = parse(body.to_string().as_bytes(), None).unwrap();
        assert_eq!(m.media_type, media::OCI_MANIFEST);
        assert!(m.layers.is_empty());
    }

    #[test]
    fn refuses_mismatch_schema1_and_bad_descriptors() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media::OCI_MANIFEST,
            "config": {"mediaType": media::OCI_EMPTY, "digest": EMPTY_JSON_DIGEST, "size": 2},
            "layers": []
        })
        .to_string();
        assert!(matches!(
            parse(body.as_bytes(), Some(media::DOCKER_MANIFEST)),
            Err(ManifestError::Invalid(_))
        ));
        assert!(parse(
            body.as_bytes(),
            Some(&format!("{}; charset=utf-8", media::OCI_MANIFEST))
        )
        .is_ok());

        let schema1 = serde_json::json!({"schemaVersion": 1, "name": "x", "tag": "y"}).to_string();
        assert!(matches!(
            parse(schema1.as_bytes(), Some(media::DOCKER_SCHEMA1_SIGNED)),
            Err(ManifestError::UnsupportedMediaType(_))
        ));

        let bad_digest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media::OCI_MANIFEST,
            "config": {"mediaType": media::OCI_EMPTY, "digest": "sha256:nothex", "size": 2}
        })
        .to_string();
        assert!(parse(bad_digest.as_bytes(), None).is_err());

        assert!(matches!(
            parse(b"not json", None),
            Err(ManifestError::Json(_))
        ));
    }

    #[test]
    fn empty_json_digest_is_right() {
        assert_eq!(Digest::sha256_of(EMPTY_JSON).as_str(), EMPTY_JSON_DIGEST);
    }

    #[test]
    fn config_platform_reads_image_configs() {
        let p = config_platform(br#"{"architecture":"amd64","os":"linux","rootfs":{}}"#).unwrap();
        assert_eq!(p.label(), "linux/amd64");
        assert!(config_platform(b"{}").is_none());
    }
}
