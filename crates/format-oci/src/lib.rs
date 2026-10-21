//! Docker / OCI registry format: the distribution-spec v1.1 API under
//! `/v2`, with hosted, proxy and group repositories over Forge's CAS.
//!
//! * [`digest`], [`reference`], [`manifest`] — the protocol's grammar and
//!   manifest parsing (Docker v2 schema 2 manifests and manifest lists, OCI
//!   image manifests and indexes, artifacts with `artifactType`/`subject`);
//! * [`token`] — the registry Bearer tokens of the Docker token protocol;
//! * [`Registry`] — the service answering every `/v2` request.
//!
//! Repositories are addressed by path (`<host>/<forge-repo>/<image>`) or,
//! with `config.host`, by host name (`<repo-host>/<image>`).

pub mod digest;
pub mod error;
pub mod gc;
pub mod manifest;
pub mod path;
pub mod reference;
pub mod token;

mod auth;
mod group;
mod proxy;
mod pull;
mod push;
mod service;

pub use service::{
    registry_origin, PublishRecorder, Registry, RegistryConfig, RegistryParts, WorkloadCheck,
};

/// `repository.format` of registry repositories.
pub const FORMAT: &str = forge_db::model::DOCKER_FORMAT;
