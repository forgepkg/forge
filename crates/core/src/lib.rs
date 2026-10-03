//! `forge-core`: format-agnostic domain logic for envisia-forge.
//!
//! This crate sits above [`forge_db`] and below the protocol crates
//! (`forge-format-nuget`) and the server. It defines:
//!
//! * [`domain`] — neutral types ([`domain::ParsedUpload`]) produced by parsing
//!   an uploaded package, the boundary between a concrete format and the rest
//!   of the system.
//! * [`format`] — the object-safe [`format::Format`] seam every package format
//!   implements (parse, version normalize/compare, id lowercasing).
//! * [`auth`] — principal extraction (token/password/anonymous), client-IP
//!   resolution behind trusted proxies, and the coarse Slice-1 authorization
//!   seam.
//! * [`net`] — outbound-networking helpers, notably the [`net::ssrf`] guard.
//! * [`retention`] — the slice-12.1 retention policy model + pure evaluator
//!   (decides which versions to delete/unlist; no I/O).
//! * [`oidc`] — the slice-12.2 OpenID Connect support: discovery + JWKS fetch
//!   (cached via [`forge_cache`]), ID-token verification, the authorization-code
//!   + PKCE flow, and claim → user resolution/provisioning.
//! * [`session`] — the slice-12.2 server-side login-session service
//!   (create/validate/rotate/revoke + CSRF), backed by the shared `session`
//!   table so sessions are correct and revocable across instances.

pub mod auth;
pub mod authz;
pub mod domain;
pub mod format;
pub mod net;
pub mod oidc;
pub mod repo;
pub mod retention;
pub mod session;

pub use domain::{Dependency, DependencyGroup, FormatError, ParsedUpload};
pub use format::{Format, ReadSeek};
pub use repo::{
    CacheInvalidator, DeleteOutcome, NoopCacheInvalidator, NupkgLocation, PackageFilteredReadOps,
    PackageMutation, PublishAuthorizationContext, PublishOutcome, PublishPolicy, RegistrationEntry,
    RepoError, RepoKind, RepoReadOps, RepoWriteOps, SearchHit, SearchParams, SearchResult,
    UploadReader, VersionEntry, WriteError,
};
