//! `forge-core`: format-agnostic domain logic for Forge.
//!
//! This crate sits above [`forge_db`] and below the format plugins
//! (`plugins/*`) and the server. It defines:
//!
//! * [`domain`] — neutral types ([`domain::ParsedUpload`]) produced by parsing
//!   an uploaded package, the boundary between a concrete format and the rest
//!   of the system.
//! * [`format`] — the object-safe [`format::Format`] seam every package format
//!   implements (parse, version normalize/compare, id lowercasing).
//! * [`auth`] — principal extraction (token/password/anonymous), client-IP
//!   resolution behind trusted proxies, and the authorization seam over the
//!   fine-grained RBAC evaluator ([`authz`]).
//! * [`net`] — outbound-networking helpers, notably the [`net::ssrf`] guard.
//! * [`retention`] — the retention policy model + pure evaluator
//!   (decides which versions to delete/unlist; no I/O).
//! * [`oidc`] — OpenID Connect support: discovery + JWKS fetch
//!   (cached via [`forge_cache`]), ID-token verification, the authorization-code
//!   + PKCE flow, and claim → user resolution/provisioning.
//! * [`session`] — the server-side login-session service
//!   (create/validate/rotate/revoke + CSRF), backed by the shared `session`
//!   table so sessions are correct and revocable across instances.

// The proxy's nested read futures (cache fill → envelope open → key cache)
// exceed the default depth the trait solver walks to prove them `Send`.
#![recursion_limit = "256"]

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
