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

pub mod auth;
pub mod domain;
pub mod format;
pub mod net;

pub use domain::{Dependency, DependencyGroup, FormatError, ParsedUpload};
pub use format::{Format, ReadSeek};
