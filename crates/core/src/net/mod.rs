//! Outbound-networking helpers.
//!
//! * [`ssrf`] — the scheme guard for admin-configured upstream URLs.
//! * [`upstream`] — the pooled, timeout- and size-bounded client the proxy
//!   repository uses for all upstream traffic.

pub mod ssrf;
pub mod upstream;
