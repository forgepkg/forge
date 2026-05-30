//! Outbound-networking helpers.
//!
//! Currently just [`ssrf`], the guard the proxy repository (and §12.3) use to
//! safely fetch admin-configured upstream URLs.

pub mod ssrf;
