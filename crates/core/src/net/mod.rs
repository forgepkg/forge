//! Outbound-networking helpers.
//!
//! * [`budget`] — the memory the upstream conversations of the instance hold
//!   at once (`proxy.max_metadata_memory_bytes`).
//! * [`deadline`] — the deadline of the request a task serves, which an
//!   upstream download extends.
//! * [`origins`] — where a format's upstream conversation may send requests:
//!   the `remote_url`'s origin and those the upstream's documents name.
//! * [`ssrf`] — the scheme guard for admin-configured upstream URLs.
//! * [`upstream`] — the pooled, timeout- and size-bounded client the proxy
//!   repository uses for all upstream traffic.

pub mod budget;
pub mod deadline;
pub mod origins;
pub mod ssrf;
pub mod upstream;
