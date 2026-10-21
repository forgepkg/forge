//! `forge-e2e` — end-to-end test harness for envisia-forge (plan Phase 11,
//! spec §9).
//!
//! The whole crate is gated behind the `forge-e2e` feature so a plain
//! `cargo build/test --workspace` never compiles testcontainers or touches
//! Docker. With the feature on it exposes:
//!
//! * [`start_stack`] — boot Postgres + versitygw (and, on demand, Redis)
//!   testcontainers, run migrations, assemble a real `AppState`, serve the
//!   axum app on an ephemeral port and return a [`TestServer`] (with a ready-to-
//!   use admin token).
//! * [`StackBuilder`] / [`TestServer::spawn_peer`] — start a **second** server
//!   instance sharing the same DB + S3 (+ Redis), for scale-out scenarios.
//! * [`MockUpstream`] — an in-process mock NuGet V3 upstream feed with per-
//!   resource hit counters, for proxy scenarios.
//! * [`make_nupkg`] — build a minimal valid `.nupkg` fixture.
//! * [`S3Gate`] — a proxy in front of the shared S3 that counts requests and
//!   can simulate an outage (local blob cache scenarios).
//! * [`versitygw_sts::VersitygwSts`] — a versitygw whose STS trusts a
//!   [`MockOidc`] issuer (short-lived S3 credentials via web identity).
//!
//! Containers are shared per test-binary process (booted once, leaked so their
//! async `Drop` never runs on a torn-down runtime) but every [`start_stack`]
//! call gets a **fresh database** (a uniquely-named Postgres database created on
//! the shared server) so tests are isolated and can run in parallel.

#![cfg(feature = "forge-e2e")]

mod mock_basic_upstream;
mod mock_oidc;
mod mock_upstream;
mod s3_gate;
mod stack;
pub mod versitygw_sts;

pub use mock_basic_upstream::MockBasicUpstream;
pub use mock_oidc::MockOidc;
pub use mock_upstream::{MockUpstream, UpstreamPackage};
pub use s3_gate::S3Gate;
pub use stack::{
    make_nupkg, make_nupkg_with_desc, start_stack, AnonMode, StackBuilder, TestServer, S3_ACCESS,
    S3_BUCKET, S3_SECRET,
};
