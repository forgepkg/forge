//! `forge-server`: configuration, application state, HTTP middleware, repository
//! dispatch, the admin REST API, read-side browse endpoints, and background
//! workers for Forge.

// Handlers and their helpers use axum's `Result<T, Response>` error idiom, and
// `http::Response<Body>` exceeds the 128-byte `Err` threshold clippy enforces
// since Rust 1.98. Boxing every handler error would fight the framework on a
// path that is not hot, so the lint is opted out crate-wide.
#![allow(clippy::result_large_err)]
// The background tasks that run the proxy's reads (a listing refresh, its
// not-found check, a cache invalidation) nest deeper than the default depth
// the trait solver walks to prove a spawned future `Send`; `forge-core`
// raises it for the same reason.
#![recursion_limit = "256"]

pub mod admin;
pub mod app;
pub mod auth;
pub mod browse;
pub mod browse_images;
pub mod config;
pub mod crypto;
pub mod dispatch;
pub mod feed;
pub mod health;
pub mod me;
pub mod me_tokens;
pub mod middleware;
pub mod nexus_import;
pub mod object_store;
pub mod plugins;
pub mod raw;
pub mod registry;
pub mod serve;
pub mod state;
pub mod web_ui;
pub mod workers;
