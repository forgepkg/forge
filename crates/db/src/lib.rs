//! Database access layer for envisia-forge.
//!
//! For slice 1 this only provides the connection pool and the migration runner.
//! DAOs are added in a later task.

mod pool;

pub use pool::{connect, migrate};
