//! Database access layer for envisia-forge.
//!
//! Provides the connection pool, the migration runner, the row models, and a
//! DAO module per table. DAOs use sqlx **compile-time-checked** queries
//! (`query!`/`query_as!`); the cached `.sqlx/` directory lets CI build with
//! `SQLX_OFFLINE=true`.

mod pool;

pub mod asset_dao;
pub mod auth_realm_dao;
pub mod authz_dao;
pub mod blob_dao;
pub mod component_dao;
pub mod download_dao;
pub mod encryption_key_dao;
pub mod external_identity_dao;
pub mod ids;
pub mod model;
pub mod oidc_flow_dao;
pub mod outbox_dao;
pub mod proxy_dao;
pub mod repository_dao;
pub mod retention_dao;
pub mod secret_dao;
pub mod session_dao;
pub mod token_dao;
pub mod trusted_publish_audit_dao;
pub mod user_dao;
pub mod validated_credential_dao;

pub use pool::{connect, connect_with, migrate};
