//! HTTP middleware.

pub mod principal;

pub use principal::{attach_principal, principal_of, AnonSource, PrincipalLayer};
