//! Authentication and authorization.
//!
//! * [`principal`] — the [`Principal`] enum and its `User` payload.
//! * [`token`] — credential verification (API tokens, passwords) and the
//!   [`PrincipalSource`] chain that turns request headers into a principal.
//! * [`client_ip`] — client-IP resolution behind trusted proxies and the
//!   anonymous-access policy ([`AnonPolicy`]).
//! * [`authz`] — the coarse Slice-1 authorization seam (`can_read` /
//!   `can_write` / `can_admin`), the single extension point §12.4 replaces.

pub mod authz;
pub mod client_ip;
pub mod principal;
pub mod session_source;
pub mod token;

pub use authz::{can_admin, can_read, can_write};
pub use client_ip::{resolve_client_ip, AllowlistParseError, AnonPolicy};
pub use principal::{Principal, UserPrincipal};
pub use session_source::{cookie_value, SessionCookieSource, SESSION_COOKIE};
pub use token::{
    generate_token_secret, hash_token, resolve_principal, verify_password, verify_token, AuthError,
    BasicAuthSource, PrincipalSource, SourceOutcome, TokenHeaderSource,
};
