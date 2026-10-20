//! Authentication and authorization.
//!
//! * [`principal`] — the [`Principal`] enum and its `User` payload.
//! * [`token`] — credential verification (API tokens, passwords) and the
//!   [`PrincipalSource`] chain that turns request headers into a principal.
//! * [`client_ip`] — client-IP resolution behind trusted proxies and the
//!   anonymous-access policy ([`AnonPolicy`]).
//! * [`authz`] — the authorization seam: the [`Authz`] service whose
//!   `can_read` / `can_write` / `can_admin` methods are the single decision
//!   point every gate routes through (§12.4).
//! * [`provider`] / [`chain`] — the pluggable, ordered [`AuthProvider`] chain
//!   for the password-style auth path (slice 12.3). The local-password and
//!   upstream-basic providers plug in here; OIDC stays its own interactive
//!   path.
//! * [`cred_cache`] — the validated-credential cache (slice 12.3): an HMAC-keyed
//!   L1/L2 + Postgres cache of upstream verdicts so NuGet's per-request Basic
//!   auth does not hammer the upstream. Plaintext is never stored; fail-closed.
//! * [`login_throttle`] — per `(client IP, username)` password-failure lockout
//!   shared by the browser login and the wire Basic password path.

pub mod authz;
pub mod chain;
pub mod client_ip;
pub mod cred_cache;
pub mod local_password;
pub mod login_throttle;
pub mod principal;
pub mod provider;
pub mod session_source;
pub mod token;
pub mod upstream_basic;

pub use authz::Authz;
pub use chain::{
    map_identity_to_principal, provision_and_map, Chain, ChainOutcome, ChainSource,
    StaticChainSource,
};
pub use client_ip::{
    forwarded_for, resolve_client, resolve_client_ip, AllowlistParseError, AnonPolicy,
    ResolvedClient,
};
pub use cred_cache::{
    cred_key, revoke_credentials_for_user, CredCacheError, CredKeyPepper, ForwardLimits,
    UpstreamVerdict, ValidatedCredentialCache, DEFAULT_FORWARD_TIMEOUT,
    DEFAULT_MAX_CONCURRENT_FORWARDS,
};
pub use local_password::{LimiterSaturated, LocalPasswordProvider, PasswordHashLimiter};
pub use login_throttle::{
    client_network, username_for_log, AttemptRefused, KnownNetworkStore, LoginAttempt,
    LoginThrottle, PgKnownNetworks, WindowLimiter, MAX_USERNAME_BYTES,
};
pub use principal::{AuthMethod, Principal, UserPrincipal};
pub use provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential, ProvenIdentity};
pub use session_source::{
    cookie_value, session_cookie_name, unique_cookie_value, DuplicateCookie, SessionCookieSource,
    SECURE_SESSION_COOKIE, SESSION_COOKIE,
};
pub use token::{
    generate_token_secret, hash_token, resolve_principal, resolve_principal_with_origin,
    verify_password, verify_token, AuthError, BasicAuthSource, PrincipalSource, ResolvedPrincipal,
    SourceOutcome, TokenHeaderSource,
};
pub use upstream_basic::{UpstreamBasicConfig, UpstreamBasicProvider, UPSTREAM_BASIC_ID};
// Canonical usernames live with the DAOs that enforce them.
pub use forge_db::username::{canonical_password_username, canonical_username, InvalidUsername};
