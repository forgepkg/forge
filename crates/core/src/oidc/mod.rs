//! OpenID Connect support (slice 12.2).
//!
//! This module implements the IdP-facing half of interactive OIDC login:
//!
//! * [`jwks`] — OIDC **discovery** (`/.well-known/openid-configuration`) and
//!   **JWKS** fetching, both cached through [`forge_cache::Cache`], plus an
//!   **ID-token verifier** that checks the RS/PS signature against the JWKS and
//!   the `iss` / `aud` / `exp` / `nbf` / `nonce` claims.
//!
//! Later phases add the authorization-code + PKCE flow (`flow.rs`), claim → user
//! mapping (`claims.rs`) and the session service. Phase 2 (this commit) only
//! covers discovery, JWKS caching/rotation, and token verification — all of
//! which are pure given an injected HTTP client and cache, so they are unit-
//! testable with a static JWKS and a self-signed token (no network).
//!
//! ## Multi-instance / no-advisory-lock posture
//!
//! Discovery and JWKS are cached via the slice-1 [`forge_cache::Cache`]
//! (L1 moka + optional Redis L2 + invalidation backplane). Request coalescing is
//! moka's per-instance [`try_get_with`](forge_cache::Cache::get_or_try_insert_with);
//! an occasional duplicate JWKS fetch across instances is harmless, so we use
//! **no** Postgres advisory locks. On a `kid` miss (Entra rotated keys before the
//! TTL elapsed) we force exactly one cache-bypassing refetch, repopulate the
//! cache, broadcast an invalidation, and retry validation once.

pub mod jwks;

pub use jwks::{
    DiscoveryDocument, IdTokenClaims, OidcError, OidcMetadataClient, Verified, VerifyParams,
};
