//! Workload API keys: the short-lived keys the trusted-publishing token
//! exchange (`POST /api/v2/token`) issues for a CI job's OIDC token.
//!
//! A key is [`WORKLOAD_KEY_PREFIX`] followed by a 256-bit random secret
//! ([`generate_token_secret`]). The prefix contains a `.`, which a user API
//! token (URL-safe base64) never does, so a key is recognized by its spelling
//! alone: the workload-identity source claims it in every transport and no
//! other source ever treats one as a user token or a password (a
//! credential-forwarding realm would send it upstream). Only its SHA-256 is
//! stored.

use sha2::{Digest, Sha256};

use super::token::generate_token_secret;

/// What every workload API key starts with. Also the pattern a secret
/// scanner can match: `forge_wif\.[A-Za-z0-9_-]{43}`.
pub const WORKLOAD_KEY_PREFIX: &str = "forge_wif.";

/// A fresh workload API key (shown to the CI job once).
pub fn generate_workload_key() -> String {
    format!("{WORKLOAD_KEY_PREFIX}{}", generate_token_secret())
}

/// Whether `secret` is spelled as a workload API key (live or not).
pub fn is_workload_key(secret: &str) -> bool {
    secret.starts_with(WORKLOAD_KEY_PREFIX)
}

/// The SHA-256 a workload API key is stored and looked up by.
pub fn workload_key_sha256(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_carry_the_prefix_and_never_collide_with_user_tokens() {
        let key = generate_workload_key();
        assert!(is_workload_key(&key));
        assert_eq!(key.len(), WORKLOAD_KEY_PREFIX.len() + 43);
        assert_ne!(key, generate_workload_key());
        // A user API token is URL-safe base64: no `.`, so never a key.
        for _ in 0..64 {
            assert!(!is_workload_key(&generate_token_secret()));
        }
        assert_ne!(workload_key_sha256(&key), workload_key_sha256("other"));
    }
}
