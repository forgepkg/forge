//! Error type shared by every layer of the crypto crate.

/// Errors from envelope encode/decode, key (un)wrapping, the key store, and
/// the root provider.
///
/// Variants deliberately carry **no key material and no plaintext** — an error
/// is always safe to log. Decryption failures are intentionally coarse
/// (`DecryptFailed`) so an attacker probing tampered blobs learns nothing
/// beyond "the tag did not verify".
/// `Clone` so an error surfaced through the unwrapped-key cache's shared
/// `Arc<CryptoError>` (moka `try_get_with`) keeps its variant for callers.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CryptoError {
    /// A blob was too short / structurally invalid for the envelope format.
    #[error("malformed envelope: {0}")]
    MalformedEnvelope(&'static str),
    /// The envelope's `format_version` byte is not one we understand.
    #[error("unsupported envelope format version {0}")]
    UnsupportedFormatVersion(u8),
    /// The envelope's `algorithm_id` byte is not a known AEAD.
    #[error("unsupported algorithm id {0}")]
    UnsupportedAlgorithm(u8),
    /// An algorithm name (config / DB column) did not parse.
    #[error("unknown algorithm name {0:?}")]
    UnknownAlgorithmName(String),
    /// AEAD decryption failed: wrong key, tampered ciphertext/nonce, or an AAD
    /// (row-binding) mismatch. Deliberately indistinguishable.
    #[error("decryption failed (wrong key, tampered data, or binding mismatch)")]
    DecryptFailed,
    /// A decrypted secret was not valid UTF-8 (secret values are strings; the
    /// error carries no plaintext bytes).
    #[error("decrypted plaintext is not valid UTF-8")]
    NotUtf8,
    /// Key material had the wrong length (root/KEK/DEK keys are 32 bytes).
    #[error("invalid key length {got} (expected {expected})")]
    InvalidKeyLength { expected: usize, got: usize },
    /// The root provider has no root key matching the requested version label.
    #[error("no root key available for version {0:?}")]
    UnknownRootVersion(String),
    /// Loading the root key from its env var / file failed.
    #[error("root key unavailable: {0}")]
    RootKeyUnavailable(String),
    /// A referenced key row does not exist in the key store.
    #[error("encryption key not found: layer={layer} scope={scope} version={version}")]
    KeyNotFound {
        layer: &'static str,
        scope: String,
        version: i32,
    },
    /// A key needed for an operation is `revoked` (no longer usable at all).
    #[error("encryption key is revoked: layer={layer} version={version}")]
    KeyRevoked { layer: &'static str, version: i32 },
    /// No active key exists for a layer that requires one (bootstrap missing).
    #[error("no active {0} key (key bootstrap has not run)")]
    NoActiveKey(&'static str),
    /// The key store rejected or failed an operation (e.g. a unique-constraint
    /// race on the single-active partial index, or an I/O error).
    #[error("key store error: {0}")]
    Store(String),
}
