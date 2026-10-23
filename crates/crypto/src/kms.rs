//! The root-layer abstraction.
//!
//! The root key wraps **KEK material only** — nothing else ever touches the
//! root. [`KmsProvider`] abstracts where the root lives so the rest of the
//! hierarchy is identical across deployments:
//!
//! * [`StaticRootProvider`] — dev / test / lower environments: a 32-byte root
//!   key loaded from an **env var** or a **file** (base64). Wrap/unwrap are
//!   local AEAD operations under the AAD [`crate::envelope::ROOT_WRAP_AAD`].
//! * `AwsKmsProvider` — a later, additive impl of the same trait (`kms:Encrypt`
//!   / `kms:Decrypt`; the root never leaves the HSM). Not shipped yet; the
//!   trait is the seam.
//!
//! Every instance is configured with the **same** provider, so every instance
//! reaches the same root, can unwrap the same KEKs, and can decrypt every
//! secret — key material is always reachable from shared config + Postgres,
//! never generated per-instance, so instances stay stateless.
//!
//! ## Root rotation (static provider)
//!
//! The operator swaps the env/file value to the **new** root and supplies the
//! **old** one as the *previous* root for the rotation window. Version labels
//! are derived from the key bytes (a SHA-256 prefix), so "which root wrapped
//! this KEK" is recorded in `encryption_key.root_key_version` and the provider
//! can pick the right root to unwrap with. Once the KEK re-wrap sweep has moved
//! every KEK to the current root, the previous value can be dropped.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::envelope::{self, Algorithm, ROOT_WRAP_AAD};
use crate::error::CryptoError;
use crate::secret::{KeyBytes, KEY_LEN};

/// Root-layer key wrap/unwrap (KMS in production, env/file in dev/test).
///
/// Implementations operate **only on KEK bytes**: `wrap_kek` encrypts a fresh
/// KEK's raw bytes under the root; `unwrap_kek` recovers them. The returned
/// material is a zeroizing [`KeyBytes`] so unwrapped KEKs never outlive their
/// use unscrubbed.
#[async_trait]
pub trait KmsProvider: Send + Sync {
    /// Identifier of the root key (a KMS key id/ARN, or `"env"` / `"file"` for
    /// the static provider). Stored in `encryption_key.root_key_id` for audit.
    fn root_key_id(&self) -> &str;

    /// Current root key version label. KEKs wrapped from now on record this
    /// label; root rotation is "re-wrap every KEK whose recorded label differs".
    async fn current_root_version(&self) -> Result<String, CryptoError>;

    /// Wrap (encrypt) raw KEK bytes under the **current** root. The returned
    /// blob is opaque to callers (a KMS ciphertext, or a local AEAD envelope).
    async fn wrap_kek(&self, kek_plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Unwrap (decrypt) a wrapped KEK that was produced under `root_version`.
    async fn unwrap_kek(&self, wrapped: &[u8], root_version: &str)
        -> Result<KeyBytes, CryptoError>;
}

/// Derive the stable version label for a root key: `sha256:<first 16 hex>` of
/// the raw key bytes. Identifies *which* root wrapped a KEK without revealing
/// anything about the key (a 64-bit prefix of a one-way hash).
pub fn root_version_label(key: &KeyBytes) -> String {
    let digest = Sha256::digest(key.expose());
    format!("sha256:{}", hex::encode(&digest[..8]))
}

/// Dev / test / lower-environment root provider: a static 32-byte root key from
/// an env var or a file (base64-encoded), with optional **previous** roots kept
/// reachable during a root-rotation window.
///
/// Wrap = local AEAD (`seal_with_key`) under [`ROOT_WRAP_AAD`]; unwrap selects
/// the root whose derived version label matches the recorded
/// `root_key_version`.
pub struct StaticRootProvider {
    /// `"env"` or `"file"` (or a caller-chosen label in tests).
    id: String,
    /// AEAD used for **new** wraps (unwrap reads the algorithm from the blob).
    algorithm: Algorithm,
    /// `(version label, key)` — index 0 is the current root; the rest are
    /// previous roots kept for unwrapping during a rotation window.
    roots: Vec<(String, KeyBytes)>,
}

/// Manual `Debug`: never print root key bytes (labels are safe — one-way hash
/// prefixes).
impl std::fmt::Debug for StaticRootProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticRootProvider")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field(
                "roots",
                &self
                    .roots
                    .iter()
                    .map(|(v, _)| v.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl StaticRootProvider {
    /// Build from raw key material. `current` is used for new wraps; `previous`
    /// roots stay reachable for unwrapping (rotation window).
    pub fn new(
        id: impl Into<String>,
        algorithm: Algorithm,
        current: KeyBytes,
        previous: Vec<KeyBytes>,
    ) -> Self {
        let mut roots = Vec::with_capacity(1 + previous.len());
        roots.push((root_version_label(&current), current));
        for key in previous {
            roots.push((root_version_label(&key), key));
        }
        StaticRootProvider {
            id: id.into(),
            algorithm,
            roots,
        }
    }

    /// Load the root (and optional previous root) from **env vars** holding
    /// base64-encoded 32-byte keys.
    pub fn from_env(
        algorithm: Algorithm,
        var: &str,
        previous_var: Option<&str>,
    ) -> Result<Self, CryptoError> {
        let current = key_from_base64(&env_value(var)?)?;
        let previous = match previous_var {
            Some(v) => vec![key_from_base64(&env_value(v)?)?],
            None => Vec::new(),
        };
        Ok(Self::new("env", algorithm, current, previous))
    }

    /// Load the root (and optional previous root) from **files** holding
    /// base64-encoded 32-byte keys (e.g. mounted Kubernetes secrets).
    pub fn from_file(
        algorithm: Algorithm,
        path: &std::path::Path,
        previous_path: Option<&std::path::Path>,
    ) -> Result<Self, CryptoError> {
        let current = key_from_base64(&file_value(path)?)?;
        let previous = match previous_path {
            Some(p) => vec![key_from_base64(&file_value(p)?)?],
            None => Vec::new(),
        };
        Ok(Self::new("file", algorithm, current, previous))
    }

    fn root_for(&self, version: &str) -> Result<&KeyBytes, CryptoError> {
        self.roots
            .iter()
            .find(|(v, _)| v == version)
            .map(|(_, k)| k)
            .ok_or_else(|| CryptoError::UnknownRootVersion(version.to_string()))
    }
}

#[async_trait]
impl KmsProvider for StaticRootProvider {
    fn root_key_id(&self) -> &str {
        &self.id
    }

    async fn current_root_version(&self) -> Result<String, CryptoError> {
        Ok(self.roots[0].0.clone())
    }

    async fn wrap_kek(&self, kek_plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // key_version 0: the root's version is the text label recorded on the
        // KEK row, not a numeric `encryption_key` version.
        envelope::seal_with_key(
            self.algorithm,
            &self.roots[0].1,
            0,
            kek_plaintext,
            ROOT_WRAP_AAD,
        )
    }

    async fn unwrap_kek(
        &self,
        wrapped: &[u8],
        root_version: &str,
    ) -> Result<KeyBytes, CryptoError> {
        let root = self.root_for(root_version)?;
        let plaintext = envelope::open_with_key(root, wrapped, ROOT_WRAP_AAD)?;
        KeyBytes::from_slice(&plaintext)
    }
}

// The encoded and decoded root key are wiped once the key is loaded: only
// the `KeyBytes` (itself zeroized on drop) outlives these helpers.

fn env_value(var: &str) -> Result<Zeroizing<String>, CryptoError> {
    std::env::var(var)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::RootKeyUnavailable(format!("env var {var} is not set")))
}

fn file_value(path: &std::path::Path) -> Result<Zeroizing<String>, CryptoError> {
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| CryptoError::RootKeyUnavailable(format!("read {}: {e}", path.display())))
}

/// Decode a base64 root key and enforce the 32-byte length. Whitespace around
/// the value (trailing newline in a file/secret) is tolerated.
fn key_from_base64(b64: &str) -> Result<KeyBytes, CryptoError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map(Zeroizing::new)
        .map_err(|e| CryptoError::RootKeyUnavailable(format!("invalid base64 root key: {e}")))?;
    if bytes.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_LEN,
            got: bytes.len(),
        });
    }
    KeyBytes::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn provider() -> StaticRootProvider {
        StaticRootProvider::new("test", Algorithm::Aes256Gcm, KeyBytes::generate(), vec![])
    }

    #[tokio::test]
    async fn wrap_unwrap_round_trips_kek_bytes() {
        let p = provider();
        let kek = KeyBytes::generate();
        let wrapped = p.wrap_kek(kek.expose()).await.expect("wrap");
        let version = p.current_root_version().await.expect("version");
        let unwrapped = p.unwrap_kek(&wrapped, &version).await.expect("unwrap");
        assert_eq!(unwrapped.expose(), kek.expose());
    }

    #[tokio::test]
    async fn tampered_wrapped_blob_fails() {
        let p = provider();
        let kek = KeyBytes::generate();
        let mut wrapped = p.wrap_kek(kek.expose()).await.expect("wrap");
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        let version = p.current_root_version().await.expect("version");
        assert!(matches!(
            p.unwrap_kek(&wrapped, &version).await.unwrap_err(),
            CryptoError::DecryptFailed
        ));
    }

    #[tokio::test]
    async fn version_label_is_stable_and_key_dependent() {
        let key = KeyBytes::generate();
        let a = root_version_label(&key);
        let b = root_version_label(&key);
        assert_eq!(a, b, "label must be deterministic for fixed bytes");
        assert!(a.starts_with("sha256:"));

        let other = KeyBytes::generate();
        assert_ne!(
            a,
            root_version_label(&other),
            "label must change with the key"
        );
    }

    #[tokio::test]
    async fn previous_root_still_unwraps_during_rotation_window() {
        let old_root = KeyBytes::generate();
        let old_provider = StaticRootProvider::new(
            "test",
            Algorithm::Aes256Gcm,
            KeyBytes::from_slice(old_root.expose()).unwrap(),
            vec![],
        );
        let kek = KeyBytes::generate();
        let wrapped = old_provider.wrap_kek(kek.expose()).await.expect("wrap");
        let old_version = old_provider.current_root_version().await.unwrap();

        // Rotate: new current root, old root kept as previous.
        let rotated = StaticRootProvider::new(
            "test",
            Algorithm::Aes256Gcm,
            KeyBytes::generate(),
            vec![old_root],
        );
        assert_ne!(rotated.current_root_version().await.unwrap(), old_version);
        let unwrapped = rotated
            .unwrap_kek(&wrapped, &old_version)
            .await
            .expect("previous root unwraps");
        assert_eq!(unwrapped.expose(), kek.expose());

        // A label nothing matches is refused.
        assert!(matches!(
            rotated
                .unwrap_kek(&wrapped, "sha256:0000000000000000")
                .await
                .unwrap_err(),
            CryptoError::UnknownRootVersion(_)
        ));
    }

    #[tokio::test]
    async fn from_env_decodes_base64_and_enforces_length() {
        // Set a process env var; safe here (tests in this module run in one
        // process and the var name is unique to this test).
        let var = "FORGE_TEST_ROOT_KEY_KMS_RS";
        let key = KeyBytes::generate();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key.expose());
        std::env::set_var(var, &b64);
        let p = StaticRootProvider::from_env(Algorithm::Aes256Gcm, var, None).expect("load");
        assert_eq!(p.root_key_id(), "env");
        assert_eq!(
            p.current_root_version().await.unwrap(),
            root_version_label(&key)
        );

        std::env::set_var(var, "dG9vLXNob3J0"); // "too-short"
        assert!(matches!(
            StaticRootProvider::from_env(Algorithm::Aes256Gcm, var, None).unwrap_err(),
            CryptoError::InvalidKeyLength { expected: 32, .. }
        ));
        std::env::remove_var(var);

        assert!(matches!(
            StaticRootProvider::from_env(Algorithm::Aes256Gcm, var, None).unwrap_err(),
            CryptoError::RootKeyUnavailable(_)
        ));
    }

    #[tokio::test]
    async fn from_file_reads_and_trims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("root.key");
        let key = KeyBytes::generate();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key.expose());
        std::fs::write(&path, format!("{b64}\n")).expect("write");
        let p = StaticRootProvider::from_file(Algorithm::Aes256Gcm, &path, None).expect("load");
        assert_eq!(p.root_key_id(), "file");
        assert_eq!(
            p.current_root_version().await.unwrap(),
            root_version_label(&key)
        );
    }

    #[test]
    fn debug_redacts_key_bytes() {
        let p = provider();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("sha256:"), "{dbg}");
        // The raw key bytes must not appear (KeyBytes redacts; the provider
        // Debug only prints version labels).
        assert!(!dbg.contains("KeyBytes("), "{dbg}");
        let raw_hex = hex::encode(p.roots[0].1.expose());
        assert!(!dbg.contains(&raw_hex), "{dbg}");
    }
}
