//! Zeroizing newtypes for plaintext secrets and raw key bytes.

use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Plaintext secret as seen by callers of the envelope service.
///
/// [`secrecy::SecretString`] zeroizes on drop and **redacts** itself from
/// `Debug`, so a decrypted `upstream_password` can never leak into a log line
/// or an error body. Read the value with
/// [`secrecy::ExposeSecret::expose_secret`] at the single sanctioned use site
/// (the proxy upstream fetch building its outbound Basic header).
pub type PlaintextSecret = secrecy::SecretString;

/// Length of every raw key in the hierarchy (root, KEK, DEK): 256 bits.
pub const KEY_LEN: usize = 32;

/// 32 bytes of raw symmetric key material, zeroized on drop.
///
/// Used for unwrapped DEKs/KEKs and the dev root key. The bytes live in RAM
/// only while needed (bounded by the unwrapped-key cache TTL) — this is the
/// documented exception to keeping instances stateless: the material is
/// *derivable* (it can always be re-unwrapped from Postgres + the root), never
/// authoritative.
pub struct KeyBytes(Zeroizing<[u8; KEY_LEN]>);

impl KeyBytes {
    /// Generate a fresh random key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        SysRng
            .try_fill_bytes(bytes.as_mut())
            .expect("OS random number generator failed");
        KeyBytes(bytes)
    }

    /// Build from a slice, enforcing the 32-byte length.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_LEN,
                got: slice.len(),
            });
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        bytes.copy_from_slice(slice);
        Ok(KeyBytes(bytes))
    }

    /// Borrow the raw key bytes for an AEAD operation.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Never print key bytes — even `{:?}` in a stray log line stays safe.
impl std::fmt::Debug for KeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyBytes(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_random_and_right_length() {
        let a = KeyBytes::generate();
        let b = KeyBytes::generate();
        assert_ne!(a.expose(), b.expose(), "two generated keys must differ");
    }

    #[test]
    fn from_slice_enforces_length() {
        assert!(KeyBytes::from_slice(&[0u8; 32]).is_ok());
        let err = KeyBytes::from_slice(&[0u8; 16]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 32,
                got: 16
            }
        ));
    }

    #[test]
    fn debug_redacts() {
        let k = KeyBytes::generate();
        assert_eq!(format!("{k:?}"), "KeyBytes(<redacted>)");
    }
}
