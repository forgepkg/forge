//! The versioned AEAD envelope format.
//!
//! Every encrypted value stored in a database column is a self-describing
//! binary blob:
//!
//! ```text
//! byte 0      : format_version  (u8)         -- currently 1
//! byte 1      : algorithm_id    (u8)         -- 1 = aes-256-gcm, 2 = xchacha20-poly1305
//! bytes 2..6  : key_version     (u32, BE)    -- which key (DEK/KEK) decrypts this
//! byte 6      : nonce_len       (u8)         -- 12 (GCM) or 24 (XChaCha)
//! bytes 7..   : nonce           (random per encryption)
//! then        : ciphertext || tag            -- AEAD output
//! ```
//!
//! The **AAD** is *not* stored in the blob: it is recomputed at encrypt and
//! decrypt time from the owning row's identity ([`AeadBinding`]) or from the
//! key-wrap context ([`key_wrap_aad`] / [`ROOT_WRAP_AAD`]). A ciphertext moved
//! to a different row, column, or table therefore fails authentication —
//! the copy-paste/swap defense.
//!
//! Functions here operate on a **provided raw key**; key management (which key,
//! wrapped how) lives in [`crate::service`].

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::secret::KeyBytes;

/// Current envelope `format_version` byte.
pub const FORMAT_VERSION: u8 = 1;

/// Domain-separation prefix for secret-value AADs bound to a row only
/// (versioned; see [`AeadBinding::destination`]).
const SECRET_AAD_PREFIX: &[u8] = b"forge.secret.v1";

/// Domain-separation prefix for secret-value AADs bound to a row **and** the
/// destination the secret is sent to.
const SECRET_AAD_V2_PREFIX: &[u8] = b"forge.secret.v2";

/// Domain-separation prefix for DEK-wrapped-by-KEK AADs (versioned).
const KEY_WRAP_AAD_PREFIX: &[u8] = b"forge.key.wrap.v1";

/// AAD under which the static root provider wraps KEK bytes.
pub const ROOT_WRAP_AAD: &[u8] = b"forge.root.wrap";

/// Field separator inside AADs (ASCII Unit Separator — cannot appear in
/// identifiers, so `("ab","c")` and `("a","bc")` cannot collide).
const AAD_SEP: u8 = 0x1F;

/// The supported AEAD algorithms. The id is persisted in envelope blobs and in
/// `encryption_key.algorithm`, so a single table can hold rows under different
/// AEADs (e.g. during an algorithm migration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// AES-256-GCM (default): hardware-accelerated, KMS/FIPS-friendly, 96-bit
    /// nonce. Random nonces are safe well below the GCM birthday bound at our
    /// low secret-write volumes; DEK rotation keeps the per-key count bounded.
    Aes256Gcm,
    /// XChaCha20-Poly1305 (opt-in): 192-bit extended nonce, collision-safe
    /// under pure-random generation with no per-key counter state.
    XChaCha20Poly1305,
}

impl Algorithm {
    /// The on-disk `algorithm_id` byte.
    pub fn id(self) -> u8 {
        match self {
            Algorithm::Aes256Gcm => 1,
            Algorithm::XChaCha20Poly1305 => 2,
        }
    }

    /// Parse an `algorithm_id` byte.
    pub fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            1 => Ok(Algorithm::Aes256Gcm),
            2 => Ok(Algorithm::XChaCha20Poly1305),
            other => Err(CryptoError::UnsupportedAlgorithm(other)),
        }
    }

    /// Canonical name as stored in config and `encryption_key.algorithm`.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Aes256Gcm => "aes-256-gcm",
            Algorithm::XChaCha20Poly1305 => "xchacha20-poly1305",
        }
    }

    /// Parse a canonical name (config / DB column).
    pub fn parse(name: &str) -> Result<Self, CryptoError> {
        match name {
            "aes-256-gcm" => Ok(Algorithm::Aes256Gcm),
            "xchacha20-poly1305" => Ok(Algorithm::XChaCha20Poly1305),
            other => Err(CryptoError::UnknownAlgorithmName(other.to_string())),
        }
    }

    /// Nonce length in bytes (12 for GCM, 24 for XChaCha).
    pub fn nonce_len(self) -> usize {
        match self {
            Algorithm::Aes256Gcm => 12,
            Algorithm::XChaCha20Poly1305 => 24,
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The row identity a secret ciphertext is bound to via AAD.
///
/// Kept **explicit** at every call site (rather than hidden in a sqlx codec)
/// because the row-pk binding is the whole security property and must not be
/// silently wrong. Identity PKs never reuse values, so a binding can never
/// silently shift to a different logical row.
#[derive(Debug, Clone, Copy)]
pub struct AeadBinding<'a> {
    /// Owning table name, e.g. `"repository"`.
    pub table: &'a str,
    /// Owning column name, e.g. `"upstream_password_enc"`.
    pub column: &'a str,
    /// The row's primary key.
    pub row_pk: i64,
    /// Where the secret is used, taken from the same row: an upstream
    /// origin, an OIDC issuer. Binding it means a row repointed elsewhere
    /// (by a database write that bypasses the API, which drops or replaces
    /// the secret) no longer decrypts, so the secret is never sent to the
    /// new destination. `None` is the row-only binding of earlier builds.
    pub destination: Option<&'a str>,
}

impl AeadBinding<'_> {
    /// Serialize the binding into AAD bytes:
    /// `"forge.secret.v1" || table || 0x1F || column || 0x1F || row_pk_be`
    /// without a destination, and
    /// `"forge.secret.v2" || table || 0x1F || column || 0x1F || row_pk_be ||
    /// destination` with one (the fixed-width row key keeps the destination
    /// unambiguous).
    pub fn aad(&self) -> Vec<u8> {
        let destination = self.destination.unwrap_or_default();
        let mut aad = Vec::with_capacity(
            SECRET_AAD_V2_PREFIX.len()
                + self.table.len()
                + self.column.len()
                + 2
                + 8
                + destination.len(),
        );
        aad.extend_from_slice(match self.destination {
            Some(_) => SECRET_AAD_V2_PREFIX,
            None => SECRET_AAD_PREFIX,
        });
        aad.extend_from_slice(self.table.as_bytes());
        aad.push(AAD_SEP);
        aad.extend_from_slice(self.column.as_bytes());
        aad.push(AAD_SEP);
        aad.extend_from_slice(&self.row_pk.to_be_bytes());
        aad.extend_from_slice(destination.as_bytes());
        aad
    }

    /// The same row without its destination: the binding earlier builds
    /// sealed under.
    pub fn row_only(self) -> Self {
        AeadBinding {
            destination: None,
            ..self
        }
    }
}

/// AAD under which a DEK's raw bytes are wrapped by a KEK:
/// `"forge.key.wrap.v1" || layer || 0x1F || scope`.
///
/// Binds the wrapped blob to its layer + scope (a wrapped DEK pasted into a KEK
/// row, or into another scope, fails to unwrap). The child version is not part
/// of the AAD because the store assigns it at insert time; swapping wrapped
/// blobs *between rows of the same layer+scope* only mislabels which version
/// maps to which bytes — every dependent ciphertext then fails its own
/// authenticated open, so no plaintext is ever disclosed.
pub fn key_wrap_aad(layer: &str, scope: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEY_WRAP_AAD_PREFIX.len() + layer.len() + scope.len() + 1);
    aad.extend_from_slice(KEY_WRAP_AAD_PREFIX);
    aad.extend_from_slice(layer.as_bytes());
    aad.push(AAD_SEP);
    aad.extend_from_slice(scope.as_bytes());
    aad
}

/// Parsed envelope header (everything before the ciphertext).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeHeader {
    /// The blob's `format_version` byte.
    pub format_version: u8,
    /// AEAD that produced the ciphertext.
    pub algorithm: Algorithm,
    /// Version of the key (DEK for secrets, KEK for wrapped DEKs) that
    /// encrypted this blob — the link into the `encryption_key` table.
    pub key_version: u32,
}

/// Parse and validate an envelope's header without decrypting.
///
/// Used by [`open_with_key`] and by the data-access layer to discover which
/// key version a stored blob needs (e.g. the DEK-rotation sweep).
pub fn parse_header(blob: &[u8]) -> Result<EnvelopeHeader, CryptoError> {
    if blob.len() < 7 {
        return Err(CryptoError::MalformedEnvelope("blob shorter than header"));
    }
    if blob[0] != FORMAT_VERSION {
        return Err(CryptoError::UnsupportedFormatVersion(blob[0]));
    }
    let algorithm = Algorithm::from_id(blob[1])?;
    let key_version = u32::from_be_bytes([blob[2], blob[3], blob[4], blob[5]]);
    let nonce_len = blob[6] as usize;
    if nonce_len != algorithm.nonce_len() {
        return Err(CryptoError::MalformedEnvelope("nonce length mismatch"));
    }
    if blob.len() < 7 + nonce_len {
        return Err(CryptoError::MalformedEnvelope("blob shorter than nonce"));
    }
    Ok(EnvelopeHeader {
        format_version: blob[0],
        algorithm,
        key_version,
    })
}

/// Encrypt `plaintext` under `key` with a fresh random nonce, producing a
/// self-describing envelope blob bound to `aad`.
///
/// `key_version` records which key row the blob references (DEK version for
/// secret values, KEK version for wrapped DEKs, `0` for root-wrapped blobs
/// whose version lives in a text label elsewhere).
pub fn seal_with_key(
    algorithm: Algorithm,
    key: &KeyBytes,
    key_version: u32,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce_len = algorithm.nonce_len();
    let mut nonce = vec![0u8; nonce_len];
    SysRng
        .try_fill_bytes(&mut nonce)
        .expect("OS random number generator failed");

    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = match algorithm {
        Algorithm::Aes256Gcm => Aes256Gcm::new(key.expose().into())
            .encrypt(
                nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::MalformedEnvelope("bad nonce length"))?,
                payload,
            )
            // RustCrypto's encrypt only fails on absurd input sizes.
            .map_err(|_| CryptoError::MalformedEnvelope("AEAD encryption failed"))?,
        Algorithm::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.expose().into())
            .encrypt(
                nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::MalformedEnvelope("bad nonce length"))?,
                payload,
            )
            .map_err(|_| CryptoError::MalformedEnvelope("AEAD encryption failed"))?,
    };

    let mut blob = Vec::with_capacity(7 + nonce_len + ciphertext.len());
    blob.push(FORMAT_VERSION);
    blob.push(algorithm.id());
    blob.extend_from_slice(&key_version.to_be_bytes());
    blob.push(nonce_len as u8);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt an envelope blob with `key`, verifying the AEAD tag **and** that
/// `aad` matches the AAD the blob was sealed under.
///
/// The caller selects `key` from the header's `key_version`
/// (see [`parse_header`]). Returns the plaintext in a [`Zeroizing`] buffer so
/// transient copies are scrubbed once the caller is done.
pub fn open_with_key(
    key: &KeyBytes,
    blob: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let header = parse_header(blob)?;
    let nonce_len = header.algorithm.nonce_len();
    let nonce = &blob[7..7 + nonce_len];
    let ciphertext = &blob[7 + nonce_len..];

    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let plaintext = match header.algorithm {
        Algorithm::Aes256Gcm => Aes256Gcm::new(key.expose().into())
            .decrypt(
                nonce
                    .try_into()
                    .map_err(|_| CryptoError::MalformedEnvelope("bad nonce length"))?,
                payload,
            )
            .map_err(|_| CryptoError::DecryptFailed)?,
        Algorithm::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.expose().into())
            .decrypt(
                nonce
                    .try_into()
                    .map_err(|_| CryptoError::MalformedEnvelope("bad nonce length"))?,
                payload,
            )
            .map_err(|_| CryptoError::DecryptFailed)?,
    };
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGOS: [Algorithm; 2] = [Algorithm::Aes256Gcm, Algorithm::XChaCha20Poly1305];

    fn binding(row_pk: i64) -> AeadBinding<'static> {
        AeadBinding {
            table: "repository",
            column: "upstream_password_enc",
            row_pk,
            destination: None,
        }
    }

    #[test]
    fn round_trip_both_algorithms() {
        for algo in ALGOS {
            let key = KeyBytes::generate();
            let blob = seal_with_key(algo, &key, 7, b"hunter2", &binding(42).aad()).expect("seal");
            let header = parse_header(&blob).expect("header");
            assert_eq!(header.format_version, FORMAT_VERSION);
            assert_eq!(header.algorithm, algo);
            assert_eq!(header.key_version, 7);
            let pt = open_with_key(&key, &blob, &binding(42).aad()).expect("open");
            assert_eq!(pt.as_slice(), b"hunter2");
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        for algo in ALGOS {
            let key = KeyBytes::generate();
            let mut blob =
                seal_with_key(algo, &key, 1, b"secret", &binding(1).aad()).expect("seal");
            let last = blob.len() - 1;
            blob[last] ^= 0x01; // flip a ciphertext/tag bit
            let err = open_with_key(&key, &blob, &binding(1).aad()).unwrap_err();
            assert!(matches!(err, CryptoError::DecryptFailed));
        }
    }

    #[test]
    fn tampered_nonce_fails() {
        for algo in ALGOS {
            let key = KeyBytes::generate();
            let mut blob =
                seal_with_key(algo, &key, 1, b"secret", &binding(1).aad()).expect("seal");
            blob[7] ^= 0x01; // first nonce byte
            let err = open_with_key(&key, &blob, &binding(1).aad()).unwrap_err();
            assert!(matches!(err, CryptoError::DecryptFailed));
        }
    }

    #[test]
    fn aad_swap_attack_fails() {
        let key = KeyBytes::generate();
        let blob =
            seal_with_key(Algorithm::Aes256Gcm, &key, 1, b"pw", &binding(7).aad()).expect("seal");

        // Same blob replayed into another row → binding mismatch.
        assert!(matches!(
            open_with_key(&key, &blob, &binding(9).aad()).unwrap_err(),
            CryptoError::DecryptFailed
        ));
        // …or another column.
        let other_column = AeadBinding {
            table: "repository",
            column: "other_secret_enc",
            row_pk: 7,
            destination: None,
        };
        assert!(matches!(
            open_with_key(&key, &blob, &other_column.aad()).unwrap_err(),
            CryptoError::DecryptFailed
        ));
        // …or another table.
        let other_table = AeadBinding {
            table: "oidc",
            column: "upstream_password_enc",
            row_pk: 7,
            destination: None,
        };
        assert!(matches!(
            open_with_key(&key, &blob, &other_table.aad()).unwrap_err(),
            CryptoError::DecryptFailed
        ));
    }

    #[test]
    fn destination_is_bound_and_distinct_from_the_row_only_binding() {
        let key = KeyBytes::generate();
        let to = |destination| AeadBinding {
            destination: Some(destination),
            ..binding(7)
        };
        let blob = seal_with_key(
            Algorithm::Aes256Gcm,
            &key,
            1,
            b"pw",
            &to("https://nexus.example").aad(),
        )
        .unwrap();
        assert_eq!(
            &*open_with_key(&key, &blob, &to("https://nexus.example").aad()).unwrap(),
            b"pw"
        );
        // Repointed elsewhere, or read under the row-only binding: no plaintext.
        for aad in [
            to("https://attacker.example").aad(),
            to("").aad(),
            to("https://nexus.example").row_only().aad(),
        ] {
            assert!(matches!(
                open_with_key(&key, &blob, &aad).unwrap_err(),
                CryptoError::DecryptFailed
            ));
        }
        // An empty destination is still a destination binding, not the v1 one.
        assert_ne!(to("").aad(), binding(7).aad());
        // The row-only binding is byte-for-byte what earlier builds used.
        let mut v1 = b"forge.secret.v1repository".to_vec();
        v1.push(0x1F);
        v1.extend_from_slice(b"upstream_password_enc");
        v1.push(0x1F);
        v1.extend_from_slice(&7i64.to_be_bytes());
        assert_eq!(binding(7).aad(), v1);
    }

    #[test]
    fn aad_fields_cannot_collide_across_separator() {
        // ("ab","c") vs ("a","bc") must produce different AADs (0x1F separator).
        let a = AeadBinding {
            table: "ab",
            column: "c",
            row_pk: 1,
            destination: None,
        };
        let b = AeadBinding {
            table: "a",
            column: "bc",
            row_pk: 1,
            destination: None,
        };
        assert_ne!(a.aad(), b.aad());
    }

    #[test]
    fn wrong_key_fails() {
        let key = KeyBytes::generate();
        let other = KeyBytes::generate();
        let blob =
            seal_with_key(Algorithm::Aes256Gcm, &key, 1, b"pw", &binding(1).aad()).expect("seal");
        assert!(matches!(
            open_with_key(&other, &blob, &binding(1).aad()).unwrap_err(),
            CryptoError::DecryptFailed
        ));
    }

    #[test]
    fn nonces_are_unique_across_seals() {
        let key = KeyBytes::generate();
        let aad = binding(1).aad();
        let mut nonces = std::collections::HashSet::new();
        let mut blobs = std::collections::HashSet::new();
        for _ in 0..64 {
            let blob =
                seal_with_key(Algorithm::Aes256Gcm, &key, 1, b"same plaintext", &aad).unwrap();
            let nonce_len = Algorithm::Aes256Gcm.nonce_len();
            assert!(
                nonces.insert(blob[7..7 + nonce_len].to_vec()),
                "nonce reused"
            );
            assert!(blobs.insert(blob), "identical blob produced twice");
        }
    }

    #[test]
    fn malformed_blobs_rejected() {
        // Too short for a header.
        assert!(matches!(
            parse_header(&[1, 1, 0, 0]).unwrap_err(),
            CryptoError::MalformedEnvelope(_)
        ));
        // Unknown format version.
        let mut blob =
            seal_with_key(Algorithm::Aes256Gcm, &KeyBytes::generate(), 1, b"x", b"aad").unwrap();
        blob[0] = 99;
        assert!(matches!(
            parse_header(&blob).unwrap_err(),
            CryptoError::UnsupportedFormatVersion(99)
        ));
        // Unknown algorithm id.
        blob[0] = FORMAT_VERSION;
        blob[1] = 99;
        assert!(matches!(
            parse_header(&blob).unwrap_err(),
            CryptoError::UnsupportedAlgorithm(99)
        ));
        // Truncated nonce.
        blob[1] = Algorithm::Aes256Gcm.id();
        assert!(matches!(
            parse_header(&blob[..9]).unwrap_err(),
            CryptoError::MalformedEnvelope(_)
        ));
    }

    #[test]
    fn algorithm_name_round_trip() {
        for algo in ALGOS {
            assert_eq!(Algorithm::parse(algo.as_str()).unwrap(), algo);
            assert_eq!(Algorithm::from_id(algo.id()).unwrap(), algo);
        }
        assert!(matches!(
            Algorithm::parse("rot13").unwrap_err(),
            CryptoError::UnknownAlgorithmName(_)
        ));
    }
}
