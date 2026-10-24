//! The digests the store verifies content against: `sha256:<hex>` and
//! `sha512:<hex>`, in the canonical form the format names them in. The CAS
//! hashes everything it stages with SHA-256 and SHA-512 at once, and is
//! keyed by SHA-256: a `sha512:` digest names the same CAS blob as its
//! `sha256:` twin, it is only verified against the other hash.

use base64::Engine;
use sha2::{Digest as _, Sha256, Sha512};

use crate::images::{Failure, ImgResult};

/// A content digest of a supported algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentDigest {
    text: String,
    sha512: bool,
}

impl ContentDigest {
    /// `sha256:<64 lowercase hex>` or `sha512:<128 lowercase hex>`.
    pub fn parse(text: &str) -> Option<Self> {
        let (sha512, hex) = match text.split_once(':')? {
            ("sha256", hex) if hex.len() == 64 => (false, hex),
            ("sha512", hex) if hex.len() == 128 => (true, hex),
            _ => return None,
        };
        hex.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            .then(|| ContentDigest {
                text: text.to_string(),
                sha512,
            })
    }

    /// A digest the format named: one of the store's, or the format broke
    /// the contract.
    pub fn named(text: &str) -> ImgResult<Self> {
        Self::parse(text).ok_or_else(|| {
            Failure::internal(
                "image digest",
                format!("the images format named {text:?} as a digest"),
            )
        })
    }

    /// The SHA-256 digest of `bytes`.
    pub fn sha256_of(bytes: &[u8]) -> Self {
        ContentDigest {
            text: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            sha512: false,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The hex part after the colon.
    pub fn hex(&self) -> &str {
        &self.text[self.text.find(':').map_or(0, |i| i + 1)..]
    }

    /// The CAS key of the content, for a `sha256:` digest.
    pub fn sha256_hex(&self) -> Option<&str> {
        (!self.sha512).then(|| self.hex())
    }

    /// Whether this digest names content with the given CAS hashes (the
    /// lowercase hex SHA-256 and the standard-base64 SHA-512 the CAS
    /// computes while staging).
    pub fn matches(&self, sha256_hex: &str, sha512_base64: &str) -> bool {
        if self.sha512 {
            base64::engine::general_purpose::STANDARD
                .decode(sha512_base64)
                .is_ok_and(|raw| hex::encode(raw) == self.hex())
        } else {
            self.hex() == sha256_hex
        }
    }

    /// Whether this digest names `bytes`.
    pub fn matches_bytes(&self, bytes: &[u8]) -> bool {
        if self.sha512 {
            hex::encode(Sha512::digest(bytes)) == self.hex()
        } else {
            hex::encode(Sha256::digest(bytes)) == self.hex()
        }
    }
}

impl std::fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_canonical_forms_only() {
        let empty = ContentDigest::sha256_of(b"");
        assert_eq!(
            empty.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(ContentDigest::parse(empty.as_str()), Some(empty.clone()));
        let sha512 = format!("sha512:{}", hex::encode(Sha512::digest(b"")));
        assert!(ContentDigest::parse(&sha512).is_some());
        for bad in [
            "",
            "sha256:",
            "sha256:abc",
            "md5:d41d8cd98f00b204e9800998ecf8427e",
            &empty.as_str().to_uppercase(),
            &format!("{}/", &empty.as_str()[..70]),
        ] {
            assert_eq!(ContentDigest::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn matches_cas_hashes() {
        let sha256 = hex::encode(Sha256::digest(b"hello"));
        let sha512 = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(b"hello"));
        let digest256 = ContentDigest::sha256_of(b"hello");
        let digest512 =
            ContentDigest::parse(&format!("sha512:{}", hex::encode(Sha512::digest(b"hello"))))
                .unwrap();
        assert!(digest256.matches(&sha256, &sha512));
        assert!(digest512.matches(&sha256, &sha512));
        assert!(digest512.matches_bytes(b"hello"));
        assert!(!ContentDigest::sha256_of(b"world").matches(&sha256, &sha512));
        assert_eq!(digest256.sha256_hex(), Some(sha256.as_str()));
        assert_eq!(digest512.sha256_hex(), None);
    }
}
