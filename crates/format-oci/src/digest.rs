//! OCI content digests (`<algorithm>:<encoded>`).
//!
//! The CAS is keyed by SHA-256, and every staged file is hashed with SHA-256
//! and SHA-512 at once, so both registered algorithms of the image spec are
//! supported: a `sha512:` digest names the same CAS blob as its `sha256:`
//! twin, it is only verified against the other hash. Any other algorithm is
//! refused as unsupported.

use std::fmt;

use base64::Engine;
use sha2::{Digest as _, Sha256, Sha512};

/// A digest algorithm Forge can verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
        }
    }

    /// Length of the lowercase hex encoding.
    fn hex_len(self) -> usize {
        match self {
            Algorithm::Sha256 => 64,
            Algorithm::Sha512 => 128,
        }
    }
}

/// Why a digest string was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    /// Not of the `<algorithm>:<encoded>` grammar, or the encoding does not
    /// fit the algorithm.
    #[error("invalid digest {0:?}")]
    Invalid(String),
    /// A well-formed digest of an algorithm Forge does not implement.
    #[error("unsupported digest algorithm {0:?}")]
    Unsupported(String),
}

/// A validated digest of a supported algorithm, kept in its canonical
/// `<algorithm>:<lowercase hex>` form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(String);

impl Digest {
    /// Parse `sha256:<64 hex>` or `sha512:<128 hex>`. Upper-case hex is
    /// refused: the image spec requires lowercase, and accepting both would
    /// give one blob two spellings.
    pub fn parse(s: &str) -> Result<Self, DigestError> {
        let (algorithm, encoded) = s
            .split_once(':')
            .ok_or_else(|| DigestError::Invalid(s.to_string()))?;
        if !valid_algorithm_grammar(algorithm) || !valid_encoded_grammar(encoded) {
            return Err(DigestError::Invalid(s.to_string()));
        }
        let algorithm = match algorithm {
            "sha256" => Algorithm::Sha256,
            "sha512" => Algorithm::Sha512,
            _ => return Err(DigestError::Unsupported(s.to_string())),
        };
        if encoded.len() != algorithm.hex_len()
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DigestError::Invalid(s.to_string()));
        }
        Ok(Digest(s.to_string()))
    }

    /// The SHA-256 digest of `bytes`.
    pub fn sha256_of(bytes: &[u8]) -> Self {
        Digest(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    /// The digest of `bytes` with `algorithm`.
    pub fn of(algorithm: Algorithm, bytes: &[u8]) -> Self {
        match algorithm {
            Algorithm::Sha256 => Self::sha256_of(bytes),
            Algorithm::Sha512 => Digest(format!("sha512:{}", hex::encode(Sha512::digest(bytes)))),
        }
    }

    /// A `sha256:` digest from the CAS's lowercase hex key.
    pub fn from_sha256_hex(hex: &str) -> Result<Self, DigestError> {
        Self::parse(&format!("sha256:{hex}"))
    }

    pub fn algorithm(&self) -> Algorithm {
        if self.0.starts_with("sha512:") {
            Algorithm::Sha512
        } else {
            Algorithm::Sha256
        }
    }

    /// The hex part after the colon.
    pub fn hex(&self) -> &str {
        &self.0[self.0.find(':').map_or(0, |i| i + 1)..]
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this digest names content with the given CAS hashes (the
    /// lowercase hex SHA-256 and the standard-base64 SHA-512 the CAS
    /// computes while staging).
    pub fn matches(&self, sha256_hex: &str, sha512_base64: &str) -> bool {
        match self.algorithm() {
            Algorithm::Sha256 => self.hex() == sha256_hex,
            Algorithm::Sha512 => base64::engine::general_purpose::STANDARD
                .decode(sha512_base64)
                .is_ok_and(|raw| hex::encode(raw) == self.hex()),
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Digest {
    type Err = DigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// `algorithm ::= component (separator component)*`,
/// `component ::= [a-z0-9]+`, `separator ::= [+._-]`.
fn valid_algorithm_grammar(s: &str) -> bool {
    !s.is_empty()
        && s.split(['+', '.', '_', '-'])
            .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

/// `encoded ::= [a-zA-Z0-9=_-]+`.
fn valid_encoded_grammar(s: &str) -> bool {
    !s.is_empty()
        && s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_sha256_and_sha512() {
        let d = Digest::parse(EMPTY_SHA256).unwrap();
        assert_eq!(d.algorithm(), Algorithm::Sha256);
        assert_eq!(d.hex().len(), 64);
        assert_eq!(Digest::sha256_of(b""), d);

        let d512 = Digest::of(Algorithm::Sha512, b"");
        assert_eq!(Digest::parse(d512.as_str()).unwrap(), d512);
        assert_eq!(d512.algorithm(), Algorithm::Sha512);
    }

    #[test]
    fn refuses_malformed_and_unknown() {
        for bad in [
            "",
            "sha256",
            "sha256:",
            ":abc",
            "sha256:abc",
            "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85/",
            "sha256:../../etc/passwd",
        ] {
            assert!(
                matches!(Digest::parse(bad), Err(DigestError::Invalid(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(
            Digest::parse("md5:d41d8cd98f00b204e9800998ecf8427e"),
            Err(DigestError::Unsupported(_))
        ));
    }

    #[test]
    fn matches_cas_hashes() {
        let sha256 = hex::encode(Sha256::digest(b"hello"));
        let sha512 = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(b"hello"));
        assert!(Digest::sha256_of(b"hello").matches(&sha256, &sha512));
        assert!(Digest::of(Algorithm::Sha512, b"hello").matches(&sha256, &sha512));
        assert!(!Digest::sha256_of(b"world").matches(&sha256, &sha512));
        assert!(!Digest::of(Algorithm::Sha512, b"world").matches(&sha256, &sha512));
    }
}
