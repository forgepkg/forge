//! Tarball digests: `dist.integrity` (Subresource Integrity, as `ssri` reads
//! it) and `dist.shasum` (the hex SHA-1).

use std::io::Read;

use base64::Engine as _;
use sha1::Digest as _;

/// The digests of a tarball.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// Lowercase hex SHA-1: `dist.shasum`.
    pub sha1_hex: String,
    /// Base64 SHA-256.
    pub sha256_base64: String,
    /// Base64 SHA-384.
    pub sha384_base64: String,
    /// Base64 SHA-512.
    pub sha512_base64: String,
    /// The number of bytes read.
    pub size: u64,
}

impl Digests {
    /// Digest everything `reader` yields.
    pub fn of(mut reader: impl Read) -> std::io::Result<Self> {
        let mut sha1 = sha1::Sha1::new();
        let mut sha256 = sha2::Sha256::new();
        let mut sha384 = sha2::Sha384::new();
        let mut sha512 = sha2::Sha512::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            sha1.update(chunk);
            sha256.update(chunk);
            sha384.update(chunk);
            sha512.update(chunk);
            size += n as u64;
        }
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        Ok(Digests {
            sha1_hex: hex::encode(sha1.finalize()),
            sha256_base64: b64(&sha256.finalize()),
            sha384_base64: b64(&sha384.finalize()),
            sha512_base64: b64(&sha512.finalize()),
            size,
        })
    }

    /// The `dist.integrity` Forge serves: `sha512-<base64>`.
    pub fn integrity(&self) -> String {
        format!("sha512-{}", self.sha512_base64)
    }

    /// The base64 digest of algorithm `alg`, if it is one of these.
    fn of_algorithm(&self, alg: &str) -> Option<&str> {
        match alg {
            "sha1" => None,
            "sha256" => Some(&self.sha256_base64),
            "sha384" => Some(&self.sha384_base64),
            "sha512" => Some(&self.sha512_base64),
            _ => None,
        }
    }

    /// Check the tarball against what its metadata claims: `integrity` (an
    /// SRI string) and `shasum` (hex SHA-1), each when given. At least one
    /// must be given. Like `ssri`, an SRI string is checked with its
    /// strongest algorithm, any of whose hashes may match.
    pub fn verify(&self, integrity: Option<&str>, shasum: Option<&str>) -> Result<(), String> {
        let integrity = integrity.map(str::trim).filter(|s| !s.is_empty());
        let shasum = shasum.map(str::trim).filter(|s| !s.is_empty());
        if integrity.is_none() && shasum.is_none() {
            return Err("the version has neither dist.integrity nor dist.shasum".into());
        }
        if let Some(integrity) = integrity {
            self.verify_sri(integrity)?;
        }
        if let Some(shasum) = shasum {
            if !shasum.eq_ignore_ascii_case(&self.sha1_hex) {
                return Err(format!(
                    "dist.shasum {shasum} does not match the tarball (sha1 {})",
                    self.sha1_hex
                ));
            }
        }
        Ok(())
    }

    fn verify_sri(&self, integrity: &str) -> Result<(), String> {
        const STRENGTH: [&str; 4] = ["sha512", "sha384", "sha256", "sha1"];
        let hashes: Vec<(&str, &str)> = integrity
            .split_ascii_whitespace()
            .filter_map(|entry| {
                let (alg, rest) = entry.split_once('-')?;
                // Options after `?` (SRI's extension point) are ignored.
                let digest = rest.split('?').next().unwrap_or(rest);
                Some((alg, digest))
            })
            .filter(|(alg, _)| STRENGTH.contains(alg))
            .collect();
        let Some(strongest) = STRENGTH
            .iter()
            .find(|alg| hashes.iter().any(|(a, _)| a == *alg))
        else {
            return Err(format!(
                "dist.integrity {integrity:?} names no supported algorithm"
            ));
        };
        let matches = hashes
            .iter()
            .filter(|(alg, _)| alg == strongest)
            .any(|(_, digest)| {
                match self.of_algorithm(strongest) {
                    Some(ours) => *digest == ours,
                    // SHA-1 integrity: base64 of the raw digest.
                    None => hex::decode(&self.sha1_hex)
                        .map(|raw| base64::engine::general_purpose::STANDARD.encode(raw))
                        .is_ok_and(|ours| *digest == ours),
                }
            });
        if matches {
            Ok(())
        } else {
            Err(format!(
                "dist.integrity does not match the tarball ({})",
                self.integrity()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_integrity_and_shasum() {
        let d = Digests::of(&b"hello"[..]).unwrap();
        assert_eq!(d.size, 5);
        assert_eq!(d.sha1_hex, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        let sri = d.integrity();
        assert!(sri.starts_with("sha512-"));
        d.verify(Some(&sri), Some(&d.sha1_hex)).unwrap();
        d.verify(Some(&sri), None).unwrap();
        d.verify(None, Some("AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D"))
            .unwrap();
        // The strongest algorithm decides; a weaker one may be wrong.
        d.verify(Some(&format!("sha1-AAAA {sri}")), None).unwrap();
        assert!(d
            .verify(Some(&format!("{} sha1-x", "sha512-AAAA")), None)
            .is_err());
        assert!(d.verify(Some("sha512-AAAA"), None).is_err());
        assert!(d.verify(Some("md5-AAAA"), None).is_err());
        assert!(d.verify(None, Some("00")).is_err());
        assert!(d.verify(None, None).is_err());
        // SHA-1 integrity strings, as old packages carry.
        d.verify(Some("sha1-qvTGHdzF6KLavt4PO0gs2a6pQ00="), None)
            .unwrap();
        // Options are ignored.
        d.verify(Some(&format!("{sri}?foo")), None).unwrap();
    }
}
