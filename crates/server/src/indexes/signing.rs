//! The OpenPGP keys that sign a repository's indexes (apt's `InRelease` and
//! `Release.gpg`), with rPGP.
//!
//! A key Forge generates is a v4 Ed25519 key (EdDSA, which `gpgv` 2.1 and
//! later verify: Debian 9, Ubuntu 18.04 and newer) whose primary key signs.
//! An imported key must sign with Ed25519 too (its newest signing subkey,
//! else its primary key): rPGP links RSA and NIST-curve code whose secret-key
//! operations are not constant-time (RUSTSEC-2023-0071, RUSTSEC-2026-0387),
//! and Forge never uses them. A passphrase is removed on import: the key is
//! kept sealed by the secret encryption instead, and never leaves the
//! server.
//!
//! Signatures are made with SHA-512, by every key of the repository, so a
//! client trusting either key of a rollover verifies them.

use pgp::armor::{self, BlockType};
use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, EncryptionCaps,
    KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, KeyVersion, Password, SigningKey, Timestamp};
use rand_core_06::OsRng;

/// Why a key could not be made, read or used.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// What an administrator gave is not a usable key (shown to them).
    #[error("{0}")]
    Invalid(String),
    #[error("OpenPGP: {0}")]
    Pgp(#[from] pgp::errors::Error),
}

/// What is shown of a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The primary key's fingerprint, uppercase hex.
    pub fingerprint: String,
    /// The signing key's algorithm.
    pub algorithm: String,
    /// The primary user id.
    pub user_id: String,
    /// The certificate, ASCII-armored.
    pub public_key: String,
}

/// A secret key, ready to sign.
#[derive(Clone)]
pub struct Key {
    secret: SignedSecretKey,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("fingerprint", &fingerprint(&self.secret))
            .finish_non_exhaustive()
    }
}

fn fingerprint(key: &SignedSecretKey) -> String {
    format!("{:X}", key.fingerprint())
}

impl Key {
    /// A new Ed25519 key for `user_id` (`Forge apt-internal <forge@host>`).
    pub fn generate(user_id: &str) -> Result<Key, SigningError> {
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .preferred_hash_algorithms(
                [HashAlgorithm::Sha512, HashAlgorithm::Sha256]
                    .into_iter()
                    .collect(),
            )
            .primary_user_id(user_id.to_string());
        let params = params
            .build()
            .map_err(|e| SigningError::Invalid(format!("key parameters: {e}")))?;
        let secret = params.generate(OsRng)?;
        Ok(Key { secret })
    }

    /// An administrator's ASCII-armored secret key, its passphrase removed.
    pub fn import(armored: &str, passphrase: Option<&str>) -> Result<Key, SigningError> {
        let (mut secret, _) = SignedSecretKey::from_string(armored.trim()).map_err(|e| {
            SigningError::Invalid(format!("not an ASCII-armored OpenPGP secret key: {e}"))
        })?;
        secret.verify_bindings().map_err(|e| {
            SigningError::Invalid(format!("the key's self-signatures do not verify: {e}"))
        })?;
        if secret.version() != KeyVersion::V4 {
            return Err(SigningError::Invalid(
                "only v4 keys are supported (gpgv verifies no v6 signatures yet)".into(),
            ));
        }
        let password = Password::from(passphrase.unwrap_or(""));
        let locked = |e: pgp::errors::Error| {
            SigningError::Invalid(format!(
                "the key could not be unlocked (a wrong or missing passphrase?): {e}"
            ))
        };
        if secret.primary_key.secret_params().is_encrypted() {
            secret
                .primary_key
                .remove_password(&password)
                .map_err(locked)?;
        }
        for sub in &mut secret.secret_subkeys {
            if sub.key.secret_params().is_encrypted() {
                sub.key.remove_password(&password).map_err(locked)?;
            }
        }
        let key = Key { secret };
        let algorithm = key.signer().algorithm();
        if algorithm != PublicKeyAlgorithm::EdDSALegacy {
            return Err(SigningError::Invalid(format!(
                "Forge signs with Ed25519 (EdDSA) keys, and this key signs with {algorithm:?}: \
                 generate a key, or import an Ed25519 one \
                 (gpg --quick-gen-key '<user id>' ed25519 sign)"
            )));
        }
        // It must be able to sign.
        key.sign_detached(b"probe")?;
        Ok(key)
    }

    /// A key sealed with [`Key::to_sealable`].
    pub fn from_sealed(armored: &str) -> Result<Key, SigningError> {
        let (secret, _) = SignedSecretKey::from_string(armored)?;
        Ok(Key { secret })
    }

    /// The secret key, ASCII-armored, without a passphrase: what is sealed.
    pub fn to_sealable(&self) -> Result<String, SigningError> {
        Ok(self.secret.to_armored_string(ArmorOptions::default())?)
    }

    /// The certificate.
    pub fn public(&self) -> SignedPublicKey {
        self.secret.to_public_key()
    }

    /// What is shown of the key.
    pub fn info(&self) -> Result<KeyInfo, SigningError> {
        let public = self.public();
        let user_id = public
            .details
            .users
            .first()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .unwrap_or_default();
        let signer = self.signer();
        Ok(KeyInfo {
            fingerprint: fingerprint(&self.secret),
            algorithm: algorithm_name(*signer),
            user_id,
            public_key: public.to_armored_string(ArmorOptions::default())?,
        })
    }

    /// The key that signs: the newest subkey whose binding allows signing,
    /// else the primary key.
    // rPGP signs with a `Box<&dyn SigningKey>` (it implements its traits for
    // that type, not for `&dyn SigningKey`).
    #[allow(clippy::redundant_allocation)]
    fn signer(&self) -> Box<&dyn SigningKey> {
        let signing_subkey = self
            .secret
            .secret_subkeys
            .iter()
            .filter(|sub| sub.signatures.iter().any(|sig| sig.key_flags().sign()))
            .max_by_key(|sub| sub.key.created_at());
        match signing_subkey {
            Some(sub) => Box::new(&sub.key as &dyn SigningKey),
            None => Box::new(&self.secret.primary_key as &dyn SigningKey),
        }
    }

    /// A signature of `data` of type `typ` (`data` normalized as that type
    /// requires).
    fn signature(&self, typ: SignatureType, data: &[u8]) -> pgp::errors::Result<Signature> {
        let signer = self.signer();
        let mut config = SignatureConfig::from_key(OsRng, &signer, typ)?;
        config.hash_alg = HashAlgorithm::Sha512;
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
        ];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            signer.legacy_key_id(),
        ))?];
        config.sign(&signer, &Password::empty(), data)
    }

    /// A detached signature of `data` (binary), ASCII-armored.
    pub fn sign_detached(&self, data: &[u8]) -> Result<String, SigningError> {
        sign_detached(std::slice::from_ref(self), data)
    }
}

fn algorithm_name(key: &dyn SigningKey) -> String {
    match key.algorithm() {
        PublicKeyAlgorithm::EdDSALegacy | PublicKeyAlgorithm::Ed25519 => "EdDSA (Ed25519)".into(),
        other => format!("{other:?}"),
    }
}

/// `text` inside a cleartext signature of every one of `keys` (apt's
/// `InRelease`).
pub fn sign_cleartext(keys: &[Key], text: &str) -> Result<String, SigningError> {
    let message = CleartextSignedMessage::new_many(text, |normalized| {
        keys.iter()
            .map(|key| key.signature(SignatureType::Text, normalized.as_bytes()))
            .collect()
    })?;
    Ok(message.to_armored_string(ArmorOptions::default())?)
}

/// One ASCII-armored block of detached signatures of `data` (binary), one
/// of every one of `keys` (apt's `Release.gpg`).
pub fn sign_detached(keys: &[Key], data: &[u8]) -> Result<String, SigningError> {
    // With their packet headers, as a detached signature is written.
    let signatures = keys
        .iter()
        .map(|key| {
            key.signature(SignatureType::Binary, data)
                .map(DetachedSignature::new)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    armor::write(&signatures, BlockType::Signature, &mut out, None, true)?;
    String::from_utf8(out).map_err(|e| SigningError::Invalid(e.to_string()))
}

/// The certificates of `keys` as one binary keyring, and as one
/// ASCII-armored block.
pub fn keyring(keys: &[Key]) -> Result<(Vec<u8>, String), SigningError> {
    let publics: Vec<SignedPublicKey> = keys.iter().map(Key::public).collect();
    let binary = publics.to_bytes()?;
    let mut armored = Vec::new();
    armor::write(&publics, BlockType::PublicKey, &mut armored, None, true)?;
    let armored = String::from_utf8(armored).map_err(|e| SigningError::Invalid(e.to_string()))?;
    Ok((binary, armored))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_sign_both_ways() {
        let a = Key::generate("Forge test <forge@example.com>").unwrap();
        let b = Key::generate("Forge next <forge@example.com>").unwrap();
        let info = a.info().unwrap();
        assert_eq!(info.fingerprint.len(), 40);
        assert_eq!(info.algorithm, "EdDSA (Ed25519)");
        assert_eq!(info.user_id, "Forge test <forge@example.com>");

        let text = "Origin: Forge\nSuite: bookworm\n";
        let signed = sign_cleartext(&[a.clone(), b.clone()], text).unwrap();
        assert!(
            signed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n"),
            "{signed}"
        );
        let (message, _) = CleartextSignedMessage::from_string(&signed).unwrap();
        assert_eq!(message.signatures().len(), 2);
        message.verify(&a.public()).unwrap();
        message.verify(&b.public()).unwrap();

        let detached = sign_detached(&[a.clone(), b.clone()], text.as_bytes()).unwrap();
        assert!(detached.starts_with("-----BEGIN PGP SIGNATURE-----"));
        let (parsed, _) = DetachedSignature::from_armor_many(detached.as_bytes()).unwrap();
        let parsed: Vec<DetachedSignature> = parsed.collect::<Result<_, _>>().unwrap();
        assert_eq!(parsed.len(), 2);
        parsed[0].verify(&a.public(), text.as_bytes()).unwrap();
        parsed[1].verify(&b.public(), text.as_bytes()).unwrap();
        let (binary, armored) = keyring(&[a.clone(), b]).unwrap();
        assert!(!binary.is_empty());
        assert!(armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        // A sealed key comes back the same.
        let again = Key::from_sealed(&a.to_sealable().unwrap()).unwrap();
        assert_eq!(again.info().unwrap(), a.info().unwrap());
    }

    #[test]
    fn imports_refuse_what_cannot_sign() {
        assert!(matches!(
            Key::import("not a key", None),
            Err(SigningError::Invalid(_))
        ));
        let public = Key::generate("x <x@example.com>")
            .unwrap()
            .info()
            .unwrap()
            .public_key;
        assert!(matches!(
            Key::import(&public, None),
            Err(SigningError::Invalid(_))
        ));
        let key = Key::generate("x <x@example.com>").unwrap();
        let imported = Key::import(&key.to_sealable().unwrap(), None).unwrap();
        assert_eq!(
            imported.info().unwrap().fingerprint,
            key.info().unwrap().fingerprint
        );
        // A key of another algorithm is refused: Forge signs with Ed25519 only.
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::ECDSA(pgp::crypto::ecc_curve::ECCCurve::P256))
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id("p256 <p@example.com>".into());
        let p256 = params.build().unwrap().generate(OsRng).unwrap();
        let armored = p256.to_armored_string(ArmorOptions::default()).unwrap();
        let err = Key::import(&armored, None).unwrap_err().to_string();
        assert!(err.contains("Ed25519"), "{err}");
    }
}
