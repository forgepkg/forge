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
//! A key signs only while its certificate says it may ([`Certificate`]): a
//! key that is revoked or expired, by the self-signatures that verify, is
//! refused on import, and one that expires later stops signing then
//! ([`Key::can_sign`]): apt refuses a signature of an expired or revoked key
//! (gpgv's `EXPKEYSIG` and `REVKEYSIG`).
//!
//! Signatures are made with SHA-512, by every key of the repository, so a
//! client trusting either key of a rollover verifies them.

use chrono::{DateTime, Utc};
use pgp::armor::{self, BlockType};
use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, EncryptionCaps,
    KeyType, SecretKeyParamsBuilder, SignedKeyDetails, SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{
    PublicKey, PublicSubkey, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
};
use pgp::ser::Serialize;
use pgp::types::{Fingerprint, KeyDetails, KeyVersion, Password, SigningKey, Tag, Timestamp};
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
        // Not revoked, not expired, and an Ed25519 key of it may sign.
        key.can_sign()?;
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
        let signer = self.signer()?;
        Ok(KeyInfo {
            fingerprint: fingerprint(&self.secret),
            algorithm: algorithm_name(*signer),
            user_id,
            public_key: public.to_armored_string(ArmorOptions::default())?,
        })
    }

    /// What the certificate's self-signatures say of its keys: of the
    /// primary key and of the subkeys whose secret key is here.
    fn certificate(&self) -> Certificate {
        Certificate::read(
            self.secret.primary_key.public_key(),
            &self.secret.details,
            self.secret
                .secret_subkeys
                .iter()
                .map(|sub| (sub.key.public_key(), &sub.signatures[..])),
        )
    }

    /// Whether the key can sign now. It cannot when it is revoked, when it
    /// has expired (also after it was imported), or when no key of it that
    /// may sign is left; the error says which.
    pub fn can_sign(&self) -> Result<(), SigningError> {
        self.signer().map(drop)
    }

    /// The key that signs now ([`Key::signer_at`]).
    #[allow(clippy::redundant_allocation)]
    fn signer(&self) -> Result<Box<&dyn SigningKey>, SigningError> {
        self.signer_at(now())
    }

    /// The key that signs at `now` (seconds since the epoch): the newest
    /// subkey that may sign and is neither revoked nor expired then, else
    /// the primary key if it may sign ([`Certificate::signer`]). It is an
    /// Ed25519 key, or the key does not sign at all.
    // rPGP signs with a `Box<&dyn SigningKey>` (it implements its traits for
    // that type, not for `&dyn SigningKey`).
    #[allow(clippy::redundant_allocation)]
    fn signer_at(&self, now: u64) -> Result<Box<&dyn SigningKey>, SigningError> {
        let certificate = self.certificate();
        let chosen = certificate.signer(now)?;
        if chosen.algorithm != PublicKeyAlgorithm::EdDSALegacy {
            return Err(SigningError::Invalid(format!(
                "Forge signs with Ed25519 (EdDSA) keys, and this key signs with {:?}: \
                 generate a key, or import an Ed25519 one \
                 (gpg --quick-gen-key '<user id>' ed25519 sign)",
                chosen.algorithm
            )));
        }
        if chosen.fingerprint == self.secret.primary_key.fingerprint() {
            return Ok(Box::new(&self.secret.primary_key as &dyn SigningKey));
        }
        self.secret
            .secret_subkeys
            .iter()
            .find(|sub| sub.key.fingerprint() == chosen.fingerprint)
            .map(|sub| Box::new(&sub.key as &dyn SigningKey))
            .ok_or_else(|| SigningError::Invalid("the signing subkey is missing".into()))
    }

    /// A signature of `data` of type `typ` (`data` normalized as that type
    /// requires).
    fn signature(&self, typ: SignatureType, data: &[u8]) -> Result<Signature, SigningError> {
        let signer = self.signer()?;
        let mut config = SignatureConfig::from_key(OsRng, &signer, typ)?;
        config.hash_alg = HashAlgorithm::Sha512;
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
        ];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            signer.legacy_key_id(),
        ))?];
        Ok(config.sign(&signer, &Password::empty(), data)?)
    }

    /// A detached signature of `data` (binary), ASCII-armored.
    pub fn sign_detached(&self, data: &[u8]) -> Result<String, SigningError> {
        sign_detached(std::slice::from_ref(self), data)
    }
}

/// Now, in seconds since the epoch.
fn now() -> u64 {
    u64::from(Timestamp::now().as_secs())
}

/// The earlier of two expiries, `None` being never.
fn earlier(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// `at` (seconds since the epoch) as it is shown.
fn date(at: u64) -> String {
    match i64::try_from(at)
        .ok()
        .and_then(|at| DateTime::from_timestamp(at, 0))
    {
        Some(at) => at.format("%Y-%m-%d %H:%M UTC").to_string(),
        None => format!("{at} seconds after 1970"),
    }
}

/// When a key made at `created` stops being valid by `signature`, the
/// self-signature that holds for it (RFC 9580, 5.2.3.13): the key expiration
/// time counts from the key's creation, none or zero being never. A
/// self-signature that itself expires (its signature expiration time, from
/// its own creation) holds no longer than that.
fn expiry(created: Timestamp, signature: &Signature) -> Option<u64> {
    let after = |from: Timestamp, seconds: u32| u64::from(from.as_secs()) + u64::from(seconds);
    let key = signature
        .key_expiration_time()
        .filter(|d| d.as_secs() > 0)
        .map(|d| after(created, d.as_secs()));
    let itself = signature
        .signature_expiration_time()
        .filter(|d| d.as_secs() > 0)
        .zip(signature.created())
        .map(|(d, made)| after(made, d.as_secs()));
    earlier(key, itself)
}

/// Whether `signature` says which uses its key has (a key flags subpacket).
fn has_key_flags(signature: &Signature) -> bool {
    signature.config().is_some_and(|config| {
        config
            .hashed_subpackets()
            .any(|p| matches!(p.data, SubpacketData::KeyFlags(_)))
    })
}

/// A key of a certificate that may sign, by its self-signatures.
#[derive(Debug)]
struct Candidate {
    fingerprint: Fingerprint,
    algorithm: PublicKeyAlgorithm,
    created: Timestamp,
    /// By a subkey revocation signature of the primary key.
    revoked: bool,
    /// Seconds since the epoch; `None` is never.
    expires: Option<u64>,
}

/// What a certificate's self-signatures say of its keys: which may sign,
/// which are revoked, and when each expires.
///
/// Only a signature that verifies with the primary key counts, whatever it
/// says: a revocation or an expiry is never taken from a signature that is
/// merely present (another key's certification of a user id, a forged
/// packet), and of the signatures that verify, the newest of its kind holds,
/// as an expiry is extended by a newer self-signature.
#[derive(Debug)]
struct Certificate {
    /// A self-signature of the primary key verifies.
    self_signed: bool,
    /// By a key revocation signature of the primary key.
    revoked: bool,
    /// When the primary key expires, and every subkey with it.
    expires: Option<u64>,
    /// The primary key, if it may sign.
    primary: Option<Candidate>,
    /// The subkeys that may sign.
    subkeys: Vec<Candidate>,
}

impl Certificate {
    fn read<'a>(
        primary: &PublicKey,
        details: &SignedKeyDetails,
        subkeys: impl Iterator<Item = (&'a PublicSubkey, &'a [Signature])>,
    ) -> Certificate {
        let revoked = details.revocation_signatures.iter().any(|sig| {
            sig.typ() == Some(SignatureType::KeyRevocation) && sig.verify_key(primary).is_ok()
        });
        // The self-signatures that hold for the primary key: the newest
        // direct key signature, and the newest self-certification of each
        // user id that is not revoked (a certification revocation that is
        // the newest of the user id's). Verifiers differ in which of them
        // they read the expiry from (gpgv prefers the direct key signature,
        // Sequoia's sqv the primary user id's), so the earliest one holds:
        // a signature must verify with all of them.
        let mut holding: Vec<&Signature> = Vec::new();
        holding.extend(
            details
                .direct_signatures
                .iter()
                .filter(|sig| {
                    sig.typ() == Some(SignatureType::Key) && sig.verify_key(primary).is_ok()
                })
                .max_by_key(|sig| sig.created()),
        );
        for user in &details.users {
            let newest = user
                .signatures
                .iter()
                .filter(|sig| {
                    sig.verify_certification(primary, Tag::UserId, &user.id)
                        .is_ok()
                })
                .max_by_key(|sig| sig.created());
            holding.extend(newest.filter(|sig| sig.typ() != Some(SignatureType::CertRevocation)));
        }
        let expires = holding.iter().fold(None, |at, sig| {
            earlier(at, expiry(primary.created_at(), sig))
        });
        // Without key flags the key may do what its algorithm can.
        let signs = holding.iter().any(|sig| sig.key_flags().sign())
            || !holding.iter().any(|sig| has_key_flags(sig));
        let subkeys = subkeys
            .filter_map(|(key, signatures)| {
                let verified = |typ: SignatureType| {
                    signatures.iter().filter(move |sig| {
                        sig.typ() == Some(typ) && sig.verify_subkey_binding(primary, key).is_ok()
                    })
                };
                let binding =
                    verified(SignatureType::SubkeyBinding).max_by_key(|sig| sig.created())?;
                binding.key_flags().sign().then(|| Candidate {
                    fingerprint: key.fingerprint(),
                    algorithm: key.algorithm(),
                    created: key.created_at(),
                    revoked: verified(SignatureType::SubkeyRevocation).next().is_some(),
                    expires: expiry(key.created_at(), binding),
                })
            })
            .collect();
        Certificate {
            self_signed: !holding.is_empty(),
            revoked,
            expires,
            primary: (signs && !holding.is_empty()).then(|| Candidate {
                fingerprint: primary.fingerprint(),
                algorithm: primary.algorithm(),
                created: primary.created_at(),
                revoked,
                expires,
            }),
            subkeys,
        }
    }

    /// The key that signs at `now`: the newest subkey that may sign and is
    /// neither revoked nor expired then, else the primary key if it may
    /// sign. None when the primary key is revoked or expired (its subkeys go
    /// with it) or no such key is left; the error says why.
    fn signer(&self, now: u64) -> Result<&Candidate, SigningError> {
        let refuse = |why: String| Err(SigningError::Invalid(why));
        if !self.self_signed {
            return refuse("the key has no self-signature that verifies".into());
        }
        if self.revoked {
            return refuse("the key is revoked".into());
        }
        if let Some(at) = self.expires.filter(|at| *at <= now) {
            return refuse(format!("the key expired on {}", date(at)));
        }
        let valid = |key: &&Candidate| !key.revoked && key.expires.is_none_or(|at| at > now);
        if let Some(subkey) = self.subkeys.iter().filter(valid).max_by_key(|k| k.created) {
            return Ok(subkey);
        }
        if let Some(primary) = &self.primary {
            return Ok(primary);
        }
        if self.subkeys.is_empty() {
            return refuse(
                "no key of it may sign (neither the primary key nor a subkey has the \
                 signing flag)"
                    .into(),
            );
        }
        let subkeys: Vec<String> = self
            .subkeys
            .iter()
            .map(|key| match key.expires {
                _ if key.revoked => format!("{:X} is revoked", key.fingerprint),
                Some(at) => format!("{:X} expired on {}", key.fingerprint, date(at)),
                None => format!("{:X} is not valid", key.fingerprint),
            })
            .collect();
        refuse(format!(
            "no key of it can sign: the primary key may not sign, and signing subkey {}",
            subkeys.join(", signing subkey ")
        ))
    }

    /// When the certificate stops signing: when its primary key expires, or
    /// the last of the keys that may sign. `None` is never.
    fn expires(&self) -> Option<u64> {
        let mut signing = self
            .subkeys
            .iter()
            .chain(&self.primary)
            .filter(|key| !key.revoked)
            .map(|key| key.expires);
        let last = match signing.next() {
            Some(first) => signing.fold(first, |last, at| match (last, at) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            }),
            None => None,
        };
        earlier(self.expires, last)
    }
}

/// When the certificate `public_key` (ASCII-armored, as [`KeyInfo`] has it)
/// stops signing, or stopped: `None` when it never expires.
pub fn expires_at(public_key: &str) -> Result<Option<DateTime<Utc>>, SigningError> {
    let (public, _) = SignedPublicKey::from_string(public_key)?;
    let certificate = Certificate::read(
        &public.primary_key,
        &public.details,
        public
            .public_subkeys
            .iter()
            .map(|sub| (&sub.key, &sub.signatures[..])),
    );
    Ok(certificate
        .expires()
        .and_then(|at| i64::try_from(at).ok())
        .and_then(|at| DateTime::from_timestamp(at, 0)))
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
    // rPGP's closure answers its own errors: a key's is carried out of it.
    let mut failed = None;
    let message = CleartextSignedMessage::new_many(text, |normalized| {
        let mut signatures = Vec::with_capacity(keys.len());
        for key in keys {
            match key.signature(SignatureType::Text, normalized.as_bytes()) {
                Ok(signature) => signatures.push(signature),
                Err(SigningError::Pgp(e)) => return Err(e),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        Ok(signatures)
    });
    if let Some(e) = failed {
        return Err(e);
    }
    Ok(message?.to_armored_string(ArmorOptions::default())?)
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
        .collect::<Result<Vec<_>, SigningError>>()?;
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

    const DAY: u32 = 86_400;

    fn days_ago(days: u32) -> Timestamp {
        Timestamp::from_secs(Timestamp::now().as_secs() - days * DAY)
    }

    /// A key made 30 days ago, as gpg makes them: an Ed25519 primary key
    /// that certifies (and signs, if `primary_signs`), with an Ed25519
    /// signing subkey made 20 days ago if `subkey`. Nothing of it expires.
    fn made(primary_signs: bool, subkey: bool) -> SignedSecretKey {
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .created_at(days_ago(30))
            .can_certify(true)
            .can_sign(primary_signs)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id("Imported <imported@example.com>".into());
        if subkey {
            params.subkey(
                pgp::composed::SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519Legacy)
                    .created_at(days_ago(20))
                    .can_sign(true)
                    .build()
                    .unwrap(),
            );
        }
        params.build().unwrap().generate(OsRng).unwrap()
    }

    fn armored(key: &SignedSecretKey) -> String {
        key.to_armored_string(ArmorOptions::default()).unwrap()
    }

    fn refusal(key: &SignedSecretKey) -> String {
        Key::import(&armored(key), None).unwrap_err().to_string()
    }

    /// A signature of `signer`'s primary key, made `days` ago, to be signed
    /// as a self-signature of `typ` with `subpackets` hashed.
    fn self_signature(
        signer: &SignedSecretKey,
        typ: SignatureType,
        days: u32,
        subpackets: Vec<SubpacketData>,
    ) -> SignatureConfig {
        let mut config = SignatureConfig::from_key(OsRng, &signer.primary_key, typ).unwrap();
        config.hashed_subpackets = [
            SubpacketData::SignatureCreationTime(days_ago(days)),
            SubpacketData::IssuerFingerprint(signer.primary_key.fingerprint()),
        ]
        .into_iter()
        .chain(subpackets)
        .map(|data| Subpacket::regular(data).unwrap())
        .collect();
        config
    }

    fn lifetime(days: u32) -> SubpacketData {
        SubpacketData::KeyExpirationTime(pgp::types::Duration::from_secs(days * DAY))
    }

    /// A self-certification of `key`'s user id by `signer` (`key` itself,
    /// unless it is forged), made `days` ago, with the primary key's flags
    /// and, if `expires`, its expiry that many days after it was made.
    fn certification(
        key: &SignedSecretKey,
        signer: &SignedSecretKey,
        days: u32,
        expires: Option<u32>,
    ) -> Signature {
        let user = &key.details.users[0];
        let flags = user.signatures[0].key_flags();
        let subpackets = std::iter::once(SubpacketData::KeyFlags(flags))
            .chain(expires.map(lifetime))
            .collect();
        self_signature(signer, SignatureType::CertPositive, days, subpackets)
            .sign_certification(
                &signer.primary_key,
                key.primary_key.public_key(),
                &Password::empty(),
                Tag::UserId,
                &user.id,
            )
            .unwrap()
    }

    /// `key`, its primary key expiring `days` after it was made, by a new
    /// self-certification in place of the user id's.
    fn primary_expiring(mut key: SignedSecretKey, days: u32) -> SignedSecretKey {
        let signature = certification(&key, &key, 0, Some(days));
        key.details.users[0].signatures = vec![signature];
        key
    }

    /// A binding of `key`'s subkey by its primary key, made `days` ago, with
    /// the binding's flags and back signature and, if `expires`, the
    /// subkey's expiry that many days after it was made.
    fn binding(key: &SignedSecretKey, days: u32, expires: Option<u32>) -> Signature {
        let sub = &key.secret_subkeys[0];
        let old = &sub.signatures[0];
        let subpackets = [
            SubpacketData::KeyFlags(old.key_flags()),
            SubpacketData::EmbeddedSignature(Box::new(old.embedded_signature().unwrap().clone())),
        ]
        .into_iter()
        .chain(expires.map(lifetime))
        .collect();
        self_signature(key, SignatureType::SubkeyBinding, days, subpackets)
            .sign_subkey_binding(
                &key.primary_key,
                key.primary_key.public_key(),
                &Password::empty(),
                sub.key.public_key(),
            )
            .unwrap()
    }

    /// `key`, its subkey expiring `days` after it was made, by a new binding
    /// in place of the subkey's.
    fn subkey_expiring(mut key: SignedSecretKey, days: u32) -> SignedSecretKey {
        let signature = binding(&key, 0, Some(days));
        key.secret_subkeys[0].signatures = vec![signature];
        key
    }

    /// A revocation of `key`'s primary key, signed by `signer`'s.
    fn key_revocation(key: &SignedSecretKey, signer: &SignedSecretKey) -> Signature {
        self_signature(signer, SignatureType::KeyRevocation, 0, Vec::new())
            .sign_key(
                &signer.primary_key,
                &Password::empty(),
                key.primary_key.public_key(),
            )
            .unwrap()
    }

    /// A revocation of `key`'s subkey, signed by `signer`'s primary key.
    fn subkey_revocation(key: &SignedSecretKey, signer: &SignedSecretKey) -> Signature {
        self_signature(signer, SignatureType::SubkeyRevocation, 0, Vec::new())
            .sign_subkey_binding(
                &signer.primary_key,
                key.primary_key.public_key(),
                &Password::empty(),
                key.secret_subkeys[0].key.public_key(),
            )
            .unwrap()
    }

    /// The fingerprint of the key that made `key`'s signature.
    fn signed_by(key: &Key) -> Fingerprint {
        let signature = key.signature(SignatureType::Binary, b"data").unwrap();
        signature.issuer_fingerprint()[0].clone()
    }

    fn subkey_fingerprint(key: &SignedSecretKey) -> Fingerprint {
        key.secret_subkeys[0].key.fingerprint()
    }

    #[test]
    fn import_refuses_an_expired_primary_key() {
        // Made 30 days ago, for 10 days. The subkey goes with it.
        for subkey in [false, true] {
            let key = primary_expiring(made(true, subkey), 10);
            let why = refusal(&key);
            assert!(why.contains("the key expired on 2"), "{why}");
        }
    }

    #[test]
    fn import_refuses_a_revoked_primary_key() {
        for subkey in [false, true] {
            let mut key = made(true, subkey);
            let revocation = key_revocation(&key, &key);
            key.details.revocation_signatures.push(revocation);
            let why = refusal(&key);
            assert!(why.contains("the key is revoked"), "{why}");
        }
    }

    #[test]
    fn import_skips_an_expired_subkey() {
        // The subkey was made 20 days ago, for 5 days. A primary key that
        // may sign signs instead.
        let key = subkey_expiring(made(true, true), 5);
        let imported = Key::import(&armored(&key), None).unwrap();
        assert_eq!(signed_by(&imported), key.primary_key.fingerprint());
        // One that may not leaves no key to sign with.
        let key = subkey_expiring(made(false, true), 5);
        let why = refusal(&key);
        let subkey = format!("signing subkey {:X} expired on 2", subkey_fingerprint(&key));
        assert!(why.contains(&subkey), "{why}");
    }

    #[test]
    fn import_skips_a_revoked_subkey() {
        let mut key = made(true, true);
        let revocation = subkey_revocation(&key, &key);
        key.secret_subkeys[0].signatures.push(revocation);
        let imported = Key::import(&armored(&key), None).unwrap();
        assert_eq!(signed_by(&imported), key.primary_key.fingerprint());

        let mut key = made(false, true);
        let revocation = subkey_revocation(&key, &key);
        key.secret_subkeys[0].signatures.push(revocation);
        let why = refusal(&key);
        let subkey = format!("signing subkey {:X} is revoked", subkey_fingerprint(&key));
        assert!(why.contains(&subkey), "{why}");
    }

    #[test]
    fn a_key_that_expires_later_is_imported_and_its_expiry_shown() {
        let at = |made: u32, days: u32| {
            DateTime::from_timestamp(i64::from(days_ago(made).as_secs() + days * DAY), 0)
        };
        // Nothing expires.
        let key = made(true, true);
        let imported = Key::import(&armored(&key), None).unwrap();
        assert_eq!(signed_by(&imported), subkey_fingerprint(&key));
        let public = imported.info().unwrap().public_key;
        assert_eq!(expires_at(&public).unwrap(), None);
        assert_eq!(
            expires_at(
                &Key::generate("x <x@example.com>")
                    .unwrap()
                    .info()
                    .unwrap()
                    .public_key
            )
            .unwrap(),
            None
        );

        // The primary key (made 30 days ago) expires 60 days after.
        let key = primary_expiring(made(true, true), 60);
        let imported = Key::import(&armored(&key), None).unwrap();
        let public = imported.info().unwrap().public_key;
        assert_eq!(expires_at(&public).unwrap(), at(30, 60));

        // The only key that may sign, the subkey (made 20 days ago), expires
        // 40 days after, before the primary key.
        let key = subkey_expiring(primary_expiring(made(false, true), 365), 40);
        let imported = Key::import(&armored(&key), None).unwrap();
        assert_eq!(signed_by(&imported), subkey_fingerprint(&key));
        let public = imported.info().unwrap().public_key;
        assert_eq!(expires_at(&public).unwrap(), at(20, 40));

        // A subkey that expires leaves a primary key that may sign.
        let key = subkey_expiring(made(true, true), 40);
        let imported = Key::import(&armored(&key), None).unwrap();
        let public = imported.info().unwrap().public_key;
        assert_eq!(expires_at(&public).unwrap(), None);
    }

    #[test]
    fn a_key_stops_signing_when_it_expires_after_the_import() {
        let later = |days: u32| now() + u64::from(days * DAY);
        // The subkey (made 20 days ago) expires 40 days after: in 20 days.
        let key = subkey_expiring(made(false, true), 40);
        let imported = Key::import(&armored(&key), None).unwrap();
        let subkey = subkey_fingerprint(&key);
        assert_eq!(imported.signer_at(now()).unwrap().fingerprint(), subkey);
        assert_eq!(imported.signer_at(later(19)).unwrap().fingerprint(), subkey);
        let why = imported.signer_at(later(21)).err().unwrap().to_string();
        assert!(why.contains(&format!("{subkey:X} expired on 2")), "{why}");

        // A primary key that may sign takes over from the expired subkey.
        let key = subkey_expiring(made(true, true), 40);
        let imported = Key::import(&armored(&key), None).unwrap();
        let primary = key.primary_key.fingerprint();
        assert_eq!(
            imported.signer_at(later(19)).unwrap().fingerprint(),
            subkey_fingerprint(&key)
        );
        assert_eq!(
            imported.signer_at(later(21)).unwrap().fingerprint(),
            primary
        );

        // A primary key that expires (in 30 days) takes its subkey with it.
        let key = primary_expiring(made(true, true), 60);
        let imported = Key::import(&armored(&key), None).unwrap();
        assert!(imported.signer_at(later(29)).is_ok());
        let why = imported.signer_at(later(31)).err().unwrap().to_string();
        assert!(why.contains("the key expired on 2"), "{why}");

        // A key that is sealed already and has expired signs nothing, and
        // says why.
        let expired = Key {
            secret: primary_expiring(made(true, false), 10),
        };
        let why = expired.can_sign().unwrap_err().to_string();
        assert!(why.contains("the key expired on 2"), "{why}");
        assert!(sign_cleartext(std::slice::from_ref(&expired), "Origin: Forge\n").is_err());
        assert!(sign_detached(std::slice::from_ref(&expired), b"Origin: Forge\n").is_err());
    }

    #[test]
    fn the_newest_self_signature_holds() {
        // An expiry is extended by a newer self-signature: the one of 25
        // days ago let the key expire after 10 days, today's lets it live a
        // year, wherever each stands in the certificate.
        for newest_first in [false, true] {
            let mut key = made(true, true);
            let mut certifications = vec![
                certification(&key, &key, 25, Some(10)),
                certification(&key, &key, 0, Some(365)),
            ];
            let mut bindings = vec![binding(&key, 15, Some(5)), binding(&key, 0, Some(365))];
            if newest_first {
                certifications.reverse();
                bindings.reverse();
            }
            key.details.users[0].signatures = certifications;
            key.secret_subkeys[0].signatures = bindings;
            let imported = Key::import(&armored(&key), None).unwrap();
            assert_eq!(signed_by(&imported), subkey_fingerprint(&key));
        }
        // And shortened by one.
        let mut key = made(true, false);
        key.details.users[0].signatures = vec![
            certification(&key, &key, 0, Some(10)),
            certification(&key, &key, 25, Some(365)),
        ];
        assert!(refusal(&key).contains("the key expired on 2"));
    }

    #[test]
    fn a_signature_that_does_not_verify_says_nothing() {
        // Revocations and an expiry that another key signed: the import
        // refuses the certificate as a whole.
        let other = made(true, false);
        let mut forged = made(true, true);
        let mut signatures = vec![certification(&forged, &other, 0, Some(1))];
        signatures.append(&mut forged.details.users[0].signatures);
        forged.details.users[0].signatures = signatures;
        let why = refusal(&forged);
        assert!(why.contains("self-signatures do not verify"), "{why}");

        let mut forged = made(true, true);
        let revocation = key_revocation(&forged, &other);
        forged.details.revocation_signatures.push(revocation);
        let revocation = subkey_revocation(&forged, &other);
        forged.secret_subkeys[0].signatures.push(revocation);
        let why = refusal(&forged);
        assert!(why.contains("self-signatures do not verify"), "{why}");
        // And they neither revoke nor expire a key that is read without
        // that check: only what the primary key signed counts.
        let mut signatures = vec![certification(&forged, &other, 0, Some(1))];
        signatures.append(&mut forged.details.users[0].signatures);
        forged.details.users[0].signatures = signatures;
        let subkey = subkey_fingerprint(&forged);
        let key = Key { secret: forged };
        assert_eq!(signed_by(&key), subkey);
        assert_eq!(expires_at(&key.info().unwrap().public_key).unwrap(), None);
    }
}
