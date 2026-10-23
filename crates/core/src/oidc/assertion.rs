//! Forge as the issuer of its own client assertions: OIDC login without a
//! client secret.
//!
//! An `oidc` realm can authenticate forge at the IdP's token endpoint with a
//! short-lived JWT that forge signs itself (`client_assertion`, RFC 7523)
//! instead of a `client_secret`. The IdP trusts forge as an OIDC issuer: it
//! reads `{issuer}/.well-known/openid-configuration` and the JWKS it names,
//! both served by forge, and checks the assertion's signature, `iss`, `sub`
//! and `aud` against the credential registered for the client — in Microsoft
//! Entra a *federated identity credential* (workload identity federation).
//!
//! This module is the pure half: the [`IssuerKeySet`] (RSA keys, their
//! rotation, the JWKS, the stored form) and the signing of an assertion. The
//! server keeps the key set in the database, shared by every instance, and
//! serves the discovery document and the JWKS.
//!
//! ## Keys and rotation
//!
//! Entra accepts RS256 only, so every key is RSA-2048. A key set holds at
//! most [`MAX_KEYS`] keys, newest first, all of them published. A new key is
//! generated [`KEY_ROTATION`] after the newest one, published at once and used
//! for signing only [`KEY_ACTIVATION`] later: an IdP that cached the JWKS
//! before the new key appeared (Entra caches it up to a day) has refetched it
//! by then. The key it replaces stays published until the next rotation drops
//! it.

use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKeyComponents};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};

/// `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2).
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The audience Microsoft recommends for a federated identity credential
/// (the default of an `oidc` realm's `assertion_audience`).
pub const DEFAULT_ASSERTION_AUDIENCE: &str = "api://AzureADTokenExchange";

/// How long a signed assertion is valid: it is sent to the token endpoint
/// right away, so a few minutes cover clock skew and nothing more.
pub const ASSERTION_LIFETIME: Duration = Duration::minutes(5);

/// How often a new signing key is generated.
pub const KEY_ROTATION: Duration = Duration::days(30);

/// How long a new key is published before it signs.
pub const KEY_ACTIVATION: Duration = Duration::days(2);

/// Keys a key set keeps publishing: the one waiting to sign, the one
/// signing and the one before it.
pub const MAX_KEYS: usize = 3;

/// The only signing algorithm (Entra's federated credentials require it).
pub const SIGNING_ALG: &str = "RS256";

/// Errors of the key set and the signer.
#[derive(Debug, thiserror::Error)]
pub enum AssertionError {
    /// The stored key set does not parse (or holds no key).
    #[error("malformed issuer key set: {0}")]
    Malformed(String),
    /// Key generation or signing failed.
    #[error("issuer key error: {0}")]
    Crypto(String),
}

/// The `sub` of the assertions forge presents to `issuer` as `client_id`:
/// `{client_id}@{issuer}`, the issuer without a trailing `/`.
///
/// The subject names the IdP the assertion is for, so an assertion is only
/// worth something to the IdP and client it was signed for: a realm pointed at
/// another issuer gets assertions with another subject, which the federated
/// credential of the real client does not accept.
pub fn federated_subject(issuer: &str, client_id: &str) -> String {
    format!(
        "{}@{}",
        client_id.trim(),
        issuer.trim().trim_end_matches('/')
    )
}

/// What an assertion asserts: forge (`issuer`) authenticating as `subject`
/// to `audience`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionClaims {
    /// Forge's issuer URL (its public base URL).
    pub issuer: String,
    /// See [`federated_subject`].
    pub subject: String,
    /// The audience the IdP's credential expects.
    pub audience: String,
}

/// One RSA signing key.
pub struct IssuerKey {
    /// RFC 7638 JWK thumbprint (base64url SHA-256), the JWKS `kid`.
    kid: String,
    /// When the key was generated; it signs from `created + KEY_ACTIVATION`.
    created: DateTime<Utc>,
    /// The private key, PKCS#8 DER (the stored form).
    pkcs8: Vec<u8>,
    pair: KeyPair,
    /// Public modulus and exponent, big-endian without leading zeros.
    n: Vec<u8>,
    e: Vec<u8>,
}

impl std::fmt::Debug for IssuerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerKey")
            .field("kid", &self.kid)
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

impl IssuerKey {
    fn generate(created: DateTime<Utc>) -> Result<Self, AssertionError> {
        let pair = KeyPair::generate(KeySize::Rsa2048)
            .map_err(|_| AssertionError::Crypto("RSA key generation failed".into()))?;
        let der: Pkcs8V1Der<'static> = pair
            .as_der()
            .map_err(|_| AssertionError::Crypto("RSA key encoding failed".into()))?;
        let pkcs8 = der.as_ref().to_vec();
        Self::from_parts(pair, pkcs8, created)
    }

    fn from_pkcs8(pkcs8: Vec<u8>, created: DateTime<Utc>) -> Result<Self, AssertionError> {
        let pair = KeyPair::from_pkcs8(&pkcs8)
            .map_err(|e| AssertionError::Malformed(format!("RSA key: {e}")))?;
        Self::from_parts(pair, pkcs8, created)
    }

    fn from_parts(
        pair: KeyPair,
        pkcs8: Vec<u8>,
        created: DateTime<Utc>,
    ) -> Result<Self, AssertionError> {
        let public = PublicKeyComponents::<Vec<u8>>::from(pair.public_key());
        let kid = jwk_thumbprint(&public.n, &public.e);
        Ok(IssuerKey {
            kid,
            created,
            pkcs8,
            pair,
            n: public.n,
            e: public.e,
        })
    }

    /// The JWKS `kid`.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// When the key was generated.
    pub fn created(&self) -> DateTime<Utc> {
        self.created
    }

    /// The key as a JWK (public part only).
    fn jwk(&self) -> JsonValue {
        json!({
            "kty": "RSA",
            // Entra expects `use` on the keys of an external issuer.
            "use": "sig",
            "alg": SIGNING_ALG,
            "kid": self.kid,
            "n": b64url(&self.n),
            "e": b64url(&self.e),
        })
    }
}

/// The RFC 7638 thumbprint of an RSA public key: base64url SHA-256 of its
/// required JWK members in lexicographic order.
fn jwk_thumbprint(n: &[u8], e: &[u8]) -> String {
    let canonical = format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, b64url(e), b64url(n));
    b64url(&Sha256::digest(canonical.as_bytes()))
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The stored form of a key set (a secret: it holds the private keys).
#[derive(Serialize, Deserialize)]
struct StoredKeySet {
    keys: Vec<StoredKey>,
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    /// Unix seconds.
    created: i64,
    /// Standard base64 of the PKCS#8 DER private key.
    pkcs8: String,
}

/// Forge's issuer keys, newest first (module docs).
#[derive(Debug)]
pub struct IssuerKeySet {
    keys: Vec<Arc<IssuerKey>>,
}

impl IssuerKeySet {
    /// A key set of one fresh key, which signs right away: nothing can have
    /// cached a JWKS without it.
    pub fn generate(now: DateTime<Utc>) -> Result<Self, AssertionError> {
        Ok(IssuerKeySet {
            keys: vec![Arc::new(IssuerKey::generate(now)?)],
        })
    }

    /// Parse the stored form ([`IssuerKeySet::to_stored`]).
    pub fn from_stored(stored: &str) -> Result<Self, AssertionError> {
        let parsed: StoredKeySet =
            serde_json::from_str(stored).map_err(|e| AssertionError::Malformed(e.to_string()))?;
        let mut keys = parsed
            .keys
            .into_iter()
            .map(|key| {
                let created = DateTime::from_timestamp(key.created, 0)
                    .ok_or_else(|| AssertionError::Malformed("key creation time".into()))?;
                let pkcs8 = base64::engine::general_purpose::STANDARD
                    .decode(&key.pkcs8)
                    .map_err(|e| AssertionError::Malformed(format!("key encoding: {e}")))?;
                IssuerKey::from_pkcs8(pkcs8, created).map(Arc::new)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Err(AssertionError::Malformed("no keys".into()));
        }
        keys.sort_by_key(|key| std::cmp::Reverse(key.created));
        Ok(IssuerKeySet { keys })
    }

    /// The stored form: JSON with the private keys (PKCS#8, base64).
    pub fn to_stored(&self) -> String {
        let stored = StoredKeySet {
            keys: self
                .keys
                .iter()
                .map(|key| StoredKey {
                    created: key.created.timestamp(),
                    pkcs8: base64::engine::general_purpose::STANDARD.encode(&key.pkcs8),
                })
                .collect(),
        };
        serde_json::to_string(&stored).expect("serializable")
    }

    /// The published keys, newest first.
    pub fn keys(&self) -> &[Arc<IssuerKey>] {
        &self.keys
    }

    /// The key that signs at `now`: the newest one published for at least
    /// [`KEY_ACTIVATION`], else (every key is newer) the oldest one.
    pub fn signing_key(&self, now: DateTime<Utc>) -> &IssuerKey {
        self.keys
            .iter()
            .find(|key| key.created + KEY_ACTIVATION <= now)
            .unwrap_or_else(|| self.keys.last().expect("a key set is never empty"))
    }

    /// The key set after the rotation due at `now`, if one is: a fresh key
    /// in front once the newest key is [`KEY_ROTATION`] old, the oldest keys
    /// dropped beyond [`MAX_KEYS`].
    pub fn rotated(&self, now: DateTime<Utc>) -> Option<Result<Self, AssertionError>> {
        if self.keys[0].created + KEY_ROTATION > now {
            return None;
        }
        Some(IssuerKey::generate(now).map(|fresh| {
            IssuerKeySet {
                keys: std::iter::once(Arc::new(fresh))
                    .chain(self.keys.iter().take(MAX_KEYS - 1).cloned())
                    .collect(),
            }
        }))
    }

    /// The JWKS document: every key, public parts only.
    pub fn jwks(&self) -> JsonValue {
        json!({ "keys": self.keys.iter().map(|key| key.jwk()).collect::<Vec<_>>() })
    }

    /// Sign a client assertion at `now` with the [signing
    /// key](Self::signing_key): RS256, `kid` in the header, valid for
    /// [`ASSERTION_LIFETIME`] and carrying a fresh `jti`.
    pub fn sign(
        &self,
        claims: &AssertionClaims,
        now: DateTime<Utc>,
    ) -> Result<String, AssertionError> {
        let key = self.signing_key(now);
        let header = json!({ "alg": SIGNING_ALG, "typ": "JWT", "kid": key.kid });
        let iat = now.timestamp();
        let payload = json!({
            "iss": claims.issuer,
            "sub": claims.subject,
            "aud": claims.audience,
            "iat": iat,
            "nbf": iat,
            "exp": (now + ASSERTION_LIFETIME).timestamp(),
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        let signing_input = format!(
            "{}.{}",
            b64url(header.to_string().as_bytes()),
            b64url(payload.to_string().as_bytes())
        );
        let mut signature = vec![0u8; key.pair.public_modulus_len()];
        key.pair
            .sign(
                &RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| AssertionError::Crypto("RSA signing failed".into()))?;
        Ok(format!("{signing_input}.{}", b64url(&signature)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    fn claims() -> AssertionClaims {
        AssertionClaims {
            issuer: "https://forge.example.com".into(),
            subject: federated_subject(
                "https://login.microsoftonline.com/tenant/v2.0/",
                " client ",
            ),
            audience: DEFAULT_ASSERTION_AUDIENCE.into(),
        }
    }

    fn at(day: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap() + Duration::days(day)
    }

    /// Verify `jwt` against the published JWKS, as an IdP does.
    fn verify(set: &IssuerKeySet, jwt: &str) -> serde_json::Map<String, JsonValue> {
        let kid = decode_header(jwt).unwrap().kid.expect("kid");
        let jwks = set.jwks();
        let jwk = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["kid"] == kid.as_str())
            .expect("the signing key is published");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "RS256");
        let key = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[DEFAULT_ASSERTION_AUDIENCE]);
        validation.set_issuer(&["https://forge.example.com"]);
        // The tests sign at fixed past instants.
        validation.validate_exp = false;
        decode::<serde_json::Map<String, JsonValue>>(jwt, &key, &validation)
            .expect("valid signature")
            .claims
    }

    #[test]
    fn the_subject_binds_the_client_to_its_issuer() {
        assert_eq!(
            federated_subject(" https://login.microsoftonline.com/t/v2.0/ ", " abc "),
            "abc@https://login.microsoftonline.com/t/v2.0"
        );
        assert_ne!(
            federated_subject("https://evil.example", "abc"),
            federated_subject("https://login.microsoftonline.com/t/v2.0", "abc")
        );
    }

    #[test]
    fn an_assertion_verifies_against_the_jwks_and_carries_the_claims() {
        let now = Utc::now();
        let set = IssuerKeySet::generate(now).unwrap();
        let jwt = set.sign(&claims(), now).unwrap();
        let payload = verify(&set, &jwt);
        assert_eq!(
            payload["sub"],
            "client@https://login.microsoftonline.com/tenant/v2.0"
        );
        assert_eq!(payload["iat"], payload["nbf"]);
        assert_eq!(
            payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
            ASSERTION_LIFETIME.num_seconds()
        );
        assert_ne!(
            payload["jti"],
            verify(&set, &set.sign(&claims(), now).unwrap())["jti"],
            "every assertion has its own jti"
        );
        let header = decode_header(&jwt).unwrap();
        assert_eq!(header.typ.as_deref(), Some("JWT"));
    }

    #[test]
    fn the_stored_form_round_trips_without_changing_kids() {
        let set = IssuerKeySet::generate(at(0)).unwrap();
        let set = set.rotated(at(30)).unwrap().unwrap();
        let stored = set.to_stored();
        let back = IssuerKeySet::from_stored(&stored).unwrap();
        let kids = |s: &IssuerKeySet| {
            s.keys()
                .iter()
                .map(|k| k.kid().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(kids(&set), kids(&back));
        assert_eq!(back.keys()[0].created(), at(30));
        assert_eq!(back.to_stored(), stored);
        // Signed with a reloaded key, verified with the original JWKS.
        verify(&set, &back.sign(&claims(), at(31)).unwrap());

        for bad in [
            "",
            "{}",
            r#"{"keys":[]}"#,
            r#"{"keys":[{"created":0,"pkcs8":"AAAA"}]}"#,
        ] {
            assert!(IssuerKeySet::from_stored(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_new_key_is_published_before_it_signs_and_old_keys_age_out() {
        let first = IssuerKeySet::generate(at(0)).unwrap();
        let first_kid = first.keys()[0].kid().to_string();
        // Fresh install: the only key signs at once.
        assert_eq!(first.signing_key(at(0)).kid(), first_kid);
        assert!(first.rotated(at(29)).is_none(), "not due yet");

        let second = first.rotated(at(30)).unwrap().unwrap();
        assert_eq!(second.keys().len(), 2);
        let second_kid = second.keys()[0].kid().to_string();
        assert_ne!(second_kid, first_kid);
        // Published, but the previous key signs until the new one is
        // KEY_ACTIVATION old.
        assert_eq!(second.signing_key(at(31)).kid(), first_kid);
        assert_eq!(second.signing_key(at(32)).kid(), second_kid);
        assert!(second.rotated(at(59)).is_none());

        let third = second.rotated(at(60)).unwrap().unwrap();
        let fourth = third.rotated(at(90)).unwrap().unwrap();
        assert_eq!(fourth.keys().len(), MAX_KEYS);
        let kids: Vec<_> = fourth.keys().iter().map(|k| k.kid().to_string()).collect();
        assert!(!kids.contains(&first_kid), "the oldest key is dropped");
        assert_eq!(kids[2], second_kid);
        assert_eq!(fourth.jwks()["keys"].as_array().unwrap().len(), MAX_KEYS);
    }

    #[test]
    fn kids_are_rfc7638_thumbprints() {
        // RFC 7638 §3.1 example key.
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            )
            .unwrap();
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("AQAB")
            .unwrap();
        assert_eq!(
            jwk_thumbprint(&n, &e),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
