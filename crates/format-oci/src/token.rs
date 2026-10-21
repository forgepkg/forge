//! Registry Bearer tokens (the Docker token-service protocol).
//!
//! `docker login`/`docker pull` present credentials once, to the token
//! endpoint (`/v2/token`), and get a short-lived HS256 JWT naming the
//! principal and the `repository:<name>:<actions>` it was granted. Registry
//! requests then carry `Authorization: Bearer <jwt>`. The JWT only narrows
//! access: every request is still authorized against the live RBAC state,
//! and the user (and API token) behind it must still be active.
//!
//! Tokens are honored only by the `/v2` handler, never by the rest of the
//! API, so a registry token cannot be replayed against `/admin`.

use std::sync::Arc;

use forge_core::auth::{AuthMethod, Principal};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// The `typ`-like marker in the issuer, keeping registry tokens apart from
/// any workload-identity issuer (those are `https://` URLs).
const ISSUER_PREFIX: &str = "forge-registry:";

/// Signing keys: the current one signs, every one verifies (a key replaced
/// by another instance is still accepted while its tokens live).
#[derive(Clone)]
pub struct TokenKeys {
    keys: Arc<Vec<Vec<u8>>>,
}

impl std::fmt::Debug for TokenKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenKeys")
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl TokenKeys {
    /// Keys from raw key material; the first signs.
    pub fn new(keys: Vec<Vec<u8>>) -> Self {
        assert!(!keys.is_empty(), "at least one registry token key");
        TokenKeys {
            keys: Arc::new(keys),
        }
    }

    fn signing(&self) -> &[u8] {
        &self.keys[0]
    }
}

/// One `access` entry: what a token grants on one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub actions: Vec<String>,
}

/// The principal a token stands for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum TokenPrincipal {
    /// No credentials were presented: the request's own (anonymous or
    /// unauthenticated) principal applies.
    Anonymous,
    User {
        uid: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tid: Option<i64>,
        /// `true` when minted from a password (the API-token flag is `tid`).
        #[serde(default)]
        pw: bool,
    },
    Workload {
        realm: i64,
        role: i64,
        iss: String,
        cfg: String,
        sub: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jti: Option<String>,
        iat: i64,
    },
}

impl TokenPrincipal {
    /// The token principal of a resolved request principal. A browser
    /// session is not a registry credential and maps to anonymous.
    pub fn of(principal: &Principal) -> Self {
        match *principal {
            Principal::User {
                user_id,
                token_id,
                method,
                ..
            } if method != AuthMethod::Session => TokenPrincipal::User {
                uid: user_id,
                tid: token_id,
                pw: method == AuthMethod::Password,
            },
            Principal::Workload {
                realm_id,
                role_id,
                issuer_sha256,
                config_sha256,
                subject_sha256,
                jti_sha256,
                issued_at,
            } => TokenPrincipal::Workload {
                realm: realm_id,
                role: role_id,
                iss: hex::encode(issuer_sha256),
                cfg: hex::encode(config_sha256),
                sub: hex::encode(subject_sha256),
                jti: jti_sha256.map(hex::encode),
                iat: issued_at,
            },
            _ => TokenPrincipal::Anonymous,
        }
    }

    /// Back to a request principal. `is_admin` is re-read by the caller
    /// (see [`crate::service`]); `fallback` is the request's own principal,
    /// used for anonymous tokens.
    pub fn to_principal(&self, fallback: Principal) -> Option<Principal> {
        fn arr(hex_str: &str) -> Option<[u8; 32]> {
            hex::decode(hex_str).ok()?.try_into().ok()
        }
        Some(match self {
            TokenPrincipal::Anonymous => fallback,
            TokenPrincipal::User { uid, tid, pw } => Principal::User {
                user_id: *uid,
                token_id: *tid,
                is_admin: false,
                method: if tid.is_some() {
                    AuthMethod::Token
                } else if *pw {
                    AuthMethod::Password
                } else {
                    return None;
                },
            },
            TokenPrincipal::Workload {
                realm,
                role,
                iss,
                cfg,
                sub,
                jti,
                iat,
            } => Principal::Workload {
                realm_id: *realm,
                role_id: *role,
                issuer_sha256: arr(iss)?,
                config_sha256: arr(cfg)?,
                subject_sha256: arr(sub)?,
                jti_sha256: match jti {
                    Some(j) => Some(arr(j)?),
                    None => None,
                },
                issued_at: *iat,
            },
        })
    }
}

/// The claims of a registry token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(default)]
    pub access: Vec<Access>,
    /// Forge's principal.
    pub fp: TokenPrincipal,
}

impl Claims {
    /// Whether the token grants `action` (`pull`, `push`, `delete`) on the
    /// repository `name`.
    pub fn grants(&self, name: &str, action: &str) -> bool {
        self.access.iter().any(|a| {
            a.kind == "repository"
                && a.name == name
                && a.actions.iter().any(|x| x == action || x == "*")
        })
    }
}

/// The issuer of tokens minted for `public_base_url`.
pub fn issuer(public_base_url: &str) -> String {
    format!("{ISSUER_PREFIX}{public_base_url}")
}

/// Sign a token.
pub fn issue(keys: &TokenKeys, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(keys.signing()),
    )
}

/// Verify a token's signature, issuer, audience and lifetime.
pub fn verify(keys: &TokenKeys, token: &str, issuer: &str, audience: &str) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "nbf"]);
    validation.validate_nbf = true;
    validation.leeway = 30;
    keys.keys.iter().find_map(|key| {
        jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(key), &validation)
            .ok()
            .map(|data| data.claims)
    })
}

/// Whether a bearer value looks like one of our tokens (three JWT segments
/// whose payload names a registry issuer), so other bearer values are left
/// to the rest of the authentication chain.
pub fn looks_like_registry_token(token: &str) -> bool {
    use base64::Engine;
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|v| v.get("iss").and_then(|i| i.as_str()).map(str::to_string))
        .is_some_and(|iss| iss.starts_with(ISSUER_PREFIX))
}

/// A requested scope `repository:<name>:<actions>` (the only resource type
/// Forge grants; `registry:catalog:*` and others get nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub name: String,
    pub actions: Vec<String>,
}

/// Parse a `scope` query value. Docker sends one per resource; several
/// space-separated scopes in one value are accepted too.
pub fn parse_scopes(value: &str) -> Vec<Scope> {
    value
        .split(' ')
        .filter_map(|scope| {
            let (kind, rest) = scope.split_once(':')?;
            let (name, actions) = rest.rsplit_once(':')?;
            // `repository(plugin)` is the legacy class syntax.
            let kind = kind.split('(').next().unwrap_or(kind);
            if kind != "repository" || name.is_empty() {
                return None;
            }
            Some(Scope {
                name: name.to_string(),
                actions: actions
                    .split(',')
                    .filter(|a| !a.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(access: Vec<Access>) -> Claims {
        let now = chrono::Utc::now().timestamp();
        Claims {
            iss: issuer("https://forge.example.com"),
            aud: "forge.example.com".into(),
            sub: "user:1".into(),
            iat: now,
            nbf: now,
            exp: now + 300,
            jti: "j".into(),
            access,
            fp: TokenPrincipal::User {
                uid: 1,
                tid: Some(2),
                pw: false,
            },
        }
    }

    #[test]
    fn round_trip_and_scope() {
        let keys = TokenKeys::new(vec![b"0123456789abcdef0123456789abcdef".to_vec()]);
        let c = claims(vec![Access {
            kind: "repository".into(),
            name: "docker/app".into(),
            actions: vec!["pull".into()],
        }]);
        let jwt = issue(&keys, &c).unwrap();
        assert!(looks_like_registry_token(&jwt));
        let back = verify(&keys, &jwt, &c.iss, &c.aud).unwrap();
        assert!(back.grants("docker/app", "pull"));
        assert!(!back.grants("docker/app", "push"));
        assert!(!back.grants("docker/other", "pull"));
        assert_eq!(back.fp, c.fp);

        // Wrong key, issuer or audience.
        let other = TokenKeys::new(vec![b"another-key-another-key-another!!".to_vec()]);
        assert!(verify(&other, &jwt, &c.iss, &c.aud).is_none());
        assert!(verify(&keys, &jwt, "forge-registry:https://x", &c.aud).is_none());
        assert!(verify(&keys, &jwt, &c.iss, "x").is_none());
        // A rotated key set still verifies the old token.
        let rotated = TokenKeys::new(vec![
            b"another-key-another-key-another!!".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        ]);
        assert!(verify(&rotated, &jwt, &c.iss, &c.aud).is_some());
    }

    #[test]
    fn expired_tokens_fail() {
        let keys = TokenKeys::new(vec![b"0123456789abcdef0123456789abcdef".to_vec()]);
        let mut c = claims(Vec::new());
        c.exp = chrono::Utc::now().timestamp() - 120;
        let jwt = issue(&keys, &c).unwrap();
        assert!(verify(&keys, &jwt, &c.iss, &c.aud).is_none());
    }

    #[test]
    fn scopes() {
        assert_eq!(
            parse_scopes("repository:docker/team/app:pull,push"),
            vec![Scope {
                name: "docker/team/app".into(),
                actions: vec!["pull".into(), "push".into()]
            }]
        );
        assert_eq!(
            parse_scopes("repository(plugin):a:pull registry:catalog:*").len(),
            1
        );
        assert!(parse_scopes("registry:catalog:*").is_empty());
        assert!(parse_scopes("nonsense").is_empty());
    }

    #[test]
    fn principals_round_trip() {
        let p = Principal::Workload {
            realm_id: 1,
            role_id: 2,
            issuer_sha256: [1; 32],
            config_sha256: [2; 32],
            subject_sha256: [3; 32],
            jti_sha256: Some([4; 32]),
            issued_at: 5,
        };
        let tp = TokenPrincipal::of(&p);
        assert_eq!(tp.to_principal(Principal::Unauthenticated), Some(p));

        let session = Principal::User {
            user_id: 1,
            token_id: None,
            is_admin: true,
            method: AuthMethod::Session,
        };
        assert_eq!(TokenPrincipal::of(&session), TokenPrincipal::Anonymous);
    }
}
