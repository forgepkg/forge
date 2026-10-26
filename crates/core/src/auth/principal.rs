//! The authenticated (or not) caller of a request.

use std::net::IpAddr;
use std::sync::Arc;

/// Identity established for an authenticated user.
///
/// This is the success payload of token/password verification and the body of
/// [`Principal::User`]. The `user_id` and `token_id` fields are a **contract**:
/// authorization (RBAC, token scopes) and the audit log rely on them being
/// present here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPrincipal {
    /// `app_user.id` of the authenticated user.
    pub user_id: i64,
    /// `token.id` if authentication used an API token; `None` for password auth.
    pub token_id: Option<i64>,
}

/// How a [`Principal::User`] proved its identity on this request.
///
/// Recorded so that endpoints can demand a particular kind of credential: the
/// admin API and token minting accept a browser session (or, for the admin
/// API, an explicitly admin-scoped token) but never a password replayed over
/// HTTP Basic — a password that NuGet clients store and send on every feed
/// request must not double as an administrator login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// An API token (`X-NuGet-ApiKey`, or the password field of HTTP Basic).
    Token,
    /// A password sent with the request over HTTP Basic, verified by the
    /// password chain (locally or by credential forwarding).
    Password,
    /// A browser session cookie, minted by an interactive login.
    Session,
    /// The headers the load balancer or reverse proxy in front of Forge adds
    /// to name the account (a `trusted_header` realm). Never an administrator
    /// login: the account's `admin` role does not apply to such a request.
    TrustedHeader,
}

impl AuthMethod {
    /// Whether the request carries this credential without its client
    /// presenting one: the session cookie a browser attaches, or the headers
    /// the proxy in front adds. A foreign page can make a browser send a
    /// request with either, so neither is a credential to publish with.
    pub fn is_ambient(self) -> bool {
        matches!(self, AuthMethod::Session | AuthMethod::TrustedHeader)
    }
}

/// Who is making a request, after credential resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// No credentials and anonymous access is not permitted.
    Unauthenticated,
    /// No credentials, but anonymous access is permitted for this client IP.
    Anonymous {
        /// The resolved client IP (post XFF processing).
        ip: IpAddr,
    },
    /// A verified user.
    User {
        /// `app_user.id`.
        user_id: i64,
        /// `token.id` if a token was used, else `None`.
        token_id: Option<i64>,
        /// The kind of credential that authenticated this request.
        method: AuthMethod,
    },
    /// A verified **workload** (WIF): a non-interactive CI/automation
    /// caller authenticated by a validated OIDC `id_token` (no `app_user` row,
    /// no session). It is authorized solely by the forge **role** its realm's
    /// claim-rules mapped it to — the role id is resolved at token-validation
    /// time and the authz seam loads that role's effective set directly.
    Workload {
        /// `auth_realm.id` of the `workload_identity` realm that vouched for it
        /// (audit/diagnostic context).
        realm_id: i64,
        /// `role.id` the matched claim-rule granted. The authz seam resolves
        /// this role's effective set (deny-all if the role was since deleted).
        role_id: i64,
        /// SHA-256 of the normalized trusted issuer. The publish audit hook
        /// compares this to the current realm row while holding a row lock, so
        /// a stale realm snapshot cannot be attributed to a reconfigured issuer.
        issuer_sha256: [u8; 32],
        /// SHA-256 of the complete normalized workload-realm configuration.
        /// Publish re-computes it from the locked database row so a peer's stale
        /// audience, claim-rule, lifetime, or cache-policy snapshot cannot
        /// authorize a package after an administrator changes the trust policy.
        config_sha256: [u8; 32],
        /// SHA-256 of `issuer || 0x00 || sub`. A fixed-size, pseudonymous audit
        /// identifier that correlates publishes from the same workload without
        /// putting provider claims into every authorization context.
        subject_sha256: [u8; 32],
        /// SHA-256 of the token's `jti`, when present. This supports immutable
        /// publish provenance without retaining the bearer token or raw `jti`.
        jti_sha256: Option<[u8; 32]>,
        /// Validated token `iat` (Unix seconds), recorded with publish audit
        /// events. WIF validation guarantees it is fresh and not in the future.
        issued_at: i64,
        /// `workload_api_key.id` when the workload presented a key the token
        /// exchange issued; `None` for the CI token itself.
        key_id: Option<i64>,
        /// When the presented credential ends (Unix seconds): the key's
        /// expiry, or the CI token's `exp`. Nothing derived from it (a
        /// registry token) may outlive it.
        expires_at: i64,
        /// Trusted publishers that matched the verified token. Each digest
        /// binds the grant to the definition that was current at authentication.
        /// A shared slice keeps the principal small and cheap to clone.
        matched_publishers: Arc<[TrustedPublisherMatch]>,
    },
}

/// Snapshot reference to a trusted-publisher definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedPublisherMatch {
    pub id: i64,
    pub definition_sha256: [u8; 32],
}

impl Principal {
    /// Who this is, for audit log lines: ids only, never secrets
    /// (`user:5 token:12`, `user:5 session`, `user:5 trusted-header`,
    /// `workload realm:3 role:7`).
    pub fn audit_label(&self) -> String {
        match self {
            Principal::Unauthenticated => "unauthenticated".into(),
            Principal::Anonymous { ip } => format!("anonymous {ip}"),
            Principal::User {
                user_id,
                token_id,
                method,
                ..
            } => match (token_id, method) {
                (Some(token_id), _) => format!("user:{user_id} token:{token_id}"),
                (None, AuthMethod::Session) => format!("user:{user_id} session"),
                (None, AuthMethod::TrustedHeader) => format!("user:{user_id} trusted-header"),
                (None, _) => format!("user:{user_id} password"),
            },
            Principal::Workload {
                realm_id, role_id, ..
            } => format!("workload realm:{realm_id} role:{role_id}"),
        }
    }

    /// Build a [`Principal::User`] from a [`UserPrincipal`] verified on this
    /// request: [`AuthMethod::Token`] when a token was used, else
    /// [`AuthMethod::Password`].
    pub fn from_user(u: UserPrincipal) -> Self {
        Principal::User {
            user_id: u.user_id,
            token_id: u.token_id,
            method: if u.token_id.is_some() {
                AuthMethod::Token
            } else {
                AuthMethod::Password
            },
        }
    }

    /// The [`AuthMethod`] of a user principal (`None` otherwise).
    pub fn auth_method(&self) -> Option<AuthMethod> {
        match self {
            Principal::User { method, .. } => Some(*method),
            _ => None,
        }
    }

    /// Whether this principal is an authenticated user.
    pub fn is_user(&self) -> bool {
        matches!(self, Principal::User { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_labels_name_the_credential_never_a_secret() {
        let user = |token_id, method| Principal::User {
            user_id: 5,
            token_id,
            method,
        };
        assert_eq!(
            user(Some(12), AuthMethod::Token).audit_label(),
            "user:5 token:12"
        );
        assert_eq!(
            user(None, AuthMethod::Session).audit_label(),
            "user:5 session"
        );
        assert_eq!(
            user(None, AuthMethod::Password).audit_label(),
            "user:5 password"
        );
        assert_eq!(
            user(None, AuthMethod::TrustedHeader).audit_label(),
            "user:5 trusted-header"
        );
        let workload = Principal::Workload {
            realm_id: 3,
            role_id: 7,
            issuer_sha256: [0; 32],
            config_sha256: [0; 32],
            subject_sha256: [0; 32],
            jti_sha256: None,
            issued_at: 0,
            key_id: None,
            expires_at: 0,
            matched_publishers: Arc::from([]),
        };
        assert_eq!(workload.audit_label(), "workload realm:3 role:7");
    }

    #[test]
    fn from_user_preserves_fields() {
        let up = UserPrincipal {
            user_id: 7,
            token_id: Some(3),
        };
        assert_eq!(
            Principal::from_user(up),
            Principal::User {
                user_id: 7,
                token_id: Some(3),
                method: AuthMethod::Token
            }
        );
    }

    #[test]
    fn is_user_only_for_user_variant() {
        assert!(Principal::User {
            user_id: 1,
            token_id: None,
            method: AuthMethod::Password
        }
        .is_user());
        assert!(!Principal::Unauthenticated.is_user());
        assert!(!Principal::Anonymous {
            ip: "127.0.0.1".parse().unwrap()
        }
        .is_user());
    }
}
