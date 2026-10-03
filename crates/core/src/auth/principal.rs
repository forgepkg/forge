//! The authenticated (or not) caller of a request.

use std::net::IpAddr;

/// Identity established for an authenticated user.
///
/// This is the success payload of token/password verification and the body of
/// [`Principal::User`]. The `user_id` and `token_id` fields are a **cross-slice
/// contract**: later slices (auditing, RBAC) rely on them being present here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPrincipal {
    /// `app_user.id` of the authenticated user.
    pub user_id: i64,
    /// `token.id` if authentication used an API token; `None` for password auth.
    pub token_id: Option<i64>,
    /// Whether the user has the admin flag.
    pub is_admin: bool,
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
}

/// Who is making a request, after credential resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        /// Admin flag.
        is_admin: bool,
        /// The kind of credential that authenticated this request.
        method: AuthMethod,
    },
    /// A verified **workload** (slice 12.8, WIF): a non-interactive CI/automation
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
    },
}

impl Principal {
    /// Build a [`Principal::User`] from a [`UserPrincipal`] verified on this
    /// request: [`AuthMethod::Token`] when a token was used, else
    /// [`AuthMethod::Password`].
    pub fn from_user(u: UserPrincipal) -> Self {
        Principal::User {
            user_id: u.user_id,
            token_id: u.token_id,
            is_admin: u.is_admin,
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
    fn from_user_preserves_fields() {
        let up = UserPrincipal {
            user_id: 7,
            token_id: Some(3),
            is_admin: true,
        };
        assert_eq!(
            Principal::from_user(up),
            Principal::User {
                user_id: 7,
                token_id: Some(3),
                is_admin: true,
                method: AuthMethod::Token
            }
        );
    }

    #[test]
    fn is_user_only_for_user_variant() {
        assert!(Principal::User {
            user_id: 1,
            token_id: None,
            is_admin: false,
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
