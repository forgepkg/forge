//! The pluggable, ordered authentication-provider abstraction (slice 12.3).
//!
//! Slice 1 baked exactly one password check (local argon2id) into the
//! principal middleware. This module introduces a **pluggable, ordered
//! [`AuthProvider`] chain** so that a username/password pair can be validated
//! by the local store, by forwarding to a configured upstream over HTTP Basic
//! (`upstream-basic`), or — conceptually — by any future backend, without the
//! middleware knowing *how*.
//!
//! Token auth (`X-NuGet-ApiKey` / Basic-as-token) is handled *before* the chain
//! (see [`super::token`]) and is **not** a provider: the chain is only the
//! password-style path.
//!
//! ## Security invariants encoded here
//! * **First [`AuthOutcome::Authenticated`] wins.** Providers run in configured
//!   order; the first acceptance short-circuits the rest.
//! * **Fail closed.** An [`AuthOutcome::Unavailable`] (upstream down / infra
//!   error) is *never* silently treated as "skip and grant later" — it is
//!   remembered, and if no provider authenticates the chain reports it so the
//!   caller denies access. An unreachable upstream must not open a hole.
//! * [`AuthOutcome::Rejected`] (a definitive "no", e.g. upstream 401) does not
//!   stop the chain — a user may be local *or* upstream — but on its own never
//!   grants access.
//! * [`AuthOutcome::Skip`] ("not my user") simply advances to the next provider.

use std::net::IpAddr;

/// How a principal was authenticated / provisioned.
///
/// The string forms match the `app_user.auth_source` column values
/// (`'local'` | `'upstream-basic'` | `'oidc'`, see migration `0004`). Keeping
/// the mapping here means the provider chain and the DB never disagree on the
/// spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthSource {
    /// Slice-1 local argon2id password (the `local-password` provider).
    Local,
    /// Credential forwarded to a configured upstream over HTTP Basic.
    UpstreamBasic,
    /// OpenID Connect (§12.2). Not driven through this chain — OIDC is its own
    /// interactive login path — but listed for `app_user.auth_source` symmetry.
    Oidc,
}

impl AuthSource {
    /// The canonical `app_user.auth_source` string for this source.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthSource::Local => "local",
            AuthSource::UpstreamBasic => "upstream-basic",
            AuthSource::Oidc => "oidc",
        }
    }
}

/// A username/password pair an end user presents for password-style auth.
///
/// Token auth is resolved before the chain and is not represented here. The
/// `password` is plaintext only for the lifetime of the request; it is never
/// stored or logged (see the slice 12.3 cache design, which stores only an
/// HMAC of it).
#[derive(Debug, Clone, Copy)]
pub struct PasswordCredential<'a> {
    /// The presented username.
    pub username: &'a str,
    /// The presented plaintext password. Never persisted; never logged.
    pub password: &'a str,
    /// The resolved client IP, carried for audit / SSRF context. **Never** a
    /// trust signal on its own.
    pub client_ip: IpAddr,
}

/// The identity a provider vouches for after a successful authentication.
///
/// `core` maps this to an `app_user` (lookup by `username`, auto-provision when
/// the provider allows). The `groups` are the *raw, coarse* upstream
/// groups/roles — stashed for §12.4, used here at most as an allow/deny gate;
/// they are not authoritative forge authz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenIdentity {
    /// The authenticated username (the forge `app_user.username`).
    pub username: String,
    /// Which provider/source vouched for this identity.
    pub source: AuthSource,
    /// Opaque upstream identifier when the source is not local. For
    /// `upstream-basic` this is usually just the username.
    pub external_subject: Option<String>,
    /// Raw upstream groups/roles (coarse). Empty for local.
    pub groups: Vec<String>,
    /// Whether an admin-group mapping suggests this identity is an admin. Only
    /// ever used to *grant* admin on provision, never to revoke (see §12.3).
    pub suggested_is_admin: bool,
}

impl ProvenIdentity {
    /// A minimal local identity (no external subject, no groups, not admin).
    pub fn local(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            source: AuthSource::Local,
            external_subject: None,
            groups: Vec::new(),
            suggested_is_admin: false,
        }
    }
}

/// The outcome of one provider's attempt to authenticate a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The provider authenticated the user and vouches for [`ProvenIdentity`].
    /// First `Authenticated` in the chain wins.
    Authenticated(ProvenIdentity),
    /// The provider definitively rejected the credential (e.g. upstream 401,
    /// wrong local password). Does **not** stop the chain, but never grants.
    Rejected,
    /// The provider can't decide — typically "this username isn't mine".
    /// The chain advances to the next provider.
    Skip,
    /// The provider hit an infrastructure error (upstream unreachable, timeout,
    /// 5xx). **Fail closed:** this is remembered and never silently downgraded
    /// to a grant. If no provider authenticates, the chain surfaces that an
    /// `Unavailable` occurred so the caller can log/deny appropriately.
    Unavailable,
}

/// An ordered authentication backend for username/password credentials.
///
/// Implementations MUST be safe to call on the hot path: a provider doing
/// network I/O (e.g. `upstream-basic`) consults the validated-credential cache
/// itself so that NuGet's per-request Basic auth does not hammer the upstream.
#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    /// Stable provider id, e.g. `"local-password"` / `"upstream-basic"`.
    fn id(&self) -> &'static str;

    /// The [`AuthSource`] identities from this provider carry.
    fn source(&self) -> AuthSource;

    /// Validate a username/password pair.
    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_source_strings_match_db_values() {
        assert_eq!(AuthSource::Local.as_str(), "local");
        assert_eq!(AuthSource::UpstreamBasic.as_str(), "upstream-basic");
        assert_eq!(AuthSource::Oidc.as_str(), "oidc");
    }

    #[test]
    fn proven_identity_local_is_minimal() {
        let id = ProvenIdentity::local("alice");
        assert_eq!(id.username, "alice");
        assert_eq!(id.source, AuthSource::Local);
        assert!(id.external_subject.is_none());
        assert!(id.groups.is_empty());
        assert!(!id.suggested_is_admin);
    }
}
