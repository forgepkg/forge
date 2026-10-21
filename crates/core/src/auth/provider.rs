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
//!   grants access. The exception is a **local** rejection (a local account with
//!   a password owns the username): it is terminal, so the password is never
//!   forwarded upstream.
//! * [`AuthOutcome::Skip`] ("not my user") simply advances to the next provider.

use std::fmt;
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
///
/// `Debug` is implemented **manually** so the plaintext `password` field is
/// always redacted: any future caller that logs a `PasswordCredential` with
/// `{:?}` — or includes it in a `tracing` span — must never emit the cleartext
/// password. Deriving `Debug` here would be a latent credential-leak.
#[derive(Clone, Copy)]
pub struct PasswordCredential<'a> {
    /// The presented username.
    pub username: &'a str,
    /// The presented plaintext password. Never persisted; never logged.
    pub password: &'a str,
    /// The resolved client IP, carried for audit / SSRF context. **Never** a
    /// trust signal on its own.
    pub client_ip: IpAddr,
}

impl fmt::Debug for PasswordCredential<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordCredential")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("client_ip", &self.client_ip)
            .finish()
    }
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
    /// Whether an admin-group mapping suggests this identity is an admin.
    pub suggested_is_admin: bool,
    /// Whether [`Self::suggested_is_admin`] is an **authoritative** reading of
    /// the upstream's admin state: the realm configures an admin mapping AND the
    /// groups were freshly fetched for this login (not a cache hit, which
    /// carries no groups). Only then may provisioning *revoke* admin; otherwise
    /// the suggestion is ignored for existing users (see
    /// [`super::chain::provision_and_map`]). Always `false` for local.
    pub admin_authoritative: bool,
    /// Whether the vouching provider is configured to auto-provision an
    /// `app_user` for this identity on first success (12.7: per-realm — each
    /// credential-forwarding realm carries its own flag, so the chain caller no
    /// longer needs a chain-global setting). Always `false` for local.
    pub auto_provision: bool,
    /// The `auth_realm.id` of the vouching realm, when the provider was built
    /// from a realm row (12.7). Recorded as `app_user.realm_id` provenance on
    /// provision; `None` for the built-in/static wiring.
    pub realm_id: Option<i64>,
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
            admin_authoritative: false,
            auto_provision: false,
            realm_id: None,
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
    /// wrong local password). Never grants; terminal when the provider's source
    /// is [`AuthSource::Local`], otherwise the chain continues.
    Rejected,
    /// The provider can't decide — typically "this username isn't mine".
    /// The chain advances to the next provider.
    Skip,
    /// The provider hit an infrastructure error (upstream unreachable, timeout,
    /// 5xx). **Fail closed:** this is remembered and never silently downgraded
    /// to a grant. If no provider authenticates, the chain surfaces that an
    /// `Unavailable` occurred so the caller can log/deny appropriately.
    Unavailable,
    /// Forge's own store failed (a database error): nobody can decide this
    /// credential right now, so the chain stops. Unlike an upstream outage,
    /// which callers answer like a wrong password, this is answered as
    /// "temporarily unavailable" (503) so clients retry instead of asking
    /// for new credentials.
    Failed,
}

/// An ordered authentication backend for username/password credentials.
///
/// Implementations MUST be safe to call on the hot path: a provider doing
/// network I/O (e.g. `upstream-basic`) consults the validated-credential cache
/// itself so that NuGet's per-request Basic auth does not hammer the upstream.
#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    /// Stable provider id, e.g. `"local-password"` / `"upstream-basic"`, or a
    /// realm-scoped id like `"realm:corp-nexus"` (12.7). Keys the
    /// validated-credential cache, so it must be stable for a given realm.
    fn id(&self) -> &str;

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
        assert!(!id.admin_authoritative);
        assert!(!id.auto_provision);
        assert!(id.realm_id.is_none());
    }

    #[test]
    fn password_credential_debug_redacts_plaintext() {
        let cred = PasswordCredential {
            username: "alice",
            password: "hunter2-super-secret",
            client_ip: "203.0.113.7".parse().unwrap(),
        };
        let rendered = format!("{cred:?}");
        assert!(
            !rendered.contains("hunter2-super-secret"),
            "Debug must never expose the plaintext password: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "expected redaction marker: {rendered}"
        );
        // The non-secret fields stay visible for diagnostics.
        assert!(rendered.contains("alice"));
        assert!(rendered.contains("203.0.113.7"));
    }
}
