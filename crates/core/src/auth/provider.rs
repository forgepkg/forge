//! The pluggable, ordered authentication-provider abstraction.
//!
//! The password-style auth path is a **pluggable, ordered [`AuthProvider`]
//! chain**, so that a username/password pair can be validated by the local
//! store, by forwarding to a configured upstream over HTTP Basic
//! (`upstream-basic`), or — conceptually — by any future backend, without the
//! principal middleware knowing *how*.
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
/// (`'local'` | `'upstream-basic'` | `'oidc'`, see its CHECK constraint). Keeping
/// the mapping here means the provider chain and the DB never disagree on the
/// spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthSource {
    /// Local argon2id password (the `local-password` provider).
    Local,
    /// Credential forwarded to a configured upstream over HTTP Basic.
    UpstreamBasic,
    /// OpenID Connect. Not driven through this chain — OIDC is its own
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
/// stored or logged (the validated-credential cache, [`super::cred_cache`],
/// stores only an HMAC of it).
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
/// `core` maps this to an existing `app_user` (lookup by `username`; no
/// provider creates accounts). The `groups` are the *raw, coarse* upstream
/// groups/roles, used at most as an allow/deny gate; they are not
/// authoritative forge authz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenIdentity {
    /// The authenticated username (the forge `app_user.username`).
    pub username: String,
    /// Which provider/source vouched for this identity.
    pub source: AuthSource,
    /// Opaque upstream identifier when the source is not local. For
    /// `upstream-basic` this is the name sent upstream: the local part of the
    /// username.
    pub external_subject: Option<String>,
    /// Raw upstream groups/roles (coarse). Empty for local.
    pub groups: Vec<String>,
    /// Whether an admin-group mapping suggests this identity is an admin.
    pub suggested_is_admin: bool,
    /// Whether [`Self::suggested_is_admin`] is an **authoritative** reading of
    /// the upstream's admin state: the realm configures an admin mapping AND the
    /// groups were freshly fetched for this login (not a cache hit, which
    /// carries no groups). Only then may the login grant or *revoke* admin;
    /// otherwise the suggestion is ignored (see
    /// [`super::chain::provision_and_map`]). Always `false` for local.
    pub admin_authoritative: bool,
    /// The `auth_realm.id` of the vouching realm, when the provider was built
    /// from a realm row: only an account of that realm signs in
    /// (`app_user.realm_id`). `None` for the built-in/static wiring.
    pub realm_id: Option<i64>,
    /// An argon2id hash of the presented password, set only when the vouching
    /// realm keeps password hashes (`capture_password_hash`)
    /// and this login asked the upstream, which accepted it (a cache hit
    /// carries none). The account keeps it
    /// ([`super::chain::provision_and_map`]). Always `None` for local.
    pub captured_password_hash: Option<CapturedPasswordHash>,
}

/// The argon2id PHC hash of a password an upstream just accepted, to be kept
/// on the account so an administrator can later switch it to a local one.
///
/// `Debug` is redacted like [`PasswordCredential`]'s: a leaked hash can be
/// attacked offline, so it must never reach a log through a `{:?}` of the
/// identity carrying it.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedPasswordHash(String);

impl CapturedPasswordHash {
    /// Wrap an argon2id PHC string.
    pub fn new(phc: String) -> Self {
        Self(phc)
    }

    /// The PHC string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CapturedPasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapturedPasswordHash([REDACTED])")
    }
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
            realm_id: None,
            captured_password_hash: None,
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
    /// realm-scoped id like `"realm:corp-nexus"`. Keys the
    /// validated-credential cache, so it must be stable for a given realm.
    fn id(&self) -> &str;

    /// The [`AuthSource`] identities from this provider carry.
    fn source(&self) -> AuthSource;

    /// Validate a username/password pair.
    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome;
}

/// A provider shared by several chains (a realm's, in the chain of the
/// browser login and in the one of the clients' passwords).
#[async_trait::async_trait]
impl<P: AuthProvider + ?Sized> AuthProvider for std::sync::Arc<P> {
    fn id(&self) -> &str {
        (**self).id()
    }

    fn source(&self) -> AuthSource {
        (**self).source()
    }

    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome {
        (**self).authenticate(cred).await
    }
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
        assert!(id.realm_id.is_none());
        assert!(id.captured_password_hash.is_none());
    }

    #[test]
    fn captured_password_hash_debug_redacts() {
        let hash = CapturedPasswordHash::new("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into());
        let id = ProvenIdentity {
            captured_password_hash: Some(hash.clone()),
            ..ProvenIdentity::local("alice")
        };
        for rendered in [format!("{hash:?}"), format!("{id:?}")] {
            assert!(!rendered.contains("argon2id"), "{rendered}");
            assert!(rendered.contains("[REDACTED]"), "{rendered}");
        }
        assert!(hash.as_str().starts_with("$argon2id$"));
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
