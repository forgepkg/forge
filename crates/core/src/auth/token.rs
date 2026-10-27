//! Credential verification: API tokens and passwords, plus the
//! [`PrincipalSource`] abstraction that turns request headers into a
//! [`Principal`].
//!
//! ## Security invariants
//! * Tokens are stored only as a SHA-256 hash. We look up by hash and then
//!   compare the stored hash against the recomputed hash in **constant time**
//!   (defense in depth against any non-constant-time DB comparison).
//! * Expired or revoked tokens, and inactive users, are rejected.
//! * Password verification (argon2 PHC) runs on a blocking thread.
//! * **Bad credentials are never downgraded to anonymous.** If any source
//!   reports credentials were present but invalid, [`resolve_principal`]
//!   returns `Unauthorized` even when anonymous access would otherwise apply.
//! * **A credential that could not be checked fails closed.** A database error
//!   while looking up a token or a session is [`AuthError::Unavailable`]
//!   (503), never `Unauthorized` (a client would take its credential for
//!   wrong) nor "not a token": the secret is not run through the password
//!   chain, whose credential-forwarding realm could send it upstream.

use std::net::IpAddr;
use std::sync::Arc;

use base64::Engine;
use chrono::Utc;
use http::HeaderMap;
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use super::chain::{provision_and_map, Chain, ChainOutcome, ChainSource, StaticChainSource};
use super::local_password::PasswordHashLimiter;
use super::login_throttle::{username_for_log, AttemptRefused, LoginThrottle, MAX_USERNAME_BYTES};
use super::principal::{Principal, UserPrincipal};
use super::provider::PasswordCredential;

/// A token's `last_used_at` is written at most this often (seconds), so the
/// parallel requests of one restore do not all write the token's row.
const TOKEN_TOUCH_INTERVAL_SECS: i64 = 60;

/// Hash a token secret into the lowercase-hex SHA-256 form stored in the DB.
pub fn hash_token(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode(digest)
}

/// Generate a fresh 256-bit token secret as a URL-safe base64 string (no
/// padding). The plaintext is shown to the user once; only its [`hash_token`]
/// is persisted.
pub fn generate_token_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Verify an API token secret.
///
/// Returns `Ok(Some(UserPrincipal))` only if the token exists, is neither
/// expired nor revoked, and belongs to an active user; `Ok(None)` when the
/// secret is not such a token. `Err` only on a database failure: the secret may
/// still be a live token, so the caller must fail closed and must not treat it
/// as anything else (e.g. a password). Best-effort updates `last_used_at`, at
/// most once a minute (failure there does not fail authentication).
/// [`check_token`] also tells an unusable token from a secret that is no token
/// at all.
pub async fn verify_token(pool: &PgPool, secret: &str) -> sqlx::Result<Option<UserPrincipal>> {
    Ok(match check_token(pool, secret).await? {
        TokenCheck::Live(up) => Some(up),
        TokenCheck::Unusable | TokenCheck::Unknown => None,
    })
}

/// What an API token secret is ([`check_token`]).
#[derive(Debug)]
pub enum TokenCheck {
    /// A live token of an active user.
    Live(UserPrincipal),
    /// A token Forge issued that cannot be used now: expired, revoked, or
    /// owned by an inactive (or deleted) user. It is still a secret, and a
    /// deactivated user's tokens work again on reactivation, so it must not
    /// be tried as anything else either (e.g. sent upstream as a password).
    Unusable,
    /// Not a token Forge issued.
    Unknown,
}

/// [`verify_token`], telling a token that exists but cannot be used
/// ([`TokenCheck::Unusable`]) from a secret that is no token
/// ([`TokenCheck::Unknown`]).
pub async fn check_token(pool: &PgPool, secret: &str) -> sqlx::Result<TokenCheck> {
    let hash = hash_token(secret);

    let Some(token) = forge_db::token_dao::find_token_by_hash(pool, &hash)
        .await
        .inspect_err(|e| tracing::warn!(error = %e, "token lookup failed"))?
    else {
        return Ok(TokenCheck::Unknown);
    };

    // Defense in depth: constant-time compare of stored vs recomputed hash.
    // (The DB lookup matched on `hash`, but we never want a timing side channel
    // to leak whether a near-miss hash exists.)
    if token
        .token_hash
        .as_bytes()
        .ct_eq(hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Ok(TokenCheck::Unknown);
    }

    let now = Utc::now();
    if let Some(exp) = token.expires_at {
        if exp <= now {
            return Ok(TokenCheck::Unusable);
        }
    }
    if token.revoked_at.is_some() {
        return Ok(TokenCheck::Unusable);
    }

    let Some(user) = forge_db::user_dao::find_user_by_id(pool, token.user_id)
        .await
        .inspect_err(|e| tracing::warn!(error = %e, "token user lookup failed"))?
    else {
        return Ok(TokenCheck::Unusable);
    };
    if !user.active {
        return Ok(TokenCheck::Unusable);
    }

    // Best-effort touch, at most once a minute per token; ignore errors.
    if let Err(e) =
        forge_db::token_dao::touch_last_used(pool, token.id, TOKEN_TOUCH_INTERVAL_SECS).await
    {
        tracing::debug!(error = %e, token_id = token.id, "touch_last_used failed");
    }

    Ok(TokenCheck::Live(UserPrincipal {
        user_id: user.id,
        token_id: Some(token.id),
    }))
}

/// Verify a username/password pair against the stored argon2 PHC hash.
///
/// Returns `Some(UserPrincipal)` only for an active user whose password
/// verifies. argon2 verification (CPU-bound) runs on a blocking thread behind
/// the process-wide [`PasswordHashLimiter::shared_default`]; a verification
/// that finds no free slot in time returns `None`.
pub async fn verify_password(
    pool: &PgPool,
    username: &str,
    password: &str,
) -> Option<UserPrincipal> {
    let user = forge_db::user_dao::find_user_by_username(pool, username)
        .await
        .map_err(|e| tracing::warn!(error = %e, "user lookup failed"))
        .ok()??;
    if !user.active {
        return None;
    }

    // Users with no local password (auth_source upstream-basic / oidc) can never
    // authenticate via password-basic against the local store.
    let stored = user.password_hash.clone()?;
    let verified = PasswordHashLimiter::shared_default()
        .verify(stored, password.to_string())
        .await
        .unwrap_or(false);

    if !verified {
        return None;
    }

    Some(UserPrincipal {
        user_id: user.id,
        token_id: None,
    })
}

/// Result of asking a [`PrincipalSource`] to resolve credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceOutcome {
    /// Credentials were present and valid.
    Authenticated(Principal),
    /// No credentials of this source's kind were present.
    NoCredentials,
    /// Credentials were present but invalid (wrong/expired/revoked). This is
    /// **non-terminal**: later sources are still tried (e.g. an invalid token
    /// header must not stop a valid Basic password). It only blocks the
    /// anonymous downgrade.
    Invalid,
    /// The source **definitively owns** this credential and rejects it: stop the
    /// chain immediately and return `Unauthorized`. Unlike [`Self::Invalid`],
    /// **no later source is tried**. Used when a source has positively claimed a
    /// credential (e.g. WIF recognized a presented JWT by its issuer) and must
    /// not let it fall through to another source — so a rejected workload JWT can
    /// never be re-interpreted as an opaque token or forwarded upstream as a
    /// password.
    Reject,
    /// An **ambient** credential (the session cookie) was presented but no
    /// longer names a live session (expired, revoked, or its user is gone or
    /// deactivated). The browser attaches it on its own, so it proves nothing
    /// and is treated like [`Self::NoCredentials`] — the request continues as
    /// anonymous/unauthenticated rather than failing with 401 — and the caller
    /// is told to clear the dead cookie ([`ResolvedPrincipal::stale_ambient`]).
    /// Otherwise a stale cookie would lock the user out of every route,
    /// including the login endpoint and the SPA itself.
    Stale,
    /// The source could not check the credential it was handed (a database
    /// error looking up the token or the session). **Fail closed** and, like
    /// [`Self::Reject`], terminal: the request is refused with
    /// [`AuthError::Unavailable`] (503) and no later source is tried. Not
    /// [`Self::Invalid`]: a 401 would tell the client its possibly valid
    /// credential is wrong, and a later source could reinterpret the secret
    /// (an unchecked token must never reach the password chain, whose
    /// credential-forwarding realm would send it upstream).
    Unavailable,
}

/// Errors from principal resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// Credentials were supplied but rejected.
    #[error("unauthorized")]
    Unauthorized,
    /// Credentials were supplied but could not be checked (a database error).
    /// Fail closed: the caller answers 503, not 401.
    #[error("authentication unavailable")]
    Unavailable,
}

/// A way to derive a principal from request headers (token header, basic auth, …).
#[async_trait::async_trait]
pub trait PrincipalSource: Send + Sync {
    /// Attempt to resolve a principal from the given headers / peer IP.
    async fn resolve(&self, headers: &HeaderMap, peer_ip: IpAddr) -> SourceOutcome;

    /// Whether this source authenticates from an **ambient** credential — one
    /// the browser attaches to every request on its own (the session cookie).
    /// A state-changing request authenticated by an ambient source must also
    /// prove same-origin intent (the CSRF token); explicit credentials (API
    /// key, Basic, bearer JWT) cannot be forged cross-site and are exempt.
    fn is_ambient(&self) -> bool {
        false
    }
}

/// Resolves the `X-NuGet-ApiKey` header as an API token.
pub struct TokenHeaderSource {
    pool: PgPool,
}

impl TokenHeaderSource {
    /// Header name carrying the NuGet API key.
    pub const HEADER: &'static str = "X-NuGet-ApiKey";

    /// Build a source over the given pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl PrincipalSource for TokenHeaderSource {
    async fn resolve(&self, headers: &HeaderMap, _peer_ip: IpAddr) -> SourceOutcome {
        let Some(value) = headers.get(Self::HEADER) else {
            return SourceOutcome::NoCredentials;
        };
        let Ok(secret) = value.to_str() else {
            // Present but unreadable → treat as invalid (creds were attempted).
            return SourceOutcome::Invalid;
        };
        if secret.is_empty() {
            return SourceOutcome::NoCredentials;
        }
        match verify_token(&self.pool, secret).await {
            Ok(Some(up)) => SourceOutcome::Authenticated(Principal::from_user(up)),
            Ok(None) => SourceOutcome::Invalid,
            Err(_) => SourceOutcome::Unavailable,
        }
    }
}

/// Resolves HTTP Basic auth. The basic secret is tried as a **token** first,
/// then (only if password-basic is enabled) as a **password** for the supplied
/// username, run through the [`crate::auth::Chain`] of
/// [`crate::auth::AuthProvider`]s:
/// * token-as-basic always wins first;
/// * the password path is gated — when no chain is configured (neither
///   `allow_password_basic` nor an enabled credential-forwarding realm) the
///   password path is skipped entirely;
/// * a present-but-wrong / unknown password yields
///   [`SourceOutcome::Invalid`] (→ 401, never downgraded to anonymous).
///
/// The local argon2id check is the [`crate::auth::LocalPasswordProvider`];
/// `upstream-basic` providers slot in behind it without any change to this
/// source.
pub struct BasicAuthSource {
    pool: PgPool,
    /// Where the *current* password chain comes from. A [`StaticChainSource`]
    /// holds a fixed chain; the realm-driven server wiring plugs in a
    /// snapshot-cached source rebuilt from the `auth_realm` table.
    /// `password_chain() == None` means the password path is disabled.
    chain: Arc<dyn ChainSource>,
    /// Password-failure lockout per `(client IP, username)`, shared with the
    /// browser login endpoint. Disabled unless wired via
    /// [`BasicAuthSource::with_throttle`].
    throttle: Arc<LoginThrottle>,
    /// The authorization cache: an authoritative upstream login may grant or
    /// revoke admin, and the user's cached effective set must follow at once.
    authz_cache: Option<forge_cache::Cache>,
}

impl BasicAuthSource {
    /// Build a source with an explicit, fixed password-auth chain. Pass `None`
    /// to disable the password path entirely. An upstream-vouched login maps
    /// only onto an existing account of its realm
    /// ([`crate::auth::provision_and_map`]).
    pub fn with_chain(pool: PgPool, chain: Option<Arc<Chain>>) -> Self {
        Self::with_source(pool, Arc::new(StaticChainSource(chain)))
    }

    /// Build a source whose chain is re-resolved per attempt (the realm-driven
    /// server wiring hands in its snapshot-cached source).
    pub fn with_source(pool: PgPool, chain: Arc<dyn ChainSource>) -> Self {
        Self {
            pool,
            chain,
            throttle: Arc::new(LoginThrottle::disabled()),
            authz_cache: None,
        }
    }

    /// Enforce a password-failure lockout on the password path (the token
    /// path is never throttled: token secrets are high-entropy).
    pub fn with_throttle(mut self, throttle: Arc<LoginThrottle>) -> Self {
        self.throttle = throttle;
        self
    }

    /// Drop a user's cached effective set when an authoritative upstream
    /// login re-synced their admin role (as the browser login does).
    pub fn with_authz_cache(mut self, cache: forge_cache::Cache) -> Self {
        self.authz_cache = Some(cache);
        self
    }
}

/// Decode a `Basic <base64>` header value into `(username, secret)`.
///
/// A username over [`MAX_USERNAME_BYTES`] is refused (`None` → invalid
/// credentials) before it reaches any lookup or the login throttle.
fn parse_basic(value: &str) -> Option<(String, String)> {
    let rest = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    // NuGet sends `username:apikey`; the colon splits user from secret. A secret
    // may itself contain colons, so split only on the first.
    let (user, secret) = text.split_once(':')?;
    if user.len() > MAX_USERNAME_BYTES {
        return None;
    }
    Some((user.to_string(), secret.to_string()))
}

#[async_trait::async_trait]
impl PrincipalSource for BasicAuthSource {
    async fn resolve(&self, headers: &HeaderMap, peer_ip: IpAddr) -> SourceOutcome {
        let Some(value) = headers.get(http::header::AUTHORIZATION) else {
            return SourceOutcome::NoCredentials;
        };
        let Ok(text) = value.to_str() else {
            return SourceOutcome::Invalid;
        };
        // Only handle the Basic scheme; other schemes are "no credentials" for us.
        if !(text.starts_with("Basic ") || text.starts_with("basic ")) {
            return SourceOutcome::NoCredentials;
        }
        let Some((username, secret)) = parse_basic(text) else {
            return SourceOutcome::Invalid;
        };
        if secret.is_empty() {
            return SourceOutcome::Invalid;
        }
        // The workload-identity username (`oidc`) and workload API keys belong
        // to the workload-identity source, which claims them first. Should one
        // reach this source anyway it is refused here: never a user token,
        // never a password, never forwarded upstream.
        let reserved = forge_db::username::canonical_username(&username)
            .is_ok_and(|name| forge_db::username::is_reserved_username(&name));
        if reserved || super::workload_key::is_workload_key(&secret) {
            return SourceOutcome::Invalid;
        }

        // Try the secret as a token first, ahead of the password chain. A
        // token Forge issued is never a password, even one that cannot be
        // used now, and a lookup that failed has not ruled out a live token:
        // neither is run through the password chain (a credential-forwarding
        // realm would send it upstream).
        match check_token(&self.pool, &secret).await {
            Ok(TokenCheck::Live(up)) => {
                return SourceOutcome::Authenticated(Principal::from_user(up))
            }
            Ok(TokenCheck::Unusable) => return SourceOutcome::Invalid,
            Ok(TokenCheck::Unknown) => {}
            Err(_) => return SourceOutcome::Unavailable,
        }
        // Then, if a password chain is configured, run the secret as a password
        // through the AuthProvider chain. The chain is re-resolved per attempt
        // so runtime realm edits take effect without a restart.
        let chain = match self.chain.password_chain().await {
            Ok(chain) => chain,
            Err(_) => return SourceOutcome::Unavailable,
        };
        if let Some(chain) = chain {
            // The lockout, the chain and the account lookup all key on the
            // canonical username, so `Alice`/`alice ` share one budget and
            // one account. A name that cannot be canonical is a bad login.
            let Ok(username) = forge_db::username::canonical_username(&username) else {
                return SourceOutcome::Invalid;
            };
            // Reserve the attempt against the (IP, username) lockout budget
            // before running the chain; a locked pair is refused without any
            // provider work (no argon2, nothing forwarded upstream).
            let attempt = match self.throttle.begin(peer_ip, &username).await {
                Ok(attempt) => attempt,
                Err(refused) => {
                    let username = username_for_log(&username);
                    match refused {
                        AttemptRefused::Locked => {
                            tracing::warn!(%username, ip = %peer_ip, "basic password auth throttled");
                        }
                        AttemptRefused::Busy => {
                            tracing::warn!(%username, ip = %peer_ip, "basic password auth: too many concurrent attempts");
                        }
                    }
                    return SourceOutcome::Invalid;
                }
            };
            let cred = PasswordCredential {
                username: &username,
                password: &secret,
                client_ip: peer_ip,
            };
            match chain.authenticate(&cred).await {
                ChainOutcome::Authenticated { identity, .. } => {
                    // Map the vouched-for username back to a concrete principal
                    // (an upstream-vouched login only to an existing account of
                    // its realm).
                    match provision_and_map(&self.pool, &identity).await {
                        Ok(Some(up)) => {
                            attempt.succeeded();
                            if identity.admin_authoritative {
                                // The upstream may just have granted or
                                // revoked admin: this very request must be
                                // authorized against the new role set.
                                if let Some(cache) = &self.authz_cache {
                                    crate::authz::invalidate_user(cache, up.user_id).await;
                                }
                            }
                            return SourceOutcome::Authenticated(Principal::from_user(up));
                        }
                        // Vouched-for but no (active) app_user row: fail closed.
                        // Basic creds were presented, so this is an
                        // attempted-but-failed login (Invalid → 401), never a
                        // downgrade to anonymous.
                        Ok(None) => {
                            attempt.failed();
                            return SourceOutcome::Invalid;
                        }
                        // A DB error during mapping: denied too, but as
                        // temporarily unavailable (503), so clients retry.
                        Err(e) => {
                            tracing::warn!(error = %e, "principal mapping failed");
                            attempt.released();
                            return SourceOutcome::Unavailable;
                        }
                    }
                }
                // A definitive rejection (wrong local password) means:
                // credentials were presented and not accepted → Invalid (401).
                ChainOutcome::Rejected => {
                    attempt.failed();
                    return SourceOutcome::Invalid;
                }
                // A fail-closed outage (or an argon2 overload) also denies, but
                // is not the caller's fault, so it does not count towards the
                // lockout.
                ChainOutcome::Unavailable => {
                    attempt.released();
                    return SourceOutcome::Invalid;
                }
                // Forge's own database failed: 503, so clients retry instead
                // of asking for new credentials.
                ChainOutcome::Failed => {
                    attempt.released();
                    return SourceOutcome::Unavailable;
                }
                // No provider had anything to say (e.g. unknown user that no
                // provider owns). Basic creds *were* presented, so this is still
                // an attempted-but-invalid login (401), never anonymous.
                ChainOutcome::NoCredentials => {
                    attempt.failed();
                    return SourceOutcome::Invalid;
                }
            }
        }
        SourceOutcome::Invalid
    }
}

/// The anonymous-access policy: whether a request without credentials is
/// served as [`Principal::Anonymous`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonPolicy {
    /// No anonymous access at all.
    Off,
    /// Anonymous access for every client.
    All,
}

impl AnonPolicy {
    /// Whether a request without credentials may be served anonymously.
    pub fn allows(self) -> bool {
        self == AnonPolicy::All
    }
}

/// Resolve a [`Principal`] from a chain of sources.
///
/// Semantics (security-critical):
/// * Sources run in order; the **first** `Authenticated` wins.
/// * A `Reject` from any source stops the chain immediately with
///   `Err(Unauthorized)` — the source has positively claimed the credential and
///   no later source may reinterpret it (WIF uses this so a rejected workload
///   JWT is never forwarded to a password provider).
/// * An `Unavailable` (a credential that could not be checked) likewise stops
///   the chain, with `Err(Unavailable)`: fail closed, and no 401 for a
///   credential that may be valid.
/// * If no source authenticates or rejects but **any** reported `Invalid`,
///   return `Err(Unauthorized)`. Bad credentials are *never* downgraded to
///   anonymous.
/// * If all sources report `NoCredentials`, apply the anonymous policy: become
///   [`Principal::Anonymous`] if it allows anonymous access, else
///   [`Principal::Unauthenticated`].
pub async fn resolve_principal(
    sources: &[Box<dyn PrincipalSource>],
    headers: &HeaderMap,
    client_ip: IpAddr,
    anon: &AnonPolicy,
) -> Result<Principal, AuthError> {
    resolve_principal_with_origin(sources, headers, client_ip, anon)
        .await
        .map(|r| r.principal)
}

/// A resolved principal plus how it was authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrincipal {
    /// The resolved principal.
    pub principal: Principal,
    /// Whether the winning source was ambient ([`PrincipalSource::is_ambient`],
    /// i.e. the session cookie). `false` for anonymous / unauthenticated.
    pub ambient: bool,
    /// An ambient credential was presented but is dead
    /// ([`SourceOutcome::Stale`]); the caller should clear it on the response.
    pub stale_ambient: bool,
}

/// [`resolve_principal`], also reporting whether the principal came from an
/// ambient (cookie) credential so the caller can enforce CSRF on it.
pub async fn resolve_principal_with_origin(
    sources: &[Box<dyn PrincipalSource>],
    headers: &HeaderMap,
    client_ip: IpAddr,
    anon: &AnonPolicy,
) -> Result<ResolvedPrincipal, AuthError> {
    resolve_principal_with_fallback(sources, None, headers, client_ip, anon).await
}

/// [`resolve_principal_with_origin`] with a `fallback` source, asked in place
/// of the anonymous policy: only when every source found no credentials (or
/// a dead session cookie). A credential another source refused is never
/// replaced by the fallback's principal, any more than by the anonymous one.
/// `Unavailable` from the fallback is `Unavailable`, and no credentials
/// leaves the anonymous policy to decide. A fallback that refuses what it
/// was shown (`Invalid`, `Reject`) names nobody: the request goes on
/// [`Principal::Unauthenticated`], whatever the anonymous policy, not with a
/// 401 here. It may still carry a credential only its handler reads (a
/// Bearer API token on a feed, a registry token), or be a sign-in.
///
/// The trusted-header realms are such a fallback: the headers the proxy in
/// front adds to every request it admits name the caller only when the
/// request presents no credential of its own, and headers the realm refuses
/// (a deactivated account, a wrong secret) must not keep the request's own
/// credential from being read, nor its sender from signing in.
pub async fn resolve_principal_with_fallback(
    sources: &[Box<dyn PrincipalSource>],
    fallback: Option<&dyn PrincipalSource>,
    headers: &HeaderMap,
    client_ip: IpAddr,
    anon: &AnonPolicy,
) -> Result<ResolvedPrincipal, AuthError> {
    let mut saw_invalid = false;
    let mut saw_stale = false;
    for source in sources {
        match source.resolve(headers, client_ip).await {
            SourceOutcome::Authenticated(principal) => {
                return Ok(ResolvedPrincipal {
                    principal,
                    ambient: source.is_ambient(),
                    stale_ambient: false,
                })
            }
            // Terminal: the source owns this credential and rejected it.
            SourceOutcome::Reject => return Err(AuthError::Unauthorized),
            // Terminal: the credential could not be checked (fail closed).
            SourceOutcome::Unavailable => return Err(AuthError::Unavailable),
            SourceOutcome::Invalid => saw_invalid = true,
            SourceOutcome::Stale => saw_stale = true,
            SourceOutcome::NoCredentials => {}
        }
    }

    if saw_invalid {
        return Err(AuthError::Unauthorized);
    }

    if let Some(source) = fallback {
        match source.resolve(headers, client_ip).await {
            SourceOutcome::Authenticated(principal) => {
                return Ok(ResolvedPrincipal {
                    principal,
                    ambient: source.is_ambient(),
                    stale_ambient: saw_stale,
                })
            }
            SourceOutcome::Invalid | SourceOutcome::Reject => {
                return Ok(ResolvedPrincipal {
                    principal: Principal::Unauthenticated,
                    ambient: false,
                    stale_ambient: saw_stale,
                })
            }
            SourceOutcome::Unavailable => return Err(AuthError::Unavailable),
            SourceOutcome::Stale => saw_stale = true,
            SourceOutcome::NoCredentials => {}
        }
    }

    let principal = if anon.allows() {
        Principal::Anonymous { ip: client_ip }
    } else {
        Principal::Unauthenticated
    };
    Ok(ResolvedPrincipal {
        principal,
        ambient: false,
        stale_ambient: saw_stale,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_sha256_hex() {
        // Known SHA-256 of "abc".
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn generate_token_secret_is_unique_and_decodes_to_32_bytes() {
        let a = generate_token_secret();
        let b = generate_token_secret();
        assert_ne!(a, b);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&a)
            .expect("valid base64url");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn parse_basic_decodes_user_and_secret() {
        // base64("alice:s3cr3t")
        let enc = base64::engine::general_purpose::STANDARD.encode("alice:s3cr3t");
        let (u, s) = parse_basic(&format!("Basic {enc}")).unwrap();
        assert_eq!(u, "alice");
        assert_eq!(s, "s3cr3t");
    }

    #[test]
    fn parse_basic_refuses_oversized_usernames() {
        let at_limit = "u".repeat(MAX_USERNAME_BYTES);
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{at_limit}:pw"));
        assert_eq!(
            parse_basic(&format!("Basic {enc}")).map(|(u, _)| u),
            Some(at_limit.clone())
        );
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{at_limit}x:pw"));
        assert_eq!(parse_basic(&format!("Basic {enc}")), None);
    }

    #[test]
    fn parse_basic_secret_may_contain_colon() {
        let enc = base64::engine::general_purpose::STANDARD.encode("bob:a:b:c");
        let (u, s) = parse_basic(&format!("Basic {enc}")).unwrap();
        assert_eq!(u, "bob");
        assert_eq!(s, "a:b:c");
    }

    // ── downgrade-prevention: pure unit tests with stub sources ──────────────

    struct StubSource(SourceOutcome);

    #[async_trait::async_trait]
    impl PrincipalSource for StubSource {
        async fn resolve(&self, _h: &HeaderMap, _ip: IpAddr) -> SourceOutcome {
            self.0.clone()
        }
    }

    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    #[tokio::test]
    async fn invalid_creds_never_downgrade_to_anonymous() {
        // Anonymous would normally be allowed (All), but an Invalid source must
        // force 401 instead of anonymous.
        let sources: Vec<Box<dyn PrincipalSource>> =
            vec![Box::new(StubSource(SourceOutcome::Invalid))];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
        assert_eq!(res, Err(AuthError::Unauthorized));
    }

    #[tokio::test]
    async fn invalid_after_nocreds_still_unauthorized() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::NoCredentials)),
            Box::new(StubSource(SourceOutcome::Invalid)),
        ];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
        assert_eq!(res, Err(AuthError::Unauthorized));
    }

    #[tokio::test]
    async fn stale_ambient_falls_back_to_anonymous_policy_and_flags_it() {
        // A dead session cookie is not a presented credential: it must not 401
        // (that would lock the browser out of login and the SPA), and the caller
        // is told to clear it.
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::NoCredentials)),
            Box::new(StubSource(SourceOutcome::Stale)),
        ];
        let open =
            resolve_principal_with_origin(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All)
                .await
                .unwrap();
        assert_eq!(open.principal, Principal::Anonymous { ip: ip() });
        assert!(open.stale_ambient && !open.ambient);
        let closed =
            resolve_principal_with_origin(&sources, &HeaderMap::new(), ip(), &AnonPolicy::Off)
                .await
                .unwrap();
        assert_eq!(closed.principal, Principal::Unauthenticated);
        assert!(closed.stale_ambient);
    }

    #[tokio::test]
    async fn stale_does_not_mask_an_invalid_credential() {
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::Invalid)),
            Box::new(StubSource(SourceOutcome::Stale)),
        ];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
        assert_eq!(res, Err(AuthError::Unauthorized));
    }

    #[tokio::test]
    async fn first_authenticated_wins_over_later_invalid() {
        let authed = Principal::User {
            user_id: 1,
            token_id: Some(2),
            method: crate::auth::AuthMethod::Token,
        };
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::Authenticated(authed.clone()))),
            Box::new(StubSource(SourceOutcome::Invalid)),
        ];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::Off).await;
        assert_eq!(res, Ok(authed));
    }

    #[tokio::test]
    async fn reject_is_terminal_and_blocks_a_later_authenticated() {
        // A `Reject` (the source owns the credential and refuses it) must stop the
        // chain immediately — a later source that WOULD authenticate is never
        // reached. This is the WIF "no fall-through" guarantee: a rejected
        // workload JWT can't be re-accepted (or forwarded) by a downstream source.
        let authed = Principal::User {
            user_id: 1,
            token_id: None,
            method: crate::auth::AuthMethod::Password,
        };
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::Reject)),
            Box::new(StubSource(SourceOutcome::Authenticated(authed))),
        ];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
        assert_eq!(res, Err(AuthError::Unauthorized));
    }

    #[tokio::test]
    async fn unavailable_is_terminal_and_never_anonymous_nor_unauthorized() {
        // A credential the source could not check (a lookup error) fails
        // closed as `Unavailable` (503): not anonymous even when anonymous
        // access is open, not a 401 that would condemn a possibly valid
        // credential, and no later source gets to reinterpret it.
        let authed = Principal::User {
            user_id: 1,
            token_id: None,
            method: crate::auth::AuthMethod::Password,
        };
        for sources in [
            vec![Box::new(StubSource(SourceOutcome::Unavailable)) as Box<dyn PrincipalSource>],
            vec![
                Box::new(StubSource(SourceOutcome::NoCredentials)),
                Box::new(StubSource(SourceOutcome::Unavailable)),
                Box::new(StubSource(SourceOutcome::Authenticated(authed))),
            ],
            vec![
                Box::new(StubSource(SourceOutcome::Invalid)),
                Box::new(StubSource(SourceOutcome::Unavailable)),
            ],
        ] {
            let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
            assert_eq!(res, Err(AuthError::Unavailable));
        }
    }

    #[tokio::test]
    async fn no_credentials_becomes_anonymous_when_allowed() {
        let sources: Vec<Box<dyn PrincipalSource>> =
            vec![Box::new(StubSource(SourceOutcome::NoCredentials))];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All).await;
        assert_eq!(res, Ok(Principal::Anonymous { ip: ip() }));
    }

    /// A stub that reports itself as an ambient (cookie) source.
    struct AmbientStub(SourceOutcome);

    #[async_trait::async_trait]
    impl PrincipalSource for AmbientStub {
        async fn resolve(&self, _h: &HeaderMap, _ip: IpAddr) -> SourceOutcome {
            self.0.clone()
        }
        fn is_ambient(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn origin_reports_whether_the_winner_was_ambient() {
        let authed = Principal::User {
            user_id: 1,
            token_id: None,
            method: crate::auth::AuthMethod::Password,
        };
        // An explicit credential wins before the cookie source: not ambient.
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::Authenticated(authed.clone()))),
            Box::new(AmbientStub(SourceOutcome::Authenticated(authed.clone()))),
        ];
        let res =
            resolve_principal_with_origin(&sources, &HeaderMap::new(), ip(), &AnonPolicy::Off)
                .await
                .unwrap();
        assert!(!res.ambient);

        // Only the cookie authenticated: ambient.
        let sources: Vec<Box<dyn PrincipalSource>> = vec![
            Box::new(StubSource(SourceOutcome::NoCredentials)),
            Box::new(AmbientStub(SourceOutcome::Authenticated(authed.clone()))),
        ];
        let res =
            resolve_principal_with_origin(&sources, &HeaderMap::new(), ip(), &AnonPolicy::Off)
                .await
                .unwrap();
        assert_eq!(res.principal, authed);
        assert!(res.ambient);

        // Anonymous is never ambient.
        let sources: Vec<Box<dyn PrincipalSource>> =
            vec![Box::new(AmbientStub(SourceOutcome::NoCredentials))];
        let res =
            resolve_principal_with_origin(&sources, &HeaderMap::new(), ip(), &AnonPolicy::All)
                .await
                .unwrap();
        assert!(!res.ambient);
    }

    #[tokio::test]
    async fn the_fallback_names_the_caller_only_without_other_credentials() {
        let named = Principal::User {
            user_id: 7,
            token_id: None,
            method: crate::auth::AuthMethod::TrustedHeader,
        };
        let token = Principal::User {
            user_id: 1,
            token_id: Some(2),
            method: crate::auth::AuthMethod::Token,
        };
        let fallback = StubSource(SourceOutcome::Authenticated(named.clone()));
        async fn resolve(
            sources: Vec<Box<dyn PrincipalSource>>,
            fallback: &StubSource,
        ) -> Result<ResolvedPrincipal, AuthError> {
            resolve_principal_with_fallback(
                &sources,
                Some(fallback),
                &HeaderMap::new(),
                ip(),
                &AnonPolicy::All,
            )
            .await
        }

        // No credentials, or a dead session cookie: the fallback names the
        // caller (and the dead cookie is still cleared), not the anonymous
        // policy.
        let res = resolve(
            vec![Box::new(StubSource(SourceOutcome::NoCredentials))],
            &fallback,
        )
        .await
        .unwrap();
        assert_eq!(res.principal, named);
        assert!(!res.ambient && !res.stale_ambient);
        let res = resolve(vec![Box::new(AmbientStub(SourceOutcome::Stale))], &fallback)
            .await
            .unwrap();
        assert_eq!(res.principal, named);
        assert!(res.stale_ambient);

        // A credential of the request's own wins over it.
        let res = resolve(
            vec![Box::new(StubSource(SourceOutcome::Authenticated(
                token.clone(),
            )))],
            &fallback,
        )
        .await
        .unwrap();
        assert_eq!(res.principal, token);

        // A refused credential is never replaced by it.
        for refused in [SourceOutcome::Invalid, SourceOutcome::Reject] {
            assert_eq!(
                resolve(vec![Box::new(StubSource(refused))], &fallback).await,
                Err(AuthError::Unauthorized)
            );
        }

        // What it refuses names nobody: the request goes on unauthenticated
        // (never anonymous, though the policy allows it), for a credential
        // only its handler reads, or a sign-in. It cannot be read, or without
        // credentials of its kind the anonymous policy decides.
        for (outcome, want) in [
            (SourceOutcome::Invalid, Ok(Principal::Unauthenticated)),
            (SourceOutcome::Reject, Ok(Principal::Unauthenticated)),
            (SourceOutcome::Unavailable, Err(AuthError::Unavailable)),
            (
                SourceOutcome::NoCredentials,
                Ok(Principal::Anonymous { ip: ip() }),
            ),
        ] {
            let res = resolve(
                vec![Box::new(StubSource(SourceOutcome::NoCredentials))],
                &StubSource(outcome.clone()),
            )
            .await
            .map(|r| r.principal);
            assert_eq!(res, want, "{outcome:?}");
        }
        // A dead session cookie is still cleared.
        let res = resolve(
            vec![Box::new(AmbientStub(SourceOutcome::Stale))],
            &StubSource(SourceOutcome::Invalid),
        )
        .await
        .unwrap();
        assert_eq!(res.principal, Principal::Unauthenticated);
        assert!(res.stale_ambient);
    }

    #[tokio::test]
    async fn no_credentials_becomes_unauthenticated_when_anon_off() {
        let sources: Vec<Box<dyn PrincipalSource>> =
            vec![Box::new(StubSource(SourceOutcome::NoCredentials))];
        let res = resolve_principal(&sources, &HeaderMap::new(), ip(), &AnonPolicy::Off).await;
        assert_eq!(res, Ok(Principal::Unauthenticated));
    }
}
