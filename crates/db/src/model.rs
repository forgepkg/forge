//! Row models mirroring the `0001_init.sql` schema.
//!
//! Every struct derives [`sqlx::FromRow`] so it can be produced both by the
//! compile-time `query_as!` macros and the runtime `query_as::<_, T>` API.
//! Ids are plain `i64` (see [`crate::ids`] for the rationale).

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;

/// Kind of a repository. Stored as `text` with a CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoKind {
    Hosted,
    Proxy,
    Group,
}

impl RepoKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RepoKind::Hosted => "hosted",
            RepoKind::Proxy => "proxy",
            RepoKind::Group => "group",
        }
    }
}

impl From<&str> for RepoKind {
    fn from(s: &str) -> Self {
        match s {
            "hosted" => RepoKind::Hosted,
            "proxy" => RepoKind::Proxy,
            "group" => RepoKind::Group,
            other => panic!("invalid repository.kind value in database: {other:?}"),
        }
    }
}

impl std::fmt::Display for RepoKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of a blob. Stored as `text` with a CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobState {
    Pending,
    Committed,
}

impl BlobState {
    pub fn as_str(self) -> &'static str {
        match self {
            BlobState::Pending => "pending",
            BlobState::Committed => "committed",
        }
    }
}

impl From<&str> for BlobState {
    fn from(s: &str) -> Self {
        match s {
            "pending" => BlobState::Pending,
            "committed" => BlobState::Committed,
            other => panic!("invalid blob.state value in database: {other:?}"),
        }
    }
}

impl std::fmt::Display for BlobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A row of `repository`.
///
/// `kind` and `format` are kept as the raw `text` from the DB; use
/// [`Repository::kind`] for the parsed [`RepoKind`].
#[derive(Clone, sqlx::FromRow)]
pub struct Repository {
    pub id: i64,
    pub name: String,
    pub format: String,
    pub kind: String,
    pub anonymous_read: bool,
    pub online: bool,
    pub config: JsonValue,
    pub remote_url: Option<String>,
    pub package_delay_seconds: i32,
    pub upstream_username: Option<String>,
    /// Legacy plaintext upstream password. Slice 12.5 supersedes it with
    /// [`Self::upstream_password_enc`]: new writes go through the envelope
    /// service (which clears this column), existing values are backfilled by
    /// the startup job, and a later migration drops the column entirely. Until
    /// then it remains the read fallback for not-yet-backfilled rows.
    pub upstream_password: Option<String>,
    /// Envelope-encrypted upstream password (slice 12.5): an opaque AEAD blob
    /// bound to this row. Decrypted **only** via
    /// [`crate::secret_dao::get_upstream_password`] at the proxy upstream
    /// fetch; everywhere else only its presence matters.
    pub upstream_password_enc: Option<Vec<u8>>,
    pub allow_private_upstream: bool,
    pub metadata_ttl_seconds: Option<i32>,
    pub not_found_ttl_seconds: Option<i32>,
    pub allow_redeploy: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Manual `Debug` that **redacts the upstream password**: the plaintext column
/// value must never land in a log line, and the ciphertext blob is reduced to
/// its byte length (its content is opaque and only adds noise).
impl std::fmt::Debug for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repository")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("format", &self.format)
            .field("kind", &self.kind)
            .field("anonymous_read", &self.anonymous_read)
            .field("online", &self.online)
            .field("config", &self.config)
            .field("remote_url", &self.remote_url)
            .field("package_delay_seconds", &self.package_delay_seconds)
            .field("upstream_username", &self.upstream_username)
            .field(
                "upstream_password",
                &self.upstream_password.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "upstream_password_enc",
                &self
                    .upstream_password_enc
                    .as_ref()
                    .map(|b| format!("<{} bytes>", b.len())),
            )
            .field("allow_private_upstream", &self.allow_private_upstream)
            .field("metadata_ttl_seconds", &self.metadata_ttl_seconds)
            .field("not_found_ttl_seconds", &self.not_found_ttl_seconds)
            .field("allow_redeploy", &self.allow_redeploy)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl Repository {
    /// Parsed repository kind.
    pub fn kind(&self) -> RepoKind {
        RepoKind::from(self.kind.as_str())
    }

    /// Whether an upstream password is stored (encrypted or, pre-backfill,
    /// plaintext). The value itself is never exposed through the model.
    pub fn has_upstream_password(&self) -> bool {
        self.upstream_password_enc.is_some() || self.upstream_password.is_some()
    }
}

/// A row of `group_member`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupMember {
    pub group_id: i64,
    pub member_id: i64,
    pub priority: i32,
}

/// A row of `blob`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Blob {
    pub sha256: String,
    pub size: i64,
    pub s3_key: String,
    pub ref_count: i64,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

impl Blob {
    /// Parsed blob state.
    pub fn state(&self) -> BlobState {
        BlobState::from(self.state.as_str())
    }
}

/// A row of `blob_outbox`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlobOutbox {
    pub id: i64,
    pub op: String,
    pub sha256: String,
    pub s3_key: String,
    pub available_at: DateTime<Utc>,
    pub attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub processed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A row of `component`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Component {
    pub id: i64,
    pub repository_id: i64,
    pub name: String,
    pub original_id: String,
    pub version: String,
    pub version_original: String,
    pub listed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A row of `asset`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Asset {
    pub id: i64,
    pub component_id: i64,
    pub path: String,
    pub content_type: String,
    pub blob_sha256: String,
    pub size: i64,
    pub sha512_base64: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A row of `proxy_cached_version`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProxyCachedVersion {
    pub id: i64,
    pub repository_id: i64,
    pub name: String,
    pub version: String,
    pub listed: bool,
    pub first_seen_at: DateTime<Utc>,
    pub downloaded: bool,
    pub metadata_refreshed_at: Option<DateTime<Utc>>,
    pub not_found: bool,
    pub not_found_at: Option<DateTime<Utc>>,
}

/// A row of `proxy_upstream_index`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProxyUpstreamIndex {
    pub repository_id: i64,
    pub resources: JsonValue,
    pub fetched_at: DateTime<Utc>,
    pub etag: Option<String>,
}

/// A row of `app_user`.
///
/// `password_hash` is `None` for users with no local password (auth_source
/// `'upstream-basic'` or `'oidc'`); a `'local'` user always has one (DB CHECK
/// `app_user_local_password_hash_check`, slice 12.3). `auth_source` records how
/// the user last authenticated / was provisioned; `external_subject` is the
/// opaque upstream identifier for non-local sources.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AppUser {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub active: bool,
    pub auth_source: String,
    pub external_subject: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A row of `token`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Token {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub token_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A row of `external_identity` (slice 12.2).
///
/// Maps an IdP identity `(issuer, subject)` to an `app_user`. The denormalized
/// claim columns are for display/debugging only and carry no authority — the
/// join key is `(issuer, subject)`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExternalIdentity {
    pub id: i64,
    pub user_id: i64,
    pub issuer: String,
    pub subject: String,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A row of `session` (slice 12.2).
///
/// Server-side login session — the authority behind the opaque `forge_session`
/// cookie. `token_hash` is `sha256(cookie_secret)` (mirrors `token.token_hash`);
/// the plaintext secret never reaches the DB. A session is valid iff
/// `revoked_at IS NULL AND now() < idle_expiry AND now() < absolute_expiry`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub external_identity_id: Option<i64>,
    pub token_hash: String,
    pub csrf_secret: String,
    pub user_agent_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub idle_expiry: DateTime<Utc>,
    pub absolute_expiry: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A row of `oidc_flow` (slice 12.2).
///
/// Ephemeral authorization-code-flow state, shared across instances so any
/// instance can complete a callback started by another. Rows are single-use:
/// the callback consumes them with `DELETE ... RETURNING`. `state` is the
/// natural text PK (the IdP echoes it back, so it cannot be hashed).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OidcFlow {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub redirect_to: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A row of `validated_credential` (slice 12.3): the durable, authoritative
/// record of one forwarded credential-validation decision.
///
/// The plaintext password is **never** stored — `cred_hmac` is
/// `HMAC-SHA256(pepper, provider_id | username | password)` (hex), so a DB-only
/// compromise cannot brute-force passwords without the server-held pepper, and
/// the same password for two users yields distinct hmacs (no cross-user
/// inference). `verdict` is the boolean decision (`true` = valid, `false` =
/// definitively rejected). Infrastructure errors / timeouts are fail-closed and
/// are never written here. `expires_at` bounds the trust window.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ValidatedCredential {
    pub id: i64,
    pub provider_id: String,
    pub username: String,
    /// `HMAC-SHA256(pepper, provider_id | username | password)`, hex-encoded.
    /// Never the plaintext password.
    pub cred_hmac: String,
    /// `true` = valid (positive cache), `false` = rejected (negative cache).
    pub verdict: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_kind_round_trip() {
        for k in [RepoKind::Hosted, RepoKind::Proxy, RepoKind::Group] {
            assert_eq!(RepoKind::from(k.as_str()), k);
        }
    }

    #[test]
    fn blob_state_round_trip() {
        for s in [BlobState::Pending, BlobState::Committed] {
            assert_eq!(BlobState::from(s.as_str()), s);
        }
    }
}
