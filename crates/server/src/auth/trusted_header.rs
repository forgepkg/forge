//! Trusted-header realms (#506): authenticate a request as the account a
//! header of the load balancer or reverse proxy in front of Forge names, in
//! the style of `REMOTE_USER`.
//!
//! The proxy decides who gets which name: an SSO proxy (oauth2-proxy,
//! Authelia) names the person it signed in, a load balancer names an account
//! for the network or machine it admits. Forge checks two headers of a
//! `trusted_header` realm: `username_header` naming the account, and
//! `secret_header` carrying the realm's `secret`, which proves the request
//! came through the proxy (compared in constant time; sealed at rest,
//! write-only and redacted like the other realms' secrets).
//!
//! ## What the realm trusts
//! * The headers count only from a **trusted peer**: the socket peer must be
//!   in `auth.trusted_proxy_cidrs`, and the request's `Host` must name this
//!   server (the DNS-rebinding guard: the host of `server.public_base_url` or
//!   an entry of `server.allowed_hosts`). Otherwise the principal middleware
//!   does not ask this source at all, and the headers are ignored.
//! * The realm names the caller only when the request presents no credential
//!   of its own ([`forge_core::auth::resolve_principal_with_fallback`]): an
//!   API token, a password or a session cookie wins, and one that is refused
//!   is never replaced by the account the headers name.
//! * The headers present but no realm's secret among them, or the right
//!   secret with a missing, empty, repeated or invalid name, or a name that
//!   is not an account of the realm: the credentials are present but invalid
//!   (401), never anonymous.
//!
//! ## The accounts
//! A realm names only its own accounts, with the realm as `realm_id`
//! ([`forge_db::user_dao::find_trusted_header_user`]): users
//! (`auth_source = 'trusted-header'`), the people an SSO proxy signs in, and
//! service accounts (#508), the networks or machines a load balancer admits.
//! An account of another source (local, OIDC, credential forwarding) or of
//! another realm is never mapped onto, whatever its name. With
//! `auto_provision` the realm creates a missing user's account on its first
//! request; otherwise an administrator creates it (`POST /admin/users` with
//! the realm). The realm never creates service accounts: an administrator
//! creates each one with its realm (`"kind": "service"`). The built-in
//! `anonymous` principal is never one of them. When the realm last
//! authenticated an account is kept (`app_user.last_auth_source_at`, written
//! at most once a minute), so the service accounts screen shows when each was
//! last used.
//!
//! ## An ambient credential
//! The proxy adds the headers to every request of a client it admits,
//! including the ones a browser sends for a foreign page. So the request is
//! [`AuthMethod::TrustedHeader`]: it holds the account's grants but never the
//! `admin` role, cannot reach the admin API or mint tokens, and publishes
//! nothing (packages and images take an API token). A state-changing request
//! a browser labels cross-site is refused before authentication, as for every
//! credential.

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use forge_core::auth::login_throttle::username_for_log;
use forge_core::auth::principal::{AuthMethod, Principal};
use forge_core::auth::token::{PrincipalSource, SourceOutcome};
use forge_db::model::{AppUser, AuthRealm};
use forge_db::user_dao;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use super::RealmAuth;

/// Shortest accepted `secret`, in bytes.
pub const MIN_SECRET_BYTES: usize = 16;

/// Longest accepted `secret`, in bytes.
const MAX_SECRET_BYTES: usize = 1024;

/// An account's `last_auth_source_at` is written at most this often
/// (seconds), so the requests of a busy account do not all write its row.
const LAST_AUTHENTICATED_INTERVAL_SECS: i64 = 60;

/// Headers that carry Forge's own credentials or routing: neither may be a
/// realm's `username_header` or `secret_header`.
const RESERVED_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "x-nuget-apikey",
    "x-csrf-token",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
];

/// `config` shape for a `trusted_header` realm.
///
/// `secret` is a **secret**: write-only at the API layer, redacted from
/// responses and `Debug`, and sealed into `auth_realm.secrets_enc`. Unknown
/// keys are refused, as for the other kinds.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHeaderRealmConfig {
    /// The header naming the account (e.g. `X-Forwarded-User`), stored
    /// lowercase.
    pub username_header: String,
    /// The header the proxy proves itself with (e.g. `X-Forge-Proxy-Secret`),
    /// stored lowercase.
    pub secret_header: String,
    /// The value of `secret_header`. **Write-only / redacted.**
    #[serde(default)]
    pub secret: String,
    /// Create a user's account on its first request when none of the realm
    /// has the name. Off: an administrator creates the accounts.
    #[serde(default)]
    pub auto_provision: bool,
}

impl std::fmt::Debug for TrustedHeaderRealmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedHeaderRealmConfig")
            .field("username_header", &self.username_header)
            .field("secret_header", &self.secret_header)
            .field("secret", &"<redacted>")
            .field("auto_provision", &self.auto_provision)
            .finish()
    }
}

/// `raw` as a header name the realm may read (lowercase), or why not.
fn header_name(field: &str, raw: &str) -> Result<HeaderName, String> {
    let name = HeaderName::from_bytes(raw.trim().as_bytes())
        .map_err(|_| format!("{field}: {raw:?} is not a header name"))?;
    if RESERVED_HEADERS.contains(&name.as_str()) {
        return Err(format!(
            "{field}: {name} carries Forge's own credentials or routing; name another header"
        ));
    }
    Ok(name)
}

/// Parse and validate a `trusted_header` realm `config`, returning the
/// normalized document (header names lowercase).
pub fn validate_trusted_header_config(config: &JsonValue) -> Result<JsonValue, String> {
    let mut cfg: TrustedHeaderRealmConfig =
        serde_json::from_value(config.clone()).map_err(|e| format!("invalid config: {e}"))?;
    let username = header_name("username_header", &cfg.username_header)?;
    let secret = header_name("secret_header", &cfg.secret_header)?;
    if username == secret {
        return Err("username_header and secret_header must be different headers".into());
    }
    if cfg.secret.len() < MIN_SECRET_BYTES || cfg.secret.len() > MAX_SECRET_BYTES {
        return Err(format!(
            "secret must be {MIN_SECRET_BYTES} to {MAX_SECRET_BYTES} characters \
             (e.g. `openssl rand -hex 32`)"
        ));
    }
    if !cfg.secret.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(
            "secret must be printable ASCII without spaces (it is sent as a header value)".into(),
        );
    }
    cfg.username_header = username.as_str().to_string();
    cfg.secret_header = secret.as_str().to_string();
    Ok(serde_json::to_value(&cfg).expect("serializable"))
}

/// An enabled `trusted_header` realm, as a snapshot holds it.
pub struct TrustedHeaderRealm {
    /// `auth_realm.id`: the realm whose accounts it names.
    pub realm_id: i64,
    /// `auth_realm.name`, for logs.
    pub name: String,
    username_header: HeaderName,
    secret_header: HeaderName,
    /// SHA-256 of the secret: compared in constant time with the presented
    /// value's, whatever its length.
    secret_sha256: [u8; 32],
    auto_provision: bool,
}

/// What a realm makes of a request's headers.
enum Presented<'h> {
    /// Neither of its headers.
    Nothing,
    /// One of its headers, without its secret (missing, wrong or repeated).
    WrongSecret,
    /// Its secret: the values of the username header.
    Proven(Vec<&'h HeaderValue>),
}

impl TrustedHeaderRealm {
    /// The runtime of a realm row, from its logical `config` (the secret
    /// merged in).
    pub fn build(realm: &AuthRealm, config: &JsonValue) -> anyhow::Result<Self> {
        let cfg: TrustedHeaderRealmConfig = serde_json::from_value(
            validate_trusted_header_config(config).map_err(anyhow::Error::msg)?,
        )
        .map_err(|e| anyhow::anyhow!("config: {e}"))?;
        Ok(Self {
            realm_id: realm.id,
            name: realm.name.clone(),
            username_header: HeaderName::from_bytes(cfg.username_header.as_bytes())?,
            secret_header: HeaderName::from_bytes(cfg.secret_header.as_bytes())?,
            secret_sha256: Sha256::digest(cfg.secret.as_bytes()).into(),
            auto_provision: cfg.auto_provision,
        })
    }

    fn check<'h>(&self, headers: &'h HeaderMap) -> Presented<'h> {
        let secrets: Vec<&HeaderValue> = headers.get_all(&self.secret_header).iter().collect();
        let names: Vec<&HeaderValue> = headers.get_all(&self.username_header).iter().collect();
        if secrets.is_empty() && names.is_empty() {
            return Presented::Nothing;
        }
        // One secret, the realm's: a second value means a client's own made
        // it through next to the proxy's.
        let proven = match secrets.as_slice() {
            [secret] => {
                let presented: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
                bool::from(presented.ct_eq(&self.secret_sha256))
            }
            _ => false,
        };
        if proven {
            Presented::Proven(names)
        } else {
            Presented::WrongSecret
        }
    }
}

/// The trusted-header realms as a [`PrincipalSource`]. The principal
/// middleware asks it last, and only for a request from a trusted peer that
/// names this server (see the [module docs](self)).
pub struct TrustedHeaderSource {
    realms: Arc<RealmAuth>,
    pool: PgPool,
}

impl TrustedHeaderSource {
    /// A source over the realm snapshots of `realms`, looking accounts up in
    /// `pool`.
    pub fn new(realms: Arc<RealmAuth>, pool: PgPool) -> Self {
        Self { realms, pool }
    }

    /// The account `names` names in `realm`, whose secret the request
    /// carries.
    async fn authenticate(
        &self,
        realm: &TrustedHeaderRealm,
        names: &[&HeaderValue],
    ) -> SourceOutcome {
        let refused = |why: &str, username: &str| {
            tracing::warn!(
                realm = %realm.name,
                username = ?username_for_log(username),
                "trusted-header credentials refused: {why}"
            );
            SourceOutcome::Invalid
        };
        // Exactly one name: a second value means a client's own made it
        // through next to the proxy's.
        let [name] = names else {
            return refused("the username header is missing or repeated", "");
        };
        let Ok(raw) = std::str::from_utf8(name.as_bytes()) else {
            return refused("the username is not UTF-8", "");
        };
        let username = match forge_db::username::canonical_username(raw) {
            Ok(username) if !forge_db::username::is_reserved_username(&username) => username,
            _ => return refused("the username is empty, reserved or not valid", raw),
        };
        match user_dao::find_trusted_header_user(&self.pool, &username, realm.realm_id).await {
            Ok(Some(user)) => self.signed_in(realm, &user).await,
            Ok(None) if realm.auto_provision => self.provision(realm, &username).await,
            Ok(None) => refused("no account of the realm has this name", &username),
            Err(e) => {
                tracing::warn!(realm = %realm.name, error = %e, "trusted-header account lookup failed");
                SourceOutcome::Unavailable
            }
        }
    }

    /// Create the account `username` of `realm` (`auto_provision`). A name
    /// another account holds is refused; one a concurrent first request just
    /// created for the realm is adopted.
    async fn provision(&self, realm: &TrustedHeaderRealm, username: &str) -> SourceOutcome {
        let refused = |why: &str| {
            tracing::warn!(
                realm = %realm.name,
                username = ?username_for_log(username),
                "trusted-header credentials refused: {why}"
            );
            SourceOutcome::Invalid
        };
        match user_dao::insert_trusted_header_user(&self.pool, username, realm.realm_id).await {
            Ok(user) => {
                tracing::info!(
                    target: "forge::audit",
                    realm = %realm.name,
                    user_id = user.id,
                    username = %user.username,
                    "trusted-header realm created an account"
                );
                self.signed_in(realm, &user).await
            }
            // Not a UPN, which every account is named by.
            Err(sqlx::Error::InvalidArgument(_)) => refused("the username is no UPN"),
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
                match user_dao::find_trusted_header_user(&self.pool, username, realm.realm_id).await
                {
                    Ok(Some(user)) => self.signed_in(realm, &user).await,
                    Ok(None) => refused("the name belongs to an account of another kind or realm"),
                    Err(e) => {
                        tracing::warn!(realm = %realm.name, error = %e, "trusted-header account lookup failed");
                        SourceOutcome::Unavailable
                    }
                }
            }
            Err(e) => {
                tracing::warn!(realm = %realm.name, error = %e, "trusted-header account creation failed");
                SourceOutcome::Unavailable
            }
        }
    }

    async fn signed_in(&self, realm: &TrustedHeaderRealm, user: &AppUser) -> SourceOutcome {
        if !user.active {
            tracing::warn!(
                realm = %realm.name,
                user_id = user.id,
                "trusted-header credentials refused: the account is deactivated"
            );
            return SourceOutcome::Invalid;
        }
        // Best effort: when the account was last used is for the admin
        // screens, and never fails the request.
        if let Err(e) = user_dao::touch_last_authenticated(
            &self.pool,
            user.id,
            LAST_AUTHENTICATED_INTERVAL_SECS,
        )
        .await
        {
            tracing::debug!(error = %e, user_id = user.id, "touch_last_authenticated failed");
        }
        SourceOutcome::Authenticated(Principal::User {
            user_id: user.id,
            token_id: None,
            method: AuthMethod::TrustedHeader,
        })
    }
}

#[async_trait::async_trait]
impl PrincipalSource for TrustedHeaderSource {
    async fn resolve(&self, headers: &HeaderMap, _client_ip: std::net::IpAddr) -> SourceOutcome {
        // Without the realms Forge cannot tell the headers apart from any
        // others: fail closed rather than serve the request as anonymous.
        // Past their TTL the ones at hand do while a rebuild runs, so a slow
        // database holds up only the requests that carry a realm's headers
        // (their account lookup needs it anyway).
        let snap = match self.realms.current_or_stale().await {
            Ok(snap) => snap,
            Err(e) => {
                tracing::error!(error = %e, "realm snapshot failed; trusted-header requests refused");
                return SourceOutcome::Unavailable;
            }
        };
        let mut presented = false;
        for realm in &snap.trusted_header {
            match realm.check(headers) {
                Presented::Nothing => {}
                Presented::WrongSecret => presented = true,
                Presented::Proven(names) => return self.authenticate(realm, &names).await,
            }
        }
        if presented {
            tracing::warn!(
                "trusted-header credentials refused: no realm's secret among the headers"
            );
            return SourceOutcome::Invalid;
        }
        SourceOutcome::NoCredentials
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn config() -> JsonValue {
        json!({
            "username_header": "X-Forwarded-User",
            "secret_header": "X-Forge-Proxy-Secret",
            "secret": SECRET,
        })
    }

    fn realm(config: &JsonValue) -> TrustedHeaderRealm {
        let row = AuthRealm {
            id: 3,
            kind: super::super::KIND_TRUSTED_HEADER.into(),
            name: "proxy".into(),
            enabled: true,
            priority: 30,
            config: config.clone(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            secrets_enc: None,
        };
        TrustedHeaderRealm::build(&row, config).expect("valid realm")
    }

    #[test]
    fn config_validates_and_normalizes_the_header_names() {
        let ok = validate_trusted_header_config(&config()).expect("valid");
        assert_eq!(ok["username_header"], "x-forwarded-user");
        assert_eq!(ok["secret_header"], "x-forge-proxy-secret");
        assert_eq!(ok["auto_provision"], false);

        let with = |key: &str, value: JsonValue| {
            let mut config = config();
            config[key] = value;
            validate_trusted_header_config(&config)
        };
        for (key, value) in [
            ("username_header", json!("Authorization")),
            ("secret_header", json!("cookie")),
            ("username_header", json!("X-NuGet-ApiKey")),
            ("username_header", json!("not a header")),
            ("username_header", json!("")),
            ("secret_header", json!("x-forwarded-user")),
            ("secret", json!("")),
            ("secret", json!("short")),
            ("secret", json!("0123456789abcdef 0123456789abcdef")),
            ("secret", json!("x".repeat(MAX_SECRET_BYTES + 1))),
            ("auto_provison", json!(true)),
        ] {
            assert!(with(key, value.clone()).is_err(), "{key}: {value}");
        }
        let mut missing = config();
        missing.as_object_mut().unwrap().remove("secret_header");
        assert!(validate_trusted_header_config(&missing).is_err());
    }

    #[test]
    fn the_secret_is_never_printed() {
        let cfg: TrustedHeaderRealmConfig = serde_json::from_value(config()).unwrap();
        let printed = format!("{cfg:?}");
        assert!(!printed.contains(SECRET), "{printed}");
    }

    #[test]
    fn only_the_secret_proves_the_names() {
        let realm = realm(&config());
        let headers = |pairs: &[(&str, &str)]| {
            let mut map = HeaderMap::new();
            for (k, v) in pairs {
                map.append(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            map
        };
        assert!(matches!(
            realm.check(&headers(&[("x-other", "x")])),
            Presented::Nothing
        ));
        match realm.check(&headers(&[
            ("x-forge-proxy-secret", SECRET),
            ("x-forwarded-user", "alice@example.com"),
        ])) {
            Presented::Proven(names) => assert_eq!(names, ["alice@example.com"]),
            _ => panic!("the right secret proves the name"),
        }
        // The right secret without a name is still proven: the source then
        // refuses the missing name.
        assert!(matches!(
            realm.check(&headers(&[("X-Forge-Proxy-Secret", SECRET)])),
            Presented::Proven(names) if names.is_empty()
        ));
        for wrong in [
            headers(&[("x-forwarded-user", "alice@example.com")]),
            headers(&[
                ("x-forge-proxy-secret", "0123456789abcdef0123456789abcdeX"),
                ("x-forwarded-user", "alice@example.com"),
            ]),
            headers(&[
                ("x-forge-proxy-secret", &SECRET[..20]),
                ("x-forwarded-user", "alice@example.com"),
            ]),
            // A client's own secret header next to the proxy's.
            headers(&[
                ("x-forge-proxy-secret", SECRET),
                ("x-forge-proxy-secret", SECRET),
                ("x-forwarded-user", "alice@example.com"),
            ]),
        ] {
            assert!(
                matches!(realm.check(&wrong), Presented::WrongSecret),
                "{wrong:?}"
            );
        }
    }
}
