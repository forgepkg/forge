//! Sign-in and anonymous-access policy, set at runtime (#294).
//!
//! The anonymous mode, the login screen's mode and its remembered accounts,
//! the session lifetimes and the password lockout are policy
//! an administrator changes while Forge runs, and every instance must
//! apply the same values. They are kept in `forge_setting` under
//! [`AUTH_SETTINGS_KEY`] as one JSON document ([`AuthSettings`]), changed
//! through `GET`/`PUT /admin/settings/auth` (the web UI's **Admin →
//! Settings**), and never read from the configuration file.
//!
//! [`AuthSettingsCache`] is the per-instance copy, refreshed like the realm
//! snapshot ([`super::RealmAuth`]): a write replaces this instance's copy at
//! once, and the other instances re-read the row within
//! `auth.realm_cache_ttl_seconds`. The principal middleware asks for the
//! current settings on every request (it needs the anonymous policy), so an
//! instance re-reads them as soon as they are due, whatever it serves. Each
//! copy is also pushed into the services that hold a value of their own:
//! [`Authz`] (public read for signed-in callers under anonymous mode `all`),
//! the [`SessionService`] (session lifetimes) and the [`LoginThrottle`]
//! (lockout limits).
//!
//! An install that never saved them uses [`AuthSettings::default`]: no
//! anonymous access, the identifier-first login screen remembering accounts,
//! 8 h / 7 d sessions and 10 failures per 5 minutes. (Whether a realm accepts
//! passwords from clients over HTTP Basic is the realm's own setting,
//! `accept_client_passwords`.) When the
//! row cannot be read, an instance keeps the settings it has (the defaults
//! before the first read) and tries again after the TTL.

use std::sync::Arc;
use std::time::{Duration, Instant};

use forge_core::auth::authz::Authz;
use forge_core::auth::AnonPolicy;
use forge_core::auth::LoginThrottle;
use forge_core::session::SessionService;
use forge_db::authz_dao;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// `forge_setting` key of the [`AuthSettings`] document.
pub const AUTH_SETTINGS_KEY: &str = "auth_settings";

/// Longest accepted session lifetime (10 years): longer ones overflow the
/// duration arithmetic and are a mistake anyway.
pub const MAX_SESSION_TTL_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;

/// Longest accepted lockout window (a day).
pub const MAX_LOGIN_FAILURE_WINDOW_SECONDS: u64 = 24 * 60 * 60;

/// Who is served anonymously (without credentials). A repository is read
/// anonymously only when it allows anonymous reads too.
///
/// A stored mode this version does not know (the removed `allowlist`, or one
/// a later version added) reads as [`AnonymousMode::Off`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnonymousMode {
    /// Everyone. Signed-in callers then also read what anonymous ones may.
    All,
    /// Nobody: every request needs credentials.
    #[default]
    #[serde(other)]
    Off,
}

impl std::str::FromStr for AnonymousMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(AnonymousMode::Off),
            "all" => Ok(AnonymousMode::All),
            _ => Err(format!("unknown anonymous_mode {s:?} (expected off|all)")),
        }
    }
}

/// What the login screen asks for first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginMode {
    /// The username, then a password prompt or a redirect to the identity
    /// provider whose login domains match it.
    #[default]
    IdentifierFirst,
    /// Username and password, plus a button for the enabled OIDC realm.
    Combined,
}

impl LoginMode {
    /// The name the API and `/auth/login-options` use.
    pub fn as_str(self) -> &'static str {
        match self {
            LoginMode::IdentifierFirst => "identifier_first",
            LoginMode::Combined => "combined",
        }
    }
}

impl std::str::FromStr for LoginMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "identifier_first" => Ok(LoginMode::IdentifierFirst),
            "combined" => Ok(LoginMode::Combined),
            _ => Err(format!(
                "unknown login_mode {s:?} (expected identifier_first|combined)"
            )),
        }
    }
}

/// The stored settings document, as `GET /admin/settings/auth` answers it.
///
/// Read leniently: a key left out takes its default, and one this version
/// does not know is ignored, so a row written by another version still
/// loads. Writes go through [`AuthSettingsUpdate`] and [`Self::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthSettings {
    /// Who is served anonymously.
    pub anonymous_mode: AnonymousMode,
    /// What the login screen asks for first.
    pub login_mode: LoginMode,
    /// A browser session ends this long (seconds) after its last use.
    pub session_idle_ttl_seconds: u64,
    /// A browser session ends this long (seconds) after sign-in, used or not.
    pub session_absolute_ttl_seconds: u64,
    /// Failed password attempts allowed per client network and username
    /// within [`Self::login_failure_window_seconds`] before further attempts
    /// are refused until the window ends (each instance counts its own).
    /// `0` turns the lockout off.
    pub login_max_failures: u32,
    /// Length (seconds) of the failure window and the lockout.
    pub login_failure_window_seconds: u64,
    /// Whether the login screen remembers the accounts signed in on a
    /// device and offers them for the next sign-in. The browser keeps them;
    /// `false` (a kiosk, a shared terminal) has it keep and show none.
    pub remember_accounts: bool,
}

impl Default for AuthSettings {
    fn default() -> Self {
        AuthSettings {
            anonymous_mode: AnonymousMode::Off,
            login_mode: LoginMode::IdentifierFirst,
            session_idle_ttl_seconds: 8 * 60 * 60,
            session_absolute_ttl_seconds: 7 * 24 * 60 * 60,
            login_max_failures: 10,
            login_failure_window_seconds: 300,
            remember_accounts: true,
        }
    }
}

impl AuthSettings {
    /// Check the values and build the anonymous policy they describe; the
    /// error is the message an administrator sees.
    pub fn validate(&self) -> Result<AnonPolicy, String> {
        for (key, ttl) in [
            ("session_idle_ttl_seconds", self.session_idle_ttl_seconds),
            (
                "session_absolute_ttl_seconds",
                self.session_absolute_ttl_seconds,
            ),
        ] {
            if !(1..=MAX_SESSION_TTL_SECONDS).contains(&ttl) {
                return Err(format!(
                    "{key} must be between 1 and {MAX_SESSION_TTL_SECONDS} (10 years), got {ttl}"
                ));
            }
        }
        let window = self.login_failure_window_seconds;
        if !(1..=MAX_LOGIN_FAILURE_WINDOW_SECONDS).contains(&window) {
            return Err(format!(
                "login_failure_window_seconds must be between 1 and \
                 {MAX_LOGIN_FAILURE_WINDOW_SECONDS} (a day), got {window}"
            ));
        }
        Ok(match self.anonymous_mode {
            AnonymousMode::Off => AnonPolicy::Off,
            AnonymousMode::All => AnonPolicy::All,
        })
    }

    /// The names of the settings `other` sets differently, for the log.
    pub fn changed_keys(&self, other: &AuthSettings) -> Vec<&'static str> {
        let mut keys = Vec::new();
        let mut diff = |key, changed: bool| {
            if changed {
                keys.push(key);
            }
        };
        diff(
            "anonymous_mode",
            self.anonymous_mode != other.anonymous_mode,
        );
        diff("login_mode", self.login_mode != other.login_mode);
        diff(
            "session_idle_ttl_seconds",
            self.session_idle_ttl_seconds != other.session_idle_ttl_seconds,
        );
        diff(
            "session_absolute_ttl_seconds",
            self.session_absolute_ttl_seconds != other.session_absolute_ttl_seconds,
        );
        diff(
            "login_max_failures",
            self.login_max_failures != other.login_max_failures,
        );
        diff(
            "login_failure_window_seconds",
            self.login_failure_window_seconds != other.login_failure_window_seconds,
        );
        diff(
            "remember_accounts",
            self.remember_accounts != other.remember_accounts,
        );
        keys
    }
}

/// A `PUT /admin/settings/auth` body: the settings to change. A field left
/// out keeps its value; an unknown one is refused, not dropped. The modes are
/// strings so a wrong one is answered with the values it may take.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSettingsUpdate {
    pub anonymous_mode: Option<String>,
    pub login_mode: Option<String>,
    /// Gone in 2.2: whether passwords are accepted from clients is set per
    /// realm (`accept_client_passwords`). Refused with where it went.
    #[serde(default, rename = "allow_password_basic")]
    removed_allow_password_basic: Option<serde::de::IgnoredAny>,
    pub session_idle_ttl_seconds: Option<u64>,
    pub session_absolute_ttl_seconds: Option<u64>,
    pub login_max_failures: Option<u32>,
    pub login_failure_window_seconds: Option<u64>,
    pub remember_accounts: Option<bool>,
}

impl AuthSettingsUpdate {
    /// `current` with this update's values applied, validated.
    pub fn apply_to(self, current: &AuthSettings) -> Result<AuthSettings, String> {
        if self.removed_allow_password_basic.is_some() {
            return Err(ALLOW_PASSWORD_BASIC_MOVED.to_string());
        }
        let mut next = current.clone();
        if let Some(mode) = self.anonymous_mode {
            next.anonymous_mode = mode.parse()?;
        }
        if let Some(mode) = self.login_mode {
            next.login_mode = mode.parse()?;
        }
        if let Some(ttl) = self.session_idle_ttl_seconds {
            next.session_idle_ttl_seconds = ttl;
        }
        if let Some(ttl) = self.session_absolute_ttl_seconds {
            next.session_absolute_ttl_seconds = ttl;
        }
        if let Some(max) = self.login_max_failures {
            next.login_max_failures = max;
        }
        if let Some(window) = self.login_failure_window_seconds {
            next.login_failure_window_seconds = window;
        }
        if let Some(remember) = self.remember_accounts {
            next.remember_accounts = remember;
        }
        next.validate()?;
        Ok(next)
    }
}

/// The answer to a settings update that still sets `allow_password_basic`.
const ALLOW_PASSWORD_BASIC_MOVED: &str =
    "allow_password_basic is gone: whether passwords are accepted from clients over HTTP \
     Basic is set per realm, as accept_client_passwords in the config of the local and \
     credential-forwarding realms (Admin → Authentication, PATCH /admin/realms/{id})";

/// The settings stored for the install, [`AuthSettings::default`] when none
/// were saved. A stored document that does not validate is an error.
pub async fn load(pool: &PgPool) -> anyhow::Result<AuthSettings> {
    let Some(raw) = authz_dao::get_setting(pool, AUTH_SETTINGS_KEY).await? else {
        return Ok(AuthSettings::default());
    };
    let settings: AuthSettings = serde_json::from_str(&raw).map_err(|e| {
        anyhow::anyhow!("stored {AUTH_SETTINGS_KEY} is not a settings document: {e}")
    })?;
    settings
        .validate()
        .map_err(|e| anyhow::anyhow!("stored {AUTH_SETTINGS_KEY} is invalid: {e}"))?;
    Ok(settings)
}

/// One instance's copy of the settings, with the anonymous policy built from
/// them.
#[derive(Debug)]
pub struct CurrentAuthSettings {
    /// The settings.
    pub settings: AuthSettings,
    /// [`AuthSettings::anonymous_mode`] as the policy the middleware applies.
    pub anon: AnonPolicy,
    /// When the copy was read (or written) here.
    read_at: Instant,
}

impl CurrentAuthSettings {
    fn new(settings: AuthSettings) -> Self {
        // Settings are validated before they are stored or used; a policy
        // that does not build here would be a bug, and denies.
        let anon = settings.validate().unwrap_or(AnonPolicy::Off);
        CurrentAuthSettings {
            settings,
            anon,
            read_at: Instant::now(),
        }
    }
}

/// The per-instance copy of the stored settings (see the
/// [module docs](self)).
pub struct AuthSettingsCache {
    pool: PgPool,
    ttl: Duration,
    current: std::sync::RwLock<Option<Arc<CurrentAuthSettings>>>,
    /// Held while the row is read or written: one refresh at a time, and a
    /// refresh never replaces a copy saved while it ran.
    refresh: tokio::sync::Mutex<()>,
    /// The session service every login path uses; its lifetimes follow the
    /// settings.
    sessions: SessionService,
    /// Gets public read for signed-in callers under anonymous mode `all`.
    authz: Option<Authz>,
    /// Each gets the lockout limits.
    login_throttles: Vec<Arc<LoginThrottle>>,
}

impl AuthSettingsCache {
    /// A cache over `pool` whose copy is re-read once it is older than `ttl`.
    /// It owns the [`SessionService`] ([`Self::sessions`]), whose lifetimes
    /// it sets.
    pub fn new(pool: PgPool, ttl: Duration) -> Self {
        let defaults = AuthSettings::default();
        let sessions = SessionService::new(
            pool.clone(),
            seconds(defaults.session_idle_ttl_seconds),
            seconds(defaults.session_absolute_ttl_seconds),
        );
        AuthSettingsCache {
            pool,
            ttl,
            current: std::sync::RwLock::new(None),
            refresh: tokio::sync::Mutex::new(()),
            sessions,
            authz: None,
            login_throttles: Vec::new(),
        }
    }

    /// Give `authz` public read for signed-in callers under anonymous mode
    /// `all`.
    pub fn with_authz(mut self, authz: Authz) -> Self {
        self.authz = Some(authz);
        self
    }

    /// Set the lockout limits of `throttle` too.
    pub fn with_login_throttle(mut self, throttle: Arc<LoginThrottle>) -> Self {
        self.login_throttles.push(throttle);
        self
    }

    /// The session service whose lifetimes follow the settings.
    pub fn sessions(&self) -> &SessionService {
        &self.sessions
    }

    /// The current settings: this instance's copy, re-read from the
    /// database once it is older than the TTL. While another task re-reads
    /// them, the copy at hand is returned rather than waited on: every
    /// request asks, and a slow database must not hold them all up.
    pub async fn current(&self) -> Arc<CurrentAuthSettings> {
        let held = self.held();
        if let Some(current) = held.as_ref().filter(|c| c.read_at.elapsed() < self.ttl) {
            return current.clone();
        }
        let _refresh = match (held, self.refresh.try_lock()) {
            (_, Ok(guard)) => guard,
            (Some(stale), Err(_)) => return stale,
            (None, Err(_)) => self.refresh.lock().await,
        };
        // Another task may have read them meanwhile.
        let held = self.held();
        if let Some(current) = held.as_ref().filter(|c| c.read_at.elapsed() < self.ttl) {
            return current.clone();
        }
        let previous = held.as_ref().map(|c| &c.settings);
        let settings = match load(&self.pool).await {
            Ok(settings) => {
                match previous {
                    None => tracing::info!(settings = ?settings, "auth settings loaded"),
                    Some(previous) if *previous != settings => tracing::info!(
                        changed = %previous.changed_keys(&settings).join(", "),
                        settings = ?settings,
                        "auth settings changed"
                    ),
                    Some(_) => {}
                }
                settings
            }
            Err(e) => {
                // Keep what this instance has; try again after the TTL.
                tracing::error!(
                    error = %format!("{e:#}"),
                    "cannot read the auth settings; keeping the current ones"
                );
                previous.cloned().unwrap_or_default()
            }
        };
        self.install(settings)
    }

    /// Validate and store `settings` for every instance; this instance uses
    /// them at once.
    pub async fn save(
        &self,
        settings: AuthSettings,
    ) -> Result<Arc<CurrentAuthSettings>, SaveError> {
        settings.validate().map_err(SaveError::Invalid)?;
        let document = serde_json::to_string(&settings).expect("settings serialize");
        let _refresh = self.refresh.lock().await;
        authz_dao::set_setting(&self.pool, AUTH_SETTINGS_KEY, &document)
            .await
            .map_err(SaveError::Db)?;
        Ok(self.install(settings))
    }

    /// Drop this instance's copy, so the next [`Self::current`] reads the
    /// row again.
    pub fn invalidate(&self) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// This instance's copy, fresh or not.
    fn held(&self) -> Option<Arc<CurrentAuthSettings>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Make `settings` this instance's copy (the caller holds `refresh`).
    fn install(&self, settings: AuthSettings) -> Arc<CurrentAuthSettings> {
        self.apply(&settings);
        let current = Arc::new(CurrentAuthSettings::new(settings));
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(current.clone());
        current
    }

    /// Push `settings` into the services that hold values of their own.
    fn apply(&self, settings: &AuthSettings) {
        self.sessions.set_ttls(
            seconds(settings.session_idle_ttl_seconds),
            seconds(settings.session_absolute_ttl_seconds),
        );
        if let Some(authz) = &self.authz {
            authz.set_public_read_for_signed_in(settings.anonymous_mode == AnonymousMode::All);
        }
        for throttle in &self.login_throttles {
            throttle.set_limits(
                settings.login_max_failures,
                Duration::from_secs(settings.login_failure_window_seconds),
            );
        }
    }
}

/// Why [`AuthSettingsCache::save`] failed.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    /// A value is out of range or does not parse (the message says which).
    #[error("{0}")]
    Invalid(String),
    /// The database refused the write.
    #[error("database: {0}")]
    Db(sqlx::Error),
}

/// `secs` (validated to at most [`MAX_SESSION_TTL_SECONDS`]) as a chrono
/// duration.
fn seconds(secs: u64) -> chrono::Duration {
    chrono::Duration::seconds(secs.min(MAX_SESSION_TTL_SECONDS) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_closed_and_valid() {
        let settings = AuthSettings::default();
        assert_eq!(settings.validate().unwrap(), AnonPolicy::Off);
        assert_eq!(settings.login_mode, LoginMode::IdentifierFirst);
        assert!(settings.remember_accounts);
        // An empty or partial stored document takes the defaults, so a row
        // saved before `remember_accounts` existed remembers accounts.
        let stored: AuthSettings =
            serde_json::from_str(r#"{"anonymous_mode":"all","removed_later":1}"#).unwrap();
        assert_eq!(stored.anonymous_mode, AnonymousMode::All);
        assert_eq!(stored.session_idle_ttl_seconds, 8 * 60 * 60);
        assert!(stored.remember_accounts);
    }

    #[test]
    fn a_stored_mode_this_version_does_not_know_reads_as_off() {
        // A row an earlier version saved under the removed `allowlist` mode
        // still loads, with its other settings, and serves nobody anonymously.
        let stored: AuthSettings = serde_json::from_str(
            r#"{"anonymous_mode":"allowlist","anonymous_ip_allowlist":["10.0.0.0/8"],"allow_password_basic":true}"#,
        )
        .unwrap();
        assert_eq!(stored.anonymous_mode, AnonymousMode::Off);
        assert!(
            serde_json::to_value(&stored)
                .unwrap()
                .get("allow_password_basic")
                .is_none(),
            "the moved setting is read past, and not written back"
        );
        assert_eq!(stored.validate().unwrap(), AnonPolicy::Off);
        let off: AuthSettings = serde_json::from_str(r#"{"anonymous_mode":"off"}"#).unwrap();
        assert_eq!(off.anonymous_mode, AnonymousMode::Off);
        assert_eq!(
            serde_json::to_value(AuthSettings::default()).unwrap()["anonymous_mode"],
            "off"
        );
    }

    #[test]
    fn an_update_keeps_what_it_leaves_out() {
        let current = AuthSettings {
            login_max_failures: 3,
            ..AuthSettings::default()
        };
        let update: AuthSettingsUpdate = serde_json::from_value(serde_json::json!({
            "anonymous_mode": " All",
            "login_mode": "combined",
            "remember_accounts": false,
        }))
        .unwrap();
        let next = update.apply_to(&current).unwrap();
        assert_eq!(next.anonymous_mode, AnonymousMode::All);
        assert_eq!(next.login_mode, LoginMode::Combined);
        assert!(!next.remember_accounts);
        assert_eq!(
            current.changed_keys(&next).last(),
            Some(&"remember_accounts")
        );
        assert_eq!(next.login_max_failures, 3, "left out, kept");
        assert_eq!(next.validate().unwrap(), AnonPolicy::All);
    }

    #[test]
    fn invalid_values_are_refused_with_what_is_wrong() {
        let refused = |body: serde_json::Value| {
            serde_json::from_value::<AuthSettingsUpdate>(body)
                .unwrap()
                .apply_to(&AuthSettings::default())
                .unwrap_err()
        };
        assert_eq!(
            refused(serde_json::json!({"anonymous_mode": "allowlist"})),
            "unknown anonymous_mode \"allowlist\" (expected off|all)"
        );
        assert_eq!(
            refused(serde_json::json!({"login_mode": "both"})),
            "unknown login_mode \"both\" (expected identifier_first|combined)"
        );
        assert!(refused(serde_json::json!({"session_idle_ttl_seconds": 0}))
            .starts_with("session_idle_ttl_seconds must be between 1 and"));
        assert!(
            refused(serde_json::json!({"session_absolute_ttl_seconds": u64::MAX}))
                .starts_with("session_absolute_ttl_seconds must be between 1 and")
        );
        assert!(
            refused(serde_json::json!({"login_failure_window_seconds": 0}))
                .starts_with("login_failure_window_seconds must be between 1 and")
        );
        // An unknown field is refused, not dropped.
        for body in [
            serde_json::json!({"anonymous": "all"}),
            serde_json::json!({"anonymous_ip_allowlist": ["10.0.0.0/8"]}),
        ] {
            assert!(serde_json::from_value::<AuthSettingsUpdate>(body).is_err());
        }
        // The moved setting is refused with where it went, whatever its value.
        for allow in [true, false] {
            assert!(refused(serde_json::json!({"allow_password_basic": allow}))
                .contains("accept_client_passwords"),);
        }
    }
}
