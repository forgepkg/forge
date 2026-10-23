//! The email settings document (`email_settings.config`, migration 0041):
//! what an administrator enters on **Admin → Settings → Email**, its
//! validation, and the write-only handling of the transport's secrets.
//!
//! The stored document is [`EmailConfig`] as JSON. Its transport secrets
//! (the SMTP password) are sealed by [`forge_db::secret_dao`] while secret
//! encryption is on; the API never returns them ([`EmailConfig::redacted`])
//! and an update that omits one keeps the stored one, unless a field the
//! secret belongs to changed ([`merge_secrets`]).

use std::net::IpAddr;
use std::time::Duration;

use lettre::message::Mailbox;
use lettre::Address;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// The default invitation lifetime, in hours.
pub const DEFAULT_INVITATION_TTL_HOURS: u32 = 72;
/// The longest invitation lifetime, in hours (30 days).
pub const MAX_INVITATION_TTL_HOURS: u32 = 720;
/// The longest secret accepted, in bytes.
const MAX_SECRET_BYTES: usize = 1024;

/// The email settings document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    /// The sender address (`From`).
    pub from_address: String,
    /// The sender's display name, e.g. `Forge`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    /// The `Reply-To` address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// How long an invitation link stays valid, in hours.
    #[serde(default = "default_invitation_ttl_hours")]
    pub invitation_ttl_hours: u32,
    /// How Forge hands the mail over.
    pub transport: TransportConfig,
}

fn default_invitation_ttl_hours() -> u32 {
    DEFAULT_INVITATION_TTL_HOURS
}

/// The transport, by `kind`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportConfig {
    /// SMTP submission, with or without a username and password.
    Smtp(SmtpConfig),
}

impl TransportConfig {
    /// The `kind` tag.
    pub fn kind(&self) -> &'static str {
        match self {
            TransportConfig::Smtp(_) => "smtp",
        }
    }
}

/// SMTP submission settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    /// The server's host name or IP address.
    pub host: String,
    /// The port; the TLS mode's usual port when absent (465, 587 or 25).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// How the connection is protected.
    pub tls: SmtpTls,
    /// The account to authenticate as; no authentication without one (a
    /// relay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The account's password. Write-only: never returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// How an SMTP connection is protected. Certificates are always verified
/// against the system roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    /// TLS from the first byte (SMTPS, port 465).
    Implicit,
    /// Plain, then `STARTTLS` before anything else; refused when the server
    /// does not offer it (port 587).
    Starttls,
    /// No TLS: only to a loopback host (a local relay).
    None,
}

impl SmtpTls {
    /// The usual port of the mode.
    pub fn default_port(self) -> u16 {
        match self {
            SmtpTls::Implicit => 465,
            SmtpTls::Starttls => 587,
            SmtpTls::None => 25,
        }
    }
}

impl SmtpConfig {
    /// The port to connect to.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.tls.default_port())
    }
}

/// A setting an administrator must fix, as the 400 names it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidSettings(pub String);

fn invalid(message: impl Into<String>) -> InvalidSettings {
    InvalidSettings(message.into())
}

impl EmailConfig {
    /// Validate and normalize the document (trimmed values, blank optional
    /// values dropped). With `require_secrets`, a transport that
    /// authenticates must carry its secret (a stored or a new one).
    pub fn validated(mut self, require_secrets: bool) -> Result<Self, InvalidSettings> {
        self.from_address = self.from_address.trim().to_string();
        parse_address("from_address", &self.from_address)?;
        self.from_name = blank_to_none(self.from_name);
        if let Some(name) = &self.from_name {
            if name.chars().count() > 128 || name.chars().any(char::is_control) {
                return Err(invalid(
                    "from_name must be at most 128 characters without control characters",
                ));
            }
        }
        self.reply_to = blank_to_none(self.reply_to);
        if let Some(reply_to) = &self.reply_to {
            parse_address("reply_to", reply_to)?;
        }
        if !(1..=MAX_INVITATION_TTL_HOURS).contains(&self.invitation_ttl_hours) {
            return Err(invalid(format!(
                "invitation_ttl_hours must be between 1 and {MAX_INVITATION_TTL_HOURS}"
            )));
        }
        match &mut self.transport {
            TransportConfig::Smtp(smtp) => smtp.validate(require_secrets)?,
        }
        Ok(self)
    }

    /// The `From` mailbox.
    pub fn from_mailbox(&self) -> Result<Mailbox, InvalidSettings> {
        Ok(Mailbox::new(
            self.from_name.clone(),
            parse_address("from_address", &self.from_address)?,
        ))
    }

    /// The `Reply-To` mailbox, if set.
    pub fn reply_to_mailbox(&self) -> Result<Option<Mailbox>, InvalidSettings> {
        self.reply_to
            .as_deref()
            .map(|a| parse_address("reply_to", a).map(|a| Mailbox::new(None, a)))
            .transpose()
    }

    /// How long an invitation stays valid.
    pub fn invitation_ttl(&self) -> Duration {
        Duration::from_secs(u64::from(self.invitation_ttl_hours) * 3600)
    }

    /// The document without its secrets, as the API returns it: each secret
    /// becomes `<key>_set: true|false`.
    pub fn redacted(&self) -> JsonValue {
        let mut doc = serde_json::to_value(self).unwrap_or(JsonValue::Null);
        if let Some(JsonValue::Object(transport)) = doc.get_mut("transport") {
            let kind = self.transport.kind();
            for key in forge_db::secret_dao::email_secret_keys(kind) {
                let set = transport
                    .remove(*key)
                    .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()));
                transport.insert(format!("{key}_set"), JsonValue::Bool(set));
            }
        }
        doc
    }
}

impl SmtpConfig {
    fn validate(&mut self, require_secrets: bool) -> Result<(), InvalidSettings> {
        self.host = self.host.trim().to_string();
        if !is_host(&self.host) {
            return Err(invalid(
                "transport.host must be a host name or an IP address (no scheme or port)",
            ));
        }
        if self.port == Some(0) {
            return Err(invalid("transport.port must be between 1 and 65535"));
        }
        if self.tls == SmtpTls::None && !is_loopback_host(&self.host) {
            return Err(invalid(
                "transport.tls \"none\" sends mail unencrypted: Forge connects without TLS \
                 only to a loopback host (a local relay); use \"starttls\" or \"implicit\"",
            ));
        }
        self.username = blank_to_none(self.username.take());
        if let Some(username) = &self.username {
            if username.len() > 256 || username.chars().any(char::is_control) {
                return Err(invalid(
                    "transport.username must be at most 256 bytes without control characters",
                ));
            }
        }
        if self.password.as_deref() == Some("") {
            self.password = None;
        }
        if let Some(password) = &self.password {
            if password.len() > MAX_SECRET_BYTES {
                return Err(invalid(format!(
                    "transport.password must be at most {MAX_SECRET_BYTES} bytes"
                )));
            }
            if self.username.is_none() {
                return Err(invalid(
                    "transport.password needs a transport.username to authenticate as",
                ));
            }
        }
        if require_secrets && self.username.is_some() && self.password.is_none() {
            return Err(invalid(
                "transport.password is required to authenticate as transport.username",
            ));
        }
        Ok(())
    }
}

/// Fill the secrets an update left out (absent or blank) from the `stored`
/// document, as long as the transport kind and every field the secret
/// belongs to ([`forge_db::secret_dao::email_secret_binding_keys`]: the SMTP
/// host and username) are unchanged. Otherwise the secret must be entered
/// again, which validation then reports.
pub fn merge_secrets(stored: Option<&EmailConfig>, mut incoming: EmailConfig) -> EmailConfig {
    let Some(stored) = stored else {
        return incoming;
    };
    match (&stored.transport, &mut incoming.transport) {
        (TransportConfig::Smtp(old), TransportConfig::Smtp(new)) => {
            let same_party = old.host.trim().eq_ignore_ascii_case(new.host.trim())
                && old.username.as_deref().map(str::trim) == new.username.as_deref().map(str::trim);
            if new.password.as_deref().is_none_or(str::is_empty) && same_party {
                new.password = old.password.clone();
            }
        }
    }
    incoming
}

/// Parse an email address for the setting `field`.
fn parse_address(field: &str, raw: &str) -> Result<Address, InvalidSettings> {
    raw.parse::<Address>()
        .map_err(|_| invalid(format!("{field} must be an email address such as forge@example.com")))
}

fn blank_to_none(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// A host name (DNS labels of letters, digits, `-` and `_`), or an IPv4 or
/// IPv6 address without brackets.
fn is_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// `localhost` or a loopback IP address. A name is never resolved here: what
/// it resolves to could change after the check.
pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn smtp(extra: JsonValue) -> EmailConfig {
        let mut transport = json!({"kind": "smtp", "host": "smtp.example.com", "tls": "starttls"});
        transport
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(json!({
            "from_address": "forge@example.com",
            "transport": transport,
        }))
        .unwrap()
    }

    #[test]
    fn a_minimal_relay_validates_with_defaults() {
        let config = smtp(json!({})).validated(true).unwrap();
        assert_eq!(config.invitation_ttl_hours, DEFAULT_INVITATION_TTL_HOURS);
        let TransportConfig::Smtp(smtp) = &config.transport;
        assert_eq!(smtp.port(), 587);
        assert_eq!(smtp.username, None);
    }

    #[test]
    fn plain_smtp_only_to_a_loopback_relay() {
        for host in ["localhost", "127.0.0.1", "::1", "LOCALHOST"] {
            assert!(
                smtp(json!({"host": host, "tls": "none"})).validated(true).is_ok(),
                "{host}"
            );
        }
        for host in ["smtp.example.com", "10.0.0.5", "localhost.example.com"] {
            let err = smtp(json!({"host": host, "tls": "none"}))
                .validated(true)
                .unwrap_err();
            assert!(err.0.contains("loopback"), "{host}: {err}");
        }
    }

    #[test]
    fn a_username_needs_a_password_and_the_reverse() {
        let err = smtp(json!({"username": "forge"})).validated(true).unwrap_err();
        assert!(err.0.contains("transport.password is required"), "{err}");
        // Before the stored secret is merged in, it may be missing.
        assert!(smtp(json!({"username": "forge"})).validated(false).is_ok());
        let err = smtp(json!({"password": "pw"})).validated(true).unwrap_err();
        assert!(err.0.contains("needs a transport.username"), "{err}");
        assert!(smtp(json!({"username": "forge", "password": "pw"}))
            .validated(true)
            .is_ok());
    }

    #[test]
    fn addresses_hosts_and_lifetimes_are_checked() {
        let bad = |config: JsonValue| {
            serde_json::from_value::<EmailConfig>(config)
                .unwrap()
                .validated(true)
                .unwrap_err()
                .0
        };
        let base = || {
            json!({
                "from_address": "forge@example.com",
                "transport": {"kind": "smtp", "host": "smtp.example.com", "tls": "implicit"},
            })
        };
        let mut c = base();
        c["from_address"] = json!("not an address");
        assert!(bad(c).contains("from_address"));
        let mut c = base();
        c["reply_to"] = json!("nope");
        assert!(bad(c).contains("reply_to"));
        let mut c = base();
        c["invitation_ttl_hours"] = json!(0);
        assert!(bad(c).contains("invitation_ttl_hours"));
        let mut c = base();
        c["invitation_ttl_hours"] = json!(721);
        assert!(bad(c).contains("invitation_ttl_hours"));
        for host in ["smtp://example.com", "example.com:25", "", "a b", "-x.example"] {
            let mut c = base();
            c["transport"]["host"] = json!(host);
            assert!(bad(c).contains("transport.host"), "{host}");
        }
        // Unknown fields and kinds are refused when parsing.
        let mut c = base();
        c["transport"]["kind"] = json!("carrier_pigeon");
        assert!(serde_json::from_value::<EmailConfig>(c).is_err());
        let mut c = base();
        c["bcc"] = json!("x@example.com");
        assert!(serde_json::from_value::<EmailConfig>(c).is_err());
    }

    #[test]
    fn the_password_is_never_returned() {
        let config = smtp(json!({"username": "forge", "password": "hunter2"}));
        let view = config.redacted();
        assert_eq!(view["transport"]["password_set"], json!(true));
        assert!(view["transport"].get("password").is_none());
        assert!(!view.to_string().contains("hunter2"));
        let view = smtp(json!({})).redacted();
        assert_eq!(view["transport"]["password_set"], json!(false));
    }

    #[test]
    fn an_omitted_password_is_kept_for_the_same_host_and_username() {
        let stored = smtp(json!({"username": "forge", "password": "old"}));
        let kept = merge_secrets(Some(&stored), smtp(json!({"username": "forge", "port": 2525})));
        let TransportConfig::Smtp(s) = &kept.transport;
        assert_eq!(s.password.as_deref(), Some("old"));

        let replaced = merge_secrets(
            Some(&stored),
            smtp(json!({"username": "forge", "password": "new"})),
        );
        let TransportConfig::Smtp(s) = &replaced.transport;
        assert_eq!(s.password.as_deref(), Some("new"));

        for changed in [
            json!({"username": "other"}),
            json!({"username": "forge", "host": "mail.example.org"}),
        ] {
            let merged = merge_secrets(Some(&stored), smtp(changed.clone()));
            let TransportConfig::Smtp(s) = &merged.transport;
            assert_eq!(s.password, None, "{changed}");
            assert!(merged.validated(true).is_err(), "{changed}");
        }
    }
}
