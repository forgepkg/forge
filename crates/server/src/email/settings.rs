//! The email settings document (`email_settings.config`):
//! what an administrator enters on **Admin → Settings → Email**, its
//! validation, and the write-only handling of the transport's secrets.
//!
//! The stored document is [`EmailConfig`] as JSON. Its transport secrets
//! (the SMTP password, the Graph client secret) are sealed by
//! [`forge_db::secret_dao`] while secret
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
    /// Microsoft Graph `sendMail`, as an Entra app registration (#320).
    MicrosoftGraph(GraphConfig),
    /// SMTP submission authenticated with an OAuth access token (SASL
    /// OAUTHBEARER or XOAUTH2) from the mail server's own authorization
    /// server (#321).
    SmtpOauth(SmtpOauthConfig),
}

impl TransportConfig {
    /// The `kind` tag.
    pub fn kind(&self) -> &'static str {
        match self {
            TransportConfig::Smtp(_) => "smtp",
            TransportConfig::MicrosoftGraph(_) => "microsoft_graph",
            TransportConfig::SmtpOauth(_) => "smtp_oauth",
        }
    }
}

/// Microsoft Graph settings: Forge signs in as an Entra app registration
/// with the client credentials grant and sends with `sendMail` as the sender
/// mailbox. No mailbox password is involved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphConfig {
    /// The Entra tenant: its id (a GUID) or a verified domain such as
    /// `contoso.onmicrosoft.com`.
    pub tenant_id: String,
    /// The app registration's application (client) id.
    pub client_id: String,
    /// The mailbox to send as, its UPN or object id; the `From` address when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// How Forge authenticates at the token endpoint.
    #[serde(default)]
    pub client_authentication: GraphClientAuth,
    /// The app's client secret (`client_secret` authentication). Write-only:
    /// never returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// How Forge authenticates as the Graph app registration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphClientAuth {
    /// A client secret of the app registration.
    #[default]
    ClientSecret,
    /// A client assertion Forge signs with its own issuer keys, which the
    /// app's federated identity credential trusts ([`GraphConfig::federated_credential`]).
    FederatedCredential,
}

/// Entra's sign-in host.
pub const MICROSOFT_LOGIN_HOST: &str = "https://login.microsoftonline.com";

/// SMTP submission with an OAuth access token (#321): Forge holds a token an
/// administrator authorized once (or gets one with the client credentials
/// grant), never a mailbox password.
///
/// The administrator enters the server, the authorization server's issuer
/// and the mailbox. The rest is Forge's: the client it registered (RFC 7591)
/// or that was entered by hand, and the refresh token the authorization gave
/// ([`merge_secrets`] keeps them across saves of the same issuer and
/// mailbox).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpOauthConfig {
    /// The SMTP server's host name or IP address.
    pub host: String,
    /// The port; the TLS mode's usual port when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// How the SMTP connection is protected.
    pub tls: SmtpTls,
    /// The authorization server's issuer URL (`https`, or `http` to a
    /// loopback host).
    pub issuer: String,
    /// The mailbox Forge sends as: the SASL user, and the account that
    /// authorizes Forge.
    pub username: String,
    /// The scope to ask for; none when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The OAuth client id: registered by Forge, or entered by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The client's secret. Write-only: never returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Whether Forge registered the client (RFC 7591) rather than an
    /// administrator entering it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub registered: bool,
    /// Where the registration is managed (RFC 7592), when Forge registered
    /// the client and the server said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    /// The registration's access token (RFC 7592). Write-only: never
    /// returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    /// How Forge gets its access tokens, once it can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<OauthGrant>,
    /// The refresh token of the mailbox's authorization. Write-only: never
    /// returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Why the mailbox must authorize Forge again (a refresh that failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_error: Option<String>,
}

/// How an [`SmtpOauthConfig`] gets its access tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OauthGrant {
    /// The mailbox authorized Forge (authorization code or device flow):
    /// access tokens come from the refresh token.
    RefreshToken,
    /// The authorization server issues tokens to the client itself.
    ClientCredentials,
}

impl SmtpOauthConfig {
    /// The port to connect to.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.tls.default_port())
    }

    /// Whether Forge can get an access token without the mailbox's help.
    pub fn authorized(&self) -> bool {
        match self.grant {
            Some(OauthGrant::ClientCredentials) => self.client_id.is_some(),
            Some(OauthGrant::RefreshToken) => {
                self.refresh_token.is_some() && self.authorization_error.is_none()
            }
            None => false,
        }
    }

    fn validate(&mut self) -> Result<(), InvalidSettings> {
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
                "transport.tls \"none\" sends the token unencrypted: Forge connects without \
                 TLS only to a loopback host; use \"starttls\" or \"implicit\"",
            ));
        }
        self.issuer = self.issuer.trim().trim_end_matches('/').to_string();
        check_oauth_url("transport.issuer", &self.issuer)?;
        self.username = self.username.trim().to_string();
        if self.username.is_empty()
            || self.username.len() > 256
            || self.username.chars().any(char::is_control)
        {
            return Err(invalid(
                "transport.username must be the mailbox Forge sends as (at most 256 bytes)",
            ));
        }
        self.scope = blank_to_none(self.scope.take());
        if let Some(scope) = &self.scope {
            if scope.len() > 1024 || scope.chars().any(char::is_control) {
                return Err(invalid(
                    "transport.scope must be space-separated scope names (at most 1024 bytes)",
                ));
            }
        }
        self.client_id = blank_to_none(self.client_id.take());
        if let Some(client_id) = &self.client_id {
            if client_id.len() > 256 || client_id.chars().any(char::is_control) {
                return Err(invalid("transport.client_id must be at most 256 bytes"));
            }
        }
        if self.client_secret.as_deref() == Some("") {
            self.client_secret = None;
        }
        if let Some(secret) = &self.client_secret {
            if secret.len() > MAX_SECRET_BYTES {
                return Err(invalid(format!(
                    "transport.client_secret must be at most {MAX_SECRET_BYTES} bytes"
                )));
            }
            if self.client_id.is_none() {
                return Err(invalid(
                    "transport.client_secret needs a transport.client_id",
                ));
            }
        }
        if let Some(uri) = &self.registration_client_uri {
            check_oauth_url("transport.registration_client_uri", uri)?;
        }
        Ok(())
    }
}

/// An OAuth endpoint or issuer URL: `https`, or `http` to a loopback host (a
/// test server, an authorization server on the same machine).
pub fn check_oauth_url(field: &str, raw: &str) -> Result<url::Url, InvalidSettings> {
    let url = url::Url::parse(raw)
        .map_err(|_| invalid(format!("{field} must be an absolute https URL")))?;
    let loopback = url
        .host_str()
        .is_some_and(|h| is_loopback_host(h.trim_start_matches('[').trim_end_matches(']')));
    let ok = match url.scheme() {
        "https" => true,
        "http" => loopback,
        _ => false,
    };
    if !ok || url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(invalid(format!("{field} must be an https URL")));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(invalid(format!(
            "{field} must not carry credentials or a fragment"
        )));
    }
    Ok(url)
}

/// What the app registration's federated identity credential must name for
/// Forge's client assertions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FederatedCredential {
    /// Forge's issuer URL (`server.public_base_url`).
    pub issuer: String,
    /// `{client_id}@https://login.microsoftonline.com/{tenant_id}/v2.0`:
    /// what a federated `oidc` realm of the same app and tenant asserts too,
    /// so one credential serves both.
    pub subject: String,
    /// `api://AzureADTokenExchange`.
    pub audience: String,
}

impl GraphConfig {
    /// The mailbox Graph sends as: [`Self::sender`], else `from_address`.
    pub fn sender_mailbox<'a>(&'a self, from_address: &'a str) -> &'a str {
        self.sender.as_deref().unwrap_or(from_address)
    }

    /// The federated credential Forge (the issuer `forge_issuer`) presents
    /// with `federated_credential` authentication.
    pub fn federated_credential(&self, forge_issuer: &str) -> Option<FederatedCredential> {
        (self.client_authentication == GraphClientAuth::FederatedCredential).then(|| {
            FederatedCredential {
                issuer: forge_issuer.trim_end_matches('/').to_string(),
                subject: forge_core::oidc::assertion::federated_subject(
                    &format!("{MICROSOFT_LOGIN_HOST}/{}/v2.0", self.tenant_id),
                    &self.client_id,
                ),
                audience: forge_core::oidc::assertion::DEFAULT_ASSERTION_AUDIENCE.to_string(),
            }
        })
    }

    fn validate(&mut self, require_secrets: bool) -> Result<(), InvalidSettings> {
        self.tenant_id = self.tenant_id.trim().to_string();
        let tenant_ok = !self.tenant_id.is_empty()
            && self.tenant_id.len() <= 253
            && self
                .tenant_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
        if !tenant_ok {
            return Err(invalid(
                "transport.tenant_id must be the tenant's id or one of its domains, such as \
                 contoso.onmicrosoft.com",
            ));
        }
        self.client_id = self.client_id.trim().to_string();
        if self.client_id.is_empty()
            || self.client_id.len() > 64
            || !self
                .client_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(invalid(
                "transport.client_id must be the app registration's application (client) id",
            ));
        }
        self.sender = blank_to_none(self.sender.take());
        if let Some(sender) = &self.sender {
            let object_id =
                sender.len() == 36 && sender.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
            if !object_id {
                parse_address("transport.sender", sender)?;
            }
        }
        match self.client_authentication {
            GraphClientAuth::ClientSecret => {
                if self.client_secret.as_deref() == Some("") {
                    self.client_secret = None;
                }
                if let Some(secret) = &self.client_secret {
                    if secret.len() > MAX_SECRET_BYTES {
                        return Err(invalid(format!(
                            "transport.client_secret must be at most {MAX_SECRET_BYTES} bytes"
                        )));
                    }
                }
                if require_secrets && self.client_secret.is_none() {
                    return Err(invalid(
                        "transport.client_secret is required with client_secret authentication",
                    ));
                }
            }
            // Nothing sends a secret: it is not kept (switching back takes a
            // new one).
            GraphClientAuth::FederatedCredential => self.client_secret = None,
        }
        Ok(())
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
            TransportConfig::MicrosoftGraph(graph) => graph.validate(require_secrets)?,
            // Nothing is required up front: registration and authorization
            // follow the save.
            TransportConfig::SmtpOauth(oauth) => oauth.validate()?,
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
/// host and username, the Graph tenant and client id) are unchanged.
/// Otherwise the secret must be entered again, which validation then
/// reports.
///
/// An `smtp_oauth` transport takes Forge's OAuth state (the registration and
/// the authorization) from the stored settings only, never from `incoming`
/// ([`merge_oauth_state`]).
pub fn merge_secrets(stored: Option<&EmailConfig>, mut incoming: EmailConfig) -> EmailConfig {
    match (stored.map(|s| &s.transport), &mut incoming.transport) {
        (Some(TransportConfig::Smtp(old)), TransportConfig::Smtp(new)) => {
            let same_party = old.host.trim().eq_ignore_ascii_case(new.host.trim())
                && old.username.as_deref().map(str::trim) == new.username.as_deref().map(str::trim);
            if new.password.as_deref().is_none_or(str::is_empty) && same_party {
                new.password = old.password.clone();
            }
        }
        (Some(TransportConfig::MicrosoftGraph(old)), TransportConfig::MicrosoftGraph(new)) => {
            let same_app = old
                .tenant_id
                .trim()
                .eq_ignore_ascii_case(new.tenant_id.trim())
                && old
                    .client_id
                    .trim()
                    .eq_ignore_ascii_case(new.client_id.trim());
            if new.client_secret.as_deref().is_none_or(str::is_empty) && same_app {
                new.client_secret = old.client_secret.clone();
            }
        }
        (Some(TransportConfig::SmtpOauth(old)), TransportConfig::SmtpOauth(new)) => {
            merge_oauth_state(old, new);
        }
        // The OAuth state is Forge's: an update never sets it.
        (_, TransportConfig::SmtpOauth(new)) => {
            new.registered = false;
            new.registration_client_uri = None;
            new.registration_access_token = None;
            new.grant = None;
            new.refresh_token = None;
            new.authorization_error = None;
        }
        _ => {}
    }
    incoming
}

/// Carry Forge's OAuth state over a save: the registered client while the
/// issuer is the same (and the update names no other client), and the
/// authorization while the client and the mailbox are the same too. What an
/// update cannot set (the registration, the grant, the refresh token) is
/// never taken from it.
fn merge_oauth_state(old: &SmtpOauthConfig, new: &mut SmtpOauthConfig) {
    let same_issuer =
        old.issuer.trim().trim_end_matches('/') == new.issuer.trim().trim_end_matches('/');
    let named_client = new
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    let same_client = same_issuer
        && match named_client {
            None => true,
            Some(client) => old.client_id.as_deref() == Some(client),
        };
    new.registered = false;
    new.registration_client_uri = None;
    new.registration_access_token = None;
    new.grant = None;
    new.refresh_token = None;
    new.authorization_error = None;
    if !same_client {
        return;
    }
    new.client_id = old.client_id.clone();
    new.registered = old.registered;
    if new.client_secret.as_deref().is_none_or(str::is_empty) {
        new.client_secret = old.client_secret.clone();
    }
    new.registration_client_uri = old.registration_client_uri.clone();
    new.registration_access_token = old.registration_access_token.clone();
    let same_mailbox = old.username.trim() == new.username.trim()
        && old.scope.as_deref().map(str::trim) == new.scope.as_deref().map(str::trim);
    if same_mailbox {
        new.grant = old.grant;
        new.refresh_token = old.refresh_token.clone();
        new.authorization_error = old.authorization_error.clone();
    } else if old.grant == Some(OauthGrant::ClientCredentials) {
        new.grant = old.grant;
    }
}

/// Parse an email address for the setting `field`.
fn parse_address(field: &str, raw: &str) -> Result<Address, InvalidSettings> {
    raw.parse::<Address>().map_err(|_| {
        invalid(format!(
            "{field} must be an email address such as forge@example.com"
        ))
    })
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
        let TransportConfig::Smtp(smtp) = &config.transport else {
            panic!("an SMTP transport");
        };
        assert_eq!(smtp.port(), 587);
        assert_eq!(smtp.username, None);
    }

    #[test]
    fn plain_smtp_only_to_a_loopback_relay() {
        for host in ["localhost", "127.0.0.1", "::1", "LOCALHOST"] {
            assert!(
                smtp(json!({"host": host, "tls": "none"}))
                    .validated(true)
                    .is_ok(),
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
        let err = smtp(json!({"username": "forge"}))
            .validated(true)
            .unwrap_err();
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
        for host in [
            "smtp://example.com",
            "example.com:25",
            "",
            "a b",
            "-x.example",
        ] {
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

    fn smtp_of(config: &EmailConfig) -> &SmtpConfig {
        match &config.transport {
            TransportConfig::Smtp(smtp) => smtp,
            other => panic!("not SMTP: {other:?}"),
        }
    }

    fn graph(extra: JsonValue) -> EmailConfig {
        let mut transport = json!({
            "kind": "microsoft_graph",
            "tenant_id": "contoso.onmicrosoft.com",
            "client_id": "00000000-1111-2222-3333-444444444444",
        });
        transport
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(json!({
            "from_address": "forge@contoso.com",
            "transport": transport,
        }))
        .unwrap()
    }

    fn graph_of(config: &EmailConfig) -> &GraphConfig {
        match &config.transport {
            TransportConfig::MicrosoftGraph(graph) => graph,
            other => panic!("not Graph: {other:?}"),
        }
    }

    #[test]
    fn graph_needs_a_secret_unless_it_is_federated() {
        let err = graph(json!({})).validated(true).unwrap_err();
        assert!(
            err.0.contains("transport.client_secret is required"),
            "{err}"
        );
        let config = graph(json!({"client_secret": "s3cret"}))
            .validated(true)
            .unwrap();
        assert_eq!(
            graph_of(&config).sender_mailbox("forge@contoso.com"),
            "forge@contoso.com"
        );

        let federated = graph(json!({
            "client_authentication": "federated_credential",
            "client_secret": "typed before switching",
            "sender": " 9a8b7c6d-0000-1111-2222-333344445555 ",
        }))
        .validated(true)
        .unwrap();
        let g = graph_of(&federated);
        assert_eq!(g.client_secret, None, "a federated app keeps no secret");
        assert_eq!(
            g.sender.as_deref(),
            Some("9a8b7c6d-0000-1111-2222-333344445555")
        );
        assert_eq!(
            g.federated_credential("https://forge.example.com/"),
            Some(FederatedCredential {
                issuer: "https://forge.example.com".into(),
                subject: "00000000-1111-2222-3333-444444444444@https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0".into(),
                audience: "api://AzureADTokenExchange".into(),
            })
        );
        assert_eq!(
            graph_of(
                &graph(json!({"client_secret": "x"}))
                    .validated(true)
                    .unwrap()
            )
            .federated_credential("https://forge.example.com"),
            None
        );
    }

    #[test]
    fn graph_ids_and_the_sender_are_checked() {
        for (extra, field) in [
            (json!({"tenant_id": "contoso/../x"}), "transport.tenant_id"),
            (json!({"tenant_id": " "}), "transport.tenant_id"),
            (json!({"client_id": "not an id"}), "transport.client_id"),
            (json!({"sender": "not a mailbox"}), "transport.sender"),
        ] {
            let mut extra = extra;
            extra["client_secret"] = json!("s");
            let err = graph(extra).validated(true).unwrap_err();
            assert!(err.0.contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn the_graph_secret_is_redacted_and_kept_for_the_same_app() {
        let stored = graph(json!({"client_secret": "old"}));
        let doc = stored.redacted();
        assert_eq!(doc["transport"]["client_secret_set"], json!(true));
        assert!(doc["transport"].get("client_secret").is_none());

        let kept = merge_secrets(Some(&stored), graph(json!({"sender": "ops@contoso.com"})));
        assert_eq!(graph_of(&kept).client_secret.as_deref(), Some("old"));
        for changed in [
            json!({"tenant_id": "fabrikam.onmicrosoft.com"}),
            json!({"client_id": "55555555-1111-2222-3333-444444444444"}),
        ] {
            let merged = merge_secrets(Some(&stored), graph(changed.clone()));
            assert_eq!(graph_of(&merged).client_secret, None, "{changed}");
        }
        // Another transport keeps nothing of the old one.
        let switched = merge_secrets(Some(&stored), smtp(json!({"username": "forge"})));
        assert_eq!(smtp_of(&switched).password, None);
    }

    #[test]
    fn an_omitted_password_is_kept_for_the_same_host_and_username() {
        let stored = smtp(json!({"username": "forge", "password": "old"}));
        let kept = merge_secrets(
            Some(&stored),
            smtp(json!({"username": "forge", "port": 2525})),
        );
        let s = smtp_of(&kept);
        assert_eq!(s.password.as_deref(), Some("old"));

        let replaced = merge_secrets(
            Some(&stored),
            smtp(json!({"username": "forge", "password": "new"})),
        );
        let s = smtp_of(&replaced);
        assert_eq!(s.password.as_deref(), Some("new"));

        for changed in [
            json!({"username": "other"}),
            json!({"username": "forge", "host": "mail.example.org"}),
        ] {
            let merged = merge_secrets(Some(&stored), smtp(changed.clone()));
            let s = smtp_of(&merged);
            assert_eq!(s.password, None, "{changed}");
            assert!(merged.validated(true).is_err(), "{changed}");
        }
    }

    fn oauth(extra: JsonValue) -> EmailConfig {
        let mut transport = json!({
            "kind": "smtp_oauth",
            "host": "mail.example.com",
            "tls": "starttls",
            "issuer": "https://mail.example.com",
            "username": "forge@example.com",
        });
        transport
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(json!({"from_address": "forge@example.com", "transport": transport}))
            .unwrap()
    }

    fn oauth_of(config: &EmailConfig) -> &SmtpOauthConfig {
        match &config.transport {
            TransportConfig::SmtpOauth(o) => o,
            other => panic!("not smtp_oauth: {other:?}"),
        }
    }

    /// What Forge stored after registering and an authorization.
    fn authorized() -> EmailConfig {
        oauth(json!({
            "scope": "smtp",
            "client_id": "forge-client",
            "client_secret": "client-s3cret",
            "registered": true,
            "registration_client_uri": "https://mail.example.com/register/forge-client",
            "registration_access_token": "reg-token",
            "grant": "refresh_token",
            "refresh_token": "refresh-1",
        }))
    }

    #[test]
    fn oauth_settings_need_no_secret_but_a_safe_issuer_and_connection() {
        let config = oauth(json!({"issuer": " https://mail.example.com/ "}))
            .validated(true)
            .unwrap();
        assert_eq!(oauth_of(&config).issuer, "https://mail.example.com");
        assert_eq!(oauth_of(&config).port(), 587);
        assert!(!oauth_of(&config).authorized());
        assert!(oauth(json!({"issuer": "http://127.0.0.1:8080"}))
            .validated(true)
            .is_ok());
        assert!(oauth(json!({"host": "127.0.0.1", "tls": "none"}))
            .validated(true)
            .is_ok());
        for bad in [
            json!({"issuer": "http://mail.example.com"}),
            json!({"issuer": "mail.example.com"}),
            json!({"issuer": "https://mail.example.com/#x"}),
            json!({"tls": "none"}),
            json!({"username": ""}),
            json!({"client_secret": "s"}),
            json!({"scope": "smtp\nx"}),
        ] {
            assert!(oauth(bad.clone()).validated(true).is_err(), "{bad}");
        }
    }

    #[test]
    fn oauth_secrets_are_redacted() {
        let view = authorized().redacted();
        let transport = &view["transport"];
        for key in [
            "client_secret",
            "registration_access_token",
            "refresh_token",
        ] {
            assert!(transport.get(key).is_none(), "{key}");
            assert_eq!(transport[format!("{key}_set")], json!(true), "{key}");
        }
        assert_eq!(transport["client_id"], "forge-client");
        assert_eq!(transport["grant"], "refresh_token");
    }

    #[test]
    fn a_save_never_sets_forges_oauth_state() {
        let planted = json!({
            "registered": true,
            "registration_client_uri": "https://evil.example/r",
            "registration_access_token": "x",
            "grant": "client_credentials",
            "refresh_token": "x",
            "authorization_error": "x",
        });
        for stored in [None, Some(smtp(json!({})))] {
            let merged = merge_secrets(stored.as_ref(), oauth(planted.clone()));
            let o = oauth_of(&merged);
            assert!(!o.registered);
            assert_eq!(o.registration_client_uri, None);
            assert_eq!(o.registration_access_token, None);
            assert_eq!(o.grant, None);
            assert_eq!(o.refresh_token, None);
            assert_eq!(o.authorization_error, None);
        }
        // Over stored state, the stored state wins.
        let merged = merge_secrets(Some(&authorized()), oauth(planted));
        assert_eq!(oauth_of(&merged).refresh_token, None, "another scope");
        let merged = merge_secrets(Some(&authorized()), oauth(planted_with_scope()));
        let o = oauth_of(&merged);
        assert_eq!(o.refresh_token.as_deref(), Some("refresh-1"));
        assert_eq!(o.grant, Some(OauthGrant::RefreshToken));
        assert_eq!(o.authorization_error, None);
        assert_eq!(
            o.registration_client_uri.as_deref(),
            Some("https://mail.example.com/register/forge-client")
        );
    }

    fn planted_with_scope() -> JsonValue {
        json!({"scope": "smtp", "grant": "client_credentials", "refresh_token": "x"})
    }

    #[test]
    fn the_oauth_state_is_kept_for_the_same_issuer_client_and_mailbox() {
        let stored = authorized();
        // The same: everything kept, the client and its secret too.
        let merged = merge_secrets(Some(&stored), oauth(json!({"scope": "smtp", "port": 2525})));
        let o = oauth_of(&merged);
        assert_eq!(o.client_id.as_deref(), Some("forge-client"));
        assert_eq!(o.client_secret.as_deref(), Some("client-s3cret"));
        assert_eq!(o.registration_access_token.as_deref(), Some("reg-token"));
        assert!(o.registered);
        assert!(o.authorized());

        // Another mailbox or scope: the client stays, the authorization goes.
        for changed in [
            json!({"scope": "smtp", "username": "other@example.com"}),
            json!({"scope": "smtp submission"}),
        ] {
            let merged = merge_secrets(Some(&stored), oauth(changed.clone()));
            let o = oauth_of(&merged);
            assert_eq!(o.client_id.as_deref(), Some("forge-client"), "{changed}");
            assert_eq!(o.refresh_token, None, "{changed}");
            assert_eq!(o.grant, None, "{changed}");
        }

        // Another issuer, or another client named: nothing is kept.
        for changed in [
            json!({"scope": "smtp", "issuer": "https://idp.example.com"}),
            json!({"scope": "smtp", "client_id": "manual", "client_secret": "m"}),
        ] {
            let merged = merge_secrets(Some(&stored), oauth(changed.clone()));
            let o = oauth_of(&merged);
            assert_ne!(o.client_id.as_deref(), Some("forge-client"), "{changed}");
            assert!(!o.registered, "{changed}");
            assert_eq!(o.registration_client_uri, None, "{changed}");
            assert_eq!(o.registration_access_token, None, "{changed}");
            assert_eq!(o.refresh_token, None, "{changed}");
        }

        // The client credentials grant needs no mailbox: kept across one.
        let cc = oauth(json!({
            "client_id": "forge-client",
            "client_secret": "client-s3cret",
            "grant": "client_credentials",
        }));
        let merged = merge_secrets(Some(&cc), oauth(json!({"username": "other@example.com"})));
        assert_eq!(oauth_of(&merged).grant, Some(OauthGrant::ClientCredentials));
    }
}
