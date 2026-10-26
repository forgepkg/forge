//! Outgoing email (#319): the email service.
//!
//! The settings live in the database only (`email_settings`),
//! written on **Admin → Settings → Email** (`/admin/settings/email`): there is
//! no `forge.toml` section and no `FORGE_*` variable, so they can change while
//! the server runs and every instance uses the same ones. Their secrets are
//! sealed at rest like realm secrets ([`forge_db::secret_dao`]).
//!
//! [`Mailer`] is each instance's sender. It keeps a snapshot of the settings
//! like the realm snapshot ([`crate::auth::RealmAuth`]): a write through the
//! admin API drops it at once ([`Mailer::invalidate`]), and other instances
//! converge within `auth.realm_cache_ttl_seconds`.
//!
//! Every send is logged with its purpose, the recipient's domain and the
//! outcome; never the message, its links or tokens, or a secret. The outcome
//! is also kept on the settings row for the settings page.

mod graph;
pub(crate) mod oauth;
pub mod settings;
mod smtp;
pub mod templates;

use std::sync::Arc;
use std::time::{Duration, Instant};

use forge_crypto::service::EnvelopeService;
use forge_db::email_settings_dao::{self, EmailSettingsRow};
use forge_db::secret_dao::{self, SecretDbError};
use lettre::message::{Mailbox, MultiPart};
use lettre::{Address, Message};
use sqlx::PgPool;

pub use graph::MicrosoftEndpoints;
pub use settings::{
    EmailConfig, FederatedCredential, GraphClientAuth, GraphConfig, InvalidSettings, OauthGrant,
    SmtpConfig, SmtpOauthConfig, SmtpTls, TransportConfig,
};
pub use templates::Content;

use crate::auth::AssertionIssuer;
use crate::config::Config;

/// How long one send may take in all.
const SEND_TIMEOUT: Duration = Duration::from_secs(90);

/// Why a message was not sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// No email service is configured, or it is turned off.
    #[error("no email service is configured")]
    NotConfigured,
    /// The settings could not be read (the database, or secrets that do not
    /// decrypt).
    #[error("the email settings cannot be read: {0}")]
    Unavailable(String),
    /// The recipient is not an email address.
    #[error("{0:?} is not an email address")]
    BadRecipient(String),
    /// The transport refused or failed: its error, as text for the
    /// administrator.
    #[error("{0}")]
    Failed(String),
}

/// The email settings as stored, read for the admin API.
#[derive(Debug, Clone)]
pub struct StoredEmail {
    /// The row as stored.
    pub row: EmailSettingsRow,
    /// The logical document (secrets merged in). When the stored secrets do
    /// not decrypt it is the row's config without them, and the admin must
    /// enter them again.
    pub config: EmailConfig,
    /// Whether the stored secrets could not be read.
    pub secrets_unreadable: bool,
}

/// Read the stored email settings, `None` when there are none.
pub async fn load_stored(
    pool: &PgPool,
    envelope: &EnvelopeService,
) -> Result<Option<StoredEmail>, String> {
    let Some(row) = email_settings_dao::get(pool)
        .await
        .map_err(|e| format!("database error: {e}"))?
    else {
        return Ok(None);
    };
    let (doc, secrets_unreadable) = match secret_dao::email_config(envelope, &row).await {
        Ok(doc) => (doc, false),
        Err(SecretDbError::Db(e)) => return Err(format!("database error: {e}")),
        Err(e) => {
            tracing::warn!(error = %e, "stored email settings secrets are unreadable");
            (row.config.clone(), true)
        }
    };
    let config: EmailConfig = serde_json::from_value(doc)
        .map_err(|e| format!("the stored email settings are malformed: {e}"))?;
    Ok(Some(StoredEmail {
        row,
        config,
        secrets_unreadable,
    }))
}

/// A snapshot of the settings in use: `None` when email is not configured
/// or turned off.
struct Snapshot {
    built_at: Instant,
    active: Option<Arc<EmailConfig>>,
}

/// This instance's sender (see the [module docs](self)).
pub struct Mailer {
    pool: PgPool,
    envelope: Arc<EnvelopeService>,
    public_base_url: String,
    ttl: Duration,
    snapshot: tokio::sync::RwLock<Option<Snapshot>>,
    graph: graph::GraphTransport,
    oauth: oauth::OauthTokens,
}

impl Mailer {
    /// A sender over the settings in `pool`, opening their secrets with
    /// `envelope`; a federated Graph app signs its client assertions with
    /// `issuer`.
    pub fn new(
        pool: PgPool,
        envelope: Arc<EnvelopeService>,
        issuer: AssertionIssuer,
        config: &Config,
    ) -> Self {
        Mailer {
            public_base_url: config.public_base_url(),
            ttl: Duration::from_secs(config.auth.realm_cache_ttl_seconds.max(1)),
            snapshot: tokio::sync::RwLock::new(None),
            graph: graph::GraphTransport::new(issuer),
            oauth: oauth::OauthTokens::new(pool.clone(), envelope.clone()),
            pool,
            envelope,
        }
    }

    /// `server.public_base_url`, which links in messages start with.
    pub fn public_base_url(&self) -> &str {
        &self.public_base_url
    }

    /// The redirect URI of the `smtp_oauth` authorization code flow.
    pub fn oauth_redirect_uri(&self) -> String {
        format!("{}{}", self.public_base_url, oauth::CALLBACK_PATH)
    }

    /// Forge's issuer URL, which a federated Graph app's credential names.
    pub fn forge_issuer(&self) -> &str {
        self.graph.issuer()
    }

    /// Send Graph mail through `endpoints` instead of Microsoft's: for tests
    /// against mock servers. There is no setting for it.
    #[doc(hidden)]
    pub fn use_microsoft_endpoints(&self, endpoints: MicrosoftEndpoints) {
        self.graph.set_endpoints(endpoints);
    }

    /// The OAuth client side of the `smtp_oauth` transport.
    pub(crate) fn oauth(&self) -> &oauth::OauthTokens {
        &self.oauth
    }

    /// Drop the snapshot (after an admin write), so the next send reads the
    /// settings again, and the OAuth tokens of the settings before.
    pub async fn invalidate(&self) {
        *self.snapshot.write().await = None;
        self.oauth.clear().await;
    }

    /// The settings in use, `None` when email is not configured or turned
    /// off.
    pub async fn active(&self) -> Result<Option<Arc<EmailConfig>>, SendError> {
        if let Some(s) = self.snapshot.read().await.as_ref() {
            if s.built_at.elapsed() < self.ttl {
                return Ok(s.active.clone());
            }
        }
        let mut slot = self.snapshot.write().await;
        if let Some(s) = slot.as_ref() {
            if s.built_at.elapsed() < self.ttl {
                return Ok(s.active.clone());
            }
        }
        let active = match load_stored(&self.pool, &self.envelope)
            .await
            .map_err(SendError::Unavailable)?
        {
            Some(stored) if stored.row.enabled => {
                if stored.secrets_unreadable {
                    return Err(SendError::Unavailable(
                        "the stored secrets do not decrypt; enter them again on the email \
                         settings page"
                            .to_string(),
                    ));
                }
                let config = stored
                    .config
                    .validated(true)
                    .map_err(|e| SendError::Unavailable(e.to_string()))?;
                Some(Arc::new(config))
            }
            _ => None,
        };
        *slot = Some(Snapshot {
            built_at: Instant::now(),
            active: active.clone(),
        });
        Ok(active)
    }

    /// How long an invitation link stays valid, in hours: the stored
    /// settings' lifetime, whether or not sending is on, else the default.
    pub async fn invitation_ttl_hours(&self) -> u32 {
        if let Ok(Some(config)) = self.active().await {
            return config.invitation_ttl_hours;
        }
        match load_stored(&self.pool, &self.envelope).await {
            Ok(Some(stored)) => stored.config.invitation_ttl_hours,
            _ => settings::DEFAULT_INVITATION_TTL_HOURS,
        }
    }

    /// Whether an email service is configured and turned on.
    pub async fn is_configured(&self) -> bool {
        matches!(self.active().await, Ok(Some(_)))
    }

    /// Send `content` to `to` with the settings in use. `purpose` names the
    /// message in the log (`test`, `invitation`, …).
    pub async fn send(
        &self,
        purpose: &'static str,
        to: &str,
        content: Content,
    ) -> Result<(), SendError> {
        let Some(config) = self.active().await? else {
            return Err(SendError::NotConfigured);
        };
        self.send_with(&config, purpose, to, content).await
    }

    /// Send `content` to `to` with `config` (the test send uses the stored
    /// settings as they are, not the snapshot). Records the outcome on the
    /// settings row.
    pub async fn send_with(
        &self,
        config: &EmailConfig,
        purpose: &'static str,
        to: &str,
        content: Content,
    ) -> Result<(), SendError> {
        let recipient: Address = to
            .trim()
            .parse()
            .map_err(|_| SendError::BadRecipient(to.to_string()))?;
        let domain = recipient.domain().to_string();
        let result =
            match tokio::time::timeout(SEND_TIMEOUT, self.transmit(config, recipient, content))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(format!(
                    "the send did not finish within {} seconds",
                    SEND_TIMEOUT.as_secs()
                )),
            };
        match result {
            Ok(()) => {
                tracing::info!(
                    purpose,
                    recipient_domain = %domain,
                    transport = config.transport.kind(),
                    outcome = "sent",
                    "email sent"
                );
                if let Err(e) = email_settings_dao::record_success(&self.pool).await {
                    tracing::warn!(error = %e, "email send outcome not recorded");
                }
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    purpose,
                    recipient_domain = %domain,
                    transport = config.transport.kind(),
                    outcome = "failed",
                    %error,
                    "email not sent"
                );
                if let Err(e) = email_settings_dao::record_failure(&self.pool, &error).await {
                    tracing::warn!(error = %e, "email send outcome not recorded");
                }
                Err(SendError::Failed(error))
            }
        }
    }

    /// Hand the message to the configured transport.
    async fn transmit(
        &self,
        config: &EmailConfig,
        to: Address,
        content: Content,
    ) -> Result<(), String> {
        match &config.transport {
            TransportConfig::Smtp(smtp_config) => {
                let message = build_message(config, Mailbox::new(None, to), content)?;
                smtp::send(smtp_config, message).await
            }
            TransportConfig::MicrosoftGraph(graph_config) => {
                self.graph.send(config, graph_config, &to, content).await
            }
            TransportConfig::SmtpOauth(oauth_config) => {
                let message = build_message(config, Mailbox::new(None, to), content)?;
                let token = self
                    .oauth
                    .access_token(oauth_config)
                    .await
                    .map_err(|e| e.to_string())?;
                match smtp::send_oauth(oauth_config, &token, message).await {
                    Ok(()) => Ok(()),
                    // The next send gets a fresh token.
                    Err(smtp::OauthSendError::TokenRefused(why)) => {
                        self.oauth.forget(oauth_config).await;
                        Err(why)
                    }
                    Err(smtp::OauthSendError::Failed(why)) => Err(why),
                }
            }
        }
    }
}

/// The message: `From`, optional `Reply-To`, `To`, the subject, and the text
/// and HTML bodies as alternatives.
fn build_message(config: &EmailConfig, to: Mailbox, content: Content) -> Result<Message, String> {
    let mut builder = Message::builder()
        .from(config.from_mailbox().map_err(|e| e.to_string())?)
        .to(to)
        .subject(content.subject);
    if let Some(reply_to) = config.reply_to_mailbox().map_err(|e| e.to_string())? {
        builder = builder.reply_to(reply_to);
    }
    builder
        .multipart(MultiPart::alternative_plain_html(
            content.text,
            content.html,
        ))
        .map_err(|e| format!("the message could not be built: {e}"))
}
