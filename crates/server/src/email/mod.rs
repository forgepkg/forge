//! Outgoing email (#319): the email service.
//!
//! The settings live in the database only (`email_settings`, migration 0043),
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

pub use settings::{EmailConfig, InvalidSettings, SmtpConfig, SmtpTls, TransportConfig};
pub use templates::Content;

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
    envelope: Option<&EnvelopeService>,
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
    envelope: Option<Arc<EnvelopeService>>,
    public_base_url: String,
    ttl: Duration,
    snapshot: tokio::sync::RwLock<Option<Snapshot>>,
}

impl Mailer {
    /// A sender over the settings in `pool`, opening their secrets with
    /// `envelope`.
    pub fn new(pool: PgPool, envelope: Option<Arc<EnvelopeService>>, config: &Config) -> Self {
        Mailer {
            pool,
            envelope,
            public_base_url: config.public_base_url(),
            ttl: Duration::from_secs(config.auth.realm_cache_ttl_seconds.max(1)),
            snapshot: tokio::sync::RwLock::new(None),
        }
    }

    /// `server.public_base_url`, which links in messages start with.
    pub fn public_base_url(&self) -> &str {
        &self.public_base_url
    }

    /// Drop the snapshot (after an admin write), so the next send reads the
    /// settings again.
    pub async fn invalidate(&self) {
        *self.snapshot.write().await = None;
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
        let active = match load_stored(&self.pool, self.envelope.as_deref())
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

    /// Whether an email service is configured and turned on.
    pub async fn is_configured(&self) -> bool {
        matches!(self.active().await, Ok(Some(_)))
    }

    /// Send `content` to `to` with the settings in use. `purpose` names the
    /// message in the log (`test`, `invitation`, …).
    pub async fn send(&self, purpose: &'static str, to: &str, content: Content) -> Result<(), SendError> {
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
        let result = match build_message(config, Mailbox::new(None, recipient), content) {
            Ok(message) => match tokio::time::timeout(SEND_TIMEOUT, transmit(config, message)).await
            {
                Ok(result) => result,
                Err(_) => Err(format!(
                    "the send did not finish within {} seconds",
                    SEND_TIMEOUT.as_secs()
                )),
            },
            Err(e) => Err(e),
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
        .multipart(MultiPart::alternative_plain_html(content.text, content.html))
        .map_err(|e| format!("the message could not be built: {e}"))
}

/// Hand `message` to the configured transport.
async fn transmit(config: &EmailConfig, message: Message) -> Result<(), String> {
    match &config.transport {
        TransportConfig::Smtp(smtp_config) => smtp::send(smtp_config, message).await,
    }
}
