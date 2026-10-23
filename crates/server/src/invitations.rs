//! Inviting users (#322): an administrator creates a local account without a
//! password (`POST /admin/users`), and Forge emails its user a link with
//! which they choose it themselves (`/invite`, `POST
//! /auth/invitations/accept`).
//!
//! * The token is 256 random bits; only its SHA-256 is stored
//!   ([`forge_db::invitation_dao`]). It is never logged.
//! * The link is `{public_base_url}/invite#<token>`: the fragment keeps the
//!   token out of server and proxy logs and out of `Referer`.
//! * It works once, until the lifetime set on the email settings page
//!   (`invitation_ttl_hours`, 72 hours unless set). A new invitation
//!   replaces the previous one; deleting or deactivating the account revokes
//!   it.
//! * Without an email service, or when the send fails, the link is handed to
//!   the administrator instead ([`Issued::link`]), once.

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use forge_db::invitation_dao;
use forge_db::model::AppUser;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::email;
use crate::state::AppState;

/// The fewest characters a password chosen from an invitation has.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// The most bytes it has.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// The one answer for a token that is unknown, used, expired, replaced or
/// revoked: it does not say which, nor whose.
pub const INVALID_INVITATION: &str =
    "This invitation is invalid or has expired; ask your administrator for a new one.";

/// A fresh token: 256 random bits, URL-safe base64.
pub fn new_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The stored form of `token`: its SHA-256, hex.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

/// The link of `token`.
pub fn link(public_base_url: &str, token: &str) -> String {
    format!("{}/invite#{token}", public_base_url.trim_end_matches('/'))
}

/// Whether `password` may be chosen: [`MIN_PASSWORD_CHARS`] characters to
/// [`MAX_PASSWORD_BYTES`] bytes. `Err` says why not.
pub fn check_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "the password must have at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!(
            "the password must have at most {MAX_PASSWORD_BYTES} bytes"
        ));
    }
    Ok(())
}

/// How an invitation reaches its user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// By email, or as a link for the administrator when that cannot be.
    Email,
    /// As a link for the administrator only ("Copy invitation link").
    Link,
}

/// An invitation just made, as the admin API shows it.
#[derive(Debug, Clone, Serialize)]
pub struct Issued {
    /// The address it is for.
    pub email: String,
    pub expires_at: DateTime<Utc>,
    /// Whether the email service took the message.
    pub email_sent: bool,
    /// Why no email went out, when one should have.
    pub error: Option<String>,
    /// The link, when no email carries it: shown once, never stored.
    pub link: Option<String>,
}

/// Make `user`'s invitation for `email` (replacing the previous one) and
/// deliver it. `Ok(None)` when the account is not an active invited one.
pub async fn issue(
    state: &AppState,
    user: &AppUser,
    email: &str,
    created_by: Option<i64>,
    delivery: Delivery,
) -> sqlx::Result<Option<Issued>> {
    let ttl = state.mailer.invitation_ttl_hours().await;
    let expires_at = Utc::now() + Duration::hours(i64::from(ttl));
    let token = new_token();
    let hash = token_hash(&token);
    let Some(made) =
        invitation_dao::put(&state.pool, user.id, &hash, email, expires_at, created_by).await?
    else {
        return Ok(None);
    };
    let link = link(state.mailer.public_base_url(), &token);
    let mut issued = Issued {
        email: made.email.clone(),
        expires_at: made.expires_at,
        email_sent: false,
        error: None,
        link: Some(link.clone()),
    };
    if delivery == Delivery::Email {
        let content = email::templates::invitation(
            state.mailer.public_base_url(),
            &user.username,
            &link,
            made.expires_at,
        );
        match state.mailer.send("invitation", email, content).await {
            Ok(()) => {
                invitation_dao::mark_sent(&state.pool, user.id, &hash).await?;
                issued.email_sent = true;
                issued.link = None;
            }
            Err(e) => issued.error = Some(e.to_string()),
        }
    }
    tracing::info!(
        user_id = user.id,
        email_sent = issued.email_sent,
        expires_at = %made.expires_at,
        "invitation made"
    );
    Ok(Some(issued))
}
