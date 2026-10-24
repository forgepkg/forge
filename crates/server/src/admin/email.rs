//! The email service's settings (#319), **Admin → Settings → Email**:
//!
//! * `GET /admin/settings/email` — the settings without their secrets
//!   (`{"configured": false}` before any), the outcome of the last send.
//! * `PUT /admin/settings/email` — store them. A secret the body omits keeps
//!   the stored one, unless the transport or a field the secret belongs to
//!   changed. Applies on this instance at once, on the others within
//!   `auth.realm_cache_ttl_seconds`.
//! * `DELETE /admin/settings/email` — remove them: Forge sends no email.
//! * `POST /admin/settings/email/test` — send a test message to `to`, or to
//!   the calling admin's address (their UPN); a failure answers **502** with
//!   the server's error text.
//!
//! A Microsoft Graph app that authenticates with a federated credential
//! (#320) is shown with the issuer, subject and audience to register on the
//! app (`federated_credential`), and saving it creates Forge's issuer keys
//! first: the credential can be set up before the first send.
//!
//! An `smtp_oauth` transport (#321) is shown with the redirect URI to
//! register a client with by hand (`oauth_redirect_uri`); registering Forge
//! and authorizing it are [`super::email_oauth`]'s.
//!
//! The settings exist here only: there is no `forge.toml` section and no
//! `FORGE_*` variable for them.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::Extension;
use forge_core::auth::principal::Principal;
use forge_db::email_settings_dao;
use forge_db::secret_dao::{self, SecretDbError};
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};

use super::db_error;
use crate::email::{
    self, oauth, settings, EmailConfig, GraphClientAuth, Mailer, SendError, StoredEmail,
    TransportConfig,
};
use crate::state::AppState;

/// `PUT /admin/settings/email` body: [`EmailConfig`] and whether email is on.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutEmailSettings {
    /// `false` keeps the settings but sends nothing.
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub from_address: String,
    #[serde(default)]
    pub from_name: Option<String>,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default = "default_ttl")]
    pub invitation_ttl_hours: u32,
    pub transport: TransportConfig,
}

fn default_true() -> bool {
    true
}

fn default_ttl() -> u32 {
    settings::DEFAULT_INVITATION_TTL_HOURS
}

/// `POST /admin/settings/email/test` body.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestEmail {
    /// The recipient; the calling admin's address when absent.
    #[serde(default)]
    pub to: Option<String>,
}

/// The API view of the stored settings: secrets as `<key>_set` markers, a
/// federated Graph app's credential as forge presents it, and the redirect
/// URI an `smtp_oauth` client is registered with.
pub(super) fn view(stored: &StoredEmail, mailer: &Mailer) -> JsonValue {
    let mut doc = stored.config.redacted();
    if let JsonValue::Object(map) = &mut doc {
        map.insert("configured".into(), json!(true));
        match &stored.config.transport {
            TransportConfig::MicrosoftGraph(graph) => {
                if let Some(credential) = graph.federated_credential(mailer.forge_issuer()) {
                    map.insert("federated_credential".into(), json!(credential));
                }
            }
            TransportConfig::SmtpOauth(_) => {
                map.insert(
                    "oauth_redirect_uri".into(),
                    json!(mailer.oauth_redirect_uri()),
                );
            }
            TransportConfig::Smtp(_) => {}
        }
        map.insert("enabled".into(), json!(stored.row.enabled));
        map.insert(
            "secrets_unreadable".into(),
            json!(stored.secrets_unreadable),
        );
        map.insert(
            "last_failure".into(),
            match &stored.row.last_failure {
                Some(error) => json!({"at": stored.row.last_failure_at, "error": error}),
                None => JsonValue::Null,
            },
        );
        map.insert("last_success_at".into(), json!(stored.row.last_success_at));
        map.insert("updated_at".into(), json!(stored.row.updated_at));
    }
    doc
}

async fn load(state: &AppState) -> Result<Option<StoredEmail>, Response> {
    email::load_stored(&state.pool, &state.envelope)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "email settings unreadable");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        })
}

/// `GET /admin/settings/email`
pub async fn get(State(state): State<AppState>) -> Response {
    match load(&state).await {
        Ok(Some(stored)) => Json(view(&stored, &state.mailer)).into_response(),
        Ok(None) => Json(json!({"configured": false})).into_response(),
        Err(resp) => resp,
    }
}

/// `PUT /admin/settings/email`
pub async fn put(State(state): State<AppState>, Json(body): Json<PutEmailSettings>) -> Response {
    let stored = match load(&state).await {
        Ok(stored) => stored,
        Err(resp) => return resp,
    };
    let incoming = EmailConfig {
        from_address: body.from_address,
        from_name: body.from_name,
        reply_to: body.reply_to,
        invitation_ttl_hours: body.invitation_ttl_hours,
        transport: body.transport,
    };
    // Secrets are write-only: an omitted one is kept from the stored
    // settings, unless they do not decrypt (then it must be entered again).
    let keep_from = stored
        .as_ref()
        .filter(|s| !s.secrets_unreadable)
        .map(|s| &s.config);
    let config = match settings::merge_secrets(keep_from, incoming).validated(true) {
        Ok(config) => config,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // A federated Graph app trusts forge's issuer keys: they must be
    // published before its federated credential can be set up.
    if let TransportConfig::MicrosoftGraph(graph) = &config.transport {
        if graph.client_authentication == GraphClientAuth::FederatedCredential {
            if let Err(error) = state.assertion_issuer.ensure().await {
                tracing::error!(error = %format!("{error:#}"), "cannot create the issuer keys");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the issuer keys a federated credential needs could not be created; \
                     try again",
                )
                    .into_response();
            }
        }
    }
    let doc = match serde_json::to_value(&config) {
        Ok(doc) => doc,
        Err(e) => {
            tracing::error!(error = %e, "email settings did not serialize");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let row =
        match secret_dao::store_email_settings(&state.pool, &state.envelope, body.enabled, &doc)
            .await
        {
            Ok(row) => row,
            Err(SecretDbError::Db(e)) => return db_error(e),
            Err(e) => {
                tracing::error!(error = %e, "email settings secret encryption failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "email settings secret encryption failed",
                )
                    .into_response();
            }
        };
    state.mailer.invalidate().await;
    // The OAuth client and authorization of the settings before, when these
    // no longer use them.
    let mut warning = None;
    if let Some(TransportConfig::SmtpOauth(old)) = stored.as_ref().map(|s| &s.config.transport) {
        let kept = match &config.transport {
            TransportConfig::SmtpOauth(new) => Some(new),
            _ => None,
        };
        if old.registered && kept.is_none_or(|new| new.client_id != old.client_id) {
            warning = super::email_oauth::release_registration(&state, old).await;
        }
        if kept.is_none_or(|new| !oauth::same_authorization(old, new)) {
            super::email_oauth::drop_flows(&state).await;
        }
    }
    tracing::info!(
        transport = config.transport.kind(),
        enabled = row.enabled,
        "email settings changed"
    );
    let mut doc = view(
        &StoredEmail {
            row,
            config,
            secrets_unreadable: false,
        },
        &state.mailer,
    );
    if let Some(warning) = warning {
        doc["warning"] = json!(warning);
    }
    Json(doc).into_response()
}

/// `DELETE /admin/settings/email`: also deletes the OAuth client Forge
/// registered for them.
pub async fn delete(State(state): State<AppState>) -> Response {
    let before = match load(&state).await {
        Ok(stored) => stored,
        Err(resp) => return resp,
    };
    let result = email_settings_dao::delete(&state.pool).await;
    state.mailer.invalidate().await;
    if result.is_ok() {
        if let Some(TransportConfig::SmtpOauth(old)) = before.as_ref().map(|s| &s.config.transport)
        {
            if let Some(warning) = super::email_oauth::release_registration(&state, old).await {
                tracing::warn!(%warning, "email settings removed with Forge's OAuth client");
            }
        }
        super::email_oauth::drop_flows(&state).await;
    }
    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/settings/email/test`
pub async fn test(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    body: Option<Json<TestEmail>>,
) -> Response {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let stored = match load(&state).await {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return (StatusCode::CONFLICT, "no email service is configured").into_response()
        }
        Err(resp) => return resp,
    };
    if stored.secrets_unreadable {
        return (
            StatusCode::CONFLICT,
            "the stored email secrets do not decrypt; enter them again",
        )
            .into_response();
    }
    let to = match body
        .to
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        Some(to) => to,
        None => match caller_address(&state, &principal).await {
            Ok(Some(to)) => to,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "give a recipient (\"to\"): your username is not an email address",
                )
                    .into_response()
            }
            Err(resp) => return resp,
        },
    };
    // The settings as stored, even while turned off: the admin is checking
    // them before turning them on.
    let config = match stored.config.validated(true) {
        Ok(config) => config,
        Err(e) => return (StatusCode::CONFLICT, e.to_string()).into_response(),
    };
    let content = email::templates::test_message(state.mailer.public_base_url());
    match state.mailer.send_with(&config, "test", &to, content).await {
        Ok(()) => Json(json!({"sent": true, "to": to})).into_response(),
        Err(SendError::BadRecipient(_)) => (
            StatusCode::BAD_REQUEST,
            format!("{to:?} is not an email address"),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"sent": false, "to": to, "error": e.to_string()})),
        )
            .into_response(),
    }
}

/// The calling admin's address: their username when it is a UPN.
async fn caller_address(
    state: &AppState,
    principal: &Principal,
) -> Result<Option<String>, Response> {
    let Principal::User { user_id, .. } = principal else {
        return Ok(None);
    };
    match forge_db::user_dao::find_user_by_id(&state.pool, *user_id).await {
        Ok(Some(user)) if forge_core::auth::is_upn(&user.username) => Ok(Some(user.username)),
        Ok(_) => Ok(None),
        Err(e) => Err(db_error(e)),
    }
}
