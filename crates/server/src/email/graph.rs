//! The Microsoft Graph transport (#320): Forge signs in as an Entra app
//! registration with the OAuth client credentials grant and sends with
//! `POST /v1.0/users/{sender}/sendMail`. No mailbox password is stored, and
//! SMTP AUTH stays off in the tenant.
//!
//! The app authenticates with a client secret, or with a client assertion
//! (RFC 7523) Forge signs with its own issuer keys, which the app's federated
//! identity credential trusts: the keys and the rotation `oidc` realms use
//! ([`crate::auth::AssertionIssuer`]), nothing new to keep.
//!
//! Each instance caches its access token until shortly before it expires.
//! Graph's error code and message are what a failed send reports.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};

use forge_core::oidc::assertion::AssertionClaims;
use lettre::Address;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};

use super::settings::{EmailConfig, GraphClientAuth, GraphConfig, MICROSOFT_LOGIN_HOST};
use super::templates::Content;
use crate::auth::AssertionIssuer;

/// Microsoft Graph's host.
pub const GRAPH_HOST: &str = "https://graph.microsoft.com";

/// The scope of the token: the app's Graph application permissions.
const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";

/// `client_assertion_type` of a signed assertion (RFC 7523).
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How long a token or `sendMail` request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A cached token is dropped this long before it expires.
const TOKEN_MARGIN: Duration = Duration::from_secs(300);

/// The most of an error response a failed send reports.
const MAX_ERROR_BYTES: usize = 2048;

/// Where the token endpoint and Graph live. Always Microsoft's global cloud;
/// tests point them at mock servers ([`super::Mailer::use_microsoft_endpoints`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrosoftEndpoints {
    /// `https://login.microsoftonline.com`.
    pub login: String,
    /// `https://graph.microsoft.com`.
    pub graph: String,
}

impl Default for MicrosoftEndpoints {
    fn default() -> Self {
        MicrosoftEndpoints {
            login: MICROSOFT_LOGIN_HOST.to_string(),
            graph: GRAPH_HOST.to_string(),
        }
    }
}

struct CachedToken {
    access_token: String,
    expires: Instant,
}

/// The Graph sender of one instance: its HTTP client, token cache and
/// issuer.
pub(super) struct GraphTransport {
    http: reqwest::Client,
    issuer: AssertionIssuer,
    endpoints: RwLock<MicrosoftEndpoints>,
    tokens: tokio::sync::Mutex<HashMap<String, CachedToken>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl GraphTransport {
    pub(super) fn new(issuer: AssertionIssuer) -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("forge/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("the Graph HTTP client builds");
        GraphTransport {
            http,
            issuer,
            endpoints: RwLock::new(MicrosoftEndpoints::default()),
            tokens: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn issuer(&self) -> &str {
        self.issuer.issuer()
    }

    pub(super) fn set_endpoints(&self, endpoints: MicrosoftEndpoints) {
        *self
            .endpoints
            .write()
            .unwrap_or_else(PoisonError::into_inner) = endpoints;
    }

    fn endpoints(&self) -> MicrosoftEndpoints {
        self.endpoints
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Send `content` to `to` as `graph`'s sender mailbox.
    pub(super) async fn send(
        &self,
        config: &EmailConfig,
        graph: &GraphConfig,
        to: &Address,
        content: Content,
    ) -> Result<(), String> {
        let endpoints = self.endpoints();
        let token = self.token(&endpoints, graph).await?;
        let sender = graph.sender_mailbox(&config.from_address);
        let mut url = url::Url::parse(&endpoints.graph)
            .map_err(|e| format!("the Graph URL is invalid: {e}"))?;
        url.path_segments_mut()
            .map_err(|()| "the Graph URL is invalid".to_string())?
            .pop_if_empty()
            .extend(["v1.0", "users", sender, "sendMail"]);
        let mut from = json!({"address": config.from_address});
        if let Some(name) = &config.from_name {
            from["name"] = json!(name);
        }
        let mut message = json!({
            "subject": content.subject,
            "body": {"contentType": "HTML", "content": content.html},
            "from": {"emailAddress": from},
            "toRecipients": [{"emailAddress": {"address": to.to_string()}}],
        });
        if let Some(reply_to) = &config.reply_to {
            message["replyTo"] = json!([{"emailAddress": {"address": reply_to}}]);
        }
        let response = self
            .http
            .post(url)
            .bearer_auth(&token)
            .json(&json!({"message": message, "saveToSentItems": false}))
            .send()
            .await
            .map_err(|e| {
                format!(
                    "Microsoft Graph could not be reached: {}",
                    super::smtp::describe(&e)
                )
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        if status == reqwest::StatusCode::UNAUTHORIZED {
            // A token Graph no longer takes is not used again.
            self.tokens.lock().await.remove(&token_key(graph));
        }
        let body = response.text().await.unwrap_or_default();
        Err(graph_error(status, &body, sender))
    }

    /// An access token for `graph`'s app: the cached one, or a new one from
    /// the token endpoint.
    async fn token(
        &self,
        endpoints: &MicrosoftEndpoints,
        graph: &GraphConfig,
    ) -> Result<String, String> {
        let key = token_key(graph);
        let mut tokens = self.tokens.lock().await;
        if let Some(cached) = tokens.get(&key) {
            if Instant::now() < cached.expires {
                return Ok(cached.access_token.clone());
            }
        }
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            endpoints.login.trim_end_matches('/'),
            graph.tenant_id
        );
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", graph.client_id.clone()),
            ("scope", GRAPH_SCOPE.to_string()),
        ];
        match graph.client_authentication {
            GraphClientAuth::ClientSecret => {
                let secret = graph
                    .client_secret
                    .clone()
                    .ok_or_else(|| "no client secret is stored for the Graph app".to_string())?;
                form.push(("client_secret", secret));
            }
            GraphClientAuth::FederatedCredential => {
                let credential = graph
                    .federated_credential(self.issuer.issuer())
                    .expect("federated_credential authentication");
                let assertion = self
                    .issuer
                    .sign(&AssertionClaims {
                        issuer: credential.issuer,
                        subject: credential.subject,
                        audience: credential.audience,
                    })
                    .await
                    .map_err(|error| {
                        tracing::error!(error = %format!("{error:#}"), "cannot sign the Graph client assertion");
                        "the client assertion could not be signed".to_string()
                    })?;
                form.push(("client_assertion_type", JWT_BEARER.to_string()));
                form.push(("client_assertion", assertion));
            }
        }
        let response = self.http.post(&url).form(&form).send().await.map_err(|e| {
            format!(
                "the Microsoft token endpoint could not be reached: {}",
                super::smtp::describe(&e)
            )
        })?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(token_error(status, &body));
        }
        let token: TokenResponse = serde_json::from_str(&body).map_err(|_| {
            "the Microsoft token endpoint answered without an access token".to_string()
        })?;
        let lifetime = Duration::from_secs(token.expires_in.unwrap_or(3600));
        tokens.insert(
            key,
            CachedToken {
                access_token: token.access_token.clone(),
                expires: Instant::now() + lifetime.saturating_sub(TOKEN_MARGIN),
            },
        );
        Ok(token.access_token)
    }
}

/// The cache key of `graph`'s token: its app and how it authenticates (a
/// new client secret gets a new token).
fn token_key(graph: &GraphConfig) -> String {
    let secret = graph
        .client_secret
        .as_deref()
        .map(|s| hex::encode(Sha256::digest(s.as_bytes())))
        .unwrap_or_default();
    format!(
        "{}\n{}\n{:?}\n{secret}",
        graph.tenant_id.to_ascii_lowercase(),
        graph.client_id.to_ascii_lowercase(),
        graph.client_authentication
    )
}

/// `text` cut to [`MAX_ERROR_BYTES`] at a character boundary.
fn clip(text: &str) -> &str {
    let mut end = text.len().min(MAX_ERROR_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// A refusal of the token endpoint: its OAuth `error` and description
/// (`AADSTS…`).
fn token_error(status: reqwest::StatusCode, body: &str) -> String {
    let parsed: Option<JsonValue> = serde_json::from_str(body).ok();
    let error = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(JsonValue::as_str);
    let description = parsed
        .as_ref()
        .and_then(|v| v.get("error_description"))
        .and_then(JsonValue::as_str);
    match (error, description) {
        (Some(error), Some(description)) => format!(
            "Entra refused the app's sign-in ({} {error}): {}",
            status.as_u16(),
            clip(description)
        ),
        (Some(error), None) => {
            format!(
                "Entra refused the app's sign-in ({} {error})",
                status.as_u16()
            )
        }
        _ => format!(
            "Entra refused the app's sign-in ({}): {}",
            status.as_u16(),
            clip(body.trim())
        ),
    }
}

/// A refusal of `sendMail`: Graph's error code and message, with what the
/// usual ones mean.
fn graph_error(status: reqwest::StatusCode, body: &str, sender: &str) -> String {
    let parsed: Option<JsonValue> = serde_json::from_str(body).ok();
    let error = parsed.as_ref().and_then(|v| v.get("error"));
    let code = error
        .and_then(|e| e.get("code"))
        .and_then(JsonValue::as_str);
    let message = error
        .and_then(|e| e.get("message"))
        .and_then(JsonValue::as_str);
    let mut text = match (code, message) {
        (Some(code), Some(message)) => format!(
            "Microsoft Graph refused the message ({} {code}): {}",
            status.as_u16(),
            clip(message)
        ),
        (Some(code), None) => {
            format!(
                "Microsoft Graph refused the message ({} {code})",
                status.as_u16()
            )
        }
        _ => format!(
            "Microsoft Graph refused the message ({}): {}",
            status.as_u16(),
            clip(body.trim())
        ),
    };
    if code == Some("ErrorAccessDenied") {
        text.push_str(&format!(
            " ({sender} is outside the mailboxes the app's Exchange Online \
             \"Application Mail.Send\" role is scoped to)"
        ));
    } else if status == reqwest::StatusCode::UNAUTHORIZED {
        text.push_str(&format!(
            " ({sender} may have no Exchange Online mailbox or licence)"
        ));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_errors_name_the_code_and_what_it_means() {
        let denied = graph_error(
            reqwest::StatusCode::FORBIDDEN,
            r#"{"error":{"code":"ErrorAccessDenied","message":"Access is denied. Check credentials and try again."}}"#,
            "forge@contoso.com",
        );
        assert!(
            denied.starts_with(
                "Microsoft Graph refused the message (403 ErrorAccessDenied): Access is denied."
            ),
            "{denied}"
        );
        assert!(denied.contains("Application Mail.Send"), "{denied}");
        let unlicensed = graph_error(reqwest::StatusCode::UNAUTHORIZED, "", "forge@contoso.com");
        assert!(
            unlicensed.contains("no Exchange Online mailbox"),
            "{unlicensed}"
        );
        let long = "x".repeat(10_000);
        assert!(graph_error(reqwest::StatusCode::BAD_GATEWAY, &long, "s").len() < 2200);
    }

    #[test]
    fn token_errors_carry_entras_description() {
        let refused = token_error(
            reqwest::StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#,
        );
        assert_eq!(
            refused,
            "Entra refused the app's sign-in (401 invalid_client): AADSTS7000215: Invalid client secret provided."
        );
        assert_eq!(
            token_error(reqwest::StatusCode::BAD_REQUEST, "plain"),
            "Entra refused the app's sign-in (400): plain"
        );
    }
}
