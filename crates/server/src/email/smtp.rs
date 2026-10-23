//! The SMTP transport: submission to the configured server with `lettre`,
//! over implicit TLS or required `STARTTLS` (certificates verified against
//! the system roots, like every other outbound TLS connection), or without
//! TLS to a loopback relay. With a username it authenticates with `AUTH
//! PLAIN` or `LOGIN`, whichever the server offers, and never sends without
//! authenticating.
//!
//! The `smtp_oauth` transport (#321) authenticates with an OAuth access token
//! instead: SASL `OAUTHBEARER` (RFC 7628) when the server offers it, else
//! `XOAUTH2`. `lettre` knows only the latter, so that session is driven
//! command by command ([`send_oauth`]).

use std::time::Duration;

use base64::Engine as _;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{AsyncSmtpConnection, Tls, TlsParameters};
use lettre::transport::smtp::commands::Ehlo;
use lettre::transport::smtp::extension::ClientId;
use lettre::transport::smtp::response::Response;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use super::settings::{SmtpConfig, SmtpOauthConfig, SmtpTls};

/// How long connecting, and each SMTP command, may take.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

/// Send `message` through the server `config` names. The error is the
/// server's or the connection's, as text to show an administrator.
pub(super) async fn send(config: &SmtpConfig, message: Message) -> Result<(), String> {
    let tls = match config.tls {
        SmtpTls::Implicit => Tls::Wrapper(tls_parameters(&config.host)?),
        SmtpTls::Starttls => Tls::Required(tls_parameters(&config.host)?),
        SmtpTls::None => Tls::None,
    };
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
        .port(config.port())
        .tls(tls)
        .timeout(Some(COMMAND_TIMEOUT));
    if let Some(username) = &config.username {
        let Some(password) = &config.password else {
            return Err("no password is stored for the SMTP account".to_string());
        };
        builder = builder
            .credentials(Credentials::new(username.clone(), password.clone()))
            .authentication(vec![Mechanism::Plain, Mechanism::Login]);
    }
    builder
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(|e| describe(&e))
}

/// Why an OAuth submission failed.
#[derive(Debug)]
pub(super) enum OauthSendError {
    /// The server refused the access token.
    TokenRefused(String),
    /// Anything else.
    Failed(String),
}

/// Send `message` through the server `config` names, authenticated as its
/// mailbox with `access_token` (module docs).
pub(super) async fn send_oauth(
    config: &SmtpOauthConfig,
    access_token: &str,
    message: Message,
) -> Result<(), OauthSendError> {
    let failed = |e: lettre::transport::smtp::Error| OauthSendError::Failed(describe(&e));
    let hello = ClientId::default();
    let implicit = match config.tls {
        SmtpTls::Implicit => Some(tls_parameters(&config.host).map_err(OauthSendError::Failed)?),
        SmtpTls::Starttls | SmtpTls::None => None,
    };
    let mut connection = AsyncSmtpConnection::connect_tokio1(
        (config.host.as_str(), config.port()),
        Some(COMMAND_TIMEOUT),
        &hello,
        implicit,
        None,
    )
    .await
    .map_err(failed)?;
    let result = oauth_session(&mut connection, config, access_token, &hello, &message).await;
    match result {
        Ok(()) => {
            let _ = connection.quit().await;
        }
        Err(_) => connection.abort().await,
    }
    result
}

async fn oauth_session(
    connection: &mut AsyncSmtpConnection,
    config: &SmtpOauthConfig,
    access_token: &str,
    hello: &ClientId,
    message: &Message,
) -> Result<(), OauthSendError> {
    let failed = |e: lettre::transport::smtp::Error| OauthSendError::Failed(describe(&e));
    if config.tls == SmtpTls::Starttls {
        if !connection.can_starttls() {
            return Err(OauthSendError::Failed(
                "the server does not offer STARTTLS".to_string(),
            ));
        }
        connection
            .starttls(
                tls_parameters(&config.host).map_err(OauthSendError::Failed)?,
                hello,
            )
            .await
            .map_err(failed)?;
    }
    // `lettre` drops the mechanisms it does not know (OAUTHBEARER) from what
    // the server offers: ask again and read them from the answer.
    let ehlo = connection
        .command(Ehlo::new(hello.clone()))
        .await
        .map_err(failed)?;
    let offered = auth_mechanisms(&ehlo);
    let mechanism = if offered.iter().any(|m| m == "OAUTHBEARER") {
        "OAUTHBEARER"
    } else if offered.iter().any(|m| m == "XOAUTH2") {
        "XOAUTH2"
    } else {
        return Err(OauthSendError::Failed(format!(
            "the server offers neither OAUTHBEARER nor XOAUTH2 (it offers {})",
            if offered.is_empty() {
                "no authentication".to_string()
            } else {
                offered.join(", ")
            }
        )));
    };
    let initial = initial_response(mechanism, config, access_token);
    let b64 = base64::engine::general_purpose::STANDARD;
    let answer = connection
        .command(format!("AUTH {mechanism} {}\r\n", b64.encode(initial)))
        .await
        .map_err(|e| {
            OauthSendError::TokenRefused(format!(
                "the server refused the access token ({mechanism}): {}",
                describe(&e)
            ))
        })?;
    if answer.has_code(334) {
        // The token was refused, and the challenge says why (RFC 7628
        // §3.2.2); the exchange ends with a dummy response and a 5xx.
        let status = answer
            .first_line()
            .and_then(|line| b64.decode(line.trim()).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        let dummy = if mechanism == "OAUTHBEARER" {
            "AQ==\r\n"
        } else {
            "\r\n"
        };
        let end = connection.command(dummy).await;
        let mut why = format!("the server refused the access token ({mechanism})");
        if !status.trim().is_empty() {
            why.push_str(": ");
            why.push_str(status.trim());
        }
        if let Err(e) = end {
            why.push_str(" - ");
            why.push_str(&describe(&e));
        }
        return Err(OauthSendError::TokenRefused(why));
    }
    connection
        .send(message.envelope(), &message.formatted())
        .await
        .map_err(failed)?;
    Ok(())
}

/// The SASL mechanisms an `EHLO` answer offers (`AUTH …` or `AUTH=…`),
/// uppercase.
fn auth_mechanisms(ehlo: &Response) -> Vec<String> {
    let mut mechanisms = Vec::new();
    for line in ehlo.message() {
        let line = line.trim();
        let Some(keyword) = line.get(..5) else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("AUTH ") || keyword.eq_ignore_ascii_case("AUTH=") {
            for mechanism in line[5..].split_ascii_whitespace() {
                let mechanism = mechanism.to_ascii_uppercase();
                if !mechanisms.contains(&mechanism) {
                    mechanisms.push(mechanism);
                }
            }
        }
    }
    mechanisms
}

/// The client's initial response for `mechanism`: RFC 7628's GS2 header and
/// key-value pairs, or XOAUTH2's `user=…^Aauth=Bearer …^A^A`.
fn initial_response(mechanism: &str, config: &SmtpOauthConfig, access_token: &str) -> String {
    if mechanism == "OAUTHBEARER" {
        // A `saslname` escapes `,` and `=` (RFC 5801 §4).
        let user = config.username.replace('=', "=3D").replace(',', "=2C");
        format!(
            "n,a={user},\x01host={}\x01port={}\x01auth=Bearer {access_token}\x01\x01",
            config.host,
            config.port()
        )
    } else {
        format!(
            "user={}\x01auth=Bearer {access_token}\x01\x01",
            config.username
        )
    }
}

fn tls_parameters(host: &str) -> Result<TlsParameters, String> {
    TlsParameters::new(host.to_string()).map_err(|e| describe(&e))
}

/// An error with its causes, `outer: inner: …`.
pub(super) fn describe(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use lettre::transport::smtp::response::{Category, Code, Detail, Severity};

    fn config() -> SmtpOauthConfig {
        serde_json::from_value(serde_json::json!({
            "host": "mail.example.com",
            "tls": "starttls",
            "issuer": "https://mail.example.com",
            "username": "forge,bot=1@example.com",
        }))
        .unwrap()
    }

    #[test]
    fn mechanisms_are_read_from_the_ehlo_answer() {
        let ehlo = Response::new(
            Code::new(
                Severity::PositiveCompletion,
                Category::MailSystem,
                Detail::Zero,
            ),
            vec![
                "mail.example.com".into(),
                "PIPELINING".into(),
                "AUTH PLAIN oauthbearer XOAUTH2".into(),
                "AUTH=LOGIN".into(),
            ],
        );
        assert_eq!(
            auth_mechanisms(&ehlo),
            ["PLAIN", "OAUTHBEARER", "XOAUTH2", "LOGIN"]
        );
    }

    #[test]
    fn initial_responses_follow_rfc_7628_and_xoauth2() {
        assert_eq!(
            initial_response("OAUTHBEARER", &config(), "tok"),
            "n,a=forge=2Cbot=3D1@example.com,\x01host=mail.example.com\x01port=587\x01\
             auth=Bearer tok\x01\x01"
        );
        assert_eq!(
            initial_response("XOAUTH2", &config(), "tok"),
            "user=forge,bot=1@example.com\x01auth=Bearer tok\x01\x01"
        );
    }
}
