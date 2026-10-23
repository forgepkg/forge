//! The SMTP transport: submission to the configured server with `lettre`,
//! over implicit TLS or required `STARTTLS` (certificates verified against
//! the system roots, like every other outbound TLS connection), or without
//! TLS to a loopback relay. With a username it authenticates with `AUTH
//! PLAIN` or `LOGIN`, whichever the server offers, and never sends without
//! authenticating.

use std::time::Duration;

use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use super::settings::{SmtpConfig, SmtpTls};

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
