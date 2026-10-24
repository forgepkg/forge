//! Logins of command-line clients, as format plugins ask for them
//! ([`AuthRequest`]): npm's `npm login`, `npm logout` and `npm whoami`.
//!
//! * A **password** login is checked through the realm chain like the web
//!   UI's (local passwords, credential forwarding to a Nexus or a
//!   directory, the login lockout); it mints a new API token. No account is
//!   ever created here.
//! * A **web** login gives the client a login URL, Forge's page
//!   `/cli-login/<secret>`, which it opens in the browser, and a secret it
//!   polls with. The user signs in there as always (password or OIDC) and
//!   approves the request ([`crate::auth`]'s `/auth/cli-login`); the next
//!   poll mints the token. The two secrets differ: only the client that
//!   started the login can collect the token, and only the approving
//!   user's session can approve it. A request lives
//!   `cli_login.web_login_ttl_seconds` (10 minutes).
//! * A **logout** revokes the token, when it is the caller's own.
//!
//! Tokens minted by a login carry the user's rights (no scope), expire
//! after `cli_login.token_lifetime_days`, and are listed and revocable on
//! the user's tokens page like every token. Logins, mints and revocations
//! are audit-logged (`forge::audit`).

use std::net::IpAddr;

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use forge_core::auth::principal::Principal;
use forge_core::auth::token::{generate_token_secret, hash_token};
use forge_db::cli_login_dao::{self, CliLoginState};
use forge_db::model::Repository;
use forge_db::token_dao::{self, NewToken};
use forge_db::user_dao;
use forge_plugin::api::{AuthOutcome, AuthRequest};

use crate::auth::{verify_password_login, LoginRefusal};
use crate::state::AppState;

/// The longest host name a web login keeps.
const MAX_HOSTNAME: usize = 255;

fn unauthorized(message: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"Forge\"")],
        message,
    )
        .into_response()
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "30")],
        "authentication temporarily unavailable",
    )
        .into_response()
}

fn db_error(e: sqlx::Error) -> Response {
    tracing::error!(error = %e, "cli login failed");
    unavailable()
}

/// Perform `request` for `principal` on `repo`, asked from `client_ip`:
/// what the format plugin renders, or the refusal to answer with.
pub async fn perform(
    state: &AppState,
    repo: &Repository,
    principal: Principal,
    client_ip: IpAddr,
    request: AuthRequest,
) -> Result<AuthOutcome, Response> {
    match request {
        AuthRequest::Password { username, password } => {
            password_login(state, repo, client_ip, &username, &password).await
        }
        AuthRequest::StartWebLogin { hostname } => {
            start_web_login(state, repo, client_ip, hostname).await
        }
        AuthRequest::PollWebLogin { secret } => poll_web_login(state, repo, &secret).await,
        AuthRequest::Logout { token } => logout(state, repo, principal, &token).await,
        AuthRequest::Whoami => whoami(state, principal).await,
    }
}

/// Mint a login token for `user_id`, named `name`.
async fn mint(
    state: &AppState,
    repo: &Repository,
    user_id: i64,
    name: String,
    how: &str,
) -> Result<AuthOutcome, Response> {
    let user = user_dao::find_user_by_id(&state.pool, user_id)
        .await
        .map_err(db_error)?
        .filter(|u| u.active)
        .ok_or_else(|| unauthorized("the account is not active"))?;
    let days = state.config.cli_login.token_lifetime_days;
    let secret = generate_token_secret();
    let token = token_dao::insert_token(
        &state.pool,
        NewToken {
            user_id,
            name,
            token_hash: hash_token(&secret),
            expires_at: (days > 0)
                .then(|| chrono::Utc::now() + chrono::Duration::days(i64::from(days))),
            // A credential-forwarding account's login came through its
            // upstream: an admin-forced reauth revokes the token.
            minted_with_forwarded_credential: user.auth_source == "upstream-basic",
        },
    )
    .await
    .map_err(db_error)?;
    tracing::info!(
        target: "forge::audit",
        user_id,
        token_id = token.id,
        repo = %repo.name,
        client = %repo.format,
        how,
        "cli login: token minted"
    );
    Ok(AuthOutcome::Token {
        token: secret,
        username: user.username,
    })
}

async fn password_login(
    state: &AppState,
    repo: &Repository,
    client_ip: IpAddr,
    username: &str,
    password: &str,
) -> Result<AuthOutcome, Response> {
    let (principal, _) = match verify_password_login(state, client_ip, username, password).await {
        Ok(verified) => verified,
        Err(refusal) => {
            tracing::info!(
                target: "forge::audit",
                repo = %repo.name,
                client = %repo.format,
                ip = %client_ip,
                outcome = ?refusal,
                "cli login refused"
            );
            return Err(match refusal {
                LoginRefusal::Invalid => unauthorized("invalid credentials"),
                refusal => refusal.into_response(),
            });
        }
    };
    mint(
        state,
        repo,
        principal.user_id,
        format!("{} login ({})", repo.format, repo.name),
        "password",
    )
    .await
}

/// Without the web UI there is no page to approve a web login on: 404,
/// and npm falls back to asking for a password.
async fn start_web_login(
    state: &AppState,
    repo: &Repository,
    client_ip: IpAddr,
    hostname: Option<String>,
) -> Result<AuthOutcome, Response> {
    if !state.config.web.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            "logins approved in the browser need the web UI",
        )
            .into_response());
    }
    // Starting a login is free for anyone: bounded per client network, as
    // OIDC logins are.
    if !state.oidc_login_starts.allow(client_ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "too many logins started; try again later",
        )
            .into_response());
    }
    let hostname = hostname.map(|h| {
        h.chars()
            .filter(|c| !c.is_control())
            .take(MAX_HOSTNAME)
            .collect::<String>()
    });
    let login_secret = generate_token_secret();
    let done_secret = generate_token_secret();
    let ttl = chrono::Duration::seconds(state.config.cli_login.web_login_ttl_seconds as i64);
    cli_login_dao::insert(
        &state.pool,
        &hash_token(&login_secret),
        &hash_token(&done_secret),
        &repo.format,
        repo.id,
        hostname.as_deref(),
        Some(&client_ip.to_string()),
        chrono::Utc::now() + ttl,
    )
    .await
    .map_err(db_error)?;
    let public = state.config.public_base_url();
    Ok(AuthOutcome::WebLoginStarted {
        login_url: format!("{}/cli-login/{login_secret}", public.trim_end_matches('/')),
        secret: done_secret,
    })
}

async fn poll_web_login(
    state: &AppState,
    repo: &Repository,
    secret: &str,
) -> Result<AuthOutcome, Response> {
    match cli_login_dao::poll(&state.pool, &hash_token(secret))
        .await
        .map_err(db_error)?
    {
        CliLoginState::Pending => Ok(AuthOutcome::WebLoginPending),
        CliLoginState::Unknown => Ok(AuthOutcome::WebLoginUnknown),
        CliLoginState::Approved {
            user_id, hostname, ..
        } => {
            let name = match hostname.as_deref().filter(|h| !h.is_empty()) {
                Some(host) => format!("{} login ({}) on {host}", repo.format, repo.name),
                None => format!("{} login ({})", repo.format, repo.name),
            };
            mint(state, repo, user_id, name, "web").await
        }
    }
}

/// The caller must be authenticated as the user the token is of.
async fn logout(
    state: &AppState,
    repo: &Repository,
    principal: Principal,
    token: &str,
) -> Result<AuthOutcome, Response> {
    let Principal::User { user_id, .. } = principal else {
        return Err(unauthorized("authentication required"));
    };
    let not_found = || (StatusCode::NOT_FOUND, "no such token").into_response();
    let row = token_dao::find_token_by_hash(&state.pool, &hash_token(token))
        .await
        .map_err(db_error)?
        .filter(|row| row.user_id == user_id)
        .ok_or_else(not_found)?;
    token_dao::revoke_token(&state.pool, row.id)
        .await
        .map_err(db_error)?;
    tracing::info!(
        target: "forge::audit",
        user_id,
        token_id = row.id,
        repo = %repo.name,
        client = %repo.format,
        "cli logout: token revoked"
    );
    Ok(AuthOutcome::LoggedOut)
}

async fn whoami(state: &AppState, principal: Principal) -> Result<AuthOutcome, Response> {
    let username = match principal {
        Principal::User { user_id, .. } => user_dao::find_user_by_id(&state.pool, user_id)
            .await
            .map_err(db_error)?
            .map(|u| u.username)
            .ok_or_else(|| unauthorized("authentication required"))?,
        Principal::Workload { .. } => forge_core::auth::WORKLOAD_USERNAME.to_string(),
        _ => return Err(unauthorized("authentication required")),
    };
    Ok(AuthOutcome::Identity { username })
}
