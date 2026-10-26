//! The native NuGet and npm trusted-publishing token exchanges.
//!
//! A CI job presents its OIDC token as `Authorization: Bearer` and receives a
//! short-lived workload API key, the same exchange nuget.org's trusted
//! publishing does (same path and JSON shape, so the `NuGet/login` GitHub
//! Action works with `token-service-url` pointed here):
//!
//! ```text
//! POST /api/v2/token
//! Authorization: Bearer <CI OIDC token>
//! {"username": "oidc", "tokenType": "ApiKey"}
//!
//! 200 {"apiKey": "forge_wif.…", "expires": "2026-10-21T15:04:05Z"}
//! ```
//!
//! * The token is verified exactly as on any other request: its issuer picks
//!   the `workload_identity` realm, whose claim rules map it to a role.
//! * It must carry a `jti`, and each `(issuer, jti)` is exchanged **once**
//!   (the `workload_api_key` table's unique index is the redemption ledger).
//! * The key lives for the realm's `api_key_ttl_seconds` (default an hour),
//!   independent of the token's own lifetime, and authorizes as the token's
//!   workload principal ([`super::wif::WorkloadIdentitySource`] resolves it):
//!   as `X-NuGet-ApiKey` (`dotnet nuget push --api-key`, `NUGET_API_KEY`),
//!   as a Bearer token, or as the Basic password of the username `oidc`.
//! * `username` is optional and, when given, must be `oidc`: identity comes
//!   only from the verified token, never from the request body.
//!
//! npm uses `POST /-/npm/v1/oidc/token/exchange/package/{name}` and receives
//! `{"token":"forge_wif.…"}`. It shares NuGet's verifier and redemption ledger;
//! the realm's role authorizes the key, not the package named in the URL.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum::Router;
use chrono::{DateTime, Utc};
use forge_core::auth::{generate_workload_key, is_workload_key, workload_key_sha256, Principal};
use forge_db::trusted_publish_audit_dao;
use forge_db::trusted_publisher_dao;
use forge_db::workload_api_key_dao::{self, NewWorkloadApiKey, Redemption};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::wif::{ExchangeRefusal, WorkloadIdentitySource};
use crate::middleware::principal::auth_unavailable;
use crate::state::AppState;

/// Where the exchange is served (nuget.org's path).
pub const TOKEN_EXCHANGE_PATH: &str = "/api/v2/token";

pub(crate) const NPM_TOKEN_EXCHANGE_PATH: &str = "/-/npm/v1/oidc/token/exchange/package/{name}";

/// The only `tokenType` there is.
const TOKEN_TYPE_API_KEY: &str = "ApiKey";

/// A request body is a few dozen bytes; refuse anything much larger unread.
const MAX_REQUEST_BYTES: usize = 4 * 1024;

/// The NuGet and npm token-exchange routes.
pub fn token_exchange_router() -> Router<AppState> {
    Router::new()
        .route(TOKEN_EXCHANGE_PATH, post(exchange))
        .route(NPM_TOKEN_EXCHANGE_PATH, post(npm_exchange))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
}

async fn npm_exchange(
    State(state): State<AppState>,
    name: Result<Path<String>, axum::extract::rejection::PathRejection>,
    headers: HeaderMap,
) -> Response {
    let Ok(Path(name)) = name else {
        return npm_refused(StatusCode::BAD_REQUEST, "invalid npm package name");
    };
    if forge_format_npm::PackageName::parse(&name).is_err() {
        return npm_refused(StatusCode::BAD_REQUEST, "invalid npm package name");
    }
    let Some(token) = bearer_token(&headers) else {
        return npm_refused(
            StatusCode::UNAUTHORIZED,
            "present the CI job's OIDC token as `Authorization: Bearer`",
        );
    };
    match issue_key(&state, token).await {
        Ok(redeemed) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({"token": redeemed.api_key})),
        )
            .into_response(),
        Err((status, message)) => npm_refused(status, message),
    }
}

fn npm_refused(status: StatusCode, message: &'static str) -> Response {
    let mut response = refused(status, message);
    *response.body_mut() =
        axum::body::Body::from(serde_json::json!({"error": message}).to_string());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

/// `POST /api/v2/token` request body (every field optional).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeRequest {
    /// Accepted for nuget.org client compatibility; must be `oidc` if given.
    #[serde(default)]
    username: Option<String>,
    /// Must be `ApiKey` if given.
    #[serde(default)]
    token_type: Option<String>,
}

/// `POST /api/v2/token` response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    api_key: String,
    expires: DateTime<Utc>,
}

fn refused(status: StatusCode, message: &'static str) -> Response {
    match status {
        StatusCode::UNAUTHORIZED => {
            (status, [(header::WWW_AUTHENTICATE, "Bearer")], message).into_response()
        }
        StatusCode::SERVICE_UNAVAILABLE => auth_unavailable(),
        _ => (status, message).into_response(),
    }
}

/// The Bearer token of `headers`, if the request carries one.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

async fn exchange(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return refused(
            StatusCode::UNAUTHORIZED,
            "present the CI job's OIDC token as `Authorization: Bearer`",
        );
    };
    if is_workload_key(token) {
        // A key never renews itself: only a fresh CI token is exchanged.
        return refused(
            StatusCode::UNAUTHORIZED,
            "an API key cannot be exchanged; present the CI job's OIDC token",
        );
    }

    let request = if body.iter().all(u8::is_ascii_whitespace) {
        ExchangeRequest::default()
    } else {
        match serde_json::from_slice::<ExchangeRequest>(&body) {
            Ok(request) => request,
            Err(_) => return refused(StatusCode::BAD_REQUEST, "invalid JSON request body"),
        }
    };
    if request
        .token_type
        .as_deref()
        .is_some_and(|token_type| token_type != TOKEN_TYPE_API_KEY)
    {
        return refused(
            StatusCode::BAD_REQUEST,
            "unsupported tokenType (expected \"ApiKey\")",
        );
    }
    if let Some(username) = &request.username {
        let workload = forge_core::auth::canonical_username(username)
            .is_ok_and(|name| name == forge_core::auth::WORKLOAD_USERNAME);
        if !workload {
            return refused(
                StatusCode::BAD_REQUEST,
                "username must be \"oidc\" (or omitted): the token alone identifies the workload",
            );
        }
    }

    match issue_key(&state, token).await {
        Ok(Redeemed {
            api_key, expires, ..
        }) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(ExchangeResponse { api_key, expires }),
        )
            .into_response(),
        Err((status, message)) => refused(status, message),
    }
}

async fn issue_key(state: &AppState, token: &str) -> Result<Redeemed, (StatusCode, &'static str)> {
    use forge_metrics::auth::ExchangeOutcome;
    let issued = issue(state, token).await;
    forge_metrics::auth::token_exchange(match &issued {
        Ok(_) => ExchangeOutcome::Issued,
        Err((status, _)) if status.is_server_error() => ExchangeOutcome::Error,
        Err(_) => ExchangeOutcome::Rejected,
    });
    issued
}

/// [`issue_key`] proper.
async fn issue(state: &AppState, token: &str) -> Result<Redeemed, (StatusCode, &'static str)> {
    if is_workload_key(token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "an API key cannot be exchanged; present the CI job's OIDC token",
        ));
    }
    let source = WorkloadIdentitySource::new(state.realms.clone(), state.pool.clone());
    let redeemed = match redeem(&state.pool, &source, token, false).await {
        // The database holds another realm configuration than this
        // instance's snapshot: the realm was edited, possibly on another
        // instance whose peers have not rebuilt their snapshots yet. Verify
        // once more against a rebuilt snapshot before refusing.
        Err(Refusal::RealmChanged) => redeem(&state.pool, &source, token, true).await,
        other => other,
    };
    let redeemed = match redeemed {
        Ok(redeemed) => redeemed,
        Err(Refusal::RealmChanged) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "the workload identity realm changed during the exchange; try again",
            ))
        }
        Err(Refusal::Answer(status, message)) => return Err((status, message)),
    };
    tracing::info!(
        target: "forge::audit",
        realm_id = redeemed.realm_id,
        role_id = redeemed.role_id,
        subject = %hex::encode(&redeemed.subject_sha256[..8]),
        expires = %redeemed.expires,
        "workload token exchanged for an API key"
    );
    Ok(redeemed)
}

/// A key [`redeem`] issued.
struct Redeemed {
    api_key: String,
    expires: DateTime<Utc>,
    realm_id: i64,
    role_id: i64,
    subject_sha256: [u8; 32],
}

/// Why [`redeem`] issued no key.
enum Refusal {
    /// The realm or role row no longer matches the snapshot the token was
    /// verified against ([`Stored::RealmChanged`]).
    RealmChanged,
    /// Any other refusal, as the answer to send.
    Answer(StatusCode, &'static str),
}

/// Verify `token` (against a rebuilt realm snapshot with `refresh`) and
/// exchange it for a key.
async fn redeem(
    pool: &PgPool,
    source: &WorkloadIdentitySource,
    token: &str,
    refresh: bool,
) -> Result<Redeemed, Refusal> {
    let refuse = |status, message| Err(Refusal::Answer(status, message));
    let workload = match source.verify_for_exchange(token, refresh).await {
        Ok(workload) => workload,
        Err(ExchangeRefusal::NotWorkloadToken) => {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "not an OIDC token of a configured workload identity realm",
            )
        }
        Err(ExchangeRefusal::Rejected) => {
            return refuse(StatusCode::UNAUTHORIZED, "invalid credentials")
        }
        Err(ExchangeRefusal::Unavailable) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication temporarily unavailable",
            )
        }
    };
    // The one-time redemption is keyed on `jti`: a token without one could
    // be exchanged again and again until it expires.
    if workload
        .jti
        .as_deref()
        .is_none_or(|jti| jti.trim().is_empty())
    {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "the token has no jti, so it cannot be exchanged (each token is redeemed once)",
        );
    }
    let Principal::Workload {
        realm_id,
        role_id,
        issuer_sha256,
        config_sha256,
        subject_sha256,
        jti_sha256: Some(jti_sha256),
        matched_publishers,
        issued_at,
        key_id: None,
        expires_at,
    } = workload.principal
    else {
        return refuse(StatusCode::UNAUTHORIZED, "invalid credentials");
    };
    let (Some(token_issued_at), Some(token_expires_at)) = (
        DateTime::<Utc>::from_timestamp(issued_at, 0),
        DateTime::<Utc>::from_timestamp(expires_at, 0),
    ) else {
        return refuse(StatusCode::UNAUTHORIZED, "invalid credentials");
    };

    let api_key = generate_workload_key();
    let db_matched_publishers: Vec<_> = matched_publishers
        .iter()
        .map(
            |matched| forge_db::trusted_publisher_dao::TrustedPublisherMatch {
                id: matched.id,
                definition_sha256: matched.definition_sha256,
            },
        )
        .collect();
    let stored = store_key(
        pool,
        NewWorkloadApiKey {
            key_sha256: &workload_key_sha256(&api_key),
            realm_id,
            role_id,
            issuer_sha256: &issuer_sha256,
            config_sha256: &config_sha256,
            subject_sha256: &subject_sha256,
            jti_sha256: &jti_sha256,
            token_issued_at,
            token_expires_at,
            token_leeway_seconds: workload.clock_skew_seconds,
            ttl_seconds: i64::try_from(workload.api_key_ttl_seconds).unwrap_or(i64::MAX),
            matched_publishers: &db_matched_publishers,
        },
    )
    .await;
    match stored {
        Ok(Stored::Issued {
            expires_at: expires,
            ..
        }) => Ok(Redeemed {
            api_key,
            expires,
            realm_id,
            role_id,
            subject_sha256,
        }),
        Ok(Stored::Replayed) => {
            tracing::warn!(
                realm_id,
                role_id,
                "workload token replayed at the token exchange"
            );
            refuse(
                StatusCode::UNAUTHORIZED,
                "this token was already exchanged; request a new one from the CI job",
            )
        }
        Ok(Stored::TokenExpired) => {
            tracing::warn!(
                realm_id,
                role_id,
                "workload token expired by the database clock at the token exchange"
            );
            refuse(
                StatusCode::UNAUTHORIZED,
                "the token has expired; request a new one from the CI job",
            )
        }
        Ok(Stored::RealmChanged) => {
            tracing::warn!(
                realm_id,
                role_id,
                refresh,
                "workload realm or role changed during the token exchange"
            );
            Err(Refusal::RealmChanged)
        }
        Ok(Stored::PublisherChanged) => refuse(
            StatusCode::UNAUTHORIZED,
            "a trusted publisher changed during the exchange; request a new CI token",
        ),
        Err(e) => {
            tracing::error!(error = %e, "storing a workload API key failed");
            refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication temporarily unavailable",
            )
        }
    }
}

/// What [`store_key`] did.
enum Stored {
    Issued {
        expires_at: DateTime<Utc>,
    },
    /// The token was exchanged before.
    Replayed,
    /// The token has expired by the database's clock.
    TokenExpired,
    /// The realm was disabled, deleted or edited (or the role deleted)
    /// since the token was verified against it.
    RealmChanged,
    /// One of the trusted publishers changed while the token was exchanged.
    PublisherChanged,
}

/// Store `new` while holding the realm and role rows, and only while the
/// realm still has the issuer and configuration the token was verified
/// under. A realm change waits for this transaction and then revokes the
/// key (`workload_api_key_dao::revoke_realm`), or lands first and no key is
/// issued: a key never outlives the change, whatever the realm later
/// becomes.
async fn store_key(pool: &PgPool, new: NewWorkloadApiKey<'_>) -> sqlx::Result<Stored> {
    let mut tx = pool.begin().await?;
    let Some(identity) =
        trusted_publish_audit_dao::lock_identity_snapshot(&mut tx, new.realm_id, new.role_id)
            .await?
    else {
        return Ok(Stored::RealmChanged);
    };
    let issuer: [u8; 32] = Sha256::digest(identity.issuer.trim_end_matches('/').as_bytes()).into();
    let config = super::workload_identity_config_sha256(&identity.realm_config).ok();
    if issuer != *new.issuer_sha256 || config.as_ref() != Some(new.config_sha256) {
        return Ok(Stored::RealmChanged);
    }
    if !trusted_publisher_dao::lock_matches(&mut tx, new.matched_publishers).await? {
        return Ok(Stored::PublisherChanged);
    }
    match workload_api_key_dao::insert(&mut tx, new).await? {
        Redemption::Issued { expires_at, .. } => {
            tx.commit().await?;
            Ok(Stored::Issued { expires_at })
        }
        Redemption::Replayed => Ok(Stored::Replayed),
        Redemption::TokenExpired => Ok(Stored::TokenExpired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_requires_the_bearer_scheme() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(header::AUTHORIZATION, "Bearer a.b.c".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("a.b.c"));
        headers.insert(header::AUTHORIZATION, "bearer  a.b.c ".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("a.b.c"));
        headers.insert(header::AUTHORIZATION, "Basic b2lkYzp4".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn request_body_uses_nuget_org_field_names() {
        let request: ExchangeRequest =
            serde_json::from_str(r#"{"username":"oidc","tokenType":"ApiKey"}"#).unwrap();
        assert_eq!(request.username.as_deref(), Some("oidc"));
        assert_eq!(request.token_type.as_deref(), Some("ApiKey"));
        let response = serde_json::to_value(ExchangeResponse {
            api_key: "k".into(),
            expires: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
        })
        .unwrap();
        assert_eq!(response["apiKey"], "k");
        assert!(response.get("expires").is_some());
    }

    #[tokio::test]
    async fn npm_refusals_are_json_and_keep_authentication_headers() {
        for status in [StatusCode::UNAUTHORIZED, StatusCode::SERVICE_UNAVAILABLE] {
            let response = npm_refused(status, "invalid credentials");
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            if status == StatusCode::UNAUTHORIZED {
                assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
            } else {
                assert!(response.headers().contains_key(header::RETRY_AFTER));
            }
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"error": "invalid credentials"})
            );
        }
    }
}
