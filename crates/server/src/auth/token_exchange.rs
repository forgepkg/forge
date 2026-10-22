//! The trusted-publishing token exchange: `POST /api/v2/token`.
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

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum::Router;
use chrono::{DateTime, Utc};
use forge_core::auth::{generate_workload_key, is_workload_key, workload_key_sha256, Principal};
use forge_db::trusted_publish_audit_dao;
use forge_db::workload_api_key_dao::{self, NewWorkloadApiKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::wif::{ExchangeRefusal, WorkloadIdentitySource};
use crate::middleware::principal::auth_unavailable;
use crate::state::AppState;

/// Where the exchange is served (nuget.org's path).
pub const TOKEN_EXCHANGE_PATH: &str = "/api/v2/token";

/// The only `tokenType` there is.
const TOKEN_TYPE_API_KEY: &str = "ApiKey";

/// A request body is a few dozen bytes; refuse anything much larger unread.
const MAX_REQUEST_BYTES: usize = 4 * 1024;

/// The `/api/v2/token` route.
pub fn token_exchange_router() -> Router<AppState> {
    Router::new()
        .route(TOKEN_EXCHANGE_PATH, post(exchange))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
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

    let source = WorkloadIdentitySource::new(state.realms.clone(), state.pool.clone());
    let redeemed = match redeem(&state.pool, &source, token, false).await {
        // The database holds another realm configuration than this
        // instance's snapshot: the realm was edited, possibly on another
        // instance whose peers have not rebuilt their snapshots yet. Verify
        // once more against a rebuilt snapshot before refusing.
        Err(Refusal::RealmChanged) => redeem(&state.pool, &source, token, true).await,
        other => other,
    };
    let Redeemed {
        api_key,
        expires,
        realm_id,
        role_id,
        subject_sha256,
    } = match redeemed {
        Ok(redeemed) => redeemed,
        Err(Refusal::RealmChanged) => {
            return refused(
                StatusCode::UNAUTHORIZED,
                "the workload identity realm changed during the exchange; try again",
            )
        }
        Err(Refusal::Answer(response)) => return response,
    };
    tracing::info!(
        target: "forge::audit",
        realm_id,
        role_id,
        subject = %hex::encode(&subject_sha256[..8]),
        %expires,
        "workload token exchanged for an API key"
    );
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(ExchangeResponse { api_key, expires }),
    )
        .into_response()
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
    Answer(Response),
}

/// Verify `token` (against a rebuilt realm snapshot with `refresh`) and
/// exchange it for a key.
async fn redeem(
    pool: &PgPool,
    source: &WorkloadIdentitySource,
    token: &str,
    refresh: bool,
) -> Result<Redeemed, Refusal> {
    let refuse = |status, message| Err(Refusal::Answer(refused(status, message)));
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
        issued_at,
    } = workload.principal
    else {
        return refuse(StatusCode::UNAUTHORIZED, "invalid credentials");
    };
    let (Some(token_issued_at), Some(token_expires_at)) = (
        DateTime::<Utc>::from_timestamp(issued_at, 0),
        DateTime::<Utc>::from_timestamp(workload.expires_at, 0),
    ) else {
        return refuse(StatusCode::UNAUTHORIZED, "invalid credentials");
    };

    let api_key = generate_workload_key();
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
            ttl_seconds: i64::try_from(workload.api_key_ttl_seconds).unwrap_or(i64::MAX),
        },
    )
    .await;
    match stored {
        Ok(Stored::Issued(expires)) => Ok(Redeemed {
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
        Ok(Stored::RealmChanged) => {
            tracing::warn!(
                realm_id,
                role_id,
                refresh,
                "workload realm or role changed during the token exchange"
            );
            Err(Refusal::RealmChanged)
        }
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
    Issued(DateTime<Utc>),
    /// The token was exchanged before.
    Replayed,
    /// The realm was disabled, deleted or edited (or the role deleted)
    /// since the token was verified against it.
    RealmChanged,
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
    let Some(expires) = workload_api_key_dao::insert(&mut tx, new).await? else {
        return Ok(Stored::Replayed);
    };
    tx.commit().await?;
    Ok(Stored::Issued(expires))
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
}
