//! The Docker / OCI registry (`/v2`), wired into the server: the route
//! handler, the registry-token signing key, and the trusted-publishing
//! ledger of workload pushes.

use std::sync::Arc;

use anyhow::Context;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use forge_core::auth::Principal;
use forge_core::repo::PublishPolicy;
use forge_crypto::service::EnvelopeService;
use forge_crypto::{ExposeSecret, PlaintextSecret};
use forge_db::model::Repository;
use forge_db::{authz_dao, secret_dao, workload_api_key_dao};
use forge_oci::token::TokenKeys;
use sha2::Digest;
use sqlx::PgPool;

use crate::config::Config;
use crate::middleware::principal_of;
use crate::state::AppState;

/// `forge_setting` key of the generated registry-token signing key.
pub const TOKEN_KEY_SETTING: &str = secret_dao::REGISTRY_TOKEN_KEY_SETTING;

/// The `/v2` handler.
pub async fn registry(State(state): State<AppState>, req: Request<Body>) -> Response {
    let principal = principal_of(&req);
    state.registry().handle(principal, req).await
}

/// Workload pushes go to the trusted-publishing ledger.
pub(crate) struct LedgerRecorder;

impl forge_oci::PublishRecorder for LedgerRecorder {
    fn for_repository(&self, repository: &Repository) -> Arc<dyn PublishPolicy> {
        crate::dispatch::workload_ledger_policy(repository)
    }
}

/// Registry tokens of a workload stand only while their realm and key do.
pub(crate) struct WorkloadLiveness {
    pub realms: Arc<crate::auth::RealmAuth>,
    pub pool: PgPool,
}

#[async_trait::async_trait]
impl forge_oci::WorkloadCheck for WorkloadLiveness {
    async fn still_valid(&self, principal: &Principal) -> Result<bool, String> {
        let Principal::Workload {
            realm_id,
            issuer_sha256,
            config_sha256,
            jti_sha256,
            ..
        } = *principal
        else {
            return Ok(true);
        };
        let snapshot = self.realms.snapshot().await.map_err(|e| e.to_string())?;
        if !crate::auth::realm_current(&snapshot, realm_id, &config_sha256) {
            return Ok(false);
        }
        let Some(jti_sha256) = jti_sha256 else {
            return Ok(true);
        };
        workload_api_key_dao::redemption_ended(&self.pool, &issuer_sha256, &jti_sha256)
            .await
            .map(|ended| !ended)
            .map_err(|e| e.to_string())
    }
}

/// A 401 the authentication middleware answered itself (wrong credentials)
/// on a `/v2` path, made a registry error: the Bearer challenge clients
/// expect and the distribution-spec error body.
pub(crate) fn amend_registry_rejection(public_base_url: &str, response: Response) -> Response {
    if response.status() != StatusCode::UNAUTHORIZED
        || response.headers().contains_key(header::WWW_AUTHENTICATE)
    {
        return response;
    }
    let (scheme, service) = forge_oci::registry_origin(public_base_url);
    let challenge = format!("Bearer realm=\"{scheme}://{service}/v2/token\",service=\"{service}\"");
    let body = serde_json::json!({
        "errors": [{ "code": "UNAUTHORIZED", "message": "invalid credentials" }]
    })
    .to_string();
    let mut amended = (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        amended
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    amended.headers_mut().insert(
        "docker-distribution-api-version",
        HeaderValue::from_static("registry/2.0"),
    );
    amended
}

/// The registry-token signing keys: derived from `docker.token_secret`, or
/// the install's generated key (created on first use and shared by every
/// instance through `forge_setting`; sealed with the envelope service when
/// secret encryption is enabled, and re-sealed by DEK rotation like every
/// other secret).
///
/// A stored key is replaced only when it can never be opened (malformed, or
/// sealed under a data key that does not open it). A database, key store or
/// configuration error fails startup instead: replacing the shared key would
/// split the instances that still hold it from this one.
pub async fn load_token_keys(
    config: &Config,
    pool: &PgPool,
    envelope: Option<&EnvelopeService>,
) -> anyhow::Result<TokenKeys> {
    if let Some(secret) = &config.docker.token_secret {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"forge-registry-token\0");
        hasher.update(secret.as_bytes());
        return Ok(TokenKeys::new(vec![hasher.finalize().to_vec()]));
    }
    for _ in 0..5 {
        let stored = authz_dao::get_setting(pool, TOKEN_KEY_SETTING)
            .await
            .context("read the registry token key")?;
        if let Some(stored) = &stored {
            match open_key(stored, envelope).await {
                Ok(key) => return Ok(TokenKeys::new(vec![key])),
                Err(error) if secret_dao::is_unreadable_setting(&error) => {
                    // Tokens only live minutes, so a new key costs the
                    // instances still holding the old one a re-login, once
                    // they have picked it up (`spawn_token_key_refresh`).
                    tracing::warn!(%error, "registry token key unreadable; generating a new one");
                }
                Err(error) => return Err(error).context("open the registry token key"),
            }
        }
        let key = new_key();
        let secret = PlaintextSecret::from(base64::engine::general_purpose::STANDARD.encode(&key));
        // Replaces only the value read above; another instance that stored
        // one first wins, and the next round uses theirs.
        if secret_dao::store_secret_setting(
            pool,
            envelope,
            TOKEN_KEY_SETTING,
            &secret,
            stored.as_deref(),
        )
        .await
        .context("store the registry token key")?
        .is_some()
        {
            return Ok(TokenKeys::new(vec![key]));
        }
    }
    anyhow::bail!("could not settle the registry token key with the other instances")
}

/// How often [`spawn_token_key_refresh`] re-reads the shared key.
pub const TOKEN_KEY_REFRESH: std::time::Duration = std::time::Duration::from_secs(30);

/// Pick up a registry token key another instance stored (one that could not
/// open the previous key replaced it): sign with it from then on, and keep
/// accepting the previous key's tokens ([`TokenKeys::rotate_to`]). Runs every
/// [`TOKEN_KEY_REFRESH`]; only for the generated key, not with
/// `docker.token_secret`. A key that does not open is logged and left to the
/// instance that next starts.
pub fn spawn_token_key_refresh(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut seen: Option<String> = None;
        let mut ticker = tokio::time::interval(TOKEN_KEY_REFRESH);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let stored = match authz_dao::get_setting(&state.pool, TOKEN_KEY_SETTING).await {
                Ok(Some(stored)) => stored,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(%error, "cannot re-read the registry token key");
                    continue;
                }
            };
            if seen.as_deref() == Some(stored.as_str()) {
                continue;
            }
            match open_key(&stored, state.envelope.as_deref()).await {
                Ok(key) => {
                    if state.registry_keys.rotate_to(key) {
                        tracing::info!("picked up a new registry token key");
                    }
                    seen = Some(stored);
                }
                Err(error) => {
                    tracing::warn!(%error, "cannot open the stored registry token key");
                    // Warn once about a key that never opens; retry others.
                    if secret_dao::is_unreadable_setting(&error) {
                        seen = Some(stored);
                    }
                }
            }
        }
    })
}

fn new_key() -> Vec<u8> {
    use rand::Rng;
    let mut key = vec![0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

/// Open a stored registry token key (base64 key material, as a secret
/// setting). Bad key material counts as malformed.
async fn open_key(
    stored: &str,
    envelope: Option<&EnvelopeService>,
) -> Result<Vec<u8>, secret_dao::SecretDbError> {
    let malformed = || secret_dao::SecretDbError::MalformedSetting(TOKEN_KEY_SETTING.to_string());
    let secret = secret_dao::open_secret_setting(envelope, TOKEN_KEY_SETTING, stored).await?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(secret.expose_secret())
        .map_err(|_| malformed())?;
    if key.len() < 32 {
        return Err(malformed());
    }
    Ok(key)
}
