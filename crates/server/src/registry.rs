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
use forge_core::repo::PublishPolicy;
use forge_crypto::service::EnvelopeService;
use forge_crypto::{AeadBinding, ExposeSecret, PlaintextSecret};
use forge_db::authz_dao;
use forge_db::model::Repository;
use forge_oci::token::TokenKeys;
use sha2::Digest;
use sqlx::PgPool;

use crate::config::Config;
use crate::middleware::principal_of;
use crate::state::AppState;

/// `forge_setting` key of the generated registry-token signing key.
pub const TOKEN_KEY_SETTING: &str = "docker_token_key";

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
/// secret encryption is enabled).
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
        match authz_dao::get_setting(pool, TOKEN_KEY_SETTING)
            .await
            .context("read the registry token key")?
        {
            Some(stored) => match open_key(&stored, envelope).await {
                Ok(key) => return Ok(TokenKeys::new(vec![key])),
                Err(error) => {
                    // Sealed under a key this instance cannot open (crypto
                    // turned off, a retired DEK): tokens only live minutes,
                    // so a new key costs nothing but a re-login.
                    tracing::warn!(%error, "registry token key unreadable; generating a new one");
                    let key = new_key();
                    let encoded = seal_key(&key, envelope).await?;
                    if authz_dao::replace_setting(pool, TOKEN_KEY_SETTING, &stored, &encoded)
                        .await
                        .context("replace the registry token key")?
                    {
                        return Ok(TokenKeys::new(vec![key]));
                    }
                }
            },
            None => {
                let key = new_key();
                let encoded = seal_key(&key, envelope).await?;
                if authz_dao::insert_setting_if_absent(pool, TOKEN_KEY_SETTING, &encoded)
                    .await
                    .context("store the registry token key")?
                {
                    return Ok(TokenKeys::new(vec![key]));
                }
                // Another instance stored one first: use theirs.
            }
        }
    }
    anyhow::bail!("could not settle the registry token key with the other instances")
}

fn new_key() -> Vec<u8> {
    use rand::Rng;
    let mut key = vec![0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

fn binding() -> AeadBinding<'static> {
    AeadBinding {
        table: "forge_setting",
        column: "value",
        row_pk: 0,
        destination: Some(TOKEN_KEY_SETTING),
    }
}

async fn seal_key(key: &[u8], envelope: Option<&EnvelopeService>) -> anyhow::Result<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    match envelope {
        Some(envelope) => {
            let sealed = envelope
                .seal(&PlaintextSecret::from(b64.encode(key)), binding())
                .await
                .context("seal the registry token key")?;
            Ok(format!("sealed:{}", b64.encode(sealed)))
        }
        None => Ok(format!("plain:{}", b64.encode(key))),
    }
}

async fn open_key(stored: &str, envelope: Option<&EnvelopeService>) -> anyhow::Result<Vec<u8>> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let key = if let Some(plain) = stored.strip_prefix("plain:") {
        b64.decode(plain).context("decode the registry token key")?
    } else if let Some(sealed) = stored.strip_prefix("sealed:") {
        let envelope =
            envelope.context("the registry token key is sealed but [crypto] is not configured")?;
        let blob = b64
            .decode(sealed)
            .context("decode the sealed registry token key")?;
        let opened = envelope
            .open(&blob, binding())
            .await
            .context("open the registry token key")?;
        b64.decode(opened.expose_secret())
            .context("decode the registry token key")?
    } else {
        anyhow::bail!("unknown registry token key encoding");
    };
    anyhow::ensure!(key.len() >= 32, "registry token key too short");
    Ok(key)
}
