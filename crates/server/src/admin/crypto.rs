//! Admin surface for secret encryption at rest (slice 12.5). **Admin-only**
//! (mounted under the [`super::require_admin`] gate).
//!
//! * `GET /admin/crypto/keys` — key **metadata only** (layer, version,
//!   algorithm, state, timestamps, parent references). Wrapped key bytes —
//!   let alone unwrapped ones or decrypted secrets — are **never** returned;
//!   the view type below simply has no field for them.
//! * `POST /admin/crypto/rotate/{dek|kek|root}` — on-demand rotation per
//!   layer. `dek` mints a new active DEK and immediately runs the re-encrypt
//!   sweep + revoke bookkeeping (the secret tables are small); `kek` mints a
//!   new KEK and re-wraps every DEK (ciphertext untouched); `root` re-wraps
//!   every KEK under the provider's current root (run it after swapping the
//!   root key; DEKs + ciphertext untouched).
//!
//! When encryption is disabled, `keys` reports `enabled: false` and rotation
//! returns **409 Conflict** (the operator asked for something the deployment
//! is not configured to do).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_crypto::store::{KeyLayer, KeyRecord};
use forge_db::secret_dao;
use serde::Serialize;
use serde_json::json;

use crate::state::AppState;

/// Metadata-only view of an `encryption_key` row. Deliberately has **no**
/// `wrapped_key` field, so key bytes cannot leak through this endpoint.
#[derive(Debug, Serialize)]
pub struct KeyView {
    pub layer: String,
    pub version: i32,
    pub algorithm: String,
    pub state: String,
    pub scope: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// KEK rows: which root id wrapped this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_key_id: Option<String>,
    /// KEK rows: which root version label wrapped this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_key_version: Option<String>,
    /// DEK rows: which KEK version wrapped this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapping_kek_version: Option<i32>,
}

impl From<&KeyRecord> for KeyView {
    fn from(k: &KeyRecord) -> Self {
        KeyView {
            layer: k.layer.as_str().to_string(),
            version: k.version,
            algorithm: k.algorithm.as_str().to_string(),
            state: k.state.as_str().to_string(),
            scope: k.scope.clone(),
            created_at: k.created_at,
            rotated_at: k.rotated_at,
            root_key_id: k.root_key_id.clone(),
            root_key_version: k.root_key_version.clone(),
            wrapping_kek_version: k.wrapping_kek_version,
        }
    }
}

fn crypto_error(e: impl std::fmt::Display) -> Response {
    // CryptoError/SecretDbError carry no key material or plaintext by
    // construction, so the message is safe to return to an admin.
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("crypto error: {e}"),
    )
        .into_response()
}

fn disabled() -> Response {
    (
        StatusCode::CONFLICT,
        "secret encryption at rest is not enabled (configure [crypto])",
    )
        .into_response()
}

/// `GET /admin/crypto/keys`
pub async fn list_keys(State(state): State<AppState>) -> Response {
    let Some(envelope) = &state.envelope else {
        return Json(json!({ "enabled": false, "keys": [] })).into_response();
    };

    let mut keys = Vec::new();
    for layer in [KeyLayer::Kek, KeyLayer::Dek] {
        match envelope.list_keys(layer).await {
            Ok(records) => keys.extend(records.iter().map(KeyView::from)),
            Err(e) => return crypto_error(e),
        }
    }
    let root_version = match envelope.current_root_version().await {
        Ok(v) => v,
        Err(e) => return crypto_error(e),
    };
    let backfill_pending = match secret_dao::plaintext_passwords_pending(&state.pool).await {
        Ok(p) => p,
        Err(e) => return crypto_error(e),
    };
    Json(json!({
        "enabled": true,
        "root_key_version": root_version,
        "plaintext_backfill_pending": backfill_pending,
        "keys": keys,
    }))
    .into_response()
}

/// `POST /admin/crypto/rotate/{layer}` with `layer` ∈ `dek` | `kek` | `root`.
pub async fn rotate(State(state): State<AppState>, Path(layer): Path<String>) -> Response {
    let Some(envelope) = &state.envelope else {
        return disabled();
    };

    match layer.as_str() {
        "dek" => {
            let rec = match envelope.rotate_dek().await {
                Ok(r) => r,
                Err(e) => return crypto_error(e),
            };
            // The secret tables are small, so run the re-encrypt sweep inline
            // rather than waiting for the next worker tick. Idempotent — the
            // worker re-running it later is harmless.
            let mut after_id = 0i64;
            let mut resealed = 0usize;
            loop {
                match secret_dao::reseal_upstream_passwords_batch(
                    &state.pool,
                    envelope,
                    after_id,
                    500,
                )
                .await
                {
                    Ok(batch) => {
                        resealed += batch.resealed;
                        match batch.next_after_id {
                            Some(id) => after_id = id,
                            None => break,
                        }
                    }
                    Err(e) => return crypto_error(e),
                }
            }
            let revoked = match secret_dao::revoke_unreferenced_deks(&state.pool, envelope).await {
                Ok(n) => n,
                Err(e) => return crypto_error(e),
            };
            Json(json!({
                "rotated": "dek",
                "new_version": rec.version,
                "resealed_secrets": resealed,
                "revoked_deks": revoked,
            }))
            .into_response()
        }
        "kek" => match envelope.rotate_kek().await {
            // rotate_kek already re-wraps every DEK + revokes unreferenced
            // KEKs; secret ciphertext is untouched by design.
            Ok(rec) => {
                Json(json!({ "rotated": "kek", "new_version": rec.version })).into_response()
            }
            Err(e) => crypto_error(e),
        },
        "root" => match envelope.rewrap_keks().await {
            Ok(rewrapped) => Json(json!({
                "rotated": "root",
                "rewrapped_keks": rewrapped,
            }))
            .into_response(),
            Err(e) => crypto_error(e),
        },
        other => (
            StatusCode::BAD_REQUEST,
            format!("unknown rotation layer {other:?} (expected dek|kek|root)"),
        )
            .into_response(),
    }
}
