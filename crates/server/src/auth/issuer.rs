//! Forge as an OIDC issuer of its own client assertions (see
//! [`forge_core::oidc::assertion`]): what lets an `oidc` realm with
//! `client_authentication = "federated_credential"` sign in at Microsoft
//! Entra without a client secret.
//!
//! * [`AssertionIssuer`] — the install's issuer key set. Every instance
//!   shares it through the `forge_setting` [`ISSUER_KEYS_SETTING`] (sealed
//!   with the envelope service when secret encryption is enabled, and
//!   re-sealed by DEK rotation like every other secret). It is created on
//!   first use (a federated realm is saved, enabled or signs in), re-read by
//!   every instance every [`ISSUER_REFRESH`], and rotated by whichever
//!   instance first finds a rotation due: a compare-and-swap on the setting,
//!   no locks.
//! * [`issuer_router`] — `GET /.well-known/openid-configuration` and
//!   `GET /.well-known/jwks.json`, public, for the IdP that verifies the
//!   assertions. The issuer is `server.public_base_url`. Both answer 404
//!   until a key set exists: before, forge has issued nothing.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use chrono::Utc;
use forge_core::oidc::assertion::{AssertionClaims, IssuerKeySet, SIGNING_ALG};
use forge_core::oidc::ClientAssertion;
use forge_crypto::service::EnvelopeService;
use forge_crypto::{ExposeSecret, PlaintextSecret};
use forge_db::{authz_dao, secret_dao};
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;

use crate::state::AppState;

/// `forge_setting` key of the issuer key set (private keys: a secret).
pub const ISSUER_KEYS_SETTING: &str = secret_dao::OIDC_ISSUER_KEYS_SETTING;

/// Where the discovery document is served.
pub const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// Where the JWKS is served.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// How often every instance re-reads the shared key set (and checks whether a
/// rotation is due). A rotated key is published days before it signs, so
/// instances converge long before it matters.
pub const ISSUER_REFRESH: Duration = Duration::from_secs(60);

/// While no key set is known, how often the public endpoints ask the
/// database whether another instance created one meanwhile.
const EMPTY_RECHECK: Duration = Duration::from_secs(1);

/// `Cache-Control` of the discovery document and the JWKS.
const PUBLIC_CACHE: &str = "public, max-age=300";

/// The install's issuer key set, shared by every instance (module docs).
/// Clones share it.
#[derive(Clone)]
pub struct AssertionIssuer {
    inner: Arc<Inner>,
}

struct Inner {
    pool: PgPool,
    envelope: Option<Arc<EnvelopeService>>,
    /// The issuer URL (`server.public_base_url`, no trailing `/`).
    issuer: String,
    current: RwLock<Current>,
    /// Serializes this instance's reads and writes of the stored key set;
    /// holds when the database was last asked while no key set was known.
    sync: tokio::sync::Mutex<Option<Instant>>,
}

/// The key set this instance publishes, and the stored value it was read
/// from.
#[derive(Clone, Default)]
struct Current {
    stored: Option<String>,
    keys: Option<Arc<IssuerKeySet>>,
}

impl AssertionIssuer {
    /// The issuer `issuer` (the public base URL), keeping its keys in `pool`,
    /// sealed with `envelope` when secret encryption is enabled.
    pub fn new(pool: PgPool, envelope: Option<Arc<EnvelopeService>>, issuer: String) -> Self {
        AssertionIssuer {
            inner: Arc::new(Inner {
                pool,
                envelope,
                issuer: issuer.trim_end_matches('/').to_string(),
                current: RwLock::new(Current::default()),
                sync: tokio::sync::Mutex::new(None),
            }),
        }
    }

    /// The issuer URL: the assertions' `iss`, and what the IdP's credential
    /// names.
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    fn current(&self) -> Current {
        self.inner
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_current(&self, stored: Option<String>, keys: Option<Arc<IssuerKeySet>>) {
        *self
            .inner
            .current
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Current { stored, keys };
    }

    /// The published key set, if one exists. While none is known the
    /// database is asked (at most every [`EMPTY_RECHECK`]): another instance
    /// may just have created one, and the IdP may ask this instance first.
    pub async fn published(&self) -> anyhow::Result<Option<Arc<IssuerKeySet>>> {
        if let Some(keys) = self.current().keys {
            return Ok(Some(keys));
        }
        let mut checked = self.inner.sync.lock().await;
        if let Some(keys) = self.current().keys {
            return Ok(Some(keys));
        }
        if checked.is_some_and(|at| at.elapsed() < EMPTY_RECHECK) {
            return Ok(None);
        }
        *checked = Some(Instant::now());
        let Some(stored) = self.read_stored().await? else {
            return Ok(None);
        };
        match self.open(&stored).await {
            Ok(keys) => {
                let keys = Arc::new(keys);
                self.set_current(Some(stored), Some(keys.clone()));
                Ok(Some(keys))
            }
            Err(error) => Err(error).context("open the issuer keys"),
        }
    }

    /// The key set, created when none exists yet. A stored key set that can
    /// never be opened (malformed, or sealed under a data key that does not
    /// open it) is replaced; a database, key store or configuration error is
    /// returned instead, since replacing the shared keys would unpublish the
    /// ones the other instances sign with.
    pub async fn ensure(&self) -> anyhow::Result<Arc<IssuerKeySet>> {
        if let Some(keys) = self.current().keys {
            return Ok(keys);
        }
        let _sync = self.inner.sync.lock().await;
        for _ in 0..5 {
            if let Some(keys) = self.current().keys {
                return Ok(keys);
            }
            let stored = self.read_stored().await?;
            if let Some(stored) = &stored {
                match self.open(stored).await {
                    Ok(keys) => {
                        let keys = Arc::new(keys);
                        self.set_current(Some(stored.clone()), Some(keys.clone()));
                        return Ok(keys);
                    }
                    Err(error) if secret_dao::is_unreadable_setting(&error) => {
                        tracing::warn!(%error, "issuer keys unreadable; generating new ones");
                    }
                    Err(error) => return Err(error).context("open the issuer keys"),
                }
            }
            let keys = Arc::new(
                tokio::task::spawn_blocking(|| IssuerKeySet::generate(Utc::now()))
                    .await
                    .context("generate the issuer keys")??,
            );
            // Replaces only the value read above; another instance that
            // stored one first wins, and the next round uses theirs.
            if let Some(written) = self.store(&keys, stored.as_deref()).await? {
                tracing::info!(issuer = %self.issuer(), "created the client assertion issuer keys");
                self.set_current(Some(written), Some(keys.clone()));
                return Ok(keys);
            }
        }
        anyhow::bail!("could not settle the issuer keys with the other instances")
    }

    /// Pick up the key set another instance stored, then rotate it when a
    /// rotation is due ([`IssuerKeySet::rotated`]). A key set that does not
    /// open is left to [`AssertionIssuer::ensure`].
    pub async fn refresh(&self) -> anyhow::Result<()> {
        let _sync = self.inner.sync.lock().await;
        let Some(stored) = self.read_stored().await? else {
            self.set_current(None, None);
            return Ok(());
        };
        let current = self.current();
        let keys = match current.keys {
            Some(keys) if current.stored.as_deref() == Some(stored.as_str()) => keys,
            _ => {
                let keys = Arc::new(self.open(&stored).await.context("open the issuer keys")?);
                self.set_current(Some(stored.clone()), Some(keys.clone()));
                keys
            }
        };
        let rotating = keys.clone();
        let rotated = tokio::task::spawn_blocking(move || rotating.rotated(Utc::now()))
            .await
            .context("rotate the issuer keys")?;
        if let Some(rotated) = rotated {
            let rotated = Arc::new(rotated?);
            // Lost to another instance's rotation: picked up next round.
            if let Some(written) = self.store(&rotated, Some(&stored)).await? {
                tracing::info!(
                    kid = %rotated.keys()[0].kid(),
                    "rotated the client assertion issuer keys (the new key signs once published for a while)"
                );
                self.set_current(Some(written), Some(rotated));
            }
        }
        Ok(())
    }

    /// A client assertion for `claims`, signed now.
    pub async fn sign(&self, claims: &AssertionClaims) -> anyhow::Result<String> {
        let keys = self.ensure().await?;
        Ok(keys.sign(claims, Utc::now())?)
    }

    async fn read_stored(&self) -> anyhow::Result<Option<String>> {
        authz_dao::get_setting(&self.inner.pool, ISSUER_KEYS_SETTING)
            .await
            .context("read the issuer keys")
    }

    /// Open a stored key set. Key material that does not parse counts as
    /// malformed.
    async fn open(&self, stored: &str) -> Result<IssuerKeySet, secret_dao::SecretDbError> {
        let secret = secret_dao::open_secret_setting(
            self.inner.envelope.as_deref(),
            ISSUER_KEYS_SETTING,
            stored,
        )
        .await?;
        IssuerKeySet::from_stored(secret.expose_secret()).map_err(|error| {
            tracing::warn!(%error, "stored issuer keys do not parse");
            secret_dao::SecretDbError::MalformedSetting(ISSUER_KEYS_SETTING.to_string())
        })
    }

    /// Store `keys` while the stored value is still `expected` (unset for
    /// `None`). Returns the stored value, or `None` when another instance
    /// wrote first.
    async fn store(
        &self,
        keys: &IssuerKeySet,
        expected: Option<&str>,
    ) -> anyhow::Result<Option<String>> {
        secret_dao::store_secret_setting(
            &self.inner.pool,
            self.inner.envelope.as_deref(),
            ISSUER_KEYS_SETTING,
            &PlaintextSecret::from(keys.to_stored()),
            expected,
        )
        .await
        .context("store the issuer keys")
    }
}

/// The client assertion of one `oidc` realm: forge's issuer signing
/// `claims` per token request.
pub struct RealmAssertion {
    pub issuer: AssertionIssuer,
    pub claims: AssertionClaims,
}

#[async_trait::async_trait]
impl ClientAssertion for RealmAssertion {
    async fn client_assertion(&self) -> Result<String, String> {
        self.issuer.sign(&self.claims).await.map_err(|error| {
            tracing::error!(error = %format!("{error:#}"), "cannot sign the client assertion");
            "the client assertion could not be signed".to_string()
        })
    }
}

/// Keep the issuer keys current on this instance: create them as soon as an
/// enabled `oidc` realm authenticates with them (the IdP is set up from the
/// published issuer before the first login), re-read them every
/// [`ISSUER_REFRESH`], and rotate them when due.
pub fn spawn_issuer_refresh(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ISSUER_REFRESH);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let needed = state
                .realms
                .snapshot()
                .await
                .is_ok_and(|snapshot| snapshot.uses_assertion_issuer());
            if needed {
                if let Err(error) = state.assertion_issuer.ensure().await {
                    tracing::warn!(error = %format!("{error:#}"), "cannot create the issuer keys");
                }
            }
            if let Err(error) = state.assertion_issuer.refresh().await {
                tracing::warn!(error = %format!("{error:#}"), "cannot refresh the issuer keys");
            }
        }
    })
}

/// `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json`.
pub fn issuer_router() -> Router<AppState> {
    Router::new()
        .route(DISCOVERY_PATH, get(discovery))
        .route(JWKS_PATH, get(jwks))
}

/// The discovery document of an issuer that signs tokens and nothing else:
/// the members an IdP reads to verify them (the shape Kubernetes' service
/// account issuer publishes).
async fn discovery(State(state): State<AppState>) -> Response {
    let issuer = &state.assertion_issuer;
    published(issuer, |_| {
        json!({
            "issuer": issuer.issuer(),
            "jwks_uri": format!("{}{JWKS_PATH}", issuer.issuer()),
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [SIGNING_ALG],
        })
    })
    .await
}

async fn jwks(State(state): State<AppState>) -> Response {
    published(&state.assertion_issuer, IssuerKeySet::jwks).await
}

/// `document` of the published key set, cacheable for a few minutes; 404
/// while there is none.
async fn published(
    issuer: &AssertionIssuer,
    document: impl FnOnce(&IssuerKeySet) -> JsonValue,
) -> Response {
    match issuer.published().await {
        Ok(Some(keys)) => (
            [(
                header::CACHE_CONTROL,
                HeaderValue::from_static(PUBLIC_CACHE),
            )],
            Json(document(&keys)),
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "forge issues no client assertions").into_response(),
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "cannot read the issuer keys");
            (StatusCode::SERVICE_UNAVAILABLE, "issuer keys unavailable").into_response()
        }
    }
}
