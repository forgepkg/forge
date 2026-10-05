//! The envelope service: key bootstrap, seal/open, per-layer rotation, and the
//! bounded zeroizing cache of unwrapped keys (plan §2.4–§2.7).
//!
//! ```text
//! seal(pt, binding):  active DEK ──(cache)── unwrap via KEK via root ── AEAD encrypt
//! open(blob, binding): blob.dek_version ──(cache)── unwrap ───────────── AEAD decrypt
//! ```
//!
//! ## The unwrapped-key cache and §2.1
//!
//! Unwrapping a KEK (a root-provider call — a KMS round-trip in production) or
//! a DEK (an AEAD under a KEK) on every secret read would be slow, so unwrapped
//! key bytes are kept in a **bounded, TTL'd `moka` cache** with singleflight
//! (`try_get_with`): a burst of reads unwraps once. This is *not* authoritative
//! in-memory state — the authoritative material is the wrapped rows in the
//! [`KeyStore`] plus the root held by the [`KmsProvider`]; a cold instance
//! reconstructs every key from those. Values are [`KeyBytes`]
//! (zeroized on drop/eviction). Revoking a key evicts it immediately on the
//! instance performing the revoke; other instances converge within the TTL
//! (default 300 s) — acceptable because `revoked` is only ever applied to keys
//! nothing references anymore.
//!
//! ## Rotation (plan §2.7) — each layer re-wraps only its own rows
//!
//! * [`EnvelopeService::rotate_dek`] — new active DEK for new writes; old
//!   ciphertext is re-encrypted lazily by the data-access sweep (which calls
//!   [`EnvelopeService::reseal`]) and the old DEK is revoked once unreferenced.
//! * [`EnvelopeService::rotate_kek`] — new active KEK, then
//!   [`EnvelopeService::rewrap_deks`]: every DEK row is re-wrapped under the
//!   new KEK. **Secret ciphertext is never touched.**
//! * Root rotation — the operator swaps the root (KMS rotation / new env+file
//!   value with the old kept as *previous*); [`EnvelopeService::rewrap_keks`]
//!   re-wraps every KEK row under the current root. **DEK rows and secret
//!   ciphertext are never touched.**
//!
//! All sweeps are idempotent and resumable: a crash mid-sweep leaves a mix of
//! old/new parent references that the next run finishes, and both parents
//! remain usable (`active`/`retiring`) during the window.
//!
//! ## Concurrent rotations
//!
//! The server serializes rotation passes cluster-wide (an advisory lock taken
//! by the worker *and* the admin endpoints), but the key store does not rely
//! on it: every re-wrap is a compare-and-swap against the row as read
//! ([`KeyStore::update_wrapped`]) that also refuses a revoked target parent,
//! and a KEK is revoked only if no DEK references it at commit time
//! ([`KeyStore::revoke_kek_if_unreferenced`]). Racing rotations can therefore
//! skip rows (picked up by the next pass) or fail, but never leave a DEK
//! wrapped under a revoked KEK.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;

use crate::envelope::{self, AeadBinding, Algorithm};
use crate::error::CryptoError;
use crate::kms::KmsProvider;
use crate::secret::{KeyBytes, PlaintextSecret};
use crate::store::{KeyLayer, KeyRecord, KeyState, KeyStore, NewKeyRecord};

/// Tuning for the envelope service (mirrors the `[crypto]` config surface).
#[derive(Debug, Clone)]
pub struct EnvelopeServiceConfig {
    /// AEAD for **new** keys and new secret envelopes (existing material keeps
    /// the algorithm recorded on its key row / blob header).
    pub algorithm: Algorithm,
    /// Key scope discriminator; `"default"` until multi-tenancy needs more.
    pub scope: String,
    /// TTL of the unwrapped-key cache (bounds both KMS traffic and how long
    /// unwrapped key bytes may linger in RAM).
    pub unwrapped_key_ttl: Duration,
    /// Max entries in the unwrapped-key cache.
    pub unwrapped_key_max: u64,
    /// Also open secrets sealed by pre-release builds, which bound a secret to
    /// its row but not to where it is sent ([`AeadBinding::row_only`]), so the
    /// re-seal sweep can move them to the destination binding. Off by default:
    /// while on, someone who can write to the database can replay such a blob
    /// into a row they repointed.
    pub accept_row_bound_secrets: bool,
}

impl Default for EnvelopeServiceConfig {
    fn default() -> Self {
        EnvelopeServiceConfig {
            algorithm: Algorithm::Aes256Gcm,
            scope: "default".to_string(),
            unwrapped_key_ttl: Duration::from_secs(300),
            unwrapped_key_max: 64,
            accept_row_bound_secrets: false,
        }
    }
}

/// Seals/opens secret values under the double-envelope hierarchy.
///
/// Cheap to clone-via-`Arc` and shared process-wide; all state is either the
/// shared stores or the bounded unwrapped-key cache.
pub struct EnvelopeService {
    store: Arc<dyn KeyStore>,
    root: Arc<dyn KmsProvider>,
    config: EnvelopeServiceConfig,
    /// Unwrapped key bytes, keyed by `(layer, version)`. Values are zeroized
    /// when evicted/dropped ([`KeyBytes`] wraps `Zeroizing`).
    keys: moka::future::Cache<(KeyLayer, i32), Arc<KeyBytes>>,
}

impl std::fmt::Debug for EnvelopeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeService")
            .field("root_key_id", &self.root.root_key_id())
            .field("config", &self.config)
            .field("cached_keys", &self.keys.entry_count())
            .finish()
    }
}

impl EnvelopeService {
    /// Build the service over a key store (Postgres in production) and a root
    /// provider (env/file in dev, KMS later).
    pub fn new(
        store: Arc<dyn KeyStore>,
        root: Arc<dyn KmsProvider>,
        config: EnvelopeServiceConfig,
    ) -> Self {
        let keys = moka::future::Cache::builder()
            .max_capacity(config.unwrapped_key_max)
            .time_to_live(config.unwrapped_key_ttl)
            .build();
        EnvelopeService {
            store,
            root,
            config,
            keys,
        }
    }

    /// The configured key scope.
    pub fn scope(&self) -> &str {
        &self.config.scope
    }

    /// Whether secrets sealed under [`AeadBinding::row_only`] by pre-release
    /// builds may still be opened (`crypto.accept_row_bound_secrets`).
    pub fn accepts_row_bound_secrets(&self) -> bool {
        self.config.accept_row_bound_secrets
    }

    // ── Bootstrap ────────────────────────────────────────────────────────────

    /// Idempotently make sure an active KEK **and** an active DEK exist
    /// (startup bootstrap; also runs lazily on the first [`Self::seal`]).
    /// Concurrent callers converge on one active key per layer (the store's
    /// `insert_active_if_absent` is atomic).
    pub async fn ensure_active_keys(&self) -> Result<(), CryptoError> {
        self.ensure_active_dek().await?;
        Ok(())
    }

    async fn ensure_active_kek(&self) -> Result<KeyRecord, CryptoError> {
        if let Some(rec) = self.store.get_active(KeyLayer::Kek, self.scope()).await? {
            return Ok(rec);
        }
        let kek = KeyBytes::generate();
        let wrapped = self.root.wrap_kek(kek.expose()).await?;
        let new = NewKeyRecord {
            layer: KeyLayer::Kek,
            algorithm: self.config.algorithm,
            wrapped_key: wrapped,
            root_key_id: Some(self.root.root_key_id().to_string()),
            root_key_version: Some(self.root.current_root_version().await?),
            wrapping_kek_version: None,
            scope: self.scope().to_string(),
        };
        self.store.insert_active_if_absent(new).await
    }

    async fn ensure_active_dek(&self) -> Result<KeyRecord, CryptoError> {
        if let Some(rec) = self.store.get_active(KeyLayer::Dek, self.scope()).await? {
            return Ok(rec);
        }
        let new = self.new_wrapped_dek().await?;
        self.store.insert_active_if_absent(new).await
    }

    /// Generate fresh DEK bytes and wrap them under the active KEK.
    async fn new_wrapped_dek(&self) -> Result<NewKeyRecord, CryptoError> {
        let kek_record = self.ensure_active_kek().await?;
        let kek = self.unwrap_kek_cached(kek_record.version).await?;
        let dek = KeyBytes::generate();
        let wrapped = envelope::seal_with_key(
            kek_record.algorithm,
            &kek,
            version_u32(kek_record.version)?,
            dek.expose(),
            &envelope::key_wrap_aad(KeyLayer::Dek.as_str(), self.scope()),
        )?;
        Ok(NewKeyRecord {
            layer: KeyLayer::Dek,
            algorithm: self.config.algorithm,
            wrapped_key: wrapped,
            root_key_id: None,
            root_key_version: None,
            wrapping_kek_version: Some(kek_record.version),
            scope: self.scope().to_string(),
        })
    }

    // ── Seal / open ──────────────────────────────────────────────────────────

    /// Encrypt a plaintext secret under the **active DEK**, binding the
    /// ciphertext to its row identity via AAD. Returns the envelope blob to
    /// store in the owning table's `bytea` column.
    pub async fn seal(
        &self,
        plaintext: &PlaintextSecret,
        binding: AeadBinding<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        let dek_record = self.ensure_active_dek().await?;
        let dek = self.unwrap_dek_cached(dek_record.version).await?;
        envelope::seal_with_key(
            dek_record.algorithm,
            &dek,
            version_u32(dek_record.version)?,
            plaintext.expose_secret().as_bytes(),
            &binding.aad(),
        )
    }

    /// Decrypt an envelope blob, verifying it was sealed for exactly this
    /// `binding` (a blob copied to another row/column/table fails).
    pub async fn open(
        &self,
        blob: &[u8],
        binding: AeadBinding<'_>,
    ) -> Result<PlaintextSecret, CryptoError> {
        let header = envelope::parse_header(blob)?;
        let dek = self
            .unwrap_dek_cached(version_i32(header.key_version)?)
            .await?;
        let plaintext = envelope::open_with_key(&dek, blob, &binding.aad())?;
        // Validate UTF-8 before constructing the SecretString; the only copy of
        // the bytes goes straight into the zeroizing SecretString.
        std::str::from_utf8(&plaintext).map_err(|_| CryptoError::NotUtf8)?;
        let s = String::from_utf8(plaintext.to_vec()).expect("validated UTF-8");
        Ok(PlaintextSecret::from(s))
    }

    /// Whether `blob` was sealed under a DEK other than the current active one
    /// (i.e. the DEK-rotation sweep should re-encrypt it).
    pub async fn needs_reseal(&self, blob: &[u8]) -> Result<bool, CryptoError> {
        let header = envelope::parse_header(blob)?;
        let active = self.store.get_active(KeyLayer::Dek, self.scope()).await?;
        match active {
            Some(a) => Ok(version_u32(a.version)? != header.key_version),
            // No active DEK at all: stale by definition (resealing bootstraps).
            None => Ok(true),
        }
    }

    /// Re-encrypt a blob under the **active** DEK (same plaintext, same
    /// binding, fresh nonce). Used by the DEK-rotation sweep.
    pub async fn reseal(
        &self,
        blob: &[u8],
        binding: AeadBinding<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        let plaintext = self.open(blob, binding).await?;
        self.seal(&plaintext, binding).await
    }

    /// The DEK version a stored blob references (sweep bookkeeping).
    pub fn blob_dek_version(blob: &[u8]) -> Result<i32, CryptoError> {
        version_i32(envelope::parse_header(blob)?.key_version)
    }

    // ── Rotation (plan §2.7) ─────────────────────────────────────────────────

    /// Mint a new **active DEK** (wrapped under the active KEK); the previous
    /// active DEK flips to `retiring` and keeps decrypting old ciphertext until
    /// the data sweep re-encrypts it and revokes the key.
    pub async fn rotate_dek(&self) -> Result<KeyRecord, CryptoError> {
        let new = self.new_wrapped_dek().await?;
        let rec = self.store.insert_active(new).await?;
        tracing::info!(version = rec.version, scope = %rec.scope, "rotated DEK");
        Ok(rec)
    }

    /// Mint a new **active KEK** (wrapped under the current root), re-wrap
    /// every DEK row under it, and revoke now-unreferenced old KEKs. Secret
    /// ciphertext is never read or written.
    pub async fn rotate_kek(&self) -> Result<KeyRecord, CryptoError> {
        let kek = KeyBytes::generate();
        let wrapped = self.root.wrap_kek(kek.expose()).await?;
        let new = NewKeyRecord {
            layer: KeyLayer::Kek,
            algorithm: self.config.algorithm,
            wrapped_key: wrapped,
            root_key_id: Some(self.root.root_key_id().to_string()),
            root_key_version: Some(self.root.current_root_version().await?),
            wrapping_kek_version: None,
            scope: self.scope().to_string(),
        };
        let rec = self.store.insert_active(new).await?;
        tracing::info!(version = rec.version, scope = %rec.scope, "rotated KEK");
        self.rewrap_deks().await?;
        self.revoke_unreferenced_keks().await?;
        Ok(rec)
    }

    /// Re-wrap every non-revoked DEK row whose `wrapping_kek_version` is not
    /// the active KEK (KEK-rotation sweep; idempotent + resumable). Returns the
    /// number of DEK rows re-wrapped.
    pub async fn rewrap_deks(&self) -> Result<usize, CryptoError> {
        let active_kek = self
            .store
            .get_active(KeyLayer::Kek, self.scope())
            .await?
            .ok_or(CryptoError::NoActiveKey("kek"))?;
        let active_bytes = self.unwrap_kek_cached(active_kek.version).await?;
        let aad = envelope::key_wrap_aad(KeyLayer::Dek.as_str(), self.scope());

        let mut rewrapped = 0;
        for dek in self.store.list(KeyLayer::Dek, self.scope()).await? {
            if dek.state == KeyState::Revoked
                || dek.wrapping_kek_version == Some(active_kek.version)
            {
                continue;
            }
            let old_kek_version = dek.wrapping_kek_version.ok_or_else(|| {
                CryptoError::Store(format!("DEK v{} has no wrapping_kek_version", dek.version))
            })?;
            let old_kek = self.unwrap_kek_cached(old_kek_version).await?;
            let dek_bytes =
                KeyBytes::from_slice(&envelope::open_with_key(&old_kek, &dek.wrapped_key, &aad)?)?;
            let new_wrapped = envelope::seal_with_key(
                active_kek.algorithm,
                &active_bytes,
                version_u32(active_kek.version)?,
                dek_bytes.expose(),
                &aad,
            )?;
            // Compare-and-swap: a concurrent rotation that already moved this
            // row (or revoked the KEK we are wrapping under) wins; the next
            // pass re-reads the row.
            if self
                .store
                .update_wrapped(&dek, &new_wrapped, None, None, Some(active_kek.version))
                .await?
            {
                rewrapped += 1;
            } else {
                tracing::debug!(
                    dek = dek.version,
                    kek = active_kek.version,
                    "DEK re-wrap lost a race with a concurrent rotation; skipped"
                );
            }
        }
        if rewrapped > 0 {
            tracing::info!(rewrapped, "re-wrapped DEK rows under the active KEK");
        }
        Ok(rewrapped)
    }

    /// Re-wrap every non-revoked KEK row whose recorded `root_key_version`
    /// differs from the provider's **current** root (root-rotation sweep;
    /// idempotent + resumable). DEK rows and secret ciphertext are untouched.
    /// Returns the number of KEK rows re-wrapped.
    pub async fn rewrap_keks(&self) -> Result<usize, CryptoError> {
        let current = self.root.current_root_version().await?;
        let mut rewrapped = 0;
        for kek in self.store.list(KeyLayer::Kek, self.scope()).await? {
            if kek.state == KeyState::Revoked || kek.root_key_version.as_deref() == Some(&current) {
                continue;
            }
            let old_version = kek.root_key_version.as_deref().ok_or_else(|| {
                CryptoError::Store(format!("KEK v{} has no root_key_version", kek.version))
            })?;
            let kek_bytes = self.root.unwrap_kek(&kek.wrapped_key, old_version).await?;
            let new_wrapped = self.root.wrap_kek(kek_bytes.expose()).await?;
            // Compare-and-swap, as in `rewrap_deks`.
            if self
                .store
                .update_wrapped(
                    &kek,
                    &new_wrapped,
                    Some(self.root.root_key_id()),
                    Some(&current),
                    None,
                )
                .await?
            {
                rewrapped += 1;
            } else {
                tracing::debug!(
                    kek = kek.version,
                    "KEK re-wrap lost a race with a concurrent rotation; skipped"
                );
            }
        }
        if rewrapped > 0 {
            tracing::info!(rewrapped, "re-wrapped KEK rows under the current root");
        }
        Ok(rewrapped)
    }

    /// Revoke `retiring` KEKs that no non-revoked DEK references anymore
    /// (post-KEK-rotation cleanup) and evict them from the unwrapped-key cache.
    /// Returns the number of KEKs revoked.
    ///
    /// The listing below is only a pre-filter: the store re-checks the
    /// reference **at commit time** ([`KeyStore::revoke_kek_if_unreferenced`]),
    /// so a DEK re-wrapped onto a KEK after this listing keeps that KEK alive.
    pub async fn revoke_unreferenced_keks(&self) -> Result<usize, CryptoError> {
        let referenced: std::collections::HashSet<i32> = self
            .store
            .list(KeyLayer::Dek, self.scope())
            .await?
            .into_iter()
            .filter(|d| d.state != KeyState::Revoked)
            .filter_map(|d| d.wrapping_kek_version)
            .collect();
        let mut revoked = 0;
        for kek in self.store.list(KeyLayer::Kek, self.scope()).await? {
            if kek.state == KeyState::Retiring
                && !referenced.contains(&kek.version)
                && self.store.revoke_kek_if_unreferenced(&kek).await?
            {
                self.forget_unwrapped(KeyLayer::Kek, kek.version).await;
                tracing::info!(layer = %kek.layer, version = kek.version, "revoked encryption key");
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    /// Evict a key's unwrapped bytes from this instance's cache (after the key
    /// was revoked elsewhere, e.g. by the DEK sweep in `forge-db`, which flips
    /// the state under its own commit-time reference check).
    pub async fn forget_unwrapped(&self, layer: KeyLayer, version: i32) {
        self.keys.invalidate(&(layer, version)).await;
    }

    /// Revoke a specific key version **unconditionally** and evict its
    /// unwrapped bytes from the cache. The caller must guarantee nothing
    /// references the key; the rotation paths use the commit-time checked
    /// [`Self::revoke_unreferenced_keks`] and `forge-db`'s
    /// `secret_dao::revoke_unreferenced_deks` instead.
    pub async fn revoke_key(&self, layer: KeyLayer, version: i32) -> Result<(), CryptoError> {
        let rec = self
            .store
            .get_version(layer, self.scope(), version)
            .await?
            .ok_or(CryptoError::KeyNotFound {
                layer: layer.as_str(),
                scope: self.scope().to_string(),
                version,
            })?;
        self.revoke(&rec).await
    }

    async fn revoke(&self, rec: &KeyRecord) -> Result<(), CryptoError> {
        self.store.set_state(rec.id, KeyState::Revoked).await?;
        self.keys.invalidate(&(rec.layer, rec.version)).await;
        tracing::info!(layer = %rec.layer, version = rec.version, "revoked encryption key");
        Ok(())
    }

    /// Key **metadata** for a layer (admin `GET /admin/crypto/keys`). Callers
    /// must not expose `wrapped_key` (the admin view strips it).
    pub async fn list_keys(&self, layer: KeyLayer) -> Result<Vec<KeyRecord>, CryptoError> {
        self.store.list(layer, self.scope()).await
    }

    /// The current root version label (admin metadata / readiness checks).
    pub async fn current_root_version(&self) -> Result<String, CryptoError> {
        self.root.current_root_version().await
    }

    // ── Unwrapped-key cache ──────────────────────────────────────────────────

    /// Unwrap a KEK by version through the cache (singleflight; the root
    /// provider is called at most once per version per TTL window).
    async fn unwrap_kek_cached(&self, version: i32) -> Result<Arc<KeyBytes>, CryptoError> {
        self.keys
            .try_get_with((KeyLayer::Kek, version), async {
                let rec = self.load_usable(KeyLayer::Kek, version).await?;
                let root_version = rec.root_key_version.as_deref().ok_or_else(|| {
                    CryptoError::Store(format!("KEK v{version} has no root_key_version"))
                })?;
                let bytes = self.root.unwrap_kek(&rec.wrapped_key, root_version).await?;
                Ok(Arc::new(bytes))
            })
            .await
            .map_err(unarc)
    }

    /// Unwrap a DEK by version through the cache (unwraps its KEK via
    /// [`Self::unwrap_kek_cached`] first).
    async fn unwrap_dek_cached(&self, version: i32) -> Result<Arc<KeyBytes>, CryptoError> {
        self.keys
            .try_get_with((KeyLayer::Dek, version), async {
                let rec = self.load_usable(KeyLayer::Dek, version).await?;
                let kek_version = rec.wrapping_kek_version.ok_or_else(|| {
                    CryptoError::Store(format!("DEK v{version} has no wrapping_kek_version"))
                })?;
                let kek = self.unwrap_kek_cached(kek_version).await?;
                let aad = envelope::key_wrap_aad(KeyLayer::Dek.as_str(), self.scope());
                let bytes = envelope::open_with_key(&kek, &rec.wrapped_key, &aad)?;
                Ok(Arc::new(KeyBytes::from_slice(&bytes)?))
            })
            .await
            .map_err(unarc)
    }

    /// Load a key row, refusing `revoked` keys (fail closed: a revoked key must
    /// never decrypt anything again; if ciphertext still references it, that is
    /// an operational error to surface, not to paper over).
    async fn load_usable(&self, layer: KeyLayer, version: i32) -> Result<KeyRecord, CryptoError> {
        let rec = self
            .store
            .get_version(layer, self.scope(), version)
            .await?
            .ok_or(CryptoError::KeyNotFound {
                layer: layer.as_str(),
                scope: self.scope().to_string(),
                version,
            })?;
        if rec.state == KeyState::Revoked {
            return Err(CryptoError::KeyRevoked {
                layer: layer.as_str(),
                version,
            });
        }
        Ok(rec)
    }
}

/// Convert a stored `i32` key version to the envelope's `u32` field.
fn version_u32(version: i32) -> Result<u32, CryptoError> {
    u32::try_from(version)
        .map_err(|_| CryptoError::Store(format!("negative key version {version}")))
}

/// Convert an envelope `u32` key version back to the store's `i32`.
fn version_i32(version: u32) -> Result<i32, CryptoError> {
    i32::try_from(version)
        .map_err(|_| CryptoError::Store(format!("key version {version} out of range")))
}

/// Unwrap moka's shared `Arc<CryptoError>` (errors are never cached; the Arc
/// only fans an error out to concurrent waiters).
fn unarc(e: Arc<CryptoError>) -> CryptoError {
    (*e).clone()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::kms::StaticRootProvider;
    use crate::store::InMemoryKeyStore;

    /// Root provider wrapper counting `unwrap_kek` calls (cache assertions).
    struct CountingRoot {
        inner: StaticRootProvider,
        unwraps: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl KmsProvider for CountingRoot {
        fn root_key_id(&self) -> &str {
            self.inner.root_key_id()
        }
        async fn current_root_version(&self) -> Result<String, CryptoError> {
            self.inner.current_root_version().await
        }
        async fn wrap_kek(&self, kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.inner.wrap_kek(kek).await
        }
        async fn unwrap_kek(&self, wrapped: &[u8], v: &str) -> Result<KeyBytes, CryptoError> {
            self.unwraps.fetch_add(1, Ordering::SeqCst);
            self.inner.unwrap_kek(wrapped, v).await
        }
    }

    fn service_with(
        store: Arc<dyn KeyStore>,
        root: Arc<dyn KmsProvider>,
        ttl: Duration,
    ) -> EnvelopeService {
        EnvelopeService::new(
            store,
            root,
            EnvelopeServiceConfig {
                unwrapped_key_ttl: ttl,
                ..Default::default()
            },
        )
    }

    fn service() -> EnvelopeService {
        service_with(
            Arc::new(InMemoryKeyStore::new()),
            Arc::new(StaticRootProvider::new(
                "test",
                Algorithm::Aes256Gcm,
                KeyBytes::generate(),
                vec![],
            )),
            Duration::from_secs(300),
        )
    }

    fn binding(row_pk: i64) -> AeadBinding<'static> {
        AeadBinding {
            table: "repository",
            column: "upstream_password_enc",
            row_pk,
            destination: None,
        }
    }

    fn secret(s: &str) -> PlaintextSecret {
        PlaintextSecret::from(s.to_string())
    }

    #[tokio::test]
    async fn end_to_end_seal_open_through_the_hierarchy() {
        let svc = service();
        // Keys are bootstrapped lazily by the first seal.
        let blob = svc
            .seal(&secret("hunter2"), binding(7))
            .await
            .expect("seal");
        assert!(
            !blob.windows(7).any(|w| w == b"hunter2"),
            "ciphertext must not contain the plaintext"
        );
        let pt = svc.open(&blob, binding(7)).await.expect("open");
        assert_eq!(pt.expose_secret(), "hunter2");

        // Binding swap fails at the service level too.
        assert!(matches!(
            svc.open(&blob, binding(9)).await.unwrap_err(),
            CryptoError::DecryptFailed
        ));
    }

    #[tokio::test]
    async fn ensure_active_keys_is_idempotent() {
        let svc = service();
        svc.ensure_active_keys().await.expect("bootstrap");
        svc.ensure_active_keys().await.expect("re-bootstrap");
        let deks = svc.list_keys(KeyLayer::Dek).await.unwrap();
        let keks = svc.list_keys(KeyLayer::Kek).await.unwrap();
        assert_eq!(deks.len(), 1);
        assert_eq!(keks.len(), 1);
        assert_eq!(deks[0].state, KeyState::Active);
        assert_eq!(keks[0].state, KeyState::Active);
    }

    #[tokio::test]
    async fn concurrent_bootstrap_converges_on_one_active_key_per_layer() {
        let svc = Arc::new(service());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let svc = svc.clone();
            handles.push(tokio::spawn(async move { svc.ensure_active_keys().await }));
        }
        for h in handles {
            h.await.expect("join").expect("bootstrap");
        }
        let deks = svc.list_keys(KeyLayer::Dek).await.unwrap();
        let keks = svc.list_keys(KeyLayer::Kek).await.unwrap();
        assert_eq!(
            deks.iter().filter(|k| k.state == KeyState::Active).count(),
            1
        );
        assert_eq!(
            keks.iter().filter(|k| k.state == KeyState::Active).count(),
            1
        );
        // `insert_active_if_absent` means no spurious extra rows either.
        assert_eq!(deks.len(), 1, "{deks:?}");
        assert_eq!(keks.len(), 1, "{keks:?}");
    }

    #[tokio::test]
    async fn multi_dek_decrypt_old_and_new_after_dek_rotation() {
        let svc = service();
        let old_blob = svc.seal(&secret("old"), binding(1)).await.unwrap();
        let v1 = EnvelopeService::blob_dek_version(&old_blob).unwrap();

        let rotated = svc.rotate_dek().await.expect("rotate dek");
        assert_eq!(rotated.version, v1 + 1);

        let new_blob = svc.seal(&secret("new"), binding(2)).await.unwrap();
        assert_eq!(
            EnvelopeService::blob_dek_version(&new_blob).unwrap(),
            rotated.version
        );

        // Both decrypt: the old DEK is `retiring`, not gone.
        assert_eq!(
            svc.open(&old_blob, binding(1))
                .await
                .unwrap()
                .expose_secret(),
            "old"
        );
        assert_eq!(
            svc.open(&new_blob, binding(2))
                .await
                .unwrap()
                .expose_secret(),
            "new"
        );
        let deks = svc.list_keys(KeyLayer::Dek).await.unwrap();
        assert_eq!(deks[0].state, KeyState::Retiring);
        assert_eq!(deks[1].state, KeyState::Active);
    }

    #[tokio::test]
    async fn reseal_moves_a_blob_to_the_active_dek() {
        let svc = service();
        let blob = svc.seal(&secret("pw"), binding(3)).await.unwrap();
        assert!(!svc.needs_reseal(&blob).await.unwrap());

        svc.rotate_dek().await.unwrap();
        assert!(svc.needs_reseal(&blob).await.unwrap());

        let resealed = svc.reseal(&blob, binding(3)).await.expect("reseal");
        assert!(!svc.needs_reseal(&resealed).await.unwrap());
        assert_eq!(
            svc.open(&resealed, binding(3))
                .await
                .unwrap()
                .expose_secret(),
            "pw"
        );

        // Once nothing references the old DEK it can be revoked; the old blob
        // then refuses to open (fail closed).
        let old_version = EnvelopeService::blob_dek_version(&blob).unwrap();
        svc.revoke_key(KeyLayer::Dek, old_version).await.unwrap();
        assert!(matches!(
            svc.open(&blob, binding(3)).await.unwrap_err(),
            CryptoError::KeyRevoked { layer: "dek", .. }
        ));
        // The resealed blob is unaffected.
        assert_eq!(
            svc.open(&resealed, binding(3))
                .await
                .unwrap()
                .expose_secret(),
            "pw"
        );
    }

    #[tokio::test]
    async fn kek_rotation_rewraps_deks_without_touching_ciphertext() {
        let svc = service();
        let blob = svc.seal(&secret("pw"), binding(5)).await.unwrap();
        let dek_before = svc.list_keys(KeyLayer::Dek).await.unwrap().remove(0);

        let new_kek = svc.rotate_kek().await.expect("rotate kek");
        assert_eq!(new_kek.version, 2);

        // DEK row re-wrapped: same version, new wrapped bytes, new parent ref.
        let dek_after = svc.list_keys(KeyLayer::Dek).await.unwrap().remove(0);
        assert_eq!(dek_after.version, dek_before.version);
        assert_ne!(dek_after.wrapped_key, dek_before.wrapped_key);
        assert_eq!(dek_after.wrapping_kek_version, Some(new_kek.version));

        // The secret ciphertext was never touched and still decrypts — even on
        // a cold instance (fresh cache over the same store/root).
        assert_eq!(
            svc.open(&blob, binding(5)).await.unwrap().expose_secret(),
            "pw"
        );

        // The old KEK is revoked once nothing references it.
        let keks = svc.list_keys(KeyLayer::Kek).await.unwrap();
        assert_eq!(keks[0].state, KeyState::Revoked);
        assert_eq!(keks[1].state, KeyState::Active);

        // Idempotent: a second sweep has nothing to do.
        assert_eq!(svc.rewrap_deks().await.unwrap(), 0);
    }

    /// Review M13: rotations racing on several "instances" (shared store and
    /// root) must never leave a DEK wrapped under a revoked KEK, and the next
    /// converging pass re-wraps everything under the active KEK.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_kek_rotations_never_strand_a_dek() {
        let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::new());
        let root_bytes = KeyBytes::generate();
        let instance = || {
            Arc::new(service_with(
                store.clone(),
                Arc::new(StaticRootProvider::new(
                    "test",
                    Algorithm::Aes256Gcm,
                    KeyBytes::from_slice(root_bytes.expose()).unwrap(),
                    vec![],
                )),
                Duration::from_secs(300),
            ))
        };
        let first = instance();
        let blob = first.seal(&secret("pw"), binding(8)).await.unwrap();

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let svc = instance();
            tasks.push(tokio::spawn(async move {
                for _ in 0..5 {
                    // A losing racer may error (its KEK was revoked under it);
                    // it must never corrupt the hierarchy.
                    let _ = svc.rotate_kek().await;
                    tokio::task::yield_now().await;
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        let check = |keks: &[KeyRecord], deks: &[KeyRecord]| {
            for dek in deks.iter().filter(|d| d.state != KeyState::Revoked) {
                let parent = dek.wrapping_kek_version.unwrap();
                assert!(
                    keks.iter()
                        .any(|k| k.version == parent && k.state != KeyState::Revoked),
                    "DEK v{} under revoked KEK v{parent}",
                    dek.version
                );
            }
        };
        let svc = instance();
        check(
            &svc.list_keys(KeyLayer::Kek).await.unwrap(),
            &svc.list_keys(KeyLayer::Dek).await.unwrap(),
        );
        svc.rewrap_deks().await.unwrap();
        svc.revoke_unreferenced_keks().await.unwrap();
        let keks = svc.list_keys(KeyLayer::Kek).await.unwrap();
        let deks = svc.list_keys(KeyLayer::Dek).await.unwrap();
        check(&keks, &deks);
        let active = keks.iter().find(|k| k.state == KeyState::Active).unwrap();
        assert!(deks
            .iter()
            .all(|d| d.wrapping_kek_version == Some(active.version)));
        assert_eq!(
            svc.open(&blob, binding(8)).await.unwrap().expose_secret(),
            "pw"
        );
    }

    #[tokio::test]
    async fn root_rotation_rewraps_keks_only() {
        let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::new());
        let old_root_bytes = KeyBytes::generate();
        let old_root = Arc::new(StaticRootProvider::new(
            "test",
            Algorithm::Aes256Gcm,
            KeyBytes::from_slice(old_root_bytes.expose()).unwrap(),
            vec![],
        ));
        let svc = service_with(store.clone(), old_root.clone(), Duration::from_secs(300));
        let blob = svc.seal(&secret("pw"), binding(6)).await.unwrap();
        let kek_before = svc.list_keys(KeyLayer::Kek).await.unwrap().remove(0);
        let dek_before = svc.list_keys(KeyLayer::Dek).await.unwrap().remove(0);

        // Operator rotates the root: new current, old kept as previous. A new
        // service instance (cold cache) picks up the new provider.
        let new_root = Arc::new(StaticRootProvider::new(
            "test",
            Algorithm::Aes256Gcm,
            KeyBytes::generate(),
            vec![old_root_bytes],
        ));
        let svc2 = service_with(store, new_root.clone(), Duration::from_secs(300));
        let rewrapped = svc2.rewrap_keks().await.expect("rewrap keks");
        assert_eq!(rewrapped, 1);

        // KEK row re-wrapped under the new root.
        let kek_after = svc2.list_keys(KeyLayer::Kek).await.unwrap().remove(0);
        assert_eq!(kek_after.version, kek_before.version);
        assert_ne!(kek_after.wrapped_key, kek_before.wrapped_key);
        assert_eq!(
            kek_after.root_key_version.as_deref(),
            Some(new_root.current_root_version().await.unwrap().as_str())
        );

        // DEK row and ciphertext untouched; the secret still decrypts.
        let dek_after = svc2.list_keys(KeyLayer::Dek).await.unwrap().remove(0);
        assert_eq!(dek_after.wrapped_key, dek_before.wrapped_key);
        assert_eq!(
            svc2.open(&blob, binding(6)).await.unwrap().expose_secret(),
            "pw"
        );

        // Idempotent.
        assert_eq!(svc2.rewrap_keks().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn multi_instance_decrypt_with_a_shared_root_and_store() {
        // Two "instances" share the store (Postgres in production) and the same
        // root config; instance B starts with a cold cache and still decrypts
        // what A sealed — no in-memory-only key state.
        let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::new());
        let root_bytes = KeyBytes::generate();
        let a = service_with(
            store.clone(),
            Arc::new(StaticRootProvider::new(
                "env",
                Algorithm::Aes256Gcm,
                KeyBytes::from_slice(root_bytes.expose()).unwrap(),
                vec![],
            )),
            Duration::from_secs(300),
        );
        let blob = a.seal(&secret("shared"), binding(11)).await.unwrap();

        let b = service_with(
            store,
            Arc::new(StaticRootProvider::new(
                "env",
                Algorithm::Aes256Gcm,
                root_bytes,
                vec![],
            )),
            Duration::from_secs(300),
        );
        assert_eq!(
            b.open(&blob, binding(11)).await.unwrap().expose_secret(),
            "shared"
        );
    }

    #[tokio::test]
    async fn unwrapped_keys_are_cached_and_expire() {
        let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::new());
        let counting = Arc::new(CountingRoot {
            inner: StaticRootProvider::new(
                "test",
                Algorithm::Aes256Gcm,
                KeyBytes::generate(),
                vec![],
            ),
            unwraps: AtomicUsize::new(0),
        });
        let svc = service_with(store, counting.clone(), Duration::from_millis(80));

        let blob = svc.seal(&secret("pw"), binding(1)).await.unwrap();
        let after_seal = counting.unwraps.load(Ordering::SeqCst);
        assert_eq!(
            after_seal, 1,
            "bootstrap + seal unwrap the KEK exactly once"
        );

        // Repeated opens hit the cache: no further root-provider calls.
        for _ in 0..5 {
            svc.open(&blob, binding(1)).await.unwrap();
        }
        assert_eq!(counting.unwraps.load(Ordering::SeqCst), after_seal);

        // TTL expiry forces a re-unwrap.
        tokio::time::sleep(Duration::from_millis(120)).await;
        svc.open(&blob, binding(1)).await.unwrap();
        assert_eq!(counting.unwraps.load(Ordering::SeqCst), after_seal + 1);
    }

    #[tokio::test]
    async fn xchacha_service_round_trips() {
        let svc = EnvelopeService::new(
            Arc::new(InMemoryKeyStore::new()),
            Arc::new(StaticRootProvider::new(
                "test",
                Algorithm::XChaCha20Poly1305,
                KeyBytes::generate(),
                vec![],
            )),
            EnvelopeServiceConfig {
                algorithm: Algorithm::XChaCha20Poly1305,
                ..Default::default()
            },
        );
        let blob = svc.seal(&secret("pw"), binding(1)).await.unwrap();
        assert_eq!(
            envelope::parse_header(&blob).unwrap().algorithm,
            Algorithm::XChaCha20Poly1305
        );
        assert_eq!(
            svc.open(&blob, binding(1)).await.unwrap().expose_secret(),
            "pw"
        );
    }
}
