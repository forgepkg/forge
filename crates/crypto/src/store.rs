//! Persistence seam for **wrapped** key material (the `encryption_key` table,
//! plan §2.2).
//!
//! The store holds only ciphertext: KEK rows wrapped by the root, DEK rows
//! wrapped by a KEK. No unwrapped key bytes are ever persisted — cold-start
//! recovery is "read rows, unwrap KEKs via the root provider, unwrap DEKs via
//! KEKs". `forge-db` implements [`KeyStore`] over Postgres;
//! [`InMemoryKeyStore`] backs the hermetic unit tests in this crate.
//!
//! ## Lifecycle (plan §2.2)
//!
//! * `active`   — used for **new** wraps/encrypts; exactly one per layer+scope
//!   (the Postgres impl enforces this with a partial unique index, the
//!   in-memory impl with the same flip-then-insert discipline).
//! * `retiring` — still used to **decrypt/unwrap** existing material, never for
//!   new encrypts.
//! * `revoked`  — no longer usable at all (kept for audit).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::envelope::Algorithm;
use crate::error::CryptoError;

/// Which layer of the hierarchy a stored key belongs to. The root is **never**
/// stored (it lives in KMS / env / file), so there is no `Root` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyLayer {
    /// Key-encryption key: wrapped by the root, wraps DEKs.
    Kek,
    /// Data-encryption key: wrapped by a KEK, seals secret values.
    Dek,
}

impl KeyLayer {
    /// Canonical name as stored in `encryption_key.layer`.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyLayer::Kek => "kek",
            KeyLayer::Dek => "dek",
        }
    }

    /// Parse the canonical name.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        match s {
            "kek" => Ok(KeyLayer::Kek),
            "dek" => Ok(KeyLayer::Dek),
            other => Err(CryptoError::Store(format!("unknown key layer {other:?}"))),
        }
    }
}

impl std::fmt::Display for KeyLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of a stored key (plan §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Used for new wraps/encrypts. Exactly one per layer+scope.
    Active,
    /// Decrypt/unwrap only; superseded for new material.
    Retiring,
    /// Unusable; kept for audit until nothing references it.
    Revoked,
}

impl KeyState {
    /// Canonical name as stored in `encryption_key.state`.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyState::Active => "active",
            KeyState::Retiring => "retiring",
            KeyState::Revoked => "revoked",
        }
    }

    /// Parse the canonical name.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        match s {
            "active" => Ok(KeyState::Active),
            "retiring" => Ok(KeyState::Retiring),
            "revoked" => Ok(KeyState::Revoked),
            other => Err(CryptoError::Store(format!("unknown key state {other:?}"))),
        }
    }
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A stored (wrapped) key row.
///
/// `wrapped_key` is ciphertext (safe at rest) but the manual `Debug` still
/// prints only its length — key rows should never be eyeball-diffed in logs.
#[derive(Clone)]
pub struct KeyRecord {
    /// Surrogate row id.
    pub id: i64,
    /// `kek` or `dek`.
    pub layer: KeyLayer,
    /// Monotonic per layer+scope; the link referenced by envelope blobs
    /// (DEK version) and DEK rows (`wrapping_kek_version`).
    pub version: i32,
    /// AEAD this key's **own bytes** use when wrapping children / sealing data.
    pub algorithm: Algorithm,
    /// This key's raw bytes, encrypted by its parent (root for KEKs, a KEK for
    /// DEKs).
    pub wrapped_key: Vec<u8>,
    /// KEK rows: which root produced `wrapped_key` (`"env"`/`"file"`/KMS id).
    pub root_key_id: Option<String>,
    /// KEK rows: the root version label that wrapped this row.
    pub root_key_version: Option<String>,
    /// DEK rows: the KEK version that wrapped this row.
    pub wrapping_kek_version: Option<i32>,
    /// Lifecycle state.
    pub state: KeyState,
    /// Multi-tenant / multi-purpose discriminator; `"default"` in §12.5.
    pub scope: String,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// When the key left `active` (rotation), if it has.
    pub rotated_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRecord")
            .field("id", &self.id)
            .field("layer", &self.layer)
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field(
                "wrapped_key",
                &format_args!("<{} bytes>", self.wrapped_key.len()),
            )
            .field("root_key_id", &self.root_key_id)
            .field("root_key_version", &self.root_key_version)
            .field("wrapping_kek_version", &self.wrapping_kek_version)
            .field("state", &self.state)
            .field("scope", &self.scope)
            .field("created_at", &self.created_at)
            .field("rotated_at", &self.rotated_at)
            .finish()
    }
}

/// Fields of a new key row; the store assigns `id`, `version` (next per
/// layer+scope), `state = active`, and `created_at`.
#[derive(Clone)]
pub struct NewKeyRecord {
    /// `kek` or `dek`.
    pub layer: KeyLayer,
    /// AEAD of this key's own bytes.
    pub algorithm: Algorithm,
    /// The wrapped key bytes (root-wrapped for KEKs, KEK-wrapped for DEKs).
    pub wrapped_key: Vec<u8>,
    /// KEK rows: root id; DEK rows: `None`.
    pub root_key_id: Option<String>,
    /// KEK rows: root version label; DEK rows: `None`.
    pub root_key_version: Option<String>,
    /// DEK rows: wrapping KEK version; KEK rows: `None`.
    pub wrapping_kek_version: Option<i32>,
    /// Scope discriminator (`"default"`).
    pub scope: String,
}

impl std::fmt::Debug for NewKeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewKeyRecord")
            .field("layer", &self.layer)
            .field("algorithm", &self.algorithm)
            .field(
                "wrapped_key",
                &format_args!("<{} bytes>", self.wrapped_key.len()),
            )
            .field("root_key_id", &self.root_key_id)
            .field("root_key_version", &self.root_key_version)
            .field("wrapping_kek_version", &self.wrapping_kek_version)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Storage of wrapped KEK/DEK rows (`encryption_key`).
///
/// `forge-db` provides the Postgres implementation; [`InMemoryKeyStore`] backs
/// hermetic tests. All methods operate on **wrapped** bytes only.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Insert a new **active** key, atomically flipping the current active key
    /// of the same layer+scope (if any) to `retiring` and assigning the next
    /// version. Two concurrent calls race benignly: exactly one wins (the
    /// unique constraints reject the loser, surfaced as
    /// [`CryptoError::Store`]); callers re-read the active key on conflict.
    /// A DEK whose `wrapping_kek_version` names a missing or `revoked` KEK is
    /// refused ([`CryptoError::KeyRevoked`]) — checked under the same
    /// serialization as [`Self::revoke_kek_if_unreferenced`].
    async fn insert_active(&self, new: NewKeyRecord) -> Result<KeyRecord, CryptoError>;

    /// Create-if-absent bootstrap (plan §2.8 step 2): atomically either insert
    /// `new` as the first **active** key of its layer+scope or return the
    /// already-active key. Unlike [`Self::insert_active`] this never retires an
    /// existing key, so concurrent bootstrapping instances converge on exactly
    /// one key with no spurious retired siblings.
    async fn insert_active_if_absent(&self, new: NewKeyRecord) -> Result<KeyRecord, CryptoError>;

    /// The single `active` key for a layer+scope, if one exists.
    async fn get_active(
        &self,
        layer: KeyLayer,
        scope: &str,
    ) -> Result<Option<KeyRecord>, CryptoError>;

    /// Fetch a specific key version (any state).
    async fn get_version(
        &self,
        layer: KeyLayer,
        scope: &str,
        version: i32,
    ) -> Result<Option<KeyRecord>, CryptoError>;

    /// All keys of a layer+scope, ordered by version (any state). Key counts
    /// are tiny (a handful of KEKs/DEKs), so no pagination.
    async fn list(&self, layer: KeyLayer, scope: &str) -> Result<Vec<KeyRecord>, CryptoError>;

    /// **Compare-and-swap** re-wrap (the re-wrap sweeps: KEK rotation rewraps
    /// DEK rows, root rotation rewraps KEK rows): replace `current`'s wrapped
    /// bytes + parent reference only if, at commit time, the row still holds
    /// exactly `current.wrapped_key` and `current`'s parent reference, is not
    /// `revoked`, and — for a DEK row — the new parent KEK
    /// (`wrapping_kek_version`) exists and is not `revoked`. Returns `false`
    /// (nothing written) when another rotation got there first or revoked
    /// the target parent; the caller skips the row and the next pass re-reads
    /// it. Serialized with [`Self::insert_active`] and
    /// [`Self::revoke_kek_if_unreferenced`] of the same scope, so a DEK can
    /// never end up wrapped under a revoked KEK however rotations interleave.
    /// The parent-reference fields must match the row's layer (root fields for
    /// KEKs, `wrapping_kek_version` for DEKs).
    async fn update_wrapped(
        &self,
        current: &KeyRecord,
        wrapped_key: &[u8],
        root_key_id: Option<&str>,
        root_key_version: Option<&str>,
        wrapping_kek_version: Option<i32>,
    ) -> Result<bool, CryptoError>;

    /// Revoke the `retiring` KEK `kek` only if, at commit time, no non-revoked
    /// DEK row of its scope references it (`wrapping_kek_version`). Returns
    /// whether it was revoked. The reference check and the state flip are one
    /// atomic step serialized with [`Self::update_wrapped`] /
    /// [`Self::insert_active`], so a concurrent re-wrap onto `kek` either
    /// commits first (and keeps it alive) or is refused.
    async fn revoke_kek_if_unreferenced(&self, kek: &KeyRecord) -> Result<bool, CryptoError>;

    /// Flip a row's lifecycle state **unconditionally**. Stamps `rotated_at`
    /// the first time a key leaves `active`. Revocation in the rotation paths
    /// goes through a commit-time reference check instead
    /// ([`Self::revoke_kek_if_unreferenced`]; the DEK sweep in `forge-db`
    /// checks the secret columns under row locks); this is the low-level
    /// primitive for callers that already guarantee nothing references the key.
    async fn set_state(&self, id: i64, state: KeyState) -> Result<(), CryptoError>;
}

/// In-memory [`KeyStore`] for hermetic tests (no Postgres). Mirrors the
/// Postgres semantics: one active key per layer+scope, monotonic versions,
/// flip-to-retiring on insert.
#[derive(Default)]
pub struct InMemoryKeyStore {
    inner: std::sync::Mutex<InMemoryInner>,
}

#[derive(Default)]
struct InMemoryInner {
    rows: Vec<KeyRecord>,
    next_id: i64,
}

impl InMemoryKeyStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Whether `version` names an existing, non-revoked KEK of `scope` (the parent
/// check of DEK inserts/re-wraps). Runs under the store mutex.
fn usable_kek(inner: &InMemoryInner, scope: &str, version: i32) -> bool {
    inner.rows.iter().any(|r| {
        r.layer == KeyLayer::Kek
            && r.scope == scope
            && r.version == version
            && r.state != KeyState::Revoked
    })
}

/// Refuse a DEK whose wrapping KEK is missing or revoked (mirrors the Postgres
/// impl). Runs under the store mutex.
fn check_dek_parent(inner: &InMemoryInner, new: &NewKeyRecord) -> Result<(), CryptoError> {
    match (new.layer, new.wrapping_kek_version) {
        (KeyLayer::Dek, Some(kek)) if !usable_kek(inner, &new.scope, kek) => {
            Err(CryptoError::KeyRevoked {
                layer: "kek",
                version: kek,
            })
        }
        _ => Ok(()),
    }
}

/// Flip the active key of `new`'s layer+scope to `retiring` (if any) and insert
/// `new` as the next-version active key. Runs entirely under the store mutex.
fn insert_active_locked(
    inner: &mut InMemoryInner,
    new: NewKeyRecord,
) -> Result<KeyRecord, CryptoError> {
    check_dek_parent(inner, &new)?;
    let now = Utc::now();
    let mut max_version = 0;
    for row in inner.rows.iter_mut() {
        if row.layer == new.layer && row.scope == new.scope {
            max_version = max_version.max(row.version);
            if row.state == KeyState::Active {
                row.state = KeyState::Retiring;
                row.rotated_at = Some(now);
            }
        }
    }
    inner.next_id += 1;
    let record = KeyRecord {
        id: inner.next_id,
        layer: new.layer,
        version: max_version + 1,
        algorithm: new.algorithm,
        wrapped_key: new.wrapped_key,
        root_key_id: new.root_key_id,
        root_key_version: new.root_key_version,
        wrapping_kek_version: new.wrapping_kek_version,
        state: KeyState::Active,
        scope: new.scope,
        created_at: now,
        rotated_at: None,
    };
    inner.rows.push(record.clone());
    Ok(record)
}

#[async_trait]
impl KeyStore for InMemoryKeyStore {
    async fn insert_active(&self, new: NewKeyRecord) -> Result<KeyRecord, CryptoError> {
        let mut inner = self.inner.lock().expect("key store mutex");
        insert_active_locked(&mut inner, new)
    }

    async fn insert_active_if_absent(&self, new: NewKeyRecord) -> Result<KeyRecord, CryptoError> {
        // Check-and-insert under ONE lock acquisition so concurrent bootstraps
        // converge on exactly one key (mirrors the Postgres impl's atomicity).
        let mut inner = self.inner.lock().expect("key store mutex");
        if let Some(existing) = inner
            .rows
            .iter()
            .find(|r| r.layer == new.layer && r.scope == new.scope && r.state == KeyState::Active)
        {
            return Ok(existing.clone());
        }
        insert_active_locked(&mut inner, new)
    }

    async fn get_active(
        &self,
        layer: KeyLayer,
        scope: &str,
    ) -> Result<Option<KeyRecord>, CryptoError> {
        let inner = self.inner.lock().expect("key store mutex");
        Ok(inner
            .rows
            .iter()
            .find(|r| r.layer == layer && r.scope == scope && r.state == KeyState::Active)
            .cloned())
    }

    async fn get_version(
        &self,
        layer: KeyLayer,
        scope: &str,
        version: i32,
    ) -> Result<Option<KeyRecord>, CryptoError> {
        let inner = self.inner.lock().expect("key store mutex");
        Ok(inner
            .rows
            .iter()
            .find(|r| r.layer == layer && r.scope == scope && r.version == version)
            .cloned())
    }

    async fn list(&self, layer: KeyLayer, scope: &str) -> Result<Vec<KeyRecord>, CryptoError> {
        let inner = self.inner.lock().expect("key store mutex");
        let mut rows: Vec<KeyRecord> = inner
            .rows
            .iter()
            .filter(|r| r.layer == layer && r.scope == scope)
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.version);
        Ok(rows)
    }

    async fn update_wrapped(
        &self,
        current: &KeyRecord,
        wrapped_key: &[u8],
        root_key_id: Option<&str>,
        root_key_version: Option<&str>,
        wrapping_kek_version: Option<i32>,
    ) -> Result<bool, CryptoError> {
        // Compare-and-swap under the store mutex (the Postgres impl's scope
        // lock + guarded UPDATE).
        let mut inner = self.inner.lock().expect("key store mutex");
        if let Some(kek) = wrapping_kek_version {
            if !usable_kek(&inner, &current.scope, kek) {
                return Ok(false);
            }
        }
        let Some(row) = inner.rows.iter_mut().find(|r| r.id == current.id) else {
            return Err(CryptoError::Store(format!("no key row id {}", current.id)));
        };
        if row.state == KeyState::Revoked
            || row.wrapped_key != current.wrapped_key
            || row.root_key_version != current.root_key_version
            || row.wrapping_kek_version != current.wrapping_kek_version
        {
            return Ok(false);
        }
        row.wrapped_key = wrapped_key.to_vec();
        row.root_key_id = root_key_id.map(str::to_string);
        row.root_key_version = root_key_version.map(str::to_string);
        row.wrapping_kek_version = wrapping_kek_version;
        Ok(true)
    }

    async fn revoke_kek_if_unreferenced(&self, kek: &KeyRecord) -> Result<bool, CryptoError> {
        let mut inner = self.inner.lock().expect("key store mutex");
        let referenced = inner.rows.iter().any(|d| {
            d.layer == KeyLayer::Dek
                && d.scope == kek.scope
                && d.state != KeyState::Revoked
                && d.wrapping_kek_version == Some(kek.version)
        });
        if referenced {
            return Ok(false);
        }
        let Some(row) = inner
            .rows
            .iter_mut()
            .find(|r| r.id == kek.id && r.layer == KeyLayer::Kek)
        else {
            return Err(CryptoError::Store(format!("no KEK row id {}", kek.id)));
        };
        if row.state != KeyState::Retiring {
            return Ok(false);
        }
        row.state = KeyState::Revoked;
        if row.rotated_at.is_none() {
            row.rotated_at = Some(Utc::now());
        }
        Ok(true)
    }

    async fn set_state(&self, id: i64, state: KeyState) -> Result<(), CryptoError> {
        let mut inner = self.inner.lock().expect("key store mutex");
        let row = inner
            .rows
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| CryptoError::Store(format!("no key row id {id}")))?;
        if row.state == KeyState::Active && state != KeyState::Active && row.rotated_at.is_none() {
            row.rotated_at = Some(Utc::now());
        }
        row.state = state;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_key(layer: KeyLayer) -> NewKeyRecord {
        NewKeyRecord {
            layer,
            algorithm: Algorithm::Aes256Gcm,
            wrapped_key: vec![1, 2, 3],
            root_key_id: None,
            root_key_version: None,
            wrapping_kek_version: None,
            scope: "default".to_string(),
        }
    }

    #[tokio::test]
    async fn insert_active_flips_previous_to_retiring_and_bumps_version() {
        let store = InMemoryKeyStore::new();
        let v1 = store.insert_active(new_key(KeyLayer::Dek)).await.unwrap();
        assert_eq!(v1.version, 1);
        assert_eq!(v1.state, KeyState::Active);

        let v2 = store.insert_active(new_key(KeyLayer::Dek)).await.unwrap();
        assert_eq!(v2.version, 2);

        let active = store
            .get_active(KeyLayer::Dek, "default")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.version, 2);
        let old = store
            .get_version(KeyLayer::Dek, "default", 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(old.state, KeyState::Retiring);
        assert!(old.rotated_at.is_some());

        // Layers are independent version sequences.
        let kek = store.insert_active(new_key(KeyLayer::Kek)).await.unwrap();
        assert_eq!(kek.version, 1);
    }

    #[tokio::test]
    async fn update_wrapped_is_compare_and_swap() {
        let store = InMemoryKeyStore::new();
        let kek1 = store.insert_active(new_key(KeyLayer::Kek)).await.unwrap();
        let mut dek = new_key(KeyLayer::Dek);
        dek.wrapping_kek_version = Some(kek1.version);
        let dek = store.insert_active(dek).await.unwrap();
        let kek2 = store.insert_active(new_key(KeyLayer::Kek)).await.unwrap();

        // First writer (holding the current row) wins…
        assert!(store
            .update_wrapped(&dek, &[9, 9], None, None, Some(kek2.version))
            .await
            .unwrap());
        // …a second writer still holding the old row loses, nothing written.
        assert!(!store
            .update_wrapped(&dek, &[7, 7], None, None, Some(kek1.version))
            .await
            .unwrap());
        let now = store
            .get_version(KeyLayer::Dek, "default", dek.version)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(now.wrapped_key, vec![9, 9]);
        assert_eq!(now.wrapping_kek_version, Some(kek2.version));
    }

    #[tokio::test]
    async fn dek_never_lands_under_a_revoked_kek() {
        let store = InMemoryKeyStore::new();
        let kek1 = store.insert_active(new_key(KeyLayer::Kek)).await.unwrap();
        let mut dek = new_key(KeyLayer::Dek);
        dek.wrapping_kek_version = Some(kek1.version);
        let dek = store.insert_active(dek).await.unwrap();
        let kek2 = store.insert_active(new_key(KeyLayer::Kek)).await.unwrap();

        // KEK v1 is still referenced by the DEK: the commit-time check keeps it.
        assert!(!store.revoke_kek_if_unreferenced(&kek1).await.unwrap());
        // The active KEK is never revoked by this path either.
        assert!(!store.revoke_kek_if_unreferenced(&kek2).await.unwrap());

        // Move the DEK to v2; now v1 is unreferenced and gets revoked.
        assert!(store
            .update_wrapped(&dek, &[4, 4], None, None, Some(kek2.version))
            .await
            .unwrap());
        assert!(store.revoke_kek_if_unreferenced(&kek1).await.unwrap());

        // Neither a re-wrap nor a new DEK may name the revoked KEK.
        let current = store
            .get_version(KeyLayer::Dek, "default", dek.version)
            .await
            .unwrap()
            .unwrap();
        assert!(!store
            .update_wrapped(&current, &[5, 5], None, None, Some(kek1.version))
            .await
            .unwrap());
        let mut late = new_key(KeyLayer::Dek);
        late.wrapping_kek_version = Some(kek1.version);
        assert!(matches!(
            store.insert_active(late).await.unwrap_err(),
            CryptoError::KeyRevoked { layer: "kek", .. }
        ));
    }

    #[tokio::test]
    async fn debug_prints_no_wrapped_bytes() {
        let store = InMemoryKeyStore::new();
        let rec = store.insert_active(new_key(KeyLayer::Kek)).await.unwrap();
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("<3 bytes>"), "{dbg}");
        assert!(!dbg.contains("[1, 2, 3]"), "{dbg}");
    }
}
