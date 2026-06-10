//! Postgres implementation of the `forge-crypto` [`KeyStore`] over the
//! `encryption_key` table (slice 12.5, plan §2.2), plus the secret-column
//! helpers for `repository.upstream_password_enc` (plan §2.4/§2.8).
//!
//! Only **wrapped** key bytes are stored; the partial unique index
//! `encryption_key_one_active` guarantees at most one `active` key per
//! layer+scope, and [`PgKeyStore::insert_active`] flips the previous active key
//! to `retiring` in the same transaction so a rotation can never leave zero or
//! two active keys. Two instances rotating concurrently serialize on a
//! transaction-scoped advisory lock keyed by layer+scope (the plan's
//! "advisory-locked create-if-absent" bootstrap); the loser of any remaining
//! race is rejected by the unique constraints and surfaces as
//! [`CryptoError::Store`].

use async_trait::async_trait;
use forge_crypto::envelope::Algorithm;
use forge_crypto::store::{KeyLayer, KeyRecord, KeyState, KeyStore, NewKeyRecord};
use forge_crypto::CryptoError;
use sqlx::PgPool;

/// [`KeyStore`] over Postgres. Cheap to clone (pool handle).
#[derive(Debug, Clone)]
pub struct PgKeyStore {
    pool: PgPool,
}

impl PgKeyStore {
    /// Build over an existing pool.
    pub fn new(pool: PgPool) -> Self {
        PgKeyStore { pool }
    }
}

/// Map a database error into the crypto crate's transport-agnostic error.
fn store_err(e: sqlx::Error) -> CryptoError {
    CryptoError::Store(format!("encryption_key: {e}"))
}

/// Raw row shape shared by every SELECT/RETURNING in this DAO.
struct Row {
    id: i64,
    layer: String,
    version: i32,
    algorithm: String,
    wrapped_key: Vec<u8>,
    root_key_id: Option<String>,
    root_key_version: Option<String>,
    wrapping_kek_version: Option<i32>,
    state: String,
    scope: String,
    created_at: chrono::DateTime<chrono::Utc>,
    rotated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Row {
    fn into_record(self) -> Result<KeyRecord, CryptoError> {
        Ok(KeyRecord {
            id: self.id,
            layer: KeyLayer::parse(&self.layer)?,
            version: self.version,
            algorithm: Algorithm::parse(&self.algorithm)?,
            wrapped_key: self.wrapped_key,
            root_key_id: self.root_key_id,
            root_key_version: self.root_key_version,
            wrapping_kek_version: self.wrapping_kek_version,
            state: KeyState::parse(&self.state)?,
            scope: self.scope,
            created_at: self.created_at,
            rotated_at: self.rotated_at,
        })
    }
}

/// Serialize key-row mutations of one layer+scope across instances: a
/// transaction-scoped advisory lock (released automatically at commit/rollback,
/// so a crash can never leak it). The key hashes a namespaced string so it
/// cannot collide with other forge advisory-lock users.
async fn lock_layer_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    layer: KeyLayer,
    scope: &str,
) -> Result<(), CryptoError> {
    sqlx::query!(
        r#"SELECT pg_advisory_xact_lock(hashtextextended('forge.encryption_key.' || $1 || '.' || $2, 0))"#,
        layer.as_str(),
        scope,
    )
    .execute(&mut **tx)
    .await
    .map_err(store_err)?;
    Ok(())
}

#[async_trait]
impl KeyStore for PgKeyStore {
    async fn insert_active(&self, new: NewKeyRecord) -> Result<KeyRecord, CryptoError> {
        let mut tx = self.pool.begin().await.map_err(store_err)?;
        lock_layer_scope(&mut tx, new.layer, &new.scope).await?;

        // Retire the current active key (if any)…
        sqlx::query!(
            r#"
            UPDATE encryption_key
            SET state = 'retiring', rotated_at = now()
            WHERE layer = $1 AND scope = $2 AND state = 'active'
            "#,
            new.layer.as_str(),
            new.scope,
        )
        .execute(&mut *tx)
        .await
        .map_err(store_err)?;

        // …and insert the successor with the next version, atomically.
        let row = sqlx::query_as!(
            Row,
            r#"
            INSERT INTO encryption_key
                (layer, version, algorithm, wrapped_key,
                 root_key_id, root_key_version, wrapping_kek_version, state, scope)
            SELECT $1, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6, $7, 'active', $2
            FROM encryption_key WHERE layer = $1 AND scope = $2
            RETURNING
                id, layer, version, algorithm, wrapped_key,
                root_key_id, root_key_version, wrapping_kek_version,
                state, scope, created_at, rotated_at
            "#,
            new.layer.as_str(),
            new.scope,
            new.algorithm.as_str(),
            new.wrapped_key,
            new.root_key_id,
            new.root_key_version,
            new.wrapping_kek_version,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(store_err)?;

        tx.commit().await.map_err(store_err)?;
        row.into_record()
    }

    async fn insert_active_if_absent(&self, new: NewKeyRecord) -> Result<KeyRecord, CryptoError> {
        let mut tx = self.pool.begin().await.map_err(store_err)?;
        lock_layer_scope(&mut tx, new.layer, &new.scope).await?;

        // Under the lock, the check-then-insert is race-free.
        let existing = sqlx::query_as!(
            Row,
            r#"
            SELECT id, layer, version, algorithm, wrapped_key,
                   root_key_id, root_key_version, wrapping_kek_version,
                   state, scope, created_at, rotated_at
            FROM encryption_key
            WHERE layer = $1 AND scope = $2 AND state = 'active'
            "#,
            new.layer.as_str(),
            new.scope,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        if let Some(row) = existing {
            tx.commit().await.map_err(store_err)?;
            return row.into_record();
        }

        let row = sqlx::query_as!(
            Row,
            r#"
            INSERT INTO encryption_key
                (layer, version, algorithm, wrapped_key,
                 root_key_id, root_key_version, wrapping_kek_version, state, scope)
            SELECT $1, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6, $7, 'active', $2
            FROM encryption_key WHERE layer = $1 AND scope = $2
            RETURNING
                id, layer, version, algorithm, wrapped_key,
                root_key_id, root_key_version, wrapping_kek_version,
                state, scope, created_at, rotated_at
            "#,
            new.layer.as_str(),
            new.scope,
            new.algorithm.as_str(),
            new.wrapped_key,
            new.root_key_id,
            new.root_key_version,
            new.wrapping_kek_version,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(store_err)?;

        tx.commit().await.map_err(store_err)?;
        row.into_record()
    }

    async fn get_active(
        &self,
        layer: KeyLayer,
        scope: &str,
    ) -> Result<Option<KeyRecord>, CryptoError> {
        sqlx::query_as!(
            Row,
            r#"
            SELECT id, layer, version, algorithm, wrapped_key,
                   root_key_id, root_key_version, wrapping_kek_version,
                   state, scope, created_at, rotated_at
            FROM encryption_key
            WHERE layer = $1 AND scope = $2 AND state = 'active'
            "#,
            layer.as_str(),
            scope,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?
        .map(Row::into_record)
        .transpose()
    }

    async fn get_version(
        &self,
        layer: KeyLayer,
        scope: &str,
        version: i32,
    ) -> Result<Option<KeyRecord>, CryptoError> {
        sqlx::query_as!(
            Row,
            r#"
            SELECT id, layer, version, algorithm, wrapped_key,
                   root_key_id, root_key_version, wrapping_kek_version,
                   state, scope, created_at, rotated_at
            FROM encryption_key
            WHERE layer = $1 AND scope = $2 AND version = $3
            "#,
            layer.as_str(),
            scope,
            version,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?
        .map(Row::into_record)
        .transpose()
    }

    async fn list(&self, layer: KeyLayer, scope: &str) -> Result<Vec<KeyRecord>, CryptoError> {
        sqlx::query_as!(
            Row,
            r#"
            SELECT id, layer, version, algorithm, wrapped_key,
                   root_key_id, root_key_version, wrapping_kek_version,
                   state, scope, created_at, rotated_at
            FROM encryption_key
            WHERE layer = $1 AND scope = $2
            ORDER BY version
            "#,
            layer.as_str(),
            scope,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?
        .into_iter()
        .map(Row::into_record)
        .collect()
    }

    async fn update_wrapped(
        &self,
        id: i64,
        wrapped_key: &[u8],
        root_key_id: Option<&str>,
        root_key_version: Option<&str>,
        wrapping_kek_version: Option<i32>,
    ) -> Result<(), CryptoError> {
        let res = sqlx::query!(
            r#"
            UPDATE encryption_key
            SET wrapped_key = $2, root_key_id = $3, root_key_version = $4,
                wrapping_kek_version = $5
            WHERE id = $1
            "#,
            id,
            wrapped_key,
            root_key_id,
            root_key_version,
            wrapping_kek_version,
        )
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        if res.rows_affected() == 0 {
            return Err(CryptoError::Store(format!("no encryption_key row id {id}")));
        }
        Ok(())
    }

    async fn set_state(&self, id: i64, state: KeyState) -> Result<(), CryptoError> {
        let res = sqlx::query!(
            r#"
            UPDATE encryption_key
            SET state = $2,
                rotated_at = CASE
                    WHEN $2 <> 'active' AND rotated_at IS NULL THEN now()
                    ELSE rotated_at
                END
            WHERE id = $1
            "#,
            id,
            state.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        if res.rows_affected() == 0 {
            return Err(CryptoError::Store(format!("no encryption_key row id {id}")));
        }
        Ok(())
    }
}
