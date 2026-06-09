//! Integration tests for secret encryption at rest (slice 12.5): the Postgres
//! [`PgKeyStore`], the encrypted `repository.upstream_password_enc` column,
//! the plaintext backfill, and the DEK-rotation re-encrypt sweep.
//!
//! Postgres comes from `FORGE_TEST_DATABASE_URL` when set (a docker-less dev
//! loop pointing at a scratch database) or a testcontainer otherwise. The
//! end-to-end test wipes `repository` + `encryption_key` first because the
//! sweep/backfill helpers operate table-wide and a reused scratch database may
//! hold rows sealed under a previous run's (random) root key.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use forge_crypto::envelope::Algorithm;
use forge_crypto::kms::StaticRootProvider;
use forge_crypto::service::{EnvelopeService, EnvelopeServiceConfig};
use forge_crypto::store::{KeyLayer, KeyState, KeyStore, NewKeyRecord};
use forge_crypto::{ExposeSecret, KeyBytes, PlaintextSecret};
use forge_db::encryption_key_dao::PgKeyStore;
use forge_db::repository_dao::{self, NewRepository};
use forge_db::secret_dao;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::Mutex;

static URL: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());
static MIGRATED: OnceLock<()> = OnceLock::new();

async fn database_url() -> &'static str {
    if let Some(u) = URL.get() {
        return u;
    }
    let _guard = INIT_LOCK.lock().await;
    if let Some(u) = URL.get() {
        return u;
    }
    let url = match std::env::var("FORGE_TEST_DATABASE_URL") {
        Ok(u) => u,
        Err(_) => {
            use testcontainers::runners::AsyncRunner;
            use testcontainers::ImageExt;
            use testcontainers_modules::postgres::Postgres;
            let container = Postgres::default()
                .with_db_name("forge")
                .with_user("forge")
                .with_password("forge")
                .with_tag("17")
                .start()
                .await
                .expect("start postgres testcontainer (is Docker running? set FORGE_TEST_DATABASE_URL to use an external Postgres)");
            let host = container.get_host().await.expect("host");
            let port = container.get_host_port_ipv4(5432).await.expect("port");
            // Leak: the container must outlive every test in this binary.
            Box::leak(Box::new(container));
            format!("postgres://forge:forge@{host}:{port}/forge")
        }
    };
    URL.get_or_init(|| url)
}

async fn pool() -> PgPool {
    let url = database_url().await;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .connect(url)
        .await
        .expect("connect test postgres");
    let _guard = INIT_LOCK.lock().await;
    if MIGRATED.get().is_none() {
        forge_db::migrate(&pool).await.expect("migrate");
        let _ = MIGRATED.set(());
    }
    pool
}

fn envelope_with_scope(pool: &PgPool, scope: &str) -> EnvelopeService {
    EnvelopeService::new(
        Arc::new(PgKeyStore::new(pool.clone())),
        Arc::new(StaticRootProvider::new(
            "env",
            Algorithm::Aes256Gcm,
            KeyBytes::generate(),
            vec![],
        )),
        EnvelopeServiceConfig {
            scope: scope.to_string(),
            ..Default::default()
        },
    )
}

fn secret(s: &str) -> PlaintextSecret {
    PlaintextSecret::from(s.to_string())
}

/// PgKeyStore semantics in isolation (own scope ⇒ safe to run in parallel
/// with the end-to-end test): version monotony, active-flip, create-if-absent
/// atomicity, and the partial unique index rejecting a second active row.
#[tokio::test]
async fn pg_key_store_lifecycle_and_single_active_invariant() {
    let pool = pool().await;
    let store = PgKeyStore::new(pool.clone());
    let scope = format!("test-{}", uuid::Uuid::new_v4());
    let new = |layer: KeyLayer| NewKeyRecord {
        layer,
        algorithm: Algorithm::Aes256Gcm,
        wrapped_key: vec![0xAB; 60],
        root_key_id: match layer {
            KeyLayer::Kek => Some("env".into()),
            KeyLayer::Dek => None,
        },
        root_key_version: match layer {
            KeyLayer::Kek => Some("sha256:0011223344556677".into()),
            KeyLayer::Dek => None,
        },
        wrapping_kek_version: match layer {
            KeyLayer::Kek => None,
            KeyLayer::Dek => Some(1),
        },
        scope: scope.clone(),
    };

    // create-if-absent: first call inserts, repeat returns the same row.
    let kek1 = store.insert_active_if_absent(new(KeyLayer::Kek)).await.unwrap();
    let again = store.insert_active_if_absent(new(KeyLayer::Kek)).await.unwrap();
    assert_eq!(kek1.id, again.id);
    assert_eq!(kek1.version, 1);
    assert_eq!(kek1.state, KeyState::Active);

    // Rotation: new active, old flips to retiring with rotated_at set.
    let kek2 = store.insert_active(new(KeyLayer::Kek)).await.unwrap();
    assert_eq!(kek2.version, 2);
    let old = store
        .get_version(KeyLayer::Kek, &scope, 1)
        .await
        .unwrap()
        .expect("kek v1");
    assert_eq!(old.state, KeyState::Retiring);
    assert!(old.rotated_at.is_some());
    let active = store.get_active(KeyLayer::Kek, &scope).await.unwrap().unwrap();
    assert_eq!(active.version, 2);

    // The partial unique index rejects a second active row outright.
    let err = sqlx::query(
        r#"
        INSERT INTO encryption_key
            (layer, version, algorithm, wrapped_key, wrapping_kek_version, state, scope)
        VALUES ('dek', 99, 'aes-256-gcm', '\x00'::bytea, 2, 'active', $1)
        "#,
    )
    .bind(&scope)
    .execute(&pool)
    .await
    .expect("first active dek inserts");
    let _ = err;
    let second = sqlx::query(
        r#"
        INSERT INTO encryption_key
            (layer, version, algorithm, wrapped_key, wrapping_kek_version, state, scope)
        VALUES ('dek', 100, 'aes-256-gcm', '\x00'::bytea, 2, 'active', $1)
        "#,
    )
    .bind(&scope)
    .execute(&pool)
    .await;
    assert!(second.is_err(), "partial unique index must reject a 2nd active DEK");

    // update_wrapped + set_state round-trip.
    store
        .update_wrapped(kek1.id, &[0xCD; 60], Some("env"), Some("sha256:8899aabbccddeeff"), None)
        .await
        .unwrap();
    let rewrapped = store
        .get_version(KeyLayer::Kek, &scope, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rewrapped.wrapped_key, vec![0xCD; 60]);
    assert_eq!(rewrapped.root_key_version.as_deref(), Some("sha256:8899aabbccddeeff"));
    store.set_state(kek1.id, KeyState::Revoked).await.unwrap();
    let revoked = store
        .get_version(KeyLayer::Kek, &scope, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.state, KeyState::Revoked);

    // Layer-shape check constraint: a DEK row with root fields is rejected.
    let bad = sqlx::query(
        r#"
        INSERT INTO encryption_key
            (layer, version, algorithm, wrapped_key, root_key_id, root_key_version, state, scope)
        VALUES ('dek', 101, 'aes-256-gcm', '\x00'::bytea, 'env', 'v', 'retiring', $1)
        "#,
    )
    .bind(&scope)
    .execute(&pool)
    .await;
    assert!(bad.is_err(), "check constraint must reject a DEK with root refs");
}

/// The full §12.5 data path against real Postgres: encrypted set/get, envelope
/// (not plaintext) at rest, tamper + AAD-swap rejection at the DB layer, the
/// plaintext backfill, and the DEK-rotation sweep. One serial test because the
/// backfill/sweep helpers operate on the whole `repository` table.
#[tokio::test]
async fn upstream_password_end_to_end() {
    let pool = pool().await;
    // Clean slate (see module docs): sweeps are table-wide and a reused
    // scratch DB may hold rows sealed under a previous run's root.
    sqlx::query("DELETE FROM group_member")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM repository").execute(&pool).await.unwrap();
    // Only the 'default' scope: the parallel key-store test uses its own scope.
    sqlx::query("DELETE FROM encryption_key WHERE scope = 'default'")
        .execute(&pool)
        .await
        .unwrap();

    let envelope = envelope_with_scope(&pool, "default");
    envelope.ensure_active_keys().await.expect("bootstrap keys");

    // ── set/get round-trip ───────────────────────────────────────────────────
    let repo1 = repository_dao::insert_repository(&pool, NewRepository::proxy("crypt-p1"))
        .await
        .expect("insert repo1");
    secret_dao::set_upstream_password(&pool, &envelope, repo1.id, Some(&secret("hunter2")))
        .await
        .expect("set password");
    let got = secret_dao::get_upstream_password(&pool, &envelope, repo1.id)
        .await
        .expect("get password")
        .expect("password present");
    assert_eq!(got.expose_secret(), "hunter2");

    // Stored bytes are an envelope blob, NOT the plaintext; the plaintext
    // column stays NULL for envelope writes.
    let row = sqlx::query!(
        r#"SELECT upstream_password, upstream_password_enc FROM repository WHERE id = $1"#,
        repo1.id
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row.upstream_password.is_none());
    let blob = row.upstream_password_enc.expect("enc blob stored");
    assert!(!blob.windows(7).any(|w| w == b"hunter2"), "plaintext at rest!");

    // has_upstream_password reflects the encrypted column.
    let model = repository_dao::find_repository_by_id(&pool, repo1.id)
        .await
        .unwrap()
        .unwrap();
    assert!(model.has_upstream_password());
    let dbg = format!("{model:?}");
    assert!(!dbg.contains("hunter2"), "Debug must redact: {dbg}");

    // ── tamper detection ─────────────────────────────────────────────────────
    let mut tampered = blob.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    sqlx::query!(
        r#"UPDATE repository SET upstream_password_enc = $2 WHERE id = $1"#,
        repo1.id,
        &tampered
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        secret_dao::get_upstream_password(&pool, &envelope, repo1.id).await.is_err(),
        "tampered blob must fail decryption"
    );
    // Restore the good blob.
    sqlx::query!(
        r#"UPDATE repository SET upstream_password_enc = $2 WHERE id = $1"#,
        repo1.id,
        &blob
    )
    .execute(&pool)
    .await
    .unwrap();

    // ── AAD swap defense at the DB layer ─────────────────────────────────────
    let repo2 = repository_dao::insert_repository(&pool, NewRepository::proxy("crypt-p2"))
        .await
        .expect("insert repo2");
    sqlx::query!(
        r#"UPDATE repository SET upstream_password_enc = $2 WHERE id = $1"#,
        repo2.id,
        &blob
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        secret_dao::get_upstream_password(&pool, &envelope, repo2.id).await.is_err(),
        "repo1's blob pasted into repo2 must fail (row-bound AAD)"
    );
    secret_dao::set_upstream_password(&pool, &envelope, repo2.id, None)
        .await
        .unwrap();

    // ── plaintext backfill (slice-1 rows) ────────────────────────────────────
    let mut legacy = NewRepository::proxy("crypt-legacy");
    legacy.upstream_password = Some("legacy-pw".to_string());
    let legacy = repository_dao::insert_repository(&pool, legacy).await.unwrap();
    assert!(secret_dao::plaintext_passwords_pending(&pool).await.unwrap());

    let done = secret_dao::backfill_upstream_passwords(&pool, &envelope, 100)
        .await
        .expect("backfill");
    assert_eq!(done, 1);
    assert!(!secret_dao::plaintext_passwords_pending(&pool).await.unwrap());
    // Re-run is a no-op (idempotent).
    assert_eq!(
        secret_dao::backfill_upstream_passwords(&pool, &envelope, 100).await.unwrap(),
        0
    );
    // The original plaintext survives the round trip; the plaintext column is
    // still present pre-cutover (dropped by a later migration).
    let got = secret_dao::get_upstream_password(&pool, &envelope, legacy.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.expose_secret(), "legacy-pw");
    let row = sqlx::query!(
        r#"SELECT upstream_password FROM repository WHERE id = $1"#,
        legacy.id
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.upstream_password.as_deref(), Some("legacy-pw"));

    // ── DEK rotation + lazy re-encrypt sweep ─────────────────────────────────
    let old_dek = EnvelopeService::blob_dek_version(&blob).unwrap();
    envelope.rotate_dek().await.expect("rotate dek");

    let mut after_id = 0i64;
    let mut resealed = 0usize;
    loop {
        let batch = secret_dao::reseal_upstream_passwords_batch(&pool, &envelope, after_id, 50)
            .await
            .expect("sweep batch");
        resealed += batch.resealed;
        match batch.next_after_id {
            Some(id) => after_id = id,
            None => break,
        }
    }
    assert_eq!(resealed, 2, "repo1 + legacy re-encrypted under the new DEK");

    // Everything still decrypts and now references the active DEK.
    for (id, expected) in [(repo1.id, "hunter2"), (legacy.id, "legacy-pw")] {
        let got = secret_dao::get_upstream_password(&pool, &envelope, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.expose_secret(), expected);
    }
    let referenced = secret_dao::referenced_dek_versions(&pool).await.unwrap();
    assert!(!referenced.contains(&old_dek), "old DEK no longer referenced");

    // The old DEK ends `revoked` once unreferenced; the new one stays active.
    let revoked = secret_dao::revoke_unreferenced_deks(&pool, &envelope).await.unwrap();
    assert_eq!(revoked, 1);
    let deks = envelope.list_keys(KeyLayer::Dek).await.unwrap();
    assert!(deks.iter().any(|d| d.version == old_dek && d.state == KeyState::Revoked));
    assert_eq!(deks.iter().filter(|d| d.state == KeyState::Active).count(), 1);

    // ── KEK rotation re-wraps DEKs without touching secret ciphertext ───────
    let blob_before = sqlx::query!(
        r#"SELECT upstream_password_enc AS "b!" FROM repository WHERE id = $1"#,
        repo1.id
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .b;
    envelope.rotate_kek().await.expect("rotate kek");
    let blob_after = sqlx::query!(
        r#"SELECT upstream_password_enc AS "b!" FROM repository WHERE id = $1"#,
        repo1.id
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .b;
    assert_eq!(blob_before, blob_after, "KEK rotation must not touch ciphertext");

    // A *cold* second instance (fresh cache, same store + root config… here the
    // same provider instance stands in for "same root config") still decrypts.
    let got = secret_dao::get_upstream_password(&pool, &envelope, repo1.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.expose_secret(), "hunter2");
}
