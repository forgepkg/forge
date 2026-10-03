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
use forge_db::auth_realm_dao::{self, AuthRealmUpdate, NewAuthRealm};
use forge_db::encryption_key_dao::PgKeyStore;
use forge_db::repository_dao::{self, NewRepository};
use forge_db::secret_dao;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::Mutex;

static URL: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());
static MIGRATED: OnceLock<()> = OnceLock::new();
/// Serializes the tests whose helpers scan secret columns table-wide (the DEK
/// reference scan spans `repository` AND `auth_realm`).
static TABLE_WIDE: Mutex<()> = Mutex::const_new(());

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
    let kek1 = store
        .insert_active_if_absent(new(KeyLayer::Kek))
        .await
        .unwrap();
    let again = store
        .insert_active_if_absent(new(KeyLayer::Kek))
        .await
        .unwrap();
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
    let active = store
        .get_active(KeyLayer::Kek, &scope)
        .await
        .unwrap()
        .unwrap();
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
    assert!(
        second.is_err(),
        "partial unique index must reject a 2nd active DEK"
    );

    // update_wrapped (compare-and-swap) + set_state round-trip.
    assert!(store
        .update_wrapped(
            &kek1,
            &[0xCD; 60],
            Some("env"),
            Some("sha256:8899aabbccddeeff"),
            None,
        )
        .await
        .unwrap());
    let rewrapped = store
        .get_version(KeyLayer::Kek, &scope, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rewrapped.wrapped_key, vec![0xCD; 60]);
    assert_eq!(
        rewrapped.root_key_version.as_deref(),
        Some("sha256:8899aabbccddeeff")
    );
    // A second writer still holding the pre-swap record loses: nothing written.
    assert!(!store
        .update_wrapped(&kek1, &[0xEE; 60], Some("env"), Some("sha256:stale"), None)
        .await
        .unwrap());
    let unchanged = store
        .get_version(KeyLayer::Kek, &scope, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.wrapped_key, vec![0xCD; 60]);
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
    assert!(
        bad.is_err(),
        "check constraint must reject a DEK with root refs"
    );
}

/// One "instance" of the envelope service over the shared Postgres key store,
/// with a fixed root (several instances built from the same `root` bytes model
/// a multi-instance deployment).
fn instance(pool: &PgPool, scope: &str, root: &KeyBytes) -> EnvelopeService {
    EnvelopeService::new(
        Arc::new(PgKeyStore::new(pool.clone())),
        Arc::new(StaticRootProvider::new(
            "env",
            Algorithm::Aes256Gcm,
            KeyBytes::from_slice(root.expose()).unwrap(),
            vec![],
        )),
        EnvelopeServiceConfig {
            scope: scope.to_string(),
            ..Default::default()
        },
    )
}

/// Assert the hierarchy invariant of review M13: every non-revoked DEK names
/// a KEK that exists and is not revoked.
async fn assert_no_dek_under_revoked_kek(store: &PgKeyStore, scope: &str) {
    let keks = store.list(KeyLayer::Kek, scope).await.unwrap();
    for dek in store.list(KeyLayer::Dek, scope).await.unwrap() {
        if dek.state == KeyState::Revoked {
            continue;
        }
        let parent = dek.wrapping_kek_version.expect("DEK parent");
        assert!(
            keks.iter()
                .any(|k| k.version == parent && k.state != KeyState::Revoked),
            "DEK v{} is wrapped under revoked/missing KEK v{parent}: {keks:?}",
            dek.version
        );
    }
}

/// Review M13: a re-wrap computed from a stale read can never land, a DEK can
/// never be (re-)wrapped under or inserted beneath a revoked KEK, and a KEK
/// that a DEK still references is not revoked — checked by the store at commit
/// time, not by the caller's earlier listing.
#[tokio::test]
async fn kek_rewrap_is_compare_and_swap_and_never_targets_a_revoked_kek() {
    let pool = pool().await;
    let store = PgKeyStore::new(pool.clone());
    let scope = format!("cas-{}", uuid::Uuid::new_v4());
    let root = KeyBytes::generate();
    let a = instance(&pool, &scope, &root);
    let blob = a.seal(&secret("cas-secret"), realm_like(1)).await.unwrap();

    // Instance A reads DEK v1 (under KEK v1) to re-wrap it under KEK v2 ...
    let stale = store.list(KeyLayer::Dek, &scope).await.unwrap().remove(0);
    assert_eq!(stale.wrapping_kek_version, Some(1));
    // ... while "instance B" completes two KEK rotations: the DEK moves to
    // KEK v3 and KEK v1 + v2 end up revoked.
    a.rotate_kek().await.unwrap();
    a.rotate_kek().await.unwrap();
    let keks = store.list(KeyLayer::Kek, &scope).await.unwrap();
    assert_eq!(keks[0].state, KeyState::Revoked);
    assert_eq!(keks[1].state, KeyState::Revoked);
    assert_eq!(keks[2].state, KeyState::Active);

    // A's late write (stale row, revoked target) is refused, nothing written.
    assert!(!store
        .update_wrapped(&stale, &[0xAB; 60], None, None, Some(2))
        .await
        .unwrap());
    // Even against the current row, a revoked target parent is refused.
    let current = store.list(KeyLayer::Dek, &scope).await.unwrap().remove(0);
    assert_eq!(current.wrapping_kek_version, Some(3));
    assert!(!store
        .update_wrapped(&current, &[0xAB; 60], None, None, Some(2))
        .await
        .unwrap());
    let after = store.list(KeyLayer::Dek, &scope).await.unwrap().remove(0);
    assert_eq!(after.wrapped_key, current.wrapped_key);
    assert_eq!(after.wrapping_kek_version, Some(3));
    // A brand-new DEK cannot be inserted beneath a revoked KEK either.
    let err = store
        .insert_active(NewKeyRecord {
            layer: KeyLayer::Dek,
            algorithm: Algorithm::Aes256Gcm,
            wrapped_key: vec![0xAB; 60],
            root_key_id: None,
            root_key_version: None,
            wrapping_kek_version: Some(2),
            scope: scope.clone(),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            forge_crypto::CryptoError::KeyRevoked {
                layer: "kek",
                version: 2
            }
        ),
        "{err:?}"
    );

    // Commit-time reference check: KEK v4 becomes active while the DEK still
    // references v3 (now retiring) — v3 must survive a revoke attempt.
    let provider = StaticRootProvider::new(
        "env",
        Algorithm::Aes256Gcm,
        KeyBytes::from_slice(root.expose()).unwrap(),
        vec![],
    );
    use forge_crypto::KmsProvider as _;
    store
        .insert_active(NewKeyRecord {
            layer: KeyLayer::Kek,
            algorithm: Algorithm::Aes256Gcm,
            wrapped_key: provider
                .wrap_kek(KeyBytes::generate().expose())
                .await
                .unwrap(),
            root_key_id: Some("env".into()),
            root_key_version: Some(provider.current_root_version().await.unwrap()),
            wrapping_kek_version: None,
            scope: scope.clone(),
        })
        .await
        .unwrap();
    let kek3 = store
        .get_version(KeyLayer::Kek, &scope, 3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kek3.state, KeyState::Retiring);
    assert!(!store.revoke_kek_if_unreferenced(&kek3).await.unwrap());
    assert_eq!(
        store
            .get_version(KeyLayer::Kek, &scope, 3)
            .await
            .unwrap()
            .unwrap()
            .state,
        KeyState::Retiring
    );
    // Once the sweep moved the DEK, v3 is revoked; the secret still opens on
    // a cold instance.
    assert_eq!(a.rewrap_deks().await.unwrap(), 1);
    assert_eq!(a.revoke_unreferenced_keks().await.unwrap(), 1);
    assert_no_dek_under_revoked_kek(&store, &scope).await;
    let cold = instance(&pool, &scope, &root);
    assert_eq!(
        cold.open(&blob, realm_like(1))
            .await
            .unwrap()
            .expose_secret(),
        "cas-secret"
    );
}

/// Review M13 under real concurrency: several instances rotating the KEK at
/// once (as an admin request racing the worker on another node would) may
/// fail or skip rows, but never leave a DEK wrapped under a revoked KEK; one
/// converging pass afterwards moves everything under the active KEK.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_kek_rotations_keep_every_dek_unwrappable() {
    let pool = pool().await;
    let store = PgKeyStore::new(pool.clone());
    let scope = format!("race-{}", uuid::Uuid::new_v4());
    let root = KeyBytes::generate();
    let first = instance(&pool, &scope, &root);
    let blob = first
        .seal(&secret("race-secret"), realm_like(2))
        .await
        .unwrap();
    // A second DEK so the re-wrap sweeps have more than one row to race on.
    first.rotate_dek().await.unwrap();
    let blob2 = first
        .seal(&secret("race-secret-2"), realm_like(3))
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for _ in 0..6 {
        let svc = Arc::new(instance(&pool, &scope, &root));
        tasks.push(tokio::spawn(async move {
            for _ in 0..3 {
                // Errors are acceptable here (a racing rotation revoked a KEK
                // this one was about to read); corruption is not.
                let _ = svc.rotate_kek().await;
                let _ = svc.rewrap_deks().await;
                let _ = svc.revoke_unreferenced_keks().await;
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_no_dek_under_revoked_kek(&store, &scope).await;

    let converge = instance(&pool, &scope, &root);
    converge.rewrap_deks().await.expect("converging re-wrap");
    converge
        .revoke_unreferenced_keks()
        .await
        .expect("converging revoke");
    assert_no_dek_under_revoked_kek(&store, &scope).await;
    let active = store
        .get_active(KeyLayer::Kek, &scope)
        .await
        .unwrap()
        .expect("active KEK");
    for dek in store.list(KeyLayer::Dek, &scope).await.unwrap() {
        assert_eq!(dek.wrapping_kek_version, Some(active.version));
    }
    let cold = instance(&pool, &scope, &root);
    assert_eq!(
        cold.open(&blob, realm_like(2))
            .await
            .unwrap()
            .expose_secret(),
        "race-secret"
    );
    assert_eq!(
        cold.open(&blob2, realm_like(3))
            .await
            .unwrap()
            .expose_secret(),
        "race-secret-2"
    );
}

/// A test-only AEAD binding (the key-hierarchy tests never store the blob).
fn realm_like(row_pk: i64) -> forge_crypto::envelope::AeadBinding<'static> {
    forge_crypto::envelope::AeadBinding {
        table: "test",
        column: "secret",
        row_pk,
        destination: None,
    }
}

/// Review M13, DEK layer: a retiring DEK is revoked only if no ciphertext
/// references it **at commit time**. The revoker waits for an in-flight writer
/// that still seals under that DEK (and then keeps it), and a writer whose DEK
/// is revoked while it waits writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dek_revocation_is_checked_at_commit_time_against_writers() {
    let _serial = TABLE_WIDE.lock().await;
    let pool = pool().await;
    // The reference scan is table-wide; start from no stored ciphertext.
    sqlx::query("DELETE FROM group_member")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM repository")
        .execute(&pool)
        .await
        .unwrap();
    let scope = format!("dek-revoke-{}", uuid::Uuid::new_v4());
    let envelope = Arc::new(envelope_with_scope(&pool, &scope));
    envelope.ensure_active_keys().await.unwrap();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy("crypt-inflight"))
        .await
        .unwrap();
    let repo_binding = forge_crypto::envelope::AeadBinding {
        table: secret_dao::UPSTREAM_PASSWORD_TABLE,
        column: secret_dao::UPSTREAM_PASSWORD_COLUMN,
        row_pk: repo.id,
        destination: None,
    };

    // A writer sealed under DEK v1, then DEK v2 became active (v1 retiring).
    let blob_v1 = envelope
        .seal(&secret("in-flight"), repo_binding)
        .await
        .unwrap();
    assert_eq!(EnvelopeService::blob_dek_version(&blob_v1).unwrap(), 1);
    envelope.rotate_dek().await.unwrap();

    // The writer's transaction (the protocol every secret_dao write follows):
    // FOR SHARE on its DEK, then the ciphertext write — not committed yet.
    let mut writer = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT 1 FROM encryption_key WHERE layer = 'dek' AND scope = $1 AND version = 1 \
         AND state <> 'revoked' FOR SHARE",
    )
    .bind(&scope)
    .fetch_one(&mut *writer)
    .await
    .unwrap();
    sqlx::query("UPDATE repository SET upstream_password_enc = $2 WHERE id = $1")
        .bind(repo.id)
        .bind(&blob_v1)
        .execute(&mut *writer)
        .await
        .unwrap();

    // The sweep's revocation must wait for the writer instead of revoking v1
    // from a snapshot that cannot see the uncommitted blob.
    let revoker = {
        let pool = pool.clone();
        let envelope = envelope.clone();
        tokio::spawn(async move { secret_dao::revoke_unreferenced_deks(&pool, &envelope).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !revoker.is_finished(),
        "revocation must wait for the in-flight ciphertext writer"
    );
    writer.commit().await.unwrap();
    let revoked = revoker.await.unwrap().expect("revoke sweep");
    assert_eq!(revoked, 0, "DEK v1 is referenced at commit time: kept");
    let deks = envelope.list_keys(KeyLayer::Dek).await.unwrap();
    assert_eq!(deks[0].state, KeyState::Retiring);
    assert_eq!(
        secret_dao::get_upstream_password(&pool, &envelope, repo.id)
            .await
            .unwrap()
            .unwrap()
            .expose_secret(),
        "in-flight"
    );

    // Writer side: set_upstream_password seals under the active DEK v2; if v2
    // is revoked while the write waits for its row lock, nothing is written.
    let mut revoker_tx = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT 1 FROM encryption_key WHERE layer = 'dek' AND scope = $1 AND version = 2 \
         FOR UPDATE",
    )
    .bind(&scope)
    .fetch_one(&mut *revoker_tx)
    .await
    .unwrap();
    let write = {
        let pool = pool.clone();
        let envelope = envelope.clone();
        let id = repo.id;
        tokio::spawn(async move {
            secret_dao::set_upstream_password(
                &mut *pool.acquire().await.unwrap(),
                &envelope,
                id,
                Some(&secret("late")),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !write.is_finished(),
        "the write must wait for the DEK row lock"
    );
    sqlx::query(
        "UPDATE encryption_key SET state = 'revoked' WHERE layer = 'dek' AND scope = $1 \
         AND version = 2",
    )
    .bind(&scope)
    .execute(&mut *revoker_tx)
    .await
    .unwrap();
    revoker_tx.commit().await.unwrap();
    let err = write.await.unwrap().unwrap_err();
    assert!(
        matches!(
            err,
            secret_dao::SecretDbError::Crypto(forge_crypto::CryptoError::KeyRevoked {
                layer: "dek",
                version: 2
            })
        ),
        "{err:?}"
    );
    let stored = sqlx::query!(
        r#"SELECT upstream_password_enc AS "b!" FROM repository WHERE id = $1"#,
        repo.id
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .b;
    assert_eq!(stored, blob_v1, "no ciphertext under the revoked DEK");

    repository_dao::delete_repository(&pool, repo.id)
        .await
        .unwrap();
}

/// The full §12.5 data path against real Postgres: encrypted set/get, envelope
/// (not plaintext) at rest, tamper + AAD-swap rejection at the DB layer, the
/// plaintext backfill, and the DEK-rotation sweep. One serial test because the
/// backfill/sweep helpers operate on the whole `repository` table.
#[tokio::test]
async fn upstream_password_end_to_end() {
    let _serial = TABLE_WIDE.lock().await;
    let pool = pool().await;
    // Clean slate (see module docs): sweeps are table-wide and a reused
    // scratch DB may hold rows sealed under a previous run's root.
    sqlx::query("DELETE FROM group_member")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM repository")
        .execute(&pool)
        .await
        .unwrap();
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
    secret_dao::set_upstream_password(
        &mut *pool.acquire().await.unwrap(),
        &envelope,
        repo1.id,
        Some(&secret("hunter2")),
    )
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
    assert!(
        !blob.windows(7).any(|w| w == b"hunter2"),
        "plaintext at rest!"
    );

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
        secret_dao::get_upstream_password(&pool, &envelope, repo1.id)
            .await
            .is_err(),
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
        secret_dao::get_upstream_password(&pool, &envelope, repo2.id)
            .await
            .is_err(),
        "repo1's blob pasted into repo2 must fail (row-bound AAD)"
    );
    secret_dao::set_upstream_password(
        &mut *pool.acquire().await.unwrap(),
        &envelope,
        repo2.id,
        None,
    )
    .await
    .unwrap();

    // ── plaintext backfill (slice-1 rows) ────────────────────────────────────
    let mut legacy = NewRepository::proxy("crypt-legacy");
    legacy.upstream_password = Some("legacy-pw".to_string());
    let legacy = repository_dao::insert_repository(&pool, legacy)
        .await
        .unwrap();
    // A row 0.1.0's backfill left behind: envelope written, plaintext kept.
    let mut leftover = NewRepository::proxy("crypt-leftover");
    leftover.upstream_password = Some("leftover-pw".to_string());
    let leftover = repository_dao::insert_repository(&pool, leftover)
        .await
        .unwrap();
    let leftover_blob = envelope
        .seal(
            &secret("leftover-pw"),
            forge_crypto::envelope::AeadBinding {
                table: secret_dao::UPSTREAM_PASSWORD_TABLE,
                column: secret_dao::UPSTREAM_PASSWORD_COLUMN,
                row_pk: leftover.id,
                destination: None,
            },
        )
        .await
        .unwrap();
    sqlx::query!(
        r#"UPDATE repository SET upstream_password_enc = $2 WHERE id = $1"#,
        leftover.id,
        &leftover_blob
    )
    .execute(&pool)
    .await
    .unwrap();
    // A row whose envelope is stale (the password was changed while
    // encryption was off) and one whose envelope does not decrypt: in both
    // the plaintext is the copy to keep, so it is sealed afresh.
    let mut stale = NewRepository::proxy("crypt-stale");
    stale.upstream_password = Some("new-pw".to_string());
    let stale = repository_dao::insert_repository(&pool, stale)
        .await
        .unwrap();
    let stale_blob = envelope
        .seal(
            &secret("old-pw"),
            forge_crypto::envelope::AeadBinding {
                table: secret_dao::UPSTREAM_PASSWORD_TABLE,
                column: secret_dao::UPSTREAM_PASSWORD_COLUMN,
                row_pk: stale.id,
                destination: None,
            },
        )
        .await
        .unwrap();
    let mut broken = NewRepository::proxy("crypt-broken");
    broken.upstream_password = Some("broken-pw".to_string());
    let broken = repository_dao::insert_repository(&pool, broken)
        .await
        .unwrap();
    for (id, blob) in [
        (stale.id, stale_blob),
        (broken.id, b"not an envelope".to_vec()),
    ] {
        sqlx::query!(
            r#"UPDATE repository SET upstream_password_enc = $2 WHERE id = $1"#,
            id,
            &blob
        )
        .execute(&pool)
        .await
        .unwrap();
    }
    assert!(secret_dao::plaintext_passwords_pending(&pool)
        .await
        .unwrap());

    // One pass seals the plaintext-only row, clears the verified leftover
    // copy and re-seals the stale and the undecryptable rows.
    let done = secret_dao::backfill_upstream_passwords(&pool, &envelope, 100)
        .await
        .expect("backfill");
    assert_eq!(done, 4);
    // Every plaintext copy is gone, not just the un-sealed ones.
    assert!(!secret_dao::plaintext_passwords_pending(&pool)
        .await
        .unwrap());
    let plaintext_rows = sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM repository WHERE upstream_password IS NOT NULL"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        plaintext_rows, 0,
        "no plaintext password may remain at rest"
    );
    // Re-run is a no-op (idempotent).
    assert_eq!(
        secret_dao::backfill_upstream_passwords(&pool, &envelope, 100)
            .await
            .unwrap(),
        0
    );
    // The original plaintexts survive the round trip, now only as envelopes.
    for (id, expected) in [
        (legacy.id, "legacy-pw"),
        (leftover.id, "leftover-pw"),
        (stale.id, "new-pw"),
        (broken.id, "broken-pw"),
    ] {
        let got = secret_dao::get_upstream_password(&pool, &envelope, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.expose_secret(), expected);
        let row = sqlx::query!(
            r#"SELECT upstream_password, upstream_password_enc FROM repository WHERE id = $1"#,
            id
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(row.upstream_password.is_none(), "plaintext cleared");
        assert!(row.upstream_password_enc.is_some());
    }

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
    assert_eq!(
        resealed, 5,
        "repo1 + legacy + leftover + stale + broken re-encrypted under the new DEK"
    );

    // Everything still decrypts and now references the active DEK.
    for (id, expected) in [(repo1.id, "hunter2"), (legacy.id, "legacy-pw")] {
        let got = secret_dao::get_upstream_password(&pool, &envelope, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.expose_secret(), expected);
    }
    let referenced = secret_dao::referenced_dek_versions(&pool).await.unwrap();
    assert!(
        !referenced.contains(&old_dek),
        "old DEK no longer referenced"
    );

    // The old DEK ends `revoked` once unreferenced; the new one stays active.
    let revoked = secret_dao::revoke_unreferenced_deks(&pool, &envelope)
        .await
        .unwrap();
    assert_eq!(revoked, 1);
    let deks = envelope.list_keys(KeyLayer::Dek).await.unwrap();
    assert!(deks
        .iter()
        .any(|d| d.version == old_dek && d.state == KeyState::Revoked));
    assert_eq!(
        deks.iter().filter(|d| d.state == KeyState::Active).count(),
        1
    );

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
    assert_eq!(
        blob_before, blob_after,
        "KEK rotation must not touch ciphertext"
    );

    // A *cold* second instance (fresh cache, same store + root config… here the
    // same provider instance stands in for "same root config") still decrypts.
    let got = secret_dao::get_upstream_password(&pool, &envelope, repo1.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.expose_secret(), "hunter2");
}

/// Realm secrets at rest (review P1.5): sealed into `auth_realm.secrets_enc`
/// and stripped from the plaintext `config`, AAD-bound to the row, readable
/// back as the logical config, legacy plaintext rows backfilled, re-sealed by
/// the DEK sweep, and stored as plaintext again when encryption is off.
#[tokio::test]
async fn realm_secrets_end_to_end() {
    let _serial = TABLE_WIDE.lock().await;
    let pool = pool().await;
    let envelope = envelope_with_scope(&pool, "realm-secrets-test");
    envelope.ensure_active_keys().await.expect("bootstrap keys");
    let keys: &[&str] = &["key_pepper"];
    let suffix = std::process::id();
    let prio_base = 3_000_000 + (suffix % 100_000) as i32 * 10;
    let new_realm = |name: &str, prio: i32, pepper: &str| NewAuthRealm {
        kind: "credential_forwarding".into(),
        name: format!("{name}-{suffix}"),
        enabled: false,
        priority: prio,
        config: serde_json::json!({ "url": "https://nexus.test/s", "key_pepper": pepper }),
    };

    // ── encrypted insert ─────────────────────────────────────────────────────
    let sealed = secret_dao::insert_realm_with_secrets(
        &pool,
        Some(&envelope),
        new_realm("sealed", prio_base, "p3pper-secret"),
        keys,
    )
    .await
    .expect("insert sealed");
    assert!(
        sealed.config.get("key_pepper").is_none(),
        "stripped from config"
    );
    let blob = sealed.secrets_enc.clone().expect("secrets_enc set");
    assert!(
        !String::from_utf8_lossy(&blob).contains("p3pper-secret"),
        "ciphertext, not plaintext"
    );
    let logical = secret_dao::realm_config(Some(&envelope), &sealed)
        .await
        .expect("decrypt");
    assert_eq!(logical["key_pepper"], "p3pper-secret");
    assert_eq!(logical["url"], "https://nexus.test/s");
    // Without an envelope an encrypted realm fails closed.
    assert!(secret_dao::realm_config(None, &sealed).await.is_err());

    // ── legacy plaintext row: read as-is, then backfilled ────────────────────
    let legacy =
        auth_realm_dao::insert_realm(&pool, new_realm("legacy", prio_base + 1, "old-pepper"))
            .await
            .expect("insert legacy");
    assert_eq!(
        secret_dao::realm_config(None, &legacy).await.unwrap()["key_pepper"],
        "old-pepper"
    );
    // The AAD binds the blob to its row: copied onto another row it won't open.
    let mut swapped = legacy.clone();
    swapped.secrets_enc = Some(blob.clone());
    assert!(secret_dao::realm_config(Some(&envelope), &swapped)
        .await
        .is_err());

    let realm_keys = |kind: &str| -> &'static [&'static str] {
        if kind == "credential_forwarding" {
            &["key_pepper"]
        } else {
            &[]
        }
    };
    assert!(
        secret_dao::plaintext_realm_secrets_pending(&pool, realm_keys)
            .await
            .unwrap(),
        "the legacy realm's plaintext pepper is reported pending"
    );
    let backfilled = secret_dao::backfill_realm_secrets(&pool, &envelope, realm_keys)
        .await
        .expect("backfill");
    assert!(backfilled >= 1);
    assert!(
        !secret_dao::plaintext_realm_secrets_pending(&pool, realm_keys)
            .await
            .unwrap()
    );
    let legacy = auth_realm_dao::find_realm_by_id(&pool, legacy.id)
        .await
        .unwrap()
        .unwrap();
    assert!(legacy.config.get("key_pepper").is_none());
    assert!(legacy.secrets_enc.is_some());
    assert_eq!(
        secret_dao::realm_config(Some(&envelope), &legacy)
            .await
            .unwrap()["key_pepper"],
        "old-pepper"
    );

    // ── DEK rotation: the sweep re-seals realm secrets too ───────────────────
    envelope.rotate_dek().await.expect("rotate dek");
    let resealed = secret_dao::reseal_realm_secrets(&pool, &envelope)
        .await
        .expect("reseal");
    assert!(resealed >= 2, "both realms resealed: {resealed}");
    let sealed_now = auth_realm_dao::find_realm_by_id(&pool, sealed.id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(sealed_now.secrets_enc.as_deref(), Some(blob.as_slice()));
    assert_eq!(
        secret_dao::realm_config(Some(&envelope), &sealed_now)
            .await
            .unwrap()["key_pepper"],
        "p3pper-secret"
    );
    let referenced = secret_dao::referenced_dek_versions(&pool).await.unwrap();
    assert!(referenced.contains(
        &EnvelopeService::blob_dek_version(sealed_now.secrets_enc.as_deref().unwrap()).unwrap()
    ));

    // ── encryption off: an update stores plaintext and clears secrets_enc ────
    let plain = secret_dao::update_realm_with_secrets(
        &pool,
        None,
        sealed.id,
        AuthRealmUpdate {
            name: sealed_now.name.clone(),
            enabled: false,
            priority: sealed_now.priority,
            config: secret_dao::realm_config(Some(&envelope), &sealed_now)
                .await
                .unwrap(),
        },
        keys,
    )
    .await
    .expect("update")
    .expect("row");
    assert!(plain.secrets_enc.is_none());
    assert_eq!(plain.config["key_pepper"], "p3pper-secret");

    for id in [sealed.id, legacy.id] {
        auth_realm_dao::delete_realm(&pool, id).await.unwrap();
    }
}

/// The upstream password is bound to the origin of its row's `remote_url`
/// (review: "the ciphertext is not bound to where the secret is sent"). A
/// row repointed at another host outside the API no longer decrypts, so the
/// proxy can never send the password there; a path change on the same origin
/// keeps it. A blob an earlier build sealed under the row-only binding still
/// opens and is moved to the origin binding by the re-encrypt sweep.
#[tokio::test]
async fn upstream_password_is_bound_to_the_remote_origin() {
    let pool = pool().await;
    let envelope = envelope_with_scope(&pool, &format!("origin-{}", uuid::Uuid::new_v4()));
    envelope.ensure_active_keys().await.unwrap();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let mut new = NewRepository::proxy(format!("crypt-origin-{suffix}"));
    new.remote_url = Some("https://Nexus.Example:443/repository/nuget/index.json".into());
    let repo = repository_dao::insert_repository(&pool, new).await.unwrap();
    let set_url = |url: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query("UPDATE repository SET remote_url = $2 WHERE id = $1")
                .bind(repo.id)
                .bind(url)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    let read = || secret_dao::get_upstream_credential(&pool, &envelope, repo.id);

    secret_dao::set_upstream_password(
        &mut *pool.acquire().await.unwrap(),
        &envelope,
        repo.id,
        Some(&secret("pw")),
    )
    .await
    .unwrap();
    let got = read().await.unwrap().unwrap();
    assert_eq!(got.secret.expose_secret(), "pw");
    assert_eq!(
        got.remote_url.as_deref(),
        Some("https://Nexus.Example:443/repository/nuget/index.json")
    );

    // Same origin (case, default port and path do not matter): still readable.
    set_url("https://nexus.example/other/index.json").await;
    assert_eq!(read().await.unwrap().unwrap().secret.expose_secret(), "pw");

    // Another origin: the password does not decrypt, and the sweep leaves it.
    for elsewhere in [
        "https://attacker.example/index.json",
        "http://nexus.example/index.json",
        "https://nexus.example:8443/index.json",
    ] {
        set_url(elsewhere).await;
        assert!(
            matches!(
                read().await,
                Err(secret_dao::SecretDbError::Crypto(
                    forge_crypto::CryptoError::DecryptFailed
                ))
            ),
            "{elsewhere}"
        );
    }
    let swept = secret_dao::reseal_upstream_passwords_batch(&pool, &envelope, repo.id - 1, 1)
        .await
        .expect("an undecryptable row does not fail the sweep");
    assert_eq!(swept.resealed, 0);
    set_url("https://nexus.example/index.json").await;
    assert_eq!(read().await.unwrap().unwrap().secret.expose_secret(), "pw");

    // A blob sealed by an earlier build (row-only binding) still opens …
    let legacy = envelope
        .seal(
            &secret("legacy-pw"),
            forge_crypto::envelope::AeadBinding {
                table: secret_dao::UPSTREAM_PASSWORD_TABLE,
                column: secret_dao::UPSTREAM_PASSWORD_COLUMN,
                row_pk: repo.id,
                destination: None,
            },
        )
        .await
        .unwrap();
    sqlx::query("UPDATE repository SET upstream_password_enc = $2 WHERE id = $1")
        .bind(repo.id)
        .bind(&legacy)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        read().await.unwrap().unwrap().secret.expose_secret(),
        "legacy-pw"
    );
    // … and the sweep re-seals it for the current origin, once.
    let swept = secret_dao::reseal_upstream_passwords_batch(&pool, &envelope, repo.id - 1, 1)
        .await
        .unwrap();
    assert_eq!(swept.resealed, 1);
    let swept = secret_dao::reseal_upstream_passwords_batch(&pool, &envelope, repo.id - 1, 1)
        .await
        .unwrap();
    assert_eq!(swept.resealed, 0, "converged");
    assert_eq!(
        read().await.unwrap().unwrap().secret.expose_secret(),
        "legacy-pw"
    );
    set_url("https://attacker.example/index.json").await;
    assert!(read().await.is_err(), "now bound to the origin");
}

/// An OIDC realm's client secret is bound to its issuer and client id: a
/// realm repointed at another issuer outside the API fails closed instead of
/// handing the secret to that issuer's token endpoint.
#[tokio::test]
async fn oidc_client_secret_is_bound_to_the_issuer() {
    let pool = pool().await;
    let envelope = envelope_with_scope(&pool, &format!("issuer-{}", uuid::Uuid::new_v4()));
    envelope.ensure_active_keys().await.unwrap();
    let realm = secret_dao::insert_realm_with_secrets(
        &pool,
        Some(&envelope),
        NewAuthRealm {
            kind: "oidc".into(),
            name: format!("idp-{}", uuid::Uuid::new_v4().simple()),
            enabled: false,
            priority: 4_000_000 + (std::process::id() % 100_000) as i32,
            config: serde_json::json!({
                "issuer": "https://login.example/tenant/v2.0",
                "client_id": "forge",
                "client_secret": "s3cret",
            }),
        },
        &["client_secret"],
    )
    .await
    .unwrap();
    assert_eq!(
        secret_dao::realm_config(Some(&envelope), &realm)
            .await
            .unwrap()["client_secret"],
        "s3cret"
    );
    for (key, value) in [
        ("issuer", "https://attacker.example/v2.0"),
        ("client_id", "someone-else"),
    ] {
        let mut repointed = realm.clone();
        repointed.config[key] = serde_json::json!(value);
        assert!(
            matches!(
                secret_dao::realm_config(Some(&envelope), &repointed).await,
                Err(secret_dao::SecretDbError::Crypto(
                    forge_crypto::CryptoError::DecryptFailed
                ))
            ),
            "{key}"
        );
    }
    // Fields the secret is not bound to may change.
    let mut renamed = realm.clone();
    renamed.config["scopes"] = serde_json::json!(["openid", "email"]);
    assert_eq!(
        secret_dao::realm_config(Some(&envelope), &renamed)
            .await
            .unwrap()["client_secret"],
        "s3cret"
    );
    auth_realm_dao::delete_realm(&pool, realm.id).await.unwrap();
}
