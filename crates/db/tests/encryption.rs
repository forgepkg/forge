//! Integration tests for secret encryption at rest: the Postgres
//! [`PgKeyStore`], the encrypted `repository.upstream_password_enc` column,
//! and the DEK-rotation re-encrypt sweep.
//!
//! Postgres comes from `FORGE_TEST_DATABASE_URL` when set (a docker-less dev
//! loop pointing at a scratch database) or a testcontainer otherwise. The
//! end-to-end test wipes `repository` + `encryption_key` first because the
//! sweep helpers operate table-wide and a reused scratch database may
//! hold rows sealed under a previous run's (random) root key.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use forge_crypto::envelope::Algorithm;
use forge_crypto::kms::StaticRootProvider;
use forge_crypto::service::{EnvelopeService, EnvelopeServiceConfig};
use forge_crypto::store::{KeyLayer, KeyState, KeyStore, NewKeyRecord};
use forge_crypto::{ExposeSecret, KeyBytes, PlaintextSecret};
use forge_db::auth_realm_dao::{self, AuthRealmUpdate, NewAuthRealm};
use forge_db::authz_dao;
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
                .with_name("mirror.gcr.io/library/postgres")
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
    let destination = secret_dao::upstream_destination(repo.remote_url.as_deref());
    let repo_binding = forge_crypto::envelope::AeadBinding {
        table: secret_dao::UPSTREAM_PASSWORD_TABLE,
        column: secret_dao::UPSTREAM_PASSWORD_COLUMN,
        row_pk: repo.id,
        destination: Some(&destination),
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
                &mut pool.acquire().await.unwrap(),
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

/// The full encryption data path against real Postgres: encrypted set/get,
/// envelope (not plaintext) at rest, tamper + AAD-swap rejection at the DB
/// layer, and the DEK-rotation sweep. One serial test because the sweep
/// helpers operate on the whole `repository` table.
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
        &mut pool.acquire().await.unwrap(),
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

    // Stored bytes are an envelope blob, NOT the plaintext.
    let blob = sqlx::query_scalar!(
        r#"SELECT upstream_password_enc FROM repository WHERE id = $1"#,
        repo1.id
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .expect("enc blob stored");
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
        &mut pool.acquire().await.unwrap(),
        &envelope,
        repo2.id,
        None,
    )
    .await
    .unwrap();

    // A second sealed password, for the sweep below.
    let repo3 = repository_dao::insert_repository(&pool, NewRepository::proxy("crypt-p3"))
        .await
        .unwrap();
    secret_dao::set_upstream_password(
        &mut pool.acquire().await.unwrap(),
        &envelope,
        repo3.id,
        Some(&secret("second-pw")),
    )
    .await
    .unwrap();

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
    assert_eq!(resealed, 2, "repo1 + repo3 re-encrypted under the new DEK");

    // Everything still decrypts and now references the active DEK.
    for (id, expected) in [(repo1.id, "hunter2"), (repo3.id, "second-pw")] {
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
/// and stripped from the stored `config`, AAD-bound to the row, readable back
/// as the logical config, re-sealed by the DEK sweep and by an update.
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
        &envelope,
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
    let logical = secret_dao::realm_config(&envelope, &sealed)
        .await
        .expect("decrypt");
    assert_eq!(logical["key_pepper"], "p3pper-secret");
    assert_eq!(logical["url"], "https://nexus.test/s");

    // ── a second realm; the AAD binds a blob to its row ──────────────────────
    let second = secret_dao::insert_realm_with_secrets(
        &pool,
        &envelope,
        new_realm("second", prio_base + 1, "old-pepper"),
        keys,
    )
    .await
    .expect("insert second");
    assert_eq!(
        secret_dao::realm_config(&envelope, &second).await.unwrap()["key_pepper"],
        "old-pepper"
    );
    // Copied onto another row it won't open.
    let mut swapped = second.clone();
    swapped.secrets_enc = Some(blob.clone());
    assert!(secret_dao::realm_config(&envelope, &swapped).await.is_err());

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
        secret_dao::realm_config(&envelope, &sealed_now)
            .await
            .unwrap()["key_pepper"],
        "p3pper-secret"
    );
    let referenced = secret_dao::referenced_dek_versions(&pool).await.unwrap();
    assert!(referenced.contains(
        &EnvelopeService::blob_dek_version(sealed_now.secrets_enc.as_deref().unwrap()).unwrap()
    ));

    // ── an update re-seals the secrets and keeps them out of `config` ────────
    let updated = secret_dao::update_realm_with_secrets(
        &pool,
        &envelope,
        sealed.id,
        AuthRealmUpdate {
            name: sealed_now.name.clone(),
            enabled: false,
            priority: sealed_now.priority,
            config: secret_dao::realm_config(&envelope, &sealed_now)
                .await
                .unwrap(),
        },
        keys,
    )
    .await
    .expect("update")
    .expect("row");
    assert!(updated.config.get("key_pepper").is_none());
    assert_ne!(updated.secrets_enc, sealed_now.secrets_enc);
    assert_eq!(
        secret_dao::realm_config(&envelope, &updated).await.unwrap()["key_pepper"],
        "p3pper-secret"
    );

    for id in [sealed.id, second.id] {
        auth_realm_dao::delete_realm(&pool, id).await.unwrap();
    }
}

/// The server's realm secret keys (`forge_server::auth::secret_keys`).
fn realm_secret_keys(kind: &str) -> &'static [&'static str] {
    match kind {
        "oidc" => &["client_secret"],
        "credential_forwarding" => &["key_pepper"],
        _ => &[],
    }
}

/// A priority no other test of this binary uses (the column is unique).
fn race_priority(offset: i32) -> i32 {
    5_000_000 + (std::process::id() % 100_000) as i32 * 10 + offset
}

/// #82: one malformed sealed secret (a botched restore, a manual edit) does
/// not stop the passes over every row: the startup re-seal, and the
/// key-reference scan behind DEK revocation, warn about it and go on.
#[tokio::test]
async fn a_malformed_sealed_secret_does_not_stop_the_sweeps() {
    let _serial = TABLE_WIDE.lock().await;
    let pool = pool().await;
    let envelope = envelope_with_scope(&pool, &format!("malformed-{}", uuid::Uuid::new_v4()));
    envelope.ensure_active_keys().await.unwrap();

    let mut repo = NewRepository::proxy(format!("malformed{}", uuid::Uuid::new_v4().simple()));
    repo.remote_url = Some("https://feed.example/v3/index.json".into());
    let repo = repository_dao::insert_repository(&pool, repo)
        .await
        .unwrap();
    let realm = secret_dao::insert_realm_with_secrets(
        &pool,
        &envelope,
        NewAuthRealm {
            kind: "oidc".into(),
            name: format!("malformed-{}", uuid::Uuid::new_v4().simple()),
            enabled: false,
            priority: race_priority(2),
            config: serde_json::json!({
                "issuer": "https://login.example/v2.0",
                "client_id": "forge",
                "client_secret": "secret",
            }),
        },
        realm_secret_keys("oidc"),
    )
    .await
    .unwrap();
    for blob in [&b"\x00"[..], &b"\x01\x02\x03"[..]] {
        sqlx::query("UPDATE repository SET upstream_password_enc = $2 WHERE id = $1")
            .bind(repo.id)
            .bind(blob)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE auth_realm SET secrets_enc = $2 WHERE id = $1")
            .bind(realm.id)
            .bind(blob)
            .execute(&pool)
            .await
            .unwrap();

        let mut after_id = 0;
        loop {
            let batch =
                secret_dao::reseal_upstream_passwords_batch(&pool, &envelope, after_id, 100)
                    .await
                    .expect("the upstream password sweep goes on");
            match batch.next_after_id {
                Some(next) => after_id = next,
                None => break,
            }
        }
        secret_dao::reseal_realm_secrets(&pool, &envelope)
            .await
            .expect("the realm re-seal goes on");
        secret_dao::referenced_dek_versions(&pool)
            .await
            .expect("the reference scan goes on");
    }
    auth_realm_dao::delete_realm(&pool, realm.id).await.unwrap();
    sqlx::query("DELETE FROM repository WHERE id = $1")
        .bind(repo.id)
        .execute(&pool)
        .await
        .unwrap();
}

/// The generated registry-token key in `forge_setting` is a secret like the
/// secret columns (#196): the DEK it is sealed under is not revoked while it
/// is, DEK rotation re-seals it, and only a value that can never be opened
/// counts as unreadable (a `plain:` value 1.x stored without `[crypto]`
/// among them).
#[tokio::test]
async fn secret_settings_follow_dek_rotation() {
    let _serial = TABLE_WIDE.lock().await;
    let pool = pool().await;
    let envelope = envelope_with_scope(&pool, &format!("settings-{}", uuid::Uuid::new_v4()));
    envelope.ensure_active_keys().await.unwrap();
    // DEK versions no other test's ciphertext uses, so that the reference
    // scan alone decides whether this one's DEKs are revoked.
    for _ in 0..6 {
        envelope.rotate_dek().await.unwrap();
    }
    let key = secret_dao::REGISTRY_TOKEN_KEY_SETTING;
    sqlx::query("DELETE FROM forge_setting WHERE key = $1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let open = |value: String| {
        let envelope = &envelope;
        async move { secret_dao::open_secret_setting(envelope, key, &value).await }
    };

    let stored = secret_dao::store_secret_setting(&pool, &envelope, key, &secret("k1"), None)
        .await
        .unwrap()
        .expect("stored");
    assert!(stored.starts_with("sealed:") && !stored.contains("k1"));
    assert!(
        secret_dao::store_secret_setting(&pool, &envelope, key, &secret("k9"), None)
            .await
            .unwrap()
            .is_none(),
        "stored only while unset"
    );
    assert_eq!(open(stored.clone()).await.unwrap().expose_secret(), "k1");

    // Its DEK stays while the key is sealed under it.
    envelope.rotate_dek().await.unwrap();
    secret_dao::revoke_unreferenced_deks(&pool, &envelope)
        .await
        .unwrap();
    assert_eq!(open(stored.clone()).await.unwrap().expose_secret(), "k1");

    // The sweep re-seals it under the active DEK; then the old one goes.
    assert_eq!(
        secret_dao::reseal_secret_settings(&pool, &envelope)
            .await
            .unwrap(),
        1
    );
    let resealed = authz_dao::get_setting(&pool, key).await.unwrap().unwrap();
    assert_ne!(resealed, stored);
    assert_eq!(
        secret_dao::reseal_secret_settings(&pool, &envelope)
            .await
            .unwrap(),
        0,
        "converged"
    );
    assert!(
        secret_dao::revoke_unreferenced_deks(&pool, &envelope)
            .await
            .unwrap()
            >= 1
    );
    assert_eq!(open(resealed.clone()).await.unwrap().expose_secret(), "k1");
    let err = open(stored).await.unwrap_err();
    assert!(secret_dao::is_unreadable_setting(&err), "{err}");
    for malformed in ["sealed:***", "sealed:AAAA", "bogus", "plain:k2"] {
        let err = open(malformed.to_string()).await.unwrap_err();
        assert!(
            secret_dao::is_unreadable_setting(&err),
            "{malformed}: {err}"
        );
    }

    sqlx::query("DELETE FROM forge_setting WHERE key = $1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
}

/// The upstream password is bound to the origin of its row's `remote_url`
/// (review: "the ciphertext is not bound to where the secret is sent"). A
/// row repointed at another host outside the API no longer decrypts, so the
/// proxy can never send the password there; a path change on the same origin
/// keeps it. A blob sealed under the row-only binding (as pre-release builds
/// did) does not decrypt either, and the sweep leaves it.
#[tokio::test]
async fn upstream_password_is_bound_to_the_remote_origin() {
    let pool = pool().await;
    let scope = format!("origin-{}", uuid::Uuid::new_v4());
    let root = KeyBytes::generate();
    let envelope = instance(&pool, &scope, &root);
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
        &mut pool.acquire().await.unwrap(),
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

    // A blob sealed under the row-only binding (as pre-release builds did)
    // is refused, and the sweep leaves it alone.
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
    assert!(matches!(
        read().await,
        Err(secret_dao::SecretDbError::Crypto(
            forge_crypto::CryptoError::DecryptFailed
        ))
    ));
    let swept = secret_dao::reseal_upstream_passwords_batch(&pool, &envelope, repo.id - 1, 1)
        .await
        .unwrap();
    assert_eq!(swept.resealed, 0);
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
        &envelope,
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
        secret_dao::realm_config(&envelope, &realm).await.unwrap()["client_secret"],
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
                secret_dao::realm_config(&envelope, &repointed).await,
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
        secret_dao::realm_config(&envelope, &renamed).await.unwrap()["client_secret"],
        "s3cret"
    );
    auth_realm_dao::delete_realm(&pool, realm.id).await.unwrap();
}

/// #319: the email settings' transport secret (the SMTP password) is sealed
/// into `email_settings.secrets_enc` and stripped from `config`, bound to the
/// transport's host and username, follows DEK rotation (the sweep re-seals
/// it, the reference scan protects its DEK), and a transport without a
/// secret seals nothing.
#[tokio::test]
async fn email_settings_secrets_are_sealed_bound_and_rotated() {
    use forge_db::email_settings_dao;
    use serde_json::json;

    let _serial = TABLE_WIDE.lock().await;
    let pool = pool().await;
    let envelope = envelope_with_scope(&pool, &format!("email-{}", uuid::Uuid::new_v4()));
    envelope.ensure_active_keys().await.unwrap();
    for _ in 0..6 {
        envelope.rotate_dek().await.unwrap();
    }
    sqlx::query("DELETE FROM email_settings")
        .execute(&pool)
        .await
        .unwrap();
    let logical = json!({
        "from_address": "forge@example.com",
        "invitation_ttl_hours": 72,
        "transport": {
            "kind": "smtp", "host": "smtp.example.com", "tls": "starttls",
            "username": "forge", "password": "smtp-secret-1",
        },
    });

    let row = secret_dao::store_email_settings(&pool, &envelope, true, &logical)
        .await
        .unwrap();
    assert!(row.config["transport"].get("password").is_none());
    let blob = row.secrets_enc.clone().expect("sealed");
    assert!(!String::from_utf8_lossy(&blob).contains("smtp-secret-1"));
    let opened = secret_dao::email_config(&envelope, &row).await.unwrap();
    assert_eq!(opened, logical);

    // Bound to the host (and username): a row repointed outside the API no
    // longer decrypts, so the password never goes to the other server.
    sqlx::query(
        "UPDATE email_settings SET config = jsonb_set(config, '{transport,host}', '\"evil.example\"')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let moved = email_settings_dao::get(&pool).await.unwrap().unwrap();
    assert!(secret_dao::email_config(&envelope, &moved).await.is_err());
    sqlx::query("UPDATE email_settings SET config = $1")
        .bind(&row.config)
        .execute(&pool)
        .await
        .unwrap();

    // Its DEK stays while the secret is sealed under it; the sweep re-seals
    // it under the active DEK, and then the old one goes.
    envelope.rotate_dek().await.unwrap();
    secret_dao::revoke_unreferenced_deks(&pool, &envelope)
        .await
        .unwrap();
    let current = email_settings_dao::get(&pool).await.unwrap().unwrap();
    assert_eq!(
        secret_dao::email_config(&envelope, &current).await.unwrap(),
        logical
    );
    assert_eq!(
        secret_dao::reseal_email_secrets(&pool, &envelope)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        secret_dao::reseal_email_secrets(&pool, &envelope)
            .await
            .unwrap(),
        0,
        "converged"
    );
    let resealed = email_settings_dao::get(&pool).await.unwrap().unwrap();
    assert_ne!(resealed.secrets_enc, current.secrets_enc);
    assert!(
        secret_dao::revoke_unreferenced_deks(&pool, &envelope)
            .await
            .unwrap()
            >= 1
    );
    assert_eq!(
        secret_dao::email_config(&envelope, &resealed)
            .await
            .unwrap(),
        logical
    );

    // A transport without a secret seals nothing.
    let edited = json!({
        "from_address": "noreply@example.com",
        "invitation_ttl_hours": 24,
        "transport": {"kind": "smtp", "host": "localhost", "tls": "none"},
    });
    let relay = secret_dao::store_email_settings(&pool, &envelope, true, &edited)
        .await
        .unwrap();
    assert!(relay.secrets_enc.is_none());
    assert_eq!(relay.config, edited);

    sqlx::query("DELETE FROM email_settings")
        .execute(&pool)
        .await
        .unwrap();
}

/// #320: a Microsoft Graph app's client secret is sealed like the SMTP
/// password, bound to the tenant and the client id: a row repointed to
/// another tenant or app outside the API no longer decrypts.
#[tokio::test]
async fn the_graph_client_secret_is_sealed_and_bound_to_the_app() {
    use forge_db::email_settings_dao;
    use serde_json::json;

    let _serial = TABLE_WIDE.lock().await;
    let pool = pool().await;
    let envelope = envelope_with_scope(&pool, &format!("graph-{}", uuid::Uuid::new_v4()));
    envelope.ensure_active_keys().await.unwrap();
    sqlx::query("DELETE FROM email_settings")
        .execute(&pool)
        .await
        .unwrap();
    let logical = json!({
        "from_address": "forge@contoso.com",
        "invitation_ttl_hours": 72,
        "transport": {
            "kind": "microsoft_graph",
            "tenant_id": "contoso.onmicrosoft.com",
            "client_id": "00000000-1111-2222-3333-444444444444",
            "client_authentication": "client_secret",
            "client_secret": "graph-secret-1",
        },
    });

    let row = secret_dao::store_email_settings(&pool, &envelope, true, &logical)
        .await
        .unwrap();
    assert!(row.config["transport"].get("client_secret").is_none());
    let blob = row.secrets_enc.clone().expect("sealed");
    assert!(!String::from_utf8_lossy(&blob).contains("graph-secret-1"));
    assert_eq!(
        secret_dao::email_config(&envelope, &row).await.unwrap(),
        logical
    );

    for (field, value) in [
        ("tenant_id", "fabrikam.onmicrosoft.com"),
        ("client_id", "55555555-1111-2222-3333-444444444444"),
    ] {
        sqlx::query("UPDATE email_settings SET config = jsonb_set(config, $1, $2)")
            .bind(vec!["transport", field])
            .bind(json!(value))
            .execute(&pool)
            .await
            .unwrap();
        let moved = email_settings_dao::get(&pool).await.unwrap().unwrap();
        assert!(
            secret_dao::email_config(&envelope, &moved).await.is_err(),
            "{field}"
        );
        sqlx::query("UPDATE email_settings SET config = $1")
            .bind(&row.config)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM email_settings")
        .execute(&pool)
        .await
        .unwrap();
}

/// The `smtp_oauth` transport's secrets (#321), the client secret, the
/// registration access token and the refresh token, are sealed, and bound to
/// the issuer, the client and the mailbox; a compare-and-set update reseals
/// them and refuses a row that changed meanwhile.
#[tokio::test]
async fn the_smtp_oauth_secrets_are_sealed_and_bound_to_the_authorization() {
    use forge_db::email_settings_dao;
    use serde_json::json;

    let _serial = TABLE_WIDE.lock().await;
    let pool = pool().await;
    let envelope = envelope_with_scope(&pool, &format!("oauth-{}", uuid::Uuid::new_v4()));
    envelope.ensure_active_keys().await.unwrap();
    sqlx::query("DELETE FROM email_settings")
        .execute(&pool)
        .await
        .unwrap();
    let secrets = ["client-s3cret", "reg-token-1", "refresh-1"];
    let logical = json!({
        "from_address": "forge@example.com",
        "invitation_ttl_hours": 72,
        "transport": {
            "kind": "smtp_oauth",
            "host": "mail.example.com",
            "tls": "starttls",
            "issuer": "https://mail.example.com",
            "username": "forge@example.com",
            "client_id": "forge-client",
            "client_secret": secrets[0],
            "registration_access_token": secrets[1],
            "grant": "refresh_token",
            "refresh_token": secrets[2],
        },
    });

    let row = secret_dao::store_email_settings(&pool, &envelope, true, &logical)
        .await
        .unwrap();
    let blob = row.secrets_enc.clone().expect("sealed");
    for secret in secrets {
        assert!(!row.config.to_string().contains(secret), "{secret}");
        assert!(!String::from_utf8_lossy(&blob).contains(secret), "{secret}");
    }
    assert_eq!(
        secret_dao::email_config(&envelope, &row).await.unwrap(),
        logical
    );

    for (field, value) in [
        ("issuer", "https://evil.example"),
        ("client_id", "other-client"),
        ("username", "other@example.com"),
    ] {
        sqlx::query("UPDATE email_settings SET config = jsonb_set(config, $1, $2)")
            .bind(vec!["transport", field])
            .bind(json!(value))
            .execute(&pool)
            .await
            .unwrap();
        let moved = email_settings_dao::get(&pool).await.unwrap().unwrap();
        assert!(
            secret_dao::email_config(&envelope, &moved).await.is_err(),
            "{field}"
        );
        sqlx::query("UPDATE email_settings SET config = $1")
            .bind(&row.config)
            .execute(&pool)
            .await
            .unwrap();
    }

    // A rotated refresh token, stored over the row as read.
    let row = email_settings_dao::get(&pool).await.unwrap().unwrap();
    let mut rotated = logical.clone();
    rotated["transport"]["refresh_token"] = json!("refresh-2");
    let updated = secret_dao::update_email_settings(&pool, &envelope, &row, &rotated)
        .await
        .unwrap()
        .expect("unchanged row");
    assert_eq!(
        secret_dao::email_config(&envelope, &updated).await.unwrap(),
        rotated
    );
    // The row as read before is stale now.
    assert!(
        secret_dao::update_email_settings(&pool, &envelope, &row, &logical)
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("DELETE FROM email_settings")
        .execute(&pool)
        .await
        .unwrap();
}
