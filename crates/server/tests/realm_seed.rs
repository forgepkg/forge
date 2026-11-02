//! Importing a legacy `[auth.upstream_basic]` or `[oidc]` block into its
//! `auth_realm` row ("config as seed"): drift detection whose marker holds
//! nothing derived from the realm's secrets, an `oidc` realm's
//! `auto_provision`, which no block sets, imports that race a realm create or
//! each other, and imports whose slot in the try-order another realm holds.
//!
//! Every test seeds into its own database: a seeded, enabled
//! credential-forwarding realm in the shared one would change how every other
//! test's password logins are answered.

mod common;

use figment::providers::Format as _;
use forge_server::auth::{KIND_CRED_FORWARD, KIND_OIDC};
use forge_server::config::Config;
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;

const MARKER_KEY: &str = "auth_realm_seed_credential_forwarding";
const OIDC_MARKER_KEY: &str = "auth_realm_seed_oidc";
const REALMS_SEEDED_KEY: &str = "auth_realms_seeded";

/// A configuration with `blocks` appended.
fn load(blocks: &str) -> Config {
    let root_key_env = common::ensure_test_root_key();
    let toml = format!(
        r#"
        [server]
        bind = "127.0.0.1:0"
        public_base_url = "http://test.local"

        [database]
        url = "postgres://forge:forge@localhost/forge"

        [s3]
        endpoint = "http://localhost:7070"
        bucket = "forge"
        access_key = "test"
        secret_key = "test"

        [crypto.root]
        provider = "env"
        root_key_env = "{root_key_env}"

        {blocks}
        "#
    );
    Config::from_figment(figment::Figment::new().merge(figment::providers::Toml::string(&toml)))
        .expect("valid config")
}

fn config(pepper: &str, request_timeout_ms: u64) -> Config {
    load(&format!(
        r#"
        [auth]
        providers = ["local-password", "upstream-basic"]

        [auth.upstream_basic]
        url = "https://nexus.invalid/service/rest/v1/status"
        request_timeout_ms = {request_timeout_ms}

        [auth.upstream_basic.cache]
        key_pepper = "{pepper}"
        "#
    ))
}

fn oidc_config(admin_claim: &str) -> Config {
    load(&format!(
        r#"
        [oidc]
        issuer = "https://idp.invalid/v2.0"
        client_id = "client-abc"
        client_secret = "shh-secret"
        redirect_url = "http://test.local/auth/oidc/callback"
        admin_claim = "{admin_claim}"
        "#
    ))
}

/// The envelope service the realm's secrets are sealed with, its keys
/// created in `pool`.
async fn envelope(pool: &PgPool) -> std::sync::Arc<forge_crypto::service::EnvelopeService> {
    let config = config("pepper-one", 5000);
    let envelope = forge_server::crypto::build_envelope(&config, pool).expect("envelope service");
    forge_server::crypto::bootstrap(pool, &envelope, &config.crypto)
        .await
        .expect("bootstrap secret encryption");
    envelope
}

async fn seed(pool: &PgPool, config: &Config) {
    let envelope = envelope(pool).await;
    forge_server::app::ensure_auth_realms(config, pool, &envelope)
        .await
        .expect("seed auth realms");
}

async fn marker(pool: &PgPool) -> Option<String> {
    forge_db::authz_dao::get_setting(pool, MARKER_KEY)
        .await
        .unwrap()
}

/// The seeded row's logical config (secrets merged in).
async fn seeded_config(pool: &PgPool) -> (i64, JsonValue) {
    let realm = forge_db::auth_realm_dao::find_realm_by_name(pool, "upstream-basic")
        .await
        .unwrap()
        .expect("seeded realm");
    assert_eq!(realm.kind, KIND_CRED_FORWARD);
    let envelope = envelope(pool).await;
    let config = forge_db::secret_dao::realm_config(&envelope, &realm)
        .await
        .unwrap();
    (realm.id, config)
}

/// The seeded `oidc` realm and its logical config.
async fn seeded_oidc(pool: &PgPool) -> (forge_db::model::AuthRealm, JsonValue) {
    let realm = forge_db::auth_realm_dao::find_realm_by_name(pool, "oidc")
        .await
        .unwrap()
        .expect("seeded realm");
    assert_eq!(realm.kind, KIND_OIDC);
    let envelope = envelope(pool).await;
    let config = forge_db::secret_dao::realm_config(&envelope, &realm)
        .await
        .unwrap();
    (realm, config)
}

#[tokio::test]
async fn seed_marker_holds_no_secret_and_tracks_the_block() {
    let pool = common::fresh_pool().await;

    seed(&pool, &config("pepper-one", 5000)).await;
    let first = marker(&pool).await.expect("marker recorded");
    assert!(first.starts_with("v2:"), "{first}");
    let (_, stored) = seeded_config(&pool).await;
    assert_eq!(stored["key_pepper"], "pepper-one");
    assert_ne!(
        first.trim_start_matches("v2:"),
        forge_core::auth::token::hash_token(&stored.to_string()),
        "the marker must not hash the secret"
    );

    // A new pepper in the block re-applies (the row is unmodified), and the
    // marker does not change with it: it is independent of the secret.
    seed(&pool, &config("pepper-two", 5000)).await;
    let (_, stored) = seeded_config(&pool).await;
    assert_eq!(stored["key_pepper"], "pepper-two");
    assert_eq!(marker(&pool).await.as_deref(), Some(first.as_str()));

    // A changed non-secret field re-applies too and moves the marker.
    seed(&pool, &config("pepper-two", 7000)).await;
    let (_, stored) = seeded_config(&pool).await;
    assert_eq!(stored["request_timeout_ms"], 7000);
    assert_ne!(marker(&pool).await.as_deref(), Some(first.as_str()));
}

/// A secret changed through the admin API is not overwritten by the block on
/// the next boot, although the marker no longer covers secrets.
#[tokio::test]
async fn admin_edit_of_a_seeded_secret_survives_the_next_boot() {
    let pool = common::fresh_pool().await;
    seed(&pool, &config("pepper-one", 5000)).await;
    let (id, _) = seeded_config(&pool).await;

    let srv = common::start_with(pool.clone(), common::ServerOpts::default()).await;
    let (admin, password) = srv.admin_basic();
    let view: JsonValue = srv
        .client()
        .get(format!("{}/admin/realms/{id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut edited = view["config"].clone();
    edited["key_pepper"] = json!("admin-pepper");
    let resp = srv
        .client()
        .patch(format!("{}/admin/realms/{id}", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({ "config": edited }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    assert_eq!(marker(&pool).await, None, "the API edit drops the marker");

    // The block changes too; the operator's edit still wins.
    seed(&pool, &config("pepper-two", 7000)).await;
    let (_, stored) = seeded_config(&pool).await;
    assert_eq!(stored["key_pepper"], "admin-pepper");
    assert_eq!(stored["request_timeout_ms"], 5000);
}

/// A marker written by a pre-release build (sha256 over the whole config,
/// secret included, without the `v2:` prefix) counts as an edited row's,
/// even for a row unmodified since that seed: it is dropped, and the block
/// is not applied.
#[tokio::test]
async fn a_legacy_marker_is_dropped() {
    let pool = common::fresh_pool().await;
    seed(&pool, &config("pepper-one", 5000)).await;
    let (_, stored) = seeded_config(&pool).await;
    let legacy = forge_core::auth::token::hash_token(&stored.to_string());
    forge_db::authz_dao::set_setting(&pool, MARKER_KEY, &legacy)
        .await
        .unwrap();

    seed(&pool, &config("pepper-one", 6000)).await;
    let (_, stored) = seeded_config(&pool).await;
    assert_eq!(stored["request_timeout_ms"], 5000);
    assert_eq!(marker(&pool).await, None);
}

/// #313: the `[oidc]` block does not set `auto_provision`. The realm it
/// creates has it on; a block re-applied to a realm that has it off, as a
/// 1.x build seeded from `auto_provision = false`, keeps it off.
#[tokio::test]
async fn an_oidc_seed_leaves_auto_provision_to_the_realm() {
    let pool = common::fresh_pool().await;

    seed(&pool, &oidc_config("roles")).await;
    let (realm, stored) = seeded_oidc(&pool).await;
    assert_eq!(stored["auto_provision"], true, "on, the realm's default");

    // What a 1.x build seeded from `auto_provision = false`: the realm with
    // it off, and the marker of that config (its non-secret fields' hash).
    let mut seeded_by_1x = stored.clone();
    seeded_by_1x["auto_provision"] = json!(false);
    forge_db::auth_realm_dao::update_realm(
        &pool,
        realm.id,
        forge_db::auth_realm_dao::AuthRealmUpdate {
            name: realm.name.clone(),
            enabled: realm.enabled,
            priority: realm.priority,
            config: seeded_by_1x.clone(),
        },
    )
    .await
    .unwrap();
    let mut public = seeded_by_1x.clone();
    public.as_object_mut().unwrap().remove("client_secret");
    let marker_1x = format!(
        "v2:{}",
        forge_core::auth::token::hash_token(&public.to_string())
    );
    forge_db::authz_dao::set_setting(&pool, OIDC_MARKER_KEY, &marker_1x)
        .await
        .unwrap();

    // The same block without the key changes nothing.
    seed(&pool, &oidc_config("roles")).await;
    let (_, stored) = seeded_oidc(&pool).await;
    assert_eq!(stored, seeded_by_1x);
    assert_eq!(
        forge_db::authz_dao::get_setting(&pool, OIDC_MARKER_KEY)
            .await
            .unwrap()
            .as_deref(),
        Some(marker_1x.as_str())
    );

    // A changed field re-applies, under the same drift rules, and leaves
    // `auto_provision` as the realm has it.
    seed(&pool, &oidc_config("groups")).await;
    let (_, stored) = seeded_oidc(&pool).await;
    assert_eq!(stored["admin_claim"], "groups");
    assert_eq!(stored["auto_provision"], false);
    let marker = forge_db::authz_dao::get_setting(&pool, OIDC_MARKER_KEY)
        .await
        .unwrap()
        .expect("marker kept");
    assert_ne!(marker, marker_1x, "the re-apply moved the marker");

    // And it keeps re-applying: the new marker covers the kept value.
    seed(&pool, &oidc_config("roles")).await;
    let (_, stored) = seeded_oidc(&pool).await;
    assert_eq!(stored["admin_claim"], "roles");
    assert_eq!(stored["auto_provision"], false);
}

/// Start the import of `config`'s blocks, as an instance does at boot, in the
/// background.
async fn spawn_seed(pool: &PgPool, config: Config) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let envelope = envelope(pool).await;
    let pool = pool.clone();
    tokio::spawn(
        async move { forge_server::app::ensure_auth_realms(&config, &pool, &envelope).await },
    )
}

/// A realm insert that has not committed yet, under the lock a realm create
/// takes: `kind` and `name` go after the last realm.
async fn uncommitted_realm(
    pool: &PgPool,
    kind: &str,
    name: &str,
    config: JsonValue,
) -> (sqlx::Transaction<'static, sqlx::Postgres>, i32) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_realm IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .unwrap();
    let priority: i32 = sqlx::query_scalar(
        "INSERT INTO auth_realm (kind, name, enabled, priority, config) \
         SELECT $1, $2, false, max(priority) + 10, $3 FROM auth_realm \
         RETURNING priority",
    )
    .bind(kind)
    .bind(name)
    .bind(config)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    (tx, priority)
}

/// The import of a block, once it read that its realm is missing, waits for
/// the realm table: on the lock appends take, or on the insert's.
async fn wait_for_the_import(pool: &PgPool) {
    common::wait_for_lock_wait(
        pool,
        &["%LOCK TABLE auth_realm%", "%INSERT INTO auth_realm%"],
    )
    .await;
}

/// A realm created through the admin API while an instance booted could take
/// the priority the import of an `[oidc]` block had read for its realm, and
/// the import then failed on the order's unique key: the instance did not
/// start. The import now waits for the create and appends after it.
#[tokio::test]
async fn an_import_racing_a_realm_create_appends_after_it() {
    let pool = common::fresh_pool().await;
    let (create, created) = uncommitted_realm(
        &pool,
        KIND_CRED_FORWARD,
        "created",
        json!({"url": "https://nexus.invalid/status"}),
    )
    .await;
    let import = spawn_seed(&pool, oidc_config("roles")).await;
    wait_for_the_import(&pool).await;
    create.commit().await.unwrap();

    import.await.unwrap().expect("the import");
    let (realm, stored) = seeded_oidc(&pool).await;
    assert!(
        realm.priority > created,
        "{} after {created}",
        realm.priority
    );
    assert_eq!(stored["client_secret"], "shh-secret");
}

/// Instances that boot at once all import a block whose realm is missing. The
/// realm went in once, and the others failed on its name or its priority
/// (their unique keys) and did not start. An import now waits for the one
/// before it and then leaves the realm it inserted alone.
#[tokio::test]
async fn instances_importing_a_block_at_once_insert_its_realm_once() {
    let pool = common::fresh_pool().await;
    let (other, _) = uncommitted_realm(
        &pool,
        KIND_CRED_FORWARD,
        "upstream-basic",
        json!({"url": "https://nexus.invalid/status"}),
    )
    .await;
    let import = spawn_seed(&pool, config("pepper-one", 5000)).await;
    wait_for_the_import(&pool).await;
    other.commit().await.unwrap();

    import.await.unwrap().expect("the import");
    let realms: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_realm WHERE kind = $1")
        .bind(KIND_CRED_FORWARD)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(realms, 1);
    assert_eq!(marker(&pool).await, None, "the other instance's to record");
}

/// An `[auth.upstream_basic]` block with `providers` as the configured order.
fn ordered_config(providers: &str) -> Config {
    load(&format!(
        r#"
        [auth]
        providers = {providers}

        [auth.upstream_basic]
        url = "https://nexus.invalid/service/rest/v1/status"

        [auth.upstream_basic.cache]
        key_pepper = "pepper-one"
        "#
    ))
}

async fn realm(pool: &PgPool, name: &str) -> forge_db::model::AuthRealm {
    forge_db::auth_realm_dao::find_realm_by_name(pool, name)
        .await
        .unwrap()
        .expect(name)
}

/// The `[auth.upstream_basic]` realm goes in at its slot in the configured
/// order, 20 here. A realm created through the admin API could hold it: one
/// created before the block was added, or after the seeded realm was deleted.
/// The import then failed on the order's unique key, on every boot, and the
/// instance did not start. It now goes after the last realm.
#[tokio::test]
async fn an_import_whose_slot_is_taken_goes_after_the_last_realm() {
    let pool = common::fresh_pool().await;
    let envelope = envelope(&pool).await;
    let created = forge_db::secret_dao::append_realm_with_secrets(
        &pool,
        &envelope,
        KIND_OIDC,
        "corp-sso",
        false,
        &json!({"issuer": "https://idp.invalid/v2.0", "client_id": "corp"}),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(created.priority, 20, "the block's slot");

    seed(&pool, &config("pepper-one", 5000)).await;
    let (_, stored) = seeded_config(&pool).await;
    assert_eq!(stored["key_pepper"], "pepper-one");
    let seeded = realm(&pool, "upstream-basic").await;
    assert!(
        seeded.priority > created.priority,
        "{} after {}",
        seeded.priority,
        created.priority
    );
    assert_eq!(realm(&pool, "corp-sso").await.priority, created.priority);
    assert!(marker(&pool).await.is_some());
}

/// The first import also moves the built-in `local` realm to its slot in the
/// configured order. The import repeats on every boot until one completes, and
/// a realm can hold that slot by then: here the one a block was imported into
/// before the order changed. The move failed on the order's unique key, on
/// every boot. `local` now stays where it is.
#[tokio::test]
async fn a_first_import_leaves_local_in_place_when_its_slot_is_taken() {
    let pool = common::fresh_pool().await;
    seed(
        &pool,
        &ordered_config(r#"["upstream-basic", "local-password"]"#),
    )
    .await;
    assert_eq!(realm(&pool, "local").await.priority, 20);
    assert_eq!(realm(&pool, "upstream-basic").await.priority, 10);
    // A first import that did not complete.
    forge_db::authz_dao::delete_setting(&pool, REALMS_SEEDED_KEY)
        .await
        .unwrap();

    seed(
        &pool,
        &ordered_config(r#"["local-password", "upstream-basic"]"#),
    )
    .await;
    assert_eq!(realm(&pool, "local").await.priority, 20);
    assert_eq!(realm(&pool, "upstream-basic").await.priority, 10);
    assert_eq!(
        forge_db::authz_dao::get_setting(&pool, REALMS_SEEDED_KEY)
            .await
            .unwrap()
            .as_deref(),
        Some("true"),
        "the first import completed"
    );
}
