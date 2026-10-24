//! Importing a legacy `[auth.upstream_basic]` or `[oidc]` block into its
//! `auth_realm` row ("config as seed"): drift detection whose marker holds
//! nothing derived from the realm's secrets, and an `oidc` realm's
//! `auto_provision`, which no block sets.
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

/// A configuration with `blocks` appended.
fn load(blocks: &str) -> Config {
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

async fn seed(pool: &PgPool, config: &Config) {
    forge_server::app::ensure_auth_realms(config, pool, None)
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
    let config = forge_db::secret_dao::realm_config(None, &realm)
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
    let config = forge_db::secret_dao::realm_config(None, &realm)
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
