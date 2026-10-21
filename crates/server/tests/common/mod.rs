//! Shared test harness for `forge-server` integration tests.
//!
//! Boots a Postgres + versitygw container per test binary (leaked so their
//! async `Drop` never runs on a torn-down runtime), migrates a fresh pool, and
//! assembles a real [`AppState`] + axum app served on an ephemeral port. Tests
//! drive it over HTTP with `reqwest`, exactly as a NuGet client would.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use forge_cache::Cache;
use forge_server::app::{build_router, ensure_bootstrap_admin, principal_layer};
use forge_server::config::Config;
use forge_server::state::AppState;
use forge_server::workers::{self, WorkerHandles};
use forge_storage::{BlobStore, S3Config};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::Mutex;

static PG_ENDPOINT: OnceLock<String> = OnceLock::new();
static S3_ENDPOINT: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());
static MIGRATED: OnceLock<()> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(0);

const S3_ACCESS: &str = "test";
const S3_SECRET: &str = "test";
const S3_BUCKET: &str = "forge-test";
const S3_PORT: u16 = 7070;

/// A process-unique suffix for collision-free names.
pub fn unique() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

async fn pg_endpoint() -> &'static str {
    if let Some(e) = PG_ENDPOINT.get() {
        return e;
    }
    let _guard = INIT_LOCK.lock().await;
    if let Some(e) = PG_ENDPOINT.get() {
        return e;
    }
    let container = Postgres::default()
        .with_db_name("forge")
        .with_user("forge")
        .with_password("forge")
        .with_tag("17")
        .start()
        .await
        .expect("start postgres testcontainer (is Docker running?)");
    let host = container.get_host().await.expect("host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");
    let _: &'static ContainerAsync<Postgres> = Box::leak(Box::new(container));
    PG_ENDPOINT.set(format!("{host}:{port}")).ok();
    PG_ENDPOINT.get().unwrap()
}

async fn s3_endpoint() -> &'static str {
    if let Some(e) = S3_ENDPOINT.get() {
        return e;
    }
    let _guard = INIT_LOCK.lock().await;
    if let Some(e) = S3_ENDPOINT.get() {
        return e;
    }
    // Docker-less environments point at an already-running gateway.
    if let Ok(endpoint) = std::env::var("FORGE_TEST_S3_ENDPOINT") {
        S3_ENDPOINT.set(endpoint).ok();
        return S3_ENDPOINT.get().unwrap();
    }
    let container = GenericImage::new("versity/versitygw", "v1.4.1")
        .with_exposed_port(S3_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("listening on"))
        .with_cmd([
            "--port", ":7070", "--access", S3_ACCESS, "--secret", S3_SECRET, "posix", "/tmp",
        ])
        .start()
        .await
        .expect("start versitygw testcontainer (is Docker running?)");
    let host = container.get_host().await.expect("host");
    let port = container
        .get_host_port_ipv4(S3_PORT)
        .await
        .expect("mapped port");
    let _: &'static ContainerAsync<GenericImage> = Box::leak(Box::new(container));
    S3_ENDPOINT.set(format!("http://{host}:{port}")).ok();
    S3_ENDPOINT.get().unwrap()
}

/// A fresh migrated pool over the shared Postgres container — or over an
/// external Postgres when `FORGE_TEST_DATABASE_URL` is set (no Docker).
pub async fn pool() -> PgPool {
    let url = match std::env::var("FORGE_TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            let endpoint = pg_endpoint().await;
            format!("postgres://forge:forge@{endpoint}/forge")
        }
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect");
    if MIGRATED.get().is_none() {
        let _guard = INIT_LOCK.lock().await;
        if MIGRATED.get().is_none() {
            forge_db::migrate(&pool).await.expect("migrate");
            MIGRATED.set(()).ok();
        }
    }
    pool
}

/// A migrated pool over a fresh, uniquely named database on the same Postgres
/// server, for tests that change install-wide state (seeded realms, settings)
/// the rest of the binary must not see.
pub async fn fresh_pool() -> PgPool {
    let admin = pool().await;
    let name = format!("forge_fresh_{}_{}", std::process::id(), unique());
    // The name is generated here, never user input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(r#"CREATE DATABASE "{name}""#)))
        .execute(&admin)
        .await
        .expect("create database");
    let shared = match std::env::var("FORGE_TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => format!("postgres://forge:forge@{}/forge", pg_endpoint().await),
    };
    let (server, _db) = shared.rsplit_once('/').expect("database url with a path");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&format!("{server}/{name}"))
        .await
        .expect("connect fresh database");
    forge_db::migrate(&pool).await.expect("migrate");
    pool
}

async fn blob_store() -> BlobStore {
    let endpoint = s3_endpoint().await.to_string();
    let store = BlobStore::new(S3Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: S3_BUCKET.into(),
        access_key: S3_ACCESS.into(),
        secret_key: S3_SECRET.into(),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: Default::default(),
    });
    let mut last = None;
    for _ in 0..30 {
        match store.ensure_bucket().await {
            Ok(()) => return store,
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
    panic!("versitygw never became ready: {last:?}");
}

/// A built TOML config string for the harness, parameterized by the bootstrap
/// admin credentials and anonymous mode.
fn config_toml(db_url: &str, s3_endpoint: &str, opts: &ServerOpts) -> String {
    let admin = opts
        .bootstrap_admin
        .as_ref()
        .map(|(u, p)| (u.as_str(), p.as_str()));
    let anon = &opts.anonymous_mode;
    let web_assets_dir = opts.web_assets_dir.as_deref();
    let oidc_block = opts.oidc_block.as_deref();
    let crypto_block = opts.crypto_block.as_deref();
    let plugins_block = opts.plugins_block.as_deref();
    let public_base_url = opts
        .public_base_url
        .as_deref()
        .unwrap_or("http://test.local");
    let server_extra = opts.server_extra.as_deref().unwrap_or("");
    let bootstrap = match admin {
        Some((u, p)) => format!("[auth.bootstrap_admin]\nusername = \"{u}\"\npassword = \"{p}\"\n"),
        None => String::new(),
    };
    // Default to a disabled web UI in tests so a missing `web/dist` never
    // affects API behaviour; tests that exercise SPA serving pass an explicit
    // assets dir.
    let web = match web_assets_dir {
        Some(dir) => format!("[web]\nenabled = true\nassets_dir = {dir:?}\n"),
        None => "[web]\nenabled = false\n".to_string(),
    };
    format!(
        r#"
[server]
bind = "127.0.0.1:0"
public_base_url = "{public_base_url}"
{server_extra}

[database]
url = "{db_url}"

[s3]
endpoint = "{s3_endpoint}"
bucket = "{bucket}"
access_key = "{access}"
secret_key = "{secret}"
force_path_style = true

[auth]
anonymous_mode = "{anon}"
allow_password_basic = true
{bootstrap}

[cache]
l1_max_capacity = 1000
default_ttl_seconds = 5

[outbox]
batch_size = 50
grace_seconds = 0
poll_interval_seconds = 1

{web}
{oidc}
{crypto}
{plugins}
"#,
        bucket = S3_BUCKET,
        access = S3_ACCESS,
        secret = S3_SECRET,
        oidc = oidc_block.unwrap_or(""),
        crypto = crypto_block.unwrap_or(""),
        plugins = plugins_block.unwrap_or(""),
    )
}

/// A running test server.
pub struct TestServer {
    pub base_url: String,
    pub pool: PgPool,
    pub state: AppState,
    pub admin_user: Option<String>,
    pub admin_pass: Option<String>,
    /// An admin-scoped API token of the bootstrap admin (`{"actions":
    /// ["admin"]}`): the admin API refuses a password sent over Basic, so
    /// [`TestServer::admin_basic`] carries this in the password field.
    pub admin_scoped_token: Option<String>,
    handle: tokio::task::JoinHandle<()>,
    workers: Option<WorkerHandles>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(w) = &self.workers {
            w.abort();
        }
        self.handle.abort();
    }
}

/// Options for spinning up a test server.
pub struct ServerOpts {
    pub bootstrap_admin: Option<(String, String)>,
    pub anonymous_mode: String,
    pub spawn_workers: bool,
    /// When set, the static SPA is served from this directory; otherwise the
    /// web UI is disabled for the test.
    pub web_assets_dir: Option<String>,
    /// When set, this raw TOML is appended as the `[oidc]` section so the server
    /// builds an `OidcRuntime` + mounts the `/auth/oidc/*` routes (slice 12.2).
    pub oidc_block: Option<String>,
    /// When set, this raw TOML is appended as the `[crypto]` section so the
    /// server builds the secret-encryption envelope service (slice 12.5). The
    /// caller is responsible for exporting the root-key env var it references.
    pub crypto_block: Option<String>,
    /// `server.public_base_url` (default `http://test.local`); an `https://`
    /// URL makes the server issue `Secure` (`__Host-`) cookies.
    pub public_base_url: Option<String>,
    /// Extra raw TOML lines for the `[server]` section (e.g. timeouts).
    pub server_extra: Option<String>,
    /// When set, this raw TOML is appended last (the `[plugins]` section, or
    /// any other), and the format plugins it lists are loaded.
    pub plugins_block: Option<String>,
    /// Format plugins installed next to the built-in ones, as if built in.
    pub extra_plugins: Vec<std::sync::Arc<forge_plugin::Plugin>>,
}

impl Default for ServerOpts {
    fn default() -> Self {
        ServerOpts {
            bootstrap_admin: Some(("admin".into(), "adminpw".into())),
            anonymous_mode: "off".into(),
            spawn_workers: false,
            web_assets_dir: None,
            oidc_block: None,
            crypto_block: None,
            public_base_url: None,
            server_extra: None,
            plugins_block: None,
            extra_plugins: Vec::new(),
        }
    }
}

/// Start a server with the given options against the shared containers, sharing
/// `pool` (so a caller can run two instances against one DB for scale-out).
pub async fn start_with(pool: PgPool, opts: ServerOpts) -> TestServer {
    let db_url = match std::env::var("FORGE_TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            let endpoint = pg_endpoint().await;
            format!("postgres://forge:forge@{endpoint}/forge")
        }
    };
    let store = blob_store().await;
    let s3 = s3_endpoint().await;

    let toml = config_toml(&db_url, s3, &opts);
    use figment::providers::Format as _;
    let config = Config::from_figment(
        figment::Figment::new().merge(figment::providers::Toml::string(&toml)),
    )
    .expect("valid config");
    // As in `main`: the local blob cache in front of S3 when configured.
    let store = match config.blob_cache() {
        Some(cache) => {
            store.with_cache(forge_storage::BlobCache::open(cache).expect("open the blob cache"))
        }
        None => store,
    };

    ensure_bootstrap_admin(&config, &pool)
        .await
        .expect("bootstrap admin");

    // §12.5: build + bootstrap the envelope service when the test enabled the
    // [crypto] block (no-op otherwise).
    let envelope =
        forge_server::crypto::build_envelope(&config, &pool).expect("build envelope service");
    if let (Some(env), Some(crypto_cfg)) = (&envelope, config.crypto.as_ref()) {
        forge_server::crypto::bootstrap(&pool, env, crypto_cfg)
            .await
            .expect("bootstrap secret encryption");
    }

    // 12.7: import any [oidc]/[auth.upstream_basic] block into auth_realm rows
    // (drift-detected) so the realm-driven runtime sees them.
    forge_server::app::ensure_auth_realms(&config, &pool, envelope.as_deref())
        .await
        .expect("seed auth realms");

    let cache = Cache::l1_only(config.cache.l1_max_capacity);
    let mut plugins = forge_server::plugins::load(&config.plugins).expect("load format plugins");
    plugins.extend(opts.extra_plugins.iter().cloned());
    let registry_keys =
        forge_server::registry::load_token_keys(&config, &pool, envelope.as_deref())
            .await
            .expect("registry token key");
    let state = AppState::new(pool.clone(), store, cache, config)
        .with_envelope(envelope)
        .with_registry_keys(registry_keys)
        .with_plugins(plugins)
        .expect("install format plugins");
    let layer = principal_layer(&state).expect("principal layer");

    let workers = if opts.spawn_workers {
        Some(workers::spawn_all(&state))
    } else {
        None
    };

    let serve_options = forge_server::serve::ServeOptions::from_config(&state.config);
    let app = build_router(state.clone(), layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        forge_server::serve::serve(listener, app, serve_options, std::future::pending()).await;
    });

    let admin_scoped_token = match &opts.bootstrap_admin {
        Some((username, _)) => mint_admin_scoped_token(&pool, username).await,
        None => None,
    };

    TestServer {
        base_url: format!("http://{addr}"),
        pool,
        state,
        admin_user: opts.bootstrap_admin.as_ref().map(|(u, _)| u.clone()),
        admin_pass: opts.bootstrap_admin.as_ref().map(|(_, p)| p.clone()),
        admin_scoped_token,
        handle,
        workers,
    }
}

/// Mint (directly in the database) an admin-scoped API token for `username`;
/// `None` when no such account exists (a bootstrap admin that was not created).
pub async fn mint_admin_scoped_token(pool: &PgPool, username: &str) -> Option<String> {
    let user = forge_db::user_dao::find_user_by_username(pool, username)
        .await
        .expect("admin lookup")?;
    let secret = forge_core::auth::generate_token_secret();
    let token = forge_db::token_dao::insert_token(
        pool,
        forge_db::token_dao::NewToken {
            user_id: user.id,
            name: "test-admin".into(),
            token_hash: forge_core::auth::hash_token(&secret),
            expires_at: None,
            minted_with_forwarded_credential: false,
        },
    )
    .await
    .expect("insert admin token");
    forge_db::token_dao::set_token_scope(
        pool,
        token.id,
        Some(&serde_json::json!({ "actions": ["admin"] })),
    )
    .await
    .expect("scope admin token");
    Some(secret)
}

/// Start a server with a **unique** bootstrap admin (so parallel tests sharing
/// the one Postgres container don't collide on the `admin` username), anonymous
/// off, no workers.
pub async fn start() -> TestServer {
    let admin = format!("admin{}", unique());
    start_with(
        pool().await,
        ServerOpts {
            bootstrap_admin: Some((admin, "adminpw".into())),
            ..Default::default()
        },
    )
    .await
}

/// A browser session for tests: the cookie pair plus its CSRF token.
#[derive(Clone, Debug)]
pub struct BrowserSession {
    /// `forge_session=<secret>`.
    pub cookie: String,
    /// The session's double-submit CSRF token.
    pub csrf: String,
}

impl BrowserSession {
    /// Attach the session cookie and CSRF header to a request.
    pub fn apply(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.header("cookie", &self.cookie)
            .header("x-csrf-token", &self.csrf)
    }
}

impl TestServer {
    /// Sign `username` in through `/auth/login` (password realms).
    pub async fn login(&self, username: &str, password: &str) -> BrowserSession {
        let resp = self
            .client()
            .post(format!("{}/auth/login", self.base_url))
            .json(&serde_json::json!({"username": username, "password": password}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "login of {username}");
        let cookie = resp
            .headers()
            .get("set-cookie")
            .expect("session cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body: serde_json::Value = resp.json().await.unwrap();
        BrowserSession {
            cookie,
            csrf: body["csrf_token"].as_str().expect("csrf").to_string(),
        }
    }

    /// Mint a browser session for `user_id` directly (for accounts without a
    /// local password, e.g. credential-forwarding users).
    pub async fn session_for(&self, user_id: i64) -> BrowserSession {
        let issued = self
            .state
            .sessions
            .create_for_user(user_id, None, None)
            .await
            .expect("create session");
        BrowserSession {
            cookie: format!(
                "{}={}",
                forge_core::auth::SESSION_COOKIE,
                issued.cookie_secret
            ),
            csrf: issued.session.csrf_secret,
        }
    }

    /// A reqwest client (no default auth).
    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    /// Basic credentials for the bootstrap admin: its username and an
    /// **admin-scoped token** in the password field (the admin API refuses a
    /// password sent over Basic). For the real password use
    /// [`TestServer::admin_password_basic`].
    pub fn admin_basic(&self) -> (String, String) {
        (
            self.admin_user.clone().expect("admin user"),
            self.admin_scoped_token.clone().expect("admin token"),
        )
    }

    /// The bootstrap admin's username and real password.
    pub fn admin_password_basic(&self) -> (String, String) {
        (
            self.admin_user.clone().expect("admin user"),
            self.admin_pass.clone().expect("admin pass"),
        )
    }

    /// Issue an API token for the bootstrap admin and return its plaintext
    /// secret (used for `X-NuGet-ApiKey` on publish endpoints).
    pub async fn admin_token(&self) -> String {
        let (u, p) = self.admin_basic();
        let client = self.client();
        let users: serde_json::Value = client
            .get(format!("{}/admin/users", self.base_url))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let admin_id = users
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["username"] == serde_json::json!(u))
            .expect("admin user present")["id"]
            .as_i64()
            .unwrap();
        let body: serde_json::Value = client
            .post(format!("{}/admin/users/{admin_id}/tokens", self.base_url))
            .basic_auth(&u, Some(&p))
            .json(&serde_json::json!({"name": "test"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["token"].as_str().expect("plaintext token").to_string()
    }
}

/// Build a minimal valid `.nupkg` (a zip with `[Content_Types].xml` + a
/// `{id}.nuspec`) that parses to `id@version`.
pub fn make_nupkg(id: &str, version: &str) -> Vec<u8> {
    make_nupkg_with_payload(id, version, 0)
}

/// Like [`make_nupkg`], plus an incompressible `lib/net8.0/payload.bin` of
/// `payload_len` bytes stored uncompressed — for size-limit tests.
pub fn make_nupkg_with_payload(id: &str, version: &str, payload_len: usize) -> Vec<u8> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    let nuspec = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <authors>test</authors>
    <description>generated test package</description>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="[13.0.1, )" />
      </group>
    </dependencies>
  </metadata>
</package>"#
    );
    let content_types = r#"<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="nuspec" ContentType="application/octet" /></Types>"#;

    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    zw.start_file("[Content_Types].xml", opts).unwrap();
    zw.write_all(content_types.as_bytes()).unwrap();
    zw.start_file(format!("{id}.nuspec"), opts).unwrap();
    zw.write_all(nuspec.as_bytes()).unwrap();
    if payload_len > 0 {
        let stored = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .large_file(payload_len as u64 >= u32::MAX as u64);
        zw.start_file("lib/net8.0/payload.bin", stored).unwrap();
        // xorshift: cheap, deterministic, incompressible enough.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut buf = Vec::with_capacity(payload_len);
        while buf.len() < payload_len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            buf.extend_from_slice(&x.to_le_bytes());
        }
        buf.truncate(payload_len);
        zw.write_all(&buf).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

/// Wait until a database session is blocked on a lock while running a
/// statement matching one of the SQL `LIKE` `patterns` (a request that
/// reached the row another transaction holds). Only sessions on `pool`'s own
/// database count, so a test on a fresh database never sees another test's
/// waits. Panics after 10 s.
pub async fn wait_for_lock_wait(pool: &PgPool, patterns: &[&str]) {
    let patterns: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
    for _ in 0..500 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE wait_event_type = 'Lock' AND query LIKE ANY($1) \
             AND datname = current_database()",
        )
        .bind(&patterns)
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no statement like {patterns:?} waited for a lock");
}
