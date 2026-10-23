//! The e2e stack harness: containers, fresh-per-test databases, and a running
//! axum server (with optional peer instances sharing the same DB + S3 + Redis).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use forge_cache::Cache;
use forge_server::app::{build_router, ensure_bootstrap_admin, principal_layer};
use forge_server::config::Config;
use forge_server::state::AppState;
use forge_server::workers::{self, WorkerHandles};
use forge_storage::{BlobStore, S3Config, S3Credentials};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::redis::{Redis, REDIS_PORT};
use tokio::sync::Mutex;

/// versitygw access key (CI-only credentials).
pub const S3_ACCESS: &str = "test";
/// versitygw secret key (CI-only credentials).
pub const S3_SECRET: &str = "test";
/// Bucket holding all blobs in tests.
pub const S3_BUCKET: &str = "forge-e2e";
const S3_PORT: u16 = 7070;

static PG_ENDPOINT: OnceLock<String> = OnceLock::new();
static S3_ENDPOINT: OnceLock<String> = OnceLock::new();
static REDIS_URL: OnceLock<String> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::const_new(());
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A process-unique suffix for collision-free names (db names, repos, …).
pub fn unique() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ── Container bootstrap (shared per process, leaked) ────────────────────────

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
        .with_name("mirror.gcr.io/library/postgres")
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

/// The shared versitygw's endpoint (booted on first use).
pub(crate) async fn shared_s3_endpoint() -> &'static str {
    s3_endpoint().await
}

async fn s3_endpoint() -> &'static str {
    if let Some(e) = S3_ENDPOINT.get() {
        return e;
    }
    let _guard = INIT_LOCK.lock().await;
    if let Some(e) = S3_ENDPOINT.get() {
        return e;
    }
    let container = GenericImage::new("mirror.gcr.io/versity/versitygw", "v1.4.1")
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

/// Boot (once) a shared Redis container and return its URL. Tests that exercise
/// the optional L2 backplane call [`StackBuilder::with_redis`].
async fn redis_url() -> &'static str {
    if let Some(u) = REDIS_URL.get() {
        return u;
    }
    let _guard = INIT_LOCK.lock().await;
    if let Some(u) = REDIS_URL.get() {
        return u;
    }
    let container = Redis::default()
        .with_name("mirror.gcr.io/library/redis")
        .start()
        .await
        .expect("start redis testcontainer (is Docker running?)");
    let host = container.get_host().await.expect("host");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("mapped port");
    let _: &'static ContainerAsync<Redis> = Box::leak(Box::new(container));
    REDIS_URL.set(format!("redis://{host}:{port}")).ok();
    REDIS_URL.get().unwrap()
}

/// Create a fresh, uniquely-named database on the shared Postgres server and
/// return its connection URL. Each stack gets its own DB for isolation.
async fn fresh_database() -> String {
    let endpoint = pg_endpoint().await;
    let admin_url = format!("postgres://forge:forge@{endpoint}/forge");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("connect admin db");
    let db = format!("e2e_{}", unique());
    // The name is generated here (never user input), so the dynamic SQL is safe.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(r#"CREATE DATABASE "{db}""#)))
        .execute(&admin)
        .await
        .expect("create database");
    admin.close().await;
    format!("postgres://forge:forge@{endpoint}/{db}")
}

async fn connect_migrated(db_url: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(db_url)
        .await
        .expect("connect fresh db");
    forge_db::migrate(&pool).await.expect("migrate");
    pool
}

async fn blob_store() -> BlobStore {
    let endpoint = s3_endpoint().await.to_string();
    let store = BlobStore::new(S3Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: S3_BUCKET.into(),
        credentials: S3Credentials::from_keys(S3_ACCESS, S3_SECRET),
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

// ── Configuration ───────────────────────────────────────────────────────────

/// Anonymous-access mode for a stack (the `anonymous_mode` auth setting).
#[derive(Debug, Clone)]
pub enum AnonMode {
    /// `off` — every read requires authentication.
    Off,
    /// `allowlist` with the given allowlist tokens.
    Allowlist(Vec<String>),
    /// `all` — anonymous reads of `anonymous_read` repos.
    All,
}

impl AnonMode {
    /// The auth settings update that selects this mode.
    fn settings(&self) -> serde_json::Value {
        match self {
            AnonMode::Off => serde_json::json!({"anonymous_mode": "off"}),
            AnonMode::Allowlist(tokens) => serde_json::json!({
                "anonymous_mode": "allowlist",
                "anonymous_ip_allowlist": tokens,
            }),
            AnonMode::All => serde_json::json!({"anonymous_mode": "all"}),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn config_toml(
    db_url: &str,
    s3_endpoint: &str,
    admin: Option<(&str, &str)>,
    redis: Option<&str>,
    trusted_proxies: &[String],
    cache_ttl_seconds: u64,
    public_base_url: &str,
    oidc_block: &str,
    auth_block: &str,
    blob_cache: Option<&BlobCacheSetup>,
    s3_credentials: Option<&str>,
) -> String {
    let s3_credentials = s3_credentials.map_or_else(
        || format!("access_key = \"{S3_ACCESS}\"\nsecret_key = \"{S3_SECRET}\""),
        str::to_string,
    );
    let blob_cache_block = match blob_cache {
        // No free-space reserve: whether the cache may grow must not depend
        // on how full the test host's disk is.
        Some(cache) => format!(
            "[blob_cache]\npath = {:?}\nmax_bytes = {}\nmin_free_bytes = 0\n",
            cache.path.display().to_string(),
            cache
                .max_bytes
                .map_or_else(|| "\"auto\"".to_string(), |b| b.to_string())
        ),
        None => String::new(),
    };
    let bootstrap = match admin {
        Some((u, p)) => format!("[auth.bootstrap_admin]\nusername = \"{u}\"\npassword = \"{p}\"\n"),
        None => String::new(),
    };
    let redis_block = match redis {
        Some(url) => format!("[redis]\nurl = \"{url}\"\n"),
        None => String::new(),
    };
    let trusted = {
        let quoted: Vec<String> = trusted_proxies.iter().map(|t| format!("{t:?}")).collect();
        format!("trusted_proxy_cidrs = [{}]\n", quoted.join(", "))
    };
    format!(
        r#"
[server]
bind = "127.0.0.1:0"
public_base_url = "{public_base_url}"

[database]
url = "{db_url}"

[s3]
endpoint = "{s3_endpoint}"
bucket = "{bucket}"
force_path_style = true
{s3_credentials}

[auth]
{trusted}{auth_block}{bootstrap}
{redis_block}
[cache]
l1_max_capacity = 1000
default_ttl_seconds = {cache_ttl_seconds}

[outbox]
batch_size = 50
grace_seconds = 0
poll_interval_seconds = 1

[retention]
enabled = true
poll_interval_seconds = 1
default_run_interval_seconds = 3600
lease_seconds = 30
{oidc_block}
{blob_cache_block}
"#,
        bucket = S3_BUCKET,
    )
}

// ── Stack builder ───────────────────────────────────────────────────────────

/// The `[blob_cache]` of a stack.
#[derive(Debug, Clone)]
struct BlobCacheSetup {
    path: std::path::PathBuf,
    /// `None`: `"auto"`.
    max_bytes: Option<u64>,
}

/// Produces the `[oidc]` TOML block from the (post-bind) public base URL, so the
/// `redirect_url` can embed the ephemeral address the server actually binds to.
type OidcBlockFn = Box<dyn Fn(&str) -> String + Send + Sync>;

/// Builder for a stack ([`start_stack`] is the common case with defaults).
pub struct StackBuilder {
    anon: AnonMode,
    /// Further auth settings to store (an `/admin/settings/auth` update).
    auth_settings: Option<serde_json::Value>,
    bootstrap_admin: Option<(String, String)>,
    spawn_workers: bool,
    use_redis: bool,
    trusted_proxies: Vec<String>,
    cache_ttl_seconds: u64,
    /// `None` ⇒ OIDC disabled.
    oidc_block_fn: Option<OidcBlockFn>,
    /// `None` ⇒ default local-only provider chain (no credential forwarding).
    /// When set, this is the `providers = [...]` line plus the
    /// `[auth.upstream_basic]` table injected into the `[auth]` config section.
    auth_block: Option<String>,
    /// `None` ⇒ the shared versitygw.
    s3_endpoint: Option<String>,
    /// `None` ⇒ no local blob cache.
    blob_cache: Option<BlobCacheSetup>,
    /// `None` ⇒ the static test keys.
    s3_credentials: Option<String>,
}

impl Default for StackBuilder {
    fn default() -> Self {
        StackBuilder {
            anon: AnonMode::Off,
            auth_settings: None,
            bootstrap_admin: Some((format!("admin{}@example.com", unique()), "adminpw".into())),
            spawn_workers: false,
            use_redis: false,
            // Trust loopback so XFF-driven anon-allowlist tests can spoof the
            // client IP from the in-process client.
            trusted_proxies: vec!["127.0.0.1/32".into(), "::1/128".into()],
            cache_ttl_seconds: 5,
            oidc_block_fn: None,
            auth_block: None,
            s3_endpoint: None,
            blob_cache: None,
            s3_credentials: None,
        }
    }
}

impl StackBuilder {
    /// Set the anonymous-access mode (default [`AnonMode::Off`]).
    pub fn anon(mut self, anon: AnonMode) -> Self {
        self.anon = anon;
        self
    }
    /// Store these auth settings too (fields of a `PUT
    /// /admin/settings/auth` body, e.g. `{"session_idle_ttl_seconds": 1}`).
    /// Every stack has password Basic on and its [`Self::anon`] mode.
    pub fn auth_settings(mut self, update: serde_json::Value) -> Self {
        self.auth_settings = Some(update);
        self
    }
    /// Override the bootstrap admin (default a unique `adminN`/`adminpw`).
    pub fn bootstrap_admin(mut self, username: &str, password: &str) -> Self {
        self.bootstrap_admin = Some((username.to_string(), password.to_string()));
        self
    }
    /// Omit the bootstrap admin entirely (for negative tests / peers).
    pub fn no_bootstrap_admin(mut self) -> Self {
        self.bootstrap_admin = None;
        self
    }
    /// Spawn the background workers (outbox/reconciler/proxy refresh).
    pub fn workers(mut self, on: bool) -> Self {
        self.spawn_workers = on;
        self
    }
    /// Use the shared Redis container as the L2 cache backplane.
    pub fn with_redis(mut self) -> Self {
        self.use_redis = true;
        self
    }
    /// Set the read-cache TTL (seconds).
    pub fn cache_ttl_seconds(mut self, secs: u64) -> Self {
        self.cache_ttl_seconds = secs;
        self
    }

    /// Enable OIDC login, deriving the `[oidc]` config block from the server's
    /// (post-bind) public base URL via `block_fn` — typically
    /// `move |base| mock.oidc_block(base)`. The closure runs once the ephemeral
    /// listener address is known, so the `redirect_url` matches `public_base_url`.
    pub fn with_oidc<F>(mut self, block_fn: F) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        self.oidc_block_fn = Some(Box::new(block_fn));
        self
    }

    /// Enable the credential-forwarding auth chain. `block` is the
    /// `providers = [...]` line plus the `[auth.upstream_basic]` table (typically
    /// `mock.upstream_basic_block(...)`). Injected into the `[auth]` config
    /// section so the server builds the real `AuthProvider` chain at startup.
    pub fn with_upstream_basic(mut self, block: impl Into<String>) -> Self {
        self.auth_block = Some(block.into());
        self
    }

    /// Talk to S3 at `endpoint` (e.g. an [`S3Gate`](crate::S3Gate) in front
    /// of the shared versitygw) instead of the shared versitygw directly.
    pub fn s3_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.s3_endpoint = Some(endpoint.into());
        self
    }

    /// Replace the static test keys with `toml` at the end of the `[s3]`
    /// section: further `s3.*` keys, then e.g. `credentials = "web_identity"`
    /// and its `[s3.web_identity]` table. Combine with [`Self::s3_endpoint`].
    pub fn s3_credentials(mut self, toml: impl Into<String>) -> Self {
        self.s3_credentials = Some(toml.into());
        self
    }

    /// Enable the local blob cache at `path`, `max_bytes` bytes large
    /// (`None`: `"auto"`). The server then starts even while S3 is down.
    pub fn blob_cache(
        mut self,
        path: impl Into<std::path::PathBuf>,
        max_bytes: Option<u64>,
    ) -> Self {
        self.blob_cache = Some(BlobCacheSetup {
            path: path.into(),
            max_bytes,
        });
        self
    }

    /// Boot a server over an existing stack's database (e.g. an instance
    /// restarted on its persistent blob cache), without creating the
    /// bootstrap admin or minting tokens.
    pub async fn start_on(self, db_url: &str) -> TestServer {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(db_url)
            .await
            .expect("connect existing db");
        self.serve(db_url.to_string(), pool, false).await
    }

    /// Boot a fresh stack: a new database + a server instance.
    pub async fn start(self) -> TestServer {
        let db_url = fresh_database().await;
        let pool = connect_migrated(&db_url).await;
        self.serve(db_url, pool, true).await
    }

    /// Build the config + server for `pool`, optionally creating the bootstrap
    /// admin and minting an admin token.
    async fn serve(self, db_url: String, pool: PgPool, mint_token: bool) -> TestServer {
        let shared_s3 = s3_endpoint().await;
        let s3 = self.s3_endpoint.as_deref().unwrap_or(shared_s3);
        let redis = if self.use_redis {
            Some(redis_url().await.to_string())
        } else {
            None
        };

        // Bind first so the public base URL can advertise the *real* ephemeral
        // address — a real NuGet client follows the absolute `@id`s the service
        // index returns, so they must be reachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        let base_url = format!("http://{addr}");

        let admin_ref = self
            .bootstrap_admin
            .as_ref()
            .map(|(u, p)| (u.as_str(), p.as_str()));
        // Build the [oidc] block now that the public base URL is known (the
        // redirect_url must match it). Empty when OIDC is disabled.
        let oidc_block = self
            .oidc_block_fn
            .as_ref()
            .map(|f| f(&base_url))
            .unwrap_or_default();
        let toml = config_toml(
            &db_url,
            s3,
            admin_ref,
            redis.as_deref(),
            &self.trusted_proxies,
            self.cache_ttl_seconds,
            &base_url,
            &oidc_block,
            self.auth_block.as_deref().unwrap_or_default(),
            self.blob_cache.as_ref(),
            self.s3_credentials.as_deref(),
        );
        use figment::providers::Format as _;
        let config = Config::from_figment(
            figment::Figment::new().merge(figment::providers::Toml::string(&toml)),
        )
        .expect("valid config");

        // A stack with its own S3 endpoint or a blob cache builds its store
        // the way `main` does (degraded start while S3 is down, with the
        // cache); the others share the readiness-checked versitygw store.
        let store = if self.s3_endpoint.is_some()
            || self.blob_cache.is_some()
            || self.s3_credentials.is_some()
        {
            let store = forge_server::object_store::open(&config).expect("object store");
            forge_server::object_store::ensure_bucket(&store)
                .await
                .expect("ensure bucket");
            store
        } else {
            blob_store().await
        };

        ensure_bootstrap_admin(&config, &pool)
            .await
            .expect("bootstrap admin");

        // Seed auth realms from the [oidc]/[auth.upstream_basic] config blocks.
        forge_server::app::ensure_auth_realms(&config, &pool, None)
            .await
            .expect("seed auth realms");

        let cache = match &redis {
            Some(url) => Cache::with_redis(config.cache.l1_max_capacity, url)
                .await
                .expect("connect redis L2"),
            None => Cache::l1_only(config.cache.l1_max_capacity),
        };
        let registry_keys = forge_server::registry::load_token_keys(&config, &pool, None)
            .await
            .expect("registry token key");
        let state =
            AppState::new(pool.clone(), store, cache, config).with_registry_keys(registry_keys);
        // The access policy is stored in the database: password Basic on
        // (tests sign in over Basic), the stack's anonymous mode, and any
        // further settings. A peer on the same database stores the same.
        let mut update = serde_json::json!({"allow_password_basic": true});
        for extra in [Some(self.anon.settings()), self.auth_settings.clone()]
            .into_iter()
            .flatten()
        {
            if let (Some(update), serde_json::Value::Object(extra)) =
                (update.as_object_mut(), extra)
            {
                update.extend(extra);
            }
        }
        let update: forge_server::auth::AuthSettingsUpdate =
            serde_json::from_value(update).expect("an auth settings update");
        let current = forge_server::auth::load_auth_settings(&pool)
            .await
            .expect("stored auth settings");
        state
            .auth_settings
            .save(update.apply_to(&current).expect("valid auth settings"))
            .await
            .expect("store auth settings");
        let layer = principal_layer(&state).expect("principal layer");

        let worker_handles = if self.spawn_workers {
            Some(workers::spawn_all(&state))
        } else {
            None
        };

        let serve_options = forge_server::serve::ServeOptions::from_config(&state.config);
        let app = build_router(state.clone(), layer);
        let handle = tokio::spawn(async move {
            forge_server::serve::serve(listener, app, serve_options, std::future::pending()).await;
        });

        let admin_user = self.bootstrap_admin.as_ref().map(|(u, _)| u.clone());
        let admin_pass = self.bootstrap_admin.as_ref().map(|(_, p)| p.clone());
        let admin_scoped_token = match &admin_user {
            Some(username) => mint_admin_scoped_token(&pool, username).await,
            None => None,
        };

        let mut srv = TestServer {
            base_url,
            pool,
            db_url,
            state,
            admin_user,
            admin_pass,
            admin_scoped_token,
            admin_token: String::new(),
            use_redis: self.use_redis,
            handle,
            workers: worker_handles,
        };

        // `axum::serve` runs in a spawned task, so the listener may not yet be
        // accepting (and routing) when the first request fires. Under load —
        // many concurrent test processes contending for CPU/Docker — that race
        // surfaces as an empty/non-JSON body on the first call. Gate on a real
        // HTTP response before handing the stack back to the test.
        srv.wait_until_ready().await;

        if mint_token && srv.admin_user.is_some() {
            srv.admin_token = srv.issue_admin_token().await;
        }
        srv
    }
}

// ── Public entry points ─────────────────────────────────────────────────────

/// Boot the default stack: Postgres + versitygw, a fresh DB, a single server
/// instance with a bootstrap admin and a ready-to-use admin token.
pub async fn start_stack() -> TestServer {
    StackBuilder::default().start().await
}

// ── The running test server ─────────────────────────────────────────────────

/// A running test server instance plus its DB handle and admin credentials.
pub struct TestServer {
    /// Base URL, e.g. `http://127.0.0.1:54321`.
    pub base_url: String,
    /// A pool over this stack's database.
    pub pool: PgPool,
    /// The database connection URL (so peers can share it).
    pub db_url: String,
    /// The fully-assembled application state.
    pub state: AppState,
    /// Bootstrap admin username (if any).
    pub admin_user: Option<String>,
    /// Bootstrap admin password (if any).
    pub admin_pass: Option<String>,
    /// An admin-scoped API token of the bootstrap admin (`{"actions":
    /// ["admin"]}`), minted directly in the database. The admin API refuses a
    /// password sent over Basic, so [`TestServer::admin_basic`] carries this.
    pub admin_scoped_token: Option<String>,
    /// A plaintext API token for the bootstrap admin (empty if no admin).
    pub admin_token: String,
    use_redis: bool,
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

impl TestServer {
    /// A reqwest client (no default auth).
    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    /// Block until the server is accepting connections and routing requests.
    ///
    /// `/admin/me` always routes and returns a proper HTTP status (200 when
    /// authenticated, 401 otherwise) once the router is live, so any structured
    /// status — as opposed to a connection error — proves readiness. Polls for
    /// up to ~10s before giving up.
    async fn wait_until_ready(&self) {
        let client = self.client();
        let url = format!("{}/admin/me", self.base_url);
        for _ in 0..200 {
            if let Ok(resp) = client.get(&url).send().await {
                // Any real HTTP status means the router is serving requests.
                if resp.status().as_u16() != 0 {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server at {} never became ready", self.base_url);
    }

    /// GET a basic-auth-protected endpoint and decode its JSON body, retrying a
    /// few times on transport errors or a non-JSON body. Belt-and-braces on top
    /// of [`Self::wait_until_ready`]: even a routed request can momentarily race
    /// the body if the connection was accepted mid-startup.
    async fn get_json_with_retry(
        &self,
        client: &reqwest::Client,
        url: &str,
        user: &str,
        pass: &str,
    ) -> serde_json::Value {
        let mut last_err = String::from("no attempt made");
        for _ in 0..40 {
            match client.get(url).basic_auth(user, Some(pass)).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    match serde_json::from_str::<serde_json::Value>(&text) {
                        Ok(v) => return v,
                        Err(e) => {
                            last_err =
                                format!("{status}: non-JSON body ({e}): {:?}", text.get(..200))
                        }
                    }
                }
                Err(e) => last_err = format!("transport error: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("GET {url} never returned JSON: {last_err}");
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

    /// Start a **peer** server instance sharing this stack's DB + S3 (+ Redis),
    /// with no bootstrap admin (it reuses the one already created) and workers
    /// enabled by default for scale-out scenarios.
    pub async fn spawn_peer(&self) -> TestServer {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&self.db_url)
            .await
            .expect("peer connect");
        let mut builder = StackBuilder::default()
            .no_bootstrap_admin()
            .workers(true)
            .cache_ttl_seconds(5);
        if self.use_redis {
            builder = builder.with_redis();
        }
        let mut peer = builder.serve(self.db_url.clone(), pool, false).await;
        // The peer shares the admin token already minted on the primary.
        peer.admin_user = self.admin_user.clone();
        peer.admin_pass = self.admin_pass.clone();
        peer.admin_scoped_token = self.admin_scoped_token.clone();
        peer.admin_token = self.admin_token.clone();
        peer
    }

    /// Like [`spawn_peer`](Self::spawn_peer) but the peer also enables OIDC with
    /// the same provider, so it can complete a callback whose login was started
    /// on the primary (the headline cross-instance scale-out scenario). The
    /// `block_fn` is the mock IdP's `oidc_block` closure (it derives the peer's
    /// own `redirect_url` from the peer's bind address — the token endpoint
    /// ignores `redirect_uri`, and issuer/client_id are what matter).
    pub async fn spawn_peer_with_oidc<F>(&self, block_fn: F) -> TestServer
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&self.db_url)
            .await
            .expect("peer connect");
        let mut builder = StackBuilder::default()
            .no_bootstrap_admin()
            .workers(true)
            .cache_ttl_seconds(5)
            .with_oidc(block_fn);
        if self.use_redis {
            builder = builder.with_redis();
        }
        let mut peer = builder.serve(self.db_url.clone(), pool, false).await;
        peer.admin_user = self.admin_user.clone();
        peer.admin_pass = self.admin_pass.clone();
        peer.admin_scoped_token = self.admin_scoped_token.clone();
        peer.admin_token = self.admin_token.clone();
        peer
    }

    /// Like [`spawn_peer`](Self::spawn_peer) but the peer also enables the
    /// credential-forwarding chain with the same `[auth.upstream_basic]` block,
    /// so a first-time login can be raced across both instances (the
    /// scale-out singleflight scenario) and a reauth on one instance invalidates
    /// the cached verdict on the other (the shared validated_credential table +
    /// cache backplane).
    pub async fn spawn_peer_with_upstream_basic(&self, block: impl Into<String>) -> TestServer {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&self.db_url)
            .await
            .expect("peer connect");
        let mut builder = StackBuilder::default()
            .no_bootstrap_admin()
            .workers(true)
            .cache_ttl_seconds(5)
            .with_upstream_basic(block);
        if self.use_redis {
            builder = builder.with_redis();
        }
        let mut peer = builder.serve(self.db_url.clone(), pool, false).await;
        peer.admin_user = self.admin_user.clone();
        peer.admin_pass = self.admin_pass.clone();
        peer.admin_scoped_token = self.admin_scoped_token.clone();
        peer.admin_token = self.admin_token.clone();
        peer
    }

    /// Issue an API token for the bootstrap admin and return its plaintext
    /// secret (used for `X-NuGet-ApiKey` on publish endpoints).
    async fn issue_admin_token(&self) -> String {
        let (u, p) = self.admin_basic();
        let client = self.client();
        let users = self
            .get_json_with_retry(&client, &format!("{}/admin/users", self.base_url), &u, &p)
            .await;
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
            .json(&serde_json::json!({"name": "e2e"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["token"].as_str().expect("plaintext token").to_string()
    }

    /// Create a repository via the admin API, returning the parsed JSON view.
    pub async fn create_repo(&self, body: serde_json::Value) -> reqwest::Response {
        let (u, p) = self.admin_basic();
        self.client()
            .post(format!("{}/admin/repositories", self.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// Grant the built-in `anonymous` role `read` on `repo` directly in the DB,
    /// mirroring the RBAC data migration that converted the `anonymous_read`
    /// flag into an anonymous-role grant. Under fine-grained RBAC, anonymous
    /// read flows through this grant (not the column), so a test that wants an
    /// anonymously-readable repo creates it with `anonymous_read: true` **and**
    /// calls this. Done before any anonymous request, so the (cold) anonymous
    /// cache entry loads the grant on first use.
    pub async fn grant_anonymous_read(&self, repo: &str) {
        let repo_id = forge_db::repository_dao::find_repository_by_name(&self.pool, repo)
            .await
            .expect("repo lookup")
            .expect("repo exists")
            .id;
        let anon_role = forge_db::authz_dao::role_id_by_name(&self.pool, "anonymous")
            .await
            .expect("role lookup")
            .expect("anonymous role seeded");
        forge_db::authz_dao::add_grant(&self.pool, anon_role, Some(repo_id), "read", None)
            .await
            .expect("add anonymous read grant");
    }

    /// Push a `.nupkg` to a hosted repo via the NuGet multipart PUT endpoint,
    /// authenticating with the admin API key.
    pub async fn push_nupkg(&self, repo: &str, bytes: Vec<u8>) -> reqwest::Response {
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name("package.nupkg")
            .mime_str("application/octet-stream")
            .unwrap();
        let form = reqwest::multipart::Form::new().part("package", part);
        self.client()
            .put(format!("{}/v3/{repo}/package", self.base_url))
            .header("X-NuGet-ApiKey", &self.admin_token)
            .multipart(form)
            .send()
            .await
            .unwrap()
    }

    /// Add `member` to group `group` at the given priority via the admin API.
    pub async fn add_member(&self, group: &str, member: &str, priority: i32) -> reqwest::Response {
        let (u, p) = self.admin_basic();
        self.client()
            .post(format!(
                "{}/admin/repositories/{group}/members",
                self.base_url
            ))
            .basic_auth(&u, Some(&p))
            .json(&serde_json::json!({"member": member, "priority": priority}))
            .send()
            .await
            .unwrap()
    }

    // ── RBAC admin helpers ───────────────────────────────────────────────────

    /// Create a non-admin user via the admin API and return its numeric id.
    pub async fn create_user(&self, username: &str, password: &str) -> i64 {
        let (u, p) = self.admin_basic();
        let body: serde_json::Value = self
            .client()
            .post(format!("{}/admin/users", self.base_url))
            .basic_auth(&u, Some(&p))
            .json(&serde_json::json!({
                "username": username, "password": password, "is_admin": false
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["id"].as_i64().expect("created user id")
    }

    /// Issue an API token for `user_id`, optionally with a per-token `scope`
    /// (`{"actions":[..],"repositories":[..]}`). Returns the plaintext secret.
    pub async fn issue_token(&self, user_id: i64, scope: Option<serde_json::Value>) -> String {
        let (u, p) = self.admin_basic();
        let mut body = serde_json::json!({"name": "e2e"});
        if let Some(s) = scope {
            body["scope"] = s;
        }
        let resp: serde_json::Value = self
            .client()
            .post(format!("{}/admin/users/{user_id}/tokens", self.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        resp["token"].as_str().expect("plaintext token").to_string()
    }

    /// Create a role with the given name via the admin API; returns its id.
    pub async fn create_role(&self, name: &str) -> i64 {
        let (u, p) = self.admin_basic();
        let body: serde_json::Value = self
            .client()
            .post(format!("{}/admin/roles", self.base_url))
            .basic_auth(&u, Some(&p))
            .json(&serde_json::json!({"name": name}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["id"].as_i64().expect("created role id")
    }

    /// Add a grant `(repository|ANY, action, selector?)` to a role. `repository`
    /// `None` ⇒ an ANY-repo (wildcard) grant. Returns the HTTP response so callers
    /// can assert on the status.
    pub async fn add_grant(
        &self,
        role_id: i64,
        repository: Option<&str>,
        action: &str,
        selector_id: Option<i64>,
    ) -> reqwest::Response {
        let (u, p) = self.admin_basic();
        let mut body = serde_json::json!({"action": action});
        if let Some(r) = repository {
            body["repository"] = serde_json::json!(r);
        }
        if let Some(s) = selector_id {
            body["selector_id"] = serde_json::json!(s);
        }
        self.client()
            .put(format!("{}/admin/roles/{role_id}/grants", self.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// Assign `role_id` to `user_id` via the admin API.
    pub async fn assign_role(&self, user_id: i64, role_id: i64) -> reqwest::Response {
        let (u, p) = self.admin_basic();
        self.client()
            .put(format!("{}/admin/users/{user_id}/roles", self.base_url))
            .basic_auth(&u, Some(&p))
            .json(&serde_json::json!({"role_id": role_id}))
            .send()
            .await
            .unwrap()
    }

    /// Look up the numeric id of a role by name (built-in or otherwise).
    pub async fn role_id(&self, name: &str) -> i64 {
        forge_db::authz_dao::role_id_by_name(&self.pool, name)
            .await
            .expect("role lookup")
            .expect("role exists")
    }

    /// Create a content selector with include/exclude globs; returns its id.
    pub async fn create_content_selector(
        &self,
        name: &str,
        includes: &[&str],
        excludes: &[&str],
    ) -> i64 {
        let (u, p) = self.admin_basic();
        let body: serde_json::Value = self
            .client()
            .post(format!("{}/admin/content-selectors", self.base_url))
            .basic_auth(&u, Some(&p))
            .json(&serde_json::json!({
                "name": name,
                "includes": includes,
                "excludes": excludes,
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["id"].as_i64().expect("created selector id")
    }

    /// GET `/v3/{repo}/index.json` authenticating with an API token; returns the
    /// HTTP status (the repo-level read gate's verdict).
    pub async fn read_index_with_token(&self, repo: &str, token: &str) -> reqwest::StatusCode {
        self.client()
            .get(format!("{}/v3/{repo}/index.json", self.base_url))
            .header("X-NuGet-ApiKey", token)
            .send()
            .await
            .unwrap()
            .status()
    }

    /// Push a `.nupkg` to `repo` authenticating with the given API token (rather
    /// than the admin token), returning the HTTP response. Used to probe the
    /// write gate for a scoped / role-limited token.
    pub async fn push_nupkg_with_token(
        &self,
        repo: &str,
        token: &str,
        bytes: Vec<u8>,
    ) -> reqwest::Response {
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name("package.nupkg")
            .mime_str("application/octet-stream")
            .unwrap();
        let form = reqwest::multipart::Form::new().part("package", part);
        self.client()
            .put(format!("{}/v3/{repo}/package", self.base_url))
            .header("X-NuGet-ApiKey", token)
            .multipart(form)
            .send()
            .await
            .unwrap()
    }
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// Build a minimal valid `.nupkg` (a zip with `[Content_Types].xml` + a
/// `{id}.nuspec`) that parses to `id@version`.
pub fn make_nupkg(id: &str, version: &str) -> Vec<u8> {
    make_nupkg_with_desc(id, version, "generated test package")
}

/// Like [`make_nupkg`] but with a caller-supplied description, so two packages
/// with the same `id@version` but different `desc` produce **distinct bytes**
/// (distinct CAS blobs) — used to prove which group member served a download.
pub fn make_nupkg_with_desc(id: &str, version: &str, desc: &str) -> Vec<u8> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    let nuspec = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <authors>test</authors>
    <description>{desc}</description>
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
    zw.finish().unwrap().into_inner()
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
            name: "e2e-admin".into(),
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
