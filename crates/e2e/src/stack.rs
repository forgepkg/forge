//! The e2e stack harness: containers, fresh-per-test databases, and a running
//! axum server (with optional peer instances sharing the same DB + S3 + Redis).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use forge_cache::Cache;
use forge_nuget::NugetFormat;
use forge_server::app::{build_router, ensure_bootstrap_admin, principal_layer};
use forge_server::config::Config;
use forge_server::state::AppState;
use forge_server::workers::{self, WorkerHandles};
use forge_storage::{BlobStore, S3Config};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};
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
    admin
        .execute(format!(r#"CREATE DATABASE "{db}""#).as_str())
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
        access_key: S3_ACCESS.into(),
        secret_key: S3_SECRET.into(),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
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

/// Anonymous-access mode for a stack.
#[derive(Debug, Clone)]
pub enum AnonMode {
    /// `anonymous_mode = "off"` — every read requires authentication.
    Off,
    /// `anonymous_mode = "allowlist"` with the given allowlist tokens.
    Allowlist(Vec<String>),
    /// `anonymous_mode = "all"` — anonymous reads of `anonymous_read` repos.
    All,
}

impl AnonMode {
    fn mode(&self) -> &'static str {
        match self {
            AnonMode::Off => "off",
            AnonMode::Allowlist(_) => "allowlist",
            AnonMode::All => "all",
        }
    }
    fn allowlist_toml(&self) -> String {
        match self {
            AnonMode::Allowlist(tokens) => {
                let quoted: Vec<String> = tokens.iter().map(|t| format!("{t:?}")).collect();
                format!("anonymous_ip_allowlist = [{}]\n", quoted.join(", "))
            }
            _ => String::new(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn config_toml(
    db_url: &str,
    s3_endpoint: &str,
    admin: Option<(&str, &str)>,
    anon: &AnonMode,
    redis: Option<&str>,
    trusted_proxies: &[String],
    cache_ttl_seconds: u64,
    public_base_url: &str,
) -> String {
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
access_key = "{access}"
secret_key = "{secret}"
force_path_style = true

[auth]
anonymous_mode = "{anon_mode}"
allow_password_basic = true
{allowlist}{trusted}{bootstrap}
{redis_block}
[cache]
l1_max_capacity = 1000
default_ttl_seconds = {cache_ttl_seconds}

[outbox]
batch_size = 50
grace_seconds = 0
poll_interval_seconds = 1
"#,
        bucket = S3_BUCKET,
        access = S3_ACCESS,
        secret = S3_SECRET,
        anon_mode = anon.mode(),
        allowlist = anon.allowlist_toml(),
    )
}

// ── Stack builder ───────────────────────────────────────────────────────────

/// Builder for a stack ([`start_stack`] is the common case with defaults).
pub struct StackBuilder {
    anon: AnonMode,
    bootstrap_admin: Option<(String, String)>,
    spawn_workers: bool,
    use_redis: bool,
    trusted_proxies: Vec<String>,
    cache_ttl_seconds: u64,
}

impl Default for StackBuilder {
    fn default() -> Self {
        StackBuilder {
            anon: AnonMode::Off,
            bootstrap_admin: Some((format!("admin{}", unique()), "adminpw".into())),
            spawn_workers: false,
            use_redis: false,
            // Trust loopback so XFF-driven anon-allowlist tests can spoof the
            // client IP from the in-process client.
            trusted_proxies: vec!["127.0.0.1/32".into(), "::1/128".into()],
            cache_ttl_seconds: 5,
        }
    }
}

impl StackBuilder {
    /// Set the anonymous-access mode (default [`AnonMode::Off`]).
    pub fn anon(mut self, anon: AnonMode) -> Self {
        self.anon = anon;
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

    /// Boot a fresh stack: a new database + a server instance.
    pub async fn start(self) -> TestServer {
        let db_url = fresh_database().await;
        let pool = connect_migrated(&db_url).await;
        self.serve(db_url, pool, true).await
    }

    /// Build the config + server for `pool`, optionally creating the bootstrap
    /// admin and minting an admin token.
    async fn serve(self, db_url: String, pool: PgPool, mint_token: bool) -> TestServer {
        let store = blob_store().await;
        let s3 = s3_endpoint().await;
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
        let toml = config_toml(
            &db_url,
            s3,
            admin_ref,
            &self.anon,
            redis.as_deref(),
            &self.trusted_proxies,
            self.cache_ttl_seconds,
            &base_url,
        );
        use figment::providers::Format as _;
        let config = Config::from_figment(
            figment::Figment::new().merge(figment::providers::Toml::string(&toml)),
        )
        .expect("valid config");

        ensure_bootstrap_admin(&config, &pool)
            .await
            .expect("bootstrap admin");

        let layer = principal_layer(&config, &pool).expect("principal layer");
        let nuget: Arc<dyn forge_core::format::Format> = Arc::new(NugetFormat::default());
        let cache = match &redis {
            Some(url) => Cache::with_redis(config.cache.l1_max_capacity, url)
                .await
                .expect("connect redis L2"),
            None => Cache::l1_only(config.cache.l1_max_capacity),
        };
        let state = AppState::new(pool.clone(), store, cache, nuget, config);

        let worker_handles = if self.spawn_workers {
            Some(workers::spawn_all(&state))
        } else {
            None
        };

        let app = build_router(state.clone(), layer);
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .ok();
        });

        let admin_user = self.bootstrap_admin.as_ref().map(|(u, _)| u.clone());
        let admin_pass = self.bootstrap_admin.as_ref().map(|(_, p)| p.clone());

        let mut srv = TestServer {
            base_url,
            pool,
            db_url,
            state,
            admin_user,
            admin_pass,
            admin_token: String::new(),
            use_redis: self.use_redis,
            handle,
            workers: worker_handles,
        };

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

    /// Basic-auth credentials for the bootstrap admin.
    pub fn admin_basic(&self) -> (String, String) {
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
        peer.admin_token = self.admin_token.clone();
        peer
    }

    /// Issue an API token for the bootstrap admin and return its plaintext
    /// secret (used for `X-NuGet-ApiKey` on publish endpoints).
    async fn issue_admin_token(&self) -> String {
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
