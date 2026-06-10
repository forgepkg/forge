//! Shared test harness for `forge-server` integration tests.
//!
//! Boots a Postgres + versitygw container per test binary (leaked so their
//! async `Drop` never runs on a torn-down runtime), migrates a fresh pool, and
//! assembles a real [`AppState`] + axum app served on an ephemeral port. Tests
//! drive it over HTTP with `reqwest`, exactly as a NuGet client would.

#![allow(dead_code)]

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

/// A fresh migrated pool over the shared Postgres container.
pub async fn pool() -> PgPool {
    let endpoint = pg_endpoint().await;
    let url = format!("postgres://forge:forge@{endpoint}/forge");
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
fn config_toml(
    db_url: &str,
    s3_endpoint: &str,
    admin: Option<(&str, &str)>,
    anon: &str,
    web_assets_dir: Option<&str>,
    oidc_block: Option<&str>,
    crypto_block: Option<&str>,
) -> String {
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
public_base_url = "http://test.local"

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
"#,
        bucket = S3_BUCKET,
        access = S3_ACCESS,
        secret = S3_SECRET,
        oidc = oidc_block.unwrap_or(""),
        crypto = crypto_block.unwrap_or(""),
    )
}

/// A running test server.
pub struct TestServer {
    pub base_url: String,
    pub pool: PgPool,
    pub state: AppState,
    pub admin_user: Option<String>,
    pub admin_pass: Option<String>,
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
        }
    }
}

/// Start a server with the given options against the shared containers, sharing
/// `pool` (so a caller can run two instances against one DB for scale-out).
pub async fn start_with(pool: PgPool, opts: ServerOpts) -> TestServer {
    let endpoint = pg_endpoint().await;
    let db_url = format!("postgres://forge:forge@{endpoint}/forge");
    let store = blob_store().await;
    let s3 = s3_endpoint().await;

    let admin_ref = opts
        .bootstrap_admin
        .as_ref()
        .map(|(u, p)| (u.as_str(), p.as_str()));
    let toml = config_toml(
        &db_url,
        s3,
        admin_ref,
        &opts.anonymous_mode,
        opts.web_assets_dir.as_deref(),
        opts.oidc_block.as_deref(),
        opts.crypto_block.as_deref(),
    );
    use figment::providers::Format as _;
    let config = Config::from_figment(
        figment::Figment::new().merge(figment::providers::Toml::string(&toml)),
    )
    .expect("valid config");

    ensure_bootstrap_admin(&config, &pool)
        .await
        .expect("bootstrap admin");

    // 12.7: import any [oidc]/[auth.upstream_basic] block into auth_realm rows
    // (drift-detected) so the realm-driven runtime sees them.
    forge_server::app::ensure_auth_realms(&config, &pool)
        .await
        .expect("seed auth realms");

    // §12.5: build + bootstrap the envelope service when the test enabled the
    // [crypto] block (no-op otherwise).
    let envelope =
        forge_server::crypto::build_envelope(&config, &pool).expect("build envelope service");
    if let (Some(env), Some(crypto_cfg)) = (&envelope, config.crypto.as_ref()) {
        forge_server::crypto::bootstrap(&pool, env, crypto_cfg)
            .await
            .expect("bootstrap secret encryption");
    }

    let cache = Cache::l1_only(config.cache.l1_max_capacity);
    let nuget: Arc<dyn forge_core::format::Format> = Arc::new(NugetFormat::default());
    let state = AppState::new(pool.clone(), store, cache, nuget, config).with_envelope(envelope);
    let layer = principal_layer(&state).expect("principal layer");

    let workers = if opts.spawn_workers {
        Some(workers::spawn_all(&state))
    } else {
        None
    };

    let app = build_router(state.clone(), layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
    });

    TestServer {
        base_url: format!("http://{addr}"),
        pool,
        state,
        admin_user: opts.bootstrap_admin.as_ref().map(|(u, _)| u.clone()),
        admin_pass: opts.bootstrap_admin.as_ref().map(|(_, p)| p.clone()),
        handle,
        workers,
    }
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

impl TestServer {
    /// A reqwest client (no default auth).
    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    /// Basic-auth header value for the bootstrap admin.
    pub fn admin_basic(&self) -> (String, String) {
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
    zw.finish().unwrap().into_inner()
}
