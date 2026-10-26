//! Forge's Prometheus metrics.
//!
//! One process-wide registry holds every metric family; the crates record
//! into it through the functions of this crate's modules, and the server
//! encodes it on its metrics listener ([`encode`]). Each family is declared
//! once, here, with its labels as a type:
//!
//! * **Labels stay bounded.** A label is an enum of the values the code
//!   chooses (a surface, an outcome, an operation) or, for the
//!   repository, a name an administrator chose. No label ever carries a
//!   package id, a version, an image name or tag, a username, a token or a
//!   path. [`set_per_repository`] turns the repository labels off: every
//!   series is then recorded with an empty `repo`, which Prometheus reads as
//!   no label at all.
//! * **Recording is cheap.** A counter is an atomic add behind a read lock;
//!   nothing here does I/O. Values that need a database query (the outbox
//!   backlog, the inventory) are computed by a worker and published as a
//!   snapshot ([`storage::publish_outbox`], [`inventory::publish`]), never
//!   per scrape.
//!
//! The text is OpenMetrics ([`CONTENT_TYPE`]), which Prometheus scrapes like
//! its own text format: counters end in `_total`, and the exposition ends
//! with `# EOF`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, PoisonError};

use prometheus_client::encoding::text::{encode_eof, encode_registry};
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::metrics::info::Info;
use prometheus_client::registry::Registry;

pub use prometheus_client;

/// The `Content-Type` of [`encode`]'s output.
pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Every label name a Forge metric may carry. A test fails when a metric
/// gets another one (`le` is a histogram's bucket bound).
pub const LABEL_NAMES: &[&str] = &[
    "action",
    "commit",
    "format",
    "kind",
    "le",
    "method",
    "op",
    "outcome",
    "reason",
    "realm_type",
    "repo",
    "result",
    "source",
    "state",
    "status",
    "surface",
    "tier",
    "version",
    "worker",
];

static PER_REPOSITORY: AtomicBool = AtomicBool::new(true);

/// Whether metrics carry the repository name (`metrics.per_repository`,
/// default on). Off, every series is recorded with an empty `repo`.
pub fn set_per_repository(enabled: bool) {
    PER_REPOSITORY.store(enabled, Ordering::Relaxed);
}

/// The `repo` label value of repository `name`.
fn repo(name: &str) -> String {
    if PER_REPOSITORY.load(Ordering::Relaxed) {
        name.to_string()
    } else {
        String::new()
    }
}

/// Declare a label value enum: its variants and the text each is encoded as.
macro_rules! label_enum {
    ($(#[$meta:meta])* pub enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)*
        }

        impl $name {
            /// The label value.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)*
                }
            }

            /// Every value (tests).
            pub const ALL: &'static [$name] = &[$($name::$variant,)*];
        }

        impl EncodeLabelValue for $name {
            fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
                EncodeLabelValue::encode(&self.as_str(), encoder)
            }
        }
    };
}

/// A histogram with fixed `buckets`.
fn histogram(buckets: &[f64]) -> Histogram {
    Histogram::new(buckets.iter().copied())
}

/// Buckets of request and operation latencies, in seconds.
const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0,
];

/// Buckets of database connection acquire waits, in seconds.
const ACQUIRE_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Buckets of worker pass durations, in seconds.
const RUN_BUCKETS: &[f64] = &[
    0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0,
];

fn latency_histogram() -> Histogram {
    histogram(LATENCY_BUCKETS)
}

fn acquire_histogram() -> Histogram {
    histogram(ACQUIRE_BUCKETS)
}

fn run_histogram() -> Histogram {
    histogram(RUN_BUCKETS)
}

type HistogramFamily<L> = Family<L, Histogram, fn() -> Histogram>;

/// The process-wide registry and its families.
struct Metrics {
    registry: Registry,
    build: Mutex<Option<BuildLabels>>,
    http: http::Families,
    proxy: proxy::Families,
    storage: storage::Families,
    cache: cache::Families,
    db: db::Families,
    workers: workers::Families,
    retention: retention::Families,
    auth: auth::Families,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let mut registry = Registry::default();
    Metrics {
        build: Mutex::new(None),
        http: http::Families::register(&mut registry),
        proxy: proxy::Families::register(&mut registry),
        storage: storage::Families::register(&mut registry),
        cache: cache::Families::register(&mut registry),
        db: db::Families::register(&mut registry),
        workers: workers::Families::register(&mut registry),
        retention: retention::Families::register(&mut registry),
        auth: auth::Families::register(&mut registry),
        registry,
    }
});

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct BuildLabels {
    version: String,
    commit: String,
}

/// Record the running build: `forge_build_info{version, commit} 1`.
pub fn set_build_info(version: &str, commit: &str) {
    *METRICS.build.lock().unwrap_or_else(PoisonError::into_inner) = Some(BuildLabels {
        version: version.to_string(),
        commit: commit.to_string(),
    });
}

/// Encode every metric as OpenMetrics text into `out`: the process-wide
/// families, the snapshots the workers published, and `live`, what the
/// caller read from in-process state at scrape time.
pub fn encode(out: &mut String, live: &live::Snapshot) -> std::fmt::Result {
    let metrics = &*METRICS;
    let mut snapshots = Registry::default();
    if let Some(build) = metrics
        .build
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
    {
        snapshots.register(
            "forge_build",
            "The running build of Forge",
            Info::new(build),
        );
    }
    storage::encode_outbox(&mut snapshots);
    inventory::encode(&mut snapshots);
    live.register(&mut snapshots);
    encode_registry(out, &metrics.registry)?;
    encode_registry(out, &snapshots)?;
    encode_eof(out)
}

/// Values read from in-process state when scraped: cheap reads of what the
/// process keeps anyway (the pool's sizes, the blob cache's counters), so
/// they are exact at scrape time and never duplicated into counters of
/// their own.
pub mod live {
    use prometheus_client::metrics::counter::ConstCounter;
    use prometheus_client::metrics::gauge::ConstGauge;

    use super::*;

    /// The database connection pool.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Pool {
        /// Open connections.
        pub size: u32,
        /// Those of them idle.
        pub idle: u32,
        /// The most the pool opens (`database.max_connections`).
        pub max: u32,
    }

    /// The local blob cache's state and its activity since startup (the
    /// numbers of `GET /admin/blob-cache`).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct BlobCache {
        pub entries: u64,
        pub size_bytes: u64,
        pub reserved_bytes: u64,
        pub limit_bytes: u64,
        pub hits: u64,
        pub hit_bytes: u64,
        pub hits_while_store_down: u64,
        pub misses: u64,
        pub fills: u64,
        pub fill_failures: u64,
        pub corrupt: u64,
        pub evictions: u64,
        pub evicted_bytes: u64,
        pub bypassed: u64,
        pub verifications: u64,
    }

    /// What a scrape reads from the process.
    #[derive(Debug, Clone, Default)]
    pub struct Snapshot {
        pub pool: Option<Pool>,
        /// Whether the S3 circuit breaker is open; `None` without one (it
        /// comes with the blob cache).
        pub breaker_open: Option<bool>,
        pub blob_cache: Option<BlobCache>,
        /// Bytes staged now and `server.max_staging_bytes`; `None` without
        /// a staging budget.
        pub staging: Option<(u64, u64)>,
        /// Whether the Redis invalidation backplane is subscribed; `None`
        /// without Redis.
        pub backplane_connected: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct StateLabels {
        state: &'static str,
    }

    fn gauge(n: u64) -> ConstGauge {
        ConstGauge::new(i64::try_from(n).unwrap_or(i64::MAX))
    }

    impl Snapshot {
        pub(super) fn register(&self, registry: &mut Registry) {
            if let Some(pool) = self.pool {
                let connections = Family::<StateLabels, Gauge>::default();
                connections
                    .get_or_create(&StateLabels { state: "idle" })
                    .set(i64::from(pool.idle));
                connections
                    .get_or_create(&StateLabels { state: "in_use" })
                    .set(i64::from(pool.size.saturating_sub(pool.idle)));
                registry.register(
                    "forge_db_pool_connections",
                    "Open database connections, by state (in_use or idle)",
                    connections,
                );
                registry.register(
                    "forge_db_pool_max_connections",
                    "The most connections the pool opens (database.max_connections)",
                    gauge(u64::from(pool.max)),
                );
            }
            if let Some(open) = self.breaker_open {
                registry.register(
                    "forge_s3_circuit_breaker_open",
                    "Whether S3 is considered down: the circuit breaker in front of it is \
                     open (1) or closed (0)",
                    gauge(u64::from(open)),
                );
            }
            if let Some(connected) = self.backplane_connected {
                registry.register(
                    "forge_cache_redis_backplane_connected",
                    "Whether the Redis invalidation backplane is subscribed (1) or not (0)",
                    gauge(u64::from(connected)),
                );
            }
            if let Some((in_use, limit)) = self.staging {
                registry.register(
                    "forge_staging_bytes",
                    "Bytes of pushes and proxy downloads staged on disk now",
                    gauge(in_use),
                );
                registry.register(
                    "forge_staging_limit_bytes",
                    "The staging budget (server.max_staging_bytes)",
                    gauge(limit),
                );
            }
            let Some(c) = self.blob_cache else {
                return;
            };
            for (name, help, value) in [
                (
                    "forge_blob_cache_entries",
                    "Blobs in the local blob cache",
                    c.entries,
                ),
                (
                    "forge_blob_cache_size_bytes",
                    "Bytes in the local blob cache",
                    c.size_bytes,
                ),
                (
                    "forge_blob_cache_reserved_bytes",
                    "Bytes the local blob cache promised to fills in progress",
                    c.reserved_bytes,
                ),
                (
                    "forge_blob_cache_limit_bytes",
                    "The local blob cache's effective size limit",
                    c.limit_bytes,
                ),
            ] {
                registry.register(name, help, gauge(value));
            }
            for (name, help, value) in [
                (
                    "forge_blob_cache_hits",
                    "Reads served from the local blob cache",
                    c.hits,
                ),
                (
                    "forge_blob_cache_hit_bytes",
                    "Bytes reads served from the local blob cache",
                    c.hit_bytes,
                ),
                (
                    "forge_blob_cache_hits_while_store_down",
                    "Reads the local blob cache served while S3 was down",
                    c.hits_while_store_down,
                ),
                (
                    "forge_blob_cache_misses",
                    "Reads that found no blob in the local blob cache",
                    c.misses,
                ),
                (
                    "forge_blob_cache_fills",
                    "Blobs added to the local blob cache",
                    c.fills,
                ),
                (
                    "forge_blob_cache_fill_failures",
                    "Fills of the local blob cache that failed",
                    c.fill_failures,
                ),
                (
                    "forge_blob_cache_corrupt",
                    "Cached blobs found damaged and dropped",
                    c.corrupt,
                ),
                (
                    "forge_blob_cache_evictions",
                    "Blobs evicted from the local blob cache",
                    c.evictions,
                ),
                (
                    "forge_blob_cache_evicted_bytes",
                    "Bytes evicted from the local blob cache",
                    c.evicted_bytes,
                ),
                (
                    "forge_blob_cache_bypassed",
                    "Misses served from S3 without caching (no room)",
                    c.bypassed,
                ),
                (
                    "forge_blob_cache_verifications",
                    "Cached blobs checked against their hash on their first hit",
                    c.verifications,
                ),
            ] {
                registry.register(name, help, ConstCounter::new(value));
            }
        }
    }
}

/// HTTP requests of the main listener.
pub mod http {
    use std::time::Duration;

    use super::*;

    label_enum! {
        /// Which part of Forge a request is for, from the route it matched.
        pub enum Surface {
            /// `/v2`: the Docker / OCI registry.
            Oci => "oci",
            /// `/repository/…` of a NuGet repository.
            Nuget => "nuget",
            /// `/repository/…` of a repository of another format plugin
            /// ([`super::http::plugin_surface`]).
            PluginNpm => "plugin_npm",
            PluginRaw => "plugin_raw",
            PluginOther => "plugin_other",
            /// `/repository/…` that named no repository Forge has.
            Repository => "repository",
            /// `/admin/…`: the admin API.
            Admin => "admin",
            /// `/browse/…`.
            Browse => "browse",
            /// `/auth/…`, token exchange and Forge's OIDC issuer.
            Auth => "auth",
            /// `/healthz`, `/readyz`, `/version`.
            Health => "health",
            /// Everything else: the web UI.
            Ui => "ui",
        }
    }

    /// The surface of a repository of format `format` (a format plugin's
    /// id): `nuget`, else `plugin_<format>` for the built-in formats and
    /// `plugin_other` for any other, so the label stays bounded.
    pub fn plugin_surface(format: &str) -> Surface {
        match format {
            "nuget" => Surface::Nuget,
            "npm" => Surface::PluginNpm,
            "raw" => Surface::PluginRaw,
            "docker" => Surface::Oci,
            _ => Surface::PluginOther,
        }
    }

    label_enum! {
        /// A request's method; any other is `OTHER`.
        pub enum Method {
            Get => "GET",
            Head => "HEAD",
            Post => "POST",
            Put => "PUT",
            Patch => "PATCH",
            Delete => "DELETE",
            Options => "OPTIONS",
            Other => "OTHER",
        }
    }

    impl Method {
        /// The label of method `name`.
        pub fn of(name: &str) -> Method {
            match name {
                "GET" => Method::Get,
                "HEAD" => Method::Head,
                "POST" => Method::Post,
                "PUT" => Method::Put,
                "PATCH" => Method::Patch,
                "DELETE" => Method::Delete,
                "OPTIONS" => Method::Options,
                _ => Method::Other,
            }
        }
    }

    label_enum! {
        /// An HTTP status, by class.
        pub enum StatusClass {
            Informational => "1xx",
            Success => "2xx",
            Redirection => "3xx",
            ClientError => "4xx",
            ServerError => "5xx",
        }
    }

    impl StatusClass {
        /// The class of status `code`.
        pub fn of(code: u16) -> StatusClass {
            match code {
                ..=199 => StatusClass::Informational,
                200..=299 => StatusClass::Success,
                300..=399 => StatusClass::Redirection,
                400..=499 => StatusClass::ClientError,
                _ => StatusClass::ServerError,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct RequestLabels {
        surface: Surface,
        method: Method,
        status: StatusClass,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct SurfaceLabels {
        surface: Surface,
    }

    pub(super) struct Families {
        requests: Family<RequestLabels, Counter>,
        duration: HistogramFamily<RequestLabels>,
        in_flight: Gauge,
        response_bytes: Family<SurfaceLabels, Counter>,
    }

    impl Families {
        pub(super) fn register(registry: &mut Registry) -> Self {
            let families = Families {
                requests: Family::default(),
                duration: Family::new_with_constructor(latency_histogram),
                in_flight: Gauge::default(),
                response_bytes: Family::default(),
            };
            registry.register(
                "forge_http_requests",
                "HTTP requests answered, by surface, method and status class",
                families.requests.clone(),
            );
            registry.register(
                "forge_http_request_duration_seconds",
                "Time from receiving an HTTP request to sending its response headers",
                families.duration.clone(),
            );
            registry.register(
                "forge_http_requests_in_flight",
                "HTTP requests being handled",
                families.in_flight.clone(),
            );
            registry.register(
                "forge_http_response_bytes",
                "Bytes of HTTP response bodies sent, by surface",
                families.response_bytes.clone(),
            );
            families
        }
    }

    /// Record an answered request: its response headers were ready after
    /// `elapsed`.
    pub fn request(surface: Surface, method: Method, status: u16, elapsed: Duration) {
        let labels = RequestLabels {
            surface,
            method,
            status: StatusClass::of(status),
        };
        let http = &METRICS.http;
        http.requests.get_or_create(&labels).inc();
        http.duration
            .get_or_create(&labels)
            .observe(elapsed.as_secs_f64());
    }

    /// Count `bytes` of response body sent for `surface`.
    pub fn response_bytes(surface: Surface, bytes: u64) {
        METRICS
            .http
            .response_bytes
            .get_or_create(&SurfaceLabels { surface })
            .inc_by(bytes);
    }

    /// A request being handled, counted in `forge_http_requests_in_flight`
    /// until dropped.
    pub struct InFlight(());

    impl InFlight {
        /// Start counting a request.
        pub fn start() -> InFlight {
            METRICS.http.in_flight.inc();
            InFlight(())
        }
    }

    impl Drop for InFlight {
        fn drop(&mut self) {
            METRICS.http.in_flight.dec();
        }
    }
}

/// Proxy repositories and their upstreams.
pub mod proxy {
    use std::time::Duration;

    use super::*;

    label_enum! {
        /// What a proxy looked up.
        pub enum Kind {
            /// A package's version listing.
            Metadata => "metadata",
            /// A package archive.
            Package => "package",
            /// An image manifest.
            Manifest => "manifest",
            /// An image blob (a layer, a config).
            Blob => "blob",
            /// A file of a files format (raw).
            File => "file",
        }
    }

    label_enum! {
        /// How a proxy answered a lookup.
        pub enum Outcome {
            /// From the cache, without asking the upstream (or after it
            /// confirmed the cached copy).
            Hit => "hit",
            /// Fetched from the upstream.
            Fetched => "fetched",
            /// From the cache because the upstream failed.
            StaleServed => "stale_served",
            /// "Not found" from the negative cache, without asking the
            /// upstream.
            NegativeCached => "negative_cached",
            /// Withheld by the package delay.
            DelayGated => "delay_gated",
            /// The upstream does not have it.
            NotFound => "not_found",
            /// The repository is offline and has no copy.
            Offline => "offline",
            /// The upstream could not be reached or answered an error.
            UpstreamError => "upstream_error",
            /// Forge failed (database, storage).
            Error => "error",
        }
    }

    label_enum! {
        /// The answer of one upstream request.
        pub enum UpstreamStatus {
            Success => "2xx",
            Redirection => "3xx",
            ClientError => "4xx",
            RateLimited => "429",
            ServerError => "5xx",
            /// No answer: connection failure, timeout, refused redirect.
            Error => "error",
        }
    }

    impl UpstreamStatus {
        /// The label of an upstream's status `code`.
        pub fn of(code: u16) -> UpstreamStatus {
            match code {
                429 => UpstreamStatus::RateLimited,
                ..=299 => UpstreamStatus::Success,
                300..=399 => UpstreamStatus::Redirection,
                400..=499 => UpstreamStatus::ClientError,
                _ => UpstreamStatus::ServerError,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct LookupLabels {
        repo: String,
        kind: Kind,
        outcome: Outcome,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct UpstreamLabels {
        repo: String,
        status: UpstreamStatus,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct RepoLabels {
        repo: String,
    }

    pub(super) struct Families {
        lookups: Family<LookupLabels, Counter>,
        upstream_requests: Family<UpstreamLabels, Counter>,
        upstream_duration: HistogramFamily<RepoLabels>,
        upstream_bytes: Family<RepoLabels, Counter>,
        rate_limited: Family<RepoLabels, Counter>,
    }

    impl Families {
        pub(super) fn register(registry: &mut Registry) -> Self {
            let families = Families {
                lookups: Family::default(),
                upstream_requests: Family::default(),
                upstream_duration: Family::new_with_constructor(latency_histogram),
                upstream_bytes: Family::default(),
                rate_limited: Family::default(),
            };
            registry.register(
                "forge_proxy_lookups",
                "Proxy lookups, by repository, kind and outcome",
                families.lookups.clone(),
            );
            registry.register(
                "forge_proxy_upstream_requests",
                "Requests proxy repositories sent their upstreams, by answer",
                families.upstream_requests.clone(),
            );
            registry.register(
                "forge_proxy_upstream_request_duration_seconds",
                "Time from sending an upstream request to its response headers",
                families.upstream_duration.clone(),
            );
            registry.register(
                "forge_proxy_upstream_bytes",
                "Bytes proxy repositories fetched from their upstreams",
                families.upstream_bytes.clone(),
            );
            registry.register(
                "forge_proxy_upstream_rate_limited",
                "Upstream answers 429 Too Many Requests (Docker Hub's pull limit)",
                families.rate_limited.clone(),
            );
            families
        }
    }

    /// Record a lookup of proxy repository `repository`.
    pub fn lookup(repository: &str, kind: Kind, outcome: Outcome) {
        METRICS
            .proxy
            .lookups
            .get_or_create(&LookupLabels {
                repo: repo(repository),
                kind,
                outcome,
            })
            .inc();
    }

    /// A lookup in progress: the paths it takes mark what they found
    /// ([`Self::mark`]), and the caller records it once it has the answer
    /// ([`Self::finish`]). A lookup dropped unfinished (its request was
    /// cancelled) records nothing.
    pub struct Lookup {
        repository: String,
        kind: Kind,
        marked: Option<Outcome>,
    }

    impl Lookup {
        /// Start a lookup of `kind` in proxy repository `repository`.
        pub fn start(repository: &str, kind: Kind) -> Lookup {
            Lookup {
                repository: repository.to_string(),
                kind,
                marked: None,
            }
        }

        /// What the lookup found, as far as the path it took knows.
        pub fn mark(&mut self, outcome: Outcome) {
            self.marked = Some(outcome);
        }

        /// The last [`Self::mark`].
        pub fn marked(&self) -> Option<Outcome> {
            self.marked
        }

        /// Record the lookup with `outcome`.
        pub fn finish(self, outcome: Outcome) {
            lookup(&self.repository, self.kind, outcome);
        }
    }

    /// Record a request proxy `repository` sent its upstream: answered with
    /// `status` after `elapsed`, or not answered (`None`).
    pub fn upstream_request(repository: &str, status: Option<u16>, elapsed: Duration) {
        let proxy = &METRICS.proxy;
        let status = status.map_or(UpstreamStatus::Error, UpstreamStatus::of);
        let repo = repo(repository);
        proxy
            .upstream_requests
            .get_or_create(&UpstreamLabels {
                repo: repo.clone(),
                status,
            })
            .inc();
        let labels = RepoLabels { repo };
        proxy
            .upstream_duration
            .get_or_create(&labels)
            .observe(elapsed.as_secs_f64());
        if status == UpstreamStatus::RateLimited {
            proxy.rate_limited.get_or_create(&labels).inc();
        }
    }

    /// Count `bytes` proxy `repository` fetched from its upstream.
    pub fn upstream_bytes(repository: &str, bytes: u64) {
        METRICS
            .proxy
            .upstream_bytes
            .get_or_create(&RepoLabels {
                repo: repo(repository),
            })
            .inc_by(bytes);
    }
}

/// The object store, garbage collection and the outbox.
pub mod storage {
    use std::time::Duration;

    use prometheus_client::metrics::gauge::ConstGauge;

    use super::*;

    label_enum! {
        /// An S3 operation.
        pub enum S3Op {
            HeadBucket => "head_bucket",
            CreateBucket => "create_bucket",
            Head => "head",
            Put => "put",
            PutConditional => "put_conditional",
            CreateMultipart => "create_multipart",
            UploadPart => "upload_part",
            CompleteMultipart => "complete_multipart",
            AbortMultipart => "abort_multipart",
            Get => "get",
            Delete => "delete",
        }
    }

    label_enum! {
        /// How an S3 operation ended.
        pub enum S3Outcome {
            Ok => "ok",
            /// The object does not exist (a `404`).
            NotFound => "not_found",
            /// A conditional write found the object there (a `412`).
            PreconditionFailed => "precondition_failed",
            /// S3 could not be reached: no connection, a timeout, a `5xx`.
            Unreachable => "unreachable",
            /// Not sent: the circuit breaker is open.
            BreakerOpen => "breaker_open",
            /// Any other error.
            Error => "error",
        }
    }

    label_enum! {
        /// Who deleted a blob from S3.
        pub enum GcSource {
            /// The outbox worker (deletes deferred by garbage collection).
            Outbox => "outbox",
            /// The orphan reconciler (blobs never committed).
            Reconciler => "reconciler",
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct OpLabels {
        op: S3Op,
        outcome: S3Outcome,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct OpOnly {
        op: S3Op,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct SourceLabels {
        source: GcSource,
    }

    pub(super) struct Families {
        operations: Family<OpLabels, Counter>,
        duration: HistogramFamily<OpOnly>,
        gc_deleted: Family<SourceLabels, Counter>,
    }

    impl Families {
        pub(super) fn register(registry: &mut Registry) -> Self {
            let families = Families {
                operations: Family::default(),
                duration: Family::new_with_constructor(latency_histogram),
                gc_deleted: Family::default(),
            };
            registry.register(
                "forge_s3_operations",
                "S3 operations, by operation and outcome",
                families.operations.clone(),
            );
            registry.register(
                "forge_s3_operation_duration_seconds",
                "Time an S3 operation took (to its response headers for a download)",
                families.duration.clone(),
            );
            registry.register(
                "forge_gc_blobs_deleted",
                "Blobs deleted from S3, by who deleted them",
                families.gc_deleted.clone(),
            );
            families
        }
    }

    /// Record an S3 operation that ended with `outcome` after `elapsed`.
    pub fn s3_operation(op: S3Op, outcome: S3Outcome, elapsed: Duration) {
        let storage = &METRICS.storage;
        storage
            .operations
            .get_or_create(&OpLabels { op, outcome })
            .inc();
        if outcome != S3Outcome::BreakerOpen {
            storage
                .duration
                .get_or_create(&OpOnly { op })
                .observe(elapsed.as_secs_f64());
        }
    }

    /// Count `blobs` that `source` deleted from S3.
    pub fn gc_deleted(source: GcSource, blobs: u64) {
        METRICS
            .storage
            .gc_deleted
            .get_or_create(&SourceLabels { source })
            .inc_by(blobs);
    }

    /// The outbox backlog as a worker last read it.
    #[derive(Debug, Clone, Copy, Default, PartialEq)]
    pub struct OutboxBacklog {
        /// Deferred deletes not processed yet.
        pub pending: u64,
        /// Those of them that are due.
        pub due: u64,
        /// How long the oldest due one has been due, in seconds (`0` without
        /// one).
        pub oldest_due_age_seconds: f64,
    }

    static OUTBOX: Mutex<Option<OutboxBacklog>> = Mutex::new(None);

    /// Publish the outbox backlog.
    pub fn publish_outbox(backlog: OutboxBacklog) {
        *OUTBOX.lock().unwrap_or_else(PoisonError::into_inner) = Some(backlog);
    }

    pub(super) fn encode_outbox(registry: &mut Registry) {
        let Some(backlog) = *OUTBOX.lock().unwrap_or_else(PoisonError::into_inner) else {
            return;
        };
        registry.register(
            "forge_outbox_pending",
            "Deferred S3 deletes not processed yet (a worker's last count)",
            ConstGauge::new(backlog.pending as i64),
        );
        registry.register(
            "forge_outbox_due",
            "Deferred S3 deletes that are due and not processed yet",
            ConstGauge::new(backlog.due as i64),
        );
        registry.register(
            "forge_outbox_oldest_due_age_seconds",
            "How long the oldest unprocessed due delete has been due",
            ConstGauge::new(backlog.oldest_due_age_seconds),
        );
    }
}

/// The cache (in-process L1, Redis L2 and its invalidation backplane).
pub mod cache {
    use super::*;

    label_enum! {
        /// A cache tier.
        pub enum Tier {
            L1 => "l1",
            L2 => "l2",
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct LookupLabels {
        tier: Tier,
        result: &'static str,
    }

    pub(super) struct Families {
        lookups: Family<LookupLabels, Counter>,
        invalidations_sent: Counter,
        invalidations_received: Counter,
    }

    impl Families {
        pub(super) fn register(registry: &mut Registry) -> Self {
            let families = Families {
                lookups: Family::default(),
                invalidations_sent: Counter::default(),
                invalidations_received: Counter::default(),
            };
            registry.register(
                "forge_cache_lookups",
                "Cache lookups, by tier and result (hit or miss)",
                families.lookups.clone(),
            );
            registry.register(
                "forge_cache_invalidations_sent",
                "Cache invalidations this instance made",
                families.invalidations_sent.clone(),
            );
            registry.register(
                "forge_cache_invalidations_received",
                "Cache invalidations received from other instances over the backplane",
                families.invalidations_received.clone(),
            );
            families
        }
    }

    /// Record a lookup in `tier`.
    pub fn lookup(tier: Tier, hit: bool) {
        let result = if hit { "hit" } else { "miss" };
        METRICS
            .cache
            .lookups
            .get_or_create(&LookupLabels { tier, result })
            .inc();
    }

    /// Count an invalidation this instance made.
    pub fn invalidation_sent() {
        METRICS.cache.invalidations_sent.inc();
    }

    /// Count an invalidation received from another instance.
    pub fn invalidation_received() {
        METRICS.cache.invalidations_received.inc();
    }
}

/// The database connection pool.
pub mod db {
    use std::time::Duration;

    use super::*;

    pub(super) struct Families {
        acquire: Histogram,
        acquire_timeouts: Counter,
    }

    impl Families {
        pub(super) fn register(registry: &mut Registry) -> Self {
            let families = Families {
                acquire: acquire_histogram(),
                acquire_timeouts: Counter::default(),
            };
            registry.register(
                "forge_db_pool_acquire_duration_seconds",
                "Time a database connection took to acquire from the pool",
                families.acquire.clone(),
            );
            registry.register(
                "forge_db_pool_acquire_timeouts",
                "Requests for a database connection that timed out \
                 (database.acquire_timeout_seconds)",
                families.acquire_timeouts.clone(),
            );
            families
        }
    }

    /// Record a connection acquired after `elapsed`.
    pub fn acquired(elapsed: Duration) {
        METRICS.db.acquire.observe(elapsed.as_secs_f64());
    }

    /// Count an acquire that timed out.
    pub fn acquire_timeout() {
        METRICS.db.acquire_timeouts.inc();
    }
}

/// The background workers.
pub mod workers {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use prometheus_client::metrics::gauge::Gauge;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct WorkerLabels {
        worker: &'static str,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct RunLabels {
        worker: &'static str,
        outcome: &'static str,
    }

    type FloatGauge = Gauge<f64, std::sync::atomic::AtomicU64>;

    pub(super) struct Families {
        restarts: Family<WorkerLabels, Counter>,
        runs: Family<RunLabels, Counter>,
        last_success: Family<WorkerLabels, FloatGauge>,
        interval: Family<WorkerLabels, FloatGauge>,
        duration: HistogramFamily<WorkerLabels>,
    }

    impl Families {
        pub(super) fn register(registry: &mut Registry) -> Self {
            let families = Families {
                restarts: Family::default(),
                runs: Family::default(),
                last_success: Family::default(),
                interval: Family::default(),
                duration: Family::new_with_constructor(run_histogram),
            };
            registry.register(
                "forge_worker_restarts",
                "Background worker loops restarted after a panic or exit",
                families.restarts.clone(),
            );
            registry.register(
                "forge_worker_runs",
                "Passes of background workers, by outcome (success or failure)",
                families.runs.clone(),
            );
            registry.register(
                "forge_worker_last_success_timestamp_seconds",
                "Unix time of a background worker's last successful pass",
                families.last_success.clone(),
            );
            registry.register(
                "forge_worker_interval_seconds",
                "How often a background worker runs a pass",
                families.interval.clone(),
            );
            registry.register(
                "forge_worker_run_duration_seconds",
                "Time a background worker's pass took",
                families.duration.clone(),
            );
            families
        }
    }

    /// Count a restart of worker `worker`.
    pub fn restarted(worker: &'static str) {
        METRICS
            .workers
            .restarts
            .get_or_create(&WorkerLabels { worker })
            .inc();
    }

    /// Record that worker `worker` runs a pass every `interval`.
    pub fn set_interval(worker: &'static str, interval: Duration) {
        METRICS
            .workers
            .interval
            .get_or_create(&WorkerLabels { worker })
            .set(interval.as_secs_f64());
    }

    /// One pass of a worker, recorded when [finished](Self::finish) (a pass
    /// dropped unfinished, aborted at shutdown, is not recorded).
    pub struct Run {
        worker: &'static str,
        started: Instant,
    }

    impl Run {
        /// Start a pass of worker `worker`.
        pub fn start(worker: &'static str) -> Run {
            Run {
                worker,
                started: Instant::now(),
            }
        }

        /// The pass is done: `ok` if it succeeded.
        pub fn finish(self, ok: bool) {
            let workers = &METRICS.workers;
            let labels = WorkerLabels {
                worker: self.worker,
            };
            workers
                .duration
                .get_or_create(&labels)
                .observe(self.started.elapsed().as_secs_f64());
            workers
                .runs
                .get_or_create(&RunLabels {
                    worker: self.worker,
                    outcome: if ok { "success" } else { "failure" },
                })
                .inc();
            if ok {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();
                workers.last_success.get_or_create(&labels).set(now);
            }
        }
    }
}

/// Retention runs.
pub mod retention {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct RunLabels {
        repo: String,
        outcome: &'static str,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct VersionLabels {
        repo: String,
        action: &'static str,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct RepoLabels {
        repo: String,
    }

    pub(super) struct Families {
        runs: Family<RunLabels, Counter>,
        versions: Family<VersionLabels, Counter>,
        freed: Family<RepoLabels, Counter>,
    }

    impl Families {
        pub(super) fn register(registry: &mut Registry) -> Self {
            let families = Families {
                runs: Family::default(),
                versions: Family::default(),
                freed: Family::default(),
            };
            registry.register(
                "forge_retention_runs",
                "Retention runs, by repository and outcome (success or failure)",
                families.runs.clone(),
            );
            registry.register(
                "forge_retention_versions",
                "Versions retention unlisted or deleted, by repository and action",
                families.versions.clone(),
            );
            registry.register(
                "forge_retention_freed_bytes",
                "Bytes retention runs removed from a repository (its size before the \
                 run less its size after)",
                families.freed.clone(),
            );
            families
        }
    }

    /// Record a retention run of `repository`: whether it succeeded, the
    /// versions it unlisted and deleted, and the bytes it freed (dry runs
    /// change nothing and record zeros).
    pub fn run(repository: &str, ok: bool, unlisted: u64, deleted: u64, freed_bytes: u64) {
        let retention = &METRICS.retention;
        let repo = repo(repository);
        retention
            .runs
            .get_or_create(&RunLabels {
                repo: repo.clone(),
                outcome: if ok { "success" } else { "failure" },
            })
            .inc();
        if !ok {
            return;
        }
        for (action, count) in [("unlisted", unlisted), ("deleted", deleted)] {
            retention
                .versions
                .get_or_create(&VersionLabels {
                    repo: repo.clone(),
                    action,
                })
                .inc_by(count);
        }
        retention
            .freed
            .get_or_create(&RepoLabels { repo })
            .inc_by(freed_bytes);
    }
}

/// Sign-ins and the identity providers behind them.
pub mod auth {
    use super::*;

    label_enum! {
        /// The kind of realm that decided a sign-in.
        pub enum RealmType {
            Local => "local",
            CredentialForwarding => "credential_forwarding",
            Oidc => "oidc",
            WorkloadIdentity => "workload_identity",
            /// No realm decided (no realm knew the credential).
            None => "none",
        }
    }

    label_enum! {
        /// How a sign-in ended.
        pub enum SignInOutcome {
            Success => "success",
            /// The credential was wrong.
            Rejected => "rejected",
            /// A realm's upstream could not decide (fail-closed).
            Unavailable => "unavailable",
            /// Forge failed (its database).
            Error => "error",
        }
    }

    label_enum! {
        /// Why the login throttle refused an attempt.
        pub enum Throttle {
            /// The client and username used up their failures.
            Locked => "locked",
            /// Every remaining attempt stayed in flight for the whole wait.
            Busy => "busy",
        }
    }

    label_enum! {
        /// How a token exchange (trusted publishing) ended.
        pub enum ExchangeOutcome {
            Issued => "issued",
            Rejected => "rejected",
            Error => "error",
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct SignInLabels {
        realm_type: RealmType,
        outcome: SignInOutcome,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct ThrottleLabels {
        reason: Throttle,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct ExchangeLabels {
        outcome: ExchangeOutcome,
    }

    pub(super) struct Families {
        sign_ins: Family<SignInLabels, Counter>,
        throttled: Family<ThrottleLabels, Counter>,
        exchanges: Family<ExchangeLabels, Counter>,
        jwks_failures: Counter,
        forwarding_errors: Counter,
    }

    impl Families {
        pub(super) fn register(registry: &mut Registry) -> Self {
            let families = Families {
                sign_ins: Family::default(),
                throttled: Family::default(),
                exchanges: Family::default(),
                jwks_failures: Counter::default(),
                forwarding_errors: Counter::default(),
            };
            registry.register(
                "forge_auth_sign_ins",
                "Sign-ins (a password through the realms, an OIDC login), by realm type \
                 and outcome",
                families.sign_ins.clone(),
            );
            registry.register(
                "forge_auth_throttled",
                "Password attempts the login throttle refused, by reason",
                families.throttled.clone(),
            );
            registry.register(
                "forge_auth_token_exchanges",
                "Token exchanges of trusted publishing, by outcome",
                families.exchanges.clone(),
            );
            registry.register(
                "forge_auth_jwks_refresh_failures",
                "Failed fetches of an identity provider's signing keys (JWKS)",
                families.jwks_failures.clone(),
            );
            registry.register(
                "forge_auth_credential_forwarding_errors",
                "Credential-forwarding upstreams that could not decide a login \
                 (unreachable, a timeout, an unexpected answer)",
                families.forwarding_errors.clone(),
            );
            families
        }
    }

    /// Record a sign-in.
    pub fn sign_in(realm_type: RealmType, outcome: SignInOutcome) {
        METRICS
            .auth
            .sign_ins
            .get_or_create(&SignInLabels {
                realm_type,
                outcome,
            })
            .inc();
    }

    /// Count an attempt the throttle refused.
    pub fn throttled(reason: Throttle) {
        METRICS
            .auth
            .throttled
            .get_or_create(&ThrottleLabels { reason })
            .inc();
    }

    /// Record a token exchange.
    pub fn token_exchange(outcome: ExchangeOutcome) {
        METRICS
            .auth
            .exchanges
            .get_or_create(&ExchangeLabels { outcome })
            .inc();
    }

    /// Count a failed JWKS fetch.
    pub fn jwks_refresh_failed() {
        METRICS.auth.jwks_failures.inc();
    }

    /// Count a credential-forwarding upstream that could not decide.
    pub fn forwarding_error() {
        METRICS.auth.forwarding_errors.inc();
    }
}

/// What Forge holds, counted by a worker.
pub mod inventory {
    use prometheus_client::metrics::gauge::Gauge;

    use super::*;

    /// One repository's numbers.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RepositoryCount {
        /// Its format (a format plugin's id).
        pub format: String,
        /// `hosted`, `proxy` or `group`.
        pub kind: String,
        /// Its name.
        pub name: String,
        /// Versions (packages' versions, image tags, files), `None` for a
        /// group.
        pub versions: Option<u64>,
        /// Stored bytes, `None` for a group.
        pub bytes: Option<u64>,
    }

    static SNAPSHOT: Mutex<Option<Vec<RepositoryCount>>> = Mutex::new(None);

    /// Publish the repositories as a worker last counted them.
    pub fn publish(repositories: Vec<RepositoryCount>) {
        *SNAPSHOT.lock().unwrap_or_else(PoisonError::into_inner) = Some(repositories);
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct FormatKind {
        format: String,
        kind: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
    struct RepoLabels {
        repo: String,
    }

    pub(super) fn encode(registry: &mut Registry) {
        let snapshot = SNAPSHOT.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(repositories) = snapshot.as_ref() else {
            return;
        };
        let by_kind = Family::<FormatKind, Gauge>::default();
        let versions = Family::<RepoLabels, Gauge>::default();
        let bytes = Family::<RepoLabels, Gauge>::default();
        for r in repositories {
            by_kind
                .get_or_create(&FormatKind {
                    format: r.format.clone(),
                    kind: r.kind.clone(),
                })
                .inc();
            let labels = RepoLabels {
                repo: repo(&r.name),
            };
            if let Some(n) = r.versions {
                versions
                    .get_or_create(&labels)
                    .inc_by(i64::try_from(n).unwrap_or(i64::MAX));
            }
            if let Some(n) = r.bytes {
                bytes
                    .get_or_create(&labels)
                    .inc_by(i64::try_from(n).unwrap_or(i64::MAX));
            }
        }
        registry.register(
            "forge_repositories",
            "Repositories, by format and kind",
            by_kind,
        );
        registry.register(
            "forge_repository_versions",
            "Versions a repository holds (package versions, image tags, files)",
            versions,
        );
        registry.register(
            "forge_repository_stored_bytes",
            "Bytes a repository holds",
            bytes,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn scrape() -> String {
        let live = live::Snapshot {
            pool: Some(live::Pool {
                size: 5,
                idle: 2,
                max: 20,
            }),
            breaker_open: Some(false),
            blob_cache: Some(live::BlobCache {
                hits: 7,
                ..Default::default()
            }),
            staging: Some((1024, 4096)),
            backplane_connected: Some(true),
        };
        let mut out = String::new();
        encode(&mut out, &live).expect("encode");
        out
    }

    /// The label names of every sample line of `text`.
    fn label_names(text: &str) -> Vec<String> {
        let mut names = Vec::new();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let Some(open) = line.find('{') else { continue };
            let close = line.rfind('}').expect("closing brace");
            let mut rest = &line[open + 1..close];
            while let Some(eq) = rest.find("=\"") {
                names.push(rest[..eq].trim_start_matches(',').to_string());
                let value = &rest[eq + 2..];
                let end = value.find('"').expect("closing quote");
                rest = &value[end + 1..];
            }
        }
        names
    }

    /// Record a sample into every family, then check that each label the
    /// exposition carries is one of [`LABEL_NAMES`].
    #[test]
    fn every_label_is_a_known_one() {
        set_build_info("0.0.0-test", "abc");
        for &surface in http::Surface::ALL {
            http::request(surface, http::Method::Get, 200, Duration::from_millis(3));
            http::response_bytes(surface, 10);
        }
        drop(http::InFlight::start());
        for &kind in proxy::Kind::ALL {
            for &outcome in proxy::Outcome::ALL {
                proxy::lookup("proxy-repo", kind, outcome);
            }
        }
        let mut pending = proxy::Lookup::start("proxy-repo", proxy::Kind::Blob);
        pending.mark(proxy::Outcome::Fetched);
        let outcome = pending.marked().unwrap_or(proxy::Outcome::Hit);
        pending.finish(outcome);
        proxy::upstream_request("proxy-repo", Some(429), Duration::from_millis(5));
        proxy::upstream_request("proxy-repo", None, Duration::from_millis(5));
        proxy::upstream_bytes("proxy-repo", 100);
        for &op in storage::S3Op::ALL {
            for &outcome in storage::S3Outcome::ALL {
                storage::s3_operation(op, outcome, Duration::from_millis(2));
            }
        }
        storage::gc_deleted(storage::GcSource::Outbox, 1);
        storage::publish_outbox(storage::OutboxBacklog {
            pending: 3,
            due: 1,
            oldest_due_age_seconds: 12.5,
        });
        cache::lookup(cache::Tier::L1, true);
        cache::lookup(cache::Tier::L2, false);
        cache::invalidation_sent();
        cache::invalidation_received();
        db::acquired(Duration::from_millis(1));
        db::acquire_timeout();
        workers::restarted("outbox");
        workers::set_interval("outbox", Duration::from_secs(10));
        workers::Run::start("outbox").finish(true);
        workers::Run::start("outbox").finish(false);
        retention::run("hosted-repo", true, 1, 2, 300);
        retention::run("hosted-repo", false, 0, 0, 0);
        for &realm in auth::RealmType::ALL {
            for &outcome in auth::SignInOutcome::ALL {
                auth::sign_in(realm, outcome);
            }
        }
        auth::throttled(auth::Throttle::Locked);
        auth::token_exchange(auth::ExchangeOutcome::Issued);
        auth::jwks_refresh_failed();
        auth::forwarding_error();
        inventory::publish(vec![inventory::RepositoryCount {
            format: "nuget".into(),
            kind: "hosted".into(),
            name: "hosted-repo".into(),
            versions: Some(4),
            bytes: Some(4096),
        }]);

        let text = scrape();
        assert!(text.ends_with("# EOF\n"), "{text}");
        for name in label_names(&text) {
            assert!(
                LABEL_NAMES.contains(&name.as_str()),
                "label {name:?} is not in LABEL_NAMES:\n{text}"
            );
        }
        for expected in [
            "forge_build_info{version=\"0.0.0-test\",commit=\"abc\"} 1",
            "forge_http_requests_total{surface=\"nuget\",method=\"GET\",status=\"2xx\"}",
            "forge_proxy_upstream_rate_limited_total{repo=\"proxy-repo\"} ",
            "forge_outbox_due 1",
            "forge_repository_stored_bytes{repo=\"hosted-repo\"} 4096",
            "forge_repositories{format=\"nuget\",kind=\"hosted\"} 1",
            "forge_worker_runs_total{worker=\"outbox\",outcome=\"failure\"}",
            "forge_db_pool_connections{state=\"in_use\"} 3",
            "forge_blob_cache_hits_total 7",
            "forge_staging_bytes 1024",
            "forge_cache_redis_backplane_connected 1",
        ] {
            assert!(text.contains(expected), "{expected:?} missing:\n{text}");
        }
    }

    #[test]
    fn statuses_fall_in_their_class() {
        assert_eq!(http::StatusClass::of(204), http::StatusClass::Success);
        assert_eq!(http::StatusClass::of(404), http::StatusClass::ClientError);
        assert_eq!(http::StatusClass::of(503), http::StatusClass::ServerError);
        assert_eq!(
            proxy::UpstreamStatus::of(429),
            proxy::UpstreamStatus::RateLimited
        );
        assert_eq!(
            proxy::UpstreamStatus::of(404),
            proxy::UpstreamStatus::ClientError
        );
        assert_eq!(http::Method::of("PROPFIND"), http::Method::Other);
    }
}
