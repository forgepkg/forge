//! Forge's telemetry: OpenTelemetry metrics, and the `tracing` spans that
//! become OpenTelemetry traces.
//!
//! The crates record through this crate's modules; `forge-server` sets up the
//! OpenTelemetry SDK and exports metrics, traces and logs over OTLP. Each
//! instrument is declared once, here, on the meter [`init`] is given. Until
//! then (or without one: telemetry off) recording does nothing.
//!
//! * **Attributes stay bounded.** An attribute value is one the code chooses
//!   (a surface, an outcome, an operation) or, for the repository, a name an
//!   administrator chose. No metric attribute carries a package id, a
//!   version, an image name or tag, a username, a token or a path; every
//!   attribute key is one of [`ATTRIBUTE_KEYS`]. [`set_per_repository`]
//!   drops the repository attribute.
//! * **Recording is cheap.** An instrument update is an atomic add on the
//!   SDK's aggregation; nothing here does I/O. Values that need a database
//!   query (the outbox backlog, the inventory) are computed by a worker and
//!   published as a snapshot ([`storage::publish_outbox`],
//!   [`inventory::publish`]); values the process keeps anyway (the pool's
//!   sizes, the blob cache's counters) are read when the SDK collects
//!   ([`live::set_source`]).
//! * **Spans** are `tracing` spans of the target [`TARGET`], which
//!   `forge-server` exports as OpenTelemetry spans (and keeps out of its
//!   console log). Their fields use OpenTelemetry's names: `otel.name`,
//!   `otel.kind`, `otel.status_code` and semantic-convention attributes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError, RwLock};

use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter, UpDownCounter};
use opentelemetry::KeyValue;

/// The `tracing` target of the spans meant for export as OpenTelemetry
/// spans.
pub const TARGET: &str = "forge::otel";

/// Every attribute key a Forge metric may carry. A test fails when a metric
/// gets another one.
pub const ATTRIBUTE_KEYS: &[&str] = &[
    "db.client.connection.pool.name",
    "db.client.connection.state",
    "error.type",
    "forge.auth.exchange.outcome",
    "forge.auth.outcome",
    "forge.auth.realm_type",
    "forge.auth.throttle.reason",
    "forge.cache.direction",
    "forge.cache.result",
    "forge.cache.tier",
    "forge.gc.source",
    "forge.proxy.kind",
    "forge.proxy.outcome",
    "forge.repository",
    "forge.repository.format",
    "forge.repository.kind",
    "forge.retention.action",
    "forge.retention.outcome",
    "forge.s3.operation",
    "forge.s3.outcome",
    "forge.surface",
    "forge.worker",
    "forge.worker.outcome",
    "http.request.method",
    "http.response.status_code",
];

static PER_REPOSITORY: AtomicBool = AtomicBool::new(true);

/// Whether metrics carry the repository name (`telemetry.per_repository`,
/// default on). Off, the repositories' measurements add up.
pub fn set_per_repository(enabled: bool) {
    PER_REPOSITORY.store(enabled, Ordering::Relaxed);
}

/// The repository attribute of repository `name`, unless turned off.
fn repo(name: &str) -> Option<KeyValue> {
    PER_REPOSITORY
        .load(Ordering::Relaxed)
        .then(|| KeyValue::new("forge.repository", name.to_string()))
}

/// `attributes` with the repository's, unless turned off.
fn with_repo<const N: usize>(name: &str, attributes: [KeyValue; N]) -> Vec<KeyValue> {
    let mut all = Vec::with_capacity(N + 1);
    all.extend(repo(name));
    all.extend(attributes);
    all
}

/// Declare an attribute value enum: its variants and the text each is.
macro_rules! value_enum {
    ($(#[$meta:meta])* pub enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)*
        }

        impl $name {
            /// The attribute value.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)*
                }
            }

            /// Every value (tests).
            pub const ALL: &'static [$name] = &[$($name::$variant,)*];
        }
    };
}

/// Buckets of request and operation durations, in seconds: the semantic
/// conventions' HTTP buckets, stretched to the slow pushes and downloads a
/// package registry sees.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0, 30.0, 60.0,
    120.0,
];

/// Buckets of database connection waits, in seconds.
const WAIT_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Buckets of worker pass durations, in seconds.
const RUN_BUCKETS: &[f64] = &[
    0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0,
];

/// Buckets of response body sizes, in bytes.
const SIZE_BUCKETS: &[f64] = &[
    0.0,
    1024.0,
    16384.0,
    131072.0,
    1048576.0,
    8388608.0,
    67108864.0,
    536870912.0,
    4294967296.0,
];

/// The instruments, built once on the meter [`init`] is given.
struct Instruments {
    http_duration: Histogram<f64>,
    http_active: UpDownCounter<i64>,
    http_body_size: Histogram<u64>,
    proxy_lookups: Counter<u64>,
    upstream_duration: Histogram<f64>,
    upstream_fetched: Counter<u64>,
    s3_duration: Histogram<f64>,
    gc_deleted: Counter<u64>,
    cache_lookups: Counter<u64>,
    cache_invalidations: Counter<u64>,
    db_wait: Histogram<f64>,
    db_timeouts: Counter<u64>,
    worker_runs: Counter<u64>,
    worker_duration: Histogram<f64>,
    worker_last_success: Gauge<f64>,
    worker_interval: Gauge<f64>,
    worker_restarts: Counter<u64>,
    retention_runs: Counter<u64>,
    retention_versions: Counter<u64>,
    retention_freed: Counter<u64>,
    sign_ins: Counter<u64>,
    throttled: Counter<u64>,
    exchanges: Counter<u64>,
    jwks_failures: Counter<u64>,
    forwarding_errors: Counter<u64>,
}

static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();

/// The instruments, `None` before [`init`].
fn instruments() -> Option<&'static Instruments> {
    INSTRUMENTS.get()
}

/// Whether the metrics record: [`init`] was called.
pub fn enabled() -> bool {
    INSTRUMENTS.get().is_some()
}

/// The W3C trace context (`traceparent`, `tracestate`) of the current span,
/// as the headers of a request that continues its trace. None without the
/// trace export (the propagator is the no-op one then).
pub fn trace_headers() -> Vec<(String, String)> {
    struct Headers(Vec<(String, String)>);
    impl opentelemetry::propagation::Injector for Headers {
        fn set(&mut self, key: &str, value: String) {
            self.0.push((key.to_string(), value));
        }
    }
    let mut headers = Headers(Vec::new());
    opentelemetry::global::get_text_map_propagator(|propagator| propagator.inject(&mut headers));
    headers.0
}

/// Build Forge's instruments on `meter` (the server's, from the SDK it set
/// up) and start recording. Only the first call counts.
pub fn init(meter: &Meter) {
    if INSTRUMENTS.get().is_some() {
        return;
    }
    let duration = |name: &'static str, description: &'static str, buckets: &[f64]| {
        meter
            .f64_histogram(name)
            .with_unit("s")
            .with_description(description)
            .with_boundaries(buckets.to_vec())
            .build()
    };
    let counter = |name: &'static str, unit: &'static str, description: &'static str| {
        meter
            .u64_counter(name)
            .with_unit(unit)
            .with_description(description)
            .build()
    };
    let instruments = Instruments {
        http_duration: duration(
            "http.server.request.duration",
            "Time from receiving an HTTP request to sending its response headers",
            DURATION_BUCKETS,
        ),
        http_active: meter
            .i64_up_down_counter("http.server.active_requests")
            .with_unit("{request}")
            .with_description("HTTP requests being handled")
            .build(),
        http_body_size: meter
            .u64_histogram("http.server.response.body.size")
            .with_unit("By")
            .with_description("Size of HTTP response bodies sent")
            .with_boundaries(SIZE_BUCKETS.to_vec())
            .build(),
        proxy_lookups: counter(
            "forge.proxy.lookups",
            "{lookup}",
            "Proxy lookups, by repository, kind and outcome",
        ),
        upstream_duration: duration(
            "http.client.request.duration",
            "Time from sending a proxy's upstream request to its response headers",
            DURATION_BUCKETS,
        ),
        upstream_fetched: counter(
            "forge.proxy.upstream.fetched",
            "By",
            "Bytes proxy repositories fetched from their upstreams",
        ),
        s3_duration: duration(
            "forge.s3.operation.duration",
            "Time an S3 operation took (to its response headers for a download)",
            DURATION_BUCKETS,
        ),
        gc_deleted: counter(
            "forge.gc.deleted",
            "{blob}",
            "Blobs deleted from S3, by who deleted them",
        ),
        cache_lookups: counter(
            "forge.cache.lookups",
            "{lookup}",
            "Cache lookups, by tier and result (hit or miss)",
        ),
        cache_invalidations: counter(
            "forge.cache.invalidations",
            "{invalidation}",
            "Cache invalidations made here (sent) and heard from other instances (received)",
        ),
        db_wait: duration(
            "db.client.connection.wait_time",
            "Time a database connection took to acquire from the pool",
            WAIT_BUCKETS,
        ),
        db_timeouts: counter(
            "db.client.connection.timeouts",
            "{timeout}",
            "Requests for a database connection that timed out \
             (database.acquire_timeout_seconds)",
        ),
        worker_runs: counter(
            "forge.worker.runs",
            "{run}",
            "Passes of background workers, by outcome (success or failure)",
        ),
        worker_duration: duration(
            "forge.worker.run.duration",
            "Time a background worker's pass took",
            RUN_BUCKETS,
        ),
        worker_last_success: meter
            .f64_gauge("forge.worker.last_success.time")
            .with_unit("s")
            .with_description("Unix time of a background worker's last successful pass")
            .build(),
        worker_interval: meter
            .f64_gauge("forge.worker.interval")
            .with_unit("s")
            .with_description("How often a background worker runs a pass")
            .build(),
        worker_restarts: counter(
            "forge.worker.restarts",
            "{restart}",
            "Background worker loops restarted after a panic or exit",
        ),
        retention_runs: counter(
            "forge.retention.runs",
            "{run}",
            "Retention runs, by repository and outcome (success or failure)",
        ),
        retention_versions: counter(
            "forge.retention.versions",
            "{version}",
            "Versions retention unlisted or deleted, by repository and action",
        ),
        retention_freed: counter(
            "forge.retention.freed",
            "By",
            "Bytes retention runs removed from a repository (its size before a run less \
             its size after)",
        ),
        sign_ins: counter(
            "forge.auth.sign_ins",
            "{sign_in}",
            "Sign-ins (a password through the realms, an OIDC login), by realm type and \
             outcome",
        ),
        throttled: counter(
            "forge.auth.throttled",
            "{attempt}",
            "Password attempts the login throttle refused, by reason",
        ),
        exchanges: counter(
            "forge.auth.token_exchanges",
            "{exchange}",
            "Token exchanges of trusted publishing, by outcome",
        ),
        jwks_failures: counter(
            "forge.auth.jwks.refresh_failures",
            "{failure}",
            "Failed fetches of an identity provider's signing keys (JWKS)",
        ),
        forwarding_errors: counter(
            "forge.auth.forwarding.errors",
            "{error}",
            "Credential-forwarding upstreams that could not decide a login (unreachable, \
             a timeout, an unexpected answer)",
        ),
    };
    live::register(meter);
    storage::register_outbox(meter);
    inventory::register(meter);
    let _ = INSTRUMENTS.set(instruments);
}

/// HTTP requests of the server.
pub mod http {
    use std::time::Duration;

    use super::*;

    value_enum! {
        /// Which part of Forge a request is for, from the route it matched.
        pub enum Surface {
            /// `/v2`: the Docker / OCI registry.
            Oci => "oci",
            /// `/repository/…` of a NuGet repository.
            Nuget => "nuget",
            /// `/repository/…` of a repository of another format plugin
            /// ([`plugin_surface`]).
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
    /// `plugin_other` for any other, so the attribute stays bounded.
    pub fn plugin_surface(format: &str) -> Surface {
        match format {
            "nuget" => Surface::Nuget,
            "npm" => Surface::PluginNpm,
            "raw" => Surface::PluginRaw,
            "docker" => Surface::Oci,
            _ => Surface::PluginOther,
        }
    }

    /// A request method as the semantic conventions name it: the known
    /// methods as they are, any other `_OTHER`.
    pub fn method(name: &str) -> &'static str {
        match name {
            "GET" => "GET",
            "HEAD" => "HEAD",
            "POST" => "POST",
            "PUT" => "PUT",
            "PATCH" => "PATCH",
            "DELETE" => "DELETE",
            "OPTIONS" => "OPTIONS",
            "CONNECT" => "CONNECT",
            "TRACE" => "TRACE",
            _ => "_OTHER",
        }
    }

    fn attributes(surface: Surface, method: &str, status: u16) -> [KeyValue; 3] {
        [
            KeyValue::new("forge.surface", surface.as_str()),
            KeyValue::new("http.request.method", self::method(method)),
            KeyValue::new("http.response.status_code", i64::from(status)),
        ]
    }

    /// Record an answered request: its response headers were ready after
    /// `elapsed`.
    pub fn request(surface: Surface, method: &str, status: u16, elapsed: Duration) {
        if let Some(i) = instruments() {
            i.http_duration
                .record(elapsed.as_secs_f64(), &attributes(surface, method, status));
        }
    }

    /// Record a response body of `bytes`, sent in full or cut off.
    pub fn response_size(surface: Surface, method: &str, status: u16, bytes: u64) {
        if let Some(i) = instruments() {
            i.http_body_size
                .record(bytes, &attributes(surface, method, status));
        }
    }

    /// A request being handled, counted in `http.server.active_requests`
    /// until dropped.
    pub struct Active(&'static str);

    impl Active {
        /// Start counting a request of `method`.
        pub fn start(method: &str) -> Active {
            let method = self::method(method);
            if let Some(i) = instruments() {
                i.http_active
                    .add(1, &[KeyValue::new("http.request.method", method)]);
            }
            Active(method)
        }
    }

    impl Drop for Active {
        fn drop(&mut self) {
            if let Some(i) = instruments() {
                i.http_active
                    .add(-1, &[KeyValue::new("http.request.method", self.0)]);
            }
        }
    }
}

/// Proxy repositories and their upstreams.
pub mod proxy {
    use std::time::Duration;

    use super::*;

    value_enum! {
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

    value_enum! {
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

    /// A lookup in progress, with its span (`proxy lookup`): the paths it
    /// takes mark what they found ([`Self::mark`]), the caller runs it in
    /// [`Self::span`] and records it once it has the answer
    /// ([`Self::finish`]). A lookup dropped unfinished (its request was
    /// cancelled) records nothing.
    pub struct Lookup {
        repository: String,
        kind: Kind,
        marked: Option<Outcome>,
        span: tracing::Span,
    }

    impl Lookup {
        /// Start a lookup of `kind` in proxy repository `repository`.
        pub fn start(repository: &str, kind: Kind) -> Lookup {
            let span = tracing::info_span!(
                target: crate::TARGET,
                "proxy lookup",
                otel.name = %format!("proxy {}", kind.as_str()),
                otel.kind = "internal",
                otel.status_code = tracing::field::Empty,
                "forge.repository" = repository,
                "forge.proxy.kind" = kind.as_str(),
                "forge.proxy.outcome" = tracing::field::Empty,
            );
            Lookup {
                repository: repository.to_string(),
                kind,
                marked: None,
                span,
            }
        }

        /// The lookup's span, to run it in.
        pub fn span(&self) -> tracing::Span {
            self.span.clone()
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
            self.span.record("forge.proxy.outcome", outcome.as_str());
            if matches!(outcome, Outcome::UpstreamError | Outcome::Error) {
                self.span.record("otel.status_code", "ERROR");
            }
            if let Some(i) = instruments() {
                i.proxy_lookups.add(
                    1,
                    &with_repo(
                        &self.repository,
                        [
                            KeyValue::new("forge.proxy.kind", self.kind.as_str()),
                            KeyValue::new("forge.proxy.outcome", outcome.as_str()),
                        ],
                    ),
                );
            }
        }
    }

    /// Record a request proxy `repository` sent its upstream with `method`:
    /// answered with `status` after `elapsed`, or not answered (`None`).
    pub fn upstream_request(
        repository: &str,
        method: &str,
        status: Option<u16>,
        elapsed: Duration,
    ) {
        let Some(i) = instruments() else { return };
        let method = KeyValue::new("http.request.method", crate::http::method(method));
        let attributes = match status {
            Some(status) => with_repo(
                repository,
                [
                    method,
                    KeyValue::new("http.response.status_code", i64::from(status)),
                ],
            ),
            None => with_repo(
                repository,
                [method, KeyValue::new("error.type", "transport")],
            ),
        };
        i.upstream_duration
            .record(elapsed.as_secs_f64(), &attributes);
    }

    /// Count `bytes` proxy `repository` fetched from its upstream.
    pub fn upstream_bytes(repository: &str, bytes: u64) {
        if let Some(i) = instruments() {
            i.upstream_fetched.add(bytes, &with_repo(repository, []));
        }
    }
}

/// The object store, garbage collection and the outbox.
pub mod storage {
    use std::time::{Duration, Instant};

    use super::*;

    value_enum! {
        /// An S3 operation (its `rpc.method` in a span).
        pub enum S3Op {
            HeadBucket => "HeadBucket",
            CreateBucket => "CreateBucket",
            Head => "HeadObject",
            Put => "PutObject",
            PutConditional => "PutObjectIfAbsent",
            CreateMultipart => "CreateMultipartUpload",
            UploadPart => "UploadPart",
            CompleteMultipart => "CompleteMultipartUpload",
            AbortMultipart => "AbortMultipartUpload",
            Get => "GetObject",
            List => "ListObjectsV2",
            Delete => "DeleteObject",
        }
    }

    value_enum! {
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

    value_enum! {
        /// Who deleted a blob from S3.
        pub enum GcSource {
            /// The outbox worker (deletes deferred by garbage collection).
            Outbox => "outbox",
            /// The orphan reconciler (blobs never committed).
            Reconciler => "reconciler",
        }
    }

    /// One S3 operation, with its client span (`S3.<operation>`): run the
    /// call in [`Self::span`], then [`Self::finish`] it.
    pub struct S3Call {
        op: S3Op,
        started: Instant,
        span: tracing::Span,
    }

    impl S3Call {
        /// Start operation `op` on `bucket`.
        pub fn start(op: S3Op, bucket: &str) -> S3Call {
            let span = tracing::info_span!(
                target: crate::TARGET,
                "s3",
                otel.name = %format!("S3.{}", op.as_str()),
                otel.kind = "client",
                otel.status_code = tracing::field::Empty,
                "rpc.system" = "aws-api",
                "rpc.service" = "S3",
                "rpc.method" = op.as_str(),
                "aws.s3.bucket" = bucket,
                "forge.s3.outcome" = tracing::field::Empty,
            );
            S3Call {
                op,
                started: Instant::now(),
                span,
            }
        }

        /// The operation's span, to run it in.
        pub fn span(&self) -> tracing::Span {
            self.span.clone()
        }

        /// The operation ended with `outcome`.
        pub fn finish(self, outcome: S3Outcome) {
            self.span.record("forge.s3.outcome", outcome.as_str());
            if matches!(outcome, S3Outcome::Unreachable | S3Outcome::Error) {
                self.span.record("otel.status_code", "ERROR");
            }
            s3_operation(self.op, outcome, self.started.elapsed());
        }
    }

    /// Record an S3 operation that ended with `outcome` after `elapsed`
    /// (refused by the open breaker: no time at all).
    pub fn s3_operation(op: S3Op, outcome: S3Outcome, elapsed: Duration) {
        if let Some(i) = instruments() {
            i.s3_duration.record(
                elapsed.as_secs_f64(),
                &[
                    KeyValue::new("forge.s3.operation", op.as_str()),
                    KeyValue::new("forge.s3.outcome", outcome.as_str()),
                ],
            );
        }
    }

    /// Count `blobs` that `source` deleted from S3.
    pub fn gc_deleted(source: GcSource, blobs: u64) {
        if let Some(i) = instruments() {
            i.gc_deleted
                .add(blobs, &[KeyValue::new("forge.gc.source", source.as_str())]);
        }
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

    fn outbox() -> Option<OutboxBacklog> {
        *OUTBOX.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn register_outbox(meter: &Meter) {
        meter
            .u64_observable_gauge("forge.outbox.pending")
            .with_unit("{delete}")
            .with_description("Deferred S3 deletes not processed yet (a worker's last count)")
            .with_callback(|o| {
                if let Some(b) = outbox() {
                    o.observe(b.pending, &[]);
                }
            })
            .build();
        meter
            .u64_observable_gauge("forge.outbox.due")
            .with_unit("{delete}")
            .with_description("Deferred S3 deletes that are due and not processed yet")
            .with_callback(|o| {
                if let Some(b) = outbox() {
                    o.observe(b.due, &[]);
                }
            })
            .build();
        meter
            .f64_observable_gauge("forge.outbox.oldest_due.age")
            .with_unit("s")
            .with_description("How long the oldest unprocessed due delete has been due")
            .with_callback(|o| {
                if let Some(b) = outbox() {
                    o.observe(b.oldest_due_age_seconds, &[]);
                }
            })
            .build();
    }
}

/// The cache (in-process L1, Redis L2 and its invalidation backplane).
pub mod cache {
    use super::*;

    value_enum! {
        /// A cache tier.
        pub enum Tier {
            L1 => "l1",
            L2 => "l2",
        }
    }

    /// Record a lookup in `tier`.
    pub fn lookup(tier: Tier, hit: bool) {
        if let Some(i) = instruments() {
            i.cache_lookups.add(
                1,
                &[
                    KeyValue::new("forge.cache.tier", tier.as_str()),
                    KeyValue::new("forge.cache.result", if hit { "hit" } else { "miss" }),
                ],
            );
        }
    }

    /// Count an invalidation this instance made.
    pub fn invalidation_sent() {
        if let Some(i) = instruments() {
            i.cache_invalidations
                .add(1, &[KeyValue::new("forge.cache.direction", "sent")]);
        }
    }

    /// Count an invalidation received from another instance.
    pub fn invalidation_received() {
        if let Some(i) = instruments() {
            i.cache_invalidations
                .add(1, &[KeyValue::new("forge.cache.direction", "received")]);
        }
    }
}

/// The database connection pool.
pub mod db {
    use std::time::Duration;

    use super::*;

    /// Record a connection acquired after `elapsed`.
    pub fn acquired(elapsed: Duration) {
        if let Some(i) = instruments() {
            i.db_wait.record(elapsed.as_secs_f64(), &[pool()]);
        }
    }

    /// Count an acquire that timed out.
    pub fn acquire_timeout() {
        if let Some(i) = instruments() {
            i.db_timeouts.add(1, &[pool()]);
        }
    }

    /// The pool's name, as the semantic conventions want one.
    pub(super) fn pool() -> KeyValue {
        KeyValue::new("db.client.connection.pool.name", "forge")
    }
}

/// The background workers.
pub mod workers {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::*;

    /// Count a restart of worker `worker`.
    pub fn restarted(worker: &'static str) {
        if let Some(i) = instruments() {
            i.worker_restarts
                .add(1, &[KeyValue::new("forge.worker", worker)]);
        }
    }

    /// Record that worker `worker` runs a pass every `interval`.
    pub fn set_interval(worker: &'static str, interval: Duration) {
        if let Some(i) = instruments() {
            i.worker_interval.record(
                interval.as_secs_f64(),
                &[KeyValue::new("forge.worker", worker)],
            );
        }
    }

    /// One pass of a worker, with its span (a trace of its own, `worker
    /// pass`): run the pass in [`Self::span`] and record it when
    /// [finished](Self::finish). A pass dropped unfinished, aborted at
    /// shutdown, is not recorded.
    pub struct Run {
        worker: &'static str,
        started: Instant,
        span: tracing::Span,
    }

    impl Run {
        /// Start a pass of worker `worker`.
        pub fn start(worker: &'static str) -> Run {
            let span = tracing::info_span!(
                target: crate::TARGET,
                parent: None,
                "worker pass",
                otel.name = %format!("{worker} pass"),
                otel.kind = "internal",
                otel.status_code = tracing::field::Empty,
                "forge.worker" = worker,
                "forge.worker.outcome" = tracing::field::Empty,
            );
            Run {
                worker,
                started: Instant::now(),
                span,
            }
        }

        /// The pass's span, to run it in.
        pub fn span(&self) -> tracing::Span {
            self.span.clone()
        }

        /// The pass is done: `ok` if it succeeded.
        pub fn finish(self, ok: bool) {
            let outcome = if ok { "success" } else { "failure" };
            self.span.record("forge.worker.outcome", outcome);
            if !ok {
                self.span.record("otel.status_code", "ERROR");
            }
            let Some(i) = instruments() else { return };
            let worker = KeyValue::new("forge.worker", self.worker);
            i.worker_duration.record(
                self.started.elapsed().as_secs_f64(),
                std::slice::from_ref(&worker),
            );
            i.worker_runs.add(
                1,
                &[
                    worker.clone(),
                    KeyValue::new("forge.worker.outcome", outcome),
                ],
            );
            if ok {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();
                i.worker_last_success.record(now, &[worker]);
            }
        }
    }
}

/// Retention runs.
pub mod retention {
    use super::*;

    /// Record a retention run of `repository`: whether it succeeded, the
    /// versions it unlisted and deleted, and the bytes it freed (dry runs
    /// change nothing and record zeros).
    pub fn run(repository: &str, ok: bool, unlisted: u64, deleted: u64, freed_bytes: u64) {
        let Some(i) = instruments() else { return };
        let outcome = if ok { "success" } else { "failure" };
        i.retention_runs.add(
            1,
            &with_repo(
                repository,
                [KeyValue::new("forge.retention.outcome", outcome)],
            ),
        );
        if !ok {
            return;
        }
        for (action, count) in [("unlisted", unlisted), ("deleted", deleted)] {
            i.retention_versions.add(
                count,
                &with_repo(
                    repository,
                    [KeyValue::new("forge.retention.action", action)],
                ),
            );
        }
        i.retention_freed
            .add(freed_bytes, &with_repo(repository, []));
    }
}

/// Sign-ins and the identity providers behind them.
pub mod auth {
    use super::*;

    value_enum! {
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

    value_enum! {
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

    value_enum! {
        /// Why the login throttle refused an attempt.
        pub enum Throttle {
            /// The client and username used up their failures.
            Locked => "locked",
            /// Every remaining attempt stayed in flight for the whole wait.
            Busy => "busy",
        }
    }

    value_enum! {
        /// How a token exchange (trusted publishing) ended.
        pub enum ExchangeOutcome {
            Issued => "issued",
            Rejected => "rejected",
            Error => "error",
        }
    }

    /// Record a sign-in.
    pub fn sign_in(realm_type: RealmType, outcome: SignInOutcome) {
        if let Some(i) = instruments() {
            i.sign_ins.add(
                1,
                &[
                    KeyValue::new("forge.auth.realm_type", realm_type.as_str()),
                    KeyValue::new("forge.auth.outcome", outcome.as_str()),
                ],
            );
        }
    }

    /// Count an attempt the throttle refused.
    pub fn throttled(reason: Throttle) {
        if let Some(i) = instruments() {
            i.throttled.add(
                1,
                &[KeyValue::new("forge.auth.throttle.reason", reason.as_str())],
            );
        }
    }

    /// Record a token exchange.
    pub fn token_exchange(outcome: ExchangeOutcome) {
        if let Some(i) = instruments() {
            i.exchanges.add(
                1,
                &[KeyValue::new(
                    "forge.auth.exchange.outcome",
                    outcome.as_str(),
                )],
            );
        }
    }

    /// Count a failed JWKS fetch.
    pub fn jwks_refresh_failed() {
        if let Some(i) = instruments() {
            i.jwks_failures.add(1, &[]);
        }
    }

    /// Count a credential-forwarding upstream that could not decide.
    pub fn forwarding_error() {
        if let Some(i) = instruments() {
            i.forwarding_errors.add(1, &[]);
        }
    }
}

/// What Forge holds, counted by a worker.
pub mod inventory {
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

    /// Call `f` with the last snapshot, if there is one.
    fn with_snapshot(f: impl FnOnce(&[RepositoryCount])) {
        if let Some(repositories) = SNAPSHOT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
        {
            f(repositories);
        }
    }

    /// Observe `value` of every repository that has one, added up per
    /// repository attribute (one sum without the repository attributes).
    fn per_repository(
        o: &dyn opentelemetry::metrics::AsyncInstrument<u64>,
        value: fn(&RepositoryCount) -> Option<u64>,
    ) {
        with_snapshot(|repositories| {
            let mut sums: Vec<(Option<KeyValue>, u64)> = Vec::new();
            for r in repositories {
                let Some(n) = value(r) else { continue };
                let key = repo(&r.name);
                match sums.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, sum)) => *sum += n,
                    None => sums.push((key, n)),
                }
            }
            for (key, sum) in sums {
                let attributes: Vec<KeyValue> = key.into_iter().collect();
                o.observe(sum, &attributes);
            }
        });
    }

    pub(super) fn register(meter: &Meter) {
        meter
            .u64_observable_gauge("forge.repositories")
            .with_unit("{repository}")
            .with_description("Repositories, by format and kind")
            .with_callback(|o| {
                with_snapshot(|repositories| {
                    let mut counts: Vec<((&str, &str), u64)> = Vec::new();
                    for r in repositories {
                        let key = (r.format.as_str(), r.kind.as_str());
                        match counts.iter_mut().find(|(k, _)| *k == key) {
                            Some((_, n)) => *n += 1,
                            None => counts.push((key, 1)),
                        }
                    }
                    for ((format, kind), n) in counts {
                        o.observe(
                            n,
                            &[
                                KeyValue::new("forge.repository.format", format.to_string()),
                                KeyValue::new("forge.repository.kind", kind.to_string()),
                            ],
                        );
                    }
                });
            })
            .build();
        meter
            .u64_observable_gauge("forge.repository.versions")
            .with_unit("{version}")
            .with_description("Versions a repository holds (package versions, image tags, files)")
            .with_callback(|o| per_repository(o, |r| r.versions))
            .build();
        meter
            .u64_observable_gauge("forge.repository.size")
            .with_unit("By")
            .with_description("Bytes a repository holds")
            .with_callback(|o| per_repository(o, |r| r.bytes))
            .build();
    }
}

/// Values read from in-process state when the SDK collects: cheap reads of
/// what the process keeps anyway (the pool's sizes, the blob cache's
/// counters), exact at collection time and never duplicated into counters
/// of their own.
pub mod live {
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

    /// What a collection reads from the process.
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

    type Source = Box<dyn Fn() -> Snapshot + Send + Sync>;

    static SOURCE: RwLock<Option<Source>> = RwLock::new(None);

    /// An instrument read from the [`Snapshot`]: its name, unit, description,
    /// and its value in a snapshot.
    type Live = (
        &'static str,
        &'static str,
        &'static str,
        fn(&Snapshot) -> Option<u64>,
    );

    /// Read the process's state with `source` at every collection.
    pub fn set_source(source: impl Fn() -> Snapshot + Send + Sync + 'static) {
        *SOURCE.write().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(source));
    }

    /// The process's state now, `None` without a source.
    fn read() -> Option<Snapshot> {
        SOURCE
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|source| source())
    }

    /// Register an observable gauge (`counter`: an observable counter) of
    /// one `u64` of the snapshot.
    fn u64_instrument(
        meter: &Meter,
        name: &'static str,
        unit: &'static str,
        description: &'static str,
        counter: bool,
        value: fn(&Snapshot) -> Option<u64>,
    ) {
        let callback = move |o: &dyn opentelemetry::metrics::AsyncInstrument<u64>| {
            if let Some(v) = read().as_ref().and_then(value) {
                o.observe(v, &[]);
            }
        };
        if counter {
            meter
                .u64_observable_counter(name)
                .with_unit(unit)
                .with_description(description)
                .with_callback(callback)
                .build();
        } else {
            meter
                .u64_observable_gauge(name)
                .with_unit(unit)
                .with_description(description)
                .with_callback(callback)
                .build();
        }
    }

    pub(super) fn register(meter: &Meter) {
        meter
            .i64_observable_up_down_counter("db.client.connection.count")
            .with_unit("{connection}")
            .with_description("Open database connections, by state (used or idle)")
            .with_callback(|o| {
                if let Some(pool) = read().and_then(|s| s.pool) {
                    let state = |s: &'static str| KeyValue::new("db.client.connection.state", s);
                    o.observe(i64::from(pool.idle), &[db::pool(), state("idle")]);
                    o.observe(
                        i64::from(pool.size.saturating_sub(pool.idle)),
                        &[db::pool(), state("used")],
                    );
                }
            })
            .build();
        meter
            .i64_observable_up_down_counter("db.client.connection.max")
            .with_unit("{connection}")
            .with_description("The most connections the pool opens (database.max_connections)")
            .with_callback(|o| {
                if let Some(pool) = read().and_then(|s| s.pool) {
                    o.observe(i64::from(pool.max), &[db::pool()]);
                }
            })
            .build();
        let gauges: [Live; 8] = [
            (
                "forge.s3.circuit_breaker.open",
                "{open}",
                "Whether S3 is considered down: the circuit breaker in front of it is open \
                 (1) or closed (0)",
                |s| s.breaker_open.map(u64::from),
            ),
            (
                "forge.staging.usage",
                "By",
                "Bytes of pushes and proxy downloads staged on disk now",
                |s| s.staging.map(|(used, _)| used),
            ),
            (
                "forge.staging.limit",
                "By",
                "The staging budget (server.max_staging_bytes)",
                |s| s.staging.map(|(_, limit)| limit),
            ),
            (
                "forge.cache.backplane.connected",
                "{connected}",
                "Whether the Redis invalidation backplane is subscribed (1) or not (0)",
                |s| s.backplane_connected.map(u64::from),
            ),
            (
                "forge.blob_cache.entries",
                "{blob}",
                "Blobs in the local blob cache",
                |s| s.blob_cache.map(|c| c.entries),
            ),
            (
                "forge.blob_cache.usage",
                "By",
                "Bytes in the local blob cache",
                |s| s.blob_cache.map(|c| c.size_bytes),
            ),
            (
                "forge.blob_cache.reserved",
                "By",
                "Bytes the local blob cache promised to fills in progress",
                |s| s.blob_cache.map(|c| c.reserved_bytes),
            ),
            (
                "forge.blob_cache.limit",
                "By",
                "The local blob cache's effective size limit",
                |s| s.blob_cache.map(|c| c.limit_bytes),
            ),
        ];
        for (name, unit, description, value) in gauges {
            u64_instrument(meter, name, unit, description, false, value);
        }
        let counters: [Live; 11] = [
            (
                "forge.blob_cache.hits",
                "{read}",
                "Reads served from the local blob cache",
                |s| s.blob_cache.map(|c| c.hits),
            ),
            (
                "forge.blob_cache.served",
                "By",
                "Bytes reads served from the local blob cache",
                |s| s.blob_cache.map(|c| c.hit_bytes),
            ),
            (
                "forge.blob_cache.hits_while_store_down",
                "{read}",
                "Reads the local blob cache served while S3 was down",
                |s| s.blob_cache.map(|c| c.hits_while_store_down),
            ),
            (
                "forge.blob_cache.misses",
                "{read}",
                "Reads that found no blob in the local blob cache",
                |s| s.blob_cache.map(|c| c.misses),
            ),
            (
                "forge.blob_cache.fills",
                "{blob}",
                "Blobs added to the local blob cache",
                |s| s.blob_cache.map(|c| c.fills),
            ),
            (
                "forge.blob_cache.fill_failures",
                "{blob}",
                "Fills of the local blob cache that failed",
                |s| s.blob_cache.map(|c| c.fill_failures),
            ),
            (
                "forge.blob_cache.corrupt",
                "{blob}",
                "Cached blobs found damaged and dropped",
                |s| s.blob_cache.map(|c| c.corrupt),
            ),
            (
                "forge.blob_cache.evictions",
                "{blob}",
                "Blobs evicted from the local blob cache",
                |s| s.blob_cache.map(|c| c.evictions),
            ),
            (
                "forge.blob_cache.evicted",
                "By",
                "Bytes evicted from the local blob cache",
                |s| s.blob_cache.map(|c| c.evicted_bytes),
            ),
            (
                "forge.blob_cache.bypassed",
                "{read}",
                "Misses served from S3 without caching (no room)",
                |s| s.blob_cache.map(|c| c.bypassed),
            ),
            (
                "forge.blob_cache.verifications",
                "{blob}",
                "Cached blobs checked against their hash on their first hit",
                |s| s.blob_cache.map(|c| c.verifications),
            ),
        ];
        for (name, unit, description, value) in counters {
            u64_instrument(meter, name, unit, description, true, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

    use super::*;

    /// Every metric's name and the attribute sets of its data points.
    fn collect(
        provider: &SdkMeterProvider,
        exporter: &InMemoryMetricExporter,
    ) -> BTreeMap<String, Vec<Vec<KeyValue>>> {
        provider.force_flush().expect("flush");
        let mut out: BTreeMap<String, Vec<Vec<KeyValue>>> = BTreeMap::new();
        for rm in exporter.get_finished_metrics().expect("metrics") {
            for sm in rm.scope_metrics() {
                for m in sm.metrics() {
                    let points = out.entry(m.name().to_string()).or_default();
                    macro_rules! points {
                        ($data:expr) => {
                            match $data {
                                MetricData::Gauge(g) => {
                                    for p in g.data_points() {
                                        points.push(p.attributes().cloned().collect());
                                    }
                                }
                                MetricData::Sum(s) => {
                                    for p in s.data_points() {
                                        points.push(p.attributes().cloned().collect());
                                    }
                                }
                                MetricData::Histogram(h) => {
                                    for p in h.data_points() {
                                        points.push(p.attributes().cloned().collect());
                                    }
                                }
                                MetricData::ExponentialHistogram(_) => {}
                            }
                        };
                    }
                    match m.data() {
                        AggregatedMetrics::F64(d) => points!(d),
                        AggregatedMetrics::U64(d) => points!(d),
                        AggregatedMetrics::I64(d) => points!(d),
                    }
                }
            }
        }
        out
    }

    /// Record into every instrument, then check that each attribute key is
    /// one of [`ATTRIBUTE_KEYS`] and that the instruments are there.
    #[test]
    fn every_attribute_is_a_known_one() {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        init(&provider.meter("forge"));
        live::set_source(|| live::Snapshot {
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
        });

        for &surface in http::Surface::ALL {
            http::request(surface, "GET", 200, Duration::from_millis(3));
            http::response_size(surface, "PROPFIND", 404, 10);
        }
        drop(http::Active::start("GET"));
        for &kind in proxy::Kind::ALL {
            for &outcome in proxy::Outcome::ALL {
                proxy::Lookup::start("proxy-repo", kind).finish(outcome);
            }
        }
        proxy::upstream_request("proxy-repo", "GET", Some(429), Duration::from_millis(5));
        proxy::upstream_request("proxy-repo", "HEAD", None, Duration::from_millis(5));
        proxy::upstream_bytes("proxy-repo", 100);
        for &op in storage::S3Op::ALL {
            for &outcome in storage::S3Outcome::ALL {
                storage::S3Call::start(op, "bucket").finish(outcome);
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

        let metrics = collect(&provider, &exporter);
        let mut keys = BTreeSet::new();
        for points in metrics.values() {
            for attributes in points {
                for kv in attributes {
                    keys.insert(kv.key.as_str().to_string());
                }
            }
        }
        for key in &keys {
            assert!(
                ATTRIBUTE_KEYS.contains(&key.as_str()),
                "attribute {key:?} is not in ATTRIBUTE_KEYS"
            );
        }
        for name in [
            "http.server.request.duration",
            "http.server.active_requests",
            "http.server.response.body.size",
            "http.client.request.duration",
            "forge.proxy.lookups",
            "forge.s3.operation.duration",
            "forge.outbox.oldest_due.age",
            "db.client.connection.count",
            "db.client.connection.wait_time",
            "forge.worker.last_success.time",
            "forge.repository.size",
            "forge.repositories",
            "forge.blob_cache.hits",
            "forge.staging.usage",
            "forge.cache.backplane.connected",
            "forge.auth.sign_ins",
        ] {
            assert!(metrics.contains_key(name), "{name} missing: {metrics:?}");
        }
        let methods: BTreeSet<String> = metrics["http.server.response.body.size"]
            .iter()
            .flatten()
            .filter(|kv| kv.key.as_str() == "http.request.method")
            .map(|kv| kv.value.to_string())
            .collect();
        assert_eq!(methods, BTreeSet::from(["_OTHER".to_string()]));

        // Without the repository attribute, the repositories add up.
        set_per_repository(false);
        proxy::upstream_bytes("other-repo", 1);
        let metrics = collect(&provider, &exporter);
        assert!(metrics["forge.proxy.upstream.fetched"]
            .iter()
            .any(|attributes| attributes.is_empty()));
        set_per_repository(true);
    }
}
