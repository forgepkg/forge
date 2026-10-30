//! OpenTelemetry: Forge's metrics, traces and logs, exported over OTLP.
//!
//! * [`Telemetry`] sets up the OpenTelemetry SDK for the signals
//!   `[telemetry]` turns on, each with its OTLP/HTTP exporter, configured
//!   by the standard `OTEL_*` variables (`OTEL_EXPORTER_OTLP_ENDPOINT`,
//!   `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`,
//!   `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER`, …): Forge's
//!   instruments ([`forge_telemetry`]) record on its meter provider, the
//!   `tracing` spans of [`forge_telemetry::TARGET`] become trace spans, and
//!   the `tracing` events become log records, which carry the trace and
//!   span they happened in.
//! * [`track`], the middleware of the main listener: the HTTP server span of
//!   every request (joining the caller's trace from its `traceparent`) and
//!   the HTTP metrics: request duration by surface (from the route, never
//!   the raw path), method and status, the requests in flight and the
//!   response body sizes. It also counts the request in the traffic
//!   statistics ([`crate::traffic`]), which the metrics' bounded attributes
//!   leave out: the repository, the client address, the path.
//! * [`install_live_source`]: what the SDK reads from the process when it
//!   collects (the connection pool, the blob cache's counters, those of `GET
//!   /admin/blob-cache`, the circuit breaker, the staging space, the
//!   backplane).
//! * The **inventory worker** ([`spawn_inventory`]): repositories by format
//!   and kind, each repository's versions and stored bytes, and the outbox
//!   backlog, counted every `telemetry.inventory_interval_seconds`, never
//!   per collection.
//! * [`AcquireTimes`], the tracing layer that turns the connection pool's
//!   acquire events into `db.client.connection.wait_time`.

use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use axum::body::{Body, Bytes};
use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderMap};
use axum::middleware::Next;
use axum::response::Response;
use forge_db::model::RepoKind;
use forge_telemetry::http::Surface;
use forge_telemetry::{inventory, live, storage};
use forge_traffic::Recorder;
use http_body::{Frame, SizeHint};
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::propagation::Extractor;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::resource::{EnvResourceDetector, TelemetryResourceDetector};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tokio::task::JoinHandle;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::filter::{filter_fn, FilterExt};
use tracing_subscriber::layer::{Filter, Layer};
use tracing_subscriber::{EnvFilter, Registry};

use crate::config::TelemetryConfig;
use crate::state::AppState;
use crate::web_ui::is_under;

/// A layer of the process's `tracing` subscriber.
pub type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

/// The OpenTelemetry providers of the signals `[telemetry]` turns on.
#[derive(Default)]
pub struct Telemetry {
    meter: Option<SdkMeterProvider>,
    tracer: Option<SdkTracerProvider>,
    logger: Option<SdkLoggerProvider>,
}

impl Telemetry {
    /// The providers of the signals `config` turns on, each exporting over
    /// OTLP/HTTP to where the `OTEL_EXPORTER_OTLP_*` variables say (by
    /// default `http://localhost:4318`). Nothing when none is on, or with
    /// `OTEL_SDK_DISABLED=true`.
    pub fn new(config: &TelemetryConfig) -> anyhow::Result<Telemetry> {
        if !config.any() || env_flag("OTEL_SDK_DISABLED") {
            return Ok(Telemetry::default());
        }
        refuse_grpc()?;
        let resource = resource();
        let meter = if config.metrics {
            let exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_http()
                .build()
                .context("build the OTLP metric exporter")?;
            Some(
                SdkMeterProvider::builder()
                    .with_resource(resource.clone())
                    .with_periodic_exporter(exporter)
                    .build(),
            )
        } else {
            None
        };
        let tracer = if config.traces {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .build()
                .context("build the OTLP span exporter")?;
            Some(
                SdkTracerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(exporter)
                    .build(),
            )
        } else {
            None
        };
        let logger = if config.logs {
            let exporter = opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .build()
                .context("build the OTLP log exporter")?;
            Some(
                SdkLoggerProvider::builder()
                    .with_resource(resource)
                    .with_batch_exporter(exporter)
                    .build(),
            )
        } else {
            None
        };
        Ok(Telemetry {
            meter,
            tracer,
            logger,
        })
    }

    /// Providers built by the caller (tests: in-memory exporters).
    pub fn from_providers(
        meter: Option<SdkMeterProvider>,
        tracer: Option<SdkTracerProvider>,
        logger: Option<SdkLoggerProvider>,
    ) -> Telemetry {
        Telemetry {
            meter,
            tracer,
            logger,
        }
    }

    /// Whether metrics are exported.
    pub fn metrics(&self) -> bool {
        self.meter.is_some()
    }

    /// Make the providers the process's: Forge's instruments record on the
    /// meter provider, and incoming requests are read for a W3C
    /// `traceparent` to join.
    pub fn install(&self) {
        if let Some(meter) = &self.meter {
            opentelemetry::global::set_meter_provider(meter.clone());
            forge_telemetry::init(&meter.meter("forge"));
        }
        if let Some(tracer) = &self.tracer {
            opentelemetry::global::set_tracer_provider(tracer.clone());
            opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        }
    }

    /// The `tracing` layers that export: the spans of
    /// [`forge_telemetry::TARGET`] as trace spans, and the events the log
    /// prints (`RUST_LOG`) as log records. Never the SDK's and the HTTP
    /// client's own events, which would feed back into the export.
    pub fn layers(&self) -> Vec<BoxedLayer> {
        let mut layers: Vec<BoxedLayer> = Vec::new();
        if let Some(tracer) = &self.tracer {
            layers.push(Box::new(
                tracing_opentelemetry::layer()
                    .with_tracer(tracer.tracer("forge"))
                    .with_tracked_inactivity(false)
                    .with_location(false)
                    .with_threads(false)
                    .with_target(false)
                    .with_filter(
                        tracing_subscriber::filter::Targets::new()
                            .with_target(forge_telemetry::TARGET, tracing::Level::INFO),
                    ),
            ));
        }
        if let Some(logger) = &self.logger {
            layers.push(Box::new(
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(logger)
                    .with_filter(export_log_filter()),
            ));
        }
        layers
    }

    /// Export what is buffered and stop. Blocks: call it off the async
    /// workers.
    pub fn shutdown(&self) {
        if let Some(tracer) = &self.tracer {
            if let Err(e) = tracer.shutdown() {
                tracing::warn!(error = %e, "flushing the trace export failed");
            }
        }
        if let Some(meter) = &self.meter {
            if let Err(e) = meter.shutdown() {
                tracing::warn!(error = %e, "flushing the metric export failed");
            }
        }
        if let Some(logger) = &self.logger {
            if let Err(e) = logger.shutdown() {
                tracing::warn!(error = %e, "flushing the log export failed");
            }
        }
    }
}

/// The filter of the console log: `RUST_LOG` (default `info`), without the
/// spans meant for export.
pub fn console_log_filter() -> EnvFilter {
    rust_log().add_directive(
        format!("{}=off", forge_telemetry::TARGET)
            .parse()
            .expect("a valid directive"),
    )
}

/// The filter of the exported logs: what the console log prints, but never
/// the events of the export itself (OpenTelemetry, whose OTLP exporter logs
/// as `opentelemetry-otlp`, and the HTTP client it sends with), which would
/// feed back into it.
fn export_log_filter() -> impl Filter<Registry> + Send + Sync {
    console_log_filter().and(filter_fn(|metadata| {
        let target = metadata.target();
        !(target.starts_with("opentelemetry")
            || [
                "reqwest",
                "hyper",
                "hyper_util",
                "h2",
                "tower",
                ACQUIRE_TARGET,
            ]
            .iter()
            .any(|module| {
                target == *module
                    || target
                        .strip_prefix(module)
                        .is_some_and(|rest| rest.starts_with("::"))
            }))
    }))
}

/// `RUST_LOG`, default `info`.
fn rust_log() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Whether the environment variable `name` is `true`.
fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Forge exports over OTLP/HTTP only: refuse an `OTEL_EXPORTER_OTLP_*_PROTOCOL`
/// that asks for gRPC, which would otherwise be sent HTTP.
fn refuse_grpc() -> anyhow::Result<()> {
    for var in [
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
        "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
    ] {
        if let Ok(protocol) = std::env::var(var) {
            let protocol = protocol.trim();
            if !protocol.is_empty() && protocol != "http/protobuf" {
                anyhow::bail!(
                    "{var}={protocol:?}: Forge exports OTLP over HTTP (http/protobuf, port \
                     4318); unset it or set it to http/protobuf"
                );
            }
        }
    }
    Ok(())
}

/// What the exported telemetry says about this process: the service name
/// `forge`, the version and revision, the host and an id of this instance,
/// each unless the environment says otherwise (`OTEL_RESOURCE_ATTRIBUTES`,
/// then `OTEL_SERVICE_NAME`).
pub fn resource() -> Resource {
    let mut defaults = vec![
        KeyValue::new("service.name", "forge"),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("service.instance.id", uuid::Uuid::new_v4().to_string()),
    ];
    if let Some(revision) = option_env!("FORGE_GIT_SHA") {
        defaults.push(KeyValue::new("vcs.ref.head.revision", revision));
    }
    if let Some(host) = crate::state::Instance::current().host {
        defaults.push(KeyValue::new("host.name", host));
    }
    let mut builder = Resource::builder_empty()
        .with_attributes(defaults)
        .with_detector(Box::new(TelemetryResourceDetector))
        .with_detector(Box::new(EnvResourceDetector::new()));
    if let Ok(name) = std::env::var("OTEL_SERVICE_NAME") {
        if !name.trim().is_empty() {
            builder = builder.with_service_name(name.trim().to_string());
        }
    }
    builder.build()
}

/// Read the process's state for the metrics at every collection.
pub fn install_live_source(state: &AppState) {
    let state = state.clone();
    live::set_source(move || snapshot(&state));
}

/// What a collection reads from the process.
pub fn snapshot(state: &AppState) -> live::Snapshot {
    let pool = &state.pool;
    let blob_cache = state.blob_store.cache().map(|cache| {
        let s = cache.stats();
        live::BlobCache {
            entries: s.entries,
            size_bytes: s.size_bytes,
            reserved_bytes: s.reserved_bytes,
            limit_bytes: s.limit_bytes,
            hits: s.hits,
            hit_bytes: s.hit_bytes,
            hits_while_store_down: s.hits_while_store_down,
            misses: s.misses,
            fills: s.fills,
            fill_failures: s.fill_failures,
            corrupt: s.corrupt,
            evictions: s.evictions,
            evicted_bytes: s.evicted_bytes,
            bypassed: s.bypassed,
            verifications: s.verifications,
        }
    });
    live::Snapshot {
        pool: Some(live::Pool {
            size: pool.size(),
            idle: u32::try_from(pool.num_idle()).unwrap_or(u32::MAX),
            max: pool.options().get_max_connections(),
        }),
        // The breaker comes with the blob cache.
        breaker_open: blob_cache
            .is_some()
            .then(|| state.blob_store.is_unavailable()),
        blob_cache,
        staging: state.cas.staging().usage(),
        backplane_connected: state.cache.backplane_subscribed(),
    }
}

/// The surface of a request for `path`, from the route it is served by.
/// `/repository/…` is narrowed to the repository's format by the handler
/// ([`forge_telemetry::http::plugin_surface`], a [`Surface`] response
/// extension); this is what a request is counted under without one.
fn surface_of(path: &str) -> Surface {
    let under = |prefix| is_under(path, prefix);
    if under(forge_plugin::api::IMAGES_MOUNT) {
        Surface::Oci
    } else if under("/repository") {
        Surface::Repository
    } else if under("/admin") {
        Surface::Admin
    } else if under("/browse") {
        Surface::Browse
    } else if under("/auth") || under("/.well-known") || under("/api") || under("/-/npm/v1/oidc") {
        Surface::Auth
    } else if matches!(path, "/healthz" | "/readyz" | "/version") {
        Surface::Health
    } else {
        Surface::Ui
    }
}

/// The secret path segment of a command-line client's login or logout, as a
/// span records it.
const SECRET_SEGMENT: &str = "{secret}";

/// `path` as a request's span (`url.path`) and the audit line of a package
/// mutation record it: a secret in the path, and whatever follows it,
/// replaced by [`SECRET_SEGMENT`]. The page that approves a web login
/// (`/cli-login/<secret>`) and the API behind it (`/auth/cli-login/<secret>`)
/// carry the secret that approves it; the URL npm polls (its `doneUrl`,
/// `/repository/<repo>/-/v1/login/done/<secret>`) carries the one that
/// collects the user's new token, once; `npm logout`
/// (`/repository/<repo>/-/user/token/<token>`) carries the API token it
/// revokes, which stays valid when the logout fails.
pub(crate) fn recorded_path(path: &str) -> Cow<'_, str> {
    let secret_at = ["/cli-login/", "/auth/cli-login/"]
        .into_iter()
        .find(|prefix| path.starts_with(prefix))
        .map(str::len)
        .or_else(|| {
            ["/-/v1/login/done/", "/-/user/token/"]
                .into_iter()
                .find_map(|segment| path.find(segment).map(|at| at + segment.len()))
        });
    match secret_at {
        Some(at) => Cow::Owned(format!("{}{SECRET_SEGMENT}", &path[..at])),
        None => Cow::Borrowed(path),
    }
}

/// The request headers, as the propagator reads them.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// The server span of `req`, a child of the trace its `traceparent` names,
/// with its path as [`recorded_path`] records it.
/// A health probe's is never exported, nor is what it does (the readiness
/// checks): they would bury the traces worth reading.
fn request_span(req: &Request, surface: Surface, route: Option<&str>) -> tracing::Span {
    if surface == Surface::Health {
        let span = tracing::info_span!(target: forge_telemetry::TARGET, "health probe");
        // Fails only without the trace export, when the span goes nowhere.
        let _ = span.set_parent(unsampled());
        return span;
    }
    let method = forge_telemetry::http::method(req.method().as_str());
    let path = recorded_path(req.uri().path());
    let span = tracing::info_span!(
        target: forge_telemetry::TARGET,
        "HTTP request",
        otel.name = %match route {
            Some(route) => format!("{method} {route}"),
            None => method.to_string(),
        },
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        "http.request.method" = method,
        "http.route" = route,
        "url.path" = path.as_ref(),
        "user_agent.original" = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
        // Recorded with the answer: the handler narrows it to the format.
        "forge.surface" = tracing::field::Empty,
        "http.response.status_code" = tracing::field::Empty,
    );
    let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    });
    // Fails only without the trace export, when the span goes nowhere.
    let _ = span.set_parent(parent);
    span
}

/// A context whose spans the (parent-based) sampler drops: a trace no one
/// sampled.
fn unsampled() -> opentelemetry::Context {
    use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId};
    let ids = uuid::Uuid::new_v4().as_u128();
    opentelemetry::Context::new().with_remote_span_context(SpanContext::new(
        TraceId::from(ids),
        SpanId::from(ids as u64 | 1),
        TraceFlags::default(),
        true,
        Default::default(),
    ))
}

/// Middleware of the main listener: the request's server span and its
/// metrics, the size of its response body, and its count in the traffic
/// statistics ([`forge_traffic`]).
pub async fn track(State(recorder): State<Arc<Recorder>>, req: Request, next: Next) -> Response {
    let surface = surface_of(req.uri().path());
    let method = forge_telemetry::http::method(req.method().as_str());
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned());
    let span = request_span(&req, surface, route.as_deref());
    // Health probes are no traffic.
    let counted = (surface != Surface::Health && recorder.enabled()).then(|| Counted {
        path: if recorder.logs_requests() {
            recorded_path(req.uri().path()).into_owned()
        } else {
            String::new()
        },
        user_agent: req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        slot: forge_traffic::Slot::new(),
        recorder,
        elapsed: Duration::ZERO,
    });
    let started = Instant::now();
    let active = forge_telemetry::http::Active::start(method);
    let run = next.run(req).instrument(span.clone());
    let mut response = match &counted {
        Some(counted) => counted.slot.scope(run).await,
        None => run.await,
    };
    drop(active);
    let surface = response
        .extensions_mut()
        .remove::<Surface>()
        .unwrap_or(surface);
    let status = response.status().as_u16();
    span.record("forge.surface", surface.as_str());
    span.record("http.response.status_code", status);
    if status >= 500 {
        span.record("otel.status_code", "ERROR");
    }
    let elapsed = started.elapsed();
    forge_telemetry::http::request(surface, method, status, elapsed);
    response.map(|inner| {
        Body::new(CountingBody {
            inner,
            surface,
            method,
            status,
            bytes: 0,
            counted: counted.map(|c| Counted { elapsed, ..c }),
            _span: span,
        })
    })
}

/// A request to count in the traffic statistics once its body is sent.
struct Counted {
    recorder: Arc<Recorder>,
    /// What the layers inside noted.
    slot: forge_traffic::Slot,
    /// For the request log; empty when it is off.
    path: String,
    user_agent: Option<String>,
    /// Time to the response headers.
    elapsed: Duration,
}

/// A response body that counts the bytes it yields: their total is
/// recorded, and the request's span ends, when the body is done or
/// dropped (a client that went away).
struct CountingBody {
    inner: Body,
    surface: Surface,
    method: &'static str,
    status: u16,
    bytes: u64,
    counted: Option<Counted>,
    _span: tracing::Span,
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled {
            if let Some(data) = frame.data_ref() {
                let len = data.len() as u64;
                self.bytes += len;
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CountingBody {
    fn drop(&mut self) {
        forge_telemetry::http::response_size(self.surface, self.method, self.status, self.bytes);
        if let Some(counted) = self.counted.take() {
            counted.recorder.record(forge_traffic::Event {
                at: chrono::Utc::now(),
                surface: self.surface.as_str(),
                method: self.method,
                status: self.status,
                duration: counted.elapsed,
                bytes: self.bytes,
                path: counted.path,
                user_agent: counted.user_agent,
                noted: counted.slot.take(),
            });
        }
    }
}

/// The inventory worker: count what this instance's database holds every
/// `interval` ([`count_inventory`]).
pub fn spawn_inventory(state: AppState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let run = forge_telemetry::workers::Run::start(INVENTORY_WORKER);
            let result = count_inventory(&state).instrument(run.span()).await;
            if let Err(e) = &result {
                tracing::warn!(error = %e, "counting the inventory for the metrics failed");
            }
            run.finish(result.is_ok());
        }
    })
}

/// The inventory worker's name (`forge.worker`).
pub const INVENTORY_WORKER: &str = "metrics-inventory";

/// Count the repositories (by format and kind, with each one's versions and
/// stored bytes) and the outbox backlog, and publish them to the metrics.
pub async fn count_inventory(state: &AppState) -> anyhow::Result<()> {
    let pool = &state.pool;
    let (pending, due, oldest_due_age_seconds): (i64, i64, f64) = sqlx::query_as(
        "SELECT count(*), \
                count(*) FILTER (WHERE available_at <= now()), \
                COALESCE(EXTRACT(EPOCH FROM now() - min(available_at) \
                    FILTER (WHERE available_at <= now()))::float8, 0) \
         FROM blob_outbox WHERE processed_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    storage::publish_outbox(storage::OutboxBacklog {
        pending: u64::try_from(pending).unwrap_or_default(),
        due: u64::try_from(due).unwrap_or_default(),
        oldest_due_age_seconds,
    });

    let mut counts = Vec::new();
    for repo in forge_db::repository_dao::list_repositories(pool).await? {
        let (versions, bytes) = if repo.kind() == RepoKind::Group {
            (None, None)
        } else {
            let format = state.formats.for_repository(&repo).ok();
            let (versions, bytes) = if format.as_ref().is_some_and(|f| f.stores_images()) {
                (
                    sqlx::query_scalar::<_, i64>(
                        "SELECT count(*) FROM oci_tag WHERE repository_id = $1",
                    )
                    .bind(repo.id)
                    .fetch_one(pool)
                    .await?,
                    forge_db::oci_dao::repository_size(pool, repo.id).await?,
                )
            } else if format.as_ref().is_some_and(|f| f.stores_files()) {
                (
                    sqlx::query_scalar::<_, i64>(
                        "SELECT count(*) FROM raw_file WHERE repository_id = $1",
                    )
                    .bind(repo.id)
                    .fetch_one(pool)
                    .await?,
                    forge_db::raw_dao::repository_size(pool, repo.id).await?,
                )
            } else {
                (
                    sqlx::query_scalar::<_, i64>(
                        "SELECT count(*) FROM component WHERE repository_id = $1",
                    )
                    .bind(repo.id)
                    .fetch_one(pool)
                    .await?,
                    forge_db::retention_dao::package_repository_size(pool, repo.id).await?,
                )
            };
            (
                Some(u64::try_from(versions).unwrap_or_default()),
                Some(bytes),
            )
        };
        counts.push(inventory::RepositoryCount {
            format: repo.format.clone(),
            kind: repo.kind().as_str().to_string(),
            name: repo.name.clone(),
            versions,
            bytes,
        });
    }
    inventory::publish(counts);
    Ok(())
}

/// A tracing layer that records the connection pool's acquire times
/// (`sqlx::pool::acquire` events, see [`forge_db::connect_with`]) into
/// `db.client.connection.wait_time`.
pub struct AcquireTimes;

/// The target of sqlx's acquire events.
pub const ACQUIRE_TARGET: &str = "sqlx::pool::acquire";

impl<S: tracing::Subscriber> Layer<S> for AcquireTimes {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != ACQUIRE_TARGET {
            return;
        }
        struct Seconds(Option<f64>);
        impl tracing::field::Visit for Seconds {
            fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
                if field.name() == "acquired_after_secs" {
                    self.0 = Some(value);
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut seconds = Seconds(None);
        event.record(&mut seconds);
        if let Some(secs) = seconds.0.filter(|s| s.is_finite() && *s >= 0.0) {
            forge_telemetry::db::acquired(Duration::from_secs_f64(secs));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surfaces_follow_the_routes() {
        assert_eq!(surface_of("/v2/"), Surface::Oci);
        assert_eq!(surface_of("/v2/team/app/manifests/1"), Surface::Oci);
        assert_eq!(
            surface_of("/repository/nuget/index.json"),
            Surface::Repository
        );
        assert_eq!(surface_of("/admin/repositories"), Surface::Admin);
        assert_eq!(surface_of("/admin/me"), Surface::Admin);
        assert_eq!(surface_of("/browse/repos"), Surface::Browse);
        assert_eq!(surface_of("/auth/login"), Surface::Auth);
        assert_eq!(surface_of("/.well-known/jwks.json"), Surface::Auth);
        assert_eq!(surface_of("/api/v2/token"), Surface::Auth);
        assert_eq!(surface_of("/healthz"), Surface::Health);
        assert_eq!(surface_of("/manage/repositories"), Surface::Ui);
        assert_eq!(surface_of("/v2x"), Surface::Ui);
        assert_eq!(surface_of("/"), Surface::Ui);
    }

    #[test]
    fn a_recorded_path_never_holds_a_cli_logins_secret() {
        for (path, recorded) in [
            ("/cli-login/s3cret", "/cli-login/{secret}"),
            ("/auth/cli-login/s3cret", "/auth/cli-login/{secret}"),
            (
                "/repository/npm/-/v1/login/done/s3cret",
                "/repository/npm/-/v1/login/done/{secret}",
            ),
            // `npm logout`'s token, in the request's path and in the part
            // of it after the repository that the audit line records.
            (
                "/repository/npm/-/user/token/s3cret",
                "/repository/npm/-/user/token/{secret}",
            ),
            ("/-/user/token/s3cret", "/-/user/token/{secret}"),
            // Whatever follows the secret goes with it.
            ("/cli-login/s3cret/x", "/cli-login/{secret}"),
            (
                "/repository/npm/-/v1/login/done/s3cret/",
                "/repository/npm/-/v1/login/done/{secret}",
            ),
        ] {
            assert_eq!(recorded_path(path), recorded, "{path}");
        }
        for path in [
            "/repository/nuget/flat/a/1.0.0/a.1.0.0.nupkg",
            "/repository/npm/-/v1/login",
            "/repository/npm/-/user/org.couchdb.user:alice",
            "/auth/cli-login",
            "/manage/repositories",
        ] {
            assert!(
                matches!(recorded_path(path), Cow::Borrowed(p) if p == path),
                "{path}"
            );
        }
    }

    #[test]
    fn the_export_never_logs_into_itself() {
        use tracing_subscriber::layer::SubscriberExt;

        /// Counts the events that reach it.
        struct Count(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Layer<Registry> for Count {
            fn on_event(
                &self,
                _: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, Registry>,
            ) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let subscriber =
            Registry::default().with(Count(seen.clone()).with_filter(export_log_filter()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "opentelemetry-otlp", "export failed");
            tracing::error!(target: "opentelemetry_sdk", "export failed");
            tracing::warn!(target: "reqwest::connect", "refused");
            tracing::warn!(target: "hyper_util::client", "closed");
            tracing::warn!(target: "hyperion", "a crate of its own");
            tracing::warn!("Forge's own");
        });
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn a_grpc_protocol_is_refused() {
        // The only test of this binary touching these variables.
        std::env::set_var("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc");
        let err = refuse_grpc().unwrap_err();
        assert!(
            err.to_string()
                .contains("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"),
            "{err}"
        );
        std::env::set_var("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf");
        refuse_grpc().expect("http/protobuf is fine");
        std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL");
    }
}
