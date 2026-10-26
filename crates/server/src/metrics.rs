//! Prometheus metrics ([`forge_metrics`]) of the server:
//!
//! * the **metrics listener** (`server.metrics_bind`): `GET /metrics` on a
//!   listener of its own ([`router`]), never on the main one, so the metrics
//!   stay off the ingress; with `server.metrics_token` a scrape must present
//!   it as a bearer token;
//! * the **HTTP metrics** of the main listener ([`track`]): requests by
//!   surface (from the route, never the raw path), method and status class,
//!   their latency, the requests in flight and the response bytes;
//! * the values read from in-process state when scraped ([`snapshot`]): the
//!   connection pool, the blob cache's counters (those of `GET
//!   /admin/blob-cache`), the circuit breaker, the staging space;
//! * the **inventory worker** ([`spawn_inventory`]): repositories by format
//!   and kind, each repository's versions and stored bytes, and the outbox
//!   backlog, counted every `metrics.inventory_interval_seconds`, never per
//!   scrape;
//! * [`AcquireTimes`], the tracing layer that turns the connection pool's
//!   acquire events into the acquire-wait histogram.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use forge_db::model::RepoKind;
use forge_metrics::http::{InFlight, Method, Surface};
use forge_metrics::{inventory, live, storage};
use http_body::{Frame, SizeHint};
use tokio::task::JoinHandle;

use crate::state::AppState;
use crate::web_ui::is_under;

/// The metrics listener's router: `GET /metrics`, nothing else.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .with_state(state)
}

/// `GET /metrics`
async fn scrape(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = &state.config.server.metrics_token {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if !presented.is_some_and(|presented| token.matches(presented.trim())) {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
            )
                .into_response();
        }
    }
    let mut text = String::new();
    if let Err(e) = forge_metrics::encode(&mut text, &snapshot(&state)) {
        tracing::error!(error = %e, "encoding the metrics failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(forge_metrics::CONTENT_TYPE),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        text,
    )
        .into_response()
}

/// What a scrape reads from the process.
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
/// ([`forge_metrics::http::plugin_surface`], a [`Surface`] response
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

/// Middleware of the main listener: count and time every request, and the
/// bytes of its response body.
pub async fn track(req: Request, next: Next) -> Response {
    let surface = surface_of(req.uri().path());
    let method = Method::of(req.method().as_str());
    let started = Instant::now();
    let in_flight = InFlight::start();
    let mut response = next.run(req).await;
    drop(in_flight);
    let surface = response
        .extensions_mut()
        .remove::<Surface>()
        .unwrap_or(surface);
    forge_metrics::http::request(
        surface,
        method,
        response.status().as_u16(),
        started.elapsed(),
    );
    response.map(|inner| Body::new(CountingBody { inner, surface }))
}

/// A response body that counts the bytes it yields.
struct CountingBody {
    inner: Body,
    surface: Surface,
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
                forge_metrics::http::response_bytes(self.surface, data.len() as u64);
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

/// The inventory worker: count what this instance's database holds every
/// `interval` ([`count_inventory`]).
pub fn spawn_inventory(state: AppState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let run = forge_metrics::workers::Run::start(INVENTORY_WORKER);
            let result = count_inventory(&state).await;
            if let Err(e) = &result {
                tracing::warn!(error = %e, "counting the inventory for the metrics failed");
            }
            run.finish(result.is_ok());
        }
    })
}

/// The inventory worker's name in `forge_worker_*`.
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
/// `forge_db_pool_acquire_duration_seconds`.
pub struct AcquireTimes;

/// The target of sqlx's acquire events.
pub const ACQUIRE_TARGET: &str = "sqlx::pool::acquire";

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AcquireTimes {
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
            forge_metrics::db::acquired(Duration::from_secs_f64(secs));
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
}
