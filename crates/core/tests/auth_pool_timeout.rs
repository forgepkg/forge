//! A pool acquire that times out while looking up the principal counts in
//! `db.client.connection.timeouts` (the `ForgeDatabasePoolExhausted` alert),
//! as on every other request path, and the request still fails closed with
//! `Unavailable` (503).
//!
//! The pool points at a listener that takes the connection and never
//! answers, so every acquire runs into its deadline: no database is needed.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine as _;
use forge_core::auth::{
    check_token, BasicAuthSource, PrincipalSource, SessionCookieSource, SourceOutcome,
    TokenHeaderSource,
};
use forge_core::session::SessionService;
use http::{HeaderMap, HeaderValue};
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use sqlx::postgres::{PgPool, PgPoolOptions};

/// The metrics, recorded to memory.
struct Metrics {
    provider: SdkMeterProvider,
    exporter: InMemoryMetricExporter,
}

impl Metrics {
    fn install() -> Self {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        forge_telemetry::init(&provider.meter("forge"));
        Self { provider, exporter }
    }

    /// The cumulative count of `db.client.connection.timeouts`.
    fn timeouts(&self) -> u64 {
        self.provider.force_flush().expect("flush");
        let finished = self.exporter.get_finished_metrics().expect("metrics");
        let Some(last) = finished.last() else {
            return 0;
        };
        let mut total = 0;
        for sm in last.scope_metrics() {
            for m in sm.metrics() {
                if m.name() != "db.client.connection.timeouts" {
                    continue;
                }
                if let AggregatedMetrics::U64(MetricData::Sum(sum)) = m.data() {
                    total += sum.data_points().map(|p| p.value()).sum::<u64>();
                }
            }
        }
        total
    }
}

/// A pool whose every acquire times out: its server accepts the
/// connection and never answers the startup message.
async fn exhausted_pool() -> (PgPool, tokio::net::TcpListener) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy(&format!("postgres://forge@127.0.0.1:{port}/forge"))
        .expect("lazy pool");
    (pool, listener)
}

fn ip() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

fn header(name: &'static str, value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(name, HeaderValue::from_str(value).unwrap());
    headers
}

// One test: the counter is the process's, so the paths run one after another.
#[tokio::test]
async fn a_pool_timeout_on_the_principal_lookup_counts() {
    let metrics = Metrics::install();
    let (pool, _listener) = exhausted_pool().await;

    let before = metrics.timeouts();
    let err = check_token(&pool, "secret")
        .await
        .expect_err("no connection");
    assert!(matches!(err, sqlx::Error::PoolTimedOut), "{err:?}");
    assert_eq!(metrics.timeouts(), before + 1, "check_token");

    let api_key = TokenHeaderSource::new(pool.clone());
    let before = metrics.timeouts();
    assert_eq!(
        api_key
            .resolve(&header(TokenHeaderSource::HEADER, "secret"), ip())
            .await,
        SourceOutcome::Unavailable
    );
    assert_eq!(metrics.timeouts(), before + 1, "API key header");

    let basic = BasicAuthSource::with_chain(pool.clone(), None);
    let credentials = base64::engine::general_purpose::STANDARD.encode("alice:secret");
    let before = metrics.timeouts();
    assert_eq!(
        basic
            .resolve(
                &header("authorization", &format!("Basic {credentials}")),
                ip()
            )
            .await,
        SourceOutcome::Unavailable
    );
    assert_eq!(metrics.timeouts(), before + 1, "Basic");

    let sessions = SessionService::new(
        pool.clone(),
        chrono::Duration::hours(1),
        chrono::Duration::hours(8),
    );
    let session = SessionCookieSource::new(sessions, pool, false);
    let before = metrics.timeouts();
    assert_eq!(
        session
            .resolve(&header("cookie", "forge_session=secret"), ip())
            .await,
        SourceOutcome::Unavailable
    );
    assert_eq!(metrics.timeouts(), before + 1, "session cookie");
}
