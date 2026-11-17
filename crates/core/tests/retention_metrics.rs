//! With the metrics on, a retention run reads the repository's size before
//! and after it deleted something, and `forge.retention.freed` counts the
//! difference; a dry run and a disabled policy, which free nothing, read no
//! size (#549). `retention_metrics_off.rs` is the run with the metrics off.
//!
//! The tests of this binary share the metrics and the statement recorder,
//! as a process does, so they run one at a time. Postgres only.

mod common;
mod retention_size;

use common::{pool, unique};
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use retention_size::{Statements, ASSET_SIZE};
use serde_json::json;
use std::sync::OnceLock;

/// The metrics, recorded to memory.
struct Metrics {
    provider: SdkMeterProvider,
    exporter: InMemoryMetricExporter,
}

/// Turn the metrics on, once per process.
fn metrics() -> &'static Metrics {
    static METRICS: OnceLock<Metrics> = OnceLock::new();
    METRICS.get_or_init(|| {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        forge_telemetry::init(&provider.meter("forge"));
        Metrics { provider, exporter }
    })
}

impl Metrics {
    /// The cumulative value of counter `name` for `repository`, `None`
    /// when it has no such series.
    fn counter(&self, name: &str, repository: &str) -> Option<u64> {
        self.exporter.reset();
        self.provider.force_flush().expect("flush");
        let finished = self.exporter.get_finished_metrics().expect("metrics");
        let latest = finished.last()?;
        let mut total = None;
        for scope in latest.scope_metrics() {
            for metric in scope.metrics().filter(|m| m.name() == name) {
                let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
                    panic!("{name} is a u64 counter");
                };
                for point in sum.data_points() {
                    if point.attributes().any(|kv| kv.value.as_str() == repository) {
                        *total.get_or_insert(0) += point.value();
                    }
                }
            }
        }
        total
    }
}

/// One test at a time: they read the shared statement recorder.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn a_run_that_deletes_reads_the_size_twice_and_records_the_freed_bytes() {
    let _one = ONE_AT_A_TIME.lock().await;
    let statements = Statements::install();
    let metrics = metrics();
    assert!(forge_telemetry::enabled());
    let pool = pool().await;
    let name = format!("rsize-on-{}", unique());
    let repo = retention_size::seed(&pool, &name, json!({})).await;

    let mark = statements.len();
    let summary = retention_size::run(&pool, repo).await;

    assert_eq!(summary.deleted, 1);
    assert_eq!(
        statements.size_reads_since(mark).len(),
        2,
        "the size before and after the run: {:?}",
        statements.size_reads_since(mark)
    );
    assert_eq!(
        metrics.counter("forge.retention.freed", &name),
        Some(ASSET_SIZE),
        "the deleted version's bytes"
    );
    assert_eq!(metrics.counter("forge.retention.runs", &name), Some(1));
}

#[tokio::test]
async fn a_dry_run_and_a_disabled_policy_read_no_size() {
    let _one = ONE_AT_A_TIME.lock().await;
    let statements = Statements::install();
    let metrics = metrics();
    let pool = pool().await;

    for (what, extra, would_delete) in [
        ("dry", json!({ "dry_run_only": true }), 1),
        ("disabled", json!({ "enabled": false }), 0),
    ] {
        let name = format!("rsize-{what}-{}", unique());
        let repo = retention_size::seed(&pool, &name, extra).await;

        let mark = statements.len();
        let summary = retention_size::run(&pool, repo).await;

        assert_eq!(summary.deleted, would_delete, "{what}");
        assert_eq!(
            statements.size_reads_since(mark),
            Vec::<String>::new(),
            "{what}: a run that frees nothing reads no size"
        );
        // The run still counts, with nothing freed.
        assert_eq!(
            metrics.counter("forge.retention.runs", &name),
            Some(1),
            "{what}"
        );
        assert_eq!(
            metrics.counter("forge.retention.freed", &name),
            Some(0),
            "{what}"
        );
    }
}
