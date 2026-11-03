//! `forge.worker.interval` under delta temporality (#582): it is reported on
//! every collection, not only the one after a worker was spawned, so
//! `ForgeWorkerStalled` keeps finding it next to the last success.
//!
//! A test binary of its own: [`forge_telemetry::init`] counts only its first
//! call in a process, and this one needs a meter that exports deltas.

use std::time::Duration;

use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{
    InMemoryMetricExporter, InMemoryMetricExporterBuilder, PeriodicReader, SdkMeterProvider,
    Temporality,
};

/// Collect once and return the `forge.worker.interval` points (worker,
/// seconds), then clear the exporter for the next collection.
fn collect_intervals(
    provider: &SdkMeterProvider,
    exporter: &InMemoryMetricExporter,
) -> Vec<(String, f64)> {
    provider.force_flush().expect("flush");
    let mut out = Vec::new();
    for rm in exporter.get_finished_metrics().expect("metrics") {
        for sm in rm.scope_metrics() {
            for m in sm.metrics() {
                if m.name() != "forge.worker.interval" {
                    continue;
                }
                assert_eq!(m.unit(), "s");
                let AggregatedMetrics::F64(MetricData::Gauge(g)) = m.data() else {
                    panic!("forge.worker.interval is not an f64 gauge: {:?}", m.data());
                };
                for p in g.data_points() {
                    let attributes: Vec<KeyValue> = p.attributes().cloned().collect();
                    assert_eq!(attributes.len(), 1, "{attributes:?}");
                    assert_eq!(attributes[0].key.as_str(), "forge.worker");
                    out.push((attributes[0].value.to_string(), p.value()));
                }
            }
        }
    }
    exporter.reset();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn interval_is_reported_on_every_delta_collection() {
    let exporter = InMemoryMetricExporterBuilder::new()
        .with_temporality(Temporality::Delta)
        .build();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    forge_telemetry::init(&provider.meter("forge"));

    // Set once, as forge-server does when it spawns its workers.
    forge_telemetry::workers::set_interval("outbox", Duration::from_secs(10));
    forge_telemetry::workers::set_interval("reconciler", Duration::from_secs(3600));

    let expected = vec![
        ("outbox".to_string(), 10.0),
        ("reconciler".to_string(), 3600.0),
    ];
    for collection in 1..=3 {
        assert_eq!(
            collect_intervals(&provider, &exporter),
            expected,
            "collection {collection}"
        );
    }
}
