//! `forge.worker.last_success.time` under delta temporality (#874): it is
//! reported on every collection, not only the one after a successful pass,
//! so `ForgeWorkerStalled` still has it while a worker stalls.
//!
//! A test binary of its own: [`forge_telemetry::init`] counts only its first
//! call in a process, and this one needs a meter that exports deltas.

use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{
    InMemoryMetricExporter, InMemoryMetricExporterBuilder, PeriodicReader, SdkMeterProvider,
    Temporality,
};

/// Collect once and return the `forge.worker.last_success.time` points
/// (worker, Unix seconds), then clear the exporter for the next collection.
fn collect_last_success(
    provider: &SdkMeterProvider,
    exporter: &InMemoryMetricExporter,
) -> Vec<(String, f64)> {
    provider.force_flush().expect("flush");
    let mut out = Vec::new();
    for rm in exporter.get_finished_metrics().expect("metrics") {
        for sm in rm.scope_metrics() {
            for m in sm.metrics() {
                if m.name() != "forge.worker.last_success.time" {
                    continue;
                }
                assert_eq!(m.unit(), "s");
                let AggregatedMetrics::F64(MetricData::Gauge(g)) = m.data() else {
                    panic!(
                        "forge.worker.last_success.time is not an f64 gauge: {:?}",
                        m.data()
                    );
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
fn last_success_is_reported_on_every_delta_collection() {
    let exporter = InMemoryMetricExporterBuilder::new()
        .with_temporality(Temporality::Delta)
        .build();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    forge_telemetry::init(&provider.meter("forge"));

    // One successful pass each; a failed pass leaves no last success.
    forge_telemetry::workers::Run::start("outbox").finish(true);
    forge_telemetry::workers::Run::start("reconciler").finish(true);
    forge_telemetry::workers::Run::start("retention").finish(false);

    let first = collect_last_success(&provider, &exporter);
    let workers: Vec<&str> = first.iter().map(|(w, _)| w.as_str()).collect();
    assert_eq!(workers, ["outbox", "reconciler"]);
    for (worker, time) in &first {
        assert!(*time > 1.0e9, "{worker}: {time} is not a Unix time");
    }

    // No pass in between: the same values, on every collection.
    for collection in 2..=3 {
        assert_eq!(
            collect_last_success(&provider, &exporter),
            first,
            "collection {collection}"
        );
    }

    // A failed pass keeps the last success.
    forge_telemetry::workers::Run::start("outbox").finish(false);
    assert_eq!(collect_last_success(&provider, &exporter), first);
}
