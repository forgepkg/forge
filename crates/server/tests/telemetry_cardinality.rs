//! The cardinality limits of the per-repository metrics, on the meter
//! provider `main` builds ([`meter_provider`]) and through Forge's own
//! instruments: more attribute sets than the SDK's default of 2,000 per
//! instrument are exported under their own attributes, and a set past the
//! raised limit, which the SDK folds into its `otel.metric.overflow` series
//! without a word, is warned about once. Needs neither Docker nor a
//! database.
//!
//! The tests of this binary share one provider, as a process does: each
//! records into, and asserts on, instruments of its own.

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use forge_server::telemetry::{cardinality_limit, meter_provider, REPOSITORY_BUDGET};
use forge_telemetry::proxy;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;

/// The SDK's limit without a view.
const SDK_DEFAULT: usize = 2000;

/// The process's meter provider, exporting to memory, and the warnings
/// logged.
struct Export {
    meter: SdkMeterProvider,
    metrics: InMemoryMetricExporter,
}

/// The warnings logged, each as its message and fields.
static WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Keeps the warnings: the export logs from the reader's thread, so this is
/// the process's subscriber.
struct Warnings;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Text(String);
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={value:?}", field.name()));
            }
        }
        if *event.metadata().level() == tracing::Level::WARN {
            let mut text = Text(String::new());
            event.record(&mut text);
            WARNINGS.lock().expect("warnings").push(text.0);
        }
    }
}

/// Set up the provider as `main` does, with Forge's instruments on it, once
/// per process.
fn export() -> &'static Export {
    static EXPORT: OnceLock<Export> = OnceLock::new();
    EXPORT.get_or_init(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(Warnings))
            .expect("the process's subscriber");
        let metrics = InMemoryMetricExporter::default();
        let meter = meter_provider(true, Resource::builder_empty().build(), metrics.clone());
        forge_telemetry::init(&meter.meter("forge"));
        Export { meter, metrics }
    })
}

/// A data point of a metric: its attributes and, of a histogram, its
/// bucket bounds.
struct Point {
    attributes: Vec<KeyValue>,
    bounds: Vec<f64>,
}

impl Point {
    fn value(&self, key: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| kv.value.to_string())
    }
}

/// Collect, and return the data points of metric `name` in that export.
fn points(name: &str) -> Vec<Point> {
    let export = export();
    export.meter.force_flush().expect("flush");
    let exports = export.metrics.get_finished_metrics().expect("metrics");
    // Cumulative: the last export holds every series.
    let last = exports.last().expect("an export");
    let mut out = Vec::new();
    for metric in last
        .scope_metrics()
        .flat_map(|scope| scope.metrics())
        .filter(|metric| metric.name() == name)
    {
        fn of<T>(data: &MetricData<T>, out: &mut Vec<Point>) {
            match data {
                MetricData::Sum(sum) => out.extend(sum.data_points().map(|p| Point {
                    attributes: p.attributes().cloned().collect(),
                    bounds: Vec::new(),
                })),
                MetricData::Histogram(histogram) => {
                    out.extend(histogram.data_points().map(|p| Point {
                        attributes: p.attributes().cloned().collect(),
                        bounds: p.bounds().collect(),
                    }))
                }
                MetricData::Gauge(_) | MetricData::ExponentialHistogram(_) => {
                    panic!("neither a sum nor a histogram")
                }
            }
        }
        match metric.data() {
            AggregatedMetrics::F64(data) => of(data, &mut out),
            AggregatedMetrics::U64(data) => of(data, &mut out),
            AggregatedMetrics::I64(data) => of(data, &mut out),
        }
    }
    out
}

/// The warnings logged about instrument `name`.
fn warnings_about(name: &str) -> Vec<String> {
    WARNINGS
        .lock()
        .expect("warnings")
        .iter()
        .filter(|warning| warning.contains(&format!("instrument={name:?}")))
        .cloned()
        .collect()
}

/// Every point carries its own attributes: none is the overflow series.
fn assert_none_overflowed(name: &str, points: &[Point]) {
    for point in points {
        assert_eq!(
            point.value("otel.metric.overflow"),
            None,
            "{name} overflowed"
        );
        assert!(
            point.value("forge.repository").is_some(),
            "{name}: a point without its repository: {:?}",
            point.attributes
        );
    }
}

#[test]
fn more_sets_than_the_sdks_default_keep_their_attributes() {
    export();
    // What the issue describes: a hundred proxies, each answered with thirty
    // statuses by its upstream and looking up two kinds with every outcome.
    let repositories: Vec<String> = (0..100).map(|n| format!("proxy-{n}")).collect();
    let statuses: Vec<u16> = (0..29).map(|n| 200 + n * 7).collect();
    for repository in &repositories {
        for &status in &statuses {
            proxy::upstream_request(repository, "GET", Some(status), Duration::from_millis(20));
        }
        proxy::upstream_request(repository, "GET", None, Duration::from_millis(20));
        for kind in [proxy::Kind::Metadata, proxy::Kind::Package] {
            for &outcome in proxy::Outcome::ALL {
                proxy::Lookup::start(repository, kind).finish(outcome);
            }
        }
    }

    let requests = points("http.client.request.duration");
    assert_eq!(requests.len(), 100 * 30);
    assert!(requests.len() > SDK_DEFAULT);
    assert_none_overflowed("http.client.request.duration", &requests);
    // The combination the alerts are about: each proxy's own 429.
    let rate_limited: BTreeSet<String> = requests
        .iter()
        .filter(|p| p.value("http.response.status_code").as_deref() == Some("249"))
        .filter_map(|p| p.value("forge.repository"))
        .collect();
    assert_eq!(rate_limited.len(), 100);
    // The view changes the limit alone: the buckets are the instrument's.
    let bounds = &requests[0].bounds;
    assert_eq!(bounds.len(), 17, "{bounds:?}");
    assert_eq!(
        (bounds.first(), bounds.last()),
        (Some(&0.005), Some(&120.0))
    );

    // 1,800 sets: under the default, and still all there.
    let lookups = points("forge.proxy.lookups");
    assert_eq!(lookups.len(), 100 * 2 * proxy::Outcome::ALL.len());
    assert_none_overflowed("forge.proxy.lookups", &lookups);

    for name in ["http.client.request.duration", "forge.proxy.lookups"] {
        assert_eq!(warnings_about(name), Vec::<String>::new());
    }
}

#[test]
fn a_set_past_the_raised_limit_is_warned_about_once() {
    export();
    let name = "forge.proxy.upstream.documents";
    let limit = cardinality_limit(name, true);
    assert_eq!(limit, REPOSITORY_BUDGET * proxy::DocumentSource::ALL.len());
    assert!(limit > SDK_DEFAULT);
    // Without the repository's name the SDK's limit stands.
    assert_eq!(cardinality_limit(name, false), SDK_DEFAULT);
    assert_eq!(
        cardinality_limit("http.server.request.duration", true),
        SDK_DEFAULT
    );

    // Exactly the limit: every repository of the budget, nothing to warn of.
    for n in 0..REPOSITORY_BUDGET {
        for &source in proxy::DocumentSource::ALL {
            proxy::upstream_document(&format!("budgeted-{n}"), source);
        }
    }
    let documents = points(name);
    assert_eq!(documents.len(), limit);
    assert_none_overflowed(name, &documents);
    assert_eq!(warnings_about(name), Vec::<String>::new());

    // One repository more: its sets land in the overflow series.
    for &source in proxy::DocumentSource::ALL {
        proxy::upstream_document("one-too-many", source);
    }
    let documents = points(name);
    assert_eq!(documents.len(), limit + 1);
    let overflow: Vec<&Point> = documents
        .iter()
        .filter(|p| p.value("otel.metric.overflow").is_some())
        .collect();
    assert_eq!(overflow.len(), 1);
    assert_eq!(overflow[0].value("forge.repository"), None);
    let warnings = warnings_about(name);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    for part in [
        format!("limit={limit}"),
        format!("repositories={REPOSITORY_BUDGET}"),
        "otel.metric.overflow=true".to_string(),
        "telemetry.per_repository".to_string(),
    ] {
        assert!(warnings[0].contains(&part), "{part}: {warnings:?}");
    }

    // The series stays in every export; the warning is not repeated.
    proxy::upstream_document("another-too-many", proxy::DocumentSource::Stored);
    points(name);
    assert_eq!(warnings_about(name).len(), 1);
}
