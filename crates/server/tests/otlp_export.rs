//! The OTLP/HTTP export as `main` sets it up ([`Telemetry::new`]): with
//! `[telemetry]` on, Forge's metrics, a span and the log record written in
//! it reach the receiver `OTEL_EXPORTER_OTLP_ENDPOINT` names, as protobuf,
//! with Forge's resource. A binary of its own: it sets the process's
//! `OTEL_*` variables. Needs no database.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::routing::post;
use axum::Router;
use forge_server::config::TelemetryConfig;
use forge_server::telemetry::Telemetry;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::SpanKind;
use prost::Message as _;
use tracing_subscriber::layer::SubscriberExt;

/// What the receiver was sent: the signal, the content type, the body.
type Received = Arc<Mutex<Vec<(String, String, Bytes)>>>;

/// A mock OTLP/HTTP receiver keeping every export it is sent.
async fn start_receiver() -> (String, Received) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let received: Received = Arc::default();
    async fn export(
        State(received): State<Received>,
        Path(signal): Path<String>,
        headers: HeaderMap,
        body: Bytes,
    ) -> ([(header::HeaderName, &'static str); 1], Vec<u8>) {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        received.lock().unwrap().push((signal, content_type, body));
        // An empty Export*ServiceResponse: everything accepted.
        (
            [(header::CONTENT_TYPE, "application/x-protobuf")],
            Vec::new(),
        )
    }
    let app = Router::new()
        .route("/v1/{signal}", post(export))
        .with_state(received.clone());
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, received)
}

fn string(kv: &KeyValue) -> Option<&str> {
    match kv.value.as_ref()?.value.as_ref()? {
        AnyValue::StringValue(s) => Some(s),
        _ => None,
    }
}

fn resource_attribute<'a>(resource: Option<&'a Resource>, key: &str) -> Option<&'a str> {
    resource?
        .attributes
        .iter()
        .find(|kv| kv.key == key)
        .and_then(string)
}

#[tokio::test(flavor = "multi_thread")]
async fn signals_are_exported_over_otlp_http() {
    let (endpoint, received) = start_receiver().await;
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", &endpoint);
    std::env::set_var(
        "OTEL_RESOURCE_ATTRIBUTES",
        "deployment.environment.name=test,service.instance.id=ns.pod-1.forge",
    );
    std::env::remove_var("OTEL_SERVICE_NAME");
    std::env::remove_var("OTEL_SDK_DISABLED");

    let telemetry = Telemetry::new(&TelemetryConfig {
        metrics: true,
        traces: true,
        logs: true,
        ..Default::default()
    })
    .expect("set up the export");
    assert!(telemetry.metrics());
    telemetry.install();
    let subscriber = tracing_subscriber::registry().with(telemetry.layers());
    tracing::subscriber::with_default(subscriber, || {
        forge_telemetry::http::request(
            forge_telemetry::http::Surface::Nuget,
            "GET",
            200,
            Duration::from_millis(12),
        );
        let run = forge_telemetry::workers::Run::start("otlp-test");
        run.span()
            .in_scope(|| tracing::warn!(attempt = 1, "an exported warning"));
        run.finish(true);
        // The export's own client never logs into the export.
        tracing::warn!(target: "reqwest::connect", "not exported");
    });
    tokio::task::spawn_blocking(move || telemetry.shutdown())
        .await
        .unwrap();

    let received = received.lock().unwrap().clone();
    for (signal, content_type, _) in &received {
        assert_eq!(content_type, "application/x-protobuf", "{signal}");
    }
    let bodies = |signal: &str| -> Vec<Bytes> {
        received
            .iter()
            .filter(|(s, _, _)| s == signal)
            .map(|(_, _, body)| body.clone())
            .collect()
    };

    // Metrics: Forge's instruments, under Forge's resource.
    let metrics: Vec<ExportMetricsServiceRequest> = bodies("metrics")
        .iter()
        .map(|b| ExportMetricsServiceRequest::decode(b.as_ref()).expect("OTLP metrics"))
        .collect();
    let resource_metrics = metrics
        .iter()
        .flat_map(|m| &m.resource_metrics)
        .next()
        .expect("metrics were exported");
    let resource = resource_metrics.resource.as_ref();
    assert_eq!(resource_attribute(resource, "service.name"), Some("forge"));
    assert_eq!(
        resource_attribute(resource, "service.version"),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        resource_attribute(resource, "deployment.environment.name"),
        Some("test")
    );
    // The environment's attributes win over Forge's own.
    assert_eq!(
        resource_attribute(resource, "service.instance.id"),
        Some("ns.pod-1.forge")
    );
    assert!(resource_attribute(resource, "telemetry.sdk.name").is_some());
    let names: Vec<&str> = metrics
        .iter()
        .flat_map(|m| &m.resource_metrics)
        .flat_map(|rm| &rm.scope_metrics)
        .flat_map(|sm| &sm.metrics)
        .map(|m| m.name.as_str())
        .collect();
    for name in [
        "http.server.request.duration",
        "forge.worker.runs",
        "forge.worker.run.duration",
    ] {
        assert!(names.contains(&name), "{name} not in {names:?}");
    }

    // Traces: the worker pass.
    let spans: Vec<_> = bodies("traces")
        .iter()
        .map(|b| ExportTraceServiceRequest::decode(b.as_ref()).expect("OTLP traces"))
        .flat_map(|t| t.resource_spans)
        .flat_map(|rs| rs.scope_spans)
        .flat_map(|ss| ss.spans)
        .collect();
    let pass = spans
        .iter()
        .find(|s| s.name == "otlp-test pass")
        .unwrap_or_else(|| panic!("the pass's span: {spans:#?}"));
    assert_eq!(pass.kind, SpanKind::Internal as i32);
    assert!(pass
        .attributes
        .iter()
        .any(|kv| kv.key == "forge.worker" && string(kv) == Some("otlp-test")));

    // Logs: the warning, in the pass's span; nothing of the export's client.
    let records: Vec<_> = bodies("logs")
        .iter()
        .map(|b| ExportLogsServiceRequest::decode(b.as_ref()).expect("OTLP logs"))
        .flat_map(|l| l.resource_logs)
        .flat_map(|rl| rl.scope_logs)
        .flat_map(|sl| sl.log_records)
        .collect();
    let body = |record: &opentelemetry_proto::tonic::logs::v1::LogRecord| {
        record
            .body
            .as_ref()
            .and_then(|b| b.value.as_ref())
            .and_then(|v| match v {
                AnyValue::StringValue(s) => Some(s.clone()),
                _ => None,
            })
    };
    let warning = records
        .iter()
        .find(|r| body(r).as_deref() == Some("an exported warning"))
        .unwrap_or_else(|| panic!("the warning: {records:#?}"));
    assert_eq!(warning.severity_text, "WARN");
    assert_eq!(warning.trace_id, pass.trace_id);
    assert_eq!(warning.span_id, pass.span_id);
    assert!(
        records
            .iter()
            .all(|r| body(r).as_deref() != Some("not exported")),
        "{records:#?}"
    );
}
