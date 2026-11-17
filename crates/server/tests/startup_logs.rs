//! What the `forge-server` binary logs while it starts (#559), run as a
//! process with the trace and log export on, against a database that
//! refuses the connection:
//!
//! * the OpenTelemetry SDK's warning about an `OTEL_TRACES_SAMPLER_ARG` it
//!   cannot use is printed on the console, where it went nowhere before the
//!   process's subscriber was installed;
//! * the failed start is an `ERROR` of the log, on the console and in the
//!   log export, which is flushed before the process ends: the batch delay
//!   is far longer than the test, so only the shutdown sends the record.
//!
//! Needs no database and no Docker.

use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::routing::post;
use axum::Router;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::common::v1::AnyValue as Any;
use opentelemetry_proto::tonic::logs::v1::SeverityNumber;
use prost::Message as _;

/// What the receiver was sent: the signal and the body.
type Received = Arc<Mutex<Vec<(String, Bytes)>>>;

/// A mock OTLP/HTTP receiver keeping every export it is sent.
async fn start_receiver() -> (String, Received) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let received: Received = Arc::default();
    async fn export(
        State(received): State<Received>,
        Path(signal): Path<String>,
        body: Bytes,
    ) -> Vec<u8> {
        received.lock().unwrap().push((signal, body));
        // An empty Export*ServiceResponse: everything accepted.
        Vec::new()
    }
    let app = Router::new()
        .route("/v1/{signal}", post(export))
        .with_state(received.clone());
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, received)
}

fn text(value: Option<&Any>) -> Option<&str> {
    match value?.value.as_ref()? {
        AnyValue::StringValue(s) => Some(s),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_start_and_the_sdks_warnings_reach_the_logs() {
    let (endpoint, received) = start_receiver().await;
    // A port nothing listens on: the database refuses the connection.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("forge.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[server]
bind = "127.0.0.1:0"
public_base_url = "http://localhost:8421"
allow_insecure_defaults = true

[database]
url = "postgres://forge:forge@127.0.0.1:{closed}/forge"
acquire_timeout_seconds = 2

[s3]
endpoint = "http://127.0.0.1:{closed}"
region = "us-east-1"
bucket = "forge"
access_key = "minioadmin"
secret_key = "minioadmin"
force_path_style = true

[crypto.root]
provider = "env"

[telemetry]
traces = true
logs = true
"#
        ),
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_forge-server"));
    // Nothing of the environment the tests run in configures the server.
    for (name, _) in std::env::vars_os() {
        let name_str = name.to_string_lossy();
        if name_str.starts_with("FORGE_") || name_str.starts_with("OTEL_") || name_str == "RUST_LOG"
        {
            command.env_remove(&name);
        }
    }
    command
        .current_dir(dir.path())
        .env("FORGE_CONFIG", &config)
        .env(
            "FORGE_ROOT_KEY",
            "ZGV2LXJvb3Qta2V5LWZvci1sb2NhbC1mb3JnZS0wMDE=",
        )
        .env("NO_COLOR", "1")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", &endpoint)
        // Helm's `telemetry.samplerArg: "10%"`: no number.
        .env("OTEL_TRACES_SAMPLER", "parentbased_traceidratio")
        .env("OTEL_TRACES_SAMPLER_ARG", "10%")
        // No batch is sent on its own within the test: what arrives was
        // flushed by the shutdown.
        .env("OTEL_BLRP_SCHEDULE_DELAY", "600000")
        .env("OTEL_BSP_SCHEDULE_DELAY", "600000")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = tokio::task::spawn_blocking(move || command.output())
        .await
        .unwrap()
        .expect("run forge-server");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let said = format!("stdout:\n{stdout}\nstderr:\n{stderr}");

    assert!(!output.status.success(), "the start fails\n{said}");

    // The SDK's warning, on the console.
    let warning = stdout
        .lines()
        .find(|line| line.contains("OTEL_TRACES_SAMPLER_ARG"))
        .unwrap_or_else(|| panic!("the SDK's warning is printed\n{said}"));
    assert!(warning.contains("WARN"), "{warning}");
    assert!(warning.contains("10%"), "{warning}");

    // The failed start, on the console as a log line...
    let error = stdout
        .lines()
        .find(|line| line.contains("forge-server failed to start"))
        .unwrap_or_else(|| panic!("the failed start is logged\n{said}"));
    assert!(error.contains("ERROR"), "{error}");
    assert!(error.contains("connect database"), "{error}");
    // ...and still what the process ends with.
    assert!(stderr.contains("connect database"), "{said}");

    // ...and in the log export, which the shutdown flushed.
    let received = received.lock().unwrap().clone();
    let records: Vec<_> = received
        .iter()
        .filter(|(signal, _)| signal == "logs")
        .map(|(_, body)| ExportLogsServiceRequest::decode(body.as_ref()).expect("OTLP logs"))
        .flat_map(|request| request.resource_logs)
        .flat_map(|resource| resource.scope_logs)
        .flat_map(|scope| scope.log_records)
        .collect();
    let record = records
        .iter()
        .find(|record| text(record.body.as_ref()) == Some("forge-server failed to start"))
        .unwrap_or_else(|| panic!("the failed start is exported: {records:?}\n{said}"));
    assert_eq!(record.severity_number, SeverityNumber::Error as i32);
    let cause = record
        .attributes
        .iter()
        .find(|kv| kv.key == "error")
        .and_then(|kv| text(kv.value.as_ref()))
        .expect("the error's cause");
    assert!(cause.contains("connect database"), "{cause}");
}
