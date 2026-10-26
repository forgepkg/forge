# Monitoring

An example OpenTelemetry Collector configuration, a Grafana dashboard and
example Prometheus alerting rules for Forge's telemetry.
[docs/deployment.md → Telemetry](../../docs/deployment.md#telemetry)
describes how Forge exports metrics, traces and logs over OTLP, and every
metric.

| File | What it is |
| --- | --- |
| [`otel-collector.yaml`](otel-collector.yaml) | An OpenTelemetry Collector (`otelcol-contrib`) receiving Forge's OTLP/HTTP on port 4318: the metrics for Prometheus to scrape on port 8889, the traces and logs sent on over OTLP (placeholders for Tempo and Loki). |
| [`grafana-dashboard.json`](grafana-dashboard.json) | A Grafana dashboard: requests, proxies, storage, cache and database, workers, retention, authentication, inventory. Import it (Dashboards → New → Import) and pick your Prometheus data source; the `job`, `instance` and `repository` variables narrow it down. |
| [`alerts.yaml`](alerts.yaml) | Example alerting rules: a stalled, failing or restarting worker, S3 down, a high 5xx rate, a growing outbox backlog, upstream errors and rate limits per proxy, an exhausted connection pool, a lost Redis backplane, nearly full staging space. |

The dashboard and the rules use the names Prometheus gives OpenTelemetry
metrics: dots become underscores and the unit a suffix
(`http.server.request.duration` is `http_server_request_duration_seconds`,
`forge.proxy.lookups` is `forge_proxy_lookups_total`), attributes become
labels (`forge.repository` is `forge_repository`), and `job` and `instance`
come from the resource's `service.name` and `service.instance.id`. That is
what the Collector's `prometheus` and `prometheusremotewrite` exporters
write, and what Prometheus' own OTLP receiver (`--web.enable-otlp-receiver`,
which Forge can export to directly) stores by default.

Scrape the Collector with `honor_labels: true`: otherwise Prometheus
replaces each series' `job` and `instance` with the Collector's own. With
the prometheus-operator, a ServiceMonitor or PodMonitor for the Collector's
port 8889 with `honorLabels: true`.

To load the rules with the prometheus-operator, wrap them in a
PrometheusRule (labeled for your Prometheus's `ruleSelector`):

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: forge
spec:
  groups: [] # the `groups` of alerts.yaml
```

The thresholds are starting points; check edits with
`promtool check rules deploy/monitoring/alerts.yaml`, and the Collector's
configuration with
`otelcol-contrib validate --config deploy/monitoring/otel-collector.yaml`.
