# Monitoring

A Grafana dashboard and example Prometheus alerting rules for Forge's
metrics. [docs/deployment.md → Metrics](../../docs/deployment.md#metrics)
describes the metrics listener and every metric.

| File | What it is |
| --- | --- |
| [`grafana-dashboard.json`](grafana-dashboard.json) | A Grafana dashboard: requests, proxies, storage, cache and database, workers, retention, authentication, inventory. Import it (Dashboards → New → Import) and pick your Prometheus data source; the `job`, `instance` and `repo` variables narrow it down. |
| [`alerts.yaml`](alerts.yaml) | Example alerting rules: a stalled, failing or restarting worker, S3 down, a high 5xx rate, a growing outbox backlog, upstream errors and rate limits per proxy, an exhausted connection pool, a lost Redis backplane, nearly full staging space. |

Scrape every Forge pod's metrics port (9421 in the Helm chart and the
kustomize base): with the prometheus-operator, the chart's
`metrics.serviceMonitor` / `metrics.podMonitor` or the kustomize component
`components/metrics`; with a plain Prometheus, a `kubernetes_sd_configs` job
for the pods' `metrics` port.

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
`promtool check rules deploy/monitoring/alerts.yaml`.
