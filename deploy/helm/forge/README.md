# Helm chart

A Helm chart for running Forge on Kubernetes (1.30 or later), next to the
kustomize manifests in [deploy/kubernetes](../../kubernetes/README.md). Both
set the same probes, shutdown timing and `restricted` security context; read
[docs/deployment.md](../../../docs/deployment.md) for what every Forge setting
means.

Each release publishes the chart to GitHub Container Registry as an OCI
artifact, with the same version as the image:

```bash
helm install forge oci://ghcr.io/schmitch/charts/forge --version 1.0.0 \
  --namespace forge --create-namespace --values my-values.yaml
```

## Which image runs

The chart's `appVersion` is the release it belongs to, and the image tag
defaults to it. The release workflow also writes the digest of the image it
built and signed into the published chart (the `forge.envisia.de/image-digest`
annotation in `Chart.yaml`), so a published chart deploys exactly that image:

```
ghcr.io/schmitch/forge:1.0.0@sha256:…
```

Setting `image.tag` or `image.digest` replaces that pin. Upgrading Forge is
upgrading the chart (`helm upgrade --version <new>`); read the changelog
first, since migrations only go forward. Both the image and the chart are
signed with keyless cosign; the commands are in each GitHub release.

## Configuration

Forge reads `forge.toml` plus `FORGE_*` environment variables. The chart maps
them like this:

| Values | Becomes |
| --- | --- |
| `config` | `forge.toml` in a ConfigMap, loaded through `FORGE_CONFIG`. Any key of [forge.toml.example](../../../forge.toml.example), as YAML, nested by section. |
| `host` | `server.public_base_url` (`https://<host>`), and the default host of the HTTPRoute, the ListenerSet listener and the Certificate. |
| `secretEnv` | A Secret the chart creates (`<fullname>-secret-env`), loaded with `envFrom`: `FORGE_DATABASE__URL`, `FORGE_S3__ACCESS_KEY`, `FORGE_ROOT_KEY`, … |
| `existingSecret` | An existing Secret loaded with `envFrom` (External Secrets, Sealed Secrets, SOPS, …); it wins over `secretEnv` for a key in both. Any name but the chart's own `<fullname>-secret-env`. |
| `env`, `envFrom` | Further variables; `valueFrom` reads single Secret keys. They win over the chart's own. |

Environment variables override `forge.toml`. Keep secrets out of `config`:
the chart warns when it finds one there. The chart sets `server.bind` from
`containerPort`, and a key set to `null` in `config` removes a chart default.

A production setup with an external PostgreSQL and S3 and a Redis in the
cluster:

```yaml
host: forge.example.com
replicaCount: 2

config:
  auth:
    trusted_proxy_cidrs: [10.0.0.0/8]   # the gateway's pod network
  s3:
    endpoint: https://s3.eu-central-1.amazonaws.com
    region: eu-central-1
    bucket: forge
    force_path_style: false
  crypto:
    root:
      provider: env                     # secret encryption at rest

existingSecret: forge-credentials       # FORGE_DATABASE__URL, FORGE_S3__ACCESS_KEY,
                                        # FORGE_S3__SECRET_KEY, FORGE_ROOT_KEY,
                                        # FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD
redis:
  enabled: true

podDisruptionBudget:
  enabled: true
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway

httpRoute:
  enabled: true
  parentRefs:
    - name: gateway
      namespace: gateway-system
      sectionName: https
```

Turn on secret encryption at rest (`config.crypto` and `FORGE_ROOT_KEY`)
before you configure proxy repositories or auth realms, and keep the root key
with your backups. Every other value is documented in
[values.yaml](values.yaml).

## Routing: HTTPRoute and ListenerSet

The chart has no Ingress; it routes through the Gateway API.

- **`httpRoute`** attaches an HTTPRoute for `host` to the Gateways in
  `httpRoute.parentRefs`. A rule without `backendRefs` routes to the forge
  Service, so rules can add `timeouts`, `filters` or `matches` without
  repeating it.
- **`listenerSet`** adds the release's own HTTPS listener to a shared Gateway
  as a ListenerSet (Gateway API 1.5+), so the Gateway's owner does not add a
  listener per application. The Gateway must allow it
  (`spec.allowedListeners.namespaces.from`). The HTTPRoute attaches to the
  ListenerSet automatically, and the listener terminates TLS with the Secret
  `<fullname>-tls`, which `certificate.enabled` has cert-manager issue:

  ```yaml
  host: forge.example.com
  httpRoute:
    enabled: true
  listenerSet:
    enabled: true
    parentRef:
      name: gateway
      namespace: gateway-system
  certificate:
    enabled: true
    issuerRef:
      name: letsencrypt
  ```

Request size limits and timeouts are implementation-specific: allow pushes of
`server.max_upload_bytes` (512 MiB) and keep the gateway's upstream idle
timeout below `server.header_read_timeout_seconds` (150 s; Envoy and Istio
default to one hour). Add the policy objects of your implementation (Envoy
Gateway `BackendTrafficPolicy`, …), or an Ingress if you need one, with
`extraObjects`.

## extraObjects

`extraObjects` renders further objects with the release, given as YAML or as
strings. Both go through `tpl`, so they can use values and the chart's
helpers:

```yaml
extraObjects:
  - apiVersion: gateway.envoyproxy.io/v1alpha1
    kind: BackendTrafficPolicy
    metadata:
      name: '{{ include "forge.fullname" . }}'
    spec:
      targetRefs:
        - group: gateway.networking.k8s.io
          kind: HTTPRoute
          name: '{{ include "forge.fullname" . }}'
      timeout:
        http:
          connectionIdleTimeout: 120s
```

## Optional dependencies

Three single-instance backing services ship inside the chart (`charts/`), for
evaluation and small installs. Each is a chart dependency, off by default,
and wired into Forge when enabled:

| Dependency | Enable with | Sets |
| --- | --- | --- |
| PostgreSQL 17 (StatefulSet) | `postgresql.enabled` | `FORGE_DATABASE__URL` |
| Redis, cache only (Deployment) | `redis.enabled` | `FORGE_REDIS__URL` |
| versitygw S3 gateway (StatefulSet) | `versitygw.enabled` | `s3.endpoint`, `s3.bucket`, `FORGE_S3__ACCESS_KEY` / `_SECRET_KEY` |

None has backups, replication or failover. For production use a managed
PostgreSQL (or an operator such as CloudNativePG; point
`FORGE_DATABASE__URL` at its app Secret with `env`) and a real object store.
Each one only accepts connections from this release's Forge pods (a
NetworkPolicy), and every value is listed in
`charts/<name>/values.yaml`; set them under the dependency's key.

Passwords are generated on install and kept across upgrades by looking up the
existing Secret; the PostgreSQL and S3 Secrets also survive `helm uninstall`
together with their volumes. Tools that render without a cluster (Argo CD,
`helm template`) cannot look them up and would generate new ones on every
render: set `auth.password` (or `auth.existingSecret`) there. Passwords are
pasted into Forge's connection URLs unescaped, so use URL-safe values
(`openssl rand -hex 24`).

Evaluation install, everything in the cluster:

```bash
password=$(openssl rand -hex 12); echo "admin password: $password"
helm install forge oci://ghcr.io/schmitch/charts/forge --version 1.0.0 \
  --namespace forge-eval --create-namespace \
  --set postgresql.enabled=true --set versitygw.enabled=true \
  --set secretEnv.FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD="$password"
kubectl -n forge-eval rollout status deployment/forge
kubectl -n forge-eval port-forward svc/forge 8421
```

Open http://localhost:8421 and sign in as `admin` with that password.

## Checking changes

CI lints the chart and renders it with the default values and each file in
[ci/](ci), validates the output with kubeconform, and parses every rendered
`forge.toml`. Locally, with `helm`, `kubeconform` and `python3` on your PATH:

```bash
.github/scripts/helm-check.sh 1.33.0
```
