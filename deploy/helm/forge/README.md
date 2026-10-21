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

A change of `config` or `secretEnv` rolls the pods through pod annotations.
Anyone who can read the pods can read those, and a plain hash of a password
can be tested against guesses, so `secretEnv` is hashed with a random salt
that the chart generates on install and keeps in the Secret
`<fullname>-checksum-salt` (looked up in the cluster on every upgrade).
Tools that render without a cluster (Argo CD, `helm template`) cannot look
it up and would roll the pods on every render: set `secretEnvChecksumSalt`
there (`openssl rand -hex 16`). A change inside `existingSecret` rolls
nothing; restart the pods yourself.

A production setup with an external PostgreSQL and S3 and a Redis in the
cluster:

```yaml
host: forge.example.com
replicaCount: 2

# Only the gateway may reach Forge: every address in trusted_proxy_cidrs
# chooses the client IP Forge sees. Listing a peer turns the policy on.
networkPolicy:
  from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: gateway-system   # your gateway's namespace

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

Forge believes the `X-Forwarded-For` header of every peer in
`trusted_proxy_cidrs`, which on Kubernetes is usually the whole pod network.
Without a NetworkPolicy any pod in the cluster can call the Service with a
forged client address and get past the login lockout and the anonymous-IP
allowlist. List the pods that proxy to Forge (the namespace of your gateway's
data plane or ingress controller) in `networkPolicy.from`, and the chart
renders the policy (`networkPolicy.enabled` is null by default, which means
"on as soon as `from` lists a peer"; `false` turns it off). The CNI must
enforce NetworkPolicy. The install notes warn while trusted proxies are set
without it.

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

Their images are pinned by digest: `image.tag` is `<tag>@sha256:…` (the
multi-arch index), which Dependabot bumps together with the tag. A digest in
`image.digest` replaces the pinned one; a plain `image.tag` such as `"16"`
pulls by tag.

Passwords are generated on install and kept across upgrades by looking up the
existing Secret; the PostgreSQL and S3 Secrets also survive `helm uninstall`
together with their volumes. Tools that render without a cluster (Argo CD,
`helm template`) cannot look them up and would generate new ones on every
render: set `auth.password` (or `auth.existingSecret`) there. Passwords are
pasted into Forge's connection URLs unescaped, so use URL-safe values
(`openssl rand -hex 24`). Redis restarts when `redis.auth.password` changes,
through a pod annotation salted like Forge's (the salt is kept in the Redis
Secret): with `redis.auth.password` in Argo CD, set
`redis.auth.checksumSalt` too.

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
[ci/](ci), validates the output with kubeconform, parses every rendered
`forge.toml`, and checks that the pod annotations hashing secrets are
salted. Locally, with `helm`, `kubeconform` and `python3` on your PATH:

```bash
.github/scripts/helm-check.sh 1.33.0
```
