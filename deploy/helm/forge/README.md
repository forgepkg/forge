# Helm chart

A Helm chart for running Forge on Kubernetes (1.30 or later), next to the
kustomize manifests in [deploy/kubernetes](../../kubernetes/README.md). Both
set the same probes, shutdown timing and `restricted` security context; read
[docs/deployment.md](../../../docs/deployment.md) for what every Forge setting
means.

Each release publishes the chart to GitHub Packages as an OCI artifact,
[`oci://ghcr.io/forgepkg/charts/forge`](https://github.com/forgepkg/forge/pkgs/container/charts%2Fforge),
with the same version as the image (from 2.0.0 on; the releases up to 1.1.0
are at `oci://ghcr.io/schmitch/charts/forge` and `ghcr.io/schmitch/forge`):

```bash
helm install forge oci://ghcr.io/forgepkg/charts/forge --version 2.0.0 \
  --namespace forge --create-namespace --values my-values.yaml
```

## Which image runs

The chart's `appVersion` is the release it belongs to, and the image tag
defaults to it. The release workflow also writes the digest of the image it
built and signed into the published chart (the `forge/image-digest`
annotation in `Chart.yaml`), so a published chart deploys exactly that image
([`ghcr.io/forgepkg/forge`](https://github.com/forgepkg/forge/pkgs/container/forge)):

```
ghcr.io/forgepkg/forge:2.0.0@sha256:…
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
| `secretEnv` | A Secret the chart creates (`<fullname>-secret-env`), loaded with `envFrom`: `FORGE_DATABASE__URL`, `FORGE_S3__ACCESS_KEY`, `FORGE_ROOT_KEY` (required), … |
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

A production setup with an external PostgreSQL and S3 and a Valkey in the
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
    bootstrap_admin:
      username: admin@example.com       # a UPN of your organization
  s3:
    endpoint: https://s3.eu-central-1.amazonaws.com
    region: eu-central-1
    bucket: forge
    force_path_style: false

existingSecret: forge-credentials       # FORGE_DATABASE__URL, FORGE_S3__ACCESS_KEY,
                                        # FORGE_S3__SECRET_KEY, FORGE_ROOT_KEY,
                                        # FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD
valkey:
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

Secret encryption at rest is required: Forge seals the secrets it stores
(proxy passwords, realm secrets, the email credentials, its signing keys)
under a root key, `FORGE_ROOT_KEY` (`openssl rand -base64 32`). The chart
defaults to the `env` provider (`config.crypto.root.provider`) and refuses to
render unless `secretEnv`, `existingSecret` or `env` provides the key (or
`config.crypto.root` names a key file). Keep the root key with your backups:
without it the stored secrets cannot be read. Every other value is documented
in [values.yaml](values.yaml).

## Short-lived S3 credentials

Instead of `FORGE_S3__ACCESS_KEY` / `FORGE_S3__SECRET_KEY` in a Secret, Forge
can get temporary S3 credentials from the pod's identity and refresh them
itself (`s3.credentials`; the IAM policy and the store-side setup are in
[docs/deployment.md](../../../docs/deployment.md#short-lived-s3-credentials)).
Leave the S3 keys out of `secretEnv` and `existingSecret` then: Forge refuses
to start with keys it would not use, and the chart refuses them in
`secretEnv`.

IRSA on EKS: annotate the service account with the role and use the AWS SDK
default credentials chain, which reads what the EKS webhook injects:

```yaml
s3:
  credentials: default_chain
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/forge
```

EKS Pod Identity: `s3.credentials: default_chain` and a Pod Identity
association for the release's service account (`<fullname>`, or
`serviceAccount.name`); nothing else in the values.

MinIO, Ceph RGW, or AWS without EKS: `web_identity` exchanges a projected
service-account token at the store's STS. The chart mounts the token
(audience `s3.webIdentity.projectedToken.audience`) at
`/var/run/secrets/forge/s3/token`:

```yaml
s3:
  credentials: web_identity
  webIdentity:
    stsEndpoint: http://minio.storage.svc:9000   # empty: AWS STS
    roleArn: arn:minio:iam:::role/<id>           # the role ARN MinIO logs at startup
    projectedToken:
      audience: forge-s3                         # MINIO_IDENTITY_OPENID_CLIENT_ID
```

`automountServiceAccountToken` stays `false` in every mode. The chart's
token is a separate projected volume for the STS audience, not a Kubernetes
API token. The EKS IRSA and Pod Identity webhook also adds its own projected
token volume and environment variables. It chooses pods by the service
account's role annotation or a Pod Identity association, and does not read
`automountServiceAccountToken` (amazon-eks-pod-identity-webhook,
`pkg/handler/handler.go`). With a restricted `networkPolicy.egress`, allow
the STS, or for EKS Pod Identity the node's agent at `169.254.170.23:80`.

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
the largest repository upload limit (set per repository in the web UI; by
default 512 MiB, and 1 GiB per image layer), and keep the gateway's upstream
idle timeout below `server.header_read_timeout_seconds` (150 s; Envoy and
Istio default to one hour). Add the policy objects of your implementation (Envoy
Gateway `BackendTrafficPolicy`, …), or an Ingress if you need one, with
`extraObjects`.

## extraObjects

`extraObjects` renders further objects with the release, given as YAML or as
strings. Both go through `tpl`, so they can use values and the chart's
helpers. It is a list or a map; the keys of a map only name its entries,
which render in key order:

```yaml
extraObjects:
  envoy-policy:
    apiVersion: gateway.envoyproxy.io/v1alpha1
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

Helm merges a map across values files (`-f base.yaml -f production.yaml`):
each file can add its own objects, and a later one replaces an entry by its
key or drops it with `null` (`--set extraObjects.envoy-policy=null`). A list
in a later file replaces the whole list.

## Optional dependencies

Three single-instance backing services ship inside the chart (`charts/`), for
evaluation and small installs. Each is a chart dependency, off by default,
and wired into Forge when enabled:

| Dependency | Enable with | Sets |
| --- | --- | --- |
| PostgreSQL 17 (StatefulSet) | `postgresql.enabled` | `FORGE_DATABASE__URL` |
| Valkey, cache only (Deployment) | `valkey.enabled` | `FORGE_REDIS__URL` |
| versitygw S3 gateway (StatefulSet) | `versitygw.enabled` | `s3.endpoint`, `s3.bucket`, `FORGE_S3__ACCESS_KEY` / `_SECRET_KEY` (static root credentials only: not with short-lived `s3.credentials`) |

None has backups, replication or failover. For production use a managed
PostgreSQL (or an operator such as CloudNativePG; point
`FORGE_DATABASE__URL` at its app Secret with `env`) and a real object store.
Leaving `valkey.enabled` off and setting `FORGE_REDIS__URL` (in `secretEnv` or
`existingSecret`) uses your own Valkey or Redis instead; Forge speaks the
Redis protocol to either.
Each one only accepts connections from this release's Forge pods (a
NetworkPolicy), and every value is listed in
`charts/<name>/values.yaml`; set them under the dependency's key.

Their images come from ghcr.io, like Forge's: `ghcr.io/forgepkg/forge/<name>`
holds byte-for-byte copies of the Docker Hub images (`library/postgres`,
`valkey/valkey`, `versity/versitygw`) under the same digests, so a cluster
needs no access to Docker Hub. To pull the originals instead, set
`image.registry: docker.io` and `image.repository` to the Docker Hub name;
the pinned digest stays valid. They are pinned by digest: `image.tag` is
`<tag>@sha256:…` (the multi-arch index), which Dependabot bumps together with
the tag. A digest in `image.digest` replaces the pinned one; a plain
`image.tag` such as `"16"` pulls by tag.

Passwords are generated on install and kept across upgrades by looking up the
existing Secret; the PostgreSQL and S3 Secrets also survive `helm uninstall`
together with their volumes. Tools that render without a cluster (Argo CD,
`helm template`) cannot look them up and would generate new ones on every
render: set `auth.password` (or `auth.existingSecret`) there. Passwords are
pasted into Forge's connection URLs unescaped, so use URL-safe values
(`openssl rand -hex 24`). Valkey restarts when `valkey.auth.password`
changes, through a pod annotation salted like Forge's (the salt is kept in
the Valkey Secret): with `valkey.auth.password` in Argo CD, set
`valkey.auth.checksumSalt` too.

Evaluation install, everything in the cluster:

```bash
password=$(openssl rand -hex 12); echo "admin password: $password"
helm install forge oci://ghcr.io/forgepkg/charts/forge --version 2.0.0 \
  --namespace forge-eval --create-namespace \
  --set postgresql.enabled=true --set versitygw.enabled=true \
  --set config.auth.bootstrap_admin.username=admin@example.com \
  --set secretEnv.FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD="$password"
kubectl -n forge-eval rollout status deployment/forge
kubectl -n forge-eval port-forward svc/forge 8421
```

Open http://localhost:8421 and sign in as `admin@example.com` with that
password. The bootstrap admin is named by a UPN and has no default name.

## Checking changes

CI lints the chart and renders it with the default values and each file in
[ci/](ci), validates the output with kubeconform, parses every rendered
`forge.toml`, and checks that the pod annotations hashing secrets are
salted. Locally, with `helm`, `kubeconform` and `python3` on your PATH:

```bash
.github/scripts/helm-check.sh 1.33.0
```
