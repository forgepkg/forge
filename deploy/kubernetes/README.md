# Kubernetes manifests

Kustomize manifests for running Forge on Kubernetes (1.30 or later). Read
[docs/deployment.md](../../docs/deployment.md) first: it explains every
setting these manifests set or leave to you. If you deploy with Helm, use the
chart in [deploy/helm/forge](../helm/forge/README.md) instead: it is
published with every release and needs no copied overlay.

```
deploy/kubernetes/
├── base/                    the Forge server: Deployment, Service, ServiceAccount, ConfigMap
├── components/
│   ├── ingress/             Ingress with TLS (ingress-nginx annotations for large, slow pushes)
│   ├── httproute/           Gateway API HTTPRoute instead of an Ingress
│   ├── network-policy/      only the ingress controller / gateway reaches Forge
│   ├── valkey/              in-cluster Valkey (shared cache), password-protected
│   ├── high-availability/   two replicas, spread over nodes, PodDisruptionBudget
│   ├── local-cache/         local blob cache on an emptyDir (faster downloads, serves through an S3 outage)
│   ├── local-cache-persistent/  the same on a PersistentVolume (one replica, survives restarts)
│   ├── postgres/            in-cluster PostgreSQL 17 (evaluation / small installs)
│   ├── s3-versitygw/        in-cluster S3 gateway on a PersistentVolume (evaluation / small installs)
│   ├── s3-workload-identity/  short-lived S3 credentials from a projected service-account token (no S3 keys)
│   └── image-latest/        run :latest instead of the pinned release
└── overlays/
    ├── production/          external PostgreSQL + S3, Valkey, two replicas, Ingress, NetworkPolicy
    └── evaluation/          everything in-cluster, no Ingress
```

## Which image runs

The base pins the image to the release it belongs to:

```yaml
images:
  - name: ghcr.io/forgepkg/forge
    newTag: 1.0.0
```

`cargo xtask release <version>` rewrites that `newTag` in the same commit as
the version bump, before it creates the `v<version>` tag, and the release
workflow refuses a tag whose base names another version. So the manifests at
a release tag always deploy that release's image, and upgrading is a change
of one `ref`:

```yaml
resources:
  - https://github.com/schmitch/forge//deploy/kubernetes/base?ref=v1.0.0
components:
  - https://github.com/schmitch/forge//deploy/kubernetes/components/valkey?ref=v1.0.0
```

To follow `:latest` instead, add `components/image-latest`. Nothing restarts
the pods when `:latest` moves; they pick up the new release when they are
recreated (`kubectl rollout restart deployment/forge`), and since migrations
only go forward, read the changelog before that happens.

Release images are signed; the cosign command is in each GitHub release. If
the GHCR package is not public, give the `forge` ServiceAccount an
`imagePullSecrets` entry. The postgres, valkey and s3-versitygw components
pull from ghcr.io too: `ghcr.io/forgepkg/forge/<name>` holds byte-for-byte
copies of the Docker Hub images under the same digests, pinned by digest
(`tag@sha256:…`); Dependabot proposes updates. To pull the originals
instead, add an `images:` entry to your overlay (`name:
ghcr.io/forgepkg/forge/valkey`, `newName: valkey/valkey`); the digest stays
valid.

## Configuration and secrets

Forge reads its configuration from `FORGE_*` environment variables
(docs/deployment.md lists them):

- **Non-secret settings** go into the `forge-config` ConfigMap. Overlays add
  to it with a `configMapGenerator` using `behavior: merge`; set at least
  `FORGE_SERVER__PUBLIC_BASE_URL`.
- **Secrets** come from a Secret named `forge-env`, loaded with `envFrom`.
  The overlays generate it from a git-ignored `forge.env` next to their
  `kustomization.yaml` (copy `forge.env.example`). If you manage secrets
  elsewhere (External Secrets, Sealed Secrets, SOPS), create a Secret named
  `forge-env` and drop the `secretGenerator`.

The components that run a backing service read their password from the same
Secret: `POSTGRES_PASSWORD` (postgres), `VALKEY_PASSWORD` (valkey), and the
gateway uses Forge's own `FORGE_S3__ACCESS_KEY`/`FORGE_S3__SECRET_KEY`
(s3-versitygw). The Postgres and Valkey passwords are pasted into a URL, so
generate URL-safe values: `openssl rand -hex 24`.

Turn on secret encryption at rest before you configure proxy repositories or
auth realms (`FORGE_CRYPTO__ROOT__PROVIDER` and `FORGE_ROOT_KEY` in
`forge.env`; the production example has them), and keep the root key with
your backups.

## Quick start (evaluation)

```bash
cd deploy/kubernetes/overlays/evaluation
cp forge.env.example forge.env      # fill in the passwords
kubectl apply -k .
kubectl -n forge-eval rollout status deployment/forge
kubectl -n forge-eval port-forward svc/forge 8421
```

Open http://localhost:8421 and sign in as the bootstrap admin (`FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME`) with its password.
The evaluation overlay has no backups and single instances of everything.

## Production

Copy `overlays/production` into your deployment repository, switch its
`resources` and `components` to the remote, tag-pinned URLs shown above, and
adjust:

- the host in `FORGE_SERVER__PUBLIC_BASE_URL` and the Ingress patch, and the
  `forge-tls` certificate Secret (or a cert-manager annotation);
- `FORGE_AUTH__TRUSTED_PROXY_CIDRS`: the pod network of your ingress
  controller or gateway, so Forge sees the real client IP;
- the namespace in the NetworkPolicy patch: that of your ingress controller
  (or your gateway's data plane), the only pods that may reach Forge;
- the S3 endpoint, region and bucket (on AWS, create the bucket beforehand;
  docs/deployment.md lists the S3 permissions Forge needs), and `forge.env`.

Points that matter on Kubernetes:

- **Probes.** A startup probe gives migrations up to five minutes on the first
  start of a new version before the liveness probe takes over.
- **Rolling updates.** `maxUnavailable: 0`, a 10 s `preStop` sleep so the
  Service stops routing before Forge stops accepting connections, and a
  300 s termination grace period for in-flight downloads. Do not roll back to
  an older image once a newer one has migrated the database.
- **Temp space.** `/tmp` is an `emptyDir` (the root filesystem is read-only).
  Pushes and first-time proxy downloads are staged there, up to
  `server.max_staging_bytes` (4 GiB by default); the volume's `sizeLimit` is
  6 GiB. Raise both together.
- **Two or more replicas** need Valkey or Redis (`components/valkey` or your
  own `FORGE_REDIS__URL`), and replicas × `database.max_connections` (20) must fit
  PostgreSQL's `max_connections`.
- **Reverse proxy.** Allow 1 GiB request bodies without buffering (image
  layers are up to 1 GiB and package pushes up to 512 MiB unless a
  repository's upload limit, set in the web UI, says otherwise), and
  keep the proxy's upstream idle timeout below 150 s (Envoy and Istio default
  to one hour; see the httproute component).
- **Who reaches Forge.** Forge believes the `X-Forwarded-For` of every peer
  in `FORGE_AUTH__TRUSTED_PROXY_CIDRS`, usually the whole pod network, so any
  other pod could call the Service with a forged client address and get past
  the login lockout and the anonymous-IP allowlist. `components/network-policy`
  admits only the ingress controller or gateway; use it whenever you set
  trusted proxies (the CNI must enforce NetworkPolicy).
- **Pod security.** Every workload here satisfies the `restricted` Pod
  Security Standard; the overlays' namespaces enforce it.

## Short-lived S3 credentials

Instead of `FORGE_S3__ACCESS_KEY` / `FORGE_S3__SECRET_KEY` in `forge-env`,
Forge can get temporary S3 credentials from the pod's identity and refresh
them itself (`FORGE_S3__CREDENTIALS`; the IAM policy and the store-side setup
are in [docs/deployment.md](../../docs/deployment.md#short-lived-s3-credentials)).
Take the keys out of `forge-env` then: Forge refuses to start with keys it
would not use.

- **IRSA / EKS Pod Identity** (EKS): set `FORGE_S3__CREDENTIALS=default_chain`
  in `forge-config`. For IRSA, annotate the ServiceAccount; for Pod Identity,
  create an association for the `forge` ServiceAccount instead. The EKS
  webhook injects its own token volume and `AWS_*` variables. It does not
  read `automountServiceAccountToken`, which stays `false`.

  ```yaml
  patches:
    - patch: |-
        apiVersion: v1
        kind: ServiceAccount
        metadata:
          name: forge
          annotations:
            eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/forge
  ```

- **MinIO, Ceph RGW, AWS without EKS**: `components/s3-workload-identity`
  mounts a projected service-account token for the STS audience and sets
  `FORGE_S3__CREDENTIALS=web_identity`. Add
  `FORGE_S3__WEB_IDENTITY__STS_ENDPOINT` (MinIO / Ceph RGW) and
  `FORGE_S3__WEB_IDENTITY__ROLE_ARN` to `forge-config`, and patch the
  token's audience for anything but AWS (the component shows how).

With `components/network-policy` and your own egress rules, allow the STS
(for EKS Pod Identity, the node's agent at `169.254.170.23:80`). The
s3-versitygw component keeps its static root credentials.

## Local blob cache

Forge can keep a copy of the blobs it serves on a local disk: hot downloads
skip S3, and cached packages keep resolving while S3 is unreachable (see
[docs/deployment.md](../../docs/deployment.md#local-blob-cache)). The
components mount a volume at `/var/cache/forge` and set
`FORGE_BLOB_CACHE__PATH` to `/var/cache/forge/blobs`, a directory Forge creates
in it (the cache refuses one its user does not own), and `__MAX_BYTES` where
needed. The existing
`/readyz` readiness probe needs no change: with the cache, an S3 outage
reports `degraded` but keeps the pod in the Service.

- **`components/local-cache`**: an `emptyDir` (`sizeLimit: 10Gi`) with a
  fixed 8 GiB cache. `statvfs` on an `emptyDir` sees the node's disk, not the
  `sizeLimit`, so the cache must not size itself (`auto`) there: raise both
  numbers together. Works with any number of replicas; the cache goes with
  the pod, so it bridges an S3 outage only while the pod keeps running.
- **`components/local-cache-persistent`**: a 20 GiB ReadWriteOnce
  PersistentVolumeClaim, so the cache survives restarts, and an instance
  restarted during an S3 outage serves what it had. One pod can mount the
  volume, so it runs one replica with `strategy: Recreate` (a short gap on
  every rollout); it cannot be combined with `components/high-availability`.
  The cache sizes itself from the volume (`auto`). The base's
  `fsGroupChangePolicy: OnRootMismatch` keeps the kubelet from walking the
  volume at each pod start, which would make the cache directory
  group-writable (Forge restores it, with a warning) and take long on a
  large cache.

For a dedicated disk per pod (e.g. local NVMe) with any number of replicas,
use `components/local-cache` and swap its volume for a generic ephemeral
volume, where `auto` works because the cache sees the volume itself:

```yaml
patches:
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: forge
      spec:
        template:
          spec:
            containers:
              - name: forge
                env:
                  - name: FORGE_BLOB_CACHE__MAX_BYTES
                    value: auto
            volumes:
              - name: blob-cache
                emptyDir: null
                ephemeral:
                  volumeClaimTemplate:
                    spec:
                      accessModes: [ReadWriteOnce]
                      storageClassName: local-nvme
                      resources: { requests: { storage: 50Gi } }
```

## Checking changes

CI renders every overlay, and the base with each component, validates the
output with kubeconform, and checks that an overlay with trusted proxies has
the NetworkPolicy. Locally, with `kustomize` and `kubeconform` on your PATH:

```bash
.github/scripts/kustomize-check.sh 1.33.0
```
