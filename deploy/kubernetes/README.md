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
│   ├── redis/               in-cluster Redis (shared cache), password-protected
│   ├── high-availability/   two replicas, spread over nodes, PodDisruptionBudget
│   ├── local-cache/         local blob cache on an emptyDir (faster downloads, serves through an S3 outage)
│   ├── local-cache-persistent/  the same on a PersistentVolume (one replica, survives restarts)
│   ├── postgres/            in-cluster PostgreSQL 17 (evaluation / small installs)
│   ├── s3-versitygw/        in-cluster S3 gateway on a PersistentVolume (evaluation / small installs)
│   └── image-latest/        run :latest instead of the pinned release
└── overlays/
    ├── production/          external PostgreSQL + S3, Redis, two replicas, Ingress
    └── evaluation/          everything in-cluster, no Ingress
```

## Which image runs

The base pins the image to the release it belongs to:

```yaml
images:
  - name: ghcr.io/schmitch/forge
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
  - https://github.com/schmitch/forge//deploy/kubernetes/components/redis?ref=v1.0.0
```

To follow `:latest` instead, add `components/image-latest`. Nothing restarts
the pods when `:latest` moves; they pick up the new release when they are
recreated (`kubectl rollout restart deployment/forge`), and since migrations
only go forward, read the changelog before that happens.

Release images are signed; the cosign command is in each GitHub release. If
the GHCR package is not public, give the `forge` ServiceAccount an
`imagePullSecrets` entry.

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
Secret: `POSTGRES_PASSWORD` (postgres), `REDIS_PASSWORD` (redis), and the
gateway uses Forge's own `FORGE_S3__ACCESS_KEY`/`FORGE_S3__SECRET_KEY`
(s3-versitygw). The Postgres and Redis passwords are pasted into a URL, so
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

Open http://localhost:8421 and sign in as `admin` with the bootstrap password.
The evaluation overlay has no backups and single instances of everything.

## Production

Copy `overlays/production` into your deployment repository, switch its
`resources` and `components` to the remote, tag-pinned URLs shown above, and
adjust:

- the host in `FORGE_SERVER__PUBLIC_BASE_URL` and the Ingress patch, and the
  `forge-tls` certificate Secret (or a cert-manager annotation);
- `FORGE_AUTH__TRUSTED_PROXY_CIDRS`: the pod network of your ingress
  controller or gateway, so Forge sees the real client IP;
- the S3 endpoint, region and bucket, and `forge.env`.

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
- **Two or more replicas** need Redis (`components/redis` or your own
  `FORGE_REDIS__URL`), and replicas × `database.max_connections` (20) must fit
  PostgreSQL's `max_connections`.
- **Reverse proxy.** Allow 512 MiB request bodies without buffering, and keep
  the proxy's upstream idle timeout below 150 s (Envoy and Istio default to
  one hour; see the httproute component).
- **Pod security.** Every workload here satisfies the `restricted` Pod
  Security Standard; the overlays' namespaces enforce it.

## Local blob cache

Forge can keep a copy of the blobs it serves on a local disk: hot downloads
skip S3, and cached packages keep resolving while S3 is unreachable (see
[docs/deployment.md](../../docs/deployment.md#local-blob-cache)). The
components mount a volume at `/var/cache/forge` and set
`FORGE_BLOB_CACHE__PATH` (and `__MAX_BYTES` where needed). The existing
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
  The cache sizes itself from the volume (`auto`).

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

CI renders every overlay, and the base with each component, and validates
the output with kubeconform. Locally, with `kustomize` and `kubeconform` on
your PATH:

```bash
.github/scripts/kustomize-check.sh 1.33.0
```
