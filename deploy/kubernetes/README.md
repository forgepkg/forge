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
│   ├── redis/               in-cluster Redis (shared cache), password-protected
│   ├── high-availability/   two replicas, spread over nodes, PodDisruptionBudget
│   ├── postgres/            in-cluster PostgreSQL 17 (evaluation / small installs)
│   ├── s3-versitygw/        in-cluster S3 gateway on a PersistentVolume (evaluation / small installs)
│   └── image-latest/        run :latest instead of the pinned release
└── overlays/
    ├── production/          external PostgreSQL + S3, Redis, two replicas, Ingress, NetworkPolicy
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
- the namespace in the NetworkPolicy patch: that of your ingress controller
  (or your gateway's data plane), the only pods that may reach Forge;
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
- **Who reaches Forge.** Forge believes the `X-Forwarded-For` of every peer
  in `FORGE_AUTH__TRUSTED_PROXY_CIDRS`, usually the whole pod network, so any
  other pod could call the Service with a forged client address and get past
  the login lockout and the anonymous-IP allowlist. `components/network-policy`
  admits only the ingress controller or gateway; use it whenever you set
  trusted proxies (the CNI must enforce NetworkPolicy).
- **Pod security.** Every workload here satisfies the `restricted` Pod
  Security Standard; the overlays' namespaces enforce it.

## Checking changes

CI renders every overlay, and the base with each component, validates the
output with kubeconform, and checks that an overlay with trusted proxies has
the NetworkPolicy. Locally, with `kustomize` and `kubeconform` on your PATH:

```bash
.github/scripts/kustomize-check.sh 1.33.0
```
