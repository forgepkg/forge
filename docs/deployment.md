# Production deployment

This is the operator guide for running the `envisia-forge` image in
production. For local development see [DEVELOPMENT.md](../DEVELOPMENT.md); for
CI publishing without stored API keys see
[trusted publishing](trusted-publishing.md).

## What you need

| Dependency | Notes |
| --- | --- |
| PostgreSQL 15+ (17 tested) | The authority for all metadata, sessions, RBAC and coordination. Migrations run automatically at startup. |
| S3-compatible object store | Package blobs (content-addressed). AWS S3, MinIO, Ceph RGW, versitygw, … The bucket is created if missing. |
| TLS termination | A reverse proxy or load balancer in front of Forge (nginx, Traefik, an ingress, an ALB). Forge itself speaks plain HTTP. |
| Redis 6+ (optional) | Shared L2 cache and cross-instance invalidation. Recommended as soon as you run more than one instance. |

Forge is a single stateless process. The API, the NuGet feed and the web UI
share one port (`8421`), so one upstream on the reverse proxy is enough.

## Image

```bash
docker pull ghcr.io/<owner>/<repo>:0.1.0
```

Release images are signed with keyless cosign and carry an SBOM and a
provenance attestation. The exact `cosign verify` command is in each GitHub
release's notes. `GET /version` on a running instance reports its version and
source revision.

## Required configuration

The image ships a secret-free base config (`/app/forge.toml`, from
[`docker/forge.docker.toml`](../docker/forge.docker.toml)). Everything is
overridden with `FORGE_*` environment variables (`__` separates nesting
levels).

| Variable | Value |
| --- | --- |
| `FORGE_SERVER__PUBLIC_BASE_URL` | The **https** URL clients use, e.g. `https://nuget.example.com`. It is used for every absolute URL in NuGet responses, and it decides whether session cookies are `Secure`. |
| `FORGE_DATABASE__URL` | `postgres://forge:<password>@db:5432/forge` |
| `FORGE_S3__ENDPOINT` | e.g. `https://s3.eu-central-1.amazonaws.com` or `http://minio:9000` |
| `FORGE_S3__REGION` | e.g. `eu-central-1` |
| `FORGE_S3__BUCKET` | e.g. `forge` |
| `FORGE_S3__ACCESS_KEY` / `FORGE_S3__SECRET_KEY` | Object-store credentials. |
| `FORGE_S3__FORCE_PATH_STYLE` | `true` for MinIO and most self-hosted stores, `false` for AWS. |
| `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` | Initial admin password (the user name defaults to `admin`). |
| `FORGE_CRYPTO__ROOT__PROVIDER` + root key | Turns on secret encryption at rest; see below. |
| `FORGE_AUTH__TRUSTED_PROXY_CIDRS` | The CIDRs of your reverse proxies, e.g. `[10.0.0.0/8]`. Without it, every request appears to come from the proxy's IP, so anonymous-IP allowlists and the login lockout see one client. |

Startup refuses the known placeholder credentials (`changeme`, `minioadmin`).
It logs a warning when `public_base_url` is not https, points at localhost, or
secret encryption is off. Treat those warnings as deployment errors.

Never set `FORGE_SERVER__ALLOW_INSECURE_DEFAULTS=true` in production. It is
meant only for the local compose stack.

### The bootstrap admin

The bootstrap admin is created **once**, on the first start after it is
configured. Sign in, create personal admin accounts (or connect
OIDC), then delete the bootstrap account. It is not re-created on later
restarts. Remove the password from the environment once you no longer need
it.

## Secret encryption at rest

Upstream proxy passwords and authentication-realm secrets (OIDC client
secrets, credential-forwarding peppers) are stored with double-envelope
encryption: DEK → KEK → a root key that never enters the database. Without a
`[crypto]` section these values are stored in **plaintext**. Enable it before
you configure proxies or realms:

```bash
openssl rand -base64 32          # generate the root key once; store it in your secret manager
FORGE_CRYPTO__ROOT__PROVIDER=env
FORGE_ROOT_KEY=<base64 32 bytes>
# or, for a mounted secret file:
# FORGE_CRYPTO__ROOT__PROVIDER=file
# FORGE_CRYPTO__ROOT__ROOT_KEY_PATH=/run/secrets/forge_root_key
```

The root key is part of your backup. Without it, stored secrets cannot be
recovered, although packages and metadata are unaffected. Root rotation keeps
the previous key reachable (`…_PREVIOUS`) until
`POST /admin/crypto/rotate/root` has re-wrapped every KEK. AWS KMS is not
supported yet.

## Reverse proxy

- Terminate TLS and forward to `http://forge:8421`, preserving `Host`.
  Forward `X-Forwarded-For`, and list the proxy in
  `FORGE_AUTH__TRUSTED_PROXY_CIDRS`.
- Allow large request bodies for `PUT /v3/{repo}/package` (package pushes).
  In nginx that is `client_max_body_size`. Match it to
  `FORGE_SERVER__MAX_UPLOAD_BYTES` if you raised that limit.
- Disable response buffering or give it enough room. Package downloads are
  streamed.
- Do not rewrite the `Origin` or `Sec-Fetch-Site` headers. Forge refuses
  state-changing browser requests that are cross-site, so a proxy that strips
  or fakes these headers breaks that protection.

Minimal nginx example:

```nginx
server {
    listen 443 ssl http2;
    server_name nuget.example.com;
    # ssl_certificate …; ssl_certificate_key …;

    client_max_body_size 512m;
    proxy_request_buffering off;
    proxy_buffering off;

    location / {
        proxy_pass http://forge:8421;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

## Health probes

| Endpoint | Use |
| --- | --- |
| `GET /healthz` | Liveness. Never touches a dependency. |
| `GET /readyz` | Readiness. PostgreSQL and S3 are each checked with a 3 s deadline; the endpoint returns 503 with the failing check names. |
| `GET /version` | The running version and revision. |

The image has no shell tools such as `curl`. Use your orchestrator's HTTP
probes rather than a Docker `HEALTHCHECK`.

On SIGTERM, Forge stops accepting connections and lets in-flight requests
finish before exiting. Give it a termination grace period long enough for your
largest package download.

## Running more than one instance

Instances coordinate through PostgreSQL (row locks and leases), so any number
can run behind the load balancer. Configure `FORGE_REDIS__URL` so that caches
and invalidations converge immediately, not only after a TTL expires. The
password-failure lockout is kept in memory on each instance.

## Backup and restore

PostgreSQL and the object store are **one** backup unit. Metadata references
blobs by content hash, so the restored bucket must still contain every object
the restored database references.

The safe order is: take the database snapshot **first**, and make sure no
object that existed at that moment can be missing from the bucket copy.
Garbage collection deletes objects after packages are deleted or retained
away, so a bucket copied *later* could already lack them. Either:

- enable **bucket versioning** (or an equivalent point-in-time feature) and
  restore the bucket to the database snapshot's timestamp or later, keeping
  noncurrent versions longer than your backup retention; or
- stop Forge (or at least its garbage collection) while both copies are taken.

Objects written after the database snapshot are harmless: nothing in the
restored database references them. They only use storage.

Keep the secret-encryption root key with the backup set, stored separately
from it.

To restore: stop every Forge instance, restore PostgreSQL, restore the bucket
as described above, then start Forge. Practise this before you need it.

## Upgrades

- Read the [changelog](../CHANGELOG.md) for each version you skip over. A
  release that needs something other than a rolling restart says so there.
- Migrations run automatically on the first start of a new version and only
  move forward. Rolling back to an older binary after a newer one has migrated
  the database requires restoring the backup taken before the upgrade.
- Back up (see above) before every upgrade.

## Known limitations in 0.1.0

See the "Known limitations" section of the [changelog](../CHANGELOG.md#010).
