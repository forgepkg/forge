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
| Redis 6+ (optional) | Shared L2 cache and cross-instance invalidation. Recommended as soon as you run more than one instance. TLS via `rediss://`. |

Forge is a single stateless process. The API, the NuGet feed and the web UI
share one port (`8421`), so one upstream on the reverse proxy is enough.

On Kubernetes, install the Helm chart
(`oci://ghcr.io/<owner>/charts/forge`, see
[`deploy/helm/forge`](../deploy/helm/forge/README.md)) or start from the
kustomize manifests in [`deploy/kubernetes`](../deploy/kubernetes/README.md).
Both set the probes, the shutdown timing and the security context described
below, and pin the image to the release they belong to.

## Image

```bash
docker pull ghcr.io/<owner>/<repo>:1.0.0
```

Release images are signed with keyless cosign and carry an SBOM and a
provenance attestation. The exact `cosign verify` command is in each GitHub
release's notes; it pins the signer to this repository's release workflow at
that release's tag:

```bash
cosign verify ghcr.io/<owner>/<repo>@<digest> \
  --certificate-identity https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v1.0.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each release also publishes the Helm chart of the same version,
`oci://ghcr.io/<owner>/charts/forge`, which pulls the image by the digest the
release signed. It is signed the same way; its `cosign verify` command is in
the release notes too.

`:latest` always names the newest stable release and `:<major>.<minor>` the
newest release of that line; prereleases and patches to older lines never move
them. Pin deployments to a version or digest. `GET /version` on a running
instance reports its version and source revision.

## Required configuration

The image ships a secret-free base config (`/app/forge.toml`, from
[`docker/forge.docker.toml`](../docker/forge.docker.toml), loaded through
`FORGE_CONFIG`). Everything is overridden with `FORGE_*` environment variables
(`__` separates nesting levels). If you point `FORGE_CONFIG` at your own file,
that file must exist: a missing file fails startup instead of being ignored.

Secret values (`FORGE_DATABASE__URL`, `FORGE_REDIS__URL`, the S3 keys, the
bootstrap password, `FORGE_OIDC__CLIENT_SECRET`, the credential-forwarding
pepper) are read verbatim as strings, so a numeric or bracketed password needs
no quoting, and configuration errors never print their values.

| Variable | Value |
| --- | --- |
| `FORGE_SERVER__PUBLIC_BASE_URL` | The **https** URL clients use, e.g. `https://nuget.example.com`. It is used for every absolute URL in NuGet responses, and it decides whether session cookies are `Secure`. |
| `FORGE_DATABASE__URL` | `postgres://forge:<password>@db:5432/forge` |
| `FORGE_S3__ENDPOINT` | e.g. `https://s3.eu-central-1.amazonaws.com` or `http://minio:9000` |
| `FORGE_S3__REGION` | e.g. `eu-central-1` |
| `FORGE_S3__BUCKET` | e.g. `forge` |
| `FORGE_S3__ACCESS_KEY` / `FORGE_S3__SECRET_KEY` | Object-store credentials. |
| `FORGE_S3__FORCE_PATH_STYLE` | `true` for MinIO and most self-hosted stores, `false` for AWS. |
| `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` | First start only: the initial admin password (`FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME` defaults to `admin`). Without it no bootstrap admin is created. |
| `FORGE_CRYPTO__ROOT__PROVIDER` + root key | Turns on secret encryption at rest; see below. |
| `FORGE_AUTH__TRUSTED_PROXY_CIDRS` | The CIDRs of your reverse proxies, e.g. `[10.0.0.0/8]`. Without it, every request appears to come from the proxy's IP, so the login lockout sees one client, and an anonymous-IP allowlist that contains the proxy's address admits every client. A request whose `X-Forwarded-For` is malformed where the walk reaches it is never allowlisted. |

Startup refuses the known placeholder credentials (a `changeme` bootstrap
password, `minioadmin` S3 keys). It logs a warning when `public_base_url` is
not https, points at localhost, or secret encryption is off. Treat those
warnings as deployment errors.

Never set `FORGE_SERVER__ALLOW_INSECURE_DEFAULTS=true` in production. It is
meant only for the local compose stack.

### The bootstrap admin

The image bakes no bootstrap admin; it comes only from the environment, and
only while a password is set. Set `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` for
the first start: the account is created **once**. Sign in to the web UI,
create personal admin accounts (or connect OIDC), then delete the bootstrap
account. It is not re-created on later restarts. Then remove the password from
the environment: with no bootstrap password configured, Forge simply starts
without a bootstrap admin.

Forge never lets the last active administrator go: deleting or deactivating
that account, or removing its `admin` role, is refused with `409 Conflict`.
So the replacement admin has to exist first; an OIDC or credential-forwarding
admin counts once they have signed in.

### Password Basic auth

The image defaults to `allow_password_basic = false`: the web UI signs in
through its login form (not affected by this setting), and NuGet clients and
scripts authenticate with API tokens (a token in the Basic password field is
always accepted). An enabled credential-forwarding realm turns the Basic
password path on by itself, because its users have no tokens until they first
sign in — and that path runs the whole password chain, so **local** users'
passwords are then accepted over Basic too, whatever this setting says. Set
`FORGE_AUTH__ALLOW_PASSWORD_BASIC=true` only if a client must send a local
user's password over Basic without such a realm.

A password sent over Basic is a **feed** credential only: the admin API
(`/admin/*`) and token minting refuse it with 403, even for an administrator,
because NuGet clients store that password and replay it on every request.
Administer through a browser session (the web UI, or `POST /auth/login` plus
the returned CSRF token), or mint an admin-scoped token
(`{"scope": {"actions": ["admin"]}}`) for automation.

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
recovered, although packages and metadata are unaffected. AWS KMS is not
supported yet.

Enabling encryption on an existing installation is safe, but enable it on
**every instance at once** (a full restart, not a rolling one): at startup
(and on every pass of the rotation worker) existing plaintext proxy passwords
and realm secrets are encrypted and the plaintext copies are removed, and an
instance still running without `[crypto]` cannot read them from then on.
Turning encryption off again is not supported: an instance without `[crypto]`
refuses to start while the database holds encrypted secrets.

Each encrypted secret is bound to its row and to where it is sent: a proxy
password to the origin (scheme, host and port) of the repository's
`remote_url`, an OIDC client secret to the realm's `issuer` and `client_id`.
Changing those through the admin API asks for the secret again. Changing
them directly in the database makes the secret undecryptable (the proxy
then fails instead of sending the password to the new host), and it has to
be entered again through the API. For a realm, that is an edit
(`PATCH /admin/realms/{id}` or the realm form) that includes the secret:
until then the realm is skipped at login, and an edit without the secret
answers 400 naming it.
`GET /admin/crypto/keys` reports `plaintext_backfill_pending: false` once no
plaintext secret is left. Key rotations (`POST /admin/crypto/rotate/{dek,kek,root}`
and the worker's age-based rotation) are serialized across all instances; a
rotation requested while another one runs is answered with `409 Conflict` and
can simply be retried.

### Rotating the root key on a running cluster

Every instance must be able to unwrap the KEKs with whichever root they were
last wrapped under, so rotate the root in **two phases**, with a complete
rolling restart after each:

1. **Add the new key as the previous key everywhere.** Keep the current key
   in `FORGE_ROOT_KEY` and add the *new* key as the previous one:
   `FORGE_CRYPTO__ROOT__ROOT_KEY_ENV_PREVIOUS=FORGE_ROOT_KEY_PREVIOUS` plus
   `FORGE_ROOT_KEY_PREVIOUS=<new key>` (with the file provider,
   `FORGE_CRYPTO__ROOT__ROOT_KEY_PATH_PREVIOUS`). Roll this out to every
   instance. Nothing is re-wrapped yet, but every instance can now read keys
   wrapped under either root.
2. **Swap.** Put the new key in `FORGE_ROOT_KEY` and the old one in
   `FORGE_ROOT_KEY_PREVIOUS`, and roll this out. Each instance re-wraps the
   KEKs under the new root at startup; `POST /admin/crypto/rotate/root` does
   the same on demand. During the roll-out old and new instances both reach
   both roots, so neither fails to unwrap (an instance that has not restarted
   yet may wrap a KEK back under the old root; that is harmless and converges
   once every instance runs phase 2).
3. Once `GET /admin/crypto/keys` shows every **non-revoked** KEK on the new
   `root_key_version` (revoked KEKs keep the old one and are never used
   again), remove the previous key and roll out once more. Keep the old root
   key with your backups for as long as you keep a database backup taken
   before the rotation: restoring such a backup needs it.

Swapping in one step makes the instances that still run with only the old
key fail to unwrap KEKs that a new instance has already re-wrapped.

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
- With an `https://` `public_base_url` Forge sends
  `Strict-Transport-Security: max-age=31536000`; serve it over https only.
  API responses and every feed response to a request with credentials are
  `Cache-Control: private, no-store`, and feed responses carry
  `Vary: Authorization, Cookie, X-NuGet-ApiKey`: keep a caching proxy from
  overriding either.
- With `anonymous_mode = "allowlist"`, do not let a shared cache store `/v3`
  responses at all. Anonymous feed responses carry no `Cache-Control`, and
  whether Forge serves one depends on the client's address, which the cache
  does not key on: a cache that stores responses without caching headers
  (Varnish's default does) would serve what an allowlisted client fetched to
  a client outside the allowlist.
- Forge bounds slow clients itself (`server.header_read_timeout_seconds`,
  `body_idle_timeout_seconds`, `request_timeout_seconds`); keep the proxy's
  own timeouts at least as long for package pushes.
- Forge speaks HTTP/1.1 to the proxy (no h2c). `header_read_timeout_seconds`
  (default 150) also closes keep-alive connections that stay idle that long.
  If the proxy keeps upstream connections open longer than that (Envoy and
  Istio default to 1 hour), lower the proxy's upstream idle timeout or raise
  this setting; otherwise the proxy can reuse a connection Forge is closing
  and answer 502, which it does not retry for a push. AWS ALB and
  ingress-nginx (60 s), Traefik (90 s) and Caddy (120 s) are below the
  default.

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

Forge starts listening only **after** startup work is done: database
migrations, the bucket check, the bootstrap admin, the secret-encryption
bootstrap and backfill. On the first start of a new version (migrations) or
against a slow database this can take a while, and `/healthz` does not answer
until then. Give the container a **startup probe** on `/healthz` with a
generous budget, so the liveness probe does not restart it mid-migration:

```yaml
startupProbe:
  httpGet: { path: /healthz, port: 8421 }
  periodSeconds: 5
  failureThreshold: 60      # up to 5 minutes for migrations
livenessProbe:
  httpGet: { path: /healthz, port: 8421 }
  periodSeconds: 10
readinessProbe:
  httpGet: { path: /readyz, port: 8421 }
  periodSeconds: 10
```

The image runs as the numeric user `10001:10001`, so
`securityContext.runAsNonRoot: true` works without further settings.

On SIGTERM, Forge stops accepting connections and lets in-flight requests
finish before exiting. Give it a termination grace period long enough for your
largest package download.

## Running more than one instance

Instances coordinate through PostgreSQL (row locks and leases), so any number
can run behind the load balancer. Configure `FORGE_REDIS__URL` so that caches
and invalidations converge immediately, not only after a TTL expires. The
password-failure lockout is kept in memory on each instance; the networks a
username signed in from, which that username's backoff exempts, are shared
through the database.

Redis is optional at runtime: an instance starts while Redis is unreachable
(after waiting a few seconds for it) and works from its own memory until
Redis is back. A Redis that stops answering slows only the requests that
talk to it, and an instance whose invalidation subscription goes silent
notices within about 15 s, drops its in-memory cache and resubscribes.

- **Connections.** Every instance opens up to `database.max_connections`
  (default 20); keep instances × that below PostgreSQL's `max_connections`.
  Through PgBouncer, use **session** pooling: migrations and key rotation
  take session-level advisory locks, which transaction pooling breaks.
- **Upgrades.** Migrations run at startup, serialized by an advisory lock.
  Once a newer version has migrated, an instance of the older version
  refuses to start, so roll forward and do not restart old instances in the
  middle of a rollout.
- **Rolling deploys.** On SIGTERM Forge stops accepting connections at once
  and drains in-flight requests. Give the load balancer time to stop routing
  to the instance first (for Kubernetes a `preStop` sleep of 5 to 10 s),
  otherwise requests routed in that gap are refused, and a refused push is
  not retried.
- **Temp space.** Pushes and first-time proxy downloads are staged in
  `server.staging_dir` (default `forge-staging` in the system temp
  directory). All staged files of an instance share `server.max_staging_bytes`
  (default four times the larger of `server.max_upload_bytes` and
  `proxy.max_package_bytes`, so 4 GiB; `0` removes the limit); past it,
  pushes and downloads are answered `503` with `Retry-After` until space
  frees up. Size the volume above that budget. Each process stages in a
  locked subdirectory of its own, and the files a killed process left are
  removed at the next start however recent they are, so they do not add to
  the space a restarted instance needs. Give each instance a volume of its
  own (the Helm chart and the Kubernetes base do). Instances on different
  hosts may share one only if its file locks work across those hosts (NFSv4,
  or NFSv3 with `lockd`; not a mount with `nolock` or `local_lock`):
  otherwise one instance's startup can remove another's files mid-request.
  Where locks do not work at all, a killed process's files are removed once
  idle for an hour instead.
- **Audit log.** Package mutations and admin changes are logged at INFO
  under the `forge::audit` target, with the user/token or workload that
  made them; keep those lines.

### Redis is a trust boundary

Anything that can write to Redis can write Forge's shared cache. Forge
therefore keeps every value a security decision or a client rests on **out of
Redis**: authorization sets, credential-forwarding verdicts, OIDC discovery
documents and signing keys, workload-identity token verdicts, and a proxy's
upstream service index, manifests and registrations are cached in each
instance's memory only. Redis carries only their invalidations, so the worst
a Redis writer can do to them is evict them early. The only values still
shared through Redis are two proxy markers ("listing refreshed", "version
rejected"); forging them can hide a proxied package until its TTL expires,
not change what is served.

Still treat Redis like the database: a dedicated instance (or ACL user) for
Forge, `requirepass`/ACL credentials in the URL, not reachable from outside
the deployment, and TLS when it crosses a network you do not control
(`FORGE_REDIS__URL=rediss://user:password@redis.internal:6380`; the server
verifies the certificate against the system trust store).

## Backup and restore

PostgreSQL and the object store are **one** backup unit. Metadata references
blobs by content hash, so the restored bucket must still contain every object
the restored database references.

The safe order is: take the database snapshot **first**, and make sure no
object that existed at that moment can be missing from the bucket copy.
Garbage collection deletes objects after packages are deleted or retained
away, so a bucket copied *later* could already lack them. Either:

- enable **bucket versioning** (or an equivalent point-in-time feature) and
  restore the bucket to a point **at the database snapshot's time, and no
  later than the snapshot time plus `outbox.grace_seconds`** (default 3600 s;
  garbage collection deletes an object only after that grace period, so a
  later bucket state can already lack objects the restored database still
  references). Keep noncurrent versions longer than your backup retention; or
- stop **every** Forge instance while both copies are taken (garbage
  collection runs on every instance and has no separate switch;
  `retention.enabled = false` does not stop it).

Objects written after the database snapshot are harmless: nothing in the
restored database references them. They only use storage.

Keep the secret-encryption root key with the backup set, stored separately
from it.

### S3 bucket lifecycle

Large pushes and proxied downloads are uploaded with S3 multipart uploads. An
upload that is interrupted (client disconnect, process restart) leaves its
parts in the bucket, invisible but billed. Add a lifecycle rule that aborts
incomplete multipart uploads, for example after one day:

```json
{
  "Rules": [{
    "ID": "abort-incomplete-multipart-uploads",
    "Status": "Enabled",
    "Filter": {},
    "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 1 }
  }]
}
```

(`aws s3api put-bucket-lifecycle-configuration --bucket forge
--lifecycle-configuration file://lifecycle.json`; MinIO and Ceph RGW accept
the same rule.) Do not add expiration rules for current objects: Forge's own
garbage collection decides when a blob may go.

To restore: stop every Forge instance, restore PostgreSQL, restore the bucket
as described above, then start Forge. Practise this before you need it.

## Locked out of every realm (break-glass)

The admin API and the web UI refuse (`409 Conflict`) to disable or delete a
realm when no enabled realm people can sign in with interactively (`local` or
OIDC) would remain. They cannot tell whether that realm works, though: with an
enabled OIDC realm whose IdP is down or misconfigured, `local` can still be
disabled, and then nobody can sign in. API tokens keep working, so restores
and pushes continue. To turn the `local` realm back on:

- **With an admin-scoped API token**, minted beforehand with
  `{"scope": {"actions": ["admin"]}}` (keep one for this): look up the
  realm's id, then enable it. The token can also go in the Basic password.

  ```bash
  curl -H "X-NuGet-ApiKey: $TOKEN" https://nuget.example.com/admin/realms
  curl -H "X-NuGet-ApiKey: $TOKEN" -X PATCH https://nuget.example.com/admin/realms/<id> \
    -H 'content-type: application/json' -d '{"enabled": true}'
  ```

- **With SQL**, when there is no such token:

  ```sql
  UPDATE auth_realm SET enabled = true WHERE kind = 'local';
  ```

  Every instance picks the change up within `auth.realm_cache_ttl_seconds`
  (default 10 s); no restart is needed.

Then sign in as a local administrator and fix or disable the broken realm.

## Upgrades

- Read the [changelog](../CHANGELOG.md) for each version you skip over. A
  release that needs something other than a rolling restart says so there.
- Migrations run automatically on the first start of a new version and only
  move forward. Rolling back to an older binary after a newer one has migrated
  the database requires restoring the backup taken before the upgrade.
- Back up (see above) before every upgrade.

## Known limitations

See the "Known limitations" section of the [changelog](../CHANGELOG.md#known-limitations).
