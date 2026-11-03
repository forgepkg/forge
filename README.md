# Forge

A self-hosted **NuGet package registry, npm registry, Docker / OCI registry,
apt repository and raw file repository** written in Rust. It speaks the NuGet **V3**
protocol, the **npm registry** protocol (npm, pnpm, Yarn, Bun) and the **OCI Distribution Spec**
v1.1 (Docker, Podman, containerd, crane, Helm, cosign), and supports the
three repository types you expect from an enterprise registry. For NuGet:

- **hosted** — push and restore your own `.nupkg` packages.
- **proxy** — cache packages on demand from an upstream NuGet V3 feed —
  `api.nuget.org` or a private/custom feed (Azure Artifacts, GitHub Packages,
  Artifactory, Nexus, …) with Basic/PAT credentials — with an optional
  publication delay that holds back new upstream releases.
- **group** — fan a single feed URL out across several member repos by
  priority; tolerates a failing member and, by default, keeps public feeds
  from shadowing internal package ids (dependency-confusion guard).

The same three types exist for npm packages: publish with `npm publish`,
log in with `npm login` (approved in the browser), proxies of
`registry.npmjs.org` or any registry, and groups that keep your scopes
internal and pass `npm audit` on — see **[docs/npm.md](./docs/npm.md)**;
for container images and other OCI artifacts,
Helm charts included (`helm push`, `helm install oci://…`): hosted image
repositories, pull-through proxies of Docker Hub, GHCR, Quay or any OCI
registry, and groups — see **[docs/docker.md](./docs/docker.md)** — and for plain files
under arbitrary paths (binaries, installers, fixtures), like Nexus' raw
repositories, with ranges, checksum sidecars and proxies of any HTTP(S)
download URL such as GitHub release assets — see
**[docs/raw.md](./docs/raw.md)**; and for Debian and Ubuntu packages, apt
repositories whose indexes Forge signs with keys of their own, and proxies of
Debian and Ubuntu mirrors (apt has no groups) — see
**[docs/apt.md](./docs/apt.md)**.

Storage is **content-addressed (CAS)** on top of any **S3-compatible** object
store; package metadata lives in **PostgreSQL**. Access control is **fine-grained
RBAC** (users, nested groups, roles, package/content selectors). Authentication
is organized into ordered, web-managed **auth realms** — local passwords,
**OIDC / Microsoft Entra** browser login, and credential-forwarding against an
existing registry — with an identifier-first login flow. CI jobs can publish
without stored API keys through **trusted publishing**: a job of GitHub
Actions, GitLab CI or another OIDC workload issuer exchanges its identity
token for a short-lived API key
([docs/trusted-publishing.md](docs/trusted-publishing.md), which also covers
its limitations).
A **retention** engine reaps cold versions and garbage-collects dereferenced
blobs. Every format is a **format crate** built into the server: it speaks
the format's protocol, while the server keeps all of the above the same for
every format ([docs/format-plugins.md](docs/format-plugins.md)). The admin +
browse UI is a **TanStack Router SPA** served by the same Rust process on a
single origin — there is no Node server in production.

## Architecture

A Cargo workspace of small crates plus the web SPA:

| Crate (`crates/…`) | Package | Responsibility |
| --- | --- | --- |
| `db` | `forge-db` | PostgreSQL data access (sqlx), row models, DAOs. |
| `storage` | `forge-storage` | CAS over S3, blob outbox / GC reconciler. |
| `cache` | `forge-cache` | In-process L1 + optional Redis L2 with cross-instance invalidation (no Postgres advisory locks). |
| `crypto` | `forge-crypto` | Secret encryption at rest: the envelope encryption of stored secrets (proxy passwords, realm secrets, signing keys) under a root key. |
| `telemetry` | `forge-telemetry` | OpenTelemetry metrics and the `tracing` spans that become traces. |
| `traffic` | `forge-traffic` | Traffic statistics: requests per repository and client network per day, kept as Parquet files in the object store. |
| `core` | `forge-core` | Domain logic: repo dispatch, the formats' adapter to it (`SpecFormat`), auth chain, authz/RBAC, sessions, OIDC, retention. |
| `format-api` | `forge-format-api` | The format contract: the `FormatSpec` trait every format implements, and its types. |
| `formats/<id>` | `forge-format-*` | The formats, built into the server: `apt`, `docker` (the distribution-spec `/v2` API, manifests, upstream registries), `nuget`, `npm`, `raw`. |
| `server` | `forge-server` | Axum HTTP server: the formats' feeds under `/repository/{repo}` (except Docker at `/v2`), the file store of files formats, the image store and registry tokens of images formats, `/admin` + `/auth` REST, background workers, static SPA serving. |
| `e2e` | `forge-e2e` | End-to-end suite (testcontainers + mock upstream/IdP). |
| `xtask` | — | The task runner (`cargo xtask …`); replaces Make/Just. |
| `web/` | — | TanStack Router SPA (pnpm + Vite), built into `web/dist/`. |

**Every format is a crate in `crates/formats/`.** A format is a crate in
`crates/formats/<id>/` implementing `FormatSpec`, linked into the server.
Docker / OCI is one too, an images format: the crate speaks the protocol,
and the server's image store (`crates/server/src/images`) keeps the
images.

**Single-origin serving.** `forge-server` serves every non-Docker format
at `/repository/{repo}`, the Docker / OCI registry at `/v2`,
the admin/browse APIs (`/admin`, `/browse`, `/auth`) and then serves the built SPA
from `web/dist/` via a `ServeDir` SPA fallback. The browser talks to the API on
the same origin with relative URLs; no routing proxy is required (production
still puts a TLS-terminating proxy in front — see
[docs/deployment.md](docs/deployment.md)).

## Quickstart

Prerequisites: **Docker**, a **Rust** toolchain (pinned in `rust-toolchain.toml`),
and **Node 26 + pnpm 11** (`npm install -g corepack && corepack enable`).
Optionally the **.NET SDK** to drive the feed with a real client.

```bash
cargo xtask dev
```

That one command uses your **local Postgres on :5432** (creating the `forge`
role + database if missing), brings up an S3 gateway (**:8422**) via
`docker-compose.yml`, runs migrations, and starts the Rust API on **:8421** plus
Vite HMR on **:8420**. A bootstrap admin **`admin@example.com` / `changeme`** is created on
first run (dev only: the bundled `forge.toml` sets
`server.allow_insecure_defaults = true`; any other config refuses to start with
the `changeme` password or `minioadmin` S3 keys). (Requires a running local PostgreSQL with permission to create the
role/db; use `--db docker` if you don't have one — see below.)

- **UI:** http://localhost:8420
- **NuGet feed:** `http://localhost:8421/repository/{repo}/index.json`
- **npm registry:** `http://localhost:8421/repository/{repo}/`

Add demo data (anonymous-readable `nuget` repo + a pushed sample package) in a
second terminal:

```bash
cargo xtask seed
# feed: http://localhost:8421/repository/nuget/index.json
```

### Choosing where Postgres comes from

```bash
cargo xtask dev              # default: host Postgres on :5432 (forge role+db auto-created)
cargo xtask dev --db docker  # self-contained docker-compose Postgres on :5433
cargo xtask dev --db none    # assume the DB is already up; don't start one
```

### Run via the Docker image

Every release publishes the signed image to GitHub Packages as
[`ghcr.io/forgepkg/forge`](https://github.com/forgepkg/forge/pkgs/container/forge),
for `linux/amd64` and `linux/arm64` (from 2.0.0 on; up to 1.1.0
`ghcr.io/schmitch/forge`, amd64 only; see
[docs/deployment.md](docs/deployment.md#image)). To build it from a
checkout instead, the root `Dockerfile` packages the SPA **and** the Rust
server into one image (no Node in prod):

```bash
cargo xtask docker-build     # docker build -t forge:latest .
cargo xtask docker-run       # run the image against the compose db + s3 on :8421
```

Or directly, against your own infra (configure with `FORGE_*` env vars, e.g.
`FORGE_DATABASE__URL`, `FORGE_S3__ENDPOINT`/`__BUCKET`/`__ACCESS_KEY`/`__SECRET_KEY`):

```bash
docker run --rm -p 8421:8421 \
  -e FORGE_DATABASE__URL=postgres://forge:forge@db:5432/forge \
  -e FORGE_S3__ENDPOINT=http://s3:8422 -e FORGE_S3__BUCKET=forge \
  -e FORGE_S3__ACCESS_KEY=… -e FORGE_S3__SECRET_KEY=… \
  -e FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME=admin@example.com \
  -e FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD=… \
  forge:latest
```

The image refuses to start without S3 credentials and with placeholder
credentials (`minioadmin` S3 keys, a `changeme` bootstrap password). Instead
of S3 keys it can use short-lived credentials from the platform's workload
identity (IRSA, EKS Pod Identity, STS web identity; see
[docs/deployment.md](docs/deployment.md#short-lived-s3-credentials)). It
bakes no bootstrap admin: `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` creates one on the first start,
named by `FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME` (a UPN, default `admin@example.com`), and
once it is removed the image simply starts without one. A new install has
no anonymous access and its local realm accepts no passwords over HTTP Basic
(clients use API tokens); an administrator changes them in the web UI under
**Admin → Settings** and **Admin → Authentication** (see
[docs/deployment.md](docs/deployment.md#access-and-sign-in-settings)).

### Point a `dotnet` client at it

```bash
dotnet nuget add source http://localhost:8421/repository/nuget/index.json -n forge
dotnet nuget push -s forge -k <TOKEN> your.1.0.0.nupkg
dotnet add package <PackageId>          # in a project
```

For a non-anonymous repo, pass `--username admin@example.com --password <TOKEN>
--store-password-in-clear-text` to the source (the password is a **token**, not
the user password).

### Push and pull container images

Create a docker repository (`"format": "docker"`) under **Admin →
Repositories**, then log in with an API token as the password:

```bash
docker login localhost:8421 -u admin@example.com  # password: an API token
docker tag alpine:3.20 localhost:8421/docker-hosted/team/alpine:3.20
docker push localhost:8421/docker-hosted/team/alpine:3.20
docker pull localhost:8421/docker-hosted/team/alpine:3.20
```

### Upload and download files

Create a raw repository (`"format": "raw"`), then upload with an API token as
the password and download with its checksum:

```bash
curl -u admin@example.com:<TOKEN> --upload-file tool.tgz http://localhost:8421/repository/binaries/tools/1.0/tool.tgz
curl -u admin@example.com:<TOKEN> -O http://localhost:8421/repository/binaries/tools/1.0/tool.tgz
curl -u admin@example.com:<TOKEN> http://localhost:8421/repository/binaries/tools/1.0/tool.tgz.sha256 | sha256sum -c
```

## Documentation

The guides below are also a site, with navigation and search:
**<https://forgepkg.github.io/forge/>**.

- **[Production deployment](./docs/deployment.md)** — required settings, TLS
  and reverse proxy, secret encryption, health probes, backup/restore and
  upgrades. Kubernetes: a Helm chart published with every release
  (**[deploy/helm/forge](./deploy/helm/forge/README.md)**, on GitHub Packages
  as [`oci://ghcr.io/forgepkg/charts/forge`](https://github.com/forgepkg/forge/pkgs/container/charts%2Fforge)), or kustomize
  manifests (**[deploy/kubernetes](./deploy/kubernetes/README.md)**).
  Monitoring: an OpenTelemetry Collector configuration, a Grafana dashboard
  and alerting rules (**[deploy/monitoring](./deploy/monitoring/README.md)**).
- **[CHANGELOG.md](./CHANGELOG.md)** — release notes, upgrade notes and known
  limitations; **[SECURITY.md](./SECURITY.md)** — how to report a
  vulnerability.
- **[DEVELOPMENT.md](./DEVELOPMENT.md)** — full local-dev guide: every
  `cargo xtask` command, configuration knobs, OIDC/Entra setup, the web UI dev
  server, tests, and Docker packaging details.
- **[apt repositories](./docs/apt.md)** — Debian and Ubuntu packages (hosted,
  proxy) for `apt`: `.deb` uploads, indexes signed with the repository's keys
  and their rotation, `sources.list` and `auth.conf.d`, proxies of Debian and
  Ubuntu mirrors.
- **[Docker / OCI registry](./docs/docker.md)** — image repositories (hosted,
  proxy, group), naming and host-based routing, `docker login`, retention and
  garbage collection.
- **[npm registries](./docs/npm.md)** — npm packages (hosted, proxy, group)
  for npm, pnpm, Yarn and Bun: `.npmrc`, logins, publishing, dist-tags,
  deprecations, unpublishing, proxies of `registry.npmjs.org`, internal
  scopes, audits and retention.
- **[NuGet feeds](./docs/nuget.md)** — NuGet packages (hosted, proxy,
  group) for `dotnet`, `nuget.exe` and Visual Studio: `dotnet nuget add
  source`, `NuGet.config` credentials, logins, pushes with an API key and
  unlisting.
- **[Raw file repositories](./docs/raw.md)** — files under arbitrary paths
  (hosted, proxy, group): logins, uploads with curl, ranges and checksum sidecars,
  listings, the deployment policy, proxies of release downloads (the pdfium
  example) and retention.
- **[Retention](./docs/retention.md)** — the retention rules of each kind
  of repository with examples, cron schedules in a time zone with a time
  limit per run, and size budgets.
- **[Package delay](./docs/package-delay.md)** — a NuGet or npm proxy's
  dependency cooldown for new upstream releases, other delays for some
  packages, and releasing one version early.
- **[Trusted publishing](./docs/trusted-publishing.md)** — configure short-lived
  workload identity for GitHub Actions, GitLab CI, and compatible OIDC issuers,
  and exchange a job's OIDC token for a short-lived API key (`POST /api/v2/token`,
  or npm's own exchange) that publishes NuGet and npm packages and pushes
  container images (`dotnet nuget push`, `npm publish`, `docker push`,
  `dotnet publish`).
- **[GitLab CI with workload identity](./docs/gitlab-ci.md)** — step by step:
  every job of a GitLab project restores from Forge's NuGet feeds, and only
  the release job, on a protected tag or environment, pushes the packages a
  trusted publisher names. No secret in GitLab.
- **[CI with service accounts](./docs/ci-service-accounts.md)** — for
  pipelines that cannot use workload identity: a read token and a release
  token of service accounts in GitLab's CI/CD variables, and how both
  methods run side by side.
- **[Format crates](./docs/format-plugins.md)** — how every format is built:
  the `FormatSpec` contract, what the server does for each format, and
  adding a new one.
- **[Importing repositories](./docs/import.md)** — copy a hosted repository
  of Nexus, Artifactory, Verdaccio, a registry or another Forge (NuGet, npm,
  Docker, raw, apt) into Forge through the format's own protocol: dry run,
  conflicts, resuming, and the cutover.

Run `cargo xtask help` for the complete command list.

## License

Forge is licensed under the [MIT License](./LICENSE) (SPDX `MIT`).

Contributions are accepted under the [Contributor License Agreement](./CLA.md),
which grants the forgepkg organization the rights to distribute them under
the MIT License or other terms. See [CONTRIBUTING.md](./CONTRIBUTING.md) for
how to sign it.
