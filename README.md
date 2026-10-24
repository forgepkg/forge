# Forge

A self-hosted **NuGet package registry, Docker / OCI registry and raw file
repository** written in Rust. It speaks the NuGet **V3** protocol and the **OCI Distribution Spec**
v1.1 (Docker, Podman, containerd, crane, Helm, cosign), and supports the
three repository types you expect from an enterprise registry (more package
formats come as **format plugins**, see below):

- **hosted** — push and restore your own `.nupkg` packages.
- **proxy** — cache packages on demand from an upstream NuGet V3 feed —
  `api.nuget.org` or a private/custom feed (Azure Artifacts, GitHub Packages,
  Artifactory, Nexus, …) with Basic/PAT credentials — with an optional
  publication delay that holds back new upstream releases.
- **group** — fan a single feed URL out across several member repos by
  priority; tolerates a failing member and, by default, keeps public feeds
  from shadowing internal package ids (dependency-confusion guard).

The same three types exist for container images and other OCI artifacts,
Helm charts included (`helm push`, `helm install oci://…`): hosted image
repositories, pull-through proxies of Docker Hub, GHCR, Quay or any OCI
registry, and groups — see **[docs/docker.md](./docs/docker.md)** — and for plain files
under arbitrary paths (binaries, installers, fixtures), like Nexus' raw
repositories, with ranges, checksum sidecars and proxies of any HTTP(S)
download URL such as GitHub release assets — see
**[docs/raw.md](./docs/raw.md)**.

Storage is **content-addressed (CAS)** on top of any **S3-compatible** object
store; package metadata lives in **PostgreSQL**. Access control is **fine-grained
RBAC** (users, nested groups, roles, package/content selectors). Authentication
is organized into ordered, web-managed **auth realms** — local passwords,
**OIDC / Microsoft Entra** browser login, and credential-forwarding against an
existing registry — with an identifier-first login flow. CI jobs can publish
without stored API keys through Forge's **direct-token OIDC trusted-publishing**
flow for GitHub Actions, GitLab CI, and compatible workload issuers; its bearer
token, cache, and audit limitations are documented below.
A **retention** engine reaps cold versions and garbage-collects dereferenced
blobs. **Format plugins** (preview), crates built into the server, add
further package formats that reuse all of the above
([docs/format-plugins.md](docs/format-plugins.md)). The admin + browse UI is
a **TanStack Router SPA** served by the same Rust process on a single origin —
there is no Node server in production.

## Architecture

A Cargo workspace of small crates plus the web SPA:

| Crate (`crates/…`) | Package | Responsibility |
| --- | --- | --- |
| `db` | `forge-db` | PostgreSQL data access (sqlx), row models, DAOs. |
| `storage` | `forge-storage` | CAS over S3, blob outbox / GC reconciler. |
| `cache` | `forge-cache` | In-process L1 + optional Redis L2 with cross-instance invalidation (no Postgres advisory locks). |
| `core` | `forge-core` | Domain logic: repo dispatch, auth chain, authz/RBAC, sessions, OIDC, retention. |
| `plugin-api` | `forge-plugin-api` | The format-plugin contract: the `FormatPlugin` trait and its types. |
| `plugin` | `forge-plugin` | The host side of format plugins: an installed plugin and its adapter to the repository machinery. |
| `formats/<id>` | `forge-format-*` | Format plugins, built into the server: `docker` (the distribution-spec `/v2` API, manifests, upstream registries), `nuget`, `raw`. |
| `server` | `forge-server` | Axum HTTP server: the format plugins' feeds (NuGet at `/v3`, raw files at `/raw`, the Docker / OCI registry at `/v2`), the file store of files formats, the image store and registry tokens of images formats, `/admin` + `/auth` REST, background workers, static SPA serving. |
| `e2e` | `forge-e2e` | End-to-end suite (testcontainers + mock upstream/IdP). |
| `xtask` | — | The task runner (`cargo xtask …`); replaces Make/Just. |
| `web/` | — | TanStack Router SPA (pnpm + Vite), built into `web/dist/`. |

**Every format is a plugin in `crates/formats/`.** A format is a crate in
`crates/formats/<id>/` implementing `FormatPlugin`, linked into the server.
Docker / OCI is one too, an images format: the plugin speaks the protocol,
and the server's image store (`crates/server/src/images`) keeps the
images.

**Single-origin serving.** `forge-server` mounts each format plugin's feed
(NuGet at `/v3`, others at `/repository`), the Docker / OCI registry (`/v2`),
raw file repositories (`/raw`),
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
- **NuGet feed:** `http://localhost:8421/v3/{repo}/index.json`

Add demo data (anonymous-readable `nuget` repo + a pushed sample package) in a
second terminal:

```bash
cargo xtask seed
# feed: http://localhost:8421/v3/nuget/index.json
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
no anonymous access and accepts no passwords over HTTP Basic (clients use API
tokens); an administrator changes both in the web UI under **Admin →
Settings** (see
[docs/deployment.md](docs/deployment.md#access-and-sign-in-settings)).

### Point a `dotnet` client at it

```bash
dotnet nuget add source http://localhost:8421/v3/nuget/index.json -n forge
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
curl -u admin@example.com:<TOKEN> --upload-file tool.tgz http://localhost:8421/raw/binaries/tools/1.0/tool.tgz
curl -u admin@example.com:<TOKEN> -O http://localhost:8421/raw/binaries/tools/1.0/tool.tgz
curl -u admin@example.com:<TOKEN> http://localhost:8421/raw/binaries/tools/1.0/tool.tgz.sha256 | sha256sum -c
```

## Documentation

- **[Production deployment](./docs/deployment.md)** — required settings, TLS
  and reverse proxy, secret encryption, health probes, backup/restore and
  upgrades. Kubernetes: a Helm chart published with every release
  (**[deploy/helm/forge](./deploy/helm/forge/README.md)**, on GitHub Packages
  as [`oci://ghcr.io/forgepkg/charts/forge`](https://github.com/forgepkg/forge/pkgs/container/charts%2Fforge)), or kustomize
  manifests (**[deploy/kubernetes](./deploy/kubernetes/README.md)**).
- **[CHANGELOG.md](./CHANGELOG.md)** — release notes, upgrade notes and known
  limitations; **[SECURITY.md](./SECURITY.md)** — how to report a
  vulnerability.
- **[DEVELOPMENT.md](./DEVELOPMENT.md)** — full local-dev guide: every
  `cargo xtask` command, configuration knobs, OIDC/Entra setup, the web UI dev
  server, tests, and Docker packaging details.
- **[Docker / OCI registry](./docs/docker.md)** — image repositories (hosted,
  proxy, group), naming and host-based routing, `docker login`, retention and
  garbage collection.
- **[Raw file repositories](./docs/raw.md)** — files under arbitrary paths
  (hosted, proxy, group): uploads with curl, ranges and checksum sidecars,
  listings, the deployment policy, proxies of release downloads (the pdfium
  example) and retention.
- **[Trusted publishing](./docs/trusted-publishing.md)** — configure short-lived
  workload identity for GitHub Actions, GitLab CI, and compatible OIDC issuers,
  and exchange a job's OIDC token for a short-lived API key (`POST /api/v2/token`).
- **[Format plugins](./docs/format-plugins.md)** — further package formats,
  built into the server: design, operation, and writing one.
- **[Importing from Nexus](./docs/nexus-import.md)** — copy a Nexus hosted
  repository (NuGet, Docker) into Forge, with its publish dates:
  dry run, conflicts, resuming, and the cutover.

Run `cargo xtask help` for the complete command list.

## License

Forge is licensed under the [MIT License](./LICENSE) (SPDX `MIT`).

Contributions are accepted under the [Contributor License Agreement](./CLA.md),
which grants the forgepkg organization the rights to distribute them under
the MIT License or other terms. See [CONTRIBUTING.md](./CONTRIBUTING.md) for
how to sign it.
