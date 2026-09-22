# envisia-forge

A self-hosted **NuGet package registry** written in Rust. It speaks the NuGet
**V3** protocol and supports the three repository types you expect from an
enterprise registry:

- **hosted** — push and restore your own `.nupkg` packages.
- **proxy** — cache packages on demand from an upstream feed (e.g.
  `api.nuget.org`), with an optional publication delay.
- **group** — fan a single feed URL out across several member repos by priority.

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
blobs. The admin + browse UI is a **TanStack Router SPA** served by the same Rust
process on a single origin — there is no Node server in production.

## Architecture

A Cargo workspace of small crates plus the web SPA:

| Crate (`crates/…`) | Package | Responsibility |
| --- | --- | --- |
| `db` | `forge-db` | PostgreSQL data access (sqlx), row models, DAOs. |
| `storage` | `forge-storage` | CAS over S3, blob outbox / GC reconciler. |
| `cache` | `forge-cache` | In-process L1 + optional Redis L2 with cross-instance invalidation (no Postgres advisory locks). |
| `core` | `forge-core` | Domain logic: repo dispatch, auth chain, authz/RBAC, sessions, OIDC, retention. |
| `format-nuget` | `forge-nuget` | NuGet V3 protocol + `.nupkg`/`.nuspec` parsing. |
| `server` | `forge-server` | Axum HTTP server: NuGet feed, `/admin` + `/auth` REST, background workers, static SPA serving. |
| `e2e` | `forge-e2e` | End-to-end suite (testcontainers + mock upstream/IdP). |
| `xtask` | — | The task runner (`cargo xtask …`); replaces Make/Just. |
| `web/` | — | TanStack Router SPA (pnpm + Vite), built into `web/dist/`. |

**Single-origin serving.** `forge-server` mounts the NuGet feed (`/v3`), the
admin/browse APIs (`/admin`, `/browse`, `/auth`) and then serves the built SPA
from `web/dist/` via a `ServeDir` SPA fallback. The browser talks to the API on
the same origin with relative URLs; no reverse proxy is required.

## Quickstart

Prerequisites: **Docker**, a **Rust** toolchain (pinned in `rust-toolchain.toml`),
and **Node 22 + pnpm 11** (`corepack enable`). Optionally the **.NET SDK** to
drive the feed with a real client.

```bash
cargo xtask dev
```

That one command uses your **local Postgres on :5432** (creating the `forge`
role + database if missing), brings up an S3 gateway (**:8422**) via
`docker-compose.yml`, runs migrations, and starts the Rust API on **:8421** plus
Vite HMR on **:8420**. A bootstrap admin **`admin` / `changeme`** is created on
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

The root `Dockerfile` packages the SPA **and** the Rust server into one image
(no Node in prod):

```bash
cargo xtask docker-build     # docker build -t envisia-forge:latest .
cargo xtask docker-run       # run the image against the compose db + s3 on :8421
```

Or directly, against your own infra (configure with `FORGE_*` env vars, e.g.
`FORGE_DATABASE__URL`, `FORGE_S3__ENDPOINT`/`__BUCKET`/`__ACCESS_KEY`/`__SECRET_KEY`):

```bash
docker run --rm -p 8421:8421 \
  -e FORGE_DATABASE__URL=postgres://forge:forge@db:5432/forge \
  -e FORGE_S3__ENDPOINT=http://s3:8422 -e FORGE_S3__BUCKET=forge \
  -e FORGE_S3__ACCESS_KEY=… -e FORGE_S3__SECRET_KEY=… \
  -e FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD=… \
  envisia-forge:latest
```

The image refuses to start while its placeholder credentials (`minioadmin` S3
keys, bootstrap password `changeme`) are in effect, and defaults to
`anonymous_mode = "off"` (set `FORGE_AUTH__ANONYMOUS_MODE=all` for public reads).

### Point a `dotnet` client at it

```bash
dotnet nuget add source http://localhost:8421/v3/nuget/index.json -n forge
dotnet nuget push -s forge -k <TOKEN> your.1.0.0.nupkg
dotnet add package <PackageId>          # in a project
```

For a non-anonymous repo, pass `--username admin --password <TOKEN>
--store-password-in-clear-text` to the source (the password is a **token**, not
the user password).

## Documentation

- **[DEVELOPMENT.md](./DEVELOPMENT.md)** — full local-dev guide: every
  `cargo xtask` command, configuration knobs, OIDC/Entra setup, the web UI dev
  server, tests, and Docker packaging details.
- **[Trusted publishing](./docs/trusted-publishing.md)** — configure short-lived
  workload identity for GitHub Actions, GitLab CI, and compatible OIDC issuers.
- **Design specs** — `docs/superpowers/specs/` (NuGet registry design;
  auth-realms & workload-identity design) and implementation plans in
  `docs/superpowers/plans/`.

Run `cargo xtask help` for the complete command list.
