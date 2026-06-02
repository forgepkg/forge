# Developing & running envisia-forge locally

envisia-forge is a Rust NuGet package registry. Locally it runs as a single
`forge-server` process backed by **PostgreSQL** (metadata) and an **S3-compatible**
object store (blobs) — both provided by `docker-compose.yml` (versitygw stands in
for S3).

## Prerequisites

- **Docker** (for Postgres + versitygw, and for the test suites).
- **Rust** stable toolchain (`rustup`, pinned in `rust-toolchain.toml`).
- **Node 22 + npm 10** (for the web UI in `web/`).
- *Optional:* the **.NET SDK** (`dotnet`) to drive the feed with a real client.
- *Optional:* `sqlx-cli` (`cargo install sqlx-cli --no-default-features --features postgres,rustls`)
  only if you change SQL queries and need to regenerate the offline data.

## One command

```bash
make dev
```

`make dev` starts Postgres (host port **5433**) + versitygw (**:7070**), waits for
both to be healthy, then runs the server on **http://localhost:3000** using the
checked-in [`forge.toml`](./forge.toml). Press **Ctrl-C** to stop the server;
`make down` stops the containers.

> First run compiles the workspace (a minute or two) and runs DB migrations
> automatically. A bootstrap admin **`admin` / `changeme`** is created (the server
> logs a warning while that seeded password is in use).

### Add demo data (optional)

With the server running, in a second terminal:

```bash
make seed
```

This creates an anonymous-readable hosted repo `nuget`, mints a push token, and
pushes the bundled sample package. It prints the feed URL and the available
versions. The feed is then browsable without auth at
`http://localhost:3000/v3/nuget/index.json`.

## Web UI (admin + browse SPA)

The UI is a **TanStack Router SPA** in [`web/`](./web), built by Vite into
`web/dist/`. There is **no Node server in production**: the Rust `forge-server`
serves `web/dist/` directly (a `ServeDir` with an `index.html` SPA fallback,
mounted *after* `/admin`, `/browse`, `/v3`), and the browser calls the Rust HTTP
API on the **same origin** with relative URLs. Auth today is token-paste (slice
1 has no sessions yet): paste a repository token on the login screen; it is
verified via `GET /admin/me` and stored in `localStorage`.

### Production-like run (single origin)

Build the UI first, then run the server — the build order matters because the
server serves the built directory:

```bash
make web     # npm ci && npm run build  -> web/dist/
make run     # forge-server serves web/dist at http://localhost:3000
```

`make dev` does both for you (infra → build UI → run server), so the UI is live
at **http://localhost:3000** alongside the API.

### Frontend dev server (HMR)

For fast iteration on the UI, run Vite's dev server (assets + hot reload) against
a running `forge-server`:

```bash
make up && make run            # terminal 1: infra + API on :3000
make web-dev                   # terminal 2: Vite on http://localhost:5173
```

The Vite dev server proxies `/admin`, `/browse`, `/v3`, `/auth` to the Rust
origin (default `http://localhost:3000`, override with `FORGE_DEV_API_TARGET`)
so the same relative API URLs work in dev — this is a dev-only static route, not
a production API proxy.

### Frontend tests

```bash
make web-test                  # Vitest + React Testing Library (unit/component)
make web-e2e                   # Playwright e2e (needs Docker; builds the UI first)
cd web && npm run tsc          # typecheck
cd web && npm run e2e:install  # one-time: download the Playwright browser
```

The Playwright suite (`web/e2e/`) drives a **real `forge-server` serving the
built UI** against an isolated Postgres + versitygw stack (its own compose
project + ports, see `web/e2e/docker-compose.e2e.yml`), brought up automatically
in the suite's global setup. It covers single-origin serving, the SPA fallback,
token sign-in, admin gating, creating a repo, and push-then-see-package. If
Playwright can't download a browser in a restricted environment, `npm run
e2e:list` still enumerates the specs and `npm run e2e:tsc` typechecks them.

> **Known limitation:** the admin UI routes reuse the `/admin/*` paths owned by
> the admin REST API, so a **hard refresh / bookmark / deep-link** of an
> `/admin/<sub>` page is answered by the API, not the SPA. In-app navigation
> (clicking through the nav) is unaffected. Pinned by
> `web/e2e/specs/admin-deeplink.spec.ts`; a fix (move the admin UI off `/admin/*`)
> is a tracked follow-up.

## Doing it by hand

```bash
make up                       # infra only
SQLX_OFFLINE=true cargo run -p forge-server   # or: make run

# create a hosted repo (admin API uses HTTP Basic; allow_password_basic=true in forge.toml)
curl -u admin:changeme -X POST localhost:3000/admin/repositories \
  -H 'content-type: application/json' \
  -d '{"name":"nuget","kind":"hosted","anonymous_read":true}'

# mint a push token (admin is user id 1)
curl -u admin:changeme -X POST localhost:3000/admin/users/1/tokens \
  -H 'content-type: application/json' -d '{"name":"local"}'
# -> {"token":"<SECRET>", ...}   (shown once)

# push a package, then read it back
curl -X PUT localhost:3000/v3/nuget/package \
  -H "X-NuGet-ApiKey: <SECRET>" -F package=@fixtures/nuget/sample.lib.1.0.0.nupkg   # 201
curl localhost:3000/v3/nuget/index.json                          # service index
curl localhost:3000/v3/nuget/flat/sample.lib/index.json          # {"versions":["1.2.3"]}
```

### Use it from the `dotnet` client

```bash
dotnet nuget add source http://localhost:3000/v3/nuget/index.json -n forge
dotnet nuget push -s forge -k <SECRET> your.1.0.0.nupkg
# in a project:
dotnet add package <PackageId>
```

If the repo is **not** anonymous-readable, pass credentials to the source
(`--username admin --password <token> --store-password-in-clear-text`); the
password supplied to NuGet should be a **token**.

## Repository types

- **hosted** — `{"name":"nuget","kind":"hosted"}`; push/restore your own packages.
- **proxy** — `{"name":"nuget-proxy","kind":"proxy","remote_url":"https://api.nuget.org/v3/index.json","package_delay_seconds":0}`; caches on demand, with an optional package delay.
- **group** — `{"name":"all","kind":"group"}`, then
  `POST /admin/repositories/all/members` with `{"member":"nuget","priority":100}`
  (higher priority wins ties).

## Configuration

Everything is in [`forge.toml`](./forge.toml) (loaded by default; override the
path with `FORGE_CONFIG`, or override individual keys with `FORGE_*` env vars
using **double-underscore** nesting, e.g. `FORGE_AUTH__ANONYMOUS_MODE=off`).
Key knobs:

| Setting | Meaning |
| --- | --- |
| `auth.anonymous_mode` | `off` / `allowlist` / `all`. Makes unauthenticated requests an *anonymous principal*. |
| repo `anonymous_read` | **Also required** for anonymous reads — set it per-repo at create time. |
| `auth.allow_password_basic` | Allow HTTP Basic with the user password (needed to use the admin API as the bootstrap admin). |
| `auth.bootstrap_admin` | First-run admin username/password. |
| `[redis]` | Optional shared L2 cache + cross-instance invalidation. Omit for in-process cache only. |

> **Anonymous reads need both** `anonymous_mode` *and* the repo's `anonymous_read=true`
> (authz = authenticated user **or** anonymous-and-repo-allows). For zero-auth
> local browsing, keep `anonymous_mode = "all"` and create repos with
> `"anonymous_read": true`.

## Tests

The integration/e2e suites use **testcontainers** — they start their own
Postgres/versitygw/Redis automatically, so you only need Docker running (you do
**not** need `make up`).

```bash
make test    # unit + integration (cargo test --workspace)
make e2e     # end-to-end suite (cargo test -p forge-e2e --features forge-e2e)
make check   # cargo fmt --check + clippy -D warnings
```

The e2e suite includes an optional `dotnet` smoke test that is skipped when the
.NET SDK isn't installed.

## Resetting & troubleshooting

- `make down` stops the containers but **keeps** the Postgres volume. To wipe all
  state (start fresh): `docker compose down -v`.
- **Port 5432 already in use / `role "forge" does not exist`** — you have another
  Postgres on 5432. The dev DB is intentionally mapped to **5433** to avoid this;
  if the server still connects to the wrong one, check `forge.toml`'s
  `database.url` points at `localhost:5433`.
- **Bucket** — the server auto-creates the S3 bucket on startup; no manual step.
- **`make logs`** tails the container logs; **`make psql`** opens a psql shell on
  the dev DB.

## Helper targets (`make help`)

`up` · `down` · `dev` · `run` · `seed` · `test` · `e2e` · `check` · `fmt` ·
`clippy` · `build` · `prepare` (regenerate sqlx offline data) · `psql` · `logs` ·
`ps` · `clean`.

Web UI: `web` (build) · `web-install` · `web-dev` (Vite HMR) · `web-test`
(Vitest) · `web-e2e` (Playwright).
