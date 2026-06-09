# Developing & running envisia-forge locally

envisia-forge is a Rust NuGet package registry. Locally it runs as a single
`forge-server` process backed by **PostgreSQL** (metadata) and an **S3-compatible**
object store (blobs) — both provided by `docker-compose.yml` (versitygw stands in
for S3).

## Prerequisites

- **Docker** (for Postgres + versitygw, and for the test suites).
- **Rust** stable toolchain (`rustup`, pinned in `rust-toolchain.toml`).
- **Node 22 + pnpm 11** (for the web UI in `web/`; `corepack enable` activates the
  pinned `pnpm@11.5.0` from `web/package.json`).
- *Optional:* the **.NET SDK** (`dotnet`) to drive the feed with a real client.
- *Optional:* `sqlx-cli` (`cargo install sqlx-cli --no-default-features --features postgres,rustls`)
  only if you change SQL queries and need to regenerate the offline data.

## One command

```bash
cargo xtask dev
```

`cargo xtask dev` starts Postgres (host port **5433**) + versitygw (**:8422**),
waits for both to be healthy, builds the web SPA, then runs the server on
**http://localhost:8421** using the checked-in [`forge.toml`](./forge.toml).
Press **Ctrl-C** to stop the server; `cargo xtask down` stops the containers.

`xtask` is a plain Rust binary (in [`xtask/`](./xtask)) that replaces the old
Makefile + Justfile — there is nothing extra to install (no `make`, no `just`).
The `cargo xtask` alias is wired up in [`.cargo/config.toml`](./.cargo/config.toml).

### Picking where Postgres comes from (`--db`)

```bash
cargo xtask dev                # --db local (default): host Postgres on :5432 (forge role+db auto-created)
cargo xtask dev --db docker    # self-contained docker-compose Postgres on :5433
cargo xtask dev --db none      # assume the DB is already up; don't start one
```

By default (`--db local`) the server points at a host Postgres on **:5432**
(creating the `forge` role + `forge` database if missing) via
`FORGE_DATABASE__URL`; versitygw (S3) still comes up via docker. Use `--db
docker` for a fully self-contained stack (Postgres on :5433) if you don't run a
local PostgreSQL. `--db none` starts no infra at all. Run `cargo xtask help` for
the full command list.

> First run compiles the workspace (a minute or two) and runs DB migrations
> automatically. A bootstrap admin **`admin` / `changeme`** is created (the server
> logs a warning while that seeded password is in use).

### Add demo data (optional)

With the server running, in a second terminal:

```bash
cargo xtask seed
```

This creates an anonymous-readable hosted repo `nuget`, mints a push token, and
pushes the bundled sample package. It prints the feed URL and the available
versions. The feed is then browsable without auth at
`http://localhost:8421/v3/nuget/index.json`.

## Web UI (admin + browse SPA)

The UI is a **TanStack Router SPA** in [`web/`](./web), built by Vite into
`web/dist/`. There is **no Node server in production**: the Rust `forge-server`
serves `web/dist/` directly (a `ServeDir` with an `index.html` SPA fallback,
mounted *after* `/admin`, `/browse`, `/v3`), and the browser calls the Rust HTTP
API on the **same origin** with relative URLs. Auth today is token-paste (slice
1 has no sessions yet): paste a repository token on the login screen; it is
verified via `GET /admin/me` and stored in `localStorage`.

The web project uses **pnpm** (pinned via `packageManager` in `web/package.json`)
with a 7-day `minimumReleaseAge` cooldown (`web/pnpm-workspace.yaml`): pnpm will
not install a dependency version published within the last week, a supply-chain
hardening measure against freshly compromised releases.

### Production-like run (single origin)

Build the UI first, then run the server — the build order matters because the
server serves the built directory:

```bash
cargo xtask web     # pnpm install --frozen-lockfile && pnpm run build  -> web/dist/
cargo xtask run     # forge-server serves web/dist at http://localhost:8421
```

`cargo xtask dev` does both for you (infra → build UI → run server), so the UI is
live at **http://localhost:8421** alongside the API.

### Frontend dev server (HMR)

For fast iteration on the UI, run Vite's dev server (assets + hot reload) against
a running `forge-server`:

```bash
cargo xtask up && cargo xtask run   # terminal 1: infra + API on :8421
cargo xtask web-dev                 # terminal 2: Vite on http://localhost:8420
```

The Vite dev server proxies `/admin`, `/browse`, `/v3`, `/auth` to the Rust
origin (default `http://localhost:8421`, override with `FORGE_DEV_API_TARGET`)
so the same relative API URLs work in dev — this is a dev-only static route, not
a production API proxy.

### Frontend tests

```bash
cargo xtask web-test           # Vitest + React Testing Library (unit/component)
cargo xtask web-e2e            # Playwright e2e (needs Docker; builds the UI first)
cd web && pnpm run tsc         # typecheck
cd web && pnpm run e2e:install # one-time: download the Playwright browser
```

The Playwright suite (`web/e2e/`) drives a **real `forge-server` serving the
built UI** against an isolated Postgres + versitygw stack (its own compose
project + ports, see `web/e2e/docker-compose.e2e.yml`), brought up automatically
in the suite's global setup. It covers single-origin serving, the SPA fallback,
token sign-in, admin gating, creating a repo, and push-then-see-package. If
Playwright can't download a browser in a restricted environment, `pnpm run
e2e:list` still enumerates the specs and `pnpm run e2e:tsc` typechecks them.

> **Known limitation:** the admin UI routes reuse the `/admin/*` paths owned by
> the admin REST API, so a **hard refresh / bookmark / deep-link** of an
> `/admin/<sub>` page is answered by the API, not the SPA. In-app navigation
> (clicking through the nav) is unaffected. Pinned by
> `web/e2e/specs/admin-deeplink.spec.ts`; a fix (move the admin UI off `/admin/*`)
> is a tracked follow-up.

## Doing it by hand

```bash
cargo xtask up                # infra only
SQLX_OFFLINE=true cargo run -p forge-server   # or: cargo xtask run

# create a hosted repo (admin API uses HTTP Basic; allow_password_basic=true in forge.toml)
curl -u admin:changeme -X POST localhost:8421/admin/repositories \
  -H 'content-type: application/json' \
  -d '{"name":"nuget","kind":"hosted","anonymous_read":true}'

# mint a push token (admin is user id 1)
curl -u admin:changeme -X POST localhost:8421/admin/users/1/tokens \
  -H 'content-type: application/json' -d '{"name":"local"}'
# -> {"token":"<SECRET>", ...}   (shown once)

# push a package, then read it back
curl -X PUT localhost:8421/v3/nuget/package \
  -H "X-NuGet-ApiKey: <SECRET>" -F package=@fixtures/nuget/sample.lib.1.0.0.nupkg   # 201
curl localhost:8421/v3/nuget/index.json                          # service index
curl localhost:8421/v3/nuget/flat/sample.lib/index.json          # {"versions":["1.2.3"]}
```

### Use it from the `dotnet` client

```bash
dotnet nuget add source http://localhost:8421/v3/nuget/index.json -n forge
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

## OIDC / Microsoft Entra login (optional)

Browser login uses the **OpenID Connect authorization-code flow with PKCE**.
A successful login creates a server-side **session** (an opaque `forge_session`
cookie → a `session` row; the DB stores only `sha256(cookie)`, like API tokens)
and maps the IdP identity to an `app_user`. NuGet protocol endpoints are
unchanged — clients still authenticate with `X-NuGet-ApiKey`/Basic; humans mint
those keys after logging in (`POST /auth/tokens`).

Configure a single provider via the `[oidc]` TOML section or `FORGE_OIDC__*`
env vars (see [`forge.toml.example`](./forge.toml.example) / `.env.example`).
Omitting the section disables login entirely (no `/auth/oidc/*` routes).

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/auth/oidc/login?redirect_to=/path` | Start login; 302 → IdP. Writes an `oidc_flow` row (state/nonce/PKCE). |
| `GET` | `/auth/oidc/callback` | Complete login; sets the session cookie, 302 → validated relative target. |
| `GET` | `/auth/me` | Who-am-I for the SPA: `{user_id, username, is_admin, csrf_token}`; 401 if no session. |
| `POST` | `/auth/logout` | Revoke the session + clear the cookie (CSRF-protected). |
| `GET`/`POST`/`DELETE` | `/auth/tokens[/{id}]` | List / mint / revoke the session user's repository tokens. |

State-changing cookie endpoints (`logout`, token mint/revoke) require a
**double-submit CSRF token**: read `csrf_token` from `/auth/me` and echo it in
the `X-CSRF-Token` header.

### Microsoft Entra setup

1. **App registration** (Entra admin center → *App registrations* → *New*):
   - *Redirect URI* (type **Web**): `https://forge.example.com/auth/oidc/callback`
     — must equal `server.public_base_url` host + the exact callback path.
   - Note the **Application (client) ID** and **Directory (tenant) ID**.
2. **Client secret**: *Certificates & secrets* → *New client secret*; copy the
   value (it is redacted from forge logs and never echoed by any API).
3. **Admin assignment (recommended: app roles, not raw groups)**: *App roles* →
   add e.g. `forge-admins`, then assign users/groups under *Enterprise
   applications* → *Users and roles*. App roles arrive in the `roles` claim and
   avoid the Entra "groups overage" Graph callout. Set `admin_groups =
   ["forge-admins"]` and `admin_claim = "roles"`. Empty `admin_groups` ⇒ OIDC
   never grants admin (admins stay locally managed).

```toml
[oidc]
enabled       = true
issuer        = "https://login.microsoftonline.com/<tenant-id>/v2.0"  # must be https
client_id     = "00000000-0000-0000-0000-000000000000"
client_secret = "<application-client-secret>"        # redacted from APIs/logs
redirect_url  = "https://forge.example.com/auth/oidc/callback"
scopes        = ["openid", "profile", "email"]
# admin via Entra app role:
admin_groups  = ["forge-admins"]
admin_claim   = "roles"
```

`is_admin` is **recomputed on every login** from the current claims (a user
removed from the admin role loses admin on next login; existing sessions are not
downgraded mid-session). With `auto_provision = true` (default) a first-time
login creates an `app_user`; `link_existing_by_username = true` lets the matching
Entra identity claim an existing local user (the **bootstrap admin** interplay) —
set it `false` if the username claim is not trustworthy.

### Multi-instance / scale-out

All ephemeral flow state (`state`/`nonce`/PKCE verifier/redirect) and all
sessions live in **Postgres**, never process memory, so a callback can be
completed by a **different** instance than the one that began the login. The
`oidc_flow` row is single-use (`DELETE … RETURNING`). JWKS/discovery are cached
through the `cache` crate (no Postgres advisory locks); a background **auth
reaper** (one of the workers in `crates/server/src/workers.rs`) periodically
deletes expired/used flow rows and dead sessions on any instance.

### Local testing against the in-process mock IdP

The e2e suite (`cargo xtask e2e`) stands up an in-process mock OIDC provider
(discovery + JWKS + a token endpoint signing a test ID token) so OIDC login can
be exercised end-to-end without a real Entra tenant. For a real self-hosted IdP
on a private/dev network (e.g. Keycloak over plain `http`), set
`oidc.allow_private_issuer = true` to relax the https-issuer check. (Since the
12.7 auth-realms slice the old SSRF private-range guard is gone entirely —
outbound upstream/issuer URLs are only restricted to http/https.)

## Tests

The integration/e2e suites use **testcontainers** — they start their own
Postgres/versitygw/Redis automatically, so you only need Docker running (you do
**not** need `cargo xtask up`).

```bash
cargo xtask test    # unit + integration (cargo test --workspace)
cargo xtask e2e     # end-to-end suite (cargo test -p forge-e2e --features forge-e2e)
cargo xtask check   # cargo fmt --check + clippy -D warnings
```

The e2e suite includes an optional `dotnet` smoke test that is skipped when the
.NET SDK isn't installed.

## Resetting & troubleshooting

- `cargo xtask down` stops the containers but **keeps** the Postgres volume. To
  wipe all state (start fresh): `docker compose down -v`.
- **Port 5432 already in use / `role "forge" does not exist`** — you have another
  Postgres on 5432. The dev DB is intentionally mapped to **5433** to avoid this;
  if the server still connects to the wrong one, check `forge.toml`'s
  `database.url` points at `localhost:5433`.
- **Bucket** — the server auto-creates the S3 bucket on startup; no manual step.
- **`cargo xtask logs`** tails the container logs; **`cargo xtask psql`** opens a
  psql shell on the dev DB.

## Helper commands (`cargo xtask help`)

`up` · `down` · `dev` · `run` · `seed` · `test` · `e2e` · `check` · `fmt` ·
`clippy` · `build` · `prepare` (regenerate sqlx offline data) · `psql` · `logs` ·
`ps` · `clean`.

Web UI: `web` (build) · `web-install` · `web-dev` (Vite HMR) · `web-test`
(Vitest) · `web-e2e` (Playwright).

Docker image: `docker-build` · `docker-run` (wired to the `Dockerfile`).

## Single-container Docker image

The root `Dockerfile` is a multi-stage build that packages the TanStack Router
SPA **and** the Rust `forge-server` into ONE image. The server serves the API
and the static SPA on a single port (no Node in prod):

1. **web** — Node 22 + pnpm (corepack): `pnpm install --frozen-lockfile` +
   `pnpm run build` → `web/dist`.
2. **builder** — `rust:1.95` with cargo-chef for dependency-layer caching;
   `cargo build --release -p forge-server` with `SQLX_OFFLINE=true` against the
   committed `.sqlx/` cache (no DB needed at build time).
3. **runtime** — `debian:bookworm-slim` (+ `ca-certificates`) running as an
   unprivileged `forge` user, with the binary, the built SPA at `/app/web/dist`,
   the `migrations/` dir, and a baked secret-free base config at `/app/forge.toml`
   (migrations are also embedded into the binary via `sqlx::migrate!`).

```bash
cargo xtask docker-build       # docker build -t envisia-forge:latest .
cargo xtask docker-run         # run the image against the compose db + s3 on :8421
```

`docker-run` composes `docker-compose.yml` (db + versitygw) with
`docker-compose.app.yml` (the `app` service) and serves API + SPA on
http://localhost:8421.

**Runtime configuration.** The baked `forge.toml` carries non-secret defaults
(`bind 0.0.0.0:8421`, SPA at `/app/web/dist`, `anonymous_mode=all`,
`allow_password_basic`, bootstrap admin `admin/changeme`). Override anything via
`FORGE_*` env vars (double-underscore nesting). Required at runtime (no safe
default):

| Env var | Example |
| --- | --- |
| `FORGE_DATABASE__URL` | `postgres://forge:forge@db:5432/forge` |
| `FORGE_S3__ENDPOINT` | `http://s3:8422` |
| `FORGE_S3__BUCKET` | `forge` |
| `FORGE_S3__ACCESS_KEY` | `…` |
| `FORGE_S3__SECRET_KEY` | `…` |

Strongly recommended: `FORGE_SERVER__PUBLIC_BASE_URL` (absolute NuGet `@id`
URLs) and `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` (change the seeded password).
