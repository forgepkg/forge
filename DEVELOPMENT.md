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

`cargo xtask dev` uses local Postgres on **:5432** by default, starts
versitygw (**:8422**), then runs both the Rust API (**:8421**) and Vite HMR
(**:8420**). Open the printed Vite portal URL. Press **Ctrl-C** to stop both
processes; `cargo xtask down` stops the containers.

> **Note on Ctrl-C.** Pressing Ctrl-C is the normal, supported way to stop
> `cargo xtask dev`. The terminal delivers the interrupt to the whole process
> group, so `pnpm`/Vite receives it directly and prints `[ELIFECYCLE] Command
> failed.` (and the command exits non-zero). This is harmless shutdown noise,
> **not** a real failure — all child processes (Rust API + Vite) are stopped.
> `xtask` is intentionally dependency-free and `std` offers no signal-handler
> API, so it does not trap the interrupt to suppress that message.

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
> logs a warning while that seeded password is in use). These placeholder
> credentials (and the `minioadmin` S3 keys) are only accepted because the dev
> `forge.toml` sets `server.allow_insecure_defaults = true`; without it the
> server refuses to start with them.

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
API on the **same origin** with relative URLs. `index.html` is served
`Cache-Control: no-cache`, the content-hashed `/assets/*` files
`public, max-age=31536000, immutable`, and a missing `/assets/*` file is a 404
(a tab left open across a deploy reloads once to pick up the new chunks). The SPA uses server-side
password/OIDC sessions and restores its identity through `/auth/me`. Repository
tokens remain credentials for NuGet clients; the browser does not use a pasted
token in `localStorage` as its primary login model.

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

For day-to-day development, `cargo xtask dev` runs Vite HMR in front of the Rust
API. Use **http://localhost:8420** for the UI and **http://localhost:8421** for
the API/feed.

### Frontend dev server (HMR)

For fast iteration on the UI, run Vite's dev server (assets + hot reload) against
a running `forge-server`:

```bash
cargo xtask up && cargo xtask run   # terminal 1: infra + API on :8421
cargo xtask web-dev                 # terminal 2: Vite on :8420
```

The Vite dev server proxies `/admin`, `/browse`, `/v3`, `/auth` to the Rust
origin (default `http://127.0.0.1:8421`, override with `FORGE_DEV_API_TARGET`)
so the same relative API URLs work in dev — this is a dev-only static route, not
a production API proxy.
`web-dev` binds Vite to IPv4 all-interfaces and prints local/network portal
URLs before handing off to Vite.

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

> **Admin UI paths:** the admin screens live under **`/manage/*`**
> (`/manage/repositories`, `/manage/users/<id>`, `/manage/realms`, ...);
> `/admin/*` belongs to the admin REST API, which is routed before the SPA
> fallback. (Before the first release, 1.0.0, the UI shared `/admin/*`, so a
> refresh, bookmark or deep link of an admin screen got raw JSON, a 404 or a
> 405.) A browser navigation (`Sec-Fetch-Dest: document`, or an `Accept`
> preferring `text/html`) to a former UI path such as `/admin/repositories?x=1` is
> 302-redirected to `/manage/repositories?x=1`; API requests to `/admin/*` are
> unchanged. Covered by `web/e2e/specs/admin-deeplink.spec.ts` and
> `crates/server/tests/web_ui.rs`. In Vite dev (`:8420`) `/manage/*` is served
> by Vite itself; `/admin` is still proxied to the API.

## Doing it by hand

```bash
cargo xtask up                # infra only
SQLX_OFFLINE=true cargo run -p forge-server   # or: cargo xtask run

# sign in: the admin API takes a session (or an admin-scoped token), never a
# password over HTTP Basic. Keep the cookie and echo the CSRF token.
CSRF=$(curl -sc /tmp/forge.jar localhost:8421/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"changeme"}' | sed 's/.*"csrf_token":"\([^"]*\)".*/\1/')

# create a hosted repo
curl -b /tmp/forge.jar -H "X-CSRF-Token: $CSRF" -X POST localhost:8421/admin/repositories \
  -H 'content-type: application/json' \
  -d '{"name":"nuget","kind":"hosted","anonymous_read":true}'

# mint a push token for yourself
curl -b /tmp/forge.jar -H "X-CSRF-Token: $CSRF" -X POST localhost:8421/admin/me/tokens \
  -H 'content-type: application/json' -d '{"name":"local"}'
# -> {"token":"<SECRET>", ...}   (shown once)
# For scripted administration, mint one with '{"name":"ops","scope":{"actions":["admin"]}}'
# and send it as the Basic password (curl -u admin:<SECRET>) or X-NuGet-ApiKey.

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
  Private / custom **NuGet V3** feeds (Azure Artifacts, GitHub Packages,
  Artifactory, Nexus, ProGet, MyGet, …) work too: set `upstream_username` and
  `upstream_password` (typically a PAT). The credentials are sent with every
  request to the `remote_url` host — never to a resource the service index
  points at on a different host — and must not be embedded in `remote_url`.
  NuGet V2-only feeds cannot be proxied. Version listings are refreshed at
  most once per `metadata_ttl_seconds`; a failing upstream degrades to what
  is already cached.
- **group** — `{"name":"all","kind":"group"}`, then
  `POST /admin/repositories/all/members` with `{"member":"nuget","priority":100}`
  (higher priority wins ties). A member that errors (e.g. an unreachable
  proxy) is skipped while the others answer. With `prefer_hosted` (default
  **on**, settable on create/update and in the UI), once a hosted member has a
  package id, proxy members are not consulted for it — so a same-named,
  higher-versioned package on a public feed cannot shadow an internal one
  (dependency confusion). Set `"prefer_hosted": false` for plain union
  semantics. That guard only knows names a hosted member already has; list
  your organization's id prefixes in `"reserved_prefixes": ["Acme."]` so ids
  under them never come from a proxy member, also before their first
  internal publish. Both guards trust every hosted member of the group; when
  some of them accept pushes from a wider audience (a developer or scratch
  feed), flag the trusted ones as owners — `"owner": true` when adding the
  member, or `PATCH /admin/repositories/all/members/releases`
  `{"owner": true}`. Once any member is flagged, only owners (and the hosted
  repositories inside an owning nested group) claim ids: an id an owner has
  is served by the owners alone (no proxy or other hosted member adds
  versions to it), and only owners serve reserved ids. Unflag an owner (`{"owner": false}`) before removing it from
  the group or deleting it; both are refused with 409 otherwise.
  Reading a group grants no read on its members: a caller is served from
  the members it may read itself. The same holds for a token whose `scope`
  lists repositories: scoped to the group alone it sees an empty feed, so
  list the group **and** every member it should be served from, e.g.
  `{"scope": {"actions": ["read"], "repositories": [<all>, <nuget>, <nuget-proxy>]}}`.

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
| `auth.bootstrap_admin` | First-run admin username (default `admin`) / password. No or a blank password means no bootstrap admin. |
| `server.allow_insecure_defaults` | Default `false`: startup fails while the bootstrap-admin password is `changeme` or the S3 keys are `minioadmin`. `true` only in dev configs (`forge.toml`, `.env.example`, `docker-compose.app.yml`). |
| `auth.login_max_failures` / `auth.login_failure_window_seconds` | Password-failure lockout per client IP + username for `/auth/login` and Basic password auth (default 10 per 300 s; `0` disables). |
| `[redis]` | Optional shared L2 cache + cross-instance invalidation. Omit for in-process cache only. `connect_timeout_ms` / `response_timeout_ms` (default 2000) bound every Redis call. |
| `server.max_upload_bytes` | Largest accepted push (default 512 MiB); streamed to disk, 413 above it. |
| `server.max_staging_bytes` | Temp space all staged pushes and proxy downloads may use at once (default 4 × the largest item, 4 GiB; `0` = no limit); 503 + `Retry-After` above it. `server.staging_dir` picks the directory. |
| `database.max_connections` / `database.acquire_timeout_seconds` | Pool size (default 20) and how long a request waits for a connection (default 10 s). |
| `[proxy]` | Upstream connect/read/metadata/download timeouts (15 s / 60 s / 60 s / 30 min), size caps (32 MiB metadata, 1 GiB packages) and the 2 MiB in-memory spool threshold — see `forge.toml.example`. |

### Health probes

`GET /healthz` is a dependency-free liveness probe; `GET /readyz` returns 200
only when PostgreSQL and the object store answer within 3 s (503 with
`{"checks":{"database":…,"object_store":…}}` otherwise). The server handles
SIGTERM (as sent by `docker stop` / Kubernetes): it stops accepting
connections, drains in-flight requests, then stops the background workers.

> **Anonymous reads need both** `anonymous_mode` *and* the repo's `anonymous_read=true`
> (authz = authenticated user **or** anonymous-and-repo-allows). For zero-auth
> local browsing, keep `anonymous_mode = "all"` and create repos with
> `"anonymous_read": true`.

## Authentication realms (12.7)

Authentication is driven by ordered, web-managed **auth realms** stored in the
`auth_realm` table: the built-in `local` password realm, optional `oidc`
realms (interactive IdP login) and `credential_forwarding` realms (validate a
login by forwarding it to an upstream like a Nexus over HTTP Basic), plus
`workload_identity` realms for non-interactive, direct-token OIDC trusted
publishing. Manage
them under **Admin → Authentication** (`/manage/realms`) or via the `/admin/realms` API (CRUD +
`PUT /admin/realms/order`); changes apply at runtime — no redeploy. Secrets in
a realm config (`client_secret`, `key_pepper`) are write-only: responses carry
`<key>_set` markers, and an update that omits/blanks a secret keeps the stored
one.

For trust-policy validation, direct-token replay/cache limits, and GitHub
Actions/GitLab CI examples, see
[Trusted publishing](./docs/trusted-publishing.md).

### Usernames and credential forwarding

Usernames are **canonical**: surrounding whitespace is trimmed, the name is
Unicode-NFC-normalized and lowercased, and names that are empty or contain
control characters are refused. `Alice`, `alice` and ` alice ` are one
account everywhere — login, the lockout, the credential cache, provisioning —
and the database enforces it with a unique index on the canonical form.
Migration 0021 canonicalizes existing accounts; where two collide, the oldest
keeps the name and the others are renamed `<name>#<id>` (logged as a warning).
A name that signs in with a password must not contain `:`: HTTP Basic splits
at the first colon, so neither a feed client nor a forwarding realm's upstream
could carry it. Form login answers such a name with 401, and admin user
creation and the bootstrap admin refuse it. OIDC-provisioned names may still
contain one.

A `credential_forwarding` realm forwards the **canonical** username with the
password and, on success, signs the user in as that name. That is only safe
when the upstream **binds the username to the secret**. Many do not: GitHub,
Azure DevOps and GitLab accept a personal access token with *any* username,
so anyone with a token could sign in as any Forge user. For such an upstream,
set `identity_path` to where its JSON success response names the
authenticated account (e.g. `login` for GitHub's `/user`): that name, in
canonical form, must equal the username entered, or the login is rejected; a
success without it fails closed.

`identity_path` also matters for deactivation. A directory often accepts
other spellings of one account (`CORP\mallory`, `mallory@corp`), and Forge
provisions each spelling it forwards as an account of its own. Deactivating
`mallory` then does not stop a login as `corp\mallory` unless the upstream
names the account it authenticated (`identity_path`), or `auto_provision` is
off, or the user is disabled in the directory too. Names a directory could
fold onto another account by Unicode alone (full-width letters, a soft
hyphen, zero-width characters) are never forwarded. Forge logs a warning for
an auto-provisioning realm without `identity_path`.

Every login sends the user's password to the realm's `url`, so it must be
`https` — plain `http` only for a loopback sidecar, or with `"allow_http":
true` set explicitly. The forwarding client ignores `HTTP(S)_PROXY` (the
password goes straight to the configured host), follows no redirects and reads
at most 1 MiB of a success body for `groups_path` / `identity_path`. With the
`local` realm ordered before it, a name that belongs to a local password
account is never forwarded: a wrong password, or any password for a
deactivated local account, is refused locally.

Legacy config import: an existing `[oidc]` or `[auth.upstream_basic]` TOML
block is imported into realm rows on the first boot after the upgrade (one-shot,
recorded in `forge_setting`); afterwards the database is the authority.

The login screen is **identifier-first** by default (username → password
prompt, or a 302 to the IdP when the identifier's email domain matches an OIDC
realm's `login_domains`); set `auth.login_mode = "combined"` for a classic
combined form with per-realm OIDC buttons.

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/auth/login-options` | Public: `{mode, password, oidc: [{name,label,login_url}]}` for the login screen. |
| `POST` | `/auth/identify` | Identifier-first routing: `{mode: password\|oidc_redirect, realm, login_url?}`. Decided by realm config only (never reveals account existence). |
| `POST` | `/auth/login` | Username/password through the realm chain; mints the session cookie; uniform 401 on failure. |
| `GET` | `/auth/oidc/login?redirect_to=/path` | Start OIDC login; 302 → IdP. Writes an `oidc_flow` row (state/nonce/PKCE). |
| `GET` | `/auth/oidc/callback` | Complete login; sets the session cookie, 302 → validated relative target. |
| `GET` | `/auth/me` | Who-am-I for the SPA: `{user_id, username, is_admin, csrf_token}`; 401 if no session. |
| `POST` | `/auth/logout` | Revoke the session + clear the cookie (CSRF-protected). |
| `GET`/`POST`/`DELETE` | `/auth/tokens[/{id}]` | List / mint / revoke the session user's repository tokens (unscoped; `/admin/me/tokens` also takes a `scope`). |

State-changing cookie endpoints (`logout`, token mint/revoke) require a
**double-submit CSRF token**: read `csrf_token` from `/auth/me` (or the
`/auth/login` response) and echo it in the `X-CSRF-Token` header.

> **Security note (12.7 §3.6).** The slice-1 SSRF private-range guard is gone:
> upstream URLs (proxy `remote_url`, credential-forwarding upstreams, OIDC
> issuers) are restricted to `http`/`https` only and **may point at internal
> addresses**. Realm/repository configuration is admin-only by design;
> credential-forwarding sends the user's password to its configured upstream,
> so treat realm admin rights accordingly. Configured hosts are logged on save.

## OIDC / Microsoft Entra login (optional)

Browser login uses the **OpenID Connect authorization-code flow with PKCE**.
A successful login creates a server-side **session** (an opaque cookie → a
`session` row; the DB stores only `sha256(cookie)`, like API tokens) and maps
the IdP identity to an `app_user`. The cookie is `__Host-forge_session`
(`Secure`, host-only) when `public_base_url` is `https://`, and plain
`forge_session` on an http development setup; a request carrying the session
cookie twice is treated as signed out. Ordinary NuGet clients authenticate
with a repository token through `X-NuGet-ApiKey` or Basic; humans mint those
keys after logging in (`POST /auth/tokens`). When the database cannot say
whether a presented token or session is valid, the request is answered `503`,
not `401`, and a Basic secret is then not tried as a password. A validated workload JWT may
instead be supplied as the Basic password, `X-NuGet-ApiKey`, or
`Authorization: Bearer` for the direct-token publishing flow.

Configure the provider as an `oidc` **auth realm** (Admin → Authentication), or
seed it via the legacy `[oidc]` TOML section / `FORGE_OIDC__*` env vars (see
[`forge.toml.example`](./forge.toml.example) / `.env.example`) — imported into
a realm row on first boot. With no enabled oidc realm the `/auth/oidc/*`
endpoints answer 404.

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

When `admin_groups` is set, admin is **recomputed on every login** from the
current claims — both the legacy flag and the built-in `admin` role (a user
removed from the admin role loses admin on next login; existing sessions are not
downgraded mid-session). With an empty `admin_groups` OIDC never touches admin.
OIDC users are identified by the `(issuer, sub)` link. With `auto_provision =
true` (default) a first-time login creates an `app_user`;
`link_existing_by_username` is **off by default** — when enabled it links a new
identity to an existing user of the same name, but never to an account that has
a local password or is an admin, and an email claim is only used as the
username when `email_verified` is true.

The discovery document's token, JWKS and authorization endpoints must live on
the issuer's host. An IdP that serves them elsewhere needs those hosts in the
realm's `endpoint_hosts`: for Google (issuer `https://accounts.google.com`)
`["oauth2.googleapis.com", "www.googleapis.com"]`; restrict it to your
Workspace domain with `required_claims = {"hd": ["corp.example"]}`.

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

**Without Docker**, point the db / storage / core / server suites at running
services instead (use a fresh database per crate run — suites share it):

```bash
export FORGE_TEST_DATABASE_URL=postgres://forge:forge@localhost:5432/forge_test
export FORGE_TEST_S3_ENDPOINT=http://127.0.0.1:7070   # versitygw --access test --secret test posix <dir>
export FORGE_TEST_REDIS_URL=redis://127.0.0.1:6379    # an empty, dedicated Redis
cargo test -p forge-server
```

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

Release: `release <version> [--no-tag]` (see [Releasing](#releasing)).

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

The runtime image carries `LICENSE` and the third-party notices of what it
redistributes in `/usr/share/doc/forge/`: `THIRD-PARTY-RUST.txt` for the
crates compiled into the binary (cargo-about, configured in
`docker/licenses/about.toml`; a crate under a license missing from its
`accepted` list fails the build) and `THIRD-PARTY-WEB.txt` for the npm
packages the SPA ships (`pnpm licenses list --prod`, rendered by
`docker/licenses/web-notices.mjs`). The binary is built with `cargo auditable`,
so it embeds its crate list for SBOM generators and image scanners, and the
`web` and `builder` stages declare `BUILDKIT_SBOM_SCAN_STAGE`, so the release's
SBOM attestation covers the npm packages and crates, not just Debian's.

```bash
cargo xtask docker-build       # docker build -t envisia-forge:latest .
cargo xtask docker-run         # run the image against the compose db + s3 on :8421
```

`docker-run` composes `docker-compose.yml` (db + versitygw) with
`docker-compose.app.yml` (the `app` service) and serves API + SPA on
http://localhost:8421.

## Releasing

A `v<version>` tag on the default branch publishes the release: the release
workflow (`.github/workflows/release.yml`) builds, signs and pushes
`ghcr.io/schmitch/forge:<version>`, packages the Helm chart pinned to that
image's digest, pushes and signs it as `oci://ghcr.io/schmitch/charts/forge`
(version `<version>`), and creates the GitHub release from the matching
`CHANGELOG.md` section with the chart attached. It refuses a tag unless the
workspace version (`Cargo.toml`), `web/package.json`, the image tag of the
Kubernetes base (`deploy/kubernetes/base/kustomization.yaml`) and the chart's
`version` and `appVersion` (`deploy/helm/forge/Chart.yaml`) all equal it, and
unless the `[Unreleased]` section of `CHANGELOG.md` is empty (entries left
there would be missing from the release notes).

`main` only accepts commits whose required checks passed, so the release
commit goes through a pull request and the tag goes on the merge commit; a
direct `git push origin main v1.0.1` of the release commit is refused.
`cargo xtask release <version> --no-tag` prepares the commit:

```bash
git switch -c release-1.0.1 origin/main   # clean and up to date
cargo xtask release 1.0.1 --no-tag        # commits `release: v1.0.1`
git push -u origin release-1.0.1          # open a pull request, merge it
```

Then wait until CI on the merge commit is green, **including `e2e` and
`web-e2e`**: they run only on `main`, after the merge, never on the pull
request. Every push to `main` gets its own CI run, which a later push never
cancels. The release workflow checks this as well: before it builds anything,
it waits (up to an hour) for the tagged commit's CI run on `main` and fails
unless every job of it passed. Tag that commit and push the tag:

```bash
git fetch origin
git tag -a v1.0.1 -m v1.0.1 <merge commit>
git push origin v1.0.1
```

The xtask sets the version in `Cargo.toml`, `Cargo.lock` (`cargo update
--workspace`), `web/package.json`, the Kubernetes base and the Helm chart,
renames `## [Unreleased]` in `CHANGELOG.md` to `## [1.0.1]` under a new, empty
`[Unreleased]`, updates the links at its bottom, and commits
`release: v1.0.1`. It pushes nothing. A `## [1.0.1]` section drafted ahead of
time is kept as it is, but only while `[Unreleased]` is empty; with entries
in both, the release is refused. It also refuses a changelog with a version
section whose tag does not exist (a section drafted for a release that then
got another number): fold its entries into `[Unreleased]` first. Run without
`--no-tag` on a clean `main`, it also creates the annotated tag, for a
repository whose `main` accepts direct pushes.

### Upgrade boundary for migration 0011

Migration `0011_blob_deletion_reservations.sql` changes the CAS coordination
protocol as well as the database schema: new instances acquire `blob_ingest`
leases and create incarnation-qualified S3 keys. Instances built before this
migration do neither. **Do not perform a rolling upgrade across this boundary.**

For the first deployment containing migration 0011:

1. disable old upload traffic **and** old blob-outbox/reconciler workers;
2. stop every pre-0011 Forge instance, wait for active uploads, and ensure every
   S3 DELETE issued by the old workers has reached an unambiguous terminal
   state before continuing;
3. take a coordinated PostgreSQL and object-store backup;
4. start only the new version and let one instance apply migrations; and
5. verify package upload and download before restoring normal replica count.

Stopping the old process is not by itself proof that an S3 DELETE did not reach
the backend: a timed-out or disconnected request can complete later. Use the
object store's documented operation bound/active-request observability for the
quiescence check. If the backend cannot provide that guarantee, copy/restore
the coordinated backup into a clean object namespace before starting the new
version. A delayed pre-0011 DELETE must never overlap a post-0011 revival of the
same legacy object key.

Do not roll back to a pre-0011 binary after new instances have accepted writes.
A rollback requires restoring the coordinated PostgreSQL/object-store backup.
Later versions that use the same lease and key protocol may again be deployed
with the operator's normal rolling strategy.

**Runtime configuration.** The baked `forge.toml` carries non-secret defaults
(`bind 0.0.0.0:8421`, SPA at `/app/web/dist`, `anonymous_mode=off` — no
anonymous access unless you set `FORGE_AUTH__ANONYMOUS_MODE=all`/`allowlist` —,
`allow_password_basic=false`, no bootstrap admin — that comes only from
`FORGE_AUTH__BOOTSTRAP_ADMIN__*` env). The placeholder credentials
(`minioadmin` S3 keys, a `changeme` password) are **refused at startup** unless
overridden; only the dev compose stack sets
`FORGE_SERVER__ALLOW_INSECURE_DEFAULTS=true` (plus admin/changeme and
`FORGE_AUTH__ALLOW_PASSWORD_BASIC=true`). Override anything via `FORGE_*`
env vars (double-underscore nesting). Required at runtime (no safe default):

| Env var | Example |
| --- | --- |
| `FORGE_DATABASE__URL` | `postgres://forge:forge@db:5432/forge` |
| `FORGE_S3__ENDPOINT` | `http://s3:8422` |
| `FORGE_S3__BUCKET` | `forge` |
| `FORGE_S3__ACCESS_KEY` | `…` |
| `FORGE_S3__SECRET_KEY` | `…` |
| `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` | first start only: a real password (the placeholder is refused; without it no bootstrap admin is created) |

Strongly recommended: `FORGE_SERVER__PUBLIC_BASE_URL` (absolute NuGet `@id`
URLs). For a production deployment (TLS, secret encryption, trusted proxies,
backups, upgrades) follow [docs/deployment.md](docs/deployment.md).
