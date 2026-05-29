# envisia-forge — NuGet-capable package registry (Slice 1 design)

**Date:** 2026-05-29
**Status:** Approved (pending spec review)
**Product name:** `envisia-forge`

## 1. Context & goal

`envisia-forge` is a self-hostable, Nexus-style package registry. The long-term
vision is a multi-format registry (NuGet, npm, Maven, Cargo, …) with hosted,
proxy, and group repositories, content-addressable deduplicated storage,
retention policies, an OIDC-capable auth system, and an admin frontend.

This document specifies **Slice 1** only: a working **NuGet V3** registry with
all three repository types, content-addressable S3 storage, and a coarse auth
model. Everything else is explicitly deferred (Section 12) with a per-item plan.

### Non-negotiable constraints

- **Backend in Rust.** No TypeScript proxying in front of the Rust API; when the
  frontend slice lands, the browser talks directly to the Rust HTTP API.
- **S3 as the file backend.** Local dev and e2e use [versitygw](https://github.com/versity/versitygw)
  (S3 gateway over a POSIX filesystem). Production points at real S3.
- **PostgreSQL** for all metadata.
- **Performance matters.** Streaming I/O, content-addressable dedup, minimal
  copies.
- Unit tests **and** e2e tests.

### Stack (decided)

axum + tokio (HTTP), sqlx with compile-time-checked queries (Postgres),
aws-sdk-s3 (S3 client, pointed at versitygw locally), sha256 content-addressable
blobs, argon2id password hashing.

### Process

`codex` is used as an **adversarial reviewer at checkpoints** (this spec, then
code/PRs); Claude reconciles its feedback. Claude does the design and
implementation.

## 2. Architecture — format-agnostic core + NuGet adapter (Approach A)

Cargo workspace. The hosted/proxy/group orchestration lives in `core` behind a
minimal `Format` seam; NuGet is the only `Format` implementation in this slice.
The seam exists so format #2 is cheap and so the DB schema is designed correctly
up front — but it is kept minimal (no speculative generality).

```
repo/
├─ Cargo.toml                # workspace manifest
├─ crates/
│  ├─ storage/               # CAS blob store over S3 (aws-sdk-s3): sha256, dedup, refcount
│  ├─ db/                    # sqlx Postgres pool, migrations runner, data-access layer
│  ├─ core/                  # domain model; hosted/proxy/group orchestration; auth/authz; Format trait
│  ├─ format-nuget/          # NuGet V3 protocol: routes, nuspec/zip parsing, version normalization
│  └─ server/                # axum app, config, principal middleware, admin API, wiring, bin
├─ migrations/               # sqlx SQL migrations
├─ tests/                    # e2e harness (testcontainers: postgres + versitygw)
└─ fixtures/                 # sample .nupkg files for tests
```

### The `Format` seam (minimal)

```rust
// crates/core — illustrative, not final
trait Format {
    fn id(&self) -> &'static str;                 // "nuget"
    // Parse an uploaded artifact into component identity + assets + derived metadata.
    fn parse_upload(&self, bytes: &[u8]) -> Result<ParsedUpload, FormatError>;
    // Map a logical asset request to a stored asset path / content type.
    // Protocol HTTP routes themselves live in the format crate and are mounted by `server`.
}
```

Routes are NuGet-specific and provided by `format-nuget` as an axum `Router`
that `server` mounts under `/v3/{repo}`. `core` exposes format-agnostic
operations the routes call: `resolve_versions`, `resolve_asset`,
`store_upload`, `delete_component`, plus the proxy/group resolution logic.

## 3. Data model (PostgreSQL)

All tables use `bigint` generated identity PKs unless noted; timestamps are
`timestamptz`.

- **`repository`**
  - `id`, `name` (unique, url-safe slug), `format` (`nuget`), `kind`
    (`hosted` | `proxy` | `group`), `anonymous_read bool not null default false`,
    `online bool not null default true`, `config jsonb not null`,
    `created_at`, `updated_at`.
  - `config` (proxy): `remote_url`, `package_delay_seconds int`,
    `upstream_username`, `upstream_password` (basic auth; nullable),
    `metadata_ttl_seconds`, `not_found_ttl_seconds`.
  - `config` (group): empty (members live in `group_member`).
  - `config` (hosted): `allow_redeploy bool` (default false ⇒ 409 on duplicate).
- **`group_member`**: `group_id` (FK→repository), `member_id` (FK→repository),
  `priority int not null`. PK `(group_id, member_id)`. **Higher `priority`
  wins** when the same package id+version exists in multiple visible members.
- **`component`**: `id`, `repository_id` (FK), `name` (lowercased NuGet id),
  `original_id` (original-case id), `version` (normalized, lowercased),
  `version_original`, `listed bool not null default true`,
  `first_seen_at timestamptz` (proxy delay clock), `created_at`, `updated_at`.
  Unique `(repository_id, name, version)`. Index on `(repository_id, name)`.
- **`asset`**: `id`, `component_id` (FK), `path` (logical, e.g.
  `<id>.<version>.nupkg`), `content_type`, `blob_sha256` (FK→blob), `size`,
  `created_at`. A NuGet component has exactly one `.nupkg` asset; the `.nuspec`
  is extracted on demand from the blob (or cached as a second asset — see §6).
- **`blob`**: `sha256` (PK, text/bytea), `size bigint`, `s3_key text`,
  `ref_count bigint not null default 0`, `created_at`. Identical bytes are
  stored once; dedup keyed on `sha256`.
- **`app_user`**: `id`, `username` (unique), `password_hash` (argon2id),
  `active bool`, `created_at`, `updated_at`. (`user` is reserved in Postgres ⇒
  table named `app_user`.)
- **`token`**: `id`, `user_id` (FK), `name`, `token_hash` (sha256 of the random
  secret; the plaintext is shown once at creation), `last_used_at`,
  `created_at`. Used both as the NuGet API key (`X-NuGet-ApiKey`, push) and as
  the basic-auth password (restore).

## 4. Content-addressable storage layer (`storage`)

- aws-sdk-s3 client. Endpoint/credentials configurable ⇒ versitygw locally,
  real S3 in prod. Force path-style addressing for versitygw.
- **Blob key layout:** `blobs/sha256/<aa>/<bb>/<full-hash>` (fan-out by first
  two byte-pairs to avoid hot prefixes).
- **Write path (streaming, single hashing pass):**
  1. Stream the incoming body to a temp file, computing sha256 incrementally.
  2. `HEAD` the content key. If present ⇒ dedup: bump `ref_count` in Postgres,
     discard temp, return `(sha256, size)`.
  3. Else `PUT` (multipart upload for bodies over a threshold, e.g. 8 MiB),
     then insert/`ref_count`-bump the `blob` row.
  - Blob insert and `ref_count` changes happen in the **same DB transaction** as
    the owning `asset` insert/delete, so counts never drift.
- **Read path:** `GET` by content key, stream to the HTTP response.
- **GC:** not in this slice. `ref_count` is maintained now; the retention slice
  adds the sweeper that deletes `ref_count == 0` blobs from S3. (See §12.)

## 5. Authentication & authorization

Deliberately coarse in Slice 1. Fine-grained RBAC and OIDC are deferred (§12).

### Principal extraction (axum middleware)

Resolve, in order:
1. **`X-NuGet-ApiKey: <token>`** ⇒ look up `token` by hash ⇒ `User`.
2. **HTTP Basic** `username:secret` where `secret` is the password **or** a
   token ⇒ `User`.
3. Otherwise **anonymous** per the configured anonymous mode (below).
4. Otherwise unauthenticated (no principal).

`last_used_at` on tokens is updated best-effort.

### Anonymous modes (global config: `anonymous_mode`)

- **`off`** — no anonymous access. Unauthenticated requests to protected repos → 401.
- **`allowlist`** — an unauthenticated request from a client IP in
  `anonymous_ip_allowlist` becomes `Anonymous(ip)`. The literal `"local"` entry
  expands to `127.0.0.0/8, ::1/128, 10.0.0.0/8, 172.16.0.0/12,
  192.168.0.0/16, 169.254.0.0/16, fc00::/7, fe80::/10`.
- **`all`** — every unauthenticated request becomes `Anonymous` regardless of IP
  ("anonymous access for everything").

Client IP is the socket peer unless the request arrives from a configured
trusted proxy (`trusted_proxy_cidrs`), in which case the last untrusted hop in
`X-Forwarded-For` is used.

### Authorization (Slice 1)

- **Read** a repository: allowed if principal is `User` (any authenticated user)
  **or** (principal is `Anonymous` **and** `repository.anonymous_read = true`).
- **Write** (push / delete / relist): requires `User`. Never anonymous. (No
  per-user write permissions yet — any authenticated user may write to a hosted
  repo. Fine-grained RBAC deferred.)

### Identity-aware group resolution

When resolving a group for principal `P`, the visible member set is
`[m for m in members if can_read(P, m)]`, evaluated **before** package
resolution. Consequence: an anonymous request to a group containing both
anonymous and non-anonymous members only ever sees packages from the anonymous
members. Authenticated users see all members.

## 6. NuGet V3 protocol surface

All endpoints are scoped per repository under base `/v3/{repo}`. The service
index advertises resource `@id`s that point back into the same `{repo}` base, so
clients self-configure from one URL.

- **Service index:** `GET /v3/{repo}/index.json` →
  `{ "version": "3.0.0", "resources": [...] }` advertising the resources below.
- **Flat container** (`PackageBaseAddress/3.0.0`, drives restore):
  - `GET /v3/{repo}/flat/{lower_id}/index.json` → `{ "versions": [..] }`
    (normalized, lowercased; 404 if none).
  - `GET /v3/{repo}/flat/{lower_id}/{lower_ver}/{lower_id}.{lower_ver}.nupkg` →
    binary nupkg.
  - `GET /v3/{repo}/flat/{lower_id}/{lower_ver}/{lower_id}.nuspec` → XML manifest.
- **Registration** (`RegistrationsBaseUrl/3.6.0`, metadata + dependencies):
  - `GET /v3/{repo}/registration/{lower_id}/index.json` → inlined registration
    pages built from stored nuspecs (dependency groups, listed flag, etc.).
- **Search** (`SearchQueryService/3.5.0`):
  - `GET /v3/{repo}/query?q=&skip=&take=&prerelease=` → search results.
- **Publish** (`PackagePublish/2.0.0`, hosted only):
  - `PUT /v3/{repo}/package` — `multipart/form-data`, first part = raw `.nupkg`;
    `X-NuGet-ApiKey` header. 201/202 success, 400 invalid, 409 duplicate.
  - `DELETE /v3/{repo}/package/{id}/{version}` — unlist (204 / 404).
  - `POST /v3/{repo}/package/{id}/{version}` — relist (200 / 404).

ID lowercasing follows `System.String.ToLowerInvariant()`; versions are
normalized per NuGet's version normalization rules (build metadata stripped).

The `.nuspec` is extracted from the `.nupkg` zip on first request and may be
cached as a derived `asset` referencing its own blob (dedup applies).

## 7. Repository behaviors

### Hosted
- **Push:** parse the `.nupkg` (zip → locate `*.nuspec` → parse id/version/deps),
  validate, store bytes via CAS, write `component` + `asset` (+ derived nuspec).
  Duplicate `(id, version)` → 409 unless `allow_redeploy`.
- **Read:** serve all read resources from local data.
- **Delete/relist:** flip `listed`; hard delete optional (config), decrementing
  `ref_count`.

### Proxy
- **Read-through cache:** on a miss, fetch from `remote_url` via reqwest
  (optional upstream HTTP Basic from config), store into CAS, create a
  `component` with `first_seen_at = now`.
- **Package delay:** a discovered version is only **enumerated/served** once
  `now − first_seen_at ≥ package_delay_seconds`. The clock starts at the proxy's
  **first sighting** of the version (open question 3 — confirmable to use the
  upstream publish timestamp instead). Versions still inside the delay window are
  hidden from flat-container/registration/search output and return 404 on direct
  download.
- **Caching TTLs:** positive metadata cached for `metadata_ttl_seconds`;
  negative (404) cached for `not_found_ttl_seconds`. Downloaded `.nupkg` blobs
  are immutable once cached. Respects the repo `online` flag (offline ⇒ serve
  only cached).

### Group
- Ordered members by `priority`. **Enumeration** = union of visible members'
  versions. **Specific id+version download** = the **highest-priority** visible
  member that has it serves it. Registration/search merge across visible
  members, dedup by id+version with highest-priority winning. No writes.

## 8. Configuration

TOML file with environment-variable overrides (`FORGE_*`). Keys:
`server.bind`, `database.url`, `s3.endpoint/region/bucket/access_key/secret_key/force_path_style`,
`auth.anonymous_mode` (`off|allowlist|all`), `auth.anonymous_ip_allowlist`
(list, supports `"local"`), `auth.trusted_proxy_cidrs`, blob `multipart_threshold`.

Repositories, users, and tokens are managed via a **minimal admin REST API** in
`server` (create/list/update repositories, members, users, tokens) and a
seed-on-boot option for first-run bootstrap. The admin **UI** is a later slice.

## 9. Testing strategy

### Unit tests
- NuGet version normalization + `ToLowerInvariant` id rules.
- nuspec extraction + parsing from a `.nupkg` zip fixture.
- Group priority resolution (union enumeration; highest-priority download winner).
- Package-delay gating (inside vs. outside the window).
- CAS sha256 hashing + dedup + refcount transitions.
- Principal extraction and authz decisions (user/anon/unauth × read/write).
- Anonymous IP allowlist matching, incl. `"local"` expansion and IPv6.

### E2E tests (`tests/`, testcontainers)
Bring up Postgres + versitygw containers and an in-process axum server. Mock
upstream NuGet feed served in-process for proxy scenarios.
- Push to hosted, then restore via flat container; assert nupkg bytes round-trip.
- Registration + search responses for a pushed package.
- Proxy cache-on-demand: first request fetches from mock upstream and caches;
  second request served locally.
- Proxy package-delay: version hidden inside the window, visible after.
- Group ordered resolution across two members with an overlapping version.
- Anonymous mode `allowlist`: allowed IP reads an `anonymous_read` repo; denied
  IP gets 401; non-anon repo denied to anonymous.
- Mixed-anon group: anonymous principal sees only anon members' packages.
- CAS dedup: same package pushed to two repos stores one blob (ref_count == 2).
- **Optional** `dotnet restore`/`dotnet nuget push` smoke test, gated on the
  dotnet SDK being present on the runner.

## 10. Performance notes

- Stream everything; never buffer a whole nupkg in memory beyond the hashing
  temp file. Multipart S3 upload above the threshold.
- Dedup avoids re-storing identical blobs across repos/versions.
- DB indexes on `(repository_id, name)` and `(repository_id, name, version)`.
- Proxy metadata caching avoids hammering upstreams.

## 11. Open questions (to settle in spec review)

1. **Product name** — `envisia-forge` confirmed.
2. **Group priority direction** — **higher integer wins** (confirmed in design).
3. **Package-delay clock origin** — proposal: proxy's **first sighting**.
   Alternative: upstream publish timestamp when the remote exposes it. Default
   to first-sighting unless overridden.

## 12. Deferred scope — with plans

Each deferred item is its own future spec → plan → build cycle. Order below is
the recommended sequencing.

### 12.1 Retention / cleanup + blob GC  *(recommended next slice)*
- **What:** per-repository retention policies — "keep last N versions",
  "keep for X days", "keep N most-recently-downloaded", and proxy
  "evict cached not pulled in X days". Survey Nexus cleanup policies and
  Artifactory retention for parity.
- **Plan:** add `retention_policy jsonb` to `repository`; a background tokio task
  (or external cron-invoked endpoint) evaluates policies, unlists/deletes
  components, decrements `blob.ref_count`; a separate **blob GC sweeper** deletes
  `ref_count == 0` blobs from S3 (with a grace period to avoid races with
  in-flight uploads). Add `last_downloaded_at` tracking to `asset`/`component`.
  Tests: policy evaluation unit tests; e2e that pushes >N versions and asserts
  pruning + blob deletion.

### 12.2 OIDC / Microsoft Entra authentication
- **What:** OpenID Connect login (authorization-code + PKCE), primarily Entra.
  Map OIDC identities to `app_user` (auto-provision option); issue session
  cookies for the UI and let users mint repository tokens.
- **Plan:** add `oidc` config (issuer, client id/secret, redirect, scopes);
  `/auth/oidc/login` + `/auth/oidc/callback`; `external_identity` table linking
  subject→`app_user`. Token minting endpoint already exists from Slice 1.
  Tests: callback flow against a mock OIDC provider.

### 12.3 Credential-forwarding authentication backend  *("authenticate against the registry")*
- **What:** validate a login by forwarding the supplied username/password to a
  configured upstream (e.g. an existing Nexus) via HTTP Basic — the pattern from
  `github.com/schmitch/verdaccio-nexus-auth-proxy`. Distinct from a proxy repo's
  own upstream credentials (which Slice 1 has). This is an **authentication
  provider** for end-user logins.
- **Plan:** pluggable auth-provider chain in `core` (local password provider +
  upstream-basic provider + later OIDC). Config: provider order, upstream URL,
  success criteria, auto-provision + caching of validated users. Tests: mock
  upstream returning 200/401.

### 12.4 Fine-grained RBAC / authorization
- **What:** roles, per-repository read/write/admin privileges, content
  selectors. Replaces Slice 1's "any authenticated user can read/write".
- **Plan:** `role`, `privilege`, `user_role`, `repository_privilege` tables;
  privilege checks in the existing authz layer (the authz seam from Slice 1 is
  the extension point). Tests: matrix of principals × repos × actions.

### 12.5 Frontend (admin + browse UI)
- **What:** TanStack Start admin UI: manage repositories/members/users/tokens,
  browse/search packages, view download stats.
- **Constraint:** the browser calls the **Rust HTTP API directly** — TanStack
  Start serves UI/SSR only; **no Node→Rust API proxy**. CORS/static-serving
  configured on the Rust side (the Rust server may also serve the built static
  assets to keep a single origin).
- **Plan:** its own brainstorming pass for IA and screens; reuse the admin REST
  API from Slice 1, extended as needed.

### 12.6 Additional formats (npm, Maven, Cargo, …)
- **What:** implement the `Format` seam for more ecosystems; npm modeled with
  reference to verdaccio.
- **Plan:** each format is a new `format-*` crate implementing `Format` and
  providing its protocol `Router`; the `core` hosted/proxy/group orchestration
  and storage are reused unchanged. This is the payoff of Approach A.

## 13. Out-of-scope assumptions

- Single-node deployment in Slice 1 (no clustering/HA). Stateless server +
  shared Postgres + shared S3 means horizontal scaling is feasible later without
  redesign, but it is not a Slice 1 goal or test target.
- No mirroring/replication between forge instances.
- No package signing/verification beyond what NuGet clients already do.
