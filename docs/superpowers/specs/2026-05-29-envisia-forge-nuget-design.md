# envisia-forge — NuGet-capable package registry (Slice 1 design)

**Date:** 2026-05-29
**Status:** Approved (revised after adversarial review)
**Product name:** `envisia-forge`

> Revision note: this spec was reviewed adversarially by `codex`; 26 findings
> were reconciled. The protocol, CAS, proxy, group, and auth sections below
> reflect that pass. Appendix A pins the concrete NuGet V3 JSON shapes.

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
- **Performance matters.** Streaming I/O, content-addressable dedup, minimal copies.
- **Horizontal scale-out is a slice-1 requirement.** Multiple stateless server
  instances must run against shared Postgres + shared S3 (+ optional Redis).
  **No authoritative state lives in process memory only** — caches, locks,
  sessions, proxy metadata, and blob bookkeeping are all backed by a shared
  store, so a cold instance rebuilds everything from Postgres/S3/Redis. In-memory
  is permitted only as an L1 cache in front of a shared source of truth.
- Unit tests **and** e2e tests.

### Stack (decided)

axum + tokio (HTTP), sqlx with compile-time-checked queries (Postgres),
aws-sdk-s3 (S3 client, pointed at versitygw locally), sha256 content-addressable
blobs, argon2id password hashing, reqwest (proxy upstream client).

### Process

`codex` is used as an **adversarial reviewer at checkpoints** (this spec, then
code/PRs); Claude reconciles its feedback. Claude does the design and
implementation.

## 2. Architecture — format-agnostic core + NuGet adapter (Approach A)

Cargo workspace. The hosted/proxy/group orchestration lives in `core` behind a
minimal `Format` seam; NuGet is the only `Format` implementation in this slice.
The seam exists so format #2 is cheap and the DB schema is designed correctly up
front — but it is kept minimal (no speculative generality).

```
repo/
├─ Cargo.toml                # workspace manifest
├─ crates/
│  ├─ storage/               # CAS blob store over S3 (aws-sdk-s3): sha256, dedup, refcount, outbox worker
│  ├─ db/                    # sqlx Postgres pool, migrations runner, data-access layer
│  ├─ cache/                 # HybridCache-style L1 (moka) + optional L2 (Redis) + invalidation backplane
│  ├─ core/                  # domain model; hosted/proxy/group orchestration; auth/authz; Format trait
│  ├─ format-nuget/          # NuGet V3 protocol: routes, nuspec/zip parsing, version normalization
│  └─ server/                # axum app, config, principal middleware, admin API, wiring, bin
├─ migrations/               # sqlx SQL migrations
├─ tests/                    # e2e harness (testcontainers: postgres + versitygw)
└─ fixtures/                 # sample .nupkg files for tests
```

### The `Format` seam (minimal)

The artifact parser reads from a **seekable temp file** (a `.nupkg` is a zip; its
central directory is at the end, so streaming-only parsing is impossible and we
must not buffer the whole package in memory). The CAS write produces that temp
file as a side effect of hashing (§4), so parsing reuses it.

```rust
// crates/core — illustrative, not final
trait Format {
    fn id(&self) -> &'static str;                       // "nuget"
    /// Parse an uploaded artifact (from a seekable file) into component
    /// identity + assets + derived metadata. Bounded reads; no full-buffer.
    fn parse_upload(&self, file: &mut (impl Read + Seek)) -> Result<ParsedUpload, FormatError>;
}
```

Routes are NuGet-specific and provided by `format-nuget` as an axum `Router`
mounted by `server` under `/v3/{repo}`. `core` exposes format-agnostic
operations the routes call: `resolve_versions`, `resolve_asset`, `store_upload`,
`delete_component`, plus the proxy/group resolution logic.

### 2.1 State, caching & scale-out (no in-memory-only state)

Every server instance is stateless and interchangeable. The source of truth is
always **Postgres** (metadata, locks, outbox, sessions later) and **S3** (bytes).
Redis is **optional** and used only as a shared L2 cache / invalidation
backplane; the system is fully correct without it (just with more Postgres reads
on cold caches).

- **`cache` crate — a HybridCache analogue.** L1 = `moka` (in-process, TTL +
  size-bounded). L2 = optional Redis. Lookups: L1 → L2 → factory; on factory run,
  write both layers. This mirrors .NET `HybridCache`. `foyer` (memory+*disk*)
  and `multi-tier-cache` (moka+redis) are references; we keep a thin in-house
  wrapper so the L2 and the invalidation backplane are ours to control.
- **Stampede protection.** Per-instance request coalescing via `moka`'s
  `try_get_with`. Cross-instance coalescing for *expensive* shared work (proxy
  upstream fetch) uses **row-level `SELECT … FOR UPDATE` locks** on the relevant
  row (e.g. `proxy_cached_version` / `proxy_upstream_index`) — **no Postgres
  advisory locks**. Cheap idempotent rebuilds (hosted registration/search) rely
  on per-instance coalescing + short TTL.
- **Cross-node invalidation.** When Redis is present, a pub/sub backplane
  broadcasts key invalidations so every instance drops the stale L1 entry
  (HybridCache's distributed-invalidation approach). Without Redis, L1 entries
  use short TTLs and authoritative re-reads from Postgres bound staleness.
- **What is cached vs. authoritative.** Everything cached is *derivable* from
  Postgres/S3: proxy upstream service-index resolution, proxy metadata/version
  listings, registration/search documents, service-index docs. The authoritative
  copies live in Postgres tables (`proxy_cached_version`, `proxy_upstream_index`,
  `repository`, …). A cold instance never needs another instance's memory.
- **Sessions & ephemeral auth state (forward-looking).** Slice 1 auth is
  stateless (tokens / basic), so there are no sessions yet. The §12.2 OIDC slice
  and anything session-like (login sessions, CSRF/nonce, rate-limit counters)
  **must** use Postgres or Redis — never in-process memory. This constraint is
  recorded now so later slices honor it.
- **Background workers** (outbox processor §4, orphan reconciler, proxy refresh)
  run on every instance and coordinate via Postgres (`SELECT … FOR UPDATE
  SKIP LOCKED` for the outbox; row-level `FOR UPDATE` for proxy refresh) so work
  is not duplicated across the cluster — **no advisory locks**.

## 3. Data model (PostgreSQL)

`bigint` generated identity PKs unless noted; timestamps are `timestamptz`.

- **`repository`**
  - `id`, `name` (unique, url-safe slug), `format` (`nuget`), `kind`
    (`hosted` | `proxy` | `group`), `anonymous_read bool not null default false`,
    `online bool not null default true`, `config jsonb not null`,
    `created_at`, `updated_at`.
  - proxy also has dedicated columns (not in `config`, so they can be redacted
    and later encrypted): `remote_url text`, `package_delay_seconds int not null
    default 0`, `upstream_username text`, `upstream_password text` (redacted from
    all API responses — §5), `metadata_ttl_seconds int`, `not_found_ttl_seconds int`.
  - hosted `config`: `allow_redeploy bool` (default false ⇒ 409 on duplicate).
- **`group_member`**: `group_id` (FK→repository), `member_id` (FK→repository),
  `priority int not null`. PK `(group_id, member_id)`; **unique `(group_id,
  priority)`** so resolution is deterministic. **Higher `priority` wins** ties.
  Slice 1: `member_id` must reference a `hosted` or `proxy` repo — **nested
  groups are rejected** at config time (cycle-free by construction; nesting
  deferred to §12.4-adjacent work).
- **`component`**: `id`, `repository_id` (FK), `name` (lowercased NuGet id),
  `original_id`, `version` (normalized, lowercased), `version_original`,
  `listed bool not null default true`, `created_at`, `updated_at`.
  Unique `(repository_id, name, version)`. Index `(repository_id, name)`.
- **`asset`**: `id`, `component_id` (FK), `path` (logical, e.g.
  `<id>.<version>.nupkg`), `content_type`, `blob_sha256` (FK→blob),
  `size bigint`, `sha512_base64 text` (NuGet `packageHash`, computed on ingest
  for the primary `.nupkg` asset), `created_at`. A NuGet component has one
  `.nupkg` asset; the `.nuspec` is extracted on demand and may be cached as a
  second derived asset (its own blob; dedup applies).
- **`blob`**: `sha256` (PK), `size bigint`, `s3_key text`, `ref_count bigint not
  null default 0`, `state text` (`pending` | `committed`), `created_at`.
  Identical bytes stored once.
- **`blob_outbox`**: reliable, crash-safe blob side-effects (the transactional
  outbox pattern). `id`, `op text` (`delete_object`), `sha256`, `s3_key`,
  `available_at timestamptz` (grace delay before a delete fires), `attempts int`,
  `locked_until timestamptz null`, `processed_at timestamptz null`,
  `created_at`. Rows are enqueued **in the same transaction** as the refcount
  change that produced them; a worker drains them idempotently (§4).
- **`proxy_cached_version`**: proxy metadata cache distinct from `component`
  (versions are *discovered* from upstream before any download). Columns:
  `id`, `repository_id` (FK, proxy), `name`, `version`, `listed bool`,
  `first_seen_at timestamptz not null` (package-delay clock), `downloaded bool
  not null default false`, `metadata_refreshed_at`, `not_found bool` +
  `not_found_at` (negative cache). Unique `(repository_id, name, version)`.
- **`proxy_upstream_index`**: authoritative cache of a proxy's resolved upstream
  V3 service index (so any instance can use it; L1/L2 sit on top). `repository_id`
  (PK, proxy), `resources jsonb` (resolved `@id`s), `fetched_at`, `etag`.
- **`app_user`**: `id`, `username` (unique), `password_hash` (argon2id),
  `is_admin bool not null default false`, `active bool`, `created_at`,
  `updated_at`. (`user` is reserved in Postgres ⇒ `app_user`.)
- **`token`**: `id`, `user_id` (FK), `name`, `token_hash` (sha256 of a 256-bit
  random secret; **unique index**), `expires_at timestamptz null`,
  `revoked_at timestamptz null`, `last_used_at`, `created_at`. Plaintext shown
  once at creation. Compared in constant time.

## 4. Content-addressable storage layer (`storage`)

- aws-sdk-s3 client; endpoint/credentials/region/path-style configurable ⇒
  versitygw locally (force path-style), real S3 in prod.
- **Blob key layout:** `blobs/sha256/<aa>/<bb>/<full-hash>` (prefix fan-out).
- **Write path (streaming, single hashing pass, race- and crash-safe):**
  1. Stream the body to a temp file, computing sha256 incrementally; also
     compute SHA512 for the NuGet `packageHash` in the same pass.
  2. Upsert a `blob` row `state='pending'` via `INSERT … ON CONFLICT (sha256)
     DO NOTHING`. If it already exists `committed`, treat as dedup hit.
  3. `HEAD` the content key; if absent, `PUT` (multipart above
     `multipart_threshold`, e.g. 8 MiB). Idempotent — re-PUT of identical
     content is harmless.
  4. In **one DB transaction**: set the `blob` row `state='committed'`, insert
     the owning `asset`, and `UPDATE blob SET ref_count = ref_count + 1`. The
     refcount change is atomic and always in the asset's transaction, so counts
     never drift.
  5. The temp file (already hashed) is handed to `Format::parse_upload`.
- **Delete via transactional outbox (reliable, crash-safe, cluster-safe):**
  deleting an asset decrements `ref_count` in its transaction; **iff** that drops
  the blob to `ref_count = 0`, the same transaction inserts a `blob_outbox`
  `delete_object` row with `available_at = now + grace`. The Postgres write
  (refcount + outbox row) is atomic, so a delete intent is never lost even if the
  process dies immediately after commit.
- **Outbox worker (runs on every instance):** `SELECT … FOR UPDATE SKIP LOCKED`
  a batch of due (`available_at <= now`, unprocessed) rows, lease them
  (`locked_until`), and execute. For `delete_object`: re-check the blob still has
  `ref_count = 0` (a concurrent re-push may have revived it — if so, drop the
  outbox row without deleting), then `DELETE` the S3 object (idempotent: a
  missing object is success) and remove the `blob` row. Mark `processed_at`.
  Retries with backoff via `attempts`; `SKIP LOCKED` makes it safe across
  instances. This is the primary blob-GC mechanism.
- **Orphan reconciler (backstop):** a periodic job covers the one gap the outbox
  cannot — bytes PUT to S3 whose owning transaction never committed (crash
  between PUT and commit). It deletes S3 objects whose `blob` row is `pending`
  (or absent) and older than a grace period, and any `ref_count = 0` blob with no
  pending outbox row. Belt-and-suspenders to the outbox, not the main path.
- **Read path:** `GET` by content key, stream to the HTTP response. `HEAD`
  supported (returns size/hash headers, no body).

Policy-driven retention GC (§12.1) reuses this exact machinery: it just enqueues
the asset deletes that drive refcounts to zero.

## 5. Authentication & authorization

Deliberately coarse in Slice 1 (no per-user RBAC). OIDC and credential
forwarding are deferred (§12).

### Principal extraction (axum middleware)

1. **`X-NuGet-ApiKey: <token>`** → token lookup (hash, constant-time) → `User`.
2. **HTTP Basic** `username:secret`: `secret` is matched as a **token** first,
   then (if `auth.allow_password_basic = true`) as the user password. NuGet
   clients are expected to use tokens; password-basic defaults **off** for repo
   endpoints and is intended for the admin API.
3. If an auth header (Basic or `X-NuGet-ApiKey`) is **present but invalid** →
   **401**. Never silently downgrade bad credentials to anonymous.
4. No auth header → anonymous per `anonymous_mode` (below), else unauthenticated.

`last_used_at` updated best-effort. Tokens past `expires_at`/`revoked_at` are
rejected.

### Anonymous modes (global `auth.anonymous_mode`)

- **`off`** — no anonymous; unauthenticated → 401 on protected repos.
- **`allowlist`** — unauthenticated request whose resolved client IP ∈
  `auth.anonymous_ip_allowlist` becomes `Anonymous(ip)`. Tokens:
  - `"loopback"` → `127.0.0.0/8, ::1/128`
  - `"private"` → `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fc00::/7, fe80::/10`
  - `"local"` → loopback **+** private. **Documented risk:** behind a reverse
    proxy on RFC1918 space, `private`/`local` can effectively grant anonymous
    access to anyone the proxy forwards. Use `loopback`, explicit CIDRs, and/or
    correct `trusted_proxy_cidrs`. `off`/`loopback` are the safe defaults.
- **`all`** — every unauthenticated request becomes `Anonymous` regardless of IP
  ("anonymous access for everything").

### Client IP resolution

Client IP is the **socket peer** unless the peer ∈ `auth.trusted_proxy_cidrs`.
When trusted, walk `X-Forwarded-For` **right-to-left**, dropping trusted hops,
and take the first untrusted address. Malformed XFF → reject (treat as
untrusted). Never trust XFF from an untrusted peer.

### Authorization (Slice 1)

- **Read** a repository: `User` (any authenticated user) **or** (`Anonymous`
  **and** `repository.anonymous_read = true`).
- **Write** (push/delete/relist): requires `User`. Never anonymous.
- **Admin API** (repositories/users/tokens/members): requires `User` with
  `is_admin = true`. A **bootstrap admin** is created on first run from
  `auth.bootstrap_admin` config/env (username + password or pre-hashed); a
  warning is logged until its password is changed.

### Identity-aware group resolution

Resolving a group for principal `P`: visible members = `[m for m in members if
can_read(P, m)]`, evaluated **before** package resolution. ⇒ an anonymous
request to a mixed group only sees packages from `anonymous_read` members;
authenticated users see all members.

## 6. NuGet V3 protocol surface

Per repository under base `/v3/{repo}`. The service index advertises **absolute**
resource `@id`s built from a configured `server.public_base_url` +
`/v3/{repo}/...` so clients self-configure from one URL. Trailing slashes match
NuGet conventions (Appendix A). `GET` resources also support `HEAD`.

- **Service index:** `GET /v3/{repo}/index.json` — advertises only the
  resources the repo supports. **`PackagePublish` is advertised for `hosted`
  repos only**; proxy/group advertise read resources only.
- **Flat container** (`PackageBaseAddress/3.0.0`):
  - `GET /flat/{lower_id}/index.json` → `{ "versions": [..] }` (normalized,
    lowercased; 404 if none). Includes unlisted versions (per spec).
  - `GET /flat/{lower_id}/{lower_ver}/{lower_id}.{lower_ver}.nupkg` → bytes.
  - `GET /flat/{lower_id}/{lower_ver}/{lower_id}.nuspec` → XML.
- **Registration** (`RegistrationsBaseUrl/3.6.0`): `GET
  /registration/{lower_id}/index.json` — inlined pages with `catalogEntry`
  (id, version, deps groups, `listed`, `packageHash` (SHA512 base64),
  `packageContent` absolute URL). Exact JSON in Appendix A.
- **Search** (`SearchQueryService/3.5.0`): `GET
  /query?q=&skip=&take=&prerelease=&semVerLevel=` → `{ totalHits, data:[…] }`
  with per-package `versions`, honoring `listed` and `prerelease` filtering.
  Exact JSON in Appendix A.
- **Publish** (`PackagePublish/2.0.0`, hosted only):
  - `PUT /package` — `multipart/form-data`, first part = raw `.nupkg`;
    `X-NuGet-ApiKey`. 201/202 ok, 400 invalid, 409 duplicate (unless
    `allow_redeploy`).
  - `DELETE /package/{id}/{version}` — **unlist** (`listed=false`); the package
    **remains downloadable by exact version** and present in flat-container
    enumeration; it is hidden from search and "latest"/registration listed
    views. 204 / 404. Hard delete is an admin-API operation, not this endpoint.
  - `POST /package/{id}/{version}` — relist (200 / 404).

ID lowercasing follows `ToLowerInvariant()`; versions normalized per NuGet rules
(build metadata stripped).

### Redeploy (`allow_redeploy = true`)

`SELECT … FOR UPDATE` the component, replace the `.nupkg` asset (and derived
nuspec) to point at the new blob, **decrement the old blob's `ref_count` and
increment the new one's in the same transaction**. Idempotent re-push of
identical bytes is a no-op (same sha256).

## 7. Repository behaviors

### Hosted
- **Push:** CAS-store the bytes (§4) → parse the temp `.nupkg` (zip → `*.nuspec`
  → id/version/deps) → write `component` + `.nupkg` asset (+ derived nuspec).
  Duplicate `(id, version)` → 409 unless `allow_redeploy`.
- **Read:** served from local data.
- **Delete/relist:** flip `listed`. Hard delete is admin-only and decrements
  `ref_count`.

### Proxy
- **Upstream discovery:** `remote_url` is treated as an **upstream V3 service
  index**; forge fetches it, resolves the upstream's `PackageBaseAddress` /
  `RegistrationsBaseUrl` / search `@id`s, and caches them for
  `metadata_ttl_seconds`. Defined timeouts; bounded redirects; redirects
  re-validated by the SSRF guard.
- **SSRF guard:** `remote_url` and every redirect target must be `http`/`https`
  and, by default, must **not** resolve to loopback/link-local/private ranges
  (overridable per-proxy `allow_private_upstream` for internal mirrors). DNS is
  re-checked at connect time.
- **Read-through cache + singleflight:** on a miss, serialize with a **row lock**
  — `INSERT … ON CONFLICT DO NOTHING` the `proxy_cached_version` row then
  `SELECT … FOR UPDATE` it (NO advisory locks) — so concurrent requests fetch
  once. Fetch from
  upstream (optional HTTP Basic from `upstream_username`/`password`), CAS-store,
  mark `downloaded=true`, attach a `component` + asset.
- **Package delay:** on metadata discovery, upsert `proxy_cached_version` with
  `first_seen_at = now` **without serving**. A version is enumerated/served only
  once `now − first_seen_at ≥ package_delay_seconds`. Inside the window it is
  omitted from flat/registration/search and direct download returns 404.
  Open question 3 settled: clock = **proxy's first sighting** (configurable to
  use upstream publish timestamp later).
- **Negative cache vs. delay:** delay-gated 404s are **never** written to the
  not-found cache; they expire naturally at `first_seen_at + delay`. Genuine
  upstream 404s use `not_found` + `not_found_at` with `not_found_ttl_seconds`.
- **Offline:** `online=false` ⇒ serve only what is already cached.

### Group
- Ordered visible members by `priority` (unique per group). **Enumeration** =
  union of visible members' versions. **Specific id+version download** = the
  **highest-priority** visible member that has it. Registration/search merge
  across visible members, dedup by id+version, highest-priority wins. No writes;
  no nested members (slice 1).

## 8. Configuration

TOML + env overrides (`FORGE_*`). Keys: `server.bind`,
`server.public_base_url`, `database.url`,
`s3.{endpoint,region,bucket,access_key,secret_key,force_path_style,multipart_threshold}`,
`auth.{anonymous_mode, anonymous_ip_allowlist, trusted_proxy_cidrs,
allow_password_basic, bootstrap_admin}`, `redis.url` (**optional**; absent ⇒
L1-only caching with short TTLs, still fully correct),
`cache.{l1_max_capacity, default_ttl}`, `outbox.{batch_size, grace_seconds,
poll_interval}`. Repositories, members, users, and tokens are managed via the
**admin REST API** (admin-only) in `server`, plus first-run bootstrap. Admin
**UI** is a later slice.

## 9. Testing strategy

### Unit tests
- Version normalization + `ToLowerInvariant` id rules.
- nuspec extraction + parsing from a `.nupkg` zip fixture (seekable).
- Group priority resolution (union enumeration; highest-priority download
  winner); rejection of nested-group config; tie determinism.
- Package-delay gating (inside vs. outside the window); delay-404 not negatively
  cached.
- CAS sha256/sha512 hashing, dedup, refcount transitions, pending→committed.
- Outbox: enqueue-on-refcount-zero in the same tx; worker idempotent delete;
  revival check (re-push before delete cancels the delete); `SKIP LOCKED`
  leasing; retry/backoff; orphan reconciler selection.
- `cache` crate: L1 hit/miss, factory coalescing, TTL expiry; with a mocked L2,
  L1→L2→factory order and invalidation-backplane drop of a stale L1 entry.
- Principal extraction: token, password-basic on/off, invalid-creds→401,
  anonymous modes; admin vs non-admin authz.
- IP allowlist matching incl. `loopback`/`private`/`local`, IPv6; XFF
  right-to-left stripping with trusted/untrusted peers; malformed XFF rejection.
- SSRF guard: scheme + private-range blocking, redirect re-validation.

### E2E tests (`tests/`, testcontainers: Postgres + versitygw, in-process server)
Mock upstream NuGet feed served in-process for proxy scenarios.
- Push to hosted → restore via flat container; nupkg bytes round-trip;
  registration + search responses; SHA512 `packageHash` matches.
- Unlist: hidden from search but still downloadable by exact version; relist.
- Proxy cache-on-demand (singleflight: concurrent first requests fetch once);
  package-delay hidden→visible; genuine upstream 404 negative cache.
- Group ordered resolution across two members with an overlapping version
  (highest priority wins); union enumeration.
- Anonymous modes `off`/`allowlist`/`all`; allowed vs denied IP; mixed-anon
  group exposes only anon members.
- CAS dedup: same package pushed to two repos ⇒ one blob, `ref_count == 2`;
  delete one ⇒ `ref_count == 1`, no S3 delete; delete the other ⇒ outbox worker
  removes the S3 object and `blob` row.
- Orphan reconciler reclaims a `pending` blob whose transaction never committed.
- Admin API requires admin; bootstrap admin works.
- SSRF: proxy `remote_url` to a private address is rejected by default.
- **Scale-out:** run two server instances against the same Postgres + versitygw
  (+ Redis); push on instance A is visible on instance B; concurrent proxy
  misses across both instances fetch upstream once (row `FOR UPDATE`); outbox is
  drained exactly once cluster-wide (`SKIP LOCKED`).
- **Redis L2 (optional, gated on a Redis container):** invalidation backplane
  drops a stale L1 entry on the other instance after a mutation.
- **Optional** `dotnet restore` / `dotnet nuget push` smoke test, gated on the
  dotnet SDK being present on the runner.

## 10. Performance notes

Stream everything; single hashing pass yields both sha256 (CAS key) and SHA512
(`packageHash`). Multipart S3 upload above threshold. Dedup avoids re-storing
identical blobs. Indexes on `(repository_id, name)` and `(repository_id, name,
version)`; `proxy_cached_version` unique key. Proxy metadata caching avoids
hammering upstreams; singleflight avoids thundering-herd fetches.

## 11. Open questions — resolved

1. **Product name** — `envisia-forge`.
2. **Group priority direction** — higher integer wins; unique priority per group.
3. **Package-delay clock** — proxy's first sighting (upstream-timestamp variant
   deferred as a config option).

## 12. Deferred scope — with plans

Each deferred item is its own future spec → plan → build cycle. Recommended
sequencing below.

### 12.1 Retention / cleanup + policy-driven blob GC  *(recommended next slice)*
- **What:** per-repository retention — "keep last N versions", "keep for X
  days", "keep N most-recently-downloaded", proxy "evict cached not pulled in X
  days". Parity survey vs. Nexus cleanup policies and Artifactory retention.
- **Plan:** `retention_policy jsonb` on `repository`; background tokio evaluator
  unlists/deletes components, decrementing `ref_count` and enqueuing
  `blob_outbox` deletes — i.e. it reuses the slice-1 outbox + reconciler (§4)
  rather than adding a parallel GC path. Add `last_downloaded_at` to
  `asset`/`component`. Tests: policy unit tests; e2e push >N versions → pruning +
  blob deletion via the outbox.

### 12.2 OIDC / Microsoft Entra authentication
- **What:** OIDC login (auth-code + PKCE), primarily Entra; map identities to
  `app_user` (auto-provision option); session cookies for the UI; users mint
  repository tokens (token endpoint already exists from slice 1).
- **Plan:** `oidc` config (issuer, client id/secret, redirect, scopes);
  `/auth/oidc/login` + `/callback`; `external_identity` table (subject→user).
  Tests: callback against a mock OIDC provider.

### 12.3 Credential-forwarding authentication backend  *("authenticate against the registry")*
- **What:** validate a login by forwarding username/password to a configured
  upstream (e.g. existing Nexus) via HTTP Basic — the
  `github.com/schmitch/verdaccio-nexus-auth-proxy` pattern. Distinct from a proxy
  repo's own upstream credentials (slice 1 has those). This is an
  **authentication provider** for end-user logins.
- **Plan:** pluggable auth-provider chain in `core` (local password + upstream-
  basic + later OIDC). Config: provider order, upstream URL, success criteria,
  auto-provision + validated-user caching. Tests: mock upstream 200/401.

### 12.4 Fine-grained RBAC / authorization (+ nested groups)
- **What:** roles, per-repository read/write/admin privileges, content
  selectors; nested group membership with cycle detection. Replaces slice 1's
  "any authenticated user can read/write" and the no-nesting limitation.
- **Plan:** `role`, `privilege`, `user_role`, `repository_privilege` tables;
  checks in the slice-1 authz seam; group cycle detection. Tests: principal ×
  repo × action matrix; nested-group resolution + cycle rejection.

### 12.5 Secret encryption at rest (double envelope encryption)
- **What:** proxy `upstream_password` and similar secrets are redacted from APIs
  in slice 1 but stored plaintext in Postgres; encrypt them at rest with
  **double envelope encryption** (preferred): a per-secret Data Encryption Key
  (DEK) wraps the plaintext; the DEK is itself wrapped by a Key Encryption Key
  (KEK); the KEK is wrapped by a root key held in a KMS/HSM (or, lower
  environments, a root key from env/file). Two wrapping layers ⇒ KEK rotation
  re-wraps only DEKs (cheap) and root-key rotation re-wraps only KEKs, without
  touching ciphertext.
- **Plan:** `encryption_key` table storing wrapped DEKs/KEKs + versions;
  transparent encrypt/decrypt in the data-access layer; AEAD (AES-GCM or
  XChaCha20-Poly1305) with per-secret nonces; migration to wrap existing
  plaintext; rotation jobs for each layer. Tests: round-trip, rotation at each
  layer, tamper detection.

### 12.6 Frontend (admin + browse UI)
- **What:** TanStack Start admin UI: manage repositories/members/users/tokens,
  browse/search packages, view download stats.
- **Constraint:** the browser calls the **Rust HTTP API directly** — TanStack
  Start serves UI/SSR only; **no Node→Rust API proxy**. The Rust server may also
  serve the built static assets for a single origin; otherwise CORS is
  configured on the Rust side.
- **Plan:** its own brainstorming pass for IA/screens; reuse + extend the slice-1
  admin REST API.

### 12.7 Additional formats (npm, Maven, Cargo, …)
- **What:** implement the `Format` seam for more ecosystems; npm modeled with
  reference to verdaccio.
- **Plan:** each format is a new `format-*` crate implementing `Format` +
  protocol `Router`; `core` orchestration and storage reused unchanged — the
  payoff of Approach A.

## 13. Scale-out posture & out-of-scope assumptions

**In scope (slice 1):** multiple stateless server instances against shared
Postgres + S3 (+ optional Redis). No in-memory-only authoritative state (§2.1):
caches are L1+optional-L2 over Postgres/S3; cross-instance coordination uses
row-level `SELECT … FOR UPDATE` and `SELECT … FOR UPDATE SKIP LOCKED` (no advisory locks); blob bookkeeping
uses the transactional outbox; sessions/ephemeral auth state (when later added)
go to Postgres/Redis. The scale-out e2e test (§9) exercises two instances. A
cold instance reconstructs all state from the shared stores.

**Out of scope (slice 1):**
- Managing the scale-out *infrastructure* itself: HA/replication of Postgres,
  S3, and Redis are operated externally (managed services / the deployment),
  not by forge. Forge assumes they are available and shared.
- Leader election / cross-node scheduling beyond Postgres-lock coordination.
- Mirroring/replication between independent forge clusters.
- No package signing/verification beyond what NuGet clients already do.

## Appendix A — concrete NuGet V3 JSON shapes

`{base}` = `server.public_base_url` + `/v3/{repo}`.

### Service index (`GET {base}/index.json`)
```json
{
  "version": "3.0.0",
  "resources": [
    { "@id": "{base}/query",                "@type": "SearchQueryService/3.5.0" },
    { "@id": "{base}/registration/",        "@type": "RegistrationsBaseUrl/3.6.0" },
    { "@id": "{base}/flat/",                "@type": "PackageBaseAddress/3.0.0" },
    { "@id": "{base}/package",              "@type": "PackagePublish/2.0.0" }
  ]
}
```
`PackagePublish` entry present **only** for hosted repos. `@type` aliases may be
duplicated (e.g. also advertise `SearchQueryService/3.0.0-rc`) for client
compatibility.

### Flat container versions (`GET {base}/flat/{lower_id}/index.json`)
```json
{ "versions": ["1.0.0", "1.1.0", "2.0.0-beta1"] }
```

### Registration index (`GET {base}/registration/{lower_id}/index.json`)
Inlined single page (slice 1 always inlines):
```json
{
  "count": 1,
  "items": [{
    "count": 2,
    "lower": "1.0.0",
    "upper": "2.0.0",
    "items": [{
      "catalogEntry": {
        "id": "Sample.Lib",
        "version": "1.0.0",
        "listed": true,
        "packageHash": "<base64 SHA512>",
        "packageHashAlgorithm": "SHA512",
        "packageContent": "{base}/flat/sample.lib/1.0.0/sample.lib.1.0.0.nupkg",
        "dependencyGroups": [{
          "targetFramework": "net8.0",
          "dependencies": [
            { "id": "Newtonsoft.Json", "range": "[13.0.1, )" }
          ]
        }]
      },
      "packageContent": "{base}/flat/sample.lib/1.0.0/sample.lib.1.0.0.nupkg"
    }]
  }]
}
```

### Search (`GET {base}/query?q=&skip=&take=&prerelease=&semVerLevel=2.0.0`)
```json
{
  "totalHits": 1,
  "data": [{
    "id": "Sample.Lib",
    "version": "2.0.0",
    "description": "...",
    "versions": [
      { "version": "1.0.0", "downloads": 0,
        "@id": "{base}/registration/sample.lib/1.0.0.json" },
      { "version": "2.0.0", "downloads": 0,
        "@id": "{base}/registration/sample.lib/2.0.0.json" }
    ]
  }]
}
```
