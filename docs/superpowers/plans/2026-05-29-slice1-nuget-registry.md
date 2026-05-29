# envisia-forge Slice 1 (NuGet registry) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every code task is TDD: write the failing test first, watch it fail, implement minimally, watch it pass, commit.

**Goal:** A horizontally-scalable Rust NuGet V3 registry supporting hosted, proxy (with package delay), and group repositories over content-addressable S3 storage with PostgreSQL metadata, coarse token/basic/anonymous auth, and unit + e2e tests.

**Architecture:** Cargo workspace with a format-agnostic `core` over a minimal `Format` seam (NuGet only); `storage` (CAS + transactional-outbox blob GC), `db` (sqlx + migrations), `cache` (moka L1 + optional Redis L2, HybridCache-style), `format-nuget` (protocol), `server` (axum + config + admin API + principal middleware). Stateless instances; no in-memory-only authoritative state.

**Tech Stack:** Rust 2024, tokio, axum 0.7+, sqlx (Postgres, compile-time-checked), aws-sdk-s3, reqwest, moka, redis (optional), argon2, sha2, zip, quick-xml, serde, testcontainers, versitygw (e2e).

**Source of truth:** [`docs/superpowers/specs/2026-05-29-envisia-forge-nuget-design.md`](../specs/2026-05-29-envisia-forge-nuget-design.md). Read it before starting. This plan implements that spec; section refs (§N) point into it.

**Cross-slice contracts (deferred plans depend on these — honor exactly):**
- `core::authz` exposes async `can_read(&Principal,&Repository)`, `can_write(...)`, `can_admin(...)` — the single extension point §12.4 will replace.
- `Principal::User` carries `user_id: i64` and `token_id: Option<i64>`.
- `core::delete_component` / asset-delete decrements `blob.ref_count` and enqueues `blob_outbox` in one DB transaction.
- `db` provides `claim_due_rows`/advisory-lock helpers using `FOR UPDATE SKIP LOCKED`.
- Version normalization + ordering are exposed through the `Format` trait (so `core` and §12.1 order versions without depending on `format-nuget`).
- `cache` exposes generic `get_or_try_insert_with(ns, key, ttl, factory)` and `invalidate(ns, key)`.
- `core::net::ssrf` guard is reusable (proxy uses it; §12.3 reuses it).
- The principal middleware resolves principals via an ordered list of `PrincipalSource`s so §12.2 can add a session-cookie source without refactor.

---

## File Structure

```
repo/
├─ Cargo.toml                         # [workspace] members = crates/*
├─ rust-toolchain.toml                # pin stable
├─ .env.example                       # FORGE_* sample
├─ docker-compose.yml                 # postgres + versitygw for local dev
├─ migrations/                        # sqlx SQL migrations (0001_init.sql, …)
├─ crates/
│  ├─ db/                  src/{lib,pool,model,ids,locks,repository_dao,component_dao,asset_dao,blob_dao,outbox_dao,proxy_dao,user_dao,token_dao}.rs
│  ├─ storage/             src/{lib,cas,s3,outbox_worker,reconciler,hash}.rs
│  ├─ cache/               src/{lib,l1,l2_redis,backplane}.rs
│  ├─ core/                src/{lib,domain,format,auth/{mod,principal,authz,token},net/ssrf,repo/{hosted,proxy,group},service}.rs
│  ├─ format-nuget/        src/{lib,version,nuspec,routes/{index,flat,registration,search,publish},model}.rs
│  ├─ server/              src/{main,config,state,middleware/principal,admin/{repositories,users,tokens,members},workers}.rs
│  └─ e2e/                 # a REAL workspace member (root tests/*.rs would be ignored by a virtual workspace)
│                          src/lib.rs (harness) + tests/{hosted,proxy,group,auth,cas,scaleout}.rs
└─ fixtures/               *.nupkg (built once, checked in)
```

---

## Phase 0 — Workspace, toolchain, dev infra

### Task 0.1: Workspace skeleton
**Files:** Create `Cargo.toml`, `rust-toolchain.toml`, `crates/*/Cargo.toml`, `crates/*/src/lib.rs` (empty `pub fn _stub(){}`), `.env.example`, `docker-compose.yml`.
- [ ] **Step 1:** Write workspace `Cargo.toml` with `[workspace] resolver="2" members=["crates/db","crates/storage","crates/cache","crates/core","crates/format-nuget","crates/server","crates/e2e"]` and a `[workspace.dependencies]` table pinning tokio, axum, sqlx, aws-sdk-s3, reqwest, moka, serde, anyhow/thiserror, tracing. `crates/e2e` is the integration-test package (its `tests/*.rs` run under `--features forge-e2e`).
- [ ] **Step 2:** `docker-compose.yml`: `postgres:17` (db `forge`, user/pw `forge`) and `versity/versitygw` serving a local dir on `:7070` (path-style S3, root creds). Document the exact `versitygw posix` command + env in a comment.
- [ ] **Step 3:** `cargo build` succeeds (empty crates).
- [ ] **Step 4:** Commit: `chore: workspace skeleton + dev compose`.

### Task 0.2: CI
**Files:** Create `.gitlab-ci.yml` (or `.github/workflows/ci.yml` — pick to match host once known; default GitHub Actions).
- [ ] **Step 1:** Jobs: `fmt` (`cargo fmt --check`), `clippy` (`-D warnings`), `test` (services: postgres + a versitygw container; `cargo test --workspace`). Gate e2e behind a `forge-e2e` feature so unit tests run without containers.
- [ ] **Step 2:** Commit.

---

## Phase 1 — `db` crate: schema + data access

### Task 1.1: Migration `0001_init.sql`
**Files:** Create `migrations/0001_init.sql`; `crates/db/src/{lib,pool}.rs`.
- [ ] **Step 1 (test first):** `crates/db/tests/migrations.rs` — spin a Postgres testcontainer, run `sqlx::migrate!()`, assert all expected tables exist (`information_schema.tables`). Expected: FAIL (no migration).
- [ ] **Step 2:** Write `0001_init.sql` creating every table from spec §3 exactly:
  `repository`(+proxy columns `remote_url`,`package_delay_seconds`,`upstream_username`,`upstream_password`,`metadata_ttl_seconds`,`not_found_ttl_seconds`,`allow_redeploy`),
  `group_member`(unique `(group_id,priority)`, PK `(group_id,member_id)`, CHECK member≠group),
  `component`(unique `(repository_id,name,version)`, index `(repository_id,name)`),
  `asset`(`sha512_base64`),
  `blob`(`state` CHECK in `('pending','committed')`, `ref_count`),
  `blob_outbox`(`op`,`sha256`,`s3_key`,`available_at`,`attempts`,`locked_until`,`processed_at`),
  `proxy_cached_version`(unique `(repository_id,name,version)`),
  `proxy_upstream_index`(PK `repository_id`),
  `app_user`(unique `username`,`is_admin`),
  `token`(unique `token_hash`,`expires_at`,`revoked_at`).
  Add `CHECK (kind in ('hosted','proxy','group'))`, `format='nuget'` default, and FK constraints.
- [ ] **Step 3:** `crates/db/src/pool.rs`: `pub async fn connect(url)->PgPool` + `pub async fn migrate(pool)`.
- [ ] **Step 4:** Run test → PASS. Commit: `feat(db): initial schema`.

### Task 1.2: Typed model + DAOs
**Files:** `crates/db/src/{model,ids,locks,*_dao}.rs`.
- [ ] **Step 1:** `model.rs`: `#[derive(sqlx::FromRow)]` structs for each table; enums `RepoKind`, `BlobState` (`#[sqlx(type_name=...)]` or text). `ids.rs`: newtype `RepositoryId(i64)` etc.
- [ ] **Step 2 (test):** `repository_dao` round-trip test (insert hosted repo, fetch by name) on a testcontainer. FAIL → implement `insert_repository`, `find_repository_by_name`, `list_repositories`, `group_members(group_id)->Vec<(Repository,priority)>` **`ORDER BY priority DESC`** (highest priority first = wins ties, per spec §7); test asserts ordering direction. PASS.
- [ ] **Step 3 (test):** `blob_dao`: `upsert_pending(sha256,size,s3_key)->bool(inserted)` via `INSERT … ON CONFLICT (sha256) DO NOTHING RETURNING`; `commit_and_incref(tx, sha256)`; `decref_and_maybe_enqueue_delete(tx, sha256, grace)` returns whether it hit zero. Test refcount transitions + that decref-to-zero inserts a `blob_outbox` row in the SAME tx. PASS.
- [ ] **Step 4 (test):** `outbox_dao::claim_due(tx, batch, now)` using `SELECT … WHERE processed_at IS NULL AND available_at<=now AND (locked_until IS NULL OR locked_until<now) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT n` + lease update. Test two concurrent claimers get disjoint rows. PASS.
- [ ] **Step 5:** `locks.rs`: `pub async fn with_advisory_lock<T>(pool, key:i64, f)` using `pg_advisory_xact_lock`. Test mutual exclusion. PASS.
- [ ] **Step 6:** DAOs for `component`,`asset`,`proxy_cached_version`,`proxy_upstream_index`,`app_user`,`token`. Each: a focused round-trip test. Commit per DAO.

---

## Phase 2 — `storage` crate: CAS + outbox worker

### Task 2.1: Hashing writer
**Files:** `crates/storage/src/hash.rs`.
- [ ] **Step 1 (test):** feed known bytes through `HashingWriter` (wraps an `AsyncWrite`), assert sha256 hex and sha512 base64 match precomputed vectors. FAIL.
- [ ] **Step 2:** Implement `HashingWriter` updating both `Sha256` and `Sha512` as bytes stream to a `tokio::fs::File` temp; `finalize()->(sha256_hex, sha512_b64, size)`. PASS. Commit.

### Task 2.2: S3 client wrapper
**Files:** `crates/storage/src/s3.rs`.
- [ ] **Step 1 (test, `forge-e2e`):** against versitygw container, `put_if_absent(key,path)` then `head(key)` true; `get(key)->ByteStream`; `delete(key)` idempotent (delete twice ok). FAIL.
- [ ] **Step 2:** Implement with aws-sdk-s3 (path-style, configurable endpoint); multipart above `multipart_threshold`. Blob key = `blobs/sha256/{aa}/{bb}/{hash}`. PASS. Commit.

### Task 2.3: CAS store (write path §4)
**Files:** `crates/storage/src/cas.rs`.
- [ ] **Step 1 (test, e2e):** `store(reader)`: writes temp+hash → `blob upsert_pending` → `head`; if absent `put` → returns `StoredBlob{sha256,sha512_b64,size,temp_path}`. Calling `store` twice with identical bytes results in ONE S3 object and the second is a dedup hit (no second PUT — assert via a counting fake or head-before/after). FAIL.
- [ ] **Step 2:** Implement. Note: `store` does NOT incref or insert asset — the caller (`core`) does `commit_and_incref` + asset insert in its own tx, then drops the temp file (handed to `Format::parse_upload` first). PASS. Commit.

### Task 2.4: Outbox worker + reconciler
**Files:** `crates/storage/src/{outbox_worker,reconciler}.rs`.
- [ ] **Step 1 (test, e2e):** enqueue a `delete_object` (via `decref` to zero), run one worker tick → S3 object gone, `blob` row gone, outbox `processed_at` set. Add a second test: if a concurrent re-push revived `ref_count>0` before the tick, the worker drops the outbox row WITHOUT deleting S3. FAIL.
- [ ] **Step 2:** Implement `run_once(pool,s3,batch)`: `claim_due` → for each, re-check `ref_count==0` (else mark processed, skip delete) → `s3.delete` (idempotent) → delete `blob` row → mark processed; on error bump `attempts`, set `available_at=now+backoff(attempts)`. PASS.
- [ ] **Step 3 (test, e2e):** reconciler deletes a `pending` blob older than grace whose tx never committed. Implement `reconcile_orphans(pool,s3,grace)`. PASS. Commit.

---

## Phase 3 — `cache` crate (HybridCache analogue §2.1)

### Task 3.1: L1 + factory coalescing
**Files:** `crates/cache/src/{lib,l1}.rs`.
- [ ] **Step 1 (test):** `Cache::get_or_try_insert_with(ns,key,ttl,factory)` — factory runs once for concurrent callers (count invocations under `tokio::join!` of 50 calls == 1); TTL expiry triggers a re-run. FAIL.
- [ ] **Step 2:** Implement over `moka::future::Cache` keyed by `(ns,key)` with per-entry TTL; coalescing via `try_get_with`. `invalidate(ns,key)` + `invalidate_ns(ns)`. PASS. Commit.

### Task 3.2: Optional Redis L2 + backplane
**Files:** `crates/cache/src/{l2_redis,backplane}.rs`.
- [ ] **Step 1 (test, gated on a Redis container):** with L2 enabled, miss → factory → both layers populated; second process (new `Cache` sharing Redis) gets L2 hit without factory; `invalidate` publishes on the backplane and the other instance drops its L1 entry. FAIL.
- [ ] **Step 2:** Implement: lookup L1→L2→factory, write-through to L2 (serde JSON), pub/sub channel `forge:cache:invalidate` carrying `(ns,key)`. When `redis.url` absent, L2 is a no-op and TTLs bound staleness. PASS. Commit.

---

## Phase 4 — `core`: domain, Format seam, auth/authz, SSRF

### Task 4.1: Domain types + Format trait
**Files:** `crates/core/src/{domain,format}.rs`.
- [ ] **Step 1:** `domain.rs`: re-export db models as domain or thin wrappers; `ParsedUpload{ id, original_id, version, version_original, deps: Vec<DepGroup>, listed }`. `format.rs`: the `Format` trait:
```rust
// Object-safe: stored as Arc<dyn Format> in AppState, so NO generic methods.
pub trait ReadSeek: std::io::Read + std::io::Seek {}
impl<T: std::io::Read + std::io::Seek> ReadSeek for T {}

pub struct ParsedUpload { /* …; carries `nuspec_bytes: Vec<u8>` so the derived
    .nuspec asset can be stored without re-reading the zip */ }

pub trait Format: Send + Sync {
    fn id(&self) -> &'static str;
    fn parse_upload(&self, file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError>;
    fn normalize_version(&self, raw: &str) -> Result<String, FormatError>;
    fn compare_versions(&self, a: &str, b: &str) -> std::cmp::Ordering; // SemVer2 ordering
    fn lower_id(&self, id: &str) -> String;
}
```
- [ ] **Step 2:** Trait compiles with a `#[cfg(test)]` dummy impl. Commit.

### Task 4.2: Principal + sources
**Files:** `crates/core/src/auth/{mod,principal,token}.rs`.
- [ ] **Step 1 (test):** `Principal` enum: `Anonymous{ip:IpAddr}`, `User{user_id:i64, token_id:Option<i64>, is_admin:bool}`, `Unauthenticated`. Token verify: `verify_token(pool,secret)->Option<TokenPrincipal>` hashing sha256, constant-time compare, rejecting expired/revoked, updating `last_used_at` best-effort. FAIL → implement. PASS.
- [ ] **Step 2:** `PrincipalSource` trait (`async fn resolve(&self, req_parts, peer_ip)->Option<Principal>`) with `TokenHeaderSource` (`X-NuGet-ApiKey`) and `BasicAuthSource` (token-then-optional-password). Ordered resolution + "auth header present but invalid ⇒ Err(Unauthorized)" (NEVER downgrade to anonymous). Test the downgrade-prevention explicitly. PASS. Commit.

### Task 4.3: Anonymous IP allowlist + XFF
**Files:** `crates/core/src/auth/principal.rs` (extend) — `client_ip.rs`.
- [ ] **Step 1 (test):** `resolve_client_ip(peer, xff, trusted_cidrs)`: untrusted peer ⇒ peer; trusted peer ⇒ right-to-left first untrusted hop; malformed XFF ⇒ peer (treat untrusted). `AnonAllowlist` parsing of `loopback`/`private`/`local` + explicit CIDRs; `contains(ip)`. Cover IPv6. FAIL → implement. PASS. Commit.

### Task 4.4: authz seam
**Files:** `crates/core/src/auth/authz.rs`.
- [ ] **Step 1 (test):** `can_read(p,repo)` = `User` OR (`Anonymous` AND `repo.anonymous_read`); `can_write`/`can_admin` require `User`(/admin). Async signatures (future-proof for §12.4). Table-driven test of the full matrix. FAIL → implement. PASS. Commit.

### Task 4.5: SSRF guard
**Files:** `crates/core/src/net/ssrf.rs`.
- [ ] **Step 1 (test):** `validate_url(url, allow_private)` rejects non-http(s), and (unless `allow_private`) URLs resolving to loopback/link-local/private; `guarded_client()` builds a reqwest client with a redirect policy re-validating each hop. Use a resolver injection so tests don't hit DNS. FAIL → implement. PASS. Commit.

---

## Phase 5 — `format-nuget`: version + nuspec parsing

### Task 5.1: Version normalization + ordering
**Files:** `crates/format-nuget/src/version.rs`.
- [ ] **Step 1 (test):** `normalize("1.0")=="1.0.0"`, `"1.02.3"=="1.2.3"`, strips build metadata (`"1.0.0+abc"=="1.0.0"`), preserves prerelease lowercased (`"1.0.0-Beta"=="1.0.0-beta"`), 4-part `"1.0.0.0"=="1.0.0"` when revision 0 (per NuGet rules). `compare` orders prerelease < release, numeric-vs-alpha identifiers per SemVer2. Cover the documented NuGet normalization cases. FAIL.
- [ ] **Step 2:** Implement parser + comparator. PASS. Commit.

### Task 5.2: nuspec + nupkg parsing
**Files:** `crates/format-nuget/src/{nuspec,lib}.rs`.
- [ ] **Step 1:** Build a tiny real `.nupkg` fixture (script under `fixtures/` using `zip`), checked in. `crates/format-nuget/tests/parse.rs`: open fixture as `File`, `NugetFormat::parse_upload` returns expected id/version/deps/listed. FAIL.
- [ ] **Step 2:** Implement: `zip::ZipArchive` over the seekable file → find `*.nuspec` → `quick-xml` parse `id`,`version`,`dependencies/group` → `ParsedUpload`. Implement `Format for NugetFormat` (delegating version fns to Task 5.1, `lower_id` = `to_lowercase` invariant-ish). PASS. Commit.

---

## Phase 6 — Hosted read protocol

### Task 6.1: core service ops (hosted reads)
**Files:** `crates/core/src/{service,repo/hosted}.rs`.
- [ ] **Step 1 (test, e2e):** seed a component+asset+blob; `list_versions(repo,id)` returns normalized versions incl. unlisted; `resolve_nupkg(repo,id,ver)->Option<(blob_s3_key,size)>`; `registration(repo,id)` returns a structure with deps + `packageHash` + `listed`; `search(repo,q,skip,take,prerelease)`. FAIL → implement against DAOs. PASS. Commit.

### Task 6.2: NuGet route handlers + service index
**Files:** `crates/format-nuget/src/routes/{index,flat,registration,search}.rs`.
- [ ] **Step 1 (test):** axum handler tests (in-process, mocked core via a trait) asserting JSON matches Appendix A shapes; service index emits absolute `@id`s from `public_base_url`; `PackagePublish` present only for hosted; `GET`+`HEAD` both work; flat-container 404 on unknown id; `.nupkg` streams bytes with correct content-type; lowercasing enforced. FAIL.
- [ ] **Step 2:** Implement handlers calling core ops; build the `Router` factory `nuget_router(kind)`. PASS. Commit.

---

## Phase 7 — Hosted publish

### Task 7.1: push / delete / relist
**Files:** `crates/core/src/repo/hosted.rs` (extend); `crates/format-nuget/src/routes/publish.rs`.
- [ ] **Step 1 (test, e2e):** `PUT /v3/{repo}/package` multipart with the fixture → 201; duplicate → 409 (unless `allow_redeploy`); `allow_redeploy` swaps asset, old blob ref decremented, new incremented (one tx). `DELETE …/{id}/{version}` → `listed=false` but still downloadable by exact version + still in flat index; `POST` relist → listed. Push requires `User` (anonymous/invalid → 401). FAIL.
- [ ] **Step 2:** Implement: stream multipart first part through `cas::store` → `parse_upload` from temp file → validate id/version → in one tx `commit_and_incref` + insert `component`+`asset` (+ derived nuspec asset) → invalidate cache ns for `(repo,id)`. Redeploy path per §6. PASS. Commit.

---

## Phase 8 — Proxy behavior

### Task 8.1: upstream index resolution
**Files:** `crates/core/src/repo/proxy.rs`.
- [ ] **Step 1 (test, e2e w/ in-process mock upstream):** first call fetches `remote_url` service index (SSRF-guarded), resolves `PackageBaseAddress`/`Registration`/search `@id`s, persists `proxy_upstream_index`, caches via `cache`; second call within TTL does not re-fetch (assert mock hit count). FAIL → implement. PASS. Commit.

### Task 8.2: read-through cache + singleflight + delay
**Files:** `crates/core/src/repo/proxy.rs` (extend).
- [ ] **Step 1 (test, e2e):** version discovery upserts `proxy_cached_version{first_seen_at=now}` WITHOUT serving; with `package_delay_seconds>0`, the version is absent from `list_versions`/registration/search and direct download 404s until the clock passes; after, it serves. Delay-404 is NOT written to negative cache (a later in-window request still re-checks). Genuine upstream 404 sets `not_found`+`not_found_at` honoring `not_found_ttl_seconds`. FAIL.
- [ ] **Step 2 (test, e2e):** two concurrent first-time downloads of the same version trigger ONE upstream fetch (advisory lock on `(repo,name,version)`); both get bytes; `downloaded=true`; blob stored once. FAIL.
- [ ] **Step 3:** Implement the state machine + singleflight + delay gating + offline mode. PASS. Commit.

---

## Phase 9 — Group resolution (identity-aware)

### Task 9.1: ordered, principal-filtered resolution
**Files:** `crates/core/src/repo/group.rs`.
- [ ] **Step 1 (test, e2e):** members ordered by `priority` (unique). For principal `P`, visible = members passing `can_read(P,member)`. `list_versions` = union across visible members; `resolve_nupkg(id,ver)` = highest-priority visible member that has it. Mixed-anon group: anonymous principal sees only `anonymous_read` members; authenticated sees all. Nested-group member rejected at config time (covered in admin API test). FAIL.
- [ ] **Step 2:** Implement; registration/search merge across visible members deduped by id+version with highest-priority winning. PASS. Commit.

---

## Phase 10 — `server`: config, state, middleware, admin API, workers

### Task 10.1: config + state
**Files:** `crates/server/src/{config,state,main}.rs`.
- [ ] **Step 1 (test):** load TOML + `FORGE_*` env overrides into `Config` (all keys from §8 incl. `anonymous_mode`, allowlist, `trusted_proxy_cidrs`, `allow_password_basic`, `redis.url` optional, `outbox.*`, `cache.*`, `bootstrap_admin`). Missing required → clear error. FAIL → implement (figment or serde+envy). PASS. Commit.
- [ ] **Step 2:** `AppState` holds pool, S3, cache, `Arc<dyn Format>` registry, config. `main.rs` wires it, runs migrations, creates the bootstrap admin if absent (log warning), starts axum + background workers.

### Task 10.2: principal middleware
**Files:** `crates/server/src/middleware/principal.rs`.
- [ ] **Step 1 (test):** middleware runs ordered `PrincipalSource`s, resolves client IP, attaches `Principal` extension; invalid creds → 401; no creds + `anonymous_mode` → Anonymous/Unauthenticated accordingly. FAIL → implement. PASS. Commit.

### Task 10.3: repo dispatch + mount
**Files:** `crates/server/src/state.rs` (extend), route mounting.
- [ ] **Step 1 (test, e2e):** `/v3/{repo}/...` looks up the repo, branches on `kind` to hosted/proxy/group ops, enforces `can_read`/`can_write` before handling. Unknown repo → 404; read denied → 401/403. FAIL → implement. PASS. Commit.

### Task 10.4: admin REST API (admin-only)
**Files:** `crates/server/src/admin/{repositories,users,tokens,members}.rs`.
- [ ] **Step 1 (test, e2e):** CRUD for repositories (incl. proxy fields; `upstream_password` write-only, REDACTED in all responses; SSRF-validate `remote_url` on create), users (argon2 hash), tokens (returns plaintext once; stores hash), group members (reject nested group + duplicate priority). All endpoints require `is_admin`; non-admin → 403. FAIL → implement. PASS. Commit.

### Task 10.5: background workers
**Files:** `crates/server/src/workers.rs`.
- [ ] **Step 1:** Spawn outbox worker, orphan reconciler, proxy metadata refresh on intervals; each guarded so multi-instance is safe (SKIP LOCKED / advisory locks). Test (e2e) that with two `AppState`s sharing a DB the outbox is drained exactly once. Commit.

---

## Phase 11 — E2E suite (testcontainers: Postgres + versitygw [+ Redis])

### Task 11.1: harness
**Files:** `tests/harness/mod.rs`.
- [ ] **Step 1:** `start_stack()` boots Postgres + versitygw containers, runs migrations, builds an `AppState`, serves the axum app on an ephemeral port, returns a `TestServer{base_url, pool, admin_token}` + a builder for a second instance sharing the same DB/S3. Helper to mount an in-process mock upstream NuGet feed. Commit.

### Task 11.2: scenario tests
**Files:** `tests/{hosted,proxy,group,auth,cas,scaleout}.rs`.
- [ ] Implement each spec §9 e2e scenario as a test (one per bullet): hosted push→restore + registration/search + SHA512 match; unlist/relist; proxy cache-on-demand + singleflight + delay + genuine-404 negcache; group ordered resolution + union + mixed-anon filtering; anonymous modes off/allowlist/all + denied IP; CAS dedup ref_count 2→1→0 with outbox S3 delete; orphan reconciler; admin gating + bootstrap; SSRF rejection; scale-out (two instances: push on A visible on B, single upstream fetch, outbox drained once); optional Redis-L2 invalidation; optional `dotnet` smoke test gated on SDK presence.
- [ ] Commit per file. Final: `cargo test --workspace --features forge-e2e` green.

---

## Self-Review (completed against spec)

- **Spec coverage:** every §3 table → Task 1.1; CAS/outbox §4 → Phase 2; cache/scale-out §2.1 → Phase 3 + 10.5 + 11.2 scaleout; auth §5 → Phase 4 + 10.2/10.4; protocol §6 + Appendix A → Phase 6/7; behaviors §7 → Phase 7/8/9; config §8 → 10.1; tests §9 → Phase 11. No section left without a task.
- **Cross-slice contracts:** the async `authz` seam (4.4), `Principal` carrying `user_id`+`token_id` (4.2), one-tx decref+outbox (1.1/2.4/7.1), `db` SKIP-LOCKED helper (1.2), version ordering via `Format` (4.1/5.1), generic `cache` API (3.1), reusable SSRF guard (4.5), pluggable `PrincipalSource` (4.2/10.2) — all present, matching the deferred plans' stated assumptions.
- **Type consistency:** `Format` method names, `Principal` variants, DAO names referenced in later phases match their defining tasks.

---

## Addendum — hardening from plan review (codex)

These amend the tasks named; executors MUST apply them.

- **A1 (Task 0.2 / Phase 1) — sqlx offline.** sqlx compile-time checks need data at build. Commit a `.sqlx/` dir (`cargo sqlx prepare`) and set `SQLX_OFFLINE=true` for normal builds; CI provisions a Postgres, sets `DATABASE_URL`, runs migrations, and `cargo sqlx prepare --check` to catch drift. Add a `just prepare` / `make prepare` shortcut.
- **A2 (Task 5.2) — zip-bomb defenses.** Cap entries, per-entry uncompressed size, total uncompressed size, and compression ratio; reject encrypted/unsupported entries; only the `*.nuspec` is read (bounded). Test with an oversized/explosive fixture → rejected.
- **A3 (Task 5.2) — nuspec namespaces.** `.nuspec` uses versioned `xmlns`; parse **namespace-insensitively** (match local names), read `dependencies/group@targetFramework` and `dependency@id/@version`. Add fixtures with two different nuspec schema namespaces.
- **A4 (Task 5.2 / 6.1 / 6.2) — nuspec bytes.** `ParsedUpload.nuspec_bytes` is stored as a derived asset on push (own blob, dedup applies); the `.nuspec` route serves it (or extracts on demand if absent). Add a route test for `.nuspec`.
- **A5 (Task 2.3 / 7.1) — upload streaming + limits.** CAS `store` accepts an `impl Stream<Item=Result<Bytes>>` (axum `Multipart` field → stream) writing to the temp file; enforce `max_upload_bytes` (413 on exceed); temp files are removed on every path (RAII guard). Test the size limit and temp cleanup on error.
- **A6 (Task 4.2 / 10.4) — argon2id.** Use `argon2` PHC strings (`PasswordHash`), verify with constant-time `verify_password`; run hashing/verify in `tokio::task::spawn_blocking`. Config-gated test (`allow_password_basic`).
- **A7 (Task 2.4) — outbox tx boundaries.** Never hold a DB transaction across an S3 network call. Lease rows (one short tx, commit), perform the idempotent S3 delete, then finalize each row in its own short tx (re-check `ref_count==0`, delete blob row, set `processed_at`). On failure, bump `attempts`/`available_at`.
- **A8 (Task 8.2) — proxy lock = row lock, not text key.** Before fetch/delay decisions, `INSERT … ON CONFLICT (repository_id,name,version) DO NOTHING` then `SELECT … FOR UPDATE` the `proxy_cached_version` row as the singleflight lock (deterministic, no hash-collision risk). Direct-download-before-discovery therefore always has a row to lock.
- **A9 (Task 4.5 / 8.1) — SSRF DNS TOCTOU.** Resolve once with a guarded resolver, validate the resolved IPs, and connect to those exact IPs (custom `reqwest` resolver / `resolve()` override), re-validating on every redirect hop — so a re-resolve can't swap in a private IP after the check.
- **A10 (Task 1.1 / 8.1 / 10.4) — `allow_private_upstream`.** Add a per-proxy `allow_private_upstream bool default false` column; thread it through admin create/update, config, and the SSRF call; default-deny test + allow test.
- **A11 (Task 6.1 / 8.1) — cross-instance singleflight for expensive cache factories.** Registration/search rebuilds and proxy upstream-index refresh wrap their cache factory in a Postgres advisory lock so only one instance in the cluster recomputes; others wait and read the populated cache. Test with two instances.
- **A12 (NEW Task 7.2 + 10.4) — `core::delete_component` + hard delete.** Add `core::delete_component(repo,id,ver, hard: bool)`: unlist (soft) or hard-delete (remove component+assets, decref blobs + enqueue outbox in one tx). Expose hard delete via the admin API (`DELETE /admin/repositories/{repo}/packages/{id}/{ver}`), admin-only. This is what the CAS refcount 2→1→0 e2e (Task 11.2) drives. TDD + e2e.
- **A13 (Task 2.2 / 11.1) — versitygw setup.** Harness creates the bucket on startup; configure aws-sdk-s3 for path-style and disable default request checksums that versitygw may reject (`request_checksum_calculation = WhenRequired`); a smoke test puts/gets/deletes against versitygw.
- **A14 (Task 6.2) — search params.** Test `semVerLevel` (2.0.0 includes SemVer2 prerelease), `prerelease` default false, `skip`/`take` bounds + clamping, and `totalHits` accuracy.

## Execution note

Build phases in order (each depends on the prior crate). Within a phase, tasks are independently committable. Recommended: subagent-driven-development, one subagent per task, review between tasks; run `cargo clippy -D warnings` + `cargo fmt --check` before each commit. Apply the Addendum items as you reach the tasks they reference.
