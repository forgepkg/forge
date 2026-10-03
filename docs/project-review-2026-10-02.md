# Envisia Forge production-readiness review

**Review date:** 2026-10-02
**Reviewed revision:** `69436de` (`main`, the merge of PR #8, "0.1.0 readiness")
**Question:** is the 0.1.0 release ready for production?

## Verdict

**Not yet.** The architecture is solid and the previous review's blockers are
fixed. CI is green and 778 of 779 tests pass locally, including the
container-backed end-to-end suite. This pass still found four defects that
should block a production release:

1. **Data loss**: two concurrent admin hard-deletes of the same version can
   delete an S3 object that another repository still serves. Reproduced
   against the real schema.
2. **Supply-chain bypass**: the dependency-confusion guard (`prefer_hosted`)
   can serve an attacker's public package in place of an internal one.
3. **Unauthenticated memory exhaustion** through the login lockout map.
4. **Every unscoped API token of an admin is a full admin credential.** That
   includes the CI push token the README tells you to store in `NuGet.config`.

Each blocker has a small, local fix. Fix them, plus the **High** items, and
0.1.0 is a reasonable first production release for a single team behind a
reverse proxy. The Medium and Low items can follow in 0.1.x.

`v0.1.0` has not been tagged yet, so the release workflow (signing, SBOM,
provenance) has never actually run.

## Remediation status (2026-10-02)

Every finding below has been fixed on this branch with a regression test,
except where the table says otherwise. An independent review of the fixes
then found 15 follow-up issues (one regression in the new ZIP pre-check, the
rest low or medium); all of them are fixed as well. Operator-visible changes
and upgrade notes are in the [0.1.0 changelog](../CHANGELOG.md#010).

| Finding | Status | Commits |
|---|---|---|
| B1 hard-delete double decrement | Fixed; reproduced first, deterministic race tests; migration 0017 adds `CHECK (ref_count >= 0)` and repairs pre-existing drift; GC never deletes a blob an asset names | `e5dc1c9` `567d7d7` `076d896` `79b9ef8` `4d53dec` |
| B2 `prefer_hosted` guard bypass | Fixed: ownership decided over every hosted leaf, caller-independent; e2e for anonymous and selector-scoped callers | `d10576f` |
| B3 login-lockout memory exhaustion | Fixed: 256-byte username cap, fixed-size keys, swept entries | `ef1c95d` |
| B4 admin tokens as admin credentials | Fixed: admin only with an explicit `admin` token scope | `6aec710` |
| H1 DB connection held across credential forwards | Fixed: lease-based singleflight, per-realm concurrency bound, realm timeouts applied | `52188da` |
| H2 hosted-scope retention on proxies | Fixed: rejected at validation and in the worker; proxy self-heals a missing local copy | `70dd66d` `1b6ef2b` |
| H3 proxy not-found marker | Fixed: TTL-bound, cleared by listings, unconfirmed rows never listed and pruned | `1b6ef2b` `b275e04` |
| H4 SPA 401 loop | Fixed | `431cc1a` |
| M1 selector PATCH | Fixed | `b2dda5b` |
| M2 upstream credentials after `remote_url` change | Fixed (server and UI) | `b2dda5b` `e31f2de` |
| M3 credential forwarding follows redirects | Fixed | `52188da` |
| M4 argon2 cost and concurrency | Fixed; timing of unknown vs. federated names equalized | `ef1c95d` `dbcfa31` |
| M5 federated users cannot be cut off | Fixed: `PATCH /admin/users/{id}` deactivation | `f4adc41` |
| M6 `keep_last_n` semantics | Fixed | `e0a09c3` |
| M7 proxy eviction resets `first_seen_at` | Fixed | `72b5701` |
| M8 group search amplification | Fixed | `383fcfc` `d10576f` |
| M9 ZIP limits on every entry | Fixed; pre-check vets only the EOCD the reader uses | `f33977f` `7ddd59f` |
| M10 upstream `.nuspec` passthrough | Fixed: identity check, metadata-address refusal | `c7449e6` `1b6ef2b` |
| M11 proxy registration metadata | Fixed | `1b6ef2b` |
| M12 `X-Forwarded-For` lines, mapped IPv6 | Fixed; mapped CIDR entries canonicalized | `ef1c95d` `8b05bd5` |
| M13 key-rotation races | Fixed; lock guard owns the connection before locking | `24d09c6` `cebb9de` |
| M14 plaintext left after enabling encryption | Fixed; ciphertext verified before a plaintext copy is dropped | `24d09c6` `bca4045` |
| M15 bootstrap password removal breaks the image | Fixed: env-only bootstrap | `a9ec8f4` |
| M16 release-pipeline trust | Fixed: sign by digest, exact identity, SHA-pinned actions, digest-pinned bases | `f332b1d` |
| M17 admin deep links | Fixed: UI under `/manage/*`, legacy redirect | `45ead2b` `91c6a7a` |
| M18 repository names | Fixed (server and UI) | `b2dda5b` `e31f2de` |
| M19 GC indexes, outbox pruning | Fixed | `567d7d7` |
| M20 legacy RBAC switches | Fixed for switches made from now on; earlier ones are an upgrade note | `b2dda5b` |
| L1 cache first subscription | Fixed | `db7dbac` |
| L2 multipart abort | Fixed | `8559741` |
| L3 repository-delete gap | Fixed | `e5dc1c9` |
| L4 publish vs. GC finalize | Fixed | `567d7d7` |
| L5 backup wording | Fixed | `189f730` |
| L6 token scope, nesting depth, signed-in reads | Fixed; signed-in public reach only under `anonymous_mode = "all"` | `6aec710` `b2dda5b` `fdeef48` |
| L7 auth edge cases | Fixed (bootstrap marker, trailing-slash issuers, concurrent first OIDC logins, Host check) | `e113bfd` `4034f5b` `ef1c95d` `3ee50d6` |
| L8 parsing edge cases | Fixed: ids lowered like .NET, ZIP directory pre-check, 1 MiB nuspec cap | `f33977f` `7c17f1c` `26e1398` |
| L9 image and config | Fixed (numeric UID, secret env handling, exact `FORGE_CONFIG`, Basic default) | `a9ec8f4` `f332b1d` `6d960d0` |
| L10 retention panic | Fixed | `70dd66d` |
| L11 SPA polish | Fixed (`Retry-After` added server-side) | `45ead2b` `431cc1a` `6fd8204` |
| L12 dependencies | Fixed: advisories removed, `cargo audit` and `pnpm audit --prod` in CI, Dependabot. **Not done:** container image OS scan (see the changelog) | `f332b1d` `9b5b6c3` |
| L13 docs drift | Fixed | `189f730` |

Additional defects found while fixing: unlist rules re-touched unlisted
versions (`61c0bfc`); NuGet `DELETE` and redeploy race losers returned 500
(`076d896`, `1828dc0`); lock-order deadlocks between deleters (`4d53dec`).

The product gaps listed above (RBAC, retention and user-lifecycle consoles,
anonymous web browse) are unchanged and recorded as known limitations.

### Verification of the fixes

All checks were run on the final tree with a fresh, private build directory.

| Check | Result |
|---|---|
| `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --all-features --locked -D warnings` (offline) | Passed |
| `cargo test --workspace --features forge-e2e --locked` (Docker, Postgres 17, versitygw, Redis) | **948 passed, 0 failed** (75 test binaries; 778 before the fixes). The .NET smoke test skipped itself (no SDK here); CI's e2e job installs one |
| `cargo sqlx prepare --check` against a database migrated 0001–0020 | Passed |
| Web: `tsc`, e2e `tsc`, Vitest, `vite build` | Passed: 15 files and 110 tests |
| `cargo audit`, `pnpm audit --prod` | No vulnerabilities (`rsa`, used only by the e2e mock issuer, is ignored with a rationale) |
| Fail-without-fix checks | The new tests for B1, the drift guard and the redeploy race were run against the old code and failed there |
| Not run here | Playwright browser specs (the preinstalled Chromium is older than Playwright 1.63 needs; the `web-e2e` CI job on `main` runs them) and the image build (the `docker` CI job builds it) |

## Verification performed

| Check | Result |
|---|---|
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features --locked -D warnings` | Passed |
| `cargo test --workspace --features forge-e2e --locked` (Docker, Postgres 17, versitygw, Redis) | 778 passed, 1 failed (`forge-cache` `l2_sharing_and_backplane_invalidation`: fails under full-suite load, passes 5/5 alone; root cause in Low L1) |
| Web: `tsc`, Vitest, `vite build` | Passed: 13 files and 76 tests; no source maps shipped |
| `pnpm audit --prod` | No known vulnerabilities |
| `cargo audit` | 5 advisories; see L12. None is a practical exposure today, but nothing in CI would catch a real one. |
| GitHub Actions on `main` | Green (run 62) |
| Migrations 0001–0016 on a clean Postgres 17 | Apply cleanly |
| B1 reproduction (two psql sessions running the exact `hard_delete` statement sequence) | Reproduced; the fix (`FOR UPDATE`) verified |
| H4 reproduction (the SPA's auth flow against the installed `@tanstack/query-core`) | 94 `/admin/me` calls in 500 ms after a session expires |

Every other finding was traced end to end in the code. Some are marked
"likely": those depend on deployment configuration or client behaviour that
this review could not observe.

## What is solid

- The prior review's P0/P1 fixes hold up under scrutiny:
  - Package selectors are enforced on every read and write path, with
    non-enumerating 404s.
  - Blob revival and deletion are race-free in the outbox and reconciler,
    using ingest leases, fenced reservations and incarnation keys.
  - `delete` is a separate permission.
  - Group cycles are serialized.
  - CSRF and `Sec-Fetch-Site` checks apply to every cookie mutation.
  - WIF is hardened: workload discovery, `kid`, an algorithm allowlist,
    `iat`/lifetime bounds, and admin mapping refused.
- Token and session secrets are 256-bit, stored as SHA-256 hashes, and
  compared in constant time. The credential cache is keyed by HMAC.
  OIDC uses PKCE, nonce and browser binding.
- Uploads and downloads stream; no transaction spans S3 I/O; size caps are
  enforced while streaming; hashes are computed server-side.
- The crypto envelope design binds AAD to table, column and row; keys are
  zeroizing and redacted.
- Ops basics are in place: `/healthz`, `/readyz` (3 s deadlines), `/version`,
  graceful SIGTERM, hardening headers on every response, a non-root image,
  and a toolchain pinned everywhere.
- The SPA has no XSS sinks, safe redirects, show-once secrets kept out of
  caches, and CSRF on every call.

---

## Blockers

### B1. Concurrent admin hard-delete double-decrements blob refs, so a shared object is deleted while still referenced

- **Where:**
  - `crates/server/src/admin/repositories.rs:534-560` (`hard_delete`)
  - `crates/server/src/admin/repositories.rs:468-487` (`purge_repo_blob_refs`, same pattern)
  - `migrations/0001_init.sql:52` (no `CHECK (ref_count >= 0)`)
- **What:** The admin endpoint reads the component and its assets without
  `FOR UPDATE` and then decrements each blob. Two overlapping deletes both
  see the assets, both decrement, and both return 204. The overlap can be a
  client retry, a double click, or an admin delete racing a retention run.
  The locked implementation, `HostedWrite::delete_component`
  (`crates/core/src/repo/hosted.rs:841`), is not what the route calls.
- **Impact:** Blobs are deduplicated across repositories. The same `.nupkg`
  pushed to `dev` and `release`, or cached by a proxy, shares one blob. A
  double decrement drives it from 2 to 0, and the outbox deletes the S3
  object after the grace period, so the other repository returns 500. After
  that, `finalize_delete_reservation` fails on the `asset → blob` foreign key.
  The row stays in `deleting`, and re-pushing the same bytes fails too.
- **Reproduced:**
  - Setup: all 16 migrations, a blob with `ref_count = 2` referenced by `dev`
    and `release`, and two sessions running the exact statement sequence.
  - Result: `ref_count = 0` while `release` still references the blob, and a
    `delete_object` outbox row is queued.
  - With `SELECT … FOR UPDATE` on the component, the second session finds
    nothing and `ref_count` stays at 1.
- **Fix:** Route the endpoint through `HostedWrite::delete_component`, or lock
  the component first. Better still, use `DELETE FROM asset … RETURNING
  blob_sha256` and decrement only the rows actually deleted. Add
  `CHECK (ref_count >= 0)` so any drift aborts instead of deleting.

### B2. The dependency-confusion guard only considers hosted members the caller can see

- **Where:**
  - `crates/core/src/repo/group.rs:353-361`: unreadable members are dropped
    from the graph.
  - `crates/core/src/repo/group.rs:415-435`: `serving_members_for_id`.
  - `crates/core/src/repo/group.rs:476-493`: search builds `hosted_ids` from
    visible hits only.
- **What:** `prefer_hosted` drops proxy members for an id only when a
  *visible* hosted member has it. Two common setups defeat it:
  - A mixed-anonymity group, which is a supported layout (e2e test
    `mixed_anon_group_filters_members`): an anonymous group, a private hosted
    member, and an anonymous nuget.org proxy.
  - A caller whose read grant on the hosted member is selector-scoped.

  For these callers the internal id falls through to the proxy.
- **Impact:** An attacker publishes `Contoso.Internal 99.0.0` on nuget.org, and
  Forge serves it through `/flat`, `/registration` and `/query`. NuGet clients
  send stored credentials only after a 401 challenge. On an anonymous-readable
  group that challenge never comes, so even developers who have credentials
  configured restore anonymously and get the attacker's package. This is
  exactly the attack the module documentation says cannot happen.
- **Fix:** Decide "a hosted member owns this id" over all hosted leaves of the
  group, regardless of who is asking. When one does, remove proxy members for
  that id and answer 404 or 401 to callers who cannot see it. Apply the same
  rule in search.
- Two reviewers found this independently.

### B3. Unauthenticated memory exhaustion through the login lockout map

- **Where:**
  - `crates/core/src/auth/login_throttle.rs:57`, `:74-98`
  - `crates/server/src/auth/mod.rs:693-724`
  - `crates/core/src/auth/token.rs:362-411` (the Basic path)
- **What:** The lockout map is keyed by `(ip, username.to_lowercase())` with
  no length check, so the only limit is axum's default 2 MB JSON body. The map
  is capped at 100,000 entries, but entries are pruned only when it is full,
  and their size is never bounded.
- **Impact:** On a default install, `POST /auth/login` with a ~2 MB random
  username pins about 2 MB per request until restart, so roughly 1,000
  requests pin 2 GB. The throttled path also logs the full username at `warn`.
- **Fix:**
  - Reject usernames over about 256 bytes in `/auth/login` and `parse_basic`.
  - Key the map by a fixed-size hash.
  - Prune expired entries on insert.
  - Log a truncated username.

### B4. API tokens of admins are full admin credentials, and a token can mint tokens

- **Where:**
  - `crates/server/src/admin/mod.rs:59-78`: `require_admin` accepts any
    `Principal::User`, token-authenticated or not.
  - `crates/core/src/auth/authz.rs:237`: a NULL scope returns the owner's set
    unchanged.
  - `crates/core/src/authz/eval.rs:365-373`: `keep_admin`.
- **What:** `me_tokens.rs` documents the rule that "a token must not be able
  to mint further tokens (otherwise revoking one would not cut off access)".
  The admin routes ignore it. A token minted by an admin without a scope can
  call:
  - `POST /admin/users/{id}/tokens`
  - `POST /admin/users {is_admin: true}`
  - role and realm edits

  The SPA offers no scope field, so every UI-created token is unscoped.
- **Impact:** A leaked CI push token (the README says to store it in
  `NuGet.config` in clear text) becomes persistent admin access that survives
  revoking that token.
- **Fix:** In `require_admin`, refuse `token_id: Some(_)` unless the token's
  scope explicitly includes `admin`, or require a session or password
  principal for `/admin/*`.

## High

### H1. Credential forwarding holds a DB connection for the whole upstream HTTP call

- **Where:** `crates/core/src/auth/cred_cache.rs:371-381`. The code calls
  `pool.begin()`, takes row locks, then runs `forward().await` inside the
  transaction.
- **What:** Each verdict-cache miss holds a pooled connection for up to the
  5 s upstream timeout, and the default pool has 20 connections
  (`crates/server/src/config.rs:117`).
- **Impact:** Either of these exhausts the pool:
  - an upstream stall during normal traffic whose verdicts expired;
  - a password spray with rotating usernames, which the per-(IP, user)
    lockout does not bound.

  Once the pool is gone, every DB-backed request fails: anonymous reads,
  token auth and the UI. The upstream problem becomes a Forge outage.
- **Fix:** Claim the singleflight slot in a short transaction (a lease row),
  commit, forward, then write the verdict in a second short transaction. Cap
  concurrent forwards with a semaphore.

### H2. Hosted-scope retention rules on proxy repos break restores permanently

- **Where:**
  - `crates/core/src/retention/model.rs:273-307`: `Scope::Hosted` is the
    default and is not rejected for proxies.
  - `crates/core/src/retention/apply.rs:211-280`
  - `crates/core/src/repo/proxy.rs:647-651`
- **What:** The natural rule `{action: hard_delete, criteria:
  {older_than_days: 30}}` on a proxy validates. It deletes the proxy's
  components but leaves `proxy_cached_version.downloaded = true`.
  `ensure_downloaded` then calls `local_nupkg`, which finds nothing, and the
  request returns 404 without ever re-fetching from upstream. Registration
  still lists the version.
- **Fix:** Reject hosted-scope rules on proxy repos, or reset
  `downloaded`/`first_seen_at` in the same transaction. Also let
  `ensure_downloaded` re-fetch when `downloaded` is set but the asset is
  missing.

### H3. The proxy's "not found" marker hides versions from listings forever, and any reader can plant it

- **Where:**
  - `crates/core/src/repo/proxy.rs:670-681`: the row is inserted before
    upstream answers.
  - `crates/core/src/repo/proxy.rs:754-773`: the marker is set on a 404.
  - `crates/core/src/repo/proxy.rs:1040`, `:1150`, `:1263`: listings filter
    `!not_found` with no TTL.
  - `crates/db/src/proxy_dao.rs:58-66`: the listing upsert is `DO NOTHING`.
- **What:** Requesting `/flat/{id}/{v}/{id}.{v}.nupkg` before `v` exists sets
  `not_found = true`. When upstream later publishes `v`, the listing refresh
  never clears the marker, and `index.json`, registration and search keep
  hiding it. PackageReference clients pick versions from `index.json`, so
  they never request the nupkg, and the TTL path that would clear the marker
  is never reached.
- **Impact:** Anyone with read access can pre-hide future releases, security
  fixes included. Separately, an upstream 5xx leaves a phantom version
  listed (`not_found = false`), which floating version ranges can resolve to.
- **Fix:** Honour `not_found` in listings only within `not_found_ttl`. Clear
  it when an upstream listing contains the version (`ON CONFLICT … DO UPDATE
  … WHERE not_found`). Insert the row only after upstream confirms the
  version.

### H4. SPA: an expired session sends every open tab into an endless `/admin/me` loop

- **Where:**
  - `web/src/lib/httpClient.ts:67-70`: a 401 calls `clearSession()`.
  - `web/src/lib/auth.ts:85-93`: `clearSession` always notifies.
  - `web/src/routes/AppLayout.tsx:91-95`: the notification invalidates `me`.
- **What:** Each 401 notifies, the notification invalidates `me`, and the
  refetch gets another 401. Meanwhile the old `me` data stays cached, so the
  route guards never send the user to `/login`, and pages show "API 401" until
  a hard reload. It triggers on every tab left open past the 8 h idle timeout.
- **Reproduced:** 94 `/admin/me` requests in 500 ms at a 5 ms round-trip.
- **Fix:** On a 401, *remove* the `me` and auth-session queries (do not just
  invalidate them) and navigate to `/login`. Make `clearSession` a no-op when
  nothing was stored.

## Medium

| # | Finding | Where | Fix |
|---|---|---|---|
| M1 | **Content-selector PATCH widens access silently.** Omitted `includes`/`excludes` are stored as `[]`, and an empty `includes` means match-all, so `{"description":"x"}` turns a scoped selector into "every package" for every grant that uses it. | `crates/server/src/admin/content_selectors.rs:63-71,146-170`; `crates/core/src/authz/eval.rs:122,174` | Make the fields `Option` and keep stored values when absent. |
| M2 | **Upstream credentials follow a changed `remote_url`.** Repointing a proxy from a private feed to nuget.org sends the old PAT there. The username cannot be cleared (`null` means keep), and the password cannot be cleared at all. | `crates/server/src/admin/repositories.rs:345-353`; `crates/core/src/repo/proxy.rs:306-317`; `web/src/routes/admin/repositories/Edit.tsx:118-129` | Drop credentials when the origin changes, unless new ones are given, and add an explicit "clear credentials" option. |
| M3 | **Credential forwarding follows redirects and uses the final status as the verdict.** If the upstream sits behind SSO that 302s bad credentials to a login page that returns 200, then any password is "valid", and `auto_provision` is on by default. (Likely; depends on the upstream.) | `crates/core/src/net/ssrf.rs:70`; `crates/core/src/auth/upstream_basic.rs:204` | Use `redirect::Policy::none()` for forwarding. |
| M4 | **Argon2 cost is uncapped.** Every Basic request from a credential-forwarded user runs a dummy argon2 (19 MiB) before the verdict cache is checked. Parallel argon2 has no concurrency cap (500 at once is about 9.5 GiB), and the lockout check races its own result. | `crates/core/src/auth/local_password.rs:79,114-134`; `crates/server/src/auth/mod.rs:700-734` | Skip local verification for accounts with no local password; put argon2 behind a semaphore; pre-count attempts. |
| M5 | **Federated users cannot be cut off.** There is no deactivate API. DELETE leaves cached verdicts, and `auto_provision` re-creates the user. `reauth` kills neither sessions nor tokens. `/auth/tokens` does not check `active`. | `crates/server/src/admin/users.rs:117,134`; `crates/server/src/auth/mod.rs:444-460` | Add a deactivate endpoint (sessions, tokens, verdicts); purge verdicts on delete; check `active` in `require_session`. |
| M6 | **Retention `keep_last_n` ignores the rule's own filter.** A releases-only rule with `keep_last_n: 3` "protects" the three newest betas and deletes every stable release. Unlisted versions also use up slots. | `crates/core/src/retention/evaluate.rs:210-251,287-308` | Compute protection over the rule's filtered, listed set, or never delete the newest listed stable version. |
| M7 | **Proxy eviction resets `first_seen_at`.** With `package_delay_seconds`, long-established versions disappear for the delay window after every eviction. | `crates/core/src/retention/apply.rs:405-411`; `crates/db/src/proxy_dao.rs:50-75` | On eviction, set `downloaded = false` and keep the row. |
| M8 | **Group search amplification.** Each member fetches and enriches up to 1,000 hits (DB, S3 nuspec reads) whatever `take` is, and this is reachable anonymously on public groups. | `crates/core/src/repo/group.rs:448-450`; `crates/core/src/repo/hosted.rs:144-186` | Merge unenriched hits, page them, then enrich only the final page. |
| M9 | **Zip-bomb limits apply to every entry** (64 MiB per entry, 512 MiB total, ratio 200, not configurable), although only the `.nuspec` is decompressed. Large native packages (CUDA, libtorch) fail to proxy with a 500 and are re-downloaded on every retry. (Likely.) | `crates/format-nuget/src/nuspec.rs:218-246`; `crates/format-nuget/src/model.rs:26-35` | Cap only the nuspec; make the rest configurable. |
| M10 | **The proxy passes an upstream `.nuspec` through as-is**, following redirects to any host, and caches it for 24 h. A malicious or compromised upstream can redirect to `169.254.169.254` and have Forge serve that response to clients. | `crates/core/src/repo/proxy.rs:993-1019`; `crates/core/src/net/upstream.rs:179-184` | Parse the nuspec and check its id/version before serving; refuse link-local redirect targets. |
| M11 | **Proxy registration is incomplete for versions not yet downloaded.** It has no `dependencyGroups`, and upstream-unlisted versions are shown as listed. packages.config installs miss transitive dependencies, and yanked versions are offered as updates. (Likely.) | `crates/core/src/repo/proxy.rs:1268-1303,1067-1072` | Take metadata from the upstream registration. |
| M12 | **Only the first `X-Forwarded-For` header line is read.** HAProxy-style proxies add a second line, so the client's own line is trusted and IP allowlists and the lockout can be spoofed. IPv4-mapped IPv6 peers never match IPv4 CIDRs. (Likely; depends on the proxy.) | `crates/server/src/middleware/principal.rs:171-176`; `crates/server/src/auth/mod.rs:794` | Join `get_all(...)` values; call `to_canonical()` before CIDR checks. |
| M13 | **Concurrent key rotations can wrap DEKs under a revoked KEK, making every secret undecryptable.** The admin `rotate/*` endpoints skip the worker's advisory lock, and `update_wrapped` is not compare-and-swap. (Likely; needs concurrent timing.) | `crates/server/src/admin/crypto.rs:117-189`; `crates/db/src/encryption_key_dao.rs:270-298` | Take `ROTATION_LOCK_KEY` in the endpoints; make the update conditional. |
| M14 | **Enabling encryption later leaves upstream passwords in plaintext.** The backfill sets `_enc` but keeps `upstream_password`, and the "cutover migration" mentioned in 0009 does not exist. `plaintext_backfill_pending` reports clean. | `crates/db/src/secret_dao.rs:138-175,294-306`; `migrations/0009_secret_encryption.sql:13-17` | Null the plaintext column in the backfill (realm secrets already do this). |
| M15 | **Following the docs' "remove the bootstrap password" step stops the official image from starting.** The baked `changeme` comes back and is refused. | `docs/deployment.md:63`; `docker/forge.docker.toml:231-233`; `crates/server/src/config.rs:1272-1300` | Skip the check once the bootstrap marker exists, or make the bootstrap block env-only. |
| M16 | **Release-pipeline trust.** The published `cosign verify` identity regexp matches any workflow on any ref. Third-party actions are pinned by mutable tags in a job holding `packages: write` + `id-token: write`. Prereleases move `:latest`, and images are pushed before they are signed. | `.github/workflows/release.yml:35-131` | Pin `release.yml@refs/tags/v…` as the identity; pin actions by SHA; `latest=auto`; push by digest, sign, then tag. |
| M17 | **Admin deep links and refresh are still broken (P2.10).** For example, `/admin/repositories` returns raw JSON and `/admin/users/5` returns 405. This is not listed in the 0.1.0 known limitations. | `crates/server/src/app.rs:226,241-243`; `web/src/routes.ts:31-44` | Move the UI to `/manage/*` or the API to `/api/admin/*`. |
| M18 | **Repository names are not validated.** `Team Packages` is accepted but can never be reached as a feed (`%20` is not decoded), and a repo named `new` cannot be edited. | `crates/server/src/admin/repositories.rs:176`; `web/src/components/RepositoryForm.tsx:114-118` | Use the realm-name regex; reserve `new`. |
| M19 | **The GC hot paths are unindexed and the outbox is never pruned.** There is no index on `asset(blob_sha256)`, so every blob-row delete scans `asset` for the foreign key; no index on `blob_outbox(sha256)`; and processed rows are never deleted. | `migrations/0001_init.sql:73,101`; `crates/db/src/blob_dao.rs:471-509` | Add both indexes; prune processed rows. |
| M20 | **Legacy RBAC on upgraded pre-release installs:** turning `anonymous_read` off leaves the synthesized anonymous grant in place; `legacy_open_access` has no off switch; the CHANGELOG omits that `authenticated` is re-added for every user. (Fresh installs are not affected.) | `crates/server/src/admin/repositories.rs:338`; `migrations/0007_rbac_migrate.sql:92-109` | Delete the grant on toggle; document how to clear the flag; fix the upgrade note. |

## Low

- **L1 · Cache misses peer invalidations from before the first subscription.**
  `Cache::with_redis` returns before the subscription is live, and the
  supervisor flushes L1 on re-subscribe but not on the first subscription. If
  Redis is slow at boot, that window can be seconds to minutes, and entries
  filled in it stay stale until their TTL. This is also why
  `l2_sharing_and_backplane_invalidation` fails under load; the test does not
  wait for subscribers, unlike its sibling.
  (`crates/cache/src/backplane.rs:125-131`,
  `crates/cache/tests/redis_integration.rs:80-90`)
- **L2 · Multipart uploads are never aborted** when the client disconnects,
  the process is killed, or `complete` fails. Document an
  `AbortIncompleteMultipartUpload` bucket lifecycle rule.
  (`crates/storage/src/s3.rs:387-414`)
- **L3 · Repository-delete check-then-act gap.** The check and purge run
  outside the delete transaction, so a publish that commits in between is
  cascade-deleted without a decrement and its blob leaks.
  (`crates/server/src/admin/repositories.rs:433-473`)
- **L4 · Publish racing GC finalize can return 500.** `fetch_one` hits
  `RowNotFound`; use `fetch_optional` and retry. (`crates/db/src/blob_dao.rs:106-131`)
- **L5 · Backup-doc wording.** "restore the bucket to the snapshot timestamp
  **or later**" can lose objects deleted after the grace period. Say "no later
  than snapshot plus `outbox.grace_seconds`". (`docs/deployment.md:157-159`)
- **L6 · Token-scope and grant edge cases:**
  - `TokenScope` ignores unknown fields, so a mistyped scope
    (`{"repos":[3]}`) gives an unscoped token (`crates/core/src/authz/eval.rs:506-514`).
  - `max_nesting_depth` is checked only below the new member, not above it
    (`crates/db/src/repository_dao.rs:310-340`).
  - Signed-in users without grants are denied `anonymous_read` repos that
    anonymous callers can read (`crates/core/src/auth/authz.rs:81-85`).
- **L7 · Auth edge cases:**
  - The bootstrap marker is not written when the admin already exists, so a
    deleted bootstrap admin comes back (`crates/server/src/app.rs:176-205`).
  - Issuers with a trailing slash, such as Auth0, never validate
    (`crates/core/src/oidc/jwks.rs:497,617`).
  - Two concurrent first OIDC logins can create an orphan account
    (`crates/core/src/oidc/mod.rs:233-243`).
  - There is no Host-header check, so DNS rebinding works against
    `anonymous_mode = allowlist`.
- **L8 · Parsing edge cases:**
  - Package ids are lowercased with `to_ascii_lowercase`, so non-ASCII ids
    cannot be restored (`crates/format-nuget/src/nuspec.rs:82,104`).
  - `max_entries` is checked only after the whole zip central directory has
    been loaded into memory (`crates/format-nuget/src/nuspec.rs:185-194`).
  - The 16 MiB nuspec cap combined with re-parsing on every read amplifies
    memory use (`crates/format-nuget/src/model.rs:34`).
- **L9 · Image and config:**
  - `USER forge` is a name rather than a UID, which breaks Kubernetes
    `runAsNonRoot` (`Dockerfile:113`).
  - Figment parses env secrets by type and echoes the value in startup errors
    (`crates/server/src/config.rs:1133`).
  - A missing `FORGE_CONFIG` file is silently ignored (`config.rs:1129`).
  - The image bakes `allow_password_basic = true`.
- **L10 · A panicking retention run leaves a detached heartbeat** that holds
  that repository's lease until restart. (`crates/core/src/retention/worker.rs:142-149`)
- **L11 · SPA polish:**
  - No `Cache-Control` on `index.html`, and missing `/assets/*` files return
    200 `index.html` (`crates/server/src/web_ui.rs:47`).
  - The previous user's cached data survives logout (`AppLayout.tsx:116`).
  - Realm-toggle errors are swallowed.
  - The Back button gets stuck on repository search.
  - A 429 lockout is shown as "Is the server reachable?".
- **L12 · Dependencies.** `cargo audit` reports RUSTSEC-2026-0258 (`h2` 0.3)
  and RUSTSEC-2026-0098/0099/0104 (`rustls-webpki` 0.101). Both reach the
  release binary only through `aws-smithy-http-client` 1.4.2's legacy
  hyper 0.14 / rustls 0.21 stack, which is compiled in while the default S3
  client uses hyper 1 / rustls 0.23. RUSTSEC-2023-0071 (`rsa`) is test-only
  (the e2e mock issuer). There is no `cargo audit`/`cargo deny` step, no
  Dependabot or Renovate, and no image scan in CI. Add them, and document any
  accepted advisories in `audit.toml`.
- **L13 · Docs drift:**
  - No startupProbe guidance; `/healthz` is not served until migrations
    finish.
  - The two-phase root-key rotation for rolling deploys is undocumented.
  - `.env.example` documents a removed `ALLOW_PRIVATE_UPSTREAM` option and
    says a blank `FORGE_REDIS__URL` disables Redis (it makes startup fail).
  - Anonymous web browse is still disabled (P2.11) but is not listed as a
    known limitation.

## Product gaps (not defects)

The UI has no console for RBAC (roles, grants, selectors, token scopes),
retention, user lifecycle (deactivate, password reset), unlist/relist/delete,
or crypto rotation, and it does not show a repository's feed URL. Each of
these works only through the REST API today.

## Suggested order

1. **B1–B4**: small, local fixes, each with a regression test. For B1, port
   the psql interleaving into a barrier test in `crates/server/tests`.
2. **H1–H4**, plus M1, M2 and M14 (the cheap security fixes).
3. Tag `v0.1.0`, and watch the first release run (signing, SBOM, provenance)
   with M16's pinning applied.
4. Everything else in 0.1.x, starting with M3–M5, M12 and M19.
