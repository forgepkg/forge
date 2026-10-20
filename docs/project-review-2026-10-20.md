# Envisia Forge whole-repository review

**Review date:** 2026-10-20
**Reviewed revision:** `22ac8ff` (`main`, "Create FUNDING.yml")
**Scope:** every crate, the migrations, the web SPA, CI/CD and the release
pipeline, with a focus on what changed since the
[2026-10-02 review](project-review-2026-10-02.md) and on defects that review
did not cover.

## Verdict

**No Blocker or High findings.** The previous review's blocker classes did not
recur. Blob deletion and `ref_count` accounting, admin-token reach,
`prefer_hosted` ownership and lockout memory all held up under a fresh trace.
The full test suite, including the container-backed end-to-end tests, passes.

This pass found **7 Medium** and **16 Low** defects. The two to fix before
tagging `v0.1.0`:

- **M1:** Forge and NuGet can read a different `.nuspec`, and so a different
  package id, from the same `.nupkg`.
- **M2:** a colon in a form-login username makes credential forwarding check a
  different upstream account than the one Forge signs in. This also gets around
  a deactivation.

Both are identity confusions with small, local fixes. The other Medium items
are operator-safety and availability problems, and they can follow in 0.1.x.
Each has a short fix sketched below.

`v0.1.0` has still not been tagged, so the release workflow has still never
run end to end.

## Verification performed

| Check | Result |
|---|---|
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed |
| `cargo test --workspace --features forge-e2e --locked --no-fail-fast` (Docker, Postgres 17, versitygw v1.4.1, Redis) | **1,062 passed, 0 failed** across 73 test binaries. The .NET smoke test skipped itself (no SDK here); CI's `e2e` job installs one |
| Web: `tsc`, e2e `tsc`, Vitest | Passed: 16 files, 115 tests |
| `pnpm audit --prod` | No known vulnerabilities |
| GitHub Actions on `main` at `22ac8ff` | Green |
| M1 reproduction | A throwaway test fed the package described under M1 to `NugetFormat::parse_upload`. Forge accepted it as `Allowed.Lib` 1.0.0. NuGet's own reader (`PackageHelper.IsManifest`, `ZipArchiveExtensions.UnescapePath`) picks the other entry |
| Not run here | `cargo audit` (not installed; the CI `audit` job is green), `cargo sqlx prepare --check` (CI `test` job), Playwright browser specs, and the image build (CI `docker` job is green) |

Every other finding was traced end to end through the code: route,
middleware, handler, DAO SQL. Findings marked **likely** depend on timing or
client behaviour this review could not observe.

Repository hygiene, outside the code: the open Dependabot PRs
[schmitch/forge#4](https://github.com/schmitch/forge/pull/4) and
[schmitch/forge#9](https://github.com/schmitch/forge/pull/9) are red in the CI
`test` job. Their logs were not investigated here.
[schmitch/forge#10](https://github.com/schmitch/forge/pull/10) fixes a flaky
`sweep_expired` test that may be the cause.

## Medium

### M1. Forge and NuGet can pick different `.nuspec` files from one package

- **Where:** `crates/format-nuget/src/nuspec.rs:358` (`is_nuspec_name(&name) && !name.contains('/')`) and `:637-645`.
- **What:** Forge treats an entry as the root manifest when its *raw* name has
  no `/` and ends in `.nuspec`. NuGet's rule is different:
  - it percent-decodes every entry name that contains `%`
    (`ZipArchiveExtensions.UnescapePath`);
  - it treats both `/` and `\` as directory separators
    (`PackageHelper.Slashes = { '/', '\\' }`).

  The code comment at `nuspec.rs:326-329` states the goal of matching NuGet,
  but the rule does not.
- **Scenario:** a user whose grant covers `Allowed.*` pushes a `.nupkg` with
  two entries:
  - `x\allowed.nuspec` declaring `Allowed.Lib`;
  - `victim%2Enuspec` declaring `Victim.Lib`.

  Forge picks `x\allowed.nuspec`, which has no `/`, and ignores the other entry,
  whose raw name does not end in `.nuspec`. It stores `allowed.lib 1.0.0` (201)
  after passing the id-scoped grant, the reserved-prefix check and the
  owner-member check. NuGet sees `x\allowed.nuspec` as nested and
  `victim.nuspec` as the root manifest, so it reads **Victim.Lib**:
  - `packages.config` installs extract into `packages/Victim.Lib.1.0.0/`;
  - PackageReference restores fail identity validation;
  - registration metadata and dependencies differ from the manifest actually
    shipped inside the package.

  Reproduced against `parse_upload` (see Verification).
- **Related:**
  - **Likely:** zip 9 applies the Info-ZIP Unicode Path extra field (0x7075) to
    the entry name, and .NET's `ZipArchive` ignores it. One entry can therefore
    carry two names.
  - **Low:** Forge accepts packages that NuGet refuses to read:
    - duplicate entry names (zip's index keeps the last one, where NuGet sees
      two manifests);
    - a `<!DOCTYPE>` in the nuspec (NuGet uses `DtdProcessing.Prohibit`).
- **Fix:** classify every entry the way NuGet does: decode `%XX`, split on `/`
  and `\`, and take the name from the central-directory bytes only. Refuse the
  package unless that reading yields exactly one root manifest. Refuse entry
  names that contain `\` or `%`, duplicate names, and DOCTYPE outright. Add
  regression tests for each.

### M2. A `:` in the form-login username confuses the forwarded identity and gets around a deactivation

- **Where:** `crates/core/src/auth/upstream_basic.rs:224` (`format!("{username}:{password}")`); `crates/db/src/username.rs:37-51` (`canonical_username` allows `:`); `crates/server/src/auth/mod.rs:773-780`.
- **What:** HTTP Basic cannot carry a `:` in the username (`token.rs:334`
  splits at the first one), but the JSON form login can. The credential
  forwarding provider pastes the name into `user:pass` unescaped. The upstream
  splits at the first colon (RFC 7617), so it checks a different account than
  the one Forge then provisions and signs in.
- **Scenario:**
  1. An admin deactivates Forge user `mallory`.
  2. Mallory sets her upstream password to `abc:def`.
  3. She posts `{"username":"mallory:abc","password":"def"}` to `/auth/login`.
  4. The upstream sees `mallory` / `abc:def` and answers 200.
  5. Forge auto-provisions a new, **active** account `mallory:abc`, opens a
     session for it, and lets it mint API tokens.

  Further effects:
  - If the realm maps `admin_group` and Mallory is still in that group
    upstream, the new account is admin.
  - Every `victim:<prefix>` alias also gets a fresh lockout budget.
  - `revoke_credentials_for_user("mallory")` does not reach the alias.

  Only a realm with `identity_path` set blocks this.
- **Fix:** reject usernames containing `:` in `UpstreamBasicProvider` (or skip
  the realm for them). Preferably also reject them at `/auth/login` and when
  creating accounts.

### M3. Admin bodies with a misspelled field silently fall back to unsafe defaults

- **Where:**
  - `crates/core/src/retention/model.rs:29` (`RetentionPolicy`), the
    `RetentionRule` struct, and `:144` (`Criteria`);
  - `crates/server/src/admin/retention.rs:93-96` (`PutBody`);
  - `CreateRepo` and `UpdateRepo` in `admin/repositories.rs`;
  - `CreateRealm` and `UpdateRealm` in `admin/realms.rs`.
- **What:** none of these types has `#[serde(deny_unknown_fields)]`. Every
  field is defaulted, so a typo is dropped rather than rejected, and here every
  default points the dangerous way. There is no retention UI, so policies are
  hand-written JSON.
- **Scenario:** an operator sends
  `{"policy":{"version":1,"dry_run":true,"rules":[{"id":"old","action":"hard_delete","package_prefix":"Acme.Experimental","criteria":{"older_than_days":30,"keep_last":5}}]}}`.
  It passes validation (a trigger is present) and is stored with:
  - `dry_run_only = false`;
  - no `package_name_prefix`, so the rule matches every id;
  - no `keep_last_n` protection.

  The next worker run hard-deletes every version older than 30 days in the
  whole repository. The same pattern appears in the other bodies:
  - `{"enable": false}` leaves a policy enabled;
  - a misspelled `anonymous_read` on `UpdateRepo` leaves the repository public;
  - a misspelled `reserved_prefixes` on `CreateRepo` turns the
    dependency-confusion guard off.
- **Fix:** add `deny_unknown_fields` to all of these types. Stored policies are
  canonical serializations, so they still parse. Check the SPA's payloads first.
  The RBAC, user and token bodies already do this (`33787ea`).

### M4. A proxy whose `remote_url` changes keeps using the old upstream's index, possibly forever

- **Where:** `crates/core/src/repo/proxy.rs:574-579` (fresh row reused), `:598-605` (stale fallback on error); `migrations/0001_init.sql:126-131`.
- **What:** `proxy_upstream_index` is keyed by `repository_id` only and does not
  record which URL its resources came from. Changing a proxy's `remote_url`
  (`admin/repositories.rs`) never clears it.
- **Scenario:** an admin repoints proxy P from feed A to feed B.
  - For up to `metadata_ttl_seconds`, packages are still fetched from A's
    `PackageBaseAddress` and cached for good.
  - If B then fails with anything but 404 (DNS typo, 401, 5xx), the stale A
    index is served on every refresh with only a warning. The repoint looks
    successful while all traffic still goes to A.
  - When A and B share an origin, the kept credentials are sent to A's URLs too.

  The upstream version-listing, `.nuspec` and registration caches
  (`proxy.rs:650`, `:1358`, `:1482`) leave `remote_url` out of their keys as
  well.
- **Fix:** store the source URL with the index row, or delete the row when
  `remote_url` changes. Ignore a row whose URL differs, and only fall back to a
  stale index that came from the current URL. Add the URL, or a hash of it, to
  the other upstream cache keys. Add a test that changes `remote_url`.

### M5. A group answers 404 when the only member that could have a package is failing

- **Where:** `crates/core/src/repo/group.rs:793` (`list_versions`) and `:866` (`registration`); `MemberFailures::into_result` at `:933`.
- **What:** these two paths use the lenient `into_result()`: if any member
  succeeds, errors are dropped. When a hosted member answers `Ok([])` and the
  proxy member that would have the package errors, the group returns an empty
  list. `flat.rs` and the registration route turn that into 404. The download
  path (`resolve_nupkg`) deliberately uses `into_strict_result()` for exactly
  this reason.
- **Scenario:** while nuget.org is briefly unreachable:
  - restores through the group report NU1101 "package does not exist" instead
    of a retryable error;
  - a downstream Forge proxy pointed at the group sets its package-wide
    not-found marker and hides even the versions it has already cached, for up
    to `not_found_ttl`;
  - Nexus and Artifactory in front of the group cache the miss the same way.
- **Fix:** when the merged result is empty and any member failed, return the
  error. Keep the lenient merge for non-empty results.

### M6. `/browse/packages` reports `total` capped at `skip + take`, so the UI cannot page

- **Where:** `crates/server/src/browse.rs:191-192`, `:238-239`; `web/src/components/Paginator.tsx:22`.
- **What:** each repository is searched with `skip: 0, take: skip + take`.
  `total` is then the number of hits collected, never the backends'
  `total_hits`, although the field is documented as "pre-paging".
- **Scenario:** a repository with 50 packages, browsed in the SPA
  (`PAGE_SIZE = 20`), shows "Page 1 of 1 · 20 total" with Next disabled.
  Packages 21–50 can only be reached by searching. Every browse test asserts
  `total == 1`.
- **Fix:** sum `result.total_hits` across repositories; it is already filtered
  by the selector predicate, so nothing leaks. With a single `repo` filter, pass
  `skip`/`take` straight through. Add a test with more packages than `take`.

### M7. A realm whose secrets no longer decrypt cannot be repaired through the API

- **Where:** `crates/server/src/admin/realms.rs:308-318`.
- **What:** `update_realm` decrypts the stored secrets before it looks at the
  body. Any `DecryptFailed` returns `500 realm secrets unreadable`. The
  documented recovery, "enter it again through the API"
  (`docs/deployment.md`, upgrade notes), therefore cannot work for realms. The
  repository path handles the same case correctly.
- **Scenario:** an OIDC realm's issuer was changed in SQL, or a pre-release
  row-bound blob was left in place. Every `PATCH`, including one carrying a new
  `client_secret`, fails. The remaining options both hurt:
  - delete and re-create the realm, which orphans all its users through
    migration 0023's trigger;
  - clear `secrets_enc` by hand.
- **Fix:** on `DecryptFailed`, log a warning and treat the stored secrets as
  absent. Then `validate_config` requires the secret keys in the body. Add a
  test.

## Low

| # | Finding | Where | Fix |
|---|---|---|---|
| L1 | The credential cache's in-memory entries always live `positive_ttl` (300 s). Rejections should live `negative_ttl` (30 s), and a row read from Postgres should live only until its `expires_at`. The comment assumes an L1 hit re-checks Postgres; it does not. A peer can therefore accept an old upstream password for up to ~2× the documented bound, and a transient upstream 401 sticks for 5 minutes | `crates/core/src/auth/cred_cache.rs:384-409` | Return the row's remaining lifetime from the fill. Cache each entry for `min(ttl, expires_at - now)`, with `negative_ttl` for rejections |
| L2 | A deactivated local account returns `Skip`, so its password (or an attacker's guesses) is forwarded to the next credential-forwarding realm. This breaks the rule in `chain.rs:13-19`; the code comment acknowledges it | `crates/core/src/auth/local_password.rs:288-293` | After the dummy verify, return a terminal rejection for an inactive account that has a password hash |
| L3 | **Likely.** `verify_token` maps a database error to "not a token" (`.ok()??`). Under pool exhaustion, a live API token sent as a Basic password falls through to the password chain, and possibly upstream. The client gets 401 instead of 503 | `crates/core/src/auth/token.rs:52-58` | Return an error variant and fail closed with 503 |
| L4 | No last-admin guard. The sole admin can delete or deactivate themselves, or unassign their own `admin` role. The bootstrap marker then stops re-creation, so recovery needs SQL | `crates/server/src/admin/users.rs:151,182`; `admin/user_roles.rs:98` | Refuse with 409 in the same transaction when no active admin would remain |
| L5 | `PATCH /admin/tokens/{id}/scope` with `{}` clears the scope and widens the token to its owner's full non-admin reach. This is documented, but it is the same hazard class as the earlier M1 (selector PATCH) | `crates/server/src/admin/token_scope.rs:30-34` | Require the key to be present; clear only on an explicit `"scope": null` |
| L6 | Without `semVerLevel=2.0.0`, SemVer2-only packages are dropped from a page *after* paging. Legacy clients get short pages and a `totalHits` that is off by the number dropped | `crates/format-nuget/src/routes/search.rs:65-77,153` | Filter in core before counting and paging |
| L7 | **Likely.** `prune_unconfirmed` (every 60 s) can delete the unconfirmed row of an in-flight first-time download. The finalize step then answers 500 after the package was already stored. Mostly hits direct-URL clients or a very small `not_found_ttl_seconds` | `crates/db/src/proxy_dao.rs:186`; `crates/core/src/repo/proxy.rs:866,1066` | Re-insert the row at finalize, or exclude rows with a fetch in flight |
| L8 | Retention evaluation groups candidates in O(N·G) on a Tokio worker thread. About 7 s of CPU per run at 5k packages / 200k versions, for both the worker and the admin preview | `crates/core/src/retention/evaluate.rs:279-294` | Group in one pass (rows arrive `ORDER BY name`) and run inside `spawn_blocking` |
| L9 | With `default_run_interval_seconds = 0` and a policy's `min_run_interval_seconds: 0`, both of which validation accepts, the drain loop re-claims the same repository forever. `dry_run_only` audit rows pile up | `crates/core/src/retention/worker.rs:209,321-329`; `crates/server/src/config.rs` | Enforce a floor (e.g. 60 s) on the effective interval |
| L10 | After a crash, staged files survive for up to an hour (`sweep_stale(3600 s)`) and are not counted against `max_staging_bytes`. A restart can therefore use about 2× the budget on a volume sized just above it, and staging then fails with 500 rather than 503 | `crates/server/src/main.rs:64`; `crates/storage/src/cas.rs:216-262` | Use a per-process subdirectory guarded by an `flock`, and remove every unlocked one at startup |
| L11 | Leases and backoffs are computed from the app clock but compared with Postgres `now()`. Skew of minutes makes failing outbox rows retry every poll and makes every retention apply fail its fence. A clock 60 s ahead marks live delete reservations stale (safe, but noisy) | `crates/storage/src/outbox_worker.rs:66,90`; `cas.rs:149,397`; `crates/core/src/retention/worker.rs:130,399` | Compute leases and cutoffs in SQL, as `551a635` did for outbox due-ness |
| L12 | `backfill_realm_secrets` writes back with an unconditional `UPDATE`, which can undo a concurrent admin edit. It also turns one undecryptable realm that still has a plaintext key into a fatal startup error and a failing rotation pass. The repository backfill handles both cases | `crates/db/src/secret_dao.rs:954-980`; `crates/server/src/crypto.rs:254,392` | Use `update_realm_with_secrets_if_unchanged`; on `DecryptFailed`, warn and skip or re-seal |
| L13 | Anyone who can publish to the Redis backplane can set a tag's generation to `u64::MAX`. `saturating_add(1)` then never advances, so peers ignore later authz and credential invalidations until TTL or a restart. This contradicts the crate doc ("the worst a Redis writer can do … is evict entries early") | `crates/cache/src/backplane.rs:278-316`; `crates/cache/src/lib.rs:706-725` | Reject implausible generation jumps, or flush the namespace when a barrier saturates |
| L14 | `release.yml` concurrency is per tag ref, and channels are decided at checkout. Two overlapping tag runs can therefore move `:latest` and `:X.Y` back to the older version. `attestations: write` is granted but never used | `.github/workflows/release.yml:27-29,42` | Re-fetch tags and re-run `release-channels.sh` just before `imagetools create`; drop the unused permission |
| L15 | `.gitlab-ci.yml` cannot pass. `sqlx` is not on PATH (`CARGO_HOME` points inside the project). The `test` job has neither Docker nor `FORGE_TEST_*`, so testcontainers panic. `docker-compose-plugin` is not an Ubuntu package. It also lacks the audit jobs and digest pins that `ci.yml` has | `.gitlab-ci.yml:43,90-101,198` | Delete it now that the project is on GitHub, or fix and keep it in parity |
| L16 | A token scoped to a group's id alone sees an empty feed: each member needs `can_read` under the token's scope. This fails closed but is undocumented | `crates/core/src/repo/group.rs:404` (`group_graph`) | Document "list every member in the scope" or expand group scopes to members |

## Test-coverage gaps

These gaps are why the Medium findings got through:

1. **Package identity:** no test checks manifest choice against NuGet's rule
   for entry names with `\`, `%XX`, the 0x7075 extra field, or duplicates (M1).
2. **Login:** no test sends a `:` username through form login to a forwarding
   realm (M2). Nor does one cover an inactive local account in a
   local → forwarding chain (L2).
3. **Admin bodies:** no test sends unknown or misspelled fields to the
   retention, repository or realm bodies (M3).
4. **Proxy and group reads:**
   - no test changes a proxy's `remote_url` (M4);
   - no group test covers an id that only a failing member could serve, and
     there is no end-to-end test of a Forge proxy in front of a Forge group
     (M5).
5. **Browse:** no browse test, server or SPA, has more packages than `take`
   (M6).
6. **Realm secrets:** no test repairs a realm with undecryptable secrets
   through `PATCH` (M7).
7. **Timing and scale:** nothing injects clock skew into leases, nothing runs
   retention at scale or with zero intervals, and nothing runs migration
   0017's repair branch against a drifted, populated database.

## What is done well

- **Storage:** the CAS deletion protocol remains the strongest part of the
  codebase. Ingest leases and deletion reservations serialize on the blob row
  lock, ambiguous S3 DELETEs keep their fence, and incarnation-qualified keys
  stop a late DELETE from hitting a revived object. No transaction spans S3
  I/O. No path in this review could delete a referenced blob or drift
  `ref_count`.
- **Authorization:**
  - The evaluator is pure and fails closed.
  - Token scopes are intersected after the shared cache, and `admin` is an
    explicit scope.
  - Package visibility has a single enforcement point
    (`PackageFilteredReadOps`), applied before counts and paging.
  - Group-graph edits are serialized by a table lock, with cycle and depth
    checks.
- **Authentication:**
  - Sessions, tokens and CSRF secrets are 256-bit, stored hashed, and compared
    in constant time.
  - OIDC state lives in the database: PKCE S256, nonce, single-use state,
    browser binding, RSA-only algorithms.
  - Trusted publishing re-fences the realm configuration at publish time.
- **Secrets at rest:** each seal uses a fresh random nonce, and the AAD binds
  table, column, row and destination. Rotation is compare-and-swap under a
  scope lock, and revocation is checked at commit time.
- **Supply chain:**
  - Every action is pinned by SHA, the default token is read-only, and nothing
    runs on `pull_request_target`.
  - The image runs as a non-root UID, and releases are signed by digest.
  - pnpm enforces a seven-day release cooldown.
  - The zip 9 upgrade (`2bcb8da`) was adapted correctly.
