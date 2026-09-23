# Envisia Forge whole-project review

**Review date:** 2026-07-15
**Reviewed revision:** `93d4648f24f2` (`main`)
**Scope:** architecture, NuGet behavior, storage, authentication, authorization,
secret handling, workers, frontend, tests, CI/CD, operations, documentation, the
published roadmap, and trusted-publishing readiness.

## Status as of 0.1.0 (2026-09-23)

The remaining release blockers from this review and the 2026-09-23 readiness
pass are closed for 0.1.0. The items still open are listed as **Known
limitations** in the [0.1.0 changelog](../CHANGELOG.md#010); operator guidance
is in [deployment.md](deployment.md).

## Remediation addendum — 2026-07-16 working tree

The review below is intentionally preserved as the point-in-time assessment of
revision `93d4648f24f2`. The following items have since been implemented in the
current working tree:

| Original finding | Current remediation status |
|---|---|
| **P0.1 package/content selectors** | **Fixed.** Read predicates now wrap hosted, proxy, group, browse, registration, search, flat-container, nuspec, and package-download paths. Search applies the predicate before paging/counting without repeatedly rescanning production backends. Canonical package IDs are authorized before CAS/DB promotion; excluded reads and identifier mutations retain non-enumerating 404 behavior. HTTP E2E coverage includes hosted and nested-group selectors. |
| **P0.2 blob revival/deletion race** | **Fixed.** Ingest leases coordinate S3 upload with reference attachment, deletion uses token-fenced reservations without holding a database transaction over S3, and new blob incarnations receive distinct object keys. Ambiguous S3 DELETE failures retain the fence. Barrier-controlled worker/reconciler tests cover revival, stale deletion, lease refresh, and ambiguous completion. |
| **P1.3 delete privilege** | **Fixed.** Request dispatch distinguishes read, write, and delete actions; direct package mutations use their action-specific package filter. |
| **P1.9 trusted publishing** | **Fixed for the documented direct-token model.** Workload-only discovery supports GitHub Actions, claim/time/algorithm/JWKS checks are hardened, known public issuers require workload-identity claims, global-admin mapping is rejected, repository/package RBAC is enforced, stale realm policy is fenced at publish time, and successful publishes append an immutable application audit row atomically with the package. See [trusted publishing](trusted-publishing.md). |

This is support for the direct-token variant that the OpenSSF guidance permits,
not full adoption of its preferred repository-token exchange. Forge does not
yet exchange the OIDC identity token for a separate short-lived Forge token or
consume `jti` after one successful publication; the bearer remains reusable
until expiry. Those distinctions are documented acceptance limits, not hidden
claims of full alignment with every OpenSSF recommendation.

Migration 0011 is a storage-protocol boundary, not only a schema change. Old
instances do not participate in ingest leases or incarnation-qualified keys;
therefore the first upgrade containing it must drain every pre-0011 writer and
GC worker, including all in-flight or ambiguous S3 DELETEs. If the object store
cannot prove quiescence, the coordinated backup must be restored/copied to a
clean object namespace before restart. It is not safe as a mixed-version
rolling upgrade. The operator procedure is documented in
[DEVELOPMENT.md](../DEVELOPMENT.md).

### Remediation verification

| Working-tree gate | Result |
|---|---|
| `cargo fmt --all --check` and `git diff --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed |
| Rust unit/binary tests with all features | Passed: 321 tests |
| Container-backed RBAC/selector E2E | Passed: 10 tests, including hosted and nested-group package filtering |
| Container-backed trusted-publishing E2E | Passed: 9 tests, including a native private-feed `dotnet nuget push` |
| Blob outbox and reconciler integration suites | Passed: 5 + 4 tests, including revival, stale-owner, ambiguous-delete, and live-ingest fencing |
| PostgreSQL migrations and SQLx live metadata drift check | Passed: migrations 1–13 and workspace `prepare --check` |
| Frontend tests, type check, and production build | Passed: 13 files / 72 tests, TypeScript clean, Vite build complete |

The provider-shaped tests use controlled GitHub/GitLab-style issuers; no live
cloud-issued token was used. Default-branch CI was not run from this uncommitted
working tree.

These repairs do not close the unrelated P1 and operational findings below.
In particular, complete cookie-session CSRF enforcement, legacy-RBAC cleanup,
realm-secret encryption, nested-group mutation serialization, large-object
streaming, rate limits, effective-admin UI behavior, and production operations
remain recommended before a general-availability release.

> **Baseline review begins below.** Its findings and test counts describe the
> reviewed revision, not the remediated working tree summarized above.

## Executive assessment

Envisia Forge is a serious, well-structured NuGet registry implementation. The
original hosted/proxy/group repository slice exists, and most later roadmap
slices have substantial code, migrations, APIs, workers, and tests. This is not
an early scaffold.

It is nevertheless **not production-ready in its current state**. Two confirmed
correctness/security defects should block a production release:

1. RBAC package/content selectors are modeled and advertised but are not
   enforced by production NuGet or browse paths. A selector-scoped reader can
   access excluded packages, and a selector-scoped workload publisher is not
   actually restricted to its package namespace.
2. Blob deletion has a check/delete race in which a concurrently revived blob
   can remain referenced in PostgreSQL after its S3 object has been deleted.

There are also important high-priority gaps around cookie-session CSRF,
legacy-RBAC migration behavior, plaintext authentication-realm secrets,
workload-identity hardening, large-object buffering, OIDC session UX, and
operational readiness.

The roadmap is therefore best described as:

- foundational NuGet registry: implemented, with release-blocking hardening
  defects;
- retention, OIDC, credential forwarding, and authentication realms: mostly
  implemented;
- fine-grained RBAC, secret encryption, frontend, and workload identity:
  partially implemented;
- additional package formats: not implemented.

The project supports **partial workload identity federation**, but it does not
yet support trustworthy, package-scoped trusted publishing end to end. The
details and a concrete completion path are in
[Trusted publishing](#trusted-publishing-assessment).

## What is already strong

### Architecture

- The Rust workspace has useful boundaries: core domain behavior, database
  access, storage/CAS, NuGet protocol formatting, crypto, server composition,
  and end-to-end tests are separated into dedicated crates in
  [Cargo.toml](../Cargo.toml).
- PostgreSQL is the authority for repository metadata and coordination, S3 is
  used for content-addressed blobs, and Redis is an optional convergence/cache
  accelerator rather than a second source of truth.
- Hosted, proxy, and group repositories share a coherent abstraction instead
  of duplicating protocol routing.
- Migrations are incremental and cover retention, OIDC, credential forwarding,
  RBAC, token scope, secret encryption, authentication realms, and workload
  identity.

### Correctness-oriented foundations

- Hosted uploads stream into CAS with size enforcement before the database
  attachment is committed; component, asset, and blob references are then
  committed together in
  [hosted.rs](../crates/core/src/repo/hosted.rs#L334).
- Retention re-evaluates candidates under lock and records its audit trail in
  the same transaction. Lease and `SKIP LOCKED` behavior are covered by tests.
- OIDC uses discovery/JWKS validation, state, nonce, and PKCE; its tests include
  replay rejection, cross-instance callback, key rotation, expiry, and logout
  propagation.
- Authentication providers generally fail closed, and browser sessions use
  secure cookie attributes.
- Conditional S3 creation and CAS behavior have dedicated integration tests.

### Delivery and test foundation

- CI covers formatting, Clippy, Rust tests, SQLx metadata drift, frontend unit
  tests/build, and browser E2E suites in
  [GitHub Actions](../.github/workflows/ci.yml) and
  [GitLab CI](../.gitlab-ci.yml).
- The same-origin React application avoids a separate browser-to-API CORS
  boundary.
- The production container is multi-stage, includes CA certificates, and runs
  as an unprivileged user.

These strengths make the remaining work tractable: most gaps are integration,
hardening, and product-completion work rather than a need to replace the core
architecture.

## Roadmap implementation audit

### Status legend

- **Implemented:** promised feature behavior and representative integration
  coverage exist. This does not imply every production-hardening concern is
  closed.
- **Mostly implemented:** the main behavior exists, with explicit acceptance,
  UX, or hardening gaps.
- **Partial:** a central promised capability is absent, bypassable, or not wired
  end to end.
- **Not implemented:** no meaningful implementation was found.

| Roadmap item | Status | Assessment |
|---|---|---|
| Slice 1: hosted/proxy/group NuGet registry | **Implemented, with release blockers** | Repository modes, NuGet V3 endpoints, PostgreSQL metadata, S3 CAS, outbox/GC, authentication, workers, and E2E suites exist. The tracker is stale and the blob-revival race must be fixed. |
| 12.1 retention and cleanup | **Mostly implemented** | Schema, evaluator, worker, preview/run/audit APIs, leases, download tracking, and broad E2E coverage exist. Apply batching, a maximum-delete safety cap, audit pruning, and the planned push/apply and crash-resume acceptance tests are missing. |
| 12.2 OIDC/Entra | **Mostly implemented** | Discovery, JWKS, PKCE, server sessions, CSRF token model, and scale-out tests exist. `iat`/`azp` checks promised by the plan are not enforced; OIDC logout bootstrap and reaper scheduling have defects. |
| 12.3 credential forwarding | **Mostly implemented** | Provider chain, provision-on-success, shared verdict cache, row-lock single-flight, mappings, reauthentication, and invalidation exist. Rate limiting and the explicit simultaneous two-instance first-miss acceptance test are absent. |
| 12.4 fine-grained RBAC and nested groups | **Partial** | Roles, grants, nested groups, selectors, token scopes, APIs, caches, and evaluator tests exist. Package selectors are not called by production read/write paths; `delete` is not independently enforced; legacy bootstrap can preserve revoked rights; group cycle prevention is raceable. |
| 12.5 double-envelope secret encryption | **Partial** | Envelope format, AAD binding, zeroizing values, DEK/KEK storage, repository-password backfill, rotation workers, and admin endpoints exist. AWS KMS is deliberately unshipped, realm secrets remain plaintext JSON, encryption is optional, and the planned per-DEK AES-GCM use budget is absent. |
| 12.6 frontend | **Partial** | Browse, repository/package detail, self-service tokens, repository/user-token/realm admin, component tests, and Playwright exist. RBAC, retention, crypto operations, user lifecycle, download statistics, retention state, public browse, and reliable admin deep links are missing. |
| 12.7 authentication realms | **Mostly implemented** | Realm CRUD/order/runtime snapshot, identifier-first login, combined login, UI, legacy import, SSRF policy change, and optional conditional CAS writes exist. Secret encryption, rate limiting, database-enforced OIDC uniqueness, and prompt multi-instance invalidation remain incomplete. |
| 12.8 workload identity federation | **Partial** | Direct OIDC workload-token verification and role mapping work and have E2E coverage against test issuers. GitHub workload discovery is incompatible, package scope is unenforced, token replay/provenance controls are missing, and unsafe catch-all rules are possible. |
| Additional formats (original item 12.7) | **Not implemented** | The workspace contains only `format-nuget`; npm, Maven, Cargo, and OCI support have not started. |

### Roadmap evidence and important gaps

#### Slice 1: NuGet registry

The approved design promises hosted, proxy, and group repositories backed by
PostgreSQL and S3-compatible CAS in
[the NuGet design](superpowers/specs/2026-05-29-envisia-forge-nuget-design.md).
Those repository types, NuGet routes, storage, outbox, authentication, workers,
and E2E suites are present. Multipart S3 storage also exists and is tested.

The corresponding
[Slice 1 implementation plan](superpowers/plans/2026-05-29-slice1-nuget-registry.md)
still has every task checkbox unchecked even though its own self-review says the
coverage is complete. The implementation exists; the status document was never
maintained.

#### 12.1: Retention

Retention is much more complete than the roadmap status suggests:

- [migration 0002](../migrations/0002_retention.sql) adds policy, run, audit,
  and download-tracking data;
- [workers.rs](../crates/server/src/workers.rs#L113) starts the lease-based
  worker;
- [admin routing](../crates/server/src/admin/mod.rs#L103) exposes policy,
  preview, run, and audit operations;
- [retention E2E tests](../crates/e2e/tests/retention.rs) cover selection,
  apply behavior, leases, and audit behavior.

The explicit `apply_batch_size` and optional `max_deletes_per_run` safeguards in
the plan are not represented in the current configuration, and apply iterates
the complete decision set. Add both controls before operating retention at
large scale. Add a real kill/reclaim test, a publish-between-snapshot-and-apply
race test, and an audit-pruning policy. The frontend currently exposes none of
the retention workflow and returns a null retention status for package data.

#### 12.2: OIDC

OIDC is substantially implemented and tested, including the difficult
scale-out cases. Two claim checks called for by the plan are still only decoded,
not validated: `iat` and `azp` in
[jwks.rs](../crates/core/src/oidc/jwks.rs#L331). More immediately, the frontend
does not retrieve the CSRF token after an OIDC callback, so logout can fail while
the UI appears signed out. The session reaper is also incorrectly conditioned
on legacy static OIDC configuration even though local-login and database-owned
realms also create sessions.

#### 12.3: Credential forwarding

Credential forwarding has a thoughtful provider chain and shared verdict
model. The implementation uses a PostgreSQL row lock rather than the older
plan's advisory-lock proposal, which is consistent with most of the project's
coordination model. Missing release criteria are authentication rate limits and
a two-instance concurrent-first-miss test that proves the upstream is called
exactly once.

#### 12.4: RBAC

The schema and evaluator are extensive, but the feature is not safely complete.
[Authz::package_filter](../crates/core/src/auth/authz.rs#L120) promises a
package-aware predicate, while
[EffectiveSet::allows_repo](../crates/core/src/authz/eval.rs#L289) deliberately
performs only the repository-level gate. No production route consumes
`package_filter`. The dispatcher therefore authorizes the repository and then
hands requests to NuGet/browse implementations without a content predicate in
[dispatch.rs](../crates/server/src/dispatch.rs#L105).

This is the largest discrepancy between roadmap and implementation. Selector
tests currently prove evaluator/admin behavior, not HTTP behavior. Release
criteria must cover registration, search, flat-container index, direct `.nupkg`
and `.nuspec` downloads, browse/detail, groups, anonymous access, publish,
unlist, relist, and delete. Excluded content should consistently appear as 404.

Two further issues prevent calling RBAC complete:

- all mutating NuGet verbs use `write`; the seeded `delete` action is never
  independently checked;
- the legacy bootstrap runs on every startup and only inserts grants, so
  switching off legacy anonymous/admin access does not revoke previously
  synthesized RBAC access.

Nested-group cycle prevention also locks only one parent row, allowing
opposite-direction concurrent inserts to pass separate checks.

#### 12.5: Secret encryption

The crypto crate is well factored and repository upstream passwords can use
double-envelope encryption and rotation. The plan, however, explicitly
includes AWS KMS while
[kms.rs](../crates/crypto/src/kms.rs) states that only environment/file
providers are shipped.

More importantly, authentication realms introduced afterward put OIDC
`client_secret` and credential-forwarding `key_pepper` values into the
`auth_realm.config` JSON column in
[migration 0010](../migrations/0010_auth_realms.sql). The DAO stores that JSON
opaquely; API response redaction does not provide encryption at rest. This is a
central integration gap, not merely a future feature.

Finish a single secret-storage seam for every credential type, enforce it in a
production profile, add AWS KMS or another production KMS/HSM provider, retire
the plaintext fallback columns after migration, and test cross-instance decrypt
plus crash-resumable rotation.

#### 12.6: Frontend

The application is a React SPA using TanStack Router, not TanStack Start as the
old plan title suggests. Its core browse and administration journeys work, and
71 frontend unit tests pass. It does not yet surface several shipped backend
capabilities:

- roles, grants, assignments, selectors, token scopes, and effective access;
- retention policy, preview, run history, audit, and failures;
- crypto rotation/backfill operations;
- user activation, deactivation, password reset, and role assignment;
- package download statistics and retention state;
- unlist/relist/hard-delete lifecycle operations.

The UI also blocks all anonymous browsing even when a repository permits
anonymous reads. Admin UI routes share `/admin/*` with REST endpoints, causing a
known refresh/deep-link collision documented in
[DEVELOPMENT.md](../DEVELOPMENT.md#L136) and pinned in
[admin-deeplink.spec.ts](../web/e2e/specs/admin-deeplink.spec.ts).

#### 12.7: Authentication realms

Database-owned authentication realms, ordered provider evaluation,
identifier-first login, administration, and legacy import are present. The
implementation constrains enabled OIDC to one realm even though parts of the
design imply multiple buttons/providers. That constraint should either become
an explicit product decision and database invariant or be removed.

Realm secrets need the 12.5 encryption seam. `/auth/identify` and login also
need rate limits. Runtime realm snapshots on peer instances currently converge
by TTL rather than receiving prompt invalidation when Redis/backplane signaling
is available.

#### 12.8: Workload identity

The server can authenticate a direct OIDC workload token supplied through its
supported authorization forms, match claims, and map the identity to a role.
The E2E suite covers successful use, bad audience, expiry, bad signature,
default-deny, and multiple issuers. This is useful workload federation.

It is not yet complete trusted publishing because workload issuer discovery is
coupled to an interactive OIDC discovery model, selector-based package scope is
not enforced, and replay/provenance controls are missing. See the dedicated
assessment below.

#### Additional formats

The original roadmap calls additional formats item 12.7, while the later realm
design reuses 12.7 for authentication realms and introduces 12.8 for WIF. This
numbering collision should be fixed. Only NuGet is implemented, and repository
creation should reject non-`nuget` formats until a corresponding format module
actually exists.

## Confirmed findings

### P0 — release blockers

#### P0.1 Package/content selectors are not enforced

**Impact:** confidentiality and authorization boundary failure. A role or token
intended to read only a selected package set can enumerate and download other
packages in the repository. A WIF publisher assigned a selector-scoped write
grant can publish outside the intended namespace.

**Evidence:**

- the package-filter API is defined in
  [authz.rs](../crates/core/src/auth/authz.rs#L120);
- repository authorization intentionally ignores selectors in
  [eval.rs](../crates/core/src/authz/eval.rs#L289);
- production dispatch checks only `can_read` or `can_write` before routing in
  [dispatch.rs](../crates/server/src/dispatch.rs#L105);
- flat-container and search routes receive no package predicate in
  [flat.rs](../crates/format-nuget/src/routes/flat.rs) and
  [search.rs](../crates/format-nuget/src/routes/search.rs);
- browse performs the same repository-level check in
  [browse.rs](../crates/server/src/browse.rs#L194).

**Required fix:** make package-aware authorization an unavoidable wrapper around
all repository read operations and direct member lookups. For writes, parse the
canonical package identity first and authorize that identity before committing
the upload or mutation. Add an HTTP-level selector matrix for hosted and group
repositories and return indistinguishable 404 responses for excluded content.

#### P0.2 Concurrent blob revival can lose live object data

**Impact:** data loss. PostgreSQL can retain a live component/blob reference
while the corresponding S3 object has been deleted.

**Evidence:** the outbox worker reads a zero reference count, deletes the S3
object outside that transaction, and only afterward conditionally removes the
database row in
[outbox_worker.rs](../crates/storage/src/outbox_worker.rs#L77). A concurrent
increment between the check and object deletion revives the database record but
does not protect or restore the object. The reconciler has the same check/delete
shape in [reconciler.rs](../crates/storage/src/reconciler.rs#L39). The existing
test covers revival before worker processing, not revival during deletion.

**Required fix:** add an atomic deletion reservation/tombstone or blob
generation. Revival must coordinate with that state and either cancel deletion
before the object is removed or re-upload/verify the exact content before
restoring a live reference. Add barrier-controlled concurrency tests around the
object delete call for both worker and reconciler.

### P1 — high priority before production

#### P1.1 Cookie-authenticated administration lacks complete CSRF enforcement

`/auth/logout` and `/auth/tokens` explicitly validate `x-csrf-token`, but
mutating `/admin/*` endpoints and `/admin/me/tokens` accept cookie sessions
without an equivalent server-side check. The SPA currently sends the header,
but an unenforced client convention is not a security boundary.

Add one middleware applied to every state-changing cookie-authenticated route,
with bearer/basic requests handled explicitly. Add negative integration tests
for every router family. SameSite cookies should remain defense in depth.

#### P1.2 Legacy RBAC synthesis preserves revoked access

[main.rs](../crates/server/src/main.rs#L62) invokes legacy RBAC synchronization
on every boot. The migration helper in
[0007_rbac_migrate.sql](../migrations/0007_rbac_migrate.sql#L85) inserts
anonymous/authenticated/admin grants but does not remove them when legacy flags
change. OIDC can clear `app_user.is_admin` while the previously synthesized
global-admin role remains effective.

Make migration a one-time operation, or implement exact bidirectional
synchronization with clear ownership. Remove legacy authorization reads and
columns once the transition is complete.

#### P1.3 `delete` is a modeled but unused permission

The RBAC migration seeds a `delete` action, while
[Authz::can_write](../crates/core/src/auth/authz.rs#L87) and the dispatcher treat
PUT, POST, and DELETE as the same `write` authorization. No production path
requests `Action::Delete`.

Classify each NuGet mutation explicitly and test write-without-delete and
delete-without-write roles. Decide separately how unlist/relist map to actions.

#### P1.4 Concurrent nested-group updates can introduce a cycle

The cycle check in
[repository_dao.rs](../crates/db/src/repository_dao.rs#L254) locks only the
selected parent. Concurrent `A -> B` and `B -> A` operations lock different rows
and may both pass under `READ COMMITTED`.

Serialize graph mutations with a narrowly scoped coordination lock, use
serializable transactions with retry, or take canonical locks over the affected
subgraph. The final database state, not just request completion, needs a
concurrency test.

#### P1.5 Realm credentials are plaintext at rest

OIDC client secrets and forwarding peppers are stored in realm JSON by
[auth_realm_dao.rs](../crates/db/src/auth_realm_dao.rs). Response redaction in
the admin API prevents casual disclosure but does not protect a database dump or
read-only database compromise.

Route these values through the existing envelope-encryption service with
realm/field identity included in AAD. Backfill current rows, support rotation,
and remove plaintext material after verified migration.

#### P1.6 Large package paths buffer excessive data and hold network work across locks

Public download reads a complete S3 object into memory in
[state.rs](../crates/server/src/state.rs#L218), while proxy retrieval buffers up
to 512 MiB, parses it synchronously, and clones bytes in
[proxy.rs](../crates/core/src/repo/proxy.rs#L594). Proxy refresh also keeps a
database transaction/row lock open across the upstream request in
[proxy.rs](../crates/core/src/repo/proxy.rs#L780). The shared outbound client has
a redirect limit but no explicit connect/request timeout in
[ssrf.rs](../crates/core/src/net/ssrf.rs#L57).

Stream S3 responses to the client, spool upstream artifacts to bounded temporary
storage/CAS, move synchronous archive parsing to a bounded blocking pool, set
connect/total/idle timeouts, and avoid holding database transactions over
network I/O. Add load tests with concurrent near-limit packages.

#### P1.7 Effective RBAC administrators can be rejected by the SPA

Admin APIs authorize with the effective `Authz::is_global_admin`, but
[`/admin/me`](../crates/server/src/me.rs#L49) derives `is_admin` and all UI
capabilities from legacy `app_user.is_admin`. The application then hides and
redirects administration routes using that legacy result.

Return effective capabilities from the authoritative RBAC evaluator and gate
individual UI functions by those capabilities rather than one boolean.

#### P1.8 OIDC logout can fail invisibly

Password login stores the returned CSRF token in
[Login.tsx](../web/src/routes/Login.tsx#L136). OIDC callback login sets only an
HTTP-only session cookie, and the frontend never calls its existing
`fetchAuthSession` helper. Logout requires the missing token; the application
swallows the error and clears its local state in
[AppLayout.tsx](../web/src/routes/AppLayout.tsx#L98), leaving the server session
alive.

Bootstrap `/auth/me` after callback and on application load, retain its CSRF
token in memory, and only display logout success after the server confirms it.
Add a callback-to-logout browser test.

#### P1.9 WIF discovery and trust controls are incomplete

The shared discovery structure in
[jwks.rs](../crates/core/src/oidc/jwks.rs#L80) requires interactive
`authorization_endpoint` and `token_endpoint` fields. GitHub Actions' official
[workload OIDC discovery document](https://token.actions.githubusercontent.com/.well-known/openid-configuration)
contains the issuer and JWKS information needed for workload verification but
not those interactive endpoints. The realm UI nevertheless offers GitHub as an
example issuer.

The verifier checks issuer, audience, expiry, and not-before, but not the
planned `iat` or `azp`; routing does not consistently require `kid`; and an
empty-condition WIF rule is an intentional catch-all in
[wif.rs](../crates/server/src/auth/wif.rs#L73). There is no consumed-`jti` model
or positive-verdict cache bounded by token expiry.

Use a workload-specific discovery type, add provider templates with safe claim
requirements, validate temporal/authorized-party claims, require stable key
identification, and add replay controls appropriate to the chosen token flow.

#### P1.10 Current default-branch CI is red

At review time, the GitHub Actions run for the reviewed HEAD was
[run 28359773732](https://github.com/schmitch/repo/actions/runs/28359773732) and
finished failed. Formatting, Clippy, Rust unit/workspace tests, SQLx checks, and
frontend unit/build jobs passed. The container E2E job exhausted disk while
compiling, and web E2E had one failing group-form selector because
`getByLabel(/^priority$/i)` matched both a `<span>` and the input in
[group.spec.ts](../web/e2e/specs/group.spec.ts#L87).

Restore a green protected branch: reduce E2E image/disk pressure, avoid
duplicated heavy build artifacts, and make the Playwright locator unambiguous.
Treat repeatable E2E capacity as part of the test design rather than an
incidental runner problem.

#### P1.11 Production defaults are unsafe

[docker/forge.docker.toml](../docker/forge.docker.toml) includes placeholder
credentials, anonymous access, Basic password authentication, and
`admin/changeme`; the image embeds that configuration. These are convenient
development defaults but dangerous if the image is deployed without careful
overrides, and there is no user-facing password-change flow.

Separate a clearly named development profile from production configuration.
Production startup should fail closed when placeholder/bootstrap credentials
are present and should require an explicit one-time bootstrap secret or external
identity provider.

### P2 — important hardening and product debt

1. **Auth-session cleanup is gated incorrectly.** The reaper starts only when
   legacy `[oidc]` config is enabled in
   [workers.rs](../crates/server/src/workers.rs#L140), although password login
   and database-owned realms also create sessions. Start it unconditionally
   when session storage is active.
2. **OIDC realm uniqueness is raceable.** The admin layer checks for an existing
   enabled realm before insert/update, but the database has no partial unique
   invariant. Concurrent changes can leave multiple enabled rows while runtime
   selection takes the first. Enforce the selected product constraint in the
   database.
3. **Encrypted repository changes are not atomic.** Repository metadata is
   committed before the separate encrypted-secret write in
   [repositories.rs](../crates/server/src/admin/repositories.rs#L201). Compose
   both writes in one transaction/service operation.
4. **Search totals and paging become inaccurate at scale.** Hosted search loads
   complete results, while groups/cross-repository search cap each member and
   combine truncated totals. Introduce stable cursor/offset semantics and
   database-side filtering/counting.
5. **Concurrent first publish can return an internal error.** A plain `SELECT`
   cannot lock a version row that does not exist, so simultaneous first pushes
   can reach the unique constraint. Map the race to the documented conflict
   response and test it.
6. **Repository `format` accepts misleading values.** The format registry always
   resolves NuGet behavior. Validate `nuget` until other format modules exist.
7. **Worker settings lack range validation and supervision.** Zero intervals can
   panic, negative/invalid values are insufficiently rejected, and spawned task
   handles are retained without meaningful failure supervision. Validate all
   worker values and surface last-success/last-error state.
8. **Authentication endpoints have no rate limiter.** Add per-account plus
   per-origin limits to identify, login, reauthentication, token creation, and
   WIF failures, with trusted-proxy handling defined explicitly.
9. **Peer realm snapshots rely on TTL convergence.** Publish invalidations over
   the existing backplane where possible while retaining TTL as recovery.
10. **Admin URLs collide with API URLs.** Move browser administration to
    `/manage/*` or APIs to `/api/admin/*`, then turn the known failing deep-link
    scenario into a success test.
11. **Anonymous repository browsing is artificially disabled.** Decide whether
    public web browse is a product feature; if yes, use the same repository and
    package authorization rules as NuGet endpoints.
12. **No service health, metrics, or SIGTERM handling.** Add liveness, readiness,
    dependency/backlog health, structured request tracing, Prometheus or
    OpenTelemetry metrics, request IDs, SIGTERM handling, and bounded worker
    drain.
13. **GitLab CI has tool/runtime inconsistencies.** Its Playwright image is
    1.50.1 while the caret dependency resolves 1.60.0, and the normal Rust test
    job has no Docker service even though workspace integration tests use
    testcontainers. Pin matching versions and give the relevant test job a
    documented Docker-capable runner.
14. **Toolchains float across environments.** Rust appears as `stable`,
    `latest`, and an exact image in different locations. Pin compiler, Node,
    pnpm, Playwright, and important CI action digests, then update intentionally.
15. **Repository governance/release assets are sparse.** Add `LICENSE`,
    `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, changelog/release policy,
    automated dependency updates, minimum GitHub Actions permissions, and
    commit-pinned actions.

## Trusted publishing assessment

### Verdict

**Partial support only. Do not yet advertise this as complete trusted
publishing.**

There are two distinct questions:

1. **Can Forge accept workload identity instead of a long-lived publishing
   secret?** Yes, for compatible generic OIDC issuers. The server verifies a
   workload token, evaluates configured claim rules, maps it to a role, and has
   E2E coverage for successful and rejected requests.
2. **Can an operator safely delegate publication of one package namespace to a
   GitHub/GitLab pipeline with strong identity, scope, replay, and audit
   guarantees?** Not yet.

Current blockers:

- GitHub Actions workload discovery is rejected because the code requires
  interactive OIDC endpoints not present in the official discovery document.
  See GitHub's [OIDC security documentation](https://docs.github.com/en/actions/concepts/security/openid-connect)
  and [provider metadata](https://token.actions.githubusercontent.com/.well-known/openid-configuration).
- A workload role's package selector is not enforced by publish paths, so it
  cannot safely bind a publisher to `Company.Product.*` or another namespace.
- Empty claim conditions create a catch-all rule; there are no safe provider
  presets requiring immutable repository/project identity, protected ref, or
  deployment environment.
- There is no one-time token exchange/consumption model, `jti` replay ledger, or
  positive-verdict cache bounded by `jti` and expiry.
- Publication does not persist a provenance record linking package, issuer,
  subject, workflow/project, commit/ref, and policy rule.
- `iat`/`azp` and consistent `kid` policy remain incomplete.
- The repository's own CI has no artifact/image release workflow using
  `id-token: write`, provenance attestation, or keyless signing. Forge does not
  itself use trusted publishing for releases.

### Recommended completion design

1. Split interactive-login discovery from workload-verifier discovery. Accept
   the minimal issuer/JWKS metadata used by GitHub and GitLab workload tokens.
2. Provide reviewed issuer templates for GitHub Actions and GitLab CI. Express
   rules in immutable identifiers, require audience, repository/project ID,
   owner/group ID, protected ref or environment, and deny catch-all rules by
   default.
3. Verify `iss`, `aud`, `exp`, `nbf`, bounded `iat`, authorized party where
   applicable, signature algorithm, and `kid`. Constrain clock skew.
4. Prefer an exchange endpoint: validate the external ID token once and mint a
   very short-lived Forge publish credential containing repository, package
   pattern, allowed action, and external identity. If direct token use remains,
   add equivalent replay/cache controls.
5. Enforce package/action authorization after canonical package identity is
   parsed and before any mutation. This must share the same policy seam as
   human/token publishing.
6. Record immutable publish provenance and surface it in the package UI and
   audit API.
7. Add real GitHub/GitLab discovery fixtures and CI examples, including negative
   tests for forked repositories, wrong owner/project, wrong environment/ref,
   replay, future `iat`, missing `kid`, and out-of-scope package IDs.

Only after those acceptance criteria pass should the feature be labeled
trusted publishing rather than generic workload identity federation.

## Recommended feature roadmap

The highest-value work is not another package format yet. First make the
existing NuGet, authorization, storage, and workload-identity promises safe and
operable.

### Phase 0: release blockers and trust boundaries

1. Enforce package selectors on every read and mutation path.
2. Make CAS deletion/revival race-free.
3. Apply CSRF middleware to all cookie-authenticated mutations.
4. retire or exactly synchronize legacy RBAC; enforce `delete` separately;
   make group-cycle checks concurrency-safe.
5. Encrypt authentication-realm secrets and require safe production crypto.
6. Restore green CI and add regression tests for the above defects.

### Phase 1: production hardening

1. Finish trusted publishing with GitHub/GitLab presets, package binding,
   hardened claim validation, replay controls, and provenance.
2. Stream downloads and proxy ingestion; add timeouts, concurrency controls,
   and large-package load tests.
3. Add authentication/API rate limits and secure bootstrap configuration.
4. Add `/health/live`, `/health/ready`, metrics, request IDs, structured traces,
   worker supervision, backlog gauges, and SIGTERM drain.
5. Publish backup/restore, object/database consistency, migration, rollback,
   HA, secret-management, and disaster-recovery runbooks. Exercise restores.
6. Build and scan the production image in pull requests; publish signed,
   provenance-attested, SBOM-equipped release images on tags.

### Phase 2: operator and user experience

1. **RBAC console:** roles, grants, nested groups, repository/package selectors,
   user assignments, token scopes, WIF rules, and an effective-access simulator.
2. **Retention console:** policy editor, dry-run diff, maximum-delete guard, run
   now, progress, run history, failure details, audit, and recovery controls.
3. **User lifecycle:** activate/deactivate, password reset, external identities,
   group/role assignments, session revocation, and security-event history.
4. **Package lifecycle:** unlist/relist/hard-delete with confirmation, reason,
   policy checks, and audit records.
5. **Package analytics:** downloads, unique consumers where privacy permits,
   storage use, cache hit ratio, upstream latency/error health, top packages,
   and retention eligibility.
6. **Global discovery:** cross-repository search with repository/type filters and
   correct stable paging.
7. **Connect-to-feed experience:** copyable `dotnet nuget`/`nuget.exe` source,
   restore, and push commands; create a minimally scoped token in context.
8. **Complete NuGet metadata:** authors, description, README, tags, license,
   repository/commit URLs, deprecation, signature, provenance, and
   vulnerability state.
9. **Optional public browse:** reflect each repository's anonymous policy and
   apply the same package selectors as protocol endpoints.
10. **Unified audit log:** authentication, authorization changes, administration,
    publication, downloads where appropriate, unlist/delete, retention, and
    crypto operations.

### Phase 3: software-supply-chain features

1. NuGet signature verification and signer policy.
2. SBOM/provenance ingestion, display, and policy checks.
3. Vulnerability, malware, secrets, and license scanning with quarantine and
   operator override workflow.
4. Webhooks/event stream for publish, promote, delete, policy, and scan events.
5. Staged repository promotion (development -> candidate -> release) with
   immutable provenance and approvals.
6. Upstream health/mirroring controls and disaster-recovery replication.

### Phase 4: additional ecosystems

Add new formats only after the format boundary is exercised by a complete
second implementation. A sensible order depends on actual users:

- **npm** for broad web-application demand;
- **Cargo** to dogfood Forge for its own Rust ecosystem;
- **Maven** for enterprise JVM teams;
- **OCI artifacts** if Forge is intended to become a broader artifact platform.

Each format needs protocol conformance, immutable identity/version rules,
package-level authorization, proxy/cache semantics, retention integration,
metadata/search, signature/provenance behavior, and native-client E2E tests.

## Proposed 90-day sequence

| Window | Outcome | Exit criteria |
|---|---|---|
| Weeks 1-2 | Close release blockers | Selector HTTP matrix passes; concurrent blob revival cannot lose data; cookie mutation CSRF tests pass; default branch CI is green. |
| Weeks 3-5 | Close authorization/secret debt | Legacy RBAC has one authority; delete and nested-group concurrency are tested; realm secrets are encrypted and migratable; production defaults fail closed. |
| Weeks 6-8 | Make trusted publishing credible | GitHub and GitLab fixtures work; safe issuer templates and package binding are enforced; replay/provenance behavior is tested and documented. |
| Weeks 9-10 | Establish production operations | Health/readiness, metrics, worker status, SIGTERM drain, rate limits, backup/restore drill, and image release supply chain are in place. |
| Weeks 11-13 | Ship the highest-value UI | RBAC/effective-access and retention workflows are operable; user/package lifecycle gaps and admin deep links are fixed. |

Defer additional formats until these exit criteria hold for NuGet.

## Documentation and roadmap cleanup

The documentation currently obscures implementation status and contains several
contradictions:

1. All old implementation plans are still labeled draft/forward-looking; the
   Slice 1 checklist is unchecked even though the feature exists. Add a single
   `docs/ROADMAP.md` with `Implemented`, `Partial`, `Planned`, acceptance links,
   owner, and last-reviewed date. Mark old plans completed or superseded rather
   than rewriting historical design detail.
2. The original roadmap defines 12.7 as additional formats, while the later
   design reuses 12.7 for realms. Renumber or explicitly mark the newer roadmap
   as superseding the old sequence.
3. Retention UI ownership is contradictory: the retention plan delegates it to
   12.6 while the frontend plan puts it outside 12.6. Give it one owner and
   acceptance criteria.
4. Approved designs say PostgreSQL advisory locks are disallowed, older plans
   request them, and crypto workers actually use them. Document the real
   coordination policy and its exceptions.
5. Old OIDC/credential plans retain a private-address SSRF policy and
   `allow_private_upstream`, while the realms design intentionally replaced it
   with scheme-only validation. Mark the older sections superseded and remove
   the stale environment example.
6. [DEVELOPMENT.md](../DEVELOPMENT.md#L79) says browser authentication uses
   pasted tokens/local storage and no sessions, contradicting the current
   password/OIDC session model later in the same document.
7. The frontend plan says TanStack Start; the implementation is TanStack Router.
8. Browse comments still claim no download counters and null retention state as
   a Slice 1 limitation, even though retention later added counters.
9. The auth-realm migration says WIF rows are deferred and promises realm-secret
   encryption; WIF is live and encryption was not connected.
10. The README advertises content selectors as effective fine-grained access
    control. Until HTTP enforcement lands, qualify or remove that claim.
11. Add an operator/configuration reference, upgrade compatibility policy,
    API/authentication examples, trusted-publishing examples, `LICENSE`,
    `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and production limitations.

## Verification performed

| Check | Result |
|---|---|
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| Rust unit tests (`cargo test --workspace --lib --bins`) | Passed: 308 tests |
| TypeScript type check (`tsc --noEmit`) | Passed |
| Frontend unit tests (`vitest run`) | Passed: 13 files, 71 tests |
| Frontend production build (`vite build`) | Passed |
| Full local workspace integration run | Not completed: local Docker/testcontainer services were unavailable in this review environment |
| Local browser E2E | Not run; the current GitHub run was inspected instead |
| Current GitHub Actions run at reviewed HEAD | Failed overall: Rust/SQLx/frontend checks passed; container E2E exhausted disk and one web E2E selector failed |

The review combined source tracing, schema/config review, route-to-service
analysis, roadmap-to-code mapping, targeted test execution, frontend build
verification, and inspection of the current CI result. It was not a penetration
test, formal cryptographic audit, load test, browser accessibility audit, or
disaster-recovery exercise. Findings labeled as confirmed defects are based on
reachable code paths; feature recommendations are intentionally separated from
those defects.

## Final recommendation

Treat the next milestone as a **NuGet production-readiness release**, not a new
format release. Close selector enforcement and CAS deletion correctness first,
then finish session/RBAC/secret/WIF boundaries and operational readiness. Once
those are green, the project has a strong base for the operator UI,
supply-chain features, and additional ecosystems described above.
