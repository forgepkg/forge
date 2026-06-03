# envisia-forge — Auth realms, identifier-first login, WIF, + small items (design)

**Date:** 2026-06-03
**Status:** Draft for review
**Builds on:** slice 12.2 (OIDC), 12.3 (credential-forwarding), 12.4 (RBAC — in flight), 12.6 (frontend).
**Sequencing:** lands AFTER 12.4 RBAC merges + the `feat/pnpm-web` merge + the just/mprocs tooling consolidation, because it refactors the auth system that 12.4 is currently reworking.

## 1. Goal & decisions

Generalize the auth system into a first-class, **ordered, web-configurable set of "auth realms"**, add an **identifier-first login UX**, add a **workload-identity-federation (WIF)** realm, an **optional CAS conditional-write optimization**, and **remove `allow_private_upstream`** (dropping the SSRF restriction).

User-confirmed decisions:
- **Conditional writes:** add an *optional* `If-None-Match: *` optimization to the CAS, feature-detected per S3 backend; **fall back** to current behavior when unsupported (e.g. versitygw). CAS correctness does not depend on it (content-hash keys make parallel identical writes idempotent; proxy already singleflights).
- **SSRF:** **drop the restriction entirely** — outbound proxy/auth-upstream connections enforce only `http`/`https` scheme; no private-range blocking, no `allow_private_upstream` column/flag.
- **Login UX:** identifier-first by default; admin-configurable to always show the username/password form with OIDC realms as buttons.
- **WIF:** ship the realm framework + config UI + login UX first (slice **12.7**), then the WIF realm (slice **12.8**).
- Proxy repositories **keep** optional `upstream_username` / `upstream_password` (unchanged).
- OIDC realms prefer the **`preferred_username`** claim for the display/username mapping.

## 2. Decomposition

| Slice | Scope |
| --- | --- |
| **12.7 Auth realms + login UX** | Realm framework (DB-backed, ordered, web-managed) generalizing local/oidc/credential-forwarding; identifier-first login UX + toggle; OIDC `preferred_username`; remove `allow_private_upstream` + drop SSRF restriction; CAS optional conditional-write. |
| **12.8 WIF realm** | Workload-identity-federation realm: validate a presented `id_token` against multiple trusted OIDC issuers (`.well-known/openid-configuration` → JWKS); map claims → workload principal/role. |

(12.7 also folds in the two small items so they ship with the auth rework they relate to.)

## 3. Auth-realm model (slice 12.7)

### 3.1 Concept
An **auth realm** is a configured authentication mechanism with an order/priority. Today's auth (local password, OIDC, credential-forwarding) becomes realm *instances*. Realms are rows in the DB, edited via the admin UI; no redeploy to add/reorder a realm.

Realm `kind`s in 12.7:
- **`local`** — username/password against `app_user` (argon2). Always implicitly present; a row controls whether it's enabled/where it sits in the order.
- **`oidc`** — interactive browser OIDC (12.2 flow). Config: issuer/discovery URL, client id/secret (encrypted via 12.5 once it lands; redacted until then), scopes, the claim used as username (default `preferred_username`), group/role claim → admin/role mapping, button label.
- **`credential_forwarding`** — forward the username+password (from HTTP Basic *or* the login form) to a configured **upstream IdP URL via HTTP Basic** (the 12.3 `UpstreamBasicProvider` + validated-credential cache). Config: upstream URL, success criteria, timeouts, optional required group, auto-provision.

### 3.2 Schema (migration `00NN_auth_realms.sql`)
- **`auth_realm`**: `id`, `kind` (`local`|`oidc`|`credential_forwarding`|`workload_identity` [12.8]), `name` (unique, display + slug), `enabled bool`, `priority int` (unique; order in which realms are tried/listed), `config jsonb` (kind-specific; secrets redacted from API, encrypted at rest once 12.5 lands), `created_at`, `updated_at`.
- Migrate existing config: the 12.2 `oidc` config and 12.3 credential-forwarding config become seeded `auth_realm` rows on upgrade (data migration); a built-in `local` realm row is seeded. Fresh installs seed `local` only.
- `app_user.auth_source` (from 12.3) gains values matching realm kinds; an `app_user.realm_id` link is optional (provenance).

### 3.3 Credential resolution (server)
The existing ordered `PrincipalSource`/`AuthProvider` chain (12.3) is **driven by the realm table** instead of static config:
- HTTP Basic / `X-NuGet-ApiKey` password path → try realms in `priority` order: `local` (argon2), then each `credential_forwarding` (cached), etc.; first success wins; invalid → 401 (never downgrade). (12.8 adds: if the presented secret is a JWT, try `workload_identity` realms.)
- Token (repository token) path unchanged (always available).
- Session cookie (OIDC) path unchanged.
- **No SSRF guard** on the credential-forwarding upstream URL beyond scheme check (per decision).

### 3.4 Identifier-first login UX (frontend + a small API)
- New endpoint `POST /auth/identify { username }` → returns the realm decision for that identifier: `{ mode: "password" | "oidc_redirect", realm, oidc_authorize_url? }`. Resolution: if the username matches a local/credential-forwarding realm → `password`; if it maps to an OIDC realm (by configured domain/hint or an explicit per-realm rule) → `oidc_redirect`. Ambiguous/unknown → default to `password` against the ordered password realms.
- **UX A (default, identifier-first):** screen 1 = username → call `/auth/identify` → screen 2 = password field, *or* redirect to the OIDC authorize URL.
- **UX B (toggle `auth.login_form = always`):** single screen — username+password fields always shown + a button per enabled OIDC realm (`Login with <name>`). No identify step.
- Config flag `auth.login_mode` = `identifier_first` (default) | `combined`.
- OIDC realms display using `preferred_username` after login.

### 3.5 Admin UI (frontend)
A "Authentication" admin section: list realms (ordered, drag/up-down to reorder = set `priority`), enable/disable, create/edit per-kind config forms (OIDC: issuer/client/secret/claims/button label; credential-forwarding: upstream URL/criteria/timeouts/auto-provision), delete. Secrets are write-only + redacted. Reuses the slice-1 admin REST + RBAC admin gating.

### 3.6 Remove `allow_private_upstream` + drop SSRF (slice 12.7, small)
- Drop the `repository.allow_private_upstream` column (migration) and the `allow_private_upstream` field from the credential-forwarding/proxy config + admin DTOs.
- `forge_core::net::ssrf`: keep only the **scheme check** (`http`/`https`); remove the private/loopback/link-local IP blocking and the `allow_private` plumbing (proxy fetch + auth upstream + redirect re-validation simplify to scheme-only). Update the proxy + upstream-basic call sites and their tests (the "private address rejected" e2e becomes "scheme rejected"/removed).

### 3.7 CAS optional conditional-write (slice 12.7, small)
- `forge_storage::BlobStore`: add `put_if_absent` variant that uses `If-None-Match: *` when the backend advertises support; **feature-detect** at startup (a probe PUT, or a config flag `s3.conditional_writes = auto|on|off`, default `auto`). On `412 Precondition Failed` treat as "already present" (dedup hit). On a backend without support (versitygw) fall back to the current HEAD-then-PUT. Pure optimization; behavior identical either way. Tests cover both code paths (a fake S3 returning 412 vs. not).

## 4. WIF realm (slice 12.8)

### 4.1 Concept
A **non-interactive** realm for CI/automation: a workload (e.g. a GitLab CI job) presents its OIDC `id_token` (a JWT) and forge authenticates it by validating the JWT against a configured **trusted issuer**, mapping claims to a workload principal with scoped permissions. No password ever exists.

### 4.2 How the token arrives (NuGet)
NuGet's wire auth is Basic; native Bearer in cred providers is an open request. So forge accepts the `id_token` via any of: the Basic **password**, `X-NuGet-ApiKey`, or `Authorization: Bearer`. The realm activates when the presented secret **parses as a JWT** (3 base64url segments) and its `iss` matches a configured trusted issuer. (A client-side NuGet credential provider that auto-fetches the workload token is optional, documented polish — not required; CI can pass `$GITLAB_OIDC_TOKEN` as the password.)

### 4.3 Schema / config
`auth_realm` rows of kind `workload_identity`, each: `issuer` (discovery base; JWKS via `.well-known/openid-configuration`), `allowed_audiences` (list), and an **authorization mapping**: a set of claim-match rules (e.g. GitLab `project_path`, `namespace_path`, `sub`, `ref`, `ref_protected`) → a forge role / set of permissions, plus an optional auto-provisioned synthetic principal. **Multiple issuers** supported (GitLab, GitHub Actions, etc.), each its own realm row. Stores no secret (public JWKS).

### 4.4 Validation
Reuse 12.2's JWKS-fetch+cache + JWT verifier: validate signature against the issuer JWKS (cached, kid-rotation), `iss`, `aud` ∈ allowed_audiences, `exp`/`nbf`/`iat`, optional `azp`. Then evaluate the claim-match rules → principal + RBAC role/permissions (12.4). Cache positive verdicts briefly (token `jti`/`exp`-bounded) to avoid re-validating every request, like the 12.3 cred cache. Replay/`exp` honored. No interactive session is created (stateless per-request principal).

### 4.5 Authz
The workload principal is granted the role(s) the matched rule specifies (via 12.4 RBAC). Default deny if no rule matches. Per-issuer + per-rule, so "GitLab project group/foo on protected ref → push to repo X" is expressible.

## 5. Testing

**12.7:** realm CRUD + ordering; credential resolution tries realms in priority order (first-success, invalid→401); identifier-first `/auth/identify` (password vs oidc_redirect); `combined` login mode; OIDC `preferred_username` mapping; data-migration of existing OIDC/cred-forwarding config into realm rows; `allow_private_upstream` removed + SSRF reduced to scheme-only (proxy still works to a public mock; a non-http scheme rejected); CAS conditional-write both paths (412 → dedup hit; fallback). Frontend: realm admin screens, identifier-first + combined login flows (Vitest + Playwright). All on the testcontainers harness.

**12.8:** validate a mock-issuer `id_token` (signed by a mock JWKS) presented as Basic password / apikey / bearer → workload principal with the mapped role; wrong `aud`/`iss`/expired/`bad-signature` rejected; multiple issuers; claim-rule → role mapping (allow + default-deny); positive-verdict caching; e2e: a simulated CI job pushes/restores using only an `id_token`.

## 6. Cross-cutting constraints (unchanged)
- **No Postgres advisory locks** anywhere (row locks / `ON CONFLICT` / `SKIP LOCKED`).
- Multi-instance: realm config, sessions, verdict caches all in Postgres/Redis (no in-memory-only state); JWKS via the cache crate.
- sqlx compile-time macros + committed `.sqlx`; `SQLX_OFFLINE` build green; clippy `--all-targets` green.
- Secrets (OIDC client secret, etc.) redacted from APIs now; encrypted at rest once **12.5** lands.

## 7. Out of scope / later
- A bundled client-side NuGet credential provider package (doc the "pass id_token as password" approach instead).
- SAML / non-OIDC federation.
- 12.5 double-envelope encryption (separate slice) will wrap realm secrets.
