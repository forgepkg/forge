# Changelog

All notable changes to envisia-forge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). While the major version is 0, a
minor release may contain breaking changes; each one is called out under
**Upgrade notes**.

The release workflow publishes the section whose heading matches the tag
(`## [0.1.0]` for `v0.1.0`) as the GitHub release notes.

## [Unreleased]

### Upgrade notes

- Migration 0021 rewrites existing usernames into canonical form. Accounts
  whose names differ only in case, surrounding spaces or Unicode composition
  are not merged: the oldest keeps the name, the others are renamed
  `<name>#<id>` and a warning names each one. Review and delete or rename
  them; their tokens keep working.
- A password sent over HTTP Basic no longer reaches the admin API or token
  minting, even for an administrator (403). Scripts that ran
  `curl -u admin:<password> …/admin/…` must sign in through `/auth/login`
  (session cookie + `X-CSRF-Token`) or use an admin-scoped token
  (`{"scope": {"actions": ["admin"]}}`, sent as the Basic password or
  `X-NuGet-ApiKey`). `cargo xtask seed` and DEVELOPMENT.md show both.
- Migration 0023 flags existing credential-forwarding accounts that have no
  realm (`realm_orphaned`): they can no longer be signed in by any realm.
  Delete such an account to let its owner's next upstream login provision a
  fresh one.

### Security

- Feed responses (`/v3/...`) are inert in a browser: every one carries
  `Content-Security-Policy: default-src 'none'; sandbox`,
  `Content-Disposition: attachment` and `nosniff`. Before, a published
  `.nuspec` was served as `application/xml` on the admin UI's origin, so an
  XHTML `<script>` in it ran with the viewer's session (stored XSS).
- The web UI is served with a real Content Security Policy: scripts only from
  the server's own origin plus the inline theme bootstrap, allowed by its
  SHA-256 hash (taken from the served `index.html` at startup); no `eval`,
  plugins, `<base>` or framing, and fetches only to the same origin.
- Usernames are canonical (trimmed, Unicode NFC, lowercased; empty names and
  control characters are refused) in every login path, the lockout, the
  credential cache, provisioning and admin user creation, with a unique
  index on the canonical form. Credential forwarding sends the canonical name
  upstream and signs in as exactly that account, so case or spacing variants
  can no longer split one upstream identity into several Forge accounts
  (or lockout budgets).
- Credential-forwarding realms take an optional `identity_path`: the account
  the upstream's JSON success response names must equal the username
  entered. Set it for upstreams that accept a secret with any username
  (GitHub, Azure DevOps or GitLab personal access tokens); without it such an
  upstream lets any token holder sign in as any user. A success without the
  field fails closed. The docs now state that the upstream must bind the
  username to the secret.
- Package ids in feed URLs are validated against the NuGet id grammar on
  every read and unlist/relist route (404 otherwise), and again before a
  proxy builds an upstream URL. A percent-encoded `..%2F`, `?` or `#` in an
  id could steer the proxy's credentialed upstream requests to other paths
  and queries of the upstream host, and planted bogus names in the proxy's
  version table.
- Redis is treated as a trust boundary: authorization sets, credential
  verdicts, OIDC discovery documents and key sets, and workload-identity
  verdicts are cached in each instance's memory only and never read from or
  written to Redis (which still relays their invalidations). Before, anyone
  able to write to Redis could plant an admin authorization set, mark a
  password valid or substitute an IdP signing key for every instance.
  `rediss://` (TLS) Redis URLs are now supported, and the deployment guide
  documents how to isolate Redis.
- The principal records how it authenticated (token, password over Basic,
  or browser session). The admin API accepts a session or an admin-scoped
  token, never a password replayed over Basic; minting tokens
  (`/admin/me/tokens`) takes a session. Before, the password a NuGet client
  stores and sends on every feed request — with credential forwarding, the
  directory password — was a full admin credential that could mint tokens
  outliving it. An admin-forced reauth (`POST /admin/users/{id}/reauth`) now
  also revokes the tokens a user minted from a credential-forwarding session.
- Deleting a credential-forwarding realm no longer lets another realm adopt
  its users: their missing realm was treated as a wildcard, so the next realm
  whose directory knew the same username took over the account with its
  roles and tokens. Such accounts are now flagged as orphans and never
  matched again.
- OIDC `link_existing_by_username` links only an account that no other
  credential owns: never a credential-forwarding account or one already
  linked to an IdP identity (before, a colliding `preferred_username` at the
  same or another IdP took it over). An email claim is used as a username
  only with `email_verified`, also when `username_claim` names it.
- Registration and search no longer fetch and re-parse every version's
  `.nuspec` per request (an unauthenticated CPU and storage amplifier on
  public feeds): the manifest summary is stored at publish (migration 0024;
  older versions are summarized once and backfilled), the registration index
  is paged (64 versions per page, inlined up to 128 versions, beyond that
  served from `/registration/{id}/page/{lower}/{upper}.json`), leaf and
  catalog documents look up one version instead of all, rendering runs on
  the blocking pool, and the `.nuspec` parser tracks `<metadata>` in O(1) and
  rejects nesting deeper than 32 levels (it was quadratic in depth).

## [0.1.0]

First production release.

### Features

- **NuGet V3 registry** with three repository kinds:
  - **hosted**: push, restore, unlist/relist and delete your own packages;
  - **proxy**: on-demand caching of an upstream V3 feed (nuget.org or a
    private feed with Basic/PAT credentials), with an optional publication
    delay and negative caching;
  - **group**: one feed URL over several members, by priority. A failing
    member is tolerated, and a dependency-confusion guard keeps public feeds
    from shadowing internal package ids.
- **Storage**: content-addressed blobs on any S3-compatible store; metadata in
  PostgreSQL; race-free garbage collection with an outbox and a reconciler.
- **Access control**: fine-grained RBAC with users, nested groups, roles,
  repository grants, and package/content selectors, enforced on every read
  and publish path. Tokens can be scoped per repository.
- **Authentication**: ordered, web-managed auth realms (local passwords,
  OIDC / Microsoft Entra, and credential forwarding to an existing registry),
  an identifier-first login, and API keys.
- **Trusted publishing**: CI jobs on GitHub Actions, GitLab CI and compatible
  issuers publish with their workload OIDC token, with no stored API key. See
  [docs/trusted-publishing.md](docs/trusted-publishing.md).
- **Retention**: policies with preview, run and audit, and download tracking.
- **Secret encryption at rest**: double-envelope encryption of upstream
  passwords and realm secrets, with key rotation and backfill.
- **Web UI**: browse, repository and package detail, self-service tokens, and
  administration of repositories, users, tokens and realms. It is served by
  the same process on the same origin.
- **Operations**: `/healthz`, `/readyz` and `/version`, graceful SIGTERM,
  supervised background workers, and an optional Redis L2 cache with
  cross-instance invalidation.
- **Release**: a signed container image with an SBOM and provenance
  attestation; see [docs/deployment.md](docs/deployment.md).

### Security

- CSRF protection on every cookie-authenticated mutation. In addition,
  cross-site browser mutations are refused (`Sec-Fetch-Site`/`Origin`), which
  also covers Basic credentials a browser cached from the feed's login prompt.
- An expired or revoked session cookie is cleared and treated as signed out,
  instead of blocking every page including the login.
- Removing the built-in `admin` role revokes admin rights, including for
  accounts that carry the legacy admin flag.
- The bootstrap admin is created once and stays deleted after removal, also
  for accounts that existed before that rule. Boot logs a security warning
  while the bootstrap account still accepts the placeholder password.
- Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Content-Security-Policy: frame-ancestors 'none'` and
  `Referrer-Policy: same-origin`.
- Startup refuses placeholder credentials. It warns about a non-https or
  loopback `public_base_url` and about disabled secret encryption.
- API tokens carry admin rights only when their scope lists `admin`
  (`{"actions": ["admin"]}`). An unscoped token of an admin can still push
  and restore, but gets 403 on `/admin/*`, so a leaked CI token cannot mint
  tokens or create admins.
- A group's `prefer_hosted` guard now decides over every hosted member,
  whether or not the caller can read it. A public package can no longer
  replace an internal id for anonymous or selector-scoped callers; they get
  404 instead.
- The login lockout is memory-bounded: usernames over 256 bytes are refused,
  entries have a fixed size and expire, and parallel guesses cannot outrun
  the lockout. Password hashing runs behind a bounded queue
  (`auth.password_verify_concurrency`).
- Credential forwarding holds no database connection during the upstream
  call, is bounded per realm (`auth.credential_forward_max_concurrent`),
  never follows redirects (any 3xx counts as "unavailable"), and now applies
  the realm's connect/request timeouts.
- Users can be deactivated (`PATCH /admin/users/{id}` with
  `{"active": false}`): their sessions and cached upstream verdicts are
  revoked and their tokens refused. Re-authentication also ends sessions.
- A proxy drops its stored upstream credentials when its `remote_url` moves
  to another origin, and credentials can now be cleared.
- Content-selector `PATCH` keeps fields it does not mention (it used to widen
  a selector to "every package"). Token scopes reject unknown fields, and
  token listings show each token's scope.
- `X-Forwarded-For` is read across all header lines, and IPv4-mapped IPv6
  peers match IPv4 CIDRs. Under `anonymous_mode = "allowlist"` the anonymous
  grant requires a `Host` matching `public_base_url` or `server.allowed_hosts`
  (DNS-rebinding guard).
- The proxy refuses upstream redirects and resolutions to link-local and
  cloud-metadata addresses, and serves an upstream `.nuspec` only if it names
  the requested package.
- Secret encryption: enabling it later now removes the plaintext copies, and
  key rotations are serialized (a second rotation answers 409) with
  compare-and-swap re-wrapping, so a race cannot strand keys.
- Config errors never echo secret values, and secret environment values are
  read verbatim.
- Release images are signed by digest before any tag points at them; the
  verification command pins the exact release workflow; actions and base
  images are pinned by digest; CI audits the Rust and shipped web
  dependencies, and Dependabot keeps them current. The RUSTSEC advisories in
  the AWS SDK's legacy HTTP stack are gone from the dependency tree.
- With `anonymous_mode = "all"`, signed-in users can read what anonymous
  callers can; under `off` and `allowlist` they hold only their own grants
  (the allowlist depends on the caller's network, which a signed-in user or
  token must not carry elsewhere).
- Unknown and federated usernames take the same time in the password chain,
  so response timing no longer reveals which upstream users exist.
- Allowlist and trusted-proxy entries written as IPv4-mapped IPv6
  (`::ffff:10.0.0.1`) match as the IPv4 address they denote.
- A cancelled admin key rotation can no longer leave the rotation lock held
  on a pooled connection.

### Fixed

- Overlapping hard deletes (admin or NuGet `DELETE`) and repository deletes
  decrement shared blobs exactly once; the losing request gets 404 and
  `blob.ref_count` can no longer go negative. Before, a retry could delete a
  blob another repository still served. Garbage collection also refuses to
  delete any blob an asset still names, repairing a drifted counter instead,
  and a redeploy that races a delete publishes the version afresh.
- Writers lock shared blob rows in one order, and a repository delete that
  Postgres aborts as a deadlock victim is retried.
- A repository delete is atomic with its emptiness check or proxy purge, and
  a publish racing garbage collection retries instead of failing.
- Retention: hosted-scope rules on a proxy repository are rejected (they
  broke restores); `keep_last_n` and `keep_n_most_downloaded` protect
  versions within each rule's own filters, and `keep_last_n` counts only
  listed versions; proxy eviction keeps the version's listing and
  `first_seen_at`; an unlist rule no longer re-touches unlisted versions; a
  panicking run is recorded as failed and releases its lease.
- Proxy: a "not found" marker hides a version only for `not_found_ttl` and is
  cleared when the upstream lists the version; a failed download no longer
  lists a phantom version; a missing local copy is fetched again;
  registration carries the upstream's dependency groups, listing state and
  publish date for versions not yet downloaded; a rejected package is not
  re-downloaded on every retry; rows created only by requests for versions
  the upstream never had are pruned after the not-found window.
- Large packages with big native payloads publish and proxy: size and ratio
  caps apply to the `.nuspec` only, the ZIP directory the reader will use is
  checked before parsing, and the limits are configurable under `[nuget]`.
- Package ids, search terms, selectors and retention prefixes are lowercased
  character by character like .NET's `ToLowerInvariant`, so ids with
  non-ASCII letters resolve as NuGet clients request them.
- Group search enriches only the page it returns.
- Nested-group depth counts the levels above the new member too.
- OIDC issuers whose identifier ends in `/` validate; concurrent first
  sign-ins for one identity resolve to one account, with no orphans or
  errors.
- Secret encryption: enabling it later removes plaintext copies only after
  checking the ciphertext holds the same password; a stale or undecryptable
  ciphertext is replaced from the plaintext instead.
- Boot warns about an account that still accepts the placeholder password
  `changeme` even when no bootstrap admin is configured.
- The Redis L1 cache is flushed on the first backplane subscription, so an
  instance that starts while Redis is slow does not serve stale entries.
- Interrupted multipart uploads are aborted. Garbage-collection tables are
  indexed, and processed outbox rows are pruned.
- Web UI: an expired session sends the user to the sign-in page instead of
  looping requests; admin pages work on refresh and from bookmarks;
  `index.html` is never cached and assets are immutable; sign-out clears
  cached data; lockouts and realm errors are shown; Back works on repository
  search; repository names are validated.

### Changed

- The admin UI lives under `/manage/*`. Browser navigations to the former
  `/admin/...` UI paths are redirected; the `/admin/*` API is unchanged.
- The image bakes no bootstrap admin: set
  `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` for the first start. Without a
  password no bootstrap admin is created (startup no longer fails).
- The image sets `allow_password_basic = false` (credential-forwarding realms
  still enable the wire Basic path) and runs as UID 10001.
- `FORGE_CONFIG` must name an existing file. A blank `FORGE_REDIS__URL`
  disables Redis. Secret environment values are never type-converted;
  surrounding whitespace and one pair of surrounding double quotes are
  removed, as before.
- Repository names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`; `new` is
  reserved.
- Repository updates: an absent field keeps its value, JSON `null` clears it.
- New settings: `auth.password_verify_concurrency`,
  `auth.credential_forward_max_concurrent`, `server.allowed_hosts`,
  `outbox.processed_retention_seconds`, and the `[nuget]` archive limits.
  New endpoints: `PATCH /admin/users/{id}` and
  `GET`/`PUT /admin/settings/legacy-open-access`.

### Upgrade notes

- This is the first release; install it on an empty database.
- Installs that ran pre-release builds: on the first start, the legacy RBAC
  mapping runs once more. On a database that already had users when
  migration 0007 ran (`legacy_open_access = true`), that assigns the built-in
  `authenticated` role (read and write on every repository) to every
  existing user again, re-adds the `admin` role for accounts with the legacy
  admin flag, and re-adds anonymous-read grants for repositories with
  `anonymous_read` set, including grants revoked since migration 0007.
  Review role assignments after upgrading, and switch legacy open access off
  with `PUT /admin/settings/legacy-open-access {"enabled": false}` so new
  users are no longer given `authenticated`. Migration 0011 changes the
  storage protocol; the upgrade procedure is in
  [DEVELOPMENT.md](DEVELOPMENT.md).
- Pre-release installs, continued: migration 0017 adds
  `CHECK (ref_count >= 0)` and leaves it `NOT VALID` with a warning if a
  blob's count has already drifted below zero; migration 0019 re-lowers
  package ids with non-ASCII capitals. Migration 0017 builds its indexes
  without `CONCURRENTLY`, which briefly blocks writes on large tables.
- A stored retention policy with hosted-scope (or scope-less) rules on a
  proxy repository now fails every run until it uses `"scope":
  "proxy_cached"`. Preview other policies after upgrading: protections now
  follow each rule's own filters.
- Automation that calls `/admin/*` with an unscoped token must use a token
  scoped `{"actions": ["admin"]}`.
- With `anonymous_mode = "allowlist"`, preserve the `Host` header at the
  reverse proxy (`proxy_set_header Host $host`) or list the names clients
  use in `server.allowed_hosts`.
- Pre-release installs: a repository whose `anonymous_read` was switched off
  *before* this upgrade may still carry its synthesized anonymous read grant
  (only switches made from now on remove it). Check
  `GET /admin/anonymous/effective` and delete grants you did not intend.
- Pre-release installs on a database whose `LC_CTYPE` is `C` (the
  CloudNativePG default): Postgres cannot lowercase non-ASCII letters there,
  so migration 0019 leaves package ids with non-ASCII capitals as they were;
  delete and re-push such packages.

### Known limitations

- NuGet is the only package format.
- Trusted publishing uses the direct-token model: the workload token is
  accepted until it expires; there is no exchange for a short-lived Forge
  token and no single-use `jti` ledger.
- Browser OIDC login validates `iss`, `aud`, `exp`, `nbf`, signature and nonce
  but not `iat` or `azp`.
- Rate limiting is limited to a per-instance, in-memory lockout after failed
  passwords. There is no limit on `/auth/identify`, token creation or
  workload-token failures.
- Secret encryption is optional (plaintext without a `[crypto]` section).
  Only the env/file root-key providers exist; AWS KMS is not supported yet.
- A proxy fetches a new package version once per instance. Several instances
  that miss the same version at the same time each download it.
- A group's search is capped at 1,000 results per member, so totals and
  paging are exact only below that.
- Retention has no per-run delete cap.
- No metrics endpoint, request IDs or JSON log output. Shutdown drains
  in-flight requests without a deadline.
- The web UI requires sign-in, even for repositories that allow anonymous
  reads; NuGet clients can still read those anonymously.
- There is no web console yet for RBAC roles and grants, retention, user
  deactivation or key rotation; use the `/admin` API.
- CI does not scan the container image for OS-package vulnerabilities.

[Unreleased]: https://github.com/schmitch/repo/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/schmitch/repo/releases/tag/v0.1.0
