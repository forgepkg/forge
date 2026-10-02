# Changelog

All notable changes to envisia-forge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). While the major version is 0, a
minor release may contain breaking changes; each one is called out under
**Upgrade notes**.

The release workflow publishes the section whose heading matches the tag
(`## [0.1.0]` for `v0.1.0`) as the GitHub release notes.

## [Unreleased]

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
  images are pinned by digest; CI scans dependencies. The RUSTSEC advisories
  in the AWS SDK's legacy HTTP stack are gone from the dependency tree.

### Fixed

- Overlapping hard deletes (admin or NuGet `DELETE`) and repository deletes
  decrement shared blobs exactly once; the losing request gets 404 and
  `blob.ref_count` can no longer go negative. Before, a retry could delete a
  blob another repository still served.
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
  re-downloaded on every retry.
- Large packages with big native payloads publish and proxy: size and ratio
  caps apply to the `.nuspec` only, the ZIP directory is checked before
  parsing, and the limits are configurable under `[nuget]`.
- Package ids and search terms are lowercased with full Unicode rules, as
  NuGet clients do.
- Group search enriches only the page it returns.
- Nested-group depth counts the levels above the new member too.
- Signed-in users can read repositories that anonymous users can read.
- OIDC issuers whose identifier ends in `/` validate; two concurrent first
  sign-ins no longer create an orphan account.
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
  disables Redis.
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

[Unreleased]: https://github.com/schmitch/repo/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/schmitch/repo/releases/tag/v0.1.0
