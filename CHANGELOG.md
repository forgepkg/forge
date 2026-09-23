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
- The bootstrap admin is created once and stays deleted after removal.
- Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Content-Security-Policy: frame-ancestors 'none'` and
  `Referrer-Policy: same-origin`.
- Startup refuses placeholder credentials. It warns about a non-https or
  loopback `public_base_url` and about disabled secret encryption.

### Upgrade notes

- This is the first release; install it on an empty database.
- Installs that ran pre-release builds: on the first start, the legacy RBAC
  mapping runs once more. That re-adds admin roles for accounts with the
  legacy admin flag, and anonymous-read grants that were revoked since
  migration 0007. Review role assignments after upgrading. Migration 0011
  changes the storage protocol; the upgrade procedure is in
  [DEVELOPMENT.md](DEVELOPMENT.md).

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

[Unreleased]: https://github.com/schmitch/repo/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/schmitch/repo/releases/tag/v0.1.0
