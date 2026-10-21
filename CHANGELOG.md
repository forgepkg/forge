# Changelog

All notable changes to envisia-forge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/): breaking changes come only in a
major release, and each one is called out under **Upgrade notes**.

The release workflow publishes the section whose heading matches the tag
(`## [1.0.0]` for `v1.0.0`) as the GitHub release notes.

## [Unreleased]

Fixes for the findings of the 1.0.0 release review. The 1.0.0 known
limitations still apply, except where an entry below says otherwise.

### Upgrade notes

- Startup refuses a `server.staging_dir` that does not belong to Forge's
  user, or that group or others can write unless it is sticky like `/tmp`.
  The container image and the Kubernetes manifests are not affected.
  ([#127](https://github.com/schmitch/forge/issues/127))
- Durations above 100 years (`outbox.grace_seconds`,
  `retention.default_run_interval_seconds`, `retention.lease_seconds`,
  `crypto.cache.unwrapped_key_ttl_secs`,
  `crypto.rotation.dek_max_age_days`, `crypto.rotation.kek_max_age_days`)
  fail validation instead of panicking later.
  ([#128](https://github.com/schmitch/forge/issues/128))
- Migration 0032 deletes grants of the `admin` action on a single
  repository, which never had an effect, and the grants API refuses them
  with 400. Administration stays global.
  ([#124](https://github.com/schmitch/forge/issues/124))
- While a credential-forwarding realm is enabled, an account that an OIDC
  realm provisions is named `<claim>@<realm>`. Existing accounts keep their
  names. ([#123](https://github.com/schmitch/forge/issues/123))
- Proxy search now calls the upstream's search service, which may live on
  another host than the feed (on nuget.org, `azuresearch-*.nuget.org`).
  Where outbound traffic is restricted, allow that host, or proxy search
  keeps answering from the cache only.
  ([#112](https://github.com/schmitch/forge/issues/112))
- The production kustomize overlay adds a NetworkPolicy that admits only
  the ingress controller's namespace (set it in the overlay), and the Helm
  chart renders one as soon as `networkPolicy.from` lists a peer.
  ([#129](https://github.com/schmitch/forge/issues/129))
- Helm: the first upgrade rolls the Forge pods (when `secretEnv` is set)
  and restarts the in-cluster Redis once, because the checksum annotations
  are now salted. ([#133](https://github.com/schmitch/forge/issues/133))
- The published `cosign verify` commands also pin the tagged commit and the
  push trigger; use the commands of the release you verify.
  ([#130](https://github.com/schmitch/forge/issues/130))

### Features

- **Format plugins** (preview): further package formats as sandboxed
  WebAssembly components (the `forge:format@0.1.0` WIT contract, run by
  Wasmtime), served under `/repository/{repo}/` with the same storage,
  RBAC and package selectors, hosted and group repositories, retention and
  audit log as NuGet. Plugins are loaded from `[plugins]` only when pinned
  by SHA-256; each call runs with fuel, memory and time limits and no WASI
  capabilities. The first one, **Helm chart repositories** (`plugins/helm`),
  serves `index.yaml`, chart downloads and ChartMuseum-compatible push,
  delete and listing. `GET /admin/formats` lists the installed formats; the
  web UI offers them when creating a repository. See
  [docs/format-plugins.md](https://github.com/schmitch/forge/blob/main/docs/format-plugins.md).

### Fixed

- Proxy and group search find packages nobody has restored through Forge
  yet: a proxy forwards the search to its upstream's search service,
  applies the caller's package filter, not-found markers and the package
  delay, and answers from its cache when the upstream search fails. The
  browse UI keeps listing what Forge holds.
  ([#112](https://github.com/schmitch/forge/issues/112))
- A proxy pointed back to its previous upstream within the metadata TTL
  served empty version listings.
  ([#105](https://github.com/schmitch/forge/issues/105))
- A proxied package id's casing could flip between reads; it is the
  newest version's, as on nuget.org.
  ([#108](https://github.com/schmitch/forge/issues/108))
- The package delay held back old unlisted upstream versions, such as ones
  a lockfile pins, for the whole delay. They now count from when the
  upstream created them, and old versions of large packages are dated at
  their first sighting too.
  ([#111](https://github.com/schmitch/forge/issues/111))
- A push with a version longer than 64 characters answered 500; it is
  refused with 400. ([#134](https://github.com/schmitch/forge/issues/134))
- An offline nested group was still served through its outer group; it now
  fails like an offline hosted member.
  ([#106](https://github.com/schmitch/forge/issues/106))
- When a group was reachable along two paths, a guard on one path hid
  packages the other path admits.
  ([#107](https://github.com/schmitch/forge/issues/107))
- Downloads are counted in memory and written in batches every few
  seconds. A burst of downloads of one version no longer queues on its row
  and holds every database connection.
  ([#119](https://github.com/schmitch/forge/issues/119))
- Creating a missing S3 bucket failed on AWS outside us-east-1, and a
  bucket name owned by another account counted as created.
  ([#113](https://github.com/schmitch/forge/issues/113))
- Unknown paths under `/admin`, `/auth`, `/browse` and `/v3` answered 200
  with the web UI's page; they answer 404.
  ([#121](https://github.com/schmitch/forge/issues/121))
- `PUT /admin/realms/order` answered 500 when it raced another realm
  change; it answers 409. ([#117](https://github.com/schmitch/forge/issues/117))
- The browse API served offline hosted and group repositories; it answers
  503 like the feed, and the web UI says the repository is offline.
  ([#120](https://github.com/schmitch/forge/issues/120))
- A failed OIDC sign-in ended on a plain-text page; it returns to the
  login page with a message and a way to try again.
  ([#109](https://github.com/schmitch/forge/issues/109))
- Web UI: a proxy's version times are labelled "Cached", not "Published"
  ([#110](https://github.com/schmitch/forge/issues/110)); disabling a
  sign-in realm asks first
  ([#104](https://github.com/schmitch/forge/issues/104)); unflagging a
  group's last owner and removing a member ask first
  ([#122](https://github.com/schmitch/forge/issues/122)); the user list
  shows how each user signs in
  ([#123](https://github.com/schmitch/forge/issues/123)).

### Security

- Behind an outbound `HTTP(S)_PROXY`, a proxy refuses an upstream host
  name that resolves to a link-local or cloud-metadata address, and checks
  every redirect hop the same way.
  ([#125](https://github.com/schmitch/forge/issues/125))
- Forged Redis invalidations can no longer grow every instance's memory:
  the invalidation bookkeeping is bounded.
  ([#126](https://github.com/schmitch/forge/issues/126))
- The staging directory is private to Forge's user, and a staged package
  is parsed and uploaded from the file that was hashed, not reopened by
  name. ([#127](https://github.com/schmitch/forge/issues/127))
- An OIDC-provisioned account can no longer take a credential-forwarding
  user's username. ([#123](https://github.com/schmitch/forge/issues/123))
- Only the ingress proxies can reach Forge when it trusts
  `X-Forwarded-For` from a pod network (NetworkPolicy, see above).
  ([#129](https://github.com/schmitch/forge/issues/129))
- Release: every `cosign verify` pins the tagged commit
  ([#130](https://github.com/schmitch/forge/issues/130)); re-running a
  release reuses what it already pushed instead of moving the tags to a
  new build ([#131](https://github.com/schmitch/forge/issues/131)); the
  build helpers and the dependency images are pinned by digest
  ([#132](https://github.com/schmitch/forge/issues/132)); the Helm
  checksum annotations are salted
  ([#133](https://github.com/schmitch/forge/issues/133)).

### Documentation

- The deployment guide lists the S3 permissions and the PostgreSQL role
  Forge needs, and an S3 delete that is denied names the missing
  `s3:DeleteObject`. ([#114](https://github.com/schmitch/forge/issues/114))

### Known limitations

- With a package delay, proxy search shows a version only once the proxy
  has recorded it and the delay has passed, because a search answer names
  no publish times. Totals of a proxy search are the upstream's, less the
  ids dropped from the returned page.
- Behind an outbound proxy, a host name that resolves differently for the
  proxy than for Forge, or that only the proxy can resolve, still gets
  past the metadata guard; block those addresses on the proxy as well.
- Format plugins have no proxy repositories, receive no request bodies
  other than the published package (which must be the whole body or one
  multipart part), accept only Basic credentials, serve whole package
  downloads (no `Range` requests), and treat a version with a `-` as a
  prerelease; a response of a plugin may load at most 2,048 query answers.

## [1.0.0]

First production release. envisia-forge is dual-licensed under the GNU AGPL
v3 (`AGPL-3.0-only`, see `LICENSE`) or the envisia license, at the user's
choice. Install it on an empty PostgreSQL database;
[docs/deployment.md](https://github.com/schmitch/forge/blob/main/docs/deployment.md)
lists the required settings.

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
  [docs/trusted-publishing.md](https://github.com/schmitch/forge/blob/main/docs/trusted-publishing.md).
- **Retention**: policies with preview, run and audit, and download tracking.
- **Secret encryption at rest**: double-envelope encryption of upstream
  passwords and realm secrets, with key rotation.
- **Web UI**: browse, repository and package detail, self-service tokens, and
  administration of repositories, users, tokens and realms. It is served by
  the same process on the same origin.
- **Local blob cache** (optional, `[blob_cache]`): a copy of downloaded and
  pushed blobs on a local disk, sized from the disk (`max_bytes = "auto"`)
  or fixed, with FIFO eviction that survives a restart. Hot downloads skip
  S3, concurrent misses of one blob share a single S3 read, and cached
  packages keep resolving while S3 is unreachable: uncached downloads and
  pushes then answer 503 with `Retry-After` at once (a circuit breaker),
  `/readyz` stays 200 and reports the object store `degraded`, and an
  instance starts without S3. With the cache, package downloads also answer
  `Range` requests. Statistics at `GET /admin/blob-cache`; Kubernetes
  components `local-cache` (emptyDir) and `local-cache-persistent` (a
  PersistentVolume). See
  [docs/deployment.md](https://github.com/schmitch/forge/blob/main/docs/deployment.md#local-blob-cache).
- **Operations**: `/healthz`, `/readyz` and `/version`, graceful SIGTERM,
  supervised background workers, an audit log of every package change and
  admin action (the `forge::audit` log target), and an optional Redis L2
  cache with cross-instance invalidation.
- **Container image**: signed with cosign, with a provenance attestation and
  an SBOM that lists the Debian packages, Rust crates and npm packages it
  ships. The image carries `LICENSE` and the third-party notices in
  `/usr/share/doc/forge/`. Each release's notes print the exact
  verification command.
- **Kubernetes manifests** in `deploy/kubernetes`: a kustomize base for the
  server, components for an Ingress or Gateway API HTTPRoute, in-cluster
  Redis, PostgreSQL and S3 (versitygw), two replicas with a
  PodDisruptionBudget, and following `:latest`; plus a production and an
  evaluation overlay. The base pins the image to the release it is tagged
  with.
- **Helm chart** in `deploy/helm/forge`, published with every release to
  `oci://ghcr.io/schmitch/charts/forge` (same version as the image, signed
  with cosign, and attached to the GitHub release). The published chart pulls
  the release image by the digest the release workflow signed. Forge's whole
  configuration is settable as `config` (rendered to `forge.toml`), secrets
  through a chart-managed (`<fullname>-secret-env`) or existing Secret;
  routing through a Gateway API HTTPRoute and an optional ListenerSet (plus
  a cert-manager Certificate); PodDisruptionBudget, HorizontalPodAutoscaler,
  NetworkPolicy and `extraObjects`; and optional in-cluster PostgreSQL,
  Redis and versitygw dependencies.

### Security

**Signing in**

- Passwords are verified behind a bounded queue
  (`auth.password_verify_concurrency`). A memory-bounded login lockout
  refuses usernames over 256 bytes, keys IPv6 clients by their /64, and backs
  off a username guessed from many networks, except from networks it signed
  in from in the last 30 days. Unknown and federated usernames take the same
  time, so response timing does not reveal which accounts exist.
- Usernames are canonical (trimmed, Unicode NFC, lowercased) in every login
  path, the lockout, provisioning and admin user creation. Empty names,
  control characters and `:` are refused.
- Browser sessions: a CSRF token on every cookie-authenticated mutation, and
  cross-site browser mutations are refused (`Sec-Fetch-Site`/`Origin`),
  which also covers Basic credentials a browser cached from the feed's login
  prompt. On https the session and OIDC flow cookies carry the `__Host-`
  prefix, and a request that carries either cookie twice is not
  authenticated by it. An expired or revoked session cookie is cleared.
- OIDC login uses the authorization-code flow with PKCE (S256), a nonce and
  a flow bound to the browser. Only RSA signatures are accepted, and `iss`,
  `aud`, `exp` and `nbf` are checked. Discovery, key-set and token requests
  use https and follow no redirects. A realm can require claims
  (`required_claims`, e.g. a tenant id), an email claim becomes a username
  only with `email_verified`, `link_existing_by_username` never takes over
  an account another credential owns, and a realm's client secret is dropped
  when its `issuer` or `client_id` changes. Login starts are rate-limited per
  client network (`auth.oidc_login_starts_per_minute`).
- Credential forwarding requires https unless the upstream is a loopback
  address or the realm sets `allow_http`. It follows no redirects, ignores
  `HTTP(S)_PROXY`, holds no database connection during the upstream call,
  and is bounded per realm (`auth.credential_forward_max_concurrent`) and by
  the realm's timeouts. Set `identity_path` for upstreams that accept a
  secret under any username (GitHub, Azure DevOps or GitLab personal access
  tokens): without it, any token holder can sign in as any user. Forge sends
  the canonical, lowercased username, so an upstream that compares names
  case-sensitively (an htpasswd file, for example) must know its users in
  lowercase. Names that Unicode compatibility normalization (NFKC) would
  change, or that hold invisible characters, are never forwarded.
- The users of a deleted credential-forwarding realm are never adopted by
  another realm. Upstream and IdP admin-group verdicts apply in both
  directions, and a demotion ends the user's browser sessions.
- Users can be deactivated (`PATCH /admin/users/{id}` with
  `{"active": false}`): their sessions and cached verdicts are revoked and
  their tokens refused. A forced re-authentication
  (`POST /admin/users/{id}/reauth`) ends their sessions and revokes the
  tokens they minted from a credential-forwarding session. The last active
  administrator cannot be removed, and the last enabled realm people sign in
  with interactively cannot be disabled or deleted.
- The bootstrap admin is created once and stays deleted after removal. Boot
  logs a security warning while it still accepts the placeholder password.
  Startup refuses placeholder credentials, including a secret that still
  holds a `<…>` placeholder of the example env files, and warns about a
  non-https or loopback `public_base_url` and about disabled secret
  encryption.

**Tokens and the admin API**

- The admin API accepts a browser session or an admin-scoped token
  (`{"actions": ["admin"]}`), never a password sent over Basic, and minting
  tokens (`/admin/me/tokens`) takes a session. An unscoped token of an admin
  can push and restore but gets 403 on `/admin/*`, so a leaked CI token
  cannot mint tokens or create admins. An administrator's password still
  signs in through `/auth/login`: give administrators an OIDC realm, and
  NuGet clients tokens.
- An expired or revoked API token, or one of a deactivated user, sent as the
  Basic password is refused and never tried as a password. A token typed
  into the web login's password field is refused the same way, live or not.
- Admin request bodies refuse unknown fields (422 naming the field), and a
  realm's `config` refuses unknown keys (400), as do the `[oidc]` and
  `[auth.upstream_basic]` config sections that seed realms (at startup), so
  a typo never falls back to an unsafe default. Token listings show each
  token's scope.
- Every package change (push, redeploy, unlist, relist) and every admin
  change is logged at INFO under the `forge::audit` target with the
  principal's ids.

**Reading and publishing**

- RBAC applies on every feed, browse and admin path. A repository name that
  does not exist answers like one the caller may not read (401 or 403), so
  names cannot be enumerated.
- With `anonymous_mode = "all"`, signed-in users can also read what
  anonymous callers can; under `off` and `allowlist` they hold only their own
  grants. Under `allowlist`, the anonymous grant requires a `Host` that
  matches `public_base_url` or `server.allowed_hosts` (a DNS-rebinding
  guard), so the reverse proxy must preserve the `Host` header.
  `X-Forwarded-For` is honoured only from `auth.trusted_proxy_cidrs`, and a
  malformed hop leaves the client unknown, never allowlisted.
- With `allow_redeploy` on, replacing an existing version needs the delete
  permission as well as write, so a push-only token cannot overwrite a
  released version.
- Groups guard against dependency confusion: `prefer_hosted` decides over
  every hosted member, whatever the caller can read; ids under
  `reserved_prefixes` are never served from a proxy member; and once a group
  flags owner members, only owners claim ids. A nested group keeps its own
  guards when it is read through an outer group.
- Packages are read the way NuGet reads them: exactly one `.nuspec` at the
  package root, found with percent-decoded entry names and `\` as a
  separator, and one `<id>` and `<version>`. Archives with repeated entry
  names, Info-ZIP Unicode path fields, a `<!DOCTYPE>` manifest, inconsistent
  ZIP64 records, or a version NuGet clients cannot read are refused, so
  Forge and a NuGet client never see different identities for one package.
- Feed responses are inert in a browser (`Content-Security-Policy:
  default-src 'none'; sandbox`, `Content-Disposition: attachment`,
  `nosniff`). Package ids are validated against the NuGet id grammar on
  every route and before a proxy builds an upstream URL. Search `q` is
  capped at 256 bytes and 8 terms.

**Proxies, secrets and caches**

- A proxy refuses upstream redirects to, and resolutions of, link-local and
  cloud-metadata addresses, sends its credentials only to the origin of its
  `remote_url`, drops them when `remote_url` moves to another origin, and
  serves an upstream `.nuspec` only if it names the requested package.
  Inside the package-delay window it does not download a version at all.
- Encrypted secrets are bound to where they are sent: a proxy password to
  the origin of `remote_url`, an OIDC client secret to the realm's issuer and
  client id. Key rotations are serialized across instances, key material is
  wiped from memory after use, and an instance without `[crypto]` refuses to
  start on a database that holds encrypted secrets. Config errors and the
  `Debug` output of the configuration never contain secrets.
- Redis is a trust boundary: authorization sets, credential verdicts, OIDC
  discovery documents and signing keys, workload-identity verdicts and a
  proxy's upstream metadata are cached in each instance's memory only, and
  Redis only relays their invalidations. `rediss://` (TLS) URLs are
  supported.
- Trusted publishing: a rule for a custom issuer must pin a stable identity
  claim, or one the realm lists in `identity_claims`. Unlist, relist and
  delete by a workload pass the same checks as a publish and are recorded in
  `trusted_publish_audit`.

**HTTP and supply chain**

- Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Content-Security-Policy: frame-ancestors 'none'` and
  `Referrer-Policy: same-origin`; an https deployment sends HSTS. The web UI
  has a strict Content Security Policy: scripts only from its own origin plus
  the hashed inline theme bootstrap, no `eval`, and fetches only to the same
  origin.
- API responses (`/admin`, `/auth`, `/browse`) and feed responses to a
  request with credentials are `Cache-Control: private, no-store`, and feed
  responses carry `Vary: Authorization, Cookie, X-NuGet-ApiKey` (for
  `anonymous_mode = "allowlist"` see Known limitations).
- Slow clients are bounded by a header-read timeout
  (`server.header_read_timeout_seconds`, 150 s), a request-body idle timeout
  (`body_idle_timeout_seconds`, 60 s) and a response timeout
  (`request_timeout_seconds`, 900 s). Connections are HTTP/1 only.
- Release images are signed by digest before any tag points at them, and
  the verification command pins the exact release workflow. Actions and base
  images are pinned by digest, CI audits the Rust and shipped web
  dependencies, and Dependabot keeps them current.

### Good to know

- Repository names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`; `new` is
  reserved. In repository updates, an absent field keeps its value and JSON
  `null` clears it.
- The retention worker runs a repository automatically at most once a
  minute, whatever `default_run_interval_seconds` and a policy's
  `min_run_interval_seconds` say.

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
- The package delay is dated from the upstream publish time only for the
  versions in the newest 10 pages (640 versions on nuget.org) of a
  package's upstream registration; older versions, and versions of an
  upstream without a registration, count from the proxy's first sighting.
- A group's search is capped at 1,000 results per member, so totals and
  paging are exact only below that.
- A token whose scope lists a group's repository id reads through the group
  only from the members it lists as well: reading a group grants no read on
  its members.
- Retention has no per-run delete cap.
- No metrics endpoint, request IDs or JSON log output. Shutdown drains
  in-flight requests without a deadline.
- The web UI requires sign-in, even for repositories that allow anonymous
  reads; NuGet clients can still read those anonymously.
- There is no web console yet for RBAC roles and grants, retention, user
  deactivation or key rotation; use the `/admin` API.
- CI does not scan the container image for OS-package vulnerabilities.
- A proxy trusts its upstream: it follows the resource `@id`s and redirects
  the upstream names, also to private or plain-http addresses (credentials
  go only to the upstream's own origin), and parses its metadata documents
  (up to `proxy.max_metadata_bytes`, 32 MiB) in memory. Point proxies only
  at upstreams you trust. Behind an outbound proxy (`HTTP(S)_PROXY`) the
  proxy resolves host names, so Forge refuses only literal cloud-metadata
  addresses and the well-known metadata host names there.
- Unless a group flags owner members, it trusts all its hosted members
  equally: anyone who can push to any hosted member can publish under the
  group's `reserved_prefixes`, and with `prefer_hosted` can claim any
  public package id for the whole group. Flag the trusted members as owners
  when a group mixes feeds with different writers. Owners claim only the
  ids they have: an id no owner has is still served by every member, so
  reserve the internal prefixes as well.
- With `prefer_hosted`, a caller who cannot read a group's hosted members
  still learns whether one of them has a package id the upstream also has:
  they get 404 instead of the public package.
- A role grant of the `admin` action on one repository has no effect: every
  `/admin` operation needs a global administrator.
- An OIDC realm that provisions accounts can take a username before a
  credential-forwarding user of that name first signs in, where users choose
  their own username claim at the IdP. That user is then refused until an
  administrator removes the other account.
- Under `anonymous_mode = "allowlist"`, anonymous feed responses carry no
  `Cache-Control: no-store`, and whether one is served depends on the
  client's address, which a cache does not key on. A shared cache in front
  of Forge that stores responses without caching headers (Varnish's default
  does) can serve a package an allowlisted client fetched to a client
  outside the allowlist. Do not let such a cache store `/v3` responses.
- While Redis is unreachable, an instance hears no invalidations from the
  others and converges by TTL (60 s for authorization). Anything that can
  publish to Redis can grow every instance's memory: the invalidation
  bookkeeping is not bounded.
- Every `.nupkg` download updates its version's download counters in
  PostgreSQL, unthrottled. Hundreds of downloads of one version per second
  queue on those rows and can hold every database connection.
- Forge does not check the owner or permissions of `server.staging_dir`. On
  a host shared with other users, use a directory only Forge's user can
  write (the container image and the Kubernetes manifests are not affected).
- The Helm chart rolls the pods on a change of `secretEnv` (and of the
  in-cluster Redis `auth`) through an unsalted SHA-256 of the values in a pod
  annotation: whoever can read the Deployment can test guesses of a weak
  secret against it.
- The release build pulls the Dockerfile frontend, BuildKit and the SBOM
  scanner images by tag, not by digest.
- Login lockouts and failure counts are per instance and lost on restart
  (the networks a username signed in from are kept in the database).
- A first download through a proxy runs inside the request, so
  `server.request_timeout_seconds` (900) caps it below
  `proxy.download_timeout_seconds` (1800); NuGet clients give up far
  earlier anyway.

[Unreleased]: https://github.com/schmitch/forge/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/schmitch/forge/releases/tag/v1.0.0
