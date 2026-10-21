# Changelog

All notable changes to envisia-forge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/): breaking changes come only in a
major release, and each one is called out under **Upgrade notes**.

The release workflow publishes the section whose heading matches the tag
(`## [1.0.0]` for `v1.0.0`) as the GitHub release notes.

## [Unreleased]

First production release. envisia-forge is dual-licensed under the GNU AGPL
v3 (`AGPL-3.0-only`, see `LICENSE`) or the envisia license, at the user's
choice.

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
  passwords and realm secrets, with key rotation and backfill.
- **Web UI**: browse, repository and package detail, self-service tokens, and
  administration of repositories, users, tokens and realms. It is served by
  the same process on the same origin.
- **Operations**: `/healthz`, `/readyz` and `/version`, graceful SIGTERM,
  supervised background workers, and an optional Redis L2 cache with
  cross-instance invalidation.
- **Release**: a signed container image with an SBOM and provenance
  attestation; see [docs/deployment.md](https://github.com/schmitch/forge/blob/main/docs/deployment.md).
  The SBOM lists the Rust crates (the binary embeds its crate list with
  `cargo-auditable`) and npm packages as well as the Debian packages, and
  the image carries `LICENSE` and the third-party notices of the crates and
  npm packages it ships in `/usr/share/doc/forge/`. A tag is released only
  after CI, end-to-end tests included, passed for its commit.
- **Kubernetes manifests** in `deploy/kubernetes`: a kustomize base for the
  server, components for an Ingress or Gateway API HTTPRoute, in-cluster
  Redis, PostgreSQL and S3 (versitygw), two replicas with a
  PodDisruptionBudget, and following `:latest`; plus a production and an
  evaluation overlay. The base pins the image to the release it is tagged
  with.
- **`cargo xtask release <version>`** sets the version in `Cargo.toml`,
  `Cargo.lock`, `web/package.json` and the Kubernetes base, turns the
  `[Unreleased]` changelog section into the release's, commits and tags. It
  refuses a changelog whose release notes would leave entries out: a version
  section without its tag, or a drafted section next to a non-empty
  `[Unreleased]`. The release workflow refuses a tag whose Kubernetes base
  names another image version, or whose `[Unreleased]` section still has
  entries.
- **Helm chart** in `deploy/helm/forge`, published with every release to
  `oci://ghcr.io/schmitch/charts/forge` (same version as the image, signed
  with cosign, and attached to the GitHub release). The published chart pulls
  the release image by the digest the release workflow signed. Forge's whole
  configuration is settable as `config` (rendered to `forge.toml`), secrets
  through a chart-managed (`<fullname>-secret-env`) or existing Secret;
  routing through a Gateway API HTTPRoute and an optional ListenerSet (plus
  a cert-manager Certificate); PodDisruptionBudget, HorizontalPodAutoscaler,
  NetworkPolicy and `extraObjects`; and optional in-cluster PostgreSQL,
  Redis and versitygw dependencies. `cargo xtask release` also sets the chart's version and
  `appVersion`, and the release workflow refuses a tag whose chart names
  another version.

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
  (DNS-rebinding guard). Hops are split before they are decoded, and a
  malformed hop leaves the client unknown, never allowlisted: before, one
  non-ASCII byte in the `X-Forwarded-For` a client sent made it resolve to
  the trusted proxy's own address, which a `private` allowlist admits. Hops
  with a port (`a.b.c.d:port`, `[v6]:port`) parse.
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
  so response timing no longer reveals which upstream users exist; also
  while a credential-forwarding realm cannot be built (it is skipped, and
  unknown names then pay the dummy password hash themselves).
- Allowlist and trusted-proxy entries written as IPv4-mapped IPv6
  (`::ffff:10.0.0.1`) match as the IPv4 address they denote.
- A cancelled admin key rotation can no longer leave the rotation lock held
  on a pooled connection.
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
  (or lockout budgets). An upstream that compares usernames case-sensitively
  (an htpasswd file, for example) now receives the lowercased name: such
  users must be known to it in lowercase.
- Credential-forwarding realms take an optional `identity_path`: the account
  the upstream's JSON success response names must equal the username
  entered. Set it for upstreams that accept a secret with any username
  (GitHub, Azure DevOps or GitLab personal access tokens); without it such an
  upstream lets any token holder sign in as any user. A success without the
  field fails closed. The docs now state that the upstream must bind the
  username to the secret. `identity_path` also keeps other spellings the
  upstream accepts for one account (`DOMAIN\user`, `user@domain`) from
  signing in as separate Forge accounts, which a deactivation does not stop;
  an auto-provisioning realm without it logs a warning.
- A username containing `:` is never forwarded to a credential-forwarding
  realm. The upstream splits Basic credentials at the first colon, so a form
  login as `mallory:abc` with the password `def` was checked upstream as
  `mallory` / `abc:def`. Forge then provisioned and signed in a separate,
  active account `mallory:abc`, which got around a deactivation of
  `mallory`. Form login answers such a name with the usual 401, and admin
  user creation and `auth.bootstrap_admin.username` refuse it. For the same
  reason a name that Unicode compatibility normalization (NFKC) changes,
  such as full-width letters, or that holds an invisible character such as
  a soft hyphen, is never forwarded: a directory may fold it onto another
  account.
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
  (`/admin/me/tokens`) takes a session. Before, every feed request a NuGet
  client sent with a stored password — with credential forwarding, the
  directory password — could also call the admin API and mint tokens
  outliving that password. The password itself still signs in through
  `/auth/login`, so an administrator's password remains an admin
  credential: give administrators an OIDC realm, and NuGet clients tokens.
  An admin-forced reauth (`POST /admin/users/{id}/reauth`) now
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
  public feeds): the manifest summary is stored at publish and when a proxy
  caches a package (migration 0024; older versions are summarized once and
  backfilled), a proxy reads every cached version's registration data in
  one query, hosted and proxy search page over package ids in SQL and load
  versions for the returned page only (an empty query used to load every
  version of the repository), the registration index is paged (64 versions
  per page, inlined up to 128 versions, beyond that served from
  `/registration/{id}/page/{lower}/{upper}.json`, which answers with the
  versions in that range, so a page URL from a cached index keeps working
  after a push or delete) and loads manifest summaries only for the
  versions it inlines or the page it serves, hosted leaf and catalog
  documents look up one version instead of all, the browse API's package
  page reads every version's size in one query, rendering runs on the
  blocking pool, and the `.nuspec` parser tracks `<metadata>` in O(1) and
  rejects nesting deeper than 32 levels (it was quadratic in depth). A
  duplicate push without `allow_redeploy` is refused with 409 before the
  package is uploaded to storage.
- Proxy: a version deleted upstream leaves the listings (migrations 0025
  and 0030) instead of reappearing every `not_found_ttl`, once a refresh at
  least one metadata TTL after the first listing without it confirms the
  deletion, so a partial listing during an upstream incident (a Forge group
  with a member down) retires nothing; the package-level not-found marker
  is pruned once expired and cleared by a download of the package; a 404
  never hides a version a listing confirmed after the request started; and
  inside the package-delay window the proxy no longer downloads a version
  at all, so a reader cannot prefetch a quarantined release that would later
  be served from the cache. Proxy TTLs and the delay are validated
  (0 to 7 days; delay up to a year).
- The password lockout keys IPv6 clients by their /64 (one host owns a whole
  /64, so per-address keys gave it unlimited fresh budgets), and a username
  guessed from many networks is backed off: past three pair budgets of
  failures in a window its attempts are spaced (1 s, doubling to 30 s; an
  attempt that would wait more than 10 s is refused). Attempts from a
  network the username signed in from in the last 30 days are not backed
  off, and attempts already refused by a pair lockout take no slot, so a
  guesser cannot keep the owner out of their usual networks. A success
  clears it.
- OIDC hardening: a realm's stored client secret is dropped when its
  `issuer` or `client_id` changes (the update must supply a new one, so the
  old IdP's secret is never sent to a new issuer); discovery, JWKS and token
  requests follow no redirects (a 307 would replay the client secret) and
  must use https unless the realm allows a development http issuer; token
  responses are capped at 1 MiB; `redirect_to` is capped at 2 KiB; login
  starts are rate-limited per client network
  (`auth.oidc_login_starts_per_minute`, default 30); a callback's IdP error
  is only surfaced after the browser binding is checked and is logged
  bounded and escaped. Realms take an optional allow-gate,
  `required_claims` (e.g. `{"tid": ["<tenant>"]}` or `{"hd": ["corp.example"]}`):
  a token without an allowed value is refused.
- Workload identity (trusted publishing): for a custom issuer, a rule's
  identity anchor must be one of the known stable identity claims or one the
  realm declares in `identity_claims` (before, any claim not on a short
  denylist counted, so a rule on `actor` or `event_name` trusted every
  workload that carried it). Unlist, relist and delete by a workload now run
  the same commit-time realm fence as a publish and are recorded in
  `trusted_publish_audit` with an `action` column (migration 0026); before,
  a principal from a stale realm snapshot could still unlist, and those
  changes left no record. The docs recommend pinning `job_workflow_ref` and
  `event_name`.
- Session and OIDC flow cookies carry the `__Host-` prefix when
  `public_base_url` is https (the flow cookie moves to `Path=/`, which the
  prefix requires), so a sibling subdomain or a plain-http response can no
  longer plant one. A request carrying the session (or flow) cookie more than
  once is not authenticated by it, and neither copy is cleared — before, the
  first one won, which let a cookie planted for a narrower path or a parent
  domain fix the browser's session.
- Admin changes from an identity source take effect at once: a NuGet
  client's Basic login that re-reads the upstream's groups now drops the
  user's cached authorization set (as the browser login already did), so a
  demoted admin is not served as an admin until the cache expires; and a
  demotion by an upstream or an IdP ends the user's browser sessions. Editing
  a credential-forwarding realm retires the credential verdicts cached under
  its old config (they are keyed by it), so e.g. a newly required group
  applies to the next request rather than after `positive_ttl_secs`.
- A repository name that does not exist answers like one the caller may not
  read (401 anonymously, 403 signed in) on the feed (`/v3/{repo}/…`) and in
  the browse API, so repository names can no longer be enumerated; a global
  admin still gets 404.
- Groups take optional `reserved_prefixes` (API and UI, e.g. `["Acme."]`):
  package ids under a reserved prefix are never served from a proxy member.
  `prefer_hosted` only shields ids a hosted member already has, so an
  internal name was open to a public look-alike until its first publish (or
  after its last version was deleted).
- HTTP hardening: API responses (`/admin`, `/auth`, `/browse`) and feed
  responses to a request with credentials are `Cache-Control: private,
  no-store`, and feed responses carry `Vary: Authorization, Cookie,
  X-NuGet-ApiKey`, so a shared cache can neither store a package fetched
  with credentials nor serve one caller's answer to another (for
  `anonymous_mode = "allowlist"` see Known limitations); an https
  deployment sends HSTS. The
  server now enforces a header-read timeout (`server.header_read_timeout_seconds`,
  default 150 s, counted from accept — `axum::serve` never armed hyper's, so a
  client trickling headers, or sending nothing at all, held a connection
  forever; connections are HTTP/1 only, h2c is no longer accepted), a
  request-body idle timeout
  (`body_idle_timeout_seconds`, 60 s) and a response timeout
  (`request_timeout_seconds`, 900 s, answered with 408).
- The `Debug` output of the database, S3 and Redis configuration no longer
  contains secrets: connection-URL passwords and query strings and the S3
  secret key are redacted, so a logged config cannot leak them.
- Release workflow: only version tags on the default branch decide whether a
  release moves `:latest` / `:<major>.<minor>` (a stray tag pushed on another
  branch — never released — kept every later release from moving them).
- Package manifests must have the one shape NuGet reads: exactly one
  `.nuspec` at the package root, a root `<package>` with a single
  `<metadata>`, and in it one text-only `<id>` and `<version>` (and at most
  one `<dependencies>`). Repeated `<id>` elements were joined, and a nested
  `.nuspec` or `<metadata>` could be taken for the manifest, so Forge and a
  NuGet client could see different identities for one package — enough to
  publish past an id-scoped grant.
- The root manifest is found the way NuGet finds it: an entry name holding
  `%` is percent-decoded, and `\` separates directories as `/` does. Before,
  a package holding `x\allowed.nuspec` and `victim%2Enuspec` was stored as
  `Allowed.*` while NuGet read `Victim.*` from it. A package is now refused
  when any reading of its entry names finds more than one root manifest, or
  when the manifest's own name holds `%` or `\`. Also refused: an archive
  that repeats an entry name (the zip reader saw one of them, NuGet all);
  an entry with an Info-ZIP Unicode Path field (0x7075), which renames the
  entry for the zip reader but not for .NET; and a manifest with a
  `<!DOCTYPE>`, which NuGet will not read.
- Request bounds on the feed: a search `q` is cut to 256 bytes and at most
  8 distinct terms (each term costs a substring scan per candidate id, and
  `q` was unbounded), and a push whose multipart body does not reach its
  package part's headers within 64 KiB is refused with 400 (the parser
  buffered everything before the first boundary in memory, up to the whole
  upload limit).
- Package archives: a ZIP64 locator that does not point at a ZIP64 record
  is refused (the pre-parse limit check skipped such archives, and the zip
  reader then went looking for an unvetted record whose entry count sizes an
  allocation), and archives are read at offset 0. Versions NuGet clients
  cannot read as a package's own are refused at publish: a component above
  `int32`, a numeric prerelease identifier with a leading zero (stored
  under a normalized URL no client requests) and malformed build metadata.
- Credential forwarding: the upstream `url` must be https unless it is a
  loopback address or the realm sets `allow_http` (before, a plain-http URL
  was accepted with a log line, so every login sent a password in the clear
  and a network attacker could also forge the groups that grant admin); the
  forwarding client ignores `HTTP(S)_PROXY`; and at most 1 MiB of a success
  body is read for `groups_path` / `identity_path` (larger answers fail
  closed).
- Redis is a trust boundary for proxied content too: a proxy's upstream
  service index, manifests and registrations are cached in each instance's
  memory only. Before, a forged service index planted in Redis made other
  instances download packages from the forger's host, and the planted
  package then stayed cached.
- Admin request bodies for grants, roles, role assignments, content
  selectors, user creation, group members, retention policies, repositories
  and realms, and `POST /auth/tokens`, refuse unknown fields (422 naming the
  field). Before, a grant sent as `{"repository_id": 3, ...}` (the shape the
  grant listing returns) ignored the id and granted the action on **every**
  repository, a selector with a mistyped `include` matched every package,
  `/auth/tokens` dropped a `scope` and minted an unscoped token, and a
  misspelled field fell back to the unsafe default: a live retention policy
  over every package, a public repository, or no reserved prefixes. A grant
  now also takes `repository_id`. A realm's `config` refuses unknown keys as
  well (400 naming the key): a misspelled `identity_path`,
  `required_claims` or `required_groups` turned that gate off, and a
  misspelled `auto_provision: false` left provisioning on. A role assignment
  naming both `role` and `role_id` answers 400 instead of silently using
  `role_id`.
- With `allow_redeploy` on, replacing an existing version needs the delete
  permission (and passes the delete selectors) as well as write, so a
  push-only token can no longer overwrite a released version.
- Every package mutation (push, redeploy, unlist, relist) and every admin
  change is logged at INFO under the `forge::audit` target with the
  principal's ids (`user:5 token:12`, `user:5 session`,
  `workload realm:3 role:7`).
- An instance without `[crypto]` refuses to start on a database holding
  encrypted secrets, instead of running with every sealed credential
  unusable and storing new secrets in plaintext.
- On installs with `legacy_open_access`, removing a credential-forwarding
  user's `authenticated` role is no longer undone by the user's next login.
- Encrypted secrets are bound to where they are sent: a proxy password to
  the origin of the repository's `remote_url`, an OIDC client secret to the
  realm's issuer and client id. Before, someone who could write to the
  database but not read secrets could point `remote_url` at their own host,
  and the proxy decrypted the password and sent it there. Secrets sealed
  under the old binding are opened only while
  `crypto.accept_row_bound_secrets` is on (see Upgrade notes), so an old
  blob replayed into a repointed row is refused too.
- The marker that records whether a realm imported from `[oidc]` /
  `[auth.upstream_basic]` was edited no longer hashes the realm's secrets.
  It was an unsalted SHA-256 next to the plaintext config, so a database
  dump allowed offline guessing of an encrypted `client_secret` or
  `key_pepper`. A changed block is re-applied only while neither the row
  nor the marker changed since startup read them, so a boot that races an
  admin edit of the realm no longer overwrites it.
- The AES-GCM and XChaCha20-Poly1305 key schedules and the decoded root key
  are wiped from memory after use.
- With `auto_provision = false`, a credential-forwarding realm that maps an
  admin group now applies the upstream admin verdict to existing accounts
  in both directions, as with auto-provisioning: a user removed from the
  admin group upstream loses the flag and the `admin` role and is signed
  out; before, they kept signing in as an admin. A user added to that group
  upstream becomes an admin at their next login, where before they did not.
- A group can name the members that own its package ids
  (`group_member.owner`). Once any member is flagged, only owners claim ids:
  with `prefer_hosted`, an id an owner has is served by the owners alone (no
  proxy or other hosted member adds versions to it), and only owners serve
  ids under `reserved_prefixes`. A writer of a developer feed in the same
  group can no longer publish an internal name, add a version to an owner's
  package, or take a public id away from the proxy. An owner must be
  unflagged before it can be removed from the group or deleted, so a group
  never falls back to trusting every member unnoticed; the web UI marks
  owners. A nested group keeps its own `prefer_hosted`, `reserved_prefixes`
  and owners when it is read through an outer group, and an outer group
  that flags it as an owner trusts the inner group's owners, not every
  hosted repository inside it.
- `rustls-webpki` 0.103.16 and `webpki-root-certs` 1.0.10: certificate
  verification no longer accepts distrusted intermediates
  (RUSTSEC-2026-0382, RUSTSEC-2026-0383).
- Credential-forwarding verdicts are cached in memory no longer than they
  live: a rejection for `negative_ttl`, and a verdict another instance wrote
  only for what its row has left (before, both for the positive TTL).
- Turning a repository's `anonymous_read` off drops every cached
  authorization set, so a user or workload holding the `anonymous` role
  stops reading it at once instead of after the cache TTL.
- An expired or revoked API token, or one of a deactivated user, sent as
  the Basic password answers 401 and is never tried as a password. Before, a
  credential-forwarding realm forwarded it upstream as a password on every
  request of a client that still stored it.
- A bearer token with a made-up `kid` (no valid signature needed) no longer
  drops the issuer's cached signing keys on every instance: the refresh it
  triggers fetches first and keeps the cached keys when the fetch fails, so
  an outage of the IdP's key endpoint no longer stops trusted publishing
  and OIDC logins.

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
  search; repository names are validated; disabling the `local` realm asks
  for confirmation; group owners can be flagged and unflagged, and groups
  nested, on the members screen; realm list fields are edited one entry per
  line, so a value with a comma (an LDAP DN) survives a save, and a new OIDC
  client secret is required when the issuer or client id changes; expired
  tokens show as expired and token scopes are shown; a page past the last
  search result says so instead of "no packages yet".
- Retention `not_downloaded_for_days` counts a never-downloaded version
  from its publication (as proxy rules count from `first_seen_at`). It
  treated such a version as always cold, so a policy with this trigger
  hard-deleted a version pushed minutes before the next run.
- A blob left `deleting` while an asset still names it (aftermath of the
  pre-release concurrent hard-delete race) is restored to `committed`
  instead of having its object deleted on every re-push of the same bytes;
  a warning names the S3 key to restore if the object is already gone.
- The garbage-collection outbox decides which deletions are due on the
  database clock, so an instance whose clock runs ahead no longer deletes
  objects before the grace period.
- Retention re-checks every decision when it applies it. A run stops when
  its policy was edited, disabled or switched to `dry_run_only`, or when it
  lost its lease. A decision the package's current versions no longer
  produce is skipped: with `keep_last_n: 1`, unlisting 2.0.0 mid-run no
  longer lets the run delete 1.0.0 and leave no listed version. A
  package's decisions are applied in transactions of up to 100, each
  re-checking the package once, so packages with thousands of versions do
  not pay for a full re-check per version.
- `retention_audit` is indexed for component deletes, which scanned the
  whole table while holding locks, and rows older than
  `retention.audit_retention_seconds` (default 90 days) are pruned.
- Redis no longer takes an instance down with it:
  - an instance starts while Redis is unreachable;
  - an invalidation stalled on Redis no longer blocks every lookup in its
    namespace;
  - a subscription that goes silent without a reset is detected by a ping
    within about 15 s, L1 is flushed, and the instance resubscribes.

  Pushes, deletes and retention runs no longer pay for a Redis
  invalidation of a cache nobody read.
- Temp space for pushes and first-time proxy downloads is bounded per
  instance (`server.max_staging_bytes`, answered `503` with `Retry-After`
  when full), and files a killed process left in `server.staging_dir` are
  removed at startup instead of after an hour, so a restart cannot use more
  than the budget. Before, concurrent downloads of large packages could
  fill the disk and get the pod evicted.
- The networks a username signed in from, which exempt the owner from that
  username's login backoff during a password spray, are stored in the
  database. Before, they were lost on restart and known only to the
  instance that saw the sign-in.
- Leases, retry backoffs and staleness cutoffs are computed on the database's
  clock, so a skewed application clock no longer makes failing outbox rows
  retry every poll or retention runs fail their own lease. So are a proxy's
  package delay, not-found TTL and index freshness, the OIDC login flow's
  expiry and session expiries: with the application clock ahead, a proxy
  served a quarantined release early and negative caching stopped working;
  with it 10 minutes behind, every OIDC login failed as "unknown or expired
  state".
- A staging directory on NFS is swept too (the sweep could not take a lock
  through a read-only file there), a lock that cannot be tried falls back to
  removing files idle for an hour instead of keeping them forever, and an
  instance whose staging subdirectory was removed under it stages in a new
  one instead of failing every push and download until restarted. On a file
  system without working file locks the server stages without one (with a
  warning) instead of refusing to start, and on NFS a process directory is
  removed after its lock is closed, so emptied directories no longer pile
  up with a warning per restart.
- The last active administrator can no longer be deactivated, deleted or
  lose the `admin` role: each answers 409. The check holds a lock on the
  `admin` role, so two concurrent demotions cannot both pass.
- `PATCH /admin/tokens/{id}/scope` with `{}` answers 400 instead of clearing
  the token's scope; only an explicit `"scope": null` clears it.
- **Realms**: a realm whose secrets no longer decrypt can be repaired with
  `PATCH /admin/realms/{id}` carrying the secret again; an edit without it
  answers 400 naming it instead of 500. The realm-secret backfill (at
  startup and on key rotation) no longer overwrites a realm edited while it
  runs, and re-seals a realm whose sealed secrets no longer decrypt from its
  plaintext copy instead of failing the whole pass. One malformed sealed
  secret (a damaged envelope, a data key that is gone) no longer stops
  every instance from starting or the rotation from revoking retired keys:
  it is logged with its row and left alone. The last enabled realm people
  sign in with (`local` or OIDC) can be neither disabled nor deleted (409);
  one click on `local`'s Enabled switch used to lock every password login
  out. A realm edit answers 409 instead of undoing a change committed
  since it read the realm (another admin's edit, a reorder).
- **Authentication**: a deactivated local account's password is refused by
  the local realm, like a wrong password, and never forwarded to a
  credential-forwarding realm. When Forge's own database fails (looking up
  a token, session, user, cached upstream verdict, realm or workload role),
  the request answers 503 instead of 401, so NuGet clients and CI jobs
  retry instead of asking for new credentials.
- **OIDC** realms take `endpoint_hosts` for identity providers that serve
  their token and key endpoints on other hosts than the issuer's (Google,
  AWS Cognito); their logins failed with 502.
- **Proxy**: changing a proxy's `remote_url` takes effect at once. The
  previous upstream's service index, listings, manifests and registrations
  are no longer used, and a failing new upstream is an error instead of a
  silent fallback to the old index. Its per-version state is reset in the
  same transaction: versions never downloaded and not-found markers are
  dropped, so the package delay counts from the new upstream's first
  sighting; downloaded versions stay cached and are refreshed. A first
  download no longer answers 500 when the cleanup of unconfirmed versions
  removes its row mid-download.
- **Proxy**: a service index without a `PackageBaseAddress` (a captive
  portal, a gateway's error page) is an upstream failure. It no longer
  replaces the last good index or makes every package not cached yet
  answer 404.
- **Proxy**: the package delay counts from the upstream publish time of a
  listed version when the upstream registration states a plausible one,
  instead of from the proxy's first sighting, so it holds back new releases
  only: enabling it used to hide every version of every package the proxy
  had not served before (on a fresh install, every restore failed for the
  whole delay). Search shows a package id's own casing (`Newtonsoft.Json`,
  migration 0031) instead of the lowercased one. A registration page or
  leaf of a package with more than 640 versions carries its older
  versions' dependencies, listing state and publish date. Deleting a proxy
  while a first download is being stored no longer deadlocks (one side
  answered 500).
- **Groups** answer a failing member's error instead of 404 for a package
  only that member could serve, such as a proxy whose upstream is briefly
  unreachable, so clients retry instead of reporting NU1101 and a Forge
  proxy in front of the group does not cache the miss.
- The **Online** switch takes hosted and group repositories offline too
  (every feed request answers 503 with `Retry-After`, after authorization);
  before, only proxies read it. Inside a group an offline member fails like
  an unreachable one.
- **Search** without `semVerLevel=2.0.0` drops SemVer 2.0.0 versions before
  paging, so pages are full and `totalHits` is exact. The web UI pages
  through repositories with more than 20 packages: `/browse/packages`
  reports the total number of matches instead of capping it at
  `skip + take`.
- Registration `dependencyGroups` list what NuGet reads: only direct
  children of `<dependencies>` and of its groups, and flat dependencies
  only when the manifest has no group.
- A `HEAD` of a `.nupkg` no longer counts as a download (it kept packages
  "warm" for retention), and a redeploy keeps the version's download count.
  Unlisting, deleting or relisting a version that does not parse answers
  404, not 400.
- A token's `last_used_at` is written at most once a minute, so the
  parallel requests of one restore no longer serialize on the token's row.
- **Retention** groups versions by package in one pass and evaluates on the
  blocking pool, so a large repository's run or preview no longer stalls
  the instance. Automatic runs of a repository are at least 60 s apart;
  with both run intervals set to 0 it used to re-run back to back forever.
- **Cache backplane**: a forged `u64::MAX` tag generation published to
  Redis can no longer stop every instance from applying later
  invalidations, and an instance whose tag generations restarted low
  (after Redis lost the tag's key) is no longer ignored by its peers, which
  kept serving, for example, a revoked role until the cache TTL.
- **Releases**: the release workflow decides whether to move `:latest` and
  `:<major>.<minor>` right before tagging, so an older release whose run
  finishes last no longer moves them back. CI runs for every commit on
  `main` instead of being cancelled by the next push. The GitLab pipeline
  passes again and mirrors the GitHub CI, except for the Helm chart check.

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
  `crypto.accept_row_bound_secrets`,
  `outbox.processed_retention_seconds`, `retention.audit_retention_seconds`,
  `server.staging_dir`, `server.max_staging_bytes`, and the `[nuget]`
  archive limits. New endpoints: `PATCH /admin/users/{id}`,
  `PATCH /admin/repositories/{name}/members/{member}` (`owner`) and
  `GET`/`PUT /admin/settings/legacy-open-access`. Group members have an
  `owner` field, and OIDC realms (and the `[oidc]` seed) `endpoint_hosts`.
- Startup validates `server.public_base_url` (an absolute http(s) URL with
  a host and without query or fragment), `server.allowed_hosts` and the
  session TTLs (1 second to 10 years). The `[auth]` table may be left out.

### Upgrade notes

- This is the first release; install it on an empty database. The other
  notes concern installs that ran pre-release builds.
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
  [DEVELOPMENT.md](https://github.com/schmitch/forge/blob/main/DEVELOPMENT.md).
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
- Migration 0021 rewrites existing usernames into canonical form. Accounts
  whose names differ only in case, surrounding spaces or Unicode composition
  are not merged: the oldest keeps the name, the others are renamed
  `<name>#<id>` and a warning names each one. Review and delete them (there
  is no rename API); their tokens keep working. Because SQL `lower()` follows
  the database collation (a `C` ctype lowercases ASCII only), the server then
  re-canonicalizes every stored name at startup and logs each rename. Two
  cases it cannot undo, because 0021 already folded them under a non-`C`
  collation: a capital `İ` (stored as `i`) and a final `Σ` (stored as `σ`);
  such accounts must be recreated.
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
- Pre-release installs: an account whose name contains `:` can no longer
  sign in with a password. Its sessions and API tokens keep working. A
  credential-forwarding account with such a name was signed in by the
  upstream account named before the colon. Deactivate it, which also ends
  its sessions and refuses its tokens.
- Workload-identity realms for an issuer other than GitHub Actions or
  GitLab.com: every rule must now pin a stable identity claim (`sub`,
  `repository_id`, `job_project_id`, `project_path`, … — see
  docs/trusted-publishing.md) or a claim the realm lists in the new
  `identity_claims`. A realm with a stored rule that pins neither no longer
  loads at all (an error names it in the log), so every one of its rules
  refuses tokens until the realm is edited.
- A credential-forwarding realm (or `[auth.upstream_basic]` block) whose `url`
  is plain `http` to anything but a loopback address no longer loads until it
  is switched to https or sets `allow_http = true` explicitly. Credential
  forwarding no longer honours `HTTP(S)_PROXY`.
- On an https deployment the session and OIDC flow cookies are renamed
  `__Host-forge_session` / `__Host-forge_oidc_flow`: everyone signs in once
  more after the upgrade.
- Automation calling the admin API must not send fields the endpoint does
  not document (they are now refused with 422, this includes the retention
  policy, repository and realm endpoints), and `POST /auth/tokens` refuses
  a `scope` (use `POST /admin/me/tokens` for scoped tokens).
- A credential-forwarding or OIDC realm whose stored `config` holds a key
  its kind does not know (a typo an earlier build accepted and ignored) is
  skipped at startup, with an error naming the key, until it is edited
  without that key. Check the log after upgrading.
- The retention worker never runs a repository automatically more often
  than every 60 s, whatever `default_run_interval_seconds` and the policy's
  `min_run_interval_seconds` say (0 is still accepted).
- A hosted or group repository saved with **Online** switched off, which
  used to change nothing, answers 503 after the upgrade. Switch it back on.
- Startup refuses a `server.public_base_url` without an http(s) scheme or
  host, or with a query or fragment, an invalid `server.allowed_hosts`
  entry, and session TTLs of 0 or above 10 years.
- A CI token or workload role that redeploys existing versions needs the
  `delete` action on the repository as well as `write`.
- Retention policies with `not_downloaded_for_days` select fewer versions
  on their first runs: a never-downloaded version only qualifies once it is
  that many days old.
- Retention audit rows older than 90 days are deleted after the upgrade. To
  keep them, set `retention.audit_retention_seconds = 0` (or a longer
  window) before upgrading. Migration 0027 indexes `retention_audit` without
  `CONCURRENTLY`, which briefly blocks writes to a large table.
- Pre-release installs with secret encryption: secrets sealed by earlier
  builds are bound only to their row and do not decrypt by default. Start
  all instances at once with `crypto.accept_row_bound_secrets = true`
  (`FORGE_CRYPTO__ACCEPT_ROW_BOUND_SECRETS=true`): startup re-seals them for
  their destination, which older instances cannot read. Then remove the
  setting and restart. A secret that is still logged as undecryptable (its
  row was changed outside the admin API) must be entered again.
- Pre-release installs with a realm imported from `[oidc]` or
  `[auth.upstream_basic]`: do not edit that realm through an instance of
  the older build once a new instance has started. The older build does not
  drop the import marker, so the next start would apply the TOML block over
  a changed secret.
- Staging is limited to 4 GiB per instance by default (four times the
  larger of `server.max_upload_bytes` and `proxy.max_package_bytes`), in
  `<temp dir>/forge-staging`. Set `server.max_staging_bytes` (`0` for no
  limit) and `server.staging_dir` to match your volume; a budget below the
  larger of those two limits plus `nuget.max_nuspec_bytes` is refused at
  startup.
- Proxies with a package delay serve the versions they already list but
  had held back although the upstream published them before the delay:
  their delay is dated from the upstream publish time at the next listing
  refresh. A version deleted upstream leaves a proxy's listings one
  metadata TTL later than with pre-release builds.
- Automation that disables or deletes the last enabled `local` or OIDC
  realm gets 409, and a realm `PATCH` that races another change of the
  realm gets 409: re-read the realm and send the change again.

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
  at upstreams you trust.
- Unless a group flags owner members, it trusts all its hosted members
  equally: anyone who can push to any hosted member can publish under the
  group's `reserved_prefixes`, and with `prefer_hosted` can claim any
  public package id for the whole group. Flag the trusted members as owners
  when a group mixes feeds with different writers. Owners claim only the
  ids they have: an id no owner has is still served by every member, so
  reserve the internal prefixes as well.
- Under `anonymous_mode = "allowlist"`, anonymous feed responses carry no
  `Cache-Control: no-store`, and whether one is served depends on the
  client's address, which a cache does not key on. A shared cache in front
  of Forge that stores responses without caching headers (Varnish's default
  does) can serve a package an allowlisted client fetched to a client
  outside the allowlist. Do not let such a cache store `/v3` responses.
- While Redis is unreachable, an instance hears no invalidations from the
  others and converges by TTL (60 s for authorization).
- Login lockouts and failure counts are per instance and lost on restart
  (the networks a username signed in from are kept in the database).
- A first download through a proxy runs inside the request, so
  `server.request_timeout_seconds` (900) caps it below
  `proxy.download_timeout_seconds` (1800); NuGet clients give up far
  earlier anyway.

[Unreleased]: https://github.com/schmitch/forge/commits/main
