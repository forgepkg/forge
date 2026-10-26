# Changelog

All notable changes to Forge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/): breaking changes come only in a
major release, and each one is called out under **Upgrade notes**.

The release workflow publishes the section whose heading matches the tag
(`## [1.0.0]` for `v1.0.0`) as the GitHub release notes. Entries for changes
not released yet are fragments under [docs/changes/](docs/changes/README.md)
until the release folds them in.

## [Unreleased]

A new major release, installed fresh: 2.0.0 does not upgrade 1.0 or 1.1.
Install it on an empty PostgreSQL database and an object store of its own;
[docs/deployment.md](https://github.com/forgepkg/forge/blob/main/docs/deployment.md)
lists the required settings. It adds npm and raw (generic file)
repositories, serves every package repository at `/repository/<name>/`,
keeps Helm charts as OCI artifacts in docker repositories, invites users by
email, and manages roles, access levels and retention in the web UI. Every
format is built in: Docker / OCI, NuGet, npm and raw. Forge is licensed
under the MIT License (up to 1.1.0: the GNU AGPL v3 or a commercial
license), and is published as `ghcr.io/forgepkg/forge` for `linux/amd64`
and `linux/arm64`, with the Helm chart `oci://ghcr.io/forgepkg/charts/forge`.

### Upgrade notes

- **2.0.0 does not upgrade 1.0 or 1.1.** There is no upgrade path: 2.0.0 is
  installed fresh, with an empty PostgreSQL database and an object-store
  bucket (or prefix) of its own. Startup refuses a database created by 1.x or
  by a build before 2.0.0 ("the database was created by Forge 1.x or by a
  build before 2.0.0, and 2.0.0 does not upgrade it"). Upgrades are from 2.0.0
  on.
  ([#490](https://github.com/forgepkg/forge/issues/490),
  [#498](https://github.com/forgepkg/forge/issues/498))

### Features

- Credential forwarding: a realm can keep an argon2id hash of every password
  its upstream (e.g. a Nexus) accepts (**Keep a password hash of successful
  logins**, `capture_password_hash`, off by default; unchecking it deletes the
  hashes). Once the hashes are in place the realm can stop asking the upstream
  and sign its users in with them (`captured_password_only`), and its accounts
  can be switched to local accounts with the same password, one by one or all
  at once (`POST /admin/users/{id}/convert-to-local`,
  `POST /admin/realms/{id}/convert-to-local`), so the upstream can be retired
  without asking every user for a new password.
- **OIDC login without a client secret**: an `oidc` realm can authenticate
  at Microsoft Entra with a federated identity credential instead
  (`client_authentication = "federated_credential"`). Forge signs a
  short-lived client assertion itself, as an OpenID Connect issuer of its
  own (`server.public_base_url`), publishing
  `/.well-known/openid-configuration` and its keys at
  `/.well-known/jwks.json`. The keys are RSA-2048, shared by every instance
  through the database (sealed with `[crypto]`), and rotated every 30 days,
  each new key published two days before it signs. The realm shows the
  issuer, subject (`<client id>@<realm issuer>`) and audience to register.
  See [DEVELOPMENT.md](https://github.com/forgepkg/forge/blob/main/DEVELOPMENT.md#without-a-client-secret-a-federated-credential).
  ([#302](https://github.com/forgepkg/forge/pull/302))
- Helm: `extraObjects` can also be a map, whose keys only name its entries.
  Helm merges a map across values files, so each file can add its own
  objects, and a later one replaces an entry by its key or drops it with
  `null`; a list in a later file replaces the whole list. Lists keep
  working.
  ([#288](https://github.com/forgepkg/forge/pull/288))
- **Import from Nexus**: copy a Nexus 3 hosted repository into a Forge hosted
  repository of the same format, one repository at a time: NuGet packages,
  and Docker images with their digests, multi-platform indexes, signatures
  and SBOMs. In the web UI (a hosted repository's
  **Import from Nexus**) or the admin API
  (`/admin/repositories/{name}/imports`). The source is checked before an
  import starts; a dry run reports the counts, the size and the conflicts
  without writing. Packages are verified against Nexus' checksums and
  written through the normal push path, keep their publish dates, last
  downloads and uploaders, and are audited as imports. A version Forge has
  with other bytes is skipped and reported, overwritten, or fails the
  import, as chosen. An import resumes after a restart, a failure or a
  cancel, failed items can be retried on their own, and running it again
  copies only what is new. The Nexus password is sealed with the secret
  encryption and deleted when the import completes. See
  [docs/nexus-import.md](docs/nexus-import.md).
  ([#183](https://github.com/forgepkg/forge/issues/183))
- npm registries: repositories of `"format": "npm"`, served at
  `/repository/<repository>/` for npm, pnpm, Yarn and Bun. Hosted ones take
  `npm publish` (the tarball checked against the integrity the client claims
  and the version it names, under the repository's deployment policy),
  dist-tags and `npm deprecate` with the level `write`, and `npm unpublish`
  with `delete`. Proxies cache `registry.npmjs.org` or any registry, with
  Basic credentials or a token sent as `Authorization: Bearer` to its own
  origin only, and serve the upstream's dist-tags, deprecations and publish
  times, verified tarballs and the publication delay. Groups merge their
  members, take publishes into a writable member, keep reserved scopes
  (`@acme`) away from proxy members and pass `npm audit` on to their proxy
  without the reserved names. `npm login` is approved in the browser on a
  page of the web UI, or checks a password (`yarn npm login`), and mints an
  API token that `npm logout` revokes; npm clients send API tokens as
  `Authorization: Bearer`, which every format plugin's repositories now
  accept. Retention never deletes a version a dist-tag names. The web UI
  shows a package's dist-tags, deprecated versions and README, and a
  repository's `.npmrc` and `.yarnrc.yml` lines and install commands. npm is
  a built-in format plugin (`crates/formats/npm`). See
  [docs/npm.md](docs/npm.md).
  ([#41](https://github.com/forgepkg/forge/issues/41))
- Hosted NuGet repositories have a deployment policy, like raw and npm ones:
  allow redeploys, refuse them (the default), or read-only, which refuses
  every push, unlist and delete. `allow_redeploy` says the same and follows
  it. A NuGet group may have a writable member, a hosted member that pushes,
  unlists and deletes through the group go to. The web UI's repository form
  offers both.
  ([#41](https://github.com/forgepkg/forge/issues/41))
- Raw (generic file) repositories, like Nexus' raw-hosted, raw-proxy and
  raw-group: `"format": "raw"` repositories serve arbitrary files under
  arbitrary paths at `/repository/<repository>/<path>`. Uploads are a `PUT` with an
  API token or a multipart form (Nexus' `raw.directory` / `raw.assetN` fields
  work); downloads answer one `Range`, conditional requests, an `ETag` (the
  SHA-256) and `Last-Modified`, and `<file>.sha256`, `.sha512`, `.sha1` and
  `.md5` from the stored digests, so `sha256sum -c` checks a download.
  Directories list as HTML or JSON, a page at a time. A hosted repository's
  deployment policy allows redeploys, refuses them (the default) or makes it
  read-only; files download unless the repository displays them `inline`, and
  are sandboxed either way. Paths with `..`, `.`, empty segments, backslashes
  or encoded slashes are refused. A proxy fetches from any HTTP(S) base URL,
  following redirects (GitHub release assets) with its credentials sent to
  its own origin only, re-validates cached files after `max_age_seconds` (`0`:
  never), remembers misses, and serves its cached copy while the upstream is
  down; a group serves a path from its first member that has it. Content
  selectors match paths, retention deletes files by path prefix, age and
  downloads or keeps the newest per directory, and the web UI browses a
  repository's tree, uploads and deletes files and shows each file's URL and
  `curl` commands. See [docs/raw.md](docs/raw.md).
  ([#42](https://github.com/forgepkg/forge/issues/42))
- Helm charts pushed to a docker repository (`helm push`) have a page of their
  own in the web UI: the chart's versions, the `helm install` and `helm pull`
  commands of the selected one (the newest release by default) with the
  `helm registry login` to run first, its `Chart.yaml` facts (appVersion,
  description, home, sources, maintainers, dependencies), its README and its
  default values. The browse API serves them at
  `GET /browse/chart?repo=<name>&image=<image>&digest=<manifest digest>`; a
  proxy shows them once the chart has been pulled through it. See
  [docs/docker.md](docs/docker.md#helm-charts).
  ([#43](https://github.com/forgepkg/forge/issues/43))
- A proxy's retention rules (`scope: proxy_cached`) can keep a working set of
  each package: `keep_last_n` keeps the newest N cached versions the upstream
  lists, and `keep_n_most_downloaded` the N cached versions pulled most
  recently (by when they were last pulled, not how often). A version any proxy
  rule keeps is never evicted, however long nobody pulls it, so a quiet package
  no longer loses every cached version and stays restorable while the upstream
  is unreachable. The Retention screen offers both on proxy rules, and a new
  proxy policy starts by keeping the newest three versions of each package.
  ([#59](https://github.com/forgepkg/forge/issues/59))
- Forge runs on arm64: each release publishes `ghcr.io/forgepkg/forge` for
  `linux/amd64` and `linux/arm64` as one multi-platform image under the same
  tags, so arm64 nodes (AWS Graviton, Azure Cobalt, Ampere, Raspberry Pi) and
  Apple Silicon machines pull an image of their own platform, without
  emulation. Each platform's image carries its own SBOM and provenance
  attestations. The release signs the multi-platform index and each platform's
  image, so the release notes' `cosign verify` command passes for each of their
  digests, and the Helm chart pins the index digest. `cargo xtask docker-build
  --platform linux/arm64` builds the arm64 image from a checkout.
  ([#186](https://github.com/forgepkg/forge/issues/186))
- **Admin → Settings** (`/manage/settings`) sets who may read without signing
  in (the anonymous mode and its IP allowlist, next to the repositories that
  allow anonymous reads) and how people sign in (the login screen, password
  Basic on the feeds, the session lifetimes and the lockout), for every
  instance and without a restart: the instance that takes a change applies it
  at once, the others within `auth.realm_cache_ttl_seconds`. The admin API
  offers the same as `GET`/`PUT /admin/settings/auth`; a `PUT` changes the
  fields it names and refuses a wrong value with 400 and what is wrong. A
  repository's page shows the server-wide anonymous mode next to its own
  anonymous access.
  ([#294](https://github.com/forgepkg/forge/issues/294))
- Hosted repositories can grant package-scoped write and delete access to
  workload identities through trusted publishers, independently of their realm
  reader role. Manage trusted publishers through the admin API or the repository
  admin page; publisher changes revoke their rights from outstanding workload
  keys and registry tokens without revoking the realm's other keys.
  ([#306](https://github.com/forgepkg/forge/issues/306))
- A built-in `writer` role: `read` and `write` on every repository, no
  `delete` and no `admin`. A writer publishes NuGet packages, container images,
  Helm charts and raw files (new ones too) to every repository but cannot
  unlist or delete versions, delete tags, delete or replace raw files, or reach
  the admin API; `/admin/me` reports the
  `repo.write` capability. **Admin → Users** shows each user's access level
  (admin, writer or reader) from their roles, and the user's page switches it.
  `docs/deployment.md` describes the built-in roles.
  ([#318](https://github.com/forgepkg/forge/issues/318))
- Forge can send email: **Admin → Email** (`/manage/settings/email`) sets up
  the email service, starting with an SMTP server (STARTTLS or implicit TLS,
  with a username and password or as a relay), with a test send and the last
  failed send on the page. The settings live in the database only, with no
  `forge.toml` section or environment variable, apply on every instance
  without a restart, and the password is sealed at rest with secret
  encryption and never returned. The admin API is `/admin/settings/email`
  (`GET`, `PUT`, `DELETE`) and `POST /admin/settings/email/test`.
  ([#319](https://github.com/forgepkg/forge/issues/319))
- The email service can send through Microsoft 365: a **Microsoft 365 (Graph)**
  transport on **Admin → Email** signs in as an Entra app registration with
  the client credentials grant and sends with Graph's `sendMail`, so no mailbox
  password is stored and SMTP AUTH can stay off. The app authenticates with a
  client secret (sealed at rest, bound to the tenant and app) or with a
  federated credential: Forge signs the client assertion with the issuer keys
  federated OIDC realms use, and the page shows the issuer, subject and
  audience to register. `docs/deployment.md` walks through the setup, including
  limiting the app to the sender mailbox with RBAC for Applications.
  ([#320](https://github.com/forgepkg/forge/issues/320))
- The email service can send through an SMTP server that takes OAuth tokens
  (SASL `OAUTHBEARER`, or `XOAUTH2`), such as Stalwart: the **SMTP server with
  OAuth** transport on **Admin → Email** stores no mailbox password. Forge
  registers itself with the mail server's authorization server (RFC 7591,
  authenticated by an initial access token or an account, which are never
  stored) or uses a client entered by hand, and the mailbox authorizes it once,
  in the browser (the code flow with PKCE) or with a code on another device (RFC
  8628); the client credentials grant works too. Forge refreshes its access
  token, stores a rotated refresh token sealed at rest, and asks for a new
  authorization on the page when a refresh is refused. `docs/deployment.md`
  walks through the setup with Stalwart.
  ([#321](https://github.com/forgepkg/forge/issues/321))
- Users are invited instead of given a password: **Admin → Users → New user**
  creates the account with its email address and access level (reader, writer
  or admin), and Forge emails its user a single-use link,
  `/invite#<token>`, with which they choose their own password before signing
  in. The user's page resends the invitation, copies a new link (shown once,
  for an install without email) or revokes it, and the users list shows who is
  still invited. Only the token's hash is stored; the link expires after the
  lifetime set on the email settings page (72 hours by default), and
  deactivating or deleting the account revokes it. Until the password is
  chosen the account signs in by no path, and no credential-forwarding or OIDC
  realm can take its name.
  ([#322](https://github.com/forgepkg/forge/issues/322))
- The web UI manages RBAC without the `/admin` API: roles with their grants
  and members (deleting a role first names the users and grants it takes
  along), content selectors (with a box that tests a package name against the
  patterns, and a delete that first names the grants it removes), each user's
  roles and effective access, and token scopes, which a token gets when it is
  created and an administrator can change later. The user list shows each
  user's roles instead of `admin` or `reader`, a repository's page shows the
  anonymous role's grants on it next to its anonymous-read flag, and a
  workload-identity rule picks its role from a list. For these screens,
  `GET /admin/roles` counts each role's grants and users,
  `GET /admin/roles/{id}/users` lists its members,
  `GET /admin/content-selectors/{id}/grants` lists the grants a selector
  scopes, `POST /admin/content-selectors/match` tests a package name, a user
  lists its `roles`, and `GET /browse/repos` gives each repository's `id`.
  ([#369](https://github.com/forgepkg/forge/issues/369))
- Tokens created in the web UI now expire after 90 days by default, with 30-day,
  one-year, custom-date and no-expiry choices. Expiry is shown when the secret is
  created and in token lists; the API rejects an expiry that is not in the future.
  ([#371](https://github.com/forgepkg/forge/issues/371))
- A user's page (**Admin → Users → <user>**) deactivates, reactivates and signs
  the user out everywhere, each after a confirmation that says what happens,
  without the `/admin` API. Deactivating refuses every sign-in, ends the
  user's sessions and revokes a pending invitation; their tokens are refused
  but not revoked, so reactivating lets them work again, and the confirmation
  counts them. Deactivating the last active administrator is refused with the
  server's reason. Signing out everywhere ends the user's browser sessions;
  for a credential-forwarding account it also checks the password against the
  upstream again and revokes the tokens minted from a forwarded sign-in. The
  delete confirmation suggests deactivating an account that should be kept.
  ([#372](https://github.com/forgepkg/forge/issues/372))
- Each hosted or proxy repository has a Retention screen (**Repositories →
  <name> → Retention**): it edits the repository's policy rule by rule (package,
  proxy eviction, raw file or image rules, by the repository's format), previews
  what the policy in the form would remove before it is saved, asks before
  saving a policy whose runs delete and before removing one, starts a run, shows
  the last run, and lists the audit log, filtered to one run and paged back.
  `POST /admin/repositories/{name}/retention/preview` takes a draft `policy` to
  evaluate in place of the stored one: it is checked like a `PUT` of it,
  evaluated even when disabled, and never stored. Until now retention was
  managed through the admin API only.
  ([#373](https://github.com/forgepkg/forge/issues/373))
- Administrators can permanently delete a hosted package version from its package page after confirming the repository, package and version.
  ([#374](https://github.com/forgepkg/forge/issues/374))
- The web UI has a design of its own: Forge's design system replaces the
  Catalyst kit on every screen. A navigation rail takes the place of the top
  bar, with the places, the administration screens and the repositories you
  can read, each with its kind and format; on phones it opens as a drawer.
  Screens open with a header of breadcrumbs, title, badges and actions, lists
  are tables, and detail screens show their connect and install commands next
  to the content. The interface uses IBM Plex Sans and JetBrains Mono, served
  by Forge itself, and offers three themes (Light, Light with dark rail and
  Dark; System follows the operating system). Deleting files and revoking
  tokens ask for confirmation in a dialog.
  ([#397](https://github.com/forgepkg/forge/issues/397))
- Administration has a System screen: it lists the keys of the secret
  encryption at rest, rotates the data key or the key-encryption key and re-wraps the
  keys under the current root key after asking first, and shows the local blob
  cache of the instance that answered: its hit ratio, what it served, its size
  against the limit, its evictions and whether S3 is reachable. Until now these
  were `GET /admin/crypto/keys`, `POST /admin/crypto/rotate/{dek,kek,root}` and
  `GET /admin/blob-cache` only.
  ([#404](https://github.com/forgepkg/forge/issues/404))
- Grants and token scopes give ordered access levels, `read` < `write` <
  `delete`, each including the ones below it: one grant gives full access to a
  repository, a role can no longer push to a repository it cannot pull from,
  and a content selector on a `write` grant filters what its holder reads as
  well as what it publishes. A role holds one grant per repository and
  selector. The role page and the token dialogs pick one level, labelled with
  the Nexus actions it covers (`read`: browse, read; `write`: add, edit;
  `delete`: delete), and a token's admin opt-in is a checkbox of its own.
  `docs/deployment.md` describes the levels.
  ([#411](https://github.com/forgepkg/forge/issues/411))
- Retention policies can set a per-repository logical size budget. When a
  repository exceeds its maximum, retention evicts least-recently used eligible
  content toward a configurable target, while preserving rule protections. The
  Retention screen shows the current repository size and budget status.
  ([#417](https://github.com/forgepkg/forge/issues/417))
- **Admin → Retention** switches retention runs off and on for every repository
  and instance, and sets how long the retention audit log is kept. While runs
  are off no run starts, a run in progress stops before its next batch, Run now
  answers 409, and each repository's Retention screen says so; policies can still
  be edited and previewed. A failed run is retried after its policy's interval
  rather than the old global default.
  ([#429](https://github.com/forgepkg/forge/issues/429))
- Raw file repositories are a format plugin, `crates/formats/raw`, like
  NuGet: the plugin speaks the raw protocol (paths, checksum sidecars,
  listings, Nexus' form fields, a proxy's upstream URLs) and the server's new
  file store keeps the files. The plugin contract gains a second storage
  model for this: a format whose descriptor says `Storage::Files` asks the
  host for files and directories, stores and deletes files, and serves a file
  with `Action::ServeFile`; `render` may now answer with any action `handle`
  can. `GET /admin/formats`
  and the repositories API report what a repository holds (`storage`:
  `packages`, `files` or `images`). See
  [docs/format-plugins.md](docs/format-plugins.md#files-formats).
  ([#431](https://github.com/forgepkg/forge/issues/431))
- Docker / OCI is a format plugin, `crates/formats/docker`, like NuGet and
  raw: the plugin speaks the distribution-spec protocol (paths, names,
  manifests, error answers, Helm charts, an upstream registry's URLs), and the
  server's image store keeps the images, the registry tokens and the
  authorization. `/v2` answers as before. The plugin contract gains a third
  storage model for this, images: a plugin whose descriptor says
  `Storage::Images` asks the host for manifests, blobs, tags and referrers,
  runs upload sessions and stores manifests through it, and serves a blob or
  a manifest with `serve-blob` and `serve-manifest`; a proxy's plugin names
  the upstream's URLs and the host fetches them, exchanging the upstream's
  Bearer tokens. `GET /admin/formats` lists Docker from its descriptor, with
  its version and description. See
  [docs/format-plugins.md](docs/format-plugins.md#images-formats).
  ([#447](https://github.com/forgepkg/forge/issues/447))
- npm can publish from GitHub Actions and GitLab CI, including self-hosted
  GitLab, without a stored token through its native OIDC token exchange.
  Exchanged keys use the workload realm's lifetime, claim rules and repository
  permissions, including a group's writable member.
  ([#467](https://github.com/forgepkg/forge/issues/467))

### Fixed

- A database failure while checking a browser session or its CSRF token
  answered 500; it answers 503 with `Retry-After`, like the token and
  password checks, which now send `Retry-After` too.
  ([#205](https://github.com/forgepkg/forge/issues/205))
- Trusted publishing: a workload token answered 401 "invalid credentials"
  while its issuer's discovery document or keys could not be fetched and
  were not cached yet (after a restart, on a new replica, at the hourly key
  refresh), so CI jobs failed instead of retrying. It answers 503 with
  `Retry-After`, at the token exchange too.
  ([#202](https://github.com/forgepkg/forge/issues/202))
- Trusted publishing: after a realm edit, the other instances refused the
  workload keys the editing instance issued under the new configuration
  for up to `auth.realm_cache_ttl_seconds`, and could refuse an exchange
  with 401 "realm changed during the exchange". An instance now reloads
  the realms when a key names a configuration it does not have yet.
  ([#203](https://github.com/forgepkg/forge/issues/203))
- Trusted publishing: an instance whose clock ran behind the database's
  could exchange a CI token a second time just after the record of its
  first exchange was cleaned up. Whether a token has expired is decided on
  the database's clock, and the record is kept 15 minutes past the token's
  expiry. ([#204](https://github.com/forgepkg/forge/issues/204))
- Docker registry: a registry token got with a workload key
  (`docker login -u oidc`) worked again once the key's record was cleaned
  up, and one got with a CI token directly stopped working when a key
  exchanged from that CI token ended. A registry token stands and falls
  with the credential it was got with, and expires no later than it.
  ([#201](https://github.com/forgepkg/forge/issues/201))
- S3 `default_chain` credentials: an STS or container credentials endpoint
  that could not be reached counted as a refusal, so requests answered 500
  instead of 503, and with the blob cache an instance restarted during the
  outage failed to start instead of starting degraded.
  ([#208](https://github.com/forgepkg/forge/issues/208))
- Blob cache: making room deleted the evicted files while every cache hit
  on the instance waited, on the threads that serve requests, and each
  miss read the disk's free space. Evicted files are deleted in the
  background, and the free space is read once a minute.
  ([#212](https://github.com/forgepkg/forge/issues/212))
- Blob cache: after a restart, concurrent downloads of a cached blob each
  read and hashed the whole file before serving it; each file is checked
  once. ([#210](https://github.com/forgepkg/forge/issues/210))
- Blob cache: a blob garbage collection deleted stayed in the other
  instances' caches until it was evicted. Every instance drops such blobs
  at startup and every 10 minutes.
  ([#211](https://github.com/forgepkg/forge/issues/211))
- Docker registry: while S3 was unavailable, uncached pulls, pushes and the
  finish of a chunked upload answered 500 instead of 503 with
  `Retry-After`, and an upload whose body the client aborted answered 500
  instead of 400. ([#209](https://github.com/forgepkg/forge/issues/209))
- Blob cache: a docker blob pushed in several chunks was cached about twice:
  every chunk was written through to the cache next to the assembled blob,
  and evicted as much content that is downloaded. Only the blob is cached.
  ([#213](https://github.com/forgepkg/forge/issues/213))
- Blob cache: with several replicas, `GET /admin/blob-cache` answered with
  the statistics of whichever replica served the request, without saying
  which one. The response names it in `instance` (host name and start
  time), and the deployment guide says the numbers are per instance.
  ([#214](https://github.com/forgepkg/forge/issues/214))
- Docker image retention kept deleting what a run had decided after its
  policy was disabled, switched to dry run or changed, after the run lost
  its lease, and when the image changed meanwhile: it deleted a tag pulled
  since, older tags after the newest were deleted, and the signature of an
  image tagged again. Like package retention, a run now stops when its
  policy or lease changes, and applies an image's decisions only after
  evaluating its current state again.
  ([#215](https://github.com/forgepkg/forge/issues/215))
- Docker proxies: a tag list was cut short, without a link to the next
  page, when the upstream paged its tags (`Link: rel="next"`, as Quay
  does) or refused a large `n` (then only the cached tags were listed), so
  Renovate, Flux or `skopeo list-tags` missed tags; groups inherited it. A
  proxy follows the upstream's pages, asks again without `n` when one is
  refused, and links to its next page when the upstream has more. A group
  ends its page where a member left tags out.
  ([#216](https://github.com/forgepkg/forge/issues/216))
- Docker proxies: a fetch from the previous upstream that was still running
  when the proxy was pointed at another `remote_url` cached its tag,
  manifest or layer after the repoint had emptied the cache, so the
  previous upstream's tag was served for `metadata_ttl_seconds`. Such a
  fetch caches nothing; its client is asked to retry (503).
  ([#217](https://github.com/forgepkg/forge/issues/217))
- Docker registry: the sweeper could release a layer a client had just
  confirmed, so the manifest push answered `MANIFEST_BLOB_UNKNOWN`: a pull
  or `HEAD` of a blob recorded its use at most hourly, which with
  `docker.unreferenced_blob_ttl_seconds = 3600` left no time, and pushing
  or mounting a blob the image already had recorded none. Pushes and
  mounts record the use, and pulls record it every tenth of the TTL.
  ([#218](https://github.com/forgepkg/forge/issues/218))
- Docker groups named their `writable_member` by name: renaming that
  repository broke group pushes, and a repository created later under the
  old name silently became the push target. The member is stored by id, and
  the admin API and web UI show its current name.
  ([#219](https://github.com/forgepkg/forge/issues/219))
- Proxies of a format plugin (NuGet, npm): an upstream that refuses the
  proxy's credentials (401, 403), or serves a package the proxy does not take
  (too large, unreadable, not the version asked for, not matching the digest
  the upstream publishes), with nothing cached for the request, answered 500.
  It answers 502: the upstream or the proxy's settings need fixing, retrying
  does not help.
  ([#41](https://github.com/forgepkg/forge/issues/41))
- Proxies: `server.request_timeout_seconds` (900 s) cut off a first download
  long before `proxy.download_timeout_seconds` (1800 s), since a proxy stores
  the whole package or layer before it answers; a large layer from a slow
  upstream answered 408 and could never be cached. A download from the
  upstream extends its request's deadline to its own, and the request has
  `request_timeout_seconds` again after it.
  ([#220](https://github.com/forgepkg/forge/issues/220))
- NuGet proxies: a package id the upstream answered 404 for stayed hidden for
  `metadata_ttl_seconds`, whatever `not_found_ttl_seconds` said (0 included):
  the "unknown id" listing was cached for the metadata TTL on every instance.
  With a shorter not-found TTL, a package published upstream meanwhile
  answered 404 to restores, and with a package delay its downloads failed
  too. The cached answer now stands only while the id's not-found marker
  does.
  ([#222](https://github.com/forgepkg/forge/issues/222))
- Proxies: a failed upstream version listing was not remembered, so during an
  upstream outage every listing, registration or package-delay check waited
  for the upstream to time out (15–60 s) before serving the cached versions;
  a restore of hundreds of cached packages took many minutes or timed out.
  For a minute after the upstream was unavailable for a listing (no answer, a
  timeout, a 5xx or a 429), ids with cached versions are answered from the
  cache without asking the upstream; ids without still ask it. A listing that
  failed for one id alone (an unusable document) does not hold back the
  others.
  ([#223](https://github.com/forgepkg/forge/issues/223))
- A search through a group asked each proxy member's upstream for 1,000 hits,
  even for a page of 20: every search through a group that fronts nuget.org was
  as slow as a 1,000-hit one, and an answer over `proxy.max_metadata_bytes` sent
  the proxy's searches to its cache for a minute. The group asks an upstream for
  the hits its page needs (32 for a page of 20), and for more only while the
  proxy or the group's guards leave hits out. A group search lists its hosted
  members' packages first, then the upstreams' in the upstreams' own (relevance)
  order rather than by id, and its total is an estimate while an upstream has
  more hits than it returned.
  ([#224](https://github.com/forgepkg/forge/issues/224))
- Format plugins: a version several kilobytes long passed validation and
  failed its database insert, so a push answered 500 instead of 400, and so
  did a proxy asked for such a version. Every format plugin's ids are now at
  most 512 bytes and its versions at most 256: a longer one is refused with
  400 on push, answers 404 in a URL, and is left out of a proxy's upstream
  version listings.
  ([#231](https://github.com/forgepkg/forge/issues/231))
- Helm chart: `strategy.type: Recreate`, which a blob cache on a ReadWriteOnce
  volume needs, kept the default's `rollingUpdate`, so the API server refused
  the Deployment and `helm install` / `helm upgrade` failed. The chart leaves
  `rollingUpdate` out of a Recreate strategy.
  ([#235](https://github.com/forgepkg/forge/issues/235))
- Image listings now show accurate totals and allow paging through every image,
  including in repository groups and with content selectors, instead of stopping
  at 5,000 images per member. Image search is now case-insensitive.
  ([#242](https://github.com/forgepkg/forge/issues/242))
- The repository edit screen loads format metadata, restoring upload-size defaults
  and client-side staging-ceiling validation, and showing plugin format names and
  feed paths correctly.
  ([#243](https://github.com/forgepkg/forge/issues/243))
- The image page's pull commands started with the first tag by name: for a
  signed image a cosign `sha256-….sig` signature, otherwise often the oldest
  version. They start with `latest`, else the most recently pushed image tag,
  and skip signature, attestation and SBOM tags.
  ([#245](https://github.com/forgepkg/forge/issues/245))
- **Admin → Authentication**: one click on a workload-identity realm's
  *Enabled* switch disabled it at once, which revokes every API key its token
  exchange issued, for good. Disabling one now asks first, and so does saving
  an enabled one on its edit page, which revokes the keys too.
  ([#247](https://github.com/forgepkg/forge/issues/247))
- Proxies of a format plugin (NuGet): an upstream that could not be
  reached (connection refused, a name that does not resolve, a timeout) or
  answered a 5xx or 429, with nothing cached for the request, answered 500
  and logged an error, as if Forge were broken. It answers 503 with
  `Retry-After`, like the docker registry's proxy, and logs a warning naming
  the upstream. A group whose member failed this way answers the same.
  Credentials the upstream refuses answer 502.
  ([#283](https://github.com/forgepkg/forge/issues/283))
- Web UI: a link whose query value looked like a number or a boolean lost
  it, because the router read the value as JSON: `?tag=1.36` on an image page
  showed the pull commands of the default tag, `?tag=1.10` was even read as
  `1.1`, `?q=1.0` on a repository page searched for `1`, and `?path=2026`
  missed the directory `2026/` of a raw repository. Every query value is now
  read as the text it is. Links the web UI wrote before, such as
  `?tag=%221.36%22`, still work, and the links it writes are plain
  (`?tag=1.36`).
  ([#403](https://github.com/forgepkg/forge/issues/403))
- Widen the L1 cache TTL tests' timing windows to avoid spurious failures on busy CI runners while preserving their cache reuse and expiry checks.
  ([#471](https://github.com/forgepkg/forge/issues/471))
- Proxies: a version listing the upstream answered unusably (a document over
  `proxy.max_metadata_bytes`, or one without the versions) answered 500 when
  nothing was cached; it answers 502, like an upstream that refuses the proxy.
  ([#488](https://github.com/forgepkg/forge/issues/488))

### Security

- Proxy search no longer lets rejected search parameters disable upstream search
  for other callers for a minute. Only upstream outages trigger search backoff;
  NuGet search offsets above 3,000 use locally cached packages instead.
  ([#225](https://github.com/forgepkg/forge/issues/225))
- A proxy repository's format plugin could make Forge send a GET to any
  address Forge reaches, a loopback or private service included, and read the
  answer back into what the proxy serves. Forge now sends the requests a
  format asks for, and downloads its packages, only from the origin of the
  repository's `remote_url` and from origins that documents fetched from that
  upstream name (a NuGet service index's resources on other hosts); any other
  request is refused and logged as a warning.
  The documents an upstream serves still decide which hosts become reachable,
  so confine Forge's egress with network policy where internal services must
  stay out of reach.
  ([#233](https://github.com/forgepkg/forge/issues/233))
- The S3 client no longer compiles in SigV4a signing, and with it
  `crypto-bigint` 0.5.5 (RUSTSEC-2026-0387): several of its operations meant
  to run in constant time did not. The AWS SDK used it only to derive SigV4a
  signing keys, which sign requests to AWS S3 Multi-Region Access Points (a
  bucket given as an `arn:aws:s3::…:accesspoint/….mrap` ARN), a setup Forge
  never documented or tested; requests to such a bucket now fail.
- The `ctutils` crate moves from 0.4.2 to 0.4.5 (RUSTSEC-2026-0385): 0.4.2
  generated its masks and compared `u128` values in non-constant time. Forge
  uses it through the AES-GCM encryption of stored secrets and the hash crates.

### Documentation

- `forge.toml.example` suggested `blob_cache.path = "/var/cache/forge"`, where
  the Kubernetes manifests mount the cache volume. A volume's mount root
  belongs to root, and startup refuses a cache directory Forge's user does not
  own. The example suggests `/var/cache/forge/blobs`, a directory Forge
  creates in the volume, like the deployment docs.
  ([#236](https://github.com/forgepkg/forge/issues/236))
- Contributions from outside the forgepkg organization now require signing the
  Contributor License Agreement (`CLA.md`) once, which grants forgepkg the
  rights to distribute them under the MIT License or other terms.
  `CONTRIBUTING.md` explains how to sign.

### Known limitations

- npm's password login (`npm login --auth-type=legacy`) refuses a username
  with an `@`, which every Forge account has: log in in the browser
  (`npm login`), with `yarn npm login`, or with an API token from the web UI.
  A publish with a provenance statement (`npm publish --provenance`) is
  refused, and `npm access`, `npm owner`, `npm team`, `npm org`, `npm star`
  and `npm token` are not served.
  ([#41](https://github.com/forgepkg/forge/issues/41))

## [1.1.0]

The Docker / OCI registry, format plugins (Helm built in, NuGet ported to
one), the trusted-publishing token exchange, short-lived S3 credentials and a
local blob cache, and the fixes for the findings of the 1.0.0 release review.
The 1.0.0 known limitations still apply, except where an entry below says
otherwise.

### Upgrade notes

- Startup refuses a `server.staging_dir` that does not belong to Forge's
  user, or that group or others can write unless it is sticky like `/tmp`.
  The container image and the Kubernetes manifests are not affected.
  ([#127](https://github.com/schmitch/forge/issues/127))
- Durations above 100 years (`outbox.grace_seconds`,
  `retention.default_run_interval_seconds`, `retention.lease_seconds`,
  `crypto.cache.unwrapped_key_ttl_secs`,
  `crypto.rotation.dek_max_age_days`, `crypto.rotation.kek_max_age_days`,
  and the new `docker.upload_ttl_seconds`,
  `docker.unreferenced_blob_ttl_seconds` and `docker.sweep_interval_seconds`)
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
- Migration 0033 adds the Docker / OCI registry's tables; it changes no
  existing data. To push images through a reverse proxy, allow request
  bodies of a docker repository's upload limit (1 GiB by default: docker
  sends a whole layer in one request) on `/v2`, and serve `/v2` at the root
  of the host. The shipped Ingress now allows 1 GiB. The default
  `server.max_staging_bytes` (four times the largest item) grows with it to
  4 GiB; size the staging volume for it.
  ([#40](https://github.com/schmitch/forge/issues/40))
- An explicit `server.max_staging_bytes` keeps working as it is. When it is
  below the new 1 GiB docker defaults, they shrink to fit it (less
  `nuget.max_nuspec_bytes`): docker repositories without an upload limit of
  their own accept layers up to that size, and so do docker proxy
  downloads unless `docker.max_blob_bytes` is set; startup logs a warning.
  Raise the budget for larger layers. A budget too small for the package
  limits is refused as before, with an error that names the setting that
  decides the minimum. ([#198](https://github.com/schmitch/forge/issues/198))
- The container image's baked `forge.toml` no longer holds the placeholder
  `minioadmin` S3 keys. An image started without `FORGE_S3__ACCESS_KEY` /
  `FORGE_S3__SECRET_KEY` (and without short-lived credentials) still
  refuses to start, now with an error that names the missing keys.
  ([#60](https://github.com/schmitch/forge/issues/60))
- `server.max_upload_bytes` is deprecated: upload limits are now set per
  hosted repository, in the web UI or the admin API. The setting still
  works as the default of package repositories without a limit of their own,
  and startup logs a warning while it is set; give the repositories that
  need it their own limit, then remove it. A repository's limit may be at
  most `server.max_staging_bytes` (less `nuget.max_nuspec_bytes`); raise the
  staging budget first if a repository needs more.
- A workload identity realm's `max_token_age_seconds` defaults to 39600
  (11 hours) instead of 3600, so GitLab jobs with a timeout over an hour
  can publish. Existing realms keep the value they were saved with; to
  use the new default, clear the field in the realm form (or drop the key
  from the config) and save.
- The username `oidc` is reserved for workload identity (trusted
  publishing), and 1.0.0 allowed it. An account named `oidc` can no longer
  sign in with its password, in the browser or over Basic, and its API
  tokens work only as `X-NuGet-ApiKey`, no longer as the Basic password;
  startup logs a warning that names it. A config with
  `auth.bootstrap_admin.username = "oidc"` refuses to start. Rename the
  account before upgrading; there is no API for it, so use SQL:
  `UPDATE app_user SET username = 'oidc-admin' WHERE username = 'oidc';`
  (the account keeps its id, password, roles and tokens). Then set
  `auth.bootstrap_admin.username` to the new name if it was `oidc`.
  ([#199](https://github.com/schmitch/forge/issues/199))
- Migration 0034 adds the `workload_api_key` table for the trusted-publishing
  token exchange; it changes no existing data. `/api/v2/token` is a new
  route, so a reverse proxy that only forwards known prefixes needs `/api`.
  ([#169](https://github.com/schmitch/forge/issues/169))
- `cache.l1_max_capacity` counts an entry over 16 KiB once per started
  16 KiB, so it bounds the in-process cache's memory as well as its entry
  count (about 160 MiB of large entries at the default 10000). Small
  entries count once, as before.

### Features

- **Format plugins** (preview): further package formats, served under
  `/repository/{repo}/` (or a mount the plugin names) with the same
  storage, RBAC and package selectors, hosted, proxy and group
  repositories, retention, ranged downloads and audit log as NuGet. A
  plugin is a crate implementing one contract (`forge-plugin-api`'s
  `FormatPlugin`, mirrored by the `forge:format@0.3.0` WIT package; a
  plugin's `upstream` side tells the host what to fetch for its proxies) and
  runs either built into the server or as a WebAssembly component run by
  Wasmtime. Components are loaded from `[plugins]` only when pinned by
  SHA-256, and each call runs with fuel, memory and time limits and no WASI
  capabilities. **Helm chart repositories** (`plugins/helm`) are built in:
  `index.yaml`, chart downloads and ChartMuseum-compatible push, delete and
  listing, and proxies of other chart repositories. The index lists chart
  metadata with the types Helm reads, so a Chart.yaml with `appVersion: 2`
  or an annotation `false` does not break it
  ([#206](https://github.com/schmitch/forge/issues/206)). A Helm proxy
  parses its upstream's index once while the upstream serves the same
  document, one parse at a time, instead of once per operation
  ([#207](https://github.com/schmitch/forge/issues/207)). Parsed indexes
  are kept up to 128 MiB per instance, shared by all Helm proxies: about
  60 MB of `index.yaml`, enough for every upstream of a typical group. Past
  that, the indexes in use stay kept and only the others are parsed again
  for each operation
  ([#279](https://github.com/schmitch/forge/issues/279),
  [#284](https://github.com/schmitch/forge/issues/284)). **NuGet** is a built-in plugin too (`plugins/nuget`), served at
  `/v3/{repo}/` by the same dispatcher with the same paths, responses and
  proxy behaviour as before; its proxies read the upstream feed through the
  plugin's upstream side. `GET /admin/formats` lists the installed
  formats; the web UI offers them when creating a repository. See
  [docs/format-plugins.md](https://github.com/schmitch/forge/blob/main/docs/format-plugins.md).
- **Docker / OCI registry** under `/v2/` (OCI Distribution Spec v1.1,
  passing its conformance suite), for container images, Helm charts and
  other OCI artifacts, as a native format next to NuGet (`"format":
  "docker"`, listed by `GET /admin/formats`) with all three repository
  kinds:
  - **hosted**: monolithic, chunked and cross-repository-mount pushes,
    deletes, the referrers API for cosign signatures and attestations, and
    optional immutable tags (with a `latest` exception);
  - **proxy**: a pull-through cache of Docker Hub (with its `library/`
    names), GHCR, Quay or any distribution-spec registry, with upstream
    credentials, tag re-validation by `HEAD` after `metadata_ttl_seconds`,
    and stale serving while the upstream is down or rate limits;
  - **group**: members by priority, pushes to a `writable_member`, and the
    `prefer_hosted` / `reserved_prefixes` / owner guards of NuGet groups.

  `docker login` goes through a Bearer token service (API tokens, passwords
  where allowed, or a workload OIDC token), anonymous pulls follow the
  repository's anonymous read, and repositories are addressed by path or by
  an optional host name of their own. Image retention rules (keep the last N
  tags, stale tags, untagged manifests; a `HEAD` of a manifest counts as a
  pull, [#197](https://github.com/schmitch/forge/issues/197)) and a sweeper
  release layers only when no image references them. The web UI lists images, tags, manifests,
  platforms and referrers. New `[docker]` settings; see
  [docs/docker.md](https://github.com/schmitch/forge/blob/main/docs/docker.md).
  ([#40](https://github.com/schmitch/forge/issues/40))
- **Per-repository upload limits**: every hosted repository (NuGet, Helm,
  docker or a WebAssembly plugin format) has its own upload limit, the
  largest push it accepts (docker: per blob), editable as *Maximum upload
  size* in the web UI and as `max_upload_bytes` in the admin API. Without
  one, a repository accepts 512 MiB (docker 1 GiB per blob).
  `docker.max_blob_bytes` now bounds proxy downloads only.
- **Browse by format**: `GET /browse/repos` takes `format` and names each
  repository's client URL; the web UI's *Browse* screen filters by format,
  and NuGet and Helm repositories show their `dotnet nuget` and `helm`
  commands (other plugin formats, their URL) like docker ones show theirs.
  ([#38](https://github.com/schmitch/forge/issues/38))
- **Short-lived S3 credentials** from the platform's workload identity, so
  no long-lived S3 key has to be stored or rotated. `s3.credentials`
  (`FORGE_S3__CREDENTIALS`) is `static` (the default, `s3.access_key` /
  `s3.secret_key` as before), `default_chain` (the AWS SDK chain: IRSA, EKS
  Pod Identity, ECS task roles, EC2 instance profiles, `AWS_*` variables),
  or `web_identity`: a token file exchanged with STS
  `AssumeRoleWithWebIdentity` against AWS or MinIO / Ceph RGW
  (`[s3.web_identity]`: `token_file`, `role_arn`, `sts_endpoint`,
  `session_name`, `duration_seconds`). Credentials are refreshed before they
  expire and the token file is read again on each refresh. A failed fetch
  names the credential source and the STS error code, never the token. The
  short-lived modes refuse S3 keys, and startup warns about a plain-http
  `sts_endpoint` (the token and the temporary keys would cross the network
  in clear text). The Helm chart has `s3.credentials` and
  `s3.webIdentity` (with an optional projected service-account token), and
  the kustomize component `s3-workload-identity` mounts one. See
  [docs/deployment.md](https://github.com/schmitch/forge/blob/main/docs/deployment.md#short-lived-s3-credentials).
  ([#60](https://github.com/schmitch/forge/issues/60))
- **Trusted-publishing token exchange**: `POST /api/v2/token` (nuget.org's
  path and request/response shape, so `NuGet/login` works with
  `token-service-url`) exchanges a CI job's OIDC token, validated by a
  `workload_identity` realm, for a short-lived workload API key
  (`forge_wif.…`). Each token is redeemed once (its `jti` is required), the
  key lives for the realm's new `api_key_ttl_seconds` (default an hour)
  whatever the token's lifetime, it authorizes and is audited as the
  token's workload, and any edit, disabling or deletion of the realm
  revokes its keys for good.
  `dotnet nuget push --source <feed>/v3/<repo>/package --no-service-endpoint
  --api-key <key>` publishes with the key alone; restore takes it as the
  Basic password of the username `oidc`.
  ([#169](https://github.com/schmitch/forge/issues/169))
- **Reserved account names**: `oidc` is the workload-identity Basic
  username. Basic `oidc:<secret>` is only ever checked as a workload
  credential (an OIDC token or a workload key), never as a user token or a
  password and never forwarded to a credential-forwarding upstream, and no
  account can be created, bootstrapped or provisioned under the name (an
  OIDC login whose username claim is `oidc` gets `oidc-2`).
  ([#169](https://github.com/schmitch/forge/issues/169))
- **Proxy cache invalidation**: `POST
  /admin/repositories/{name}/proxy-cache/invalidate`, and *Invalidate
  cache* on a proxy's page in the web UI, make a NuGet, Helm or docker proxy
  ask its upstream again before its TTLs run out, for example once a package
  it answered "not found" for is published upstream. The proxy forgets the
  upstream's "not found" answers (of one package with `{"package": "<id>"}`,
  or of all) and the listings and documents it cached from the upstream, on
  every instance; invalidating the whole repository also refreshes the
  upstream's service index, and a docker proxy re-validates its tags (of one
  image, or of all) on their next pull. Downloaded packages, blobs and
  manifests stay cached, and so does the package-delay clock.

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
  PersistentVolume). The cache directory must belong to Forge's user and be
  writable by no one else (startup refuses it otherwise; a directory a
  Kubernetes `fsGroup` pass made group-writable is restored instead), and
  its entries are readable by that user alone. The kustomize base and the
  Helm chart set `fsGroupChangePolicy: OnRootMismatch`
  ([#195](https://github.com/schmitch/forge/issues/195)). See
  [docs/deployment.md](https://github.com/schmitch/forge/blob/main/docs/deployment.md#local-blob-cache).

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
- Docker registry tokens are HS256 JWTs bound to `public_base_url`, live
  for `docker.token_ttl_seconds` (5 minutes), grant only the scopes the
  caller held when they were issued, and are accepted under `/v2` only. A
  token request names at most 32 repositories
  ([#200](https://github.com/schmitch/forge/issues/200)).
  Every registry request is authorized again against current permissions
  and content selectors, the user and API token behind a token must still
  be active, and a browser session never pushes or deletes. The token
  endpoint takes the same Basic credentials as the feeds, so it adds no new
  password path. The signing key is `docker.token_secret`, or a generated
  key kept in the database, sealed when `[crypto]` is enabled and re-sealed
  by DEK rotation; an instance replaces it only when it can never be opened,
  and the others pick the new key up within 30 seconds
  ([#196](https://github.com/schmitch/forge/issues/196)).
- Registry digests are verified on every upload and every proxied blob and
  manifest. Blobs are linked per image: knowing a layer digest grants no
  read on another image's copy, and a mount needs read on the source image.
  A docker proxy sends upstream credentials only to its `remote_url` origin
  and the token realm the upstream's challenge names (over https when the
  upstream is https), and drops `Authorization` on a redirect to another
  host. Registry responses carry the feeds' hardening headers and
  `Vary: Authorization, Cookie, Accept`.

### Documentation

- The deployment guide lists the S3 permissions and the PostgreSQL role
  Forge needs, and an S3 delete that is denied names the missing
  `s3:DeleteObject`. ([#114](https://github.com/schmitch/forge/issues/114))

### Known limitations

- With a package delay, proxy search shows a version only once the proxy
  has recorded it and the delay has passed, because a search answer names
  no publish times. Totals of a proxy search are the upstream's, less the
  ids dropped from the returned page; for a caller whose content selectors
  hide packages, they count what it sees, plus one while more may follow.
- Behind an outbound proxy, a host name that resolves differently for the
  proxy than for Forge, or that only the proxy can resolve, still gets
  past the metadata guard; block those addresses on the proxy as well.
- Format plugins receive no request bodies other than the published
  package (which must be the whole body or one multipart part), accept only
  Basic credentials, and treat a version with a `-` as a prerelease; a
  response of a plugin may load at most 2,048 query answers. Helm refuses a
  `Chart.yaml` or `index.yaml` whose YAML aliases would add more than
  100,000 nodes, or that nests deeper than 64 levels. Their proxies
  read the upstream with plain GETs of whole documents (Basic credentials
  only, no token exchange).
- A docker proxy downloads a blob completely and verifies it before it
  answers, so a client waits for a large layer's first fetch; concurrent
  pulls of one layer share a download per instance only. A registry upload
  of several chunks is assembled into a new blob when it finishes (one-chunk
  uploads, what docker, podman and containerd send, are stored once). The
  registry has no catalog API (`/v2/_catalog`) and no per-repository
  connector ports.

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

[Unreleased]: https://github.com/forgepkg/forge/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/forgepkg/forge/releases/tag/v1.1.0
[1.0.0]: https://github.com/forgepkg/forge/releases/tag/v1.0.0
