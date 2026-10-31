# npm registries

Forge serves npm packages to npm, pnpm, Yarn (1 and 2+) and Bun: publish,
install, dist-tags, deprecations, unpublishing, search, `npm audit` and the
logins. Repositories of `format: "npm"` are served at
`https://<host>/repository/<repository>/`, in the usual three kinds:

- **hosted**: publish and install your own packages;
- **proxy**: a cache of another registry, `https://registry.npmjs.org` or a
  private one;
- **group**: one registry URL over several members, which keeps your scopes
  internal and passes `npm audit` on to the public registry.

npm is a format plugin built into Forge ([`crates/formats/npm`](../crates/formats/npm),
[format-plugins.md](format-plugins.md)): tarballs are blobs in the
content-addressed store, and repositories, access levels, package selectors,
retention and the web UI are the same as for every other format.

## Contents

- [Repositories](#repositories)
- [Connecting a client](#connecting-a-client)
- [Logging in](#logging-in)
- [Publishing](#publishing)
- [Dist-tags, deprecations and unpublishing](#dist-tags-deprecations-and-unpublishing)
- [Installing and searching](#installing-and-searching)
- [Proxy repositories](#proxy-repositories)
- [Group repositories](#group-repositories)
- [Importing another registry](#importing-another-registry)
- [Audits](#audits)
- [Permissions](#permissions)
- [Retention](#retention)
- [Limits](#limits)
- [Limitations](#limitations)

## Repositories

Create them in the web UI (**Admin → Repositories → New repository**, format
*npm*) or with the admin API:

```bash
api() { curl -fsS -u admin@example.com:<admin-token> -H 'content-type: application/json' "$@"; }
api https://forge.example.com/admin/repositories \
  -d '{"name": "npm-hosted", "kind": "hosted", "format": "npm"}'
api https://forge.example.com/admin/repositories \
  -d '{"name": "npm-proxy", "kind": "proxy", "format": "npm", "remote_url": "https://registry.npmjs.org"}'
api https://forge.example.com/admin/repositories \
  -d '{"name": "npm-all", "kind": "group", "format": "npm",
       "reserved_prefixes": ["@acme"], "writable_member": "npm-hosted"}'
api https://forge.example.com/admin/repositories/npm-all/members -d '{"member": "npm-hosted", "priority": 10}'
api https://forge.example.com/admin/repositories/npm-all/members -d '{"member": "npm-proxy", "priority": 5}'
```

Most teams point their clients at the group: it serves the internal packages
and the public ones, takes publishes (into its writable member) and audits.

## Connecting a client

A repository's page in the web UI shows its registry URL and these lines,
ready to copy.

**npm, pnpm, Bun and Yarn 1** read `.npmrc` (the project's, or `~/.npmrc`):

```ini
registry=https://forge.example.com/repository/npm-all/
//forge.example.com/repository/npm-all/:_authToken=<token>
```

Only one scope from Forge, the rest from elsewhere:

```ini
@acme:registry=https://forge.example.com/repository/npm-all/
//forge.example.com/repository/npm-all/:_authToken=<token>
```

**Yarn 2 and later** read `.yarnrc.yml`:

```yaml
npmRegistryServer: "https://forge.example.com/repository/npm-all/"
npmAlwaysAuth: true
npmAuthToken: "<token>"
```

The token is an API token: one `npm login` mints (below), or one you create
under **Your tokens** in the web UI. An API token of yours works for every
repository you may read, unless its scope limits it; Forge sees whose it
is, not which repository it was minted for. A repository that allows anonymous reads needs no token to
install from.

## Logging in

**`npm login`** (npm 9 and later, and `pnpm login`) opens a page of Forge in
the browser. Sign in there as always (a password or your organization's
OIDC provider), check the client, repository and host name it shows, and
approve; the client then stores a new API token in `.npmrc`:

```bash
npm login --registry https://forge.example.com/repository/npm-all/
npm whoami --registry https://forge.example.com/repository/npm-all/
```

Without a browser on the machine (`--browser=false`), npm prints the page's
URL to open elsewhere. A login waits for its approval for
`cli_login.web_login_ttl_seconds` (10 minutes), and the page answers only
the signed-in user who opens it.

**A username and a password**: `yarn npm login` (Yarn 2+) and `npm login
--auth-type=legacy` send them to Forge, which checks them through the realms
that accept passwords from clients ([Admin →
Authentication](deployment.md#passwords-from-clients): a credential-forwarding
realm by default, the local realm once it is set to), with the lockout after
failed attempts, and mints a token. No account is ever created by a login.
npm's legacy login refuses a username containing an `@`, which every Forge
account has (an e-mail address): use the browser login, Yarn's, or a token
from the web UI.

A token a login mints carries your rights, expires after
`cli_login.token_lifetime_days` (90 days; `0`: never), and is listed and
revocable under **Your tokens** like every other. **`npm logout`** revokes
the token it logged in with. Logins, the tokens they mint and logouts are
audit-logged (`forge::audit`).

```toml
[cli_login]
token_lifetime_days   = 90
web_login_ttl_seconds = 600
```

The same `[cli_login]` lifetimes apply to the [device
login](deployment.md#device-login) that Forge's command-line helpers
(`forge login`, `docker-credential-forge`, `nuget-plugin-forge`) sign in
with: the user approves it with a code on the web UI's `/device` page.

## Publishing

```bash
npm publish --registry https://forge.example.com/repository/npm-hosted/
pnpm publish --registry https://forge.example.com/repository/npm-hosted/
yarn npm publish            # with npmRegistryServer / npmPublishRegistry set
bun publish --registry https://forge.example.com/repository/npm-hosted/
```

Publishing needs the level **write** and an API token (a password typed
at the web login is not a publishing credential); CI jobs can use a
[trusted publishing](trusted-publishing.md#npm) token instead: npm 11.5.1+
automatically exchanges GitHub Actions or GitLab CI (including self-hosted
GitLab) identity tokens, with no stored `_authToken`. Publishing to a
group goes to its writable member.

Forge checks what it stores:

- the tarball's `package/package.json` names the package and version the
  document publishes, and the integrity (`sha512`) and `shasum` the client
  claims match the tarball;
- the name is a valid npm name (scoped or not; at most 214 characters,
  lowercase for new names) and the version valid SemVer;
- the tarball is a gzip'd tar that unpacks to at most `npm.max_unpacked_bytes`,
  read as npm unpacks it: one that npm would read otherwise than its headers
  say (a header npm rejects, data after the end of the archive, a PAX record
  npm reads otherwise, a file some client may unpack to `package.json` other
  than `<first>/package.json`) is refused, whether published or fetched
  through a proxy. `npm pack` writes none of these;
- the tarball fits the repository's upload limit (*Maximum upload size*,
  512 MiB by default), and the rest of the document `npm.max_document_bytes`.

A version that exists is refused (409), as on the public registry, unless
the repository's **deployment policy** allows redeploys (which needs the
level `delete`). The policy *read-only* refuses every publish,
unpublish, deprecation and dist-tag change:

```bash
api -X PUT https://forge.example.com/admin/repositories/npm-hosted \
  -d '{"deployment_policy": "read_only"}'
```

The dist-tags of the publish (`npm publish --tag next`; `latest` by default)
are set with it. Package selectors apply as for every format: a caller
whose selector covers the `@acme` scope only cannot publish `left-pad`.

## Dist-tags, deprecations and unpublishing

```bash
npm dist-tag add @acme/ui@2.0.0-rc.1 next
npm dist-tag rm @acme/ui next
npm dist-tag ls @acme/ui
npm deprecate @acme/ui@1.0.0 "use 2.x"
npm deprecate @acme/ui@1.0.0 ""            # undeprecate
npm unpublish @acme/ui@1.0.0
npm unpublish @acme/ui --force             # every version
```

- A **dist-tag** names one version. `latest` is always there: it cannot be
  removed, and when the version it named is gone it moves to the highest
  version left. Deleting a version drops its tags.
- A **deprecated** version still installs; clients warn with its message.
- **Unpublishing** deletes the version (or every version) and needs the
  level **delete**. Unlike on the public registry there is no time
  limit, and a version unpublished may be published again.

Dist-tags and deprecations need `write`. The web UI shows a
package's dist-tags, deprecated versions with their messages, and the
README of its `latest` version.

## Installing and searching

Every client installs from a hosted repository, a proxy or a group:
abbreviated packuments (`application/vnd.npm.install-v1+json`) for clients
that ask for them, full ones (with each version's publish time and the
README of `latest`) for the others, tarballs, `npm view`, `npm search`
(`GET /-/v1/search`, over the repository's packages; a proxy searches its
upstream too) and `npm ping`. Tarballs are served from the store with
counted as downloads. Tarball URLs in a packument point at the
repository it was read from, so a lockfile written through the group keeps
resolving through it.

## Proxy repositories

A proxy reads another registry on demand, `https://registry.npmjs.org` or
any registry that speaks npm's protocol:

- **Credentials.** With a username and a password, it sends Basic
  authentication; with a password alone (a registry token, such as an npm
  automation token or a GitHub Packages token), `Authorization: Bearer`.
  They go to the origin of the remote URL only, never to a tarball host
  elsewhere.
- **Caching.** A packument is read again after the repository's metadata
  TTL; installs read the abbreviated one, `npm view` and clients that want
  publish times (pnpm's `minimumReleaseAge`, `npm install --before`) the
  full one. A package the upstream does not know is remembered for the
  not-found TTL. A tarball is downloaded once, checked against the
  `integrity` (or `shasum`) the upstream publishes and against its version,
  and kept; one that does not hold up is refused (502) and not stored. A
  packument larger than `proxy.max_metadata_bytes` (32 MiB by default) is
  not read (and not downloaded again until the metadata TTL has passed). An
  abbreviated one that large leaves its package served from what is cached
  of it, or answering 502 when nothing is, until the setting is raised. A
  full one that large (`vite`'s is about 39 MB, with its license in every
  version) costs the full packument Forge serves the upstream's publish
  times (its versions' summaries come from the abbreviated packument) and
  the README; a version's manifest is then read from the version's own
  document (`/{name}/{version}`). A few packages publish that many versions
  (`renovate`'s abbreviated packument is about 36 MB, its full one about
  73 MB).
- **The upstream's dist-tags and deprecations** are served as it gives
  them, and the last dist-tags read are kept for when it is down.
- **Publication delay.** `package_delay_seconds` holds back versions
  published upstream less than that long ago (counted from the upstream's
  publish time, not from when Forge first saw them): a new release, possibly
  a compromised one, reaches your builds only after the delay.
- **Outages.** While the upstream is down, what is cached is served: the
  packument as last read, and every tarball downloaded before. A tarball
  never downloaded answers 503 with `Retry-After`. An upstream that refuses
  the proxy's credentials answers 502.
- **Invalidate cache** on the repository's page (or
  `POST /admin/repositories/<name>/proxy-cache/invalidate`) makes it read
  the upstream again now.

Publishing, dist-tag changes and unpublishing are refused on a proxy.

## Group repositories

A group serves its members, by priority:

- a packument merges the versions of every member that has the package (the
  highest-priority member's copy of a version wins), with the **dist-tags**
  of the first member, by priority, that has the package and tags for it;
- **reserved prefixes** (`@acme`, the scope `@acme/`, or a name prefix such
  as `acme-`) are never served from proxy members, also before the first
  internal version is published, so a public package that claims your
  scope or name cannot slip into a build (dependency confusion);
- **prefer hosted** (on by default) hides proxy versions of a package a
  hosted member has;
- the **writable member**, a hosted npm repository that is also a member,
  takes publishes, dist-tag changes, deprecations and unpublishing through
  the group; without one they are refused.

## Importing another registry

An [import](import.md) copies the packages of another registry's hosted
repository (Nexus, Verdaccio, Artifactory, another Forge) into a hosted npm
repository: every version's tarball, its publish time and deprecation, and
the dist-tags. In the web UI, open the hosted repository under **Admin →
Repositories** and choose **Import**, or:

```bash
api https://forge.example.com/admin/repositories/npm-hosted/imports \
  -d '{"url": "https://nexus.example.com/repository/npm-hosted",
       "username": "migrator", "password": "…", "dry_run": true}'
```

The registry's search, or else its `/-/all`, names the packages; `names`
lists packages or scopes (`"names": ["@acme", "left-pad"]`) for a registry
that serves neither. Tarballs come from the import's URL and are checked
against `dist.integrity`; a second run copies only what is new, and moves the
dist-tags the source moved. See [Importing repositories](import.md#npm-dist-tags-and-deprecations).

## Audits

`npm audit` (and `pnpm audit`) asks the registry for advisories. A proxy
passes the request on to its upstream with its credentials, and a group to
its first proxy member the caller may read, through nested groups. A hosted
repository has no upstream to ask (404). Auditing needs `read`.

Through a group, the request leaves out the packages under the reserved
prefixes of every group on the way to that proxy: the group's own, and a
nested group's when the proxy is its member. Your internal package names
stay inside, as they do when you audit the nested group directly. It also
leaves out the packages your content selectors hide on any repository on
the way, the proxy's included: you learn of advisories only for packages
you could read through it. Every audit request is filtered:

- the bulk request of npm 7 and later
  (`/-/npm/v1/security/advisories/bulk`), which names each package once;
- the legacy requests (`/-/npm/v1/security/audits/quick` and `.../audits`:
  npm 6, `pnpm audit`, and npm when the bulk request fails), whose
  dependency tree loses those packages at every depth, aliases of them
  (`npm:@acme/ui@^1.0.0`) and the project's own name when it is under a
  reserved prefix. Of each package only its version, integrity and kind of
  dependency go on.

A request that must be filtered and cannot be is refused (400), never
passed on: a body that is not a JSON object, and a legacy request that
names its packages by their paths in `node_modules` (`packages`, the
lockfile of npm 7 and later). With no reserved prefixes and no selector of
yours on the way, a proxy or a group passes the request on as it is.

## Permissions

Each access level includes the ones below it
([deployment.md](deployment.md#access-levels)):

| What | Level |
| --- | --- |
| Install, `npm view`, search, audit | read |
| Publish, `npm dist-tag add` / `rm`, `npm deprecate` | write |
| Unpublish (a version or the whole package); a redeploy | delete |
| `npm login`, `npm logout`, `npm whoami` | none (a login checks the password) |

Content selectors match package names (`@acme/*`), for every level a grant
includes. An unknown repository answers like one the caller may not read.
A read-only deployment policy refuses every change, whatever the caller's
level.

## Retention

Retention policies apply to npm repositories like to every other format,
with one rule more: **a version a dist-tag names is never deleted** (a
proxy's tags are its upstream's, as last read), so `latest`, `next` and
every other tag keep installing. The preview of a policy lists such
versions as kept.

Package retention policies may include a `size_budget` to evict least-recently
used eligible versions when a repository exceeds its logical size limit. See
[Retention](retention.md#size-budgets) for configuration and size accounting.
The rules themselves, and their schedules, are in [Retention](retention.md).

## Limits

```toml
[npm]
max_document_bytes = 33554432    # 32 MiB: a publish document without its tarball, an update, an audit
max_unpacked_bytes = 1073741824  # 1 GiB: the most a tarball may unpack to
```

A tarball's size is bounded by its repository's upload limit. A login's
body is at most 64 KiB.

## Limitations

- **No provenance.** A publish with a provenance statement (`npm publish
  --provenance`) attaches a second file, which Forge refuses: publish
  without it.
- **No package access management.** `npm access`, `npm owner`, `npm team`,
  `npm org`, `npm star` and `npm token` are not served; access is Forge's
  roles and package selectors, tokens are managed in the web UI.
- **npm's legacy login and `@` usernames.** See [Logging in](#logging-in).
- **One registry per URL.** Clients address a repository by its URL; a
  scope maps to one registry, as in npm.
