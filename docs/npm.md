# npm registries

Forge serves npm packages to npm, pnpm, Yarn (1 and 2+) and Bun: publish,
install, dist-tags, deprecations, unpublishing, search, `npm audit` and the
logins. Repositories of `format: "npm"` are served at
`https://<host>/npm/<repository>/`, in the usual three kinds:

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
registry=https://forge.example.com/npm/npm-all/
//forge.example.com/npm/npm-all/:_authToken=<token>
```

Only one scope from Forge, the rest from elsewhere:

```ini
@acme:registry=https://forge.example.com/npm/npm-all/
//forge.example.com/npm/npm-all/:_authToken=<token>
```

**Yarn 2 and later** read `.yarnrc.yml`:

```yaml
npmRegistryServer: "https://forge.example.com/npm/npm-all/"
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
npm login --registry https://forge.example.com/npm/npm-all/
npm whoami --registry https://forge.example.com/npm/npm-all/
```

Without a browser on the machine (`--browser=false`), npm prints the page's
URL to open elsewhere. A login waits for its approval for
`cli_login.web_login_ttl_seconds` (10 minutes), and the page answers only
the signed-in user who opens it. Logins in the browser need the web UI
(`[web] enabled`); without it npm falls back to asking for a password.

**A username and a password**: `yarn npm login` (Yarn 2+) and `npm login
--auth-type=legacy` send them to Forge, which checks them like the web
login does (local passwords, credential forwarding, the lockout after
failed attempts) and mints a token. No account is ever created by a login.
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

## Publishing

```bash
npm publish --registry https://forge.example.com/npm/npm-hosted/
pnpm publish --registry https://forge.example.com/npm/npm-hosted/
yarn npm publish            # with npmRegistryServer / npmPublishRegistry set
bun publish --registry https://forge.example.com/npm/npm-hosted/
```

Publishing needs the level **write** and an API token (a password typed
at the web login is not a publishing credential); CI jobs can use a
[trusted publishing](trusted-publishing.md) token instead. Publishing to a
group goes to its writable member.

Forge checks what it stores:

- the tarball's `package/package.json` names the package and version the
  document publishes, and the integrity (`sha512`) and `shasum` the client
  claims match the tarball;
- the name is a valid npm name (scoped or not; at most 214 characters,
  lowercase for new names) and the version valid SemVer;
- the tarball is a gzip'd tar that unpacks to at most `npm.max_unpacked_bytes`;
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
  and kept; one that does not hold up is refused (502) and not stored.
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

## Audits

`npm audit` (and `pnpm audit`) asks the registry for advisories. A proxy
passes the request on to its upstream with its credentials, and a group to
its first proxy member; a group leaves the packages under its reserved
prefixes out, so your internal package names stay inside. A hosted
repository has no upstream to ask (404). Auditing needs `read`.

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
