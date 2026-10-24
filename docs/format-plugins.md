# Format plugins

Forge serves the Docker / OCI registry natively ([docker.md](docker.md)).
Every package format comes from a **format plugin**: a Rust crate that
teaches Forge the format's rules, its client protocol and, for proxies, how
to read an upstream, by implementing one trait,
[`FormatPlugin`](../crates/plugin-api/src/lib.rs). The repository machinery
stays Forge's own. That covers storage, metadata, authentication, RBAC and
package selectors, hosted, proxy and group repositories, retention, and the
streaming of package bytes.

Every plugin is built in: a crate under `plugins/<id>/` linked into the
server and called directly, like any other Rust code. Plugins need no
configuration. Forge ships two: **NuGet** ([`plugins/nuget`](../plugins/nuget))
and **raw files** ([`plugins/raw`](../plugins/raw),
[Files formats](#files-formats)). Helm charts are served by the registry
([docker.md](docker.md#helm-charts)).

> **Status: preview.** The plugin contract is `forge:format@0.4.0`. It may
> change before 1.x of the contract; a plugin declares the contract version it
> was built for, and the server refuses one it does not implement. 0.4.0 added
> files formats ([Files formats](#files-formats)), and `render` returns an
> action, like `handle`.

## Contents

- [Layout](#layout)
- [How it fits together](#how-it-fits-together)
- [Files formats](#files-formats)
- [Proxy repositories](#proxy-repositories)
- [Using a plugin](#using-a-plugin)
- [Security model](#security-model)
- [Writing a plugin](#writing-a-plugin)
- [Limitations and roadmap](#limitations-and-roadmap)

## Layout

A plugin is a workspace crate with a `plugin.toml`:

```
plugins/nuget/
├── Cargo.toml
├── plugin.toml    # id, name, version, contract version; mount "/v3", kinds hosted/proxy/group
├── src/lib.rs     # impl FormatPlugin for Nuget
├── src/protocol.rs  # the V3 protocol: handle and render
├── src/upstream.rs  # proxies: reading another V3 feed (upstream)
└── tests/         # the protocol against canned answers (forge-plugin-api `testing`)

plugins/raw/
├── Cargo.toml
├── plugin.toml    # mount "/raw", storage "files", kinds hosted/proxy/group
├── src/lib.rs     # impl FormatPlugin for Raw: paths, methods, upstream URLs
├── src/listing.rs # directory listings as HTML or JSON
├── src/sidecar.rs # .sha256/.sha512/.sha1/.md5 from the stored digests
├── src/form.rs    # multipart uploads, Nexus' field names
└── tests/         # the protocol against canned answers
```

The pieces:

| Crate | What it holds |
| --- | --- |
| [`forge-plugin-api`](../crates/plugin-api) | The contract: the `FormatPlugin` trait and its types, and, behind its `testing` feature, helpers that run a plugin's protocol against canned answers. Depends on nothing but `std`. |
| [`plugins/<id>`](../plugins) | One crate per plugin, implementing `FormatPlugin`. |
| [`forge-plugin`](../crates/plugin) | The host side: `Plugin` (an installed plugin: its `plugin.toml` and its implementation) and `PluginFormat`, which adapts it to Forge's `Format` seam. |
| [`forge-server`](../crates/server/src/plugins.rs) | The plugins it links in (`plugins::builtin`), the `{mount}/{repo}/...` dispatcher, and the file store files formats keep their files in ([`crates/server/src/files`](../crates/server/src/files)). |

## How it fits together

| | Forge (the host) | The plugin |
| --- | --- | --- |
| Identity | Calls the format for every id and version it sees | `canonical_id`, `validate_id`, `normalize_version`, `compare_versions` |
| Publishing | Streams the upload to a staging file, enforces the format's upload limit, authorizes against the package selector, stores the blob content-addressed, writes the version in one transaction, records trusted-publishing provenance | `parse_package`: reads the staged file, returns id, version, manifest, dependencies |
| Reads | Runs the queries the plugin asks for through the repository read path (hosted, proxy or group). Package selectors, group membership, prefer-hosted and reserved prefixes all apply | `handle` decides what a request is; `render` turns the loaded data into the response body |
| Downloads | Streams the blob from S3, counts the download, answers `HEAD` without touching S3, and a single `Range` when the local blob cache is on | Names the version (`download`) |
| Unlist, relist, delete | Hosted write path, with the repository's permissions and selectors; a package outside the caller's selector answers 404, like an unknown one | Names the version and the success response |
| Proxies | Sends every upstream request (credentials only to the upstream's origin, bounded, cached), downloads and verifies packages, keeps the package delay, the not-found markers and the offline mode | `upstream`: which documents an operation needs, and what they say ([Proxy repositories](#proxy-repositories)) |
| Groups | Merges members by priority; the dependency-confusion guards apply | Nothing: a group of plugin repositories just works |
| Retention | Evaluates policies, ordering versions with the plugin's `compare_versions` | Nothing more |
| Files (a files format) | Keeps files under paths, content-addressed with their digests: serving, ranges and validators, uploads under the deployment policy, listings, proxies and groups, selectors on paths, retention by path ([Files formats](#files-formats)) | Which path a request names, which file or directory it needs, what the response looks like |

A request to a plugin repository is served under its format's mount,
`{mount}/{repo}/...`: `/repository` unless the plugin's `plugin.toml` names
another (see [Writing a plugin](#writing-a-plugin)); NuGet's names `/v3`.
A repository is served under its own format's mount only.
The dispatcher
([`crates/server/src/plugins.rs`](../crates/server/src/plugins.rs)) handles it
in this order:

1. Resolve the repository and authorize the method:
   GET and HEAD need read, PUT and POST need write, DELETE needs delete.
   Unknown repositories answer like unreadable ones, and offline ones get 503.
2. Call the plugin's `handle` with the repository (name, kind, base URL) and
   the request: method, path, query, and a short allowlist of headers. The
   plugin never sees credentials or cookies. Protocol calls run on a
   blocking thread, never on the async workers.
3. Act on the plugin's answer:
   - `respond`: send the response as given, keeping only the allowed headers.
   - `load(queries)`: run the queries, then call `render` with every query
     and its answer. `render` answers like `handle` does: a response, more
     data to load, or one of the actions below. One request gets at most 4
     rounds and 2,048 answers.
   - `download`: stream the stored package.
   - `serve-file`: stream a stored file (a files format).
   - `publish`, `unlist`, `relist`, `delete`: go through the hosted write
     path, but only when the request's method was authorized for that action
     (a plugin cannot turn a GET into a delete). The repository must be
     hosted, and the caller must present an API token or a workload
     identity.

The contract is [`crates/plugin-api/src/lib.rs`](../crates/plugin-api/src/lib.rs).
Its queries are targeted:

| Query | Answer |
| --- | --- |
| `versions(id)` | Every version of a package |
| `packages(id)` | Every version with its metadata: publish time, SHA-256, SHA-512, size, the stored manifest summary |
| `packages-of(id, versions)` | Some versions with their metadata (a page of a long listing) |
| `package(id, version)` | One version with its metadata |
| `manifest(id, version)` | The manifest stored at publish |
| `search(text, skip, take, prerelease, semver2, upstream)` | Matching packages with their versions, the latest version's summary and the download total |

A files format asks for files instead ([Files formats](#files-formats)); a
query of the other kind fails the request.

Prerelease filtering is the host's, and its rule is that a normalized version
is a prerelease when it contains a `-`; `semver2` adds SemVer 2.0.0 versions
(dotted prerelease labels, build metadata). Publish times are RFC 3339 in UTC
with milliseconds. A `take` of 0 is the default page (20).

### Manifest summaries and the web UI

At publish, Forge stores the JSON object the plugin's `manifest_summary`
returns with the version. `render` gets it back as `summary`, so a listing
never re-reads manifests (for a version stored before summaries were, the
host asks `manifest_summary` of its stored manifest). The web UI's package detail reads two keys from it,
if present: `description`, and `dependency_groups` (the same shape as
NuGet's).

Every listing hands each version's summary to the plugin, so a summary
should stay small.

## Files formats

A format whose `plugin.toml` says `storage = "files"` holds files under
paths, not package versions: [raw](raw.md) is one. It keeps the defaults of
the identity rules and `parse_package` (which refuse every id, version and
package) and implements the protocol over the host's file store, which keeps
everything a file repository is: the files, content-addressed, with their
SHA-256, SHA-512, SHA-1 and MD5; uploads, under the repository's upload
limit and deployment policy (`allow_redeploy`, `disable_redeploy`,
`read_only`); serving with one `Range`, `If-Range`, `ETag`, `Last-Modified`
and conditional requests, under the repository's content disposition;
listings that walk an index; proxies that fetch on first use, follow
redirects and re-validate after `max_age_seconds`; groups; package selectors
on paths; retention by path prefix, age, downloads and the newest N per
directory; and the web UI's upload, delete and the admin API's directory
delete.

The plugin decides what a request is, in the vocabulary of paths. A path is
segments joined by `/`, without a leading or trailing `/`, none of them
empty, `.` or `..`, nor holding a backslash or a control character
([`forge_plugin_api::files`](../crates/plugin-api/src/files.rs) parses
request paths by these rules); a directory is empty (the root) or a path
ending in `/`. The host refuses any other path a plugin names.

| Query | Answer |
| --- | --- |
| `file(path)` | The stored file with its size, content type, digests, modification and last download time, or none. A proxy re-validates its copy once it is due; a group answers with its first member, by priority, that has the path |
| `fetch-file(path)` | `file`, and a proxy that has not cached the path asks its upstream (`upstream`'s `file` operation) |
| `directory(directory, after, limit)` | A page of a directory: files and subdirectories in byte order of their names, and the `after` of the next page; none for a directory that does not exist. A group merges its members' entries |
| `form` | Receives the request's `multipart/form-data` body: file parts are staged, other fields read |
| `store(files)` | Stores files, each from the request body or a form part, all or none, under the deployment policy; what became of each (`created`, `replaced`, `unchanged`) |
| `remove(path)` | Deletes a file; whether there was one |

`form`, `store` and `remove` change the repository: each comes alone in its
round, needs the method's permission (write, or delete for `remove`), a
hosted repository and a package-client credential, and when one fails (403,
405, 409, 413) the host answers with its own status. The action
`serve-file(path)` serves a file as `fetch-file` finds it. The `repository`
a request is for says whether its files are shown inline (`inline`), for
responses the plugin renders itself.

Raw maps its URLs onto these: `GET /raw/<repo>/<path>` is `file(path)`
(and `file` of the file a checksum sidecar names), then `serve-file` or
the sidecar rendered from the file's digests, else `fetch-file` in a proxy
or group, else a `directory` probe for a redirect; `GET …/<dir>/` is a
`directory` page rendered as HTML or JSON; `PUT` is a `store` of the body;
`POST …/<dir>/` is a `form`, then a `store` of its parts with Nexus' field
names applied; `DELETE` is a `remove`. [plugins/raw](../plugins/raw) is the
whole protocol, in a few hundred lines; the file store is
[`crates/server/src/files`](../crates/server/src/files).

## Proxy repositories

A plugin that lists `proxy` among its kinds implements the upstream side of
the contract, `upstream`. The host keeps everything a proxy is, whatever the
format: the `proxy_cached_version` rows, the package delay, the not-found
markers and their TTL, the download singleflight, the content-addressed
store, credentials (decrypted per request, sent only to the origin of the
repository's `remote_url`), where requests may go (below), the SSRF and
cloud-metadata guards, the size and time bounds of every request, and the
offline mode. What the plugin knows is which documents an operation needs and
what they say:

| Operation | The plugin answers |
| --- | --- |
| `index` | A JSON object of its own making, from `remote_url` (NuGet: the service index's resources). The host persists it, refreshes it once per metadata TTL, falls back to the last good one when a refresh fails, and hands it to every other operation |
| `versions(id)` | The versions the upstream lists, or none when it does not know the package |
| `package(id, version)` | The package's URL. The host downloads it, checks it with `parse_package` against the version asked for, and stores it |
| `manifest(id, version)` | The manifest, verified to be that version's, without downloading the package |
| `metadata(versions)`, `dating(versions)` | Per version: listing state, publish time, a manifest summary for a version not downloaded yet, and (`dating`) when it was created upstream, which the package delay counts from |
| `search(query)` | A page of the upstream's search results |
| `file(path)` | A files format: the file's URL, or none when the upstream cannot have it. The host downloads it (following redirects; credentials go to `remote_url`'s origin only), caches it, and re-validates it with a conditional GET once the repository's `max_age_seconds` has passed (raw: `<remote_url>/<path>`) |

Each operation is a conversation: `upstream` either answers or asks for
GETs (`fetch`), and is called again with every fetch so far and how it went
(a body, a 404, or a failure), so a plugin keeps no state between calls. A
fetch says how long its document may be reused: for the repository's
metadata TTL, or for a day when it never changes once published. One
conversation gets at most 4 rounds and 256 fetches, 4 at a time.

An unavailable upstream is an outage, not a fault of Forge. Unavailable
means a fetch or a download got no answer (connection refused, a name that
does not resolve, a timeout) or a 5xx or 429. When nothing cached answers in
its place, the request answers **503** with `Retry-After`, and the host logs
a warning that names the upstream URL. So does a group whose answer waits
on such a member. Any other failure answers 500: an answer the plugin
cannot use, a 401 or 403 for the proxy's credentials, a document over its
size bound.

The host sends a fetch only where the upstream points: to the origin (scheme,
host and port) of `remote_url`, or to an origin that an absolute `http` or
`https` URL names in a document the host fetched for the same operation (in an
earlier round), or while resolving `index`. The URLs `package` and `file`
answer are held to the same rule. Anything else is not sent: the fetch comes back as a
failure, a package URL fails the download like an upstream error, and the host
logs a warning naming the format and the repository. What the plugin answers
names no origin: its index is its own making (and the host keeps fields of its
own beside it, so an index may not use the keys `remote_url` and
`named_origins`). So a NuGet service index can put its resources on other
hosts (nuget.org's search service is on `azuresearch-*.nuget.org`), and a
chart repository's index its charts (on a project's GitHub releases), but a plugin cannot make
Forge request a host its upstream does not point at. Redirects are the
upstream's to choose, and are followed under the cloud-metadata guard.

An administrator makes a proxy of any format ask its upstream again before
those TTLs run out with *Invalidate cache* on the repository's page, or
`POST /admin/repositories/{name}/proxy-cache/invalidate`: the proxy forgets
its not-found markers (of one package with `{"package": "<id>"}`, or of
all) and every document it fetched, on every instance, and invalidating the
whole repository also refreshes its `index`. Downloaded packages stay
cached.

## Using a plugin

`GET /admin/formats` lists every format the server can create repositories
of: the plugins (NuGet, raw files) and Docker, each with the repository
kinds it supports, what its repositories hold (`storage`: `packages`,
`files`, or Docker's `images`) and where its repositories are served. The
web UI's *New repository* form offers them. Plugins serve **hosted** and
**group** repositories, and **proxies** when they implement the upstream
side (NuGet and raw do). Docker has proxies of its own.

A repository of a plugin's format is created like any other, with the
plugin's format id, and served under the plugin's mount (`/repository`
unless its `plugin.toml` names another):

```bash
# Create a hosted repository of the plugin `example` (or use the web UI).
curl -u admin@example.com:$ADMIN_TOKEN -H 'content-type: application/json' \
  -d '{"name": "pkgs", "kind": "hosted", "format": "example"}' \
  https://forge.example.com/admin/repositories
# Its clients use https://forge.example.com/repository/pkgs/
```

As with every format, the password is an **API token**. A password typed at
the web login is not a publishing credential. The admin API refuses to
create a repository of a format the server does not have, and to put
repositories of different formats in one group. A repository whose format
the server no longer has stays in the database: it answers 503, is never
read as another format, and retention skips it (a failed run is recorded).

The web UI's *Browse* screen filters repositories by format
(`GET /browse/repos?format=<id>`), and a repository's screen shows its
client commands: `dotnet nuget` for NuGet, the repository's URL for other
plugin formats.

**Upload limits.** Each hosted repository has its own upload limit, the
largest push it accepts (413 above it), whatever its format: set it under
*Maximum upload size* when creating or editing the repository in the web UI,
or as `max_upload_bytes` in the admin API (`null` on an update clears it).
Without one a repository accepts 512 MiB. Every push is staged on disk, so
a limit may be at most what a push can stage, `server.max_staging_bytes` less
`nuget.max_nuspec_bytes` (`GET /admin/formats` reports it as
`max_upload_bytes_limit`, with each format's `default_max_upload_bytes`).

## Security model

The host enforces these for every plugin:

- **No data beyond the caller's.** The plugin reads only through host
  queries, and those run with the caller's package selector and group
  visibility. An id the format does not validate is unknown, not an
  error.
- **No mutations it was not asked for.** The host checks every mutating
  action against the method the caller was authorized for, the repository
  kind and the credential type, before the hosted write path applies its
  own selector and redeploy checks.
- **Bounded ids and versions.** Whatever the plugin's own rules, an id
  longer than 512 bytes or a version longer than 256 bytes, as given or as
  the plugin normalizes it, is not one: a push of a package carrying one
  answers 400, a request naming one answers like one naming an unknown
  package (404), and a proxy leaves such versions of an upstream listing
  out. Ids and versions are keys of database indexes, whose entries
  PostgreSQL limits to about 2,700 bytes. NuGet allows less: 100 characters
  for an id and 64 for a version.
- **Upstream requests go where the upstream points.** A proxy's plugin
  reaches the network only through the GETs the host sends for it, and the
  host sends them, and downloads packages, only from the origin of the
  repository's `remote_url` and from origins that the documents it fetched
  from that upstream name ([Proxy repositories](#proxy-repositories)). A
  plugin cannot have Forge read `http://localhost:8421/admin/…` or an internal
  search cluster that its upstream does not point at, and pass the answers on
  through the proxy's metadata.
- **Responses cannot attack the origin.** Only `allow`, `cache-control`,
  `content-disposition`, `content-language`, `content-type`, `etag`,
  `last-modified`, `link`, `location` and `vary` survive; `location` and
  `link` survive only when they stay inside the repository. Every response gets the feed's hardening
  headers (`Content-Security-Policy: sandbox`, `nosniff`,
  `Content-Disposition: attachment`). A plugin cannot set cookies, CORS
  headers, or redirect a client elsewhere.

A plugin is part of the server: it is reviewed, tested and released with
it, and runs in-process like the rest of Forge's code.

The documents an upstream serves decide which hosts a proxy's plugin can
reach. A public feed whose package metadata names an internal URL (a
project URL or a chart's home page pointing at `http://10.0.0.5:9200/`) makes
that host reachable for a proxy of that feed, and the plugin reads what it
answers back into what the proxy serves. The rule bounds a plugin to the
hosts its upstream points at, public or internal; where internal services
must stay out of Forge's reach altogether, confine its egress with network
policy (an outbound proxy, a Kubernetes `NetworkPolicy`).

## Writing a plugin

A plugin is a crate in `plugins/<id>/` with a `plugin.toml`, a member of the
workspace, depending on `forge-plugin-api` and implementing its trait
([`plugins/nuget`](../plugins/nuget) is a complete one):

```rust
use forge_plugin_api::{Action, FormatPlugin, Loaded, Repository, Request /* … */};

/// This crate's plugin.toml (id, name, version).
pub const PLUGIN_TOML: &str = forge_plugin_api::plugin_toml!();

#[derive(Default)]
pub struct MyFormat;

impl FormatPlugin for MyFormat {
    // identity: canonical_id, validate_id, normalize_version, compare_versions
    // packages: parse_package, manifest_summary
    //   (a files format keeps the defaults of these, which refuse everything)
    // protocol: handle, render
    // proxies (optional): upstream
}
```

```toml
# plugin.toml
[plugin]
id = "example"                 # the format id repositories are created with
name = "Example packages"
version = "0.1.0"
api = "0.4.0"                  # the forge:format contract
mount = "/repository"          # optional: served at {mount}/{repo}/…
kinds = ["hosted", "group"]    # optional: the repository kinds it serves
                               # ("proxy" too when it implements `upstream`)
storage = "packages"           # optional: or "files" (Files formats)

[assets]                       # optional: how a version's files are stored
package = "package"
package_type = "application/octet-stream"
manifest = "manifest"
manifest_type = "application/octet-stream"
```

A mount is `/` and one lowercase word; the server's own paths (`/admin`,
`/auth`, `/browse`, `/v2`, the web UI's pages, …) are reserved, and plugins
may share a mount. List `proxy` among the kinds only when the plugin
implements `upstream`.

Then build it in: add the crate to `forge-server`'s dependencies and to
`plugins::builtin()` in
[`crates/server/src/plugins.rs`](../crates/server/src/plugins.rs). A few
rules hold:

- **Keep methods pure.** The host may call any method from any thread, in
  any order, any number of times.
- **Read packages as a stream.** `parse_package` gets a `Read + Seek` over
  the staged package. Read only what you need, and bound everything you
  decompress: a gzip bomb should fail fast.
- **Ask for data, don't assume it.** `handle` returns `Action::Load(queries)`;
  `render` gets each query with its answer and may load more, respond, or
  hand the request to the host (a download, a publish, serving a file). Build absolute
  URLs from the repository's `base_url`. Groups and kinds are already
  resolved by the time data reaches you.
- **Test the protocol without a server.** `forge-plugin-api`'s `testing`
  feature runs `handle` and `render` against canned answers to the queries
  (`testing::serve`), as [`plugins/nuget/tests/protocol.rs`](../plugins/nuget/tests/protocol.rs)
  does; `testing::converse` runs `upstream` against canned upstream
  documents ([`plugins/nuget/tests/upstream.rs`](../plugins/nuget/tests/upstream.rs)).
- **Test it in a server.** The crate's unit tests run with the workspace.
  [`crates/server/tests/plugin_contract.rs`](../crates/server/tests/plugin_contract.rs)
  runs a server with a small plugin of its own installed; copy it for a new
  plugin.

## Limitations and roadmap

These are the current limits of the preview, roughly in the order we expect
to lift them:

- **Proxies fetch whole documents with GET.** An upstream request carries
  no headers but the repository's Basic credentials, and its body is read
  whole up to `proxy.max_metadata_bytes` before the plugin sees it. An
  upstream that needs a token exchange (Docker Hub's) or streams a listing
  too large to hold needs more from the contract.
- **Requests carry no body into the plugin.** A publish streams its body
  straight into the store, and other requests' bodies are not passed on.
  npm's login and audit endpoints, for example, need a small body.
- **The uploaded body must be the package.** It can be the whole body or one
  multipart part. npm publishes the tarball base64-encoded inside a JSON
  document, and Cargo frames it after a JSON length prefix; both need a
  host-side extraction step (a byte range, base64 inside a range) that the
  contract does not have yet.
- **One package file per version.** Formats that publish several files per
  version (PyPI wheels per platform, Maven's jar, pom and sources) need
  multi-asset versions.
- **Basic authentication only.** Clients that send API tokens as
  `Authorization: Bearer` (npm's `_authToken`, Cargo) need the principal
  middleware to accept Bearer API tokens.
- **Prerelease is "contains a `-`".** This is right for SemVer formats; a
  format with another rule (PEP 440's `1.0a1`) needs a contract function
  for it.
- **Listings are bounded.** A response may load at most 2,048 answers, so
  a listing of every package of a repository covers at most about 2,000
  packages.
- **An upstream document is read whole.** A proxy reads each upstream
  document it needs (cached for the metadata TTL, and at most
  `proxy.max_metadata_bytes`, 32 MiB by default); the contract has no ranged
  or streamed reads of an upstream document.

### NuGet as a plugin

NuGet is a built-in plugin: [`plugins/nuget`](../plugins/nuget)
implements `FormatPlugin`, and the dispatcher serves it at `/v3/{repo}/...`
with the same paths, status codes, messages and JSON as before. The pieces it
needed from the contract are general ones: a mount, its own asset names,
ranged downloads, paged registrations (`packages-of`), the search options of
the V3 search service, and publishing the first file of a multipart body.

Its proxies read another V3 feed through the plugin's upstream side
([`src/upstream.rs`](../plugins/nuget/src/upstream.rs)): the service
index's resources, the flat container, the registration (bounded to the
newest pages a request needs), catalog entries for the package delay of
unlisted versions, and the search service.

### Why Docker is not a plugin

The contract models a repository as package versions, each one file with an
id, a version and a manifest. A container registry is a different model:
content-addressed blobs and manifests linked per image, tags that move,
indexes that refer to other manifests, referrers, and uploads in sessions of
several requests with bodies the plugin would have to see. Its clients log in
with Bearer tokens, read layers with `Range` requests, and expect proxies of
Docker Hub and other registries. Every one of those is on the roadmap above
or outside the contract altogether.

So Docker is a native format (`crates/format-oci`, served under `/v2`),
registered next to the plugins: `GET /admin/formats` lists it with all three
repository kinds, the admin API and the web UI create its repositories the
same way, a group holds members of its format only, and repositories, RBAC,
package selectors (on image names), retention and the blob store are the
same as for every other format.

Raw file repositories ([raw.md](raw.md)) were native for similar reasons
until contract 0.4.0: they hold files under paths, not package versions,
list directories, take several files in one form, always answer ranges and
conditional requests, and their proxies follow redirects and re-validate with
`If-None-Match`. 0.4.0 gave the contract a second storage model, files
([Files formats](#files-formats)), so raw is a plugin now
([`plugins/raw`](../plugins/raw)) like NuGet, and what was the raw server
module is the host's file store.
