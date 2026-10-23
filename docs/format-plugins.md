# Format plugins

Forge serves the Docker / OCI registry natively ([docker.md](docker.md)).
Every package format comes from a **format plugin**: a Rust crate that
teaches Forge the format's rules, its client protocol and, for proxies, how
to read an upstream, by implementing one trait,
[`FormatPlugin`](../crates/plugin-api/src/lib.rs). The repository machinery
stays Forge's own. That covers storage, metadata, authentication, RBAC and
package selectors, hosted, proxy and group repositories, retention, and the
streaming of package bytes.

A plugin runs one of two ways, and the server cannot tell them apart:

- **Built in.** The crate is linked into the server and called directly, like
  any other Rust code. Built-in plugins need no configuration. Forge ships
  two: **NuGet** ([`plugins/nuget`](../plugins/nuget)) and **Helm chart
  repositories** ([`plugins/helm`](../plugins/helm)).
- **As a WebAssembly component.** The same kind of crate, built for
  `wasm32-wasip2`, loaded at startup from a digest the operator pinned and
  run in a sandbox. This is how formats that are not part of Forge are added
  without rebuilding it.

> **Status: preview.** The plugin contract is `forge:format@0.3.0`. It may
> change before 1.x of the contract; a plugin declares the contract version it
> was built for, and the server refuses one it does not implement.

## Contents

- [One contract, two ways to run it](#one-contract-two-ways-to-run-it)
- [How it fits together](#how-it-fits-together)
- [Proxy repositories](#proxy-repositories)
- [Using a plugin](#using-a-plugin)
- [Loading WebAssembly plugins](#loading-webassembly-plugins)
- [Security model](#security-model)
- [Writing a plugin](#writing-a-plugin)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Design notes: compared with artifact-keeper](#design-notes-compared-with-artifact-keeper)

## One contract, two ways to run it

Every plugin, built in or not, has the same layout:

```
plugins/helm/
├── Cargo.toml     # a workspace crate; feature `component` builds it as a component
├── plugin.toml    # id, name, version, contract version; component file and limits
└── src/lib.rs     # impl FormatPlugin for Helm

plugins/nuget/
├── Cargo.toml
├── plugin.toml    # mount "/v3", kinds hosted/proxy/group
├── src/lib.rs     # impl FormatPlugin for Nuget
├── src/protocol.rs  # the V3 protocol: handle and render
├── src/upstream.rs  # proxies: reading another V3 feed (upstream)
└── tests/         # the protocol against canned answers (forge-plugin-api `testing`)
```

The pieces:

| Crate | What it holds |
| --- | --- |
| [`forge-plugin-api`](../crates/plugin-api) | The contract: the `FormatPlugin` trait and its types, the same contract as WIT ([`wit/format.wit`](../crates/plugin-api/wit/format.wit)), and, behind its `component` feature, the glue that exports a plugin as a component (`export_component!`). Depends on nothing but `std`. |
| [`plugins/<id>`](../plugins) | One crate per plugin, implementing `FormatPlugin`. |
| [`forge-plugin`](../crates/plugin) | The host side: `Plugin` (an installed plugin, built in or WebAssembly), the Wasmtime runtime whose `WasmPlugin` implements `FormatPlugin` by calling into a component, and `PluginFormat`, which adapts any plugin to Forge's `Format` seam. |
| [`forge-server`](../crates/server/src/plugins.rs) | The built-in plugins (`plugins::builtin`), loading the configured components, and the `{mount}/{repo}/...` dispatcher. |

The trait mirrors the WIT world one to one: a component exports exactly the
trait's methods, and the host turns a loaded component back into a
`FormatPlugin`. So the dispatcher, the hosted write path, groups and
retention run the same code for both. The test
[`the_component_answers_like_the_builtin_plugin`](../crates/plugin/tests/component.rs)
runs Helm both ways and checks that every answer matches.

## How it fits together

| | Forge (the host) | The plugin |
| --- | --- | --- |
| Identity | Calls the format for every id and version it sees | `canonical_id`, `validate_id`, `normalize_version`, `compare_versions` |
| Publishing | Streams the upload to a staging file, enforces the format's upload limit, authorizes against the package selector, stores the blob content-addressed, writes the version in one transaction, records trusted-publishing provenance | `parse_package`: reads the staged file (a component through a lent reader), returns id, version, manifest, dependencies |
| Reads | Runs the queries the plugin asks for through the repository read path (hosted, proxy or group). Package selectors, group membership, prefer-hosted and reserved prefixes all apply | `handle` decides what a request is; `render` turns the loaded data into the response body |
| Downloads | Streams the blob from S3, counts the download, answers `HEAD` without touching S3, and a single `Range` when the local blob cache is on | Names the version (`download`) |
| Unlist, relist, delete | Hosted write path, with the repository's permissions and selectors; a package outside the caller's selector answers 404, like an unknown one | Names the version and the success response |
| Proxies | Sends every upstream request (credentials only to the upstream's origin, bounded, cached), downloads and verifies packages, keeps the package delay, the not-found markers and the offline mode | `upstream`: which documents an operation needs, and what they say ([Proxy repositories](#proxy-repositories)) |
| Groups | Merges members by priority; the dependency-confusion guards apply | Nothing: a group of plugin repositories just works |
| Retention | Evaluates policies, ordering versions with the plugin's `compare_versions` | Nothing more |

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
     and its answer. `render` either responds or asks for more data. One
     request gets at most 4 rounds and 2,048 answers.
   - `download`: stream the stored package.
   - `publish`, `unlist`, `relist`, `delete`: go through the hosted write
     path, but only when the request's method was authorized for that action
     (a plugin cannot turn a GET into a delete). The repository must be
     hosted, and the caller must present an API token or a workload
     identity.

The contract is [`crates/plugin-api/src/lib.rs`](../crates/plugin-api/src/lib.rs),
and as WIT [`crates/plugin-api/wit/format.wit`](../crates/plugin-api/wit/format.wit).
Its queries are targeted:

| Query | Answer |
| --- | --- |
| `versions(id)` | Every version of a package |
| `packages(id)` | Every version with its metadata: publish time, SHA-256, SHA-512, size, the stored manifest summary |
| `packages-of(id, versions)` | Some versions with their metadata (a page of a long listing) |
| `package(id, version)` | One version with its metadata |
| `manifest(id, version)` | The manifest stored at publish |
| `search(text, skip, take, prerelease, semver2, upstream)` | Matching packages with their versions, the latest version's summary and the download total |

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
should stay small. The host stores none larger than 64 KiB from a
WebAssembly plugin, and logs a warning instead; a built-in plugin bounds its
own. Helm's summary, which holds a version's index entry, takes at most
16 KiB: past that, its description is cut to 1 KiB, then its largest fields
are left out until it fits, and `apiVersion`, `name`, `version`,
`appVersion`, `kubeVersion`, `type` and `deprecated` go last. A Helm summary
stored before this bound is cut down the same way when the index is
rendered.

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

Each operation is a conversation: `upstream` either answers or asks for
GETs (`fetch`), and is called again with every fetch so far and how it went
(a body, a 404, or a failure), so a plugin keeps no state between calls. A
fetch says how long its document may be reused: for the repository's
metadata TTL, or for a day when it never changes once published. One
conversation gets at most 4 rounds and 256 fetches, 4 at a time.

The host sends a fetch only where the upstream points: to the origin (scheme,
host and port) of `remote_url`, or to an origin that an absolute `http` or
`https` URL names in a document the host fetched for the same operation (in an
earlier round), or while resolving `index`. The URL `package` answers is held
to the same rule. Anything else is not sent: the fetch comes back as a
failure, a package URL fails the download like an upstream error, and the host
logs a warning naming the format and the repository. What the plugin answers
names no origin: its index is its own making (and the host keeps fields of its
own beside it, so an index may not use the keys `remote_url` and
`named_origins`). So a NuGet service index can put its resources on other
hosts (nuget.org's search service is on `azuresearch-*.nuget.org`), and a Helm
index its charts (on a project's GitHub releases), but a plugin cannot make
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
of: the built-in plugins (`builtin: true`; NuGet first, then Helm), Docker,
raw files, and the loaded WebAssembly plugins (with the `sha256` of their component),
each with the repository kinds it supports and where its repositories are
served. The web UI's *New repository* form offers them. Plugins serve
**hosted** and **group** repositories, and **proxies** when they implement
the upstream side (NuGet and Helm do). Docker has proxies of its own.

Helm is built in, so a Helm repository needs no setup beyond creating it:

```bash
# Create a hosted Helm repository (or use the web UI).
curl -u admin@example.com:$ADMIN_TOKEN -H 'content-type: application/json' \
  -d '{"name": "charts", "kind": "hosted", "format": "helm"}' \
  https://forge.example.com/admin/repositories

# Publish (ChartMuseum API): the body, or the `chart` multipart field.
curl -u ci:$TOKEN --data-binary @mychart-1.2.0.tgz \
  https://forge.example.com/repository/charts/api/charts
helm cm-push mychart/ forge          # the helm-push plugin works too

# Consume.
helm repo add forge https://forge.example.com/repository/charts \
  --username me --password $TOKEN
helm install web forge/mychart --version 1.2.0

# Delete a version.
curl -u ci:$TOKEN -X DELETE \
  https://forge.example.com/repository/charts/api/charts/mychart/1.2.0
```

Forge takes a chart's name and version from the `Chart.yaml` Helm loads
when it installs the chart. Helm reads the whole archive and the last
`<chart>/Chart.yaml` wins, so Forge reads the whole archive as Helm does, up
to 256 MiB unpacked, and refuses one whose files are not all in one
top-level directory, that holds more than one `<chart>/Chart.yaml`, or whose
`requirements.yaml` declares more than `dependencies` (Helm reads it into
the chart's metadata too). It also refuses names Helm refuses (absolute, or
out of the chart's directory) and tar features charts do not use, such as
sparse files. Archives from `helm package` or `tar` pass; a Helm proxy
checks the charts it downloads the same way.

A Helm **proxy** mirrors another chart repository: its index lists the
upstream's charts, and each chart is downloaded from the upstream on first
use and served from Forge after.

```bash
curl -u admin@example.com:$ADMIN_TOKEN -H 'content-type: application/json' \
  -d '{"name": "bitnami", "kind": "proxy", "format": "helm",
       "remote_url": "https://charts.bitnami.com/bitnami"}' \
  https://forge.example.com/admin/repositories
helm repo add bitnami-via-forge https://forge.example.com/repository/bitnami \
  --username me --password $TOKEN
```

Chart versions are SemVer, as Helm reads them (`v1.2` is `1.2.0`), and at
most 128 characters, as written and normalized: Helm pushes a chart to an OCI
registry with its version as the tag, and an OCI tag is at most 128
characters, so every chart Helm can push there fits. A push of a chart with a
longer version answers 400, a URL naming one answers 404, and a proxy leaves
such versions of its upstream's index out.

Its index describes each chart's newest version fully and the older ones by
name, version and URL: that is what one search of the upstream says, and
reading the upstream's index once per chart would be slow for large
repositories. A group with a Helm proxy among its members reads the
upstream once per chart for its index; for a large upstream, add the proxy
itself as a Helm repository.

As with every format, the password is an **API token**. A password typed at
the web login is not a publishing credential.

The web UI's *Browse* screen filters repositories by format
(`GET /browse/repos?format=helm`), and a repository's screen shows its
client commands: `dotnet nuget` for NuGet, `helm repo add` and the push for
Helm, the repository's URL for other plugin formats.

**Upload limits.** Each hosted repository has its own upload limit, the
largest push it accepts (413 above it), whatever its format: set it under
*Maximum upload size* when creating or editing the repository in the web UI,
or as `max_upload_bytes` in the admin API (`null` on an update clears it).
Without one a repository accepts 512 MiB. Every push is staged on disk, so
a limit may be at most what a push can stage, `server.max_staging_bytes` less
`nuget.max_nuspec_bytes` (`GET /admin/formats` reports it as
`max_upload_bytes_limit`, with each format's `default_max_upload_bytes`).

## Loading WebAssembly plugins

A WebAssembly plugin is a directory holding a `plugin.toml` and the component
it names:

```
/etc/forge/plugins/
└── example/
    ├── plugin.toml
    └── forge_format_example.wasm
```

The server loads only the plugins its configuration lists, each pinned to
the SHA-256 of its component:

```toml
[plugins]
dir = "/etc/forge/plugins"

[plugins.formats]
example = "sha256:c2053ffcbcc8cd38061813f5c42436464b7917c86fa3096eb849e653a0f1bf0a"
```

or, as environment variables:

```bash
FORGE_PLUGINS__DIR=/etc/forge/plugins
FORGE_PLUGINS__FORMATS__EXAMPLE=sha256:c2053ffc…
```

- **Pinning is mandatory.** A component whose digest differs from its pin,
  a `plugin.toml` whose `id` is not its directory name, a contract version
  this server does not implement, or a component that does not instantiate
  all fail startup. A directory under `dir` that is not listed is never
  read.
- **Built-in formats come first.** A component cannot take the id of Docker,
  raw or a built-in plugin (`nuget`, `helm`); configuring one fails startup.
- **Every instance loads the same plugins.** A repository whose format is
  not loaded on an instance answers 503 there; it is never read as another
  format. The admin API refuses to create a repository of a format that is
  not loaded, and to put repositories of different formats in one group.
- **Build them** with `cargo xtask plugins`. It builds every plugin in
  `plugins/` as a component, installs it under
  `target/plugins/installed/<id>/`, and prints the `[plugins]` section with
  the digests. Built-in plugins are commented out there: their component
  loads only under another id. A plugin whose `plugin.toml` names no
  `component` is built in only, and skipped (NuGet, see
  [NuGet as a plugin](#nuget-as-a-plugin)). In a container, bake the directory into an
  image derived from Forge's, or mount it from a volume (a ConfigMap's 1 MiB
  limit leaves little room for components).
- **Limits.** A plugin's `plugin.toml` may ask for a memory ceiling per
  instance (`memory_mib`, default 64, at most 512; it covers the instance's
  linear memories and tables together, and what one call returns to the
  host), fuel per call (`fuel`,
  default 5·10⁹, at most 5·10¹⁰) and a wall-clock budget per call
  (`timeout_ms`, default 5,000, at most 30,000). Asking for more than the
  maximum fails startup. Built-in plugins ignore `[limits]`.
- **Removing a plugin** leaves its repositories in the database. They answer
  503 until the plugin is back, and retention skips them (a failed run is
  recorded).

## Security model

The host enforces these for every plugin, built in or not:

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
  PostgreSQL limits to about 2,700 bytes. The built-in plugins allow less:
  NuGet 100 characters for an id and 64 for a version, Helm 250 for a chart
  name and 128 for a version.
- **Upstream requests go where the upstream points.** A proxy's plugin
  reaches the network only through the GETs the host sends for it, and the
  host sends them, and downloads packages, only from the origin of the
  repository's `remote_url` and from origins that the documents it fetched
  from that upstream name ([Proxy repositories](#proxy-repositories)). A
  plugin cannot have Forge read `http://localhost:8421/admin/…` or an internal
  search cluster that its upstream does not point at, and pass the answers on
  through the proxy's metadata.
- **Responses cannot attack the origin.** Only `cache-control`,
  `content-disposition`, `content-language`, `content-type`, `etag`,
  `last-modified` and `location` survive; `location` survives only when it
  stays inside the repository. Every response gets the feed's hardening
  headers (`Content-Security-Policy: sandbox`, `nosniff`,
  `Content-Disposition: attachment`). A plugin cannot set cookies, CORS
  headers, or redirect a client elsewhere.

A built-in plugin is part of the server: it is reviewed, tested and released
with it, and runs in-process like the rest of Forge's code. A WebAssembly
plugin is code from elsewhere, so it is also sandboxed:

- **Integrity.** Only components pinned in the server's configuration are
  loaded, by digest. There is no upload or install API: changing what runs
  takes a configuration change and a restart, like any other code
  deployment.
- **No ambient authority.** The component gets an empty WASI context: no
  files, no sockets, no environment, no arguments; only clocks and
  randomness. Its stdout and stderr go nowhere. It imports exactly one
  host interface, the reader for the package being parsed. What it can make
  the host request for a proxy is bounded by the rule above.
- **Resource limits.** Each call runs with a fresh fuel budget and an epoch
  deadline (10 ms ticks), in an instance with a memory ceiling. The ceiling
  bounds the host memory an instance can take: all its linear memories and
  tables count against it together (each table element as a pointer), the
  strings and lists one call returns are copied into the host only up to
  it (a string that several list elements point at is copied once per
  element, and counted so), and so are the random bytes it asks WASI for. A
  trap (out of fuel, past the deadline, out of memory, a guest panic, a
  result past the ceiling) fails that call with a 500 or 400 and discards
  the instance. The sandbox tests include a gzip bomb, an instance whose
  memories together exceed the ceiling, a `table.grow` past it, and a
  result whose list elements all point at one string.
- **Isolation from the server's threads.** Guest code runs on dedicated
  threads, never on the async runtime's workers. The quick rule calls
  (`canonical-id`, `compare-versions`, …) and the slow calls (parsing a
  package, rendering a response) have separate pools, so a long render
  cannot hold up the rule calls every request makes.

Plugins are still code you run: a plugin with a bug can serve wrong
metadata for its own repositories. Review a plugin like any other
dependency before you pin it.

The documents an upstream serves decide which hosts a proxy's plugin can
reach. A public feed whose package metadata names an internal URL (a
project URL or a chart's home page pointing at `http://10.0.0.5:9200/`) makes
that host reachable for a proxy of that feed, and a plugin can read what it
answers back into what the proxy serves. The rule bounds a plugin to the
hosts its upstream points at, public or internal; where internal services
must stay out of Forge's reach altogether, confine its egress with network
policy (an outbound proxy, a Kubernetes `NetworkPolicy`).

## Writing a plugin

Start from [`plugins/helm`](../plugins/helm): a crate in `plugins/<id>/`
with a `plugin.toml`, a member of the workspace, depending on
`forge-plugin-api` and implementing its trait:

```rust
use forge_plugin_api::{Action, FormatPlugin, Loaded, Rendered, Repository, Request /* … */};

/// This crate's plugin.toml (id, name, version).
pub const PLUGIN_TOML: &str = forge_plugin_api::plugin_toml!();

#[derive(Default)]
pub struct MyFormat;

#[cfg(feature = "component")]
forge_plugin_api::export_component!(MyFormat);

impl FormatPlugin for MyFormat {
    // identity: canonical_id, validate_id, normalize_version, compare_versions
    // packages: parse_package, manifest_summary
    // protocol: handle, render
    // proxies (optional): upstream
}
```

```toml
# Cargo.toml
[features]
component = ["forge-plugin-api/component"]
```

```toml
# plugin.toml
[plugin]
id = "example"                 # the format id repositories are created with
name = "Example packages"
version = "0.1.0"
api = "0.3.0"                  # the forge:format contract
component = "forge_format_example.wasm"   # the component build's file
mount = "/repository"          # optional: served at {mount}/{repo}/…
kinds = ["hosted", "group"]    # optional: the repository kinds it serves
                               # ("proxy" too when it implements `upstream`)

[assets]                       # optional: how a version's files are stored
package = "package"
package_type = "application/octet-stream"
manifest = "manifest"
manifest_type = "application/octet-stream"

[limits]                       # optional, as a component (see above)
timeout_ms = 2000
```

A mount is `/` and one lowercase word; the server's own paths (`/admin`,
`/auth`, `/browse`, `/v2`, the web UI's pages, …) are reserved, and plugins
may share a mount. List `proxy` among the kinds only when the plugin
implements `upstream`.

Then either:

- **build it in**: add the crate to `forge-server`'s dependencies and to
  `plugins::builtin()` in
  [`crates/server/src/plugins.rs`](../crates/server/src/plugins.rs); or
- **ship it as a component**: `cargo xtask plugins` builds it (the crate as a
  `cdylib` for `wasm32-wasip2` with the `component` feature) and prints the
  configuration that loads it.

A few rules hold either way:

- **Keep methods pure.** The host may call any method from any thread, in
  any order, any number of times; a component's instances are replaced at
  will.
- **Read packages as a stream.** `parse_package` gets a `Read + Seek` over
  the staged package (in a component, a reader the host lends with `size` and
  `read-at`). Read only what you need, and bound everything you decompress:
  a gzip bomb should fail fast, and a component runs under a fuel budget.
- **Ask for data, don't assume it.** `handle` returns `Action::Load(queries)`;
  `render` gets each query with its answer and may load more. Build absolute
  URLs from the repository's `base_url`. Groups and kinds are already
  resolved by the time data reaches you.
- **Test the protocol without a server.** `forge-plugin-api`'s `testing`
  feature runs `handle` and `render` against canned answers to the queries
  (`testing::serve`), as [`plugins/nuget/tests/protocol.rs`](../plugins/nuget/tests/protocol.rs)
  does; `testing::converse` runs `upstream` against canned upstream
  documents ([`plugins/nuget/tests/upstream.rs`](../plugins/nuget/tests/upstream.rs)).
- **Test both ways.** The crate's unit tests run with the workspace.
  [`crates/plugin/tests/component.rs`](../crates/plugin/tests/component.rs)
  loads the component and compares it with the built-in crate, and
  [`crates/server/tests/plugins.rs`](../crates/server/tests/plugins.rs) runs
  a server with both; copy them for a new plugin.
- **Check it like CI does:** `cargo xtask plugins-check` lints the component
  build and builds it.

A component can also come from another language, as long as it implements
the `forge:format/format-plugin` world. The host provides WASI 0.2 imports
with no capabilities.

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
- **Listings are bounded.** A response may load at most 2,048 answers, so the
  Helm index covers at most about 2,000 charts.
- **A Helm upstream is read whole.** Every upstream operation of a Helm
  proxy reads the upstream's `index.yaml` (cached for the metadata TTL, and
  at most `proxy.max_metadata_bytes`, 32 MiB by default); the contract has
  no ranged or streamed reads of an upstream document. The built-in plugin
  keeps the parsed index while the upstream serves the same document and
  parses one index at a time, so a chart listing through a proxy, or
  through a group of several proxies, parses each upstream's index once,
  not once per chart. The kept indexes of an instance, of all its Helm
  proxies together, may hold 128 MiB, about twice the size of their
  documents, so about 60 MB of `index.yaml`. A new index that does not fit
  takes the place of kept ones nobody used for a minute; while all of them
  are in use, it is parsed for each operation instead of being kept. So
  past the budget, a group's listing keeps the indexes that fit and parses
  the others once per chart. A WebAssembly build of the plugin keeps
  nothing and parses the index for every operation.

### NuGet as a plugin

NuGet is a built-in plugin like Helm: [`plugins/nuget`](../plugins/nuget)
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

One part is missing: **a component build.** The crate reads packages with
`zip`, whose `typed-path` dependency needs a nightly compiler for
`wasm32-wasip2`, so NuGet runs built in only (its `plugin.toml` names no
`component`).

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

Raw file repositories ([raw.md](raw.md)) are native for similar reasons:
they hold files under paths, not package versions, list directories, take
several files in one form, always answer ranges and conditional requests,
and their proxies follow redirects and re-validate with `If-None-Match`. They
live in the server (`crates/server/src/raw`, served under `/raw`) and are
registered like Docker, with selectors on paths.

## Design notes: compared with artifact-keeper

[artifact-keeper](https://github.com/artifact-keeper/artifact-keeper) also
runs format plugins as WebAssembly components under Wasmtime. Its native
formats are Rust handlers in `backend/src/formats/<format>.rs` behind one
`FormatHandler` trait, and `formats/wasm.rs` wraps a loaded plugin in the
same trait, so services do not care which kind they hold. Forge follows that
shape: `FormatPlugin` is the one trait, the built-in plugins are its native
implementations, and `WasmPlugin` is the wrapper. Its WIT contract is the
`artifact-keeper:format@1.0.0` package (`backend/src/wit/format-plugin.wit`).
We studied the version of October 2026 and kept the idea while changing the
contract:

| | artifact-keeper | Forge |
| --- | --- | --- |
| Native formats | Handlers in the backend crate; the WASM contract is a separate, narrower interface | Built-in plugins are crates implementing the same contract a component exports; any of them also builds as a component |
| Package bytes into the plugin | Whole artifact as `list<u8>` (uploads are read into memory) | A lent reader over the staged file; the plugin reads what it needs |
| Data for a request | Every artifact row of the repository, on every request | Targeted queries, bounded per request |
| Repository kinds | Hosted in practice (remote and virtual repositories see only their own rows) | Hosted, group, and proxy: the plugin reads the upstream through the host |
| Authorization of data | Repository visibility | Repository grants plus package selectors, group visibility and the dependency-confusion guards |
| Uploads | A separate generic upload endpoint; the plugin validates and parses | The plugin routes the publish; the host streams it through the hosted write path |
| Response headers | Passed through as the plugin sets them | Allowlist plus the feed's hardening headers |
| Execution limits | Fuel and memory | Fuel, memory and an epoch deadline; guest code off the async workers |
| Installing plugins | Admin API from git or a ZIP, Ed25519-signed when required | Operator configuration, pinned by SHA-256; no install API |
| Instances | A new store and instance per call | Instances reused per plugin, a fresh budget per call, recycled after a trap or 10,000 calls |

The Helm plugin shows the difference in practice: a 64 MiB component serves
a repository index of any size the query bounds allow, and a chart is never
copied into the sandbox, which streams it through the lent reader and keeps
only its `Chart.yaml`.
