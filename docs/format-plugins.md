# Format plugins

Forge serves NuGet natively. Every other package format comes from a **format
plugin**: a WebAssembly component that teaches Forge the format's rules and
its client protocol. The plugin runs sandboxed inside the server process. The
repository machinery stays Forge's own. That covers storage, metadata,
authentication, RBAC and package selectors, hosted and group repositories,
retention, and the streaming of package bytes.

The repository ships one plugin, **Helm chart repositories**
([`plugins/helm`](../plugins/helm)), as the reference implementation.

> **Status: preview.** The plugin contract is `forge:format@0.1.0`. It may
> change before 1.x of the contract; a plugin declares the contract version it
> was built for, and the server refuses one it does not implement.

## Contents

- [How it fits together](#how-it-fits-together)
- [Using a plugin](#using-a-plugin)
- [Operating plugins](#operating-plugins)
- [Security model](#security-model)
- [Writing a plugin](#writing-a-plugin)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Design notes: compared with artifact-keeper](#design-notes-compared-with-artifact-keeper)

## How it fits together

| | Forge (the host) | The plugin |
| --- | --- | --- |
| Identity | Calls the format for every id and version it sees | `canonical-id`, `validate-id`, `normalize-version`, `compare-versions` |
| Publishing | Streams the upload to a staging file, enforces `max_upload_bytes`, authorizes against the package selector, stores the blob content-addressed, writes the version in one transaction, records trusted-publishing provenance | `parse-package`: reads the staged file through a lent reader, returns id, version, manifest, dependencies |
| Reads | Runs the queries the plugin asks for through the same read path as NuGet. Package selectors, group membership, prefer-hosted and reserved prefixes all apply | `handle` decides what a request is; `render` turns the loaded data into the response body |
| Downloads | Streams the blob from S3, counts the download, answers `HEAD` without touching S3 | Names the version (`download`) |
| Unlist, relist, delete | Hosted write path, with the same permissions and selectors as NuGet | Names the version and the success response |
| Groups | Merges members by priority; the dependency-confusion guards apply | Nothing: a group of plugin repositories just works |
| Retention | Evaluates policies, ordering versions with the plugin's `compare-versions` | Nothing more |

A request to a plugin repository is served under
`/repository/{repo}/...`; NuGet keeps `/v3/{repo}/...`. The dispatcher
([`crates/server/src/plugins.rs`](../crates/server/src/plugins.rs)) handles it
in this order:

1. Resolve the repository and authorize the method exactly as for `/v3`:
   GET and HEAD need read, PUT and POST need write, DELETE needs delete.
   Unknown repositories answer like unreadable ones, and offline ones get 503.
2. Call the plugin's `handle` with the repository (name, kind, base URL) and
   the request: method, path, query, and a short allowlist of headers. The
   plugin never sees credentials or cookies.
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
     identity, as for NuGet.

The contract is [`crates/plugin/wit/format.wit`](../crates/plugin/wit/format.wit).
Its queries are targeted:

| Query | Answer |
| --- | --- |
| `versions(id)` | Every version of a package |
| `packages(id)` | Every version with its metadata: publish time, SHA-256, SHA-512, size, the stored manifest summary |
| `package(id, version)` | One version with its metadata |
| `manifest(id, version)` | The manifest stored at publish |
| `search(text, skip, take, prerelease)` | Matching packages with their versions |

Prerelease filtering is the host's, and its rule is that a normalized version
is a prerelease when it contains a `-`.

### Manifest summaries and the web UI

At publish, Forge stores the JSON object the plugin's `manifest-summary`
returns with the version. `render` gets it back as `summary`, so a listing
never re-reads manifests. The web UI's package detail reads two keys from it,
if present: `description`, and `dependency_groups` (the same shape as
NuGet's).

## Using a plugin

A server with the Helm plugin loaded (see [below](#operating-plugins)) lists
it in `GET /admin/formats`. The web UI's *New repository* form then offers
it. Plugin formats support **hosted** and **group** repositories; proxies
are NuGet-only for now.

```bash
# Create a hosted Helm repository (or use the web UI).
curl -u admin:$ADMIN_TOKEN -H 'content-type: application/json' \
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

As with NuGet clients, the password is an **API token**. A password typed at
the web login is not a publishing credential.

## Operating plugins

A plugin is a directory holding a `plugin.toml` and the component it names:

```
/etc/forge/plugins/
└── helm/
    ├── plugin.toml
    └── forge_format_helm.wasm
```

The server loads only the plugins its configuration lists, each pinned to
the SHA-256 of its component:

```toml
[plugins]
dir = "/etc/forge/plugins"

[plugins.formats]
helm = "sha256:c2053ffcbcc8cd38061813f5c42436464b7917c86fa3096eb849e653a0f1bf0a"
```

or, as environment variables:

```bash
FORGE_PLUGINS__DIR=/etc/forge/plugins
FORGE_PLUGINS__FORMATS__HELM=sha256:c2053ffc…
```

- **Pinning is mandatory.** A component whose digest differs from its pin,
  a `plugin.toml` whose `id` is not its directory name, a contract version
  this server does not implement, or a component that does not instantiate
  all fail startup. A directory under `dir` that is not listed is never
  read.
- **Every instance loads the same plugins.** A repository whose format is
  not loaded on an instance answers 503 there; it is never read as another
  format. The admin API refuses to create a repository of a format that is
  not loaded, and to put repositories of different formats in one group.
- **Build them** with `cargo xtask plugins`. It builds every plugin in
  `plugins/`, installs it under `target/plugins/installed/<id>/`, and prints
  the `[plugins]` section with the digests. In a container, bake the
  directory into an image derived from Forge's, or mount it from a volume (a
  ConfigMap's 1 MiB limit leaves little room for components).
- **Limits.** A plugin's `plugin.toml` may ask for a memory ceiling per
  instance (`memory_mib`, default 64, at most 512), fuel per call (`fuel`,
  default 5·10⁹, at most 5·10¹⁰) and a wall-clock budget per call
  (`timeout_ms`, default 5,000, at most 30,000). Asking for more than the
  maximum fails startup.
- **Removing a plugin** leaves its repositories in the database. They answer
  503 until the plugin is back, and retention skips them (a failed run is
  recorded).

## Security model

- **Integrity.** Only components pinned in the server's configuration are
  loaded, by digest. There is no upload or install API: changing what runs
  takes a configuration change and a restart, like any other code
  deployment.
- **No ambient authority.** The component gets an empty WASI context: no
  files, no sockets, no environment, no arguments; only clocks and
  randomness. Its stdout and stderr go nowhere. It imports exactly one
  host interface, the reader for the package being parsed.
- **Resource limits.** Each call runs with a fresh fuel budget and an epoch
  deadline (10 ms ticks), in an instance with a memory ceiling. A trap (out
  of fuel, past the deadline, out of memory, a guest panic) fails that call
  with a 500 or 400 and discards the instance. The sandbox tests include a
  gzip bomb.
- **Isolation from the server's threads.** Guest code runs on dedicated
  threads, never on the async runtime's workers. The quick rule calls
  (`canonical-id`, `compare-versions`, …) and the slow calls (parsing a
  package, rendering a response) have separate pools, so a long render
  cannot hold up the rule calls every request makes.
- **No data beyond the caller's.** The plugin reads only through host
  queries, and those run with the caller's package selector and group
  visibility. An id the format does not validate is unknown, not an
  error.
- **No mutations it was not asked for.** The host checks every mutating
  action against the method the caller was authorized for, the repository
  kind and the credential type, before the hosted write path applies its
  own selector and redeploy checks.
- **Responses cannot attack the origin.** Only `cache-control`,
  `content-disposition`, `content-language`, `content-type`, `etag`,
  `last-modified` and `location` survive; `location` survives only when it
  stays inside the repository. Every response gets the feed's hardening
  headers (`Content-Security-Policy: sandbox`, `nosniff`,
  `Content-Disposition: attachment`). A plugin cannot set cookies, CORS
  headers, or redirect a client elsewhere.

Plugins are still code you run: a plugin with a bug can serve wrong
metadata for its own repositories. Review a plugin like any other
dependency before you pin it.

## Writing a plugin

Start from [`plugins/helm`](../plugins/helm). A plugin is a Rust crate with
its own workspace, built for `wasm32-wasip2`. `wit-bindgen` generates the
bindings from `crates/plugin/wit`:

```rust
wit_bindgen::generate!({ world: "format-plugin", path: "../../crates/plugin/wit" });

struct MyFormat;
export!(MyFormat);

impl exports::forge::format::format::Guest for MyFormat { /* identity, parse-package, manifest-summary */ }
impl exports::forge::format::protocol::Guest for MyFormat { /* handle, render */ }
```

- **Keep functions pure.** The host may call any function on any instance, in
  any order, any number of times, and replaces instances at will.
- **Read packages through the reader.** `parse-package` gets a reader with
  `size` and `read-at`. Wrap it in `std::io::Read`, as the Helm plugin's
  `Source` does. Read only what you need, and bound everything you
  decompress: the plugin runs under a fuel budget, and a gzip bomb should
  fail fast.
- **Ask for data, don't assume it.** `handle` returns `load(queries)`;
  `render` gets each query with its answer and may load more. Build absolute
  URLs from the repository's `base-url`. Groups and kinds are already
  resolved by the time data reaches you.
- **Test natively.** The crate's unit tests run on the host
  (`cargo test --lib`). The host-side tests in
  [`crates/plugin/tests/helm.rs`](../crates/plugin/tests/helm.rs) and
  [`crates/server/tests/plugins.rs`](../crates/server/tests/plugins.rs) load
  the real component; copy them for a new plugin.
- **Check it like CI does:** `cargo xtask plugins-check`, which runs fmt,
  clippy for wasm and for the native tests, and the unit tests.

Other languages work too, as long as they produce a component for the
`forge:format/format-plugin` world. The host provides WASI 0.2 imports with
no capabilities.

## Limitations and roadmap

These are the current limits of the preview, roughly in the order we expect
to lift them:

- **No proxy repositories for plugin formats.** Proxying needs format
  hooks for the upstream side (URLs for a version listing and an artifact,
  parsing the listing, verifying the fetched artifact). The host keeps the
  generic parts: delay, negative cache, singleflight, credential scoping and
  the SSRF guard.
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
- **Whole downloads only.** Plugin downloads do not answer `Range` requests
  yet (NuGet's do with the local blob cache).
- **Listings are bounded.** A response may load at most 2,048 answers, so the
  Helm index covers at most about 2,000 charts.

### Should NuGet become a plugin?

Not now. NuGet uses the same seam a plugin does (`Format`, the read ops, the
hosted write path), so most of what a rewrite would buy is already there:
groups, retention and RBAC are format-agnostic. What would move into WASM is
the NuGet protocol and its proxy, over 6,000 lines of tuned, heavily tested
code. That code relies on things the contract does not offer yet: streamed
upstream fetches, gzip-encoded upstream metadata, paged registrations.
Rewriting it would cost a call boundary on every request and re-open
settled behaviour, and it would gain nothing a NuGet user could notice.

The path we recommend is the reverse: grow the contract (the roadmap above)
until it could express NuGet, and keep NuGet native as the reference the
contract is measured against. Moving NuGet into a plugin then becomes a
packaging decision instead of a rewrite.

## Design notes: compared with artifact-keeper

[artifact-keeper](https://github.com/artifact-keeper/artifact-keeper) also
runs format plugins as WebAssembly components under Wasmtime. Its native
formats are hand-written Rust handlers, and its contract is the
`artifact-keeper:format@1.0.0` package (`backend/src/wit/format-plugin.wit`).
We studied the version of October 2026 and kept the idea while changing the
contract:

| | artifact-keeper | Forge |
| --- | --- | --- |
| Package bytes into the plugin | Whole artifact as `list<u8>` (uploads are read into memory) | A lent reader over the staged file; the plugin reads what it needs |
| Data for a request | Every artifact row of the repository, on every request | Targeted queries, bounded per request |
| Repository kinds | Hosted in practice (remote and virtual repositories see only their own rows) | Hosted and group, through the same read ops as NuGet; proxy on the roadmap |
| Authorization of data | Repository visibility | Repository grants plus package selectors, group visibility and the dependency-confusion guards |
| Uploads | A separate generic upload endpoint; the plugin validates and parses | The plugin routes the publish; the host streams it through the hosted write path |
| Response headers | Passed through as the plugin sets them | Allowlist plus the feed's hardening headers |
| Execution limits | Fuel and memory | Fuel, memory and an epoch deadline; guest code off the async workers |
| Installing plugins | Admin API from git or a ZIP, Ed25519-signed when required | Operator configuration, pinned by SHA-256; no install API |
| Instances | A new store and instance per call | Instances reused per plugin, a fresh budget per call, recycled after a trap or 10,000 calls |

The Helm plugin shows the difference in practice: a 64 MiB instance serves a
repository index of any size the query bounds allow, and a 500 MB chart is
never copied into the sandbox, which reads it only up to its `Chart.yaml`.
