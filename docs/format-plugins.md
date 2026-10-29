# Format plugins

Every format Forge serves comes from a **format plugin**: a Rust crate that
teaches Forge the format's rules, its client protocol and, for proxies, how
to read an upstream, by implementing one trait,
[`FormatPlugin`](../crates/plugin-api/src/lib.rs). The repository machinery
stays Forge's own. That covers storage, metadata, authentication, RBAC and
package selectors, hosted, proxy and group repositories, retention, and the
streaming of package bytes.

Every plugin is built in: a crate under `crates/formats/<id>/` linked into
the server and called directly, like any other Rust code. Plugins need no
configuration. Forge ships four: **Docker / OCI**
([`crates/formats/docker`](../crates/formats/docker),
[Images formats](#images-formats), [docker.md](docker.md)), **NuGet**
([`crates/formats/nuget`](../crates/formats/nuget)), **npm**
([`crates/formats/npm`](../crates/formats/npm), [npm.md](npm.md)) and **raw
files** ([`crates/formats/raw`](../crates/formats/raw),
[Files formats](#files-formats)). Helm charts are pushed to Docker
repositories ([docker.md](docker.md#helm-charts)).

> **Status: preview.** The plugin contract may change in any release. The
> plugins build with the server, so the compiler checks each of them against
> the contract it is linked with. Contract 0.4.0 added files formats
> ([Files formats](#files-formats)), and `render` returns an action, like
> `handle`; for npm, request bodies, document uploads, changes (tags,
> deprecations), logins and forwards followed ([npm as a plugin](#npm-as-a-plugin)),
> and images formats ([Images formats](#images-formats)).

## Contents

- [Layout](#layout)
- [How it fits together](#how-it-fits-together)
- [Files formats](#files-formats)
- [Images formats](#images-formats)
- [Proxy repositories](#proxy-repositories)
- [Using a plugin](#using-a-plugin)
- [Security model](#security-model)
- [Writing a plugin](#writing-a-plugin)
- [Limitations and roadmap](#limitations-and-roadmap)

## Layout

A plugin is a workspace crate that describes itself in Rust:

```
crates/formats/nuget/
├── Cargo.toml     # the plugin's version
├── src/lib.rs     # DESCRIPTOR (id, name, kinds hosted/proxy/group)
│                  # and impl FormatPlugin for Nuget
├── src/protocol.rs  # the V3 protocol: handle and render
├── src/upstream.rs  # proxies: reading another V3 feed (upstream)
└── tests/         # the protocol against canned answers (forge-plugin-api `testing`)

crates/formats/raw/
├── Cargo.toml
├── src/lib.rs     # DESCRIPTOR (storage files, kinds hosted/proxy/group)
│                  # and impl FormatPlugin for Raw: paths, methods, upstream URLs
├── src/listing.rs # directory listings as HTML or JSON
├── src/sidecar.rs # .sha256/.sha512/.sha1/.md5 from the stored digests
├── src/form.rs    # multipart uploads, Nexus' field names
└── tests/         # the protocol against canned answers

crates/formats/npm/
├── Cargo.toml
├── src/lib.rs     # DESCRIPTOR (kinds hosted/proxy/group, Bearer
│                  # upstream tokens) and impl FormatPlugin for Npm
├── src/protocol.rs  # the registry API: packuments, publishes, dist-tags, logins
├── src/publish.rs # the tarball inside a publish document, as it streams
├── src/proxy.rs   # proxies: reading another registry (upstream)
└── tests/         # the protocol against canned answers

crates/formats/docker/
├── Cargo.toml
├── src/lib.rs     # DESCRIPTOR (storage images, kinds hosted/proxy/group)
│                  # and impl FormatPlugin for Docker: paths, manifests, charts
├── src/protocol.rs  # the distribution-spec API: handle and render
├── src/upstream.rs  # proxies: URLs, tag pages and referrers of an upstream registry
├── src/error.rs   # the distribution-spec error answers
└── src/manifest.rs, chart.rs, path.rs, reference.rs, digest.rs
```

The pieces:

| Crate | What it holds |
| --- | --- |
| [`forge-plugin-api`](../crates/plugin-api) | The contract: the `FormatPlugin` trait and its types, and, behind its `testing` feature, helpers that run a plugin's protocol against canned answers. Depends on nothing but `std`. |
| [`crates/formats/<id>`](../crates/formats) | One crate per plugin, implementing `FormatPlugin`. |
| [`forge-plugin`](../crates/plugin) | The host side: `Plugin` (an installed plugin, which describes itself), `PluginFormat`, which adapts it to Forge's `Format` seam, and the checks of a descriptor (`descriptor::check`). |
| [`forge-server`](../crates/server/src/plugins.rs) | The plugins it links in (`plugins::builtin`), the `/repository/{repo}/...` dispatcher, the file store files formats keep their files in ([`crates/server/src/files`](../crates/server/src/files)), and the image store and token service of images formats, under `/v2` ([`crates/server/src/images`](../crates/server/src/images)). |

## How it fits together

| | Forge (the host) | The plugin |
| --- | --- | --- |
| Identity | Calls the format for every id and version it sees | `canonical_id`, `validate_id`, `normalize_version`, `compare_versions` |
| Publishing | Streams the upload to a staging file, enforces the format's upload limit, authorizes against the package selector, stores the blob content-addressed, writes the version in one transaction, records trusted-publishing provenance | `parse_package`: reads the staged file, returns id, version, manifest, dependencies. For a package that comes inside a document (npm's JSON with a base64 tarball), `unpack_upload` takes the package out while the body streams by, and `parse_upload` reads it with the rest of the document |
| Reads | Runs the queries the plugin asks for through the repository read path (hosted, proxy or group). Package selectors, group membership, prefer-hosted and reserved prefixes all apply | `handle` decides what a request is; `render` turns the loaded data into the response body |
| Downloads | Streams the blob from S3, counts the download, answers `HEAD` without touching S3, and a single `Range` when the local blob cache is on | Names the version (`download`) |
| Unlist, relist, delete | Hosted write path, with the repository's permissions and selectors; a package outside the caller's selector answers 404, like an unknown one | Names the version and the success response |
| Tags and deprecations | Keeps a package's tags (npm's dist-tags: a name for one version) and each version's deprecation, drops a version's tags with the version, and never lets retention delete a tagged version | Names the changes (`tag`, `untag`, `deprecate`); `published` names those a publish document carries |
| Logins | Checks a password through the realm chain, or runs a login approved in the browser, and mints, lists and revokes the API tokens; accepts `Authorization: Bearer` API tokens | Says what a request asks (`auth`) and renders the outcome (`auth_response`) |
| Proxies | Sends every upstream request (credentials only to the upstream's origin, bounded, cached), downloads and verifies packages, keeps the package delay, the not-found markers and the offline mode | `upstream`: which documents an operation needs, and what they say ([Proxy repositories](#proxy-repositories)) |
| Groups | Merges members by priority; the dependency-confusion guards apply | Nothing: a group of plugin repositories just works |
| Retention | Evaluates policies, ordering versions with the plugin's `compare_versions` | Nothing more |
| Files (a files format) | Keeps files under paths, content-addressed with their digests: serving, ranges and validators, uploads under the deployment policy, listings, proxies and groups, selectors on paths, retention by path ([Files formats](#files-formats)) | Which path a request names, which file or directory it needs, what the response looks like |

A request to every non-Docker repository is served under
`/repository/{repo}/...`; the repository name selects its format. Docker
repositories are served only through the registry under `/v2`.
The dispatcher
([`crates/server/src/plugins.rs`](../crates/server/src/plugins.rs)) handles it
in this order:

1. Resolve the repository and the caller (a session, Basic credentials, or
   an `Authorization: Bearer` API token). Unknown repositories answer like
   unreadable ones, and offline ones get 503 (to a reader). A files
   format's request is authorized by its method first: GET and HEAD need
   read, PUT and POST write, DELETE delete; a package format's actions are
   checked one by one (below).
2. Call the plugin's `handle` with the repository (name, kind, base URL, a
   group's reserved prefixes) and the request: method, path, query, and a
   short allowlist of headers. The plugin never sees credentials or
   cookies. Protocol calls run on a blocking thread, never on the async
   workers.
3. Act on the plugin's answer, checked against what the caller may do:
   - `respond`: send the response as given, keeping only the allowed
     headers. Needs read.
   - `load(queries)`: run the queries, then call `render` with every query
     and its answer. `render` answers like `handle` does: a response, more
     data to load, or one of the actions below. One request gets at most 4
     rounds and 2,048 answers. Needs read.
   - `download`: stream the stored package. Needs read.
   - `serve-file`: stream a stored file (a files format).
   - `read body`: read the request's body, bounded (at most 64 MiB, 64 KiB
     for a login), and ask `handle` again with it. Its use says what it
     needs: a login nothing, a read read, a change the permission of the
     method.
   - `publish`, `change` (`unlist`, `relist`, `delete`, `deprecate`, `tag`,
     `untag`): go through the hosted write path, but only for a mutating
     method, with the permission each needs (delete for a delete, write for
     the rest), never for a GET. The repository must be hosted, or a group
     with a writable member (where they go), its deployment policy must not
     be read-only, and the caller must present an API token or a workload
     identity.
   - `auth`: a login, a logout or a `whoami`, performed by the host; the
     plugin renders the outcome (`auth_response`).
   - `forward`: a POST to the repository's upstream (a proxy's, or a
     group's first proxy member's), with the proxy's credentials; its answer
     is passed back. npm's audits go so. Needs read.

   A host error (a refusal, a conflict, a missing package) is rendered by
   the plugin's `error_response` when it has one: npm clients print
   `{"error": "..."}`, NuGet's plain text.

The contract is [`crates/plugin-api/src/lib.rs`](../crates/plugin-api/src/lib.rs).
Its queries are targeted:

| Query | Answer |
| --- | --- |
| `versions(id)` | Every version of a package |
| `packages(id)` | Every version with its metadata: publish time, SHA-256, SHA-512, size, the stored manifest summary, the deprecation |
| `dated-packages(id)` | `packages`, with every version's publish time even where that costs more: a proxy asks its upstream with `dating` instead of `metadata` (npm's full packument, whose `time` installs with a minimum release age read) |
| `packages-of(id, versions)` | Some versions with their metadata (a page of a long listing) |
| `package(id, version)` | One version with its metadata |
| `manifest(id, version)` | The manifest stored at publish |
| `search(text, skip, take, prerelease, semver2, upstream)` | Matching packages with their versions, the latest version's summary and the download total |
| `tags(id)` | The package's tags: a hosted repository's own, a proxy's upstream's, a group's from its first member that has the package and tags for it |

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
host asks `manifest_summary` of its stored manifest). The web UI's package detail reads three keys from it,
if present: `description`, `deprecated` (a proxy's upstream deprecation),
and `dependency_groups` (the same shape as NuGet's). It shows the latest
version's README, which the plugin's `readme` reads from the stored
manifest, and the package's tags.

Every listing hands each version's summary to the plugin, so a summary
should stay small.

## Files formats

A format whose descriptor says `storage: Storage::Files` holds files under
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

Raw maps its URLs onto these: `GET /repository/<repo>/<path>` is `file(path)`
(and `file` of the file a checksum sidecar names), then `serve-file` or
the sidecar rendered from the file's digests, else `fetch-file` in a proxy
or group, else a `directory` probe for a redirect; `GET …/<dir>/` is a
`directory` page rendered as HTML or JSON; `PUT` is a `store` of the body;
`POST …/<dir>/` is a `form`, then a `store` of its parts with Nexus' field
names applied; `DELETE` is a `remove`.
[crates/formats/raw](../crates/formats/raw) is the whole protocol, in a few
hundred lines; the file store is
[`crates/server/src/files`](../crates/server/src/files).

## Images formats

A format whose descriptor says `storage: Storage::Images` holds images:
content-addressed blobs and manifests linked into each image (`team/app`),
tags that point at manifests, indexes that name other manifests, referrers,
and uploads in sessions of several requests. [Docker / OCI](docker.md) is
one ([`crates/formats/docker`](../crates/formats/docker)). Its mount is
`/v2` (`IMAGES_MOUNT`), where every registry client asks, so a server holds
one images format at most.

The split is the one files formats have. The format owns the protocol: the
grammar of paths, names, references and digests, what a manifest names and
says, the error answers, the response headers, and the URLs of an upstream
registry. The host owns the image store
([`crates/server/src/images`](../crates/server/src/images)), which keeps
everything else:

- `/v2/` (the version check), `/v2/token` (the token service and its signing
  keys) and `/v2/_catalog` (refused), answered by the host itself;
- resolving a name to a repository and an image, by path
  (`<repository>/<image>`) or on a repository's own host (`host`);
- authorization: the Bearer challenge and a token's scopes, RBAC and package
  selectors on image names, and where a change lands (a group's writable
  member);
- the store: blobs and manifests by digest in the content-addressed store,
  tags (immutable ones too), upload sessions and their chunks, mounts from
  other images, the references between manifests, and the trusted-publishing
  ledger;
- groups, a proxy's caching, retention, garbage collection, and the Nexus
  import;
- serving a blob or a manifest, with one `Range`, `Docker-Content-Digest`
  and `ETag`, and the registry's response hardening on every answer.

The plugin never sees credentials, never touches storage and never holds a
blob in memory. A request goes through three steps:

1. `image_path` splits the path below the mount into the name the client
   wrote and the endpoint (`/manifests/latest`), and says what the request
   needs: read, write (every request of an upload session included) or
   delete.
2. The host resolves the name and authorizes the request. What it refuses
   (an unknown name, a missing token, a denied scope, an offline
   repository) it hands to the format as an `ImageError`, and `image_error`
   renders it, the host adding its Bearer challenge.
3. `handle` gets the request with the endpoint as its path and the resolved
   image as `request.image`, and answers as for any format: a response,
   queries, or an action.

| Query | Answer |
| --- | --- |
| `manifest(image, reference)` | A manifest by tag or digest: digest, media type, size, artifact type, subject, the stored summary |
| `blob(image, digest)` | A blob's digest and size; a manifest is content too |
| `tags(image, last, n)` | A page of the image's tags in byte order, and whether more follow |
| `referrers(image, digest, artifact_type)` | The manifests whose subject is a manifest, of one artifact type when one is given |
| `start-upload(image, mount)` | An upload session, or a blob mounted from another image without one |
| `upload-status(id)`, `append-upload(id, range)` | How far a session got, after appending the request body (at `range`, when the client gave one) |
| `finish-upload(id, digest, range)` | Appends the body, ends the session and links its content into the image as `digest` |
| `cancel-upload(id)` | Ends a session without a blob |
| `put-manifest(image, reference, tags)` | Stores the request body as a manifest under `reference` and points `tags` at it |
| `delete-manifest(image, reference)`, `delete-blob(image, digest)` | Deletes a tag or a manifest, or unlinks a blob no manifest names |

A query that changes the repository comes alone in its round. Every answer
is a result: a query that failed (a blob unknown, a digest that does not
match, a manifest naming a blob the image lacks, a tag that is immutable, an
upload too large) comes back to `render` as its `ImageError`, and the format
answers it with its own error codes and status, which registry clients read.
The actions `serve-blob(image, digest)` and `serve-manifest(image,
reference)` stream what a query of the same request found. A response the
format renders keeps `content-type`, `docker-content-digest`,
`docker-upload-uuid`, `link`, `location`, `oci-filters-applied`,
`oci-subject`, `oci-tag`, `range` and `retry-after`; `location` and `link`
only when they stay under `/v2/`.

Manifests are the format's to read. The host stages a pushed manifest (at
most 4 MiB), and `parse_manifest` says what it is served as, the blobs and
manifests it names (which the push needs in the image), its subject and
artifact type, and a JSON summary stored with it. A proxy's manifests are
read the same way. When the manifest names a config small enough to read
(an image's, a Helm chart's), the host reads it once the image holds it,
and merges what `config_summary` makes of it (the platform, the chart's
metadata) into the summary; the summary names the config under
`config_digest` and `config_media_type`, so a proxy completes the summaries
of the manifests it cached before their config. The web UI reads
`layers_size`, `platform`, `platforms` and `chart` from a summary, and shows a
chart's README and values with `artifact_files`, over the archive blob the
host lends it (at most 16 MiB).

A proxy's upstream operations name where things are, and the host fetches
them:

| Operation | The plugin answers |
| --- | --- |
| `image-name(image)` | The name the upstream knows the image by, which the proxy caches it under (Docker Hub's `library/` namespace) |
| `image-manifest(image, reference)` | The manifest's URL, the `Accept` header to send and the scope of a token for it. The host re-validates a cached tag with a `HEAD`, downloads the manifest, checks it against its digest and reads it with `parse_manifest` |
| `image-blob(image, digest)` | The blob's URL; the host streams it into the store and checks its digest |
| `image-tags(image, last, n)` | A page of the upstream's tags, following the upstream's `Link` pages (a conversation of fetches) |
| `image-referrers(image, digest)` | The upstream's referrers of a manifest |

An images format's fetches go to the origin of `remote_url` only, carry the
`Accept` header the plugin names, and come back with their status and `Link`
headers. When the upstream answers 401 with a Bearer challenge, the host asks
the realm the challenge names for a token (with the repository's
credentials, if it has any) and sends the request again, as Docker Hub
requires; the token is the host's, cached for its lifetime.

`testing::converse_answered` runs `upstream` against canned answers with
their status and headers, as the Docker plugin's tests do.

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
| `package(id, version)` | The package's URL, and the SHA-512 or SHA-1 the upstream publishes for it when it does (`located`). The host downloads it, checks the digest and, with `parse_package`, the version asked for, and stores it |
| `manifest(id, version)` | The manifest, verified to be that version's, without downloading the package |
| `metadata(versions)`, `dating(versions)` | Per version: listing state, publish time, a manifest summary for a version not downloaded yet, and (`dating`) when it was created upstream, which the package delay counts from |
| `search(query)` | A page of the upstream's search results |
| `file(path)` | A files format: the file's URL, or none when the upstream cannot have it. The host downloads it (following redirects; credentials go to `remote_url`'s origin only), caches it, and re-validates it with a conditional GET once the repository's `max_age_seconds` has passed (raw: `<remote_url>/<path>`) |
| `tags(id)` | The tags the upstream gives the package. The host keeps the last ones read, for when the upstream is down |

Each operation is a conversation: `upstream` either answers or asks for
GETs (`fetch`), and is called again with every fetch so far and how it went
(a body, a 404, or a failure), so a plugin keeps no state between calls. A
fetch says how long its document may be reused: for the repository's
metadata TTL, or for a day when it never changes once published, and may
name the `Accept` it sends (npm's abbreviated and full packuments share a
URL). One conversation gets at most 4 rounds and 256 fetches, 4 at a time,
and keeps at most 4 × `proxy.max_metadata_bytes` of documents, all rounds
together: a document past that comes back as a failure, and so does every
later fetch of the conversation, which is not sent. A document larger than
`proxy.max_metadata_bytes` comes back as a failure too, and is not
downloaded again for as long as it would have been reused.

An unavailable upstream is an outage, not a fault of Forge. Unavailable
means a fetch or a download got no answer (connection refused, a name that
does not resolve, a timeout) or a 5xx or 429. When nothing cached answers in
its place, the request answers **503** with `Retry-After`, and the host logs
a warning that names the upstream URL. So does a group whose answer waits
on such a member. An upstream that refuses the proxy (a 401 or 403 for its
credentials), or serves a package the proxy does not take (too large,
unreadable, not the version asked for, not matching its published digest),
answers **502**: retrying does not help until the upstream or the proxy
changes. Any other failure answers 500: an answer the plugin cannot use, a
document over its size bound.

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
of: the plugins (Docker, NuGet, npm, raw files), each from its descriptor, with
the repository kinds it supports, what its repositories hold (`storage`:
`packages`, `files` or `images`) and where its repositories are served. The
web UI's *New repository* form offers them. Plugins serve **hosted** and
**group** repositories, and **proxies** when they implement the upstream
side (all four do).

A repository of a plugin's format is created like any other, with the
plugin's format id, and served under `/repository`:

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
client commands: `dotnet nuget` for NuGet, the `.npmrc` / `.yarnrc.yml`
lines and logins for npm, the repository's URL for other plugin formats.

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
  action against the request's method, the permission it needs, the
  repository kind and the credential type, before the hosted write path
  applies its own selector and redeploy checks.
- **No credentials.** The plugin never sees a password or a token: a
  login's body goes to the host's login (`auth`), which checks it and mints
  the token the plugin renders. A body is read only when the plugin asks,
  bounded, and for a caller with the permission its use needs.
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
  `last-modified`, `link`, `location`, `retry-after` and `vary` survive;
  `location` and `link` survive only when they stay inside the repository. Every response gets the feed's hardening
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

A plugin is a crate in `crates/formats/<id>/`, a member of the workspace,
depending on `forge-plugin-api` and implementing its trait
([`crates/formats/nuget`](../crates/formats/nuget) is a complete one). It
describes itself with a `'static` [`Descriptor`](../crates/plugin-api/src/types.rs)
that `descriptor()` returns:

```rust
use forge_plugin_api::{
    Action, Assets, Descriptor, FormatPlugin, Loaded, Repository, RepositoryKind, Request,
    Storage, UpstreamToken, /* … */
};

pub const DESCRIPTOR: Descriptor = Descriptor {
    id: "example",                     // the format id repositories are created with
    name: "Example packages",
    version: env!("CARGO_PKG_VERSION"),
    description: "Example packages: push and pull with the example client.",
    // The repository kinds it serves (`Proxy` too when it implements
    // `upstream`).
    kinds: &[RepositoryKind::Hosted, RepositoryKind::Group],
    storage: Storage::Packages,        // or `Storage::Files` (Files formats)
                                       // or `Storage::Images` (Images formats)
    // How a version's files are stored: `package` and `manifest`, both
    // application/octet-stream, unless it names its own.
    assets: Assets::DEFAULT,
    // What a proxy given a password and no username sends upstream:
    // nothing more (`None`), or the password as a Bearer token (npm).
    upstream_token: UpstreamToken::None,
};

#[derive(Default)]
pub struct MyFormat;

impl FormatPlugin for MyFormat {
    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }
    // identity: canonical_id, validate_id, normalize_version, compare_versions
    // packages: parse_package, manifest_summary (optional: readme, reserved_prefix)
    //   (a files format keeps the defaults of these, which refuse everything)
    // protocol: handle, render (optional: error_response, auth_response)
    // uploads in a document (optional): unpack_upload, parse_upload, published
    // proxies (optional): upstream
}
```

An id is 2–32 lowercase letters, digits and `-`, starting with a letter,
and no other format's. Every non-images format is served under
`/repository/{repo}/…`; only one format of a server may store images, which
the registry serves at `/v2`. List `Proxy` among the kinds only
when the plugin implements `upstream`. Asset names are plain file names, and
their content types `type/subtype`.

Then build it in: add the crate to `forge-server`'s dependencies and to
`plugins::builtin()` in
[`crates/server/src/plugins.rs`](../crates/server/src/plugins.rs), whose
tests check every built-in format's descriptor against these rules. A few
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
  (`testing::serve`), as
  [`crates/formats/nuget/tests/protocol.rs`](../crates/formats/nuget/tests/protocol.rs)
  does; `testing::converse` runs `upstream` against canned upstream
  documents
  ([`crates/formats/nuget/tests/upstream.rs`](../crates/formats/nuget/tests/upstream.rs)).
- **Test it in a server.** The crate's unit tests run with the workspace.
  [`crates/server/tests/plugin_contract.rs`](../crates/server/tests/plugin_contract.rs)
  runs a server with a small plugin of its own installed; copy it for a new
  plugin.

## Limitations and roadmap

These are the current limits of the preview, roughly in the order we expect
to lift them:

- **Proxies fetch whole documents with GET.** A package or files format's
  upstream request carries no headers but the repository's credentials
  (Basic, or a Bearer token) and the `Accept` the fetch names, and its body
  is read whole up to `proxy.max_metadata_bytes` before the plugin sees it;
  only a `forward` POSTs. An upstream that streams a listing too large to
  hold needs more from the contract. (An images format's fetches get a
  Bearer token exchange, and the host streams the blobs and manifests they
  name: [Images formats](#images-formats).)
- **One package file per version.** Formats that publish several files per
  version (PyPI wheels per platform, Maven's jar, pom and sources) need
  multi-asset versions.
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

NuGet is a built-in plugin: [`crates/formats/nuget`](../crates/formats/nuget)
implements `FormatPlugin`, and the dispatcher serves it at
`/repository/{repo}/...`. The pieces it needed from the contract are general
ones: its own asset names,
ranged downloads, paged registrations (`packages-of`), the search options of
the V3 search service, and publishing the first file of a multipart body.

Its proxies read another V3 feed through the plugin's upstream side
([`src/upstream.rs`](../crates/formats/nuget/src/upstream.rs)): the service
index's resources, the flat container, the registration (bounded to the
newest pages a request needs), catalog entries for the package delay of
unlisted versions, and the search service.

### npm as a plugin

npm is a built-in plugin too: [`crates/formats/npm`](../crates/formats/npm) serves
registries at `/repository/{repo}/...` for npm, pnpm, Yarn and Bun ([npm.md](npm.md)).
Contract 0.4.0 grew for it too, and every piece is general:

- **Bodies on demand** (`read body`): logins, audits, dist-tag changes and
  packument updates are small JSON bodies the plugin reads.
- **Packages inside a document** (`Upload::Document`): `npm publish` sends
  the tarball base64-encoded inside a JSON document. The plugin's
  `unpack_upload` decodes it while the body streams into the store, and the
  rest of the document (its `dist-tags`, its integrity claims) comes back
  to `parse_upload` and `published`.
- **Tags and deprecations** (`change`, `tags`): stored by the host for any
  format, kept by retention, shown by the web UI.
- **Logins** (`auth`): a password login through the realm chain, and a
  login approved in the browser (`/cli-login/<secret>`), each minting an API
  token; a logout revokes it, and `whoami` names the caller.
- **Forwards**: an audit goes to the upstream with the proxy's credentials,
  without a group's reserved names.
- **Proxies**: tags from the upstream, packages located with their digests,
  documents fetched with an `Accept` of their own, and a Bearer token for a
  registry that wants one.
- **Groups**: a writable member, where publishes and changes through the
  group go, and reserved prefixes in the format's own words (`@acme` is the
  scope `@acme/`, `reserved_prefix`).
