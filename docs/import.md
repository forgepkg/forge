# Importing repositories

A proxy repository refills from its upstream, and logins carry over with
credential forwarding. The content of another server's **hosted**
repositories (your internal packages and images) is copied by an
**import**, one repository at a time: point a Forge hosted repository at a
repository of the same format on the other server, and Forge copies its
content.

An import reads the source through the format's own protocol, the one
clients speak, so the source can be any server that speaks it: Nexus,
Artifactory, ProGet, BaGet, Harbor, a `distribution` registry or another
Forge. Raw files have no protocol beyond a `GET` of a path: an import reads
Nexus' asset listing, another Forge's listing, or the paths it names
([below](#raw-files)). [Importing from Nexus](nexus-import.md) says where
Nexus serves them, and what to know of its search.

| Format | The source | What is copied |
| --- | --- | --- |
| NuGet | A NuGet v3 feed: its service index, `…/index.json` | the `.nupkg` of every version, unlisted ones included |
| Docker | A registry API | every tag with everything it references: config and layers, the child manifests of a multi-platform index; signatures and SBOMs (cosign's `sha256-<digest>.sig` tags, the referrers the registry's referrers API lists, and those an OCI 1.1 client stored under the referrers tag schema's `sha256-<digest>` tag) |
| Raw | A raw repository: Nexus' `<nexus>/repository/<name>`, another Forge's `<forge>/repository/<name>`, or a directory of a web server | every file, with its content type, upload time and last download |

npm ([#643](https://github.com/forgepkg/forge/issues/643)) and apt
([#644](https://github.com/forgepkg/forge/issues/644)) follow. Proxy
repositories are not imported (they refill from their upstream), nor are
groups (recreate them as configuration), users, roles and privileges
(credential forwarding covers sign-in) or cleanup policies (see retention).

## Running an import

In the web UI, open the hosted repository under **Admin → Repositories** and
choose **Import**. Or with the admin API:

```bash
curl -u admin@example.com:<admin-scoped token> -X POST \
  https://forge.example.com/admin/repositories/nuget-internal/imports \
  -H 'content-type: application/json' \
  -d '{
        "url": "https://nexus.example.com/repository/nuget-hosted/index.json",
        "username": "migrator",
        "password": "…",
        "dry_run": true
      }'
```

| Field | |
| --- | --- |
| `url` | The source: a NuGet feed's service index (`…/index.json`), a registry (`https://registry.example.com`, or a path below which a server serves the registry API, as Nexus' `…/repository/<name>`), or a raw repository (`https://nexus.example.com/repository/raw-hosted`, `https://forge.example.com/repository/binaries`, a directory of a web server). |
| `names` | The package ids or images to copy (up to 10,000), instead of every package the feed's search finds or every image the registry's catalog lists. Raw: the paths of the files, below `url` (`pdfium/7350/pdfium-linux-x64.tgz`), instead of every file the source lists. |
| `username`, `password` | A user of the source that may read the repository; both, or neither for anonymous access. |
| `on_conflict` | A version (raw: a file) Forge already has with other bytes: `skip` it and report it (default), `overwrite` it with the source's bytes, or `fail` the import. |
| `concurrency` | Items copied at a time, 1–16 (default 4), so the source is not overwhelmed. |
| `dry_run` | Decide every item and write nothing. |

The request of Forge before 2.2, a Nexus server (`url`) and repository
(`repository`, and for Docker `registry_url`), is still accepted
([Importing from Nexus](nexus-import.md)).

Before an import is accepted, Forge checks the source (the **preflight**):

- NuGet: the service index resolves, and its search answers. The import
  records how many packages the search reports (`source_total`), and the
  `Server` header the feed answered with (`source_server`).
- Docker: the registry answers its API (`GET /v2/`, with its token challenge
  answered), and serves a catalog (`/v2/_catalog`).
- Raw: the source lists its files: another Forge's JSON listing of `url`,
  or, for a URL of a Nexus repository (`<nexus>/repository/<name>`), Nexus'
  asset listing. The import records which (`listing`: `directories` or
  `assets`). A source that serves neither is refused: name the paths to
  import. A raw repository that is read-only takes no import.

An import that names its packages, images or paths needs no search, catalog
or listing (raw: the first named file is asked for, so wrong credentials are
reported at once). A
failed check answers 400 (502 when the source cannot be reached or fails)
with what is wrong, and nothing is stored. A repository runs one import at a
time.

**Point an import at a hosted repository.** The protocols do not say whether
a feed or a registry is hosted: pointed at a group that holds a proxy of
nuget.org, an import would walk nuget.org's search. The preflight's
`source_total` says how big what it found is.

A **dry run** reports what would be copied and the conflicts with versions
Forge already has, without writing anything. It downloads no package: a
version Forge has is compared through the SHA-512 the feed lists, and where
the feed lists none it is planned with a note saying so. A raw dry run
reports the files with their size (`planned_size`), the conflicts, compared
through the SHA-256 the source lists, and the paths that would fail.

## What an import does

1. **Scan.** The source's listing is walked page by page: a feed's search
   (with an empty query, prerelease and SemVer 2.0.0 versions included), a
   registry's catalog, a raw repository's listing, or the names the import
   gives. For each package id,
   the feed's package base address lists its versions, unlisted ones
   included; for each image, the registry lists its tags. Each page's
   versions or tags are recorded as the import's items, and its position as
   the import's cursor, in one transaction: an import resumes after a
   restart, a failure or a cancel at the page it had not recorded. A named
   package or image the source does not have is an item that fails, saying
   so.
2. **Copy.** The items are copied, `concurrency` at a time:
   - A package is streamed from the feed's package base address into
     staging, checked against the SHA-512 the feed's registration lists
     (Forge and nuget.org list one; Nexus does not), and written through the
     same path as a push: format validation, the package selectors of the
     administrator who started the import, the repository's upload limit,
     deduplication in the content-addressed store, and the audit trail. A
     version Forge has with the SHA-512 the feed lists is skipped without
     downloading it; where the feed lists none, it is downloaded and
     compared, and comes out `identical`.
   - A Docker tag is copied like `crane copy`: digests are kept, and the
     manifests go through the same checks as a `docker push` (every blob and
     child present, the repository's immutable tags). A layer the repository
     holds already is not downloaded again. Then the referrers the
     registry's referrers API lists for the tag's manifest (signatures,
     SBOMs) are copied. A registry without that API keeps them under tags
     (cosign's `sha256-<digest>.sig`, the referrers tag schema's
     `sha256-<digest>`), which are copied like any other. An untagged
     manifest no tag or referrer reaches is not copied, and a Docker schema 1
     manifest is refused as on a push (its tag fails).
   - A raw file is downloaded from the import's URL and its path, checked,
     and stored through the same rules as an upload ([below](#raw-files)).
3. **Metadata.** What the protocols carry is kept, and what they do not is
   set so that retention does not take an import for an old, unused version:
   - A NuGet version's `published` time in the feed's registration becomes
     its creation time, which retention's `older_than_days` reads.
     nuget.org's `1900-01-01` for an unlisted version is no publish time:
     such a version is created at its import.
   - No protocol carries a last download: an imported version counts as
     downloaded at its import, so `not_downloaded_for_days` counts from
     there. Download counts are not carried either, so
     `keep_n_most_downloaded` starts from zero.
   - The registry API has no push time for a tag: a tag is created at its
     import. (The image config's `created` is no substitute: it is the build
     time, which reproducible builds set to the epoch.)
   - A raw file keeps the source's upload time and last download, where the
     source names them ([below](#raw-files)).

Every imported version and file is audited as an import: a `forge::audit`
log line with `action = "import"`, the administrator and the source (raw:
the uploader too, where Nexus names one).

## Raw files

Raw has no protocol beyond a `GET` of a path, and no standard listing. An
import of a raw repository reads one of these, and copies every file it
names:

- **Nexus' asset listing**, `GET <nexus>/service/rest/v1/assets?repository=<name>`,
  paged with `continuationToken`, for a `url` of a Nexus repository,
  `<nexus>/repository/<name>`. It lists each file's path, size, content
  type, SHA-1, SHA-256 and SHA-512, when its blob was created, when it was
  last downloaded, and who uploaded it. It is part of Nexus' REST API, and
  the only listing of a Nexus raw repository with checksums (its HTML browse
  pages have none), so for raw the import reads it
  ([Importing from Nexus](nexus-import.md#raw)).
- **Another Forge's listing**, `GET <directory>/` as JSON
  ([raw.md](raw.md#listings)), paged with `after`: each file's size, content
  type, SHA-256, upload time (`last_modified`) and last download. The import
  walks it a directory at a time; its cursor is the directory it is in and
  the entry it got to, so a stopped import resumes in that directory.
- **The paths the import names** (`names`), for a server with no listing,
  such as a plain web server: a `HEAD` of each says its size, content type
  and `Last-Modified`, and where the server serves a `.sha256` sidecar next
  to it (`<hex>`, or `<hex>  <name>` as `sha256sum` prints it), the file is
  checked against it. A named file the server does not have fails, and is
  looked for again when the failed items are retried.

Each file is copied like this:

- **Path.** The file keeps its path below `url`. A path Forge refuses (an
  empty, `.` or `..` segment, a backslash, a control character, a segment
  over 255 bytes, more than 1,024 bytes in all; [raw.md](raw.md#paths))
  fails as its own item, with the reason, and the import goes on. A
  directory of another Forge's listing that Forge refuses is not walked,
  and fails as an item too.
- **Download and checks.** The file is downloaded from the import's URL and
  its path, never from Nexus' `downloadUrl` (which names the base URL Nexus
  is configured with). It is checked against its size and every checksum
  the source lists (Nexus: SHA-512, SHA-256 and SHA-1; another Forge:
  SHA-256; a named file: its sidecar), then stored through the same path as
  an upload: the path rules, the package selectors of the administrator who
  started the import, the repository's upload limit, its read-only policy,
  deduplication in the content-addressed store, and the audit trail.
- **Files Forge already has.** A file at the same path with the SHA-256 the
  source lists is `identical` and is not downloaded. One with another
  SHA-256 follows `on_conflict`, decided without a download: `skip` reports
  it, `overwrite` replaces it (even where the repository refuses redeploys,
  but only with the delete permission on the path), `fail` fails the
  import. Where the source lists no SHA-256 (a named file without a
  sidecar), the file is downloaded and compared.
- **Content type.** The source's content type (Nexus' `contentType`,
  another Forge's `content_type`, a web server's `Content-Type`) is kept, as
  an upload's declared type is: one that only says "bytes"
  (`application/octet-stream`) gives way to the file name's.
- **Times.** When the source stored the file (Nexus' `blobCreated`, another
  Forge's `last_modified`, a web server's `Last-Modified`) becomes its
  upload time, which `Last-Modified`, `older_than_days` and
  `keep_newest_per_directory` read. Nexus' `lastDownloaded` (another Forge's
  `last_downloaded`) becomes its last download, which
  `not_downloaded_for_days` reads; a file whose source names no last
  download counts as downloaded at its import, so retention does not delete
  it right after. A time at the Unix epoch (a file unpacked without its
  times) is none. A replaced file's upload time stays after that of the
  content it replaced, so a client's `If-Modified-Since` never takes the new
  content for the cached one.
- **Uploader.** Nexus' uploader is recorded with the item and in the audit
  trail.

## Progress, cancel, resume, retry

`GET /admin/repositories/{name}/imports` (and the web UI, which refreshes
while an import runs) shows each import's state (`queued`, `running`,
`completed`, `failed`, `cancelled`), its phase, and its items by outcome:
`imported`, `replaced`, `identical`, `conflict`, `failed`, `planned` (dry
run), `pending`, with the bytes copied. `…/imports/{id}/items?state=conflict`
lists the items of one outcome, with the reason of each conflict or failure.

- `POST …/imports/{id}/cancel` stops an import after the items in flight.
- `POST …/imports/{id}/resume` continues a cancelled or failed import where it
  stopped; with `{"retry_failed": true}` (or `"items": [<ids>]`) its failed
  items are copied again, on their own.
- `DELETE …/imports/{id}` deletes a stopped import with its items.

An import fails (and can be resumed) when the source's listing cannot be
read after a few attempts, when 25 items in a row fail (the source went
away, the credentials stopped working), on a conflict with
`on_conflict: fail`, or when the administrator who started it is no longer
one.

Running an import again later copies only what is new at the source:
everything Forge already has is `identical`. A cutover is therefore an
import ahead of time, then a final one just before DNS or the clients switch
to Forge.

## Credentials and workers

The source's password is stored sealed with the secret encryption
(`[crypto]`), sent only to the source's origin and the origins its documents
name (a feed's package base address, a registry's token service), and
deleted when the import completes. A cancelled or failed import keeps it, to
be resumed; retrying the failed items of a completed import asks for it
again.

Every instance runs the import worker; an import runs on one instance at a
time, which holds it with a lease in Postgres that it renews while it works.
When that instance dies, another takes the import over once the lease has
expired (two minutes) and continues it.
