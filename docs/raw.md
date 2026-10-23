# Raw file repositories

Forge hosts arbitrary files under arbitrary paths, the way Nexus' raw-hosted,
raw-proxy and raw-group repositories do: the binaries a build downloads that
have no package manager of their own (the
[pdfium binaries](https://github.com/bblanchon/pdfium-binaries), for
example), installers, firmware images, test fixtures, tool downloads.

Files live in repositories of `format: "raw"`, a format plugin built into
Forge like NuGet ([`plugins/raw`](../plugins/raw); `GET /admin/formats`
lists it), served at `https://<host>/raw/<repository>/<path>`. The plugin
speaks the protocol below; the host's file store keeps the files
([format-plugins.md](format-plugins.md#files-formats)). They come in the
usual three kinds:

- **hosted**: upload, download and delete your own files;
- **proxy**: a cache of files under an HTTP(S) base URL, such as a GitHub
  project's release downloads;
- **group**: one URL over several members; the first member, by priority,
  that has a path serves it.

Files are blobs in the content-addressed store: the same content under
several paths, or in several repositories, is stored once.

## Contents

- [Hosted repositories](#hosted-repositories)
- [Downloads](#downloads)
- [Listings](#listings)
- [Paths](#paths)
- [Proxy repositories](#proxy-repositories)
- [Group repositories](#group-repositories)
- [Permissions](#permissions)
- [Retention](#retention)
- [Example: the pdfium binaries](#example-the-pdfium-binaries)
- [Limitations](#limitations)

## Hosted repositories

```bash
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories \
  -d '{"name": "binaries", "kind": "hosted", "format": "raw"}'
```

Upload a file with `PUT` to its path, with an API token as the password (a
password typed at the web login is not an upload credential, and neither is
a browser session):

```bash
curl -u ci:<token> --upload-file pdfium-linux-x64.tgz \
  https://forge.example.com/raw/binaries/pdfium/7350/pdfium-linux-x64.tgz
```

A new file answers `201`, a replaced one `204`. The `Content-Type` stored
with a file is the one the upload declares, unless it only says "bytes"
(none, `application/octet-stream`, or the `application/x-www-form-urlencoded`
of `curl --data-binary`): then the file name decides (`.json`, `.txt`,
`.zip`, …), else `application/octet-stream`.

Several files go in one `multipart/form-data` upload to a directory, each
stored under its part's file name. Nexus' field names for its component
upload work too: `raw.directory` names a subdirectory, and
`raw.assetN.filename` the name of the file part `raw.assetN`. Every file of
the form is stored, or none (an existing file the policy refuses fails the
whole form):

```bash
curl -u ci:<token> -F raw.directory=7350 \
  -F raw.asset1=@pdfium-linux-x64.tgz -F raw.asset1.filename=pdfium-linux-x64.tgz \
  -F raw.asset2=@pdfium-win-x64.tgz -F raw.asset2.filename=pdfium-win-x64.tgz \
  https://forge.example.com/raw/binaries/pdfium/
```

At most 100 files per form; each one is limited by the repository's upload
limit (*Maximum upload size*, `max_upload_bytes`; 512 MiB when unset) and
staged on disk like every push (see `server.max_staging_bytes`).

`DELETE /raw/<repository>/<path>` deletes a file (`204`). A directory, with
every file below it, is deleted through the admin API (or the web UI):

```bash
curl -u admin@example.com:<admin-token> -X DELETE \
  'https://forge.example.com/admin/repositories/binaries/files?path=pdfium/7350/'
# {"deleted": 2}
```

A path without a trailing `/` deletes that one file, and an empty path every
file of the repository, which a hosted repository with files needs before it
can be deleted.

### Deployment policy

As in Nexus, `deployment_policy` decides what an upload to a path that holds
a file does:

| `deployment_policy` | |
| --- | --- |
| `disable_redeploy` (default) | Refused with `409`. Uploading the same content again is accepted and changes nothing, so a retried upload succeeds. |
| `allow_redeploy` | The file is replaced. Replacing needs the `delete` permission as well as `write`. |
| `read_only` | Every upload and delete is refused with `405`. |

```bash
curl -u admin@example.com:<admin-token> -X PUT -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories/binaries \
  -d '{"deployment_policy": "allow_redeploy"}'
```

### Displayed or downloaded

Files are served as downloads (`Content-Disposition: attachment`) by
default. With `"content_disposition": "inline"` a browser displays them
instead (a PDF, a text file, an HTML report). Either way every answer
carries `Content-Security-Policy: sandbox` and `X-Content-Type-Options:
nosniff`: an HTML or SVG file cannot run script on Forge's origin.

## Downloads

`GET` and `HEAD` of a file answer with its bytes and

- `ETag`: the file's SHA-256, a strong validator; `If-None-Match` and
  `If-Modified-Since` answer `304` while it is current;
- `Last-Modified`: when its content was last uploaded (or, in a proxy,
  cached);
- `Content-Length`, `Content-Type`, and `Accept-Ranges: bytes`.

One `Range` is served (`206`, `416` past the end), and `If-Range` with the
`ETag` or the date, so an interrupted download resumes where it stopped:

```bash
curl -u me:<token> -C - -O https://forge.example.com/raw/binaries/pdfium/7350/pdfium-linux-x64.tgz
```

### Checksum sidecars

`<file>.sha256`, `<file>.sha512`, `<file>.sha1` and `<file>.md5` are
answered from the stored file's digests, as Nexus does, without being
uploaded: the digest and the file name, the way `sha256sum` prints them, so
the `-c` mode of the matching tool checks a download:

```bash
curl -u me:<token> -O https://forge.example.com/raw/binaries/pdfium/7350/pdfium-linux-x64.tgz
curl -u me:<token> https://forge.example.com/raw/binaries/pdfium/7350/pdfium-linux-x64.tgz.sha256 \
  | sha256sum -c
# pdfium-linux-x64.tgz: OK
```

A file actually stored under such a name is served as it is.

## Listings

`GET` of a directory (a path ending in `/`, or the repository's root
`/raw/<repository>/`) lists it: as an HTML page for browsers, as JSON with
`Accept: application/json` (or `?format=json`). A directory named without
its `/` redirects to it.

```bash
curl -u me:<token> -H 'Accept: application/json' https://forge.example.com/raw/binaries/pdfium/
```

```json
{
  "repository": "binaries",
  "path": "pdfium/",
  "entries": [
    {"name": "7350/", "path": "pdfium/7350/", "type": "directory"},
    {"name": "README.txt", "path": "pdfium/README.txt", "type": "file", "size": 1204,
     "content_type": "text/plain", "sha256": "…", "last_modified": "2026-10-21T10:58:44Z"}
  ],
  "next": null
}
```

Entries come in byte order of their names, a directory's ending in `/`. A
page holds `limit` entries (100 by default, at most 1,000); `next` (and a
`Link: <…>; rel="next"` header) names the `after` of the next page. A
listing costs one index lookup per entry, however many files are below the
directory. A proxy lists the files it has cached, and a group the merged
entries of the members the caller may read.

The web UI's repository screen is a tree browser of the same listings: a
file's size, type, SHA-256 and URL with the `curl` commands to download,
check and upload it; an upload of files into the directory and the delete of
a file (with the same permissions as `/raw`); and, for administrators, the
delete of a directory.

## Paths

A path is a list of segments separated by `/`. A request whose path has an
empty segment (`a//b`), a `.` or `..` segment (also spelled `%2e%2e`), an
encoded `/` (`%2F`) or a backslash (also `%5C`) in a segment, a control
character, a segment over 255 bytes or more than 1,024 bytes in all is
refused with `400`: nothing is collapsed or resolved, so every stored file
has exactly one spelling. Percent-encoded characters are decoded once
(`a%20b` is `a b`), and paths are case-sensitive.

## Proxy repositories

```bash
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories -d '{
    "name": "pdfium-releases", "kind": "proxy", "format": "raw",
    "remote_url": "https://github.com/bblanchon/pdfium-binaries/releases/download/",
    "max_age_seconds": 0
  }'
```

A file `<path>` of the proxy is `<remote_url>/<path>`, its segments
percent-encoded. The first request fetches and caches it; later ones are
served from the cache.

- **Redirects** are followed (GitHub release assets redirect to
  `release-assets.githubusercontent.com`), up to five hops, each one through
  the upstream client's guard against cloud-metadata addresses. The
  `upstream_username` / `upstream_password` are sent to the origin of
  `remote_url` only, never to the host a redirect leads to. The `remote_url`
  takes no query or fragment.
- **Re-validation.** A cached file is served for `max_age_seconds` (a day by
  default) after it was fetched or last confirmed. Then the proxy asks the
  upstream with a conditional GET (`If-None-Match` with the upstream's
  `ETag`, `If-Modified-Since` with its `Last-Modified`): unchanged, the copy
  is kept; changed, it is replaced. `0` never asks again, for upstreams
  whose files never change (release assets).
- **Misses** are remembered for `not_found_ttl_seconds` (600 seconds by
  default; `0` remembers none).
- **An unreachable upstream** (or one answering an error) does not fail a
  file that is cached: the cached copy is served. A file it never cached
  answers `502`. A file the upstream answers `404` for on re-validation is
  served from the cache too, until it is deleted (admin API) or retention
  evicts it.
- *Invalidate cache* on the repository's page (`POST
  /admin/repositories/<name>/proxy-cache/invalidate`, optionally with
  `{"package": "<file or directory/>"}`) forgets the misses and makes the
  cached files (of that file or directory) due for re-validation.
- Pointing the proxy at another `remote_url` empties its cache.
- An offline proxy serves what it cached and never asks its upstream.
- A proxy takes no uploads. Files larger than `proxy.max_package_bytes`
  (1 GiB by default) are not cached and answer `502`.

## Group repositories

```bash
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories -d '{"name": "files", "kind": "group", "format": "raw"}'
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories/files/members -d '{"member": "binaries", "priority": 100}'
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories/files/members -d '{"member": "pdfium-releases", "priority": 10}'
```

A request for a path is answered by the first member, highest priority
first, that has it (a proxy member: that has it cached or whose upstream
has it), the checksum sidecars included. Members are raw repositories (a
group cannot get a member of another format), nested groups are allowed, and
an offline hosted or group member is skipped. A member that fails (an
unreachable upstream) is skipped while another has the path. As for every
format, reading a group grants nothing on its members: the caller is served
from the members it may read itself. A raw group has no owners, preferred
hosted members or reserved prefixes: paths have no namespaces to confuse.

A group takes no uploads; upload to a hosted member.

## Permissions

`GET` and `HEAD` need `read` on the repository, `PUT` and `POST` need
`write`, `DELETE` needs `delete` (and replacing a file with
`allow_redeploy` needs both). Content selectors match file paths, so a role
can be limited to part of a repository:

```bash
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/content-selectors \
  -d '{"name": "pdfium-only", "includes": ["pdfium/**"]}'
```

A file outside the caller's selector is not found, its sidecars neither, and
a listing leaves it out; a directory is listed when the caller may see a file
in it (among its first 1,000).

Uploads and deletes are recorded in the audit log (`forge::audit`, "package
mutation"), and a workload identity's in the trusted-publishing ledger, with
the file's path and SHA-256.

## Retention

A raw repository's retention policy has the envelope of a package policy
(`version`, `enabled`, `dry_run_only`, `min_run_interval_seconds`) with file
rules:

| Field | |
| --- | --- |
| `path_prefix` | Only files whose path starts with it (`nightly/`); all files without one. |
| `keep_newest_per_directory` | The N most recently uploaded files of each directory (among the rule's) stay. Alone, it keeps N per directory and deletes the others. |
| `older_than_days` | Trigger: uploaded (or cached) at least this many days ago. |
| `not_downloaded_for_days` | Trigger: not downloaded for this many days (counted from the upload when that is later, or when it was never downloaded). |

A file goes when any rule selects it; within a rule, every trigger it sets
must hold. On a proxy the same rules evict cached files, which the upstream
serves again on their next download.

```bash
curl -u admin@example.com:<admin-token> -X PUT -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories/binaries/retention -d '{"policy": {
    "version": 1,
    "rules": [
      {"id": "nightlies", "path_prefix": "nightly/", "keep_newest_per_directory": 5},
      {"id": "cold", "older_than_days": 365, "not_downloaded_for_days": 90}
    ]}}'
```

`POST …/retention/preview` lists what a run would delete (`file_decisions`),
and every run's decisions are audited like other formats'.

## Example: the pdfium binaries

The [pdfium binaries](https://github.com/bblanchon/pdfium-binaries) are
published as GitHub release assets under tags such as `chromium/7350`. A
proxy caches them as they are, and a hosted repository keeps re-packaged
copies; a group serves both under one URL:

```bash
# The proxy of the release downloads (assets of a release never change).
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories -d '{
    "name": "pdfium-releases", "kind": "proxy", "format": "raw",
    "remote_url": "https://github.com/bblanchon/pdfium-binaries/releases/download/",
    "max_age_seconds": 0}'

# A build downloads through it and checks the download.
curl -u ci:<token> -O \
  https://forge.example.com/raw/pdfium-releases/chromium/7350/pdfium-linux-x64.tgz
curl -u ci:<token> \
  https://forge.example.com/raw/pdfium-releases/chromium/7350/pdfium-linux-x64.tgz.sha256 | sha256sum -c

# A re-packaged copy (only the library and the headers) in a hosted repository.
mkdir pdfium && tar -xzf pdfium-linux-x64.tgz -C pdfium
tar -czf pdfium-linux-x64.tgz -C pdfium lib include
curl -u ci:<token> --upload-file pdfium-linux-x64.tgz \
  https://forge.example.com/raw/binaries/pdfium/7350/pdfium-linux-x64.tgz
```

CI runs this example against GitHub (`.github/scripts/raw-e2e.sh`), next to
the other curl checks of this page.

## Limitations

- **Listings and searches.** A listing is per directory; there is no search
  across a repository's paths. A proxy lists only what it has cached: an
  upstream's own directory listings are not read.
- **Ranges.** One range per request; a multi-range request is answered in
  full.
- **No Nexus import.** Importing a Nexus raw repository is not supported yet
  ([nexus-import.md](nexus-import.md) covers NuGet and Docker).
- **No directory delete over `/raw`.** A directory is deleted through the
  admin API or the web UI (administrators).
