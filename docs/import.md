# Importing repositories

A proxy repository refills from its upstream, and logins carry over with
credential forwarding. The content of another server's **hosted**
repositories (your internal packages and images) is copied by an
**import**, one repository at a time: point a Forge hosted repository at a
repository of the same format on the other server, and Forge copies its
content.

An import reads the source through the format's own protocol, the one
clients speak, so the source can be any server that speaks it: Nexus,
Artifactory, ProGet, BaGet, Verdaccio, Harbor, a `distribution` registry or
another Forge. [Importing from Nexus](nexus-import.md) says where Nexus
serves them, and what to know of its searches.

| Format | The source | What is copied |
| --- | --- | --- |
| NuGet | A NuGet v3 feed: its service index, `…/index.json` | the `.nupkg` of every version, unlisted ones included |
| npm | An npm registry: the URL clients use as `--registry` | the tarball of every version, prereleases included, with its publish time and deprecation; the dist-tags |
| Docker | A registry API | every tag with everything it references: config and layers, the child manifests of a multi-platform index; signatures and SBOMs (cosign's `sha256-<digest>.sig` tags, the referrers the registry's referrers API lists, and those an OCI 1.1 client stored under the referrers tag schema's `sha256-<digest>` tag) |

apt ([#644](https://github.com/forgepkg/forge/issues/644)) follows. Proxy
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
| `url` | The source: a NuGet feed's service index (`…/index.json`), an npm registry (`https://nexus.example.com/repository/npm-hosted`, `https://verdaccio.example.com`), or a registry (`https://registry.example.com`, or a path below which a server serves the registry API, as Nexus' `…/repository/<name>`). |
| `names` | The package ids or images to copy (up to 10,000), instead of every package the feed's search finds or every image the registry's catalog lists. npm: package names (`left-pad`, `@acme/ui`) or scopes (`@acme`, every package of the scope). |
| `username`, `password` | A user of the source that may read the repository; both, or neither for anonymous access. |
| `on_conflict` | A version Forge already has with other bytes: `skip` it and report it (default), `overwrite` it with the source's bytes, or `fail` the import. npm: likewise a dist-tag Forge points at another version, or a deprecation Forge gives otherwise ([below](#npm-dist-tags-and-deprecations)). |
| `concurrency` | Items copied at a time, 1–16 (default 4), so the source is not overwhelmed. |
| `dry_run` | Decide every item and write nothing. |

The request of Forge before 2.2, a Nexus server (`url`) and repository
(`repository`, and for Docker `registry_url`), is still accepted
([Importing from Nexus](nexus-import.md)).

Before an import is accepted, Forge checks the source (the **preflight**):

- NuGet: the service index resolves, and its search answers. The import
  records how many packages the search reports (`source_total`), and the
  `Server` header the feed answered with (`source_server`).
- npm: the registry answers (`GET /-/ping`; one that does not serve it is let
  through, but not one that refuses the credentials), and lists its
  packages. npm's protocol has no listing of every package, so the preflight
  tries, in turn, the registry's search with an empty text
  (`/-/v1/search?text=`; another Forge lists every package so) and its legacy
  `/-/all` (Nexus' hosted repositories and Verdaccio serve it; Nexus' search
  finds nothing without a text, and Verdaccio refuses one). The import walks
  the first that lists packages (`listing`: `search` or `all`), and records
  how many it lists (`source_total`). A registry that serves neither is
  refused: name the packages or scopes to import.
- Docker: the registry answers its API (`GET /v2/`, with its token challenge
  answered), and serves a catalog (`/v2/_catalog`).

An import that names its packages, scopes or images needs no search or
catalog. A
failed check answers 400 (502 when the source cannot be reached or fails)
with what is wrong, and nothing is stored. A repository runs one import at a
time.

**Point an import at a hosted repository.** The protocols do not say whether
a feed or a registry is hosted: pointed at a group that holds a proxy of
nuget.org, an import would walk nuget.org's search. The preflight's
`source_total` says how big what it found is.

A **dry run** reports what would be copied and the conflicts with versions
Forge already has, without writing anything. It downloads no package: a
version Forge has is compared through the SHA-512 the feed or registry
lists, and where it lists none it is planned with a note saying so.

## What an import does

1. **Scan.** The source's listing is walked page by page: a feed's search
   (with an empty query, prerelease and SemVer 2.0.0 versions included), an
   npm registry's search or `/-/all`, a registry's catalog, or the names the
   import gives. For each package id, the feed's package base address lists
   its versions, unlisted ones included; for each npm package, its full
   packument lists its versions and dist-tags (a named scope's packages come
   from `/-/all`, or else from the search for the scope); for each image,
   the registry lists its tags. Each page's
   versions or tags are recorded as the import's items, and its position as
   the import's cursor, in one transaction: an import resumes after a
   restart, a failure or a cancel at the page it had not recorded. A named
   package or image the source does not have is an item that fails, saying
   so; so is an npm package the registry's search or `/-/all` lists but
   whose packument it does not serve (Nexus' search names a scoped package
   without its scope).
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
   - An npm tarball is downloaded from the import's URL
     (`<url>/<name>/-/<file>`), not from where the packument's
     `dist.tarball` points: that names the host the registry was configured
     with (Nexus' base URL), which need not be one Forge reaches it on. It is
     checked against `dist.integrity` (its SHA-512), or, for an old package
     listed without one, against `dist.shasum`, and must be the package and
     version the packument names. Then it is written through the same path
     as a publish. A version Forge has with the SHA-512 the registry lists is
     skipped without downloading it.
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
3. **Metadata.** What the protocols carry is kept, and what they do not is
   set so that retention does not take an import for an old, unused version:
   - A NuGet version's `published` time in the feed's registration becomes
     its creation time, which retention's `older_than_days` reads.
     nuget.org's `1900-01-01` for an unlisted version is no publish time:
     such a version is created at its import. An npm version's publish time
     comes from the packument's `time`. (A full packument larger than
     `proxy.max_metadata_bytes` is read abbreviated, without `time`: its
     versions are created at their import.)
   - No protocol carries a last download: an imported version counts as
     downloaded at its import, so `not_downloaded_for_days` counts from
     there. Download counts are not carried either, so
     `keep_n_most_downloaded` starts from zero.
   - The registry API has no push time for a tag: a tag is created at its
     import. (The image config's `created` is no substitute: it is the build
     time, which reproducible builds set to the epoch.)

Every imported version is audited as an import: a `forge::audit` log line
with `action = "import"`, the administrator and the source.

### npm: dist-tags and deprecations

A version's `deprecated` message comes along with it. The dist-tags
(`latest`, `next` and the rest) are items of their own (`tag`, the package
and the tag), set after the versions, once the version a tag names is in
Forge: a tag whose version failed fails too, saying so.

A dist-tag Forge already points at another version, or a deprecation Forge
gives otherwise (another message, or none where the source deprecates the
version, or one where it does not), follows `on_conflict`: `skip` keeps
Forge's and reports a conflict, `overwrite` takes the source's, `fail` fails
the import. Except where what Forge holds is what an earlier import of the
repository set: then it follows the source. So a final import before a
cutover moves `latest` to the version the source published since, and takes
a deprecation the source added, without `overwrite`; a tag or deprecation
changed in Forge since stays, and is reported.

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
everything Forge already has is `identical` (npm: a dist-tag the source moved
since moves along, as above). A cutover is therefore an
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
