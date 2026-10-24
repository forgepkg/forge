# Importing from Nexus

Forge replaces Nexus Repository 3. Logins carry over with credential
forwarding, and a proxy repository refills from its upstream. The content of
Nexus' **hosted** repositories (your internal packages and images) is copied
by an **import**, one repository at a time: point a Forge hosted repository at
a Nexus hosted repository of the same format, and Forge copies its content.

| Format | What is copied |
| --- | --- |
| NuGet | the `.nupkg` of every version |
| Docker | every tag with everything it references: config and layers, the child manifests of a multi-platform index; signatures and SBOMs (cosign's `sha256-<digest>.sig` tags, and referrers Nexus holds by digest) |

apt follows once Forge serves apt repositories
([#176](https://github.com/schmitch/forge/issues/176)). Proxy repositories
are not imported (they refill from their upstream), nor are groups (recreate
them as configuration), Nexus users, roles and privileges (credential
forwarding covers sign-in) or cleanup policies (see retention).

## Running an import

In the web UI, open the hosted repository under **Admin → Repositories** and
choose **Import from Nexus**. Or with the admin API:

```bash
curl -u admin@example.com:<admin-scoped token> -X POST \
  https://forge.example.com/admin/repositories/nuget-internal/imports \
  -H 'content-type: application/json' \
  -d '{
        "url": "https://nexus.example.com",
        "repository": "nuget-hosted",
        "username": "migrator",
        "password": "…",
        "dry_run": true
      }'
```

| Field | |
| --- | --- |
| `url` | The Nexus server, with its context path if it has one. |
| `repository` | The Nexus hosted repository. |
| `username`, `password` | A Nexus user that may browse and read it (the privileges `nx-repository-view-<format>-<name>-browse` and `-read`); both, or neither for anonymous access. |
| `registry_url` | Docker only: the repository's registry API. Default `<url>/repository/<name>`, Nexus' path route, which serves reads on Nexus' own port; otherwise its connector, e.g. `http://nexus.example.com:8082`. |
| `on_conflict` | A version Forge already has with other bytes: `skip` it and report it (default), `overwrite` it with Nexus' bytes, or `fail` the import. |
| `concurrency` | Items copied at a time, 1–16 (default 4), so Nexus is not overwhelmed. |
| `dry_run` | Decide every item and write nothing. |

Before an import is accepted, Forge checks the source (the **preflight**): that
Nexus answers its status endpoint (its version is recorded), that the
repository exists and is hosted and of the Forge repository's format, and for
Docker that its registry API answers. A failed check answers 400 (502 when
Nexus cannot be reached) with what is wrong, and nothing is stored. A
repository runs one import at a time.

A **dry run** reports how many components and assets the Nexus repository
holds and their size, what would be copied and how much, and the conflicts
with versions Forge already has, without writing anything. It downloads
nothing whose SHA-256 Nexus lists.

## What an import does

1. **Scan.** Nexus' component listing is walked page by page
   (`GET /service/rest/v1/components`). Each page's components are recorded
   as the import's items, and the page's `continuationToken` as its cursor,
   in one transaction: an import resumes after a restart, a failure or a
   cancel at the page it had not recorded. For Docker, the asset listing
   follows, for the manifests Nexus holds by digest only.
2. **Copy.** The items are copied, `concurrency` at a time:
   - A package is streamed from Nexus into staging, checked against the
     size and checksums Nexus lists (SHA-256 and SHA-512; SHA-1 where an
     older Nexus lists nothing else), and written through the same path as
     a push: format validation, the package selectors of the administrator
     who started the import, the repository's upload limit, deduplication in
     the content-addressed store, and the audit trail. A version Forge has
     with the same SHA-256 is skipped without downloading it.
   - A Docker tag is copied through the Nexus repository's registry API,
     like `crane copy`: digests are kept, and the manifests go through the
     same checks as a `docker push` (every blob and child present, the
     repository's immutable tags). A layer the repository holds already is
     not downloaded again. A referrer (a signature or SBOM with a `subject`)
     Nexus holds by digest is copied once its subject is in Forge. An
     untagged manifest that refers to nothing is not copied, and a Docker
     schema 1 manifest is refused as on a push (its tag fails).
3. **Metadata.** What Nexus records (in recent Nexus 3 versions) is kept:
   `blobCreated` becomes the version's creation time (for a Docker tag,
   `lastModified`, when the tag last moved), which retention's
   `older_than_days` reads; `lastDownloaded` becomes its last download
   (`not_downloaded_for_days`); the uploader is recorded with the item and in
   the audit trail. Download counts are not in Nexus' API, so
   `keep_n_most_downloaded` starts from zero.

Every imported version is audited as an import: a `forge::audit` log line
with `action = "import"`, the administrator, the source and the uploader.

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

An import fails (and can be resumed) when Nexus' listing cannot be read after
a few attempts, when 25 items in a row fail (Nexus went away, the
credentials stopped working), on a conflict with `on_conflict: fail`, or when
the administrator who started it is no longer one.

Running an import again later copies only what is new in Nexus: everything
Forge already has is `identical`. A cutover is therefore an import ahead of
time, then a final one just before DNS or the clients switch to Forge.

## Credentials and workers

The Nexus password is stored sealed with the secret encryption (`[crypto]`;
without it, it is stored like proxy passwords), sent only to the Nexus
origin (and the registry's), and deleted when the import completes. A
cancelled or failed import keeps it, to be resumed; retrying the failed items
of a completed import asks for it again.

Every instance runs the import worker; an import runs on one instance at a
time, which holds it with a lease in Postgres that it renews while it works.
When that instance dies, another takes the import over once the lease has
expired (two minutes) and continues it.
