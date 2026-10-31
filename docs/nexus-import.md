# Importing from Nexus

An [import](import.md) copies a Nexus hosted repository into a Forge hosted
repository through the format's own protocol, which Nexus Repository 3
serves for its hosted repositories:

- **NuGet:** the feed `<nexus>/repository/<name>/index.json` (Nexus 3.24 and
  later).
- **Docker:** the repository's connector (`http://nexus.example.com:8082`,
  its HTTP port), or its path route `<nexus>/repository/<name>`, which serves
  reads on Nexus' own port.
- **Raw:** the repository, `<nexus>/repository/<name>`; its files are listed
  through Nexus' REST API ([below](#raw)).

The user the import reads with needs the privileges
`nx-repository-view-<format>-<name>-browse` and `-read` on the repository.

Nexus' NuGet search stops at 10,000 unique packages
(`nexus.nuget.v3.search.maxTotalHits` in `nexus.properties`), and a package
whose versions are all unlisted is in no search result: name such packages
(`names`), in an import of their own or in addition to the search. Nexus
reports the hits of the page its search answers as the search's total, so a
preflight's `source_total` stops at a page's worth (100); the scan raises it
to as many packages as it walked. Nexus lists no SHA-512 in its
registration: a version is checked against nothing but the `.nupkg`'s own
format, and a second run downloads every version Forge has to compare it.

The request of Forge before 2.2, a Nexus server and repository, is still
accepted: `url` the Nexus server, `repository` the Nexus repository, and for
Docker `registry_url` its connector (default: its path route). The import
reads that repository's feed or registry (raw: `<url>/repository/<name>`).

An import stored by Forge before 2.2 read Nexus' REST API. It still lists,
with the feed or registry it now reads. Resumed, its scan starts again (its
cursor was a Nexus `continuationToken`), and what it copied already comes
out `identical`. The protocols carry no last download and no uploader: those
Nexus recorded are not carried over.

Once the repositories are imported, the cutover can keep every client's
configuration: Forge serves each repository but Docker's at the same
`/repository/<name>/` path as Nexus, so point the Nexus host name at Forge
and list it in `server.alias_base_urls`. Clients that reach Forge under it
are then handed every URL on it (a NuGet feed's resources, the registry's
token service), never the public URL. See
[Further host names](deployment.md#further-host-names-aliases).

## Raw

A raw repository speaks nothing but `GET` of a path, and Nexus' HTML browse
pages (`/service/rest/repository/browse/<name>/`) carry no checksums. So an
import of a Nexus raw repository reads Nexus' REST API:
`GET <nexus>/service/rest/v1/assets?repository=<name>`, paged with
`continuationToken` (Nexus 3.70 answers 10 assets a page). The preflight
finds it from the import's `url`, `<nexus>/repository/<name>` (a Nexus
behind a context path, `https://example.com/nexus/repository/<name>`,
works too).

The listing gives each file's path, size, content type, SHA-1, SHA-256 and
SHA-512, `blobCreated` (its upload time in Forge), `lastDownloaded` (its last
download) and its uploader (recorded with the item and in the audit trail).
A file is downloaded from `<url>/<path>`, not from the asset's
`downloadUrl`, which names the base URL Nexus is configured with
(**Administration → System → Base URL**). A second run downloads nothing
Forge holds with Nexus' SHA-256.

The user the import reads with needs `nx-repository-view-raw-<name>-browse`
(the asset listing) and `-read` (the downloads) on the repository.
