# Importing from Nexus

An [import](import.md) copies a Nexus hosted repository into a Forge hosted
repository through the format's own protocol, which Nexus Repository 3
serves for its hosted repositories:

- **NuGet:** the feed `<nexus>/repository/<name>/index.json` (Nexus 3.24 and
  later).
- **npm:** the registry `<nexus>/repository/<name>`, the URL npm clients use.
- **Docker:** the repository's connector (`http://nexus.example.com:8082`,
  its HTTP port), or its path route `<nexus>/repository/<name>`, which serves
  reads on Nexus' own port.

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

Nexus' npm search (3.70) finds nothing without a text, and names a scoped
package without its scope (`ui` for `@acme/ui`), so an npm import of a
Nexus hosted repository walks its `/-/all`, which lists every package by its
full name. Nexus' npm packuments list each version's `dist.integrity`: a
second run downloads nothing Forge has. Their `dist.tarball` names the base
URL Nexus is configured with (**Administration → System → Base URL**), where
one is set; the import downloads from its own URL instead, so a Nexus Forge
reaches under another name imports all the same.

The request of Forge before 2.2, a Nexus server and repository, is still
accepted: `url` the Nexus server, `repository` the Nexus repository, and for
Docker `registry_url` its connector (default: its path route). The import
reads that repository's feed or registry (npm: `<url>/repository/<name>`).

An import stored by Forge before 2.2 read Nexus' REST API. It still lists,
with the feed or registry it now reads. Resumed, its scan starts again (its
cursor was a Nexus `continuationToken`), and what it copied already comes
out `identical`. The protocols carry no last download and no uploader: those
Nexus recorded are not carried over.
