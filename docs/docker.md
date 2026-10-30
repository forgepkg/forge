# Docker / OCI registry

Forge serves container images and other OCI artifacts (Helm charts, cosign
signatures, SBOMs) under `/v2/`, the way Nexus' docker-hosted, docker-proxy
and docker-group repositories do. It speaks the
[OCI Distribution Spec](https://github.com/opencontainers/distribution-spec)
v1.1 that Docker, Podman, containerd, crane, skopeo, oras, Helm and cosign
use. CI runs the spec's conformance suite against Forge on every change.

Images live in repositories of `format: "docker"`, a format plugin built
into Forge like NuGet and raw (`GET /admin/formats` lists it, with `storage:
images`). It is an [images format](format-plugins.md#images-formats): the
plugin, [`crates/formats/docker`](../crates/formats/docker), speaks the
protocol, and Forge's image store keeps the images. They come in the same
three kinds as NuGet repositories:

- **hosted**: push and pull your own images;
- **proxy**: a pull-through cache of an upstream registry: Docker Hub, GHCR,
  Quay, MCR, or any registry that speaks the distribution spec;
- **group**: one name over several members, resolved by priority.

Layers, configs and manifests are blobs in the content-addressed store. A
layer shared by many images, or by images in several repositories, is
stored once.

## Names

Docker clients always talk to `https://<host>/v2/`. Forge finds the
repository in the image name:

- **By path** (always available): the first component of the name is the
  Forge repository, the rest the image.
  `forge.example.com/docker-hosted/team/app:1.2` is the image `team/app` in
  the repository `docker-hosted`.
- **By host** (optional): a repository with a `host`
  (`"host": "docker.example.com"`) also answers at the root of that host, so
  its images keep short names: `docker.example.com/team/app:1.2`. Point the
  host name at Forge, include it in the TLS certificate, keep `Host` intact
  in the reverse proxy, and add it to `server.allowed_hosts` if a
  [trusted-header realm](deployment.md#trusted-header-realms) names its
  clients.

A docker repository's name is part of every image name, so it follows the
spec's name grammar: lowercase letters and digits, separated by `.`, `_`,
`__` or `-` (for example `docker-hosted`). Image names follow the same
grammar, with `/` between components.

Nexus-style per-repository connector ports are not supported: they are
awkward behind an Ingress.

## Logging in

Forge implements Docker's Bearer token service (Nexus' "Docker Bearer Token
Realm"): `GET /v2/` answers `401` with a challenge naming the token endpoint
`/v2/token`, the client sends its credentials there once and receives a
short-lived token (`docker.token_ttl_seconds`, 5 minutes by default) for the
repositories and actions it asked for.

```bash
docker login forge.example.com -u <username>   # password: an API token
docker pull forge.example.com/docker-hosted/team/app:1.2
docker push forge.example.com/docker-hosted/team/app:1.3
```

- **API tokens** (created on the Tokens page, or `POST /admin/me/tokens`) are
  the password to use. A token's repository scope applies.
- **Passwords** work for the users of a realm that accepts passwords from
  clients ([Admin → Authentication](deployment.md#passwords-from-clients)):
  a credential-forwarding realm by default (so users of an existing Nexus or
  LDAP sign in with their upstream password), the local realm once it is set
  to.
  The password goes to the token endpoint only; the registry itself sees the
  short-lived token.
- **CI workloads** with a workload-identity realm pass their OIDC token, or
  the workload key it was exchanged for, as the password with the username
  `oidc`; their pushes and deletes are recorded in the trusted-publishing
  ledger. [Docker / OCI images](trusted-publishing.md#docker--oci-images)
  shows the setup, and GitHub Actions and GitLab CI jobs that push with
  `docker push` or `dotnet publish`.
- **Anonymous pulls** work for repositories that allow anonymous read (with
  the anonymous mode on, Admin → Settings): clients get an anonymous token
  without logging in.
- A browser session never pushes, even an administrator's.

A registry token grants only what the caller may do when it is issued:
`pull` needs `read` on the repository, `push` needs `write`, and `delete`
needs `delete`; content selectors match image names (`team/*`). An image a
selector hides from a caller who may read the repository is not found: a
pull, its tags or its referrers answer 404 `NAME_UNKNOWN`, as for a name
that does not exist (also through a group), while a push or a delete of it
is refused with 403. One token
request may name at most 32 repositories (clients ask for one to three); a
request naming more is refused with `400 UNSUPPORTED`. Every
request is authorized again against the current permissions, and the user
and API token behind a registry token must still be active; a workload's
realm must still be enabled with the configuration it was verified under,
and a token got with a workload key stands only while that key does
(checked at least every 10 seconds). A token got with a CI token directly
does not depend on any key that CI token was exchanged for. Either kind
expires no later than the key or CI token it was got with. Registry tokens
are accepted under `/v2` only.

Registry tokens are signed with `docker.token_secret` when set, otherwise
with a key Forge generates once and keeps in the database (sealed by the
secret encryption, and re-sealed by DEK rotation like the other secrets), so every instance accepts every
instance's tokens. An instance replaces the stored key only when it can
never be opened (a database or key-store error fails startup instead); the
running instances pick the new key up within 30 seconds and keep accepting
tokens of the previous one.

## Hosted repositories

```bash
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories \
  -d '{"name":"docker-hosted","kind":"hosted","format":"docker"}'
```

All of the spec's push paths work: monolithic and chunked (resumable)
uploads, cross-repository mounts (`?mount=&from=`, needs read on the source
image), pushes by tag or digest, `?tag=` parameters on a push by digest, and
deletes of tags, manifests and blobs. Manifests may be Docker v2 schema 2
manifests and manifest lists, OCI image manifests and indexes, or artifacts
with any `artifactType`; Docker schema 1 is refused.

- **Immutable tags**: `"immutable_tags": true` refuses to move an existing
  tag to another manifest (re-pushing the same manifest is fine). With
  `"latest_mutable": true`, `latest` may still move.
- A manifest must name blobs the image has (`MANIFEST_BLOB_UNKNOWN`
  otherwise), except non-distributable layers and the OCI empty config
  (`{}`), which Forge stores itself when it is missing.
- A blob a manifest of the image references cannot be deleted (`409`):
  delete the manifest first.
- `DELETE /v2/<name>/manifests/<tag>` deletes the tag alone: the manifest
  stays, under its other tags or untagged. A `DELETE` by digest deletes the
  manifest and every tag that names it.
- Uploads are limited per blob by the repository's upload limit (*Maximum
  upload size* in the web UI, `max_upload_bytes` in the admin API; 1 GiB
  when unset, or what an explicit `server.max_staging_bytes` below that
  holds) and staged on disk like package pushes (see
  `server.max_staging_bytes`, which also caps the limit).
  Upload sessions are shared by all instances; an abandoned one expires
  after `docker.upload_ttl_seconds`.

The images of a Nexus docker-hosted repository move over with an import,
digests, multi-platform indexes, signatures and SBOMs included
([nexus-import.md](nexus-import.md)).

### Signatures, SBOMs and attestations

The referrers API (`GET /v2/<name>/referrers/<digest>`, with the
`artifactType` filter) lists every manifest whose `subject` is the digest,
with its annotations. cosign 3 stores signatures and attestations there by
default; older cosign versions use tags (`sha256-<digest>.sig`), which work
as well.

### Helm charts

Helm (3.8 and later) stores charts in OCI registries, and Forge serves them
from docker repositories like any other artifact: a chart is a manifest
whose config is the chart's `Chart.yaml` (`application/vnd.cncf.helm.config.v1+json`)
and whose layer is the packaged chart. `helm push` tags it with the chart's
version. Forge serves charts this way only; it has no classic chart
repositories (`index.yaml`, `helm repo add`).

```bash
helm registry login forge.example.com --username <username>   # password: an API token
helm push mychart-1.2.3.tgz oci://forge.example.com/docker-hosted/charts
helm install myrelease oci://forge.example.com/docker-hosted/charts/mychart --version 1.2.3
helm pull oci://forge.example.com/docker-group/charts/mychart --version '~1.2'
```

The chart's name is the last component of the image name
(`docker-hosted/charts/mychart`); content selectors and retention match it
like any image name. Proxies of a registry that serves charts (Docker Hub's
`registry-1.docker.io/bitnamicharts`, GHCR) and groups work as for images.
`helm registry login` keeps its own login, so log in with Helm even when
`docker login` already did.

## Proxy repositories

```bash
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories -d '{
    "name": "docker-hub", "kind": "proxy", "format": "docker",
    "remote_url": "https://registry-1.docker.io",
    "upstream_username": "<docker hub user>", "upstream_password": "<docker hub token>"
  }'
docker pull forge.example.com/docker-hub/nginx:1.27
```

- `remote_url` is the registry's base URL: `https://registry-1.docker.io`
  (not `docker.io`), `https://ghcr.io`, `https://quay.io`,
  `https://mcr.microsoft.com`.
- Docker Hub's one-component names live in `library/`: `nginx` and
  `library/nginx` are the same image, cached once.
- Upstream credentials are optional; give Docker Hub ones to raise its pull
  rate limit. They are sent to the upstream and to the token service its
  `401` challenge names (Docker Hub's `auth.docker.io`), over https when the
  upstream is https. They are sealed at rest.
- Blobs and manifests pulled by digest are verified against their digest and
  cached for good. A tag is served from the cache for `metadata_ttl_seconds`
  (default 600) and then re-validated with a `HEAD`, which Docker Hub does not
  count against the rate limit. While the upstream is unreachable or rate
  limits, the cached tag is served; an upstream "not found" is remembered for
  `not_found_ttl_seconds` (default 60).
- A layer the proxy does not hold yet is served while it downloads: the
  client receives it as it arrives from the upstream, and other pulls of it
  on the same instance meanwhile are served from that one download. Its last
  byte is sent once the whole layer matches its digest; a layer that does
  not ends the response short, an error the client retries, and is not
  cached. The download is cached even when its client goes away. Blobs of at
  most 1 MiB (image configs), and layers whose upstream sends no
  `Content-Length`, are downloaded and verified before they are served.
- Multi-arch indexes are cached as they are; each platform's manifest and
  layers are fetched when a client asks for them. Tag lists and referrers
  come from the upstream, or from the cache while it is unreachable. A tag
  list follows the upstream's own pages (`Link: rel="next"`, up to 10
  requests) to fill the client's page, and links to the next page when the
  upstream has more; an upstream that refuses a large `n` is asked without
  one.
- An offline proxy (`"online": false`) serves only what it cached. Pointing a
  proxy at another `remote_url` empties its cache; a fetch from the previous
  upstream still running then caches nothing, and its client is asked to
  retry (503).
- To ask the upstream again before those TTLs run out (a tag moved, an image
  published after the proxy answered "not found"), invalidate the proxy's
  cache: *Invalidate cache* on its page in the web UI, or
  `curl … /admin/repositories/docker-hub/proxy-cache/invalidate -d
  '{"package": "library/nginx"}'` (with `-d '{}'`: every image). The proxy
  forgets its "not found" answers, on every instance, and re-validates the
  image's tags on their next pull; blobs and manifests stay cached.
- A proxy is read-only (`405` on pushes).

## Group repositories

```bash
curl … /admin/repositories -d '{"name":"docker","kind":"group","format":"docker",
                                 "writable_member":"docker-hosted",
                                 "reserved_prefixes":["acme/"]}'
curl … /admin/repositories/docker/members -d '{"member":"docker-hosted","priority":10}'
curl … /admin/repositories/docker/members -d '{"member":"docker-hub","priority":5}'
docker pull forge.example.com/docker/nginx:1.27
```

- A pull is served by the highest-priority member that has the image and the
  caller may read; a failing member (an unreachable upstream) is skipped
  while another answers. Tag lists and referrers are merged.
- Members must be docker repositories. An offline hosted or nested group
  member is skipped; an offline proxy member still serves its cache.
- **Pushes** to a group go to its `writable_member`, a hosted member (Nexus
  Pro's group deployment). Without one, pushes are refused. The caller needs
  read on the group and write on that member. The group keeps the member
  when it is renamed; once it is deleted, the group has no writable member
  until one is set again.
- **Dependency-confusion guard**: an image under one of the group's
  `reserved_prefixes` (namespaces such as `acme/`) is never served by a
  proxy member, and with `prefer_hosted` (on by default) neither is an image
  a hosted member already has. Flag trusted members as `owner` when hosted
  members have different writers, as for NuGet groups.

## Browsing

The web UI lists a docker repository's images, and per image its tags and
manifests with digests, sizes, platforms, referrers, push and pull times, and
ready-to-paste `docker login` / `docker pull` commands. The same data is in
the browse API: `GET /browse/images?repo=<name>` and
`GET /browse/images/<repo>/<image>`. An offline hosted or group repository
answers 503 there, as it does to pulls and pushes.

An image of Helm charts shows its charts instead: the versions, the
`helm install` and `helm pull` commands of the selected one (the newest
release by default), its `Chart.yaml` facts (version, appVersion,
description, home, sources, maintainers, dependencies), its README and its
default values. The browse API reads them from the chart's blobs:
`GET /browse/chart?repo=<name>&image=<image>&digest=<manifest digest>`. A
proxy stores a chart's blobs when it is first pulled, so until then it shows
the versions and commands only. A README or `values.yaml` over 512 KiB is cut.

### Deleting from the web UI

In a hosted repository, an administrator deletes from the image page: the
whole image (*Delete image…*), a tag, a manifest, or a chart's version (its
manifest). The admin API does the same with a session or an admin-scoped
token:

```bash
# A tag: its manifest stays, pullable by digest.
curl -u admin@example.com:<admin-token> -X DELETE \
  'https://forge.example.com/admin/repositories/docker-hosted/images?image=team/app&reference=1.0'
# {"manifests": 0, "tags": 1}
# A manifest, with its tags: reference=sha256:<hex>. The whole image: no
# reference (an empty `reference=` is refused with 400).
```

A manifest goes with its tags and with what only it kept: the manifests an
index lists and the referrers (signatures, SBOMs, attestations) of it, unless
a tag or another manifest of the image still needs them, as image retention
decides. A manifest an index lists is deleted when asked for, even though
pulling that platform through the index then fails. The answer counts the
manifests and tags deleted (404 when nothing matched). A hosted repository is
deleted only once it holds no image, so emptying one is deleting its images.

The whole image goes 100 manifests at a time, the newest first, each batch
in a transaction of its own: an image of tens of thousands of manifests
never keeps them all locked, so pulls and pushes wait for one batch at most.
An index goes before the manifests it lists. A delete that is interrupted
(the connection dropped, the server stopped) leaves a smaller image whose
indexes are whole; delete it again to finish. A manifest pushed to the image
while the delete runs goes too.

The catalog API (`/v2/_catalog`) is not supported.

## Retention and garbage collection

A manifest keeps its config and layers alive through the image's blob links.
Deleting a tag only untags its manifest; deleting a manifest releases the
manifest, and the registry sweeper (every `docker.sweep_interval_seconds`)
releases the blobs no manifest of the image references any more once they
have been unused for `docker.unreferenced_blob_ttl_seconds` (24 h by
default: the time a client has between pushing layers and pushing their
manifest). Pushing or mounting a blob the image already has counts as a
use, and so does a pull or `HEAD` of it, recorded at most every tenth of
that TTL (at most hourly). The blob outbox deletes a blob after its grace period once no
image of any repository links it, so deleting an image never removes a layer
another image uses.

A docker repository's retention policy (`PUT
/admin/repositories/<name>/retention`) has image rules:

```json
{"policy": {
  "version": 1,
  "rules": [
    {"id": "keep-10", "image_prefix": "team/", "keep_last_n_tags": 10,
     "protected_tags": ["latest", "stable"]},
    {"id": "stale-tags", "tag_older_than_days": 90, "tag_not_pulled_for_days": 30},
    {"id": "untagged", "delete_untagged_after_days": 7}
  ]
}}
```

- **Tag rules** delete tags. Per image (only those under `image_prefix`, when
  set), the `keep_last_n_tags` most recently pushed tags and the
  `protected_tags` stay; any other tag goes when every trigger the rule sets
  holds (`tag_older_than_days` since its push, `tag_not_pulled_for_days`). A
  `GET` or a `HEAD` of a tag's manifest counts as a pull, so a tag that
  containerd (Kubernetes, nerdctl, BuildKit) only resolves stays pulled. A
  rule with only `keep_last_n_tags` keeps N tags per image.
- **Tags of one digest**: a tag rule deletes the tag alone. Its manifest
  stays while another tag names it, and is untagged (for
  `delete_untagged_after_days`) from when its last tag goes. A pull is
  recorded per manifest, so pulling `latest` counts for every tag of its
  digest: while `latest` is pulled, `tag_not_pulled_for_days` deletes no
  other tag of that digest, whereas `tag_older_than_days` and
  `keep_last_n_tags` judge each tag by its own push. Every tag takes a place
  among the `keep_last_n_tags`; name aliases such as `latest` in
  `protected_tags` so that they do not.
- **Untagged rules** (`delete_untagged_after_days`) delete manifests without a
  tag for that long, except what something kept refers to: the platforms of
  a kept index, and the signatures, SBOMs and attestations (referrers) of a
  kept manifest.
- `dry_run_only`, `enabled`, `min_run_interval_seconds`, preview, run and
  audit work as for NuGet repositories; audit rows carry the image as
  `package_name` and the tag or digest as `version`. Group repositories have
  no policy of their own. The repository's **Retention** screen in the web UI
  (Repositories → the repository → Retention) edits the rules, previews a
  draft before it is saved (`POST …/retention/preview` with
  `{"policy": {…}}`), runs the policy and lists the audit log.
- A run applies its decisions image by image, in batches of up to 100. As
  for NuGet repositories, a batch first checks that the policy is still the
  one the run evaluated and that the run still holds its lease; otherwise
  the run stops, so disabling the policy, switching it to dry run or
  editing it takes effect at once. The batch then evaluates the image's
  current tags and manifests again and skips what they no longer warrant:
  a tag pulled or pushed since, a tag that newer tags deleted meanwhile now
  keep, or a signature whose image was tagged again.

An image retention policy may also include a `size_budget`; it evicts
least-recently used unprotected manifests and tags after its ordinary rules.
See [Retention size budgets](retention.md) for configuration and logical size
accounting.

## Configuration

```toml
[docker]
max_blob_bytes = 1073741824           # (default: 1 GiB, or what an explicit server.max_staging_bytes holds) largest layer a proxy downloads
token_ttl_seconds = 300               # (default: 300) registry token lifetime, 60-3600
# token_secret = "…"                  # (default: a generated key kept in the database)
upload_ttl_seconds = 86400            # (default: 24 h) abandoned upload sessions expire
unreferenced_blob_ttl_seconds = 86400 # (default: 24 h, at least 1 h)
sweep_interval_seconds = 300          # (default: 300)
```

Pushes follow the repository's upload limit, not `max_blob_bytes`.
Raising `max_blob_bytes` raises the default `server.max_staging_bytes`
(four times the largest item) as well; size the staging volume for it. The
reverse proxy must allow request bodies of the largest repository upload
limit on `/v2` (docker sends a whole layer in one request, 1 GiB by default)
and stream them without buffering; see
[deployment](deployment.md#reverse-proxy).

## Known limitations

- Concurrent pulls of a layer a proxy does not hold yet share its download
  per instance: pulls through two instances download it twice.
- An upload of several chunks is assembled into a new blob when it finishes
  (the chunks are read back from the object store); one-chunk uploads, what
  docker, podman and containerd send, are stored once.
- Mounting a blob without `from` succeeds only when the image already has it.
- The registry is served over plain http only behind a TLS-terminating proxy
  or for `localhost`; Docker refuses other plain-http registries unless they
  are listed as insecure registries in the daemon.
