# apt repositories

Forge serves Debian packages to `apt`, the way Nexus' apt-hosted and
apt-proxy repositories do: hosts and container builds install your internal
`.deb` packages from Forge, and pull Debian or Ubuntu through a cache.

Packages live in repositories of `format: "apt"`, a format plugin built into
Forge ([`crates/formats/apt`](../crates/formats/apt); `GET /admin/formats`
lists it), served at `https://<host>/repository/<repository>/`, the path
Nexus uses: a migrated `sources.list` only changes the host. They come in
two kinds:

- **hosted**: upload your packages; Forge publishes them as one
  distribution, with indexes signed by the repository's own OpenPGP key;
- **proxy**: a cache of a Debian or Ubuntu mirror's distribution, whose
  signed indexes are passed on unchanged.

Every repository serves one **distribution** (`bookworm`, `jammy`,
`stable`), its `distribution` option: the name clients write in
`sources.list`.

## Contents

- [Hosted repositories](#hosted-repositories)
- [Connecting apt](#connecting-apt)
- [Uploading packages](#uploading-packages)
- [What is served](#what-is-served)
- [Signing keys](#signing-keys)
- [Proxy repositories](#proxy-repositories)
- [Permissions](#permissions)
- [Retention](#retention)
- [Limitations](#limitations)

## Hosted repositories

```bash
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories \
  -d '{"name": "apt-internal", "kind": "hosted", "format": "apt",
       "options": {"distribution": "bookworm"}}'
```

or **Admin → Repositories → New repository**, format *apt (Debian/Ubuntu)*.
The repository gets an Ed25519 signing key when it is created
([Signing keys](#signing-keys)).

A package is one architecture of a binary package: its id is
`<name>:<architecture>` (`hello:amd64`, `tool:all`), Debian's own spelling,
which package selectors, retention rules and the web UI use. Its version is
the Debian version, ordered as dpkg orders them (epoch, upstream version,
revision, `~` before everything): `1.0~rc1` < `1.0` < `1.0-1` < `1:0.9`.
Every version is a release: a `-` starts a Debian revision, not a
prerelease label.

The repository's **components** come from the packages' `Section`: a
package of `Section: contrib/net` is in `contrib`, any other in `main`. Its
**architectures** are those of its packages; an `all` package is listed
under every one of them (and under `binary-all`).

## Connecting apt

Each repository's page in the web UI shows these lines with its name, URL
and distribution filled in, and links its keys.

```bash
# The repository's signing keys.
curl -fsSL https://forge.example.com/repository/apt-internal/key.asc \
  | sudo tee /etc/apt/keyrings/apt-internal.asc > /dev/null
# The source.
echo "deb [signed-by=/etc/apt/keyrings/apt-internal.asc] https://forge.example.com/repository/apt-internal/ bookworm main" \
  | sudo tee /etc/apt/sources.list.d/apt-internal.list
```

Add the components your packages are in (`main contrib`). A repository
that does not allow anonymous reads needs credentials: an API token as the
password, in `/etc/apt/auth.conf.d/` (mode 600):

```
machine forge.example.com/repository/apt-internal
login ci@example.com
password <token>
```

apt sends credentials over plain HTTP only to a machine written with its
scheme (`machine http://forge.internal:8421/repository/apt-internal`).
Anonymous reads follow the repository's *Allow anonymous read*, as for
every format.

Then `apt-get update` and `apt-get install` as usual.

## Uploading packages

With an API token as the password (a password typed at the web login is not
an upload credential), any of:

```bash
# Nexus' upload: the package as the body of a POST to the repository.
curl -u ci@example.com:<token> -H "Content-Type: multipart/form-data" \
  --data-binary "@hello_2.10-3_amd64.deb" https://forge.example.com/repository/apt-internal/
# A form.
curl -u ci@example.com:<token> -F "package=@hello_2.10-3_amd64.deb" \
  https://forge.example.com/repository/apt-internal/
# A PUT.
curl -u ci@example.com:<token> --upload-file hello_2.10-3_amd64.deb \
  https://forge.example.com/repository/apt-internal/
```

The package's `control` file says what it is (`Package`, `Version`,
`Architecture`; the control member compressed with gzip, xz or zstd, or
not at all). An upload answers `201`; a version that exists answers `409`
unless the repository's deployment policy allows redeploying, a file that is
not a binary package `400`. Trusted publishing works as for every format
([trusted-publishing.md](trusted-publishing.md)).

`DELETE` of a package's pool file deletes the version (delete permission):

```bash
curl -u ci@example.com:<token> -X DELETE \
  https://forge.example.com/repository/apt-internal/pool/main/h/hello/hello_2.10-3_amd64.deb
```

## What is served

```
dists/<distribution>/InRelease                     Release, signed (cleartext)
dists/<distribution>/Release                       components, architectures, digests
dists/<distribution>/Release.gpg                   Release's detached signature
dists/<distribution>/<component>/binary-<arch>/Packages     (also .gz and .xz)
dists/<distribution>/<component>/binary-<arch>/by-hash/SHA256/<sha256>
pool/<component>/<prefix>/<name>/<name>_<version>_<arch>.deb
key.asc, key.gpg                                   the signing keys
```

`<prefix>` is the name's first letter (`lib` and the next one for a `lib`
name); a version with an epoch keeps it in the file name
(`tool_2:3.0_all.deb`).

The indexes are made when a client asks for them and the repository changed
since: a publish, a delete, an unlist (an unlisted version is not listed), a
new signing key or another distribution. A new index replaces the previous
one all at once, and `Release` says `Acquire-By-Hash: yes`: every index file
is also served by its SHA-256, and those copies stay a day after a newer
index no longer names them, so a client never mixes a `Release` and a
`Packages` of two generations. The `Release` file is signed with every key
of the repository, with SHA-512.

The web UI browses a repository by distribution, component and
architecture: its `Release` (date, components, architectures) and, for a
hosted repository, the packages of each component and architecture, each
linking to its page.

## Signing keys

A hosted repository signs its indexes with its own OpenPGP keys, kept
encrypted with Forge's secret encryption (`[crypto]`,
[deployment.md](deployment.md)); a secret key never leaves the server.
**Admin → Repositories → (the repository)** shows its keys, and the admin
API manages them:

```bash
# The keys: fingerprint, algorithm, user id, public key.
curl -u admin@example.com:<admin-token> \
  https://forge.example.com/admin/repositories/apt-internal/signing-keys
# Generate another key.
curl -u admin@example.com:<admin-token> -X POST -H 'content-type: application/json' -d '{}' \
  https://forge.example.com/admin/repositories/apt-internal/signing-keys
# Import one (an ASCII-armored secret key, with its passphrase if it has one).
jq -n --rawfile key private.asc '{secret_key: $key, passphrase: "…"}' \
  | curl -u admin@example.com:<admin-token> -X POST -H 'content-type: application/json' -d @- \
    https://forge.example.com/admin/repositories/apt-internal/signing-keys
# Delete one (never the last).
curl -u admin@example.com:<admin-token> -X DELETE \
  https://forge.example.com/admin/repositories/apt-internal/signing-keys/<fingerprint>
```

Keys are v4 **Ed25519** (EdDSA) keys, which `gpgv` 2.1 and later verify
(Debian 9, Ubuntu 18.04 and newer). Forge generates them so, and imports
only them: `gpg --quick-gen-key 'apt-internal <apt@example.com>' ed25519
sign` makes one to import. An imported key's passphrase is removed: the
secret encryption protects it instead.

**Rotating a key.** Every key of a repository signs, so a rotation needs no
downtime:

1. Add the new key (generate or import). `InRelease` and `Release.gpg` now
   carry a signature of each key; a client trusting either one verifies
   them, without a warning.
2. Give clients the new key: `key.asc` (and `key.gpg`) hold every key, so
   downloading it again into `/etc/apt/keyrings/` is enough.
3. Delete the old key.

## Proxy repositories

```bash
curl -u admin@example.com:<admin-token> -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories \
  -d '{"name": "debian", "kind": "proxy", "format": "apt",
       "remote_url": "http://deb.debian.org/debian",
       "options": {"distribution": "bookworm"}}'
```

A proxy serves one distribution of its upstream (`bookworm-updates` and
`bookworm-security`, on `http://security.debian.org/debian-security`, are
proxies of their own) and the whole pool. Its files are the upstream's,
unchanged, so clients verify them with the upstream's keys:

```
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://forge.example.com/repository/debian/ bookworm main
```

- `InRelease`, `Release` and the other indexes are re-validated with the
  upstream once the repository's metadata TTL (`metadata_ttl_seconds`, 10
  minutes by default) has passed; `by-hash/` copies and pool files never
  change, and are cached on their first download for good.
- A pool file is checked against the size and SHA-256 the upstream's
  `Packages` index of its component and architecture gives it (the
  distribution's `Packages.gz`, else `.xz`, else the plain one), when the
  index lists it: a file that does not match is not cached, and answers
  `502`. A `by-hash` copy is checked against its hash.
- While the upstream is down, what is cached is served; a file the
  upstream did not have is remembered for the not-found TTL. Upstream
  credentials are optional (`upstream_username`, `upstream_password`).
- *Invalidate cache* on the repository's page (or
  `POST /admin/repositories/{name}/proxy-cache/invalidate`) has the cached
  indexes re-validated on their next download.

There is no package delay for apt proxies: the indexes are the upstream's,
signed, and cannot leave a version out.

## Permissions

A repository is read with **read**, uploaded to with **write**, and a
version deleted with **delete**, as for every format. A package selector
limits which packages a reader may download (`internal-*` matches
`internal-tool:amd64`) and upload; the signed indexes are the same for every
reader, so they name every package of the repository. Give a team that may
not see some packages a repository of its own.

## Retention

A hosted repository's versions follow the repository's retention policy,
ordered by Debian version; the indexes follow on their next request.

## Limitations

- **One distribution per repository.** A hosted repository publishes its
  packages as one distribution, as Nexus does; serve another distribution
  from another repository.
- **No groups.** Nexus has no apt groups; a group would merge its members'
  indexes and sign them with a key of its own.
- **A proxy's cache is not trimmed.** Retention does not evict an apt
  proxy's cached files yet; a proxy keeps every package and index copy it
  downloaded until it is deleted.
- **Ed25519 keys only.** RSA and NIST-curve keys are refused: the OpenPGP
  library's code for them is not constant-time.
- **Source packages** (`.dsc`, `Sources`) are not hosted; a proxy serves its
  upstream's.
