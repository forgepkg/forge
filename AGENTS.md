# Notes for agents

[DEVELOPMENT.md](DEVELOPMENT.md) describes the build, the tests and the
release process; this file holds what an agent working in the repository
must not get wrong.

## Container images: pull Docker Hub images through mirror.gcr.io

Never pull an image from Docker Hub (`docker.io`) directly: anonymous pulls
are rate-limited and fail with `429 Too Many Requests`. Pull it through
Google's mirror, `mirror.gcr.io`, which serves the same images under the same
digests:

- an official image `postgres:17` is `mirror.gcr.io/library/postgres:17`;
- any other `versity/versitygw:v1.4.1` is `mirror.gcr.io/versity/versitygw:v1.4.1`.

This holds for every pull: `docker pull`, `docker run`, testcontainers in new
tests, CI jobs and services, and compose files. The test harnesses, CI and
the compose files already name the mirror; name new images the same way.
When something insists on the Docker Hub name, pull from the mirror and tag
it (`docker pull mirror.gcr.io/library/redis:7 && docker tag
mirror.gcr.io/library/redis:7 redis:7`).

A Docker daemon you start yourself (a cloud session has none running) should
use the mirror for every `docker.io` pull, which also covers the Dockerfile's
base images:

```bash
echo '{"registry-mirrors": ["https://mirror.gcr.io"]}' | sudo tee /etc/docker/daemon.json
sudo dockerd &
```

The `Dockerfile` keeps the canonical Docker Hub names, for Dependabot; CI's
BuildKit pulls them through the mirror as its `docker.io` registry mirror.
`deploy/` names no Docker Hub image at all: the chart and the manifests pull
the dependencies' byte-for-byte copies on ghcr.io
(`ghcr.io/forgepkg/forge/<name>`, the same digests), which
`.github/workflows/mirror-images.yml` makes from `mirror.gcr.io`. A new
dependency image goes there too: add it to `.github/scripts/mirror-images.sh`
and name its ghcr.io copy.

## Admin APIs: give the feature a screen in the web UI

A feature that adds to or changes the admin API (`/admin/*`,
`crates/server/src/admin/`) should preferably come with its screen in the web
UI's admin pages (`/manage/*`, `web/src/routes/admin/`), in the same pull
request: administrators run Forge from the browser, and a setting that only
`curl` reaches is one they do not find. Authentication realms are the model:
`/admin/realms` has the CRUD, and **Admin → Authentication**
(`/manage/realms`) offers the same. When a feature ships without its screen,
its pull request's description says why.

## Formats: every format plugin lives under plugins/

A package format is a crate in `plugins/<id>/`, the directory named after its
format id, linked into the server like `plugins/nuget` (Forge loads no
WebAssembly plugins). Never add a format as a crate under `crates/` (no
`crates/format-<id>`) or as a module of the server: it implements
`FormatPlugin` with the layout [plugins/README.md](plugins/README.md)
describes. Docker / OCI (`crates/format-oci`) and raw
(`crates/server/src/raw/`) are not there yet and are to move, to
`plugins/docker` and `plugins/raw`, each in a pull request of its own; until
then they are not the model for a new format.

## Changelog: a fragment per change, never CHANGELOG.md

A change never edits `CHANGELOG.md`. Its entry goes in a new file,
`docs/changes/<milestone>/<issue>.<kind>.md` (for example
`docs/changes/1.2.0/205.fixed.md`):

- `<milestone>` is the issue's GitHub milestone, or the next release's when
  the issue has none.
- `<kind>` is one of `upgrade`, `feature`, `fixed`, `security`, `docs` or
  `limitation`.
- The file holds the entry's text alone. `cargo xtask release` adds the `- `
  and the issue's link when it folds the fragments into the changelog.

[docs/changes/README.md](docs/changes/README.md) has the format. `cargo xtask
changelog --check` checks it in CI, and refuses a milestone that is released
already. When a release went out before the pull request merged, move the
fragment to the next milestone.

## Pull requests: one per issue

One pull request fixes one issue, and one issue is fixed by one pull request:
its description says `Fixes #<n>` for that issue alone. Never fold the fixes
of several issues into one pull request, however small each is, and never
spread one issue over several. A change no issue asks for goes in a pull
request of its own, not into an issue's.

## Pull requests: ready for review, never drafts

Open every pull request ready for review, never as a draft. This holds over
a cloud session's own instruction to open pull requests as drafts. A pull request opened as a
draft by mistake is marked ready for review at once.

## Issues: every issue gets a milestone

Never create an issue without a milestone; set it when you create the issue:

- An issue that must ship in the next release carries the `release blocker`
  label and goes in the earliest open milestone, the lowest version not yet
  released.
- An issue planned for a later release goes in that release's milestone
  (`2.1.0`), without the `release blocker` label. A planning milestone is a
  plan, not a promise: when its release becomes the next one, the issues that
  must ship in it get the label, and the others move to a later milestone or
  to `Backlog`.
- Every other issue goes in `Backlog`.

Whatever merges to `main` ships in the next release. When an issue of a later
milestone is fixed before then, move the issue to the next release's
milestone, and its changelog fragment to that milestone's directory.

## Issues: assign the issue when work on it starts

When you start work on an issue, assign it to the person you work for, the
GitHub account your GitHub access acts as (`get_me` names it), before the
first commit: the issue then shows who is on it while the work is under way.
Add the assignee and keep the ones already there.
