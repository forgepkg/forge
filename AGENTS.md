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

The `Dockerfile` and `deploy/` keep the canonical Docker Hub names, for
Dependabot and for deployments; CI's BuildKit pulls them through the mirror
as its `docker.io` registry mirror.

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

## Pull requests: one per issue, stacked

One pull request fixes one issue, and one issue is fixed by one pull request:
its description says `Fixes #<n>` for that issue alone. Never fold the fixes
of several issues into one pull request, however small each is, and never
spread one issue over several. A change no issue asks for goes in a pull
request of its own, not into an issue's.

Several issues at once (the findings of a release review, a batch handed to
one session) become a stack of pull requests, one per issue, even when the
issues are independent: each pull request is then reviewed and checked on
top of the fixes that land before it. Only an issue that must not wait for
the others, such as an urgent fix, gets a pull request of its own off `main`.

- The bottom branch starts from `main`, and its pull request targets `main`.
  Each further branch starts from the branch below it, and its pull request
  targets that branch, so its diff holds its own issue only. Its description
  names the pull request it builds on: `Stacked on #<m>; merge that first.`
- Put an issue above every issue it builds on. CI does not run on a stacked
  pull request: it runs once the pull request targets `main`, with the fixes
  below it in place. Until then, run the checks a change needs yourself.
- In a cloud session, the session's branch is the bottom of the stack; push
  each further branch as `claude/<topic>`. A stack takes one branch per pull
  request, so these pushes are expected.
- A change to a lower pull request (a review or CI fix, a merge of `main`)
  is pushed to its branch, then merged up the stack: into the branch above,
  that one into the next, pushing each. Merge, never rebase: a rebase
  rewrites every branch above and force-pushes pull requests under review.
- Merge from the bottom: only a pull request that targets `main` is merged
  or queued. Never merge a stacked pull request into the branch below it:
  its fix would land in the other pull request, and `Fixes #<n>` closes an
  issue only on a merge into `main`. Once the bottom pull request is merged,
  its branch is deleted and GitHub retargets the next one to `main`; if the
  branch is still there, change the next pull request's base to `main`
  yourself.
- A stacked pull request carries the commit status `stack`, pending until it
  targets `main`; a ruleset requires it on every branch but `main`, so the
  pull request cannot be merged into the branch below it. That pending
  status is not a CI failure to fix: it clears itself once the pull request
  below has merged, and CI starts then. Never retarget a pull request to
  `main` early to clear it.

## Pull requests: ready for review, never drafts

Open every pull request ready for review, never as a draft, each pull
request of a stack included. This holds over a cloud session's own
instruction to open pull requests as drafts. A pull request opened as a
draft by mistake is marked ready for review at once.

## Issues: every issue gets a milestone

Never create an issue without a milestone; set it when you create the issue:

- An issue that must ship in the next release carries the `release blocker`
  label and goes in the earliest open milestone, the lowest version not yet
  released.
- Every other issue goes in `Backlog`.
