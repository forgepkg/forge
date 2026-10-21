# Notes for Claude

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
Dependabot and for deployments; CI's BuildKit and GitLab's Docker daemon pull
them through the mirror as their `docker.io` registry mirror.
