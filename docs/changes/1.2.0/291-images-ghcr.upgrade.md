The Helm chart and the kustomize manifests pull PostgreSQL, Valkey and
versitygw from ghcr.io, like Forge itself: `ghcr.io/forgepkg/forge/<name>`
holds byte-for-byte copies of the Docker Hub images under the same digests,
so a cluster needs no access to Docker Hub (and meets none of its pull rate
limits). To keep pulling from Docker Hub, set the dependency's
`image.registry: docker.io` and `image.repository` to the Docker Hub name
(Helm), or add an `images:` entry with `newName` (kustomize).
