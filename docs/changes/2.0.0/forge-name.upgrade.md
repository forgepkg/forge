The project is named Forge alone, without "envisia". Forge's requests to
upstream registries send `User-Agent: forge/<version>` (was
`envisia-forge/<version>`); an upstream allowlist that matches the old value
needs the new one. The Helm chart and the kustomize manifests label their
objects `app.kubernetes.io/part-of: forge` (was `envisia-forge`); a selector,
NetworkPolicy, dashboard or alert that matches the old label needs the new
one. The chart records the signed image digest under the annotation
`forge/image-digest` (was `forge.envisia.de/image-digest`).
