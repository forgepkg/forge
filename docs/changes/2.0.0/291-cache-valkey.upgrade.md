**Breaking for installs that run the in-cluster Redis:** the Helm chart and
the kustomize manifests run Valkey (9.1, the BSD-licensed fork of Redis that
speaks the same protocol) instead of Redis as their optional in-cluster
shared cache. Forge's own setting is unchanged (`FORGE_REDIS__URL`, a
`redis://` URL), and an external Redis keeps working.

Helm: the `redis:` values are now `valkey:` (`valkey.enabled`,
`valkey.auth.*`, …; still off by default), and the Deployment, Service,
Secret and NetworkPolicy are named `<release>-valkey`. The chart's schema
refuses a leftover `redis:` key. The upgrade removes the Redis objects and
generates a new password unless `valkey.auth.password` or
`valkey.auth.existingSecret` is set; the Forge pods roll onto the new URL
and start with an empty shared cache.

Kustomize: `components/redis` is now `components/valkey`, and its password
is `VALKEY_PASSWORD` in the `forge-env` Secret (was `REDIS_PASSWORD`).
`kubectl apply -k` leaves the old objects behind; delete them with
`kubectl delete deployment,service,networkpolicy forge-redis`.
