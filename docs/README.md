# Forge documentation

The guides to running Forge and publishing to it. They are also a site, with
navigation and search: **<https://forgepkg.github.io/forge/>**.

The [README](../README.md) says what Forge is and starts a first instance in
its [quickstart](../README.md#quickstart);
[DEVELOPMENT.md](../DEVELOPMENT.md) is the guide to working on Forge itself.

## Running Forge

- **[Production deployment](deployment.md)**: required settings, TLS and the
  reverse proxy, secret encryption, health probes, backup and restore, and
  upgrades.
- **[Helm chart](../deploy/helm/forge/README.md)**: the chart published with
  every release: which image it runs, its values, short-lived S3
  credentials, routing, optional dependencies and telemetry.
- **[Kubernetes manifests](../deploy/kubernetes/README.md)**: the kustomize
  base, components and overlays, for production and for an evaluation.
- **[Monitoring](../deploy/monitoring/README.md)**: an example OpenTelemetry
  Collector configuration, Grafana dashboard and Prometheus alerting rules.
- **[Retention](retention.md)**: every retention rule with examples (age,
  downloads, superseded prereleases, unlisted versions, version and tag
  patterns, keep-N), cron schedules in a time zone with a time limit per
  run, and size budgets.
- **[Importing repositories](import.md)**: copy a hosted repository of
  another server (a NuGet feed, an npm registry, a registry, a raw
  repository: Nexus, Artifactory, Verdaccio, a web server, another Forge)
  into Forge, with its publish dates.
- **[Importing from Nexus](nexus-import.md)**: where Nexus serves its feeds,
  registries and raw files, its search's limits, and imports stored before
  2.2.

## Formats

- **NuGet**: the README's [quickstart](../README.md#quickstart) points a
  `dotnet` client at a feed, and the CI guides below publish to one.
- **[apt repositories](apt.md)**: Debian and Ubuntu packages for `apt`:
  `.deb` uploads, signed indexes and key rotation, `sources.list` and
  `auth.conf.d`, proxies of Debian and Ubuntu mirrors.
- **[Docker / OCI registry](docker.md)**: image repositories (hosted, proxy,
  group), naming, `docker login`, retention and garbage collection.
- **[npm registries](npm.md)**: npm packages for npm, pnpm, Yarn and Bun:
  `.npmrc`, logins, publishing, dist-tags, proxies of `registry.npmjs.org`
  and audits.
- **[Raw file repositories](raw.md)**: files under arbitrary paths: uploads
  with curl, ranges and checksum sidecars, listings, and proxies of release
  downloads.
- **[Format plugins](format-plugins.md)**: further package formats, built
  into the server: design, operation, and writing one.

## CI and publishing

- **[Trusted publishing](trusted-publishing.md)**: short-lived workload
  identity for GitHub Actions, GitLab CI and other OIDC issuers, and the
  exchange of a job's token for an API key.
- **[GitLab CI with workload identity](gitlab-ci.md)**: step by step, every
  job of a GitLab project restores from Forge, and only the release job
  pushes. No secret in GitLab.
- **[CI with service accounts](ci-service-accounts.md)**: for pipelines that
  cannot use workload identity, a read token and a release token in GitLab's
  CI/CD variables.

## Releases

- **[Changelog](../CHANGELOG.md)**: release notes, upgrade notes and known
  limitations. A change adds its entry as a fragment under
  [changes/](changes/README.md).
