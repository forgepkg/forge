# Format plugins

Package formats for Forge, one crate per directory. Each implements
`FormatPlugin` from [`forge-plugin-api`](../plugin-api) and is linked
into the server. See [docs/format-plugins.md](../../docs/format-plugins.md) for
the design, the contract and how to write one.

| Plugin | Format id | What it serves |
| --- | --- | --- |
| [`apt`](apt) | `apt` | apt (Debian/Ubuntu) repositories at `/repository/{repo}`: `.deb` uploads, indexes signed with the repository's keys, `apt-get` installs; hosted and proxy repositories ([docs/apt.md](../../docs/apt.md)) |
| [`docker`](docker) | `docker` | Docker / OCI registries at `/v2`: push and pull images, indexes and artifacts (Helm charts, signatures, SBOMs); hosted, proxy and group repositories ([docs/docker.md](../../docs/docker.md)) |
| [`nuget`](nuget) | `nuget` | NuGet V3 feeds at `/repository/{repo}`: push, restore, search, unlist and relist; hosted, proxy and group repositories |
| [`npm`](npm) | `npm` | npm registries at `/repository/{repo}` for npm, pnpm, Yarn and Bun: publish, install, dist-tags, deprecations, unpublishing, search, audits and logins; hosted, proxy and group repositories ([docs/npm.md](../../docs/npm.md)) |
| [`raw`](raw) | `raw` | Raw files at `/repository/{repo}`: files under paths, uploads with `PUT` or a form, ranges, checksum sidecars, listings; hosted, proxy and group repositories ([docs/raw.md](../../docs/raw.md)) |

A plugin directory holds:

- `Cargo.toml`: a member of the workspace; its `version` is the plugin's;
- `src/`: `impl FormatPlugin`, and the format's `pub const DESCRIPTOR:
  Descriptor` that its `descriptor()` returns: the format id (also the
  directory's name), display name, version (`env!("CARGO_PKG_VERSION")`),
  description, repository kinds (`Proxy` when it implements
  `upstream`), its `storage` (`Packages`, `Files` for a files format such
  as raw, or `Images` for an images format such as Docker), its asset
  names, how a proxy sends a token (`upstream_token`: `Bearer` for
  npm), its options (`options`: apt's `distribution`), which versions are
  prereleases (`prereleases`), and whether the host keeps signed indexes of
  its hosted repositories (`indexes`: apt).

The server installs it in `plugins::builtin()`
([`crates/server/src/plugins.rs`](../server/src/plugins.rs)), whose tests
check every built-in format's descriptor (`forge_plugin::descriptor`). The
workspace builds, lints and tests the plugins like every other crate.
