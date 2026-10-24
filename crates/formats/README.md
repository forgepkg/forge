# Format plugins

Package formats for Forge, one crate per directory. Each implements
`FormatPlugin` from [`forge-plugin-api`](../plugin-api) and is linked
into the server. See [docs/format-plugins.md](../../docs/format-plugins.md) for
the design, the contract and how to write one.

| Plugin | Format id | What it serves |
| --- | --- | --- |
| [`nuget`](nuget) | `nuget` | NuGet V3 feeds at `/v3`: push, restore, search, unlist and relist; hosted, proxy and group repositories |
| [`raw`](raw) | `raw` | Raw files at `/raw`: files under paths, uploads with `PUT` or a form, ranges, checksum sidecars, listings; hosted, proxy and group repositories ([docs/raw.md](../../docs/raw.md)) |

[`docker`](docker) holds Docker / OCI (`forge-format-docker`), which is still
native: the server's registry serves it under `/v2`, not through
`FormatPlugin` ([docs/docker.md](../../docs/docker.md)).

A plugin directory holds:

- `Cargo.toml`: a member of the workspace; its `version` is the plugin's;
- `src/`: `impl FormatPlugin`, and the format's `pub const DESCRIPTOR:
  Descriptor` that its `descriptor()` returns: the format id (also the
  directory's name), display name, version (`env!("CARGO_PKG_VERSION")`),
  description, mount, repository kinds (`Proxy` when it implements
  `upstream`), its `storage` (`Packages`, or `Files` for a files format such
  as raw) and its asset names.

The server installs it in `plugins::builtin()`
([`crates/server/src/plugins.rs`](../server/src/plugins.rs)), whose tests
check every built-in format's descriptor (`forge_plugin::descriptor`). The
workspace builds, lints and tests the plugins like every other crate.
