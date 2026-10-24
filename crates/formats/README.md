# Format plugins

Package formats for Forge, one crate per directory. Each implements
`FormatPlugin` from [`forge-plugin-api`](../plugin-api) and is linked
into the server. See [docs/format-plugins.md](../../docs/format-plugins.md) for
the design, the contract and how to write one.

| Plugin | Format id | What it serves |
| --- | --- | --- |
| [`nuget`](nuget) | `nuget` | NuGet V3 feeds at `/v3`: push, restore, search, unlist and relist; hosted, proxy and group repositories |
| [`raw`](raw) | `raw` | Raw files at `/raw`: files under paths, uploads with `PUT` or a form, ranges, checksum sidecars, listings; hosted, proxy and group repositories ([docs/raw.md](../../docs/raw.md)) |

A plugin directory holds:

- `Cargo.toml`: a member of the workspace;
- `plugin.toml`: the format id (also the directory's name), display name,
  version, the `forge:format` contract version it targets (`api`), and
  optionally its mount, repository kinds (`proxy` when it implements
  `upstream`), its `storage` (`packages`, or `files` for a files format such
  as raw) and `[assets]` names;
- `src/`: `impl FormatPlugin`, and `pub const PLUGIN_TOML: &str =
  forge_plugin_api::plugin_toml!();`.

The server installs it in `plugins::builtin()`
([`crates/server/src/plugins.rs`](../server/src/plugins.rs)). The
workspace builds, lints and tests the plugins like every other crate.
