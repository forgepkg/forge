# Format plugins

Package formats for Forge, one crate per directory. Each implements
`FormatPlugin` from [`forge-plugin-api`](../crates/plugin-api) and runs
either way: linked into the server (built in), or as a WebAssembly component
loaded at startup. See [docs/format-plugins.md](../docs/format-plugins.md) for
the design, the contract and how to operate them.

| Plugin | Format id | Runs | What it serves |
| --- | --- | --- | --- |
| [`nuget`](nuget) | `nuget` | built in only | NuGet V3 feeds at `/v3`: push, restore, search, unlist and relist; hosted, proxy and group repositories |
| [`helm`](helm) | `helm` | built in | Helm chart repositories: `index.yaml`, chart downloads, ChartMuseum-compatible push, delete and listing; hosted, proxy and group repositories |

A plugin directory holds:

- `Cargo.toml`: a member of the workspace, with a `component` feature
  (`component = ["forge-plugin-api/component"]`) unless it is built in only;
- `plugin.toml`: the format id (also the directory's name), display name,
  version, the `forge:format` contract version it targets (`api`),
  optionally its mount, repository kinds (`proxy` when it implements
  `upstream`) and `[assets]` names, and, for the component build, the
  component's file name and optional `[limits]`;
- `src/`: `impl FormatPlugin`, `pub const PLUGIN_TOML: &str =
  forge_plugin_api::plugin_toml!();`, and
  `#[cfg(feature = "component")] forge_plugin_api::export_component!(…);`.

The workspace builds, lints and tests the plugins natively like every other
crate. As components (needs the `wasm32-wasip2` target):

```bash
rustup target add wasm32-wasip2   # once
cargo xtask plugins               # build + install under target/plugins/installed/, print the [plugins] config
cargo xtask plugins-check         # clippy of the component build, and the build, as CI runs them
```

Both skip a plugin whose `plugin.toml` names no `component`. NuGet is one:
its `.nupkg` reader (`zip`, through `typed-path`) needs a nightly compiler for
`wasm32-wasip2`.

The tests that load a component build it through
`forge_plugin::testing::example_plugin`, so `cargo test --workspace` needs the
`wasm32-wasip2` target as well.
