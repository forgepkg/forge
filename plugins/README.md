# Format plugins

Package formats for Forge as WebAssembly components (see
[docs/format-plugins.md](../docs/format-plugins.md) for the design, the
contract and how to operate them).

| Plugin | Format id | What it serves |
| --- | --- | --- |
| [`helm`](helm) | `helm` | Helm chart repositories: `index.yaml`, chart downloads, ChartMuseum-compatible push, delete and listing |

Each plugin is a crate with its own workspace (it is excluded from the
server's) and its own `Cargo.lock`, built for `wasm32-wasip2`:

```bash
rustup target add wasm32-wasip2   # once
cargo xtask plugins               # build + install under target/plugins/installed/, print the [plugins] config
cargo xtask plugins-check         # fmt, clippy (wasm and native) and unit tests, as CI runs them
```

A plugin directory holds:

- `plugin.toml` — the format id (also the directory's name), display name,
  version, the `forge:format` contract version it targets (`api`), the
  component's file name, and optional `[limits]`;
- `Cargo.toml` with `crate-type = ["cdylib"]`, and `src/` implementing the
  `format-plugin` world of [`crates/plugin/wit/format.wit`](../crates/plugin/wit/format.wit)
  with `wit-bindgen`.

The server-side tests that load a plugin build it through
`forge_plugin::testing::example_plugin`, so `cargo test --workspace` needs the
`wasm32-wasip2` target as well.
