//! Test support: build the plugins of `plugins/` as WebAssembly components
//! (feature `testing`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Build `plugins/<name>` as a component (once per process) and install it as
/// an operator would: a plugin directory holding its `plugin.toml` and the
/// component.
///
/// Needs the `wasm32-wasip2` target (`rustup target add wasm32-wasip2`).
pub fn example_plugin(name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins")
        .join(name);
    let id = crate::Manifest::load(&source)
        .expect("example plugin.toml")
        .id;
    example_plugin_as(name, &id)
}

/// [`example_plugin`], installed under format id `id` (its `plugin.toml`
/// rewritten): a component of a plugin that is also built in, under an id of
/// its own.
pub fn example_plugin_as(name: &str, id: &str) -> PathBuf {
    static BUILT: Mutex<Vec<(String, PathBuf)>> = Mutex::new(Vec::new());
    let mut built = BUILT.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, dir)) = built.iter().find(|(i, _)| i == id) {
        return dir.clone();
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = workspace.join("plugins").join(name);
    let target = workspace.join("target/plugins");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .args([
            "rustc",
            "--locked",
            "--lib",
            "--crate-type",
            "cdylib",
            "--profile",
            "plugin",
            "--target",
            "wasm32-wasip2",
            "--features",
            "component",
        ])
        .arg("--manifest-path")
        .arg(source.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target)
        // The outer build's flags are for the host, not for wasm.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .status()
        .expect("run cargo to build the example plugin");
    assert!(
        status.success(),
        "building plugins/{name} failed (is the wasm32-wasip2 target installed? \
         `rustup target add wasm32-wasip2`)"
    );
    let text = std::fs::read_to_string(source.join("plugin.toml")).expect("read plugin.toml");
    let text: String = text
        .lines()
        .map(|line| {
            let key = line.split('=').next().unwrap_or("").trim();
            if key == "id" {
                format!("id = {id:?}\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect();
    let manifest = crate::Manifest::parse(&text).expect("example plugin.toml");
    let component = manifest
        .component
        .expect("the example plugin.toml names its component");
    let dir = target.join("installed").join(id);
    std::fs::create_dir_all(&dir).expect("create the plugin directory");
    std::fs::write(dir.join("plugin.toml"), text).expect("write plugin.toml");
    let wasm = target.join("wasm32-wasip2/plugin").join(&component);
    std::fs::copy(&wasm, dir.join(&component)).expect("copy the component");
    built.push((id.to_string(), dir.clone()));
    dir
}

/// The SHA-256 (lowercase hex) of the component in plugin directory `dir`,
/// what an operator pins.
pub fn component_sha256(dir: &Path) -> String {
    use sha2::Digest;
    let manifest = crate::Manifest::load(dir).expect("plugin.toml");
    let component = manifest.component.expect("plugin.toml names a component");
    let bytes = std::fs::read(dir.join(component)).expect("read the component");
    hex::encode(sha2::Sha256::digest(bytes))
}
