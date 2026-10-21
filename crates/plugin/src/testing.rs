//! Test support: build the plugins of `plugins/` (feature `testing`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Build `plugins/<name>` for `wasm32-wasip2` (once per process) and return
/// a plugin directory holding its `plugin.toml` and component, as an
/// operator would install it.
///
/// Needs the `wasm32-wasip2` target (`rustup target add wasm32-wasip2`).
pub fn example_plugin(name: &str) -> PathBuf {
    static BUILT: Mutex<Vec<(String, PathBuf)>> = Mutex::new(Vec::new());
    let mut built = BUILT.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, dir)) = built.iter().find(|(n, _)| n == name) {
        return dir.clone();
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = workspace.join("plugins").join(name);
    let target = workspace.join("target/plugins");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            "wasm32-wasip2",
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
    let manifest = crate::Manifest::load(&source).expect("example plugin.toml");
    let dir = target.join("installed").join(name);
    std::fs::create_dir_all(&dir).expect("create the plugin directory");
    std::fs::copy(source.join("plugin.toml"), dir.join("plugin.toml")).expect("copy plugin.toml");
    let wasm = target
        .join("wasm32-wasip2/release")
        .join(&manifest.component);
    std::fs::copy(&wasm, dir.join(&manifest.component)).expect("copy the component");
    built.push((name.to_string(), dir.clone()));
    dir
}

/// The SHA-256 (lowercase hex) of the component in plugin directory `dir`,
/// what an operator pins.
pub fn component_sha256(dir: &Path) -> String {
    use sha2::Digest;
    let manifest = crate::Manifest::load(dir).expect("plugin.toml");
    let bytes = std::fs::read(dir.join(&manifest.component)).expect("read the component");
    hex::encode(sha2::Sha256::digest(bytes))
}
