//! `forge-plugin`: package formats as WebAssembly components.
//!
//! A format plugin is a [component] implementing the `forge:format` world
//! (`wit/format.wit`): the format's identity rules, its package parser, and
//! its client protocol. Forge keeps everything else — storage, metadata,
//! authentication and authorization, hosted/group semantics, retention, and
//! the streaming of package bytes — so a plugin is small and never sees a
//! credential, a storage key, or a whole package in memory.
//!
//! * [`Plugin::load`] reads a plugin directory (`plugin.toml` plus the
//!   component), checks the component against the SHA-256 the operator
//!   pinned, and compiles it once.
//! * [`PluginFormat`] adapts a plugin to [`forge_core::Format`], so hosted
//!   publishing, reads, groups and retention work for it unchanged.
//! * [`Plugin::handle`] and [`Plugin::render`] drive its client protocol
//!   ([`protocol`]).
//!
//! ## Sandbox
//! Every call runs in an instance with a memory ceiling, a fuel budget and a
//! wall-clock deadline (epoch interruption), on a dedicated thread (see
//! `executor`). A trap — out of fuel, past the deadline, out of memory, a
//! guest panic — fails that call and discards the instance. The WASI context
//! is empty: no files, no sockets, no environment, no arguments; stdout and
//! stderr go nowhere.
//!
//! [component]: https://component-model.bytecodealliance.org/

mod bindings;
mod executor;
mod format;
mod host;
pub mod manifest;
#[cfg(feature = "testing")]
pub mod testing;

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use sha2::{Digest, Sha256};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimitsBuilder, Trap};

pub use format::PluginFormat;
pub use manifest::Manifest;

use bindings::{FormatPlugin, FormatPluginPre};
use host::HostState;

/// The client-protocol types of the `forge:format` world, as the host sees
/// them (generated from `wit/format.wit`).
pub mod protocol {
    pub use crate::bindings::exports::forge::format::protocol::*;
}

/// Errors loading or calling a plugin.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// The plugin directory or component could not be read.
    #[error("{0}")]
    Io(String),
    /// `plugin.toml` is missing a key, malformed, or asks for too much.
    #[error("invalid plugin.toml: {0}")]
    Manifest(String),
    /// The component's SHA-256 is not the pinned one.
    #[error("component digest {actual} does not match the pinned {expected}")]
    Digest {
        /// The pinned digest.
        expected: String,
        /// The component's digest.
        actual: String,
    },
    /// The component does not compile or does not implement the world.
    #[error("invalid component: {0}")]
    Component(String),
    /// A call trapped, ran out of fuel or time, or the instance could not be
    /// created.
    #[error("plugin call failed: {0}")]
    Trap(String),
}

/// The most a plugin may ask for, and what it gets when it asks for nothing.
#[derive(Debug, Clone)]
pub struct HostLimits {
    /// Linear-memory ceiling per instance when the plugin names none (MiB).
    pub default_memory_mib: u64,
    /// The largest memory ceiling a plugin may request (MiB).
    pub max_memory_mib: u64,
    /// Fuel per call when the plugin names none.
    pub default_fuel: u64,
    /// The most fuel per call a plugin may request.
    pub max_fuel: u64,
    /// Wall-clock budget per call when the plugin names none.
    pub default_timeout: Duration,
    /// The longest wall-clock budget a plugin may request.
    pub max_timeout: Duration,
}

impl Default for HostLimits {
    fn default() -> Self {
        HostLimits {
            default_memory_mib: 64,
            max_memory_mib: 512,
            default_fuel: 5_000_000_000,
            max_fuel: 50_000_000_000,
            default_timeout: Duration::from_secs(5),
            max_timeout: Duration::from_secs(30),
        }
    }
}

/// The limits one plugin runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Linear-memory ceiling per instance, in bytes.
    pub memory_bytes: usize,
    /// Fuel per call.
    pub fuel: u64,
    /// Wall-clock budget per call.
    pub timeout: Duration,
}

impl HostLimits {
    /// What `requested` resolves to, or why it is refused.
    pub fn resolve(&self, requested: &manifest::RequestedLimits) -> Result<Limits, PluginError> {
        let memory_mib = requested.memory_mib.unwrap_or(self.default_memory_mib);
        if memory_mib == 0 || memory_mib > self.max_memory_mib {
            return Err(PluginError::Manifest(format!(
                "limits.memory_mib {memory_mib} is outside 1..={}",
                self.max_memory_mib
            )));
        }
        let fuel = requested.fuel.unwrap_or(self.default_fuel);
        if fuel == 0 || fuel > self.max_fuel {
            return Err(PluginError::Manifest(format!(
                "limits.fuel {fuel} is outside 1..={}",
                self.max_fuel
            )));
        }
        let timeout = requested
            .timeout_ms
            .map_or(self.default_timeout, Duration::from_millis);
        if timeout.is_zero() || timeout > self.max_timeout {
            return Err(PluginError::Manifest(format!(
                "limits.timeout_ms {} is outside 1..={}",
                timeout.as_millis(),
                self.max_timeout.as_millis()
            )));
        }
        let memory_bytes = usize::try_from(memory_mib * 1024 * 1024)
            .map_err(|_| PluginError::Manifest("limits.memory_mib is too large".into()))?;
        Ok(Limits {
            memory_bytes,
            fuel,
            timeout,
        })
    }
}

/// How often the engine's epoch advances: the granularity of call deadlines.
const EPOCH_TICK: Duration = Duration::from_millis(10);

/// An instance is replaced after this many calls, so whatever a guest leaks
/// (allocator fragmentation, a growing cache) is bounded.
const MAX_CALLS_PER_INSTANCE: u32 = 10_000;

/// Idle instances kept per plugin.
const MAX_IDLE_INSTANCES: usize = 16;

/// The engine every plugin is compiled for, and the thread advancing its
/// epoch.
fn engine() -> Result<&'static Engine, PluginError> {
    static ENGINE: OnceLock<Result<Engine, String>> = OnceLock::new();
    ENGINE
        .get_or_init(|| {
            let mut config = Config::new();
            config
                .wasm_component_model(true)
                .consume_fuel(true)
                .epoch_interruption(true)
                .max_wasm_stack(1024 * 1024);
            let engine = Engine::new(&config).map_err(|e| e.to_string())?;
            let ticker = engine.clone();
            std::thread::Builder::new()
                .name("forge-plugin-epoch".into())
                .spawn(move || loop {
                    std::thread::sleep(EPOCH_TICK);
                    ticker.increment_epoch();
                })
                .map_err(|e| e.to_string())?;
            Ok(engine)
        })
        .as_ref()
        .map_err(|e| PluginError::Component(format!("engine: {e}")))
}

/// Compile `bytes` (whose SHA-256 is `sha256`), or reuse the compilation of
/// the same component: loading a plugin again (other limits, a reload) does
/// not pay for Cranelift twice.
fn compile(engine: &Engine, sha256: &str, bytes: &[u8]) -> Result<Component, PluginError> {
    static COMPILED: Mutex<Vec<(String, Component)>> = Mutex::new(Vec::new());
    let mut compiled = COMPILED.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, component)) = compiled.iter().find(|(sha, _)| sha == sha256) {
        return Ok(component.clone());
    }
    let component =
        Component::new(engine, bytes).map_err(|e| PluginError::Component(format!("{e:#}")))?;
    compiled.push((sha256.to_string(), component.clone()));
    Ok(component)
}

/// A loaded format plugin.
pub struct Plugin {
    manifest: Manifest,
    /// The format id, leaked once per load so [`forge_core::Format::id`] can
    /// hand out a `&'static str`.
    id: &'static str,
    sha256: String,
    limits: Limits,
    pre: FormatPluginPre<HostState>,
    idle: Mutex<Vec<Warm>>,
}

/// An instantiated plugin, reused across calls.
struct Warm {
    store: Store<HostState>,
    plugin: FormatPlugin,
    calls: u32,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("id", &self.id)
            .field("version", &self.manifest.version)
            .field("sha256", &self.sha256)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Plugin {
    /// Load the plugin in `dir`: read `plugin.toml`, check the component
    /// against `expected_sha256` (lowercase hex; an operator pins every
    /// plugin), resolve its limits against `host`, and compile it.
    pub fn load(
        dir: &Path,
        expected_sha256: &str,
        host: &HostLimits,
    ) -> Result<Arc<Self>, PluginError> {
        let manifest = Manifest::load(dir)?;
        let path = dir.join(&manifest.component);
        let bytes = std::fs::read(&path)
            .map_err(|e| PluginError::Io(format!("read {}: {e}", path.display())))?;
        Self::from_parts(manifest, &bytes, expected_sha256, host)
    }

    /// [`Self::load`] from a manifest and the component's bytes.
    pub fn from_parts(
        manifest: Manifest,
        component: &[u8],
        expected_sha256: &str,
        host: &HostLimits,
    ) -> Result<Arc<Self>, PluginError> {
        let actual = hex::encode(Sha256::digest(component));
        let expected = expected_sha256.trim().to_ascii_lowercase();
        let expected = expected.strip_prefix("sha256:").unwrap_or(&expected);
        if actual != expected {
            return Err(PluginError::Digest {
                expected: expected.to_string(),
                actual,
            });
        }
        let limits = host.resolve(&manifest.limits)?;

        let engine = engine()?;
        let component = compile(engine, &actual, component)?;
        let mut linker = Linker::<HostState>::new(engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(|e| PluginError::Component(format!("link WASI: {e:#}")))?;
        FormatPlugin::add_to_linker::<_, wasmtime::component::HasSelf<HostState>>(
            &mut linker,
            |state| state,
        )
        .map_err(|e| PluginError::Component(format!("link host functions: {e:#}")))?;
        let pre = linker
            .instantiate_pre(&component)
            .map_err(|e| PluginError::Component(format!("{e:#}")))?;
        let pre =
            FormatPluginPre::new(pre).map_err(|e| PluginError::Component(format!("{e:#}")))?;

        let plugin = Arc::new(Plugin {
            id: Box::leak(manifest.id.clone().into_boxed_str()),
            manifest,
            sha256: actual,
            limits,
            pre,
            idle: Mutex::new(Vec::new()),
        });
        // Instantiate once now, so a component that cannot start fails the
        // load instead of the first request (on a plugin thread, like every
        // run of guest code).
        let starting = Arc::clone(&plugin);
        let warm = executor::run_blocking(executor::Pool::Slow, move || starting.instantiate())??;
        plugin.park(warm);
        Ok(plugin)
    }

    /// The format id.
    pub fn id(&self) -> &'static str {
        self.id
    }

    /// The parsed `plugin.toml`.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The component's SHA-256 (lowercase hex).
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The limits every call runs under.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    fn instantiate(&self) -> Result<Warm, PluginError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.memory_bytes)
            .instances(64)
            .tables(64)
            .memories(16)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(self.pre.engine(), HostState::new(limits));
        store.limiter(|state| &mut state.limits);
        self.arm(&mut store)?;
        let plugin = self
            .pre
            .instantiate(&mut store)
            .map_err(|e| PluginError::Trap(format!("instantiate: {}", describe(&e))))?;
        Ok(Warm {
            store,
            plugin,
            calls: 0,
        })
    }

    /// Give `store` a fresh fuel budget and deadline for one call.
    fn arm(&self, store: &mut Store<HostState>) -> Result<(), PluginError> {
        store
            .set_fuel(self.limits.fuel)
            .map_err(|e| PluginError::Trap(e.to_string()))?;
        let ticks = self
            .limits
            .timeout
            .as_millis()
            .div_ceil(EPOCH_TICK.as_millis())
            + 1;
        store.set_epoch_deadline(u64::try_from(ticks).unwrap_or(u64::MAX));
        store.epoch_deadline_trap();
        Ok(())
    }

    fn park(&self, warm: Warm) {
        if warm.calls >= MAX_CALLS_PER_INSTANCE {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(|p| p.into_inner());
        if idle.len() < MAX_IDLE_INSTANCES {
            idle.push(warm);
        }
    }

    /// Run `f` against an instance, on the calling thread (which must be a
    /// plugin thread, see `executor`). A failed call discards the instance.
    fn call<R>(
        &self,
        what: &str,
        f: impl FnOnce(&mut Store<HostState>, &FormatPlugin) -> wasmtime::Result<R>,
    ) -> Result<R, PluginError> {
        let idle = self.idle.lock().unwrap_or_else(|p| p.into_inner()).pop();
        let mut warm = match idle {
            Some(warm) => warm,
            None => self.instantiate()?,
        };
        self.arm(&mut warm.store)?;
        match f(&mut warm.store, &warm.plugin) {
            Ok(value) => {
                warm.calls += 1;
                self.park(warm);
                Ok(value)
            }
            Err(e) => {
                let reason = describe(&e);
                tracing::warn!(plugin = self.id, call = what, %reason, "format plugin call failed");
                Err(PluginError::Trap(format!("{what}: {reason}")))
            }
        }
    }

    /// [`Self::call`] on a thread of `pool`, blocking the caller.
    fn call_blocking<R, F>(
        self: &Arc<Self>,
        pool: executor::Pool,
        what: &'static str,
        f: F,
    ) -> Result<R, PluginError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Store<HostState>, &FormatPlugin) -> wasmtime::Result<R> + Send + 'static,
    {
        let plugin = Arc::clone(self);
        executor::run_blocking(pool, move || plugin.call(what, f))?
    }

    /// [`Self::call`] on a thread of the slow pool, awaiting the result.
    async fn call_async<R, F>(self: &Arc<Self>, what: &'static str, f: F) -> Result<R, PluginError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Store<HostState>, &FormatPlugin) -> wasmtime::Result<R> + Send + 'static,
    {
        let plugin = Arc::clone(self);
        executor::run(executor::Pool::Slow, move || plugin.call(what, f)).await?
    }

    /// Ask the plugin what a request is (see the `protocol` interface).
    pub async fn handle(
        self: &Arc<Self>,
        repo: protocol::Repository,
        req: protocol::Request,
    ) -> Result<protocol::Action, PluginError> {
        self.call_async("handle", move |store, plugin| {
            plugin
                .forge_format_protocol()
                .call_handle(store, &repo, &req)
        })
        .await
    }

    /// Render a response from the data the plugin asked for.
    pub async fn render(
        self: &Arc<Self>,
        repo: protocol::Repository,
        req: protocol::Request,
        data: Vec<protocol::Loaded>,
    ) -> Result<protocol::Rendered, PluginError> {
        self.call_async("render", move |store, plugin| {
            plugin
                .forge_format_protocol()
                .call_render(store, &repo, &req, &data)
        })
        .await
    }
}

/// A readable reason for a failed call.
fn describe(e: &wasmtime::Error) -> String {
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => "ran out of fuel".into(),
        Some(Trap::Interrupt) => "exceeded its time limit".into(),
        Some(trap) => format!("trapped: {trap}"),
        None => format!("{e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use manifest::RequestedLimits;

    #[test]
    fn limits_default_and_are_capped() {
        let host = HostLimits::default();
        let l = host.resolve(&RequestedLimits::default()).unwrap();
        assert_eq!(l.memory_bytes, 64 * 1024 * 1024);
        assert_eq!(l.fuel, host.default_fuel);
        assert_eq!(l.timeout, host.default_timeout);

        let asks = |memory_mib, fuel, timeout_ms| RequestedLimits {
            memory_mib,
            fuel,
            timeout_ms,
        };
        assert!(host.resolve(&asks(Some(513), None, None)).is_err());
        assert!(host.resolve(&asks(Some(0), None, None)).is_err());
        assert!(host.resolve(&asks(None, Some(0), None)).is_err());
        assert!(host.resolve(&asks(None, Some(u64::MAX), None)).is_err());
        assert!(host.resolve(&asks(None, None, Some(30_001))).is_err());
        assert!(host.resolve(&asks(None, None, Some(0))).is_err());
        let l = host
            .resolve(&asks(Some(128), Some(1_000), Some(250)))
            .unwrap();
        assert_eq!(l.memory_bytes, 128 * 1024 * 1024);
        assert_eq!(l.fuel, 1_000);
        assert_eq!(l.timeout, Duration::from_millis(250));
    }

    #[test]
    fn a_component_with_another_digest_is_refused() {
        let manifest = Manifest::parse(
            r#"
            [plugin]
            id = "demo"
            name = "Demo"
            version = "0.1.0"
            api = "0.1.0"
            component = "demo.wasm"
            "#,
        )
        .unwrap();
        let err = Plugin::from_parts(
            manifest,
            b"not a component",
            &"0".repeat(64),
            &HostLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, PluginError::Digest { .. }), "{err}");
    }
}
