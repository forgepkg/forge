//! WebAssembly format plugins: a [component] implementing the `forge:format`
//! world (`crates/plugin-api/wit/format.wit`), run by Wasmtime.
//!
//! [`WasmPlugin`] implements [`FormatPlugin`] by calling into the component,
//! so a loaded component serves exactly like a built-in plugin.
//!
//! ## Sandbox
//! Every call runs in an instance with a memory ceiling, a fuel budget and a
//! wall-clock deadline (epoch interruption), on a dedicated thread (see
//! `executor`). The memory ceiling covers the instance's linear memories and
//! tables together, and what one call may hand back to the host (see
//! [`store`]). A trap — out of fuel, past the deadline, out of memory, a
//! guest panic — fails that call and discards the instance. The WASI context
//! is empty: no files, no sockets, no environment, no arguments; stdout and
//! stderr go nowhere. A component reaches the network only through the GETs
//! the host sends for a proxy's upstream conversation, and the host sends
//! them only to the origins that upstream points at
//! (`forge_core::net::origins`).
//!
//! A failed call cannot fail the infallible trait methods: they log it and
//! answer as for an unknown input — [`FormatPlugin::canonical_id`] the id
//! unchanged, [`FormatPlugin::compare_versions`] byte order,
//! [`FormatPlugin::manifest_summary`] none — and the protocol methods answer
//! with a 500 response. The fallible ones return
//! [`FormatError::Internal`].
//!
//! [component]: https://component-model.bytecodealliance.org/

mod bindings;
mod executor;
mod host;

use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use forge_plugin_api::{
    Action, FetchResult, FormatError, FormatPlugin, Loaded, PackageSource, ParsedPackage, Remote,
    Rendered, Repository, Request, Response, UpstreamOp, UpstreamStep,
};
use sha2::{Digest, Sha256};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, Trap};

use crate::{manifest, Manifest, PluginError};
use bindings::{FormatPlugin as Bindings, FormatPluginPre};
use executor::Pool;
use host::{HostState, StagedPackage};

forge_plugin_api::__wit_conversions!(crate::wasm::bindings);

/// The most a plugin may ask for, and what it gets when it asks for nothing.
#[derive(Debug, Clone)]
pub struct HostLimits {
    /// Memory ceiling per instance when the plugin names none (MiB).
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
    /// Memory ceiling per instance, in bytes: its linear memories and tables
    /// together, and the most one call hands back to the host.
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

/// A store for one instance of a plugin running under `limits`.
///
/// `memory_bytes` bounds what the instance takes from the host:
///
/// * its linear memories and tables, all together ([`host::Budget`]);
/// * what one call hands back: Wasmtime copies every string and list of a
///   result into the host, once per reference, so a result whose list
///   elements all point at the same large string would otherwise cost the
///   host its length times their number. Wasmtime charges each copy against
///   the store's hostcall fuel and fails the call once it is spent;
/// * the random bytes it may ask WASI for at once.
fn store(engine: &Engine, limits: &Limits) -> Store<HostState> {
    let mut store = Store::new(engine, HostState::new(limits.memory_bytes));
    store.limiter(|state| &mut state.budget);
    store.set_hostcall_fuel(limits.memory_bytes);
    store
}

/// Comparisons remembered per plugin: sorting a package's versions asks the
/// plugin once per pair, and the same packages are listed over and over.
const MAX_REMEMBERED_COMPARISONS: usize = 65_536;

/// A format plugin running as a WebAssembly component.
pub struct WasmPlugin {
    inner: Arc<Inner>,
    comparisons: Mutex<HashMap<(String, String), Ordering>>,
}

/// What the plugin threads share of a [`WasmPlugin`].
struct Inner {
    /// The format id, for logs.
    id: String,
    sha256: String,
    limits: Limits,
    pre: FormatPluginPre<HostState>,
    idle: Mutex<Vec<Warm>>,
}

/// An instantiated plugin, reused across calls.
struct Warm {
    store: Store<HostState>,
    plugin: Bindings,
    calls: u32,
}

impl std::fmt::Debug for WasmPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmPlugin")
            .field("id", &self.inner.id)
            .field("sha256", &self.inner.sha256)
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}

impl WasmPlugin {
    /// Check `component` against `expected_sha256` (hex, optionally
    /// `sha256:`-prefixed), resolve the limits `manifest` asks for against
    /// `host`, compile it, and instantiate it once.
    pub fn new(
        manifest: &Manifest,
        component: &[u8],
        expected_sha256: &str,
        host: &HostLimits,
    ) -> Result<Self, PluginError> {
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
        Bindings::add_to_linker::<_, wasmtime::component::HasSelf<HostState>>(
            &mut linker,
            |state| state,
        )
        .map_err(|e| PluginError::Component(format!("link host functions: {e:#}")))?;
        let pre = linker
            .instantiate_pre(&component)
            .map_err(|e| PluginError::Component(format!("{e:#}")))?;
        let pre =
            FormatPluginPre::new(pre).map_err(|e| PluginError::Component(format!("{e:#}")))?;

        let inner = Arc::new(Inner {
            id: manifest.id.clone(),
            sha256: actual,
            limits,
            pre,
            idle: Mutex::new(Vec::new()),
        });
        // Instantiate once now, so a component that cannot start fails the
        // load instead of the first request (on a plugin thread, like every
        // run of guest code).
        let starting = Arc::clone(&inner);
        let warm = executor::run_blocking(Pool::Slow, move || starting.instantiate())??;
        inner.park(warm);
        Ok(WasmPlugin {
            inner,
            comparisons: Mutex::new(HashMap::new()),
        })
    }

    /// The component's SHA-256 (lowercase hex).
    pub fn sha256(&self) -> &str {
        &self.inner.sha256
    }

    /// The limits every call runs under.
    pub fn limits(&self) -> Limits {
        self.inner.limits
    }

    /// Run `f` against an instance on a thread of `pool`, blocking the
    /// caller.
    fn call<R, F>(&self, pool: Pool, what: &'static str, f: F) -> Result<R, PluginError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Store<HostState>, &Bindings) -> wasmtime::Result<R> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        executor::run_blocking(pool, move || inner.call(what, f))?
    }
}

impl Inner {
    fn instantiate(&self) -> Result<Warm, PluginError> {
        let mut store = store(self.pre.engine(), &self.limits);
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
        f: impl FnOnce(&mut Store<HostState>, &Bindings) -> wasmtime::Result<R>,
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
                tracing::warn!(plugin = %self.id, call = what, %reason, "format plugin call failed");
                Err(PluginError::Trap(format!("{what}: {reason}")))
            }
        }
    }
}

fn internal(e: PluginError) -> FormatError {
    FormatError::Internal(e.to_string())
}

/// What a protocol call that failed answers.
fn failed() -> Response {
    Response::new(500, "text/plain; charset=utf-8", "format plugin failed")
}

impl FormatPlugin for WasmPlugin {
    fn canonical_id(&self, id: &str) -> String {
        let raw = id.to_string();
        self.call(Pool::Quick, "canonical-id", move |store, plugin| {
            plugin.forge_format_format().call_canonical_id(store, &raw)
        })
        .unwrap_or_else(|_| id.to_string())
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        let id = id.to_string();
        self.call(Pool::Quick, "validate-id", move |store, plugin| {
            plugin.forge_format_format().call_validate_id(store, &id)
        })
        .map_err(internal)?
        .map_err(Into::into)
    }

    fn normalize_version(&self, version: &str) -> Result<String, FormatError> {
        let version = version.to_string();
        self.call(Pool::Quick, "normalize-version", move |store, plugin| {
            plugin
                .forge_format_format()
                .call_normalize_version(store, &version)
        })
        .map_err(internal)?
        .map_err(Into::into)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        let key = (a.to_string(), b.to_string());
        if let Some(order) = self
            .comparisons
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
        {
            return *order;
        }
        let (x, y) = key.clone();
        let order = match self.call(Pool::Quick, "compare-versions", move |store, plugin| {
            plugin
                .forge_format_format()
                .call_compare_versions(store, &x, &y)
        }) {
            Ok(n) => n.cmp(&0),
            Err(_) => return a.cmp(b),
        };
        let mut remembered = self.comparisons.lock().unwrap_or_else(|p| p.into_inner());
        if remembered.len() >= MAX_REMEMBERED_COMPARISONS {
            remembered.clear();
        }
        remembered.insert(key, order);
        order
    }

    fn parse_package(&self, package: &mut dyn PackageSource) -> Result<ParsedPackage, FormatError> {
        // The component reads a file it is lent; spool a reader into one.
        let spool = |e: std::io::Error| FormatError::Internal(format!("spool the package: {e}"));
        let mut spooled = tempfile::NamedTempFile::new().map_err(spool)?;
        package.seek(SeekFrom::Start(0)).map_err(spool)?;
        std::io::copy(package, &mut spooled).map_err(spool)?;
        self.parse_package_file(spooled.path())
    }

    fn parse_package_file(&self, path: &Path) -> Result<ParsedPackage, FormatError> {
        let file = std::fs::File::open(path)
            .map_err(|e| FormatError::Internal(format!("open the staged package: {e}")))?;
        let package = StagedPackage::new(file)
            .map_err(|e| FormatError::Internal(format!("open the staged package: {e}")))?;
        self.call(Pool::Slow, "parse-package", move |store, plugin| {
            let lent = store.data_mut().lend(package)?;
            let borrowed = wasmtime::component::Resource::new_borrow(lent.rep());
            let result = plugin
                .forge_format_format()
                .call_parse_package(&mut *store, borrowed);
            store.data_mut().reclaim(lent);
            result
        })
        .map_err(internal)?
        .map(Into::into)
        .map_err(Into::into)
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<String> {
        let manifest = manifest.to_vec();
        self.call(Pool::Quick, "manifest-summary", move |store, plugin| {
            plugin
                .forge_format_format()
                .call_manifest_summary(store, &manifest)
        })
        .ok()?
    }

    fn handle(&self, repo: &Repository, req: &Request) -> Action {
        let repo = repo.clone().into();
        let req = req.clone().into();
        match self.call(Pool::Slow, "handle", move |store, plugin| {
            plugin
                .forge_format_protocol()
                .call_handle(store, &repo, &req)
        }) {
            Ok(action) => action.into(),
            Err(_) => Action::Respond(failed()),
        }
    }

    fn render(&self, repo: &Repository, req: &Request, data: &[Loaded]) -> Rendered {
        let repo = repo.clone().into();
        let req = req.clone().into();
        let data: Vec<bindings::exports::forge::format::protocol::Loaded> =
            data.iter().cloned().map(Into::into).collect();
        match self.call(Pool::Slow, "render", move |store, plugin| {
            plugin
                .forge_format_protocol()
                .call_render(store, &repo, &req, &data)
        }) {
            Ok(rendered) => rendered.into(),
            Err(_) => Rendered::Respond(failed()),
        }
    }

    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        let remote = remote.clone().into();
        let op = op.clone().into();
        let fetched: Vec<bindings::exports::forge::format::upstream::FetchResult> =
            fetched.iter().cloned().map(Into::into).collect();
        self.call(Pool::Slow, "upstream", move |store, plugin| {
            plugin
                .forge_format_upstream()
                .call_upstream(store, &remote, &op, &fetched)
        })
        .map_err(internal)?
        .map(Into::into)
        .map_err(Into::into)
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
            api = "0.3.0"
            component = "demo.wasm"
            "#,
        )
        .unwrap();
        let err = WasmPlugin::new(
            &manifest,
            b"not a component",
            &"0".repeat(64),
            &HostLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, PluginError::Digest { .. }), "{err}");
    }

    /// Hand-built components that test the store's limits ([`store`]), each
    /// against a memory ceiling of 1 MiB.
    mod sandbox {
        use super::*;
        use wasm_encoder::{
            CanonicalOption, CodeSection, ComponentBuilder, ComponentExportKind, ComponentValType,
            ConstExpr, DataSection, ExportKind, ExportSection, Function, FunctionSection, HeapType,
            MemArg, MemorySection, MemoryType, Module, ModuleArg, PrimitiveValType, RefType,
            TableSection, TableType, TypeSection, ValType,
        };
        use wasmtime::component::Instance;

        /// The limits every test component runs under.
        const CEILING: Limits = Limits {
            memory_bytes: 1024 * 1024,
            fuel: 1_000_000_000,
            timeout: Duration::from_secs(10),
        };

        /// A store for [`CEILING`], armed for calls.
        fn armed_store() -> Store<HostState> {
            let mut store = store(engine().unwrap(), &CEILING);
            store.set_fuel(CEILING.fuel).unwrap();
            store.set_epoch_deadline(1_000);
            store
        }

        /// Instantiate `component` (its bytes) in `store`.
        fn instantiate(
            store: &mut Store<HostState>,
            component: &[u8],
        ) -> wasmtime::Result<Instance> {
            let engine = engine().unwrap();
            let component = Component::new(engine, component).unwrap();
            Linker::new(engine).instantiate(store, &component)
        }

        /// A memory section of one memory of `pages` 64 KiB pages.
        fn memories(pages: u64) -> MemorySection {
            let mut memories = MemorySection::new();
            memories.memory(MemoryType {
                minimum: pages,
                maximum: None,
                memory64: false,
                shared: false,
                page_size_log2: None,
            });
            memories
        }

        /// A core module with one memory of `pages` 64 KiB pages.
        fn memory_module(pages: u64) -> Module {
            let mut module = Module::new();
            module.section(&memories(pages));
            module
        }

        /// A component instantiating each of `modules` once, exporting
        /// nothing.
        fn component_of(modules: &[Module]) -> Vec<u8> {
            let mut component = ComponentBuilder::default();
            for module in modules {
                let index = component.core_module(None, module);
                component.core_instantiate(None, index, [] as [(&str, ModuleArg); 0]);
            }
            component.finish()
        }

        #[test]
        fn memories_share_the_ceiling() {
            // 768 KiB fits, twice does not: each memory alone is below the
            // ceiling.
            let one = component_of(&[memory_module(12)]);
            assert!(instantiate(&mut armed_store(), &one).is_ok());
            let two = component_of(&[memory_module(12), memory_module(12)]);
            let err = instantiate(&mut armed_store(), &two).unwrap_err();
            assert!(format!("{err:#}").contains("memory limit"), "{err:#}");
        }

        #[test]
        fn tables_count_against_the_ceiling() {
            // `grow: func(n: u32) -> s32`: `table.grow` by `n` null elements.
            let mut types = TypeSection::new();
            types.ty().function([ValType::I32], [ValType::I32]);
            let mut functions = FunctionSection::new();
            functions.function(0);
            let mut tables = TableSection::new();
            tables.table(TableType {
                element_type: RefType::FUNCREF,
                table64: false,
                minimum: 0,
                maximum: None,
                shared: false,
            });
            let mut exports = ExportSection::new();
            exports.export("grow", ExportKind::Func, 0);
            let mut grow = Function::new([]);
            grow.instructions()
                .ref_null(HeapType::FUNC)
                .local_get(0)
                .table_grow(0)
                .end();
            let mut code = CodeSection::new();
            code.function(&grow);
            let mut module = Module::new();
            module
                .section(&types)
                .section(&functions)
                .section(&tables)
                .section(&exports)
                .section(&code);

            let mut component = ComponentBuilder::default();
            let index = component.core_module(None, &module);
            let instance = component.core_instantiate(None, index, [] as [(&str, ModuleArg); 0]);
            let core = component.core_alias_export(None, instance, "grow", ExportKind::Func);
            let (ty, mut encoder) = component.type_function(None);
            encoder
                .async_(false)
                .params([("n", PrimitiveValType::U32)])
                .result(Some(PrimitiveValType::S32.into()));
            let lifted = component.lift_func(None, core, ty, []);
            component.export("grow", ComponentExportKind::Func, lifted, None);
            let component = component.finish();

            let mut store = armed_store();
            let instance = instantiate(&mut store, &component).unwrap();
            let grow = instance
                .get_typed_func::<(u32,), (i32,)>(&mut store, "grow")
                .unwrap();
            // 1,000 elements fit; 10 million would take 80 MB of the host's.
            assert_eq!(grow.call(&mut store, (1_000,)).unwrap(), (0,));
            let err = grow.call(&mut store, (10_000_000,)).unwrap_err();
            assert!(format!("{err:#}").contains("memory limit"), "{err:#}");
        }

        #[test]
        fn results_are_bounded_by_the_ceiling() {
            // `strings: func(n: u32) -> list<string>`: the first `n` of 1,000
            // list elements that all point at the same 16 KiB string.
            const ELEMENTS: u32 = 1_000;
            const STRING: u32 = 16 * 1024;
            let list = 8;
            let string = list + 8 * ELEMENTS;
            let mut data = Vec::new();
            data.extend_from_slice(&list.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            for _ in 0..ELEMENTS {
                data.extend_from_slice(&string.to_le_bytes());
                data.extend_from_slice(&STRING.to_le_bytes());
            }
            data.resize(data.len() + STRING as usize, b'x');

            let mut types = TypeSection::new();
            types.ty().function([ValType::I32], [ValType::I32]);
            let mut functions = FunctionSection::new();
            functions.function(0);
            let mut exports = ExportSection::new();
            exports.export("strings", ExportKind::Func, 0);
            exports.export("memory", ExportKind::Memory, 0);
            // Store `n` as the list's length, return the return area.
            let mut strings = Function::new([]);
            strings
                .instructions()
                .i32_const(4)
                .local_get(0)
                .i32_store(MemArg {
                    offset: 0,
                    align: 2,
                    memory_index: 0,
                })
                .i32_const(0)
                .end();
            let mut code = CodeSection::new();
            code.function(&strings);
            let mut segments = DataSection::new();
            segments.active(0, &ConstExpr::i32_const(0), data);
            let mut module = Module::new();
            module
                .section(&types)
                .section(&functions)
                .section(&memories(1))
                .section(&exports)
                .section(&code)
                .section(&segments);

            let mut component = ComponentBuilder::default();
            let index = component.core_module(None, &module);
            let instance = component.core_instantiate(None, index, [] as [(&str, ModuleArg); 0]);
            let core = component.core_alias_export(None, instance, "strings", ExportKind::Func);
            let memory = component.core_alias_export(None, instance, "memory", ExportKind::Memory);
            let (list_of_strings, encoder) = component.type_defined(None);
            encoder.list(PrimitiveValType::String);
            let (ty, mut encoder) = component.type_function(None);
            encoder
                .async_(false)
                .params([("n", PrimitiveValType::U32)])
                .result(Some(ComponentValType::Type(list_of_strings)));
            let lifted = component.lift_func(
                None,
                core,
                ty,
                [CanonicalOption::Memory(memory), CanonicalOption::UTF8],
            );
            component.export("strings", ComponentExportKind::Func, lifted, None);
            let component = component.finish();

            let mut store = armed_store();
            let instance = instantiate(&mut store, &component).unwrap();
            let strings = instance
                .get_typed_func::<(u32,), (Vec<String>,)>(&mut store, "strings")
                .unwrap();
            // 10 copies (160 KiB) fit the ceiling.
            let (ten,) = strings.call(&mut store, (10,)).unwrap();
            assert_eq!(ten.len(), 10);
            assert!(ten.iter().all(|s| s.len() == STRING as usize));
            // 1,000 copies (16 MiB) do not, though the guest holds 16 KiB.
            let err = strings.call(&mut store, (ELEMENTS,)).unwrap_err();
            assert!(format!("{err:#}").contains("too much data"), "{err:#}");
        }
    }
}
