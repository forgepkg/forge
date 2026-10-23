//! The per-instance host state and the functions a plugin imports.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use wasmtime::component::{Resource, ResourceTable};
use wasmtime::ResourceLimiter;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use super::bindings::forge::format::{package_source, types};

/// The most `read-at` returns in one call.
const MAX_READ: u32 = 1024 * 1024;

/// What a plugin instance's store holds: an empty WASI context (no files,
/// network, environment or arguments; stdout and stderr discard), the
/// resource table, and the memory budget.
pub(crate) struct HostState {
    wasi: WasiCtx,
    table: ResourceTable,
    pub(crate) budget: Budget,
}

impl HostState {
    /// The state of an instance whose memories and tables may hold
    /// `memory_bytes` together. WASI's random bytes are capped the same way:
    /// they are the one thing a guest can ask the host to allocate for it.
    pub(crate) fn new(memory_bytes: usize) -> Self {
        let wasi = WasiCtx::builder()
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .max_random_size(u64::try_from(memory_bytes).unwrap_or(u64::MAX))
            .build();
        HostState {
            wasi,
            table: ResourceTable::new(),
            budget: Budget::new(memory_bytes),
        }
    }

    /// Lend `package` to the guest for one call.
    pub(crate) fn lend(
        &mut self,
        package: StagedPackage,
    ) -> wasmtime::Result<Resource<StagedPackage>> {
        Ok(self.table.push(package)?)
    }

    /// Take a lent package back after the call.
    pub(crate) fn reclaim(&mut self, package: Resource<StagedPackage>) {
        let _ = self.table.delete(package);
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Core instances a store may create: a Rust component instantiates a few
/// (its module, WASI adapters and shims).
const MAX_INSTANCES: usize = 64;

/// Tables a store may create.
const MAX_TABLES: usize = 64;

/// Linear memories a store may create. They share one [`Budget`], so this
/// bounds bookkeeping, not bytes.
const MAX_MEMORIES: usize = 16;

/// What one table element holds on the host: a pointer, in Wasmtime.
const TABLE_ELEMENT_BYTES: usize = std::mem::size_of::<usize>();

/// One memory ceiling for everything an instance allocates on its behalf:
/// all its linear memories and all its tables together, counted in bytes.
///
/// Wasmtime's own limits apply per memory and leave tables unbounded, so an
/// instance with several memories, or a `table.grow` to hundreds of millions
/// of elements, would take far more host memory than its ceiling. A growth
/// past the budget traps the guest, which fails the call and discards the
/// instance.
pub(crate) struct Budget {
    /// What the memories and tables may hold together, in bytes.
    limit: usize,
    /// What they hold now.
    used: usize,
    /// What the last growth allowed added, given back when that growth then
    /// fails (past a memory's declared maximum, say).
    pending: usize,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Budget {
            limit,
            used: 0,
            pending: 0,
        }
    }

    /// Take `bytes` more out of the budget, or refuse with a trap.
    fn grow(&mut self, bytes: usize, what: &str) -> wasmtime::Result<bool> {
        match self.used.checked_add(bytes) {
            Some(used) if used <= self.limit => {
                self.used = used;
                self.pending = bytes;
                Ok(true)
            }
            _ => Err(wasmtime::format_err!(
                "growing a {what} by {bytes} bytes exceeds the plugin's memory limit of {} \
                 bytes ({} in use)",
                self.limit,
                self.used
            )),
        }
    }

    /// Give back what the growth that just failed took.
    fn grow_failed(&mut self) {
        self.used -= std::mem::take(&mut self.pending);
    }
}

// Wasmtime asks before it creates a memory or table (`current` 0) as well as
// before every growth, so the budget sees every byte.
impl ResourceLimiter for Budget {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.grow(desired.saturating_sub(current), "linear memory")
    }

    fn memory_grow_failed(&mut self, _error: wasmtime::Error) -> wasmtime::Result<()> {
        self.grow_failed();
        Ok(())
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let elements = desired.saturating_sub(current);
        self.grow(elements.saturating_mul(TABLE_ELEMENT_BYTES), "table")
    }

    fn table_grow_failed(&mut self, _error: wasmtime::Error) -> wasmtime::Result<()> {
        self.grow_failed();
        Ok(())
    }

    fn instances(&self) -> usize {
        MAX_INSTANCES
    }

    fn tables(&self) -> usize {
        MAX_TABLES
    }

    fn memories(&self) -> usize {
        MAX_MEMORIES
    }
}

/// A package the host staged on disk, lent to `parse-package`.
pub struct StagedPackage {
    file: File,
    size: u64,
}

impl StagedPackage {
    /// Wrap an open package file.
    pub(crate) fn new(file: File) -> std::io::Result<Self> {
        let size = file.metadata()?.len();
        Ok(StagedPackage { file, size })
    }

    fn read_at(&mut self, offset: u64, len: u32) -> std::io::Result<Vec<u8>> {
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let len = u64::from(len.min(MAX_READ)).min(self.size - offset);
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = Vec::with_capacity(len as usize);
        (&mut self.file).take(len).read_to_end(&mut buf)?;
        Ok(buf)
    }
}

// Both interfaces are imported for their types; only the reader has functions.
impl types::Host for HostState {}

impl package_source::Host for HostState {}

impl package_source::HostPackageReader for HostState {
    fn size(&mut self, package: Resource<StagedPackage>) -> wasmtime::Result<u64> {
        Ok(self.table.get(&package)?.size)
    }

    fn read_at(
        &mut self,
        package: Resource<StagedPackage>,
        offset: u64,
        len: u32,
    ) -> wasmtime::Result<Result<Vec<u8>, String>> {
        let package = self.table.get_mut(&package)?;
        Ok(package.read_at(offset, len).map_err(|e| e.to_string()))
    }

    fn drop(&mut self, package: Resource<StagedPackage>) -> wasmtime::Result<()> {
        self.table.delete(package)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_are_bounded_by_the_file_and_the_chunk_limit() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"0123456789").unwrap();
        let mut staged = StagedPackage::new(file).unwrap();
        assert_eq!(staged.size, 10);
        assert_eq!(staged.read_at(0, 4).unwrap(), b"0123");
        assert_eq!(staged.read_at(8, 100).unwrap(), b"89");
        assert!(staged.read_at(10, 1).unwrap().is_empty());
        assert!(staged.read_at(u64::MAX, u32::MAX).unwrap().is_empty());
    }
}
