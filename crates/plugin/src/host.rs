//! The per-instance host state and the functions a plugin imports.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use wasmtime::component::{Resource, ResourceTable};
use wasmtime::StoreLimits;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use crate::bindings::forge::format::{package_source, types};

/// The most `read-at` returns in one call.
const MAX_READ: u32 = 1024 * 1024;

/// What a plugin instance's store holds: an empty WASI context (no files,
/// network, environment or arguments; stdout and stderr discard), the
/// resource table, and the memory limits.
pub(crate) struct HostState {
    wasi: WasiCtx,
    table: ResourceTable,
    pub(crate) limits: StoreLimits,
}

impl HostState {
    pub(crate) fn new(limits: StoreLimits) -> Self {
        let wasi = WasiCtx::builder()
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .build();
        HostState {
            wasi,
            table: ResourceTable::new(),
            limits,
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
