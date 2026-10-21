//! Building a plugin crate as a WebAssembly component (feature `component`).
//!
//! ```ignore
//! #[cfg(feature = "component")]
//! forge_plugin_api::export_component!(Helm);
//! ```
//!
//! and build the crate as a `cdylib` for `wasm32-wasip2` with the feature on
//! (`cargo xtask plugins` does): the component exports the `format-plugin`
//! world of `wit/format.wit`, each function calling the plugin's
//! [`FormatPlugin`] method of the same name.

use std::io::{self, Read, Seek, SeekFrom};

use crate::FormatPlugin;

/// The guest bindings of `wit/format.wit`.
#[doc(hidden)]
pub mod bindings {
    wit_bindgen::generate!({
        world: "format-plugin",
        path: "wit",
        pub_export_macro: true,
        default_bindings_module: "forge_plugin_api::component::bindings",
    });
}

crate::__wit_conversions!(crate::component::bindings);

use bindings::exports::forge::format::{format, protocol};
use bindings::forge::format::package_source::PackageReader;
use bindings::forge::format::types;

/// The plugin a component exports (implemented by [`export_component!`]).
#[doc(hidden)]
pub trait Exported {
    fn plugin() -> &'static dyn FormatPlugin;
}

/// Export `$plugin` (an expression of a type implementing [`FormatPlugin`],
/// built once on the first call) as this component's `format-plugin` world.
#[macro_export]
macro_rules! export_component {
    ($plugin:expr) => {
        #[doc(hidden)]
        pub struct __ForgeFormatComponent;

        impl $crate::component::Exported for __ForgeFormatComponent {
            fn plugin() -> &'static dyn $crate::FormatPlugin {
                static PLUGIN: ::std::sync::OnceLock<::std::boxed::Box<dyn $crate::FormatPlugin>> =
                    ::std::sync::OnceLock::new();
                PLUGIN
                    .get_or_init(|| ::std::boxed::Box::new($plugin))
                    .as_ref()
            }
        }

        $crate::component::bindings::export!(
            __ForgeFormatComponent with_types_in $crate::component::bindings
        );
    };
}

/// The package reader the host lends, as [`Read`] and [`Seek`].
struct Lent<'a> {
    reader: &'a PackageReader,
    size: u64,
    offset: u64,
}

impl Read for Lent<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let chunk = self
            .reader
            .read_at(self.offset, len)
            .map_err(io::Error::other)?;
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        self.offset += n as u64;
        Ok(n)
    }
}

impl Seek for Lent<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.offset.checked_add_signed(d),
        };
        self.offset = target
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.offset)
    }
}

impl<T: Exported> format::Guest for T {
    fn canonical_id(id: String) -> String {
        T::plugin().canonical_id(&id)
    }

    fn validate_id(id: String) -> Result<(), types::FormatError> {
        T::plugin().validate_id(&id).map_err(Into::into)
    }

    fn normalize_version(version: String) -> Result<String, types::FormatError> {
        T::plugin().normalize_version(&version).map_err(Into::into)
    }

    fn compare_versions(a: String, b: String) -> i8 {
        T::plugin().compare_versions(&a, &b) as i8
    }

    fn parse_package(source: &PackageReader) -> Result<format::ParsedPackage, types::FormatError> {
        let mut lent = Lent {
            reader: source,
            size: source.size(),
            offset: 0,
        };
        T::plugin()
            .parse_package(&mut lent)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn manifest_summary(manifest: Vec<u8>) -> Option<String> {
        T::plugin().manifest_summary(&manifest)
    }
}

impl<T: Exported> protocol::Guest for T {
    fn handle(repo: protocol::Repository, req: protocol::Request) -> protocol::Action {
        T::plugin().handle(&repo.into(), &req.into()).into()
    }

    fn render(
        repo: protocol::Repository,
        req: protocol::Request,
        data: Vec<protocol::Loaded>,
    ) -> protocol::Rendered {
        let data: Vec<crate::Loaded> = data.into_iter().map(Into::into).collect();
        T::plugin().render(&repo.into(), &req.into(), &data).into()
    }
}
