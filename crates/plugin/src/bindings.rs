//! Host bindings generated from `wit/format.wit`.

wasmtime::component::bindgen!({
    world: "format-plugin",
    path: "wit",
    // The package reader the host lends to `parse-package` is a staged file.
    with: {
        "forge:format/package-source.package-reader": crate::host::StagedPackage,
    },
    // A host function may trap the guest (an unknown resource handle).
    imports: { default: trappable },
});
