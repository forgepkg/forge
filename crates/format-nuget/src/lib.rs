//! NuGet package format adapter: version normalization, `.nuspec`/`.nupkg`
//! parsing, and the [`forge_core::format::Format`] implementation.

pub mod model;
pub mod nuspec;
pub mod routes;
pub mod version;

mod format;
pub use format::NugetFormat;
pub use routes::{nuget_router, NupkgBytes, RouteContext};
