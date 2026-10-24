//! NuGet V3 feeds for Forge, as a format plugin.
//!
//! Served under `/v3/{repository}` (its `plugin.toml` names the mount):
//!
//! * `GET /index.json` — the service index;
//! * `GET /flat/{id}/index.json`, `/flat/{id}/{version}/{file}` — the flat
//!   container: versions, `.nupkg` and `.nuspec`;
//! * `GET /registration/{id}/index.json`, `…/page/{lower}/{upper}.json`,
//!   `…/{version}.json` and `/catalog/{id}/{version}.json` — registration;
//! * `GET /query` — search;
//! * `PUT /package` — push; `DELETE /package/{id}/{version}` — unlist;
//!   `POST /package/{id}/{version}` — relist (hosted repositories).
//!
//! Proxy repositories mirror another V3 feed ([`upstream`]): its service
//! index, flat container, registration and search, read through the host.
//!
//! Ids are matched case-insensitively (`ToLowerInvariant`); versions are
//! NuGet versions, normalized (`1.0` → `1.0.0`).
//!
//! Forge links this plugin in ([`Nuget`], [`PLUGIN_TOML`]).

pub mod model;
pub mod nuspec;
mod protocol;
pub mod upstream;
pub mod version;

use std::cmp::Ordering;

use forge_plugin_api::{
    Action, FetchResult, FormatError, FormatPlugin, Loaded, PackageSource, ParsedPackage, Remote,
    Repository, Request, UpstreamOp, UpstreamStep,
};

pub use model::NupkgLimits;

/// This plugin's `plugin.toml`: its format id, name, version and mount.
pub const PLUGIN_TOML: &str = forge_plugin_api::plugin_toml!();

/// The NuGet format, with the zip-bomb limits applied while parsing packages.
#[derive(Debug, Clone, Default)]
pub struct Nuget {
    limits: NupkgLimits,
}

impl Nuget {
    /// NuGet with explicit archive limits (the server's `[nuget]` section).
    pub fn with_limits(limits: NupkgLimits) -> Self {
        Nuget { limits }
    }
}

impl FormatPlugin for Nuget {
    fn canonical_id(&self, id: &str) -> String {
        nuspec::lower_id(id)
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        nuspec::validate_package_id(id).map_err(Into::into)
    }

    fn normalize_version(&self, version: &str) -> Result<String, FormatError> {
        version::normalize(version).map_err(Into::into)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        version::compare(a, b)
    }

    fn parse_package(&self, package: &mut dyn PackageSource) -> Result<ParsedPackage, FormatError> {
        nuspec::parse_nupkg(package, &self.limits)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<String> {
        let summary = nuspec::manifest_summary(manifest).ok()?;
        serde_json::to_string(&summary).ok()
    }

    fn handle(&self, repo: &Repository, req: &Request) -> Action {
        protocol::handle(repo, req)
    }

    fn render(&self, repo: &Repository, req: &Request, data: &[Loaded]) -> Action {
        protocol::render(repo, req, data)
    }

    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        upstream::step(remote, op, fetched, &self.limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_toml_names_this_crate() {
        let value = |key: &str| {
            PLUGIN_TOML
                .lines()
                .filter_map(|line| line.split_once('='))
                .find(|(k, _)| k.trim() == key)
                .map(|(_, v)| v.trim().trim_matches('"').to_string())
        };
        assert_eq!(value("id").as_deref(), Some("nuget"));
        assert_eq!(value("version").as_deref(), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(value("api").as_deref(), Some(forge_plugin_api::API));
        assert_eq!(value("mount").as_deref(), Some("/v3"));
    }

    #[test]
    fn the_rules_are_nugets() {
        let nuget = Nuget::default();
        assert_eq!(nuget.canonical_id("Newtonsoft.JSON"), "newtonsoft.json");
        assert_eq!(nuget.canonical_id("Ünicode.Lib"), "ünicode.lib");
        assert_eq!(nuget.normalize_version("1.0").unwrap(), "1.0.0");
        assert_eq!(nuget.compare_versions("1.0.0", "2.0.0"), Ordering::Less);
        assert_eq!(
            nuget.compare_versions("1.0.0-beta", "1.0.0"),
            Ordering::Less
        );
        assert!(nuget.validate_id("a/b").is_err());
        assert!(matches!(
            nuget.normalize_version("one"),
            Err(FormatError::InvalidVersion(_))
        ));
    }
}
