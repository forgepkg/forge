//! The [`forge_core::format::Format`] implementation for NuGet.

use std::cmp::Ordering;

use forge_core::domain::{FormatError, ParsedUpload};
use forge_core::format::{Format, ReadSeek};

use crate::model::NupkgLimits;
use crate::nuspec;
use crate::version;

/// NuGet package format adapter.
///
/// Holds the zip-bomb [`NupkgLimits`] applied while parsing uploads; use
/// [`NugetFormat::with_limits`] to override the defaults.
#[derive(Debug, Clone)]
pub struct NugetFormat {
    limits: NupkgLimits,
}

impl NugetFormat {
    /// A NuGet format with default safety limits.
    pub fn new() -> Self {
        NugetFormat {
            limits: NupkgLimits::default(),
        }
    }

    /// A NuGet format with explicit archive limits.
    pub fn with_limits(limits: NupkgLimits) -> Self {
        NugetFormat { limits }
    }
}

impl Default for NugetFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl Format for NugetFormat {
    fn id(&self) -> &'static str {
        "nuget"
    }

    fn parse_upload(&self, file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        nuspec::parse_nupkg(file, &self.limits)
    }

    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        version::normalize(raw)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        version::compare(a, b)
    }

    fn lower_id(&self, id: &str) -> String {
        nuspec::lower_id(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn is_object_safe_and_delegates() {
        let f: Arc<dyn Format> = Arc::new(NugetFormat::new());
        assert_eq!(f.id(), "nuget");
        assert_eq!(f.lower_id("Newtonsoft.JSON"), "newtonsoft.json");
        assert_eq!(f.normalize_version("1.0").unwrap(), "1.0.0");
        assert_eq!(f.compare_versions("1.0.0", "2.0.0"), Ordering::Less);
        assert_eq!(f.compare_versions("1.0.0-beta", "1.0.0"), Ordering::Less);
    }
}
