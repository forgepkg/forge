//! A package's control file: what a publish reads from it, and the summary
//! stored with the version, which holds everything the indexes list of it
//! (so that making an index reads no package and no manifest) and what the
//! web UI shows.

use forge_plugin_api::{Dependency, DependencyGroup, FormatError};
use serde::{Deserialize, Serialize};

use crate::control::{self, Paragraph};
use crate::version;

/// What the indexes and the web UI read of a version (the stored manifest
/// summary, a JSON object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub package: String,
    pub architecture: String,
    pub component: String,
    /// The control data as the indexes list it, without the fields an index
    /// sets itself (`Filename`, `Size`, the digests).
    pub control: String,
    /// The synopsis and the extended description, as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintainer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_size: Option<String>,
    /// `Depends` and `Pre-Depends`, in the shape the web UI reads
    /// (`[{target, dependencies: [{id, range}]}]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_groups: Vec<serde_json::Value>,
}

impl Summary {
    /// Read a stored summary.
    pub fn parse(json: &str) -> Option<Summary> {
        serde_json::from_str(json).ok()
    }
}

/// What a package's control file says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub component: String,
    pub paragraph: Paragraph,
}

impl Control {
    /// Read and check a control file.
    pub fn parse(bytes: &[u8]) -> Result<Control, FormatError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| FormatError::MalformedManifest("the control file is not UTF-8".into()))?;
        let paragraph = Paragraph::parse_one(text)
            .map_err(|e| FormatError::MalformedManifest(format!("control file: {e}")))?;
        let field = |name: &str| {
            paragraph
                .first_line(name)
                .map(str::to_string)
                .ok_or_else(|| {
                    FormatError::MalformedManifest(format!("the control file has no {name} field"))
                })
        };
        let name = field("Package")?;
        if !control::valid_package_name(&name) {
            return Err(FormatError::InvalidId(format!(
                "{name:?} is not a package name (lowercase letters, digits, '+', '-' and '.')"
            )));
        }
        let version = field("Version")?;
        version::Version::parse(&version)
            .map_err(|e| FormatError::InvalidVersion(e.to_string()))?;
        let architecture = field("Architecture")?;
        if !control::valid_architecture(&architecture) {
            return Err(FormatError::MalformedManifest(format!(
                "{architecture:?} is not an architecture"
            )));
        }
        let component = control::component_of(paragraph.first_line("Section"))
            .map_err(|e| FormatError::MalformedManifest(e.to_string()))?;
        Ok(Control {
            name,
            version,
            architecture,
            component,
            paragraph,
        })
    }

    /// The dependencies the web UI shows: `Pre-Depends`, then `Depends`.
    pub fn dependencies(&self) -> Vec<DependencyGroup> {
        let mut dependencies = Vec::new();
        for field in ["Pre-Depends", "Depends"] {
            if let Some(value) = self.paragraph.get(field) {
                dependencies.extend(
                    control::relations(value)
                        .into_iter()
                        .map(|(id, range)| Dependency { id, range }),
                );
            }
        }
        if dependencies.is_empty() {
            Vec::new()
        } else {
            vec![DependencyGroup {
                target: None,
                dependencies,
            }]
        }
    }

    /// The description as text: the synopsis, then the extended
    /// description without its indentation (` .` lines are blank).
    pub fn description(&self) -> Option<String> {
        let value = self.paragraph.get("Description")?;
        let mut lines = value.split('\n');
        let mut out = lines.next().unwrap_or("").trim().to_string();
        let mut extended = Vec::new();
        for line in lines {
            let line = line.strip_prefix(' ').unwrap_or(line);
            extended.push(if line.trim() == "." {
                ""
            } else {
                line.trim_end()
            });
        }
        if !extended.is_empty() {
            out.push_str("\n\n");
            out.push_str(&extended.join("\n"));
        }
        Some(out).filter(|d| !d.trim().is_empty())
    }

    /// The summary stored with the version.
    pub fn summary(&self) -> Summary {
        let mut listed = self.paragraph.clone();
        for field in [
            "Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Status",
        ] {
            listed.remove(field);
        }
        let text = |name: &str| self.paragraph.first_line(name).map(str::to_string);
        Summary {
            package: self.name.clone(),
            architecture: self.architecture.clone(),
            component: self.component.clone(),
            control: listed.to_text(),
            description: self.description(),
            section: text("Section"),
            maintainer: text("Maintainer"),
            homepage: text("Homepage"),
            source: text("Source"),
            installed_size: text("Installed-Size"),
            dependency_groups: self
                .dependencies()
                .into_iter()
                .map(|group| {
                    serde_json::json!({
                        "target": group.target,
                        "dependencies": group.dependencies.iter().map(|d| serde_json::json!({
                            "id": d.id,
                            "range": d.range,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        }
    }
}

/// The JSON summary of a control file (the manifest stored at publish).
pub fn summarize(manifest: &[u8]) -> Option<String> {
    let control = Control::parse(manifest).ok()?;
    serde_json::to_string(&control.summary()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_file_is_read_and_summarized() {
        let control = Control::parse(
            b"Package: hello\nVersion: 2.10-3\nArchitecture: amd64\nSection: contrib/utils\n\
              Depends: libc6 (>= 2.34)\nPre-Depends: dpkg\nSHA256: forged\n\
              Description: greet\n Prints a greeting.\n .\n Really.\n",
        )
        .unwrap();
        assert_eq!(
            (
                control.name.as_str(),
                control.version.as_str(),
                control.architecture.as_str()
            ),
            ("hello", "2.10-3", "amd64")
        );
        assert_eq!(control.component, "contrib");
        let summary = control.summary();
        assert_eq!(
            summary.description.as_deref(),
            Some("greet\n\nPrints a greeting.\n\nReally.")
        );
        assert!(!summary.control.contains("SHA256"));
        assert_eq!(
            summary.dependency_groups[0]["dependencies"][0],
            serde_json::json!({"id": "dpkg", "range": null})
        );
        let json = serde_json::to_string(&summary).unwrap();
        assert_eq!(Summary::parse(&json).unwrap(), summary);
    }

    #[test]
    fn a_control_file_needs_its_identity() {
        for (bad, why) in [
            (&b"Version: 1\nArchitecture: amd64\n"[..], "no Package"),
            (b"Package: hello\nArchitecture: amd64\n", "no Version"),
            (b"Package: hello\nVersion: 1\n", "no Architecture"),
            (
                b"Package: Hello\nVersion: 1\nArchitecture: amd64\n",
                "not a package name",
            ),
            (
                b"Package: hello\nVersion: x\nArchitecture: amd64\n",
                "upstream",
            ),
            (
                b"Package: hello\nVersion: 1\nArchitecture: any\n",
                "not an architecture",
            ),
            (
                b"Package: hello\nVersion: 1\nArchitecture: amd64\nSection: ../x/y\n",
                "component",
            ),
            (b"\xff\xfe", "UTF-8"),
        ] {
            let err = Control::parse(bad).unwrap_err().to_string();
            assert!(err.contains(why), "{err} should say {why}");
        }
    }
}
