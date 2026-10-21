//! Reading a chart archive: `<chart>/Chart.yaml` inside a gzipped tarball.

use std::io::Read;

use serde_json::{Map, Value};
use yaml_rust2::Yaml;

use crate::semver::Version;
use crate::tar;

/// The largest Chart.yaml read.
const MAX_CHART_YAML: u64 = 1024 * 1024;

/// How much of a chart is decompressed looking for Chart.yaml (a gzip bomb
/// stops here).
const MAX_UNPACKED: u64 = 256 * 1024 * 1024;

/// The longest chart name.
const MAX_NAME: usize = 250;

/// What a chart declares.
pub struct Chart {
    /// `name`, as written.
    pub name: String,
    /// `version`, as written.
    pub version: String,
    /// The normalized version.
    pub normalized: Version,
    /// The raw Chart.yaml.
    pub chart_yaml: Vec<u8>,
    /// Chart.yaml as JSON.
    pub metadata: Map<String, Value>,
}

/// Whether `name` is a chart name: letters, digits, `.`, `_` and `-`,
/// starting with a letter or digit.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.contains("..")
}

/// Read the chart in a `.tgz`.
pub fn read(tgz: impl Read) -> Result<Chart, String> {
    let unpacked = flate2::read::GzDecoder::new(tgz).take(MAX_UNPACKED);
    // Chart.yaml sits in the chart's top-level directory; subcharts
    // (`<chart>/charts/<sub>/Chart.yaml`) are deeper.
    let at_top = |path: &str| {
        let path = path.trim_start_matches("./");
        let mut parts = path.split('/');
        matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some(dir), Some("Chart.yaml"), None) if !dir.is_empty()
        )
    };
    let (_, chart_yaml) = tar::find_file(unpacked, at_top, MAX_CHART_YAML)
        .map_err(|e| format!("not a chart archive: {e}"))?
        .ok_or_else(|| "the archive has no <chart>/Chart.yaml".to_string())?;
    parse_chart_yaml(chart_yaml)
}

/// Parse a Chart.yaml.
pub fn parse_chart_yaml(chart_yaml: Vec<u8>) -> Result<Chart, String> {
    let text = std::str::from_utf8(&chart_yaml).map_err(|_| "Chart.yaml is not UTF-8")?;
    let docs = crate::yaml::load(text).map_err(|e| format!("Chart.yaml: {e}"))?;
    let Some(Value::Object(metadata)) = docs.first().map(to_json) else {
        return Err("Chart.yaml is not a mapping".into());
    };
    let field = |key: &str| -> Result<String, String> {
        match metadata.get(key) {
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
            Some(Value::Number(n)) => Ok(n.to_string()),
            _ => Err(format!("Chart.yaml has no {key}")),
        }
    };
    let name = field("name")?;
    if !valid_name(&name) {
        return Err(format!("invalid chart name {name:?}"));
    }
    let version = field("version")?;
    let normalized = Version::parse(&version)?;
    field("apiVersion")?;
    Ok(Chart {
        name,
        version,
        normalized,
        chart_yaml,
        metadata,
    })
}

/// A YAML value as JSON. Scalars YAML would read as numbers keep their text
/// when JSON cannot hold them exactly (`version: 1.10` stays "1.10").
pub fn to_json(yaml: &Yaml) -> Value {
    match yaml {
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Integer(i) => Value::from(*i),
        Yaml::Real(r) => Value::String(r.clone()),
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Array(items) => Value::Array(items.iter().map(to_json).collect()),
        Yaml::Hash(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let key = match k {
                        Yaml::String(s) | Yaml::Real(s) => s.clone(),
                        Yaml::Integer(i) => i.to_string(),
                        Yaml::Boolean(b) => b.to_string(),
                        _ => String::new(),
                    };
                    (key, to_json(v))
                })
                .collect(),
        ),
        Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let tar = crate::tar::tests::archive(entries);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn reads_the_top_level_chart_yaml() {
        let archive = tgz(&[
            ("demo/charts/sub/Chart.yaml", b"apiVersion: v2\nname: sub\nversion: 9.9.9\n"),
            (
                "demo/Chart.yaml",
                b"apiVersion: v2\nname: Demo\nversion: v1.10\nappVersion: 2.0\ndescription: A demo\n",
            ),
        ]);
        let chart = read(&archive[..]).unwrap();
        assert_eq!(chart.name, "Demo");
        assert_eq!(chart.version, "v1.10");
        assert_eq!(chart.normalized.to_string(), "1.10.0");
        assert_eq!(chart.metadata["appVersion"], Value::String("2.0".into()));
        assert_eq!(
            chart.metadata["description"],
            Value::String("A demo".into())
        );
    }

    #[test]
    fn refuses_what_is_not_a_chart() {
        assert!(read(&b"not gzip"[..]).is_err());
        assert!(read(&tgz(&[("demo/values.yaml", b"a: 1\n")])[..]).is_err());
        let no_version = tgz(&[("demo/Chart.yaml", b"apiVersion: v2\nname: demo\n")]);
        assert!(read(&no_version[..]).is_err());
        let bad_name = tgz(&[(
            "demo/Chart.yaml",
            b"apiVersion: v2\nname: ../x\nversion: 1.0.0\n",
        )]);
        assert!(read(&bad_name[..]).is_err());
    }

    #[test]
    fn chart_names() {
        assert!(valid_name("nginx-ingress"));
        assert!(valid_name("my_chart.v2"));
        for bad in ["", "-x", ".x", "a/b", "a..b", "a b", "a%2f"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }
}
