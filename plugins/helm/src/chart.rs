//! Reading a chart archive: `<chart>/Chart.yaml` inside a gzipped tarball,
//! found the way Helm finds it.
//!
//! A chart's name and version decide where Forge stores it and whether a
//! publisher may push it, so Forge takes them from the Chart.yaml Helm loads
//! when it installs the chart, or refuses the archive. Helm
//! (`loader.LoadArchiveFiles`, `LoadFiles`) reads the whole archive, strips
//! the first component of every name ([`chart_path`]), and reads every file
//! it then calls `Chart.yaml`, then every `requirements.yaml`, into the
//! chart's metadata: the last one wins. So Forge reads the whole archive
//! too ([`tar`] reads it as Go does), and refuses one with more than one
//! top-level directory, more than one Chart.yaml or requirements.yaml, a
//! requirements.yaml that declares more than dependencies, or a Chart.yaml
//! key that Helm reads as another field ([`folded_field`]).

use std::io::{self, Read};

use serde_json::{Map, Value};
use yaml_rust2::Yaml;

use crate::semver::Version;
use crate::tar;

/// The largest Chart.yaml (or requirements.yaml) read.
const MAX_CHART_YAML: u64 = 1024 * 1024;

/// How much of a chart is decompressed. The whole archive is read, so that
/// no Chart.yaml goes unseen; a chart that unpacks to more, or a gzip bomb,
/// is refused. (Helm itself loads at most 100 MiB of files.)
const MAX_UNPACKED: u64 = 256 * 1024 * 1024;

/// The longest chart name.
const MAX_NAME: usize = 250;

/// The UTF-8 byte order mark, which Helm strips from every file it loads.
const BOM: &[u8] = b"\xEF\xBB\xBF";

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
    read_unpacking(tgz, MAX_UNPACKED)
}

/// [`read`], decompressing at most `max_unpacked` bytes.
fn read_unpacking(tgz: impl Read, max_unpacked: u64) -> Result<Chart, String> {
    // Go's gzip reader, which Helm uses, reads concatenated gzip members as
    // one stream.
    let unpacked = Bounded {
        inner: flate2::read::MultiGzDecoder::new(tgz),
        left: max_unpacked,
        max: max_unpacked,
    };
    let mut archive = tar::Archive::new(unpacked);
    let lossy = |name: &[u8]| String::from_utf8_lossy(name).into_owned();
    let mut top_dir: Option<Vec<u8>> = None;
    let (mut chart_yaml, mut requirements) = (None, None);
    while let Some(entry) = archive
        .next_entry()
        .map_err(|e| format!("not a chart archive: {e}"))?
    {
        // Helm skips directories and global PAX headers.
        if entry.is_dir() || entry.typeflag == b'g' {
            continue;
        }
        let (top, path) = chart_path(&entry.name)?;
        let dir = top_dir.get_or_insert_with(|| top.to_vec());
        if dir.as_slice() != top {
            return Err(format!(
                "the archive holds more than one top-level directory: {:?} and {:?}",
                lossy(dir),
                lossy(top)
            ));
        }
        // Keep Chart.yaml and requirements.yaml; skip the rest.
        let found = match path.as_slice() {
            b"Chart.yaml" => &mut chart_yaml,
            b"requirements.yaml" => &mut requirements,
            _ => continue,
        };
        if found.is_some() {
            return Err(format!(
                "the archive holds more than one <chart>/{}",
                lossy(&path)
            ));
        }
        let data = archive
            .read_data(MAX_CHART_YAML)
            .map_err(|e| format!("{}: {e}", lossy(&entry.name)))?;
        *found = Some(strip_bom(data));
    }
    let chart_yaml =
        chart_yaml.ok_or_else(|| "the archive has no <chart>/Chart.yaml".to_string())?;
    if let Some(requirements) = requirements {
        check_requirements(&requirements)?;
    }
    parse_chart_yaml(chart_yaml)
}

/// What Helm makes of an entry's name (`loader.LoadArchiveFiles`): the
/// top-level directory it strips, and the file's path in the chart,
/// cleaned. An error for a name Helm refuses.
fn chart_path(name: &[u8]) -> Result<(&[u8], Vec<u8>), String> {
    // A name with a backslash is split at backslashes (a chart packaged on
    // Windows), and its `/` are then part of a name.
    let separator = if name.contains(&b'\\') { b'\\' } else { b'/' };
    let (top, rest) = match name.iter().position(|&b| b == separator) {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (name, &name[name.len()..]),
    };
    let rest: Vec<u8> = rest
        .iter()
        .map(|&b| if b == separator { b'/' } else { b })
        .collect();
    let refused = |why: &str| format!("{why}: {:?}", String::from_utf8_lossy(name));
    if rest.starts_with(b"/") {
        return Err(refused("the archive holds an absolute path"));
    }
    let path = clean(&rest);
    if path == b"." {
        return Err(refused("the archive holds a file outside a directory"));
    }
    if path.starts_with(b"..") {
        return Err(refused("the archive holds a path to a parent directory"));
    }
    if let [drive, b':', b'/', ..] = path.as_slice() {
        if drive.is_ascii_alphabetic() {
            return Err(refused("the archive holds a path with a drive letter"));
        }
    }
    if top == b"Chart.yaml" {
        return Err(refused("the archive holds a directory named Chart.yaml"));
    }
    Ok((top, path))
}

/// Go's `path.Clean` of a relative path: no empty or `.` elements, a `..`
/// removing the element before it, and `.` for nothing at all.
fn clean(path: &[u8]) -> Vec<u8> {
    let mut kept: Vec<&[u8]> = Vec::new();
    for element in path.split(|&b| b == b'/') {
        match element {
            b"" | b"." => {}
            b".." if kept.last().is_some_and(|last| *last != b"..") => {
                kept.pop();
            }
            element => kept.push(element),
        }
    }
    if kept.is_empty() {
        b".".to_vec()
    } else {
        kept.join(&b'/')
    }
}

/// `data` without a leading byte order mark.
fn strip_bom(mut data: Vec<u8>) -> Vec<u8> {
    if data.starts_with(BOM) {
        data.drain(..BOM.len());
    }
    data
}

/// Refuse a `requirements.yaml` that declares more than dependencies. Helm
/// reads it (Helm 2's list of dependencies) into the chart's metadata after
/// Chart.yaml, so a `name` or a `version` in it would be the chart's.
fn check_requirements(yaml: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(yaml).map_err(|_| "requirements.yaml is not UTF-8")?;
    let docs = crate::yaml::load(text).map_err(|e| format!("requirements.yaml: {e}"))?;
    match docs.first() {
        None | Some(Yaml::Null) => Ok(()),
        Some(Yaml::Hash(map)) if map.keys().all(|k| k.as_str() == Some("dependencies")) => Ok(()),
        _ => Err("requirements.yaml declares more than dependencies".into()),
    }
}

/// A reader of at most `max` bytes, which fails, rather than ending early,
/// when its source holds more.
struct Bounded<R> {
    /// The source.
    inner: R,
    /// The bytes it may still read.
    left: u64,
    /// The bytes it may read in all.
    max: u64,
}

impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            return match self.inner.read(&mut [0u8])? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("it unpacks to more than {} bytes", self.max),
                )),
            };
        }
        let len = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..len])?;
        self.left -= n as u64;
        Ok(n)
    }
}

/// Parse a Chart.yaml.
pub fn parse_chart_yaml(chart_yaml: Vec<u8>) -> Result<Chart, String> {
    let text = std::str::from_utf8(&chart_yaml).map_err(|_| "Chart.yaml is not UTF-8")?;
    let docs = crate::yaml::load(text).map_err(|e| format!("Chart.yaml: {e}"))?;
    let Some(Value::Object(metadata)) = docs.first().map(to_json) else {
        return Err("Chart.yaml is not a mapping".into());
    };
    if let Some((key, field)) = metadata
        .keys()
        .find_map(|key| Some((key, folded_field(key)?)))
    {
        return Err(format!(
            "Chart.yaml has the key {key:?}, which Helm reads as {field:?}"
        ));
    }
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

/// The field of Helm's chart metadata that `key` sets without being its
/// name: one that equals it only under Go's case folding.
///
/// Helm reads Chart.yaml with `sigs.k8s.io/yaml`, which turns it into JSON,
/// keys sorted, and decodes that with Go's `encoding/json`. The decoder
/// matches a key to a field case-insensitively, by Unicode simple case
/// folding, and a later key overwrites an earlier one. So `verſion` (`ſ`
/// folds to `s`), which sorts after `version`, is the version Helm installs
/// whatever `version` says, and `apiversion` sorts after `apiVersion` (#422).
/// Only ASCII letters, U+017F (`ſ`, the long s, to `s`) and U+212A (the
/// Kelvin sign, to `k`) fold to ASCII letters, and every field name is ASCII.
fn folded_field(key: &str) -> Option<&'static str> {
    if crate::METADATA_KEYS.contains(&key) {
        return None;
    }
    let folded: String = key
        .chars()
        .map(|c| match c {
            '\u{17f}' => Some('s'),
            '\u{212a}' => Some('k'),
            c if c.is_ascii() => Some(c.to_ascii_lowercase()),
            _ => None,
        })
        .collect::<Option<_>>()?;
    crate::METADATA_KEYS
        .iter()
        .copied()
        .find(|field| field.eq_ignore_ascii_case(&folded))
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
    use crate::tar::tests::{archive, entry, file, header, long, pax, seal, END};
    use std::io::Write;

    /// `tar`, gzipped.
    fn gzip(tar: &[u8]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(tar).unwrap();
        gz.finish().unwrap()
    }

    /// A gzipped archive of `(path, contents)` regular files.
    pub(crate) fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        gzip(&archive(entries))
    }

    const GOOD: &[u8] = b"apiVersion: v2\nname: good\nversion: 1.0.0\n";
    const EVIL: &[u8] = b"apiVersion: v2\nname: evil\nversion: 6.6.6\n";

    /// The name and version [`read`] finds in the archive `tar`, gzipped.
    fn identity(tar: &[u8]) -> Result<String, String> {
        read(&gzip(tar)[..]).map(|chart| format!("{} {}", chart.name, chart.version))
    }

    /// The error [`read`] refuses the archive `tar` with.
    fn refusal(tar: &[u8]) -> String {
        identity(tar).unwrap_err()
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
    fn refuses_versions_longer_than_an_oci_tag() {
        let chart_yaml = |version: &str| {
            format!("apiVersion: v2\nname: demo\nversion: {version}\n").into_bytes()
        };
        let longest = format!(
            "1.0.0-{}",
            "a".repeat(crate::semver::MAX_VERSION_LENGTH - 6)
        );
        let chart = parse_chart_yaml(chart_yaml(&longest)).unwrap();
        assert_eq!(chart.version, longest);
        assert_eq!(chart.normalized.to_string(), longest);
        for longer in [format!("{longest}a"), format!("1.0.0-{}", "x".repeat(4096))] {
            let err = parse_chart_yaml(chart_yaml(&longer)).err().unwrap();
            assert!(err.contains("longer than 128 characters"), "{err}");
        }
    }

    #[test]
    fn chart_names() {
        assert!(valid_name("nginx-ingress"));
        assert!(valid_name("my_chart.v2"));
        for bad in ["", "-x", ".x", "a/b", "a..b", "a b", "a%2f"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn reads_charts_as_tools_pack_them() {
        // `helm package`: Chart.yaml first, a long name in a PAX header, no
        // directories.
        let long_name = format!("demo/templates/{}.yaml", "x".repeat(120));
        let tar = [
            &file("demo/Chart.yaml", GOOD)[..],
            &file("demo/values.yaml", b"replicas: 1\n"),
            &pax(b'x', &[("path", &long_name)]),
            &file(&long_name[..99], b"kind: ConfigMap\n"),
            &file("demo/charts/sub/Chart.yaml", EVIL),
            &END,
        ]
        .concat();
        assert_eq!(identity(&tar).unwrap(), "good 1.0.0");
        // `git archive` (a global header first) and GNU tar (directories,
        // GNU long names).
        let tar = [
            &pax(b'g', &[("comment", "8b4c2f0")])[..],
            &header(b"demo/", b'5', 0),
            &header(b"demo/templates/", b'5', 0),
            &long(b'L', &long_name),
            &file(&long_name[..99], b""),
            &file("demo/Chart.yaml", GOOD),
            &END,
        ]
        .concat();
        assert_eq!(identity(&tar).unwrap(), "good 1.0.0");
        // Packed inside the chart's directory: `./Chart.yaml`.
        let tar = archive(&[("./Chart.yaml", GOOD), ("./values.yaml", b"")]);
        assert_eq!(identity(&tar).unwrap(), "good 1.0.0");
        // On Windows: backslashes.
        let tar = archive(&[("demo\\templates\\a.yaml", b""), ("demo\\Chart.yaml", GOOD)]);
        assert_eq!(identity(&tar).unwrap(), "good 1.0.0");
        // In two gzip members.
        let first = gzip(&file("demo/values.yaml", b""));
        let second = gzip(&[&file("demo/Chart.yaml", GOOD)[..], &END].concat());
        let chart = read(&[first, second].concat()[..]).unwrap();
        assert_eq!(chart.name, "good");
    }

    #[test]
    fn finds_the_chart_yaml_helm_finds() {
        // Helm strips the first component of a name and cleans the rest;
        // a name with a backslash is split at backslashes only.
        for name in [
            "demo/./Chart.yaml",
            "demo/templates/../Chart.yaml",
            "demo/Chart.yaml/",
            "demo/x\\Chart.yaml",
        ] {
            let tar = archive(&[(name, GOOD)]);
            assert_eq!(identity(&tar).unwrap(), "good 1.0.0", "{name:?}");
        }
        // `./demo/Chart.yaml` is the file `demo/Chart.yaml` of the
        // directory `.` to Helm, not its Chart.yaml.
        let tar = archive(&[("./demo/Chart.yaml", GOOD)]);
        assert!(refusal(&tar).contains("no <chart>/Chart.yaml"));
        // A directory by its mode is skipped like any directory, and a
        // symlink has no data.
        let mut dir = header(b"demo/Chart.yaml", b'0', EVIL.len() as u64);
        dir[100..108].copy_from_slice(b"0040755\0");
        seal(&mut dir);
        let tar = [&entry(dir, EVIL)[..], &file("demo/Chart.yaml", GOOD), &END].concat();
        assert_eq!(identity(&tar).unwrap(), "good 1.0.0");
        let tar = [&header(b"demo/Chart.yaml", b'2', 0)[..], &END].concat();
        assert!(refusal(&tar).contains("not a mapping"));
        // Helm strips a byte order mark.
        let tar = archive(&[("demo/Chart.yaml", &[BOM, GOOD].concat())]);
        assert_eq!(read(&gzip(&tar)[..]).unwrap().chart_yaml, GOOD);
    }

    #[test]
    fn refuses_more_than_one_top_level_directory() {
        // The archive of the issue: Forge stored `good` 1.0.0, Helm installs
        // `evil` 6.6.6.
        let tar = archive(&[("a/Chart.yaml", GOOD), ("b/Chart.yaml", EVIL)]);
        assert!(refusal(&tar).contains("more than one top-level directory"));
        let tar = archive(&[("demo/Chart.yaml", GOOD), ("other/templates/a.yaml", b"")]);
        assert!(refusal(&tar).contains("more than one top-level directory"));
        let tar = archive(&[("demo/Chart.yaml", GOOD), ("./demo/values.yaml", b"")]);
        assert!(refusal(&tar).contains("more than one top-level directory"));
    }

    #[test]
    fn refuses_more_than_one_chart_yaml() {
        // Helm loads every one, the last one winning.
        for second in [
            "demo/Chart.yaml",
            "demo/./Chart.yaml",
            "demo/x/../Chart.yaml",
            "demo/Chart.yaml/",
            "demo\\Chart.yaml",
        ] {
            let tar = archive(&[("demo/Chart.yaml", GOOD), (second, EVIL)]);
            let err = refusal(&tar);
            assert!(
                err.contains("more than one <chart>/Chart.yaml"),
                "{second:?}: {err}"
            );
        }
    }

    #[test]
    fn sees_every_entry_helm_sees() {
        let good = file("demo/Chart.yaml", GOOD);
        let evil = file("demo/Chart.yaml", EVIL);
        let refused = |tar: &[u8]| {
            let err = refusal(tar);
            assert!(err.contains("more than one <chart>/Chart.yaml"), "{err}");
        };
        // A PAX size of 0: what the header calls data is an entry.
        refused(
            &[
                &good[..],
                &pax(b'x', &[("size", "0")]),
                &entry(header(b"demo/values.yaml", b'0', evil.len() as u64), &evil),
                &END,
            ]
            .concat(),
        );
        // A symlink with a size has no data either.
        refused(
            &[
                &good[..],
                &header(b"demo/link", b'2', evil.len() as u64),
                &evil,
                &END,
            ]
            .concat(),
        );
        // A long link name does not take the long name before it.
        refused(
            &[
                &good[..],
                &long(b'L', "demo/Chart.yaml"),
                &long(b'K', "target"),
                &file("demo/a", EVIL),
                &END,
            ]
            .concat(),
        );
        // A GNU header's times are not a prefix.
        let mut gnu = header(b"demo/Chart.yaml", b'0', EVIL.len() as u64);
        gnu[257..265].copy_from_slice(b"ustar  \0");
        gnu[345..347].copy_from_slice(b"7\0");
        seal(&mut gnu);
        refused(&[&good[..], &entry(gnu, EVIL), &END].concat());
        // A second gzip member.
        let tgz = [gzip(&good), gzip(&[&evil[..], &END].concat())].concat();
        let err = read(&tgz[..]).err().unwrap();
        assert!(err.contains("more than one <chart>/Chart.yaml"), "{err}");
        // Not the end of the archive: a zero block, then more.
        let tar = [&good[..], &[0; 512], &evil, &END].concat();
        assert!(refusal(&tar).contains("not a chart archive"));
    }

    #[test]
    fn refuses_names_helm_refuses() {
        for name in [
            "demo//Chart.yaml",
            "demo/../../etc/passwd",
            "demo/..",
            "Chart.yaml",
            "README.md",
            "Chart.yaml/values.yaml",
            "demo/c:/x",
            "demo\\c:\\x",
        ] {
            let tar = archive(&[(name, GOOD), ("demo/Chart.yaml", GOOD)]);
            assert!(refusal(&tar).contains("the archive holds a"), "{name:?}");
        }
    }

    #[test]
    fn refuses_a_requirements_yaml_that_renames_the_chart() {
        let dependencies = b"dependencies:\n  - name: redis\n    version: 17.0.0\n";
        for requirements in [&dependencies[..], b"", b"# none\n"] {
            let tar = archive(&[
                ("demo/Chart.yaml", GOOD),
                ("demo/requirements.yaml", requirements),
            ]);
            assert_eq!(identity(&tar).unwrap(), "good 1.0.0");
        }
        // Helm reads it into the chart's metadata after Chart.yaml.
        for requirements in [
            &b"name: evil\nversion: 6.6.6\n"[..],
            b"dependencies: []\nVersion: 6.6.6\n",
            b"- name: evil\n",
        ] {
            let tar = archive(&[
                ("demo/Chart.yaml", GOOD),
                ("demo/requirements.yaml", requirements),
            ]);
            assert!(refusal(&tar).contains("more than dependencies"));
        }
        let tar = archive(&[
            ("demo/Chart.yaml", GOOD),
            ("demo/requirements.yaml", dependencies),
            ("demo/requirements.yaml", dependencies),
        ]);
        assert!(refusal(&tar).contains("more than one <chart>/requirements.yaml"));
        // A subchart's is the subchart's.
        let tar = archive(&[
            ("demo/Chart.yaml", GOOD),
            ("demo/charts/sub/requirements.yaml", b"name: evil\n"),
        ]);
        assert_eq!(identity(&tar).unwrap(), "good 1.0.0");
    }

    #[test]
    fn folds_keys_like_go() {
        for (key, field) in [
            ("verſion", Some("version")),
            ("VERSION", Some("version")),
            ("Version", Some("version")),
            ("apiversion", Some("apiVersion")),
            ("APIVERSION", Some("apiVersion")),
            ("\u{212a}ubeVersion", Some("kubeVersion")),
            ("\u{212a}EYWORDſ", Some("keywords")),
            ("Name", Some("name")),
            // Exact names, and keys that are no field.
            ("version", None),
            ("apiVersion", None),
            ("versions", None),
            ("\u{212a}ind", None),
            ("versión", None),
            ("ver\u{0131}sion", None),
            ("", None),
        ] {
            assert_eq!(folded_field(key), field, "{key:?}");
        }
    }

    #[test]
    fn refuses_keys_helm_reads_as_another_field() {
        // What Helm 3.17 (sigs.k8s.io/yaml v1.4.0) reads, after `apiVersion: v2`:
        // `good 6.6.6` for the first two, `evil 1.0.0` for the fourth, a v1
        // chart for `apiversion` and appVersion 9 for `appversion`.
        for keys in [
            "name: good\nversion: 1.0.0\nverſion: 6.6.6\n",
            "name: good\nverſion: 6.6.6\nversion: 1.0.0\n",
            "name: good\nversion: 1.0.0\nVERSION: 6.6.6\n",
            "NAME: evil\nversion: 1.0.0\n",
            "name: good\nNAME: evil\nversion: 1.0.0\n",
            "name: good\nversion: 1.0.0\napiversion: v1\n",
            "name: good\nversion: 1.0.0\nappVersion: \"1\"\nappversion: \"9\"\n",
            "name: good\nversion: 1.0.0\n\u{212a}ubeVersion: \">=1.0\"\n",
        ] {
            let chart_yaml = format!("apiVersion: v2\n{keys}");
            let err = parse_chart_yaml(chart_yaml.clone().into_bytes()).err();
            assert!(
                err.as_deref()
                    .is_some_and(|e| e.contains("which Helm reads as")),
                "{chart_yaml:?}: {err:?}"
            );
        }
        let err = parse_chart_yaml(
            "apiVersion: v2\nname: good\nversion: 1.0.0\nverſion: 6.6.6\n"
                .as_bytes()
                .to_vec(),
        )
        .err()
        .unwrap();
        assert_eq!(
            err,
            r#"Chart.yaml has the key "verſion", which Helm reads as "version""#
        );
        // In an archive, as a push or a proxy download reads it.
        let tar = archive(&[(
            "demo/Chart.yaml",
            "apiVersion: v2\nname: good\nversion: 1.0.0\nverſion: 6.6.6\n".as_bytes(),
        )]);
        assert!(refusal(&tar).contains("which Helm reads as \"version\""));
        // Keys that are no field of Helm's stay accepted, as Helm ignores them.
        let chart = parse_chart_yaml(
            b"apiVersion: v2\nname: good\nversion: 1.0.0\nappVersion: \"1\"\nversions: 2\nKind: x\n"
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            (chart.name.as_str(), chart.version.as_str()),
            ("good", "1.0.0")
        );
    }

    #[test]
    fn refuses_an_archive_it_cannot_read_to_the_end() {
        let tar = archive(&[("demo/Chart.yaml", GOOD), ("demo/big", &[7; 4096])]);
        let len = tar.len() as u64;
        assert!(read_unpacking(&gzip(&tar)[..], len).is_ok());
        let err = read_unpacking(&gzip(&tar)[..], len - 1).err().unwrap();
        assert!(err.contains("unpacks to more than"), "{err}");
    }

    #[test]
    fn cleans_paths_like_go() {
        for (path, clean_path) in [
            ("", "."),
            ("a//b/./c/", "a/b/c"),
            ("a/../..", ".."),
            ("../a/../b", "../b"),
            ("a/b/../../c", "c"),
            (".", "."),
        ] {
            assert_eq!(clean(path.as_bytes()), clean_path.as_bytes(), "{path:?}");
        }
    }
}
