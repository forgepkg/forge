//! Helm charts stored as OCI artifacts (`helm push`, Helm ≥ 3.8): their
//! media types, the chart metadata of a config blob, and the README and
//! default values of a chart archive, for the web UI.
//!
//! A chart is an image manifest whose config blob is the chart's
//! `Chart.yaml` as JSON ([`media::CONFIG`]) and whose layer is the packaged
//! chart, the `.tgz` `helm package` writes ([`media::CONTENT`]). Nothing here
//! decides what the registry stores or serves: a chart is pushed, pulled and
//! kept like any other artifact.

use std::io::Read;

use serde_json::{Map, Value};

/// The media types of a Helm chart artifact.
pub mod media {
    /// The config blob: the chart's metadata (`Chart.yaml`) as JSON.
    pub const CONFIG: &str = "application/vnd.cncf.helm.config.v1+json";
    /// The layer holding the packaged chart (`<name>-<version>.tgz`).
    pub const CONTENT: &str = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";
    /// The optional layer holding the chart's provenance file (`.prov`).
    pub const PROVENANCE: &str = "application/vnd.cncf.helm.chart.provenance.v1.prov";
}

/// Largest config blob read for its metadata.
pub const MAX_CONFIG_BYTES: i64 = 1024 * 1024;

/// Largest chart archive read for its README and values, as stored
/// (compressed). Charts are a few KiB to a few hundred KiB.
pub const MAX_ARCHIVE_BYTES: i64 = 16 * 1024 * 1024;

/// Most bytes of an archive decompressed while looking for its README and
/// values: Helm's own limit on a whole chart (`MaxDecompressedChartSize`).
const MAX_UNPACKED_BYTES: u64 = 100 * 1024 * 1024;

/// Most of a README or `values.yaml` shown; the rest is cut.
pub const MAX_FILE_TEXT: usize = 512 * 1024;

/// Longest string kept from the metadata; a longer one is cut.
const MAX_STRING: usize = 4096;

/// Most entries of a metadata list (keywords, sources, maintainers,
/// dependencies) kept.
const MAX_LIST: usize = 100;

/// The `Chart.yaml` keys whose value is a string, kept as they are.
const STRING_KEYS: &[&str] = &[
    "apiVersion",
    "name",
    "version",
    "appVersion",
    "description",
    "type",
    "kubeVersion",
    "home",
    "icon",
];

/// The metadata of a chart config blob, for display: its `Chart.yaml`
/// strings (name, version, appVersion, description, …), `deprecated`, and
/// its keywords, sources, maintainers and dependencies, each bounded. `None`
/// when the blob is not a JSON object.
pub fn metadata(config: &[u8]) -> Option<Value> {
    let Value::Object(raw) = serde_json::from_slice::<Value>(config).ok()? else {
        return None;
    };
    let mut out = Map::new();
    for key in STRING_KEYS {
        if let Some(s) = raw.get(*key).and_then(Value::as_str) {
            out.insert((*key).into(), Value::String(cut(s, MAX_STRING)));
        }
    }
    if let Some(deprecated) = raw.get("deprecated").and_then(Value::as_bool) {
        out.insert("deprecated".into(), Value::Bool(deprecated));
    }
    for key in ["keywords", "sources"] {
        let list = strings(raw.get(key));
        if !list.is_empty() {
            out.insert(key.into(), Value::from(list));
        }
    }
    let maintainers = objects(raw.get("maintainers"), &["name", "email", "url"]);
    if !maintainers.is_empty() {
        out.insert("maintainers".into(), Value::from(maintainers));
    }
    let dependencies = objects(
        raw.get("dependencies"),
        &["name", "version", "repository", "condition", "alias"],
    );
    if !dependencies.is_empty() {
        out.insert("dependencies".into(), Value::from(dependencies));
    }
    Some(Value::Object(out))
}

/// The strings of a JSON list, each bounded, at most [`MAX_LIST`].
fn strings(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(MAX_LIST)
        .map(|s| Value::String(cut(s, MAX_STRING)))
        .collect()
}

/// The objects of a JSON list with only their string `keys`, each bounded,
/// at most [`MAX_LIST`].
fn objects(value: Option<&Value>, keys: &[&str]) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .take(MAX_LIST)
        .map(|o| {
            let kept: Map<String, Value> = keys
                .iter()
                .filter_map(|k| {
                    o.get(*k)
                        .and_then(Value::as_str)
                        .map(|s| ((*k).to_string(), Value::String(cut(s, MAX_STRING))))
                })
                .collect();
            Value::Object(kept)
        })
        .collect()
}

/// `s` cut to at most `max` bytes, at a character boundary.
fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// A text file of a chart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChartFile {
    /// Its name in the chart (`README.md`, `values.yaml`).
    pub name: String,
    /// Its text (invalid UTF-8 replaced), at most [`MAX_FILE_TEXT`] bytes.
    pub text: String,
    /// Whether the text was cut.
    pub truncated: bool,
}

/// What [`read_files`] found in a chart archive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChartFiles {
    /// The chart's README: the first of `README.md`, `README.txt` or
    /// `README` (any case) at the chart's top level, as `helm show readme`
    /// picks it.
    pub readme: Option<ChartFile>,
    /// The chart's default values (`values.yaml` at its top level; the last
    /// one, as Helm loads it).
    pub values: Option<ChartFile>,
}

/// The README and default values of a packaged chart (`.tgz`). Paths are
/// read the way Helm's loader reads them: the archive's first directory is
/// the chart, so `<chart>/README.md` is the chart's README and
/// `<chart>/charts/<sub>/README.md` a subchart's. At most
/// [`MAX_UNPACKED_BYTES`] are decompressed; an archive that is not gzip or
/// tar, or ends early, yields what was found before.
pub fn read_files(archive: &[u8]) -> ChartFiles {
    let mut found = ChartFiles::default();
    let decoder = flate2::read::MultiGzDecoder::new(archive);
    let mut tar = TarReader {
        inner: decoder.take(MAX_UNPACKED_BYTES),
    };
    let mut long_name: Option<String> = None;
    while let Some(header) = tar.header() {
        let size = header.size;
        match header.kind {
            // A GNU long name, or a pax extended header, names the next
            // entry.
            b'L' => {
                let Some(data) = tar.data(size, 64 * 1024) else {
                    break;
                };
                long_name = Some(
                    String::from_utf8_lossy(&data)
                        .trim_end_matches('\0')
                        .to_string(),
                );
                continue;
            }
            b'x' => {
                let Some(data) = tar.data(size, 64 * 1024) else {
                    break;
                };
                if let Some(path) = pax_path(&data) {
                    long_name = Some(path);
                }
                continue;
            }
            b'0' | b'\0' | b'7' => {
                let name = long_name.take().unwrap_or(header.name);
                let wanted = match chart_path(&name) {
                    Some(path) if is_readme(&path) && found.readme.is_none() => Some(path),
                    Some(path) if path == "values.yaml" => Some(path),
                    _ => None,
                };
                let Some(path) = wanted else {
                    if !tar.skip(size) {
                        break;
                    }
                    continue;
                };
                let Some(data) = tar.data(size, MAX_FILE_TEXT as u64) else {
                    break;
                };
                let truncated = size > MAX_FILE_TEXT as u64;
                let text = String::from_utf8_lossy(&data);
                let text = if truncated {
                    // The cut may split a character the lossy decoding
                    // replaced: keep only whole characters.
                    cut(&text, MAX_FILE_TEXT)
                } else {
                    text.into_owned()
                };
                let file = ChartFile {
                    name: path.clone(),
                    text,
                    truncated,
                };
                if path == "values.yaml" {
                    found.values = Some(file);
                } else {
                    found.readme = Some(file);
                }
            }
            _ => {
                long_name = None;
                if !tar.skip(size) {
                    break;
                }
            }
        }
    }
    found
}

/// Whether a chart path is the chart's README (`helm show readme`).
fn is_readme(path: &str) -> bool {
    matches!(
        path.to_ascii_lowercase().as_str(),
        "readme.md" | "readme.txt" | "readme"
    )
}

/// An archive path within its chart, as Helm's loader reads it: the first
/// component (the chart's directory) dropped, `\` read as `/` in an archive
/// made on Windows, `.` components dropped. `None` for the directory itself,
/// an absolute path, or one leaving the chart.
fn chart_path(name: &str) -> Option<String> {
    let delimiter = if name.contains('\\') { '\\' } else { '/' };
    let mut parts = name.split(delimiter);
    parts.next()?;
    let mut kept = Vec::new();
    for part in parts {
        match part {
            "" | "." => {}
            ".." => return None,
            part => kept.push(part),
        }
    }
    if kept.is_empty() {
        return None;
    }
    Some(kept.join("/"))
}

/// The `path` record of a pax extended header (`<length> path=<value>\n`).
fn pax_path(data: &[u8]) -> Option<String> {
    let mut rest = data;
    let mut path = None;
    while !rest.is_empty() {
        let space = rest.iter().position(|&b| b == b' ')?;
        let length: usize = std::str::from_utf8(&rest[..space]).ok()?.parse().ok()?;
        if length <= space + 1 || length > rest.len() {
            return None;
        }
        let record = &rest[space + 1..length];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(value) = record.strip_prefix(b"path=") {
            path = Some(String::from_utf8_lossy(value).into_owned());
        }
        rest = &rest[length..];
    }
    path
}

/// A tar entry's header: what [`read_files`] needs of it.
struct Header {
    name: String,
    size: u64,
    kind: u8,
}

/// A minimal reader of a tar stream: ustar and GNU headers, entries read or
/// skipped in order.
struct TarReader<R> {
    inner: R,
}

impl<R: Read> TarReader<R> {
    /// The next entry's header; `None` at the end of the archive (a zero
    /// block), at the end of the stream, or at a header that does not parse.
    fn header(&mut self) -> Option<Header> {
        let mut block = [0u8; 512];
        self.inner.read_exact(&mut block).ok()?;
        if block.iter().all(|&b| b == 0) {
            return None;
        }
        // The checksum covers the header with its own field read as spaces,
        // its bytes unsigned or, from some old writers, signed.
        let stored = octal(&block[148..156])?;
        let summed = |i: usize, b: u8| if (148..156).contains(&i) { b' ' } else { b };
        let unsigned: i64 = block
            .iter()
            .enumerate()
            .map(|(i, &b)| i64::from(summed(i, b)))
            .sum();
        let signed: i64 = block
            .iter()
            .enumerate()
            .map(|(i, &b)| i64::from(summed(i, b) as i8))
            .sum();
        if ![unsigned, signed].contains(&i64::try_from(stored).ok()?) {
            return None;
        }
        let size = octal(&block[124..136])?;
        let name = field(&block[0..100]);
        // ustar keeps a path prefix; GNU's header uses those bytes otherwise.
        let name = if &block[257..263] == b"ustar\0" {
            let prefix = field(&block[345..500]);
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            }
        } else {
            name
        };
        Some(Header {
            name,
            size,
            kind: block[156],
        })
    }

    /// An entry's data, at most `keep` bytes of it, the rest and the padding
    /// skipped; `None` when the stream ends first.
    fn data(&mut self, size: u64, keep: u64) -> Option<Vec<u8>> {
        let kept = size.min(keep);
        let mut data = Vec::with_capacity(usize::try_from(kept).ok()?);
        (&mut self.inner).take(kept).read_to_end(&mut data).ok()?;
        if data.len() as u64 != kept {
            return None;
        }
        self.skip_raw(padded(size) - kept).then_some(data)
    }

    /// Skip an entry's data and padding; `false` when the stream ends first.
    fn skip(&mut self, size: u64) -> bool {
        self.skip_raw(padded(size))
    }

    fn skip_raw(&mut self, n: u64) -> bool {
        std::io::copy(&mut (&mut self.inner).take(n), &mut std::io::sink())
            .is_ok_and(|copied| copied == n)
    }
}

/// `size` rounded up to whole 512-byte blocks.
fn padded(size: u64) -> u64 {
    size.div_ceil(512).saturating_mul(512)
}

/// A NUL-terminated header field.
fn field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// An octal header number (NUL- or space-padded). Base-256 numbers (sizes
/// over 8 GiB) are refused: no chart file is that large.
fn octal(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.trim_matches(|c: char| c == '\0' || c == ' ');
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    /// A ustar header of a regular file (or `kind`), with its checksum.
    fn header(path: &str, size: usize, kind: u8) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..path.len()].copy_from_slice(path.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    fn entry(tar: &mut Vec<u8>, path: &str, data: &[u8], kind: u8) {
        tar.extend_from_slice(&header(path, data.len(), kind));
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }

    fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (path, data) in entries {
            entry(&mut tar, path, data, b'0');
        }
        gzip(tar)
    }

    fn gzip(mut tar: Vec<u8>) -> Vec<u8> {
        tar.extend_from_slice(&[0u8; 1024]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn metadata_keeps_the_chart_fields_bounded() {
        let long = "x".repeat(MAX_STRING + 10);
        let config = serde_json::json!({
            "apiVersion": "v2", "name": "demo", "version": "1.2.3", "appVersion": "2.0",
            "description": long, "type": "application", "deprecated": true,
            "keywords": ["web", 7, "proxy"],
            "maintainers": [{"name": "Ops", "email": "ops@example.com", "extra": "dropped"}],
            "dependencies": [{"name": "redis", "version": ">=17", "repository": "oci://r/charts", "import-values": ["a"]}],
            "annotations": {"dropped": "yes"},
            "icon": 3,
        });
        let m = metadata(config.to_string().as_bytes()).unwrap();
        assert_eq!(m["name"], "demo");
        assert_eq!(m["appVersion"], "2.0");
        assert_eq!(m["description"].as_str().unwrap().len(), MAX_STRING);
        assert_eq!(m["deprecated"], true);
        assert_eq!(m["keywords"], serde_json::json!(["web", "proxy"]));
        assert_eq!(
            m["maintainers"],
            serde_json::json!([{"name": "Ops", "email": "ops@example.com"}])
        );
        assert_eq!(
            m["dependencies"],
            serde_json::json!([{"name": "redis", "version": ">=17", "repository": "oci://r/charts"}])
        );
        assert!(m.get("annotations").is_none());
        assert!(m.get("icon").is_none());
        assert!(m.get("sources").is_none());
        assert!(metadata(b"[1]").is_none());
        assert!(metadata(b"not json").is_none());
    }

    #[test]
    fn reads_the_top_level_readme_and_values() {
        let archive = tgz(&[
            (
                "demo/Chart.yaml",
                b"apiVersion: v2\nname: demo\nversion: 1.0.0\n",
            ),
            ("demo/charts/sub/README.md", b"the subchart"),
            ("demo/charts/sub/values.yaml", b"sub: true\n"),
            ("demo/Readme.MD", b"# Demo\n"),
            ("demo/README.txt", b"second readme"),
            ("demo/values.yaml", b"replicas: 1\n"),
            ("demo/templates/values.yaml", b"not: this\n"),
        ]);
        let files = read_files(&archive);
        let readme = files.readme.unwrap();
        assert_eq!(readme.name, "Readme.MD");
        assert_eq!(readme.text, "# Demo\n");
        assert!(!readme.truncated);
        let values = files.values.unwrap();
        assert_eq!(values.name, "values.yaml");
        assert_eq!(values.text, "replicas: 1\n");
    }

    #[test]
    fn long_files_are_cut_and_long_names_followed() {
        let mut tar = Vec::new();
        // A GNU long name for the README, a pax path for the values.
        let long_dir = format!("{}/", "d".repeat(120));
        let readme = format!("{long_dir}README.md");
        entry(
            &mut tar,
            "././@LongLink",
            format!("{readme}\0").as_bytes(),
            b'L',
        );
        let big = "a".repeat(MAX_FILE_TEXT + 100);
        entry(&mut tar, "truncated-name", big.as_bytes(), b'0');
        let line = format!(" path={long_dir}values.yaml\n");
        let mut length = line.len();
        while format!("{length}{line}").len() != length {
            length += 1;
        }
        let pax = format!("{length}{line}");
        entry(&mut tar, "PaxHeaders/values", pax.as_bytes(), b'x');
        entry(&mut tar, "values.yaml-short", b"x: 1\n", b'0');
        let files = read_files(&gzip(tar));
        let readme = files.readme.unwrap();
        assert!(readme.truncated);
        assert_eq!(readme.text.len(), MAX_FILE_TEXT);
        assert_eq!(files.values.unwrap().text, "x: 1\n");
    }

    #[test]
    fn what_is_not_a_chart_yields_nothing() {
        assert_eq!(read_files(b"not gzip"), ChartFiles::default());
        assert_eq!(
            read_files(&gzip(b"not a tar header".to_vec())),
            ChartFiles::default()
        );
        // Paths outside the chart, or the chart's directory alone.
        let archive = tgz(&[("demo/../README.md", b"out"), ("README.md", b"top")]);
        assert_eq!(read_files(&archive), ChartFiles::default());
        // A truncated archive keeps what came before the cut.
        let mut noise = Vec::with_capacity(64 * 1024);
        let mut x: u32 = 1;
        for _ in 0..64 * 1024 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            noise.push((x >> 16) as u8);
        }
        let archive = tgz(&[
            ("demo/README.md", b"kept"),
            ("demo/templates/noise", &noise),
            ("demo/values.yaml", b"v: 1\n"),
        ]);
        let files = read_files(&archive[..archive.len() / 2]);
        assert_eq!(files.readme.unwrap().text, "kept");
        assert_eq!(files.values, None);
    }

    #[test]
    fn chart_paths_follow_helms_loader() {
        assert_eq!(chart_path("demo/README.md").as_deref(), Some("README.md"));
        assert_eq!(
            chart_path("./demo/README.md").as_deref(),
            Some("demo/README.md")
        );
        assert_eq!(
            chart_path("demo\\values.yaml").as_deref(),
            Some("values.yaml")
        );
        assert_eq!(
            chart_path("demo/./values.yaml").as_deref(),
            Some("values.yaml")
        );
        assert_eq!(chart_path("demo/"), None);
        assert_eq!(chart_path("demo/a/../../x"), None);
    }
}
