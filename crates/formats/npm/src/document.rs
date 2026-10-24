//! The documents npm clients `PUT` to a package: a publish (a new version
//! with its tarball attached) and the packument updates of `npm deprecate`,
//! `npm unpublish <version>` and `npm owner`.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use serde_json::{Map, Value};

use crate::integrity::Digests;
use crate::name::PackageName;
use crate::{tarball, version};

/// Whether `tag` may name a dist-tag: a short word of letters, digits,
/// `.`, `_` and `-` that no client could read as a version or a range
/// (`1.x`, `v2`, `x`, `^1`), as npm refuses those.
pub fn valid_tag(tag: &str) -> bool {
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let second = chars.next();
    tag.len() <= 64
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !first.is_ascii_digit()
        && !(matches!(first, 'v' | 'V') && second.is_some_and(|c| c.is_ascii_digit()))
        && !matches!(tag, "x" | "X")
}

/// What a publish document says.
#[derive(Debug, Clone, PartialEq)]
pub struct PublishDocument {
    pub name: PackageName,
    /// The published version, normalized.
    pub version: String,
    /// The version as the document writes it.
    pub version_original: String,
    /// The version object.
    pub manifest: Map<String, Value>,
    /// The dist-tags the document points at the version.
    pub dist_tags: Vec<String>,
    /// The attachment's name and its declared `length`.
    pub attachment: String,
    pub length: Option<u64>,
    /// The document's top-level README.
    pub readme: Option<String>,
}

/// What a packument update (a `PUT` without a tarball) says of the
/// package's versions.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UpdateDocument {
    /// Every version the document lists (normalized), with its
    /// `deprecated` message (`None`: not deprecated).
    pub versions: BTreeMap<String, Option<String>>,
    /// The dist-tags (versions normalized).
    pub dist_tags: BTreeMap<String, String>,
    /// Whether the document has dist-tags at all (a document without them
    /// changes none).
    pub dist_tags_given: bool,
}

fn object<'a>(doc: &'a Value, key: &str) -> Option<&'a Map<String, Value>> {
    doc.get(key).and_then(Value::as_object)
}

/// Check that a document's `name` (and `_id`, when present) is `name`.
fn check_name(doc: &Value, name: &PackageName) -> Result<(), String> {
    let expected = name.to_string();
    match doc.get("name").and_then(Value::as_str) {
        Some(n) if n == expected => {}
        Some(n) => {
            return Err(format!(
                "the document names package {n:?}, not {expected:?}"
            ))
        }
        None => return Err("the document has no name".into()),
    }
    if let Some(id) = doc.get("_id").and_then(Value::as_str) {
        if id != expected {
            return Err(format!("the document's _id {id:?} is not {expected:?}"));
        }
    }
    Ok(())
}

/// Read a publish document (its attachment's data extracted already) of
/// package `name`, which the URL named.
pub fn read_publish(doc: &Value, name: &PackageName) -> Result<PublishDocument, String> {
    if !doc.is_object() {
        return Err("the document is not a JSON object".into());
    }
    check_name(doc, name)?;
    let versions = object(doc, "versions").ok_or("the document has no versions")?;
    let [(version_original, manifest)] = versions.iter().collect::<Vec<_>>()[..] else {
        return Err("a publish carries exactly one version".into());
    };
    let manifest = manifest
        .as_object()
        .ok_or("the version is not a JSON object")?;
    let version = version::normalize(version_original)
        .map_err(|e| format!("invalid version {version_original:?}: {e}"))?;
    match manifest.get("version").and_then(Value::as_str) {
        Some(v) if version::normalize(v).as_deref() == Ok(version.as_str()) => {}
        _ => {
            return Err(format!(
                "the manifest of {version_original:?} names another version"
            ))
        }
    }
    match manifest.get("name").and_then(Value::as_str) {
        Some(n) if n == name.to_string() => {}
        _ => return Err("the version's manifest names another package".into()),
    }
    let attachments = object(doc, "_attachments").ok_or("the document attaches no tarball")?;
    let [(attachment, meta)] = attachments.iter().collect::<Vec<_>>()[..] else {
        return Err("a publish attaches exactly one tarball".into());
    };
    let length = meta.get("length").and_then(Value::as_u64);
    let dist_tags = object(doc, "dist-tags")
        .map(|tags| {
            tags.iter()
                .filter(|(tag, _)| valid_tag(tag))
                .filter(|(_, v)| {
                    v.as_str()
                        .is_some_and(|v| version::normalize(v).as_deref() == Ok(version.as_str()))
                })
                .map(|(t, _)| t.clone())
                .collect()
        })
        .unwrap_or_default();
    Ok(PublishDocument {
        name: name.clone(),
        version,
        version_original: version_original.clone(),
        manifest: manifest.clone(),
        dist_tags,
        attachment: attachment.clone(),
        length,
        readme: doc
            .get("readme")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Read a packument update of package `name`.
pub fn read_update(doc: &Value, name: &PackageName) -> Result<UpdateDocument, String> {
    if !doc.is_object() {
        return Err("the document is not a JSON object".into());
    }
    check_name(doc, name)?;
    let mut out = UpdateDocument::default();
    for (raw, manifest) in object(doc, "versions").into_iter().flatten() {
        let version =
            version::normalize(raw).map_err(|e| format!("invalid version {raw:?}: {e}"))?;
        let deprecated = manifest
            .get("deprecated")
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty())
            .map(str::to_string);
        out.versions.insert(version, deprecated);
    }
    out.dist_tags_given = doc.get("dist-tags").is_some_and(Value::is_object);
    for (tag, v) in object(doc, "dist-tags").into_iter().flatten() {
        if !valid_tag(tag) {
            continue;
        }
        if let Some(v) = v.as_str().and_then(|v| version::normalize(v).ok()) {
            out.dist_tags.insert(tag.clone(), v);
        }
    }
    Ok(out)
}

/// The version a publish stores: its manifest, completed from the tarball.
#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    /// The manifest stored (README included): the version object, with the
    /// `dist` the registry computes from the tarball, `_id`, `_npmUser` and
    /// `hasInstallScript`.
    pub manifest: Map<String, Value>,
    pub digests: Digests,
}

/// Check the staged `tarball` against the publish `doc` and build the
/// manifest to store. `publisher` is the account publishing it.
pub fn release<R: Read + Seek + ?Sized>(
    doc: &PublishDocument,
    tarball: &mut R,
    publisher: Option<&str>,
    max_unpacked: u64,
) -> Result<Release, String> {
    let digests = Digests::of(&mut *tarball).map_err(|e| format!("read the tarball: {e}"))?;
    if let Some(length) = doc.length {
        if length != digests.size {
            return Err(format!(
                "the attachment's length is {length}, but its data is {} bytes",
                digests.size
            ));
        }
    }
    let dist = doc.manifest.get("dist").and_then(Value::as_object);
    let claimed = |key: &str| dist.and_then(|d| d.get(key)).and_then(Value::as_str);
    digests.verify(claimed("integrity"), claimed("shasum"))?;
    tarball
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("read the tarball: {e}"))?;
    let tarball = tarball::read(&mut *tarball, max_unpacked)?;
    if tarball.name != doc.name.to_string() {
        return Err(format!(
            "the tarball's package.json names package {:?}, not {:?}",
            tarball.name,
            doc.name.to_string()
        ));
    }
    if version::normalize(&tarball.version).as_deref() != Ok(doc.version.as_str()) {
        return Err(format!(
            "the tarball's package.json is version {:?}, not {:?}",
            tarball.version, doc.version
        ));
    }

    let mut manifest = doc.manifest.clone();
    manifest.insert("name".into(), Value::String(doc.name.to_string()));
    manifest.insert("version".into(), Value::String(doc.version.clone()));
    manifest.insert(
        "_id".into(),
        Value::String(format!("{}@{}", doc.name, doc.version)),
    );
    let mut dist = dist.cloned().unwrap_or_default();
    dist.remove("tarball");
    dist.insert("integrity".into(), Value::String(digests.integrity()));
    dist.insert("shasum".into(), Value::String(digests.sha1_hex.clone()));
    dist.insert("fileCount".into(), Value::from(tarball.file_count));
    dist.insert("unpackedSize".into(), Value::from(tarball.unpacked_size));
    manifest.insert("dist".into(), Value::Object(dist));
    if crate::manifest::has_install_script(&manifest) {
        manifest.insert("hasInstallScript".into(), Value::Bool(true));
    }
    if !manifest.contains_key("readme") {
        if let Some(readme) = &doc.readme {
            manifest.insert("readme".into(), Value::String(readme.clone()));
        }
    }
    if let Some(publisher) = publisher {
        let user = serde_json::json!({ "name": publisher });
        manifest.insert("_npmUser".into(), user.clone());
        if !manifest.get("maintainers").is_some_and(Value::is_array) {
            manifest.insert("maintainers".into(), Value::Array(vec![user]));
        }
    }
    Ok(Release { manifest, digests })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn name() -> PackageName {
        PackageName::parse("@acme/a").unwrap()
    }

    fn doc(tarball: &[u8]) -> Value {
        let d = Digests::of(tarball).unwrap();
        json!({
            "_id": "@acme/a", "name": "@acme/a",
            "dist-tags": {"latest": "1.0.0", "beta": "1.0.0", "other": "0.1.0"},
            "versions": {"1.0.0": {
                "name": "@acme/a", "version": "1.0.0", "scripts": {"install": "node-gyp rebuild"},
                "dist": {"integrity": d.integrity(), "shasum": d.sha1_hex, "tarball": "http://x"}
            }},
            "_attachments": {"@acme/a-1.0.0.tgz": {"content_type": "application/octet-stream", "data": "", "length": tarball.len()}},
            "readme": "# A"
        })
    }

    fn staged(bytes: &[u8]) -> std::io::Cursor<Vec<u8>> {
        std::io::Cursor::new(bytes.to_vec())
    }

    #[test]
    fn reads_and_releases_a_publish() {
        let tgz = tarball::build(&[(
            "package/package.json",
            br#"{"name":"@acme/a","version":"1.0.0"}"#,
        )]);
        let parsed = read_publish(&doc(&tgz), &name()).unwrap();
        assert_eq!(parsed.version, "1.0.0");
        assert_eq!(parsed.attachment, "@acme/a-1.0.0.tgz");
        assert_eq!(parsed.dist_tags, ["beta", "latest"]);
        let mut file = staged(&tgz);
        let release = release(&parsed, &mut file, Some("alice@example.com"), 1 << 20).unwrap();
        let m = &release.manifest;
        assert_eq!(m["_id"], "@acme/a@1.0.0");
        assert_eq!(m["readme"], "# A");
        assert_eq!(m["hasInstallScript"], true);
        assert_eq!(m["_npmUser"], json!({"name": "alice@example.com"}));
        assert_eq!(m["dist"]["integrity"], release.digests.integrity());
        assert_eq!(m["dist"]["fileCount"], 1);
        assert!(m["dist"].get("tarball").is_none());
    }

    #[test]
    fn refuses_a_tarball_that_is_not_the_version() {
        let tgz = tarball::build(&[(
            "package/package.json",
            br#"{"name":"@acme/a","version":"1.0.0"}"#,
        )]);
        let other = tarball::build(&[(
            "package/package.json",
            br#"{"name":"@acme/a","version":"2.0.0"}"#,
        )]);
        let parsed = read_publish(&doc(&tgz), &name()).unwrap();
        // Bytes other than the integrity claims.
        let mut file = staged(&other);
        let err = release(&parsed, &mut file, None, 1 << 20).unwrap_err();
        assert!(
            err.contains("does not match") || err.contains("length"),
            "{err}"
        );
        // A tarball of another version, with matching digests.
        let parsed = read_publish(&doc(&other), &name()).unwrap();
        let mut file = staged(&other);
        let err = release(&parsed, &mut file, None, 1 << 20).unwrap_err();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn refuses_documents_of_another_shape() {
        let tgz = tarball::build(&[(
            "package/package.json",
            br#"{"name":"@acme/a","version":"1.0.0"}"#,
        )]);
        let mut d = doc(&tgz);
        d["name"] = json!("@acme/b");
        assert!(read_publish(&d, &name()).is_err());
        let mut d = doc(&tgz);
        d["versions"]["1.1.0"] = json!({"name": "@acme/a", "version": "1.1.0"});
        assert!(read_publish(&d, &name()).is_err());
        let mut d = doc(&tgz);
        d["versions"]["1.0.0"]["version"] = json!("1.0.1");
        assert!(read_publish(&d, &name()).is_err());
        let mut d = doc(&tgz);
        d["_attachments"] = json!({});
        assert!(read_publish(&d, &name()).is_err());
    }

    #[test]
    fn dist_tags_are_words() {
        for ok in ["latest", "next", "beta-2", "rc.1", "v-next", "legacy_1"] {
            assert!(valid_tag(ok), "{ok}");
        }
        for bad in [
            "",
            "1.x",
            "1",
            "v2",
            "x",
            "X",
            "^1",
            "~1",
            ">=1",
            "a b",
            "a/b",
            &"a".repeat(65),
        ] {
            assert!(!valid_tag(bad), "{bad}");
        }
    }

    #[test]
    fn reads_an_update() {
        let d = json!({
            "name": "@acme/a", "_rev": "3-x",
            "versions": {"1.0.0": {"deprecated": "use 2"}, "2.0.0": {"deprecated": ""}},
            "dist-tags": {"latest": "2.0.0"}
        });
        let u = read_update(&d, &name()).unwrap();
        assert_eq!(u.versions["1.0.0"].as_deref(), Some("use 2"));
        assert_eq!(u.versions["2.0.0"], None);
        assert_eq!(u.dist_tags["latest"], "2.0.0");
        assert!(read_update(&json!({"name": "x"}), &name()).is_err());
    }
}
