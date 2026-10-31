//! The upstream side of npm proxies ([`FormatPlugin::upstream`]): reading
//! another registry's packuments, tarball locations and search.
//!
//! A package's listing, its tags, its tarballs and its versions' summaries
//! come from the abbreviated packument (`application/vnd.npm.install-v1+json`,
//! what installs read: much smaller than the full document). A version's
//! manifest (with the README of `latest`) and the publish times the package
//! delay counts from come from the full one. Both are fetched for the
//! repository's metadata TTL, and each operation reads only what it needs of
//! them ([`upstream::Select`]). A tarball is downloaded from where the
//! packument says, and the host checks it against the packument's
//! `dist.integrity` and `dist.shasum`.
//!
//! When the upstream cannot serve the full packument (most often: it is
//! larger than `proxy.max_metadata_bytes`, as `vite`'s is with a copy of its
//! license in each of its versions), the publish times come from nowhere
//! and the summaries from the abbreviated packument, and a manifest comes
//! from the version's own document (`{remote}/{name}/{version}`), without a
//! README.
//!
//! [`FormatPlugin::upstream`]: forge_plugin_api::FormatPlugin::upstream

use std::collections::HashSet;

use forge_plugin_api::{
    Fetch, FetchResult, Fetched, Freshness, PackageLocation, PackageMetadata, PackageRef, Remote,
    SearchQuery, Tag, UpstreamAnswer, UpstreamHit, UpstreamOp, UpstreamSearch, UpstreamStep,
    VersionMetadata,
};
use serde_json::{Map, Value};

use crate::packument::{timestamp, LATEST};
use crate::upstream::{self, Keep, Kept, Select, UpstreamPackument};
use crate::{manifest, version, PackageName};

/// What a proxy asks for when it wants abbreviated metadata (as npm does).
pub const ABBREVIATED_ACCEPT: &str =
    "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

/// What it asks for when it wants the full document.
pub const FULL_ACCEPT: &str = "application/json";

fn done(answer: UpstreamAnswer) -> UpstreamStep {
    UpstreamStep::Done(answer)
}

fn failed(reason: impl Into<String>) -> UpstreamStep {
    done(UpstreamAnswer::Failed(reason.into()))
}

/// The upstream's packument of `id`: `{remote}/{escaped name}`.
fn packument_fetch(remote: &Remote, id: &str, full: bool) -> Option<Fetch> {
    let name = PackageName::parse(id).ok()?;
    let url = format!("{}/{}", remote.url.trim_end_matches('/'), name.escaped());
    let accept = if full {
        FULL_ACCEPT
    } else {
        ABBREVIATED_ACCEPT
    };
    Some(Fetch::new(url, Freshness::Metadata).accepting(accept))
}

/// The upstream's object of one version of a package,
/// `{remote}/{escaped name}/{version}`: a few KiB where the full packument
/// may be tens of MiB.
fn version_fetch(remote: &Remote, target: &PackageRef) -> Option<Fetch> {
    let name = PackageName::parse(&target.id).ok()?;
    let url = format!(
        "{}/{}/{}",
        remote.url.trim_end_matches('/'),
        name.escaped(),
        target.version
    );
    Some(Fetch::new(url, Freshness::Metadata).accepting(FULL_ACCEPT))
}

/// How `fetch` went, if it was sent.
fn outcome<'a>(fetched: &'a [FetchResult], fetch: &Fetch) -> Option<&'a Fetched> {
    fetched
        .iter()
        .find(|f| &f.fetch == fetch)
        .map(|f| &f.outcome)
}

/// Where the packument of a package stands in a conversation.
enum Packument {
    /// Not fetched yet: fetch it.
    Fetch(Fetch),
    /// The upstream does not know the package.
    NotFound,
    /// The fetch failed: the upstream is down or refuses the proxy, or the
    /// document is larger than the host reads.
    Unfetched(String),
    /// What the upstream answered is no packument of the package.
    Failed(String),
    Found(UpstreamPackument),
}

/// What `select` asks for of the packument of `id` (full or abbreviated).
fn packument(
    remote: &Remote,
    id: &str,
    full: bool,
    fetched: &[FetchResult],
    select: Select<'_>,
) -> Packument {
    let Some(fetch) = packument_fetch(remote, id, full) else {
        return Packument::Failed(format!("{id:?} is not a package name"));
    };
    match outcome(fetched, &fetch) {
        None => Packument::Fetch(fetch),
        Some(Fetched::NotFound) => Packument::NotFound,
        Some(Fetched::Failed(reason)) => Packument::Unfetched(reason.clone()),
        Some(Fetched::Found(body)) => match upstream::read(&body[..], select) {
            Ok(doc) if doc.name.is_empty() || doc.name == id => Packument::Found(doc),
            Ok(doc) => Packument::Failed(format!(
                "the upstream answered package {:?} for {id:?}",
                doc.name
            )),
            Err(e) => Packument::Failed(format!("the upstream's packument of {id}: {e}")),
        },
    }
}

/// Answer from `packument`: fetch it first, then hand it to `answer`
/// (`None` when the upstream does not know the package).
fn answer_from(
    packument: Packument,
    answer: impl FnOnce(Option<UpstreamPackument>) -> UpstreamStep,
) -> UpstreamStep {
    match packument {
        Packument::Fetch(fetch) => UpstreamStep::Fetch(vec![fetch]),
        Packument::NotFound => answer(None),
        Packument::Unfetched(reason) | Packument::Failed(reason) => failed(reason),
        Packument::Found(doc) => answer(Some(doc)),
    }
}

/// Answer `op` from what `select` asks for of the packument of `id` (full
/// or abbreviated).
fn with_packument(
    remote: &Remote,
    id: &str,
    full: bool,
    fetched: &[FetchResult],
    select: Select<'_>,
    answer: impl FnOnce(Option<UpstreamPackument>) -> UpstreamStep,
) -> UpstreamStep {
    answer_from(packument(remote, id, full, fetched, select), answer)
}

/// The SHA-512 of an SRI `integrity` (`sha512-<base64>`), if it has one.
fn sha512_of(integrity: &str) -> Option<String> {
    integrity
        .split_whitespace()
        .find_map(|sri| sri.strip_prefix("sha512-"))
        .map(|b64| b64.split('?').next().unwrap_or(b64).to_string())
}

/// `s` percent-encoded for a query string.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// One round of the upstream conversation for `op`.
pub fn upstream(remote: &Remote, op: &UpstreamOp, fetched: &[FetchResult]) -> UpstreamStep {
    match op {
        // A registry needs no index: packuments are at fixed URLs.
        UpstreamOp::Index => done(UpstreamAnswer::Index("{}".into())),
        UpstreamOp::Versions(id) => {
            with_packument(remote, id, false, fetched, Select::default(), |doc| {
                done(UpstreamAnswer::Versions(doc.map(|doc| {
                    doc.versions().into_iter().map(|v| v.version).collect()
                })))
            })
        }
        UpstreamOp::Tags(id) => {
            with_packument(remote, id, false, fetched, Select::default(), |doc| {
                done(UpstreamAnswer::Tags(doc.map(|doc| {
                    doc.normalized_dist_tags()
                        .into_iter()
                        .map(|(name, version)| Tag { name, version })
                        .collect()
                })))
            })
        }
        UpstreamOp::Package(target) => with_packument(
            remote,
            &target.id,
            false,
            fetched,
            Select {
                versions: std::slice::from_ref(&target.version),
                ..Select::default()
            },
            |doc| {
                let Some(doc) = doc else {
                    return failed(format!("the upstream has no package {}", target.id));
                };
                let Some(v) = doc.version(&target.version) else {
                    return failed(format!(
                        "the upstream has no version {} of {}",
                        target.version, target.id
                    ));
                };
                match v.tarball() {
                    Some(url) if url.starts_with("https://") || url.starts_with("http://") => {
                        done(UpstreamAnswer::Located(PackageLocation {
                            url: url.to_string(),
                            sha512: v.integrity().and_then(sha512_of),
                            sha1: v.shasum().map(str::to_ascii_lowercase),
                        }))
                    }
                    _ => failed(format!(
                        "the upstream names no tarball of {} {}",
                        target.id, target.version
                    )),
                }
            },
        ),
        UpstreamOp::Manifest(target) => {
            let select = Select {
                versions: std::slice::from_ref(&target.version),
                keep: Keep::Manifest,
                readme: true,
                ..Select::default()
            };
            match packument(remote, &target.id, true, fetched, select) {
                Packument::Unfetched(reason) => version_manifest(remote, target, fetched, reason),
                packument => answer_from(packument, |doc| {
                    done(UpstreamAnswer::Manifest(
                        doc.and_then(|doc| manifest_of(&doc, target)),
                    ))
                }),
            }
        }
        UpstreamOp::Metadata(set) => {
            let select = Select {
                versions: &set.versions,
                keep: Keep::Summary,
                ..Select::default()
            };
            with_packument(remote, &set.id, false, fetched, select, |doc| {
                done(UpstreamAnswer::Metadata(metadata(doc, &set.versions)))
            })
        }
        UpstreamOp::Dating(set) => {
            let select = Select {
                versions: &set.versions,
                keep: Keep::Summary,
                time: true,
                ..Select::default()
            };
            let answer = |doc| done(UpstreamAnswer::Metadata(metadata(doc, &set.versions)));
            match packument(remote, &set.id, true, fetched, select) {
                // The summaries without the publish times, from the
                // abbreviated packument.
                Packument::Unfetched(reason) => {
                    match packument(remote, &set.id, false, fetched, select) {
                        Packument::Unfetched(again) | Packument::Failed(again) => {
                            failed(format!("{reason}; the abbreviated packument: {again}"))
                        }
                        packument => answer_from(packument, answer),
                    }
                }
                packument => answer_from(packument, answer),
            }
        }
        UpstreamOp::Search(query) => search(remote, query, fetched),
        // No import walks an npm registry yet.
        UpstreamOp::Packages { .. } => done(UpstreamAnswer::Search(None)),
        // A registry holds packages: it has no files to fetch.
        UpstreamOp::File(_) => done(UpstreamAnswer::File(None)),
        UpstreamOp::ImageName(_)
        | UpstreamOp::ImageManifest { .. }
        | UpstreamOp::ImageBlob { .. }
        | UpstreamOp::ImageTags { .. }
        | UpstreamOp::ImageReferrers { .. }
        | UpstreamOp::ImageCatalog { .. } => failed("a registry of packages holds no images"),
    }
}

/// A version's manifest, the README of `latest` with it, when the upstream
/// has exactly that version of that package.
fn manifest_of(doc: &UpstreamPackument, target: &PackageRef) -> Option<Vec<u8>> {
    let manifest = doc.version(&target.version)?.manifest()?.clone();
    let latest = doc.normalized_dist_tags().get(LATEST).cloned();
    let readme = doc
        .readme
        .as_deref()
        .filter(|_| latest.as_deref() == Some(target.version.as_str()));
    checked(manifest, target, readme)
}

/// `manifest`, with `readme` unless it has its own, when it is exactly
/// `target`'s.
fn checked(
    mut manifest: Map<String, Value>,
    target: &PackageRef,
    readme: Option<&str>,
) -> Option<Vec<u8>> {
    if manifest.get("name").and_then(Value::as_str) != Some(target.id.as_str()) {
        return None;
    }
    if version::normalize(manifest.get("version")?.as_str()?).ok()? != target.version {
        return None;
    }
    if let Some(readme) = readme.filter(|_| !manifest.contains_key("readme")) {
        manifest.insert("readme".into(), Value::String(readme.to_string()));
    }
    serde_json::to_vec(&manifest).ok()
}

/// The manifest of `target` from its version's own document, where the
/// upstream could not serve the full packument (`reason`): without a
/// README, which only the packument has. `None` when the upstream does not
/// serve the document, and the host reads the manifest from the package.
fn version_manifest(
    remote: &Remote,
    target: &PackageRef,
    fetched: &[FetchResult],
    reason: String,
) -> UpstreamStep {
    let Some(fetch) = version_fetch(remote, target) else {
        return failed(reason);
    };
    match outcome(fetched, &fetch) {
        None => UpstreamStep::Fetch(vec![fetch]),
        Some(Fetched::NotFound) => done(UpstreamAnswer::Manifest(None)),
        Some(Fetched::Failed(again)) => failed(format!("{reason}; {again}")),
        Some(Fetched::Found(body)) => match upstream::read_manifest(&body[..]) {
            Ok(manifest) => done(UpstreamAnswer::Manifest(checked(manifest, target, None))),
            Err(e) => failed(format!(
                "{reason}; the upstream's {} {}: {e}",
                target.id, target.version
            )),
        },
    }
}

/// The metadata of `wanted` versions: their summaries, and when the
/// upstream published them if the packument's times were read.
fn metadata(doc: Option<UpstreamPackument>, wanted: &[String]) -> PackageMetadata {
    let Some(mut doc) = doc else {
        return PackageMetadata::default();
    };
    let original_id = (!doc.name.is_empty()).then(|| doc.name.clone());
    let wanted: HashSet<&str> = wanted.iter().map(String::as_str).collect();
    let chosen: Vec<(String, String, Option<String>)> = doc
        .versions()
        .into_iter()
        .filter(|v| wanted.contains(v.version.as_str()))
        .map(|v| {
            (
                v.original.to_string(),
                v.version,
                v.published.map(timestamp),
            )
        })
        .collect();
    PackageMetadata {
        original_id: original_id.clone(),
        versions: chosen
            .into_iter()
            .map(|(original, version, time)| {
                // Taken out of the packument: summaries are most of it.
                let summary = match doc.versions.remove(&original) {
                    Some(Kept::Summary(summary)) => Some(summary),
                    Some(Kept::Manifest(m)) => {
                        serde_json::to_string(&manifest::into_summary(m)).ok()
                    }
                    Some(Kept::Listed) | None => None,
                };
                VersionMetadata {
                    original_id: original_id.clone(),
                    listed: true,
                    published: time.clone(),
                    created: time,
                    summary,
                    version,
                    // npm's integrity is checked from the version's dist
                    // when its tarball is located, not here.
                    sha512: None,
                }
            })
            .collect(),
    }
}

/// A page of the upstream's `/-/v1/search`.
fn search(remote: &Remote, query: &SearchQuery, fetched: &[FetchResult]) -> UpstreamStep {
    let take = match query.take {
        0 => 20,
        n => n.min(250),
    };
    let url = format!(
        "{}/-/v1/search?text={}&size={take}&from={}",
        remote.url.trim_end_matches('/'),
        encode(&query.text),
        query.skip
    );
    let fetch = Fetch::new(url, Freshness::Metadata).accepting(FULL_ACCEPT);
    let body = match outcome(fetched, &fetch) {
        None => return UpstreamStep::Fetch(vec![fetch]),
        Some(Fetched::NotFound) => return done(UpstreamAnswer::Search(None)),
        Some(Fetched::Failed(reason)) => return failed(reason.clone()),
        Some(Fetched::Found(body)) => body,
    };
    let Ok(page) = serde_json::from_slice::<Value>(body) else {
        return failed("the upstream's search answer is not JSON");
    };
    let hits = page
        .get("objects")
        .and_then(Value::as_array)
        .map(|objects| {
            objects
                .iter()
                .filter_map(|object| {
                    let package = object.get("package")?.as_object()?;
                    let id = package.get("name")?.as_str()?;
                    PackageName::parse(id).ok()?;
                    let latest = version::normalize(package.get("version")?.as_str()?).ok()?;
                    Some(UpstreamHit {
                        id: id.to_string(),
                        versions: vec![latest],
                        summary: serde_json::to_string(package).ok(),
                        total_downloads: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    done(UpstreamAnswer::Search(Some(UpstreamSearch {
        total: page.get("total").and_then(Value::as_u64).unwrap_or(0),
        hits,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_plugin_api::testing::converse;
    use forge_plugin_api::FormatPlugin;
    use serde_json::json;

    fn remote() -> Remote {
        Remote {
            url: "https://registry.example.com/".into(),
            index: Some("{}".into()),
            options: Vec::new(),
        }
    }

    fn doc() -> Value {
        json!({
            "name": "@acme/ui",
            "dist-tags": {"latest": "1.1.0", "next": "2.0.0-rc.1"},
            "time": {"1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2021-01-01T00:00:00.000Z"},
            "readme": "# UI",
            "versions": {
                "1.0.0": {"name": "@acme/ui", "version": "1.0.0", "dist": {"tarball": "https://cdn.example.com/ui-1.0.0.tgz", "integrity": "sha512-AAAA", "shasum": "ABCD"}},
                "1.1.0": {"name": "@acme/ui", "version": "1.1.0", "dependencies": {"b": "^1"}, "dist": {"tarball": "https://cdn.example.com/ui-1.1.0.tgz"}},
                "2.0.0-rc.1": {"name": "@acme/ui", "version": "2.0.0-rc.1", "dist": {}}
            }
        })
    }

    fn found(fetch: &Fetch) -> Fetched {
        assert_eq!(fetch.url, "https://registry.example.com/@acme%2fui");
        Fetched::Found(serde_json::to_vec(&doc()).unwrap())
    }

    fn run(op: UpstreamOp) -> (UpstreamAnswer, Vec<Fetch>) {
        let conversed = converse(&crate::Npm::default(), &remote(), &op, found).unwrap();
        (conversed.answer, conversed.fetches)
    }

    #[test]
    fn lists_versions_and_tags_from_the_abbreviated_packument() {
        let (answer, fetches) = run(UpstreamOp::Versions("@acme/ui".into()));
        assert_eq!(
            answer,
            UpstreamAnswer::Versions(Some(vec![
                "1.0.0".into(),
                "1.1.0".into(),
                "2.0.0-rc.1".into()
            ]))
        );
        assert_eq!(fetches[0].accept.as_deref(), Some(ABBREVIATED_ACCEPT));
        let (answer, _) = run(UpstreamOp::Tags("@acme/ui".into()));
        let UpstreamAnswer::Tags(Some(tags)) = answer else {
            panic!("{answer:?}")
        };
        assert!(tags.contains(&Tag {
            name: "next".into(),
            version: "2.0.0-rc.1".into()
        }));
    }

    #[test]
    fn locates_tarballs_with_their_digests() {
        let (answer, _) = run(UpstreamOp::Package(PackageRef {
            id: "@acme/ui".into(),
            version: "1.0.0".into(),
        }));
        assert_eq!(
            answer,
            UpstreamAnswer::Located(PackageLocation {
                url: "https://cdn.example.com/ui-1.0.0.tgz".into(),
                sha512: Some("AAAA".into()),
                sha1: Some("abcd".into()),
            })
        );
        let (answer, _) = run(UpstreamOp::Package(PackageRef {
            id: "@acme/ui".into(),
            version: "2.0.0-rc.1".into(),
        }));
        assert!(matches!(answer, UpstreamAnswer::Failed(_)), "{answer:?}");
    }

    #[test]
    fn manifests_carry_the_readme_of_latest_only() {
        let (answer, fetches) = run(UpstreamOp::Manifest(PackageRef {
            id: "@acme/ui".into(),
            version: "1.1.0".into(),
        }));
        assert_eq!(fetches[0].accept.as_deref(), Some(FULL_ACCEPT));
        let UpstreamAnswer::Manifest(Some(manifest)) = answer else {
            panic!("{answer:?}")
        };
        assert_eq!(
            crate::Npm::default().readme(&manifest).as_deref(),
            Some("# UI")
        );
        let (answer, _) = run(UpstreamOp::Manifest(PackageRef {
            id: "@acme/ui".into(),
            version: "1.0.0".into(),
        }));
        let UpstreamAnswer::Manifest(Some(manifest)) = answer else {
            panic!("{answer:?}")
        };
        assert_eq!(crate::Npm::default().readme(&manifest), None);
    }

    #[test]
    fn dates_versions_for_the_package_delay() {
        let (answer, _) = run(UpstreamOp::Dating(forge_plugin_api::PackageVersions {
            id: "@acme/ui".into(),
            versions: vec!["1.1.0".into()],
        }));
        let UpstreamAnswer::Metadata(metadata) = answer else {
            panic!("{answer:?}")
        };
        assert_eq!(metadata.versions.len(), 1);
        assert_eq!(
            metadata.versions[0].created.as_deref(),
            Some("2021-01-01T00:00:00.000Z")
        );
        assert!(metadata.versions[0]
            .summary
            .as_deref()
            .unwrap()
            .contains("dependency_groups"));
    }

    #[test]
    fn an_unknown_package_is_none() {
        let conversed = converse(
            &crate::Npm::default(),
            &remote(),
            &UpstreamOp::Versions("left-pad".into()),
            |_| Fetched::NotFound,
        )
        .unwrap();
        assert_eq!(conversed.answer, UpstreamAnswer::Versions(None));
    }

    /// The upstream as [`found`] serves it, but for a full packument larger
    /// than the host reads, an abbreviated one without publish times (as
    /// npmjs serves it), and the object of each version on its own.
    fn too_large(fetch: &Fetch) -> Fetched {
        let Some(version) = fetch
            .url
            .strip_prefix("https://registry.example.com/@acme%2fui/")
        else {
            return match fetch.accept.as_deref() {
                Some(FULL_ACCEPT) => Fetched::Failed(format!(
                    "upstream response from {} exceeds 33554432 bytes",
                    fetch.url
                )),
                _ => {
                    let mut abbreviated = doc();
                    abbreviated.as_object_mut().unwrap().remove("time");
                    Fetched::Found(serde_json::to_vec(&abbreviated).unwrap())
                }
            };
        };
        match doc()["versions"].get(version) {
            Some(object) => Fetched::Found(serde_json::to_vec(object).unwrap()),
            None => Fetched::NotFound,
        }
    }

    #[test]
    fn a_full_packument_the_host_cannot_read_dates_nothing() {
        let conversed = converse(
            &crate::Npm::default(),
            &remote(),
            &UpstreamOp::Dating(forge_plugin_api::PackageVersions {
                id: "@acme/ui".into(),
                versions: vec!["1.0.0".into(), "1.1.0".into()],
            }),
            too_large,
        )
        .unwrap();
        let accepts: Vec<Option<&str>> = conversed
            .fetches
            .iter()
            .map(|f| f.accept.as_deref())
            .collect();
        assert_eq!(accepts, [Some(FULL_ACCEPT), Some(ABBREVIATED_ACCEPT)]);
        // The summaries still, from the abbreviated packument.
        let UpstreamAnswer::Metadata(metadata) = conversed.answer else {
            panic!("{:?}", conversed.answer)
        };
        assert_eq!(metadata.versions.len(), 2);
        assert!(metadata.versions.iter().all(|v| v.created.is_none()));
        assert!(metadata.versions[1]
            .summary
            .as_deref()
            .unwrap()
            .contains("dependency_groups"));

        // Unless the upstream fails both.
        let conversed = converse(
            &crate::Npm::default(),
            &remote(),
            &UpstreamOp::Dating(forge_plugin_api::PackageVersions {
                id: "@acme/ui".into(),
                versions: vec!["1.0.0".into()],
            }),
            |_| Fetched::Failed("down".into()),
        )
        .unwrap();
        assert_eq!(
            conversed.answer,
            UpstreamAnswer::Failed("down; the abbreviated packument: down".into())
        );
    }

    #[test]
    fn a_full_packument_the_host_cannot_read_has_manifests_without_readme() {
        let manifest = |version: &str| {
            let conversed = converse(
                &crate::Npm::default(),
                &remote(),
                &UpstreamOp::Manifest(PackageRef {
                    id: "@acme/ui".into(),
                    version: version.into(),
                }),
                too_large,
            )
            .unwrap();
            (conversed.answer, conversed.fetches)
        };
        let (answer, fetches) = manifest("1.1.0");
        assert_eq!(
            fetches[1].url,
            "https://registry.example.com/@acme%2fui/1.1.0"
        );
        let UpstreamAnswer::Manifest(Some(bytes)) = answer else {
            panic!("{answer:?}")
        };
        let object: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(object["dependencies"], json!({"b": "^1"}));
        assert_eq!(crate::Npm::default().readme(&bytes), None);
        // A version the upstream does not serve on its own: the host reads
        // the package.
        let (answer, _) = manifest("3.0.0");
        assert_eq!(answer, UpstreamAnswer::Manifest(None));
    }
}
