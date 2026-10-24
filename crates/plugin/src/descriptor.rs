//! What a format's [`Descriptor`] may say: a well-formed id that no other
//! format and none of the server's names takes, its repository kinds once
//! each, plain asset names and content types. A test over the server's built-in formats
//! (`plugins::builtin`) checks them, so a bad descriptor fails `cargo test`.

use forge_plugin_api::{Assets, Descriptor, Storage};

/// Format ids a plugin can never take: names the server routes or
/// reserves.
const RESERVED_IDS: &[&str] = &["v2", "admin", "browse", "auth", "repository"];

/// Check the descriptors of the formats one server holds: each on its own
/// ([`check_one`]), no two with the same id, and at most one images format
/// (the registry serves one).
pub fn check(formats: &[&Descriptor]) -> Result<(), String> {
    for (i, format) in formats.iter().enumerate() {
        check_one(format)?;
        let before = &formats[..i];
        if before.iter().any(|other| other.id == format.id) {
            return Err(format!("two formats have the id {:?}", format.id));
        }
        let images = |d: &Descriptor| d.storage == Storage::Images;
        if images(format) && before.iter().any(|other| images(other)) {
            return Err(format!(
                "format {:?}: only one format may store images",
                format.id
            ));
        }
    }
    Ok(())
}

/// Check one format's descriptor.
pub fn check_one(descriptor: &Descriptor) -> Result<(), String> {
    let id = descriptor.id;
    validate_id(id).map_err(|e| format!("format {id:?}: {e}"))?;
    if descriptor.name.trim().is_empty() {
        return Err(format!("format {id:?}: the name must not be empty"));
    }
    let kinds = descriptor.kinds;
    if kinds.is_empty() {
        return Err(format!("format {id:?}: kinds must not be empty"));
    }
    let twice = kinds
        .iter()
        .enumerate()
        .find_map(|(i, kind)| kinds[..i].contains(kind).then_some(kind));
    if let Some(kind) = twice {
        return Err(format!("format {id:?}: kind {kind:?} is listed twice"));
    }
    validate_assets(&descriptor.assets).map_err(|e| format!("format {id:?}: {e}"))
}

/// A format id: 2–32 characters of lowercase ASCII letters, digits and `-`,
/// starting with a letter, and not one of the reserved names.
pub fn validate_id(id: &str) -> Result<(), String> {
    let well_formed = (2..=32).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !well_formed {
        return Err(format!(
            "id {id:?} must be 2-32 lowercase letters, digits or '-', starting with a letter"
        ));
    }
    if RESERVED_IDS.contains(&id) {
        return Err(format!("id {id:?} is reserved"));
    }
    Ok(())
}

/// Asset names are plain file names; content types are `type/subtype`
/// (parameters allowed) in printable ASCII.
fn validate_assets(assets: &Assets) -> Result<(), String> {
    for name in [assets.package, assets.manifest] {
        let ok = (1..=64).contains(&name.len())
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !ok {
            return Err(format!(
                "asset name {name:?} must be 1-64 letters, digits, '.', '_' or '-', \
                 not starting with '.'"
            ));
        }
    }
    if assets.package == assets.manifest {
        return Err("the package and the manifest need different asset names".into());
    }
    for content_type in [assets.package_type, assets.manifest_type] {
        let essence = content_type.split(';').next().unwrap_or("").trim();
        let ok = content_type.len() <= 127
            && content_type
                .chars()
                .all(|c| c.is_ascii_graphic() || c == ' ')
            && essence
                .split_once('/')
                .is_some_and(|(t, s)| !t.is_empty() && !s.is_empty());
        if !ok {
            return Err(format!(
                "content type {content_type:?} must be type/subtype"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use forge_plugin_api::{RepositoryKind, Storage, UpstreamToken};

    use super::*;

    const GOOD: Descriptor = Descriptor {
        id: "helm",
        name: "Helm charts",
        version: "0.1.0",
        description: "Charts.",
        kinds: &[RepositoryKind::Hosted, RepositoryKind::Group],
        storage: Storage::Packages,
        assets: Assets::DEFAULT,
        upstream_token: UpstreamToken::None,
    };

    #[test]
    fn accepts_a_good_descriptor() {
        assert_eq!(check(&[&GOOD]), Ok(()));
        let with_proxies = Descriptor {
            id: "npm",
            kinds: &[RepositoryKind::Hosted, RepositoryKind::Proxy],
            storage: Storage::Files,
            ..GOOD
        };
        assert_eq!(check(&[&GOOD, &with_proxies]), Ok(()));
        assert!(validate_id("go-modules").is_ok());
    }

    #[test]
    fn refuses_bad_ids_and_reserved_names() {
        for id in [
            "",
            "h",
            "Helm",
            "1helm",
            "helm_charts",
            "v2",
            "admin",
            "repository",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let bad = Descriptor { id, ..GOOD };
            assert!(check(&[&bad]).is_err(), "{id:?} accepted");
        }
        let unnamed = Descriptor { name: " ", ..GOOD };
        assert!(check(&[&unnamed]).is_err());
    }

    #[test]
    fn refuses_two_formats_with_one_id() {
        let twin = Descriptor {
            name: "Other charts",
            ..GOOD
        };
        let err = check(&[&GOOD, &twin]).unwrap_err();
        assert!(err.contains("\"helm\""), "{err}");
    }

    #[test]
    fn refuses_bad_kinds() {
        for kinds in [
            &[][..],
            &[RepositoryKind::Hosted, RepositoryKind::Hosted][..],
        ] {
            let bad = Descriptor { kinds, ..GOOD };
            assert!(check(&[&bad]).is_err(), "{kinds:?} accepted");
        }
    }

    #[test]
    fn only_one_images_format_is_allowed() {
        let images = Descriptor {
            id: "oci",
            storage: Storage::Images,
            ..GOOD
        };
        assert_eq!(check(&[&GOOD, &images]), Ok(()));
        let second = Descriptor {
            id: "oci-two",
            ..images
        };
        let err = check(&[&images, &second]).unwrap_err();
        assert!(err.contains("only one format may store images"), "{err}");
    }

    #[test]
    fn refuses_invalid_asset_names_and_types() {
        let with = |assets: Assets| Descriptor { assets, ..GOOD };
        for assets in [
            Assets {
                package: "",
                ..Assets::DEFAULT
            },
            Assets {
                package: "../x",
                ..Assets::DEFAULT
            },
            Assets {
                package: ".hidden",
                ..Assets::DEFAULT
            },
            Assets {
                package: "manifest",
                ..Assets::DEFAULT
            },
            Assets {
                package_type: "binary",
                ..Assets::DEFAULT
            },
            Assets {
                manifest_type: "text/\u{1}",
                ..Assets::DEFAULT
            },
        ] {
            assert!(check(&[&with(assets)]).is_err(), "{assets:?} accepted");
        }
        let named = Assets {
            package: "chart.tgz",
            manifest_type: "application/yaml",
            ..Assets::DEFAULT
        };
        assert_eq!(check(&[&with(named)]), Ok(()));
    }
}
