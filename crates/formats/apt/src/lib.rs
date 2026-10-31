//! apt (Debian/Ubuntu) repositories for Forge, as a built-in format plugin:
//! what `apt-get` reads under `/repository/<repository>/`, and the uploads
//! of `.deb` packages, like Nexus' apt-hosted and apt-proxy repositories.
//!
//! [`Apt`] implements [`FormatPlugin`]:
//!
//! * **Identity.** A package is one architecture of a binary package: its
//!   id is `<name>:<architecture>` (`hello:amd64`), its version the Debian
//!   version, ordered by dpkg's rules ([`version`]).
//! * **Uploads** (hosted): `POST /` with the package as the body (Nexus'
//!   `curl --data-binary @pkg.deb`) or as a form's file, or `PUT
//!   /<file>.deb`. The package's `control` file ([`deb`], [`manifest`])
//!   says what it is; its `Section` names the component (`contrib/net` is
//!   in `contrib`, anything else in `main`).
//! * **Indexes** (hosted): the host keeps them, made by [`index`] from the
//!   repository's packages, signed with the repository's keys, and replaced
//!   all at once when the packages change. One distribution per repository,
//!   its `distribution` option.
//! * **Downloads** from `pool/` ([`layout`]), and `DELETE` of a pool file.
//! * **Proxies** ([`proxy`]) serve their upstream's files as they are.

pub mod control;
pub mod deb;
pub mod index;
pub mod layout;
pub mod manifest;
pub mod proxy;
pub mod version;

use std::cmp::Ordering;

use forge_plugin_api::{
    Action, Answer, Assets, ChangeRequest, Descriptor, FetchResult, FormatError, FormatOption,
    FormatPlugin, IndexFile, IndexInput, Loaded, PackageRef, PackageSource, ParsedPackage,
    Prereleases, PublishRequest, Query, Remote, Repository, RepositoryKind, Request, Response,
    Storage, Upload, UpstreamAnswer, UpstreamOp, UpstreamStep, UpstreamToken, VersionClass,
};

use crate::layout::{PoolPath, Target, KEY_ASC, KEY_GPG};
use crate::manifest::{Control, Summary};

/// The option naming a repository's distribution.
pub const DISTRIBUTION: &str = "distribution";

/// What apt says about itself: its format id, name and version.
pub const DESCRIPTOR: Descriptor = Descriptor {
    id: "apt",
    name: "apt (Debian/Ubuntu)",
    version: env!("CARGO_PKG_VERSION"),
    description: "apt repositories for Debian and Ubuntu: upload .deb packages, signed indexes, \
                  installs and upgrades with apt-get; proxies of Debian and Ubuntu mirrors.",
    kinds: &[RepositoryKind::Hosted, RepositoryKind::Proxy],
    storage: Storage::Packages,
    assets: Assets {
        package: "package.deb",
        package_type: "application/vnd.debian.binary-package",
        manifest: "control",
        manifest_type: "text/plain; charset=utf-8",
    },
    upstream_token: UpstreamToken::None,
    options: &[FormatOption {
        name: DISTRIBUTION,
        label: "Distribution",
        description: "The distribution clients name in sources.list (bookworm, jammy): a hosted \
                      repository publishes its packages as this distribution, a proxy serves \
                      this one of its upstream's.",
        kinds: &[RepositoryKind::Hosted, RepositoryKind::Proxy],
        required: true,
        example: "bookworm",
    }],
    // A `-` starts the Debian revision (`1.0-1`), it marks no prerelease.
    prereleases: Prereleases::None,
    indexes: true,
};

/// The apt format.
#[derive(Debug, Clone, Copy, Default)]
pub struct Apt;

impl FormatPlugin for Apt {
    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }

    fn canonical_id(&self, id: &str) -> String {
        id.to_ascii_lowercase()
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        match layout::split_id(id) {
            Some(_) => Ok(()),
            None => Err(FormatError::InvalidId(format!(
                "{id:?} is not <package>:<architecture>"
            ))),
        }
    }

    fn normalize_version(&self, version: &str) -> Result<String, FormatError> {
        version::normalize(version).map_err(|e| FormatError::InvalidVersion(e.to_string()))
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        version::compare(a, b)
    }

    // Every version is a release: a `-` starts the Debian revision. (A
    // package id is `<name>:<architecture>`, so retention's keep-N counts
    // per architecture without a partition of its own.)
    fn version_class(&self, _version: &str) -> VersionClass {
        VersionClass::Release
    }

    fn parse_package(&self, package: &mut dyn PackageSource) -> Result<ParsedPackage, FormatError> {
        let bytes = deb::control_file(package).map_err(|e| match e {
            deb::DebError::Invalid(m) => FormatError::InvalidPackage(m),
            deb::DebError::Io(e) => FormatError::Internal(format!("read the package: {e}")),
        })?;
        let control = Control::parse(&bytes)?;
        let id = layout::package_id(&control.name, &control.architecture);
        Ok(ParsedPackage {
            original_id: id.clone(),
            id,
            version: self.normalize_version(&control.version)?,
            version_original: control.version.clone(),
            listed: true,
            dependencies: control.dependencies(),
            manifest: bytes,
        })
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<String> {
        manifest::summarize(manifest)
    }

    fn check_option(
        &self,
        _kind: RepositoryKind,
        name: &str,
        value: &str,
    ) -> Result<String, FormatError> {
        let value = value.trim();
        match name {
            DISTRIBUTION if layout::valid_distribution(value) => Ok(value.to_string()),
            DISTRIBUTION => Err(FormatError::InvalidId(format!(
                "{value:?} is not a distribution name (letters, digits, '.', '_', '-', '+', '~')"
            ))),
            other => Err(FormatError::InvalidId(format!(
                "apt has no option {other:?}"
            ))),
        }
    }

    fn index(&self, repo: &Repository, input: &IndexInput) -> Result<Vec<IndexFile>, FormatError> {
        let distribution = repo
            .option(DISTRIBUTION)
            .ok_or_else(|| FormatError::Internal("the repository has no distribution".into()))?;
        index::render(
            &index::ReleaseInfo {
                distribution,
                label: &repo.name,
            },
            input,
        )
    }

    fn file_package(&self, path: &str) -> Option<String> {
        match layout::parse(path) {
            Ok(Target::Pool(pool)) => layout::pool_package(&pool),
            _ => None,
        }
    }

    fn handle(&self, repo: &Repository, req: &Request) -> Action {
        let target = match layout::parse(&req.path) {
            Ok(target) => target,
            Err(e) => return text(400, &e.to_string()),
        };
        let hosted = repo.kind == RepositoryKind::Hosted;
        match (req.method.as_str(), target) {
            ("GET" | "HEAD", Target::Root) => Action::Respond(about(repo)),
            ("GET" | "HEAD", Target::TopFile(file))
                if hosted && (file == KEY_ASC || file == KEY_GPG) =>
            {
                Action::Load(vec![Query::Index(file)])
            }
            (
                "GET" | "HEAD",
                Target::Dists {
                    path,
                    distribution,
                    rest,
                },
            ) => {
                if Some(distribution.as_str()) != repo.option(DISTRIBUTION) {
                    return not_found(&format!(
                        "this repository serves distribution {}, not {distribution}",
                        repo.option(DISTRIBUTION).unwrap_or("(none)")
                    ));
                }
                Action::Load(vec![match repo.kind {
                    RepositoryKind::Hosted if layout::is_by_hash(&rest) => Query::File(path),
                    RepositoryKind::Hosted => Query::Index(path),
                    _ => Query::FetchFile(path),
                }])
            }
            ("GET" | "HEAD", Target::Pool(pool)) if hosted => match pool_ref(&pool) {
                Some(target) => Action::Load(vec![Query::Package(target)]),
                None => not_found("not found"),
            },
            ("GET" | "HEAD", Target::Pool(pool)) => Action::Load(vec![Query::FetchFile(pool.path)]),
            ("GET" | "HEAD", _) => not_found("not found"),
            ("PUT" | "POST", _) if !hosted => {
                text(405, "packages are uploaded to hosted repositories")
            }
            ("PUT", Target::TopFile(file)) if file.ends_with(".deb") => publish(Upload::Body),
            ("PUT", Target::Root) => publish(Upload::Body),
            ("PUT", _) => text(
                400,
                "PUT a package to the repository's URL or to /<file>.deb directly below it",
            ),
            ("POST", Target::Root) => {
                // A form (`curl -F package=@pkg.deb`), or the package as the
                // body, whatever the content type says (Nexus' `curl -H
                // "Content-Type: multipart/form-data" --data-binary @pkg.deb`
                // sends no form).
                let form = req.header("content-type").is_some_and(|ct| {
                    ct.to_ascii_lowercase().starts_with("multipart/form-data")
                        && ct.contains("boundary=")
                });
                publish(if form {
                    Upload::FirstPart
                } else {
                    Upload::Body
                })
            }
            ("POST", _) => text(400, "POST a package to the repository's URL"),
            ("DELETE", Target::Pool(pool)) if hosted => match pool_ref(&pool) {
                Some(target) => Action::Delete(ChangeRequest {
                    target,
                    done: Response::empty(204),
                }),
                None => not_found("not found"),
            },
            ("DELETE", _) => text(400, "DELETE a package's pool file"),
            _ => Action::Respond(
                Response::text(405, "method not allowed")
                    .with_header("allow", "GET, HEAD, PUT, POST, DELETE"),
            ),
        }
    }

    fn render(&self, _repo: &Repository, req: &Request, data: &[Loaded]) -> Action {
        let Some(loaded) = data.last() else {
            return text(500, "apt: the host rendered a request without data");
        };
        match (&loaded.query, &loaded.answer) {
            (
                Query::Index(path) | Query::File(path) | Query::FetchFile(path),
                Answer::File(Some(_)),
            ) => Action::ServeFile(path.clone()),
            (Query::Index(_) | Query::File(_) | Query::FetchFile(_), Answer::File(None)) => {
                not_found("not found")
            }
            (Query::Package(target), Answer::Package(Some(info))) => {
                let summary = info.summary.as_deref().and_then(Summary::parse);
                let at_its_path = match (layout::parse(&req.path), summary) {
                    (Ok(Target::Pool(pool)), Some(summary)) => {
                        layout::pool_matches(&pool, &summary.component, &summary.package)
                    }
                    _ => false,
                };
                if at_its_path {
                    Action::Download(target.clone())
                } else {
                    not_found("not found")
                }
            }
            (Query::Package(_), Answer::Package(None)) => not_found("not found"),
            _ => text(500, "apt: the host rendered data it was not asked for"),
        }
    }

    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        Ok(match op {
            // Nothing to resolve: a file's URL is the remote's and its path.
            UpstreamOp::Index => UpstreamStep::Done(UpstreamAnswer::Index("{}".into())),
            UpstreamOp::File(path) => proxy::file(remote, path, fetched),
            _ => UpstreamStep::Done(UpstreamAnswer::Failed(
                "apt proxies serve their upstream's files".into(),
            )),
        })
    }
}

/// The version a pool path names, at the path a hosted package of it has.
fn pool_ref(pool: &PoolPath) -> Option<PackageRef> {
    let deb = layout::deb_name(&pool.file)?;
    if !pool.file.ends_with(".deb") {
        return None;
    }
    Some(PackageRef {
        id: layout::package_id(&deb.name, &deb.architecture),
        version: version::normalize(&deb.version).ok()?,
    })
}

fn publish(upload: Upload) -> Action {
    Action::Publish(PublishRequest {
        upload,
        id: None,
        done: Response::text(201, "uploaded\n"),
    })
}

fn text(status: u16, message: &str) -> Action {
    Action::Respond(Response::text(status, message))
}

fn not_found(message: &str) -> Action {
    text(404, message)
}

/// The repository's URL itself: how to use it.
fn about(repo: &Repository) -> Response {
    let distribution = repo.option(DISTRIBUTION).unwrap_or("<distribution>");
    let base = &repo.base_url;
    let body = match repo.kind {
        RepositoryKind::Hosted => format!(
            "apt repository {name} (distribution {distribution})\n\n\
             curl -fsSL {base}/{KEY_ASC} | sudo tee /etc/apt/keyrings/{name}.asc >/dev/null\n\
             echo 'deb [signed-by=/etc/apt/keyrings/{name}.asc] {base}/ {distribution} main' \
             | sudo tee /etc/apt/sources.list.d/{name}.list\n",
            name = repo.name
        ),
        _ => format!(
            "apt proxy {name} (distribution {distribution})\n\n\
             deb {base}/ {distribution} main\n",
            name = repo.name
        ),
    };
    Response::text(200, &body)
}
