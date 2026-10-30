//! Importing a repository from another server into a Forge hosted
//! repository of the same format (NuGet, Docker), one repository at a time.
//! The source is read through the format's own protocol, so it may be any
//! server that speaks it: Nexus, Artifactory, ProGet, BaGet, Harbor, a
//! `distribution` registry or another Forge.
//!
//! * **NuGet:** a feed's service index (`…/index.json`, [`feed::Feed`]):
//!   its search names the package ids, its package base address lists each
//!   package's versions (unlisted ones included) and serves the `.nupkg`,
//!   its registration says when each version was published and, where the
//!   feed lists it inline, its SHA-512.
//! * **Docker:** a registry's API ([`ImportSource`]): its catalog
//!   (`/v2/_catalog`) names the images, their tag lists the tags, and the
//!   referrers API the signatures and SBOMs of each copied manifest.
//!
//! An import can name its package ids or images instead (`names`): a feed's
//! search may miss some (Nexus stops at 10,000 packages; a package whose
//! versions are all unlisted is in no search result), and Docker Hub, GHCR
//! and ECR serve no catalog.
//!
//! An administrator starts an import on a hosted repository
//! ([`crate::admin::imports`]); this worker runs it, on one instance at a
//! time: it claims a queued import (or one whose instance died) with a
//! lease in Postgres and renews the lease while it works, like the
//! retention worker.
//!
//! 1. **Scan.** The source's listing (the search, the catalog or the names)
//!    is walked page by page; each page's versions or tags become pending
//!    items and the page's cursor the import's, in one transaction, so a
//!    scan resumes after a restart, a failure or a cancel at the page it
//!    had not recorded.
//! 2. **Copy.** Pending items are copied, `concurrency` at a time:
//!    * a package (NuGet) is streamed from the feed into staging, verified
//!      against the SHA-512 the feed lists (where it lists one), and written
//!      through the hosted write path ([`HostedWrite::import_staged`]):
//!      format validation, the package selectors of the administrator who
//!      started the import, the repository's upload limit, CAS dedup and
//!      the audit trail (`action = "import"`). A version Forge holds with
//!      the SHA-512 the feed lists is skipped without a download; without
//!      one, the download is compared;
//!    * a Docker tag is copied through the registry
//!      ([`crate::images::Registry::import_tag`]): digests are kept,
//!      multi-platform indexes arrive with every child manifest. The
//!      referrers the source's referrers API lists for the tag's manifest
//!      become items of their own, copied once their subject is in Forge
//!      ([`crate::images::Registry::import_referrer`]); a source without
//!      the API serves them under tags (the referrers tag schema's
//!      `sha256-<digest>`, cosign's `sha256-<digest>.sig`), copied like any
//!      other;
//!    * what the source says is kept: a NuGet version's publish time becomes
//!      its creation time (nuget.org's `1900-01-01` for an unlisted version
//!      is no publish time). The protocols carry no last download, so an
//!      imported version counts as downloaded at its import, and no push
//!      time for a tag, so a tag is created at its import;
//!    * a version Forge holds with other bytes is a conflict: skipped and
//!      reported (`skip`), replaced (`overwrite`), or it fails the import
//!      (`fail`).
//!
//! A dry run scans and decides every item (`planned`, `identical`,
//! `conflict`) without writing a package; it downloads no package. Running
//! an import again later copies only what is new at the source, so a
//! cutover is an import, then a final one just before clients switch to
//! Forge.
//!
//! An import stored before imports read the format's protocol names a
//! Nexus server and repository; it reads the same repository through its
//! protocol ([`source_url`]).
//!
//! A failed item can be retried on its own, and a cancelled or failed
//! import resumed ([`forge_db::import_dao::requeue`]). The source's
//! password is sealed with the secret encryption and deleted when the
//! import completes.

pub mod feed;

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, Utc};
use forge_core::auth::principal::{AuthMethod, Principal};
use forge_core::authz::Level;
use forge_core::repo::hosted::HostedWrite;
use forge_core::repo::proxy::Credentials;
use forge_core::repo::{ImportOptions, ImportOutcome, RepoKind, WriteError};
use forge_crypto::PlaintextSecret;
use forge_db::import_dao::{self, ImportItem, NewItem, RepositoryImport};
use forge_db::model::Repository;
use forge_db::{repository_dao, secret_dao, user_dao};
use forge_plugin::api::images::ImageError;
use forge_plugin::api::VersionMetadata;
use forge_storage::StagedBlob;
use futures_util::future::BoxFuture;
use futures_util::{FutureExt, StreamExt, TryStreamExt};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::images::import::{ImageImportOptions, ImageOutcome, ImportSource};
use crate::images::{Failure, Registry};
use crate::state::AppState;
use feed::Feed;

/// The formats an import copies: NuGet packages, and Docker images into
/// the image store.
pub const FORMATS: &[&str] = &["nuget", "docker"];

/// How often an idle instance looks for an import to run.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The lease a running import is held with; renewed every third of it.
const LEASE_SECONDS: i64 = 120;

/// Pending items read at a time.
const BATCH: i64 = 64;

/// Items failing in a row that stop an import (the source went away, the
/// credentials stopped working): it fails, and can be resumed.
const MAX_CONSECUTIVE_FAILURES: usize = 25;

/// Attempts at a read of the source's listing before the import fails.
const PAGE_ATTEMPTS: u32 = 4;

/// How often a copy looks whether it was cancelled (or lost its lease).
const CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Package ids a page of a feed's search names.
pub const SEARCH_PAGE: u32 = 100;

/// Images a page of a registry's catalog names.
const CATALOG_PAGE: u32 = 100;

/// Tags read at a time.
const TAGS_PAGE: u32 = 1000;

/// Named package ids or images a scan page reads.
const NAMES_PAGE: usize = 20;

/// The most package ids or images an import names.
pub const MAX_NAMES: usize = 10_000;

/// What went wrong reading the source.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The source could not be reached, or the transfer failed.
    #[error("the source is unreachable: {0}")]
    Unreachable(String),
    /// The source cannot answer now (a registry's error, its rate limit).
    #[error("{0}")]
    Unavailable(String),
    /// The credentials were refused (or may not see the resource).
    #[error("{0}")]
    Refused(String),
    /// Any other answer than the one asked for.
    #[error("the source answered {status} for {url}")]
    Status { status: StatusCode, url: String },
    /// The answer was not what the protocol describes.
    #[error("{0}")]
    Invalid(String),
}

impl SourceError {
    /// Whether trying again later may succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            SourceError::Unreachable(_) | SourceError::Unavailable(_) => true,
            SourceError::Status { status, .. } => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
            SourceError::Refused(_) | SourceError::Invalid(_) => false,
        }
    }

    /// A failure of the registry reading the source.
    pub fn of_image(e: Failure) -> Self {
        let text = e.message();
        match e.error {
            ImageError::Unavailable(_) | ImageError::RateLimited => SourceError::Unavailable(text),
            ImageError::InvalidCredentials | ImageError::Denied { .. } => {
                SourceError::Refused(text)
            }
            _ => SourceError::Invalid(text),
        }
    }
}

/// What an import's scan walks (its `scan_listing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    /// A NuGet feed's search.
    Search,
    /// A registry's catalog.
    Catalog,
    /// The package ids or images the import names.
    Names,
}

impl Listing {
    /// The listing of a new import.
    pub fn of(images: bool, named: bool) -> Listing {
        match (images, named) {
            (_, true) => Listing::Names,
            (true, false) => Listing::Catalog,
            (false, false) => Listing::Search,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Listing::Search => "search",
            Listing::Catalog => "catalog",
            Listing::Names => "names",
        }
    }

    fn parse(s: &str) -> Listing {
        match s {
            "catalog" => Listing::Catalog,
            "names" => Listing::Names,
            _ => Listing::Search,
        }
    }
}

/// Where in a Nexus server a repository is: `<url>/repository/<name>`.
/// Nexus serves a NuGet repository's service index below it, and a Docker
/// repository's registry API at it (for reads, on its own port), unless the
/// repository has a connector of its own (`registry_url`).
pub fn nexus_source_url(
    url: &str,
    repository: &str,
    registry_url: Option<&str>,
    images: bool,
) -> String {
    let path = format!("{}/repository/{repository}", url.trim_end_matches('/'));
    match registry_url {
        Some(registry_url) if images => registry_url.to_string(),
        _ if images => path,
        _ => format!("{path}/index.json"),
    }
}

/// The source `import` reads: its `url`, or, for an import stored before
/// imports read the format's protocol (a Nexus server and repository), that
/// repository's service index or registry API ([`nexus_source_url`]).
pub fn source_url(import: &RepositoryImport, images: bool) -> String {
    match &import.source_repository {
        Some(repository) => nexus_source_url(
            &import.url,
            repository,
            import.registry_url.as_deref(),
            images,
        ),
        None => import.url.clone(),
    }
}

/// The worker running imports on this instance.
pub struct ImportWorker {
    state: AppState,
}

impl ImportWorker {
    pub fn new(state: AppState) -> Self {
        ImportWorker { state }
    }

    /// Look for an import every few seconds and run each that is due.
    pub fn spawn_loop(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            loop {
                ticker.tick().await;
                loop {
                    match self.tick().await {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(e) => {
                            tracing::error!(error = %e, "import tick failed");
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Claim one import that is due and run it until it completes, fails,
    /// is cancelled or loses its lease. Returns its id, `None` when no
    /// import is due.
    pub async fn tick(&self) -> sqlx::Result<Option<i64>> {
        let pool = &self.state.pool;
        let claimed = {
            let mut tx = forge_db::begin(pool).await?;
            let now = forge_db::db_now(&mut *tx).await?;
            let claimed =
                import_dao::claim_next(&mut tx, now, chrono::Duration::seconds(LEASE_SECONDS))
                    .await?;
            tx.commit().await?;
            claimed
        };
        let Some((import, run_id)) = claimed else {
            return Ok(None);
        };
        let id = import.id;
        tracing::info!(
            import = id,
            repository_id = import.repository_id,
            source = %import.url,
            source_repository = import.source_repository.as_deref(),
            phase = %import.phase,
            "import started"
        );
        let lost = Arc::new(AtomicBool::new(false));
        let heartbeat = AbortOnDrop(spawn_heartbeat(pool.clone(), id, run_id, lost.clone()));
        let run = Run {
            state: &self.state,
            import,
            run_id,
            lost,
            stopping: AtomicBool::new(false),
            last_search: std::sync::Mutex::new(Vec::new()),
        };
        let end = AssertUnwindSafe(run.execute())
            .catch_unwind()
            .await
            .unwrap_or_else(|panic| {
                End::Failed(format!("the import panicked: {}", panic_text(&*panic)))
            });
        drop(heartbeat);
        let (state, error) = match &end {
            End::Completed => ("completed", None),
            End::Cancelled => ("cancelled", None),
            End::Failed(error) => ("failed", Some(error.as_str())),
            End::LeaseLost => {
                tracing::warn!(
                    import = id,
                    "import lease lost; another instance continues it"
                );
                return Ok(Some(id));
            }
        };
        if import_dao::finish(pool, id, run_id, state, error).await? {
            tracing::info!(import = id, state, error, "import ended");
        } else {
            tracing::warn!(import = id, "import lease lost before it ended");
        }
        Ok(Some(id))
    }
}

/// How a run ended.
enum End {
    Completed,
    Cancelled,
    Failed(String),
    /// Another instance holds the import now; it records the outcome.
    LeaseLost,
}

fn db_failed(e: sqlx::Error) -> End {
    tracing::error!(error = %e, "import: database error");
    End::Failed(format!("database error: {e}"))
}

/// Where the items of a run come from and go.
enum Target {
    /// A package format: from a feed, through the hosted write path.
    Packages {
        feed: Box<Feed>,
        writer: Box<HostedWrite>,
    },
    /// Docker: from a registry's API, through the registry.
    Images {
        registry: Registry,
        source: ImportSource,
    },
}

/// What a run works with.
struct Ctx {
    repo: Repository,
    principal: Principal,
    target: Target,
    /// The repository's upload limit.
    limit: u64,
    /// The source's URL, for the audit trail.
    source: String,
}

/// What the source says of an item beyond its name and version (an item's
/// `source`). An item an import stored before reads as none of it.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ItemSource {
    /// The package's SHA-512, base64, where the feed lists it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha512: Option<String>,
}

/// A version or tag the scan found.
struct Found {
    name: String,
    /// Empty for a named package or image the source does not have.
    version: String,
    published_at: Option<DateTime<Utc>>,
    source: ItemSource,
}

impl Found {
    /// A named package or image the source does not have: an item that
    /// fails, so the import reports it.
    fn missing(name: &str) -> Found {
        Found {
            name: name.to_string(),
            version: String::new(),
            published_at: None,
            source: ItemSource::default(),
        }
    }
}

/// One page of the scan: what it found, and the cursor of the next page
/// (`None`: the scan is complete).
struct Page {
    found: Vec<Found>,
    next: Option<String>,
    /// A search: how many packages it has walked with this page.
    walked: Option<i64>,
}

/// What became of one item.
enum Copied {
    /// It ends in `state`.
    Item {
        state: &'static str,
        detail: Option<String>,
        bytes: u64,
    },
    /// A manifest the source holds by digest that is no referrer: forgotten.
    NotReferrer,
}

/// How a recorded item bears on the run.
enum Recorded {
    Done,
    /// The run is ending: the item was left pending.
    NotStarted,
    Failed(String),
    /// A conflict, and the import fails on conflicts.
    Conflict(String),
}

/// One run of one import, on this instance.
struct Run<'a> {
    state: &'a AppState,
    import: RepositoryImport,
    run_id: Uuid,
    /// Set by the heartbeat once the lease is lost.
    lost: Arc<AtomicBool>,
    /// Set once the run is to end: no further item is started.
    stopping: AtomicBool,
    /// The ids of the search page read last: a feed whose search ignores
    /// `skip` answers the same page again.
    last_search: std::sync::Mutex<Vec<String>>,
}

impl Run<'_> {
    async fn execute(&self) -> End {
        let ctx = match self.prepare().await {
            Ok(ctx) => ctx,
            Err(end) => return end,
        };
        if self.import.phase == "scan" {
            if let Err(end) = self.scan(&ctx).await {
                return end;
            }
        }
        match self.copy(&ctx).await {
            Ok(()) => End::Completed,
            Err(end) => end,
        }
    }

    /// The repository, the administrator the import runs as, and the
    /// clients of the source.
    async fn prepare(&self) -> Result<Ctx, End> {
        let pool = &self.state.pool;
        let import = &self.import;
        let repo = repository_dao::find_repository_by_id(pool, import.repository_id)
            .await
            .map_err(db_failed)?
            .ok_or_else(|| End::Failed("the repository was deleted".into()))?;
        if repo.kind() != RepoKind::Hosted || !FORMATS.contains(&repo.format.as_str()) {
            return Err(End::Failed(format!(
                "imports go to a hosted NuGet or Docker repository; {} is a {} {} repository",
                repo.name, repo.format, repo.kind
            )));
        }

        // The import runs with the authority of the administrator who
        // started it, as long as they are one.
        let gone =
            || End::Failed("the administrator who started the import no longer is one".into());
        let user_id = import.created_by.ok_or_else(gone)?;
        let user = user_dao::find_user_by_id(pool, user_id)
            .await
            .map_err(db_failed)?
            .filter(|user| user.active)
            .ok_or_else(gone)?;
        let principal = Principal::User {
            user_id: user.id,
            token_id: None,
            method: AuthMethod::Session,
        };
        if !self.state.authz.is_global_admin(&principal).await {
            return Err(gone());
        }

        let password = secret_dao::get_import_password(pool, &self.state.envelope, import.id)
            .await
            .map_err(|e| End::Failed(format!("the import's password cannot be read: {e}")))?;
        if import.username.is_some() && password.is_none() {
            return Err(End::Failed(
                "the import has no password; resume it with the source's password".into(),
            ));
        }

        let images = self.state.formats.stores_images(&repo.format);
        let url = source_url(import, images);
        let target = if images {
            let credentials = match (&import.username, password) {
                (Some(username), Some(password)) => {
                    Some(Credentials::for_url(&url, username.clone(), password))
                }
                _ => None,
            };
            Target::Images {
                registry: self.state.registry(),
                source: ImportSource::new(&url, credentials, format!("import:{}", import.id)),
            }
        } else {
            let format = self
                .state
                .formats
                .for_repository(&repo)
                .map_err(|e| End::Failed(e.to_string()))?;
            let feed = self
                .retrying("reading the feed's service index", || {
                    let (http, format, url) =
                        (self.state.upstream.clone(), format.clone(), url.clone());
                    let (username, password) = (import.username.clone(), password.clone());
                    async move { Feed::open(http, format, &url, username, password).await }.boxed()
                })
                .await?;
            let authz = &self.state.authz;
            let filter = authz
                .package_filter_for(&principal, &repo, Level::Write)
                .await;
            let replace = authz
                .package_filter_for(&principal, &repo, Level::Delete)
                .await;
            let role_filter = authz
                .role_package_filter_for(&principal, &repo, Level::Write)
                .await;
            let role_replace = authz
                .role_package_filter_for(&principal, &repo, Level::Delete)
                .await;
            let writer = Box::new(crate::dispatch::hosted_write(
                self.state,
                format,
                repo.id,
                repo.name.clone(),
                principal.clone(),
                filter,
                replace,
                role_filter,
                role_replace,
            ));
            Target::Packages {
                feed: Box::new(feed),
                writer,
            }
        };
        Ok(Ctx {
            limit: self.state.upload_limit(&repo),
            source: url,
            repo,
            principal,
            target,
        })
    }

    /// Stop when the lease is lost or an administrator cancelled.
    async fn check(&self) -> Result<(), End> {
        if self.lost.load(Ordering::Relaxed) {
            return Err(End::LeaseLost);
        }
        match import_dao::poll(&self.state.pool, self.import.id, self.run_id).await {
            Ok(None) => Err(End::LeaseLost),
            Ok(Some(true)) => Err(End::Cancelled),
            Ok(Some(false)) => Ok(()),
            Err(e) => Err(db_failed(e)),
        }
    }

    /// A read of the source, retried with a backoff while its failure may
    /// pass.
    async fn retrying<'f, T>(
        &self,
        what: &str,
        mut read: impl FnMut() -> BoxFuture<'f, Result<T, SourceError>> + Send,
    ) -> Result<T, End> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match read().await {
                Ok(read) => return Ok(read),
                Err(e) if e.is_transient() && attempt < PAGE_ATTEMPTS => {
                    tracing::warn!(import = self.import.id, error = %e, attempt, "{what} failed; retrying");
                    tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                }
                Err(e) => return Err(End::Failed(format!("{what}: {e}"))),
            }
        }
    }

    /// Walk the listing from the stored cursor, recording each page's
    /// items with the cursor of the next page.
    async fn scan(&self, ctx: &Ctx) -> Result<(), End> {
        let listing = Listing::parse(&self.import.scan_listing);
        let mut cursor = self.import.cursor.clone();
        loop {
            self.check().await?;
            let what = format!("reading the source's {}", listing.as_str());
            let page = self
                .retrying(&what, || self.page(ctx, listing, cursor.as_deref()).boxed())
                .await?;
            let phase = if page.next.is_some() { "scan" } else { "copy" };
            let sources: Vec<serde_json::Value> = page
                .found
                .iter()
                .map(|found| serde_json::to_value(&found.source).unwrap_or_default())
                .collect();
            let new_items: Vec<NewItem<'_>> = page
                .found
                .iter()
                .zip(&sources)
                .map(|(found, source)| NewItem {
                    kind: "component",
                    name: &found.name,
                    version: &found.version,
                    size: None,
                    published_at: found.published_at,
                    downloaded_at: None,
                    uploader: None,
                    source,
                })
                .collect();
            let pool = &self.state.pool;
            let mut tx = forge_db::begin(pool).await.map_err(db_failed)?;
            import_dao::insert_items(&mut tx, self.import.id, &new_items)
                .await
                .map_err(db_failed)?;
            let held = import_dao::save_scan_page(
                &mut tx,
                self.import.id,
                self.run_id,
                page.next.as_deref(),
                phase,
                page.walked,
            )
            .await
            .map_err(db_failed)?;
            if !held {
                return Err(End::LeaseLost);
            }
            tx.commit().await.map_err(db_failed)?;
            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(()),
            }
        }
    }

    /// One page of the listing after `cursor`: its package ids' versions,
    /// or its images' tags.
    async fn page(
        &self,
        ctx: &Ctx,
        listing: Listing,
        cursor: Option<&str>,
    ) -> Result<Page, SourceError> {
        let concurrency = self.import.concurrency.clamp(1, 16) as usize;
        match (&ctx.target, listing) {
            (_, Listing::Names) => {
                let names = self.import.names.as_deref().unwrap_or_default();
                let start = cursor
                    .and_then(|c| c.parse::<usize>().ok())
                    .unwrap_or(0)
                    .min(names.len());
                let end = (start + NAMES_PAGE).min(names.len());
                let found = self
                    .expand(ctx, &names[start..end], true, concurrency)
                    .await?;
                Ok(Page {
                    found,
                    next: (end < names.len()).then(|| end.to_string()),
                    walked: None,
                })
            }
            (Target::Packages { feed, .. }, Listing::Search) => {
                let skip = cursor.and_then(|c| c.parse::<u32>().ok()).unwrap_or(0);
                let Some((_, ids)) = feed.search(skip, SEARCH_PAGE).await? else {
                    return Err(SourceError::Invalid(
                        "the feed offers no search; name the packages to import instead".into(),
                    ));
                };
                // The walk ends at an empty page: a feed's total is no end
                // (Nexus reports the hits of the page it answers), nor is a
                // short page (a feed may answer fewer than it was asked for).
                {
                    let mut last = self
                        .last_search
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if skip > 0 && !ids.is_empty() && *last == ids {
                        return Err(SourceError::Invalid(format!(
                            "the feed's search answers the same page at {skip} as before it: it \
                             ignores skip; name the packages to import instead"
                        )));
                    }
                    last.clone_from(&ids);
                }
                let walked = u64::from(skip) + ids.len() as u64;
                let next = (!ids.is_empty()).then(|| walked.to_string());
                let found = self.expand(ctx, &ids, false, concurrency).await?;
                Ok(Page {
                    found,
                    next,
                    walked: Some(i64::try_from(walked).unwrap_or(i64::MAX)),
                })
            }
            (Target::Images { registry, source }, Listing::Catalog) => {
                let page = registry
                    .source_catalog(source, cursor, CATALOG_PAGE)
                    .await
                    .map_err(SourceError::of_image)?
                    .ok_or_else(|| {
                        SourceError::Invalid(
                            "the registry serves no catalog (/v2/_catalog); name the images to \
                             import instead"
                                .into(),
                        )
                    })?;
                let next = page.more.then(|| page.images.last().cloned()).flatten();
                let found = self.expand(ctx, &page.images, false, concurrency).await?;
                Ok(Page {
                    found,
                    next,
                    walked: None,
                })
            }
            _ => Err(SourceError::Invalid(format!(
                "a {} repository's import does not walk a {}",
                ctx.repo.format,
                listing.as_str()
            ))),
        }
    }

    /// The versions of the package ids `names`, or the tags of the images
    /// `names`, in their order. A name the source does not have is left
    /// out, or, when the import `named` it, found as missing.
    async fn expand(
        &self,
        ctx: &Ctx,
        names: &[String],
        named: bool,
        concurrency: usize,
    ) -> Result<Vec<Found>, SourceError> {
        // The reads are made up front: futures do nothing until polled.
        let reads: Vec<_> = names
            .iter()
            .map(|name| expand_one(&ctx.target, name, named))
            .collect();
        let pages: Vec<Vec<Found>> = futures_util::stream::iter(reads)
            .buffered(concurrency)
            .try_collect()
            .await?;
        Ok(pages.into_iter().flatten().collect())
    }

    /// Copy the pending items: tags and versions first, then (Docker) the
    /// referrers their copies found.
    async fn copy(&self, ctx: &Ctx) -> Result<(), End> {
        let failures = AtomicUsize::new(0);
        let concurrency = self.import.concurrency.clamp(1, 16) as usize;
        for kind in ["component", "manifest"] {
            let mut after = 0;
            loop {
                self.check().await?;
                let batch =
                    import_dao::pending_items(&self.state.pool, self.import.id, kind, after, BATCH)
                        .await
                        .map_err(db_failed)?;
                let Some(last) = batch.last() else {
                    break;
                };
                after = last.id;
                let mut copies = futures_util::stream::iter(batch)
                    .map(|item| self.copy_item(ctx, item))
                    .buffer_unordered(concurrency);
                // Once the run is to end (a cancel, a lost lease, too many
                // failures), the items in flight finish and the rest stay
                // pending.
                let mut end = None;
                let mut checked = std::time::Instant::now();
                while let Some(recorded) = copies.next().await {
                    let mut stop = match recorded {
                        Err(e) => Some(db_failed(e)),
                        Ok(Recorded::Done) => {
                            failures.store(0, Ordering::Relaxed);
                            None
                        }
                        Ok(Recorded::NotStarted) => None,
                        Ok(Recorded::Failed(error)) => (failures.fetch_add(1, Ordering::Relaxed)
                            + 1
                            >= MAX_CONSECUTIVE_FAILURES)
                            .then(|| {
                                End::Failed(format!(
                                    "{MAX_CONSECUTIVE_FAILURES} items in a row failed; the last: {error}"
                                ))
                            }),
                        Ok(Recorded::Conflict(conflict)) => Some(End::Failed(conflict)),
                    };
                    if end.is_none() && stop.is_none() && checked.elapsed() >= CHECK_INTERVAL {
                        checked = std::time::Instant::now();
                        stop = self.check().await.err();
                    }
                    if let (None, Some(stop)) = (&end, stop) {
                        self.stopping.store(true, Ordering::Relaxed);
                        end = Some(stop);
                    }
                }
                if let Some(end) = end {
                    return Err(end);
                }
            }
        }
        Ok(())
    }

    /// Copy one item and record what became of it.
    async fn copy_item(&self, ctx: &Ctx, item: ImportItem) -> sqlx::Result<Recorded> {
        if self.stopping.load(Ordering::Relaxed) {
            return Ok(Recorded::NotStarted);
        }
        let pool = &self.state.pool;
        let copied = if item.version.is_empty() {
            Err(match ctx.target {
                Target::Packages { .. } => "the source has no package of this id".to_string(),
                Target::Images { .. } => "the source has no tag of this image".to_string(),
            })
        } else {
            match &ctx.target {
                Target::Packages { feed, writer } => {
                    let source: ItemSource =
                        serde_json::from_value(item.source.clone()).unwrap_or_default();
                    self.copy_package(ctx, feed, writer, &item, &source).await
                }
                Target::Images { registry, source } => {
                    self.copy_image(ctx, registry, source, &item).await
                }
            }
        };
        match copied {
            Ok(Copied::NotReferrer) => {
                import_dao::drop_item(pool, item.id).await?;
                Ok(Recorded::Done)
            }
            Ok(Copied::Item {
                state,
                detail,
                bytes,
            }) => {
                import_dao::finish_item(
                    pool,
                    item.id,
                    state,
                    detail.as_deref(),
                    i64::try_from(bytes).unwrap_or(i64::MAX),
                )
                .await?;
                if state == "conflict" && self.import.on_conflict == "fail" {
                    return Ok(Recorded::Conflict(format!(
                        "{} {}: {}",
                        item.name,
                        item.version,
                        detail.unwrap_or_default()
                    )));
                }
                Ok(Recorded::Done)
            }
            Err(error) => {
                tracing::warn!(import = self.import.id, name = %item.name, version = %item.version, %error, "import item failed");
                import_dao::finish_item(pool, item.id, "failed", Some(&error), 0).await?;
                Ok(Recorded::Failed(format!(
                    "{} {}: {error}",
                    item.name, item.version
                )))
            }
        }
    }

    /// Copy a package version through the hosted write path.
    async fn copy_package(
        &self,
        ctx: &Ctx,
        feed: &Feed,
        writer: &HostedWrite,
        item: &ImportItem,
        source: &ItemSource,
    ) -> Result<Copied, String> {
        let overwrite = self.import.on_conflict == "overwrite";

        // Nothing is downloaded for a version Forge holds with the bytes
        // the feed lists, nor for a dry run (which decides from the
        // checksums alone).
        let stored = writer
            .package_sha512(ctx.repo.id, &item.name, &item.version)
            .await
            .map_err(|e| e.to_string())?;
        if let (Some(stored), Some(expected)) = (&stored, &source.sha512) {
            if stored == expected {
                return Ok(copied("identical", None, 0));
            }
        }
        if self.import.dry_run {
            return Ok(match (stored, &source.sha512) {
                (None, _) => copied("planned", None, 0),
                (Some(_), None) => copied(
                    "planned",
                    Some("Forge has this version; the feed lists no SHA-512 to compare".into()),
                    0,
                ),
                (Some(_), Some(_)) if overwrite => copied(
                    "planned",
                    Some("would replace the version Forge has with other bytes".into()),
                    0,
                ),
                (Some(_), Some(_)) => conflict_item(),
            });
        }

        let url = feed
            .package_url(&item.name, &item.version)
            .await
            .map_err(|e| e.to_string())?;
        let response = feed.download(&url).await.map_err(|e| e.to_string())?;
        if response.content_length().is_some_and(|l| l > ctx.limit) {
            return Err(WriteError::TooLarge { limit: ctx.limit }.to_string());
        }
        let body = response.bytes_stream().map_err(std::io::Error::other);
        let staged = self
            .state
            .cas
            .stage(tokio_util::io::StreamReader::new(body), ctx.limit)
            .await
            .map_err(|e| WriteError::from(e).to_string())?;
        verify(&staged, &url, source)?;
        let bytes = staged.size;
        let options = ImportOptions {
            overwrite,
            dry_run: false,
            published_at: item.published_at,
            downloaded_at: Some(item.downloaded_at.unwrap_or_else(Utc::now)),
            uploader: item.uploader.clone(),
            source: ctx.source.clone(),
        };
        let outcome = writer
            .import_staged(&ctx.repo.name, staged, ctx.limit, &options)
            .await
            .map_err(|e| e.to_string())?;
        Ok(match outcome {
            ImportOutcome::Created { .. } => copied("imported", None, bytes),
            ImportOutcome::Replaced { .. } => copied(
                "replaced",
                Some("replaced the version Forge had with other bytes".into()),
                bytes,
            ),
            ImportOutcome::Identical { .. } => copied("identical", None, bytes),
            ImportOutcome::Conflict { .. } => conflict_item(),
            ImportOutcome::Planned { .. } => copied("planned", None, bytes),
        })
    }

    /// Copy a Docker tag (`component`) or referrer (`manifest`) through the
    /// registry, and record the referrers the source lists for it.
    async fn copy_image(
        &self,
        ctx: &Ctx,
        registry: &Registry,
        from: &ImportSource,
        item: &ImportItem,
    ) -> Result<Copied, String> {
        let options = ImageImportOptions {
            principal: ctx.principal.clone(),
            overwrite: self.import.on_conflict == "overwrite",
            dry_run: self.import.dry_run,
            published_at: item.published_at,
            downloaded_at: Some(item.downloaded_at.unwrap_or_else(Utc::now)),
            uploader: item.uploader.clone(),
            source: ctx.source.clone(),
        };
        let imported = if item.kind == "manifest" {
            registry
                .import_referrer(&ctx.repo, from, &item.name, &item.version, &options)
                .await
        } else {
            registry
                .import_tag(&ctx.repo, from, &item.name, &item.version, None, &options)
                .await
        }
        .map_err(|e| e.message())?;
        let bytes = imported.bytes_copied;
        // Its referrers come along unless it stays out of Forge.
        let held = matches!(
            imported.outcome,
            ImageOutcome::Created
                | ImageOutcome::Replaced { .. }
                | ImageOutcome::Identical
                | ImageOutcome::Planned { .. }
        );
        if let (true, Some(digest)) = (held, &imported.digest) {
            self.record_referrers(registry, from, &item.name, digest)
                .await
                .map_err(|e| format!("copied, but listing its referrers failed: {e}"))?;
        }
        Ok(match imported.outcome {
            ImageOutcome::Created => copied("imported", imported.digest, bytes),
            ImageOutcome::Replaced { previous } => {
                copied("replaced", Some(format!("moved from {previous}")), bytes)
            }
            ImageOutcome::Identical => copied("identical", imported.digest, bytes),
            ImageOutcome::Conflict {
                existing,
                immutable,
            } => copied(
                "conflict",
                Some(if immutable {
                    format!("the tag points at {existing} in Forge, and tags are immutable there")
                } else {
                    format!("the tag points at {existing} in Forge")
                }),
                bytes,
            ),
            ImageOutcome::Planned { replaces } => copied(
                "planned",
                replaces.then(|| "would move the tag Forge has".to_string()),
                bytes,
            ),
            ImageOutcome::NotReferrer => Copied::NotReferrer,
        })
    }

    /// Record the referrers the source's referrers API lists for the
    /// manifest `digest` of `image` as items, copied after the tags. A
    /// source without the API lists none.
    async fn record_referrers(
        &self,
        registry: &Registry,
        from: &ImportSource,
        image: &str,
        digest: &str,
    ) -> Result<(), String> {
        let Some(referrers) = registry
            .source_referrers(from, image, digest)
            .await
            .map_err(|e| e.message())?
        else {
            return Ok(());
        };
        if referrers.is_empty() {
            return Ok(());
        }
        let source = serde_json::json!({});
        let items: Vec<NewItem<'_>> = referrers
            .iter()
            .map(|referrer| NewItem {
                kind: "manifest",
                name: image,
                version: &referrer.digest,
                size: i64::try_from(referrer.size).ok(),
                published_at: None,
                downloaded_at: None,
                uploader: None,
                source: &source,
            })
            .collect();
        let recorded = async {
            let mut tx = forge_db::begin(&self.state.pool).await?;
            import_dao::insert_items(&mut tx, self.import.id, &items).await?;
            tx.commit().await
        };
        recorded.await.map_err(|e| format!("database error: {e}"))
    }
}

/// The versions of the package id `name`, or the tags of the image `name`.
async fn expand_one(target: &Target, name: &str, named: bool) -> Result<Vec<Found>, SourceError> {
    match target {
        Target::Packages { feed, .. } => package_versions(feed, name, named).await,
        Target::Images { registry, source } => image_tags(registry, source, name, named).await,
    }
}

/// Every version the feed lists of the package `id`, with what its
/// registration says of each. A package the feed does not know is left
/// out, or found as missing when the import `named` it.
async fn package_versions(feed: &Feed, id: &str, named: bool) -> Result<Vec<Found>, SourceError> {
    let versions = feed.versions(id).await?.unwrap_or_default();
    if versions.is_empty() {
        return Ok(if named {
            vec![Found::missing(id)]
        } else {
            Vec::new()
        });
    }
    // The registration is best effort: without it, a version has no
    // publish time and no checksum.
    let metadata = match feed.metadata(id, &versions).await {
        Ok(metadata) => metadata,
        Err(e) if e.is_transient() => return Err(e),
        Err(e) => {
            tracing::warn!(id, error = %e, "import: the feed's registration is unreadable");
            Vec::new()
        }
    };
    let metadata: HashMap<String, VersionMetadata> = metadata
        .into_iter()
        .map(|m| (m.version.to_lowercase(), m))
        .collect();
    Ok(versions
        .into_iter()
        .map(|version| {
            let meta = metadata.get(&version.to_lowercase());
            Found {
                name: id.to_string(),
                published_at: meta.and_then(|m| published_at(m.published.as_deref())),
                source: ItemSource {
                    sha512: meta.and_then(|m| m.sha512.clone()),
                },
                version,
            }
        })
        .collect())
}

/// Every tag of `image` at the source. An image the source does not have
/// (or has no tag of) is left out, or found as missing when the import
/// `named` it.
async fn image_tags(
    registry: &Registry,
    source: &ImportSource,
    image: &str,
    named: bool,
) -> Result<Vec<Found>, SourceError> {
    let mut found = Vec::new();
    let mut last: Option<String> = None;
    loop {
        let page = registry
            .source_tags(source, image, last.as_deref(), TAGS_PAGE)
            .await
            .map_err(SourceError::of_image)?;
        let Some(page) = page else {
            break;
        };
        let more = page.more && !page.tags.is_empty();
        last = page.tags.last().cloned().or(last);
        found.extend(page.tags.into_iter().map(|tag| Found {
            name: image.to_string(),
            version: tag,
            published_at: None,
            source: ItemSource::default(),
        }));
        if !more {
            break;
        }
    }
    if found.is_empty() && named {
        found.push(Found::missing(image));
    }
    Ok(found)
}

/// A publish time from a feed's registration. nuget.org gives an unlisted
/// version `1900-01-01`: no publish time.
fn published_at(published: Option<&str>) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(published?)
        .ok()
        .map(|t| t.with_timezone(&Utc))
        .filter(|t| t.year() > 1900)
}

fn copied(state: &'static str, detail: Option<String>, bytes: u64) -> Copied {
    Copied::Item {
        state,
        detail,
        bytes,
    }
}

fn conflict_item() -> Copied {
    copied(
        "conflict",
        Some("Forge has other bytes for this version".into()),
        0,
    )
}

/// Check a staged download against the SHA-512 the feed lists for it.
fn verify(staged: &StagedBlob, url: &str, source: &ItemSource) -> Result<(), String> {
    match &source.sha512 {
        Some(expected) if *expected != staged.sha512_base64 => Err(format!(
            "the download of {url} does not match the SHA-512 the feed lists for it"
        )),
        _ => Ok(()),
    }
}

/// Aborts the wrapped task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Renew the lease every third of its length until aborted; flags `lost`
/// and stops once the lease is gone.
fn spawn_heartbeat(
    pool: sqlx::PgPool,
    id: i64,
    run_id: Uuid,
    lost: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs((LEASE_SECONDS / 3) as u64));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let renewed = match forge_db::db_now(&pool).await {
                Ok(now) => {
                    import_dao::renew_lease(
                        &pool,
                        id,
                        run_id,
                        now + chrono::Duration::seconds(LEASE_SECONDS),
                    )
                    .await
                }
                Err(e) => Err(e),
            };
            match renewed {
                Ok(true) => {}
                Ok(false) => {
                    lost.store(true, Ordering::Relaxed);
                    return;
                }
                Err(e) => {
                    tracing::warn!(import = id, error = %e, "import lease renewal failed")
                }
            }
        }
    })
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

/// The password an import is created or resumed with, if any.
pub fn password_secret(password: Option<String>) -> Option<PlaintextSecret> {
    password
        .filter(|p| !p.is_empty())
        .map(PlaintextSecret::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nuget_placeholder_date_is_no_publish_time() {
        assert_eq!(published_at(Some("1900-01-01T00:00:00+00:00")), None);
        assert_eq!(published_at(Some("not a date")), None);
        assert_eq!(published_at(None), None);
        assert_eq!(
            published_at(Some("2024-05-06T07:08:09.123+02:00")),
            Some("2024-05-06T05:08:09.123Z".parse().unwrap())
        );
    }

    #[test]
    fn a_nexus_repository_reads_through_its_protocol() {
        assert_eq!(
            nexus_source_url("https://nexus.example.com/", "nuget-hosted", None, false),
            "https://nexus.example.com/repository/nuget-hosted/index.json"
        );
        assert_eq!(
            nexus_source_url("https://nexus.example.com", "docker-hosted", None, true),
            "https://nexus.example.com/repository/docker-hosted"
        );
        assert_eq!(
            nexus_source_url(
                "https://nexus.example.com",
                "docker-hosted",
                Some("https://nexus.example.com:8082"),
                true
            ),
            "https://nexus.example.com:8082"
        );
    }

    #[test]
    fn a_new_import_picks_its_listing() {
        assert_eq!(Listing::of(false, false), Listing::Search);
        assert_eq!(Listing::of(true, false), Listing::Catalog);
        assert_eq!(Listing::of(true, true), Listing::Names);
        for listing in [Listing::Search, Listing::Catalog, Listing::Names] {
            assert_eq!(Listing::parse(listing.as_str()), listing);
        }
    }

    #[test]
    fn an_item_stored_before_reads_as_no_checksum() {
        let legacy = serde_json::json!({
            "name": "Sample.Lib",
            "version": "1.0.0",
            "assets": [{ "path": "Sample.Lib/1.0.0", "sha512": "abc" }]
        });
        let source: ItemSource = serde_json::from_value(legacy).unwrap();
        assert_eq!(source.sha512, None);
    }
}
