//! Importing a Nexus hosted repository into a Forge hosted repository of the
//! same format, one repository at a time (NuGet, Docker).
//!
//! An administrator starts an import on a hosted repository
//! ([`crate::admin::imports`]); this worker runs it, on one instance at a
//! time: it claims a queued import (or one whose instance died) with a
//! lease in Postgres and renews the lease while it works, like the
//! retention worker.
//!
//! 1. **Scan.** The Nexus component listing is walked page by page; each
//!    page's components become pending items and the page's
//!    `continuationToken` becomes the import's cursor, in one transaction,
//!    so a scan resumes after a restart, a failure or a cancel at the page
//!    it had not recorded. For Docker the asset listing follows: manifests
//!    Nexus holds by digest only (not listed as components) become items
//!    too, so referrers (signatures, SBOMs) come along. The scan also
//!    counts every asset of the repository and its size.
//! 2. **Copy.** Pending items are copied, `concurrency` at a time:
//!    * a package (NuGet) is streamed from Nexus into staging,
//!      verified against Nexus' checksums (SHA-256 and SHA-512, else SHA-1)
//!      and size, and written through the hosted write path
//!      ([`HostedWrite::import_staged`]): format validation, the package
//!      selectors of the administrator who started the import, the
//!      repository's upload limit, CAS dedup and the audit trail
//!      (`action = "import"`). A version Forge holds with the same SHA-256
//!      is skipped without a download;
//!    * a Docker tag is copied through the Nexus repository's registry API
//!      ([`forge_oci::Registry::import_tag`]): digests are kept,
//!      multi-platform indexes arrive with every child manifest, and a
//!      referrer is copied once its subject is in Forge;
//!    * what Nexus recorded is kept: the publish time (`blobCreated`, for a
//!      tag `lastModified`) becomes the version's creation time, the last
//!      download its last download, the uploader goes to the audit trail;
//!    * a version Forge holds with other bytes is a conflict: skipped and
//!      reported (`skip`), replaced (`overwrite`), or it fails the import
//!      (`fail`).
//!
//! A dry run scans and decides every item (`planned`, `identical`,
//! `conflict`) without writing a package; it downloads nothing that Nexus
//! lists a SHA-256 for. Running an import again later copies only what is
//! new in Nexus, so a cutover is an import, then a final one just before
//! clients switch to Forge.
//!
//! A failed item can be retried on its own, and a cancelled or failed
//! import resumed ([`forge_db::import_dao::requeue`]). The Nexus password
//! is sealed with the secret encryption and deleted when the import
//! completes.

pub mod nexus;

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use forge_core::auth::principal::{AuthMethod, Principal};
use forge_core::authz::Level;
use forge_core::repo::hosted::HostedWrite;
use forge_core::repo::proxy::Credentials;
use forge_core::repo::{ImportOptions, ImportOutcome, RepoKind, WriteError};
use forge_crypto::PlaintextSecret;
use forge_db::import_dao::{self, ImportItem, NewItem, NexusImport};
use forge_db::model::{Repository, DOCKER_FORMAT};
use forge_db::{repository_dao, secret_dao, user_dao};
use forge_oci::import::{ImageImportOptions, ImageOutcome, ImportSource};
use forge_storage::StagedBlob;
use futures_util::{FutureExt, StreamExt, TryStreamExt};
use serde_json::Value as JsonValue;
use sha2::Digest as _;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::state::AppState;
use nexus::{Listing, Nexus, SourceAsset, SourceItem};

/// The formats an import copies (Nexus calls them by the same names).
pub const FORMATS: &[&str] = &["nuget", DOCKER_FORMAT];

/// How often an idle instance looks for an import to run.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The lease a running import is held with; renewed every third of it.
const LEASE_SECONDS: i64 = 120;

/// Pending items read at a time.
const BATCH: i64 = 64;

/// Items failing in a row that stop an import (Nexus went away, the
/// credentials stopped working): it fails, and can be resumed.
const MAX_CONSECUTIVE_FAILURES: usize = 25;

/// Attempts at a listing page before the import fails.
const PAGE_ATTEMPTS: u32 = 4;

/// How often a copy looks whether it was cancelled (or lost its lease).
const CHECK_INTERVAL: Duration = Duration::from_secs(5);

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
                            tracing::error!(error = %e, "nexus import tick failed");
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
            let mut tx = pool.begin().await?;
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
            source = %import.base_url,
            source_repository = %import.source_repository,
            phase = %import.phase,
            "nexus import started"
        );
        let lost = Arc::new(AtomicBool::new(false));
        let heartbeat = AbortOnDrop(spawn_heartbeat(pool.clone(), id, run_id, lost.clone()));
        let run = Run {
            state: &self.state,
            import,
            run_id,
            lost,
            stopping: AtomicBool::new(false),
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
                    "nexus import lease lost; another instance continues it"
                );
                return Ok(Some(id));
            }
        };
        if import_dao::finish(pool, id, run_id, state, error).await? {
            tracing::info!(import = id, state, error, "nexus import ended");
        } else {
            tracing::warn!(import = id, "nexus import lease lost before it ended");
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
    tracing::error!(error = %e, "nexus import: database error");
    End::Failed(format!("database error: {e}"))
}

/// Where the items of a run go.
enum Target {
    /// A package format, through the hosted write path.
    Packages(Box<HostedWrite>),
    /// Docker, through the registry, from the Nexus repository's registry
    /// API.
    Images {
        registry: forge_oci::Registry,
        source: ImportSource,
    },
}

/// What a run works with.
struct Ctx {
    repo: Repository,
    principal: Principal,
    nexus: Nexus,
    target: Target,
    /// The repository's upload limit.
    limit: u64,
    /// `<base url> <repository>`, for the audit trail.
    source: String,
}

impl Ctx {
    fn docker(&self) -> bool {
        matches!(self.target, Target::Images { .. })
    }
}

/// What became of one item.
enum Copied {
    /// It ends in `state`.
    Item {
        state: &'static str,
        detail: Option<String>,
        bytes: u64,
    },
    /// A manifest Nexus holds by digest that is no referrer: forgotten.
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
    import: NexusImport,
    run_id: Uuid,
    /// Set by the heartbeat once the lease is lost.
    lost: Arc<AtomicBool>,
    /// Set once the run is to end: no further item is started.
    stopping: AtomicBool,
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

        let password =
            secret_dao::get_import_password(pool, self.state.envelope.as_deref(), import.id)
                .await
                .map_err(|e| End::Failed(format!("the import's password cannot be read: {e}")))?;
        if import.username.is_some() && password.is_none() {
            return Err(End::Failed(
                "the import has no password; resume it with the Nexus password".into(),
            ));
        }
        let nexus = Nexus::new(
            self.state.upstream.clone(),
            &import.base_url,
            import.username.clone(),
            password.clone(),
        );

        let target = if repo.format == DOCKER_FORMAT {
            let registry_url = import.registry_url.clone().unwrap_or_else(|| {
                default_registry_url(&import.base_url, &import.source_repository)
            });
            let credentials = match (&import.username, password) {
                (Some(username), Some(password)) => Some(Credentials::for_url(
                    &registry_url,
                    username.clone(),
                    password,
                )),
                _ => None,
            };
            Target::Images {
                registry: self.state.registry(),
                source: ImportSource::new(
                    &registry_url,
                    credentials,
                    format!("import:{}", import.id),
                ),
            }
        } else {
            let format = self
                .state
                .formats
                .for_repository(&repo)
                .map_err(|e| End::Failed(e.to_string()))?;
            let authz = &self.state.authz;
            let filter = authz
                .package_filter_for(&principal, &repo, Level::Write)
                .await;
            let replace = authz
                .package_filter_for(&principal, &repo, Level::Delete)
                .await;
            Target::Packages(Box::new(crate::dispatch::hosted_write(
                self.state,
                format,
                repo.id,
                repo.name.clone(),
                principal,
                filter,
                replace,
            )))
        };
        Ok(Ctx {
            limit: self.state.upload_limit(&repo),
            source: format!("{} {}", import.base_url, import.source_repository),
            repo,
            principal,
            nexus,
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

    /// Walk the listings from the stored cursor, recording each page's
    /// items with the cursor of the next page.
    async fn scan(&self, ctx: &Ctx) -> Result<(), End> {
        let mut listing = Listing::parse(&self.import.scan_listing);
        let mut cursor = self.import.cursor.clone();
        loop {
            self.check().await?;
            let page = self.page(ctx, listing, cursor.as_deref()).await?;
            let scanned = scanned_items(&ctx.repo.format, listing, &page.items);
            let (next_listing, next_cursor, phase) = match page.next {
                Some(next) => (listing, Some(next), "scan"),
                None if ctx.docker() && listing == Listing::Components => {
                    (Listing::Assets, None, "scan")
                }
                None => (listing, None, "copy"),
            };
            let sources: Vec<JsonValue> = scanned
                .items
                .iter()
                .map(|(_, item, _)| serde_json::to_value(item).unwrap_or(JsonValue::Null))
                .collect();
            let new_items: Vec<NewItem<'_>> = scanned
                .items
                .iter()
                .zip(&sources)
                .map(|((kind, item, primary), source)| NewItem {
                    kind,
                    name: &item.name,
                    version: &item.version,
                    size: primary.and_then(|a| a.size),
                    published_at: primary.and_then(|a| published_at(&ctx.repo.format, a)),
                    downloaded_at: primary.and_then(|a| a.downloaded),
                    uploader: primary.and_then(|a| a.uploader.as_deref()),
                    source,
                })
                .collect();
            let pool = &self.state.pool;
            let mut tx = pool.begin().await.map_err(db_failed)?;
            import_dao::insert_items(&mut tx, self.import.id, &new_items)
                .await
                .map_err(db_failed)?;
            let held = import_dao::save_scan_page(
                &mut tx,
                self.import.id,
                self.run_id,
                next_listing.as_str(),
                next_cursor.as_deref(),
                phase,
                scanned.assets,
                scanned.bytes,
            )
            .await
            .map_err(db_failed)?;
            if !held {
                return Err(End::LeaseLost);
            }
            tx.commit().await.map_err(db_failed)?;
            if phase == "copy" {
                return Ok(());
            }
            listing = next_listing;
            cursor = next_cursor;
        }
    }

    /// One listing page, retried with a backoff while the failure may pass.
    async fn page(
        &self,
        ctx: &Ctx,
        listing: Listing,
        cursor: Option<&str>,
    ) -> Result<nexus::Page, End> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match ctx
                .nexus
                .page(listing, &self.import.source_repository, cursor)
                .await
            {
                Ok(page) => return Ok(page),
                Err(e) if e.is_transient() && attempt < PAGE_ATTEMPTS => {
                    tracing::warn!(import = self.import.id, error = %e, attempt, "nexus listing failed; retrying");
                    tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                }
                Err(e) => {
                    return Err(End::Failed(format!(
                        "listing the {}: {e}",
                        listing.as_str()
                    )))
                }
            }
        }
    }

    /// Copy the pending items: components first, then (Docker) the
    /// manifests Nexus holds by digest, whose subjects the components
    /// bring.
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
        let copied = match serde_json::from_value::<SourceItem>(item.source.clone()) {
            Err(e) => Err(format!("the item's recorded source is unreadable: {e}")),
            Ok(source) => match &ctx.target {
                Target::Packages(writer) => self.copy_package(ctx, writer, &source).await,
                Target::Images {
                    registry,
                    source: from,
                } => {
                    self.copy_image(ctx, registry, from, &item.kind, &source)
                        .await
                }
            },
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
                tracing::warn!(import = self.import.id, name = %item.name, version = %item.version, %error, "nexus import item failed");
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
        writer: &HostedWrite,
        source: &SourceItem,
    ) -> Result<Copied, String> {
        let asset = package_asset(&ctx.repo.format, &source.assets)
            .ok_or("the component has no package file among its assets")?;
        let overwrite = self.import.on_conflict == "overwrite";

        // Nothing is downloaded for a version Forge holds with these bytes,
        // nor for a dry run (which decides from the checksums alone).
        let stored = writer
            .package_sha256(ctx.repo.id, &source.name, &source.version)
            .await
            .map_err(|e| e.to_string())?;
        if let (Some(stored), Some(expected)) = (&stored, &asset.sha256) {
            if stored == expected {
                return Ok(item("identical", None, 0));
            }
        }
        if self.import.dry_run {
            return Ok(match (stored, &asset.sha256) {
                (None, _) => item("planned", None, 0),
                (Some(_), None) => item(
                    "planned",
                    Some("Forge has this version; Nexus lists no SHA-256 to compare".into()),
                    0,
                ),
                (Some(_), Some(_)) if overwrite => item(
                    "planned",
                    Some("would replace the version Forge has with other bytes".into()),
                    0,
                ),
                (Some(_), Some(_)) => conflict_item(),
            });
        }

        if asset
            .size
            .is_some_and(|size| u64::try_from(size).unwrap_or(0) > ctx.limit)
        {
            return Err(WriteError::TooLarge { limit: ctx.limit }.to_string());
        }
        let url = ctx
            .nexus
            .content_url(&self.import.source_repository, &asset.path);
        let response = ctx.nexus.download(&url).await.map_err(|e| e.to_string())?;
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
        verify(&staged, asset).await?;
        let bytes = staged.size;
        let options = ImportOptions {
            overwrite,
            dry_run: false,
            published_at: published_at(&ctx.repo.format, asset),
            downloaded_at: asset.downloaded,
            uploader: asset.uploader.clone(),
            source: ctx.source.clone(),
        };
        let outcome = writer
            .import_staged(&ctx.repo.name, staged, ctx.limit, &options)
            .await
            .map_err(|e| e.to_string())?;
        Ok(match outcome {
            ImportOutcome::Created { .. } => item("imported", None, bytes),
            ImportOutcome::Replaced { .. } => item(
                "replaced",
                Some("replaced the version Forge had with other bytes".into()),
                bytes,
            ),
            ImportOutcome::Identical { .. } => item("identical", None, bytes),
            ImportOutcome::Conflict { .. } => conflict_item(),
            ImportOutcome::Planned { .. } => item("planned", None, bytes),
        })
    }

    /// Copy a Docker tag (`component`) or referrer (`manifest`) through the
    /// registry.
    async fn copy_image(
        &self,
        ctx: &Ctx,
        registry: &forge_oci::Registry,
        from: &ImportSource,
        kind: &str,
        source: &SourceItem,
    ) -> Result<Copied, String> {
        let asset = source
            .assets
            .iter()
            .find(|a| a.path.contains("/manifests/"))
            .or(source.assets.first());
        let options = ImageImportOptions {
            principal: ctx.principal,
            overwrite: self.import.on_conflict == "overwrite",
            dry_run: self.import.dry_run,
            published_at: asset.and_then(|a| published_at(&ctx.repo.format, a)),
            downloaded_at: asset.and_then(|a| a.downloaded),
            uploader: asset.and_then(|a| a.uploader.clone()),
            source: ctx.source.clone(),
        };
        let imported = if kind == "manifest" {
            registry
                .import_referrer(&ctx.repo, from, &source.name, &source.version, &options)
                .await
        } else {
            let expected = asset
                .and_then(|a| a.sha256.as_ref())
                .map(|hex| format!("sha256:{hex}"));
            registry
                .import_tag(
                    &ctx.repo,
                    from,
                    &source.name,
                    &source.version,
                    expected.as_deref(),
                    &options,
                )
                .await
        }
        .map_err(|e| e.message)?;
        let bytes = imported.bytes_copied;
        Ok(match imported.outcome {
            ImageOutcome::Created => item("imported", imported.digest, bytes),
            ImageOutcome::Replaced { previous } => {
                item("replaced", Some(format!("moved from {previous}")), bytes)
            }
            ImageOutcome::Identical => item("identical", imported.digest, bytes),
            ImageOutcome::Conflict {
                existing,
                immutable,
            } => item(
                "conflict",
                Some(if immutable {
                    format!("the tag points at {existing} in Forge, and tags are immutable there")
                } else {
                    format!("the tag points at {existing} in Forge")
                }),
                bytes,
            ),
            ImageOutcome::Planned { replaces } => item(
                "planned",
                replaces.then(|| "would move the tag Forge has".to_string()),
                bytes,
            ),
            ImageOutcome::NotReferrer => Copied::NotReferrer,
        })
    }
}

fn item(state: &'static str, detail: Option<String>, bytes: u64) -> Copied {
    Copied::Item {
        state,
        detail,
        bytes,
    }
}

fn conflict_item() -> Copied {
    item(
        "conflict",
        Some("Forge has other bytes for this version".into()),
        0,
    )
}

/// The registry API of the Nexus Docker repository `repository`, by path
/// (`<base>/repository/<name>`, which Nexus serves for reads on its own
/// port).
pub fn default_registry_url(base_url: &str, repository: &str) -> String {
    format!("{}/repository/{repository}", base_url.trim_end_matches('/'))
}

/// When Nexus says an asset was published: for a Docker tag when it last
/// moved (`lastModified`), for a package when its bytes were stored
/// (`blobCreated`).
fn published_at(format: &str, asset: &SourceAsset) -> Option<chrono::DateTime<chrono::Utc>> {
    if format == DOCKER_FORMAT {
        asset.modified.or(asset.created)
    } else {
        asset.created.or(asset.modified)
    }
}

/// The package file among a component's assets: NuGet's `.nupkg` (Nexus
/// keeps it under `<id>/<version>`), any other format's only asset.
fn package_asset<'a>(format: &str, assets: &'a [SourceAsset]) -> Option<&'a SourceAsset> {
    match format {
        "nuget" => assets
            .iter()
            .find(|a| a.path.ends_with(".nupkg"))
            .or_else(|| assets.iter().find(|a| !a.path.ends_with(".nuspec"))),
        _ => match assets {
            [only] => Some(only),
            _ => None,
        },
    }
}

/// What one scanned page holds.
struct Scanned<'a> {
    /// `(kind, item, its primary asset)`.
    items: Vec<(&'static str, SourceItem, Option<&'a SourceAsset>)>,
    assets: i64,
    bytes: i64,
}

/// The items of a page: every component of a components listing; of a
/// (Docker) asset listing, the manifests held by digest. Every asset is
/// counted once: a package component's in the components listing, a
/// Docker repository's (blobs included) in the asset listing.
fn scanned_items<'a>(format: &str, listing: Listing, page: &'a [SourceItem]) -> Scanned<'a> {
    let docker = format == DOCKER_FORMAT;
    let mut scanned = Scanned {
        items: Vec::new(),
        assets: 0,
        bytes: 0,
    };
    for item in page {
        match listing {
            Listing::Components => {
                let primary = if docker {
                    item.assets.iter().find(|a| a.path.contains("/manifests/"))
                } else {
                    scanned.assets += item.assets.len() as i64;
                    scanned.bytes += item.assets.iter().filter_map(|a| a.size).sum::<i64>();
                    package_asset(format, &item.assets)
                };
                scanned.items.push(("component", item.clone(), primary));
            }
            Listing::Assets => {
                for asset in &item.assets {
                    scanned.assets += 1;
                    scanned.bytes += asset.size.unwrap_or(0);
                    if let Some((image, digest)) = manifest_by_digest(&asset.path) {
                        scanned.items.push((
                            "manifest",
                            SourceItem {
                                name: image.to_string(),
                                version: digest.to_string(),
                                assets: vec![asset.clone()],
                            },
                            Some(asset),
                        ));
                    }
                }
            }
        }
    }
    scanned
}

/// `(image, digest)` of a Docker asset path `v2/<image>/manifests/<digest>`.
fn manifest_by_digest(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("v2/")?;
    let (image, digest) = rest.rsplit_once("/manifests/")?;
    (!image.is_empty() && digest.starts_with("sha256:")).then_some((image, digest))
}

/// Check a staged download against what Nexus lists for it: its size, its
/// SHA-256 and SHA-512, else its SHA-1.
async fn verify(staged: &StagedBlob, asset: &SourceAsset) -> Result<(), String> {
    let mismatch = |what: &str| {
        format!(
            "the download of {} does not match its {what} in Nexus",
            asset.path
        )
    };
    if asset
        .size
        .is_some_and(|size| u64::try_from(size).ok() != Some(staged.size))
    {
        return Err(mismatch("size"));
    }
    let mut checked = false;
    if let Some(expected) = &asset.sha256 {
        if staged.sha256 != *expected {
            return Err(mismatch("SHA-256"));
        }
        checked = true;
    }
    if let Some(expected) = &asset.sha512 {
        let actual = base64::engine::general_purpose::STANDARD
            .decode(&staged.sha512_base64)
            .map(hex::encode)
            .map_err(|e| e.to_string())?;
        if actual != *expected {
            return Err(mismatch("SHA-512"));
        }
        checked = true;
    }
    if let (false, Some(expected)) = (checked, &asset.sha1) {
        let path = staged.read_path();
        let actual = tokio::task::spawn_blocking(move || -> std::io::Result<String> {
            use std::io::Read;
            let mut file = std::fs::File::open(path)?;
            let mut hasher = sha1::Sha1::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
        if actual != *expected {
            return Err(mismatch("SHA-1"));
        }
    }
    Ok(())
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
                    tracing::warn!(import = id, error = %e, "nexus import lease renewal failed")
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

    fn asset(path: &str) -> SourceAsset {
        SourceAsset {
            path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn package_files_are_picked_per_format() {
        let nuget = [asset("Sample.Lib/1.0.0")];
        assert_eq!(
            package_asset("nuget", &nuget).unwrap().path,
            "Sample.Lib/1.0.0"
        );
        let two = [asset("app-1.0.0.tgz.prov"), asset("app-1.0.0.tgz")];
        assert!(package_asset("raw", &two).is_none());
    }

    #[test]
    fn manifests_held_by_digest_are_recognized() {
        assert_eq!(
            manifest_by_digest("v2/team/app/manifests/sha256:abc"),
            Some(("team/app", "sha256:abc"))
        );
        assert_eq!(manifest_by_digest("v2/team/app/manifests/1.0"), None);
        assert_eq!(manifest_by_digest("v2/-/blobs/sha256:abc"), None);
    }

    #[test]
    fn a_docker_asset_listing_counts_blobs_and_keeps_digest_manifests() {
        let page = [
            SourceItem {
                assets: vec![SourceAsset {
                    size: Some(100),
                    ..asset("v2/-/blobs/sha256:aa")
                }],
                ..Default::default()
            },
            SourceItem {
                assets: vec![SourceAsset {
                    size: Some(10),
                    ..asset("v2/app/manifests/sha256:bb")
                }],
                ..Default::default()
            },
            SourceItem {
                assets: vec![SourceAsset {
                    size: Some(10),
                    ..asset("v2/app/manifests/1.0")
                }],
                ..Default::default()
            },
        ];
        let scanned = scanned_items(DOCKER_FORMAT, Listing::Assets, &page);
        assert_eq!(scanned.assets, 3);
        assert_eq!(scanned.bytes, 120);
        assert_eq!(scanned.items.len(), 1);
        assert_eq!(scanned.items[0].0, "manifest");
        assert_eq!(scanned.items[0].1.name, "app");
        assert_eq!(scanned.items[0].1.version, "sha256:bb");
    }
}
