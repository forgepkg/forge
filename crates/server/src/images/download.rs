//! A proxy's first download of a layer, served while it arrives.
//!
//! A proxy that does not hold a layer yet downloads it in a task of its own
//! ([`Registry::start_download`]): into a staged file of the size the
//! upstream declared (`Content-Length`, [`forge_storage::SizedStage`]),
//! verified against the layer's digest, then stored and linked like any blob
//! a proxy fetches. Every pull of the layer on this instance meanwhile, the
//! one that started the download included, is served from the staged file
//! as it grows ([`Download::stream`]), instead of waiting for the layer to be
//! cached.
//!
//! * The last byte of every response is held back until the whole layer
//!   matches its digest. A download that does not, or that brings more or
//!   fewer bytes than it declared, ends every response short (an error the
//!   client retries) and is not cached: no client receives a whole layer
//!   that does not match its digest.
//! * The download is its task's, not a request's: it is finished and cached
//!   when its clients go away, within the upstream client's download deadline
//!   (`proxy.download_timeout_seconds`).
//! * So is the staged file: it is deleted, and its staging space
//!   (`server.max_staging_bytes`) given back, when the task ends
//!   ([`Download::end`]), however far its responses are. A response still on
//!   the layer then goes on from the stored layer, through the local blob
//!   cache like a pull that comes after it, or ends short when the download
//!   failed. A client that reads slowly, or stops reading, holds no staging
//!   space past the download.
//! * A download is registered from its start until its layer is linked, or
//!   it failed. The proxy starts and joins downloads under the layer's
//!   download gate, so a pull finds the layer either linked or downloading;
//!   a pull after a failure starts a new download.
//! * A download that failed after its headers (the upstream broke off, sent
//!   more or fewer bytes than it declared, or bytes that do not match the
//!   layer's digest) is remembered for [`FAILED_FOR`]
//!   ([`Download::failed_recently`]): a group asks its other members for the
//!   layer first meanwhile, so the client's retry is served by the next
//!   member (#791).

use std::collections::HashMap;
use std::ops::Range;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use forge_core::net::upstream::UpstreamHttp;
use forge_db::model::Repository;
use forge_storage::{BlobRef, BlobStore, BlobStream, CasError, SizedStage, StageReader};
use futures_util::{Stream, StreamExt};
use tokio::sync::watch;
use tracing::Instrument;

use super::digest::ContentDigest;
use super::proxy::upstream_unreachable;
use super::{Failure, ImgResult, Registry};

/// The most a response reads of the staged file at once.
const READ_CHUNK: usize = 256 * 1024;

/// How long a failed download is remembered ([`Download::failed_recently`]).
pub(crate) const FAILED_FOR: Duration = Duration::from_secs(5 * 60);

/// The most failed downloads remembered at once: past it, the oldest go.
const MAX_FAILED: usize = 4096;

/// The downloads of this process, by [`Download::key`].
static DOWNLOADS: LazyLock<Mutex<HashMap<String, Arc<Download>>>> = LazyLock::new(Default::default);

/// The downloads of this process that failed, by [`Download::key`], with
/// when they failed.
static FAILED: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(Default::default);

/// A layer a proxy is downloading, for the pulls served from it.
pub(crate) struct Download {
    /// The layer's size, as the upstream declared it.
    pub size: u64,
    /// The staged file, until the download's task ends ([`Self::end`]).
    /// Responses take a handle for each read only, so the file and its
    /// staging space go with the task, not with the slowest response.
    staged: Mutex<Option<StageReader>>,
    /// Where the responses still on the layer read it from once it is
    /// stored.
    store: BlobStore,
    progress: watch::Receiver<Progress>,
}

/// How far a download is. A download whose task ended before
/// [`Progress::Stored`] failed.
#[derive(Debug, Clone)]
enum Progress {
    /// Arriving: the bytes in the staged file so far.
    Staging { written: u64 },
    /// All of them are there, and they match the layer's digest.
    Verified,
    /// Stored and linked. The staged file is released right after.
    Stored(Arc<StoredLayer>),
}

/// Where a downloaded layer is stored.
#[derive(Debug)]
struct StoredLayer {
    sha256: String,
    s3_key: String,
}

/// Where a response is in the layer.
enum Reading {
    /// Following the download: `at` is the next offset it sends.
    Download {
        download: Arc<Download>,
        progress: watch::Receiver<Progress>,
        at: u64,
    },
    /// Reading the stored layer, once the download stored it.
    Stored(BlobStream),
}

impl std::fmt::Debug for Download {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Download")
            .field("size", &self.size)
            .field("progress", &*self.progress.borrow())
            .finish_non_exhaustive()
    }
}

/// Unregisters a download when its task ends, however it ends.
struct Registered(String);

impl Drop for Registered {
    fn drop(&mut self) {
        DOWNLOADS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.0);
    }
}

impl Download {
    /// A download of `size` bytes into `stage`, stored in `store`, and the
    /// progress its task reports.
    fn new(
        size: u64,
        stage: &SizedStage,
        store: BlobStore,
    ) -> (Arc<Self>, watch::Sender<Progress>) {
        let (progress, watched) = watch::channel(Progress::Staging { written: 0 });
        let download = Arc::new(Download {
            size,
            staged: Mutex::new(Some(stage.reader())),
            store,
            progress: watched,
        });
        (download, progress)
    }

    /// What the download of `digest` of `image` in `repo` is registered
    /// under, and the layer's download gate. By upstream too: a pull after
    /// the proxy was pointed elsewhere never joins a download from its
    /// previous upstream, which is not cached either
    /// ([`super::proxy::still_upstream`]).
    pub(crate) fn key(repo: &Repository, image: &str, digest: &ContentDigest) -> String {
        format!(
            "{}:{}:{image}:{digest}",
            repo.id,
            repo.remote_url.as_deref().unwrap_or_default()
        )
    }

    /// The download registered under `key`, to serve a pull from.
    pub(crate) fn joinable(key: &str) -> Option<Arc<Download>> {
        DOWNLOADS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    /// Whether the download registered under `key` failed within the last
    /// [`FAILED_FOR`]: a group asks its other members first.
    pub(crate) fn failed_recently(key: &str) -> bool {
        FAILED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .is_some_and(|at| at.elapsed() < FAILED_FOR)
    }

    /// Remember that the download under `key` failed (`true`), or forget
    /// that it did once one succeeds.
    fn remember(key: &str, failed: bool) {
        let mut all = FAILED.lock().unwrap_or_else(PoisonError::into_inner);
        if !failed {
            all.remove(key);
            return;
        }
        let now = Instant::now();
        if all.len() >= MAX_FAILED && !all.contains_key(key) {
            all.retain(|_, at| now.duration_since(*at) < FAILED_FOR);
            if all.len() >= MAX_FAILED {
                if let Some(oldest) = all
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(k, _)| k.clone())
                {
                    all.remove(&oldest);
                }
            }
        }
        all.insert(key.to_string(), now);
    }

    /// A handle on the staged file, while the download's task runs.
    fn staged(&self) -> Option<StageReader> {
        self.staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// End the download, as its task does once it is unregistered: with its
    /// layer `stored`, or failed (`None`). The staged file goes, and its
    /// staging space with it, whoever still reads the layer: those
    /// responses go on from the store, or end short.
    fn end(&self, progress: watch::Sender<Progress>, stored: Option<StoredLayer>) {
        if let Some(layer) = stored {
            progress.send_replace(Progress::Stored(Arc::new(layer)));
        }
        let staged = self
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(staged);
        drop(progress);
    }

    /// The bytes `range` of the layer, as they arrive, and from the store
    /// once the layer is stored. The stream fails, cutting its response
    /// short, when the download does.
    pub(crate) fn stream(
        self: Arc<Self>,
        range: Range<u64>,
    ) -> impl Stream<Item = std::io::Result<Bytes>> + Send + 'static {
        let end = range.end;
        let progress = self.progress.clone();
        futures_util::stream::try_unfold(
            Reading::Download {
                download: self,
                progress,
                at: range.start,
            },
            move |reading| async move {
                match reading {
                    Reading::Download {
                        download,
                        progress,
                        at,
                    } => download.next(progress, at, end).await,
                    Reading::Stored(stored) => next_stored(stored).await,
                }
            },
        )
    }

    /// The next bytes of a response at `at` that ends at `end`: from the
    /// staged file as they arrive (its last byte only once the layer matches
    /// its digest), from the store once the layer is stored.
    async fn next(
        self: Arc<Self>,
        mut progress: watch::Receiver<Progress>,
        at: u64,
        end: u64,
    ) -> std::io::Result<Option<(Bytes, Reading)>> {
        if at >= end {
            return Ok(None);
        }
        let failed = || std::io::Error::other("the upstream download of the layer failed");
        loop {
            let readable = match &*progress.borrow_and_update() {
                Progress::Staging { written } => Ok((*written).min(self.size.saturating_sub(1))),
                Progress::Verified => Ok(self.size),
                Progress::Stored(layer) => Err(Arc::clone(layer)),
            };
            let ready = match readable {
                Ok(readable) => readable.min(end),
                Err(layer) => return self.read_stored(&layer, at, end).await,
            };
            if at < ready {
                let Some(staged) = self.staged() else {
                    // The task ended: it stored the layer, which its
                    // progress says by now, or it failed.
                    if matches!(*progress.borrow(), Progress::Stored(_)) {
                        continue;
                    }
                    return Err(failed());
                };
                let len = usize::try_from(ready - at)
                    .unwrap_or(usize::MAX)
                    .min(READ_CHUNK);
                let bytes = staged.read_at(at, len).await?;
                if bytes.is_empty() {
                    return Err(std::io::Error::other("the staged layer ended early"));
                }
                let next = at + bytes.len() as u64;
                return Ok(Some((
                    bytes,
                    Reading::Download {
                        download: self,
                        progress,
                        at: next,
                    },
                )));
            }
            if progress.changed().await.is_err()
                && !matches!(*progress.borrow(), Progress::Stored(_))
            {
                return Err(failed());
            }
        }
    }

    /// The first bytes of `at..end` of the stored layer, and the stream of
    /// the rest.
    async fn read_stored(
        &self,
        layer: &StoredLayer,
        at: u64,
        end: u64,
    ) -> std::io::Result<Option<(Bytes, Reading)>> {
        let blob = BlobRef {
            sha256: &layer.sha256,
            s3_key: &layer.s3_key,
            size: self.size,
        };
        let stored = self.store.open(blob, Some(at..end)).await.map_err(|e| {
            tracing::warn!(error = %e, "registry proxy: reading a layer it just stored failed");
            std::io::Error::other(e)
        })?;
        next_stored(stored).await
    }
}

/// The next bytes of a response from the stored layer.
async fn next_stored(mut stored: BlobStream) -> std::io::Result<Option<(Bytes, Reading)>> {
    match stored.next().await {
        Some(bytes) => Ok(Some((bytes?, Reading::Stored(stored)))),
        None => Ok(None),
    }
}

impl Registry {
    /// Download the layer `digest` of `image` in `repo` (`size` bytes, the
    /// body of `response` from `http`'s upstream) in a task of its own, and
    /// register it for the pulls meanwhile. The caller holds the layer's
    /// download gate. Fails before anything is served when the staging budget
    /// has no room for the layer.
    pub(crate) fn start_download(
        &self,
        repo: &Repository,
        image: &str,
        digest: &ContentDigest,
        size: u64,
        response: reqwest::Response,
        http: UpstreamHttp,
    ) -> ImgResult<Arc<Download>> {
        let stage = self.inner.cas.stage_sized(size)?;
        let (download, progress) = Download::new(size, &stage, self.inner.store.clone());
        let key = Download::key(repo, image, digest);
        DOWNLOADS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone(), Arc::clone(&download));
        let registered = Registered(key);
        let reg = self.clone();
        let (repo, image, digest) = (repo.clone(), image.to_string(), digest.clone());
        let span = tracing::info_span!(
            "proxy layer download",
            repo = %repo.name,
            image = %image,
            digest = %digest,
        );
        let ending = Arc::clone(&download);
        tokio::spawn(
            async move {
                let downloaded = reg
                    .download(&repo, &image, &digest, stage, response, &http, &progress)
                    .await;
                // Remembered, and unregistered, before its readers learn how
                // it ended: a pull after a failure starts a new download,
                // never joins this one, and a group's retry asks its other
                // members first.
                Download::remember(&registered.0, downloaded.is_err());
                drop(registered);
                let stored = match downloaded {
                    Ok(stored) => Some(stored),
                    Err(failure) => {
                        tracing::warn!(
                            error = %failure.message(),
                            "registry proxy: downloading a layer failed; nothing cached"
                        );
                        None
                    }
                };
                ending.end(progress, stored);
            }
            .instrument(span),
        );
        Ok(download)
    }

    /// The download itself: staged, published to its readers as it
    /// arrives, verified, then stored and linked.
    #[allow(clippy::too_many_arguments)]
    async fn download(
        &self,
        repo: &Repository,
        image: &str,
        digest: &ContentDigest,
        mut stage: SizedStage,
        response: reqwest::Response,
        http: &UpstreamHttp,
        progress: &watch::Sender<Progress>,
    ) -> ImgResult<StoredLayer> {
        let staging = |e: CasError| match e {
            CasError::SizeMismatch { declared } => Failure::unavailable(format!(
                "the upstream served a blob of another size than the {declared} bytes it declared"
            )),
            e => Failure::from(e),
        };
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| upstream_unreachable(&e))?;
            stage.write(&chunk).await.map_err(staging)?;
            progress.send_replace(Progress::Staging {
                written: stage.written(),
            });
        }
        let staged = stage.finish().await.map_err(staging)?;
        http.count_bytes(staged.size);
        if !digest.matches(&staged.sha256, &staged.sha512_base64) {
            tracing::warn!(repo = %repo.name, image, %digest, "registry proxy: upstream blob does not match its digest");
            return Err(Failure::unavailable(
                "the upstream served a blob that does not match its digest",
            ));
        }
        progress.send_replace(Progress::Verified);
        let sha256 = staged.sha256.clone();
        let s3_key = self.store_fetched(repo, image, digest, staged).await?;
        Ok(StoredLayer { sha256, s3_key })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use forge_storage::{Cas, ConditionalWrites, S3Config, S3Credentials, Staging};

    use super::*;

    /// The staging budget of a test's CAS.
    const BUDGET: u64 = 1024 * 1024;

    /// A store and a CAS that stages only, with a budget of [`BUDGET`]:
    /// neither the store nor the pool ever connects.
    fn cas() -> (BlobStore, Cas) {
        let store = BlobStore::new(S3Config {
            endpoint: "http://127.0.0.1:9".into(),
            region: "us-east-1".into(),
            bucket: "unused".into(),
            credentials: S3Credentials::from_keys("unused", "unused"),
            force_path_style: true,
            multipart_threshold: 8 * 1024 * 1024,
            conditional_writes: ConditionalWrites::default(),
        });
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:9/unused")
            .expect("lazy pool");
        let staging = Staging::new(Staging::default_dir(), Some(BUDGET)).expect("staging");
        (store.clone(), Cas::new(store, pool).with_staging(staging))
    }

    /// A download of `size` bytes, its stage and its progress, as its task
    /// holds them, and the staging space it counts against.
    fn download(size: u64) -> (Arc<Download>, SizedStage, watch::Sender<Progress>, Staging) {
        let (store, cas) = cas();
        let stage = cas.stage_sized(size).unwrap();
        let (download, progress) = Download::new(size, &stage, store);
        (download, stage, progress, cas.staging().clone())
    }

    /// The bytes `staging` holds.
    fn in_use(staging: &Staging) -> u64 {
        staging.usage().expect("a budget").0
    }

    async fn write(stage: &mut SizedStage, progress: &watch::Sender<Progress>, bytes: &[u8]) {
        stage.write(bytes).await.unwrap();
        progress.send_replace(Progress::Staging {
            written: stage.written(),
        });
    }

    /// The next item of `stream`, unless it waits.
    async fn ready<S: Stream<Item = std::io::Result<Bytes>> + Unpin>(
        stream: &mut S,
    ) -> Option<Option<std::io::Result<Bytes>>> {
        tokio::time::timeout(Duration::from_millis(200), stream.next())
            .await
            .ok()
    }

    async fn chunk<S: Stream<Item = std::io::Result<Bytes>> + Unpin>(stream: &mut S) -> Bytes {
        ready(stream)
            .await
            .expect("ready")
            .expect("not ended")
            .expect("not failed")
    }

    #[tokio::test]
    async fn readers_follow_the_download_and_get_its_last_byte_once_verified() {
        let (download, mut stage, progress, _staging) = download(10);
        let mut whole = Box::pin(Arc::clone(&download).stream(0..10));
        let mut range = Box::pin(Arc::clone(&download).stream(4..6));
        assert!(ready(&mut whole).await.is_none(), "nothing arrived yet");

        write(&mut stage, &progress, b"01234").await;
        assert_eq!(chunk(&mut whole).await, "01234");
        assert_eq!(chunk(&mut range).await, "4");

        write(&mut stage, &progress, b"56789").await;
        assert_eq!(chunk(&mut whole).await, "5678", "all but the last byte");
        assert_eq!(chunk(&mut range).await, "5");
        assert!(
            matches!(ready(&mut range).await, Some(None)),
            "the range is done"
        );
        assert!(ready(&mut whole).await.is_none(), "the last byte waits");

        // Verified; the task stores it.
        progress.send_replace(Progress::Verified);
        assert_eq!(chunk(&mut whole).await, "9");
        assert!(matches!(ready(&mut whole).await, Some(None)));
        // A reader that comes later reads it all.
        let late = Box::pin(Arc::clone(&download).stream(0..10));
        let all: Vec<Bytes> = late.map(Result::unwrap).collect().await;
        assert_eq!(all.concat(), b"0123456789");
    }

    #[tokio::test]
    async fn a_failed_download_ends_its_readers_short() {
        let (download, mut stage, progress, staging) = download(10);
        let mut whole = Box::pin(Arc::clone(&download).stream(0..10));
        write(&mut stage, &progress, b"0123456789").await;
        assert_eq!(chunk(&mut whole).await, "012345678");
        // The task ended without verifying the layer (it did not match its
        // digest, the upstream broke off).
        drop(stage);
        download.end(progress, None);
        assert_eq!(in_use(&staging), 0, "the staged file is gone");
        assert!(matches!(ready(&mut whole).await, Some(Some(Err(_)))));
        let mut late = Box::pin(Arc::clone(&download).stream(9..10));
        assert!(matches!(ready(&mut late).await, Some(Some(Err(_)))));
    }

    #[tokio::test]
    async fn a_verified_download_that_is_not_stored_ends_its_readers_short() {
        let (download, mut stage, progress, staging) = download(10);
        let mut whole = Box::pin(Arc::clone(&download).stream(0..10));
        write(&mut stage, &progress, b"0123456789").await;
        assert_eq!(chunk(&mut whole).await, "012345678");
        progress.send_replace(Progress::Verified);
        // Storing it failed (the object store is down, the proxy was
        // repointed meanwhile).
        drop(stage);
        download.end(progress, None);
        assert_eq!(in_use(&staging), 0, "the staged file is gone");
        assert!(matches!(ready(&mut whole).await, Some(Some(Err(_)))));
    }

    /// A client that stops reading once the layer is verified, with its
    /// response not done, holds none of the staging space once the layer is
    /// stored: the response goes on from the store when it reads again
    /// (#763).
    #[tokio::test]
    async fn a_reader_that_stalls_after_verification_holds_no_staging_space_once_stored() {
        let (download, mut stage, progress, staging) = download(10);
        let mut stalled = Box::pin(Arc::clone(&download).stream(0..10));
        write(&mut stage, &progress, b"0123").await;
        assert_eq!(chunk(&mut stalled).await, "0123");
        write(&mut stage, &progress, b"456789").await;
        let staged = stage.finish().await.unwrap();
        progress.send_replace(Progress::Verified);
        assert_eq!(in_use(&staging), 10, "the whole layer is reserved");

        // Stored: the task lets go of the staged blob, and ends.
        drop(staged);
        assert_eq!(in_use(&staging), 10, "the download still holds it");
        download.end(
            progress,
            Some(StoredLayer {
                sha256: "unused".into(),
                s3_key: "unused".into(),
            }),
        );
        assert_eq!(
            in_use(&staging),
            0,
            "released, though a response is still on the layer"
        );
        assert!(download.staged().is_none());
        assert!(matches!(&*download.progress.borrow(), Progress::Stored(_)));
        drop(stalled);
    }
}
