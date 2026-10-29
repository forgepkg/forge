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
//! * A download is registered from its start until its layer is linked, or
//!   it failed. The proxy starts and joins downloads under the layer's
//!   download gate, so a pull finds the layer either linked or downloading;
//!   a pull after a failure starts a new download.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use bytes::Bytes;
use forge_core::net::upstream::UpstreamHttp;
use forge_db::model::Repository;
use forge_storage::{CasError, SizedStage, StageReader};
use futures_util::{Stream, StreamExt};
use tokio::sync::watch;
use tracing::Instrument;

use super::digest::ContentDigest;
use super::proxy::upstream_unreachable;
use super::{Failure, ImgResult, Registry};

/// The most a response reads of the staged file at once.
const READ_CHUNK: usize = 256 * 1024;

/// The downloads of this process, by [`Download::key`].
static DOWNLOADS: LazyLock<Mutex<HashMap<String, Arc<Download>>>> = LazyLock::new(Default::default);

/// A layer a proxy is downloading, for the pulls served from it.
pub(crate) struct Download {
    /// The layer's size, as the upstream declared it.
    pub size: u64,
    reader: StageReader,
    progress: watch::Receiver<Progress>,
}

/// How far a download is.
#[derive(Debug, Clone, Copy, Default)]
struct Progress {
    /// The bytes in the staged file.
    written: u64,
    /// Whether all of them are there and match the layer's digest. A
    /// download whose task ended without it failed.
    verified: bool,
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

    /// How much of the layer may be served: what is written, its last byte
    /// only once the layer matches its digest.
    fn readable(&self, progress: Progress) -> u64 {
        if progress.verified {
            self.size
        } else {
            progress.written.min(self.size.saturating_sub(1))
        }
    }

    /// The bytes `range` of the layer, as they arrive. The stream fails,
    /// cutting its response short, when the download does.
    pub(crate) fn stream(
        self: Arc<Self>,
        range: Range<u64>,
    ) -> impl Stream<Item = std::io::Result<Bytes>> + Send + 'static {
        let end = range.end;
        let progress = self.progress.clone();
        futures_util::stream::try_unfold(
            (self, progress, range.start),
            move |(download, mut progress, at)| async move {
                if at >= end {
                    return Ok(None);
                }
                loop {
                    let ready = download.readable(*progress.borrow_and_update()).min(end);
                    if at < ready {
                        let len = usize::try_from(ready - at)
                            .unwrap_or(usize::MAX)
                            .min(READ_CHUNK);
                        let bytes = download.reader.read_at(at, len).await?;
                        if bytes.is_empty() {
                            return Err(std::io::Error::other("the staged layer ended early"));
                        }
                        let next = at + bytes.len() as u64;
                        return Ok(Some((bytes, (download, progress, next))));
                    }
                    if progress.changed().await.is_err() && !progress.borrow().verified {
                        return Err(std::io::Error::other(
                            "the upstream download of the layer failed",
                        ));
                    }
                }
            },
        )
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
        let (progress, watched) = watch::channel(Progress::default());
        let download = Arc::new(Download {
            size,
            reader: stage.reader(),
            progress: watched,
        });
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
        tokio::spawn(
            async move {
                let downloaded = reg
                    .download(&repo, &image, &digest, stage, response, &http, &progress)
                    .await;
                // Unregistered before its readers learn that it failed: a
                // pull after that starts a new download, never joins this one.
                drop(registered);
                drop(progress);
                if let Err(failure) = downloaded {
                    tracing::warn!(
                        error = %failure.message(),
                        "registry proxy: downloading a layer failed; nothing cached"
                    );
                }
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
    ) -> ImgResult<()> {
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
            progress.send_replace(Progress {
                written: stage.written(),
                verified: false,
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
        progress.send_replace(Progress {
            written: staged.size,
            verified: true,
        });
        self.store_fetched(repo, image, digest, staged).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use forge_storage::{BlobStore, Cas, ConditionalWrites, S3Config, S3Credentials};

    use super::*;

    /// A CAS that stages only: its store and pool never connect.
    fn cas() -> Cas {
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
        Cas::new(store, pool)
    }

    /// A download of `size` bytes, its stage and its progress, as its task
    /// holds them.
    fn download(size: u64) -> (Arc<Download>, SizedStage, watch::Sender<Progress>) {
        let stage = cas().stage_sized(size).unwrap();
        let (progress, watched) = watch::channel(Progress::default());
        let download = Arc::new(Download {
            size,
            reader: stage.reader(),
            progress: watched,
        });
        (download, stage, progress)
    }

    async fn write(stage: &mut SizedStage, progress: &watch::Sender<Progress>, bytes: &[u8]) {
        stage.write(bytes).await.unwrap();
        progress.send_replace(Progress {
            written: stage.written(),
            verified: false,
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
        let (download, mut stage, progress) = download(10);
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

        // Verified, and the task ended.
        progress.send_replace(Progress {
            written: 10,
            verified: true,
        });
        drop(progress);
        assert_eq!(chunk(&mut whole).await, "9");
        assert!(matches!(ready(&mut whole).await, Some(None)));
        // A reader that comes later reads it all.
        let late = Box::pin(Arc::clone(&download).stream(0..10));
        let all: Vec<Bytes> = late.map(Result::unwrap).collect().await;
        assert_eq!(all.concat(), b"0123456789");
    }

    #[tokio::test]
    async fn a_failed_download_ends_its_readers_short() {
        let (download, mut stage, progress) = download(10);
        let mut whole = Box::pin(Arc::clone(&download).stream(0..10));
        write(&mut stage, &progress, b"0123456789").await;
        assert_eq!(chunk(&mut whole).await, "012345678");
        // The task ended without verifying the layer (it did not match its
        // digest, the upstream broke off).
        drop(progress);
        assert!(matches!(ready(&mut whole).await, Some(Some(Err(_)))));
        let mut late = Box::pin(Arc::clone(&download).stream(9..10));
        assert!(matches!(ready(&mut late).await, Some(Some(Err(_)))));
    }
}
