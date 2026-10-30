//! Forge's traffic statistics: what every instance answered, counted in time
//! buckets and kept as Parquet files in the object store, so that any
//! instance can show the traffic of all of them (Admin → Traffic).
//!
//! * **Recording** ([`Recorder`]) is a counter update in memory, behind one
//!   short lock: no I/O on the request path. A request is counted in its
//!   minute by surface, repository, method and status (requests, response
//!   bytes, a latency histogram), its client address in that minute's top
//!   list ([`TopClients`], bounded whatever the number of addresses), and,
//!   with the request log on, as a row of the log.
//! * **What a request is** comes from the layers that know it: the server's
//!   outermost middleware opens a [`Slot`] around the request, and the
//!   principal layer ([`note_client`], [`note_account`]) and the handlers
//!   that resolve a repository ([`note_repository`]) fill it in.
//! * **Flushing** ([`Flusher`]) runs once a minute on every instance. Each
//!   instance writes files of its own ([`layout`]), named after the process
//!   ([`instance_id`]), so instances never write the same object:
//!   * per hour, its buckets and top clients by minute, rewritten every
//!     minute while the hour lasts;
//!   * per day, the same by hour;
//!   * every minute, the rows of the request log since the last flush.
//! * **Reading** ([`query`]) lists the files of a range in the object store,
//!   reads them (closed files are cached) and sums them: the view over all
//!   instances needs no call between them.
//! * **Pruning** ([`layout::prune`]) deletes the files past their retention
//!   ([`TrafficSettings`]); it is idempotent and runs on every instance.
//!
//! Client addresses are personal data: they are kept apart from the counts
//! (the `clients` files and the request log), with a retention of their own,
//! and can be switched off.

pub mod layout;
pub mod objects;
pub mod query;
mod record;
mod rows;
mod settings;
mod slot;
mod top;

use std::sync::Arc;

pub use layout::{instance_id, FlushReport, Flusher};
pub use objects::{Listed, MemoryObjects, Objects};
pub use record::{Drained, Event, Minute, Recorder};
pub use rows::{BucketKey, Counts, LATENCY_BOUNDS_MS};
pub use settings::{TrafficSettings, MAX_RETENTION_DAYS};
pub use slot::{note_account, note_client, note_repository, Account, Noted, Slot};
pub use top::{ClientCounts, TopClients};

/// What the server holds of the traffic statistics: this instance's
/// [`Recorder`] and [`Flusher`], the object store the files go to, and the
/// cache of the files read back.
#[derive(Clone)]
pub struct Traffic {
    /// Counts this instance's requests.
    pub recorder: Arc<Recorder>,
    /// Where the files are written and read.
    pub objects: Arc<dyn Objects>,
    /// This process's name in the files ([`instance_id`]).
    pub instance: Arc<str>,
    /// Files read back, decoded ([`query`]).
    pub cache: query::FileCache,
    /// Writes this instance's files. Shared, so that it outlives a restart
    /// of the worker and the last flush on shutdown adds to what the worker
    /// wrote instead of replacing it.
    flusher: Arc<tokio::sync::Mutex<Flusher>>,
}

impl Traffic {
    /// The statistics of the instance `instance`, kept in `objects`.
    pub fn new(objects: Arc<dyn Objects>, instance: String) -> Traffic {
        let instance: Arc<str> = instance.into();
        Traffic {
            recorder: Arc::new(Recorder::new()),
            flusher: Arc::new(tokio::sync::Mutex::new(Flusher::new(
                objects.clone(),
                instance.clone(),
            ))),
            objects,
            instance,
            cache: query::FileCache::new(),
        }
    }

    /// Write the minutes that ended before `now`, and the request log.
    pub async fn flush(
        &self,
        settings: &TrafficSettings,
        now: chrono::DateTime<chrono::Utc>,
    ) -> FlushReport {
        let mut flusher = self.flusher.lock().await;
        flusher.flush(self.recorder.drain(now), settings, now).await
    }

    /// Write everything counted, the minute still being counted included
    /// (on shutdown).
    pub async fn flush_all(&self, settings: &TrafficSettings) -> FlushReport {
        let mut flusher = self.flusher.lock().await;
        flusher
            .flush(self.recorder.drain_all(), settings, chrono::Utc::now())
            .await
    }
}
