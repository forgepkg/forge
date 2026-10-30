//! Forge's traffic statistics: how many requests each client network made to
//! each repository on each day, from which country and autonomous system,
//! kept as Parquet files in the object store, so that any instance can show
//! the traffic of all of them (Admin → Traffic).
//!
//! * **Recording** ([`Recorder`]) is a counter update in memory, behind one
//!   short lock: no I/O on the request path. A request is counted under its
//!   day (UTC), its repository and its client network, with the bytes sent.
//! * **What a request is** comes from the layers that know it: the server's
//!   outermost middleware opens a [`Slot`] around the request, and the
//!   principal layer ([`note_client`]) and the handlers that resolve a
//!   repository ([`note_repository`]) fill it in.
//! * **Flushing** ([`Flusher`]) runs once a minute on every instance: it
//!   locates the client networks in the geolocation databases ([`geo`]) and
//!   rewrites the instance's file of the day ([`layout`]), named after the
//!   process ([`instance_id`]), so instances never write the same object.
//! * **Reading** ([`query`]) lists the files of a range of days in the
//!   object store, reads them (cached by ETag) and sums them: the view over
//!   all instances needs no call between them.
//! * **Pruning** ([`layout::prune`]) deletes the days past their retention
//!   ([`TrafficSettings`]); it is idempotent and runs on every instance.
//!
//! Client addresses are personal data: they can be switched off, and then
//! requests are still counted by repository, country and autonomous system,
//! the address only looked up in memory before it is dropped.

pub mod geo;
pub mod layout;
pub mod objects;
pub mod query;
mod record;
mod rows;
mod settings;
mod slot;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::sync::Arc;

pub use geo::{DbInfo, Geo, GeoKind, Location};
pub use layout::{instance_id, FlushReport, Flusher};
pub use objects::{Listed, MemoryObjects, Objects};
pub use record::{Drained, Event, PendingCounts, PendingKey, Recorder, OTHER};
pub use settings::{TrafficSettings, MAX_RETENTION_DAYS};
pub use slot::{note_client, note_repository, Noted, Slot};

/// What the server holds of the traffic statistics: this instance's
/// [`Recorder`] and [`Flusher`], the geolocation databases, the object store
/// the files go to, and the cache of the files read back.
#[derive(Clone)]
pub struct Traffic {
    /// Counts this instance's requests.
    pub recorder: Arc<Recorder>,
    /// The geolocation databases this instance loaded.
    pub geo: Arc<Geo>,
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
            geo: Arc::new(Geo::default()),
            flusher: Arc::new(tokio::sync::Mutex::new(Flusher::new(
                objects.clone(),
                instance.clone(),
            ))),
            objects,
            instance,
            cache: query::FileCache::new(),
        }
    }

    /// Write what was counted since the last flush.
    pub async fn flush(
        &self,
        settings: &TrafficSettings,
        now: chrono::DateTime<chrono::Utc>,
    ) -> FlushReport {
        let mut flusher = self.flusher.lock().await;
        flusher
            .flush(self.recorder.drain(), settings, &self.geo, now)
            .await
    }
}
