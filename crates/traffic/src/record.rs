//! Counting requests in memory until the next flush.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use chrono::{DateTime, Utc};

use crate::slot::Noted;

/// The keys counted between two flushes before new client networks are
/// counted as [`OTHER`]: a bound whatever the number of addresses.
const MAX_PENDING: usize = 100_000;

/// The network requests are counted under past a bound.
pub const OTHER: &str = "other";

const DAY: i64 = 86_400;

/// One answered request.
#[derive(Debug, Clone)]
pub struct Event {
    /// When the response was sent (its body done or cut off).
    pub at: DateTime<Utc>,
    /// Response body bytes sent.
    pub bytes: u64,
    /// What the layers of the request noted ([`crate::Slot`]).
    pub noted: Noted,
}

/// What requests are counted under until the next flush.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingKey {
    /// The start of the day (UTC), in Unix seconds.
    pub day: i64,
    /// `""` for none.
    pub repository: String,
    /// `""` for none.
    pub network: String,
}

/// The counts of a [`PendingKey`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingCounts {
    pub requests: u64,
    pub bytes: u64,
    /// The last address of the network seen. Kept in memory until the
    /// flush looks up its country and autonomous system, even with client
    /// addresses switched off.
    pub address: Option<IpAddr>,
}

/// What a flush takes from the [`Recorder`].
#[derive(Debug, Default)]
pub struct Drained {
    pub counts: Vec<(PendingKey, PendingCounts)>,
    /// Requests counted under [`OTHER`] for want of room.
    pub overflowed: u64,
}

/// Counts this instance's requests until the next flush.
#[derive(Debug)]
pub struct Recorder {
    enabled: AtomicBool,
    overflowed: AtomicU64,
    pending: Mutex<HashMap<PendingKey, PendingCounts>>,
}

impl Default for Recorder {
    fn default() -> Self {
        Recorder::new()
    }
}

impl Recorder {
    /// A recorder that counts until [`Self::set_enabled`] says otherwise.
    pub fn new() -> Recorder {
        Recorder {
            enabled: AtomicBool::new(true),
            overflowed: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Count requests from the next one on, or not.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether requests are counted.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Count `event`.
    pub fn record(&self, event: Event) {
        if !self.enabled() {
            return;
        }
        let Event { at, bytes, noted } = event;
        let mut key = PendingKey {
            day: at.timestamp().div_euclid(DAY) * DAY,
            repository: noted.repository.unwrap_or_default(),
            network: noted.network.unwrap_or_default(),
        };
        let mut address = noted.client;
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending.len() >= MAX_PENDING && !pending.contains_key(&key) {
            key.network = OTHER.to_string();
            address = None;
            self.overflowed.fetch_add(1, Ordering::Relaxed);
        }
        let counts = pending.entry(key).or_default();
        counts.requests += 1;
        counts.bytes += bytes;
        if address.is_some() {
            counts.address = address;
        }
    }

    /// Take what was counted since the last call.
    pub fn drain(&self) -> Drained {
        let pending =
            std::mem::take(&mut *self.pending.lock().unwrap_or_else(PoisonError::into_inner));
        Drained {
            counts: pending.into_iter().collect(),
            overflowed: self.overflowed.swap(0, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn event(secs: i64, network: &str, repository: Option<&str>) -> Event {
        Event {
            at: Utc.timestamp_opt(1_793_318_400 + secs, 0).unwrap(),
            bytes: 100,
            noted: Noted {
                client: network.parse().ok(),
                network: Some(network.into()),
                repository: repository.map(str::to_string),
            },
        }
    }

    #[test]
    fn requests_are_counted_by_day_repository_and_network() {
        let r = Recorder::new();
        r.record(event(10, "192.0.2.1", Some("npm")));
        r.record(event(20, "192.0.2.1", Some("npm")));
        r.record(event(30, "192.0.2.1", None));
        r.record(event(DAY + 1, "192.0.2.1", Some("npm")));
        let mut counts = r.drain().counts;
        counts.sort_by_key(|(k, _)| (k.day, k.repository.clone()));
        assert_eq!(counts.len(), 3);
        assert_eq!(counts[0].0.repository, "");
        assert_eq!(counts[1].1.requests, 2);
        assert_eq!(counts[1].1.bytes, 200);
        assert_eq!(counts[1].1.address, "192.0.2.1".parse().ok());
        assert_eq!(counts[2].0.day, 1_793_318_400 + DAY);
        assert!(r.drain().counts.is_empty(), "drained");
    }

    #[test]
    fn switched_off_it_counts_nothing() {
        let r = Recorder::new();
        r.set_enabled(false);
        r.record(event(0, "192.0.2.1", None));
        assert!(r.drain().counts.is_empty());
    }
}
