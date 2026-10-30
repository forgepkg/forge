//! Counting requests in memory, minute by minute.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::rows::{BucketKey, Counts, LogRow};
use crate::slot::Noted;
use crate::top::TopClients;
use crate::TrafficSettings;

/// The networks a minute's top list keeps track of ([`TopClients`]).
const MINUTE_CLIENTS: usize = 1_024;
/// The keys a minute counts under before new repositories are counted
/// without their name: a bound whatever the handlers note.
const MAX_KEYS_PER_MINUTE: usize = 10_000;
/// The request log rows kept between two flushes; more are dropped (and
/// counted in the log of the flush).
const MAX_LOG_ROWS: usize = 250_000;
/// The closed minutes kept while flushes fail; older ones are dropped.
const MAX_CLOSED_MINUTES: usize = 180;
/// The longest path and user agent the request log keeps, in bytes.
const MAX_PATH_BYTES: usize = 1_024;
const MAX_USER_AGENT_BYTES: usize = 256;

/// One answered request.
#[derive(Debug, Clone)]
pub struct Event {
    /// When the response was sent (its body done or cut off).
    pub at: DateTime<Utc>,
    /// The surface (`forge_telemetry::http::Surface`).
    pub surface: &'static str,
    pub method: &'static str,
    pub status: u16,
    /// Time to the response headers.
    pub duration: Duration,
    /// Response body bytes sent.
    pub bytes: u64,
    /// The path as the log keeps it (secrets replaced); empty when the log
    /// is off ([`Recorder::logs_requests`]).
    pub path: String,
    pub user_agent: Option<String>,
    /// What the layers of the request noted ([`crate::Slot`]).
    pub noted: Noted,
}

/// The counts of one minute.
#[derive(Debug, Clone)]
pub struct Minute {
    /// Its start, in Unix seconds.
    pub start: i64,
    pub buckets: HashMap<BucketKey, Counts>,
    pub clients: TopClients,
}

impl Minute {
    fn new(start: i64) -> Minute {
        Minute {
            start,
            buckets: HashMap::new(),
            clients: TopClients::new(MINUTE_CLIENTS),
        }
    }

    fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// What a flush takes from the [`Recorder`].
#[derive(Debug, Default)]
pub struct Drained {
    /// The minutes counted to the end.
    pub minutes: Vec<Minute>,
    pub(crate) log: Vec<LogRow>,
    /// Log rows dropped for want of room.
    pub log_dropped: u64,
}

#[derive(Debug)]
struct Pending {
    current: Minute,
    closed: Vec<Minute>,
    log: Vec<LogRow>,
}

/// Counts this instance's requests until the next flush.
#[derive(Debug)]
pub struct Recorder {
    enabled: AtomicBool,
    addresses: AtomicBool,
    log: AtomicBool,
    log_dropped: AtomicU64,
    pending: Mutex<Pending>,
}

impl Default for Recorder {
    fn default() -> Self {
        Recorder::new()
    }
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn clip(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

impl Recorder {
    /// A recorder with the default settings ([`TrafficSettings::default`]),
    /// until [`Self::apply`] says otherwise.
    pub fn new() -> Recorder {
        let defaults = TrafficSettings::default();
        Recorder {
            enabled: AtomicBool::new(defaults.enabled),
            addresses: AtomicBool::new(defaults.client_addresses),
            log: AtomicBool::new(defaults.request_log),
            log_dropped: AtomicU64::new(0),
            pending: Mutex::new(Pending {
                current: Minute::new(0),
                closed: Vec::new(),
                log: Vec::new(),
            }),
        }
    }

    /// Follow `settings` from the next request on.
    pub fn apply(&self, settings: &TrafficSettings) {
        self.enabled.store(settings.enabled, Ordering::Relaxed);
        self.addresses
            .store(settings.client_addresses, Ordering::Relaxed);
        self.log.store(settings.request_log, Ordering::Relaxed);
    }

    /// Whether requests are counted at all.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Whether requests go to the request log: only then does an
    /// [`Event`] need its path.
    pub fn logs_requests(&self) -> bool {
        self.enabled() && self.log.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count `event`.
    pub fn record(&self, event: Event) {
        if !self.enabled() {
            return;
        }
        let addresses = self.addresses.load(Ordering::Relaxed);
        let Event {
            at,
            surface,
            method,
            status,
            duration,
            bytes,
            path,
            user_agent,
            noted,
        } = event;
        let user_agent = user_agent.map(|ua| clip(ua, MAX_USER_AGENT_BYTES));
        let (network, address) = match (addresses, noted.network, noted.client) {
            (true, Some(network), client) => {
                (network, client.map(|c| c.to_string()).unwrap_or_default())
            }
            _ => (String::new(), String::new()),
        };
        let (account, user_id) = noted
            .account
            .map(|a| (a.kind, a.user_id))
            .unwrap_or(("", None));
        let repository = noted.repository.unwrap_or_default();
        let row = self.log.load(Ordering::Relaxed).then(|| LogRow {
            time_ms: at.timestamp_millis(),
            network: network.clone(),
            address: address.clone(),
            method: method.to_string(),
            path: clip(path, MAX_PATH_BYTES),
            surface: surface.to_string(),
            repository: repository.clone(),
            status: i32::from(status),
            bytes: i64::try_from(bytes).unwrap_or(i64::MAX),
            duration_us: i64::try_from(duration.as_micros()).unwrap_or(i64::MAX),
            user_agent: user_agent.clone().unwrap_or_default(),
            account: account.to_string(),
            user_id: user_id.unwrap_or(0),
        });
        let mut key = BucketKey {
            surface: surface.to_string(),
            repository,
            method: method.to_string(),
            status,
        };

        let minute = at.timestamp().div_euclid(60) * 60;
        let mut pending = self.lock();
        if minute > pending.current.start {
            let done = std::mem::replace(&mut pending.current, Minute::new(minute));
            if !done.is_empty() {
                pending.closed.push(done);
                if pending.closed.len() > MAX_CLOSED_MINUTES {
                    pending.closed.remove(0);
                }
            }
        }
        // A request that ended in an earlier minute than one already counted
        // (the clock stepped back) counts in the current one.
        let current = &mut pending.current;
        if current.buckets.len() >= MAX_KEYS_PER_MINUTE && !current.buckets.contains_key(&key) {
            key.repository.clear();
        }
        current
            .buckets
            .entry(key)
            .or_default()
            .observe(duration, bytes);
        if !network.is_empty() {
            let client = current.clients.entry(&network);
            client.observe(status, bytes);
            client.address = address;
            if let Some(ua) = user_agent {
                client.user_agent = ua;
            }
            if !account.is_empty() {
                client.account = account.to_string();
                client.user_id = user_id;
            }
        }
        if let Some(row) = row {
            if pending.log.len() < MAX_LOG_ROWS {
                pending.log.push(row);
            } else {
                self.log_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Take the minutes that ended before `now`, and the request log.
    pub fn drain(&self, now: DateTime<Utc>) -> Drained {
        self.take(Some(now.timestamp().div_euclid(60) * 60))
    }

    /// Take everything, the minute still being counted included (on
    /// shutdown).
    pub fn drain_all(&self) -> Drained {
        self.take(None)
    }

    fn take(&self, before: Option<i64>) -> Drained {
        let mut pending = self.lock();
        let close = before.is_none_or(|start| pending.current.start < start);
        if close && !pending.current.is_empty() {
            let next = Minute::new(before.unwrap_or(pending.current.start));
            let done = std::mem::replace(&mut pending.current, next);
            pending.closed.push(done);
        }
        Drained {
            minutes: std::mem::take(&mut pending.closed),
            log: std::mem::take(&mut pending.log),
            log_dropped: self.log_dropped.swap(0, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot::Account;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn event(secs: i64, status: u16) -> Event {
        Event {
            at: at(secs),
            surface: "nuget",
            method: "GET",
            status,
            duration: Duration::from_millis(12),
            bytes: 100,
            path: "/repository/nuget/v3/index.json".into(),
            user_agent: Some("NuGet Command Line/6.0".into()),
            noted: Noted {
                client: Some("192.0.2.10".parse().unwrap()),
                network: Some("192.0.2.10".into()),
                account: Some(Account {
                    kind: "token",
                    user_id: Some(7),
                }),
                repository: Some("nuget".into()),
            },
        }
    }

    #[test]
    fn minutes_close_when_the_next_one_starts() {
        let r = Recorder::new();
        // 1_700_000_000 is 20 s into its minute: the first two requests
        // share it, the third starts the next one.
        r.record(event(0, 200));
        r.record(event(30, 404));
        r.record(event(45, 200));
        let early = r.drain(at(41));
        assert_eq!(early.minutes.len(), 1, "the first minute ended");
        assert_eq!(early.minutes[0].start, 1_699_999_980);
        assert_eq!(early.log.len(), 3, "the log goes with every flush");
        let minute = &early.minutes[0];
        let ok = BucketKey {
            surface: "nuget".into(),
            repository: "nuget".into(),
            method: "GET".into(),
            status: 200,
        };
        assert_eq!(minute.buckets[&ok].requests, 1);
        let top = minute.clients.top(1);
        assert_eq!(top[0].0, "192.0.2.10");
        assert_eq!(top[0].1.user_id, Some(7));

        let rest = r.drain_all();
        assert_eq!(rest.minutes.len(), 1);
        assert_eq!(rest.minutes[0].start, 1_700_000_040);
        assert_eq!(
            rest.minutes[0]
                .buckets
                .values()
                .map(|c| c.requests)
                .sum::<u64>(),
            1
        );
        assert!(r.drain_all().minutes.is_empty());
    }

    #[test]
    fn settings_switch_parts_off() {
        let r = Recorder::new();
        r.apply(&TrafficSettings {
            client_addresses: false,
            request_log: false,
            ..TrafficSettings::default()
        });
        assert!(!r.logs_requests());
        r.record(event(0, 200));
        let d = r.drain_all();
        assert!(d.log.is_empty());
        assert!(d.minutes[0].clients.is_empty(), "no addresses");

        r.apply(&TrafficSettings {
            enabled: false,
            ..TrafficSettings::default()
        });
        r.record(event(0, 200));
        assert!(r.drain_all().minutes.is_empty());
    }

    #[test]
    fn long_values_are_clipped_on_a_char_boundary() {
        assert_eq!(clip("äää".into(), 3), "ä");
        assert_eq!(clip("abc".into(), 10), "abc");
    }
}
