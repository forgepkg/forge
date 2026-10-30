//! Where the files are, what writes them and what deletes them.
//!
//! Every key is under `traffic/v1/` in Forge's bucket:
//!
//! * `days/{date}/{instance}.parquet`: one instance's requests of a day
//!   (UTC), a row per repository and client network with their country and
//!   autonomous system; rewritten every minute while the day lasts. Kept as
//!   long as the settings say ([`TrafficSettings::retention_days`]).
//! * `geoip/{country,asn}.mmdb`: the geolocation databases
//!   ([`crate::geo`]).
//!
//! Each instance writes only files named after itself ([`instance_id`]), so
//! two instances never write the same object and a restarted process (a new
//! name) never overwrites what its predecessor wrote.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use futures_util::{stream, StreamExt};

use crate::geo::{Geo, Location};
use crate::objects::Objects;
use crate::record::{Drained, OTHER};
use crate::rows::{encode, DayRow};
use crate::TrafficSettings;

/// The prefix of the day files.
pub const DAYS: &str = "traffic/v1/days/";
/// The rows a day file holds before new client networks are counted as
/// [`OTHER`]: a bound on the memory and the file whatever the number of
/// addresses.
const MAX_DAY_ROWS: usize = 500_000;
/// Deletes and reads in flight at once.
pub(crate) const CONCURRENCY: usize = 16;

const DAY: i64 = 86_400;

/// The UTC date of `day` (Unix seconds), as the keys write it.
pub(crate) fn date(day: i64) -> String {
    Utc.timestamp_opt(day, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// The start of the day `date` (`YYYY-MM-DD`) names, in Unix seconds.
pub(crate) fn day_of(date: &str) -> Option<i64> {
    Some(
        NaiveDate::parse_from_str(date, "%Y-%m-%d")
            .ok()?
            .and_hms_opt(0, 0, 0)?
            .and_utc()
            .timestamp(),
    )
}

/// The prefix of the files of `day`.
pub fn day_prefix(day: i64) -> String {
    format!("{DAYS}{}/", date(day))
}

/// The key of `instance`'s file of `day`.
pub fn day_key(day: i64, instance: &str) -> String {
    format!("{}{instance}.parquet", day_prefix(day))
}

/// The day and the instance `key`, a day file's key, names; `None` for a
/// key Forge did not write.
pub fn parse_day_key(key: &str) -> Option<(i64, String)> {
    let (date, name) = key.strip_prefix(DAYS)?.split_once('/')?;
    let instance = name.strip_suffix(".parquet")?;
    if instance.is_empty() || instance.contains('/') {
        return None;
    }
    Some((day_of(date)?, instance.to_string()))
}

/// This process's name in the files: its host name (`-` for anything a
/// host name does not hold), when it started and a random suffix, so that
/// two processes never share one. No `.`, `_` or `/` but the separators.
pub fn instance_id(host: Option<&str>, started_at: DateTime<Utc>) -> String {
    let host: String = host
        .unwrap_or("forge")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .take(63)
        .collect();
    let host = if host.is_empty() {
        "forge".into()
    } else {
        host
    };
    format!(
        "{host}_{}_{:04x}",
        started_at.format("%Y%m%dT%H%M%SZ"),
        rand::random::<u16>()
    )
}

/// The host name and start time an [`instance_id`] holds.
pub fn instance_parts(id: &str) -> (String, Option<DateTime<Utc>>) {
    let mut parts = id.split('_');
    let host = parts.next().unwrap_or_default().to_string();
    let started = parts.next().and_then(|t| {
        chrono::NaiveDateTime::parse_from_str(t, "%Y%m%dT%H%M%SZ")
            .ok()
            .map(|t| t.and_utc())
    });
    (host, started)
}

/// What a day's row is counted under. With client addresses, the network
/// (its country and autonomous system are looked up when the file is
/// written); without, the country and autonomous system, looked up before
/// the address is dropped.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct RowKey {
    repository: String,
    network: String,
    country: String,
    asn: u32,
}

#[derive(Debug, Clone, Default)]
struct RowCounts {
    requests: u64,
    bytes: u64,
    /// The last address seen; `""` without addresses.
    address: String,
    /// The autonomous system's organisation, for a row without a network.
    as_org: String,
}

/// One instance's counts of a day.
#[derive(Debug, Default)]
struct Day {
    rows: BTreeMap<RowKey, RowCounts>,
    /// Where each network is, looked up once a day (again while unknown).
    located: HashMap<String, Location>,
    dirty: bool,
}

/// What a flush did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FlushReport {
    /// Files written.
    pub files: usize,
    /// Files that could not be written (written with the next flush).
    pub failures: usize,
}

/// Writes one instance's day files.
pub struct Flusher {
    objects: Arc<dyn Objects>,
    instance: Arc<str>,
    days: BTreeMap<i64, Day>,
}

fn signed(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl Flusher {
    /// The flusher of `instance`, writing to `objects`.
    pub fn new(objects: Arc<dyn Objects>, instance: Arc<str>) -> Flusher {
        Flusher {
            objects,
            instance,
            days: BTreeMap::new(),
        }
    }

    /// Add `drained` to its days, locating the client networks with `geo`,
    /// and write the files of the days that changed. A file that cannot be
    /// written is written with the next flush.
    pub async fn flush(
        &mut self,
        drained: Drained,
        settings: &TrafficSettings,
        geo: &Geo,
        now: DateTime<Utc>,
    ) -> FlushReport {
        if drained.overflowed > 0 {
            tracing::warn!(
                requests = drained.overflowed,
                "more client networks than the traffic statistics hold between two flushes; \
                 counted as `other`"
            );
        }
        for (key, counts) in drained.counts {
            let day = self.days.entry(key.day).or_default();
            day.dirty = true;
            let address = counts.address.map(|a| a.to_string()).unwrap_or_default();
            let mut row = if !settings.client_addresses || key.network.is_empty() {
                // No network to keep: locate the address now, then drop it.
                let at = counts.address.map(|a| geo.locate(a)).unwrap_or_default();
                (
                    RowKey {
                        repository: key.repository,
                        network: String::new(),
                        country: at.country,
                        asn: at.asn,
                    },
                    String::new(),
                    at.as_org,
                )
            } else {
                (
                    RowKey {
                        repository: key.repository,
                        network: key.network,
                        country: String::new(),
                        asn: 0,
                    },
                    address,
                    String::new(),
                )
            };
            if day.rows.len() >= MAX_DAY_ROWS && !day.rows.contains_key(&row.0) {
                row.0.network = OTHER.to_string();
                row.1.clear();
            }
            let (row_key, address, as_org) = row;
            let entry = day.rows.entry(row_key).or_default();
            entry.requests += counts.requests;
            entry.bytes += counts.bytes;
            if !address.is_empty() {
                entry.address = address;
            }
            if !as_org.is_empty() {
                entry.as_org = as_org;
            }
        }

        let mut report = FlushReport::default();
        for (start, day) in self.days.iter_mut().filter(|(_, d)| d.dirty) {
            let rows = day_rows(*start, day, geo);
            let key = day_key(*start, &self.instance);
            let written = match encode(&rows) {
                Ok(body) => self.objects.put(&key, body).await,
                Err(e) => Err(e),
            };
            match written {
                Ok(()) => {
                    day.dirty = false;
                    report.files += 1;
                }
                Err(e) => {
                    report.failures += 1;
                    tracing::warn!(error = %e, key, "cannot write the traffic statistics");
                }
            }
        }
        // Keep today and yesterday (a request that ended after midnight
        // counts in its own day), and any day not written yet but for a
        // week at most.
        let today = now.timestamp().div_euclid(DAY) * DAY;
        self.days
            .retain(|start, day| *start >= today - DAY || (day.dirty && *start >= today - 7 * DAY));
        report
    }
}

/// The rows of `day`, its networks located with `geo`.
fn day_rows(start: i64, day: &mut Day, geo: &Geo) -> Vec<DayRow> {
    let mut rows = Vec::with_capacity(day.rows.len());
    for (key, counts) in &day.rows {
        let at = if key.network.is_empty() || key.network == OTHER || counts.address.is_empty() {
            Location {
                country: key.country.clone(),
                asn: key.asn,
                as_org: counts.as_org.clone(),
            }
        } else {
            let known = day.located.get(&key.network);
            if known.is_some_and(|l| !l.country.is_empty() || l.asn != 0) {
                known.cloned().unwrap_or_default()
            } else {
                let at = counts
                    .address
                    .parse()
                    .map(|ip| geo.locate(ip))
                    .unwrap_or_default();
                day.located.insert(key.network.clone(), at.clone());
                at
            }
        };
        rows.push(DayRow {
            day: start,
            repository: key.repository.clone(),
            network: key.network.clone(),
            address: counts.address.clone(),
            country: at.country,
            asn: i64::from(at.asn),
            as_org: at.as_org,
            requests: signed(counts.requests),
            bytes: signed(counts.bytes),
        });
    }
    rows
}

/// Delete the day files past `settings`' retention, whoever wrote them.
/// Idempotent and safe on every instance at once. Returns how many files it
/// deleted.
pub async fn prune(
    objects: &dyn Objects,
    settings: &TrafficSettings,
    now: DateTime<Utc>,
) -> anyhow::Result<usize> {
    let today = now.timestamp().div_euclid(DAY) * DAY;
    let oldest_kept = today - i64::from(settings.retention_days.max(1) - 1) * DAY;
    let mut expired = Vec::new();
    for dir in objects.list_dirs(DAYS).await? {
        let Some(day) = dir
            .strip_prefix(DAYS)
            .and_then(|d| d.strip_suffix('/'))
            .and_then(day_of)
        else {
            continue;
        };
        if day < oldest_kept {
            expired.extend(objects.list(&dir).await?.into_iter().map(|o| o.key));
        }
    }
    let deleted = expired.len();
    let failures: Vec<anyhow::Error> = stream::iter(expired)
        .map(|key| async move { objects.delete(&key).await })
        .buffer_unordered(CONCURRENCY)
        .filter_map(|result| async move { result.err() })
        .collect()
        .await;
    match failures.into_iter().next() {
        Some(e) => Err(e.context("cannot delete expired traffic statistics")),
        None => Ok(deleted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::GeoKind;
    use crate::objects::MemoryObjects;
    use crate::record::{Event, Recorder};
    use crate::rows::decode;
    use crate::slot::Noted;
    use crate::testing::{asn_db, country_db};

    fn t(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap().to_utc()
    }

    #[test]
    fn keys_name_what_they_hold() {
        let day = t("2026-10-30T00:00:00Z").timestamp();
        let key = day_key(day, "web-1_x_0001");
        assert_eq!(key, "traffic/v1/days/2026-10-30/web-1_x_0001.parquet");
        assert_eq!(parse_key_ok(&key), (day, "web-1_x_0001".to_string()));
        assert!(parse_day_key("traffic/v1/days/2026-13-30/a.parquet").is_none());
        assert!(parse_day_key("traffic/v1/days/2026-10-30/a.csv").is_none());
        assert!(parse_day_key("traffic/v1/geoip/country.mmdb").is_none());
    }

    fn parse_key_ok(key: &str) -> (i64, String) {
        parse_day_key(key).unwrap()
    }

    #[test]
    fn an_instance_id_holds_its_host_and_start() {
        let started = t("2026-10-30T14:05:01Z");
        let id = instance_id(Some("forge-7d9f.pod_x"), started);
        assert!(id.starts_with("forge-7d9f-pod-x_20261030T140501Z_"), "{id}");
        assert_eq!(
            instance_parts(&id),
            ("forge-7d9f-pod-x".to_string(), Some(started))
        );
        assert!(instance_id(None, started).starts_with("forge_"));
    }

    fn event(at: &str, client: &str, repository: Option<&str>) -> Event {
        Event {
            at: t(at),
            bytes: 10,
            noted: Noted {
                client: client.parse().ok(),
                network: Some(client.into()),
                repository: repository.map(str::to_string),
            },
        }
    }

    fn geo() -> Geo {
        let geo = Geo::default();
        geo.load(
            GeoKind::Country,
            country_db(&[("192.0.2.0/24", "DE")]),
            "1".into(),
        )
        .unwrap();
        geo.load(
            GeoKind::Asn,
            asn_db(&[("192.0.2.0/24", 64_500, "Example AS")]),
            "1".into(),
        )
        .unwrap();
        geo
    }

    async fn rows(objects: &MemoryObjects, key: &str) -> Vec<DayRow> {
        decode(objects.get(key).await.unwrap().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn a_flush_writes_the_day_with_countries_and_networks() {
        let objects = Arc::new(MemoryObjects::default());
        let mut flusher = Flusher::new(objects.clone(), "a".into());
        let settings = TrafficSettings::default();
        let geo = geo();
        let recorder = Recorder::new();
        recorder.record(event("2026-10-30T14:00:10Z", "192.0.2.1", Some("npm")));
        recorder.record(event("2026-10-30T14:00:20Z", "192.0.2.1", Some("npm")));
        recorder.record(event("2026-10-30T14:01:20Z", "198.51.100.2", None));
        let now = t("2026-10-30T14:02:00Z");
        let report = flusher.flush(recorder.drain(), &settings, &geo, now).await;
        assert_eq!(
            report,
            FlushReport {
                files: 1,
                failures: 0
            }
        );

        recorder.record(event("2026-10-30T14:03:00Z", "192.0.2.1", Some("npm")));
        flusher.flush(recorder.drain(), &settings, &geo, now).await;
        let day = rows(&objects, "traffic/v1/days/2026-10-30/a.parquet").await;
        assert_eq!(day.len(), 2);
        let npm = day.iter().find(|r| r.repository == "npm").unwrap();
        assert_eq!((npm.requests, npm.bytes), (3, 30), "added up over flushes");
        assert_eq!(
            (
                npm.network.as_str(),
                npm.country.as_str(),
                npm.asn,
                npm.as_org.as_str()
            ),
            ("192.0.2.1", "DE", 64_500, "Example AS")
        );
        let other = day.iter().find(|r| r.repository.is_empty()).unwrap();
        assert_eq!(
            (other.country.as_str(), other.asn),
            ("", 0),
            "not in the databases"
        );

        // Nothing new: nothing written.
        let report = flusher.flush(recorder.drain(), &settings, &geo, now).await;
        assert_eq!(report.files, 0);
        // The next day: the day before is still kept, the one before that is not.
        recorder.record(event("2026-10-31T00:00:05Z", "192.0.2.1", Some("npm")));
        flusher
            .flush(recorder.drain(), &settings, &geo, t("2026-11-01T00:00:10Z"))
            .await;
        assert!(objects
            .keys()
            .contains(&"traffic/v1/days/2026-10-31/a.parquet".to_string()));
        assert_eq!(flusher.days.len(), 1);
    }

    #[tokio::test]
    async fn without_addresses_rows_keep_the_country_alone() {
        let objects = Arc::new(MemoryObjects::default());
        let mut flusher = Flusher::new(objects.clone(), "a".into());
        let settings = TrafficSettings {
            client_addresses: false,
            ..TrafficSettings::default()
        };
        let recorder = Recorder::new();
        recorder.record(event("2026-10-30T14:00:10Z", "192.0.2.1", Some("npm")));
        recorder.record(event("2026-10-30T14:00:20Z", "192.0.2.2", Some("npm")));
        let now = t("2026-10-30T14:02:00Z");
        flusher
            .flush(recorder.drain(), &settings, &geo(), now)
            .await;
        let day = rows(&objects, "traffic/v1/days/2026-10-30/a.parquet").await;
        assert_eq!(day.len(), 1, "both addresses in one row");
        assert_eq!(
            (
                day[0].network.as_str(),
                day[0].address.as_str(),
                day[0].country.as_str()
            ),
            ("", "", "DE")
        );
        assert_eq!((day[0].requests, day[0].asn), (2, 64_500));
    }

    #[tokio::test]
    async fn pruning_deletes_the_days_past_the_retention() {
        let objects = MemoryObjects::default();
        let day = |d: &str| t(&format!("{d}T00:00:00Z")).timestamp();
        for key in [
            day_key(day("2026-07-31"), "a"),
            day_key(day("2026-08-01"), "a"),
            day_key(day("2026-08-01"), "b"),
            day_key(day("2026-10-30"), "a"),
            "traffic/v1/days/not-a-date/x.parquet".to_string(),
            "traffic/v1/geoip/country.mmdb".to_string(),
        ] {
            objects.put(&key, vec![1]).await.unwrap();
        }
        // 90 days up to 2026-10-29: from 2026-08-01 on.
        let deleted = prune(
            &objects,
            &TrafficSettings::default(),
            t("2026-10-29T12:00:00Z"),
        )
        .await
        .unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(
            objects.keys(),
            vec![
                "traffic/v1/days/2026-08-01/a.parquet",
                "traffic/v1/days/2026-08-01/b.parquet",
                "traffic/v1/days/2026-10-30/a.parquet",
                "traffic/v1/days/not-a-date/x.parquet",
                "traffic/v1/geoip/country.mmdb",
            ]
        );
    }
}
