//! Where the files are, what writes them and what deletes them.
//!
//! Every key is under `traffic/v1/` in Forge's bucket, by area, then date
//! and hour (UTC), then the writing instance ([`instance_id`]):
//!
//! * `minutes/{date}/{hour}/{instance}.buckets.parquet` and
//!   `….clients.parquet`: one instance's counts and top clients of an hour,
//!   by minute; rewritten every minute while the hour lasts. Kept
//!   [`MINUTE_RETENTION_DAYS`] (the clients no longer than the clients'
//!   retention).
//! * `hours/{date}/{instance}.buckets.parquet` and `….clients.parquet`:
//!   the same of a day, by hour; rewritten every minute while the day lasts.
//!   Kept as long as the settings say ([`TrafficSettings`]).
//! * `requests/{date}/{hour}/{instance}.{unix ms}.parquet`: the request
//!   log's rows of one flush.
//!
//! Each instance writes only files named after itself, so two instances
//! never write the same object and a restarted process (a new name) never
//! overwrites what its predecessor wrote.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use futures_util::{stream, StreamExt};

use crate::objects::Objects;
use crate::record::Drained;
use crate::rows::{encode, BucketKey, BucketRow, ClientRow, Counts};
use crate::top::{ClientCounts, TopClients};
use crate::TrafficSettings;

/// The prefix of every key.
pub const ROOT: &str = "traffic/v1/";
/// How long the counts by minute are kept: long enough for the views of the
/// last 48 hours.
pub const MINUTE_RETENTION_DAYS: u32 = 3;
/// The top clients a file keeps per time bucket.
pub const TOP_PER_BUCKET: usize = 100;
/// The networks an hour of a day file keeps track of before its top list
/// is cut to [`TOP_PER_BUCKET`].
const HOUR_CLIENTS: usize = 4_096;
/// Deletes and reads in flight at once.
pub(crate) const CONCURRENCY: usize = 16;

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;

/// The three areas of files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// By minute, a file per instance and hour.
    Minutes,
    /// By hour, a file per instance and day.
    Hours,
    /// The request log.
    Requests,
}

impl Area {
    /// The prefix of the area's keys.
    pub fn prefix(self) -> &'static str {
        match self {
            Area::Minutes => "traffic/v1/minutes/",
            Area::Hours => "traffic/v1/hours/",
            Area::Requests => "traffic/v1/requests/",
        }
    }

    /// How long one of its files covers, in seconds.
    pub fn span(self) -> i64 {
        match self {
            Area::Minutes | Area::Requests => HOUR,
            Area::Hours => DAY,
        }
    }

    /// The prefix of its files of the day starting at `day` (Unix seconds).
    pub fn day_prefix(self, day: i64) -> String {
        format!("{}{}/", self.prefix(), date(day))
    }
}

/// What a file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Buckets,
    Clients,
    Requests,
}

/// A file, as its key names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileKey {
    pub area: Area,
    pub kind: FileKind,
    /// The start of the time it covers ([`Area::span`]), Unix seconds.
    pub start: i64,
    /// The instance that wrote it ([`instance_id`]).
    pub instance: String,
}

fn date(start: i64) -> String {
    Utc.timestamp_opt(start, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

fn hour_of_day(start: i64) -> String {
    format!("{:02}", start.rem_euclid(DAY) / HOUR)
}

fn kind_suffix(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Buckets => "buckets",
        FileKind::Clients => "clients",
        FileKind::Requests => "requests",
    }
}

/// The key of the counts file (`kind` buckets or clients) of `instance`
/// covering the hour (minutes area) or day (hours area) starting at
/// `start`.
pub fn counts_key(area: Area, start: i64, instance: &str, kind: FileKind) -> String {
    let suffix = kind_suffix(kind);
    match area {
        Area::Minutes => format!(
            "{}{}/{}/{instance}.{suffix}.parquet",
            area.prefix(),
            date(start),
            hour_of_day(start)
        ),
        Area::Hours | Area::Requests => {
            format!(
                "{}{}/{instance}.{suffix}.parquet",
                area.prefix(),
                date(start)
            )
        }
    }
}

/// The key of the request log file `instance` flushes at `at`.
pub fn log_key(at: DateTime<Utc>, instance: &str) -> String {
    let start = at.timestamp();
    format!(
        "{}{}/{}/{instance}.{}.parquet",
        Area::Requests.prefix(),
        date(start),
        hour_of_day(start),
        at.timestamp_millis()
    )
}

/// What `key`, a key of `area`, names; `None` for a key Forge did not
/// write.
pub fn parse_key(area: Area, key: &str) -> Option<FileKey> {
    let rest = key.strip_prefix(area.prefix())?;
    let mut parts = rest.split('/');
    let day = NaiveDate::parse_from_str(parts.next()?, "%Y-%m-%d").ok()?;
    let mut start = day.and_hms_opt(0, 0, 0)?.and_utc().timestamp();
    if area != Area::Hours {
        let hour: i64 = parts.next()?.parse().ok()?;
        if !(0..24).contains(&hour) {
            return None;
        }
        start += hour * HOUR;
    }
    let name = parts.next()?.strip_suffix(".parquet")?;
    if parts.next().is_some() {
        return None;
    }
    let (instance, suffix) = name.split_once('.')?;
    let kind = match (area, suffix) {
        (Area::Requests, millis) if millis.parse::<i64>().is_ok() => FileKind::Requests,
        (Area::Minutes | Area::Hours, "buckets") => FileKind::Buckets,
        (Area::Minutes | Area::Hours, "clients") => FileKind::Clients,
        _ => return None,
    };
    Some(FileKey {
        area,
        kind,
        start,
        instance: instance.to_string(),
    })
}

/// This process's name in the files: its host name (`-` for anything a
/// host name does not hold), when it started and a random suffix, so that
/// two processes never share one. No `.` or `_` but the separators.
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

/// One instance's counts of an hour (by minute) or a day (by hour), as
/// written to its files.
#[derive(Debug, Default)]
struct Period {
    buckets: BTreeMap<(i64, BucketKey), Counts>,
    clients: BTreeMap<i64, TopClients>,
    dirty: bool,
}

impl Period {
    fn bucket_rows(&self) -> Vec<BucketRow> {
        self.buckets
            .iter()
            .map(|((start, key), counts)| BucketRow::new(*start, key, counts))
            .collect()
    }

    fn client_rows(&self) -> Vec<ClientRow> {
        let mut rows = Vec::new();
        for (start, top) in &self.clients {
            for (network, c) in top.top(TOP_PER_BUCKET) {
                rows.push(client_row(*start, network, c));
            }
        }
        rows
    }
}

fn client_row(start: i64, network: &str, c: &ClientCounts) -> ClientRow {
    let signed = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
    ClientRow {
        start,
        network: network.to_string(),
        address: c.address.clone(),
        requests: signed(c.requests),
        bytes: signed(c.bytes),
        client_errors: signed(c.client_errors),
        denied: signed(c.denied),
        not_found: signed(c.not_found),
        throttled: signed(c.throttled),
        server_errors: signed(c.server_errors),
        user_agent: c.user_agent.clone(),
        account: c.account.clone(),
        user_id: c.user_id.unwrap_or(0),
    }
}

/// What a flush did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FlushReport {
    /// Files written.
    pub files: usize,
    /// Request log rows written.
    pub log_rows: usize,
    /// Writes that failed (retried with the next flush, but for the log).
    pub failures: usize,
}

/// Writes one instance's files: the counts of the hours and days not over
/// yet, and the request log.
pub struct Flusher {
    objects: Arc<dyn Objects>,
    instance: Arc<str>,
    hours: BTreeMap<i64, Period>,
    days: BTreeMap<i64, Period>,
}

impl Flusher {
    /// The flusher of `instance`, writing to `objects`.
    pub fn new(objects: Arc<dyn Objects>, instance: Arc<str>) -> Flusher {
        Flusher {
            objects,
            instance,
            hours: BTreeMap::new(),
            days: BTreeMap::new(),
        }
    }

    /// Add `drained` to the hours and days it falls in and write the files
    /// that changed, and the request log rows. A file that cannot be written
    /// is written with the next flush; log rows that cannot be are dropped.
    pub async fn flush(
        &mut self,
        drained: Drained,
        settings: &TrafficSettings,
        now: DateTime<Utc>,
    ) -> FlushReport {
        let mut report = FlushReport::default();
        for minute in drained.minutes {
            let hour = minute.start - minute.start.rem_euclid(HOUR);
            let day = minute.start - minute.start.rem_euclid(DAY);
            let in_hour = self.hours.entry(hour).or_default();
            let in_day = self.days.entry(day).or_default();
            for (key, counts) in &minute.buckets {
                in_hour
                    .buckets
                    .entry((minute.start, key.clone()))
                    .or_default()
                    .add(counts);
                in_day
                    .buckets
                    .entry((hour, key.clone()))
                    .or_default()
                    .add(counts);
            }
            if settings.client_addresses && !minute.clients.is_empty() {
                let top = in_hour
                    .clients
                    .entry(minute.start)
                    .or_insert_with(|| TopClients::new(TOP_PER_BUCKET));
                top.merge(&minute.clients);
                top.truncate(TOP_PER_BUCKET);
                in_day
                    .clients
                    .entry(hour)
                    .or_insert_with(|| TopClients::new(HOUR_CLIENTS))
                    .merge(&minute.clients);
            }
            in_hour.dirty = true;
            in_day.dirty = true;
        }
        if !settings.client_addresses {
            for period in self.hours.values_mut().chain(self.days.values_mut()) {
                period.clients.clear();
            }
        }

        let instance = self.instance.clone();
        for (area, periods) in [
            (Area::Minutes, &mut self.hours),
            (Area::Hours, &mut self.days),
        ] {
            for (start, period) in periods.iter_mut().filter(|(_, p)| p.dirty) {
                let mut ok = true;
                let mut files = vec![(FileKind::Buckets, encode(&period.bucket_rows()))];
                if settings.client_addresses {
                    files.push((FileKind::Clients, encode(&period.client_rows())));
                }
                for (kind, body) in files {
                    let key = counts_key(area, *start, &instance, kind);
                    match body {
                        Ok(body) => match self.objects.put(&key, body).await {
                            Ok(()) => report.files += 1,
                            Err(e) => {
                                tracing::warn!(error = %e, key, "cannot write the traffic statistics");
                                ok = false;
                            }
                        },
                        Err(e) => {
                            tracing::error!(error = %e, key, "cannot encode the traffic statistics");
                            ok = false;
                        }
                    }
                }
                if ok {
                    period.dirty = false;
                } else {
                    report.failures += 1;
                }
            }
        }

        if drained.log_dropped > 0 {
            tracing::warn!(
                dropped = drained.log_dropped,
                "the request log dropped rows: more requests than it holds between two flushes"
            );
        }
        if !drained.log.is_empty() {
            let key = log_key(now, &instance);
            let written = match encode(&drained.log) {
                Ok(body) => self.objects.put(&key, body).await,
                Err(e) => Err(e),
            };
            match written {
                Ok(()) => {
                    report.files += 1;
                    report.log_rows = drained.log.len();
                }
                Err(e) => {
                    report.failures += 1;
                    tracing::warn!(
                        error = %e,
                        key,
                        rows = drained.log.len(),
                        "cannot write the request log; its rows are lost"
                    );
                }
            }
        }

        self.forget(now);
        report
    }

    /// Drop the periods that are over and written, and the ones that could
    /// not be written for too long; cut the top lists of the hours that are
    /// over.
    fn forget(&mut self, now: DateTime<Utc>) {
        let now = now.timestamp();
        let this_hour = now - now.rem_euclid(HOUR);
        let today = now - now.rem_euclid(DAY);
        self.hours.retain(|start, period| {
            *start >= this_hour || (period.dirty && *start >= this_hour - 3 * HOUR)
        });
        self.days
            .retain(|start, period| *start >= today || (period.dirty && *start >= today - DAY));
        for day in self.days.values_mut() {
            for (hour, top) in day.clients.iter_mut() {
                if *hour < this_hour {
                    top.truncate(TOP_PER_BUCKET);
                }
            }
        }
    }
}

/// How long the files of `area` holding `kind` are kept, in seconds;
/// `None` to keep them.
pub fn retention(settings: &TrafficSettings, area: Area, kind: FileKind) -> Option<i64> {
    let days = |d: u32| i64::from(d) * DAY;
    match (area, kind) {
        (Area::Minutes, FileKind::Clients) => Some(days(
            MINUTE_RETENTION_DAYS.min(settings.client_retention_days),
        )),
        (Area::Minutes, _) => Some(days(MINUTE_RETENTION_DAYS)),
        (Area::Hours, FileKind::Clients) => Some(days(settings.client_retention_days)),
        (Area::Hours, _) => match settings.statistics_retention_days {
            0 => None,
            d => Some(days(d)),
        },
        (Area::Requests, _) => Some(days(settings.request_log_retention_days)),
    }
}

/// Delete the files past their retention ([`retention`]), whoever wrote
/// them. Idempotent and safe on every instance at once. Returns how many
/// files it deleted.
pub async fn prune(
    objects: &dyn Objects,
    settings: &TrafficSettings,
    now: DateTime<Utc>,
) -> anyhow::Result<usize> {
    let now = now.timestamp();
    let mut expired = Vec::new();
    for area in [Area::Minutes, Area::Hours, Area::Requests] {
        let kinds: &[FileKind] = match area {
            Area::Requests => &[FileKind::Requests],
            _ => &[FileKind::Buckets, FileKind::Clients],
        };
        // A day can hold expired files once the shortest retention of the
        // area has passed since it ended.
        let Some(shortest) = kinds
            .iter()
            .filter_map(|kind| retention(settings, area, *kind))
            .min()
        else {
            continue;
        };
        for dir in objects.list_dirs(area.prefix()).await? {
            let Some(day) = dir
                .strip_prefix(area.prefix())
                .and_then(|d| d.strip_suffix('/'))
                .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .map(|d| d.and_utc().timestamp())
            else {
                continue;
            };
            if day + area.span() + shortest > now {
                // Even its earliest file is within the shortest retention.
                continue;
            }
            for listed in objects.list(&dir).await? {
                let Some(file) = parse_key(area, &listed.key) else {
                    continue;
                };
                if retention(settings, area, file.kind)
                    .is_some_and(|keep| file.start + area.span() + keep <= now)
                {
                    expired.push(listed.key);
                }
            }
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
    use crate::objects::MemoryObjects;
    use crate::record::{Event, Recorder};
    use crate::rows::decode;
    use crate::slot::Noted;
    use std::time::Duration;

    fn t(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap().to_utc()
    }

    #[test]
    fn keys_name_what_they_hold() {
        let start = t("2026-10-30T14:00:00Z").timestamp();
        let key = counts_key(Area::Minutes, start, "web-1_x_0001", FileKind::Clients);
        assert_eq!(
            key,
            "traffic/v1/minutes/2026-10-30/14/web-1_x_0001.clients.parquet"
        );
        let parsed = parse_key(Area::Minutes, &key).unwrap();
        assert_eq!(
            (parsed.start, parsed.kind, parsed.instance.as_str()),
            (start, FileKind::Clients, "web-1_x_0001")
        );

        let day = t("2026-10-30T00:00:00Z").timestamp();
        let key = counts_key(Area::Hours, day, "web-1", FileKind::Buckets);
        assert_eq!(key, "traffic/v1/hours/2026-10-30/web-1.buckets.parquet");
        assert_eq!(parse_key(Area::Hours, &key).unwrap().start, day);

        let key = log_key(t("2026-10-30T14:05:01.250Z"), "web-1");
        assert_eq!(
            key,
            "traffic/v1/requests/2026-10-30/14/web-1.1793369101250.parquet"
        );
        assert_eq!(parse_key(Area::Requests, &key).unwrap().start, start);

        assert!(parse_key(
            Area::Minutes,
            "traffic/v1/minutes/2026-10-30/24/a.buckets.parquet"
        )
        .is_none());
        assert!(parse_key(Area::Hours, "traffic/v1/hours/2026-10-30/a.other.parquet").is_none());
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

    fn event(at: DateTime<Utc>, network: &str) -> Event {
        Event {
            at,
            surface: "oci",
            method: "GET",
            status: 200,
            duration: Duration::from_millis(3),
            bytes: 10,
            path: "/v2/".into(),
            user_agent: None,
            noted: Noted {
                client: network.parse().ok(),
                network: Some(network.into()),
                account: None,
                repository: Some("docker".into()),
            },
        }
    }

    #[tokio::test]
    async fn a_flush_writes_the_hour_the_day_and_the_log() {
        let objects = Arc::new(MemoryObjects::default());
        let mut flusher = Flusher::new(objects.clone(), "a".into());
        let settings = TrafficSettings::default();
        let recorder = Recorder::new();
        recorder.record(event(t("2026-10-30T14:00:10Z"), "192.0.2.1"));
        recorder.record(event(t("2026-10-30T14:00:20Z"), "192.0.2.1"));
        recorder.record(event(t("2026-10-30T14:01:20Z"), "192.0.2.2"));
        let now = t("2026-10-30T14:02:00Z");
        let report = flusher.flush(recorder.drain(now), &settings, now).await;
        assert_eq!(
            report,
            FlushReport {
                files: 5,
                log_rows: 3,
                failures: 0
            }
        );
        let keys = objects.keys();
        assert!(keys.contains(&"traffic/v1/hours/2026-10-30/a.buckets.parquet".to_string()));

        let rows: Vec<BucketRow> = decode(
            objects
                .get("traffic/v1/minutes/2026-10-30/14/a.buckets.parquet")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rows.len(), 2, "one row per minute and key");
        assert_eq!(rows[0].requests, 2);

        // The next hour: the previous hour's files are not rewritten.
        recorder.record(event(t("2026-10-30T15:00:05Z"), "192.0.2.1"));
        let now = t("2026-10-30T15:01:00Z");
        let report = flusher.flush(recorder.drain(now), &settings, now).await;
        assert_eq!(
            report.files, 5,
            "the new hour's two, the day's two, the log"
        );
        assert_eq!(flusher.hours.len(), 1, "the hour that is over is forgotten");
        let day: Vec<BucketRow> = decode(
            objects
                .get("traffic/v1/hours/2026-10-30/a.buckets.parquet")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(day.len(), 2, "one row per hour");
        assert_eq!(day.iter().map(|r| r.requests).sum::<i64>(), 4);
    }

    #[tokio::test]
    async fn pruning_deletes_by_area_and_kind() {
        let objects = MemoryObjects::default();
        let day = |d: &str| t(&format!("{d}T00:00:00Z")).timestamp();
        for key in [
            counts_key(Area::Minutes, day("2026-10-25"), "a", FileKind::Buckets),
            counts_key(Area::Minutes, day("2026-10-29"), "a", FileKind::Buckets),
            counts_key(Area::Hours, day("2025-01-01"), "a", FileKind::Buckets),
            counts_key(Area::Hours, day("2026-09-01"), "a", FileKind::Buckets),
            counts_key(Area::Hours, day("2026-09-01"), "a", FileKind::Clients),
            log_key(t("2026-10-20T10:00:00Z"), "a"),
            log_key(t("2026-10-29T10:00:00Z"), "a"),
            "traffic/v1/hours/not-a-date/x.buckets.parquet".to_string(),
        ] {
            objects.put(&key, vec![1]).await.unwrap();
        }
        let deleted = prune(
            &objects,
            &TrafficSettings::default(),
            t("2026-10-30T12:00:00Z"),
        )
        .await
        .unwrap();
        assert_eq!(deleted, 4);
        assert_eq!(
            objects.keys(),
            vec![
                "traffic/v1/hours/2026-09-01/a.buckets.parquet",
                "traffic/v1/hours/not-a-date/x.buckets.parquet",
                "traffic/v1/minutes/2026-10-29/00/a.buckets.parquet",
                "traffic/v1/requests/2026-10-29/10/a.1793268000000.parquet",
            ]
        );
    }
}
