//! Reading the files back: the traffic of a time range, over all instances
//! or one, and one client's.
//!
//! A range of up to [`MINUTE_RANGE_HOURS`] hours within the minute files'
//! retention is read from them (by minute); a longer one from the files by
//! hour. The files are found by listing the days of the range, read in
//! parallel and summed. Files of counts are cached decoded, keyed by their
//! ETag, so a file rewritten since is read again.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use futures_util::{stream, StreamExt, TryStreamExt};
use serde::Serialize;

use crate::layout::{instance_parts, parse_key, Area, FileKey, FileKind, CONCURRENCY};
use crate::objects::{Listed, Objects};
use crate::rows::{decode, BucketRow, ClientRow, Counts, LogRow, LATENCY_BOUNDS_MS};

/// The longest range read by minute, in hours.
pub const MINUTE_RANGE_HOURS: i64 = 48;
/// The longest stretch of the request log a client's view reads, in hours.
pub const LOG_RANGE_HOURS: i64 = 24;
/// The most request log rows a client's view returns.
pub const LOG_LIMIT: usize = 500;
/// The lists' lengths: top repositories, top clients.
pub const TOP: usize = 20;
/// The most points of a series.
const MAX_POINTS: i64 = 180;
/// The steps a series may take, in seconds.
const STEPS: [i64; 13] = [
    60, 300, 600, 900, 1_800, 3_600, 7_200, 10_800, 21_600, 43_200, 86_400, 172_800, 604_800,
];
/// The rows the cache of decoded files holds.
const CACHE_ROWS: u64 = 100_000;

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;

#[derive(Debug)]
enum Decoded {
    Buckets(Vec<BucketRow>),
    Clients(Vec<ClientRow>),
}

impl Decoded {
    fn rows(&self) -> usize {
        match self {
            Decoded::Buckets(rows) => rows.len(),
            Decoded::Clients(rows) => rows.len(),
        }
    }
}

/// Files of counts read back, decoded.
#[derive(Clone)]
pub struct FileCache(moka::future::Cache<String, Arc<Decoded>>);

impl FileCache {
    pub fn new() -> FileCache {
        FileCache(
            moka::future::Cache::builder()
                .max_capacity(CACHE_ROWS)
                .weigher(|_, d: &Arc<Decoded>| u32::try_from(d.rows().max(1)).unwrap_or(u32::MAX))
                .build(),
        )
    }
}

impl Default for FileCache {
    fn default() -> Self {
        FileCache::new()
    }
}

/// An instance, as the views name it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstanceView {
    /// Its name in the files ([`crate::instance_id`]).
    pub id: String,
    pub host: String,
    pub started_at: Option<DateTime<Utc>>,
}

impl InstanceView {
    fn of(id: &str) -> InstanceView {
        let (host, started_at) = instance_parts(id);
        InstanceView {
            id: id.to_string(),
            host,
            started_at,
        }
    }
}

/// The time range a view covers, and its points.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Span {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// The length of a point of the series.
    pub step_seconds: i64,
    /// What the files read count by: `minute` or `hour`.
    pub resolution: &'static str,
}

impl Span {
    /// The span of `[from, to)` read at `now`: by minute when it is short
    /// and recent enough, else by hour; `from` aligned down to the step.
    pub fn new(from: DateTime<Utc>, to: DateTime<Utc>, now: DateTime<Utc>) -> Span {
        // The end rounded up to the second: a request of the second the
        // range ends in (the request log's times are in milliseconds) is in.
        let to_s = to.timestamp() + i64::from(to.timestamp_subsec_nanos() > 0);
        let (from_s, to_s) = (from.timestamp(), to_s.max(from.timestamp() + 60));
        let minute_files_from =
            now.timestamp() - i64::from(crate::layout::MINUTE_RETENTION_DAYS) * DAY + HOUR;
        let by_minute = to_s - from_s <= MINUTE_RANGE_HOURS * HOUR && from_s >= minute_files_from;
        let resolution = if by_minute { 60 } else { HOUR };
        let step = STEPS
            .into_iter()
            .filter(|step| *step >= resolution)
            .find(|step| (to_s - from_s).div_euclid(*step) <= MAX_POINTS)
            .unwrap_or(STEPS[STEPS.len() - 1]);
        let from_s = from_s - from_s.rem_euclid(step);
        Span {
            from: at(from_s),
            to: at(to_s),
            step_seconds: step,
            resolution: if by_minute { "minute" } else { "hour" },
        }
    }

    fn area(&self) -> Area {
        if self.resolution == "minute" {
            Area::Minutes
        } else {
            Area::Hours
        }
    }

    fn contains(&self, start: i64) -> bool {
        (self.from.timestamp()..self.to.timestamp()).contains(&start)
    }

    fn point(&self, start: i64) -> usize {
        usize::try_from((start - self.from.timestamp()).div_euclid(self.step_seconds)).unwrap_or(0)
    }

    fn points(&self) -> Vec<Point> {
        let mut points = Vec::new();
        let mut start = self.from.timestamp();
        while start < self.to.timestamp() {
            points.push(Point {
                start: at(start),
                ..Point::default()
            });
            start += self.step_seconds;
        }
        points
    }
}

fn at(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().unwrap_or_default()
}

/// A point of a series.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Point {
    pub start: DateTime<Utc>,
    pub requests: u64,
    pub bytes: u64,
    pub client_errors: u64,
    pub server_errors: u64,
}

impl Point {
    fn add(&mut self, status: u16, requests: u64, bytes: u64) {
        self.requests += requests;
        self.bytes += bytes;
        match status {
            400..=499 => self.client_errors += requests,
            500..=599 => self.server_errors += requests,
            _ => {}
        }
    }
}

/// The counts of a range.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Totals {
    pub requests: u64,
    pub bytes: u64,
    /// 4xx answers (the next three included).
    pub client_errors: u64,
    /// 401 and 403 answers.
    pub denied: u64,
    pub not_found: u64,
    /// 429 answers.
    pub throttled: u64,
    /// 5xx answers.
    pub server_errors: u64,
    /// The mean time to the response headers.
    pub mean_ms: Option<f64>,
    /// The latency histogram's bound below which half, 95 % and 99 % of
    /// the requests were answered ([`LATENCY_BOUNDS_MS`]); `None` without
    /// requests, and above the last bound.
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
    pub p99_ms: Option<u64>,
}

impl Totals {
    fn add_status(&mut self, status: u16, requests: u64) {
        match status {
            401 | 403 => self.denied += requests,
            404 => self.not_found += requests,
            429 => self.throttled += requests,
            _ => {}
        }
        match status {
            400..=499 => self.client_errors += requests,
            500..=599 => self.server_errors += requests,
            _ => {}
        }
    }

    fn finish(&mut self, counts: &Counts) {
        if counts.requests == 0 {
            return;
        }
        self.mean_ms = Some(counts.duration_us as f64 / counts.requests as f64 / 1_000.0);
        let quantile = |q: f64| {
            let wanted = (counts.requests as f64 * q).ceil() as u64;
            let mut seen = 0;
            for (i, n) in counts.latency.iter().enumerate() {
                seen += n;
                if seen >= wanted {
                    return LATENCY_BOUNDS_MS.get(i).copied();
                }
            }
            None
        };
        self.p50_ms = quantile(0.5);
        self.p95_ms = quantile(0.95);
        self.p99_ms = quantile(0.99);
    }
}

/// A surface's share of a range.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SurfaceShare {
    pub surface: String,
    pub requests: u64,
    pub bytes: u64,
}

/// A repository's share of a range.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RepositoryShare {
    pub name: String,
    pub requests: u64,
    pub bytes: u64,
    pub client_errors: u64,
    pub server_errors: u64,
}

/// A status's share of a range.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusShare {
    pub status: u16,
    pub requests: u64,
}

/// A client network's counts in a range.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ClientView {
    pub network: String,
    /// The last address of the network seen.
    pub address: String,
    pub requests: u64,
    pub bytes: u64,
    pub client_errors: u64,
    pub denied: u64,
    pub not_found: u64,
    pub throttled: u64,
    pub server_errors: u64,
    pub user_agent: Option<String>,
    /// The last account kind seen.
    pub account: Option<String>,
    pub user_id: Option<i64>,
    /// The user's name, filled in by the server.
    pub username: Option<String>,
    /// The hosts of the instances it reached.
    pub hosts: Vec<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// The traffic of a range: `GET /admin/traffic`.
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    #[serde(flatten)]
    pub span: Span,
    /// The instances whose files the range holds (whatever the instance
    /// asked for).
    pub instances: Vec<InstanceView>,
    pub totals: Totals,
    pub series: Vec<Point>,
    pub surfaces: Vec<SurfaceShare>,
    /// The [`TOP`] repositories with the most requests.
    pub repositories: Vec<RepositoryShare>,
    pub statuses: Vec<StatusShare>,
    /// The [`TOP`] client networks with the most requests (by the top
    /// lists of the time buckets, whatever the repository asked for).
    pub clients: Vec<ClientView>,
}

/// What to read.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Only the files of this instance ([`crate::instance_id`]).
    pub instance: Option<String>,
    /// Only the counts of this repository.
    pub repository: Option<String>,
}

/// The files of `area` covering any of `[from, to)`.
async fn files(
    objects: &dyn Objects,
    area: Area,
    from: i64,
    to: i64,
) -> anyhow::Result<Vec<(FileKey, Listed)>> {
    let first_day = (from - area.span() + 1).div_euclid(DAY) * DAY;
    let days: Vec<i64> = (0..)
        .map(|i| first_day + i * DAY)
        .take_while(|day| *day < to)
        .collect();
    let listings: Vec<Vec<Listed>> = stream::iter(days)
        .map(|day| async move { objects.list(&area.day_prefix(day)).await })
        .buffered(CONCURRENCY)
        .try_collect()
        .await?;
    Ok(listings
        .into_iter()
        .flatten()
        .filter_map(|listed| Some((parse_key(area, &listed.key)?, listed)))
        .filter(|(file, _)| file.start < to && file.start + area.span() > from)
        .collect())
}

/// The decoded file `listed`, from the cache when it holds this version.
async fn read_counts(
    objects: &dyn Objects,
    cache: &FileCache,
    file: &FileKey,
    listed: &Listed,
) -> anyhow::Result<Option<Arc<Decoded>>> {
    let cache_key = format!("{}#{}", listed.key, listed.etag.as_deref().unwrap_or(""));
    if let Some(hit) = cache.0.get(&cache_key).await {
        return Ok(Some(hit));
    }
    let Some(body) = objects.get(&listed.key).await? else {
        // Deleted since the listing (pruned).
        return Ok(None);
    };
    let decoded = match file.kind {
        FileKind::Buckets => Decoded::Buckets(decode(body)?),
        FileKind::Clients => Decoded::Clients(decode(body)?),
        FileKind::Requests => return Ok(None),
    };
    let decoded = Arc::new(decoded);
    if listed.etag.is_some() {
        cache.0.insert(cache_key, decoded.clone()).await;
    }
    Ok(Some(decoded))
}

/// The files of counts of `span` (of `filter`'s instance, if any), read,
/// with the instance that wrote each; and every instance found.
async fn read_span(
    objects: &dyn Objects,
    cache: &FileCache,
    span: &Span,
    instance: Option<&str>,
    kinds: &[FileKind],
) -> anyhow::Result<(Vec<(String, Arc<Decoded>)>, Vec<InstanceView>)> {
    let found = files(
        objects,
        span.area(),
        span.from.timestamp(),
        span.to.timestamp(),
    )
    .await?;
    let instances: BTreeSet<String> = found.iter().map(|(f, _)| f.instance.clone()).collect();
    let wanted: Vec<(FileKey, Listed)> = found
        .into_iter()
        .filter(|(f, _)| kinds.contains(&f.kind))
        .filter(|(f, _)| instance.is_none_or(|i| i == f.instance))
        .collect();
    let read: Vec<Option<(String, Arc<Decoded>)>> = stream::iter(wanted)
        .map(|(file, listed)| async move {
            let decoded = read_counts(objects, cache, &file, &listed).await?;
            anyhow::Ok(decoded.map(|d| (file.instance, d)))
        })
        .buffer_unordered(CONCURRENCY)
        .try_collect()
        .await?;
    Ok((
        read.into_iter().flatten().collect(),
        instances.iter().map(|id| InstanceView::of(id)).collect(),
    ))
}

/// Sum client rows into views by network.
fn sum_clients<'a>(rows: impl Iterator<Item = (&'a str, &'a ClientRow)>) -> Vec<ClientView> {
    let mut by_network: HashMap<&str, (ClientView, i64, BTreeSet<String>)> = HashMap::new();
    for (instance, row) in rows {
        let (view, latest, hosts) = by_network.entry(&row.network).or_insert_with(|| {
            (
                ClientView {
                    network: row.network.clone(),
                    ..ClientView::default()
                },
                i64::MIN,
                BTreeSet::new(),
            )
        });
        let n = |v: i64| u64::try_from(v).unwrap_or(0);
        view.requests += n(row.requests);
        view.bytes += n(row.bytes);
        view.client_errors += n(row.client_errors);
        view.denied += n(row.denied);
        view.not_found += n(row.not_found);
        view.throttled += n(row.throttled);
        view.server_errors += n(row.server_errors);
        hosts.insert(instance_parts(instance).0);
        let start = at(row.start);
        view.first_seen = Some(view.first_seen.map_or(start, |s| s.min(start)));
        view.last_seen = Some(view.last_seen.map_or(start, |s| s.max(start)));
        if row.start >= *latest {
            *latest = row.start;
            let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
            if !row.address.is_empty() {
                view.address.clone_from(&row.address);
            }
            if let Some(ua) = some(&row.user_agent) {
                view.user_agent = Some(ua);
            }
            if let Some(account) = some(&row.account) {
                view.account = Some(account);
                view.user_id = (row.user_id != 0).then_some(row.user_id);
            }
        }
    }
    let mut views: Vec<ClientView> = by_network
        .into_values()
        .map(|(mut view, _, hosts)| {
            view.hosts = hosts.into_iter().collect();
            view
        })
        .collect();
    views.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.network.cmp(&b.network)));
    views
}

/// The traffic of `span` over `objects`' files.
pub async fn overview(
    objects: &dyn Objects,
    cache: &FileCache,
    span: Span,
    filter: &Filter,
) -> anyhow::Result<Overview> {
    let (files, instances) = read_span(
        objects,
        cache,
        &span,
        filter.instance.as_deref(),
        &[FileKind::Buckets, FileKind::Clients],
    )
    .await?;

    let mut series = span.points();
    let mut totals = Totals::default();
    let mut all = Counts::default();
    let mut surfaces: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    let mut repositories: HashMap<&str, RepositoryShare> = HashMap::new();
    let mut statuses: BTreeMap<u16, u64> = BTreeMap::new();
    let mut clients = Vec::new();
    for (instance, decoded) in &files {
        match &**decoded {
            Decoded::Buckets(rows) => {
                for row in rows {
                    if !span.contains(row.start)
                        || filter
                            .repository
                            .as_deref()
                            .is_some_and(|r| r != row.repository)
                    {
                        continue;
                    }
                    let counts = row.counts();
                    let status = u16::try_from(row.status).unwrap_or(0);
                    all.add(&counts);
                    totals.add_status(status, counts.requests);
                    if let Some(point) = series.get_mut(span.point(row.start)) {
                        point.add(status, counts.requests, counts.bytes);
                    }
                    let surface = surfaces.entry(&row.surface).or_default();
                    surface.0 += counts.requests;
                    surface.1 += counts.bytes;
                    *statuses.entry(status).or_default() += counts.requests;
                    if !row.repository.is_empty() {
                        let share = repositories.entry(&row.repository).or_insert_with(|| {
                            RepositoryShare {
                                name: row.repository.clone(),
                                requests: 0,
                                bytes: 0,
                                client_errors: 0,
                                server_errors: 0,
                            }
                        });
                        share.requests += counts.requests;
                        share.bytes += counts.bytes;
                        match status {
                            400..=499 => share.client_errors += counts.requests,
                            500..=599 => share.server_errors += counts.requests,
                            _ => {}
                        }
                    }
                }
            }
            Decoded::Clients(rows) => clients.extend(
                rows.iter()
                    .filter(|row| span.contains(row.start))
                    .map(|row| (instance.as_str(), row)),
            ),
        }
    }
    totals.requests = all.requests;
    totals.bytes = all.bytes;
    totals.finish(&all);

    let mut surfaces: Vec<SurfaceShare> = surfaces
        .into_iter()
        .map(|(surface, (requests, bytes))| SurfaceShare {
            surface: surface.to_string(),
            requests,
            bytes,
        })
        .collect();
    surfaces.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.surface.cmp(&b.surface)));
    let mut repositories: Vec<RepositoryShare> = repositories.into_values().collect();
    repositories.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.name.cmp(&b.name)));
    repositories.truncate(TOP);
    let mut clients = sum_clients(clients.into_iter());
    clients.truncate(TOP);

    Ok(Overview {
        span,
        instances,
        totals,
        series,
        surfaces,
        repositories,
        statuses: statuses
            .into_iter()
            .map(|(status, requests)| StatusShare { status, requests })
            .collect(),
        clients,
    })
}

/// A request of the request log.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LogEntry {
    pub time: DateTime<Utc>,
    pub address: String,
    pub method: String,
    pub path: String,
    pub surface: String,
    pub repository: Option<String>,
    pub status: u16,
    pub bytes: u64,
    /// Time to the response headers.
    pub duration_ms: f64,
    pub user_agent: Option<String>,
    pub account: Option<String>,
    pub user_id: Option<i64>,
    /// The user's name, filled in by the server.
    pub username: Option<String>,
    /// The host of the instance that answered.
    pub host: String,
}

/// How often a value occurs in a client's log.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Tally {
    pub value: String,
    pub requests: u64,
}

/// How often an account occurs in a client's log.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccountTally {
    /// The account kind ([`crate::Account::kind`]); `None` when unknown.
    pub account: Option<String>,
    pub user_id: Option<i64>,
    /// The user's name, filled in by the server.
    pub username: Option<String>,
    pub requests: u64,
}

/// The request log's part of a client's view.
#[derive(Debug, Clone, Serialize)]
pub struct ClientLog {
    /// The stretch read: the last [`LOG_RANGE_HOURS`] of the range at most.
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// The client's requests in it.
    pub matched: u64,
    /// The newest [`LOG_LIMIT`] of them, newest first.
    pub entries: Vec<LogEntry>,
    /// The paths, user agents, accounts and statuses of all of them, most
    /// frequent first ([`TOP`] each).
    pub paths: Vec<Tally>,
    pub user_agents: Vec<Tally>,
    pub accounts: Vec<AccountTally>,
    pub statuses: Vec<Tally>,
}

/// One client network's traffic: `GET /admin/traffic/client`.
#[derive(Debug, Clone, Serialize)]
pub struct ClientDetail {
    pub network: String,
    #[serde(flatten)]
    pub span: Span,
    /// The instances whose files the range holds.
    pub instances: Vec<InstanceView>,
    /// Its counts, from the time buckets it was among the top clients of.
    pub totals: Option<ClientView>,
    pub series: Vec<Point>,
    pub log: ClientLog,
}

/// `network`'s traffic in `span`: its counts in the top lists, and its
/// requests in the request log.
pub async fn client(
    objects: &dyn Objects,
    cache: &FileCache,
    span: Span,
    instance: Option<&str>,
    network: &str,
) -> anyhow::Result<ClientDetail> {
    let (files, instances) =
        read_span(objects, cache, &span, instance, &[FileKind::Clients]).await?;
    let mut series = span.points();
    let mut rows = Vec::new();
    for (instance, decoded) in &files {
        if let Decoded::Clients(found) = &**decoded {
            for row in found {
                if row.network == network && span.contains(row.start) {
                    if let Some(point) = series.get_mut(span.point(row.start)) {
                        let n = |v: i64| u64::try_from(v).unwrap_or(0);
                        point.requests += n(row.requests);
                        point.bytes += n(row.bytes);
                        point.client_errors += n(row.client_errors);
                        point.server_errors += n(row.server_errors);
                    }
                    rows.push((instance.as_str(), row));
                }
            }
        }
    }
    let totals = sum_clients(rows.into_iter()).into_iter().next();
    let log = client_log(objects, &span, instance, network).await?;
    Ok(ClientDetail {
        network: network.to_string(),
        span,
        instances,
        totals,
        series,
        log,
    })
}

fn tallies(counts: HashMap<String, u64>) -> Vec<Tally> {
    let mut tallies: Vec<Tally> = counts
        .into_iter()
        .map(|(value, requests)| Tally { value, requests })
        .collect();
    tallies.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.value.cmp(&b.value)));
    tallies.truncate(TOP);
    tallies
}

async fn client_log(
    objects: &dyn Objects,
    span: &Span,
    instance: Option<&str>,
    network: &str,
) -> anyhow::Result<ClientLog> {
    let to = span.to.timestamp();
    let from = span.from.timestamp().max(to - LOG_RANGE_HOURS * HOUR);
    // A file is named after the hour of its flush, which comes up to a
    // minute after its rows.
    let wanted: Vec<(FileKey, Listed)> = files(objects, Area::Requests, from, to + 120)
        .await?
        .into_iter()
        .filter(|(f, _)| instance.is_none_or(|i| i == f.instance))
        .collect();
    let matched: Vec<Vec<(String, LogRow)>> = stream::iter(wanted)
        .map(|(file, listed)| async move {
            let Some(body) = objects.get(&listed.key).await? else {
                return anyhow::Ok(Vec::new());
            };
            let rows: Vec<LogRow> = decode(body)?;
            Ok(rows
                .into_iter()
                .filter(|row| row.network == network)
                .filter(|row| (from * 1_000..to * 1_000).contains(&row.time_ms))
                .map(|row| (file.instance.clone(), row))
                .collect())
        })
        .buffer_unordered(CONCURRENCY)
        .try_collect()
        .await?;
    let mut matched: Vec<(String, LogRow)> = matched.into_iter().flatten().collect();
    matched.sort_by_key(|(_, row)| std::cmp::Reverse(row.time_ms));

    let (mut paths, mut user_agents, mut accounts, mut statuses) = (
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
    );
    for (_, row) in &matched {
        *paths.entry(row.path.clone()).or_default() += 1;
        if !row.user_agent.is_empty() {
            *user_agents.entry(row.user_agent.clone()).or_default() += 1;
        }
        *accounts
            .entry((row.account.clone(), row.user_id))
            .or_insert(0u64) += 1;
        *statuses.entry(row.status.to_string()).or_default() += 1;
    }
    let some = |s: String| (!s.is_empty()).then_some(s);
    Ok(ClientLog {
        from: at(from),
        to: at(to),
        matched: matched.len() as u64,
        paths: tallies(paths),
        user_agents: tallies(user_agents),
        accounts: {
            let mut accounts: Vec<AccountTally> = accounts
                .into_iter()
                .map(|((account, user_id), requests)| AccountTally {
                    account: (!account.is_empty()).then_some(account),
                    user_id: (user_id != 0).then_some(user_id),
                    username: None,
                    requests,
                })
                .collect();
            accounts.sort_by(|a, b| {
                b.requests
                    .cmp(&a.requests)
                    .then_with(|| (&a.account, a.user_id).cmp(&(&b.account, b.user_id)))
            });
            accounts.truncate(TOP);
            accounts
        },
        statuses: tallies(statuses),
        entries: matched
            .into_iter()
            .take(LOG_LIMIT)
            .map(|(instance, row)| LogEntry {
                time: Utc
                    .timestamp_millis_opt(row.time_ms)
                    .single()
                    .unwrap_or_default(),
                address: row.address,
                method: row.method,
                path: row.path,
                surface: row.surface,
                repository: some(row.repository),
                status: u16::try_from(row.status).unwrap_or(0),
                bytes: u64::try_from(row.bytes).unwrap_or(0),
                duration_ms: row.duration_us as f64 / 1_000.0,
                user_agent: some(row.user_agent),
                account: some(row.account),
                user_id: (row.user_id != 0).then_some(row.user_id),
                username: None,
                host: instance_parts(&instance).0,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Flusher;
    use crate::objects::MemoryObjects;
    use crate::record::{Event, Recorder};
    use crate::slot::{Account, Noted};
    use crate::TrafficSettings;
    use std::time::Duration;

    fn t(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap().to_utc()
    }

    fn event(at: &str, network: &str, repository: &str, status: u16, ms: u64) -> Event {
        Event {
            at: t(at),
            surface: "plugin_npm",
            method: "GET",
            status,
            duration: Duration::from_millis(ms),
            bytes: 1_000,
            path: format!("/repository/{repository}/left-pad"),
            user_agent: Some("npm/10".into()),
            noted: Noted {
                client: network.parse().ok(),
                network: Some(network.into()),
                account: Some(Account {
                    kind: "token",
                    user_id: Some(3),
                }),
                repository: Some(repository.into()),
            },
        }
    }

    /// Two instances, each with its own files.
    async fn two_instances() -> Arc<MemoryObjects> {
        let objects = Arc::new(MemoryObjects::default());
        let settings = TrafficSettings::default();
        let now = t("2026-10-30T14:10:00Z");
        for (instance, events) in [
            (
                "a_20261030T100000Z_0001",
                vec![
                    event("2026-10-30T14:00:01Z", "192.0.2.1", "npm", 200, 20),
                    event("2026-10-30T14:00:02Z", "192.0.2.1", "npm", 404, 2),
                    event("2026-10-30T14:05:00Z", "192.0.2.2", "npm-proxy", 500, 900),
                ],
            ),
            (
                "b_20261030T110000Z_0002",
                vec![
                    event("2026-10-30T14:00:30Z", "192.0.2.1", "npm", 200, 40),
                    event("2026-10-30T13:59:59Z", "192.0.2.3", "npm", 401, 1),
                ],
            ),
        ] {
            let recorder = Recorder::new();
            for e in events {
                recorder.record(e);
            }
            let mut flusher = Flusher::new(objects.clone(), instance.into());
            flusher.flush(recorder.drain(now), &settings, now).await;
        }
        objects
    }

    #[tokio::test]
    async fn the_overview_sums_every_instance() {
        let objects = two_instances().await;
        let cache = FileCache::new();
        let now = t("2026-10-30T14:10:00Z");
        let span = Span::new(t("2026-10-30T13:10:00Z"), now, now);
        assert_eq!((span.resolution, span.step_seconds), ("minute", 60));

        let all = overview(&*objects, &cache, span, &Filter::default())
            .await
            .unwrap();
        assert_eq!(all.instances.len(), 2);
        assert_eq!(all.instances[0].host, "a");
        assert_eq!(all.totals.requests, 5);
        assert_eq!(
            (
                all.totals.client_errors,
                all.totals.denied,
                all.totals.not_found
            ),
            (2, 1, 1)
        );
        assert_eq!(all.totals.server_errors, 1);
        assert_eq!(all.totals.p50_ms, Some(25));
        assert_eq!(all.totals.p99_ms, Some(1_000));
        assert_eq!(all.series.len(), 60);
        assert_eq!(all.series.iter().map(|p| p.requests).sum::<u64>(), 5);
        assert_eq!(all.repositories[0].name, "npm");
        assert_eq!(all.repositories[0].requests, 4);
        let top = &all.clients[0];
        assert_eq!((top.network.as_str(), top.requests), ("192.0.2.1", 3));
        assert_eq!(top.hosts, vec!["a", "b"]);
        assert_eq!(top.user_id, Some(3));

        let one = overview(
            &*objects,
            &cache,
            span,
            &Filter {
                instance: Some("b_20261030T110000Z_0002".into()),
                repository: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(one.totals.requests, 2);
        assert_eq!(one.instances.len(), 2, "the selector still lists both");

        let repo = overview(
            &*objects,
            &cache,
            span,
            &Filter {
                instance: None,
                repository: Some("npm-proxy".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(repo.totals.requests, 1);

        // A week reads the files by hour.
        let week = Span::new(t("2026-10-23T14:10:00Z"), now, now);
        assert_eq!((week.resolution, week.step_seconds), ("hour", 3_600));
        let week = overview(&*objects, &cache, week, &Filter::default())
            .await
            .unwrap();
        assert_eq!(week.totals.requests, 5);
    }

    #[tokio::test]
    async fn a_client_view_reads_its_log() {
        let objects = two_instances().await;
        let now = t("2026-10-30T14:10:00Z");
        let span = Span::new(t("2026-10-30T13:10:00Z"), now, now);
        let detail = client(&*objects, &FileCache::new(), span, None, "192.0.2.1")
            .await
            .unwrap();
        assert_eq!(detail.totals.as_ref().unwrap().requests, 3);
        assert_eq!(detail.log.matched, 3);
        assert_eq!(
            detail.log.entries[0].time,
            t("2026-10-30T14:00:30Z"),
            "newest first"
        );
        assert_eq!(detail.log.entries[0].host, "b");
        assert_eq!(detail.log.entries[0].repository.as_deref(), Some("npm"));
        assert_eq!(detail.log.paths[0].value, "/repository/npm/left-pad");
        assert_eq!(
            detail.log.statuses[0],
            Tally {
                value: "200".into(),
                requests: 2
            }
        );
    }

    #[test]
    fn a_span_ends_after_the_second_it_ends_in() {
        let now = t("2026-10-30T14:10:00.250Z");
        let span = Span::new(t("2026-10-30T13:10:00Z"), now, now);
        assert_eq!(span.to, t("2026-10-30T14:10:01Z"));
    }

    #[test]
    fn spans_pick_their_resolution_and_step() {
        let now = t("2026-10-30T14:10:00Z");
        let day = Span::new(t("2026-10-29T14:10:00Z"), now, now);
        assert_eq!((day.resolution, day.step_seconds), ("minute", 600));
        assert_eq!(day.from, t("2026-10-29T14:10:00Z"));
        let month = Span::new(t("2026-09-30T14:10:00Z"), now, now);
        assert_eq!((month.resolution, month.step_seconds), ("hour", 21_600));
        // Older than the minute files: by hour.
        let old = Span::new(t("2026-10-20T00:00:00Z"), t("2026-10-20T01:00:00Z"), now);
        assert_eq!(old.resolution, "hour");
    }
}
