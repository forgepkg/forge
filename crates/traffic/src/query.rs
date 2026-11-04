//! Reading the day files back: the requests of a range of days, over all
//! instances or one, and where they came from.
//!
//! The files are found by listing the days of the range, read in parallel
//! and folded into the sums one at a time, in the order of their days: a
//! request never holds the rows of the whole range, and the client networks
//! it sums are bounded ([`MAX_CLIENTS`], [`crate::distinct`]). They are cached decoded, keyed by their ETag, so a file
//! rewritten since (today's) is read again.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use chrono::{NaiveDate, TimeZone, Utc};
use futures_util::{stream, StreamExt, TryStreamExt};
use serde::Serialize;

use crate::distinct::{self, Distinct};
use crate::layout::{day_prefix, instance_parts, parse_day_key, CONCURRENCY};
use crate::objects::{Listed, Objects};
use crate::record::OTHER;
use crate::rows::{decode, DayRow};

/// The lists' lengths: repositories, autonomous systems, clients.
pub const TOP: usize = 20;
/// The rows the cache of decoded files holds.
const CACHE_ROWS: u64 = 500_000;
/// The longest range, in days.
pub const MAX_DAYS: i64 = 400;
/// The client networks a request sums at most. A range with more counts
/// them all exactly up to this many; past it, the half with the fewest
/// requests so far are dropped from the list (their requests stay in the
/// totals and in [`Overview::other_clients`]).
pub const MAX_CLIENTS: usize = 20_000;

const DAY: i64 = 86_400;

/// Day files read back, decoded.
#[derive(Clone)]
pub struct FileCache(moka::future::Cache<String, Arc<Vec<DayRow>>>);

impl FileCache {
    pub fn new() -> FileCache {
        FileCache(
            moka::future::Cache::builder()
                .max_capacity(CACHE_ROWS)
                .weigher(|_, rows: &Arc<Vec<DayRow>>| {
                    u32::try_from(rows.len().max(1)).unwrap_or(u32::MAX)
                })
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
    pub started_at: Option<chrono::DateTime<Utc>>,
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

/// What to read: the days `from` to `to`, both included, and what to keep.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Only the files of this instance ([`crate::instance_id`]).
    pub instance: Option<String>,
    /// Only the requests to this repository; `""` for the requests that
    /// addressed none.
    pub repository: Option<String>,
    /// Only the requests of this client network.
    pub network: Option<String>,
    /// Only the requests from this country (ISO code; `""` unknown).
    pub country: Option<String>,
    /// Only the requests from this autonomous system (`0` unknown).
    pub asn: Option<u32>,
}

impl Filter {
    fn keeps(&self, row: &DayRow) -> bool {
        self.repository
            .as_ref()
            .is_none_or(|r| *r == row.repository)
            && self.network.as_ref().is_none_or(|n| *n == row.network)
            && self.country.as_ref().is_none_or(|c| *c == row.country)
            && self.asn.is_none_or(|a| i64::from(a) == row.asn)
    }
}

/// A day of the range.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DayPoint {
    pub day: NaiveDate,
    pub requests: u64,
    pub bytes: u64,
    /// The client networks that made requests that day.
    pub clients: u64,
}

/// The counts of the range.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Totals {
    pub requests: u64,
    pub bytes: u64,
    /// The client networks that made requests.
    pub clients: u64,
    /// The countries they came from (known ones).
    pub countries: u64,
    /// The autonomous systems they came from (known ones).
    pub asns: u64,
}

/// A share of the range: a repository's, a country's, an autonomous
/// system's.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Share {
    pub requests: u64,
    pub bytes: u64,
    /// The client networks among them.
    pub clients: u64,
}

#[derive(Default)]
struct Tally {
    share: Share,
    networks: Distinct,
}

impl Tally {
    /// Count `row`, whose network's [`distinct::hash`] is `network`
    /// (`None`: no client network).
    fn add(&mut self, row: &DayRow, network: Option<u64>) {
        self.share.requests += u64::try_from(row.requests).unwrap_or(0);
        self.share.bytes += u64::try_from(row.bytes).unwrap_or(0);
        if let Some(h) = network {
            self.networks.insert(h);
        }
    }

    /// The share, and whether its count of clients is an estimate.
    fn finish(mut self) -> (Share, bool) {
        self.share.clients = self.networks.count();
        (self.share, self.networks.is_estimate())
    }
}

/// A client network being summed: its share, its requests by repository,
/// the days of the range it was seen on and the latest of them.
#[derive(Default)]
struct ClientTally {
    client: ClientShare,
    repositories: HashMap<String, u64>,
    /// A bit per day of the range.
    days: Vec<u64>,
    latest: Option<i64>,
}

fn counts_as_client(network: &str) -> bool {
    !network.is_empty() && network != OTHER
}

/// A repository's requests.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RepositoryShare {
    /// `""` for the requests that addressed no repository.
    pub name: String,
    #[serde(flatten)]
    pub share: Share,
}

/// A country's requests.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CountryShare {
    /// ISO 3166-1 alpha-2; `""` unknown.
    pub country: String,
    #[serde(flatten)]
    pub share: Share,
}

/// An autonomous system's requests.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AsnShare {
    /// `0` unknown.
    pub asn: u32,
    pub org: String,
    #[serde(flatten)]
    pub share: Share,
}

/// A client network's requests.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ClientShare {
    /// The address, or an IPv6 address's /64: no address is kept whole.
    pub network: String,
    pub country: String,
    pub asn: u32,
    pub as_org: String,
    pub requests: u64,
    pub bytes: u64,
    /// The repositories it made the most requests to, most first.
    pub repositories: Vec<String>,
    /// The days it made requests on.
    pub days: u64,
    pub first_day: Option<NaiveDate>,
    pub last_day: Option<NaiveDate>,
}

/// The requests of a range of days: `GET /admin/traffic`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Overview {
    pub from: NaiveDate,
    /// The last day, included.
    pub to: NaiveDate,
    /// The instances whose files the range holds (whatever the instance
    /// asked for).
    pub instances: Vec<InstanceView>,
    pub totals: Totals,
    pub days: Vec<DayPoint>,
    /// The [`TOP`] repositories with the most requests.
    pub repositories: Vec<RepositoryShare>,
    /// Every country, most requests first.
    pub countries: Vec<CountryShare>,
    /// The [`TOP`] autonomous systems with the most requests.
    pub asns: Vec<AsnShare>,
    /// The [`TOP`] client networks with the most requests.
    pub clients: Vec<ClientShare>,
    /// The requests of the client networks [`Self::clients`] leaves out,
    /// those an instance counted as `other` included, and how many networks
    /// they are.
    pub other_clients: Share,
    /// Whether the range holds more client networks than a request sums
    /// exactly: the counts of clients are then estimates (off by about
    /// 1 %), and a network with few requests a day over many days can be
    /// missing from [`Self::clients`].
    pub estimated: bool,
}

fn naive(day: i64) -> NaiveDate {
    Utc.timestamp_opt(day, 0)
        .single()
        .map(|t| t.date_naive())
        .unwrap_or_default()
}

/// The sums of a range, folded a day file at a time: what it holds grows
/// with the days, repositories, countries and autonomous systems of the
/// range, not with its rows or client networks.
struct Sum<'f> {
    from: i64,
    to: i64,
    filter: &'f Filter,
    /// The client networks summed at most; past them, the half with the
    /// fewest requests so far are dropped.
    max_clients: usize,
    /// A day's requests and bytes; its clients once it is closed.
    days: Vec<DayPoint>,
    /// The client networks of the days not closed yet.
    open: BTreeMap<i64, Distinct>,
    all: Tally,
    /// The requests and bytes of the rows with a client network (`other`
    /// included).
    networked: Share,
    repositories: HashMap<String, Tally>,
    countries: HashMap<String, Tally>,
    asns: HashMap<i64, (Tally, String)>,
    clients: HashMap<String, ClientTally>,
    estimated: bool,
}

impl<'f> Sum<'f> {
    fn new(from: i64, to: i64, filter: &'f Filter, max_clients: usize) -> Sum<'f> {
        Sum {
            from,
            to,
            filter,
            max_clients: max_clients.max(1),
            days: (0..)
                .map(|i| from + i * DAY)
                .take_while(|d| *d <= to)
                .map(|d| DayPoint {
                    day: naive(d),
                    requests: 0,
                    bytes: 0,
                    clients: 0,
                })
                .collect(),
            open: BTreeMap::new(),
            all: Tally::default(),
            networked: Share::default(),
            repositories: HashMap::new(),
            countries: HashMap::new(),
            asns: HashMap::new(),
            clients: HashMap::new(),
            estimated: false,
        }
    }

    fn day_index(&self, day: i64) -> Option<usize> {
        usize::try_from((day - self.from).div_euclid(DAY))
            .ok()
            .filter(|i| *i < self.days.len())
    }

    /// Count the clients of the days before `day`: the files come in the
    /// order of their days, and a file holds the rows of its day alone.
    fn close_before(&mut self, day: i64) {
        let later = self.open.split_off(&day);
        for (d, networks) in std::mem::replace(&mut self.open, later) {
            if let Some(i) = self.day_index(d) {
                self.days[i].clients = networks.count();
                self.estimated |= networks.is_estimate();
            }
        }
    }

    /// Fold the rows of a day file of `day`.
    fn fold(&mut self, day: i64, rows: &[DayRow]) {
        self.close_before(day);
        for row in rows {
            if (self.from..=self.to).contains(&row.day) && self.filter.keeps(row) {
                self.add(row);
            }
        }
    }

    fn add(&mut self, row: &DayRow) {
        let client = counts_as_client(&row.network).then(|| distinct::hash(&row.network));
        let requests = u64::try_from(row.requests).unwrap_or(0);
        let bytes = u64::try_from(row.bytes).unwrap_or(0);
        self.all.add(row, client);
        if !row.network.is_empty() {
            self.networked.requests += requests;
            self.networked.bytes += bytes;
        }
        let Some(index) = self.day_index(row.day) else {
            return;
        };
        let point = &mut self.days[index];
        point.requests += requests;
        point.bytes += bytes;
        if let Some(h) = client {
            self.open.entry(row.day).or_default().insert(h);
        }
        tally(&mut self.repositories, &row.repository).add(row, client);
        tally(&mut self.countries, &row.country).add(row, client);
        let asn = self.asns.entry(row.asn).or_default();
        asn.0.add(row, client);
        if asn.1.is_empty() {
            asn.1.clone_from(&row.as_org);
        }
        if client.is_none() {
            return;
        }
        if !self.clients.contains_key(&row.network) && self.clients.len() >= self.max_clients {
            self.drop_clients();
        }
        let words = self.days.len().div_ceil(64);
        let tally = self
            .clients
            .entry(row.network.clone())
            .or_insert_with(|| ClientTally {
                days: vec![0; words],
                ..ClientTally::default()
            });
        let client = &mut tally.client;
        if client.network.is_empty() {
            client.network.clone_from(&row.network);
        }
        client.requests += requests;
        client.bytes += bytes;
        match tally.repositories.get_mut(&row.repository) {
            Some(n) => *n += requests,
            None => {
                tally.repositories.insert(row.repository.clone(), requests);
            }
        }
        tally.days[index / 64] |= 1 << (index % 64);
        if tally.latest.is_none_or(|latest| row.day >= latest) {
            tally.latest = Some(row.day);
            if !row.country.is_empty() || row.asn != 0 {
                client.country.clone_from(&row.country);
                client.asn = u32::try_from(row.asn).unwrap_or(0);
                client.as_org.clone_from(&row.as_org);
            }
        }
    }

    /// Keep the half of the client networks with the most requests so far.
    fn drop_clients(&mut self) {
        let mut held: Vec<(String, ClientTally)> = self.clients.drain().collect();
        let keep = self.max_clients / 2;
        if keep < held.len() {
            held.select_nth_unstable_by(keep, |a, b| {
                b.1.client
                    .requests
                    .cmp(&a.1.client.requests)
                    .then(a.0.cmp(&b.0))
            });
            held.truncate(keep);
        }
        self.clients.extend(held);
        self.estimated = true;
    }

    fn finish(mut self, from: NaiveDate, to: NaiveDate, instances: Vec<InstanceView>) -> Overview {
        self.close_before(i64::MAX);
        let mut estimated = self.estimated;
        let mut share = |t: Tally| {
            let (share, estimate) = t.finish();
            estimated |= estimate;
            share
        };
        let by_requests = |a: &Share, b: &Share| b.requests.cmp(&a.requests);
        let mut repositories: Vec<RepositoryShare> = self
            .repositories
            .into_iter()
            .map(|(name, t)| RepositoryShare {
                name,
                share: share(t),
            })
            .collect();
        repositories.sort_by(|a, b| by_requests(&a.share, &b.share).then(a.name.cmp(&b.name)));
        repositories.truncate(TOP);
        let mut countries: Vec<CountryShare> = self
            .countries
            .into_iter()
            .map(|(country, t)| CountryShare {
                country,
                share: share(t),
            })
            .collect();
        countries.sort_by(|a, b| by_requests(&a.share, &b.share).then(a.country.cmp(&b.country)));
        let known_countries = countries.iter().filter(|c| !c.country.is_empty()).count();
        let mut asns: Vec<AsnShare> = self
            .asns
            .into_iter()
            .map(|(asn, (t, org))| AsnShare {
                asn: u32::try_from(asn).unwrap_or(0),
                org,
                share: share(t),
            })
            .collect();
        asns.sort_by(|a, b| by_requests(&a.share, &b.share).then(a.asn.cmp(&b.asn)));
        let known_asns = asns.iter().filter(|a| a.asn != 0).count();
        asns.truncate(TOP);
        let total = share(self.all);

        let days_from = self.from;
        let mut clients: Vec<ClientShare> = self
            .clients
            .into_values()
            .map(|tally| {
                let ClientTally {
                    mut client,
                    repositories: repos,
                    days: seen,
                    ..
                } = tally;
                let mut repos: Vec<(String, u64)> = repos.into_iter().collect();
                repos.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                client.repositories = repos.into_iter().take(5).map(|(r, _)| r).collect();
                let bits = || {
                    seen.iter().enumerate().flat_map(|(w, word)| {
                        (0..64)
                            .filter(move |b| word & (1 << b) != 0)
                            .map(move |b| w * 64 + b)
                    })
                };
                let day = |i: usize| naive(days_from + i64::try_from(i).unwrap_or(0) * DAY);
                client.days = bits().count() as u64;
                client.first_day = bits().next().map(day);
                client.last_day = bits().last().map(day);
                client
            })
            .collect();
        clients.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.network.cmp(&b.network)));
        clients.truncate(TOP);
        let listed = |f: fn(&ClientShare) -> u64| clients.iter().map(f).sum::<u64>();
        let other_clients = Share {
            requests: self
                .networked
                .requests
                .saturating_sub(listed(|c| c.requests)),
            bytes: self.networked.bytes.saturating_sub(listed(|c| c.bytes)),
            clients: total.clients.saturating_sub(clients.len() as u64),
        };

        Overview {
            from,
            to,
            instances,
            totals: Totals {
                requests: total.requests,
                bytes: total.bytes,
                clients: total.clients,
                countries: known_countries as u64,
                asns: known_asns as u64,
            },
            days: self.days,
            repositories,
            countries,
            asns,
            clients,
            other_clients,
            estimated,
        }
    }
}

/// The tally of `key` in `tallies`, made if it is new.
fn tally<'t>(tallies: &'t mut HashMap<String, Tally>, key: &str) -> &'t mut Tally {
    if !tallies.contains_key(key) {
        tallies.insert(key.to_string(), Tally::default());
    }
    tallies.get_mut(key).expect("just inserted")
}

/// The day files of the days `from` to `to` (Unix seconds, both included).
async fn files(
    objects: &dyn Objects,
    from: i64,
    to: i64,
) -> anyhow::Result<Vec<(i64, String, Listed)>> {
    let days: Vec<i64> = (0..)
        .map(|i| from + i * DAY)
        .take_while(|day| *day <= to)
        .collect();
    let listings: Vec<Vec<Listed>> = stream::iter(days)
        .map(|day| async move { objects.list(&day_prefix(day)).await })
        .buffered(CONCURRENCY)
        .try_collect()
        .await?;
    Ok(listings
        .into_iter()
        .flatten()
        .filter_map(|listed| {
            let (day, instance) = parse_day_key(&listed.key)?;
            Some((day, instance, listed))
        })
        .collect())
}

/// The rows of the day file `listed`, from the cache when it holds this
/// version.
async fn read(
    objects: &dyn Objects,
    cache: &FileCache,
    listed: &Listed,
) -> anyhow::Result<Arc<Vec<DayRow>>> {
    let cache_key = format!("{}#{}", listed.key, listed.etag.as_deref().unwrap_or(""));
    if let Some(hit) = cache.0.get(&cache_key).await {
        return Ok(hit);
    }
    let Some(body) = objects.get(&listed.key).await? else {
        // Deleted since the listing (pruned).
        return Ok(Arc::new(Vec::new()));
    };
    let rows = Arc::new(decode::<DayRow>(body)?);
    if listed.etag.is_some() {
        cache.0.insert(cache_key, rows.clone()).await;
    }
    Ok(rows)
}

/// The requests of the days `from` to `to` (both included) over
/// `objects`' files, as `filter` narrows them.
///
/// The files are read in the order of their days, [`CONCURRENCY`] at once,
/// and each is folded into the sums as it comes: a request holds the rows
/// of those files at most, never those of the whole range.
pub async fn overview(
    objects: &dyn Objects,
    cache: &FileCache,
    from: NaiveDate,
    to: NaiveDate,
    filter: &Filter,
) -> anyhow::Result<Overview> {
    let start = |d: NaiveDate| {
        d.and_hms_opt(0, 0, 0)
            .map(|t| t.and_utc().timestamp())
            .unwrap_or_default()
    };
    let (from_s, to_s) = (start(from), start(to));
    let found = files(objects, from_s, to_s).await?;
    let instances: BTreeSet<String> = found.iter().map(|(_, i, _)| i.clone()).collect();
    let wanted: Vec<(i64, Listed)> = found
        .into_iter()
        .filter(|(_, i, _)| filter.instance.as_ref().is_none_or(|w| w == i))
        .map(|(day, _, listed)| (day, listed))
        .collect();
    let mut read = stream::iter(wanted)
        .map(|(day, listed)| async move {
            Ok::<_, anyhow::Error>((day, read(objects, cache, &listed).await?))
        })
        .buffered(CONCURRENCY);
    let mut sum = Sum::new(from_s, to_s, filter, MAX_CLIENTS);
    while let Some((day, rows)) = read.try_next().await? {
        sum.fold(day, &rows);
    }
    let instances = instances.iter().map(|id| InstanceView::of(id)).collect();
    Ok(sum.finish(from, to, instances))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::{Geo, GeoKind};
    use crate::layout::day_key;
    use crate::layout::Flusher;
    use crate::objects::MemoryObjects;
    use crate::record::{Event, Recorder};
    use crate::rows::encode;
    use crate::slot::Noted;
    use crate::testing::{asn_db, country_db};
    use crate::TrafficSettings;
    use chrono::DateTime;
    use std::collections::HashSet;

    fn t(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap().to_utc()
    }

    fn d(date: &str) -> NaiveDate {
        NaiveDate::parse_from_str(date, "%Y-%m-%d").unwrap()
    }

    fn event(at: &str, client: &str, repository: &str) -> Event {
        Event {
            at: t(at),
            bytes: 1_000,
            noted: Noted {
                client: client.parse().ok(),
                network: Some(client.into()),
                repository: (!repository.is_empty()).then(|| repository.to_string()),
            },
        }
    }

    /// Two instances, each with its own files, over two days.
    async fn two_instances() -> Arc<MemoryObjects> {
        let objects = Arc::new(MemoryObjects::default());
        let settings = TrafficSettings::default();
        let geo = Geo::default();
        geo.load(
            GeoKind::Country,
            country_db(&[("192.0.2.0/24", "DE"), ("198.51.100.0/24", "US")]),
            "1".into(),
        )
        .unwrap();
        geo.load(
            GeoKind::Asn,
            asn_db(&[
                ("192.0.2.0/24", 64_500, "Example DE"),
                ("198.51.100.0/24", 64_501, "Example US"),
            ]),
            "1".into(),
        )
        .unwrap();
        for (instance, events) in [
            (
                "a_20261029T100000Z_0001",
                vec![
                    event("2026-10-29T10:00:00Z", "192.0.2.1", "npm"),
                    event("2026-10-30T10:00:00Z", "192.0.2.1", "npm"),
                    event("2026-10-30T10:00:01Z", "198.51.100.9", "docker"),
                ],
            ),
            (
                "b_20261029T110000Z_0002",
                vec![
                    event("2026-10-30T11:00:00Z", "192.0.2.1", "npm"),
                    event("2026-10-30T11:00:00Z", "192.0.2.1", "npm"),
                    event("2026-10-30T11:00:01Z", "203.0.113.5", ""),
                ],
            ),
        ] {
            let recorder = Recorder::new();
            for e in events {
                recorder.record(e);
            }
            let mut flusher = Flusher::new(objects.clone(), instance.into());
            flusher
                .flush(recorder.drain(), &settings, &geo, t("2026-10-30T12:00:00Z"))
                .await;
        }
        objects
    }

    #[tokio::test]
    async fn the_overview_sums_every_instance() {
        let objects = two_instances().await;
        let cache = FileCache::new();
        let all = overview(
            &*objects,
            &cache,
            d("2026-10-24"),
            d("2026-10-30"),
            &Filter::default(),
        )
        .await
        .unwrap();
        assert_eq!(all.instances.len(), 2);
        assert_eq!(all.instances[0].host, "a");
        assert_eq!(all.days.len(), 7);
        assert_eq!(all.days[5].requests, 1, "the 29th");
        assert_eq!(
            (all.days[6].requests, all.days[6].clients),
            (5, 3),
            "the 30th"
        );
        assert_eq!(
            all.totals,
            Totals {
                requests: 6,
                bytes: 6_000,
                clients: 3,
                countries: 2,
                asns: 2
            }
        );
        assert_eq!(all.repositories[0].name, "npm");
        assert_eq!(
            (
                all.repositories[0].share.requests,
                all.repositories[0].share.clients
            ),
            (4, 1)
        );
        assert_eq!(all.countries[0].country, "DE");
        let unknown = all.countries.iter().find(|c| c.country.is_empty()).unwrap();
        assert_eq!(unknown.share.requests, 1, "203.0.113.5 is in no database");
        assert_eq!(
            (all.asns[0].asn, all.asns[0].org.as_str()),
            (64_500, "Example DE")
        );
        let top = &all.clients[0];
        assert_eq!(
            (
                top.network.as_str(),
                top.requests,
                top.days,
                top.country.as_str()
            ),
            ("192.0.2.1", 4, 2, "DE")
        );
        assert_eq!(top.repositories, vec!["npm"]);
        assert_eq!(top.first_day, Some(d("2026-10-29")));
        assert_eq!(all.clients.len(), 3);
        assert_eq!(
            all.other_clients,
            Share::default(),
            "every network is listed"
        );
        assert!(!all.estimated);
    }

    #[tokio::test]
    async fn filters_narrow_every_list() {
        let objects = two_instances().await;
        let cache = FileCache::new();
        let range = (d("2026-10-24"), d("2026-10-30"));
        let only = |f: Filter| {
            let objects = objects.clone();
            let cache = cache.clone();
            async move {
                overview(&*objects, &cache, range.0, range.1, &f)
                    .await
                    .unwrap()
            }
        };
        let b = only(Filter {
            instance: Some("b_20261029T110000Z_0002".into()),
            ..Filter::default()
        })
        .await;
        assert_eq!(b.totals.requests, 3);
        assert_eq!(b.instances.len(), 2, "the selector still lists both");
        let docker = only(Filter {
            repository: Some("docker".into()),
            ..Filter::default()
        })
        .await;
        assert_eq!(docker.totals.requests, 1);
        assert_eq!(docker.countries[0].country, "US");
        let none = only(Filter {
            repository: Some(String::new()),
            ..Filter::default()
        })
        .await;
        assert_eq!(none.totals.requests, 1, "the requests to no repository");
        let de = only(Filter {
            country: Some("DE".into()),
            ..Filter::default()
        })
        .await;
        assert_eq!(de.totals.requests, 4);
        let asn = only(Filter {
            asn: Some(64_501),
            ..Filter::default()
        })
        .await;
        assert_eq!(asn.clients[0].network, "198.51.100.9");
        let client = only(Filter {
            network: Some("192.0.2.1".into()),
            ..Filter::default()
        })
        .await;
        assert_eq!((client.totals.requests, client.totals.clients), (4, 1));
    }

    /// A row of `day` (index of the range from `FROM`).
    fn row(day: i64, network: &str, repository: &str, asn: i64, requests: i64) -> DayRow {
        DayRow {
            day: FROM + day * DAY,
            repository: repository.into(),
            network: network.into(),
            address: network.into(),
            country: ["DE", "US", "", "FR"][usize::try_from(asn % 4).unwrap()].into(),
            asn,
            as_org: format!("AS {asn}"),
            requests,
            bytes: requests * 100,
        }
    }

    /// 2026-01-01.
    const FROM: i64 = 1_767_225_600;

    /// The sums of `rows` the way `overview` summed them before it folded
    /// a file at a time: every row at once, with a set of networks per
    /// tally.
    struct Reference {
        totals: Totals,
        days: Vec<(u64, u64, u64)>,
        repositories: Vec<(String, u64, u64)>,
        countries: Vec<(String, u64, u64)>,
        asns: Vec<(u32, u64, u64)>,
        clients: Vec<(String, u64, u64, Vec<String>)>,
    }

    fn reference(rows: &[DayRow], days: usize) -> Reference {
        type Sets = HashMap<String, (u64, HashSet<String>)>;
        type Clients = HashMap<String, (u64, BTreeSet<i64>, HashMap<String, u64>)>;
        fn add(map: &mut Sets, key: String, row: &DayRow) {
            let e = map.entry(key).or_default();
            e.0 += row.requests as u64;
            if counts_as_client(&row.network) {
                e.1.insert(row.network.clone());
            }
        }
        fn sorted<K: Ord + Clone>(map: HashMap<K, (u64, HashSet<String>)>) -> Vec<(K, u64, u64)> {
            let mut v: Vec<_> = map
                .into_iter()
                .map(|(k, (r, n))| (k, r, n.len() as u64))
                .collect();
            v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            v
        }
        let mut all = (0u64, 0u64, HashSet::new());
        let mut by_day = vec![(0u64, 0u64, HashSet::new()); days];
        let (mut repos, mut countries) = (Sets::new(), Sets::new());
        let mut asns: HashMap<u32, (u64, HashSet<String>)> = HashMap::new();
        let mut clients = Clients::new();
        for row in rows {
            let (r, b) = (row.requests as u64, row.bytes as u64);
            all.0 += r;
            all.1 += b;
            let day = &mut by_day[usize::try_from((row.day - FROM) / DAY).unwrap()];
            day.0 += r;
            day.1 += b;
            add(&mut repos, row.repository.clone(), row);
            add(&mut countries, row.country.clone(), row);
            let asn = asns.entry(row.asn as u32).or_default();
            asn.0 += r;
            if counts_as_client(&row.network) {
                asn.1.insert(row.network.clone());
                all.2.insert(row.network.clone());
                day.2.insert(row.network.clone());
                let c = clients.entry(row.network.clone()).or_default();
                c.0 += r;
                c.1.insert(row.day);
                *c.2.entry(row.repository.clone()).or_default() += r;
            }
        }
        let countries = sorted(countries);
        let asns = sorted(asns);
        let mut clients: Vec<_> = clients
            .into_iter()
            .map(|(n, (r, d, repos))| {
                let mut repos: Vec<_> = repos.into_iter().collect();
                repos.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                let repos = repos.into_iter().take(5).map(|(r, _)| r).collect();
                (n, r, d.len() as u64, repos)
            })
            .collect();
        clients.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        clients.truncate(TOP);
        let mut repositories = sorted(repos);
        repositories.truncate(TOP);
        Reference {
            totals: Totals {
                requests: all.0,
                bytes: all.1,
                clients: all.2.len() as u64,
                countries: countries.iter().filter(|c| !c.0.is_empty()).count() as u64,
                asns: asns.iter().filter(|a| a.0 != 0).count() as u64,
            },
            days: by_day
                .into_iter()
                .map(|(r, b, n)| (r, b, n.len() as u64))
                .collect(),
            repositories,
            countries,
            asns: asns.into_iter().take(TOP).collect(),
            clients,
        }
    }

    /// The rows of a long range: three instances, one of them restarted
    /// (two files a day), over `days` days, with networks that come back
    /// day after day and networks seen once.
    fn long_range(days: i64) -> Vec<Vec<DayRow>> {
        let mut files = Vec::new();
        for day in 0..days {
            for instance in 0..4i64 {
                let mut rows = Vec::new();
                for n in 0..25i64 {
                    let steady = format!("192.0.2.{}", (n + day) % 40);
                    let repository =
                        ["npm", "docker", "", "maven"][usize::try_from(n % 4).unwrap()];
                    rows.push(row(
                        day,
                        &steady,
                        repository,
                        64_500 + n % 7,
                        n + instance + 1,
                    ));
                    if n < 5 {
                        let once = format!("2001:db8:{day:x}:{instance:x}{n:02x}::/64");
                        rows.push(row(day, &once, "npm", n, 1));
                    }
                }
                rows.push(row(day, OTHER, "npm", 0, 3));
                rows.push(row(day, "", "", 0, 2));
                files.push(rows);
            }
        }
        files
    }

    #[tokio::test]
    async fn a_long_range_sums_to_what_summing_every_row_at_once_did() {
        let days = 365;
        let files = long_range(days);
        let objects = MemoryObjects::default();
        for (i, rows) in files.iter().enumerate() {
            let i = i64::try_from(i).unwrap();
            let instance = format!("web-{}_x_000{}", i % 4 / 2, i % 2);
            objects
                .put(&day_key(rows[0].day, &instance), encode(rows).unwrap())
                .await
                .unwrap();
        }
        let (from, to) = (naive(FROM), naive(FROM + (days - 1) * DAY));
        let got = overview(&objects, &FileCache::new(), from, to, &Filter::default())
            .await
            .unwrap();
        let want = reference(&files.concat(), usize::try_from(days).unwrap());

        assert_eq!(got.totals, want.totals);
        assert_eq!(got.instances.len(), 4);
        assert!(!got.estimated, "{} networks fit", got.totals.clients);
        let days_got: Vec<_> = got
            .days
            .iter()
            .map(|d| (d.requests, d.bytes, d.clients))
            .collect();
        assert_eq!(days_got, want.days);
        let share = |s: &Share| (s.requests, s.clients);
        assert_eq!(
            got.repositories
                .iter()
                .map(|r| (r.name.clone(), share(&r.share)))
                .collect::<Vec<_>>(),
            want.repositories
                .iter()
                .map(|r| (r.0.clone(), (r.1, r.2)))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            got.countries
                .iter()
                .map(|c| (c.country.clone(), share(&c.share)))
                .collect::<Vec<_>>(),
            want.countries
                .iter()
                .map(|c| (c.0.clone(), (c.1, c.2)))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            got.asns
                .iter()
                .map(|a| (a.asn, share(&a.share)))
                .collect::<Vec<_>>(),
            want.asns
                .iter()
                .map(|a| (a.0, (a.1, a.2)))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            got.clients
                .iter()
                .map(|c| (
                    c.network.clone(),
                    c.requests,
                    c.days,
                    c.repositories.clone()
                ))
                .collect::<Vec<_>>(),
            want.clients
        );
        assert_eq!(got.clients[0].first_day, Some(from));
        assert_eq!(got.clients[0].last_day, Some(to));
        let listed: u64 = got.clients.iter().map(|c| c.requests).sum();
        assert_eq!(
            got.other_clients,
            Share {
                requests: want.totals.requests - 2 * 4 * 365 - listed,
                bytes: (want.totals.requests - 2 * 4 * 365 - listed) * 100,
                clients: want.totals.clients - TOP as u64,
            },
            "every networked request outside the list, `other` included"
        );
    }

    #[test]
    fn the_client_networks_summed_stay_within_the_cap() {
        let filter = Filter::default();
        let days = 200;
        let mut sum = Sum::new(FROM, FROM + (days - 1) * DAY, &filter, 100);
        let mut most = 0;
        for day in 0..days {
            // A network with many requests every day, and 30 seen once.
            let mut rows = vec![row(day, "192.0.2.1", "npm", 64_500, 50)];
            for n in 0..30 {
                rows.push(row(day, &format!("10.{day}.0.{n}"), "npm", 64_501, 1));
            }
            sum.fold(FROM + day * DAY, &rows);
            most = most.max(sum.clients.len());
        }
        assert!(most <= 100, "{most} client networks summed");
        let got = sum.finish(naive(FROM), naive(FROM + (days - 1) * DAY), Vec::new());
        assert!(got.estimated);
        assert_eq!(got.totals.clients, 1 + 30 * 200, "the count stays exact");
        assert_eq!(got.totals.requests, 50 * 200 + 30 * 200);
        let top = &got.clients[0];
        assert_eq!(
            (top.network.as_str(), top.requests, top.days),
            ("192.0.2.1", 50 * 200, 200)
        );
        let listed: u64 = got.clients.iter().map(|c| c.requests).sum();
        assert_eq!(got.other_clients.requests, got.totals.requests - listed);
        assert_eq!(
            got.other_clients.clients,
            got.totals.clients - got.clients.len() as u64
        );
    }
}
