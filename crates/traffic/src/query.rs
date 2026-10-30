//! Reading the day files back: the requests of a range of days, over all
//! instances or one, and where they came from.
//!
//! The files are found by listing the days of the range, read in parallel
//! and summed. They are cached decoded, keyed by their ETag, so a file
//! rewritten since (today's) is read again.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use chrono::{NaiveDate, TimeZone, Utc};
use futures_util::{stream, StreamExt, TryStreamExt};
use serde::Serialize;

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
    networks: HashSet<String>,
}

impl Tally {
    fn add(&mut self, row: &DayRow) {
        self.share.requests += u64::try_from(row.requests).unwrap_or(0);
        self.share.bytes += u64::try_from(row.bytes).unwrap_or(0);
        if counts_as_client(&row.network) {
            self.networks.insert(row.network.clone());
        }
    }

    fn finish(mut self) -> Share {
        self.share.clients = self.networks.len() as u64;
        self.share
    }
}

/// A client network being summed: its share, its requests by repository,
/// the days it was seen and the latest of them.
#[derive(Default)]
struct ClientTally<'a> {
    client: ClientShare,
    repositories: HashMap<&'a str, u64>,
    days: BTreeSet<i64>,
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
    pub network: String,
    /// The last address of the network seen.
    pub address: String,
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
#[derive(Debug, Clone, Serialize)]
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
}

fn naive(day: i64) -> NaiveDate {
    Utc.timestamp_opt(day, 0)
        .single()
        .map(|t| t.date_naive())
        .unwrap_or_default()
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
    let wanted: Vec<Listed> = found
        .into_iter()
        .filter(|(_, i, _)| filter.instance.as_ref().is_none_or(|w| w == i))
        .map(|(_, _, listed)| listed)
        .collect();
    let read: Vec<Arc<Vec<DayRow>>> = stream::iter(wanted)
        .map(|listed| async move { read(objects, cache, &listed).await })
        .buffer_unordered(CONCURRENCY)
        .try_collect()
        .await?;

    let mut days: BTreeMap<i64, Tally> = (0..)
        .map(|i| from_s + i * DAY)
        .take_while(|d| *d <= to_s)
        .map(|d| (d, Tally::default()))
        .collect();
    let mut all = Tally::default();
    let mut repositories: HashMap<&str, Tally> = HashMap::new();
    let mut countries: HashMap<&str, Tally> = HashMap::new();
    let mut asns: HashMap<i64, (Tally, &str)> = HashMap::new();
    let mut clients: HashMap<&str, ClientTally> = HashMap::new();
    for row in read.iter().flat_map(|rows| rows.iter()) {
        if !(from_s..=to_s).contains(&row.day) || !filter.keeps(row) {
            continue;
        }
        all.add(row);
        if let Some(day) = days.get_mut(&row.day) {
            day.add(row);
        }
        repositories.entry(&row.repository).or_default().add(row);
        countries.entry(&row.country).or_default().add(row);
        let asn = asns
            .entry(row.asn)
            .or_insert_with(|| (Tally::default(), ""));
        asn.0.add(row);
        if asn.1.is_empty() {
            asn.1 = &row.as_org;
        }
        if counts_as_client(&row.network) {
            let tally = clients.entry(&row.network).or_default();
            let client = &mut tally.client;
            if client.network.is_empty() {
                client.network.clone_from(&row.network);
            }
            let requests = u64::try_from(row.requests).unwrap_or(0);
            client.requests += requests;
            client.bytes += u64::try_from(row.bytes).unwrap_or(0);
            *tally.repositories.entry(&row.repository).or_default() += requests;
            tally.days.insert(row.day);
            if tally.latest.is_none_or(|latest| row.day >= latest) {
                tally.latest = Some(row.day);
                if !row.address.is_empty() {
                    client.address.clone_from(&row.address);
                }
                if !row.country.is_empty() || row.asn != 0 {
                    client.country.clone_from(&row.country);
                    client.asn = u32::try_from(row.asn).unwrap_or(0);
                    client.as_org.clone_from(&row.as_org);
                }
            }
        }
    }

    let by_requests = |a: &Share, b: &Share| b.requests.cmp(&a.requests);
    let mut repositories: Vec<RepositoryShare> = repositories
        .into_iter()
        .map(|(name, t)| RepositoryShare {
            name: name.to_string(),
            share: t.finish(),
        })
        .collect();
    repositories.sort_by(|a, b| by_requests(&a.share, &b.share).then(a.name.cmp(&b.name)));
    repositories.truncate(TOP);
    let mut countries: Vec<CountryShare> = countries
        .into_iter()
        .map(|(country, t)| CountryShare {
            country: country.to_string(),
            share: t.finish(),
        })
        .collect();
    countries.sort_by(|a, b| by_requests(&a.share, &b.share).then(a.country.cmp(&b.country)));
    let known_countries = countries.iter().filter(|c| !c.country.is_empty()).count();
    let mut asns: Vec<AsnShare> = asns
        .into_iter()
        .map(|(asn, (t, org))| AsnShare {
            asn: u32::try_from(asn).unwrap_or(0),
            org: org.to_string(),
            share: t.finish(),
        })
        .collect();
    asns.sort_by(|a, b| by_requests(&a.share, &b.share).then(a.asn.cmp(&b.asn)));
    let known_asns = asns.iter().filter(|a| a.asn != 0).count();
    asns.truncate(TOP);
    let mut clients: Vec<ClientShare> = clients
        .into_values()
        .map(|tally| {
            let ClientTally {
                mut client,
                repositories: repos,
                days: seen,
                ..
            } = tally;
            let mut repos: Vec<(&str, u64)> = repos.into_iter().collect();
            repos.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            client.repositories = repos
                .into_iter()
                .take(5)
                .map(|(r, _)| r.to_string())
                .collect();
            client.days = seen.len() as u64;
            client.first_day = seen.first().map(|d| naive(*d));
            client.last_day = seen.last().map(|d| naive(*d));
            client
        })
        .collect();
    clients.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.network.cmp(&b.network)));
    clients.truncate(TOP);

    let total = all.finish();
    Ok(Overview {
        from,
        to,
        instances: instances.iter().map(|id| InstanceView::of(id)).collect(),
        totals: Totals {
            requests: total.requests,
            bytes: total.bytes,
            clients: total.clients,
            countries: known_countries as u64,
            asns: known_asns as u64,
        },
        days: days
            .into_iter()
            .map(|(day, t)| {
                let share = t.finish();
                DayPoint {
                    day: naive(day),
                    requests: share.requests,
                    bytes: share.bytes,
                    clients: share.clients,
                }
            })
            .collect(),
        repositories,
        countries,
        asns,
        clients,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::{Geo, GeoKind};
    use crate::layout::Flusher;
    use crate::objects::MemoryObjects;
    use crate::record::{Event, Recorder};
    use crate::slot::Noted;
    use crate::testing::{asn_db, country_db};
    use crate::TrafficSettings;
    use chrono::DateTime;

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
}
