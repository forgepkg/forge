//! The traffic statistics of Admin → Traffic ([`forge_traffic`]): what the
//! server notes about a request for its count, the settings, and the worker
//! that writes the files, loads the geolocation databases and deletes the
//! expired files.
//!
//! * The client address is the one the principal layer resolves (the socket
//!   peer, or what a trusted proxy forwarded), counted under its network as
//!   the login lockout counts it: an IPv6 address by its /64
//!   ([`client_network`]), the rest of the address dropped before it is
//!   noted, so that it is neither written nor shown.
//! * The settings ([`TrafficSettings`]) are kept in `forge_setting` under
//!   [`SETTINGS_KEY`]; every instance follows a change with its next flush.
//! * The worker flushes once a minute, a couple of seconds after the minute
//!   turns; it loads the geolocation databases from the bucket when they
//!   change ([`GEO_REFRESH_INTERVAL`]), and about once an hour, at a random
//!   offset per instance, prunes and downloads the databases from MaxMind
//!   when they are due ([`maxmind`]).

pub mod maxmind;

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use forge_core::auth::login_throttle::client_network;
use forge_traffic::{Traffic, TrafficSettings};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::state::AppState;

/// The `forge_setting` key of the [`TrafficSettings`].
pub const SETTINGS_KEY: &str = "traffic";

/// The worker's name (`forge.worker`).
pub const WORKER: &str = "traffic";

/// How often the worker prunes and checks the MaxMind download.
const HOURLY: Duration = Duration::from_secs(3_600);

/// How often the worker looks for new geolocation databases in the bucket.
pub const GEO_REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// How long the last flush on shutdown may take.
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(10);

/// How long of it the settings may take to read.
const SHUTDOWN_READ: Duration = Duration::from_secs(3);

/// The network `ip` is counted under, as text: the address itself for IPv4,
/// `<prefix>/64` for IPv6.
pub fn network_label(ip: IpAddr) -> String {
    match client_network(ip) {
        IpAddr::V6(prefix) => format!("{prefix}/64"),
        v4 => v4.to_string(),
    }
}

/// Note the request's client address: an IPv6 address by its /64 alone.
pub fn note_client(ip: IpAddr) {
    forge_traffic::note_client(client_network(ip), network_label(ip));
}

/// The stored [`TrafficSettings`], or the defaults when never saved.
pub async fn read_settings(pool: &PgPool) -> sqlx::Result<TrafficSettings> {
    match forge_db::authz_dao::get_setting(pool, SETTINGS_KEY).await? {
        None => Ok(TrafficSettings::default()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| sqlx::Error::Decode(Box::new(e))),
    }
}

/// Store the [`TrafficSettings`] for every instance.
pub async fn write_settings(pool: &PgPool, settings: &TrafficSettings) -> sqlx::Result<()> {
    let json = serde_json::to_string(settings).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    forge_db::authz_dao::set_setting(pool, SETTINGS_KEY, &json).await
}

/// The stored settings, applied to this instance ([`Traffic::apply`]); the
/// ones applied before when they cannot be read, `None` when none were. The
/// defaults never stand in for them: they record client addresses an
/// administrator may have turned off, and their retention may be shorter.
async fn follow_settings(pool: &PgPool, traffic: &Traffic) -> Option<TrafficSettings> {
    match read_settings(pool).await {
        Ok(settings) => {
            traffic.apply(&settings);
            Some(settings)
        }
        Err(e) => {
            forge_db::observe_error(&e);
            let applied = traffic.applied();
            if applied.is_some() {
                tracing::warn!(error = %e, "cannot read the traffic settings; keeping the ones in force");
            } else {
                tracing::warn!(
                    error = %e,
                    "cannot read the traffic settings; until they are read, client addresses \
                     are dropped and nothing is pruned"
                );
            }
            applied
        }
    }
}

/// What a flush writes with: `settings`, or before any were read, the
/// defaults without client addresses.
fn flush_settings(settings: Option<&TrafficSettings>) -> TrafficSettings {
    settings.cloned().unwrap_or(TrafficSettings {
        client_addresses: false,
        ..TrafficSettings::default()
    })
}

/// Flush what was counted with `settings` ([`flush_settings`]) and, when
/// `prune` and the settings were read, delete the files past their retention.
/// Returns whether all of it went well.
async fn flush_and_prune(
    traffic: &Traffic,
    settings: Option<&TrafficSettings>,
    prune: bool,
    now: DateTime<Utc>,
) -> bool {
    let mut ok = traffic.flush(&flush_settings(settings), now).await.failures == 0;
    let Some(settings) = settings.filter(|_| prune) else {
        return ok;
    };
    match forge_traffic::layout::prune(&*traffic.objects, settings, now).await {
        Ok(0) => {}
        Ok(deleted) => {
            tracing::info!(deleted, "deleted expired traffic statistics");
        }
        Err(e) => {
            ok = false;
            tracing::warn!(error = %e, "cannot delete expired traffic statistics");
        }
    }
    ok
}

/// Load the geolocation databases from the bucket when they changed.
pub async fn refresh_geo(traffic: &Traffic) -> bool {
    match forge_traffic::geo::refresh(&*traffic.objects, &traffic.geo).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "cannot look for geolocation databases");
            false
        }
    }
}

/// How long until `now`'s next minute is two seconds old.
fn until_next_flush(now: DateTime<Utc>) -> Duration {
    let into_minute =
        now.timestamp().rem_euclid(60) * 1_000 + i64::from(now.timestamp_subsec_millis());
    Duration::from_millis(u64::try_from(62_000 - into_minute).unwrap_or(0))
}

/// The worker: flush every minute, look for new geolocation databases every
/// ten, prune and check the MaxMind download every hour.
pub fn spawn_worker(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let traffic = state.traffic.clone();
        let mut settings = follow_settings(&state.pool, &traffic).await;
        refresh_geo(&traffic).await;
        let mut next_geo = tokio::time::Instant::now() + GEO_REFRESH_INTERVAL;
        // Instances started together prune and download at different times.
        let mut next_hourly = tokio::time::Instant::now()
            + Duration::from_secs(rand::random_range(60..HOURLY.as_secs()));
        loop {
            tokio::time::sleep(until_next_flush(Utc::now())).await;
            let run = forge_telemetry::workers::Run::start(WORKER);
            let ok = async {
                settings = follow_settings(&state.pool, &traffic).await;
                let mut ok = true;
                if tokio::time::Instant::now() >= next_geo {
                    next_geo = tokio::time::Instant::now() + GEO_REFRESH_INTERVAL;
                    ok &= refresh_geo(&traffic).await;
                }
                let hourly = tokio::time::Instant::now() >= next_hourly;
                ok &= flush_and_prune(&traffic, settings.as_ref(), hourly, Utc::now()).await;
                if hourly {
                    next_hourly = tokio::time::Instant::now() + HOURLY;
                    if let Err(e) = maxmind::update_if_due(&state).await {
                        ok = false;
                        tracing::warn!(
                            error = %format!("{e:#}"),
                            "the MaxMind geolocation download failed"
                        );
                    }
                }
                ok
            }
            .instrument(run.span())
            .await;
            run.finish(ok);
        }
    })
}

/// Write what this instance counted and has not written yet, before it
/// exits: at most [`SHUTDOWN_FLUSH`].
pub async fn flush_on_shutdown(traffic: &Traffic, pool: &PgPool) {
    let flush = async {
        // Bounded, so that a database that does not answer leaves the time
        // to write with the settings applied before.
        let settings = tokio::time::timeout(SHUTDOWN_READ, follow_settings(pool, traffic))
            .await
            .unwrap_or_else(|_| traffic.applied());
        traffic
            .flush(&flush_settings(settings.as_ref()), Utc::now())
            .await
    };
    match tokio::time::timeout(SHUTDOWN_FLUSH, flush).await {
        Ok(report) if report.failures > 0 => {
            tracing::warn!(
                ?report,
                "could not write all the traffic statistics on shutdown"
            );
        }
        Ok(_) => {}
        Err(_) => tracing::warn!("writing the traffic statistics on shutdown timed out"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use forge_traffic::{Event, MemoryObjects, Noted};

    /// A pool whose every read fails: nothing listens on port 1.
    fn unreachable_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgres://forge@127.0.0.1:1/forge")
            .unwrap()
    }

    fn traffic() -> Traffic {
        Traffic::new(Arc::new(MemoryObjects::default()), "a".into())
    }

    fn request(traffic: &Traffic, at: DateTime<Utc>) {
        traffic.recorder.record(Event {
            at,
            bytes: 10,
            noted: Noted {
                client: "192.0.2.1".parse().ok(),
                network: Some("192.0.2.1".into()),
                repository: Some("npm".into()),
            },
        });
    }

    /// What `traffic`'s files of `day` hold.
    async fn overview(traffic: &Traffic, day: DateTime<Utc>) -> forge_traffic::query::Overview {
        let day = day.date_naive();
        forge_traffic::query::overview(
            &*traffic.objects,
            &traffic.cache,
            day,
            day,
            &Default::default(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn addresses_turned_off_stay_off_when_the_settings_cannot_be_read() {
        let traffic = traffic();
        let pool = unreachable_pool();
        let stored = TrafficSettings {
            client_addresses: false,
            retention_days: 365,
            ..TrafficSettings::default()
        };
        // What the worker read while the database answered.
        traffic.apply(&stored);

        // The worker's next read fails: it keeps them.
        assert_eq!(follow_settings(&pool, &traffic).await, Some(stored));

        // So does the flush on shutdown.
        let now = Utc::now();
        request(&traffic, now);
        flush_on_shutdown(&traffic, &pool).await;
        let written = overview(&traffic, now).await;
        assert_eq!(written.totals.requests, 1, "the request is counted");
        assert_eq!(written.totals.clients, 0, "{:?}", written.clients);
        assert!(written.clients.is_empty(), "{:?}", written.clients);
    }

    #[tokio::test]
    async fn nothing_is_pruned_and_no_address_written_before_the_settings_are_read() {
        let traffic = traffic();
        let pool = unreachable_pool();
        let now = Utc::now();
        // Past the default retention, within the one an administrator set.
        let old =
            forge_traffic::layout::day_key((now - chrono::Duration::days(30)).timestamp(), "b");
        traffic.objects.put(&old, vec![1]).await.unwrap();

        let settings = follow_settings(&pool, &traffic).await;
        assert_eq!(settings, None, "no defaults stand in for the settings");
        request(&traffic, now);
        flush_and_prune(&traffic, settings.as_ref(), true, now).await;
        assert!(
            traffic.objects.get(&old).await.unwrap().is_some(),
            "pruned before the settings were read"
        );
        let written = overview(&traffic, now).await;
        assert_eq!(written.totals.requests, 1, "the request is counted");
        assert!(written.clients.is_empty(), "{:?}", written.clients);

        // Read, the settings prune.
        let read = TrafficSettings::default();
        traffic.apply(&read);
        flush_and_prune(&traffic, Some(&read), true, now).await;
        assert!(traffic.objects.get(&old).await.unwrap().is_none());
    }

    #[test]
    fn ipv6_clients_are_counted_by_their_64() {
        assert_eq!(network_label("192.0.2.7".parse().unwrap()), "192.0.2.7");
        assert_eq!(
            network_label("::ffff:192.0.2.7".parse().unwrap()),
            "192.0.2.7"
        );
        assert_eq!(
            network_label("2001:db8:1:2:3:4:5:6".parse().unwrap()),
            "2001:db8:1:2::/64"
        );
    }

    #[tokio::test]
    async fn an_ipv6_client_is_noted_by_its_64_alone() {
        let slot = forge_traffic::Slot::new();
        slot.scope(async { note_client("2001:db8:1:2:3:4:5:6".parse().unwrap()) })
            .await;
        let noted = slot.take();
        assert_eq!(noted.client, "2001:db8:1:2::".parse().ok());
        assert_eq!(noted.network.as_deref(), Some("2001:db8:1:2::/64"));

        slot.scope(async { note_client("::ffff:192.0.2.7".parse().unwrap()) })
            .await;
        let noted = slot.take();
        assert_eq!(noted.client, "192.0.2.7".parse().ok());
        assert_eq!(noted.network.as_deref(), Some("192.0.2.7"));
    }

    #[test]
    fn the_flush_waits_for_the_minute_to_turn() {
        let at = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().to_utc();
        assert_eq!(
            until_next_flush(at("2026-10-30T14:00:00Z")),
            Duration::from_secs(62)
        );
        assert_eq!(
            until_next_flush(at("2026-10-30T14:00:59.500Z")),
            Duration::from_millis(2_500)
        );
    }
}
