//! The traffic statistics of Admin → Traffic ([`forge_traffic`]): what the
//! server notes about a request for its count, the settings, and the worker
//! that writes the files and deletes the expired ones.
//!
//! * The client address is the one the principal layer resolves (the socket
//!   peer, or what a trusted proxy forwarded), counted under its network as
//!   the login lockout counts it: an IPv6 address by its /64
//!   ([`client_network`]).
//! * The settings ([`TrafficSettings`]) are kept in `forge_setting` under
//!   [`SETTINGS_KEY`]; every instance follows a change with its next flush.
//! * The worker flushes once a minute, a couple of seconds after the minute
//!   turns, and prunes about once an hour, at a random offset per instance.

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use forge_core::auth::login_throttle::client_network;
use forge_core::auth::principal::{AuthMethod, Principal};
use forge_traffic::{Account, Traffic, TrafficSettings};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::state::AppState;

/// The `forge_setting` key of the [`TrafficSettings`].
pub const SETTINGS_KEY: &str = "traffic";

/// The worker's name (`forge.worker`).
pub const WORKER: &str = "traffic";

/// How often the worker prunes.
const PRUNE_INTERVAL: Duration = Duration::from_secs(3_600);

/// How long the last flush on shutdown may take.
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(10);

/// The network `ip` is counted under, as text: the address itself for IPv4,
/// `<prefix>/64` for IPv6.
pub fn network_label(ip: IpAddr) -> String {
    match client_network(ip) {
        IpAddr::V6(prefix) => format!("{prefix}/64"),
        v4 => v4.to_string(),
    }
}

/// Note the request's client address.
pub fn note_client(ip: IpAddr) {
    forge_traffic::note_client(ip.to_canonical(), network_label(ip));
}

/// The account `principal` is, as the statistics name it.
pub fn account_of(principal: &Principal) -> Account {
    match principal {
        Principal::Unauthenticated | Principal::Anonymous { .. } => Account {
            kind: "anonymous",
            user_id: None,
        },
        Principal::User {
            user_id,
            token_id,
            method,
        } => Account {
            kind: match (token_id, method) {
                (Some(_), _) | (None, AuthMethod::Token) => "token",
                (None, AuthMethod::Session) => "session",
                (None, AuthMethod::TrustedHeader) => "trusted_header",
                (None, AuthMethod::Password) => "password",
            },
            user_id: Some(*user_id),
        },
        Principal::Workload { .. } => Account {
            kind: "workload",
            user_id: None,
        },
    }
}

/// Note the account the request runs as.
pub fn note_principal(principal: &Principal) {
    forge_traffic::note_account(account_of(principal));
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

/// The stored settings, applied to this instance's recorder; the ones
/// applied before when they cannot be read.
async fn follow_settings(
    pool: &PgPool,
    traffic: &Traffic,
    last: &TrafficSettings,
) -> TrafficSettings {
    match read_settings(pool).await {
        Ok(settings) => {
            traffic.recorder.apply(&settings);
            settings
        }
        Err(e) => {
            forge_db::observe_error(&e);
            tracing::warn!(error = %e, "cannot read the traffic settings; keeping the ones in force");
            last.clone()
        }
    }
}

/// How long until `now`'s next minute is two seconds old.
fn until_next_flush(now: DateTime<Utc>) -> Duration {
    let into_minute =
        now.timestamp().rem_euclid(60) * 1_000 + i64::from(now.timestamp_subsec_millis());
    Duration::from_millis(u64::try_from(62_000 - into_minute).unwrap_or(0))
}

/// The worker: flush every minute, prune every hour.
pub fn spawn_worker(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let traffic = state.traffic.clone();
        let mut settings =
            follow_settings(&state.pool, &traffic, &TrafficSettings::default()).await;
        // Instances started together prune at different times.
        let mut next_prune = tokio::time::Instant::now()
            + Duration::from_secs(rand::random_range(60..PRUNE_INTERVAL.as_secs()));
        loop {
            tokio::time::sleep(until_next_flush(Utc::now())).await;
            let run = forge_telemetry::workers::Run::start(WORKER);
            let ok = async {
                settings = follow_settings(&state.pool, &traffic, &settings).await;
                let report = traffic.flush(&settings, Utc::now()).await;
                let mut ok = report.failures == 0;
                if tokio::time::Instant::now() >= next_prune {
                    next_prune = tokio::time::Instant::now() + PRUNE_INTERVAL;
                    match forge_traffic::layout::prune(&*traffic.objects, &settings, Utc::now())
                        .await
                    {
                        Ok(0) => {}
                        Ok(deleted) => {
                            tracing::info!(deleted, "deleted expired traffic statistics");
                        }
                        Err(e) => {
                            ok = false;
                            tracing::warn!(error = %e, "cannot delete expired traffic statistics");
                        }
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
        let settings = read_settings(pool).await.unwrap_or_default();
        traffic.flush_all(&settings).await
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

    #[test]
    fn accounts_name_how_the_caller_signed_in() {
        let user = |token_id, method| Principal::User {
            user_id: 9,
            token_id,
            method,
        };
        assert_eq!(
            account_of(&user(Some(1), AuthMethod::Password)).kind,
            "token"
        );
        assert_eq!(account_of(&user(None, AuthMethod::Session)).kind, "session");
        assert_eq!(
            account_of(&user(None, AuthMethod::Session)).user_id,
            Some(9)
        );
        assert_eq!(account_of(&Principal::Unauthenticated).kind, "anonymous");
    }
}
