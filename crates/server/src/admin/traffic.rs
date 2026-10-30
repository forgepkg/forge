//! The traffic statistics (Admin → Traffic). **Admin-only.**
//!
//! * `GET /admin/traffic?range=&instance=&repository=` — the traffic of a
//!   range ([`forge_traffic::query::Overview`]) over every instance or the
//!   one `instance` names: counts by time bucket, surface, repository and
//!   status, latency, and the top clients. `range` is one of [`RANGES`]
//!   (default `24h`), or `from` and `to` (RFC 3339) give the range.
//! * `GET /admin/traffic/client?network=&range=&instance=` — one client
//!   network's traffic and its requests in the request log
//!   ([`forge_traffic::query::ClientDetail`]).
//! * `GET /admin/settings/traffic` answers the [`TrafficSettings`]; `PUT`
//!   changes the fields a body names, for every instance (each follows with
//!   its next flush).
//!
//! The files are read from the object store, so the answers cover every
//! instance; a store that cannot be read answers 503.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Duration, Utc};
use forge_core::auth::principal::Principal;
use forge_traffic::query::{self, Filter, Span};
use forge_traffic::TrafficSettings;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::AppState;
use crate::traffic::{read_settings, write_settings};

/// The ranges `range` names, and their length.
pub const RANGES: [(&str, i64); 6] = [
    ("1h", 3_600),
    ("6h", 6 * 3_600),
    ("24h", 24 * 3_600),
    ("7d", 7 * 86_400),
    ("30d", 30 * 86_400),
    ("90d", 90 * 86_400),
];

/// The longest range `from` and `to` may give.
const MAX_RANGE_DAYS: i64 = 400;

/// The most users whose names an answer looks up.
const MAX_USERNAMES: usize = 50;

/// The query of both views.
#[derive(Debug, Default, Deserialize)]
pub struct RangeQuery {
    pub range: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Only this instance's files (an id of the answer's `instances`).
    pub instance: Option<String>,
    /// The overview: only this repository's counts.
    pub repository: Option<String>,
    /// The client view: the network ([`crate::traffic::network_label`]).
    pub network: Option<String>,
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn unavailable(e: anyhow::Error) -> Response {
    tracing::warn!(error = %format!("{e:#}"), "cannot read the traffic statistics");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "cannot read the traffic statistics from the object store",
    )
        .into_response()
}

impl RangeQuery {
    fn span(&self, now: DateTime<Utc>) -> Result<Span, Response> {
        let (from, to) = match (self.from, self.to) {
            (Some(from), Some(to)) => {
                if to <= from {
                    return Err(bad_request("to must be after from"));
                }
                if to - from > Duration::days(MAX_RANGE_DAYS) {
                    return Err(bad_request(format!(
                        "a range is at most {MAX_RANGE_DAYS} days"
                    )));
                }
                (from, to)
            }
            (None, None) => {
                let name = self.range.as_deref().unwrap_or("24h");
                let Some((_, secs)) = RANGES.iter().find(|(n, _)| *n == name) else {
                    let names: Vec<&str> = RANGES.iter().map(|(n, _)| *n).collect();
                    return Err(bad_request(format!(
                        "range must be one of {}",
                        names.join(", ")
                    )));
                };
                (now - Duration::seconds(*secs), now)
            }
            _ => return Err(bad_request("give both from and to, or neither")),
        };
        Ok(Span::new(from, to, now))
    }

    fn instance(&self) -> Option<String> {
        self.instance.clone().filter(|i| !i.is_empty())
    }
}

/// The names of the users `ids` name, as far as they still exist.
async fn usernames(state: &AppState, ids: impl Iterator<Item = i64>) -> HashMap<i64, String> {
    let mut wanted: Vec<i64> = ids.collect();
    wanted.sort_unstable();
    wanted.dedup();
    wanted.truncate(MAX_USERNAMES);
    let mut names = HashMap::new();
    for id in wanted {
        match forge_db::user_dao::find_user_by_id(&state.pool, id).await {
            Ok(Some(user)) => {
                names.insert(id, user.username);
            }
            Ok(None) => {}
            Err(e) => {
                forge_db::observe_error(&e);
                tracing::warn!(error = %e, "cannot look up the users of the traffic statistics");
                break;
            }
        }
    }
    names
}

/// What the views say of the settings, so the page can tell why something
/// is missing.
#[derive(Debug, Serialize)]
pub struct Recording {
    pub enabled: bool,
    pub client_addresses: bool,
    pub request_log: bool,
}

impl From<&TrafficSettings> for Recording {
    fn from(s: &TrafficSettings) -> Self {
        Recording {
            enabled: s.enabled,
            client_addresses: s.client_addresses,
            request_log: s.request_log,
        }
    }
}

/// `GET /admin/traffic`.
#[derive(Debug, Serialize)]
pub struct OverviewView {
    #[serde(flatten)]
    pub overview: query::Overview,
    pub recording: Recording,
}

/// `GET /admin/traffic`
pub async fn overview(State(state): State<AppState>, Query(q): Query<RangeQuery>) -> Response {
    let span = match q.span(Utc::now()) {
        Ok(span) => span,
        Err(resp) => return resp,
    };
    let settings = match stored(&state).await {
        Ok(settings) => settings,
        Err(resp) => return resp,
    };
    let filter = Filter {
        instance: q.instance(),
        repository: q.repository.clone().filter(|r| !r.is_empty()),
    };
    let traffic = &state.traffic;
    let mut overview = match query::overview(&*traffic.objects, &traffic.cache, span, &filter).await
    {
        Ok(overview) => overview,
        Err(e) => return unavailable(e),
    };
    let names = usernames(&state, overview.clients.iter().filter_map(|c| c.user_id)).await;
    for client in &mut overview.clients {
        client.username = client.user_id.and_then(|id| names.get(&id).cloned());
    }
    Json(OverviewView {
        overview,
        recording: Recording::from(&settings),
    })
    .into_response()
}

/// `GET /admin/traffic/client`.
#[derive(Debug, Serialize)]
pub struct ClientView {
    #[serde(flatten)]
    pub detail: query::ClientDetail,
    pub recording: Recording,
}

/// `GET /admin/traffic/client`
pub async fn client(State(state): State<AppState>, Query(q): Query<RangeQuery>) -> Response {
    let Some(network) = q.network.clone().filter(|n| !n.is_empty()) else {
        return bad_request("network is required");
    };
    let span = match q.span(Utc::now()) {
        Ok(span) => span,
        Err(resp) => return resp,
    };
    let settings = match stored(&state).await {
        Ok(settings) => settings,
        Err(resp) => return resp,
    };
    let traffic = &state.traffic;
    let instance = q.instance();
    let mut detail = match query::client(
        &*traffic.objects,
        &traffic.cache,
        span,
        instance.as_deref(),
        &network,
    )
    .await
    {
        Ok(detail) => detail,
        Err(e) => return unavailable(e),
    };
    let ids = detail
        .totals
        .iter()
        .filter_map(|t| t.user_id)
        .chain(detail.log.entries.iter().filter_map(|e| e.user_id))
        .chain(detail.log.accounts.iter().filter_map(|a| a.user_id));
    let names = usernames(&state, ids).await;
    if let Some(totals) = &mut detail.totals {
        totals.username = totals.user_id.and_then(|id| names.get(&id).cloned());
    }
    for entry in &mut detail.log.entries {
        entry.username = entry.user_id.and_then(|id| names.get(&id).cloned());
    }
    for account in &mut detail.log.accounts {
        account.username = account.user_id.and_then(|id| names.get(&id).cloned());
    }
    Json(ClientView {
        detail,
        recording: Recording::from(&settings),
    })
    .into_response()
}

/// The stored settings, or the 500 answer when they cannot be read.
async fn stored(state: &AppState) -> Result<TrafficSettings, Response> {
    read_settings(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "cannot read the traffic settings");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot read the traffic settings",
        )
            .into_response()
    })
}

/// `PUT /admin/settings/traffic` body: the fields to change. Unknown fields
/// are refused, so a misspelled one is not dropped.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficSettingsUpdate {
    pub enabled: Option<bool>,
    pub client_addresses: Option<bool>,
    pub request_log: Option<bool>,
    pub statistics_retention_days: Option<u32>,
    pub client_retention_days: Option<u32>,
    pub request_log_retention_days: Option<u32>,
}

/// `GET /admin/settings/traffic`
pub async fn get_settings(State(state): State<AppState>) -> Response {
    match stored(&state).await {
        Ok(settings) => Json(settings).into_response(),
        Err(resp) => resp,
    }
}

/// `PUT /admin/settings/traffic` — change the fields the body names. This
/// instance applies a change at once, the others with their next flush.
pub async fn put_settings(
    State(state): State<AppState>,
    axum::Extension(principal): axum::Extension<Principal>,
    Json(update): Json<TrafficSettingsUpdate>,
) -> Response {
    let current = match stored(&state).await {
        Ok(settings) => settings,
        Err(resp) => return resp,
    };
    let mut next = current.clone();
    let TrafficSettingsUpdate {
        enabled,
        client_addresses,
        request_log,
        statistics_retention_days,
        client_retention_days,
        request_log_retention_days,
    } = update;
    next.enabled = enabled.unwrap_or(next.enabled);
    next.client_addresses = client_addresses.unwrap_or(next.client_addresses);
    next.request_log = request_log.unwrap_or(next.request_log);
    next.statistics_retention_days =
        statistics_retention_days.unwrap_or(next.statistics_retention_days);
    next.client_retention_days = client_retention_days.unwrap_or(next.client_retention_days);
    next.request_log_retention_days =
        request_log_retention_days.unwrap_or(next.request_log_retention_days);
    if let Err(msg) = next.check() {
        return bad_request(msg);
    }
    if next != current {
        if let Err(e) = write_settings(&state.pool, &next).await {
            return super::db_error(e);
        }
        state.traffic.recorder.apply(&next);
        tracing::info!(
            target: "forge::audit",
            settings = ?next,
            principal = %principal.audit_label(),
            "traffic settings changed"
        );
    }
    Json(next).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().to_utc()
    }

    #[test]
    fn ranges_are_named_or_given() {
        let now = at("2026-10-30T14:10:00Z");
        let span = RangeQuery::default().span(now).unwrap();
        assert_eq!(span.from, at("2026-10-29T14:10:00Z"), "24 hours by default");
        let q = RangeQuery {
            range: Some("7d".into()),
            ..RangeQuery::default()
        };
        assert_eq!(q.span(now).unwrap().resolution, "hour");
        let q = RangeQuery {
            range: Some("2h".into()),
            ..RangeQuery::default()
        };
        assert!(q.span(now).is_err());
        let q = RangeQuery {
            from: Some(at("2026-10-30T10:00:00Z")),
            to: Some(at("2026-10-30T11:00:00Z")),
            ..RangeQuery::default()
        };
        assert_eq!(q.span(now).unwrap().to, at("2026-10-30T11:00:00Z"));
        let q = RangeQuery {
            from: Some(at("2026-10-30T10:00:00Z")),
            ..RangeQuery::default()
        };
        assert!(q.span(now).is_err(), "from alone");
    }
}
