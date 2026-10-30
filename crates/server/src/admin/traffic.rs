//! The traffic statistics (Admin → Traffic). **Admin-only.**
//!
//! * `GET /admin/traffic?range=&instance=&repository=&network=&country=&asn=`
//!   — the requests of a range of days ([`forge_traffic::query::Overview`])
//!   over every instance or the one `instance` names: by day, repository,
//!   country, autonomous system and client network. `range` is one of
//!   [`RANGES`] (default `30d`), or `from` and `to` (dates, both included)
//!   give it. `repository=-` keeps the requests that addressed no
//!   repository, `country=-` and `asn=0` the ones from nowhere known.
//! * `GET /admin/settings/traffic` answers the [`TrafficSettings`]; `PUT`
//!   changes the fields a body names, for every instance (each follows with
//!   its next flush).
//! * `GET /admin/traffic/geoip` — the geolocation databases this instance
//!   loaded and the MaxMind download's account and outcome; `PUT` sets the
//!   account ID and license key (sealed), `DELETE` forgets them and deletes
//!   the databases, `POST /admin/traffic/geoip/update` downloads them now.
//!
//! The files are read from the object store, so the answers cover every
//! instance; a store that cannot be read answers 503.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::{Duration, NaiveDate, Utc};
use forge_core::auth::principal::Principal;
use forge_traffic::query::{self, Filter};
use forge_traffic::{DbInfo, GeoKind, TrafficSettings};
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use crate::traffic::maxmind::{self, MaxmindState};
use crate::traffic::{read_settings, write_settings};

/// The ranges `range` names, in days up to today (included).
pub const RANGES: [(&str, i64); 5] = [
    ("today", 1),
    ("7d", 7),
    ("30d", 30),
    ("90d", 90),
    ("365d", 365),
];

/// What a filter value says for "none" (no repository, no known country).
const NONE: &str = "-";

/// The query of the overview.
#[derive(Debug, Default, Deserialize)]
pub struct OverviewQuery {
    pub range: Option<String>,
    pub from: Option<NaiveDate>,
    pub to: Option<NaiveDate>,
    /// Only this instance's files (an id of the answer's `instances`).
    pub instance: Option<String>,
    /// Only this repository's requests; `-` for the ones to none.
    pub repository: Option<String>,
    /// Only this client network's requests.
    pub network: Option<String>,
    /// Only this country's requests (ISO code); `-` for unknown.
    pub country: Option<String>,
    /// Only this autonomous system's requests; `0` for unknown.
    pub asn: Option<u32>,
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

fn some(value: &Option<String>) -> Option<String> {
    value.as_deref().filter(|v| !v.is_empty()).map(|v| {
        if v == NONE {
            String::new()
        } else {
            v.to_string()
        }
    })
}

impl OverviewQuery {
    /// The days the query covers, both included.
    fn days(&self, today: NaiveDate) -> Result<(NaiveDate, NaiveDate), Response> {
        match (self.from, self.to) {
            (Some(from), Some(to)) => {
                if to < from {
                    return Err(bad_request("to must not be before from"));
                }
                if (to - from).num_days() >= query::MAX_DAYS {
                    return Err(bad_request(format!(
                        "a range is at most {} days",
                        query::MAX_DAYS
                    )));
                }
                Ok((from, to))
            }
            (None, None) => {
                let name = self.range.as_deref().unwrap_or("30d");
                let Some((_, days)) = RANGES.iter().find(|(n, _)| *n == name) else {
                    let names: Vec<&str> = RANGES.iter().map(|(n, _)| *n).collect();
                    return Err(bad_request(format!(
                        "range must be one of {}",
                        names.join(", ")
                    )));
                };
                Ok((today - Duration::days(days - 1), today))
            }
            _ => Err(bad_request("give both from and to, or neither")),
        }
    }

    fn filter(&self) -> Filter {
        Filter {
            instance: self.instance.clone().filter(|i| !i.is_empty()),
            repository: some(&self.repository),
            network: self.network.clone().filter(|n| !n.is_empty()),
            country: some(&self.country),
            asn: self.asn,
        }
    }
}

/// What is recorded now and what can be looked up, so the page can tell why
/// something is missing.
#[derive(Debug, Serialize)]
pub struct Recording {
    pub enabled: bool,
    pub client_addresses: bool,
    /// Whether this instance has a country database loaded.
    pub countries: bool,
    /// Whether this instance has an autonomous system database loaded.
    pub asns: bool,
}

/// `GET /admin/traffic`.
#[derive(Debug, Serialize)]
pub struct OverviewView {
    #[serde(flatten)]
    pub overview: query::Overview,
    pub recording: Recording,
}

/// `GET /admin/traffic`
pub async fn overview(State(state): State<AppState>, Query(q): Query<OverviewQuery>) -> Response {
    let (from, to) = match q.days(Utc::now().date_naive()) {
        Ok(days) => days,
        Err(resp) => return resp,
    };
    let settings = match stored(&state).await {
        Ok(settings) => settings,
        Err(resp) => return resp,
    };
    let traffic = &state.traffic;
    let overview =
        match query::overview(&*traffic.objects, &traffic.cache, from, to, &q.filter()).await {
            Ok(overview) => overview,
            Err(e) => return unavailable(e),
        };
    Json(OverviewView {
        overview,
        recording: Recording {
            enabled: settings.enabled,
            client_addresses: settings.client_addresses,
            countries: traffic.geo.info(GeoKind::Country).is_some(),
            asns: traffic.geo.info(GeoKind::Asn).is_some(),
        },
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
    pub retention_days: Option<u32>,
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
    let TrafficSettingsUpdate {
        enabled,
        client_addresses,
        retention_days,
    } = update;
    let next = TrafficSettings {
        enabled: enabled.unwrap_or(current.enabled),
        client_addresses: client_addresses.unwrap_or(current.client_addresses),
        retention_days: retention_days.unwrap_or(current.retention_days),
    };
    if let Err(msg) = next.check() {
        return bad_request(msg);
    }
    if next != current {
        if let Err(e) = write_settings(&state.pool, &next).await {
            return super::db_error(e);
        }
        state.traffic.recorder.set_enabled(next.enabled);
        tracing::info!(
            target: "forge::audit",
            settings = ?next,
            principal = %principal.audit_label(),
            "traffic settings changed"
        );
    }
    Json(next).into_response()
}

/// `GET /admin/traffic/geoip`.
#[derive(Debug, Serialize)]
pub struct GeoipView {
    /// The databases the answering instance loaded.
    pub country: Option<DbInfo>,
    pub asn: Option<DbInfo>,
    /// The MaxMind download.
    pub maxmind: MaxmindView,
}

/// The MaxMind download, without the license key.
#[derive(Debug, Serialize)]
pub struct MaxmindView {
    pub account_id: Option<String>,
    pub license_key_set: bool,
    pub last_attempt: Option<chrono::DateTime<Utc>>,
    pub last_success: Option<chrono::DateTime<Utc>>,
    pub last_error: Option<String>,
    /// Where the databases are downloaded from (`traffic.maxmind_url`).
    pub url: String,
    /// The editions downloaded.
    pub editions: Vec<&'static str>,
}

async fn geoip_view(state: &AppState) -> Result<GeoipView, Response> {
    let (stored, _) = maxmind::read_state(&state.pool)
        .await
        .map_err(super::db_error)?;
    let license_key_set = maxmind::has_license_key(&state.pool)
        .await
        .map_err(super::db_error)?;
    let MaxmindState {
        account_id,
        last_attempt,
        last_success,
        last_error,
    } = stored;
    Ok(GeoipView {
        country: state.traffic.geo.info(GeoKind::Country),
        asn: state.traffic.geo.info(GeoKind::Asn),
        maxmind: MaxmindView {
            account_id,
            license_key_set,
            last_attempt,
            last_success,
            last_error,
            url: state.config.traffic.maxmind_base().to_string(),
            editions: maxmind::EDITIONS.iter().map(|(_, e)| *e).collect(),
        },
    })
}

/// `GET /admin/traffic/geoip`
pub async fn get_geoip(State(state): State<AppState>) -> Response {
    // Pick up databases another instance stored a moment ago.
    crate::traffic::refresh_geo(&state.traffic).await;
    match geoip_view(&state).await {
        Ok(view) => Json(view).into_response(),
        Err(resp) => resp,
    }
}

/// `PUT /admin/traffic/geoip` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoipCredentials {
    pub account_id: String,
    /// Left out (or empty) keeps the stored one.
    #[serde(default)]
    pub license_key: Option<String>,
}

/// `PUT /admin/traffic/geoip` — set the MaxMind account ID and license key.
/// The databases are downloaded with the worker's next check, or at once
/// with `POST /admin/traffic/geoip/update`.
pub async fn put_geoip(
    State(state): State<AppState>,
    axum::Extension(principal): axum::Extension<Principal>,
    Json(body): Json<GeoipCredentials>,
) -> Response {
    let account_id = body.account_id.trim();
    if account_id.is_empty()
        || account_id.len() > 32
        || !account_id.chars().all(|c| c.is_ascii_digit())
    {
        return bad_request("account_id must be the MaxMind account ID, a number");
    }
    let license_key = body
        .license_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty());
    if let Some(key) = license_key {
        if key.len() > 256 || !key.chars().all(|c| c.is_ascii_graphic()) {
            return bad_request("license_key must be a MaxMind license key");
        }
    } else {
        match maxmind::has_license_key(&state.pool).await {
            Ok(true) => {}
            Ok(false) => return bad_request("license_key is required"),
            Err(e) => return super::db_error(e),
        }
    }
    if let Err(e) = maxmind::set_credentials(&state, account_id, license_key).await {
        tracing::error!(error = %format!("{e:#}"), "cannot store the MaxMind credentials");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot store the MaxMind credentials",
        )
            .into_response();
    }
    tracing::info!(
        target: "forge::audit",
        account_id,
        license_key_changed = license_key.is_some(),
        principal = %principal.audit_label(),
        "MaxMind credentials changed"
    );
    match geoip_view(&state).await {
        Ok(view) => Json(view).into_response(),
        Err(resp) => resp,
    }
}

/// `DELETE /admin/traffic/geoip` — forget the MaxMind credentials and delete
/// the databases: requests are no longer located.
pub async fn delete_geoip(
    State(state): State<AppState>,
    axum::Extension(principal): axum::Extension<Principal>,
) -> Response {
    if let Err(e) = maxmind::forget(&state).await {
        tracing::error!(error = %format!("{e:#}"), "cannot remove the geolocation databases");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "cannot remove the geolocation databases",
        )
            .into_response();
    }
    tracing::info!(
        target: "forge::audit",
        principal = %principal.audit_label(),
        "MaxMind credentials and geolocation databases removed"
    );
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /admin/traffic/geoip/update` — download the databases now. Answers
/// the status, the download's error included; 409 without credentials.
pub async fn update_geoip(State(state): State<AppState>) -> Response {
    let (stored, raw) = match maxmind::read_state(&state.pool).await {
        Ok(found) => found,
        Err(e) => return super::db_error(e),
    };
    match maxmind::has_license_key(&state.pool).await {
        Ok(true) if stored.account_id.is_some() => {}
        Ok(_) => {
            return (
                StatusCode::CONFLICT,
                "set the MaxMind account ID and license key first",
            )
                .into_response()
        }
        Err(e) => return super::db_error(e),
    }
    match maxmind::claim(&state.pool, &stored, raw.as_deref(), Utc::now()).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                "another instance is downloading the databases; try again in a moment",
            )
                .into_response()
        }
        Err(e) => return super::db_error(e),
    }
    // The outcome, a failure included, is in the answer's `last_error`.
    let _ = maxmind::update(&state).await;
    match geoip_view(&state).await {
        Ok(view) => Json(view).into_response(),
        Err(resp) => resp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn ranges_are_named_or_given() {
        let today = d("2026-10-30");
        assert_eq!(
            OverviewQuery::default().days(today).unwrap(),
            (d("2026-10-01"), today),
            "30 days by default, today included"
        );
        let q = OverviewQuery {
            range: Some("today".into()),
            ..OverviewQuery::default()
        };
        assert_eq!(q.days(today).unwrap(), (today, today));
        let q = OverviewQuery {
            range: Some("2h".into()),
            ..OverviewQuery::default()
        };
        assert!(q.days(today).is_err());
        let q = OverviewQuery {
            from: Some(d("2026-10-10")),
            to: Some(d("2026-10-12")),
            ..OverviewQuery::default()
        };
        assert_eq!(q.days(today).unwrap(), (d("2026-10-10"), d("2026-10-12")));
        let q = OverviewQuery {
            from: Some(d("2026-10-10")),
            ..OverviewQuery::default()
        };
        assert!(q.days(today).is_err(), "from alone");
    }

    #[test]
    fn a_dash_filters_for_none() {
        let q = OverviewQuery {
            repository: Some("-".into()),
            country: Some("DE".into()),
            network: Some(String::new()),
            ..OverviewQuery::default()
        };
        let f = q.filter();
        assert_eq!(f.repository.as_deref(), Some(""));
        assert_eq!(f.country.as_deref(), Some("DE"));
        assert_eq!(f.network, None);
    }
}
