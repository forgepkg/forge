//! What the statistics record and how long they are kept.

/// The longest retention accepted, in days (100 years).
pub const MAX_RETENTION_DAYS: u32 = 36_500;

/// The traffic settings of every instance, set in the web UI (Admin →
/// Traffic) or through `/admin/settings/traffic` and kept in the database.
/// An install that never saved them uses [`TrafficSettings::default`].
///
/// Read leniently, like the other stored settings: a key left out takes its
/// default and one this version does not know is ignored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct TrafficSettings {
    /// Whether requests are counted at all. Off, nothing is recorded or
    /// written; what was written stays until it expires.
    pub enabled: bool,
    /// Whether client addresses are recorded: the top clients and the
    /// request log's addresses.
    pub client_addresses: bool,
    /// Whether every request is written to the request log.
    pub request_log: bool,
    /// How long the counts by hour are kept, in days; `0` keeps them.
    pub statistics_retention_days: u32,
    /// How long the top clients are kept, in days.
    pub client_retention_days: u32,
    /// How long the request log is kept, in days.
    pub request_log_retention_days: u32,
}

impl Default for TrafficSettings {
    fn default() -> Self {
        TrafficSettings {
            enabled: true,
            client_addresses: true,
            request_log: true,
            statistics_retention_days: 400,
            client_retention_days: 30,
            request_log_retention_days: 7,
        }
    }
}

impl TrafficSettings {
    /// What is wrong with these settings, if anything.
    pub fn check(&self) -> Result<(), String> {
        if self.statistics_retention_days > MAX_RETENTION_DAYS {
            return Err(format!(
                "statistics_retention_days must be at most {MAX_RETENTION_DAYS}, or 0 to keep the statistics"
            ));
        }
        for (name, days) in [
            ("client_retention_days", self.client_retention_days),
            (
                "request_log_retention_days",
                self.request_log_retention_days,
            ),
        ] {
            if !(1..=MAX_RETENTION_DAYS).contains(&days) {
                return Err(format!("{name} must be between 1 and {MAX_RETENTION_DAYS}"));
            }
        }
        Ok(())
    }
}
