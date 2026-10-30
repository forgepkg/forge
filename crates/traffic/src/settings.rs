//! What the statistics record and how long they are kept.

/// The longest retention accepted, in days (100 years).
pub const MAX_RETENTION_DAYS: u32 = 36_500;

/// The traffic settings of every instance, set in the web UI (Admin →
/// Traffic → Settings) or through `/admin/settings/traffic` and kept in the
/// database. An install that never saved them uses
/// [`TrafficSettings::default`].
///
/// Read leniently, like the other stored settings: a key left out takes its
/// default and one this version does not know is ignored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct TrafficSettings {
    /// Whether requests are counted at all. Off, nothing is recorded or
    /// written; what was written stays until it expires.
    pub enabled: bool,
    /// Whether client addresses are recorded. Off, requests are still
    /// counted by repository, country and autonomous system.
    pub client_addresses: bool,
    /// How long the day files are kept, in days.
    pub retention_days: u32,
}

impl Default for TrafficSettings {
    fn default() -> Self {
        TrafficSettings {
            enabled: true,
            client_addresses: true,
            retention_days: 90,
        }
    }
}

impl TrafficSettings {
    /// What is wrong with these settings, if anything.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=MAX_RETENTION_DAYS).contains(&self.retention_days) {
            return Err(format!(
                "retention_days must be between 1 and {MAX_RETENTION_DAYS}"
            ));
        }
        Ok(())
    }
}
