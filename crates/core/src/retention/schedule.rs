//! When a repository's retention policy runs.
//!
//! Every policy shape (package, raw file and image policies) has the same
//! scheduling fields in its envelope:
//!
//! * `min_run_interval_seconds` (default 3600): a run at most that often;
//! * `schedule`: a 5-field cron pattern (`minute hour day-of-month month
//!   day-of-week`, e.g. `0 3 * * *`), as an alternative to the interval: the
//!   worker runs the policy at the pattern's times instead;
//! * `schedule_timezone`: the IANA time zone the pattern's times are in
//!   (`Europe/Berlin`); UTC without one;
//! * `max_run_seconds`: how long a run may apply decisions before it stops
//!   (the end of a maintenance window). The next run evaluates the
//!   repository again and goes on with what is left.
//!
//! A pattern's times follow the zone's daylight-saving changes as Vixie cron
//! does ([croner]'s rules, the Open Cron Pattern Specification): a time that
//! falls into the hour the clocks skip runs right after the change, on that
//! day; a time in the hour they repeat runs once, at its first occurrence.
//! `0 3 * * *` in `Europe/Berlin` therefore runs at 03:00 Berlin time every
//! day, whether that is 01:00 or 02:00 UTC.
//!
//! The functions here are pure: the worker passes the database's clock.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use croner::parser::{CronParser, Seconds, Year};
use croner::Cron;
use serde_json::Value as JsonValue;

/// The shortest `max_run_seconds` a policy may set.
pub const MIN_MAX_RUN_SECONDS: u64 = 60;

/// The longest `max_run_seconds` a policy may set (a week).
pub const MAX_MAX_RUN_SECONDS: u64 = 7 * 24 * 60 * 60;

/// A policy's `schedule` in its `schedule_timezone`, parsed.
#[derive(Debug, Clone)]
pub struct Schedule {
    cron: Cron,
    zone: Tz,
}

impl Schedule {
    /// Parse a 5-field cron `pattern` (`@daily`, `@weekly` and the other
    /// nicknames are accepted too) for the IANA time zone `zone` (UTC when
    /// `None`).
    pub fn parse(pattern: &str, zone: Option<&str>) -> Result<Schedule, String> {
        let cron = CronParser::builder()
            .seconds(Seconds::Disallowed)
            .year(Year::Disallowed)
            .build()
            .parse(pattern)
            .map_err(|e| {
                format!(
                    "schedule {pattern:?} is not a cron pattern of 5 fields \
                     (minute hour day-of-month month day-of-week, e.g. \"0 3 * * *\"): {e}"
                )
            })?;
        let zone = match zone {
            None => Tz::UTC,
            Some(name) => Tz::from_str(name).map_err(|_| {
                format!(
                    "schedule_timezone {name:?} is not an IANA time zone \
                     (e.g. \"Europe/Berlin\" or \"UTC\")"
                )
            })?,
        };
        Ok(Schedule { cron, zone })
    }

    /// The time zone the pattern's times are in.
    pub fn zone(&self) -> Tz {
        self.zone
    }

    /// The first time of the pattern strictly after `after`, or `None` when
    /// the pattern names no time within croner's search range (e.g. the 30th
    /// of February).
    pub fn next_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.cron
            .find_next_occurrence(&after.with_timezone(&self.zone), false)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }

    /// The pattern's next `n` times after `after`.
    pub fn next_runs(&self, after: DateTime<Utc>, n: usize) -> Vec<DateTime<Utc>> {
        let mut runs = Vec::with_capacity(n);
        let mut at = after;
        while runs.len() < n {
            let Some(next) = self.next_after(at) else {
                break;
            };
            runs.push(next);
            at = next;
        }
        runs
    }
}

/// Check an envelope's scheduling fields: `schedule` parses and names a time
/// after `now`, `schedule_timezone` is a zone and comes with a schedule, and
/// `max_run_seconds` is within [`MIN_MAX_RUN_SECONDS`] and
/// [`MAX_MAX_RUN_SECONDS`].
pub fn validate(
    schedule: Option<&str>,
    zone: Option<&str>,
    max_run_seconds: Option<u64>,
    now: DateTime<Utc>,
) -> Result<(), String> {
    match schedule {
        Some(pattern) => {
            let parsed = Schedule::parse(pattern, zone)?;
            if parsed.next_after(now).is_none() {
                return Err(format!("schedule {pattern:?} names no time that comes"));
            }
        }
        None if zone.is_some() => {
            return Err("schedule_timezone needs a schedule".into());
        }
        None => {}
    }
    if let Some(secs) = max_run_seconds {
        if !(MIN_MAX_RUN_SECONDS..=MAX_MAX_RUN_SECONDS).contains(&secs) {
            return Err(format!(
                "max_run_seconds must be between {MIN_MAX_RUN_SECONDS} and \
                 {MAX_MAX_RUN_SECONDS} (a week)"
            ));
        }
    }
    Ok(())
}

/// The schedule a stored policy of any shape names, when it names one that
/// parses (validation refuses any other, so `None` means an interval policy).
pub fn of_policy(policy: &JsonValue) -> Option<Schedule> {
    let pattern = policy.get("schedule")?.as_str()?;
    let zone = policy.get("schedule_timezone").and_then(JsonValue::as_str);
    Schedule::parse(pattern, zone).ok()
}

/// How long a run of a stored policy of any shape may apply decisions
/// (`max_run_seconds`), or `None` when it may take as long as it needs.
pub fn max_run_duration(policy: &JsonValue) -> Option<std::time::Duration> {
    policy
        .get("max_run_seconds")
        .and_then(JsonValue::as_u64)
        .map(|secs| std::time::Duration::from_secs(secs.min(MAX_MAX_RUN_SECONDS)))
}

/// A run's time limit as its apply loops see it: [`Self::out_of_time`] is
/// asked before each step (a batch, an eviction), and says stop once the
/// deadline passed. The first step always goes, so a run whose evaluation
/// alone outlasts its `max_run_seconds` still makes progress.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RunClock {
    deadline: Option<std::time::Instant>,
    stepped: bool,
}

impl RunClock {
    pub(crate) fn new(deadline: Option<std::time::Instant>) -> Self {
        RunClock {
            deadline,
            stepped: false,
        }
    }

    /// Whether the run must stop before the step it is about to take.
    pub(crate) fn out_of_time(&mut self) -> bool {
        let out = self.stepped
            && self
                .deadline
                .is_some_and(|deadline| std::time::Instant::now() >= deadline);
        self.stepped = true;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    fn berlin(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        chrono_tz::Europe::Berlin
            .with_ymd_and_hms(y, mo, d, h, mi, 0)
            .earliest()
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn a_daily_run_stays_at_its_local_time_across_the_spring_change() {
        // Berlin moves from CET (UTC+1) to CEST (UTC+2) on 2026-03-29 at
        // 02:00 local time.
        let s = Schedule::parse("0 3 * * *", Some("Europe/Berlin")).unwrap();
        let runs = s.next_runs(utc(2026, 3, 27, 12, 0), 4);
        assert_eq!(
            runs,
            vec![
                utc(2026, 3, 28, 2, 0), // 03:00 CET
                utc(2026, 3, 29, 1, 0), // 03:00 CEST, the day of the change
                utc(2026, 3, 30, 1, 0),
                utc(2026, 3, 31, 1, 0),
            ]
        );
        for run in &runs {
            let local = run.with_timezone(&chrono_tz::Europe::Berlin);
            assert_eq!(local.format("%H:%M").to_string(), "03:00", "{local}");
        }
    }

    #[test]
    fn a_daily_run_stays_at_its_local_time_across_the_autumn_change() {
        // Back from CEST to CET on 2026-10-25 at 03:00 local time.
        let s = Schedule::parse("0 3 * * *", Some("Europe/Berlin")).unwrap();
        let runs = s.next_runs(utc(2026, 10, 23, 12, 0), 4);
        assert_eq!(
            runs,
            vec![
                utc(2026, 10, 24, 1, 0), // 03:00 CEST
                utc(2026, 10, 25, 2, 0), // 03:00 CET, the day of the change
                utc(2026, 10, 26, 2, 0),
                utc(2026, 10, 27, 2, 0),
            ]
        );
        for run in &runs {
            let local = run.with_timezone(&chrono_tz::Europe::Berlin);
            assert_eq!(local.format("%H:%M").to_string(), "03:00", "{local}");
        }
    }

    #[test]
    fn a_time_in_the_skipped_hour_runs_once_right_after_it() {
        // 02:30 does not exist in Berlin on 2026-03-29: the run is at 03:00
        // CEST, once, and the next day at 02:30 again.
        let s = Schedule::parse("30 2 * * *", Some("Europe/Berlin")).unwrap();
        assert_eq!(
            s.next_runs(utc(2026, 3, 28, 12, 0), 2),
            vec![berlin(2026, 3, 29, 3, 0), berlin(2026, 3, 30, 2, 30)]
        );
    }

    #[test]
    fn a_time_in_the_repeated_hour_runs_once() {
        // 02:30 happens twice in Berlin on 2026-10-25 (CEST, then CET): the
        // run is at the first, and the next one a day later.
        let s = Schedule::parse("30 2 * * *", Some("Europe/Berlin")).unwrap();
        let runs = s.next_runs(utc(2026, 10, 24, 12, 0), 2);
        assert_eq!(
            runs,
            vec![utc(2026, 10, 25, 0, 30), utc(2026, 10, 26, 1, 30)]
        );
    }

    #[test]
    fn utc_is_the_default_zone_and_the_next_time_is_strictly_later() {
        let s = Schedule::parse("0 3 * * 1-5", None).unwrap();
        assert_eq!(s.zone(), Tz::UTC);
        // Friday 2026-10-30 03:00 → the next weekday is Monday.
        assert_eq!(
            s.next_after(utc(2026, 10, 30, 3, 0)),
            Some(utc(2026, 11, 2, 3, 0))
        );
        assert_eq!(
            s.next_after(utc(2026, 10, 30, 2, 59)),
            Some(utc(2026, 10, 30, 3, 0))
        );
        let daily = Schedule::parse("@daily", None).unwrap();
        assert_eq!(
            daily.next_after(utc(2026, 10, 30, 3, 0)),
            Some(utc(2026, 10, 31, 0, 0))
        );
    }

    #[test]
    fn validation() {
        let now = utc(2026, 10, 31, 12, 0);
        assert!(validate(None, None, None, now).is_ok());
        assert!(validate(Some("0 3 * * *"), Some("Europe/Berlin"), Some(3600), now).is_ok());
        assert!(validate(Some("*/15 * * * *"), None, None, now).is_ok());
        for bad in [
            "",
            "0 3 * *",
            "0 0 3 * * *",
            "0 3 * * * 2026",
            "61 * * * *",
            "nonsense",
        ] {
            let err = validate(Some(bad), None, None, now).unwrap_err();
            assert!(err.contains("5 fields"), "{bad:?}: {err}");
        }
        let err = validate(Some("0 3 * * *"), Some("Mars/Olympus"), None, now).unwrap_err();
        assert!(err.contains("IANA"), "{err}");
        let err = validate(None, Some("Europe/Berlin"), None, now).unwrap_err();
        assert!(err.contains("needs a schedule"), "{err}");
        for secs in [0, 59, MAX_MAX_RUN_SECONDS + 1] {
            assert!(validate(None, None, Some(secs), now).is_err(), "{secs}");
        }
        assert!(validate(None, None, Some(MIN_MAX_RUN_SECONDS), now).is_ok());
    }

    #[test]
    fn a_clock_past_its_deadline_lets_the_first_step_go() {
        let mut past = RunClock::new(Some(std::time::Instant::now()));
        assert!(!past.out_of_time());
        assert!(past.out_of_time());
        let mut unlimited = RunClock::new(None);
        assert!(!unlimited.out_of_time());
        assert!(!unlimited.out_of_time());
        let mut later = RunClock::new(Some(
            std::time::Instant::now() + std::time::Duration::from_secs(3600),
        ));
        assert!(!later.out_of_time());
        assert!(!later.out_of_time());
    }

    #[test]
    fn reads_a_stored_policy_of_any_shape() {
        let policy = serde_json::json!({
            "version": 1,
            "schedule": "0 3 * * *",
            "schedule_timezone": "Europe/Berlin",
            "max_run_seconds": 7200,
            "rules": [],
        });
        let s = of_policy(&policy).unwrap();
        assert_eq!(s.zone(), chrono_tz::Europe::Berlin);
        assert_eq!(
            max_run_duration(&policy),
            Some(std::time::Duration::from_secs(7200))
        );
        let interval = serde_json::json!({"version": 1, "rules": []});
        assert!(of_policy(&interval).is_none());
        assert!(max_run_duration(&interval).is_none());
    }
}
