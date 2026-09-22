//! Password-login failure throttling (per client IP + username).
//!
//! Both password entry points — the browser `POST /auth/login` and the wire
//! HTTP Basic password path ([`super::token::BasicAuthSource`]) — record a
//! failure here for every rejected password attempt and consult
//! [`LoginThrottle::is_locked`] before running the provider chain. Once a
//! `(client IP, username)` pair has accumulated `max_failures` failures inside
//! a fixed `window`, further attempts for that pair are refused without
//! touching the chain (no argon2 work, nothing forwarded upstream) until the
//! window lapses. A success clears the pair.
//!
//! Keying on the pair (not the username alone) means an attacker cannot lock a
//! victim out from another address, while a single address still cannot brute
//! force a username. The state is **per instance and in memory** — a cheap
//! first line of defense, not a cluster-wide guarantee; the map is bounded and
//! stale entries are pruned opportunistically.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Upper bound on tracked pairs; beyond it expired entries are pruned first,
/// and if still full the oldest window is evicted.
const MAX_TRACKED: usize = 100_000;

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    window_start: Instant,
}

/// Fixed-window failure counter keyed by `(client IP, lowercased username)`.
#[derive(Debug)]
pub struct LoginThrottle {
    max_failures: u32,
    window: Duration,
    entries: Mutex<HashMap<(IpAddr, String), Entry>>,
}

impl LoginThrottle {
    /// Build a throttle allowing `max_failures` failures per `window`. A
    /// `max_failures` of `0` disables throttling entirely.
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// A throttle that never locks (tests / wiring without config).
    pub fn disabled() -> Self {
        Self::new(0, Duration::ZERO)
    }

    fn key(ip: IpAddr, username: &str) -> (IpAddr, String) {
        (ip, username.trim().to_lowercase())
    }

    /// Whether the pair is currently locked out (too many recent failures).
    pub fn is_locked(&self, ip: IpAddr, username: &str) -> bool {
        if self.max_failures == 0 {
            return false;
        }
        let now = Instant::now();
        let entries = self.entries.lock().expect("login throttle mutex poisoned");
        entries.get(&Self::key(ip, username)).is_some_and(|e| {
            now.duration_since(e.window_start) < self.window && e.failures >= self.max_failures
        })
    }

    /// Record one failed password attempt for the pair.
    pub fn record_failure(&self, ip: IpAddr, username: &str) {
        if self.max_failures == 0 {
            return;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("login throttle mutex poisoned");
        if entries.len() >= MAX_TRACKED {
            let window = self.window;
            entries.retain(|_, e| now.duration_since(e.window_start) < window);
            if entries.len() >= MAX_TRACKED {
                if let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.window_start)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&oldest);
                }
            }
        }
        let entry = entries.entry(Self::key(ip, username)).or_insert(Entry {
            failures: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) >= self.window {
            *entry = Entry {
                failures: 0,
                window_start: now,
            };
        }
        entry.failures = entry.failures.saturating_add(1);
    }

    /// Clear the pair after a successful login.
    pub fn record_success(&self, ip: IpAddr, username: &str) {
        if self.max_failures == 0 {
            return;
        }
        self.entries
            .lock()
            .expect("login throttle mutex poisoned")
            .remove(&Self::key(ip, username));
    }
}

impl Default for LoginThrottle {
    /// 10 failures per 5 minutes.
    fn default() -> Self {
        Self::new(10, Duration::from_secs(300))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn locks_after_max_failures_per_ip_and_username() {
        let t = LoginThrottle::new(3, Duration::from_secs(60));
        let a = ip("203.0.113.1");
        for _ in 0..2 {
            t.record_failure(a, "alice");
            assert!(!t.is_locked(a, "alice"));
        }
        t.record_failure(a, "Alice");
        assert!(t.is_locked(a, "alice"), "username is case-insensitive");
        // Other pairs are unaffected: another IP, another username.
        assert!(!t.is_locked(ip("203.0.113.2"), "alice"));
        assert!(!t.is_locked(a, "bob"));
    }

    #[test]
    fn success_clears_the_pair() {
        let t = LoginThrottle::new(2, Duration::from_secs(60));
        let a = ip("203.0.113.1");
        t.record_failure(a, "alice");
        t.record_success(a, "alice");
        t.record_failure(a, "alice");
        assert!(!t.is_locked(a, "alice"));
    }

    #[test]
    fn window_expiry_unlocks() {
        let t = LoginThrottle::new(1, Duration::from_millis(20));
        let a = ip("203.0.113.1");
        t.record_failure(a, "alice");
        assert!(t.is_locked(a, "alice"));
        std::thread::sleep(Duration::from_millis(30));
        assert!(!t.is_locked(a, "alice"));
        // A new failure starts a fresh window rather than stacking.
        t.record_failure(a, "alice");
        assert!(t.is_locked(a, "alice"));
    }

    #[test]
    fn zero_max_disables() {
        let t = LoginThrottle::disabled();
        let a = ip("203.0.113.1");
        for _ in 0..100 {
            t.record_failure(a, "alice");
        }
        assert!(!t.is_locked(a, "alice"));
    }
}
