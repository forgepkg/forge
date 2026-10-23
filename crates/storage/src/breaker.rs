//! Circuit breaker in front of the object store.
//!
//! Only installed together with the local blob cache
//! ([`BlobStore::with_cache`](crate::s3::BlobStore::with_cache)): there, an
//! instance keeps serving cached blobs while S3 is down, and every request
//! that does need S3 (a cache miss, a push) should learn that at once instead
//! of waiting for the connect or read timeout first.
//!
//! * **Closed** — calls go through. [`FAILURE_THRESHOLD`] consecutive calls
//!   that could not reach S3 open the breaker.
//! * **Open** — calls fail at once with
//!   [`S3Error::Unavailable`](crate::s3::S3Error::Unavailable) for
//!   [`OPEN_FOR`].
//! * **Probing** — after that, the next call is let through as a probe while
//!   the others keep failing fast. Its success closes the breaker, its
//!   failure opens it again. A probe that never reports back (its request was
//!   cancelled) is replaced by a new one after [`PROBE_TIMEOUT`].
//!
//! Any answer from S3, an error status included (a missing key, a refused
//! conditional write), proves it reachable; only connection failures,
//! timeouts and `5xx` answers count as failures.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Consecutive failed calls that open the breaker. Each call already includes
/// the SDK's own retries.
pub const FAILURE_THRESHOLD: u32 = 2;

/// How long an open breaker fails calls before it lets a probe through.
pub const OPEN_FOR: Duration = Duration::from_secs(5);

/// How long a probe may stay unanswered before another call may probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy)]
enum State {
    Closed { failures: u32 },
    Open { until: Instant },
    Probing { since: Instant },
}

/// See the [module docs](self).
#[derive(Debug)]
pub struct CircuitBreaker {
    state: Mutex<State>,
    threshold: u32,
    open_for: Duration,
    probe_timeout: Duration,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(FAILURE_THRESHOLD, OPEN_FOR, PROBE_TIMEOUT)
    }
}

impl CircuitBreaker {
    /// A closed breaker with explicit tuning (tests use short intervals).
    pub fn new(threshold: u32, open_for: Duration, probe_timeout: Duration) -> Self {
        CircuitBreaker {
            state: Mutex::new(State::Closed { failures: 0 }),
            threshold: threshold.max(1),
            open_for,
            probe_timeout,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a call may go to S3 now. While open, `false` (the caller fails
    /// fast); once [`OPEN_FOR`] has passed, `true` for the one caller that
    /// becomes the probe.
    pub fn admit(&self) -> bool {
        let now = Instant::now();
        let mut state = self.lock();
        match *state {
            State::Closed { .. } => true,
            State::Open { until } if now < until => false,
            State::Probing { since } if now.duration_since(since) < self.probe_timeout => false,
            State::Open { .. } | State::Probing { .. } => {
                *state = State::Probing { since: now };
                true
            }
        }
    }

    /// S3 answered: close the breaker.
    pub fn record_success(&self) {
        *self.lock() = State::Closed { failures: 0 };
    }

    /// S3 could not be reached: count the failure, opening the breaker at the
    /// threshold (a failed probe reopens it at once).
    pub fn record_failure(&self) {
        let open = State::Open {
            until: Instant::now() + self.open_for,
        };
        let mut state = self.lock();
        *state = match *state {
            State::Closed { failures } if failures + 1 < self.threshold => State::Closed {
                failures: failures + 1,
            },
            _ => open,
        };
    }

    /// Whether S3 is currently considered down (open, or probing).
    pub fn is_open(&self) -> bool {
        !matches!(*self.lock(), State::Closed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker(open_for: Duration) -> CircuitBreaker {
        CircuitBreaker::new(2, open_for, Duration::from_secs(60))
    }

    #[test]
    fn opens_after_consecutive_failures_only() {
        let b = breaker(Duration::from_secs(60));
        b.record_failure();
        assert!(b.admit() && !b.is_open(), "one failure keeps it closed");
        b.record_success();
        b.record_failure();
        assert!(!b.is_open(), "a success in between resets the count");
        b.record_failure();
        assert!(b.is_open());
        assert!(!b.admit(), "open: calls fail fast");
    }

    #[test]
    fn lets_one_probe_through_after_the_open_interval() {
        let b = breaker(Duration::ZERO);
        b.record_failure();
        b.record_failure();
        assert!(b.admit(), "the interval has passed: this call probes");
        assert!(!b.admit(), "others fail fast while the probe runs");
        assert!(b.is_open());
        b.record_success();
        assert!(!b.is_open() && b.admit(), "a successful probe closes it");
    }

    #[test]
    fn a_failed_probe_reopens() {
        let b = CircuitBreaker::new(2, Duration::from_secs(60), Duration::from_secs(60));
        *b.lock() = State::Open {
            until: Instant::now(),
        };
        assert!(b.admit(), "probe");
        b.record_failure();
        assert!(!b.admit(), "reopened for the full interval");
    }

    #[test]
    fn an_unanswered_probe_is_replaced() {
        let b = CircuitBreaker::new(1, Duration::ZERO, Duration::ZERO);
        b.record_failure();
        assert!(b.admit());
        assert!(b.admit(), "the probe timed out: the next call probes");
    }
}
