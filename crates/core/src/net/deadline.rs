//! The deadline of the request a task serves (`server.request_timeout_seconds`).
//!
//! The server bounds every request handler by a deadline
//! ([`HandlerDeadline::run`]). A proxy's download from its upstream has a
//! deadline of its own, `proxy.download_timeout_seconds`, which is much
//! longer: a docker proxy stages a whole layer before it answers, and a
//! first fetch of a large layer from a slow upstream cut off by the
//! handler's deadline would start over on every retry and never be cached.
//! So a download moves the deadline of the request it runs in past its own
//! ([`extend`]), and the request has its full timeout again from there for
//! what it does after (storing the download, answering).
//!
//! The deadline is a task-local the server sets around each request, so the
//! code that downloads needs no handle to it. Outside a request (a
//! background worker) there is none, and [`extend`] does nothing.

use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

tokio::task_local! {
    static CURRENT: HandlerDeadline;
}

/// One request's deadline: `timeout` from its start, moved later by
/// [`extend`].
#[derive(Debug, Clone)]
pub struct HandlerDeadline {
    timeout: Duration,
    at: Arc<Mutex<Instant>>,
}

impl HandlerDeadline {
    /// A deadline `timeout` from now.
    pub fn new(timeout: Duration) -> Self {
        HandlerDeadline {
            timeout,
            at: Arc::new(Mutex::new(Instant::now() + timeout)),
        }
    }

    fn at(&self) -> Instant {
        *self.at.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `request` under this deadline, as the deadline of the task it
    /// runs in. `None` (and `request` dropped) when the deadline passes
    /// first.
    pub async fn run<F: Future>(self, request: F) -> Option<F::Output> {
        let request = CURRENT.scope(self.clone(), request);
        tokio::pin!(request);
        loop {
            let at = self.at();
            tokio::select! {
                output = &mut request => return Some(output),
                () = tokio::time::sleep_until(at) => {
                    if self.at() <= Instant::now() {
                        return None;
                    }
                }
            }
        }
    }
}

/// Let the request the current task serves run until `until`, and then for
/// its full timeout again; a later deadline stays. Nothing outside a
/// request.
pub fn extend(until: Instant) {
    let _ = CURRENT.try_with(|deadline| {
        let mut at = deadline.at.lock().unwrap_or_else(PoisonError::into_inner);
        *at = (*at).max(until + deadline.timeout);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_request_ends_at_its_deadline_unless_extended() {
        let deadline = HandlerDeadline::new(Duration::from_secs(10));
        let slow = tokio::time::sleep(Duration::from_secs(30));
        assert!(deadline.run(slow).await.is_none());

        let deadline = HandlerDeadline::new(Duration::from_secs(10));
        let extended = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            // A 20-second download: the request may run until 25 s + 10 s.
            extend(Instant::now() + Duration::from_secs(20));
            tokio::time::sleep(Duration::from_secs(29)).await;
            "answered"
        };
        assert_eq!(deadline.run(extended).await, Some("answered"));

        let deadline = HandlerDeadline::new(Duration::from_secs(10));
        let too_slow = async {
            extend(Instant::now() + Duration::from_secs(20));
            tokio::time::sleep(Duration::from_secs(31)).await;
        };
        assert!(deadline.run(too_slow).await.is_none());
    }

    #[tokio::test]
    async fn extending_outside_a_request_does_nothing() {
        extend(Instant::now() + Duration::from_secs(1));
    }
}
