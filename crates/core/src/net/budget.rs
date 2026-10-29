//! The memory an instance's upstream conversations hold at once.
//!
//! A proxy operation is a conversation with the upstream: the documents it
//! fetches stay in memory until its format has read them and answered, and
//! the format's reading takes more again (an npm packument's summaries: up
//! to about its size). Many reads at once of large documents (a Renovate run
//! asking for the full packuments of a project's dependencies) add up to
//! more than a process's memory limit, and a process killed for it fails
//! every request it was serving.
//!
//! So every conversation of the instance holds its documents' bytes in one
//! [`DocumentBudget`] (`proxy.max_metadata_memory_bytes`). A document that does
//! not fit is let go, and its conversation waits until others have given
//! back enough (holding no document meanwhile), then reads it again (from
//! the local cache, most often); a conversation still waiting after the
//! metadata timeout gives up, and the request answers 503 with
//! `Retry-After`. A document larger than the whole budget is read alone.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The bytes one permit stands for.
const UNIT_BYTES: u64 = 1024;

/// The bytes of upstream documents all conversations of the instance hold
/// at once: see the module documentation. Clones share the budget.
#[derive(Debug, Clone)]
pub struct DocumentBudget {
    permits: Arc<Semaphore>,
    /// The permits there are.
    units: u32,
}

/// Bytes held in a [`DocumentBudget`], given back when dropped.
pub type Held = OwnedSemaphorePermit;

impl DocumentBudget {
    /// A budget of `bytes` (at least one unit).
    pub fn new(bytes: u64) -> Self {
        let max = u32::try_from(Semaphore::MAX_PERMITS).unwrap_or(u32::MAX);
        let units = u32::try_from(bytes.div_ceil(UNIT_BYTES))
            .unwrap_or(u32::MAX)
            .clamp(1, max);
        DocumentBudget {
            permits: Arc::new(Semaphore::new(units as usize)),
            units,
        }
    }

    /// The whole budget, in bytes.
    pub fn bytes(&self) -> u64 {
        u64::from(self.units) * UNIT_BYTES
    }

    /// The permits `bytes` take: the whole budget at most.
    fn units_of(&self, bytes: u64) -> u32 {
        u32::try_from(bytes.div_ceil(UNIT_BYTES))
            .unwrap_or(u32::MAX)
            .clamp(1, self.units)
    }

    /// Hold `bytes` if they are free now.
    pub fn try_hold(&self, bytes: u64) -> Option<Held> {
        self.permits
            .clone()
            .try_acquire_many_owned(self.units_of(bytes))
            .ok()
    }

    /// Hold `bytes`, waiting up to `wait` for them to come free (first come,
    /// first served). `None` when they did not.
    pub async fn hold(&self, bytes: u64, wait: Duration) -> Option<Held> {
        let units = self.units_of(bytes);
        tokio::time::timeout(wait, self.permits.clone().acquire_many_owned(units))
            .await
            .ok()?
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn holds_bytes_until_they_are_given_back() {
        let budget = DocumentBudget::new(10 * UNIT_BYTES);
        assert_eq!(budget.bytes(), 10 * UNIT_BYTES);
        let first = budget.try_hold(6 * UNIT_BYTES).unwrap();
        // Clones share it.
        let shared = budget.clone();
        assert!(shared.try_hold(5 * UNIT_BYTES).is_none());
        let small = shared.try_hold(1).unwrap();
        let wait = Duration::from_millis(20);
        assert!(budget.hold(4 * UNIT_BYTES, wait).await.is_none());
        drop(small);
        let waiting = tokio::spawn({
            let budget = budget.clone();
            async move { budget.hold(8 * UNIT_BYTES, Duration::from_secs(5)).await }
        });
        tokio::task::yield_now().await;
        drop(first);
        assert!(waiting.await.unwrap().is_some());
    }

    #[test]
    fn a_document_larger_than_the_budget_takes_all_of_it() {
        let budget = DocumentBudget::new(4 * UNIT_BYTES);
        let all = budget.try_hold(100 * UNIT_BYTES).unwrap();
        assert!(budget.try_hold(1).is_none());
        drop(all);
        assert!(budget.try_hold(4 * UNIT_BYTES).is_some());
        // A budget of no bytes still reads one document at a time.
        assert_eq!(DocumentBudget::new(0).bytes(), UNIT_BYTES);
    }
}
