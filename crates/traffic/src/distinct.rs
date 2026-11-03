//! Counting distinct client networks in bounded memory.
//!
//! A count is exact up to [`EXACT`] networks: it keeps a hash of each. Past
//! that it turns into a HyperLogLog sketch of [`EXACT`] one-byte registers
//! (16 KiB), whose count is off by about 1 %, however many networks follow.

use std::collections::HashSet;
use std::hash::{BuildHasher, BuildHasherDefault, DefaultHasher};

/// The sketch's registers: 2^`P`.
const P: u32 = 14;
/// The networks a count holds exactly, and the registers of its sketch.
pub(crate) const EXACT: usize = 1 << P;

/// The hash a network is counted by: the same for the same network
/// throughout a request.
pub(crate) fn hash(network: &str) -> u64 {
    BuildHasherDefault::<DefaultHasher>::default().hash_one(network)
}

/// The distinct networks of a tally.
#[derive(Debug, Clone)]
pub(crate) enum Distinct {
    Exact(HashSet<u64>),
    Sketch(Box<[u8]>),
}

impl Default for Distinct {
    fn default() -> Self {
        Distinct::Exact(HashSet::new())
    }
}

impl Distinct {
    /// Count the network whose [`hash`] is `h`.
    pub(crate) fn insert(&mut self, h: u64) {
        match self {
            Distinct::Exact(set) => {
                set.insert(h);
                if set.len() > EXACT {
                    let mut registers = vec![0u8; EXACT].into_boxed_slice();
                    for h in set.drain() {
                        sketch(&mut registers, h);
                    }
                    *self = Distinct::Sketch(registers);
                }
            }
            Distinct::Sketch(registers) => sketch(registers, h),
        }
    }

    /// How many networks were counted.
    pub(crate) fn count(&self) -> u64 {
        match self {
            Distinct::Exact(set) => set.len() as u64,
            Distinct::Sketch(registers) => estimate(registers),
        }
    }

    /// Whether [`Self::count`] is an estimate.
    pub(crate) fn is_estimate(&self) -> bool {
        matches!(self, Distinct::Sketch(_))
    }
}

fn sketch(registers: &mut [u8], h: u64) {
    let index = usize::try_from(h >> (64 - P)).unwrap_or(0);
    // The rank of the first one bit of the rest, at most 64 - P + 1.
    let rest = (h << P) | (1 << (P - 1));
    let rank = u8::try_from(rest.leading_zeros() + 1).unwrap_or(u8::MAX);
    if let Some(r) = registers.get_mut(index) {
        *r = (*r).max(rank);
    }
}

/// The HyperLogLog estimate, with linear counting for small counts (the
/// 64-bit hash needs no large-range correction).
fn estimate(registers: &[u8]) -> u64 {
    let m = registers.len() as f64;
    let alpha = 0.7213 / (1.0 + 1.079 / m);
    let sum: f64 = registers.iter().map(|r| 2f64.powi(-i32::from(*r))).sum();
    let raw = alpha * m * m / sum;
    let zeros = registers.iter().filter(|r| **r == 0).count();
    let estimate = if raw <= 2.5 * m && zeros > 0 {
        m * (m / zeros as f64).ln()
    } else {
        raw
    };
    estimate.round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_counts_are_exact() {
        let mut d = Distinct::default();
        for i in 0..EXACT {
            d.insert(hash(&format!("10.0.{}.{}", i / 256, i % 256)));
            d.insert(hash(&format!("10.0.{}.{}", i / 256, i % 256)));
        }
        assert_eq!(d.count(), EXACT as u64);
        assert!(!d.is_estimate());
    }

    #[test]
    fn large_counts_are_close_estimates() {
        for n in [EXACT + 1, 50_000, 300_000] {
            let mut d = Distinct::default();
            for i in 0..n {
                d.insert(hash(&format!("network-{i}")));
                d.insert(hash(&format!("network-{i}")));
            }
            assert!(d.is_estimate());
            let error = (d.count() as f64 - n as f64).abs() / n as f64;
            assert!(error < 0.03, "{n} counted as {}", d.count());
        }
    }
}
