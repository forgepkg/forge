//! The clients with the most requests, counted in bounded memory.
//!
//! [`TopClients`] keeps at most twice its capacity of networks; when full,
//! it drops the half with the fewest requests. Whatever the number of
//! addresses a flood comes from, the memory stays bounded, and a network
//! with many requests stays in: it is dropped only while it has fewer
//! requests than half the networks kept. A network dropped and seen again
//! starts counting from zero, so a count can only be low, never high.

use std::collections::HashMap;

/// A client network's counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientCounts {
    pub requests: u64,
    pub bytes: u64,
    /// 4xx answers (the next three included).
    pub client_errors: u64,
    /// 401 and 403 answers.
    pub denied: u64,
    pub not_found: u64,
    /// 429 answers.
    pub throttled: u64,
    /// 5xx answers.
    pub server_errors: u64,
    /// The last address of the network seen.
    pub address: String,
    /// The last user agent seen; `""` for none.
    pub user_agent: String,
    /// The last account kind seen; `""` for none.
    pub account: String,
    /// The last account's user.
    pub user_id: Option<i64>,
}

impl ClientCounts {
    /// Count one request answered with `status`.
    pub fn observe(&mut self, status: u16, bytes: u64) {
        self.requests += 1;
        self.bytes += bytes;
        match status {
            401 | 403 => self.denied += 1,
            404 => self.not_found += 1,
            429 => self.throttled += 1,
            _ => {}
        }
        match status {
            400..=499 => self.client_errors += 1,
            500..=599 => self.server_errors += 1,
            _ => {}
        }
    }

    /// Add `other`'s counts; its last-seen values win where it has them.
    pub fn add(&mut self, other: &ClientCounts) {
        self.requests += other.requests;
        self.bytes += other.bytes;
        self.client_errors += other.client_errors;
        self.denied += other.denied;
        self.not_found += other.not_found;
        self.throttled += other.throttled;
        self.server_errors += other.server_errors;
        if !other.address.is_empty() {
            self.address.clone_from(&other.address);
        }
        if !other.user_agent.is_empty() {
            self.user_agent.clone_from(&other.user_agent);
        }
        if !other.account.is_empty() {
            self.account.clone_from(&other.account);
            self.user_id = other.user_id;
        }
    }
}

/// The networks with the most requests, about `capacity` of them.
#[derive(Debug, Clone)]
pub struct TopClients {
    capacity: usize,
    counts: HashMap<String, ClientCounts>,
}

impl TopClients {
    /// Keep about `capacity` networks (at least one).
    pub fn new(capacity: usize) -> TopClients {
        TopClients {
            capacity: capacity.max(1),
            counts: HashMap::new(),
        }
    }

    /// The counts of `network`, added when new.
    pub fn entry(&mut self, network: &str) -> &mut ClientCounts {
        if !self.counts.contains_key(network) {
            if self.counts.len() >= self.capacity * 2 {
                self.shrink();
            }
            self.counts
                .insert(network.to_string(), ClientCounts::default());
        }
        self.counts.get_mut(network).expect("just inserted")
    }

    /// Add all of `other`'s networks.
    pub fn merge(&mut self, other: &TopClients) {
        for (network, counts) in &other.counts {
            self.entry(network).add(counts);
        }
    }

    /// Whether no network was counted.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// The `n` networks with the most requests, most first (ties by
    /// network, for a stable order).
    pub fn top(&self, n: usize) -> Vec<(&str, &ClientCounts)> {
        let mut all: Vec<_> = self
            .counts
            .iter()
            .map(|(network, counts)| (network.as_str(), counts))
            .collect();
        all.sort_by(|a, b| b.1.requests.cmp(&a.1.requests).then(a.0.cmp(b.0)));
        all.truncate(n);
        all
    }

    /// Keep only the `n` networks with the most requests.
    pub fn truncate(&mut self, n: usize) {
        if self.counts.len() > n {
            let keep: Vec<String> = self
                .top(n)
                .into_iter()
                .map(|(k, _)| k.to_string())
                .collect();
            let mut kept = HashMap::with_capacity(keep.len());
            for network in keep {
                if let Some(counts) = self.counts.remove(&network) {
                    kept.insert(network, counts);
                }
            }
            self.counts = kept;
        }
    }

    fn shrink(&mut self) {
        self.truncate(self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heavy_clients_survive_a_flood_of_light_ones() {
        let mut top = TopClients::new(8);
        for round in 0..1_000 {
            for heavy in ["192.0.2.1", "192.0.2.2"] {
                top.entry(heavy).observe(200, 10);
            }
            top.entry(&format!("10.0.{}.{}", round / 250, round % 250))
                .observe(404, 1);
        }
        let best = top.top(2);
        assert_eq!(best[0], ("192.0.2.1", &best[0].1.clone()));
        assert_eq!(best[0].1.requests, 1_000);
        assert_eq!(best[1].0, "192.0.2.2");
        assert!(top.counts.len() <= 16, "bounded: {}", top.counts.len());
    }

    #[test]
    fn status_classes_are_counted() {
        let mut c = ClientCounts::default();
        for status in [200, 401, 403, 404, 429, 500, 503, 302] {
            c.observe(status, 0);
        }
        assert_eq!(
            (
                c.client_errors,
                c.denied,
                c.not_found,
                c.throttled,
                c.server_errors
            ),
            (4, 2, 1, 1, 2)
        );
    }
}
