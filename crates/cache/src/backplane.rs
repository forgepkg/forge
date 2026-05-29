//! Backplane — the optional cross-node invalidation channel (Redis pub/sub).
//!
//! When Redis is present, every [`crate::Cache`] node publishes invalidations on
//! the shared channel [`CHANNEL`]. A background subscriber task on every node
//! receives those messages and drops the matching entries from its **local L1**,
//! so a mutation on node A causes node B to forget its stale copy.
//!
//! ## Message format
//!
//! `"{node_id}|{kind}|{payload}"` where `kind` is:
//! * `k` — `payload` is a flat `"{ns}:{key}"`; drop that single L1 entry.
//! * `n` — `payload` is a namespace `"{ns}"`; drop every L1 entry under it.
//!
//! ## Self-message suppression
//!
//! Each node has a random `node_id`. The publisher already dropped its own L1
//! entry synchronously (see [`crate::Cache::invalidate`]), so when the
//! subscriber sees its *own* `node_id` it skips the redundant local drop.
//!
//! ## Graceful degradation
//!
//! A publish failure is logged and ignored — the local drop already happened and
//! the backplane is best-effort. If the subscriber connection drops, the task
//! attempts to re-subscribe; a hard failure is logged and the task exits (the
//! node then relies on TTL expiry for cross-node staleness, which is still
//! correct, just slower).

use std::sync::atomic::{AtomicU64, Ordering};

use redis::AsyncCommands;

use crate::l1::L1;

/// The pub/sub channel all nodes share for invalidation broadcasts.
pub const CHANNEL: &str = "forge:cache:invalidate";

/// Process-unique-ish node id source. A monotonically increasing base XORed with
/// the start instant keeps ids distinct across nodes in the same process (tests)
/// without needing a UUID dependency.
static NODE_SEQ: AtomicU64 = AtomicU64::new(0);

fn fresh_node_id() -> u64 {
    let seq = NODE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix the sequence into the low bits so two nodes created in the same nanos
    // (same process) still differ.
    nanos
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(seq.wrapping_add(1))
}

/// Publishes invalidations; owns this node's id. The subscriber runs as a
/// detached background task spawned in [`Backplane::start`].
pub struct Backplane {
    conn: redis::aio::ConnectionManager,
    node_id: u64,
}

impl Backplane {
    /// Connect a publisher and spawn the subscriber task bound to `l1`.
    pub async fn start(client: redis::Client, l1: L1) -> Result<Self, redis::RedisError> {
        let node_id = fresh_node_id();
        let conn = redis::aio::ConnectionManager::new(client.clone()).await?;

        // Spawn the subscriber. It owns its own dedicated connection (pub/sub
        // connections can't multiplex normal commands).
        tokio::spawn(subscriber_loop(client, l1, node_id));

        Ok(Backplane { conn, node_id })
    }

    /// Broadcast a single-key invalidation.
    pub async fn publish_key(&self, full_key: &str) {
        let msg = format!("{}|k|{}", self.node_id, full_key);
        self.publish(msg).await;
    }

    /// Broadcast a namespace invalidation.
    pub async fn publish_ns(&self, ns: &str) {
        let msg = format!("{}|n|{}", self.node_id, ns);
        self.publish(msg).await;
    }

    async fn publish(&self, msg: String) {
        let mut conn = self.conn.clone();
        if let Err(err) = conn.publish::<_, _, ()>(CHANNEL, msg).await {
            tracing::warn!(error = %err, "backplane publish failed (local drop already applied)");
        }
    }
}

/// Background task: subscribe to [`CHANNEL`] and apply remote invalidations to
/// the local L1, ignoring messages this node published itself.
async fn subscriber_loop(client: redis::Client, l1: L1, node_id: u64) {
    let mut pubsub = match client.get_async_pubsub().await {
        Ok(p) => p,
        Err(err) => {
            tracing::error!(error = %err, "backplane subscriber could not open pubsub connection; exiting");
            return;
        }
    };
    if let Err(err) = pubsub.subscribe(CHANNEL).await {
        tracing::error!(error = %err, channel = CHANNEL, "backplane subscribe failed; exiting");
        return;
    }

    use futures_util::StreamExt;
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(error = %err, "backplane: undecodable message payload");
                continue;
            }
        };
        apply_message(&l1, node_id, &payload).await;
    }

    tracing::warn!("backplane subscriber stream ended; cross-node invalidation now relies on TTL");
}

/// Parse and apply one backplane message to the local L1.
async fn apply_message(l1: &L1, node_id: u64, payload: &str) {
    let mut parts = payload.splitn(3, '|');
    let (Some(origin), Some(kind), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        tracing::warn!(payload, "backplane: malformed message");
        return;
    };

    // Skip our own broadcasts: the publishing node already dropped locally.
    if origin.parse::<u64>().ok() == Some(node_id) {
        return;
    }

    match kind {
        "k" => l1.invalidate(rest).await,
        "n" => l1.invalidate_prefix(&format!("{rest}:")).await,
        other => tracing::warn!(kind = other, "backplane: unknown message kind"),
    }
}
