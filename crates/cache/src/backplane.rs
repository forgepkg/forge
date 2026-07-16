//! Redis pub/sub backplane for passive cache-tag invalidation.
//!
//! Invalidating a tag first advances its authoritative Redis generation, then
//! publishes `"{node_id}|t|{namespace}|{generation}|{tag}"`. Receivers acquire
//! the namespace writer fence and advance their local tag barrier. Any L1 entry
//! stamped with an older generation becomes invisible immediately, without an
//! L1/L2 scan.
//!
//! During a rolling upgrade, new publishers also send the former `k`/`n`
//! message understood by old nodes. New subscribers that hear a legacy-only
//! publisher promote that event into a Redis tag bump and republish it, closing
//! the old delete/re-delete race inside mixed-version clusters.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use redis::AsyncCommands;

use crate::l2_redis::RedisL2;
use crate::{key_tag, namespace_tag, NamespaceLocks, TagVersions};

/// The pub/sub channel shared by every cache node.
pub const CHANNEL: &str = "forge:cache:invalidate";

static NODE_SEQ: AtomicU64 = AtomicU64::new(0);

fn fresh_node_id() -> u64 {
    let seq = NODE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    nanos
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(seq.wrapping_add(1))
}

fn tag_message(node_id: u64, ns: &str, tag: &str, generation: u64) -> String {
    format!("{node_id}|t|{ns}|{generation}|{tag}")
}

/// Publishes tag invalidations; the subscriber is a detached task.
pub struct Backplane {
    conn: redis::aio::ConnectionManager,
    node_id: u64,
}

impl Backplane {
    pub async fn start(
        client: redis::Client,
        l2: RedisL2,
        namespace_locks: NamespaceLocks,
        tag_versions: TagVersions,
    ) -> Result<Self, redis::RedisError> {
        let node_id = fresh_node_id();
        let conn = redis::aio::ConnectionManager::new(client.clone()).await?;

        tokio::spawn(subscriber_loop(
            client,
            l2,
            conn.clone(),
            namespace_locks,
            tag_versions,
            node_id,
        ));

        Ok(Backplane { conn, node_id })
    }

    /// Broadcast one tag-generation barrier plus a legacy companion for nodes
    /// that have not yet upgraded to tag-aware envelopes.
    pub async fn publish_tag(&self, ns: &str, tag: &str, generation: u64) {
        let mut conn = self.conn.clone();
        if let Err(err) = conn
            .publish::<_, _, ()>(CHANNEL, tag_message(self.node_id, ns, tag, generation))
            .await
        {
            tracing::warn!(error = %err, ns, tag, generation, "backplane tag publish failed");
        }

        let legacy = if let Some(full_key) = tag.strip_prefix("@key:") {
            format!("{}|k|{}", self.node_id, full_key)
        } else {
            // Custom tags have no old wire equivalent, so old nodes receive the
            // safe coarse namespace invalidation.
            format!("{}|n|{}", self.node_id, ns)
        };
        if let Err(err) = conn.publish::<_, _, ()>(CHANNEL, legacy).await {
            tracing::warn!(error = %err, ns, tag, "legacy backplane companion publish failed");
        }
    }
}

async fn subscriber_loop(
    client: redis::Client,
    l2: RedisL2,
    publisher: redis::aio::ConnectionManager,
    namespace_locks: NamespaceLocks,
    tag_versions: TagVersions,
    node_id: u64,
) {
    let mut pubsub = match client.get_async_pubsub().await {
        Ok(pubsub) => pubsub,
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
    let mut tag_capable_origins = HashSet::new();
    let mut stream = pubsub.on_message();
    while let Some(message) = stream.next().await {
        let payload: String = match message.get_payload() {
            Ok(payload) => payload,
            Err(err) => {
                tracing::warn!(error = %err, "backplane: undecodable message payload");
                continue;
            }
        };
        apply_message(
            &l2,
            &publisher,
            &namespace_locks,
            &tag_versions,
            &mut tag_capable_origins,
            node_id,
            &payload,
        )
        .await;
    }

    tracing::warn!("backplane subscriber stream ended; cross-node invalidation now relies on TTL");
}

#[allow(clippy::too_many_arguments)]
async fn apply_message(
    l2: &RedisL2,
    publisher: &redis::aio::ConnectionManager,
    namespace_locks: &NamespaceLocks,
    tag_versions: &TagVersions,
    tag_capable_origins: &mut HashSet<u64>,
    node_id: u64,
    payload: &str,
) {
    let mut parts = payload.splitn(3, '|');
    let (Some(origin), Some(kind), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        tracing::warn!(payload, "backplane: malformed message");
        return;
    };
    let Ok(origin) = origin.parse::<u64>() else {
        tracing::warn!(payload, "backplane: malformed origin");
        return;
    };
    if origin == node_id {
        return;
    }

    match kind {
        "t" => {
            // `splitn` preserves any `|` characters inside the tag.
            let mut tagged = rest.splitn(3, '|');
            let (Some(ns), Some(generation), Some(tag)) =
                (tagged.next(), tagged.next(), tagged.next())
            else {
                tracing::warn!(payload, "backplane: malformed tag message");
                return;
            };
            let Ok(generation) = generation.parse::<u64>() else {
                tracing::warn!(generation, tag, "backplane: malformed tag generation");
                return;
            };
            tag_capable_origins.insert(origin);
            let namespace_lock = namespace_locks.get(ns);
            let _guard = namespace_lock.write().await;
            tag_versions.observe_one(tag, generation);
        }
        "k" | "n" => {
            if tag_capable_origins.contains(&origin) {
                // Companion from a new publisher; the preceding tag message is
                // already authoritative for this receiver.
                return;
            }
            let (ns, tag) = if kind == "k" {
                let Some((ns, key)) = rest.split_once(':') else {
                    tracing::warn!(full_key = rest, "backplane: malformed legacy cache key");
                    return;
                };
                (ns, key_tag(ns, key))
            } else {
                (rest, namespace_tag(rest))
            };

            let namespace_lock = namespace_locks.get(ns);
            let _guard = namespace_lock.write().await;
            let current = tag_versions.current(&tag);
            let generation = match l2.bump_tag(&tag, current).await {
                Ok(generation) => generation,
                Err(err) => {
                    tracing::warn!(error = %err, ns, tag, "legacy invalidation tag promotion failed");
                    current.saturating_add(1)
                }
            };
            tag_versions.observe_one(&tag, generation);

            let mut publisher = publisher.clone();
            if let Err(err) = publisher
                .publish::<_, _, ()>(CHANNEL, tag_message(node_id, ns, &tag, generation))
                .await
            {
                tracing::warn!(error = %err, ns, tag, "promoted tag publish failed");
            }
        }
        other => tracing::warn!(kind = other, "backplane: unknown message kind"),
    }
}
