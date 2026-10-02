//! Redis pub/sub backplane for passive cache-tag invalidation.
//!
//! Invalidating a tag first advances its authoritative Redis generation, then
//! publishes `"{node_id}|t|{namespace}|{generation}|{tag}"`. Receivers advance
//! their local tag barrier. Any L1 entry stamped with an older generation
//! becomes invisible immediately, without an L1/L2 scan.
//!
//! Applying a barrier takes **no namespace lock**: barriers are monotonic
//! (`observe_one` is a max-merge), stale L1 entries are rejected on read, and
//! every fill re-checks its stamps after completion — so the subscriber never
//! parks behind a slow in-flight fill holding the namespace read guard, which
//! would stall invalidation delivery for every namespace queued behind it.
//!
//! During a rolling upgrade, new publishers also send the former `k`/`n`
//! message understood by old nodes. New subscribers that hear a legacy-only
//! publisher promote that event into a Redis tag bump and republish it, closing
//! the old delete/re-delete race inside mixed-version clusters. The companion
//! `k`/`n` sent by an already tag-capable publisher doubles as a recovery
//! channel: receivers re-sync that tag's generation from Redis, so an
//! invalidation whose tag publish was lost is not silently dropped.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use redis::AsyncCommands;

use crate::l1::L1;
use crate::l2_redis::RedisL2;
use crate::{key_tag, namespace_tag, RedisTimeouts, TagVersions};

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
    /// Connect the publisher and spawn the subscriber supervisor, then wait —
    /// bounded by [`initial_subscribe_wait`] — until the first subscription is
    /// live, so a cache handed to callers already hears peer invalidations.
    /// If the wait times out (Redis slow at boot), construction still succeeds:
    /// the supervisor keeps retrying and flushes L1 once it subscribes, which
    /// drops anything filled while invalidations could not be heard.
    pub async fn start(
        client: redis::Client,
        l2: RedisL2,
        l1: L1,
        tag_versions: TagVersions,
        timeouts: RedisTimeouts,
    ) -> Result<Self, redis::RedisError> {
        let node_id = fresh_node_id();
        let conn = redis::aio::ConnectionManager::new_with_config(
            client.clone(),
            timeouts.manager_config(),
        )
        .await?;

        let (subscribed_tx, subscribed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(subscriber_supervisor(
            client,
            l2,
            l1,
            conn.clone(),
            tag_versions,
            node_id,
            timeouts,
            subscribed_tx,
        ));
        let wait = initial_subscribe_wait(timeouts);
        if tokio::time::timeout(wait, subscribed_rx).await.is_err() {
            tracing::warn!(
                waited = ?wait,
                "backplane subscription not live yet; continuing (L1 is flushed once it is)"
            );
        }

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

/// How long [`Backplane::start`] waits for the first subscription: one full
/// [`subscribe`] attempt (connect + `SUBSCRIBE`, each bounded by the connect
/// plus response deadline) and a retry.
fn initial_subscribe_wait(timeouts: RedisTimeouts) -> std::time::Duration {
    (timeouts.connect + timeouts.response) * 2 + std::time::Duration::from_millis(250)
}

/// Keep the subscriber alive for the life of the process. Whenever a
/// subscription becomes live — the **first** one included — the local L1 is
/// flushed: until that moment peers' invalidations could not be heard, so any
/// entry filled before it may already be stale (with a slow Redis at boot that
/// window can be long). When the subscription drops (Redis restart, network
/// partition) it is re-established with capped exponential backoff and L1 is
/// flushed again, so no stale entry outlives the outage. `subscribed` is
/// signalled after the first subscription is live and L1 flushed.
#[allow(clippy::too_many_arguments)]
async fn subscriber_supervisor(
    client: redis::Client,
    l2: RedisL2,
    l1: L1,
    publisher: redis::aio::ConnectionManager,
    tag_versions: TagVersions,
    node_id: u64,
    timeouts: RedisTimeouts,
    subscribed: tokio::sync::oneshot::Sender<()>,
) {
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);
    let mut backoff = std::time::Duration::from_millis(250);
    let mut subscribed = Some(subscribed);
    loop {
        match subscribe(&client, timeouts).await {
            Ok(pubsub) => {
                l1.invalidate_all();
                match subscribed.take() {
                    // Nobody may have filled L1 yet (construction is still
                    // waiting) — unless that wait timed out; flushed either way.
                    Some(tx) => {
                        let _ = tx.send(());
                        tracing::debug!("backplane subscribed; flushed L1");
                    }
                    None => tracing::info!(
                        "backplane resubscribed; flushed L1 to drop entries whose invalidations were missed"
                    ),
                }
                backoff = std::time::Duration::from_millis(250);
                subscriber_loop(pubsub, &l2, &publisher, &tag_versions, node_id).await;
                // The stream ended: from here until resubscribed, peers'
                // invalidations are not seen — flush eagerly too.
                l1.invalidate_all();
                tracing::warn!("backplane subscriber stream ended; reconnecting");
            }
            Err(err) => {
                tracing::warn!(error = %err, retry_in = ?backoff, "backplane subscribe failed; retrying");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn subscribe(
    client: &redis::Client,
    timeouts: RedisTimeouts,
) -> Result<redis::aio::PubSub, redis::RedisError> {
    let timed_out = || {
        redis::RedisError::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "backplane subscribe timed out",
        ))
    };
    let deadline = timeouts.connect + timeouts.response;
    let mut pubsub = tokio::time::timeout(deadline, client.get_async_pubsub())
        .await
        .map_err(|_| timed_out())??;
    tokio::time::timeout(deadline, pubsub.subscribe(CHANNEL))
        .await
        .map_err(|_| timed_out())??;
    Ok(pubsub)
}

async fn subscriber_loop(
    mut pubsub: redis::aio::PubSub,
    l2: &RedisL2,
    publisher: &redis::aio::ConnectionManager,
    tag_versions: &TagVersions,
    node_id: u64,
) {
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
            l2,
            publisher,
            tag_versions,
            &mut tag_capable_origins,
            node_id,
            &payload,
        )
        .await;
    }
}

async fn apply_message(
    l2: &RedisL2,
    publisher: &redis::aio::ConnectionManager,
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
            let (Some(_ns), Some(generation), Some(tag)) =
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
            // No namespace fence here (see module docs): barriers are
            // monotonic and every read/fill path re-validates against them.
            tag_versions.observe_one(tag, generation);
        }
        "k" | "n" => {
            let (ns, tag) = if kind == "k" {
                let Some((ns, key)) = rest.split_once(':') else {
                    tracing::warn!(full_key = rest, "backplane: malformed legacy cache key");
                    return;
                };
                (ns, key_tag(ns, key))
            } else {
                (rest, namespace_tag(rest))
            };

            if tag_capable_origins.contains(&origin) {
                // Companion of a tag-capable publisher. Usually the preceding
                // tag message already advanced our barrier — but when that
                // publish failed while the Redis bump succeeded, re-syncing the
                // generation from Redis recovers the invalidation instead of
                // silently dropping it (observe is a max-merge, so a plain
                // duplicate is a no-op).
                match l2.tag_versions(std::slice::from_ref(&tag)).await {
                    Ok(stamps) => tag_versions.observe(&stamps),
                    Err(err) => {
                        tracing::warn!(error = %err, ns, tag, "companion tag re-sync failed")
                    }
                }
                return;
            }

            // Legacy-only publisher: promote the event into a tag bump. The
            // conditional bump means one receiver bumps and republishes while
            // the rest adopt its generation, instead of every node in the
            // cluster bumping once per legacy event.
            let current = tag_versions.current(&tag);
            let generation = match l2.promote_tag(&tag, current).await {
                Ok((generation, bumped)) => {
                    if bumped {
                        let mut publisher = publisher.clone();
                        if let Err(err) = publisher
                            .publish::<_, _, ()>(
                                CHANNEL,
                                tag_message(node_id, ns, &tag, generation),
                            )
                            .await
                        {
                            tracing::warn!(error = %err, ns, tag, "promoted tag publish failed");
                        }
                    }
                    generation
                }
                Err(err) => {
                    tracing::warn!(error = %err, ns, tag, "legacy invalidation tag promotion failed");
                    current.saturating_add(1)
                }
            };
            tag_versions.observe_one(&tag, generation);
        }
        other => tracing::warn!(kind = other, "backplane: unknown message kind"),
    }
}
