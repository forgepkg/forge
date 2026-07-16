//! L2 — the optional shared Redis tier.
//!
//! Stores tagged JSON envelopes under `forge:cache:{ns}:{key}` with a TTL.
//! Conditional writes compare tag generations in Lua before `SET … EX`. All
//! operations return [`redis::RedisError`]; the caller
//! ([`crate::Cache`]) treats any such error as a *cache* failure and degrades
//! gracefully (read → fall through to factory, write → skip) — Redis is never a
//! source of truth.

use std::sync::Arc;
use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;

use crate::TagStamp;

/// Key prefix for every cache entry stored in Redis.
const PREFIX: &str = "forge:cache:";
const TAG_PREFIX: &str = "forge:cache:tag:";

/// The Redis L2 tier. Cheaply [`Clone`]able — [`ConnectionManager`] is an
/// `Arc`-backed multiplexed, auto-reconnecting connection.
#[derive(Clone)]
pub struct RedisL2 {
    conn: ConnectionManager,
}

impl RedisL2 {
    /// Establish the connection manager from an already-opened client.
    pub async fn connect(client: redis::Client) -> Result<Self, redis::RedisError> {
        let conn = ConnectionManager::new(client).await?;
        Ok(RedisL2 { conn })
    }

    /// Full Redis key for a flat `"{ns}:{key}"` cache key.
    fn redis_key(full_key: &str) -> String {
        format!("{PREFIX}{full_key}")
    }

    fn redis_tag_key(tag: &str) -> String {
        format!("{TAG_PREFIX}{tag}")
    }

    /// Fetch the JSON bytes for `full_key`, or `None` on a miss.
    pub async fn get(&self, full_key: &str) -> Result<Option<Arc<Vec<u8>>>, redis::RedisError> {
        let mut conn = self.conn.clone();
        let bytes: Option<Vec<u8>> = conn.get(Self::redis_key(full_key)).await?;
        Ok(bytes.map(Arc::new))
    }

    /// Read the authoritative generation for every tag (`0` when absent).
    pub async fn tag_versions(&self, tags: &[String]) -> Result<Vec<TagStamp>, redis::RedisError> {
        let mut conn = self.conn.clone();
        let keys: Vec<String> = tags.iter().map(|tag| Self::redis_tag_key(tag)).collect();
        let generations: Vec<Option<u64>> =
            redis::cmd("MGET").arg(&keys).query_async(&mut conn).await?;
        Ok(tags
            .iter()
            .zip(generations)
            .map(|(tag, generation)| TagStamp {
                tag: tag.clone(),
                generation: generation.unwrap_or(0),
            })
            .collect())
    }

    /// Atomically advance `tag` beyond both Redis and the caller's locally
    /// observed generation. The latter lets Redis catch up after a transient
    /// failure where pub/sub advanced local barriers first.
    pub async fn bump_tag(
        &self,
        tag: &str,
        local_generation: u64,
    ) -> Result<u64, redis::RedisError> {
        let script = redis::Script::new(
            r#"
            local current = tonumber(redis.call('GET', KEYS[1]) or '0')
            local minimum = tonumber(ARGV[1])
            local next = math.max(current, minimum) + 1
            redis.call('SET', KEYS[1], next)
            return next
            "#,
        );
        let mut conn = self.conn.clone();
        script
            .key(Self::redis_tag_key(tag))
            .arg(local_generation)
            .invoke_async(&mut conn)
            .await
    }

    /// Store a tagged envelope only if every Redis tag generation still equals
    /// the generation captured before the factory ran. This is the distributed
    /// fencing token that prevents stale fills from repopulating shared L2.
    pub async fn set_if_tag_versions(
        &self,
        full_key: &str,
        bytes: &[u8],
        ttl: Duration,
        stamps: &[TagStamp],
    ) -> Result<bool, redis::RedisError> {
        let secs = ttl
            .as_secs()
            .max(if ttl.subsec_nanos() > 0 { 1 } else { 0 })
            .max(1);
        let script = redis::Script::new(
            r#"
            for i = 2, #KEYS do
                local current = tonumber(redis.call('GET', KEYS[i]) or '0')
                local expected = tonumber(ARGV[i + 1])
                if current ~= expected then
                    return 0
                end
            end
            redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
            return 1
            "#,
        );
        let mut invocation = script.prepare_invoke();
        invocation.key(Self::redis_key(full_key));
        for stamp in stamps {
            invocation.key(Self::redis_tag_key(&stamp.tag));
        }
        invocation.arg(bytes).arg(secs);
        for stamp in stamps {
            invocation.arg(stamp.generation);
        }
        let mut conn = self.conn.clone();
        let written: i32 = invocation.invoke_async(&mut conn).await?;
        Ok(written == 1)
    }

    /// Delete a single entry.
    pub async fn del(&self, full_key: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        let _: () = conn.del(Self::redis_key(full_key)).await?;
        Ok(())
    }
}
