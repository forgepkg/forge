//! L2 — the optional shared Redis tier.
//!
//! Stores JSON bytes under the prefix `forge:cache:{ns}:{key}` with a TTL
//! (`SET … EX`). All operations return [`redis::RedisError`]; the caller
//! ([`crate::Cache`]) treats any such error as a *cache* failure and degrades
//! gracefully (read → fall through to factory, write → skip) — Redis is never a
//! source of truth.

use std::sync::Arc;
use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;

/// Key prefix for every cache entry stored in Redis.
const PREFIX: &str = "forge:cache:";

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

    /// Fetch the JSON bytes for `full_key`, or `None` on a miss.
    pub async fn get(&self, full_key: &str) -> Result<Option<Arc<Vec<u8>>>, redis::RedisError> {
        let mut conn = self.conn.clone();
        let bytes: Option<Vec<u8>> = conn.get(Self::redis_key(full_key)).await?;
        Ok(bytes.map(Arc::new))
    }

    /// Store `bytes` for `full_key` with a TTL (`SET … EX ttl_secs`).
    ///
    /// The TTL is rounded **up** to whole seconds (Redis `EX` granularity) and
    /// floored at 1s so a sub-second TTL still persists for at least one second.
    pub async fn set(
        &self,
        full_key: &str,
        bytes: &[u8],
        ttl: Duration,
    ) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        let secs = ttl
            .as_secs()
            .max(if ttl.subsec_nanos() > 0 { 1 } else { 0 })
            .max(1);
        let _: () = conn.set_ex(Self::redis_key(full_key), bytes, secs).await?;
        Ok(())
    }

    /// Delete a single entry.
    pub async fn del(&self, full_key: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        let _: () = conn.del(Self::redis_key(full_key)).await?;
        Ok(())
    }

    /// Delete every entry in a namespace (`forge:cache:{ns}:*`).
    ///
    /// Uses `SCAN` (cursor) + `DEL` rather than `KEYS` so it never blocks the
    /// Redis server on a large keyspace.
    pub async fn del_ns(&self, ns: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        let pattern = format!("{PREFIX}{ns}:*");

        let mut cursor: u64 = 0;
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(256)
                .query_async(&mut conn)
                .await?;

            if !keys.is_empty() {
                let _: () = conn.del(keys).await?;
            }

            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(())
    }
}
