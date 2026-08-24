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

/// TTL applied to every tag generation key so invalidated tags do not
/// accumulate in Redis forever (one key per ever-invalidated tag, including the
/// synthetic per-key `@key:` tags).
///
/// Safety invariant: a tag key must outlive every stored value stamped with one
/// of its **older** generations — if the key expired first, its generation
/// would read as `0` again and a previously invalidated value could pass the
/// generation comparison and be resurrected. Two rules uphold this:
///
/// 1. value TTLs are capped at this constant ([`RedisL2::set_if_tag_versions`]),
///    and every bump refreshes the tag key to the full window, so a tag bumped
///    at time T outlives any value written before T;
/// 2. a value written *after* the bump extends each existing tag key at least
///    to its own TTL inside the same conditional-write script.
///
/// A tag key can still expire while a *matching* (non-invalidated) value lives;
/// that direction is safe — the value merely reads as stale and is refilled.
const TAG_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

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
    /// failure where pub/sub advanced local barriers first. Every bump
    /// refreshes the key's [`TAG_TTL`] window.
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
            redis.call('SET', KEYS[1], next, 'EX', ARGV[2])
            return next
            "#,
        );
        let mut conn = self.conn.clone();
        script
            .key(Self::redis_tag_key(tag))
            .arg(local_generation)
            .arg(TAG_TTL.as_secs())
            .invoke_async(&mut conn)
            .await
    }

    /// Raise `tag` to at least `minimum` **without** bumping past it. Heals a
    /// Redis that fell behind locally observed generations (a bump that failed
    /// after pub/sub already advanced peer barriers): once Redis has caught up,
    /// conditional L2 writes for the tag succeed again cluster-wide instead of
    /// being rejected forever. Returns the resulting generation.
    pub async fn raise_tag(&self, tag: &str, minimum: u64) -> Result<u64, redis::RedisError> {
        let script = redis::Script::new(
            r#"
            local current = tonumber(redis.call('GET', KEYS[1]) or '0')
            local minimum = tonumber(ARGV[1])
            if current >= minimum then
                return current
            end
            redis.call('SET', KEYS[1], minimum, 'EX', ARGV[2])
            return minimum
            "#,
        );
        let mut conn = self.conn.clone();
        script
            .key(Self::redis_tag_key(tag))
            .arg(minimum)
            .arg(TAG_TTL.as_secs())
            .invoke_async(&mut conn)
            .await
    }

    /// Promote a legacy (generation-less) invalidation into a tag bump, but
    /// only when Redis has not already advanced past the caller's local
    /// barrier: the first receiver of a legacy backplane message raises Redis
    /// above every peer's barrier, so the remaining receivers adopt its
    /// generation instead of bumping again (one bump per legacy event when
    /// delivery is staggered, instead of one per node). Returns the resulting
    /// generation and whether this caller performed the bump.
    pub async fn promote_tag(
        &self,
        tag: &str,
        local_generation: u64,
    ) -> Result<(u64, bool), redis::RedisError> {
        let script = redis::Script::new(
            r#"
            local current = tonumber(redis.call('GET', KEYS[1]) or '0')
            local barrier = tonumber(ARGV[1])
            if current > barrier then
                return {current, 0}
            end
            local next = math.max(current, barrier) + 1
            redis.call('SET', KEYS[1], next, 'EX', ARGV[2])
            return {next, 1}
            "#,
        );
        let mut conn = self.conn.clone();
        let (generation, bumped): (u64, i32) = script
            .key(Self::redis_tag_key(tag))
            .arg(local_generation)
            .arg(TAG_TTL.as_secs())
            .invoke_async(&mut conn)
            .await?;
        Ok((generation, bumped == 1))
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
        // Cap value lifetimes at TAG_TTL: a value must never outlive the tag
        // keys whose generations it was stamped with (see TAG_TTL).
        let secs = ttl
            .as_secs()
            .max(if ttl.subsec_nanos() > 0 { 1 } else { 0 })
            .max(1)
            .min(TAG_TTL.as_secs());
        // After the generation comparison passes, extend each *existing* tag
        // key so it outlives this value (TTL -1 marks a pre-TTL key from an
        // older deployment: start its clock at the full window; -2 means the
        // key is absent, i.e. generation 0 — nothing to extend). ARGV layout:
        // [1]=bytes, [2]=value TTL, [3..#KEYS+1]=expected generations,
        // [#KEYS+2]=tag TTL.
        let script = redis::Script::new(
            r#"
            for i = 2, #KEYS do
                local current = tonumber(redis.call('GET', KEYS[i]) or '0')
                local expected = tonumber(ARGV[i + 1])
                if current ~= expected then
                    return 0
                end
            end
            local value_ttl = tonumber(ARGV[2])
            local tag_ttl = tonumber(ARGV[#KEYS + 2])
            for i = 2, #KEYS do
                local remaining = redis.call('TTL', KEYS[i])
                if remaining == -1 then
                    redis.call('EXPIRE', KEYS[i], tag_ttl)
                elseif remaining >= 0 and remaining < value_ttl then
                    redis.call('EXPIRE', KEYS[i], value_ttl)
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
        invocation.arg(TAG_TTL.as_secs());
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
