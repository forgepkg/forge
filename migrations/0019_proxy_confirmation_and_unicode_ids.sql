-- ---------------------------------------------------------------------------
-- 0019: proxy listing confirmation (review H3) + Unicode id lowering (L8)
-- ---------------------------------------------------------------------------

-- A proxy_cached_version row is enumerated (flat index, registration, search)
-- only once the upstream has confirmed the version exists: an upstream version
-- listing contained it, or it was downloaded. The download singleflight creates
-- a row for whatever version a client asks for; such a row starts unconfirmed,
-- so a request for a version that does not exist (yet), or one whose fetch
-- failed with a 5xx / timeout, never shows up as a phantom version. The first
-- confirmation also restarts `first_seen_at`, so a row planted early by a
-- request cannot shorten the package-delay window of a later release.
ALTER TABLE proxy_cached_version
    ADD COLUMN confirmed boolean NOT NULL DEFAULT true;

-- Backfill: rows recorded from an upstream listing carry
-- metadata_refreshed_at, downloaded rows were confirmed by the download;
-- anything else was created by a download attempt that never succeeded. (A
-- version the upstream does list is re-confirmed on the next listing refresh.)
UPDATE proxy_cached_version
SET confirmed = false
WHERE NOT downloaded AND metadata_refreshed_at IS NULL;

-- Package ids are now lowercased with full Unicode lowering (NuGet's
-- ToLowerInvariant), no longer ASCII-only, so `Ünicode.Lib` is stored and
-- looked up as `ünicode.lib`. Re-lower existing names that still carry
-- non-ASCII capitals. A name whose lowered form already exists for the same
-- version (a second case-variant) is left untouched rather than failing the
-- migration. With a "C" database ctype, lower() is ASCII-only and this is a
-- no-op.
WITH ranked AS (
    SELECT id, lower(name) AS lowered,
           row_number() OVER (PARTITION BY repository_id, lower(name), version ORDER BY id) AS rn
    FROM component
    WHERE name <> lower(name)
)
UPDATE component c
SET name = r.lowered
FROM ranked r
WHERE c.id = r.id
  AND r.rn = 1
  AND NOT EXISTS (
      SELECT 1 FROM component o
      WHERE o.repository_id = c.repository_id AND o.name = r.lowered AND o.version = c.version
  );

WITH ranked AS (
    SELECT id, lower(name) AS lowered,
           row_number() OVER (PARTITION BY repository_id, lower(name), version ORDER BY id) AS rn
    FROM proxy_cached_version
    WHERE name <> lower(name)
)
UPDATE proxy_cached_version p
SET name = r.lowered
FROM ranked r
WHERE p.id = r.id
  AND r.rn = 1
  AND NOT EXISTS (
      SELECT 1 FROM proxy_cached_version o
      WHERE o.repository_id = p.repository_id AND o.name = r.lowered AND o.version = p.version
  );
