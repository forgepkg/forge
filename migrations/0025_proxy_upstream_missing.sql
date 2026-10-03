-- ---------------------------------------------------------------------------
-- 0025: complete the proxy "not found" marker fix (review H3 follow-up)
-- ---------------------------------------------------------------------------
--
-- * A version that disappears from a fresh upstream listing (deleted
--   upstream, e.g. a malicious release removed from nuget.org) is flagged
--   `upstream_missing` and no longer enumerated; it is cleared when a listing
--   names the version again. Before, the row stayed listed and a 404 hid it
--   only for `not_found_ttl`, so it reappeared every TTL.
-- * The package-level negative-cache marker (`version = '*'`) is an
--   unconfirmed row: it is pruned with the other unconfirmed rows once its TTL
--   lapsed (before, every request for a random id left a permanent row), and a
--   listing or download of the package removes it.
ALTER TABLE proxy_cached_version
    ADD COLUMN upstream_missing boolean NOT NULL DEFAULT false;

UPDATE proxy_cached_version
SET confirmed = false
WHERE version = '*' AND NOT downloaded;
