-- ---------------------------------------------------------------------------
-- 0031: the upstream casing of a proxied package id
-- ---------------------------------------------------------------------------
--
-- `proxy_cached_version.name` is the lowercased id. Proxy search answered
-- with it, so IDEs listed and inserted `newtonsoft.json`. A downloaded
-- version knows its id from the manifest (`component.original_id`); for the
-- others, the casing the upstream registration names is recorded here.
ALTER TABLE proxy_cached_version
    ADD COLUMN original_id text NULL;
