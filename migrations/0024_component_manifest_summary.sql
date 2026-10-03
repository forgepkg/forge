-- ---------------------------------------------------------------------------
-- 0024: store each version's manifest summary (security review, DoS)
-- ---------------------------------------------------------------------------
--
-- Registration pages and search results used to fetch every version's
-- `.nuspec` from object storage and parse it on every request. The format's
-- summary of the manifest (display metadata + dependency groups) is now
-- computed once at publish and stored here. Older versions (NULL) are
-- summarized on first read and backfilled.
ALTER TABLE component ADD COLUMN manifest_summary jsonb;
