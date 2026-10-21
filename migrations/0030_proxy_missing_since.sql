-- ---------------------------------------------------------------------------
-- 0030: retire a version only once it is missing from two listings
-- ---------------------------------------------------------------------------
--
-- An upstream can serve a partial listing during an incident (a Forge group
-- with one member down answers with the other members' versions). Flagging
-- every version such a listing leaves out as `upstream_missing` hid them
-- for a whole metadata TTL, even after the upstream recovered. A version is
-- now retired only when it is still missing from a listing at least one
-- metadata TTL after the first listing that left it out: `missing_since`
-- records that first listing, and a listing that names the version clears
-- it.
ALTER TABLE proxy_cached_version
    ADD COLUMN missing_since timestamptz NULL;
