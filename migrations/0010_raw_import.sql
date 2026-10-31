-- ---------------------------------------------------------------------------
-- Imports of raw repositories (#656)
--
-- An import copies a raw repository's files into a hosted raw repository.
-- Raw has no protocol beyond a `GET` of a path, and no standard listing, so
-- the scan walks one of these:
--
-- * `assets`: Nexus' asset listing (`/service/rest/v1/assets`), its cursor
--   Nexus' `continuationToken`;
-- * `directories`: another Forge's JSON listing, a directory at a time, its
--   cursor the directory it is in and the entry it stopped after;
-- * `names`: the paths the import names.
--
-- An item may be a `file`: its `name` the path, its `version` empty.
--
-- The lists below also hold the values of the npm import (#643, migration
-- 0009: `all`, `tag`), so the two migrations apply in either order and leave
-- the same constraints behind.
-- ---------------------------------------------------------------------------
ALTER TABLE repository_import DROP CONSTRAINT repository_import_scan_listing_check;
ALTER TABLE repository_import ADD CONSTRAINT repository_import_scan_listing_check
    CHECK (scan_listing IN ('search', 'catalog', 'all', 'assets', 'directories', 'names'));

ALTER TABLE repository_import_item DROP CONSTRAINT repository_import_item_kind_check;
ALTER TABLE repository_import_item ADD CONSTRAINT repository_import_item_kind_check
    CHECK (kind IN ('component', 'manifest', 'tag', 'file'));
