-- ---------------------------------------------------------------------------
-- Imports of npm registries (#643)
--
-- An import copies an npm registry's packages into a hosted npm repository.
-- npm's protocol has no listing of every package: an import walks the
-- registry's search (`/-/v1/search`), or, where that lists nothing, its
-- legacy listing (`/-/all`), or the names and scopes it gives.
--
-- * `scan_listing` takes `all`: the scan walks `/-/all`, its cursor the last
--   package name it recorded.
-- * An item may be a `tag`: an npm dist-tag (`latest`, `next`), its `name`
--   the package and its `version` the tag. It is set once the versions are
--   copied, after them.
-- ---------------------------------------------------------------------------
ALTER TABLE repository_import DROP CONSTRAINT repository_import_scan_listing_check;
ALTER TABLE repository_import ADD CONSTRAINT repository_import_scan_listing_check
    CHECK (scan_listing IN ('search', 'catalog', 'all', 'names'));

ALTER TABLE repository_import_item DROP CONSTRAINT repository_import_item_kind_check;
ALTER TABLE repository_import_item ADD CONSTRAINT repository_import_item_kind_check
    CHECK (kind IN ('component', 'manifest', 'tag'));
