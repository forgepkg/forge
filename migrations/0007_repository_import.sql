-- ---------------------------------------------------------------------------
-- Imports read the format's own protocol, and are named neutrally (#642)
--
-- An import found what to copy through Nexus 3's REST API, so it could only
-- import from a Nexus. It now reads its source through the format's own
-- protocol: a NuGet v3 feed (its service index, search and package base
-- address) or a registry API (its catalog, tag lists and referrers), served
-- by Nexus, Artifactory, ProGet, BaGet, Harbor, a `distribution` registry or
-- another Forge alike. The tables, their constraints and the server's
-- version column drop the Nexus name:
--
-- * `nexus_import` is `repository_import`, `nexus_import_item`
--   `repository_import_item`.
-- * `base_url` is `url`: the source, a service index (`…/index.json`) or a
--   registry. An import stored before keeps the Nexus server there, with
--   `source_repository` (and, for Docker, `registry_url`) naming where in it;
--   the worker reads such an import from the same Nexus through its protocol
--   (`<url>/repository/<name>/index.json`, or the registry), so the password
--   it holds, bound to those origins, still opens. A new import leaves both
--   NULL.
-- * `nexus_version` is `source_server`: the `Server` header the source
--   answered with.
-- * `names`: the package ids or images an import names, when it copies those
--   instead of every package the source's search (or images its catalog)
--   finds.
-- * `source_total`: how many packages a feed's search finds: what it reported
--   in the preflight, or as many as the scan walked, whichever is more (Nexus
--   reports the hits of the page it answers, not of the search).
-- * `assets_seen` and `bytes_seen` go: the protocols list no assets.
-- * `scan_listing` says what the scan walks: `search` (NuGet), `catalog`
--   (Docker) or `names`. An import stored before that was still scanning
--   starts its scan again: its cursor was a Nexus `continuationToken`. Its
--   items stay, and those it copied already are not copied again.
-- ---------------------------------------------------------------------------
ALTER TABLE nexus_import RENAME TO repository_import;
ALTER TABLE nexus_import_item RENAME TO repository_import_item;

DO $$
DECLARE c record;
BEGIN
    FOR c IN
        SELECT conrelid::regclass AS tbl, conname
        FROM pg_constraint
        WHERE conrelid IN ('repository_import'::regclass, 'repository_import_item'::regclass)
          AND conname LIKE 'nexus\_import%'
    LOOP
        EXECUTE format('ALTER TABLE %s RENAME CONSTRAINT %I TO %I', c.tbl, c.conname,
                       'repository_import' || substr(c.conname, length('nexus_import') + 1));
    END LOOP;
END $$;
ALTER INDEX nexus_import_active_idx RENAME TO repository_import_active_idx;
ALTER INDEX nexus_import_repository_idx RENAME TO repository_import_repository_idx;
ALTER INDEX nexus_import_item_state_idx RENAME TO repository_import_item_state_idx;
ALTER SEQUENCE nexus_import_id_seq RENAME TO repository_import_id_seq;
ALTER SEQUENCE nexus_import_item_id_seq RENAME TO repository_import_item_id_seq;

ALTER TABLE repository_import RENAME COLUMN base_url TO url;
ALTER TABLE repository_import RENAME COLUMN nexus_version TO source_server;
ALTER TABLE repository_import ALTER COLUMN source_repository DROP NOT NULL;
ALTER TABLE repository_import ADD COLUMN names text[];
ALTER TABLE repository_import ADD COLUMN source_total bigint;
ALTER TABLE repository_import DROP COLUMN assets_seen;
ALTER TABLE repository_import DROP COLUMN bytes_seen;

ALTER TABLE repository_import DROP CONSTRAINT repository_import_scan_listing_check;
UPDATE repository_import i
SET scan_listing = CASE WHEN r.format = 'docker' THEN 'catalog' ELSE 'search' END,
    cursor = CASE WHEN i.phase = 'scan' THEN NULL ELSE i.cursor END
FROM repository r
WHERE r.id = i.repository_id;
ALTER TABLE repository_import ALTER COLUMN scan_listing SET DEFAULT 'search';
ALTER TABLE repository_import ADD CONSTRAINT repository_import_scan_listing_check
    CHECK (scan_listing IN ('search', 'catalog', 'names'));
