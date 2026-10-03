-- ---------------------------------------------------------------------------
-- 0026: audit every package mutation a workload performs (security review)
-- ---------------------------------------------------------------------------
--
-- Unlist, relist and delete by a workload-identity principal now run behind
-- the same realm fence as a publish (a stale realm snapshot is denied) and
-- append a ledger row too; `action` says which mutation it records. Existing
-- rows are publishes.
ALTER TABLE trusted_publish_audit
    ADD COLUMN action text NOT NULL DEFAULT 'publish'
        CHECK (action IN ('publish', 'unlist', 'relist', 'delete'));
