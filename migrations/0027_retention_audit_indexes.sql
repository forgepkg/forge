-- ---------------------------------------------------------------------------
-- 0027: index retention_audit for deletes and paging (review)
-- ---------------------------------------------------------------------------
--
-- `retention_audit.component_id` references `component(id)` with
-- `ON DELETE SET NULL` but had no index, so every component delete (a NuGet
-- DELETE, a redeploy, a retention hard delete) scanned the whole audit table
-- while it held the component and blob locks. Dry-run policies append rows
-- on every run, so that table only grows. Rows are now pruned after
-- `retention.audit_retention_seconds` (default 90 days).
--
-- The audit listing pages a repository's rows newest first by id; the
-- (repository_id, run_id) index could not serve that order.
CREATE INDEX retention_audit_component_idx
    ON retention_audit (component_id)
    WHERE component_id IS NOT NULL;

CREATE INDEX retention_audit_repo_id_idx
    ON retention_audit (repository_id, id DESC);
