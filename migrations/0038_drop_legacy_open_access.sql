-- ---------------------------------------------------------------------------
-- 0038: no legacy open access
-- ---------------------------------------------------------------------------
--
-- Migration 0007 mapped the data of installs from before RBAC onto roles and
-- recorded `legacy_open_access`: on such an install, every account created
-- later got the built-in `authenticated` role too. Nothing reads the setting
-- any more, and the server no longer re-runs the mapping. Existing role
-- assignments stay; the `authenticated` role stays an ordinary built-in role.
DROP FUNCTION forge_rbac_apply_legacy_migration();

DELETE FROM forge_setting WHERE key IN ('legacy_open_access', 'legacy_rbac_synced');
