-- ---------------------------------------------------------------------------
-- 0032: no `admin` grant on a single repository
-- ---------------------------------------------------------------------------
--
-- Administration is global: every `/admin` operation needs membership in the
-- built-in `admin` role, and nothing reads an `admin` grant on one
-- repository. The grants API stored such a grant and listed it, but it
-- delegated nothing. It now refuses one; the rows it accepted are removed
-- (they never had an effect) and the table refuses new ones.
DELETE FROM repository_privilege
WHERE action = 'admin' AND repository_id IS NOT NULL;

ALTER TABLE repository_privilege
    ADD CONSTRAINT repository_privilege_admin_is_global
    CHECK (action <> 'admin' OR repository_id IS NULL);
