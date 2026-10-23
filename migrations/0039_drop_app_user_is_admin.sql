-- ---------------------------------------------------------------------------
-- 0039: the built-in `admin` role is the only admin source
-- ---------------------------------------------------------------------------
--
-- Before RBAC, `app_user.is_admin` made a user an administrator. Migration
-- 0007 gave every such user the built-in `admin` role and kept the column as
-- a fallback that every write path kept in step with the role. Authorization
-- now reads only the role, so the column goes. A user it still marks as an
-- admin without the role (none should exist) gets the role first.
INSERT INTO user_role (user_id, role_id)
SELECT u.id, r.id
FROM app_user u
JOIN role r ON r.name = 'admin'
WHERE u.is_admin
ON CONFLICT (user_id, role_id) DO NOTHING;

ALTER TABLE app_user DROP COLUMN is_admin;
