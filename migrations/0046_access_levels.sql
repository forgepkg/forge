-- ---------------------------------------------------------------------------
-- 0046: ordered access levels (read < write < delete) for grants and token
-- scopes (#411)
-- ---------------------------------------------------------------------------
--
-- A grant gave one independent verb (`read`, `write`, `delete` or `admin`):
-- `write` did not include `read`, and `delete` included neither. A grant now
-- gives one of three ordered levels, each including the ones below it, so a
-- role holds one grant per (repository | ANY, selector). Administration is no
-- grant at all: it is membership in the built-in `admin` role.
--
-- This is a breaking change, made without carrying every grant and token
-- over. It never widens anyone's access:
--
--   * The grants of one (role, repository | ANY, selector) become one grant
--     when their verbs are exactly a level: `read`; `read` and `write`;
--     `read`, `write` and `delete`. The built-in roles' grants are of that
--     kind (`authenticated` and `writer` become `write` on every repository).
--     Every other combination (`write` without `read`, `delete` without
--     `write`) would be widened by a level, so its grants are deleted, and
--     the role's administrator grants the level they mean anew.
--   * Every `admin` grant is deleted, the `admin` role's own included.
--   * A token scope's `actions` becomes `level` the same way, with
--     `"admin": true` when it listed `admin`. `{"actions": ["admin"]}` without
--     `repositories`, the admin automation scope, becomes `{"admin": true}`
--     when its owner holds the `admin` role. Every other token whose scope
--     lists actions is revoked, and its scope set to reach nothing.

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
ALTER TABLE repository_privilege ADD COLUMN level text;

-- Mark the one grant of each (role, repository | ANY, selector) whose verbs
-- are exactly a level: the grant of that level's verb.
UPDATE repository_privilege rp
SET level = target.level
FROM (
    SELECT role_id, repository_id, selector_id,
           CASE string_agg(action, ',' ORDER BY action)
               WHEN 'read' THEN 'read'
               WHEN 'read,write' THEN 'write'
               WHEN 'delete,read,write' THEN 'delete'
           END AS level
    FROM repository_privilege
    WHERE action <> 'admin'
    GROUP BY role_id, repository_id, selector_id
) target
WHERE rp.role_id = target.role_id
  AND rp.repository_id IS NOT DISTINCT FROM target.repository_id
  AND rp.selector_id IS NOT DISTINCT FROM target.selector_id
  AND rp.action = target.level;

-- The others: the lower verbs a level now includes, `admin`, and the
-- combinations no level matches.
DELETE FROM repository_privilege WHERE level IS NULL;

DROP INDEX repository_privilege_uq;

ALTER TABLE repository_privilege
    DROP CONSTRAINT repository_privilege_admin_is_global,
    DROP COLUMN action,
    ALTER COLUMN level SET NOT NULL,
    ADD CONSTRAINT repository_privilege_level_check
        CHECK (level IN ('read', 'write', 'delete'));

-- One grant per (role, repository | ANY, selector); NULLs are folded via
-- COALESCE so (role, ANY, no-selector) is a single row.
CREATE UNIQUE INDEX repository_privilege_uq
    ON repository_privilege (role_id, COALESCE(repository_id, 0), COALESCE(selector_id, 0));

-- The action vocabulary the column referenced.
DROP TABLE privilege;

-- ---------------------------------------------------------------------------
-- Token scopes
-- ---------------------------------------------------------------------------

-- `"actions": null` restricted nothing, as no `level` does.
UPDATE token
SET scope = scope - 'actions'
WHERE scope->'actions' = 'null'::jsonb;

UPDATE token t
SET scope = (t.scope - 'actions')
            || jsonb_build_object('level', converted.level)
            || CASE WHEN converted.admin THEN '{"admin": true}'::jsonb ELSE '{}'::jsonb END
FROM (
    SELECT id,
           CASE array_to_string(ARRAY(
                    SELECT DISTINCT a
                    FROM jsonb_array_elements_text(scope->'actions') AS a
                    WHERE a <> 'admin'
                    ORDER BY a), ',')
               WHEN 'read' THEN 'read'
               WHEN 'read,write' THEN 'write'
               WHEN 'delete,read,write' THEN 'delete'
           END AS level,
           (scope->'actions') ? 'admin' AS admin
    FROM token
    WHERE jsonb_typeof(scope->'actions') = 'array'
) converted
WHERE t.id = converted.id AND converted.level IS NOT NULL;

UPDATE token t
SET scope = (t.scope - 'actions') || '{"admin": true}'::jsonb
WHERE jsonb_typeof(t.scope->'actions') = 'array'
  AND (t.scope->'actions') ? 'admin'
  AND NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(t.scope->'actions') AS a WHERE a <> 'admin'
  )
  AND COALESCE(t.scope->'repositories', 'null'::jsonb) = 'null'::jsonb
  AND EXISTS (
      SELECT 1 FROM user_role ur
      JOIN role r ON r.id = ur.role_id
      WHERE ur.user_id = t.user_id AND r.name = 'admin'
  );

UPDATE token
SET revoked_at = COALESCE(revoked_at, now()),
    scope = '{"repositories": []}'::jsonb
WHERE scope ? 'actions';
