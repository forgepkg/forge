-- ---------------------------------------------------------------------------
-- The built-in `reader` role
--
-- `read` on every repository, ones created later included: what the access
-- level Reader grants, as `writer` does for Writer. Until now Reader was no
-- role at all (an account holding neither `admin` nor `writer`), which reads
-- only what the account's other roles grant: nothing, under the anonymous
-- mode `off`, for an account without one. That level stays, as Roles only.
--
-- A role an administrator named `reader` keeps its grants and members under
-- the name `reader-<id>`.
--
-- Every user that is neither an administrator nor a writer was a reader and
-- gets the role, so they read every repository from now on. Service accounts
-- do not: each stands for one pipeline or network, whose roles were chosen
-- for it, and they become Roles only.
-- ---------------------------------------------------------------------------
UPDATE role SET name = 'reader-' || id WHERE name = 'reader' AND NOT builtin;

INSERT INTO role (name, description, builtin) VALUES
    ('reader', 'Read packages on every repository; publish nothing, no administration.', true);

INSERT INTO repository_privilege (role_id, repository_id, level)
SELECT id, NULL, 'read' FROM role WHERE name = 'reader';

INSERT INTO user_role (user_id, role_id)
SELECT u.id, r.id
FROM app_user u
CROSS JOIN role r
WHERE r.name = 'reader'
  AND u.kind = 'user'
  AND NOT EXISTS (
      SELECT 1
      FROM user_role held
      JOIN role held_role ON held_role.id = held.role_id
      WHERE held.user_id = u.id AND held_role.name IN ('admin', 'writer')
  );
