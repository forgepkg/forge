-- ---------------------------------------------------------------------------
-- 0037: a docker group's writable member by id
-- ---------------------------------------------------------------------------
--
-- A docker group named the hosted member its pushes go to by name
-- (`config.writable_member`). Renaming that repository broke group pushes,
-- and a repository created later under the old name silently became the
-- push target. The member is now stored by id (`config.writable_member_id`),
-- like the group's members themselves. A name no hosted docker repository
-- has any more is dropped: it named no push target before either.
UPDATE repository g
SET config = (g.config - 'writable_member') || COALESCE(
        (SELECT jsonb_build_object('writable_member_id', m.id)
         FROM repository m
         WHERE m.name = g.config->>'writable_member'
           AND m.format = 'docker' AND m.kind = 'hosted'),
        '{}'::jsonb)
WHERE g.format = 'docker' AND g.kind = 'group' AND g.config ? 'writable_member';
