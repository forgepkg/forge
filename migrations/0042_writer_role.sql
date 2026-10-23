-- The built-in `writer` role (#318): read and publish packages on every
-- repository, without any right to administer the instance.
--
-- `write` is the privilege every push checks (a NuGet push, an OCI blob or
-- manifest upload, a Helm chart upload), for a package or image name the
-- repository does not have yet too. The role gets no `delete` (unlisting or
-- deleting versions, deleting tags) and no `admin`: deleting stays with
-- administrators and custom roles, so a leaked CI token of a writer cannot
-- remove published versions. Like the other built-in roles it cannot be
-- deleted or renamed; its grants can be edited like any role's.
--
-- `role.name` is unique, and an install may already have a custom role named
-- `writer`. That role is renamed `writer#<id>`, keeping its grants and
-- assignments, and a WARNING names it, as 0021 does for usernames. A
-- workload-identity realm rule that named it follows the rename: it must not
-- start handing out the new built-in role instead.

DO $$
DECLARE
    existing bigint;
    renamed  text;
    realm    record;
BEGIN
    SELECT id INTO existing FROM role WHERE name = 'writer';
    IF existing IS NULL THEN
        RETURN;
    END IF;
    renamed := 'writer#' || existing;
    UPDATE role SET name = renamed, updated_at = now() WHERE id = existing;
    RAISE WARNING 'a role named writer exists already; renamed to % (its grants and assignments stay with it)',
        renamed;

    FOR realm IN
        SELECT id, name FROM auth_realm
        WHERE kind = 'workload_identity'
          AND jsonb_typeof(config->'rules') = 'array'
          AND config->'rules' @> '[{"role": "writer"}]'
    LOOP
        UPDATE auth_realm
        SET config = jsonb_set(
                config,
                '{rules}',
                (SELECT jsonb_agg(
                            CASE WHEN rule->>'role' = 'writer'
                                 THEN jsonb_set(rule, '{role}', to_jsonb(renamed))
                                 ELSE rule
                            END
                            ORDER BY ord)
                 FROM jsonb_array_elements(config->'rules') WITH ORDINALITY AS r(rule, ord))),
            updated_at = now()
        WHERE id = realm.id;
        RAISE WARNING 'workload identity realm % named the role writer in a rule; it now names %',
            realm.name, renamed;
    END LOOP;
END $$;

INSERT INTO role (name, description, builtin) VALUES
    ('writer', 'Read and publish packages on every repository; no administration.', true);

INSERT INTO repository_privilege (role_id, repository_id, action)
SELECT id, NULL, action
FROM role, (VALUES ('read'), ('write')) AS a(action)
WHERE name = 'writer';
