-- ---------------------------------------------------------------------------
-- 0021: canonical usernames (security review, credential forwarding)
-- ---------------------------------------------------------------------------
--
-- A username is an identity key: password lookup, the login lockout, the
-- validated-credential cache and upstream credential forwarding must agree on
-- what "the same user" is. The server now canonicalizes every username it
-- stores or looks up (trimmed, Unicode NFC, lowercased; see
-- crates/db/src/username.rs). This migration brings existing rows into that
-- form and adds a unique index on it, so two accounts can never again differ
-- only in case, surrounding spaces or Unicode composition.
--
-- Existing accounts that collide on the canonical form are not merged: the
-- oldest (lowest id) takes the canonical name and every other one is renamed
-- to `<canonical>#<id>` (a WARNING names each). Their tokens keep working; an
-- administrator decides whether to delete or keep them.
--
-- NFC needs a UTF8 database; on any other encoding only trim + lower() apply
-- (and lower() is ASCII-only under a "C" ctype).

DO $$
DECLARE
    canon text := CASE WHEN current_setting('server_encoding') = 'UTF8'
                       THEN 'lower(normalize(btrim(%s), NFC))'
                       ELSE 'lower(btrim(%s))' END;
    renamed record;
BEGIN
    CREATE TEMP TABLE username_canonical ON COMMIT DROP AS
        SELECT id, username, ''::text AS target FROM app_user WHERE false;

    EXECUTE
        'INSERT INTO username_canonical (id, username, target)
         SELECT id, username,
                CASE
                    WHEN c = '''' THEN ''user#'' || id
                    WHEN row_number() OVER (PARTITION BY c ORDER BY id) = 1 THEN c
                    ELSE c || ''#'' || id
                END
         FROM (SELECT id, username, ' || format(canon, 'username') || ' AS c FROM app_user) s';
    DELETE FROM username_canonical WHERE target = username;

    FOR renamed IN
        SELECT username, target FROM username_canonical
        WHERE target LIKE '%#%' AND target NOT LIKE 'user#%'
    LOOP
        RAISE WARNING 'username % collides with an older account on its canonical form; renamed to %',
            renamed.username, renamed.target;
    END LOOP;

    -- Two passes so the existing UNIQUE (username) never sees a transient
    -- duplicate while names swap.
    UPDATE app_user u SET username = '~canonicalizing~' || u.id
    FROM username_canonical c WHERE u.id = c.id;
    UPDATE app_user u SET username = c.target, updated_at = now()
    FROM username_canonical c WHERE u.id = c.id;

    -- The bootstrap admin's "created once" markers are keyed by username.
    EXECUTE
        'INSERT INTO forge_setting (key, value)
         SELECT ''bootstrap_admin_created:'' || ' || format(canon, 'name') || ', value
         FROM (SELECT substr(key, 25) AS name, value FROM forge_setting
               WHERE key LIKE ''bootstrap_admin_created:%'') m
         ON CONFLICT (key) DO NOTHING';
    EXECUTE
        'DELETE FROM forge_setting
         WHERE key LIKE ''bootstrap_admin_created:%''
           AND key <> ''bootstrap_admin_created:'' || ' || format(canon, 'substr(key, 25)');

    EXECUTE format(
        'CREATE UNIQUE INDEX app_user_username_canonical_key ON app_user ((%s))',
        CASE WHEN current_setting('server_encoding') = 'UTF8'
             THEN 'lower(normalize(username, NFC))'
             ELSE 'lower(username)' END);
END
$$;
