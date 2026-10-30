-- ---------------------------------------------------------------------------
-- Passwords from clients are accepted per realm (#647)
--
-- Whether a client (a feed's HTTP Basic, `docker login`, `npm login
-- --auth-type=legacy`) may sign in with a password is the realm's own
-- `accept_client_passwords`, on the `local` and `credential_forwarding`
-- realms. It was one install-wide setting, `allow_password_basic` in the
-- `auth_settings` document (off by default), which an enabled
-- credential-forwarding realm turned on for every realm.
--
-- The local realm takes the old setting's value. A credential-forwarding
-- realm accepts its passwords from clients by default, as it did; its config
-- is left as it is, so the fingerprint of a realm seeded from
-- `[auth.upstream_basic]` still matches. The old key stays in the settings
-- document, which reads past it, until the next save there drops it.
-- ---------------------------------------------------------------------------
UPDATE auth_realm
SET config = config || jsonb_build_object(
        'accept_client_passwords',
        coalesce(
            (SELECT (value::jsonb ->> 'allow_password_basic')::boolean
             FROM forge_setting
             WHERE key = 'auth_settings'
               AND jsonb_typeof(value::jsonb -> 'allow_password_basic') = 'boolean'),
            false))
WHERE kind = 'local';
