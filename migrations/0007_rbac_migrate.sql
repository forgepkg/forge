-- envisia-forge fine-grained RBAC (slice 12.4), phase 5: data migration that
-- PRESERVES slice-1 behavior on upgrade and FAILS CLOSED on a fresh install.
--
-- Builds on 0005_rbac.sql (the empty RBAC tables + the three seeded built-in
-- roles) and 0001_init.sql (app_user.is_admin, repository.anonymous_read). This
-- is the migration that flips RBAC from "inert schema" to "authoritative", and
-- it must not lock out an existing deployment:
--
--   * UPGRADE (the DB already had users before RBAC existed) ⇒ keep working.
--     Every existing app_user is granted the built-in `authenticated` role
--     (which carries (read, ANY) + (write, ANY) from 0005), so the slice-1
--     "any authenticated user can read/write everywhere" rule is reproduced
--     exactly. is_admin=true users are additionally granted the `admin` role;
--     every repository.anonymous_read=true becomes an (anonymous role, repo,
--     read) grant so anonymous callers keep seeing the same repos.
--     A `legacy_open_access = true` setting records that this install opted into
--     the open default, so NEW users created after the upgrade are auto-assigned
--     `authenticated` too (handled by the boot code path).
--
--   * FRESH install (empty DB; migrations 0001..0007 run in sequence before the
--     bootstrap admin is inserted) ⇒ default CLOSED. app_user is empty at this
--     point, so nothing is mapped and `legacy_open_access = false`. A fresh
--     deployment denies everything until an admin grants — secure by default.
--
-- Detection rule: "was app_user non-empty at the moment 0007 first ran?". On an
-- upgrade the deployment had users; on a fresh install the bootstrap admin is
-- created by the server AFTER migrations, so app_user is still empty here. This
-- is a pure-SQL signal that needs no external flag.
--
-- Idempotency & boot-safety: the mapping is expressed as a PL/pgSQL function
-- (`forge_rbac_apply_legacy_migration`) whose every write is ON CONFLICT DO
-- NOTHING, so it is safe to re-invoke on every boot (the server's bootstrap
-- step calls it for late-arriving anonymous_read / is_admin / user rows). The
-- one-shot detection above runs only inside this migration; the function itself
-- carries no fresh-vs-upgrade decision and can be called any number of times.
--
-- Multi-instance correctness: no pg_advisory_* and no in-memory-only state. The
-- migration runner (sqlx) already serializes migrations cluster-wide via its own
-- table; the function's writes are all idempotent upserts, so a concurrent boot
-- calling it cannot create duplicates or races.

-- ---------------------------------------------------------------------------
-- forge_setting: a tiny singleton key/value store for install-wide flags. Used
-- here for `legacy_open_access`; future install-level switches can reuse it.
-- ---------------------------------------------------------------------------
CREATE TABLE forge_setting (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- forge_rbac_apply_legacy_migration(): the idempotent behavior-preserving map.
--
--   1. is_admin=true app_user  -> user_role(admin)
--   2. anonymous_read=true repo -> repository_privilege(anonymous, repo, read)
--   3. when legacy_open_access  -> every app_user gets user_role(authenticated)
--
-- Step 3 is gated on the `legacy_open_access` setting so a FRESH install (flag
-- false / absent) never silently re-opens access if this function is later
-- called by the boot path. Steps 1 and 2 are always safe (they only re-encode
-- the slice-1 is_admin / anonymous_read columns, which remain authoritative as
-- a dual-read fallback until a follow-up migration drops them).
--
-- All writes are ON CONFLICT DO NOTHING, so re-running is a no-op once applied.
-- ---------------------------------------------------------------------------
CREATE FUNCTION forge_rbac_apply_legacy_migration() RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    admin_role_id         bigint;
    anonymous_role_id     bigint;
    authenticated_role_id bigint;
    open_access           boolean;
BEGIN
    SELECT id INTO admin_role_id         FROM role WHERE name = 'admin';
    SELECT id INTO anonymous_role_id     FROM role WHERE name = 'anonymous';
    SELECT id INTO authenticated_role_id FROM role WHERE name = 'authenticated';

    -- The built-in roles are seeded by 0005; if any is missing the schema is
    -- inconsistent and we must not guess. Fail loudly rather than half-apply.
    IF admin_role_id IS NULL OR anonymous_role_id IS NULL OR authenticated_role_id IS NULL THEN
        RAISE EXCEPTION 'forge_rbac_apply_legacy_migration: built-in roles missing (admin/anonymous/authenticated)';
    END IF;

    -- 1. is_admin -> admin role (dual-read fallback keeps existing admins admin).
    INSERT INTO user_role (user_id, role_id)
    SELECT u.id, admin_role_id
    FROM app_user u
    WHERE u.is_admin = true
    ON CONFLICT (user_id, role_id) DO NOTHING;

    -- 2. anonymous_read repo -> (anonymous role, repo, read) grant.
    INSERT INTO repository_privilege (role_id, repository_id, action)
    SELECT anonymous_role_id, r.id, 'read'
    FROM repository r
    WHERE r.anonymous_read = true
    ON CONFLICT (role_id, COALESCE(repository_id, 0), action, COALESCE(selector_id, 0)) DO NOTHING;

    -- 3. legacy-open-access installs: every existing user keeps read/write
    --    everywhere via the `authenticated` role. Skipped on fresh installs.
    SELECT (value = 'true') INTO open_access
    FROM forge_setting WHERE key = 'legacy_open_access';

    IF COALESCE(open_access, false) THEN
        INSERT INTO user_role (user_id, role_id)
        SELECT u.id, authenticated_role_id
        FROM app_user u
        ON CONFLICT (user_id, role_id) DO NOTHING;
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- One-shot detection + initial application (this migration runs exactly once).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    is_upgrade boolean;
BEGIN
    -- Upgrade iff the deployment already had users before RBAC. On a fresh
    -- install app_user is empty here (bootstrap admin is inserted post-migrate).
    SELECT EXISTS (SELECT 1 FROM app_user) INTO is_upgrade;

    -- Record the install-wide open-access default: open on upgrade, closed fresh.
    INSERT INTO forge_setting (key, value)
    VALUES ('legacy_open_access', CASE WHEN is_upgrade THEN 'true' ELSE 'false' END)
    ON CONFLICT (key) DO NOTHING;

    -- Apply the behavior-preserving mapping. On a fresh install this is a no-op
    -- (no users, no anonymous_read repos, flag false ⇒ no authenticated grants).
    PERFORM forge_rbac_apply_legacy_migration();
END;
$$;
