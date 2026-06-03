-- envisia-forge fine-grained RBAC (slice 12.4), phase 1.
--
-- Builds on 0001_init.sql (repository, app_user, token, group_member). ADDITIVE
-- schema only: this migration creates the RBAC tables and seeds the built-in
-- roles + the privilege action vocabulary. It DOES NOT flip any behavior:
--   * the slice-1 `repository.anonymous_read` flag is still authoritative,
--   * `app_user.is_admin` is still authoritative,
--   * no grants are derived from existing data here, and nothing reads these
--     tables yet (the evaluator + the data migration that preserves slice-1
--     behavior land in later phases).
-- A fresh install therefore behaves exactly as before this migration; the only
-- observable change is that the four seeded `privilege` rows and three built-in
-- `role` rows now exist.
--
-- Design (plan §3 "Data model"). Key decisions reflected here:
--   * The action verb lives on the GRANT row (`repository_privilege.action`),
--     not on a separate `role_privilege` table, so the effective-set query is a
--     single flat join (`user_role -> repository_privilege`). There is therefore
--     deliberately NO `role_privilege` table.
--   * Grants are purely ADDITIVE / grant-only: "no access" is the absence of a
--     grant (fail-closed). There are no explicit-deny rows.
--   * A NULL `repository_id` on a grant means ANY repository (the `*`/`ANY`
--     wildcard). A NULL `selector_id` means the grant is not package-scoped.
--
-- Multi-instance correctness: no in-memory-only state and NO pg_advisory_* — all
-- authoritative data is in these tables; the cache crate sits in front of the
-- resolved effective set with explicit cross-node invalidation (later phase).

-- ---------------------------------------------------------------------------
-- privilege: the reference table of action verbs (seeded, immutable).
-- Acts as an FK target so the action set is queryable and FK-enforced.
-- ---------------------------------------------------------------------------
CREATE TABLE privilege (
    action text PRIMARY KEY
);
INSERT INTO privilege (action) VALUES ('read'), ('write'), ('delete'), ('admin');

-- ---------------------------------------------------------------------------
-- role: a named, assignable role. `builtin` roles cannot be deleted and have
-- restricted edits (enforced in the admin API, later phase).
-- ---------------------------------------------------------------------------
CREATE TABLE role (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL UNIQUE,             -- url-safe slug, e.g. 'admin'
    description text NOT NULL DEFAULT '',
    builtin     boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- content_selector: a reusable named include/exclude glob set on the (lowercased)
-- package name. Empty `includes` ([]) means match-all; `excludes` subtract.
-- Created before repository_privilege for the FK below.
-- ---------------------------------------------------------------------------
CREATE TABLE content_selector (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    includes    jsonb NOT NULL DEFAULT '["*"]'::jsonb,
    excludes    jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- repository_privilege: the core grant. "this role gets <action> on <repo|ANY>,
-- optionally scoped by a content selector". A NULL repository_id = ANY repo; a
-- NULL selector_id = not package-scoped.
-- ---------------------------------------------------------------------------
CREATE TABLE repository_privilege (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_id       bigint NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    repository_id bigint NULL REFERENCES repository(id) ON DELETE CASCADE,  -- NULL = ANY
    action        text NOT NULL REFERENCES privilege(action),
    selector_id   bigint NULL REFERENCES content_selector(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- A given (role, repo|ANY, action, selector) edge is unique. NULLs are folded
-- via COALESCE so (role, ANY, read, no-selector) collapses to a single row.
CREATE UNIQUE INDEX repository_privilege_uq
    ON repository_privilege (role_id, COALESCE(repository_id, 0), action, COALESCE(selector_id, 0));
CREATE INDEX repository_privilege_role_idx ON repository_privilege (role_id);
CREATE INDEX repository_privilege_repo_idx ON repository_privilege (repository_id);

-- ---------------------------------------------------------------------------
-- user_role: assignment of roles to users.
-- ---------------------------------------------------------------------------
CREATE TABLE user_role (
    user_id bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id bigint NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_role_role_idx ON user_role (role_id);

-- ---------------------------------------------------------------------------
-- Seed the built-in roles. These exist on every install; the data migration
-- (later phase) is what assigns them to existing users / repos to preserve
-- slice-1 behavior. Seeding them here is behavior-neutral.
--   * admin         — allow-all (membership short-circuits the evaluator); also
--                     carries a sentinel (ANY, admin) grant for completeness.
--   * authenticated — convenience role used to preserve slice-1 "any user may
--                     read/write everywhere" on upgrade; seeded with (read, ANY)
--                     + (write, ANY) grants so the data migration only needs to
--                     assign it. Grants are inert until a user holds the role.
--   * anonymous     — the role every Anonymous principal is evaluated against;
--                     no grants seeded (the data migration converts existing
--                     anonymous_read repos into read grants on this role).
-- ---------------------------------------------------------------------------
INSERT INTO role (name, description, builtin) VALUES
    ('admin',         'Full administrative access to all repositories and privilege management.', true),
    ('authenticated', 'Legacy convenience role: read/write on all repositories (slice-1 open access).', true),
    ('anonymous',     'Grants applied to unauthenticated (anonymous) callers.', true);

-- admin role: sentinel (ANY repo, admin) grant. The evaluator treats membership
-- in the admin role as allow-all regardless, but the row documents the intent
-- and gives the admin API something concrete to show.
INSERT INTO repository_privilege (role_id, repository_id, action)
SELECT id, NULL, 'admin' FROM role WHERE name = 'admin';

-- authenticated role: (read, ANY) + (write, ANY). Inert until assigned.
INSERT INTO repository_privilege (role_id, repository_id, action)
SELECT id, NULL, 'read' FROM role WHERE name = 'authenticated';
INSERT INTO repository_privilege (role_id, repository_id, action)
SELECT id, NULL, 'write' FROM role WHERE name = 'authenticated';
