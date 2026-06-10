-- envisia-forge auth realms (slice 12.7, design doc 2026-06-03 §3).
--
-- An **auth realm** is a configured authentication mechanism with an order:
-- today's local password, OIDC and credential-forwarding auth become realm
-- *rows*, edited via the admin UI — no redeploy to add/disable/reorder one.
-- The server's password chain and the OIDC login runtime are rebuilt from this
-- table (snapshot-cached, multi-instance safe: the table is the authority and
-- every instance re-reads it; no in-memory-only state).
--
-- `config` is kind-specific jsonb. Secrets inside it (OIDC client_secret,
-- credential-forwarding key_pepper) are write-only at the API layer and
-- redacted from every response; encrypting them at rest is slice 12.5 (the
-- encryption seam wraps this column the same way it wraps
-- repository.upstream_password).
--
-- Legacy config import: the slice-12.2 `[oidc]` block and the slice-12.3
-- `[auth.upstream_basic]` block are seeded into realm rows by the server at
-- startup (the TOML is not visible to SQL); a `forge_setting` key
-- ('auth_realms_seeded') makes that import one-shot. Fresh installs get only
-- the built-in `local` row below.

CREATE TABLE auth_realm (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- 'workload_identity' is reserved for slice 12.8 (WIF); the chain builder
    -- skips rows of that kind until then.
    kind       text NOT NULL
               CHECK (kind IN ('local', 'oidc', 'credential_forwarding',
                               'workload_identity')),
    -- Display name AND URL slug (lowercase, dns-label-ish).
    name       text NOT NULL UNIQUE
               CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    enabled    bool NOT NULL DEFAULT true,
    -- Order in which realms are tried/listed: LOWER tries first. UNIQUE so the
    -- order is total; DEFERRABLE so an admin reorder can swap priorities in one
    -- transaction without tripping over intermediate duplicates.
    priority   int  NOT NULL UNIQUE DEFERRABLE INITIALLY IMMEDIATE,
    config     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The built-in local-password realm. Always present; `enabled` + `priority`
-- control whether/where local sits in the order. (Deleting it is refused at
-- the API layer; disabling it is allowed — e.g. an OIDC-only deployment.)
INSERT INTO auth_realm (kind, name, enabled, priority, config)
VALUES ('local', 'local', true, 10, '{}'::jsonb);

-- Optional provenance: which realm authenticated/provisioned this user last.
-- Informational (display/audit) — authorization never branches on it. The
-- text `auth_source` column from 0004 remains the coarse-kind record.
ALTER TABLE app_user
    ADD COLUMN realm_id bigint REFERENCES auth_realm(id) ON DELETE SET NULL;
