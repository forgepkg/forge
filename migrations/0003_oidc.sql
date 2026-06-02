-- envisia-forge OIDC / interactive login (slice 12.2)
--
-- Builds on 0001_init.sql (app_user, token) and 0002_retention.sql. Adds the
-- three tables that back interactive OpenID Connect login (authorization-code +
-- PKCE), browser sessions, and the ephemeral auth-code-flow state.
--
-- Multi-instance correctness (no in-memory-only auth state):
--   * `oidc_flow` holds state/nonce/PKCE-verifier/redirect target so ANY instance
--     can complete a callback that a DIFFERENT instance started. Rows are
--     single-use: the callback consumes them with `DELETE ... RETURNING`, which
--     is naturally race-safe (only one DELETE returns the row) and blocks replay.
--   * `session` is the authority; the cookie is just an opaque pointer. We store
--     only the sha256 of the cookie secret (`token_hash`), mirroring the slice-1
--     `token.token_hash` model, so a DB read yields no usable credential.
--
-- Conventions match slice 1: `bigint GENERATED ALWAYS AS IDENTITY` PKs (except
-- where a natural text key is required), `timestamptz`, app-maintained
-- `updated_at`.

-- ---------------------------------------------------------------------------
-- external_identity: maps an IdP identity (issuer, subject) -> app_user
--
-- The join key is `(issuer, subject)` — NEVER email (emails are reassignable;
-- `sub` is the stable, issuer-scoped identifier). One app_user may eventually
-- have several external_identity rows (multi-IdP); the unique constraint
-- prevents duplicate links. The denormalized claim columns are for
-- display/debugging only and carry no authority.
-- ---------------------------------------------------------------------------
CREATE TABLE external_identity (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    issuer              text   NOT NULL,            -- OIDC `iss` (exact match)
    subject             text   NOT NULL,            -- OIDC `sub` (stable per-issuer)
    -- denormalized last-seen claims, for display/debugging only (not authority):
    preferred_username  text,
    email               text,
    display_name        text,
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE INDEX external_identity_user_id_idx ON external_identity (user_id);

-- ---------------------------------------------------------------------------
-- session: server-side login sessions (the authority; the cookie is a pointer)
--
-- `token_hash` = sha256(cookie_secret), mirroring slice-1 `token.token_hash`.
-- The plaintext 256-bit base64url secret lives only in the `forge_session`
-- cookie; the DB never sees it. Validity:
--   revoked_at IS NULL AND now() < idle_expiry AND now() < absolute_expiry
-- `idle_expiry` is refreshed (throttled) on use; `absolute_expiry` is the hard
-- cap. `csrf_secret` is a per-session secret for double-submit CSRF on the
-- cookie-authenticated mutating endpoints (logout, token mint).
-- ---------------------------------------------------------------------------
CREATE TABLE session (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id               bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    external_identity_id  bigint REFERENCES external_identity(id) ON DELETE SET NULL,
    token_hash            text NOT NULL UNIQUE,      -- sha256(cookie secret), like token.token_hash
    csrf_secret           text NOT NULL,             -- per-session double-submit CSRF secret
    user_agent_hash       text,                      -- optional binding to detect cookie theft
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),  -- idle-timeout clock
    idle_expiry           timestamptz NOT NULL,                -- last_seen_at + idle_ttl, refreshed on use
    absolute_expiry       timestamptz NOT NULL,                -- hard cap regardless of activity
    revoked_at            timestamptz
);

CREATE INDEX session_user_id_idx ON session (user_id);
CREATE INDEX session_idle_expiry_idx ON session (idle_expiry);

-- ---------------------------------------------------------------------------
-- oidc_flow: ephemeral auth-code-flow state, shared across instances
--
-- The crux of multi-instance correctness. `state` is the OAuth `state` param the
-- IdP echoes back, so it is the natural text PK and cannot be hashed. Rows are
-- single-use: the callback runs
--   DELETE FROM oidc_flow WHERE state = $1 AND expires_at > now()
--     RETURNING nonce, pkce_verifier, redirect_to
-- An unknown/expired/replayed state returns no row -> reject. `pkce_verifier`
-- must be sent verbatim to the IdP, so it is stored as-is; rows are short-lived
-- (e.g. now()+10min) and reaped on expiry.
-- ---------------------------------------------------------------------------
CREATE TABLE oidc_flow (
    state          text PRIMARY KEY,            -- CSPRNG; also the OAuth `state` param
    nonce          text NOT NULL,               -- CSPRNG; checked against ID-token `nonce`
    pkce_verifier  text NOT NULL,               -- PKCE code_verifier (S256), sent verbatim to IdP
    redirect_to    text NOT NULL,               -- validated post-login relative path
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL         -- short, e.g. now()+10min
);

CREATE INDEX oidc_flow_expires_at_idx ON oidc_flow (expires_at);
