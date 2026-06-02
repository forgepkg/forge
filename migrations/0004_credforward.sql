-- envisia-forge credential-forwarding authentication (slice 12.3), phase 0.
--
-- Builds on 0001_init.sql (app_user) and 0003_oidc.sql (external_identity /
-- session). Adds *provenance* to app_user so the new AuthProvider chain
-- (local-password + upstream-basic, with OIDC alongside) can record HOW a user
-- last authenticated, and creates the durable backing store for the
-- validated-credential cache that absorbs NuGet's per-request Basic auth.
--
-- No behavior change in this migration: the provenance columns default to
-- 'local' (matching every existing row, all of which are local/argon2 or the
-- OIDC no-login-sentinel users from 12.2), and nothing reads validated_credential
-- yet. The AuthProvider chain that consumes these lands in later phases.
--
-- Reconciliation with 12.2:
--   * 12.2 (0003) left app_user.password_hash NOT NULL and gave auto-provisioned
--     OIDC users a random argon2 "no-login sentinel" hash. This slice makes the
--     column NULLABLE so upstream/oidc users need no local password at all, and
--     adds a CHECK that preserves the slice-1 invariant for LOCAL users
--     (auth_source = 'local' => password_hash IS NOT NULL). Existing OIDC
--     sentinel hashes remain valid (they are non-null), so 12.2 is not broken.
--
-- Multi-instance correctness (no in-memory-only auth state, no advisory locks):
--   * validated_credential is the AUTHORITATIVE record of a forwarded
--     validation decision. The cache crate (L1 moka + optional L2 redis) sits in
--     front; a cold instance with no Redis reads this table and avoids
--     re-forwarding. Cross-instance forward coalescing uses a ROW lock on this
--     table (INSERT ... ON CONFLICT then SELECT ... FOR UPDATE) in a later phase
--     -- never pg_advisory_*.

-- ---------------------------------------------------------------------------
-- app_user: provenance columns + nullable password_hash
-- ---------------------------------------------------------------------------

-- HOW this user last authenticated / was provisioned. 'local' = slice-1 argon2
-- password; 'upstream-basic' = credential-forwarding; 'oidc' = §12.2. Existing
-- rows backfill to 'local' via the DEFAULT (NOT NULL).
ALTER TABLE app_user
    ADD COLUMN auth_source text NOT NULL DEFAULT 'local';

-- Opaque upstream identifier when the source is not local. For upstream-basic
-- this is usually just the username; kept for symmetry with §12.2's
-- external_identity (issuer, subject) linkage. NULL for local users.
ALTER TABLE app_user
    ADD COLUMN external_subject text;

-- Constrain auth_source to the known set so a typo can never silently disable
-- the local-password invariant below.
ALTER TABLE app_user
    ADD CONSTRAINT app_user_auth_source_check
    CHECK (auth_source IN ('local', 'upstream-basic', 'oidc'));

-- password_hash becomes nullable: upstream/oidc users have no local password.
ALTER TABLE app_user
    ALTER COLUMN password_hash DROP NOT NULL;

-- Preserve the slice-1 invariant for local users: a 'local' user MUST have a
-- password hash (otherwise password-basic auth would be meaningless). Non-local
-- sources may have NULL. Existing OIDC sentinel-hash rows satisfy this (their
-- hash is non-null) regardless of their auth_source.
ALTER TABLE app_user
    ADD CONSTRAINT app_user_local_password_hash_check
    CHECK (auth_source <> 'local' OR password_hash IS NOT NULL);

-- ---------------------------------------------------------------------------
-- validated_credential: durable backing store for the validated-credential cache
--
-- One row records the verdict of forwarding a (provider, username, password)
-- triple upstream. The password is NEVER stored: `cred_hmac` is
-- HMAC-SHA256(secret_pepper, provider_id | username | password) (hex), so a
-- DB-only compromise cannot brute-force passwords without the server-held pepper
-- (which lives in env/KMS, §12.5-encryptable), and the same password for two
-- users yields distinct hmacs (no cross-user inference).
--
-- `verdict` is the boolean decision (true = credentials valid, false =
-- definitively rejected). Infrastructure errors / timeouts are FAIL-CLOSED and
-- are NEVER written here (no row => re-forward; never cache an "unavailable").
-- `expires_at` bounds the trust window (positive/negative TTLs from config).
-- ---------------------------------------------------------------------------
CREATE TABLE validated_credential (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider_id text NOT NULL,
    username    text NOT NULL,
    -- HMAC-SHA256(pepper, provider_id | username | password), hex-encoded.
    -- NEVER the plaintext password.
    cred_hmac   text NOT NULL,
    -- true = valid (positive cache), false = rejected (negative cache).
    verdict     bool NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- The cache lookup key. UNIQUE also makes the row the singleflight anchor:
    -- a cross-instance forward coalesces via INSERT ... ON CONFLICT on this
    -- triple then SELECT ... FOR UPDATE (a ROW lock, never pg_advisory_*).
    UNIQUE (provider_id, username, cred_hmac)
);

-- Lookup path: the cache factory reads by the unique triple (covered by the
-- UNIQUE constraint's index). This partial index serves the background sweeper
-- that reaps expired rows (DELETE ... WHERE expires_at < now()).
CREATE INDEX validated_credential_expires_at_idx
    ON validated_credential (expires_at);

-- Revocation path: "force re-auth user X" / deactivate-user deletes every cached
-- verdict for a username across all providers.
CREATE INDEX validated_credential_username_idx
    ON validated_credential (provider_id, username);
