-- ---------------------------------------------------------------------------
-- 0035: keep a password hash of credential-forwarding logins (opt-in)
-- ---------------------------------------------------------------------------
--
-- A credential-forwarding realm (e.g. a Nexus) may opt in to keeping an
-- argon2id hash of every password its upstream accepts
-- (`config.capture_password_hash`, off by default). The hash is written only
-- after the upstream definitively accepted the password, and only when a
-- login actually asked the upstream (not on a validated-credential cache hit),
-- so it is the last password that worked upstream.
--
-- The hash is NOT a local password: `password_hash` stays NULL, so the
-- local-password realm keeps skipping the account and the upstream stays the
-- authority while the realm is in use (a password changed upstream keeps
-- working, a revoked one stops). Its only use is an explicit administrator
-- switch of the account to a local one, which moves it into `password_hash`
-- (`POST /admin/users/{id}/convert-to-local`, or every account of a realm at
-- once): the way to retire the upstream without asking every user for a new
-- password.
--
-- Turning the realm option off deletes the hashes its accounts carry. Deleting
-- the realm keeps them: its accounts become orphans (migration 0023), which an
-- administrator can still switch to local accounts.
ALTER TABLE app_user
    ADD COLUMN captured_password_hash text,
    ADD COLUMN captured_password_at   timestamptz;

-- Only a credential-forwarding account carries one, and never alongside a
-- local password.
ALTER TABLE app_user
    ADD CONSTRAINT app_user_captured_password_hash_check
    CHECK (
        captured_password_hash IS NULL
        OR (auth_source = 'upstream-basic' AND password_hash IS NULL
            AND captured_password_at IS NOT NULL)
    );
