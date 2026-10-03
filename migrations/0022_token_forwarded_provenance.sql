-- ---------------------------------------------------------------------------
-- 0022: token provenance for credential forwarding (security review)
-- ---------------------------------------------------------------------------
--
-- A token minted from a session that credential forwarding established is
-- only as trustworthy as the upstream verdict behind that session. When an
-- administrator forces re-authentication (`POST /admin/users/{id}/reauth`,
-- e.g. after the user was disabled upstream), such tokens are revoked along
-- with the sessions and cached verdicts; tokens an administrator minted for
-- the user are not.
ALTER TABLE token
    ADD COLUMN minted_with_forwarded_credential boolean NOT NULL DEFAULT false;

-- Backfill: an upstream-basic account signs in only through credential
-- forwarding, so its existing tokens were minted that way unless an
-- administrator minted them — which is not recorded. Flag them all, so a
-- reauth errs on the side of revoking.
UPDATE token t
SET minted_with_forwarded_credential = true
FROM app_user u
WHERE u.id = t.user_id
  AND u.auth_source = 'upstream-basic';
