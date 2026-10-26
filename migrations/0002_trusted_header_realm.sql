-- ---------------------------------------------------------------------------
-- Trusted-header realms (#506)
--
-- A `trusted_header` realm authenticates a request as the account a header
-- of the load balancer or reverse proxy in front of Forge names (in the style
-- of `REMOTE_USER`). Its config names the headers; the secret the proxy proves
-- itself with is sealed into `secrets_enc` like the other realms' secrets.
--
-- The accounts it names are its own: `auth_source = 'trusted-header'` with
-- `realm_id` set to the realm. Like a credential-forwarding account such an
-- account has no local password, and a deleted realm orphans it
-- (`realm_orphaned`, set by the trigger on `auth_realm`).
-- ---------------------------------------------------------------------------
ALTER TABLE auth_realm DROP CONSTRAINT auth_realm_kind_check;
ALTER TABLE auth_realm ADD CONSTRAINT auth_realm_kind_check
    CHECK (kind IN ('local', 'oidc', 'credential_forwarding',
                    'workload_identity', 'trusted_header'));

ALTER TABLE app_user DROP CONSTRAINT app_user_auth_source_check;
ALTER TABLE app_user ADD CONSTRAINT app_user_auth_source_check
    CHECK (auth_source IN ('local', 'upstream-basic', 'oidc', 'trusted-header'));

-- A trusted-header account never has a local password: the headers are what
-- sign it in.
ALTER TABLE app_user ADD CONSTRAINT app_user_trusted_header_password_check
    CHECK (auth_source <> 'trusted-header' OR password_hash IS NULL);
