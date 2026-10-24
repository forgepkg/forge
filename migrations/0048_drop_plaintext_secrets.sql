-- ---------------------------------------------------------------------------
-- 0048: no plaintext secrets (#408)
-- ---------------------------------------------------------------------------
--
-- Secret encryption is mandatory from 2.0.0 on: `[crypto]` is required and
-- every secret is sealed with the envelope service. What a 1.x install
-- without `[crypto]` kept in plaintext goes:
--
--   * `repository.upstream_password` and `nexus_import.password`, the
--     plaintext columns `upstream_password_enc` and `password_enc` replaced
--     (migrations 0009 and 0036);
--   * the `plain:` values of the secret settings (the registry-token key and
--     the OIDC issuer keys), which startup generates again;
--   * the secret keys a realm's `config` or the email settings' `config`
--     still carry, which belong in their `secrets_enc`.
--
-- An install that enabled `[crypto]` on 1.x has none of these left: its
-- startup and rotation worker sealed them. The upgrade notes tell an install
-- without it to do that before upgrading; a secret still stored in plaintext
-- here is gone and is entered again.
ALTER TABLE repository DROP COLUMN upstream_password;
ALTER TABLE nexus_import DROP COLUMN password;

DELETE FROM forge_setting
WHERE key IN ('docker_token_key', 'oidc_issuer_keys') AND value LIKE 'plain:%';

UPDATE auth_realm SET config = config - 'client_secret'
WHERE kind = 'oidc' AND config ? 'client_secret';
UPDATE auth_realm SET config = config - 'key_pepper'
WHERE kind = 'credential_forwarding' AND config ? 'key_pepper';

UPDATE email_settings
SET config = jsonb_set(
    config,
    '{transport}',
    (config -> 'transport') - 'password' - 'client_secret'
        - 'registration_access_token' - 'refresh_token'
)
WHERE jsonb_typeof(config -> 'transport') = 'object'
  AND (config -> 'transport') ?| ARRAY['password', 'client_secret',
                                      'registration_access_token', 'refresh_token'];
