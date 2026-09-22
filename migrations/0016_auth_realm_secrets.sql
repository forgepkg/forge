-- envisia-forge: realm secrets encrypted at rest (review P1.5, slice 12.5 seam).
--
-- An auth realm's `config` jsonb carried its secrets (OIDC `client_secret`,
-- credential-forwarding `key_pepper`) in plaintext, so a database dump or a
-- read-only compromise disclosed them. When secret encryption is enabled
-- (`[crypto]`), the server now strips the secret keys out of `config` and
-- stores them here instead: one envelope blob (the JSON object of the realm's
-- secret keys) sealed under the active DEK, with the AAD bound to
-- ('auth_realm', 'secrets_enc', <row id>) so a blob copied to another row
-- fails to decrypt.
--
-- Compatibility: NULL means "no encrypted secrets" and the (legacy) plaintext
-- keys in `config` are used as before — existing rows keep working, the
-- startup/worker backfill re-encrypts them once an envelope is configured, and
-- every realm write re-encrypts. Without `[crypto]` nothing changes.

ALTER TABLE auth_realm
    ADD COLUMN secrets_enc bytea;
