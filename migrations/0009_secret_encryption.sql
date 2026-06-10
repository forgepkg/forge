-- envisia-forge secret encryption at rest (slice 12.5, plan §2.2/§2.8 step 1).
--
-- Double envelope encryption: per-secret ciphertext is sealed by a DEK, DEKs
-- are wrapped by a KEK, KEKs are wrapped by the root key (KMS/HSM in prod,
-- env/file in lower environments). This migration creates the wrapped-key
-- store and the first encrypted secret column.
--
--   * `encryption_key` holds ONLY wrapped key material (KEK rows wrapped by
--     the root, DEK rows wrapped by a KEK). The root key is NEVER stored here
--     — only its id + version label are referenced on KEK rows, so root
--     rotation is "re-wrap every KEK whose label differs".
--   * `repository.upstream_password_enc` is the envelope-blob replacement for
--     the plaintext `upstream_password`. The plaintext column is KEPT for now:
--     the startup backfill job copies+encrypts existing values (idempotent,
--     resumable), and a LATER migration drops the plaintext column once the
--     backfill has been verified in the field (the standard two-step
--     add+backfill-then-drop column rewrite; plan §2.8 step 4).

CREATE TABLE encryption_key (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- 'kek' = wrapped by the root, wraps DEKs; 'dek' = wrapped by a KEK,
    -- seals secret values. No 'root' layer: the root lives outside the DB.
    layer                text   NOT NULL CHECK (layer IN ('kek', 'dek')),
    -- Monotonic per layer+scope; envelope blobs reference the DEK version,
    -- DEK rows reference their wrapping KEK version.
    version              int    NOT NULL,
    -- AEAD of THIS key's own bytes when wrapping children / sealing data.
    algorithm            text   NOT NULL CHECK (algorithm IN
                              ('aes-256-gcm', 'xchacha20-poly1305')),
    -- The wrapped key material: this key's raw bytes, encrypted by its parent.
    --   kek rows: wrapped by the ROOT (KMS Encrypt output / dev-root envelope)
    --   dek rows: wrapped by a KEK (envelope produced with that KEK)
    wrapped_key          bytea  NOT NULL,
    -- Parent reference (which wrapping key produced wrapped_key):
    --   kek rows: root_key_id + root_key_version set, wrapping_kek_version NULL
    --   dek rows: wrapping_kek_version set, root fields NULL
    root_key_id          text   NULL,
    root_key_version     text   NULL,
    wrapping_kek_version int    NULL,
    -- Lifecycle:
    --   active   = used for NEW wraps/encrypts (exactly one per layer+scope)
    --   retiring = still used to DECRYPT/UNWRAP existing material, not for new
    --   revoked  = no longer used at all (kept for audit)
    state                text   NOT NULL DEFAULT 'active'
                              CHECK (state IN ('active', 'retiring', 'revoked')),
    -- Forward-looking multi-tenant / multi-purpose discriminator; slice 12.5
    -- uses the single 'default' scope.
    scope                text   NOT NULL DEFAULT 'default',
    created_at           timestamptz NOT NULL DEFAULT now(),
    -- When the key left 'active' (rotation/revocation).
    rotated_at           timestamptz NULL,
    -- Layer-shape integrity: a KEK row carries root references and never a
    -- wrapping KEK; a DEK row carries a wrapping KEK and never root references.
    CONSTRAINT encryption_key_parent_shape CHECK (
        (layer = 'kek' AND root_key_id IS NOT NULL AND root_key_version IS NOT NULL
                       AND wrapping_kek_version IS NULL)
     OR (layer = 'dek' AND wrapping_kek_version IS NOT NULL
                       AND root_key_id IS NULL AND root_key_version IS NULL)
    ),
    UNIQUE (layer, scope, version)
);

-- At most one ACTIVE key per layer+scope (partial unique index): the
-- rotation flip (retire old + insert new active in one transaction) can never
-- leave zero or two active keys visible.
CREATE UNIQUE INDEX encryption_key_one_active
    ON encryption_key (layer, scope)
    WHERE state = 'active';

-- "Give me the active / all-retiring keys of a layer+scope" lookups.
CREATE INDEX encryption_key_layer_scope_state
    ON encryption_key (layer, scope, state);

-- The encrypted upstream password: a self-describing envelope blob
-- (format_version | algorithm | dek_version | nonce | ciphertext+tag), AAD
-- bound to ('repository', 'upstream_password_enc', id). NULL = no password
-- stored (or not yet backfilled from the plaintext column).
ALTER TABLE repository
    ADD COLUMN upstream_password_enc bytea NULL;
