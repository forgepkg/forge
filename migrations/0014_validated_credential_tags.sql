-- Durable per-user revocation tags for validated credentials.
--
-- A credential fill takes a shared row lock before forwarding upstream and
-- writing its verdict. Revocation advances the generation (exclusive row lock)
-- and deletes verdicts in the same transaction. This stable lock row exists
-- even when no verdict row does, closing the miss -> singleflight insertion gap
-- where an older fill could otherwise recreate authority after revocation.
CREATE TABLE validated_credential_tag (
    username   text PRIMARY KEY,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
