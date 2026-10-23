-- Short-lived workload API keys: the trusted-publishing token exchange
-- (`POST /api/v2/token`).
--
-- A CI job presents its OIDC token, which a `workload_identity` realm
-- validates and maps to a role exactly as on any other request, and receives
-- an opaque API key in exchange. A row holds the SHA-256 of that key and the
-- workload principal captured at exchange time, so the key authorizes (and is
-- audited) exactly as the token it replaced. Raw tokens, keys and claims are
-- never stored: the subject and `jti` are SHA-256 digests.
--
-- The unique `(issuer_sha256, jti_sha256)` index is the redemption ledger: a
-- CI token can be exchanged once. A row therefore outlives its key until the
-- CI token itself has expired, so the token cannot be redeemed again after
-- its key lapses; the auth reaper deletes it once both have passed.
--
-- No foreign keys: a key is only honoured while its realm is enabled with the
-- very configuration (`config_sha256`) it was issued under, which the server
-- checks on every request, so deleting or editing the realm (or deleting the
-- role) revokes its keys without touching this table.

CREATE TABLE workload_api_key (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_sha256        bytea       NOT NULL UNIQUE CHECK (octet_length(key_sha256) = 32),
    realm_id          bigint      NOT NULL,
    role_id           bigint      NOT NULL,
    issuer_sha256     bytea       NOT NULL CHECK (octet_length(issuer_sha256) = 32),
    config_sha256     bytea       NOT NULL CHECK (octet_length(config_sha256) = 32),
    subject_sha256    bytea       NOT NULL CHECK (octet_length(subject_sha256) = 32),
    jti_sha256        bytea       NOT NULL CHECK (octet_length(jti_sha256) = 32),
    -- The exchanged CI token's `iat` (recorded with publish audit rows) and
    -- `exp` (how long the redemption must be remembered).
    token_issued_at   timestamptz NOT NULL,
    token_expires_at  timestamptz NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX workload_api_key_redemption_idx
    ON workload_api_key (issuer_sha256, jti_sha256);
