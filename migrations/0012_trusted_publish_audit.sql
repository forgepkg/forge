-- Immutable provenance for workload-identity package publication.
--
-- This is intentionally independent of repository/auth-realm foreign keys:
-- deleting operational configuration must not erase the historical statement
-- that a federated workload published a package. Raw OIDC claims and bearer
-- tokens are never stored; subject and jti are SHA-256 digests supplied only
-- after full token verification.

CREATE TABLE trusted_publish_audit (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id      bigint NOT NULL,
    repository_name    text NOT NULL CHECK (repository_name <> ''),
    package_name       text NOT NULL CHECK (package_name <> ''),
    package_version    text NOT NULL CHECK (package_version <> ''),
    realm_id           bigint NOT NULL,
    realm_name         text NOT NULL CHECK (realm_name <> ''),
    issuer             text NOT NULL CHECK (issuer <> ''),
    role_id            bigint NOT NULL,
    role_name          text NOT NULL CHECK (role_name <> ''),
    subject_sha256     bytea NOT NULL CHECK (octet_length(subject_sha256) = 32),
    jti_sha256         bytea CHECK (jti_sha256 IS NULL OR octet_length(jti_sha256) = 32),
    token_issued_at    timestamptz NOT NULL,
    published_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX trusted_publish_audit_repo_time_idx
    ON trusted_publish_audit (repository_id, published_at DESC, id DESC);
CREATE INDEX trusted_publish_audit_subject_time_idx
    ON trusted_publish_audit (subject_sha256, published_at DESC, id DESC);

-- Make the ledger insert-only at the database boundary. The application role
-- owns the schema in the default deployment, so a trigger is the reliable
-- guard against accidental UPDATE/DELETE code paths (including cascades, of
-- which this table deliberately has none).
CREATE FUNCTION reject_trusted_publish_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'trusted_publish_audit is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trusted_publish_audit_append_only
BEFORE UPDATE OR DELETE ON trusted_publish_audit
FOR EACH ROW EXECUTE FUNCTION reject_trusted_publish_audit_mutation();
