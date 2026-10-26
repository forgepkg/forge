-- Trusted publishers grant narrowly scoped workload publication rights.
CREATE TABLE trusted_publisher (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id   bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    realm_id        bigint NOT NULL REFERENCES auth_realm(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (name <> ''),
    description     text NOT NULL DEFAULT '',
    includes        jsonb NOT NULL DEFAULT '[]'::jsonb
                    CHECK (jsonb_typeof(includes) = 'array'),
    excludes        jsonb NOT NULL DEFAULT '[]'::jsonb
                    CHECK (jsonb_typeof(excludes) = 'array'),
    conditions      jsonb NOT NULL CHECK (jsonb_typeof(conditions) = 'array'),
    actions         text[] NOT NULL
                    CHECK ('write' = ANY(actions)
                       AND actions <@ ARRAY['write', 'delete']::text[]),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repository_id, name)
);

CREATE INDEX trusted_publisher_realm_idx ON trusted_publisher (realm_id);

-- A key keeps the publisher definitions that matched the verified CI token.
-- Publisher ids intentionally have no FK: deleting a publisher must leave a
-- stale snapshot that fails its next live-definition check.
CREATE TABLE workload_api_key_trusted_publisher (
    workload_api_key_id bigint NOT NULL REFERENCES workload_api_key(id) ON DELETE CASCADE,
    trusted_publisher_id bigint NOT NULL,
    definition_sha256 bytea NOT NULL CHECK (octet_length(definition_sha256) = 32),
    PRIMARY KEY (workload_api_key_id, trusted_publisher_id)
);

ALTER TABLE trusted_publish_audit
    ADD COLUMN trusted_publisher_id bigint,
    ADD COLUMN trusted_publisher_name text,
    ADD CONSTRAINT trusted_publish_audit_publisher_pair
        CHECK ((trusted_publisher_id IS NULL) = (trusted_publisher_name IS NULL));
