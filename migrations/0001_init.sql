-- envisia-forge initial schema (slice 1)
--
-- Conventions:
--   * PKs are `id bigint GENERATED ALWAYS AS IDENTITY` unless noted.
--   * Timestamps are `timestamptz`; `created_at`/`updated_at` default to now().
--   * `updated_at` is maintained by the application (no update triggers in slice 1).

-- ---------------------------------------------------------------------------
-- repository
-- ---------------------------------------------------------------------------
CREATE TABLE repository (
    id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                    text NOT NULL UNIQUE,
    format                  text NOT NULL DEFAULT 'nuget',
    kind                    text NOT NULL CHECK (kind IN ('hosted', 'proxy', 'group')),
    anonymous_read          bool NOT NULL DEFAULT false,
    online                  bool NOT NULL DEFAULT true,
    config                  jsonb NOT NULL DEFAULT '{}',
    -- proxy-only columns (nullable; used when kind = 'proxy')
    remote_url              text,
    package_delay_seconds   int NOT NULL DEFAULT 0,
    upstream_username       text,
    upstream_password       text,
    allow_private_upstream  bool NOT NULL DEFAULT false,
    metadata_ttl_seconds    int,
    not_found_ttl_seconds   int,
    -- hosted-only column
    allow_redeploy          bool NOT NULL DEFAULT false,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- group_member
-- ---------------------------------------------------------------------------
CREATE TABLE group_member (
    group_id   bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    member_id  bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    priority   int NOT NULL,
    PRIMARY KEY (group_id, member_id),
    UNIQUE (group_id, priority),
    CHECK (group_id <> member_id)
);

-- ---------------------------------------------------------------------------
-- blob
-- ---------------------------------------------------------------------------
CREATE TABLE blob (
    sha256      text PRIMARY KEY,
    size        bigint NOT NULL,
    s3_key      text NOT NULL,
    ref_count   bigint NOT NULL DEFAULT 0,
    state       text NOT NULL CHECK (state IN ('pending', 'committed')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- blob_outbox
-- ---------------------------------------------------------------------------
CREATE TABLE blob_outbox (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    op            text NOT NULL CHECK (op IN ('delete_object')),
    sha256        text NOT NULL,
    s3_key        text NOT NULL,
    available_at  timestamptz NOT NULL DEFAULT now(),
    attempts      int NOT NULL DEFAULT 0,
    locked_until  timestamptz,
    processed_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Worker claim query: only unprocessed rows, better selectivity than a full-table index.
CREATE INDEX blob_outbox_claim_idx ON blob_outbox (available_at) WHERE processed_at IS NULL;

-- ---------------------------------------------------------------------------
-- component
-- ---------------------------------------------------------------------------
CREATE TABLE component (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id    bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    name             text NOT NULL,
    original_id      text NOT NULL,
    version          text NOT NULL,
    version_original text NOT NULL,
    listed           bool NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repository_id, name, version)
);

CREATE INDEX component_repo_name_idx ON component (repository_id, name);

-- ---------------------------------------------------------------------------
-- asset
-- ---------------------------------------------------------------------------
CREATE TABLE asset (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    component_id  bigint NOT NULL REFERENCES component(id) ON DELETE CASCADE,
    path          text NOT NULL,
    content_type  text NOT NULL,
    blob_sha256   text NOT NULL REFERENCES blob(sha256),
    size          bigint NOT NULL,
    sha512_base64 text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (component_id, path)
);

-- ---------------------------------------------------------------------------
-- proxy_cached_version
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_cached_version (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id         bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    version               text NOT NULL,
    listed                bool NOT NULL DEFAULT true,
    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    downloaded            bool NOT NULL DEFAULT false,
    metadata_refreshed_at timestamptz,
    not_found             bool NOT NULL DEFAULT false,
    not_found_at          timestamptz,
    UNIQUE (repository_id, name, version)
);

-- ---------------------------------------------------------------------------
-- proxy_upstream_index
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_upstream_index (
    repository_id  bigint PRIMARY KEY REFERENCES repository(id) ON DELETE CASCADE,
    resources      jsonb NOT NULL,
    fetched_at     timestamptz NOT NULL DEFAULT now(),
    etag           text
);

-- ---------------------------------------------------------------------------
-- app_user
-- ---------------------------------------------------------------------------
CREATE TABLE app_user (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username       text NOT NULL UNIQUE,
    password_hash  text NOT NULL,
    is_admin       bool NOT NULL DEFAULT false,
    active         bool NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- token
-- ---------------------------------------------------------------------------
CREATE TABLE token (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    name          text NOT NULL,
    token_hash    text NOT NULL UNIQUE,
    expires_at    timestamptz,
    revoked_at    timestamptz,
    last_used_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);
