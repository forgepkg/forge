-- ---------------------------------------------------------------------------
-- 0040: raw (generic file) repositories
-- ---------------------------------------------------------------------------
--
-- A repository of format `raw` holds files under arbitrary paths, like
-- Nexus' raw-hosted, raw-proxy and raw-group repositories. A file is one row
-- of `raw_file` naming one CAS `blob`: the row holds exactly one
-- `blob.ref_count` reference, taken with `blob_dao::commit_ingest_and_incref`
-- in the transaction that inserts it (or points it at new content) and
-- released with `blob_dao::decref_and_maybe_enqueue_delete` in the one that
-- deletes it (or replaces its content). The same content under several paths
-- or in several repositories is one blob.
--
-- `path` is the normalized path without a leading `/`
-- (`pdfium/7350/pdfium-linux-x64.tgz`): no empty, `.` or `..` segments, no
-- backslash and no control characters. It is compared in byte order
-- (`COLLATE "C"`), so a directory is a range of the unique index and a
-- listing walks it in the order it pages in.
--
-- Proxies keep what their upstream said about a cached file (its `ETag` and
-- `Last-Modified`, for a conditional re-validation) and when the copy was
-- last confirmed (`checked_at`; NULL makes it due).

CREATE TABLE raw_file (
    id                     bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id          bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    path                   text        COLLATE "C" NOT NULL
                                       CHECK (path <> '' AND left(path, 1) <> '/' AND right(path, 1) <> '/'),
    blob_sha256            text        NOT NULL REFERENCES blob(sha256),
    size                   bigint      NOT NULL CHECK (size >= 0),
    content_type           text        NOT NULL,
    -- The content's other digests, for the `.sha512`, `.sha1` and `.md5`
    -- sidecars (the SHA-256 is the blob's).
    sha512_base64          text        NOT NULL,
    sha1                   text        NOT NULL,
    md5                    text        NOT NULL,
    -- When the path was first stored, and when its content last changed
    -- (`Last-Modified`).
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    -- Last download (bumped at most hourly), for retention.
    last_downloaded_at     timestamptz,
    upstream_etag          text,
    upstream_last_modified text,
    checked_at             timestamptz,
    UNIQUE (repository_id, path)
);

CREATE INDEX raw_file_blob_idx ON raw_file (blob_sha256);

-- Retention deletes files: audited next to components and images.
ALTER TABLE retention_audit DROP CONSTRAINT retention_audit_target_kind_check;
ALTER TABLE retention_audit
    ADD CONSTRAINT retention_audit_target_kind_check
        CHECK (target_kind IN ('component', 'proxy_cached_version', 'oci_tag', 'oci_manifest', 'raw_file'));
